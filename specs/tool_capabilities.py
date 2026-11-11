"""
工具能力声明 + HITL 推导 —— **零依赖纯函数**参考实现。

为什么必须是纯函数
------------------
安全决策必须可独立测试。`import api.py` 要 83 秒、还依赖数据库和网络时，
安全决策就只能靠人肉 review —— 而人肉 review 一定会漏。
本模块零依赖、零 IO、零 import 副作用 → 测试秒级、可进 CI 阻塞门禁。

三层职责（这是整个规格的核心）
----------------------------
    事实层   Capability / TOOL_CAPABILITIES  —— 这个工具**确实**会做什么（代码事实）
    策略层   Policy                           —— 这个环境要不要一律从严（部署策略）
    判定     derive() / resolve()             —— 事实 OR 策略，且**每条结论可追溯到来源**

三条不变量
----------
1. **策略只能收紧，不能放松。** 事实层不允许被配置推翻；
   `dangerously: false` 的含义是「这个 agent 我没有额外从严」，
   不是「这个 agent 里的工具都不危险」。
2. **否定性声明取并集。** 任一来源说危险就危险，不是「谁先匹配谁赢」。
   （旧实现的 `if cfg: return cfg` 正是互斥，F-014。）
3. **`needs_hitl` 是派生属性，不允许手填。** 手填的字段无法被 CI 断言，
   且新增工具必然漏填；推导规则一条覆盖全部工具，包括将来新增的。

配套
----
    specs/capabilities_draft.py    能力表（由 exercises/ex06_capability_draft.py 生成初稿）
    specs/test_tool_capabilities.py 零依赖测试（可进 CI）
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional

__all__ = [
    "Capability",
    "Policy",
    "Decision",
    "UI_ACTION_RISK",
    "derive",
    "resolve_interrupt_config",
    "undeclared_tools",
    "incomplete_declarations",
]


# ══════════════════════════════════════════════════════════════
# 协议层常量：前端动作名 → 风险档
# ══════════════════════════════════════════════════════════════
#
# 这张表是**关于前端协议的事实**，不是部署策略 ——
# 和 "HTTP 方法名"、"SQL 关键字"是同一性质的东西：
# `askAgent` 这个动作在协议里**就是**一次委托，不因部署而改变含义。
#
# 放在事实层而不是策略层，是为了让「策略只能收紧」这条不变量成立：
# 策略可以把某个动作升级成必须 HITL，但**不能**把一个 delegate 动作降级成 state。
#
# 有限可枚举是关键优势 —— 这正是「写库/出网」判定做不到的地方：
# 前端动作名是一个**封闭集合**（11 个），可以穷举；副作用类型是开放集合，不能。
#
# 来源：frontend/multiagent_front/src/ai/pageContract.js 的 PAGE_ACTIONS
#       （后端 shared_page_control.py 的注释把它抄成字面量：前端改了这里必须一起改）
#
# 四个档位
#   delegate —— 前端代发一次请求。模型多了一条**绕过工具层全部判定**的路。
#   display  —— 把**模型写的自由文本**摆到用户眼前。钓鱼文本的落点。
#   render   —— 把结构化结果渲染成卡片。**这是产品的正常输出通道**，
#               拦它等于拦产品本身（模型答一句就要人点一次确认）。
#   state    —— 改界面状态。路由、筛选、表单预填这类。
UI_ACTION_RISK: dict[str, str] = {
    "setData":        "render",    # 往卡片区追加一张结构化结果卡片
    "navigateTo":     "state",     # 路由跳转
    "showAlert":      "display",   # 全局提示 —— 任意文本进用户视野
    "refresh":        "state",     # 重新拉取页面数据
    "openRecord":     "state",     # 打开某条健康档案的详情弹窗
    "setFilter":      "state",     # 设置档案页的分类筛选
    "setSearch":      "state",     # 设置档案页的搜索词
    "fillForm":       "state",     # 把 AI 抽取的字段填进「新增档案」表单（只填不提交）
    "askAgent":       "delegate",  # 驱动页面内嵌对话框发起一次提问
    "highlightAgent": "state",     # 高亮某张 agent 卡片
    "setView":        "state",     # 切换页面顶部的时间/视图标签
}

#: 会让前端**代发一次请求**的动作 —— 绕过工具层判定的委托通道
UI_DELEGATE_ACTIONS = frozenset(a for a, r in UI_ACTION_RISK.items() if r == "delegate")
#: 会把**任意文本渲染给用户**的动作 —— 钓鱼文本的落点
#:
#: ⚠️ 故意**不含** ``setData``：它渲染的是结构化结果卡片，
#: 是这个产品**正常的输出通道**。把它算进来 = 每答一句都要人点一次确认。
#: 校准护栏时，误伤的代价和漏放一样真实。
UI_DISPLAY_ACTIONS = frozenset(a for a, r in UI_ACTION_RISK.items() if r == "display")


# ══════════════════════════════════════════════════════════════
# 事实层
# ══════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Capability:
    """
    一个工具的能力声明。

    所有字段都是**关于代码的事实陈述**，不是判断 —— 这是它比关键字表可靠的根本原因：
    事实可以被 CI 对账（"这个工具到底写不写库"读代码就有答案），
    判断不能（"这个工具该不该 HITL"没有 ground truth）。
    """

    writes: tuple[str, ...] = ()
    """写操作作用的资源。

    取值：
      · ``db``     —— 写数据库（PHI 等敏感数据）
      · ``memory`` —— 写长期记忆 / 记忆库
      · ``file``   —— 写文件
      · ``ui``     —— **写前端界面状态**（AG-UI ``page_update.actions``）
      · 具体资源名（如 ``health_records``）—— 更精确的粒度，推荐

    ⚠️ ``ui`` 必须单列，不能并进 ``db``/``file``：
    它是**副作用发生在工具进程之外**的一类 —— 工具自己不碰数据库、不发 HTTP，
    但它返回的 payload 会被**前端执行**。
    只扫 DB/HTTP/文件的扫描器会把它判成"只读"，这是**系统性漏报**，
    而"只读"在能力表里是一个会被下游当成"安全"的结论。
    """

    egress: tuple[str, ...] = ()
    """出网目标类型：``http``（外部 HTTP）/ ``agent``（调另一个 agent）。"""

    egress_target_from_llm: bool = False
    """出网目标是否由 **LLM 填的 tool 参数**决定。

    这是最高危的单个字段：目标不可控 = SSRF + 数据外泄通道（F-015）。
    与"出网内容由谁填"是**两种不同的风险**，判定时必须分开看。
    """

    ui_content_from_llm: bool = False
    """LLM 填的内容会不会**原样进入前端**（AG-UI 动作参数）。

    与 ``egress_target_from_llm`` 同一套思路，但落点不同：
    这里不是"数据发出去"，而是**数据被摆到用户眼前 / 被前端代发**。

    单独一个布尔不够用 —— 落点不同，严重性差两个量级：

    ==============  ====================================  ==============
    动作              后果                                 档位
    ==============  ====================================  ==============
    ``setSearch``    搜索框被改成模型写的字符串             ``state``
    ``setFilter``    列表被筛成模型选的条件                 ``state``
    ``setView``      视图切换                               ``state``
    ``highlightAgent`` 卡片高亮                             ``display``
    ``showAlert``    **任意文本弹到用户眼前**（钓鱼文本）     ``display``
    ``askAgent``     **前端替模型去问另一个 agent**          ``delegate``
    ==============  ====================================  ==============

    ``delegate`` 最重：它把"模型 → 前端 → agent"变成模型自己的一条委托通道，
    而这条通道**绕过工具层的全部判定** —— 前端根本不知道自己在替谁问。
    """

    ui_actions: tuple[str, ...] = ()
    """该工具会派发的**前端动作名**（AG-UI ``page_update.actions``）。

    有限可枚举 —— 这正是它比"写库/出网"更好判定的地方：
    动作名的集合是封闭的（见 :data:`UI_ACTION_RISK`），不是开放集合。

    空元组 = 该工具不碰界面。
    """

    ddl: bool = False
    """是否改表结构（ALTER / DROP / TRUNCATE）。"""

    mock: bool = False
    """当前是假实现。

    **注意：mock 不改变判定。** 判定依据是"这个工具**将来**会做什么"，
    否则 mock 换成真实现的那天，门禁结论纹丝不动、静默失效。
    mock 只额外挂一个 ``mock-watch`` 控制点（实现那天必须改声明）。
    """

    note: str = ""
    """人工审阅备注。初稿由机器生成时这里是 TODO。"""

    @property
    def is_readonly(self) -> bool:
        """明确只读 —— 注意"只读"不等于"安全"：出网也算副作用，界面写入也算。"""
        return (not self.writes and not self.egress and not self.ddl
                and not self.ui_actions)


# ══════════════════════════════════════════════════════════════
# 策略层
# ══════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Policy:
    """
    策略层（部署配置）。

    **只能收紧，不能放松。** `dangerous_agents` 是 agent 级的从严开关；
    `exemptions` 是**唯一**能放松事实层的机制，而且必须写理由。
    """

    dangerous_agents: frozenset[str] = frozenset()
    """整个 agent 一律从严（对应 manifest 的 ``dangerously: true``）。"""

    exemptions: frozenset[str] = frozenset()
    """豁免清单（工具名）。只能压事实层，压不住策略层。"""

    exemption_notes: Mapping[str, str] = field(default_factory=dict)
    """豁免理由。**没写理由的豁免不生效**（fail-closed）。"""

    ui_hitl_actions: frozenset[str] = frozenset()
    """把某些前端动作升级成必须 HITL。

    这是策略层**唯一的收紧方向之一**：可以加，不能减。
    协议表（:data:`UI_ACTION_RISK`）说了 ``askAgent`` 是 delegate，
    策略可以把 ``showAlert`` 也升级成必须确认 —— 但不能把 ``askAgent`` 降级。
    """


# ══════════════════════════════════════════════════════════════
# 判定结果
# ══════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Decision:
    """一条判定结论。``sources`` 让"为什么"永远可追溯。"""

    tool: str
    needs_hitl: bool
    sources: tuple[str, ...]
    """判定依据（来源）。审计时能回答"为什么这个工具被拦了"。"""

    controls: tuple[str, ...] = ()
    """这个工具**还需要**哪些别的控制点（HITL 管不到的）。"""


# ══════════════════════════════════════════════════════════════
# 推导
# ══════════════════════════════════════════════════════════════

def derive(caps: Optional[Capability]) -> tuple[bool, tuple[str, ...], tuple[str, ...]]:
    """
    从能力声明推导 ``(needs_hitl, sources, controls)``。

    这是**派生属性** —— 不允许人手填 ``needs_hitl``：

    · 手填的字段无法被 CI 断言（没有 ground truth），且新增工具必然漏填；
    · 推导规则一条覆盖全部工具，**包括将来新增的**。

    未声明（``caps is None``）→ 默认最严。
    理由：未声明不是安全策略上的"安全"，而是信息状态上的"不知道"；
    对"不知道"的正确处理是按最坏假设（fail-safe）。
    代价是吵（多一次确认），收益是不会静默（fail-open 是静默的）。
    """
    if caps is None:
        return True, ("undeclared:default-strict",), ()

    hitl_reasons: list[str] = []
    facts: list[str] = []
    controls: list[str] = []

    if caps.writes:
        # 副作用分两档：**数据面**和**界面面**。
        # 分档的理由不是"哪个更严重"，而是"哪个的误伤代价不同"：
        #   · 拦一个写库工具 → 少一次确认，安全收益高
        #   · 拦一个"切到用药页"工具 → 每次都要点确认，是噪音
        # 混成一档，要么拦得不够，要么吵到没人看。
        data_writes = tuple(w for w in caps.writes if w != "ui")
        ui_writes = tuple(w for w in caps.writes if w == "ui")
        if data_writes:
            hitl_reasons.append("capability:writes")
        if ui_writes:
            facts.append("capability:ui-write")
            controls.append("ui-action-review")

    if caps.ui_actions:
        facts.append("capability:ui-action")
        controls.append("ui-action-review")
        if caps.ui_content_from_llm:
            # LLM 内容进前端 —— 按动作档位决定要不要 HITL
            acts = set(caps.ui_actions)
            if acts & UI_DELEGATE_ACTIONS:
                # 前端代模型发起 agent 调用 = 模型自建委托通道，绕过工具层判定
                hitl_reasons.append("capability:ui-delegate-llm")
            if acts & UI_DISPLAY_ACTIONS:
                # 任意文本渲染到用户眼前 = 钓鱼文本的落点
                hitl_reasons.append("capability:ui-display-llm")
        # 未在协议表里的动作名 —— 协议扩展了，声明表没跟上
        unknown = tuple(sorted(a for a in caps.ui_actions if a not in UI_ACTION_RISK))
        if unknown:
            # 未知动作按最坏假设处理（fail-closed）
            hitl_reasons.append("capability:ui-action-unknown")
            controls.append("ui-action-review")

    if caps.ddl:
        hitl_reasons.append("capability:ddl")
    if caps.egress_target_from_llm:
        # 出网目标由 LLM 决定 = SSRF + 数据外泄通道，严重一个量级
        hitl_reasons.append("capability:egress-target-llm")
    if caps.egress:
        facts.append("capability:egress")
        # 出网但目标由服务端定 → 不是 HITL 的活，是 egress 白名单 + 字段级脱敏的活
        controls.append("egress-allowlist")
        if not caps.egress_target_from_llm:
            facts.append("capability:egress-fixed-target")
    if caps.mock:
        facts.append("capability:mock")
        # mock 换成真实现时必须改声明 —— 否则门禁结论纹丝不动、静默失效
        controls.append("mock-watch")
        if not caps.writes and not caps.egress and not caps.ddl and not caps.ui_actions:
            # ⚠️ mock + 没声明任何副作用 = **意图未声明**，不是"声明为只读"。
            #    这两者必须区分：前者是"不知道"，后者是"知道且安全"。
            #    mock 现在不写，但作者写在注释里的意图是"要写"
            #    （例：send_medication_notification 里那句
            #      `# 模拟发送通知（实际应用中可以集成推送服务）`）。
            #    如果把它当成只读，mock 换成真实现那天门禁结论不变 —— 洞静默重开。
            facts.append("capability:mock-intent-unknown")
            controls.append("intent-declaration-required")

    if not hitl_reasons and not facts:
        # 明确只读 —— 也是一条**正面结论**，同样要可追溯。
        #
        # 「为什么这个工具**没**被拦」和「为什么被拦」一样要能回答。
        # 没有这条来源，一个只读工具的判定就是空集，
        # 空集在审计里长得和「没跑过判定」一模一样。
        facts.append("capability:readonly")

    return bool(hitl_reasons), tuple(hitl_reasons + facts), tuple(controls)


def resolve_interrupt_config(
    agent_name: str,
    tool_names: Iterable[str],
    *,
    capabilities: Mapping[str, Capability],
    policy: Policy,
) -> dict[str, Decision]:
    """
    把 **事实层 ∪ 策略层** 合成最终 HITL 判定，每条结论带来源。

    与旧实现的关键差别
    ------------------
    旧：多来源**互斥** —— ``if cfg: return cfg`` 让 manifest 分支吞掉硬编码兜底表，
        连带吞掉作者亲手写进兜底表的两个工具（F-014）。
    新：**收集全部来源再合并**，任一来源说危险就危险；且每条结论可追溯。

    豁免规则
    --------
    · 豁免只能压**事实层**；策略层的 agent 级从严压不住（``manifest:dangerously`` 优先）。
    · 豁免**必须写理由**，没写理由的豁免不生效（fail-closed）。
    · 豁免**不能**用在"意图未声明"的工具上 —— 你不知道你在豁免什么。
      —— 豁免是唯一能放松的机制，所以它必须是**最显眼**的机制。
    """
    out: dict[str, Decision] = {}

    for tool in tool_names:
        caps = capabilities.get(tool)
        cap_hitl, sources, controls = derive(caps)

        policy_hitl = agent_name in policy.dangerous_agents
        if policy_hitl:
            sources = sources + ("manifest:dangerously",)

        # 策略层收紧：指定的前端动作一律要 HITL（只加不减）
        caps_acts = set(caps.ui_actions) if caps is not None else set()
        escalated = caps_acts & set(policy.ui_hitl_actions)
        if escalated:
            sources = sources + ("policy:ui-hitl-action:%s" % ",".join(sorted(escalated)),)

        exempt = tool in policy.exemptions
        if exempt and tool not in policy.exemption_notes:
            # 没写理由的豁免 → 不生效
            exempt = False
            controls = controls + ("exemption-rejected:no-reason",)
        if exempt and "capability:mock-intent-unknown" in sources:
            # 意图未声明的工具不允许被豁免 —— 你不知道你在豁免什么
            exempt = False
            controls = controls + ("exemption-rejected:intent-unknown",)
        if exempt and (caps_acts & UI_DELEGATE_ACTIONS):
            # 委托通道不允许被豁免 —— 这不是"这次操作有点危险"，
            # 是模型多了一条能绕过工具层判定的路。关掉它要改代码，不是一行配置。
            exempt = False
            controls = controls + ("exemption-rejected:delegate-channel",)

        if exempt and not policy_hitl and not escalated:
            needs_hitl = False
            controls = controls + ("exemption",)
        else:
            needs_hitl = cap_hitl or policy_hitl or bool(escalated)
            if exempt and policy_hitl:
                controls = controls + ("exemption-ignored:policy-strict",)
            if exempt and escalated:
                controls = controls + ("exemption-ignored:policy-strict-ui",)

        out[tool] = Decision(tool, needs_hitl, sources, controls)

    return out


def undeclared_tools(
    tool_names: Iterable[str],
    capabilities: Mapping[str, Capability],
) -> list[str]:
    """
    列出**未声明**的工具。

    这个数量是一个可观测指标，且应当**随时间下降**：
    默认最严 → 立刻安全；补声明 → 精度提升；补完 → 指标归零。

    这是"默认最严 = 渐进式收紧，默认宽松 = 一次性大改"的落地形态。
    """
    return sorted(t for t in tool_names if t not in capabilities)


def incomplete_declarations(
    tool_names: Iterable[str],
    capabilities: Mapping[str, Capability],
) -> list[str]:
    """
    列出**声明不完整**的工具。

    "声明完整"= 明确知道它会做什么（含明确知道"它什么都不做"）。
    以下两种情况算**不完整**：

    1. 根本没声明（不在表里）—— 由 `undeclared_tools` 覆盖；
    2. 声明了，但它是 mock 且没写任何副作用 —— **意图未声明**。
       它现在无害，但作者写在注释里的意图是"要写"，
       mock 换成真实现那天门禁结论不变 → 洞静默重开。

    ⚠️ 这一栏是 ex06 自动生成初稿时**当场暴露**出来的：
       `send_medication_notification` / `send_appointment_notification`
       的源码里写着 `# 模拟发送通知（实际应用中可以集成推送服务）`，
       机器按"当前行为"判定为只读 —— 这正是 notes.md 里
       「注释里的『模拟』是意图信号」那条坑的复现。
       **机器生成初稿，必须人工审阅。**
    """
    out = []
    for t in tool_names:
        caps = capabilities.get(t)
        if caps is None:
            continue
        if caps.mock and not caps.writes and not caps.egress and not caps.ddl \
                and not caps.ui_actions:
            out.append(t)
    return sorted(out)
