# 工具能力声明表（`TOOL_CAPABILITIES`）· 规格

> 目标：把「按工具名猜危险」换成「读声明」。
> 配套：`specs/tool_capabilities.py`（零依赖纯函数实现）·
> `specs/test_tool_capabilities.py`（28 条不变量测试，秒级跑完）·
> `specs/capabilities_draft.py`（机器生成的初稿）·
> `exercises/ex06_capability_draft.py`（初稿生成器）

---

## 0. 这份规格在解决什么问题

靶场现状（`v2/dangerous_tools.py`）用**工具名子串**判断危险：

```python
_DANGEROUS_KEYWORDS = ("delete", "complete", "log_taken", "save_", "add_", "update_", "send_")
def is_dangerous(tool_name): ...
```

三个问题，都不是"关键字不够多"能解决的：

| 问题 | 表现 |
|---|---|
| **名字不携带副作用信息** | `save_health_record`（写 PHI）和 `save_report_template`（存模板）模式完全一样，危险度差两个量级 |
| **覆盖性无底** | 写类动词是开放集合，且要同步到三处（`dangerous_tools` / `tool_permissions.WRITE_OP_PREFIXES` / `write_audit._DANGEROUS_PATTERNS`） |
| **多来源互斥** | `if cfg: return cfg` 让 manifest 分支吞掉硬编码兜底表，连带吞掉作者亲手写进兜底表的两个工具 |

ex05 实测：**三套判定对 67 个工具给出 16 个不同结论。**

规格的立场：**判定依据从「名字」换成「关于代码的事实陈述」**。

> 关键论点（也是 M2-A4 那道自检题的答案）：
> 能力表和关键字表**都是人写的**，区别不在"人手"，在**可证伪性** ——
> 能力表里的字段能被 CI 断言，关键字表的正确性不可证伪。

---

## 1. 三层模型

```
┌─────────────────────────────────────────────┐
│  事实层   Capability / TOOL_CAPABILITIES      │  这个工具**确实**会做什么
│           （跟着代码走，CI 可对账）            │  改它 = 改代码
├─────────────────────────────────────────────┤
│  策略层   Policy                              │  这个环境要不要一律从严
│           （跟着部署走）                       │  改它 = 改 yaml
├─────────────────────────────────────────────┤
│  判定     derive() / resolve()                │  事实 OR 策略
│           每条结论带 sources，可追溯          │  needs_hitl 是**派生属性**
└─────────────────────────────────────────────┘
```

**为什么必须分两层**：合成一个 `dangerous: bool` 字段后，这一个字段同时承担
「这个工具确实写库」（事实）和「这个环境要不要从严」（策略）两件事。
后果是**配置推翻了代码事实** —— `dangerously: false` 填进去，一个实际写库的工具
就被声明成"不危险"。

判定式：

```
HITL(工具) = 事实层判定(工具) OR 策略层收紧(agent)
```

`dangerously: false` 的正确含义是「这个 agent 我**没有额外从严**」，
不是「这个 agent 里的工具都不危险」。

---

## 2. 字段定义

`Capability` 的每个字段都是**关于代码的事实陈述**，不是判断。

| 字段 | 类型 | 含义 | 取值 |
|---|---|---|---|
| `writes` | `tuple[str,...]` | 写操作作用的资源 | `db` / `memory` / `file` / **`ui`** / 具体资源名 |
| `egress` | `tuple[str,...]` | 出网目标类型 | `http` / `agent` |
| `egress_target_from_llm` | `bool` | 出网**目标**是否由 LLM 填的 tool 参数决定 | |
| `ui_actions` | `tuple[str,...]` | 会派发的**前端动作名** | 见 §5 协议表 |
| `ui_content_from_llm` | `bool` | LLM 填的内容是否**原样进前端** | |
| `ddl` | `bool` | 是否改表结构 | |
| `mock` | `bool` | 当前是假实现 | |
| `note` | `str` | 人工审阅备注 | |

### 2.1 `writes` 里为什么必须有 `ui`

`ui` = **写前端界面状态**（AG-UI `page_update.actions`）。

它必须单列，不能并进 `db`/`file`，因为它是**副作用发生在工具进程之外**的一类：

- 工具自己不碰数据库、不发 HTTP
- 但它返回的 payload 会被**前端执行**

只扫 DB/HTTP/文件的扫描器会把它判成"只读" —— 而"只读"在能力表里
是一个会被下游当成"安全"的结论。这是**系统性漏报**，不是个别漏项。

### 2.2 `egress_target_from_llm` 与 `ui_content_from_llm` 不是一回事

| 字段 | 问的问题 | 后果 |
|---|---|---|
| `egress_target_from_llm` | 数据**发到哪**由模型决定？ | SSRF + 数据外泄通道（F-015） |
| `ui_content_from_llm` | 数据**被摆到哪**由模型决定？ | 钓鱼文本 / 前端代发 |

**出网目标 vs 出网内容是两种不同风险**；同理，
**出网内容 vs 进界面内容**也是两种。判定时必须分开。

### 2.3 `mock` 不改变判定

判定依据是「这个工具**将来**会做什么」。
否则 mock 换成真实现那天，门禁结论纹丝不动、静默失效。

`mock` 只额外挂一个 `mock-watch` 控制点（实现那天必须改声明）。

---

## 3. 推导规则（`derive`）

`needs_hitl` 是**派生属性，不允许手填**：

- 手填的字段无法被 CI 断言（没有 ground truth），且新增工具必然漏填；
- 推导规则一条覆盖全部工具，**包括将来新增的**。

```python
derive(caps) -> (needs_hitl, sources, controls)
```

| 条件 | needs_hitl | 来源 | 控制点 |
|---|:---:|---|---|
| **未声明**（`caps is None`） | ✅ | `undeclared:default-strict` | |
| `writes` 含 `db`/`memory`/`file` | ✅ | `capability:writes` | |
| `ddl` | ✅ | `capability:ddl` | |
| `egress_target_from_llm` | ✅ | `capability:egress-target-llm` | |
| `egress`（目标固定） | ❌ | `capability:egress` | `egress-allowlist` |
| `ui_actions` 含 `delegate` + `ui_content_from_llm` | ✅ | `capability:ui-delegate-llm` | `ui-action-review` |
| `ui_actions` 含 `display` + `ui_content_from_llm` | ✅ | `capability:ui-display-llm` | `ui-action-review` |
| `ui_actions` 含**协议表外**的动作 | ✅ | `capability:ui-action-unknown` | `ui-action-review` |
| `ui_actions` 只有 `render`/`state` | ❌ | `capability:ui-action` | `ui-action-review` |
| `mock` 且没声明任何副作用 | ❌ | `capability:mock` + **`capability:mock-intent-unknown`** | `mock-watch` + `intent-declaration-required` |
| 明确只读 | ❌ | `capability:readonly` | |

### 3.1 三条设计原则，各对应一个真实踩过的坑

**① 未声明 ≠ 声明为安全**

未声明不是安全策略上的"安全"，而是信息状态上的"不知道"。
对"不知道"的正确处理是按最坏假设（fail-safe）。

代价是吵（多一次确认），收益是**不会静默**（fail-open 是静默的）。
未声明工具数是一个**可观测指标**，应当随时间下降：
默认最严 → 立刻安全；补声明 → 精度提升；补完 → 指标归零。

**② mock + 没声明副作用 = 意图未声明，不是"声明为只读"**

这两者必须区分。前者是"不知道"，后者是"知道且安全"。

> 真实样本：`send_medication_notification` 的注释写着
> `# 模拟发送通知（实际应用中可以集成推送服务）`。
> 机器按"当前行为"判定为只读 —— 这正是「注释里的『模拟』是意图信号」那条坑的复现。
> 当成只读 → mock 换成真实现那天，门禁结论不变，**洞静默重开**。

**③ 派生属性不能手填**

推导规则一条覆盖全部工具；手填只一行一行覆盖，
而且**新增工具根本不在表里**。

---

## 4. 合并算法（`resolve_interrupt_config`）

```
输入：agent_name, tool_names, capabilities（事实层）, policy（策略层）
输出：{tool_name: Decision(needs_hitl, sources, controls)}

for tool in tool_names:
    caps = capabilities.get(tool)
    cap_hitl, sources, controls = derive(caps)      # 事实层

    # ── 策略层：只能收紧 ──
    if agent_name in policy.dangerous_agents:
        sources += ("manifest:dangerously",)
    escalated = caps.ui_actions ∩ policy.ui_hitl_actions
    if escalated:
        sources += ("policy:ui-hitl-action:...",)

    # ── 豁免：唯一能放松的机制 ──
    exempt = tool in policy.exemptions
    if exempt and tool not in policy.exemption_notes:
        exempt = False; controls += ("exemption-rejected:no-reason",)
    if exempt and "capability:mock-intent-unknown" in sources:
        exempt = False; controls += ("exemption-rejected:intent-unknown",)
    if exempt and caps.ui_actions ∩ UI_DELEGATE_ACTIONS:
        exempt = False; controls += ("exemption-rejected:delegate-channel",)

    # ── 合并：并集，不是互斥 ──
    if exempt and not policy_strict and not escalated:
        needs_hitl = False
    else:
        needs_hitl = cap_hitl or policy_strict or escalated

    emit Decision(tool, needs_hitl, sources, controls)
```

### 4.1 与旧实现的关键差别

| | 旧 | 新 |
|---|---|---|
| 多来源 | **互斥**（`if cfg: return cfg`，manifest 分支吞掉兜底表） | **收集全部来源再合并**，任一来源说危险就危险 |
| 可追溯 | 不可追溯（只知道在不在 cfg 里） | 每条结论带 `sources` |
| 新增工具 | 漏（不在任何模式里，静默放行） | 默认最严 → 立刻安全，且"未声明数"显形 |
| 豁免 | 没有 | 有，但**必须写理由**，且压不住策略层 |

### 4.2 豁免规则（三条，全部 fail-closed）

1. **豁免必须写理由** —— 没写理由的豁免不生效。
2. **豁免只能压事实层** —— 压不住 agent 级从严。
3. **豁免不能用在**：
   - 意图未声明的工具上 —— 你不知道你在豁免什么；
   - 委托通道上 —— 那不是"这次操作有点危险"，是模型多了一条绕过工具层判定的路，
     关掉它要改代码，不是一行配置。

> 豁免是唯一能放松的机制，所以它必须是**最显眼**的机制。

---

## 5. 前端动作协议（事实层常量）

`UI_ACTION_RISK` 抄自 `frontend/multiagent_front/src/ai/pageContract.js` 的
`PAGE_ACTIONS` —— 前端改了这里，后端必须一起改（后端 import 不到 JS 常量）。

| 动作 | 语义 | 档位 |
|---|---|---|
| `setData` | 往卡片区追加一张结构化结果卡片 | `render` |
| `navigateTo` | 路由跳转 | `state` |
| `showAlert` | 全局提示 | `display` |
| `refresh` | 重新拉取页面数据 | `state` |
| `openRecord` | 打开某条健康档案的详情弹窗 | `state` |
| `setFilter` | 设置档案页的分类筛选 | `state` |
| `setSearch` | 设置档案页的搜索词 | `state` |
| `fillForm` | 把 AI 抽取的字段填进「新增档案」表单（只填不提交） | `state` |
| `askAgent` | 驱动页面内嵌对话框发起一次提问 | **`delegate`** |
| `highlightAgent` | 高亮某张 agent 卡片 | `state` |
| `setView` | 切换页面顶部的时间/视图标签 | `state` |

**四个档位**

| 档 | 含义 | HITL |
|---|---|---|
| `delegate` | 前端代发一次请求 | ✅（内容来自 LLM 时） |
| `display` | 把**模型写的自由文本**摆到用户眼前 | ✅（内容来自 LLM 时） |
| `render` | 把结构化结果渲染成卡片 | ❌ |
| `state` | 改界面状态 | ❌ |

### 5.1 为什么 `render` 不拦

`setData` 是这个产品**正常的输出通道** —— 模型答一句就往卡片区贴一张卡片。
拦它等于拦产品本身（每次回答都要人点一次确认）。

> **校准护栏时，误伤的代价和漏放一样真实。**
> 这条和"默认最严"不矛盾：默认最严管的是**没声明**的，
> 这里管的是**已声明且属于产品正常输出**的。

### 5.2 为什么 `delegate` 档最重

`askAgent` 让**前端替模型发起一次 agent 调用**。后果是：

> "模型 → 前端 → agent" 变成模型自己的一条委托通道，
> 而这条通道**绕过工具层的全部判定** —— 前端根本不知道自己在替谁问。

它同时满足 Lethal Trifecta 的三件：私有数据（另一个 agent 的上下文）
+ 不可信内容（模型构造的 question）+ 外部通信（前端发出的请求）。

`fillForm` 那一档值得单独提：前端契约的注释写着
「只填表，**不提交** —— 用户核对后自己点「创建」才真正入库。
这是「AI 填 → 人确认」这条链路的落点，也是它安全的原因。」
**这是靶场里已经存在的一个正确设计** —— 规格要认出它，而不是把它也拦下来。

---

## 6. 怎么填表（工作流）

### 6.1 初稿是机器生成的

`exercises/ex06_capability_draft.py` 用 ex05 的 AST 实测生成初稿：

```
ex05  扫 AST → 每个工具的结构性副作用（DB_WRITE / EGRESS / UI_WRITE / DDL / MOCK …）
ex06  翻译成能力声明 → specs/capabilities_draft.py
```

**"表也是人手写的，凭什么可靠"** 的答案是：**初稿机器生成，人只做审阅**。
审比写容易得多，而且初稿天然可被 CI 对账。

### 6.2 审阅要点

| # | 要点 |
|---|---|
| 1 | `writes` 精确到具体资源（`health_records` / `medication_schedule`），不只是 `db` |
| 2 | mock 工具**补上它将来会做什么** —— 补完 CI 对账才绿 |
| 3 | `ui_content_from_llm` 是污点分析的近似结果，要人眼确认 |
| 4 | 名字×AST 差集发现的工具，逐个看是「没实现」还是「副作用不在扫描覆盖范围」 |

### 6.3 三处**只有实测才能看出来**的例子

先读这三个，再开始填表 —— 它们解释了为什么不能用名字判断：

| 工具 | 名字给人的印象 | 实测 |
|---|---|---|
| `list_medical_kb_documents` | 只读动词 | 调的 `_ensure_rag_schema` 会执行 `CREATE TABLE`/`ALTER TABLE` → **DDL** |
| `get_medication_overview` 等 4 个 | get 开头，像只读 | 出网**目标**由 LLM 填 → **SSRF 通道** |
| `ask_agent_in_page` | 不碰库、不发 HTTP | 返回 `page_update.actions` → **前端替它发起 agent 调用** |

---

## 7. CI 对账门禁

修复没有门禁等于没修。下一个人随手加个 `**metadata`，洞就重开。

三条断言，都不需要 ground truth —— 只要求**声明与判定自洽**：

```python
# ① 声明了副作用却没被判定为需要 HITL
for name, caps in TOOL_CAPABILITIES.items():
    if caps.writes or caps.ddl or caps.egress_target_from_llm:
        assert derive(caps)[0], f"{name} 声明了副作用却没被拦截"

# ② 判定必须带来源 —— 空来源长得和"没跑过判定"一模一样
for name, caps in TOOL_CAPABILITIES.items():
    assert derive(caps)[1], f"{name} 的判定没有来源"

# ③ 未声明工具数不得增长（只能下降）
assert len(undeclared_tools(all_tools, TOOL_CAPABILITIES)) <= 上次基线
```

再加一条**声明 vs 实测**的对账（ex05 与能力表比对）：

> 声明说只读、实测有副作用 → 门禁红
> 声明说有副作用、实测没有 → 门禁红（声明过度了，会造成误伤）

最后一条尤其重要：**能力表也会腐烂**，
如果没有人盯着"声明与代码是否还一致"，它会变成第二个关键字表。

---

## 8. 迁移路径

| 阶段 | 做什么 | 风险 |
|---|---|---|
| **0** | 上表 + 上测试，先**只观察不拦**（把新判定打成日志） | 零 |
| **1** | 开启"未声明默认最严"——此时表已填满，影响≈0 | 低 |
| **2** | 开启能力层判定，与旧判定**取并集**（谁危险都拦） | 低 |
| **3** | 移除旧关键字表 | 中 —— 此时新判定已覆盖旧判定的全部结论 |
| **4** | 启用「不再被拦」的那一批（人工确认过的） | 中 |

阶段 2 的"取并集"是刻意的：**先加不减**，确认新判定不漏之后再删旧的。
直接替换 = 一次性大改 = 出事时不知道是哪儿出的。

> 对照靶场现状（F-014）：旧实现 `if cfg: return cfg` 是互斥，
> 导致 `medication_reminder`（唯一 `dangerously: true` 的 agent）
> 丢掉 L3 兜底表里的 `log_medication_taken` 和 `set_notification_preferences` 两个工具。
> 新判定下这两个都会回来 —— 这就是「红→绿」的具体落点。

---

## 9. 已知边界

诚实地说清楚这份规格**做不到**什么：

| 边界 | 说明 |
|---|---|
| 污点分析是近似的 | `ui_content_from_llm` 只追一层局部赋值；跨文件的污点传播没做 → 必须人工复核 |
| 静态分析看不到运行时 | 动态拼出来的 SQL、反射调用、环境变量驱动的目标都扫不到 |
| 协议表会过期 | 前端加新动作 → 声明表没跟上 → **协议表外动作按最坏假设拦**（fail-closed），所以过期是安全的，只是吵 |
| 只覆盖工具层 | 模型在**没有工具**的情况下被注入，不在这张表的射程内 —— 那是 M2 注入链 PoC 的事 |
| 不解决审批疲劳 | HITL 全都拦上，人会开始闭眼点同意。**这版刻意不拦 `render` 档**，就是为了留出余量 |

---

## 10. 自检（合上文件自己答）

1. 为什么 `writes` 里必须有 `ui` 这一项？它和 `db` 的本质区别在哪？
2. 「未声明默认最严」的代价是什么？为什么这个代价是可以接受的？
3. 为什么 mock + 没声明副作用 ≠ 声明为只读？
4. 豁免有三条拒绝规则，分别在防什么？
5. `setData` 为什么不拦？这和"默认最严"矛盾吗？
6. `askAgent` 为什么最重？它绕过了什么？
7. 「声明说只读、实测有副作用」和「声明说有副作用、实测没有」，哪一条更要紧？
