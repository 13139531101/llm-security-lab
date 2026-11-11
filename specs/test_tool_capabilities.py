#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
工具能力声明 + HITL 推导 —— 零依赖测试。

为什么用纯脚本而不是 pytest
---------------------------
这个模块要**进 CI 阻塞门禁**，门禁必须满足两条：
    1. 跑得快（秒级）—— 否则没人愿意每次提交都跑；
    2. 不需要装东西 —— 否则"本地能跑、CI 装不上"就变成又一次 fail-open。
和 `tests/security/test_authz_idor.py` 一样的规矩：纯标准库，0.3 秒跑完。

但函数名按 `test_*` 命名，pytest 也能直接收集 —— 两边都能跑。

跑法
----
    python specs/test_tool_capabilities.py        # 独立跑
    pytest specs/test_tool_capabilities.py        # pytest 也行

覆盖的是**不变量**，不是具体某个工具的结论。
工具会变、结论会变，不变量不会 —— 不变量变了才需要改这个文件。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tool_capabilities import (  # noqa: E402
    UI_ACTION_RISK,
    Capability,
    Policy,
    derive,
    incomplete_declarations,
    resolve_interrupt_config,
    undeclared_tools,
)


# ============================================================
# 迷你测试框架
# ============================================================

_CASES = []


def case(fn):
    _CASES.append(fn)
    return fn


def eq(got, want, msg=""):
    assert got == want, "%s\n  got : %r\n  want: %r" % (msg or "不相等", got, want)


def truthy(v, msg=""):
    assert v, msg or "期望为真，实际为假"


def falsy(v, msg=""):
    assert not v, msg or "期望为假，实际为真"


def raises(fn, msg=""):
    try:
        fn()
    except Exception:
        return
    raise AssertionError(msg or "期望抛异常，实际没抛")


# ============================================================
# 一 · 未声明 = 最坏假设（fail-safe），不是"声明为安全"
# ============================================================

@case
def test_undeclared_defaults_to_strict():
    """没声明 → 默认最严。"""
    hitl, sources, controls = derive(None)
    truthy(hitl, "未声明的工具必须默认需要 HITL")
    truthy(any(s.startswith("undeclared") for s in sources),
           "必须能说清「为什么拦」——来源要可追溯")
    falsy(any("safe" in s for s in sources), "不存在「未声明=安全」这条路径")


@case
def test_undeclared_tools_listed():
    caps = {"a": Capability()}
    out = undeclared_tools(["a", "b", "c"], caps)
    eq(out, ["b", "c"], "未声明工具应可枚举")


@case
def test_undeclared_count_is_a_metric():
    """未声明数量是**可观测指标**，应当随时间下降。"""
    caps = {n: Capability() for n in "abcd"}
    eq(len(undeclared_tools(["a", "b", "e"], caps)), 1)


# ============================================================
# 二 · mock：意图未声明 ≠ 声明为只读
# ============================================================

@case
def test_mock_with_no_effects_is_intent_unknown():
    """mock 且没声明任何副作用 = 意图未声明，不是"只读"。"""
    caps = Capability(mock=True)
    hitl, sources, controls = derive(caps)
    truthy("capability:mock-intent-unknown" in sources,
           "必须区分「意图未声明」和「声明为只读」")
    truthy("capability:mock" in sources, "mock 本身也是一条事实")
    truthy("mock-watch" in controls, "mock 必须挂控制点：实现那天要改声明")


@case
def test_mock_with_declared_effects_is_not_incomplete():
    caps = Capability(mock=True, writes=("db",))
    hitl, sources, controls = derive(caps)
    falsy("capability:mock-intent-unknown" in sources,
          "已声明副作用的 mock 不算意图未声明")
    truthy(hitl, "声明了写操作的 mock 依然要拦")


@case
def test_incomplete_declarations_lists_intent_unknown():
    caps = {
        "mock_no_effect": Capability(mock=True),
        "mock_with_effect": Capability(mock=True, writes=("db",)),
        "real": Capability(),
    }
    out = incomplete_declarations(["mock_no_effect", "mock_with_effect", "real"], caps)
    eq(out, ["mock_no_effect"], "只有「mock + 无声明副作用」算声明不完整")


@case
def test_mock_does_not_change_judgement():
    """
    mock 不改变判定 —— 判定依据是「将来会做什么」。

    这是本规格最容易被人推翻的一条，所以单独测：
    mock 换成真实现那天，门禁结论不能纹丝不动。
    """
    mocked = Capability(mock=True, writes=("db",))
    real = Capability(writes=("db",))
    eq(derive(mocked)[0], derive(real)[0],
       "mock 与真实现必须得出同一个 needs_hitl")
    truthy("mock-watch" in derive(mocked)[2], "mock 要额外挂控制点")


# ============================================================
# 三 · 策略只能收紧，不能放松
# ============================================================

@case
def test_policy_strict_overrides_capability():
    """manifest 的 dangerously: true 压得住一切。"""
    caps = {"t": Capability()}          # 事实层：完全只读
    dec = resolve_interrupt_config("a1", ["t"], capabilities=caps,
                                   policy=Policy(dangerous_agents=frozenset({"a1"})))
    truthy(dec["t"].needs_hitl, "策略层从严必须压过事实层")
    truthy("manifest:dangerously" in dec["t"].sources, "来源要能追溯到 manifest")


@case
def test_policy_false_does_not_relax():
    """dangerously: false 的含义是「没额外从严」，不是「都不危险」。"""
    caps = {"t": Capability(writes=("db",))}
    dec = resolve_interrupt_config("a1", ["t"], capabilities=caps, policy=Policy())
    truthy(dec["t"].needs_hitl, "策略层没从严，不等于事实层的写操作被原谅")


# ============================================================
# 四 · 否定性声明取并集，不是互斥
# ============================================================

@case
def test_sources_are_unioned_not_first_match_wins():
    """
    旧实现 `if cfg: return cfg` 是**互斥** —— manifest 分支会吞掉兜底表。
    新实现必须把全部来源收集起来再合并。
    """
    caps = {
        "writes_tool": Capability(writes=("db",)),
        "egress_tool": Capability(egress=("http",)),
    }
    dec = resolve_interrupt_config(
        "a1", ["writes_tool", "egress_tool"],
        capabilities=caps,
        policy=Policy(dangerous_agents=frozenset({"a1"})))
    truthy(dec["writes_tool"].needs_hitl, "写库工具必须被拦")
    truthy(dec["egress_tool"].needs_hitl, "出网工具必须被拦")
    truthy("capability:writes" in dec["writes_tool"].sources,
           "能力层来源不能被策略层来源吞掉")


@case
def test_no_source_means_no_hitl():
    caps = {"t": Capability()}
    dec = resolve_interrupt_config("a1", ["t"], capabilities=caps, policy=Policy())
    falsy(dec["t"].needs_hitl, "只读工具不该被拦")


# ============================================================
# 五 · 豁免：唯一能放松的机制，所以必须最显眼
# ============================================================

@case
def test_exemption_without_reason_is_rejected():
    """没写理由的豁免不生效（fail-closed）。"""
    caps = {"t": Capability(writes=("db",))}
    dec = resolve_interrupt_config(
        "a1", ["t"], capabilities=caps,
        policy=Policy(exemptions=frozenset({"t"})))     # 没有 exemption_notes
    truthy(dec["t"].needs_hitl, "没理由的豁免必须不生效")
    truthy("exemption-rejected:no-reason" in dec["t"].controls, "拒绝原因要可见")


@case
def test_exemption_with_reason_works():
    caps = {"t": Capability(writes=("db",))}
    dec = resolve_interrupt_config(
        "a1", ["t"], capabilities=caps,
        policy=Policy(exemptions=frozenset({"t"}),
                      exemption_notes={"t": "只写临时草稿，不落 PHI"}))
    falsy(dec["t"].needs_hitl, "写了理由的豁免应该生效")
    truthy("exemption" in dec["t"].controls, "生效的豁免要留痕")


@case
def test_exemption_cannot_override_policy():
    """豁免只能压事实层；压不住策略层。"""
    caps = {"t": Capability(writes=("db",))}
    dec = resolve_interrupt_config(
        "a1", ["t"], capabilities=caps,
        policy=Policy(dangerous_agents=frozenset({"a1"}),
                      exemptions=frozenset({"t"}),
                      exemption_notes={"t": "我认为没事"}))
    truthy(dec["t"].needs_hitl, "豁免压不住 agent 级从严")
    truthy("exemption-ignored:policy-strict" in dec["t"].controls, "忽略原因要可见")


@case
def test_exemption_rejected_on_intent_unknown():
    """意图未声明的工具不允许被豁免 —— 你不知道你在豁免什么。"""
    caps = {"t": Capability(mock=True)}
    dec = resolve_interrupt_config(
        "a1", ["t"], capabilities=caps,
        policy=Policy(exemptions=frozenset({"t"}),
                      exemption_notes={"t": "现在没副作用"}))
    truthy("exemption-rejected:intent-unknown" in dec["t"].controls,
           "意图未声明的工具必须拒绝豁免")


@case
def test_exemption_rejected_on_delegate_channel():
    """委托通道不允许被豁免。"""
    caps = {"t": Capability(writes=("ui",), ui_actions=("askAgent",),
                            ui_content_from_llm=True)}
    dec = resolve_interrupt_config(
        "a1", ["t"], capabilities=caps,
        policy=Policy(exemptions=frozenset({"t"}),
                      exemption_notes={"t": "只是想少点一次"}))
    truthy(dec["t"].needs_hitl, "委托通道不能靠一行配置关掉")
    truthy("exemption-rejected:delegate-channel" in dec["t"].controls, "拒绝原因要可见")


# ============================================================
# 六 · 前端动作：副作用发生在工具进程之外
# ============================================================

@case
def test_delegate_action_with_llm_content_requires_hitl():
    caps = {"t": Capability(writes=("ui",), ui_actions=("askAgent",),
                            ui_content_from_llm=True)}
    dec = resolve_interrupt_config("a1", ["t"], capabilities=caps, policy=Policy())
    truthy(dec["t"].needs_hitl, "前端代模型发起 agent 调用 = 委托通道，必须拦")
    truthy("capability:ui-delegate-llm" in dec["t"].sources, "来源要能追溯")


@case
def test_display_action_with_llm_content_requires_hitl():
    caps = {"t": Capability(writes=("ui",), ui_actions=("showAlert",),
                            ui_content_from_llm=True)}
    dec = resolve_interrupt_config("a1", ["t"], capabilities=caps, policy=Policy())
    truthy(dec["t"].needs_hitl, "任意文本弹到用户眼前，必须拦")


@case
def test_render_action_is_not_blocked():
    """
    setData 是**产品的正常输出通道** —— 拦它等于拦产品本身。

    这条测的是**校准**：护栏误伤的代价和漏放一样真实。
    """
    caps = {"t": Capability(writes=("ui",), ui_actions=("setData",),
                            ui_content_from_llm=True)}
    dec = resolve_interrupt_config("a1", ["t"], capabilities=caps, policy=Policy())
    falsy(dec["t"].needs_hitl, "结构化结果卡片不该每次都要人确认")
    truthy("ui-action-review" in dec["t"].controls, "但必须留控制点")


@case
def test_state_action_is_not_blocked():
    caps = {"t": Capability(writes=("ui",), ui_actions=("navigateTo", "setSearch"),
                            ui_content_from_llm=True)}
    dec = resolve_interrupt_config("a1", ["t"], capabilities=caps, policy=Policy())
    falsy(dec["t"].needs_hitl, "界面状态类动作不该走 HITL")


@case
def test_unknown_ui_action_fails_closed():
    """协议表里没有的动作 = 前端扩展了、声明表没跟上 → 按最坏假设处理。"""
    caps = {"t": Capability(writes=("ui",), ui_actions=("brandNewAction",),
                            ui_content_from_llm=True)}
    dec = resolve_interrupt_config("a1", ["t"], capabilities=caps, policy=Policy())
    truthy(dec["t"].needs_hitl, "未知动作必须按最坏假设拦")
    truthy("capability:ui-action-unknown" in dec["t"].sources, "来源要能追溯")


@case
def test_ui_action_without_llm_content_is_not_blocked():
    """动作固定、内容不来自 LLM → 没有注入面。"""
    caps = {"t": Capability(writes=("ui",), ui_actions=("refresh",))}
    dec = resolve_interrupt_config("a1", ["t"], capabilities=caps, policy=Policy())
    falsy(dec["t"].needs_hitl, "固定动作不该拦")


@case
def test_policy_can_escalate_ui_action():
    """策略层可以**加严**：把 showAlert 升级成必须确认。"""
    caps = {"t": Capability(writes=("ui",), ui_actions=("navigateTo",))}
    dec = resolve_interrupt_config(
        "a1", ["t"], capabilities=caps,
        policy=Policy(ui_hitl_actions=frozenset({"navigateTo"})))
    truthy(dec["t"].needs_hitl, "策略升级必须生效")


@case
def test_ui_action_risk_table_is_closed():
    """协议表必须是**封闭集合**，且每一档都有明确语义。"""
    truthy("askAgent" in UI_ACTION_RISK, "委托动作必须在表里")
    eq(UI_ACTION_RISK["askAgent"], "delegate", "askAgent 必须是 delegate 档")
    truthy("setData" not in UI_ACTION_RISK
           or UI_ACTION_RISK["setData"] == "render", "setData 必须是 render 档")
    for name, tier in UI_ACTION_RISK.items():
        truthy(tier in ("delegate", "display", "render", "state"),
               "动作 %s 的档位 %r 未知" % (name, tier))


# ============================================================
# 七 · 只读语义
# ============================================================

@case
def test_is_readonly_semantics():
    truthy(Capability().is_readonly, "空声明 = 明确只读")
    falsy(Capability(writes=("db",)).is_readonly, "写库不是只读")
    falsy(Capability(egress=("http",)).is_readonly, "出网不是只读")
    falsy(Capability(ui_actions=("setData",)).is_readonly, "动界面不是只读")


# ============================================================
# 八 · 与真实初稿表对账（CI 门禁那条真正的断言）
# ============================================================

@case
def test_draft_table_is_self_consistent():
    """
    「声明了写操作却没被拦截」→ 门禁红。

    这条断言不需要 ground truth —— 它只要求**声明与判定自洽**，
    而自洽性是机器可以验证的。
    """
    from capabilities_draft import TOOL_CAPABILITIES

    for name, caps in TOOL_CAPABILITIES.items():
        hitl, sources, controls = derive(caps)
        data_writes = [w for w in caps.writes if w != "ui"]
        if data_writes or caps.ddl or caps.egress_target_from_llm:
            truthy(hitl,
                   "%s 声明了副作用（writes=%s ddl=%s egress_llm=%s）却没被判定为需要 HITL"
                   % (name, data_writes, caps.ddl, caps.egress_target_from_llm))


@case
def test_draft_table_has_no_undeclared_writes():
    """表里的每个条目都必须能被判定 —— 不能有半填的。"""
    from capabilities_draft import TOOL_CAPABILITIES

    for name, caps in TOOL_CAPABILITIES.items():
        hitl, sources, controls = derive(caps)
        truthy(sources, "%s 的判定没有来源 —— 说明它没被推导过" % name)


@case
def test_draft_table_mock_tools_are_flagged_incomplete():
    """mock 工具必须出现在「声明不完整」清单里，不能悄悄当成只读。"""
    from capabilities_draft import TOOL_CAPABILITIES

    names = list(TOOL_CAPABILITIES)
    incomplete = incomplete_declarations(names, TOOL_CAPABILITIES)
    truthy(incomplete, "初稿里必须还有 mock 工具待人工补声明")
    for n in incomplete:
        truthy(TOOL_CAPABILITIES[n].mock, "%s 应该确实是 mock" % n)


# ============================================================
# runner
# ============================================================

def main() -> int:
    failed = []
    for fn in _CASES:
        try:
            fn()
            print("  PASS  %s" % fn.__name__)
        except AssertionError as e:
            failed.append((fn.__name__, str(e)))
            print("  FAIL  %s\n        %s" % (fn.__name__, str(e).replace("\n", "\n        ")))
        except Exception as e:  # noqa: BLE001
            failed.append((fn.__name__, repr(e)))
            print("  ERROR %s\n        %r" % (fn.__name__, e))

    print("-" * 60)
    print("%d 个用例，%d 通过，%d 失败" % (len(_CASES), len(_CASES) - len(failed), len(failed)))
    if failed:
        print("\n失败明细：")
        for name, msg in failed:
            print("  · %s: %s" % (name, msg.splitlines()[0] if msg else ""))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
