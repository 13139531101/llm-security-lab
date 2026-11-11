# -*- coding: utf-8 -*-
"""
练习 7：HITL 挂不上的时候

M2 的最后一块拼图：**判定器自己会坏**。

ex05 回答了「哪些工具危险」，ex06 + specs/ 回答了「怎么把这件事写下来、怎么推导」，
这份练习回答第三个问题 —— **判定不可用的时候怎么办**。

为什么这必须单独成一课
----------------------
HITL 的四个必要条件（notes.md）：

    ① 会触发   ② 上下文够   ③ 人看到的内容可信   ④ 人不在时 fail-closed

第 ① 条有个隐含前提：**判定器是好的**。
可判定器是会挂的 —— 它读 manifest、列工具名、构造 middleware，每一步都可能抛异常。
前面三条默认判定器可用；这一课处理它不可用的情况。

靶场现状：4 个静默降级点
------------------------
    ① v2_runtime.py:301    `if HumanInTheLoopMiddleware is not None:`
                            —— import 失败就整块跳过，HITL 根本不存在
    ② v2_runtime.py:311    `except Exception: pass`
                            —— 工具发现失败 → 工具名列表为空 → 判定输入缺失
    ③ v2_runtime.py:332    `except Exception as e: logger.debug(...)`
                            —— HITL 装不上 → 静默跳过
    ④ dangerous_tools.py:84 `except Exception as e: logger.debug(...)`
                            —— manifest 读失败 → 降级到硬编码兜底表

四个的共同点：
    **降级 = 不拦**，而且都打 `logger.debug`（默认日志级别下看不见）。

> 静默的降级等于没有防御。
> fail-open 可怕的地方从来不是「会出错」，是「你不知道它在出错」。

这四个是 notes.md 里
「fail-open 换个马甲就会回来」那条笔记的**第四个马甲**：
M1 的 `default_user` 兜底 → M2 的 HITL 静默跳过 → 现在这两个。

三种修法，别搞混
----------------
    修法 1  只把 logger.debug 改成 logger.error
            → **可见了，但没防御**。这是最容易被当成"修好了"的一档。

    修法 2  fail-closed：判定不可用时，**危险工具压根不交给模型**
            → 模型看不见它 → 它就不会被调用。代价是功能受损。

    修法 3  fail-fast：判定器本身抛异常 → **拒绝启动**
            → 修法 2 的前提是"危险工具集还算得出来"；算不出来时只剩这一档。

    ⚠️ 不要走「所有工具都拦」那条路 ——
       那是审批疲劳，**审批疲劳是 fail-open 的变体**（人在场，但闭眼点同意）。

本练习量的是「**该拦却没拦**」，不是「拦了没有」
------------------------------------------------
「该拦」由 specs/capabilities_draft.py（ex06 的机器初稿）+ specs/tool_capabilities.py
的 derive() 算出来 —— 也就是**事实层**的结论：
    写库 / 改表 / 出网目标由 LLM 填 / 前端 delegate 或 display 动作（内容来自 LLM）
固定目标的出网、render 与 state 档的界面动作**不算**该拦（那是产品正常输出）。

所以本练习分得清两个问题：
    判定器**不准**  → F-014 / F-015 / F-016，由能力表规格（ex06 + specs/）修
    判定器**失效**  → 本练习，修的是「失效时额外损失了多少保护」

运行
----
    python ex07_hitl_fail_closed.py
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "specs"))

from tool_capabilities import derive                    # noqa: E402
from capabilities_draft import TOOL_CAPABILITIES        # noqa: E402

# ============================================================
# 1. 冻结的靶场快照（AST 实测 + manifest 实际配置）
# ============================================================

# 工具 → 结构性副作用。空 = 只读。
# 来源：ex05_tool_audit.py 对 I:\A2A\3\A2AServer 的实测
TOOL_EFFECTS = {
    # ── health_advisor ──
    "get_medication_overview":       ("EGRESS", "AGENT_EGRESS", "UI_WRITE"),
    "get_visit_summary_overview":    ("EGRESS", "AGENT_EGRESS", "UI_WRITE"),
    "aggregate_health_report":       ("EGRESS", "AGENT_EGRESS", "UI_WRITE"),
    "get_health_records_history":    ("EGRESS", "AGENT_EGRESS", "UI_WRITE"),
    "generate_consultation_summary": ("AGENT_EGRESS", "UI_WRITE"),
    "save_consultation":             ("DB_WRITE",),
    "upsert_medical_kb_document":    ("DB_DDL", "DB_WRITE"),
    "delete_medical_kb_document":    ("DB_DDL", "DB_WRITE"),
    "list_medical_kb_documents":     ("DB_DDL",),
    # ── health_records ──
    "open_health_record":            ("UI_WRITE",),
    "draft_health_record":           ("UI_WRITE",),
    "add_medication_reminder":       ("DB_WRITE",),
    "mark_reminder_taken":           ("DB_WRITE",),
    "add_health_reminder":           ("DB_WRITE",),
    "complete_reminder":             ("DB_WRITE",),
    "delete_reminder":               ("DB_WRITE",),
    "save_health_record":            ("DB_WRITE",),
    "save_medication":               ("DB_WRITE",),
    "delete_health_record":          ("DB_WRITE",),
    "create_user_profile":           ("DB_WRITE",),
    # ── medication_reminder ──
    "check_drug_interaction":        ("AGENT_EGRESS",),
    "get_today_reminders":           ("UI_WRITE",),
    "log_medication_taken":          ("DB_WRITE",),
    "add_medication_reminder":       ("DB_WRITE",),
    "add_appointment_reminder":      ("DB_WRITE",),
    # ── visit_summary ──
    "save_generated_summary":        ("DB_WRITE",),
    # ── PhaCore 共享工具（每个 agent 都加载）──
    "refresh_current_page":          ("UI_WRITE",),
    "show_page_alert":               ("UI_WRITE",),
    "highlight_agent_card":          ("UI_WRITE",),
    "ask_agent_in_page":             ("UI_WRITE",),
    "filter_health_records":         ("UI_WRITE",),
    "set_health_records_search":     ("UI_WRITE",),
    "switch_medication_view":        ("UI_WRITE",),
}

# agent → 自己域名下的工具
AGENT_OWN_TOOLS = {
    "health_advisor": [
        "get_medication_overview", "get_visit_summary_overview",
        "aggregate_health_report", "get_health_records_history",
        "generate_consultation_summary", "save_consultation",
        "get_consultation_history", "analyze_symptoms", "get_disease_info",
        "generate_health_assessment", "ai_medical_diagnosis",
        "search_symptom_info", "search_medication_info", "get_health_tips",
        "analyze_health_concern", "upsert_medical_kb_document",
        "delete_medical_kb_document", "list_medical_kb_documents",
    ],
    "health_records": [
        "analyze_health_trends_async", "extract_medical_info",
        "extract_prescription_info", "open_health_record",
        "draft_health_record", "add_medication_reminder",
        "get_medication_reminders", "mark_reminder_taken",
        "add_health_reminder", "get_health_reminders", "complete_reminder",
        "delete_reminder", "save_health_record", "get_health_records",
        "get_health_record_detail", "save_medication", "get_medications",
        "delete_health_record", "create_user_profile",
    ],
    "medication_reminder": [
        "check_drug_interaction", "send_medication_notification",
        "send_appointment_notification", "check_overdue_medications",
        "generate_daily_summary", "set_notification_preferences",
        "add_medication_reminder", "get_medication_reminders",
        "get_today_reminders", "log_medication_taken",
        "add_appointment_reminder", "get_upcoming_appointments",
    ],
    "visit_summary": [
        "analyze_health_trends", "generate_health_insights",
        "detect_health_alerts", "get_health_records_by_range",
        "get_visit_summaries_by_range", "get_visit_summaries_count_by_range",
        "get_visit_summary_detail", "save_generated_summary",
        "get_health_record_detail", "parse_medical_document",
        "generate_visit_summary", "get_sample_document",
    ],
}

# PhaCore/mcpserver/shared_*.py —— discover_phacore_tools() 给**每个** agent 都加上
PHACORE_TOOLS = [
    "extract_text_from_image", "validate_medical_document",
    "refresh_current_page", "show_page_alert", "highlight_agent_card",
    "ask_agent_in_page", "filter_health_records",
    "set_health_records_search", "switch_medication_view",
]

AGENTS = list(AGENT_OWN_TOOLS)

# ── manifest 实际配置（domain_manifest.load_default() 读出来的东西）──
MANIFEST_DANGEROUS = {"medication_reminder"}          # dangerously: true
MANIFEST_CUSTOM_KW = {}                                # dangerously_keywords: 全空

# ── dangerous_tools.py 里的硬编码兜底表（原样抄过来）──
FALLBACK_TABLE = {
    "health_records": {
        "delete_reminder", "delete_health_record", "complete_reminder",
        "mark_reminder_taken", "add_medication_reminder",
        "save_health_record", "save_medication",
    },
    "medication_reminder": {
        "add_medication_reminder", "add_appointment_reminder",
        "log_medication_taken", "send_medication_notification",
        "send_appointment_notification", "set_notification_preferences",
    },
    "visit_summary": {
        "save_generated_summary", "delete_visit_summary", "delete_health_record",
    },
    "health_advisor": {
        "delete_medical_kb_document", "save_consultation",
        "upsert_medical_kb_document",
    },
}

# ── dangerous_tools.py 的关键字表（原样抄过来）──
_DANGEROUS_KEYWORDS = (
    "delete", "complete", "log_taken", "save_", "add_", "update_", "send_",
)


def is_dangerous(tool_name: str) -> bool:
    """靶场 dangerous_tools.py 的逻辑副本。"""
    n = tool_name.lower()
    return any(kw in n for kw in _DANGEROUS_KEYWORDS)


def get_interrupt_config(agent_name: str, available_tools=None) -> set:
    """靶场 dangerous_tools.get_interrupt_config 的逻辑副本（含 F-014 的互斥 bug）。

    复制的目的不是重写靶场，是**把判定逻辑摊开在眼前**，
    好看清"故障注入之后判定还剩什么"。
    """
    tools = available_tools or []

    # 1. manifest 分支
    cfg = set()
    if agent_name in MANIFEST_DANGEROUS:
        cfg |= {t for t in tools if is_dangerous(t)}
    for t in tools:
        for kw in MANIFEST_CUSTOM_KW.get(agent_name, ()):
            if kw.lower() in t.lower():
                cfg.add(t)
                break
    if cfg:
        return cfg          # ← 互斥：兜底表被吞掉（F-014）

    # 2. 硬编码兜底表
    return set(FALLBACK_TABLE.get(agent_name, ()))


# ============================================================
# 2. 判定链路上的 4 个降级点
# ============================================================

FAIL_POINTS = [
    ("① v2_runtime.py:301", "if HumanInTheLoopMiddleware is not None:",
     "langchain 装不上 → 整块跳过 → HITL 根本不存在"),
    ("② v2_runtime.py:311", "except Exception: pass",
     "工具发现失败 → 工具名列表为空 → 判定输入缺失"),
    ("③ v2_runtime.py:332", "except Exception as e: logger.debug(...)",
     "HITL 装不上 → 静默跳过"),
    ("④ dangerous_tools.py:84", "except Exception as e: logger.debug(...)",
     "manifest 读失败 → 降级到硬编码兜底表"),
]

SCENARIOS = [
    ("S0 正常", "middleware 可用，工具发现成功，判定成功"),
    ("S1 middleware 缺失", "langchain import 失败 → 整块 HITL 被跳过"),
    ("S2 工具发现失败", "工具名列表为空 → manifest 分支匹配不到任何工具"),
    ("S3 判定器抛异常", "get_interrupt_config 抛异常 → HITL 装不上"),
]


def agent_tools(agent: str) -> list:
    """agent 实际加载的工具（含 PhaCore 共享工具）—— v2_runtime.py:305-310。"""
    return list(dict.fromkeys(AGENT_OWN_TOOLS[agent] + PHACORE_TOOLS))


def gold_set(agent: str) -> set:
    """**该拦**的工具集 —— 事实层（能力表）推导出来的结论。"""
    return {t for t in agent_tools(agent) if derive(TOOL_CAPABILITIES.get(t))[0]}


# ============================================================
# 3. 模拟：故障注入 → 实际被拦截的工具集
# ============================================================

def intercepted_now(agent: str, scenario: str) -> set:
    """**现状**（fail-open）：故障时实际生效的拦截集合。"""
    tools = agent_tools(agent)
    if scenario == "S0 正常":
        return get_interrupt_config(agent, tools) & set(tools)
    if scenario == "S1 middleware 缺失":
        return set()                       # 整块跳过 → 没有任何拦截
    if scenario == "S2 工具发现失败":
        # available_tools 为空 → manifest 分支匹配不到 → 落兜底表
        return get_interrupt_config(agent, []) & set(tools)
    if scenario == "S3 判定器抛异常":
        return set()                       # HITL 装不上
    raise ValueError(scenario)


def intercepted_fail_closed(agent: str, scenario: str):
    """**修法 2 + 修法 3**：fail-closed 阶梯。返回 (拦截集合, 是否拒绝启动)。"""
    tools = agent_tools(agent)
    if scenario == "S0 正常":
        return get_interrupt_config(agent, tools) & set(tools), False
    if scenario == "S1 middleware 缺失":
        # 判定器还能用（get_interrupt_config 不依赖 langchain）
        # → 危险工具**不交给模型**
        return get_interrupt_config(agent, tools) & set(tools), False
    if scenario == "S2 工具发现失败":
        # 判定器降级到兜底表，但还能用 → 同样摘工具
        return get_interrupt_config(agent, []) & set(tools), False
    if scenario == "S3 判定器抛异常":
        # 判定器本身不可用 → 危险工具集**算不出来**
        # → 修法 2 无解，只能 fail-fast：拒绝启动
        return set(), True
    raise ValueError(scenario)


# ============================================================
# 4. 输出
# ============================================================

def line(ch="-"):
    print(ch * 104)


def main() -> int:
    print("=" * 104)
    print("练习 7：HITL 挂不上的时候 —— fail-open 的第四个马甲")
    print("=" * 104)

    # ---------- 1 ----------
    print("\n【1】判定链路上有 4 个降级点")
    line()
    for where, code, effect in FAIL_POINTS:
        print(f"  {where}")
        print(f"      {code}")
        print(f"      → {effect}")
    line()
    print("  共同点：**降级 = 不拦**，而且都打 logger.debug（默认级别看不见）。")
    print("  静默的降级等于没有防御 —— 你不知道它在出错，就不会去查。")

    # ---------- 2 ----------
    print("\n【2】现状（fail-open）：故障时，「该拦却没拦」的高危工具有多少")
    line()
    print("  「该拦」= 能力表推导出的事实层结论（写库 / 改表 / 出网目标由 LLM 填 /")
    print("            前端 delegate·display 动作）")
    print()
    print(f"  {'场景':<20}{'agent':<22}{'该拦':<8}{'没拦':<8}漏掉的是")
    for scenario, desc in SCENARIOS:
        print(f"  {scenario:<20}{'':<22}{'':<8}{'':<8}—— {desc}")
        for agent in AGENTS:
            tools = agent_tools(agent)
            gold = gold_set(agent)
            hit = intercepted_now(agent, scenario)
            leak = sorted(gold - hit)
            mark = "⚠️ %d" % len(leak) if leak else "0"
            print(f"  {'':<20}{agent:<22}{len(gold):<8}{len(leak):<8}{mark}"
                  f"   {', '.join(leak) if leak else ''}")
        line()

    # ---------- 3 ----------
    print("\n【3】S1（middleware 缺失）下，多出来的漏项是什么")
    line()
    for agent in AGENTS:
        gold = gold_set(agent)
        normal = intercepted_now(agent, "S0 正常")
        broken = intercepted_now(agent, "S1 middleware 缺失")
        extra = sorted(gold - normal)
        all_lost = sorted(gold - broken)
        print(f"  {agent}")
        print(f"      正常路径就漏的（判定器不准，F-014/15/16）：{extra or '无'}")
        print(f"      S1 额外漏掉的（判定器失效，本练习要修的）："
              f"{sorted(set(all_lost) - set(extra)) or '无'}")
    line()

    # ---------- 4 ----------
    print("\n【4】三种修法对照（数字 = 该拦却没拦的工具数，越小越好）")
    line()
    print("  场景：" + "   ".join("%s = %s" % (s.split()[0], d) for s, d in SCENARIOS))
    print()
    print(f"  {'修法':<42}" + "".join("%-14s" % s.split()[0] for s, _ in SCENARIOS))
    methods = {
        "0 现状（fail-open）": (lambda a, s: (intercepted_now(a, s), False), {}),
        "1 只改日志级别（可见，但没防御）": (lambda a, s: (intercepted_now(a, s), False), {}),
        "2 fail-closed：危险工具不交给模型": (
            lambda a, s: intercepted_fail_closed(a, s),
            {"S3 判定器抛异常": "n/a（判定器不可用）"}),
        "3 fail-fast：判定器坏了就拒绝启动": (
            lambda a, s: (set(), True) if s == "S3 判定器抛异常"
            else intercepted_fail_closed(a, s),
            {"S3 判定器抛异常": "0（拒绝启动）"}),
    }
    for label, (fn, override) in methods.items():
        cells = []
        for scenario, _ in SCENARIOS:
            if scenario in override:
                cells.append(override[scenario])
                continue
            leak = 0
            for agent in AGENTS:
                gold = gold_set(agent)
                hit, refuse = fn(agent, scenario)
                if refuse:
                    continue          # 拒绝启动 → 没有"可执行"这回事
                leak += len(gold - hit)
            cells.append(str(leak))
        print(f"  {label:<42}" + "".join("%-14s" % c for c in cells))
    line()
    print("  读法：**修法 2 的作用是让失效路径不再比正常路径更差**（S1/S2 回到 S0 的水平）。")
    print("  它修不了 S0 的漏项 —— 那是判定器**不准**，归 F-014/15/16 和能力表规格管。")
    print("  S2 那列比 S0 还少一个，是硬编码兜底表碰巧比 manifest 匹配多覆盖了一个 ——")
    print("  这种「碰巧」不是设计，是没有机制保证对齐的证据。")

    # ---------- 5 ----------
    print("\n【5】三点结论")
    line()
    print("""
  ① **可见 ≠ 防御**
     修法 1 把 logger.debug 换成 logger.error，做的是「让人知道」，
     不是「让人拦下」。它值得做（静默是 fail-open 的温床），
     但拿它当修复交差，等于把「洞还在」换成了「洞现在有日志」。

  ② **fail-closed 的具体形态是「不给」，不是「拦」**
     HITL 挂不上的时候，「拦住所有危险操作」这个动作本身也不可用了
     （拦截器就是 HITL）。所以 fail-closed 不能实现成"多问一句"，
     只能实现成**危险工具压根不交给模型** —— 模型看不见它，就不会调它。
     代价是功能受损，所以必须配可见性（logger.error + 指标），
     否则用户只会说「功能坏了」，不会说「安全了」。

  ③ **fail-closed 需要一个前提：危险工具集在故障时还算得出来**
     修法 2 依赖 get_interrupt_config 能在 langchain 缺失时照样算出结果。
     它确实能 —— 它是纯函数，不依赖 langchain。
     **一旦判定器自己抛异常（S3），这个前提就没了**，只剩 fail-fast。
     所以完整的 fail-closed 是一段**阶梯**，不是一个 if。

  ⚠️ 反面提醒：**别走「所有工具都拦」那条路**。
     那是审批疲劳 —— 人在场，但闭眼点同意，是 fail-open 的变体。
     能力表规格里 `setData`（产品正常输出通道）故意不拦，就是为了留余量。

  🔁 和 F-014 的分工：
     F-014 是「判定器**不准**」—— 靠名字猜，漏了三个工具。
     本练习是「判定器**失效**」—— 判定准不准先不管，失效时别再额外丢保护。
     两个问题两个修法：不准靠能力表，失效靠 fail-closed 阶梯。
""")

    # ---------- 6 ----------
    print("【6】一条 CI 可断言的不变量")
    line()
    print("""
    「HITL 不可用时，判定器能算出来的危险工具，一个都不能出现在模型可见的工具列表里」

    这条不需要 ground truth，只要求**降级路径和正常路径给出同一个答案**。
    和 specs/test_tool_capabilities.py 的「声明了副作用却没被判定为需要 HITL」
    是同一类断言：机器能验证「两条路径自洽」，验证不了「正常路径判得准不准」。

    落点：tests/security/test_hitl_fail_closed.py（纯标准库，0.3 秒，可进 CI 阻塞）
""")

    print("=" * 104)
    print("一句话：fail-open 不是一个 bug，是一个**默认答案**。")
    print("       每一个「出错了就继续跑」的地方，都是在给同一个默认答案投票。")
    print("=" * 104)
    return 0


if __name__ == "__main__":
    sys.exit(main())
