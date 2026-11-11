"""
ex06 · 由 AST 实测生成「工具能力声明」初稿

为什么需要它
------------
任务 2 的核心质疑是："表也是人手写的，凭什么比关键字表可靠？"

答案：**初稿机器生成，人只做审阅**。

ex05 已经能算出每个工具的结构性副作用（DB_WRITE / EGRESS / LLM_TARGET / MOCK ...），
把它翻译成能力声明，70 个工具的"填表"就从**手写**变成**审阅** —— 审比写容易得多，
而且初稿天然可被 CI 对账（声明 vs 实测不一致 = 门禁红）。

产出
----
    specs/capabilities_draft.py   ← 可直接抄进靶场的 TOOL_CAPABILITIES 表

对比结论
--------
    「新判定 vs 现状判定」的差异表 —— 哪些工具**新增**被拦、哪些**不再**被拦。
    这一栏是 F-014 修复的"红→绿"预览。

只读：不修改靶场任何文件。
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent / "specs"))

import ex05_tool_audit as ex05  # noqa: E402
from tool_capabilities import Capability, Policy, resolve_interrupt_config  # noqa: E402

DEFAULT_REPO = Path(os.environ.get("PHA_REPO", r"I:\A2A\3\A2AServer"))
OUT_PATH = _HERE.parent / "specs" / "capabilities_draft.py"

# ex05 里 main() 内部的局部常量，这里复制一份
HARD = {"DB_WRITE", "EGRESS", "AGENT_EGRESS", "FILE_WRITE", "MEMORY_WRITE",
        "UI_WRITE"}
WRITE_RESOURCE = {"DB_WRITE": "db", "MEMORY_WRITE": "memory", "FILE_WRITE": "file",
                  "UI_WRITE": "ui"}
EGRESS_KIND = {"EGRESS": "http", "AGENT_EGRESS": "agent"}

# 工具名**声称**会改变状态的前缀。
#
# 注意角色：这里名字被当作「作者对外声明的契约」，**不是判定依据**。
# 判定依据永远是 AST 实测 + 能力表。
# 两者不一致 = 声明与实现不符 = 必须人工看 —— 这正是
# notes.md「注释与代码不一致 = 最高优先级审查目标」的机械化版本。
MUTATION_PREFIXES = (
    "save_", "add_", "update_", "upsert_", "create_", "new_", "set_", "put_",
    "write_", "log_", "mark_", "complete_", "send_", "delete_", "remove_",
    "purge_", "drop_", "truncate_", "destroy_", "reset_", "revoke_",
    "expire_", "archive_", "submit_", "import_", "sync_", "move_", "copy_",
)


def effects_to_capability(eff: set) -> tuple[list, list, bool]:
    """把 ex05 的副作用集合翻译成 (writes, egress, ddl)。"""
    writes = [res for key, res in WRITE_RESOURCE.items() if key in eff]
    egress = [kind for key, kind in EGRESS_KIND.items() if key in eff]
    ddl = "DB_DDL" in eff
    return writes, egress, ddl


def render_entry(name: str, cap: dict, mock: bool, src: str, noop: bool = False,
                 ui_actions: tuple = (), ui_llm: bool = False) -> str:
    """渲染成一行能力表条目。"""
    parts = []
    if cap["writes"]:
        parts.append("writes=%r," % (tuple(cap["writes"]),))
    if cap["egress"]:
        parts.append("egress=%r," % (tuple(cap["egress"]),))
    if cap["egress_target_from_llm"]:
        parts.append("egress_target_from_llm=True,")
    if ui_actions:
        parts.append("ui_actions=%r," % (tuple(ui_actions),))
    if ui_llm:
        parts.append("ui_content_from_llm=True,")
    if cap["ddl"]:
        parts.append("ddl=True,")
    if mock:
        parts.append("mock=True,")
    body = " ".join(parts)
    line = '    "%s": Capability(%s),' % (name, body)
    if noop:
        line += "  # ⚠️ 名字声称会改状态，AST 实测无任何副作用"
        line += "（要么没实现，要么副作用不在扫描覆盖范围 —— 必须人工看）"
    elif mock:
        line += "  # TODO 人工确认：当前是 mock，声明它「将来」会做什么"
    elif not body:
        line += "  # 只读（AST 实测：无写 / 无出网 / 无 DDL / 无界面动作）"
    else:
        line += "  # %s" % src
    return line


HEADER = '''"""
工具能力声明表 —— **初稿（机器生成，人工待审）**

生成器：exercises/ex06_capability_draft.py
来源：A2AServer 的 AST 实测（exercises/ex05_tool_audit.py）

⚠️ 这份表是**初稿**，人工审阅要点：
   1. `writes` 目前是粗分类（db / memory / file），要精确到具体资源
      （如 health_records / medication_schedule）需要人工细化；
   2. mock 工具的 `writes` 留空 —— 它被实现的那天，CI 对账会红；
   3. 每条都过一遍，改完把 TODO 去掉。

字段语义见 specs/tool_capabilities.py 的 `Capability` 定义。
"""
from __future__ import annotations

# 抄进靶场时改成：from .tool_capabilities import Capability
from tool_capabilities import Capability

# 工具名 → 能力声明
TOOL_CAPABILITIES: dict[str, Capability] = {
'''


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(DEFAULT_REPO))
    ap.add_argument("--out", default=str(OUT_PATH))
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    if not (repo / "backend").exists():
        print("[!] %s 不是靶场仓库（缺 backend/）" % repo)
        return 2

    # ---------- 枚举工具 ----------
    phacore_dir = repo / "backend" / "PhaCore" / "mcpserver"
    phacore_files = sorted(phacore_dir.glob("shared_*.py")) if phacore_dir.exists() else []
    agent_files = {}
    for agent in ex05.AGENTS:
        d = repo / "backend" / ex05.AGENT_DIR_MAP[agent] / "mcpserver"
        agent_files[agent] = sorted(d.glob("*_tool.py")) if d.exists() else []

    all_files = list({f for fs in agent_files.values() for f in fs} | set(phacore_files))
    scanner = ex05.EffectScanner(all_files)

    agent_tools = {a: [t for f in agent_files[a] for t in scanner.parsed[f]["tools"]]
                   for a in ex05.AGENTS}
    phacore_tools = [t for f in phacore_files for t in scanner.parsed[f]["tools"]]

    print("=" * 100)
    print("ex06 · 工具能力声明初稿生成器")
    print("靶场：%s" % repo)
    print("=" * 100)

    # ---------- 逐工具算副作用 → 能力 ----------
    records = []   # (agent, name, cap_dict, mock, src)
    for agent in ex05.AGENTS:
        for t in agent_tools[agent]:
            records.append((agent, t))
    for t in phacore_tools:
        records.append(("PhaCore", t))

    meta = []
    entries = []
    for agent, t in records:
        eff = scanner.effects_of(t["node"])
        mock = scanner.is_mock(t["node"])
        llm_target = scanner.egress_target_is_llm_controlled(t["node"])
        if mock and (eff & HARD):
            eff = (eff - HARD) | {"MOCK"}

        writes, egress, ddl = effects_to_capability(eff)

        # ── 无效 mock 检测 ────────────────────────────────────────────
        # 名字声称会改状态，但 AST 实测没有任何副作用。
        # 这类工具**没有注释标记**，静态扫关键字扫不出来，
        # 只有把「名字（声明）」和「AST（实测）」做差集才能发现。
        #
        # 典型样本：send_appointment_notification
        #   名字说"发通知" → 返回 {"status": "sent"} / "复诊提醒发送成功"
        #   实测           → 组装 notification_data 后直接 return，零 I/O
        #
        # 角色划分（重要）：
        #   名字 = 作者对外承诺的**契约**（可以当声明用）
        #   AST  = 代码**实际行为**（判定依据）
        #   差集 = 发现
        # 绝不能反过来用名字做判定 —— 那就退回关键字表了。
        claims_mutation = t["name"].lower().startswith(MUTATION_PREFIXES)
        observable = bool(eff & HARD) or bool(eff & {"DB_DDL"})
        noop = claims_mutation and not observable
        if noop:
            mock = True   # 事实上就是个假实现，只是没人写注释承认

        ui_actions = scanner.ui_actions_of(t["node"])
        ui_llm = scanner.ui_content_from_llm(t["node"])

        cap = {
            "writes": writes,
            "egress": egress,
            "egress_target_from_llm": llm_target,
            "ddl": ddl,
        }
        try:
            src = "%s:%d" % (t["file"].relative_to(repo).as_posix(), t["node"].lineno)
        except Exception:
            src = str(t["file"])

        meta.append((agent, t["name"], cap, mock, src, noop, ui_actions, ui_llm))
        entries.append(render_entry(t["name"], cap, mock, src, noop, ui_actions, ui_llm))

    caps_map = {
        name: Capability(
            writes=tuple(cap["writes"]),
            egress=tuple(cap["egress"]),
            egress_target_from_llm=cap["egress_target_from_llm"],
            ui_actions=tuple(ui_actions),
            ui_content_from_llm=ui_llm,
            ddl=cap["ddl"],
            mock=mock,
            note=src,
        )
        for _agent, name, cap, mock, src, _noop, ui_actions, ui_llm in meta
    }

    # ---------- 现状 HITL（用于对比） ----------
    sys.path.insert(0, str(repo / "backend" / "A2AServer" / "src"))
    sys.path.insert(0, str(repo / "backend"))
    from A2AServer.v2 import dangerous_tools  # noqa: E402

    print("\n【对比】现状 HITL  vs  新判定（能力声明推导）")
    print("-" * 100)

    newly, no_longer, pending = [], [], []
    noop_names = {name for _a, name, _c, _m, _s, noop, _ua, _ul in meta if noop}
    noop_rows = [(a, n, s) for a, n, _c, _m, s, noop, _ua, _ul in meta if noop]
    ui_rows = [(a, n, ua, ul)
               for a, n, _c, _m, _s, _no, ua, ul in meta if ua]
    for agent in ex05.AGENTS:
        # ⚠️ PhaCore 共享工具**每个 agent 都会加载**
        #    （v2_runtime 里 discover_phacore_tools() 的结果被并入每个 agent 的工具表）
        #    所以评估必须按 agent 展开，否则共享工具的判定一次都跑不到。
        names = ([t["name"] for t in agent_tools[agent]]
                 + [t["name"] for t in phacore_tools])
        old = dangerous_tools.get_interrupt_config(agent, available_tools=names)
        new = resolve_interrupt_config(agent, names, capabilities=caps_map, policy=Policy())
        for name in names:
            was = name in old
            now = new[name].needs_hitl
            if "capability:mock-intent-unknown" in new[name].sources:
                # 意图未声明 → 单独一栏，不能算"不再被拦"
                pending.append((agent, name, was, now))
                continue
            if now and not was:
                newly.append((agent, name, new[name]))
            elif was and not now:
                no_longer.append((agent, name, new[name]))

    print("  新增被拦：%d 个" % len(newly))
    for agent, name, dec in newly:
        why = []
        c = caps_map[name]
        data_w = [w for w in c.writes if w != "ui"]
        if data_w:
            why.append("writes=%s" % data_w)
        if c.ddl:
            why.append("ddl")
        if c.egress_target_from_llm:
            why.append("egress-target-LLM")
        if c.ui_actions:
            if c.ui_content_from_llm:
                why.append("ui-LLM:%s" % ",".join(c.ui_actions))
            else:
                why.append("ui:%s" % ",".join(c.ui_actions))
        if not why:
            why.append("未声明→默认最严")
        print("    + [%-18s] %-34s %s" % (agent, name, " ".join(why)))

    print("\n  不再被拦：%d 个" % len(no_longer))
    for agent, name, dec in no_longer:
        print("    - [%-18s] %-34s  ← 需人工确认是否可接受" % (agent, name))
    if not no_longer:
        print("    （无）")

    print("\n  ⚠️ 待人工判断（mock + 意图未声明）：%d 个" % len(pending))
    for agent, name, was, now in pending:
        tag = " [名字×行为差集发现]" if name in noop_names else " [注释已承认]"
        print("    ? [%-18s] %-34s  现状%s → 新判定%s%s" %
              (agent, name, "拦" if was else "不拦", "拦" if now else "不拦", tag))
    print("      ↑ 这些现在无害，但源码注释里的意图是『要写』。")
    print("        当成只读 → mock 换成真实现那天，门禁结论不变，洞静默重开。")

    # ---------- 名字 × 行为 差集 ----------
    print("\n【专项】名字声称会改状态，AST 实测无任何副作用（差集发现）")
    print("-" * 100)
    if not noop_rows:
        print("    （无）")
    for agent, name, src in noop_rows:
        print("    ✗ [%-18s] %-34s %s" % (agent, name, src))
    print("      ↑ 名字在这里的角色是**契约**（作者对外承诺），不是判定依据。")
    print("        关键字扫描扫不出来 —— 只能靠「名字（声明）× AST（实测）」的差集发现。")
    print("        用名字做判定就退回关键字表了；用名字做**发现线索**才是对的。")
    print("        注意：差集有两种成因 ——「真没实现」和「副作用不在扫描覆盖范围」。")
    print("        所以这一栏是**给人看的**，不是直接判定。")

    # ---------- 前端动作通道 ----------
    print("\n【专项】AG-UI 前端动作通道（副作用发生在工具进程之外）")
    print("-" * 100)
    for agent, name, acts, llm in ui_rows:
        print("    ▸ [%-18s] %-34s actions=%s%s" %
              (agent, name, ",".join(acts), "  LLM内容进前端" if llm else ""))
    print("      ↑ 这类工具不碰数据库、不发 HTTP，但它返回的 page_update.actions")
    print("        会被**前端执行** —— 只扫 DB/HTTP/文件 的扫描器会判成「只读」。")
    print("        这是**系统性漏报**：而「只读」在能力表里会被下游当成「安全」。")
    if ui_rows:
        print("        其中 askAgent 一档最重 —— 前端替模型发起一次 agent 调用，")
        print("        等于给模型开了一条**绕过工具层全部判定**的委托通道。")

    # ---------- 写出初稿 ----------
    out = Path(args.out)
    text = HEADER + "\n".join(entries) + "\n}\n"
    written = False
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        written = True
        print("\n【写出】%s" % out)
    except Exception as e:
        print("\n[!] 写文件失败（%s），改为打印到 stdout" % e)
    print("  声明条目：%d 个" % len(entries))
    if not written:
        print("\n<<<MODULE_BEGIN>>>")
        print(text)
        print("<<<MODULE_END>>>")

    mock_n = sum(1 for _a, _n, _c, m, _s, _n2, _ua, _ul in meta if m)
    noop_n = len(noop_rows)
    ui_n = len(ui_rows)
    readonly = sum(1 for _a, n, _c, m, _s, _n2, _ua, _ul in meta
                   if n in caps_map and caps_map[n].is_readonly and not m)
    print("\n【统计】")
    print("  工具总数              %d" % len(meta))
    print("  mock（需人工补声明）  %d" % mock_n)
    print("    其中差集发现        %d  ← 名字×AST 差集" % noop_n)
    print("  界面动作工具          %d  ← 副作用在工具进程之外" % ui_n)
    print("  只读（实测无副作用）  %d" % readonly)
    return 0


if __name__ == "__main__":
    sys.exit(main())
