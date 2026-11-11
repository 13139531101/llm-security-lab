# -*- coding: utf-8 -*-
"""
练习 5 · 任务 1：工具副作用全量枚举 —— 找出危险判定漏掉的写操作

背景
----
M2 的结论是：HITL（人工确认）判定靠工具名子串匹配，
            子串匹配在动词变形上天然脆弱（`log_medication_taken` 不含 `log_taken`）。

但"脆弱"是定性的。这份脚本把它变成**可数的**：
    把每个 agent 实际暴露的 MCP 工具全部列出来，
    用 AST 判断每个工具有没有写副作用，
    再和三套真实存在的"危险判定"对账，
    输出**漏项清单**。

三套判定（都在你的代码里，问的都是"这个工具危险吗"）
------------------------------------------------
 ① A2AServer/v2/dangerous_tools.py:is_dangerous()
      关键字：delete complete log_taken save_ add_ update_ send_
      —— **真正接进 v2 LangGraph 运行时的就是这一套**（v2_runtime.py:313）

 ② A2AServer/v2/write_audit.py:_DANGEROUS_PATTERNS
      关键字：delete_ drop_ truncate_ remove_ reset_ purge_ wipe_ destroy_
              update_password change_password revoke_
      —— 只在 skills/registry.py:221 被调用，而 registry 那条路**没接进 v2 MCP 调用链**（F-007）

 ③ A2AServer/v2/tool_permissions.py:WRITE_OP_PREFIXES
      关键字：save_ add_ update_ upsert_ log_ complete_ mark_ send_
      —— 同样只在 skills/registry.py:218 被调用，同样没接进 v2 MCP 调用链

三张表互相不一致，而且只有 ① 真正在生效。这本身就是结论。

脚本用到的三个技术点（都可以复用）
--------------------------------
 ① **跟进 helper**：upsert_medical_kb_document 函数体里一句 SQL 都没有，真写在
    _upsert_medical_kb_chunks 里。只扫一层会把"真在写库"误判成只读。
    注意连 `executor.submit(fn, ...)` 这种把函数当参数传的情况也要跟。
 ② **DDL ≠ 数据写**：CREATE TABLE IF NOT EXISTS 是副作用，但严重级别完全不同。
 ③ **出网目标的来源决定风险**：
      目标来自 LLM 填的 tool 参数（如 agent_address）→ SSRF + 外泄通道
      目标来自服务端配置（如 env 里的 HEALTH_ADVISOR_URL）→ 风险低一个量级
    这一条用 taint analysis 判定：从工具参数出发，看它流没流到出网调用。

运行
----
  python ex05_tool_audit.py
  python ex05_tool_audit.py --repo I:/A2A/3/A2AServer
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import sys
from pathlib import Path

DEFAULT_REPO = Path(r"I:\A2A\3\A2AServer")

# 与 backend/A2AServer/src/A2AServer/mcp/mcp_discover.py:AGENT_DIR_MAP 保持一致
AGENT_DIR_MAP = {
    "health_advisor": "HealthAdvisor",
    "health_records": "HealthRecordsManager",
    "medication_reminder": "MedicationReminder",
    "visit_summary": "VisitSummaryGenerator",
}
AGENTS = list(AGENT_DIR_MAP)

# ============================================================
# 1. AST 抽取
# ============================================================
def _is_mcp_tool_decorator(dec: ast.expr) -> bool:
    if isinstance(dec, ast.Call):
        f = dec.func
        if isinstance(f, ast.Attribute) and f.attr in ("tool", "tool_"):
            return True
    if isinstance(dec, ast.Attribute) and dec.attr in ("tool", "tool_"):
        return True
    return False


def parse_file(path: Path) -> dict:
    try:
        src = path.read_text(encoding="utf-8")
    except Exception:
        return {"tools": [], "helpers": {}, "src": ""}
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return {"tools": [], "helpers": {}, "src": ""}

    tools, helpers = [], {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            helpers[node.name] = node
            if any(_is_mcp_tool_decorator(d) for d in node.decorator_list):
                tools.append({"name": node.name, "file": path, "node": node})
    return {"tools": tools, "helpers": helpers, "src": src}


# ============================================================
# 2. 副作用分类
# ============================================================
SQL_WRITE_RE = re.compile(
    r"\b(insert\s+into|update\s+[\w.\"'`]+\s+set|delete\s+from|on\s+conflict)\b", re.I)
SQL_DDL_RE = re.compile(
    r"\b(create\s+(table|index|extension|schema)|alter\s+table|drop\s+table|"
    r"truncate\s+table|create\s+or\s+replace)\b", re.I)
SQL_READ_RE = re.compile(r"\bselect\b", re.I)

HTTP_CLIENT_NAMES = {"requests", "httpx", "aiohttp", "urllib", "urllib3", "http", "session"}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "request", "urlopen", "send", "head"}
EGRESS_HELPERS = {
    "_resolve_endpoint", "_send_call_tool", "_send_task", "send_task", "send_message",
    "_fetch_agent_card", "_post_json", "_http_post", "_http_get",
}
FILE_WRITE_FUNCS = {"remove", "unlink", "rmtree", "write_text", "write_bytes", "mkdir"}
MOCK_MARKERS = ("模拟", "mock", "假实现", "暂时不", "后续阶段", "待实现")

# ── AG-UI 前端动作通道 ──────────────────────────────────────────
# 这类工具**不碰数据库、不发 HTTP**，但它返回的 `page_update.actions`
# 会被**前端**执行 —— 副作用发生在工具进程之外。
# 只扫 DB/HTTP/文件 的扫描器会把它判成"只读"，这是系统性漏报：
#   set_health_records_search → 前端搜索框被改成模型填的字符串
#   show_page_alert          → 任意文本被弹到用户屏幕上
#   ask_agent_in_page        → 前端替模型去问另一个 agent（模型自选的 agent + 自选的问题）
UI_ACTION_HELPER = "_act"
UI_ACTION_MARKERS = {"page_update", "actions"}


class EffectScanner:
    """跨文件解析 helper 调用，把副作用追到底。"""

    def __init__(self, files: list[Path]):
        self.parsed = {}
        self.global_helpers: dict[str, ast.AST] = {}
        self.src_of: dict[int, str] = {}
        for f in files:
            p = parse_file(f)
            self.parsed[f] = p
            for name, node in p["helpers"].items():
                self.global_helpers.setdefault(name, node)
                self.src_of[id(node)] = p["src"]

    # ---------- 直接效果 ----------
    def _direct_effects(self, fn: ast.AST) -> set[str]:
        effects: set[str] = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                s = node.value
                if SQL_DDL_RE.search(s):
                    effects.add("DB_DDL")
                elif SQL_WRITE_RE.search(s):
                    effects.add("DB_WRITE")
                elif SQL_READ_RE.search(s):
                    effects.add("DB_READ")
            if isinstance(node, ast.JoinedStr):
                text = "".join(v.value for v in node.values
                               if isinstance(v, ast.Constant) and isinstance(v.value, str))
                if SQL_DDL_RE.search(text):
                    effects.add("DB_DDL")
                elif SQL_WRITE_RE.search(text):
                    effects.add("DB_WRITE")
            # AG-UI：字面量 payload 形如 {"page_update": {"actions": [...]}}
            # ⚠️ 这一段必须在下面的 `continue` **之前** —— 之前放在后面是死代码，
            #    导致只写字面量 payload 的工具（open_health_record 等）漏报 UI 副作用。
            if isinstance(node, ast.Dict):
                for k in node.keys:
                    # 只认 "page_update" 这个顶层包装 —— 它是前端契约的固定形状
                    # （pageContract.js: page_update.actions[]）。
                    # 单看 "actions" 太松，容易撞上业务数据里的同名字段。
                    if isinstance(k, ast.Constant) and k.value == "page_update":
                        effects.add("UI_WRITE")
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if isinstance(f, ast.Attribute):
                base = f.value
                base_name = (base.id if isinstance(base, ast.Name)
                             else base.attr if isinstance(base, ast.Attribute) else None)
                if f.attr in HTTP_METHODS and base_name and (
                        base_name.lower() in HTTP_CLIENT_NAMES
                        or base_name.lower().endswith(("client", "session"))):
                    effects.add("EGRESS")
                if f.attr in FILE_WRITE_FUNCS:
                    effects.add("FILE_WRITE")
                if f.attr in EGRESS_HELPERS:
                    effects.add("AGENT_EGRESS")
            elif isinstance(f, ast.Name):
                if f.id == "urlopen":
                    effects.add("EGRESS")
                if f.id in EGRESS_HELPERS:
                    effects.add("AGENT_EGRESS")
                if f.id.startswith("store_"):
                    effects.add("MEMORY_WRITE")
                if f.id.startswith(("delete_", "remove_")):
                    effects.add("FILE_WRITE")
            if isinstance(f, ast.Name) and f.id == "open":
                modes = []
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                    modes.append(str(node.args[1].value))
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        modes.append(str(kw.value.value))
                if any(m.startswith(("w", "a")) for m in modes):
                    effects.add("FILE_WRITE")
            # AG-UI：构造前端动作 payload
            if isinstance(f, ast.Name) and f.id == UI_ACTION_HELPER:
                effects.add("UI_WRITE")
        return effects

    # ---------- 递归（跟进 helper，含"函数当参数传"的情况） ----------
    def effects_of(self, fn: ast.AST, depth: int = 3, _seen=None) -> set[str]:
        if _seen is None:
            _seen = set()
        if id(fn) in _seen or depth <= 0:
            return set()
        _seen.add(id(fn))

        effects = self._direct_effects(fn)
        for node in ast.walk(fn):
            # 只要函数名出现在任何位置（调用 / 当参数传）都跟进
            if isinstance(node, ast.Name):
                helper = self.global_helpers.get(node.id)
                if helper is not None and id(helper) not in _seen:
                    effects |= self.effects_of(helper, depth - 1, _seen)
        return effects

    def is_mock(self, fn: ast.AST) -> bool:
        """
        这个实现是不是「假实现」？

        ★ 必须扫源码文本，不能只扫 AST 常量 ——
          「# 模拟保存通知偏好（实际应用中应保存到数据库）」是**注释**，
          注释根本不在 AST 里。只扫 AST 会漏掉最典型的那个信号。

        ★★ 但**只能看注释，不能看字符串字面量**（2026-11-11 修正）——
          `get_health_tips` 的返回文案里写着「当前工具不再提供**模拟**建议」，
          这不是在说"这个工具是模拟实现"，而是在说"它不再提供假数据"。
          关键词匹配分不清这两种语义 → 误报。
          用 tokenize 只取 COMMENT token，字符串归字符串、注释归注释。
        """
        src = self.src_of.get(id(fn))
        if not src:
            return False
        lo = fn.lineno
        hi = getattr(fn, "end_lineno", None) or fn.lineno
        try:
            import io
            import tokenize
            for tok in tokenize.generate_tokens(io.StringIO(src).readline):
                if tok.type != tokenize.COMMENT:
                    continue
                if not (lo <= tok.start[0] <= hi):
                    continue
                low = tok.string.lower()
                if any(m.lower() in low for m in MOCK_MARKERS):
                    return True
        except Exception:
            return False
        return False

    # ---------- 出网目标的来源（taint analysis） ----------
    def egress_target_is_llm_controlled(self, fn: ast.AST, depth: int = 3) -> bool:
        """
        出网目标是不是 LLM 填的？

        只看**出网调用的目标位**（第 0 个实参），不看内容位 —— 这是关键区分：
          _send_task(url, instr)  → url 是目标，instr 是内容
          _resolve_endpoint(addr) → addr 是目标
        内容由 LLM 决定 → 是"往合法目的地发脏数据"（Lethal Trifecta ③）
        目标由 LLM 决定 → 是 SSRF / 数据外泄通道（更严重）

        做法：从工具参数出发做污点传播，跨 helper 传递。
        """
        params = {a.arg for a in list(fn.args.posonlyargs) + list(fn.args.args)
                  + list(fn.args.kwonlyargs)}
        return self._taint_reaches_egress(fn, set(params), depth)

    def _taint_reaches_egress(self, fn: ast.AST, tainted: set[str], depth: int) -> bool:
        if depth <= 0:
            return False

        # --- 局部赋值传播：x = f(污点) → x 污 ---
        for _ in range(6):
            changed = False
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign):
                    if self._expr_tainted(node.value, tainted):
                        for tgt in node.targets:
                            if isinstance(tgt, ast.Name) and tgt.id not in tainted:
                                tainted.add(tgt.id)
                                changed = True
            if not changed:
                break

        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            fname, target = self._egress_target_of(node)

            # --- 出网调用：目标位有污点 → LLM 决定出网目标 ---
            if target is not None and self._expr_tainted(target, tainted):
                return True

            # --- 跨 helper 传播污点 ---
            helper, hargs = self._resolve_called_helper(node)
            if helper is None:
                continue
            hparams = [a.arg for a in list(helper.args.posonlyargs) + list(helper.args.args)]
            htaint = set()
            for i, arg in enumerate(hargs):
                if i < len(hparams) and self._expr_tainted(arg, tainted):
                    htaint.add(hparams[i])
            for kw in node.keywords:
                if kw.arg in hparams and self._expr_tainted(kw.value, tainted):
                    htaint.add(kw.arg)
            if htaint and self._taint_reaches_egress(helper, htaint, depth - 1):
                return True
        return False

    def _resolve_called_helper(self, node: ast.Call):
        """
        找出这次调用实际落到哪个 helper，以及实参怎么对应它的形参。

        两种形态都要处理：
          直接调用   helper(a, b)                → hargs = [a, b]
          函数当参数传 executor.submit(fn, a, b) → hargs = [a, b]（fn 在 args[0]）
        """
        f = node.func
        if isinstance(f, ast.Name):
            h = self.global_helpers.get(f.id)
            if h is not None:
                return h, list(node.args)
        if isinstance(f, ast.Attribute) and node.args and isinstance(node.args[0], ast.Name):
            h = self.global_helpers.get(node.args[0].id)
            if h is not None:
                return h, list(node.args[1:])
        return None, []

    def _egress_target_of(self, call: ast.Call):
        """
        返回 (函数名, 目标实参)。不是出网调用则返回 (None, None)。

        ★ 只认真正的出网：
          - EGRESS_HELPERS 里的 helper（第 0 个实参是 URL/地址）
          - HTTP_METHODS **且** 接收者是 http 客户端（排除 dict.get 这种同名方法）
        """
        f = call.func
        if isinstance(f, ast.Name):
            if f.id in EGRESS_HELPERS:
                return f.id, (call.args[0] if call.args else None)
            if f.id == "urlopen":
                return f.id, (call.args[0] if call.args else None)
            return None, None
        if isinstance(f, ast.Attribute):
            base = f.value
            base_name = (base.id if isinstance(base, ast.Name)
                         else base.attr if isinstance(base, ast.Attribute) else None)
            if f.attr in HTTP_METHODS and base_name and (
                    base_name.lower() in HTTP_CLIENT_NAMES
                    or base_name.lower().endswith(("client", "session"))):
                return f.attr, (call.args[0] if call.args else None)
        return None, None

    @staticmethod
    def _expr_tainted(node: ast.AST, tainted: set[str]) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in tainted:
                return True
        return False

    def ui_actions_of(self, fn: ast.AST, depth: int = 2, _seen=None) -> tuple[str, ...]:
        """该工具会派发哪些**前端动作名**（去重、保序）。

        动作名是**有限可枚举**的（见 specs/tool_capabilities.py 的 UI_ACTION_RISK），
        这正是它比"写库/出网"好判定的地方 —— 协议说清楚了有哪些动作，
        我们只需要回答"这个工具会发哪几个"。
        """
        if _seen is None:
            _seen = set()
        if id(fn) in _seen or depth <= 0:
            return ()
        _seen.add(id(fn))

        acts: list[str] = []
        for node in ast.walk(fn):
            # 写法一：_act(component, "actionName", {...})
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == UI_ACTION_HELPER):
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) \
                        and isinstance(node.args[1].value, str):
                    name = node.args[1].value
                    if name not in acts:
                        acts.append(name)
                continue
            # 写法二：{"component": ..., "action": "actionName", "params": {...}}
            #         —— 同一套协议，两种写法都必须认
            #
            # ⚠️ 必须**同时**有 "component" 和 "action" 两个键才算前端动作。
            #    只看 "action" 会误报 —— `detect_health_alerts` 返回的告警列表里
            #    每条都有 {"action": "建议立即就医"}，那是**数据字段**（建议怎么做），
            #    不是前端动作。前端动作一定有 component（要发给哪个组件）。
            if isinstance(node, ast.Dict):
                keys = {k.value for k in node.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)}
                if not {"component", "action"} <= keys:
                    continue
                for k, v in zip(node.keys, node.values):
                    if (isinstance(k, ast.Constant) and k.value == "action"
                            and isinstance(v, ast.Constant)
                            and isinstance(v.value, str)):
                        if v.value not in acts:
                            acts.append(v.value)
        if acts:
            return tuple(acts)

        # 本函数没直接发动作 → 跟进 helper
        for node in ast.walk(fn):
            if isinstance(node, ast.Name):
                helper = self.global_helpers.get(node.id)
                if helper is not None and id(helper) not in _seen:
                    acts.extend(self.ui_actions_of(helper, depth - 1, _seen))
        return tuple(dict.fromkeys(acts))

    # ---------- AG-UI：LLM 内容是否进入前端 ----------
    def ui_content_from_llm(self, fn: ast.AST) -> bool:
        """
        工具会不会把 **LLM 填的内容**送进前端？

        AG-UI 的动作 payload 形如
            {"component": "healthRecords", "action": "setSearch", "params": {"q": ...}}
        前端拿到就照着执行 —— params 里是什么字符串，
        屏幕 / 搜索框 / 对话框里就出现什么字符串。

        三种后果，严重性递增：
            setSearch({"q": <LLM>})     → 搜索框被改成模型写的字符串
            showAlert({"message": <LLM>}) → 任意文本弹到用户眼前（钓鱼文本）
            askAgent({"question": <LLM>}) → **前端替模型去问另一个 agent**

        第三种最重：它把"模型 → 前端 → agent"变成了模型自己的一条出网/委托通道，
        而这条通道**绕过了工具层的一切判定** —— 前端根本不知道自己在替谁问。

        做法：工具参数做污点源 → 局部赋值传播 → 看 `_act(...)` 的 params 字典。
        """
        params = {a.arg for a in list(fn.args.posonlyargs) + list(fn.args.args)
                  + list(fn.args.kwonlyargs)}
        tainted = set(params)

        # 局部赋值传播（`text = (message or "").strip()` 这类）
        for _ in range(3):
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign):
                    names = {t.id for t in node.targets if isinstance(t, ast.Name)}
                    if names and self._expr_tainted(node.value, tainted):
                        tainted |= names
                elif (isinstance(node, ast.AnnAssign)
                      and isinstance(node.target, ast.Name) and node.value is not None):
                    if self._expr_tainted(node.value, tainted):
                        tainted.add(node.target.id)

        for node in ast.walk(fn):
            # 写法一：_act(component, "actionName", {"k": <LLM>})
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == UI_ACTION_HELPER):
                if len(node.args) < 3:
                    continue
                d = node.args[2]
                if isinstance(d, ast.Dict):
                    for v in d.values:
                        if self._expr_tainted(v, tainted):
                            return True
                continue
            # 写法二：{"action": "...", "params": {"k": <LLM>}}
            if isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant) and k.value == "params" \
                            and isinstance(v, ast.Dict):
                        for pv in v.values:
                            if self._expr_tainted(pv, tainted):
                                return True
        return False


# ============================================================
# 3. 从真实源码里抽 dangerous_tools 的硬编码兜底表
#    （它没有导出，只能 AST 取 —— 不手抄，避免抄错）
# ============================================================
def extract_fallback_tables(dangerous_tools_path: Path) -> dict[str, list[str]]:
    """把 get_interrupt_config 里 `return {...}` 的字面量抽出来。"""
    try:
        tree = ast.parse(dangerous_tools_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        # if agent_name == "xxx": return {...}
        cmp = node.test
        if not (isinstance(cmp.left, ast.Name) and cmp.left.id == "agent_name"):
            continue
        if not (isinstance(cmp.comparators[0], ast.Constant)
                and isinstance(cmp.comparators[0].value, str)):
            continue
        agent = cmp.comparators[0].value
        for sub in node.body:
            if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Dict):
                keys = [k.value for k in sub.value.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)]
                out[agent] = keys
    return out


# ============================================================
# 4. 主流程
# ============================================================
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=os.environ.get("PHA_REPO", str(DEFAULT_REPO)))
    args = ap.parse_args()
    repo = Path(args.repo).resolve()
    if not (repo / "backend").exists():
        print(f"[!] {repo} 不是靶场仓库（缺 backend/）")
        return 2

    print("=" * 106)
    print(f"靶场：{repo}")
    print("=" * 106)

    sys.path.insert(0, str(repo / "backend" / "A2AServer" / "src"))
    sys.path.insert(0, str(repo / "backend"))
    from A2AServer.v2 import dangerous_tools, tool_permissions  # noqa: E402
    try:
        from A2AServer.v2 import write_audit  # noqa: E402
    except Exception as e:
        print(f"[warn] write_audit 导入失败: {e}")
        write_audit = None
    write_audit_patterns = tuple(write_audit._DANGEROUS_PATTERNS) if write_audit else ()

    # ---------- 4.1 枚举 ----------
    phacore_dir = repo / "backend" / "PhaCore" / "mcpserver"
    phacore_files = sorted(phacore_dir.glob("shared_*.py")) if phacore_dir.exists() else []
    agent_files = {}
    for agent in AGENTS:
        d = repo / "backend" / AGENT_DIR_MAP[agent] / "mcpserver"
        agent_files[agent] = sorted(d.glob("*_tool.py")) if d.exists() else []

    all_files = list({f for fs in agent_files.values() for f in fs} | set(phacore_files))
    scanner = EffectScanner(all_files)

    agent_tools = {a: [t for f in agent_files[a] for t in scanner.parsed[f]["tools"]]
                   for a in AGENTS}
    phacore_tools = [t for f in phacore_files for t in scanner.parsed[f]["tools"]]

    print("\n【1】工具全景")
    print("-" * 106)
    total = 0
    for agent in AGENTS:
        names = [t["name"] for t in agent_tools[agent]]
        total += len(names)
        print(f"  {agent:<22}{len(names):>3} 个   {', '.join(names)}")
    print(f"  {'PhaCore(共享)':<22}{len(phacore_tools):>3} 个   "
          f"{', '.join(t['name'] for t in phacore_tools)}")
    print(f"  {'合计':<22}{total + len(phacore_tools):>3} 个")

    # ---------- 4.2 三套判定 ----------
    print("\n【2】三套「这工具危险吗」判定 —— 三张表互相不一致")
    print("-" * 106)
    print("  ① dangerous_tools.is_dangerous       → 真正接进 v2 LangGraph 运行时（v2_runtime.py:313）")
    print("  ② write_audit._DANGEROUS_PATTERNS    → 只在 skills/registry.py:221 被调，registry 没接进 v2 MCP 链（F-007）")
    print("  ③ tool_permissions.WRITE_OP_PREFIXES → 只在 skills/registry.py:218 被调，同样没接进 v2 MCP 链")
    print()

    all_names = sorted({t["name"] for t in phacore_tools} |
                        {t["name"] for a in AGENTS for t in agent_tools[a]})
    dis = []
    for n in all_names:
        p1 = dangerous_tools.is_dangerous(n)
        p2 = any(p in n.lower() for p in write_audit_patterns)
        p3 = tool_permissions.check_write_operation(n)
        if len({p1, p2, p3}) > 1:
            dis.append((n, p1, p2, p3))
    print(f"  结论不一致：{len(dis)} / {len(all_names)} 个工具")
    print(f"  {'工具名':<36}{'①HITL':<9}{'②审计':<9}{'③RBAC写':<9}")
    for n, p1, p2, p3 in dis:
        print(f"  {n:<36}{'✔' if p1 else '✘':<9}{'✔' if p2 else '✘':<9}{'✔' if p3 else '✘':<9}")

    # ---------- 4.3 逐 agent ----------
    print("\n【3】副作用（AST 结构性事实） × HITL 实际覆盖")
    print("-" * 106)
    print("  DB_WRITE=写数据  DB_DDL=改表结构  EGRESS=出网  AGENT_EGRESS=调别的agent")
    print("  FILE_WRITE=写文件  MEMORY_WRITE=写记忆  MOCK=当前是假实现")
    print("  LLM_TARGET=出网目标由 LLM 填的参数决定（SSRF / 外泄通道）")
    print()

    HARD = {"DB_WRITE", "EGRESS", "AGENT_EGRESS", "FILE_WRITE", "MEMORY_WRITE"}
    live_missing, llm_egress, latent = [], [], []

    for agent in AGENTS:
        names = [t["name"] for t in agent_tools[agent]]
        cfg = dangerous_tools.get_interrupt_config(agent, available_tools=names)
        print(f"  ── {agent} ── HITL 实拦 {len(cfg)} 个：{sorted(cfg) or '（无）'}")

        rows = [(t, agent) for t in agent_tools[agent]] + [(t, agent) for t in phacore_tools]
        for t, owner in rows:
            eff = scanner.effects_of(t["node"])
            mock = scanner.is_mock(t["node"])
            llm_target = scanner.egress_target_is_llm_controlled(t["node"])
            if llm_target:
                eff.add("LLM_TARGET")
            if mock and (eff & HARD):
                eff -= HARD
                eff.add("MOCK")
            hit = t["name"] in cfg
            hard = eff & HARD

            if hard and not hit:
                live_missing.append((owner, t["name"], sorted(eff), t))
                if "LLM_TARGET" in eff:
                    llm_egress.append((owner, t["name"], sorted(eff), t))
            if mock and not hit:
                latent.append((owner, t["name"], t))

            tags = ",".join(sorted(eff)) or "read-only"
            rel = t["file"].relative_to(repo)
            print(f"     {'HITL✔' if hit else 'HITL✘'} {t['name']:<36} {tags:<48} {rel.name}:{t['node'].lineno}")
        print()

    # ---------- 4.4 漏项 ----------
    print("\n【4】★ 漏项 A：现在就能被打（有真副作用，HITL 不拦）")
    print("-" * 106)
    for owner, n, eff, t in live_missing:
        rel = t["file"].relative_to(repo)
        print(f"  [{owner}] {n:<32} {','.join(eff):<26} {rel}:{t['node'].lineno}")
    print(f"  合计 {len(live_missing)}")

    print("\n【5】★ 漏项 B：出网目标由 LLM 决定（SSRF / 数据外泄通道）")
    print("-" * 106)
    for owner, n, eff, t in llm_egress:
        rel = t["file"].relative_to(repo)
        print(f"  [{owner}] {n:<32} {','.join(eff):<26} {rel}:{t['node'].lineno}")
    if llm_egress:
        print("  ↑ 最危险的一类：名字是 get_ 语义，任何基于名字的清单都不会怀疑它，")
        print("    而它能把请求发到攻击者指定的 host:port。")

    fb = extract_fallback_tables(
        repo / "backend" / "A2AServer" / "src" / "A2AServer" / "v2" / "dangerous_tools.py")
    fallback_all = {n for lst in fb.values() for n in lst}

    print("\n【6】★ 漏项 C：清单声明它危险、实际没拦，而且实现是 mock（今天还不是洞）")
    print("-" * 106)
    declared_any = set()
    for n in all_names:
        if (dangerous_tools.is_dangerous(n)
                or any(p in n.lower() for p in write_audit_patterns)
                or tool_permissions.check_write_operation(n)):
            declared_any.add(n)
    for owner, n, t in latent:
        if n not in declared_any and n not in fallback_all:
            continue
        rel = t["file"].relative_to(repo)
        print(f"  [{owner}] {n:<32} 实现=模拟{' ' * 10}{rel}:{t['node'].lineno}")
    print("  ↑ 今天不是洞。但它证明门禁的判定对象是**名字**不是**行为**：")
    print("    谁把 mock 换成真实现，名字不变，门禁结论也不变 —— 于是它静默失效。")

    # ---------- 4.5 清单 vs 实现 ----------
    print("\n【7】★ 清单声明危险、实际却没拦 —— 全量对账")
    print("-" * 106)
    declared = {}
    for agent, cfg in ((a, dangerous_tools.get_interrupt_config(
            a, available_tools=[t["name"] for t in agent_tools[a]])) for a in AGENTS):
        declared[agent] = set(cfg)

    unblocked = []
    for agent in AGENTS:
        cfg = declared[agent]
        for t in agent_tools[agent]:
            n = t["name"]
            p1 = dangerous_tools.is_dangerous(n)
            p2 = any(p in n.lower() for p in write_audit_patterns)
            p3 = tool_permissions.check_write_operation(n)
            in_fb = n in fallback_all
            if (p1 or p2 or p3 or in_fb) and n not in cfg:
                unblocked.append((agent, n, p1, p2, p3, in_fb))
    print(f"  {'工具':<32}{'agent':<22}{'①':<5}{'②':<5}{'③':<5}{'兜底表':<8}")
    for agent, n, p1, p2, p3, in_fb in unblocked:
        print(f"  {n:<32}{agent:<22}{'✔' if p1 else '✘':<5}{'✔' if p2 else '✘':<5}"
              f"{'✔' if p3 else '✘':<5}{'✔' if in_fb else '✘':<8}")
    print(f"  合计 {len(unblocked)} —— 每一行都是「有人认为它危险，但没人在它面前拦一下」。")

    # ---------- 4.6 特例 ----------
    print("\n【8】★ 特例：manifest 分支会**吞掉**硬编码兜底表")
    print("-" * 106)
    mr = [t["name"] for t in agent_tools["medication_reminder"]]
    mr_cfg = dangerous_tools.get_interrupt_config("medication_reminder", available_tools=mr)
    print(f"  medication_reminder 在 manifest 里 dangerously=true → 走 is_dangerous 自动匹配")
    print(f"  自动匹配：{sorted(mr_cfg)}")
    for t in ("log_medication_taken", "set_notification_preferences"):
        print(f"    {t:<32} 自动匹配命中={str(t in mr_cfg):<6} 兜底表里有={str(t in fb.get('medication_reminder', [])):<6} "
              f"→ 实际是否被拦：{'是' if t in mr_cfg else '否 ← 漏'}")
    print("  原因：get_interrupt_config 里 `if cfg: return cfg` —— 只要自动匹配出任何一个，")
    print("        硬编码兜底表就再也走不到。")

    return 0


if __name__ == "__main__":
    sys.exit(main())
