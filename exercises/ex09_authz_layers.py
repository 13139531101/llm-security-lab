#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ex09 · 工具调用安全的三层授权模型：覆盖率盘点

M3 的动手任务 1。回答一个问题：
    **靶场的 67 个 MCP 工具里，有几个真的做到了「资源级」授权？**

三层模型（本脚本的分类轴）：
    工具级  L1 —— 这个工具**归谁**、能不能被这个 agent 调
    资源级  L2 —— 这个工具操作的那**一条具体数据**归不归你
    用户级  L3 —— tool call 里带的 user_id 是不是**这个用户**的

⚠️ 本脚本只做 **L2** 的盘点（L1/L3 只做标注），因为 L2 才是这个系统最薄的一层。

────────────────────────────────────────────────────────────────────────
设计原则（也是 M3 最重要的一课）：
    **机器只能给出「有证据 / 无证据」，给不出「有 / 没有」。**

所以输出分四档证据强度，绝不断言「某工具没有资源级校验」：

    E2  同函数体内，身份参数出现在数据访问调用的实参里   → 资源级**有证据**
    E3  身份参数传给了本地 helper，判定要看 helper 内部 → **需人工核**
    E1  有身份参数，但函数体内找不到它用在哪             → **无证据**（重点怀疑）
    E0  根本没有身份参数                                 → 资源级**做不了**

为什么必须这么保守 —— ex05 的教训：
    静态分析只扫一层函数，会把「真在写库」误判成只读
    （`upsert_medical_kb_document` 函数体里一句 SQL 都没有，真写在 helper 里）。
    所以本脚本对 E1/E3 **不下结论**，只列出来让人核。

用法：
    PYTHONIOENCODING=utf-8 python ex09_authz_layers.py
    PYTHONIOENCODING=utf-8 python ex09_authz_layers.py --repo I:\\A2A\\3\\A2AServer
    PYTHONIOENCODING=utf-8 python ex09_authz_layers.py --md > coverage.md

零外部依赖：只用标准库（ast / re / pathlib / argparse）。
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# ────────────────────────────────────────────────────────────── 常量与配置

DEFAULT_REPO = Path(os.environ.get("PHA_REPO", r"I:\A2A\3\A2AServer"))

#: 身份参数名 —— 不同 agent 的叫法不一样，都算
IDENT_NAMES = {"user_id", "uid", "patient_id", "userid", "user_name"}

#: 疑似「数据访问」调用的标志 —— 命中就算一次访问
#:
#: ⚠️ 这里**必须用子串匹配，不能用 \b 词边界**：
#:    `\bexecute\b` 匹配不上 `execute_query`（下划线不是词边界），
#:    `\bquery\b` 也匹配不上 `execute_query`。
#:    靶场里所有 DB 访问都是 `storage.db_manager.execute_query(...)`，
#:    用词边界会让**每一个**数据访问都被漏掉 —— 27 个有资源级的工具全变 E1。
QUERYISH = re.compile(
    r"(execute|executemany|fetchall|fetchone|fetchmany|query|"
    r"filter_by|where|select|find_by)",
    re.IGNORECASE,
)

#: SQL 里出现这些列名 ⇒ 这条查询是按身份限定的
IDENT_COLUMN = re.compile(r"\b(user_id|uid|patient_id)\b", re.IGNORECASE)

#: A2A 委托的客户端函数名 —— 身份从这里发出去就不是「本进程内的判定」了
A2A_NAMES = {"_send_task", "send_task", "send_a2a_task", "a2a_send_task",
              "_send_a2a_task", "delegate_task"}

#: MCP server 目录 → 归属 agent（工具级隔离的边界）
SERVER_DIRS = {
    "HealthAdvisor": "health_advisor",
    "HealthRecordsManager": "health_records_manager",
    "MedicationReminder": "medication_reminder",
    "VisitSummaryGenerator": "visit_summary_generator",
    "PhaCore": "pha_core",
}

#: 靶场里三套「这工具危险吗」的判定表（用来交叉对账）
DANGER_TABLES = [
    ("tool_permissions.WRITE_OP_PREFIXES", "backend/A2AServer/src/A2AServer/v2/tool_permissions.py"),
    ("dangerous_tools._DANGEROUS_KEYWORDS", "backend/A2AServer/src/A2AServer/v2/dangerous_tools.py"),
    ("write_audit._DANGEROUS_PATTERNS", "backend/A2AServer/src/A2AServer/v2/write_audit.py"),
]


# ────────────────────────────────────────────────────────────── AST 工具

def mentions_ident(node: ast.AST) -> bool:
    """子树里有没有出现身份参数名"""
    return bool(mentions_any(node, IDENT_NAMES))


def mentions_any(node: ast.AST, names: set[str]) -> bool:
    """子树里有没有出现给定的一组名字"""
    if not names:
        return False
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in names:
            return True
        if isinstance(sub, ast.arg) and sub.arg in names:
            return True
        if isinstance(sub, ast.keyword) and sub.arg in names:
            return True
    return False


def call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


# ────────────────────────────────────────── 条件式过滤（fail-open）识别

#: 「把过滤条件拼进查询」时常见的目标变量名
QUERY_VARS = ("where", "where_clause", "where_sql", "clauses", "conditions",
              "query", "sql", "params", "args", "values", "filters")


def branch_rejects(body: list[ast.stmt]) -> bool:
    """分支里有没有 raise / 早退 —— 表示「拒绝」，属于 fail-closed"""
    for n in body:
        for sub in ast.walk(n):
            if isinstance(sub, (ast.Raise, ast.Return)):
                return True
    return False


def branch_applies_filter(body: list[ast.stmt]) -> bool:
    """分支里有没有「把身份用进查询」的动作

    三种可观察形态：
      ① SQL 片段里出现身份列（`... AND user_id = %s`）
      ② 身份被塞进参数容器（`params.append(user_id)`）
      ③ 身份被赋给一个查询/条件变量（`where_sql = f"...{user_id}..."`）
    """
    for n in body:
        for sub in ast.walk(n):
            # ① SQL 字面量 / f-string 片段里有身份列
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                if IDENT_COLUMN.search(sub.value):
                    return True
            if isinstance(sub, ast.JoinedStr):
                if IDENT_COLUMN.search(ast.unparse(sub)):
                    return True
            # ② 参数容器追加
            if isinstance(sub, ast.Call) and call_name(sub) in (
                    "append", "extend", "insert", "add"):
                for a in list(sub.args) + [k.value for k in sub.keywords]:
                    if isinstance(a, ast.Name) and a.id in IDENT_NAMES:
                        return True
            # ③ 赋给查询/条件变量
            if isinstance(sub, ast.Assign):
                for t in sub.targets:
                    if isinstance(t, ast.Name) and t.id.lower() in QUERY_VARS:
                        rhs = ast.unparse(sub.value)
                        if IDENT_COLUMN.search(rhs) or any(
                                isinstance(a, ast.Name) and a.id in IDENT_NAMES
                                for a in ast.walk(sub.value)):
                            return True
    return False


def expand_sql(text: str, src_by_var: dict[str, str], depth: int = 3) -> str:
    """把 SQL 里引用到的局部变量的**源文本**也拼进来

    靶场里的 SQL 有两种写法：
      ① 直接 f-string 写死：f"... WHERE user_id = %s"
      ② **动态拼**：`f"... WHERE {' AND '.join(where)}"`，身份条件在 where 列表里

    只看最终 SQL 文本会把 ② 判成「SQL 里没有身份列」—— 假阴性。
    这是同一个坑的第四、五次出现：只扫表面形态。
    """
    out = text
    for _ in range(depth):
        new = out
        for var, src in src_by_var.items():
            if src in new:
                continue
            if re.search(rf"\b{re.escape(var)}\b", new):
                new += "\n" + src
        if new == out:
            break
        out = new
    return out


def detect_conditional_filter(fn: ast.FunctionDef) -> tuple[bool, str]:
    """识别 fail-open：身份**有条件**才参与过滤，且条件不成立时不拒绝

    返回 (是不是 fail-open, 证据描述)。

    判据（结构性，不是表面形态）：
      - 分支条件里出现身份名
      - 分支体在**改写查询**（不是拒绝）
      - 身份缺失的那一侧**没有拒绝**
    """
    for n in ast.walk(fn):
        if not isinstance(n, ast.If):
            continue
        if not mentions_ident(n.test):
            continue

        # `if not uid:` —— body 是「身份缺失」那一侧
        negated = (isinstance(n.test, ast.UnaryOp)
                   and isinstance(n.test.op, ast.Not))
        if negated:
            if branch_rejects(n.body):
                continue                    # 缺失即拒绝 → fail-closed
            if n.orelse and branch_applies_filter(n.orelse):
                return True, "身份缺失时不拒绝，过滤条件在 else 分支才加上"
            continue

        # `if uid:` —— body 是「身份存在」那一侧
        if branch_rejects(n.body):
            continue                        # 这不是「条件过滤」的形状
        if not branch_applies_filter(n.body):
            continue                        # 分支里没在改写查询
        if n.orelse and branch_rejects(n.orelse):
            continue                        # else 拒绝 → fail-closed
        return True, "身份为空时过滤条件整个消失 = 放行全量"
    return False, ""


def collect_local_helpers(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    """模块级函数表（用于一跳跟进）"""
    out: dict[str, ast.FunctionDef] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            out[node.name] = node
    return out


def registered_tools(tree: ast.Module) -> list[ast.FunctionDef]:
    """带 @mcp.tool() 装饰器的函数 —— 注意只认 `.tool` 属性，
    其它装饰器（@app.post 之类）不算。"""
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for d in node.decorator_list:
            f = d.func if isinstance(d, ast.Call) else d
            if isinstance(f, ast.Attribute) and f.attr == "tool":
                out.append(node)
                break
    return out


# ────────────────────────────────────────────────────────────── 单工具分析

class ToolRow:
    __slots__ = ("name", "rel", "server", "params", "level", "ident_in",
                 "ident_src", "helper_hints", "danger_tables", "writes", "note",
                 "conditional", "delegated")

    def __init__(self, name, rel, server, params):
        self.name = name
        self.rel = rel
        self.server = server
        self.params = params
        self.level = "?"
        self.ident_in = []
        self.ident_src = []
        self.helper_hints = []
        self.danger_tables = []
        self.writes = False
        self.note = ""
        self.conditional = False
        self.delegated = []


def analyze_tool(fn: ast.FunctionDef, rel: str, helpers: dict[str, ast.FunctionDef],
                 tool_names: set[str] | None = None) -> ToolRow:
    params = [a.arg for a in fn.args.args]
    server = ""
    for d in SERVER_DIRS:
        if f"/{d}/" in rel.replace("\\", "/"):
            server = d
            break
    row = ToolRow(fn.name, rel, server, params)

    body = ast.unparse(fn)
    row.ident_in = [p for p in params if p in IDENT_NAMES]

    # ── L3：身份从哪来（三个来源，靶场里三个都真实存在过）
    if row.ident_in:
        row.ident_src.append("tool参数")
    if re.search(r"os\.environ", body) and re.search(r"USER_ID|USER_UID|UID|USER_NAME", body):
        row.ident_src.append("os.environ")
    if re.search(r"contextvars|ContextVar", body):
        row.ident_src.append("ContextVar")
    if re.search(r"\bglobal\s+", body):
        row.ident_src.append("global")
    if not row.ident_src:
        row.ident_src.append("（无）")

    # ── 写操作迹象
    row.writes = bool(re.search(r"INSERT|UPDATE|DELETE|execute\(|save_|upsert|delete_", body, re.I))

    # ── L2 证据判定
    #
    # ⚠️ 第一版这里犯了 ex05 的同一个错：只认「身份名出现在调用实参里」。
    #    但真实写法是   params = (user_id, ...)  →  execute_query(query, params)
    #    —— 身份先落到中间变量，调用里已经看不见身份名了。
    #    那样会把 24 个真做了资源级的工具判成「无证据」（假阴性）。
    #
    #    所以这里做**函数内污点传播**：
    #      1) 身份参数名是污点源
    #      2) 右值含污点的赋值 → 左值也是污点（迭代到不动点）
    #      3) 数据访问调用的实参里出现污点 → 身份参与了这次访问
    #      4) 再看 SQL 文本里有没有身份列 → 区分「用于限定」和「只是参与」
    e2 = e2b = e3 = False
    helper_names: list[str] = []

    tainted: set[str] = set(row.ident_in)
    sql_by_var: dict[str, str] = {}
    src_by_var: dict[str, str] = {}

    # (2)+(3) 迭代到不动点（赋值和使用顺序无关紧要）
    for _ in range(4):
        for node in ast.walk(fn):
            # 普通赋值 `x = ...`
            if isinstance(node, ast.Assign):
                targets = {t.id for t in node.targets if isinstance(t, ast.Name)}
                rhs_txt = ast.unparse(node.value)
                for t in targets:
                    src_by_var[t] = rhs_txt
                if re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", rhs_txt, re.I):
                    for t in targets:
                        sql_by_var[t] = rhs_txt
                if mentions_any(node.value, tainted):
                    tainted |= targets
            # 带注解赋值 `params: List[Any] = []`
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                src_by_var[node.target.id] = ast.unparse(node.value)
                if mentions_any(node.value, tainted):
                    tainted.add(node.target.id)
            # 方法调用 `params.append(user_id)` → params 被污染
            elif isinstance(node, ast.Call) and call_name(node) in (
                "append", "extend", "insert", "add", "update", "setdefault"
            ):
                recv = node.func.value if isinstance(node.func, ast.Attribute) else None
                if isinstance(recv, ast.Name) and mentions_any(node, tainted):
                    tainted.add(recv.id)
            # `executor.submit(fn, user_id, ...)` —— 函数对象当实参传，
            # call_name 是 "submit"，光看调用名会漏掉这条「委托」边。
            # （这是 ex05/F-017 里点过名的形态：光扫一层会漏。）
            elif isinstance(node, ast.Call) and call_name(node) == "submit" and node.args:
                tgt = node.args[0]
                if (isinstance(tgt, ast.Name) and tgt.id in helpers
                        and mentions_any(node, tainted)):
                    e3 = True
                    if tgt.id not in helper_names:
                        helper_names.append(tgt.id)
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            cn = call_name(node)
            if cn in helpers and mentions_any(node, tainted):
                e3 = True
                if cn not in helper_names:
                    helper_names.append(cn)

    # (3) 数据访问调用：实参里有没有污点
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        txt = ast.unparse(node)
        if not QUERYISH.search(txt):
            continue
        arg_names: set[str] = set()
        for a in list(node.args) + [k.value for k in node.keywords]:
            if isinstance(a, ast.Name):
                arg_names.add(a.id)
            else:
                arg_names |= {n.id for n in ast.walk(a) if isinstance(n, ast.Name)}
        if not (arg_names & tainted):
            continue
        # 找到这次访问对应的 SQL 文本
        sql = ""
        for a in list(node.args) + [k.value for k in node.keywords]:
            if isinstance(a, ast.Name) and a.id in sql_by_var:
                sql = sql_by_var[a.id]
                break
        if not sql:
            sql = txt
        # 动态拼的 SQL：把参与拼接的局部变量的源文本也算进来
        sql = expand_sql(sql, src_by_var)
        if IDENT_COLUMN.search(sql):
            e2 = True
        else:
            e2b = True

    # 一跳跟进：身份传进了 helper，去 helper 里找数据访问
    if e3 and not e2:
        for hname in list(helper_names):
            h = helpers.get(hname)
            if h is None:
                continue
            h_tainted = set(tainted)
            for _ in range(3):
                for node in ast.walk(h):
                    if isinstance(node, ast.Assign):
                        targets = {t.id for t in node.targets if isinstance(t, ast.Name)}
                        if mentions_any(node.value, h_tainted):
                            h_tainted |= targets
            for node in ast.walk(h):
                if isinstance(node, ast.Call) and QUERYISH.search(ast.unparse(node)):
                    arg_names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
                    if arg_names & h_tainted:
                        e2 = True
                        row.note = f"（一跳到 helper `{hname}` 里找到访问）"
                        break
            if e2:
                break

    row.helper_hints = sorted(set(helper_names))

    # 委托 vs 本地 helper：
    #   委托 = 身份被**转述**给另一个注册工具，或走 A2A 发给另一个 agent
    #        —— 那边收到的 user_id 是**声明**的（asserted），不是验证过的
    #   本地 helper = 判定还在本进程内，只是换了个函数
    delegated = [h for h in helper_names
                 if (tool_names and h in tool_names) or h in A2A_NAMES]
    row.delegated = delegated

    # 条件式过滤：`if user_id:` 才把过滤条件拼进 SQL —— 这是 fail-open
    # （靶场实例：analyze_symptoms —— user_id 为空就不加过滤、返回全表 = F-009）
    #
    # ⚠️ 这里踩过一次坑：最初的判据是「函数体里任何提到身份名的 if」，
    #    结果把 `if not uid: raise RuntimeError("user_id不能为空")` 也算成了 fail-open ——
    #    那是**拒绝**（fail-closed），语义完全相反。
    #    所以判据必须区分：分支是在**改写查询**，还是在**拒绝**。
    cond, cond_evidence = detect_conditional_filter(fn)
    row.conditional = cond
    if cond:
        row.note = cond_evidence

    # 判定档位
    other_sources = set(row.ident_src) - {"tool参数", "（无）"}
    if not row.ident_in:
        # 没有身份参数 —— 看看是不是从 env / ContextVar / global 拿的
        row.level = "E0b" if other_sources else "E0"
    elif e2:
        row.level = "E2c" if cond else "E2"
    elif e2b:
        row.level = "E2b"
    elif e3 and row.delegated:
        row.level = "E4"
    elif e3:
        row.level = "E3"
    else:
        row.level = "E1"

    return row


# ────────────────────────────────────────────────────────────── 全仓扫描

def scan(repo: Path) -> tuple[list[ToolRow], dict[str, list[str]]]:
    rows: list[ToolRow] = []
    danger_hits: dict[str, list[str]] = defaultdict(list)

    # 先把三套「危险判定表」的关键词抽出来，用于交叉对账
    keyword_sets: dict[str, set[str]] = {}
    for label, relpath in DANGER_TABLES:
        p = repo / relpath
        if not p.exists():
            continue
        txt = p.read_text(encoding="utf-8", errors="replace")
        kw = set()
        for m in re.finditer(r"^\s*[\"']([a-z_]+)[\"']", txt, re.M):
            kw.add(m.group(1))
        for m in re.finditer(r"[\"']([a-z_]+)[\"']\s*,\s*[\"']([a-z_]+)[\"']", txt):
            kw.add(m.group(1))
            kw.add(m.group(2))
        keyword_sets[label] = kw

    for p in sorted(repo.rglob("*.py")):
        rel = str(p.relative_to(repo)).replace("\\", "/")
        if "/.venv/" in rel or "/node_modules/" in rel:
            continue
        if "mcpserver" not in rel and "mcp" not in p.name.lower():
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        helpers = collect_local_helpers(tree)
        tool_names = {f.name for f in registered_tools(tree)}
        for fn in registered_tools(tree):
            row = analyze_tool(fn, rel, helpers, tool_names)
            for label, kw in keyword_sets.items():
                if any(k in row.name for k in kw if len(k) > 3):
                    row.danger_tables.append(label)
            rows.append(row)

    return rows, keyword_sets


# ────────────────────────────────────────────────────────────── 输出

LEVEL_DESC = {
    "E2": "身份**无条件**进了数据访问的 SQL 条件 —— 资源级**有证据**",
    "E2c": "身份**有条件**才进 SQL（`if user_id:` 才加过滤）—— ⚠️ **fail-open**，比 E1 更危险",
    "E2b": "身份进了数据访问，但 SQL 里没有身份列 —— **需人工核**",
    "E4": "身份**委托**给别的工具 / 跨 agent —— 判定在那边，那边收到的是**声明**的身份",
    "E3": "身份传给了本地 helper —— 判定在 helper 里，**需人工核**",
    "E1": "有身份参数，但函数体内看不出它用在哪 —— **无证据**（重点怀疑）",
    "E0b": "无身份参数，但身份来自 env/ContextVar/global —— **需人工核**",
    "E0": "函数体内没有任何身份来源 —— 资源级在这层**做不了**",
}

#: 报告里的分组顺序（从「最确定没问题」到「最该立刻看」）
TIER_ORDER = ("E2", "E2b", "E4", "E3", "E1", "E2c", "E0b", "E0")

#: 明细段的列出顺序 —— 把「有 fail-open 证据」的放最前面，因为它比 E1 更危险
DETAIL_ORDER = ("E2c", "E4", "E2", "E2b", "E3", "E1", "E0b", "E0")

#: ────────────────────────────────────────────────────────────── 手核结论
#:
#: 机器判据只能给「**有证据 / 无证据**」，给不出「**有 / 没有**」。
#: 「有 / 没有」只能靠人把代码读一遍。所以这里把人工裁决单列一张表，
#: 和机器判的结果并排打印 —— **两边对不上，就是脚本错了**（而不是代码错了）。
#:
#: 这张表也是这个脚本的回归基线：改了判据就跑一遍，对账有差就说明判据退化了。
#:
#: 格式：工具名 → (人工裁决的档位, 裁决理由)
#:
#: ⚠️ 第一版手核把 `check_drug_interaction` 判成 E4（因为它经 `_send_task` 委托），
#:    机器判 E2（因为本地 `_get_active_medication_names(uid)` 有资源级证据）——
#:    对不上。查了代码才发现：**两件事都成立**，是手核在硬套一个单标签。
#:    于是定下这条规矩：**档位 = 资源级判定在哪**（单值），
#:    「有没有委托出去」是**另一个正交标记**（`row.delegated`），不占档位。
HAND_VERIFIED: dict[str, tuple[str, str]] = {
    # ── fail-open（条件过滤）
    "analyze_symptoms": (
        "E2c",
        "`if user_id:` 才把 `AND user_id = %s` 拼进 where —— 身份为空就返回全表。F-009。"),
    # ── 看着像 fail-open、其实是 fail-closed（缺身份即拒绝）
    "get_consultation_history": (
        "E2", "`if not uid: raise RuntimeError` —— 缺身份即拒绝，不是条件过滤。"),
    "save_consultation": (
        "E2", "`if not uid: raise RuntimeError` —— 同上。"),
    # ── 动态拼 SQL（身份条件在列表里，不在最终 SQL 文本里）
    "get_health_reminders": (
        "E2", "`conditions = [\"user_id = %s\", ...]` 无条件；SQL 是 join 出来的。"),
    "get_medications": (
        "E2", "`where = [\"user_id = %s\"]` 无条件；前面的 information_schema 探测是干扰项。"),
    "open_health_record": (
        "E2", "`where: List[str] = [\"user_id = %s\"]` 无条件；`if not uid: return` 拒绝。"),
    # ── 委托（判定在别处）
    "aggregate_health_report": (
        "E4", "身份转给 3 个注册工具（executor.submit），再经 A2A 到别的 agent。"),
    "generate_consultation_summary": (
        "E4", "身份转给 aggregate_health_report，再往下委托。"),
    "get_health_records_history": (
        "E4", "`_send_task(endpoint, instr, user_id=user_id)` —— 跨 agent 传的是**声明**的身份。"),
    "check_drug_interaction": (
        "E2",
        "本地 `_get_active_medication_names(uid)` 有资源级证据；**同时**又经 `_send_task` "
        "把身份委托出去 —— 两件事都成立。档位只记「判定在哪」，委托是另一个正交标记。"),
    # ── 本地 helper
    "draft_health_record": (
        "E3", "`_resolve_user_id(user_id)` —— 判定在 helper 里（helper 自己会退到 env）。"),
    # ── 无证据（人工读完确认：本层确实没有资源级判定）
    "send_medication_notification": (
        "E1", "无数据访问；user_id 只当载荷盖个章（stub），不构成越权读。"),
    "send_appointment_notification": (
        "E1", "同上。"),
    "set_notification_preferences": (
        "E1", "user_id 压根没用；偏好根本没落库（stub）。"),
}


def print_report(rows: list[ToolRow]) -> None:
    total = len(rows)
    c = Counter(r.level for r in rows)

    print("=" * 78)
    print(f"三层授权模型盘点 · L2 资源级覆盖率")
    print("=" * 78)
    print(f"注册工具总数（@mcp.tool()）：{total}\n")

    print("── 证据分布 " + "─" * 60)
    for lvl in TIER_ORDER:
        n = c.get(lvl, 0)
        pct = n * 100 // total if total else 0
        print(f"  {lvl:4s} {n:3d} 个 ({pct:2d}%)  {LEVEL_DESC[lvl]}")

    prov = c.get("E2", 0)
    failopen = c.get("E2c", 0)
    undecidable = (c.get("E2b", 0) + c.get("E4", 0) + c.get("E3", 0)
                    + c.get("E1", 0) + c.get("E0b", 0))
    impossible = c.get("E0", 0)
    print()
    print(f"  ⇒ 资源级**有证据**：{prov}/{total}")
    print(f"  ⇒ 资源级**判不了**（需人工核）：{undecidable}/{total}")
    print(f"  ⇒ 资源级**做不了**（无任何身份来源）：{impossible}/{total}")
    print(f"  ⇒ ⚠️ 资源级**有 fail-open 证据**（条件过滤）：{failopen}/{total}")
    print(f"  ⇒ ⚠️ 资源级**判定在别处**（委托）：{c.get('E4', 0)}/{total}")
    print()
    print("  ⚠️ 注意分母的意义：「有证据的占比」不是「安全率」。")
    print("     E3/E1 里混着能做资源级但本脚本没扫到的 ——")
    print("     所以这里报的是**下界**，不是结论。")
    print("  ⚠️ E2c（条件过滤）**不能**计入「有证据」：")
    print("     身份为空时过滤条件整个消失 = 放行全量数据。")

    # ── 分组列出
    for lvl in DETAIL_ORDER:
        sel = [r for r in rows if r.level == lvl]
        if not sel:
            continue
        print()
        print(f"── {lvl} · {LEVEL_DESC[lvl]} " + "─" * 40)
        for r in sorted(sel, key=lambda x: (x.server, x.name)):
            extra = ""
            if r.delegated:
                extra = f"  委托={','.join(r.delegated[:2])}"
            elif r.helper_hints:
                extra = f"  helper={','.join(r.helper_hints[:2])}"
            elif r.note:
                extra = f"  {r.note}"
            print(f"  {r.name:40s} {r.server:22s} 身份={','.join(r.ident_src):18s}{extra}")

    # ── 身份来源分布（L3）
    print()
    print("── L3 · 身份来源分布（tool 参数 / env / ContextVar / global） " + "─" * 12)
    src_c = Counter()
    for r in rows:
        src_c[",".join(r.ident_src)] += 1
    for k, n in src_c.most_common():
        print(f"  {n:3d} 个  {k}")

    # L3 的关键问题不是「身份从哪来」，是「这个来源**可不可信**」。
    # tool 参数 = 模型填的 = **声明**（asserted），不是验证过的。
    asserted = sum(1 for r in rows if "tool参数" in r.ident_src)
    trusted = sum(1 for r in rows
                  if set(r.ident_src) - {"tool参数", "（无）"})
    print()
    print(f"  ⇒ 身份来自**模型填的 tool 参数**：{asserted} 个")
    print(f"  ⇒ 身份来自 env/ContextVar/global 等进程侧：{trusted} 个")
    print()
    print("  ⚠️ L3 的关键不是「身份从哪来」，是「这个来源**可不可信**」。")
    print("     tool 参数是模型填的 = **声明**（asserted），不是验证过的（verified）。")
    print("     靶场里 49 个工具的身份全部来自这一路 —— ")
    print("     意味着 L2 做的资源级限定，**限的是一个未经核实的身份**。")

    # ── 工具级隔离边界（L1）
    print()
    print("── L1 · 工具级隔离边界（按 MCP server 归属） " + "─" * 30)
    srv = Counter(r.server or "(未识别)" for r in rows)
    for k, n in srv.most_common():
        print(f"  {n:3d} 个  {k}")

    # ── 三套危险判定表的对账
    print()
    print("── 交叉对账 · 三套「危险判定表」覆盖了哪些工具 " + "─" * 20)
    tbl_c = Counter()
    for r in rows:
        key = ",".join(r.danger_tables) if r.danger_tables else "（一套都没命中）"
        tbl_c[key] += 1
    for k, n in tbl_c.most_common():
        print(f"  {n:3d} 个  {k}")

    # ── 交叉表
    print()
    print("── L2 × 写操作 " + "─" * 56)
    x = Counter((r.level, "写" if r.writes else "只读") for r in rows)
    print(f"  {'':6s}{'只读':>8s}{'写':>8s}")
    for lvl in TIER_ORDER:
        ro = x.get((lvl, "只读"), 0)
        rw = x.get((lvl, "写"), 0)
        print(f"  {lvl:6s}{ro:8d}{rw:8d}")
    print()
    print("  ⇒ 「写 + 无证据」那一格，是最该先看的地方：")
    print("     写入操作如果没有资源级约束 = 跨用户写。")

    # ── 机器判 vs 人判 对账
    print()
    print("── 对账 · 机器判档 vs 人工裁决 " + "─" * 40)
    by_name = {r.name: r for r in rows}
    agree = disagree = missing = 0
    for name, (verdict, why) in HAND_VERIFIED.items():
        r = by_name.get(name)
        if r is None:
            print(f"  ✘ {name:40s} 脚本没扫到这个工具 —— 靶场结构变了？")
            missing += 1
            continue
        ok = (r.level == verdict)
        mark = "✓" if ok else "✘"
        if ok:
            agree += 1
        else:
            disagree += 1
        shown = r.level if ok else f"{r.level}（人判 {verdict}）"
        print(f"  {mark} {name:40s} {shown:22s} {why}")
    print()
    print(f"  ⇒ 对上 {agree} 个，对不上 {disagree} 个，脚本没扫到 {missing} 个")
    if disagree:
        print("  ⚠️ 对不上 = **脚本的判据退化了**（不是代码变安全了）。")
        print("     机器判据只能给「有证据 / 无证据」；「有 / 没有」靠人读代码。")
        print("     这次跑出来的数字只能当**线索**，不能当结论。")


def print_md(rows: list[ToolRow]) -> None:
    total = len(rows)
    c = Counter(r.level for r in rows)
    print("| 证据档 | 工具数 | 占比 | 含义 |")
    print("|---|---|---|---|")
    for lvl in TIER_ORDER:
        n = c.get(lvl, 0)
        pct = f"{n * 100 // total}%" if total else "—"
        desc = LEVEL_DESC[lvl].replace("**", "")
        print(f"| {lvl} | {n} | {pct} | {desc} |")
    print()
    print(f"注册工具总数 **{total}**；资源级**有证据** {c.get('E2', 0)} 个；"
          f"**有 fail-open 证据** {c.get('E2c', 0)} 个。")
    print()
    print("| 工具 | 归属 server | 身份来源 | 证据档 |")
    print("|---|---|---|---|")
    for r in sorted(rows, key=lambda x: (x.level, x.name)):
        print(f"| `{r.name}` | {r.server or '—'} | {', '.join(r.ident_src)} | {r.level} |")


def main() -> int:
    ap = argparse.ArgumentParser(description="M3 · 三层授权模型覆盖率盘点")
    ap.add_argument("--repo", default=str(DEFAULT_REPO), help="靶场仓库路径")
    ap.add_argument("--md", action="store_true", help="输出 Markdown 表格")
    args = ap.parse_args()

    repo = Path(args.repo)
    if not repo.exists():
        print(f"靶场不存在：{repo}", file=sys.stderr)
        print("用 --repo 指定，或设环境变量 PHA_REPO", file=sys.stderr)
        return 2

    rows, _ = scan(repo)
    if not rows:
        print("没扫到任何 @mcp.tool() —— 靶场结构变了？", file=sys.stderr)
        return 2

    if args.md:
        print_md(rows)
    else:
        print_report(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
