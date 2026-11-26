#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ex10 · 间隔复习 —— 把「能答出来」变成「过一阵还记得」

解决的是什么问题
----------------
概念题会答，但过一阵就忘。原因是三件事叠在一起：

1. 做的是**再认**（看到题想起答案）不是**回忆**（合上书从零讲）——
   再认的流畅感会被误认成掌握。
2. **间隔效应**没用上。一次性学完一次性自测，一周后只剩三成。
   留存要靠**隔一段时间主动提取一次**。
3. **题型全是解释型**（「说说 L2 和 L3 的关系」），而真实场景考的是
   **诊断型**（「这段代码哪一层断了」）—— 后者只能靠练。

这个脚本做什么
--------------
* 从 `判据卡.md` / `自检题.md` / `迁移题.md` 里抽题
* **先答后看** —— 判据折叠到你答完才展开，强制闭卷
* **逐条判据打勾** —— 全中才算过；漏的哪一条会记进日志
* **间隔排期** —— 答对就往后推（1/3/7/14/30/60/120 天），答漏就提前拉回来
* **跨模块交错** —— 一次复习不会连着 5 道同一模块（这才是面试的提问顺序）
* **遗忘曲线留档** —— 每次复习一行日志，git 里能看见「哪条一直在忘」

和仓库既有方法论是同一套逻辑：**没失败过的题不算验证过**。

用法
----
    python ex10_review.py              # 今日复习（5 题 + 2 卡，15 分钟）
    python ex10_review.py cards        # 只刷判据卡
    python ex10_review.py quiz         # 只刷题（含迁移题）
    python ex10_review.py status       # 看每条的状态：上次答对、连错几次
    python ex10_review.py stats        # 看留存曲线：哪些一直在忘
    python ex10_review.py --list       # 预览会抽到什么（不答题、不写盘）

零外部依赖（只用标准库）。Windows 上请用：
    PYTHONIOENCODING=utf-8 "I:/A2A/3/A2AServer/.venv/Scripts/python.exe" ex10_review.py
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:                                    # 老版本 python
    pass

ROOT = Path(__file__).resolve().parents[1]

CARDS_MD = ROOT / "判据卡.md"
QUIZ_MD = ROOT / "自检题.md"
TRANSFER_MD = ROOT / "迁移题.md"

STATE_JSON = ROOT / "reviews" / "state.json"
LOG_MD = ROOT / "reviews" / "日志.md"

#: 间隔天数表（天）。答对进一档，答漏退档。
INTERVALS = (1, 3, 7, 14, 30, 60, 120)

#: 达到这一档且连续命中这么多次，算「记住了」
SOLID_STAGE = 4
SOLID_HITS = 2

#: 一次复习的默认配比（15 分钟）
N_QUIZ = 5
N_CARDS = 2


# --------------------------------------------------------------------------
# 题库解析
# --------------------------------------------------------------------------

@dataclass
class Item:
    id: str
    kind: str                 # "card" | "quiz"
    title: str
    prompt: str
    criteria: list[str] = field(default_factory=list)
    stars: int = 0
    source: str = ""

    @property
    def module(self) -> str:
        if re.match(r"^T\d+$", self.id):
            return "T"
        m = re.match(r"^M(\d)", self.id)
        return f"M{m.group(1)}" if m else "?"

    @property
    def label(self) -> str:
        if self.kind == "card":
            return f"卡 {self.id} {'★' * self.stars}"
        return self.id


def _collect_criteria(block: str, marker: str) -> list[str]:
    """在 block 里找 marker 之后连续的 `- [ ] ` 行。

    marker 必须**行首匹配** —— 答案正文里出现「2. **判据粒度不对**」这种行时，
    用 `in` 找会把起点定位到答案正文中间，后面的勾选项就一个都收不到（静默丢题）。

    刻意只取 marker 之后的连续勾选项 —— 判据是「答到这些点就算过」，
    不是答案正文里恰好出现的方括号。
    """
    pat = re.compile(r"^\s*" + re.escape(marker))
    lines = block.split("\n")
    out: list[str] = []
    started = False
    for line in lines:
        if not started:
            if pat.match(line):
                started = True
            continue
        s = line.strip()
        if s.startswith("- [ ]"):
            out.append(s[6:].strip())
        elif s == "":
            continue
        else:
            break
    return out


def parse_cards(path: Path) -> list[Item]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    items: list[Item] = []
    # ### 卡 M3-01 ★★★ · 标题
    blocks = re.split(r"^### ", text, flags=re.M)
    for blk in blocks:
        m = re.match(r"^卡\s+(\S+)\s*(★*)\s*·\s*(.+)$", blk.split("\n")[0].strip())
        if not m:
            continue
        cid, stars_s, title = m.group(1), m.group(2), m.group(3).strip()
        crit = _collect_criteria(blk, "**要说出来**")
        if not crit:
            continue
        items.append(Item(
            id=cid, kind="card", title=title,
            prompt=f"复述这条判据，并说一个靶场里的例子：\n  {title}",
            criteria=crit, stars=len(stars_s), source=path.name,
        ))
    return items


def parse_quiz(path: Path) -> list[Item]:
    """解析 `#### <ID> · 标题` + 提示 + `<details>` 里的判据。"""
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    items: list[Item] = []
    parts = re.split(r"^#### ", text, flags=re.M)
    for blk in parts[1:]:
        head, _, rest = blk.partition("\n")
        m = re.match(r"^(\S+)\s*·\s*(.+)$", head.strip())
        if not m:
            continue
        qid, title = m.group(1), m.group(2).strip()
        d_open = rest.find("<details>")
        if d_open < 0:
            continue
        prompt = rest[:d_open].strip()
        d_close = rest.find("</details>")
        detail = rest[d_open:d_close if d_close > 0 else len(rest)]
        crit = _collect_criteria(detail, "**判据**")
        if not crit:
            continue
        items.append(Item(
            id=qid, kind="quiz", title=title, prompt=prompt,
            criteria=crit, source=path.name,
        ))
    return items


def load_bank() -> list[Item]:
    items = parse_cards(CARDS_MD) + parse_quiz(QUIZ_MD) + parse_quiz(TRANSFER_MD)
    seen: set[str] = set()
    uniq = []
    for it in items:
        if it.id in seen:
            continue
        seen.add(it.id)
        uniq.append(it)
    return uniq


# --------------------------------------------------------------------------
# 状态
# --------------------------------------------------------------------------

def load_state(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"version": 1, "items": {}}


def save_state(path: Path, state: dict) -> str | None:
    """写状态。返回错误信息（None = 成功）。"""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
        return None
    except PermissionError:
        return (f"没有写权限：{path}\n"
                f"    这个目录被沙箱挡住了。换一个可写路径：\n"
                f"    python ex10_review.py --state <可写路径>/state.json --log <可写路径>/日志.md")
    except OSError as e:
        return f"写状态失败：{e}"


def item_state(state: dict, item_id: str) -> dict:
    return state["items"].setdefault(item_id, {
        "stage": 0, "last": None, "hits": 0, "misses": 0,
        "seen": 0, "last_score": None, "miss": False,
    })


def is_due(item: Item, st: dict, today: date) -> bool:
    last = st.get("last")
    if not last:
        return True
    try:
        d = (today - date.fromisoformat(last)).days
    except ValueError:
        return True
    stage = min(int(st.get("stage", 0)), len(INTERVALS) - 1)
    return d >= INTERVALS[stage]


def days_until_due(item: Item, st: dict, today: date) -> int | None:
    last = st.get("last")
    if not last:
        return 0
    try:
        d = (today - date.fromisoformat(last)).days
    except ValueError:
        return 0
    stage = min(int(st.get("stage", 0)), len(INTERVALS) - 1)
    return max(0, INTERVALS[stage] - d)


def priority(item: Item, st: dict) -> int:
    """选題优先级：越大越先。答漏的必须回来。"""
    if st.get("miss"):
        return 100
    if not st.get("last"):
        return 50                       # 没做过
    return 10 + int(st.get("stage", 0))


def pick(pool: list[Item], state: dict, n: int) -> list[Item]:
    """跨模块交错地挑 n 道。

    排序键 = (这个模块本次已用几次, -优先级, id)：
    先保证模块不连着来，同一模块内再按优先级。
    """
    remaining = sorted(pool, key=lambda it: (-priority(it, item_state(state, it.id)), it.id))
    used: Counter = Counter()
    picked: list[Item] = []
    while remaining and len(picked) < n:
        best = min(remaining, key=lambda it: (used[it.module],
                                              -priority(it, item_state(state, it.id)),
                                              it.id))
        picked.append(best)
        used[best.module] += 1
        remaining.remove(best)
    return picked


# --------------------------------------------------------------------------
# 一次复习
# --------------------------------------------------------------------------

BAR = "─" * 68


def ask(prompt: str, default: str = "") -> str:
    try:
        s = input(prompt).strip()
    except EOFError:
        return default
    return s or default


def judge(item: Item, auto: bool, dry: bool) -> tuple[int, list[str]]:
    """让用户逐条判：命中 / 漏掉。返回 (命中数, 漏掉的判据)。"""
    print("\n  判据（逐条判，命中打 y，漏掉打 n）：")
    missed: list[str] = []
    hits = 0
    for i, c in enumerate(item.criteria, 1):
        print(f"    {i}. {c}")
        if dry:
            continue
        if auto:
            ans = "y"
        else:
            ans = ask(f"       命中? [y/n] ", default="n").lower()
        if ans.startswith("y"):
            hits += 1
        else:
            missed.append(c)
    return hits, missed


def run_session(items: list[Item], state: dict, today: date,
                n_quiz: int, n_cards: int, auto: bool, dry: bool) -> list[dict]:
    due = [it for it in items if is_due(it, item_state(state, it.id), today)]
    cards_pool = [it for it in due if it.kind == "card"]
    quiz_pool = [it for it in due if it.kind == "quiz"]

    # ★★★ 优先，占满卡片名额
    cards_pool.sort(key=lambda it: (-it.stars,
                                    -priority(it, item_state(state, it.id))))
    cards = pick(cards_pool, state, n_cards)
    chosen = cards + pick(quiz_pool, state, n_quiz)

    if not chosen:
        print("\n今天没有到期的条目 —— 说明上一轮都答满了。")
        print("想加练就提高配额：  python ex10_review.py --quiz 10 --cards 4")
        return []

    print(BAR)
    print(f"  今日复习 · {today} · 共 {len(chosen)} 条"
          f"（{len(cards)} 卡 + {len(chosen) - len(cards)} 题）· 预计 15 分钟")
    print("  规则：**先出声答，再展开判据**。判据要逐条对，漏的会重排到下次。")
    print(BAR)

    results: list[dict] = []
    for idx, item in enumerate(chosen, 1):
        print()
        print(f"[{idx}/{len(chosen)}] {item.label} · {item.title}")
        print(f"  来源：{item.source} · 模块 {item.module}")
        if item.kind == "card":
            print(f"  {item.prompt}")
        else:
            for ln in item.prompt.split("\n"):
                print(f"  {ln}" if ln.strip() else "")
        print()
        if dry:
            for c in item.criteria:
                print(f"    - {c}")
            results.append({"id": item.id, "kind": item.kind, "score": None,
                            "total": len(item.criteria), "missed": [],
                            "title": item.title, "stage_before": item_state(state, item.id).get("stage", 0)})
            continue

        print("  → 出声把答案讲一遍（或写下来）。讲完按 Enter 展开判据。")
        ask("  ")
        hits, missed = judge(item, auto, dry)
        total = len(item.criteria)

        st = item_state(state, item.id)
        stage_before = int(st.get("stage", 0))
        score = hits / total if total else 0.0

        if hits == total:
            st["stage"] = min(stage_before + 1, len(INTERVALS) - 1)
            st["hits"] = int(st.get("hits", 0)) + 1
            st["misses"] = 0
            st["miss"] = False
            verdict = "✓ 全中"
        elif hits > 0:
            st["stage"] = max(0, stage_before - 1)
            st["hits"] = 0
            st["misses"] = int(st.get("misses", 0)) + 1
            st["miss"] = True
            verdict = "~ 部分"
        else:
            st["stage"] = max(0, stage_before - 2)
            st["hits"] = 0
            st["misses"] = int(st.get("misses", 0)) + 1
            st["miss"] = True
            verdict = "✗ 全漏"

        st["last"] = today.isoformat()
        st["seen"] = int(st.get("seen", 0)) + 1
        st["last_score"] = round(score, 3)

        nxt = INTERVALS[min(st["stage"], len(INTERVALS) - 1)]
        print(f"\n  → {verdict}  {hits}/{total}"
              f"   阶段 {stage_before} → {st['stage']}"
              f"   下次：{nxt} 天后")
        if missed:
            print("    漏掉的（下次还会出现）：")
            for m in missed:
                print(f"      · {m}")

        results.append({"id": item.id, "kind": item.kind, "score": score,
                        "total": total, "missed": missed, "title": item.title,
                        "stage_before": stage_before, "stage_after": st["stage"],
                        "verdict": verdict})

    return results


def append_log(path: Path, today: date, results: list[dict], state: dict) -> str | None:
    if not results:
        return None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        n = state.get("sessions", 0) + 1
        state["sessions"] = n
        if not path.exists():
            path.write_text(
                "# 复习日志\n\n"
                "> 每次复习一行记录。**这份文件的价值不在「学过什么」，在「哪条一直在忘」** ——\n"
                "> 反复出现在「漏掉的判据」里的条目，就是还没进长期记忆的。\n"
                "> 它和仓库其他东西是同一个逻辑：**没失败过的题不算验证过**。\n\n",
                encoding="utf-8")
        lines = [f"## {today} · 第 {n} 次复习", ""]
        lines.append("| 条目 | 类型 | 结果 | 得分 | 阶段 |")
        lines.append("|---|---|---|---|---|")
        for r in results:
            if r.get("score") is None:
                continue
            lines.append(f"| {r['id']} | {r['kind']} | {r['verdict']} | "
                         f"{r['total'] - len(r['missed'])}/{r['total']} | "
                         f"{r['stage_before']} → {r['stage_after']} |")
        misses = [r for r in results if r.get("missed")]
        if misses:
            lines += ["", "**漏掉的判据**（这些下次一定会再出现）：", ""]
            for r in misses:
                lines.append(f"- **{r['id']}** {r['title']}")
                for m in r["missed"]:
                    lines.append(f"  - {m}")
        lines.append("")
        with path.open("a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return None
    except PermissionError:
        return (f"没有写权限：{path}\n"
                f"    用 --log <可写路径>/日志.md 换一个位置。")
    except OSError as e:
        return f"写日志失败：{e}"


# --------------------------------------------------------------------------
# status / stats
# --------------------------------------------------------------------------

def cmd_status(items: list[Item], state: dict, today: date) -> None:
    rows = []
    for it in items:
        st = item_state(state, it.id)
        due_in = days_until_due(it, st, today)
        rows.append((it, st, due_in))
    # 排序：**反复答漏的排最前**（那是真正要回炉的），其次按到期日
    rows.sort(key=lambda r: (0 if int(r[1].get("misses", 0)) > 0 else 1,
                              r[2] if r[2] is not None else 999,
                              r[0].id))

    print(BAR)
    print(f"  复习状态 · {today} · 共 {len(items)} 条")
    print(BAR)
    print(f"  {'条目':<10} {'类型':<5} {'星':<4} {'阶段':<5} {'下次':<6} {'连错':<5} {'上次得分'}")
    for it, st, due_in in rows:
        star = "★" * it.stars if it.kind == "card" else ""
        due = "到期" if due_in == 0 else f"{due_in}天"
        sc = st.get("last_score")
        scs = "-" if sc is None else f"{sc:.0%}"
        print(f"  {it.id:<10} {it.kind:<5} {star:<4} {st.get('stage', 0):<5} "
              f"{due:<6} {st.get('misses', 0):<5} {scs}")


def cmd_stats(items: list[Item], state: dict) -> None:
    print(BAR)
    print("  留存统计")
    print(BAR)
    cards = [i for i in items if i.kind == "card"]
    quiz = [i for i in items if i.kind == "quiz"]
    solid = [i for i in items
             if int(item_state(state, i.id).get("stage", 0)) >= SOLID_STAGE
             and int(item_state(state, i.id).get("hits", 0)) >= SOLID_HITS]
    never = [i for i in items if not item_state(state, i.id).get("last")]
    scores = [item_state(state, i.id).get("last_score")
              for i in items if item_state(state, i.id).get("last_score") is not None]

    print(f"  条目总数        {len(items)}（判据卡 {len(cards)} · 题 {len(quiz)}）")
    print(f"  做过            {len(items) - len(never)}")
    print(f"  还没做          {len(never)}")
    print(f"  已记住          {len(solid)}"
          f"   （阶段 ≥ {SOLID_STAGE} 且连续命中 ≥ {SOLID_HITS}）")
    if scores:
        print(f"  平均得分        {sum(scores) / len(scores):.0%}")

    dist = Counter(min(int(item_state(state, i.id).get("stage", 0)), 6) for i in items)
    print("\n  阶段分布（阶段 = 连续答对次数，决定下次隔多久）：")
    for s in range(len(INTERVALS)):
        n = dist.get(s, 0)
        bar = "█" * min(n, 40)
        label = f"{INTERVALS[s]:>3}天" if s < len(INTERVALS) - 1 else "120天+"
        print(f"    {label}  {n:>3}  {bar}")

    weak = sorted(
        (i for i in items if item_state(state, i.id).get("misses", 0) > 0),
        key=lambda i: (-int(item_state(state, i.id).get("misses", 0)),
                       item_state(state, i.id).get("last_score") or 0))
    if weak:
        print("\n  一直在忘的（连错 ≥ 1）：")
        for i in weak[:12]:
            st = item_state(state, i.id)
            sc = st.get("last_score")
            print(f"    {i.id:<10} 连错 {st['misses']} 次 · 上次 {sc:.0%} · {i.title[:34]}")
    else:
        print("\n  （还没有反复漏掉的条目）")

    unseen_cards = [i for i in cards if not item_state(state, i.id).get("last")]
    if unseen_cards:
        print(f"\n  ⚠ 有 {len(unseen_cards)} 张判据卡还没碰过 —— ★★★ 的先背")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="间隔复习 —— 判据卡 / 概念题 / 迁移题",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("cmd", nargs="?", default="session",
                    choices=["session", "cards", "quiz", "status", "stats"],
                    help="session=全部（默认） cards=只刷判据卡 quiz=只刷题 "
                         "status=逐条状态 stats=留存统计")
    ap.add_argument("--quiz", type=int, default=None, help="本次抽几道题")
    ap.add_argument("--cards", type=int, default=None, help="本次抽几张卡")
    ap.add_argument("--state", type=Path, default=STATE_JSON, help="状态文件路径")
    ap.add_argument("--log", type=Path, default=LOG_MD, help="复习日志路径")
    ap.add_argument("--list", action="store_true", help="只预览，不答题不写盘")
    ap.add_argument("--yes", action="store_true", help="自动全判命中（调试用）")
    args = ap.parse_args(argv)

    today = date.today()
    items = load_bank()
    if not items:
        print("题库是空的 —— 找不到 判据卡.md / 自检题.md / 迁移题.md")
        return 1

    state = load_state(args.state)

    if args.cmd == "status":
        cmd_status(items, state, today)
        return 0
    if args.cmd == "stats":
        cmd_stats(items, state)
        return 0

    n_quiz = args.quiz if args.quiz is not None else (
        0 if args.cmd == "cards" else N_QUIZ)
    n_cards = args.cards if args.cards is not None else (
        N_CARDS if args.cmd == "session" else 0)

    if args.cmd == "cards" and n_cards == 0:
        n_cards = N_CARDS
    if args.cmd == "quiz" and n_quiz == 0:
        n_quiz = N_QUIZ

    results = run_session(items, state, today, n_quiz, n_cards,
                          auto=args.yes, dry=args.list)

    if args.list:
        print()
        print("  （--list 模式：不写盘）")
        return 0

    err = save_state(args.state, state)
    if err:
        print(f"\n⚠ {err}")
    err = append_log(args.log, today, results, state)
    if err:
        print(f"\n⚠ {err}")
    elif results:
        print(f"\n  日志已写：{args.log}")
        print(f"  状态已写：{args.state}")

    done = [r for r in results if r.get("score") is not None]
    if done:
        full = sum(1 for r in done if r["total"] - len(r["missed"]) == r["total"])
        print(f"\n  本次 {len(done)} 条 · 全中 {full} 条 · "
              f"漏掉的部分下次会自动回来")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
