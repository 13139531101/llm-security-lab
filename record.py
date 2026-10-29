# -*- coding: utf-8 -*-
"""
记录工具 —— 一条命令记一个漏洞 / 一个概念。

用法:
  python record.py finding --title "越权读他人档案" --where "api.py:5291" ^
                            --root "请求体参与安全决策" --fix "token 优先" ^
                            [--poc tests/test_x.py] [--status 待修] [--tag vuln-001/fixed-001]
  python record.py note --text "fail-open 是根本性错误" --tag M1
  python record.py show

--tag 记的是证据 tag 对。填了 tag 的「已修」才算数 —— 没有红→绿对照的修复，
只是把洞从你看得到的地方挪到了你看不到的地方。

ID 自动分配，不用自己想编号。
"""
import argparse
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FINDINGS = HERE / "findings.md"
NOTES = HERE / "notes.md"


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _write(p: Path, s: str) -> None:
    p.write_text(s, encoding="utf-8")


def next_id(md: str) -> str:
    nums = [int(n) for n in re.findall(r"^\|\s*F-(\d+)\s*\|", md, re.M)]
    return f"F-{(max(nums) + 1) if nums else 1:03d}"


def add_finding(a) -> None:
    md = _read(FINDINGS)
    fid = next_id(md)
    evidence = f" `{a.tag}`" if a.tag else " -"
    row = (
        f"| {fid} | {a.title} | {a.where} | {a.root} | {a.fix} | {a.status} |{evidence} |"
    )
    md = md.rstrip("\n") + "\n" + row + "\n"
    _write(FINDINGS, md)
    print(f"已记录 {fid}")
    print(f"  {a.title}")
    print(f"  位置 {a.where}")
    if a.tag:
        print(f"  证据 {a.tag}")


def add_note(a) -> None:
    md = _read(NOTES).rstrip("\n")
    tag = f"[{a.tag}] " if a.tag else ""
    line = f"- **{tag}** {a.text}" if a.tag else f"- {a.text}"
    _write(NOTES, md + "\n" + line + "\n")
    print(f"已记录概念笔记: {a.text[:40]}")


def show(_a) -> None:
    md = _read(FINDINGS)
    rows = [r for r in md.splitlines() if re.match(r"^\|\s*F-\d+\s*\|", r)]
    done = sum(1 for r in rows if "已修" in r)
    print(f"漏洞 {len(rows)} 个，已修 {done} 个")
    print()
    for r in rows:
        cells = [c.strip() for c in r.strip("|").split("|")]
        print(f"  {cells[0]}  {cells[5]:<6}  {cells[1]}")


def main() -> int:
    p = argparse.ArgumentParser(description="漏洞/概念记录工具")
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("finding", help="记录一个漏洞")
    f.add_argument("--title", required=True, help="漏洞是什么")
    f.add_argument("--where", required=True, help="位置 file:line")
    f.add_argument("--root", required=True, help="根因一句话")
    f.add_argument("--fix", required=True, help="修法一句话")
    f.add_argument("--poc", default="", help="PoC 文件路径")
    f.add_argument("--status", default="待修", help="待修/已修/已复现/待验证")
    f.add_argument("--tag", default="", help="证据 tag，如 vuln-001/fixed-001")
    f.set_defaults(func=add_finding)

    n = sub.add_parser("note", help="记录一个概念")
    n.add_argument("--text", required=True, help="概念 + 一句话说明")
    n.add_argument("--tag", default="", help="模块标签，如 M1")
    n.set_defaults(func=add_note)

    s = sub.add_parser("show", help="看进度")
    s.set_defaults(func=show)

    a = p.parse_args()
    a.func(a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
