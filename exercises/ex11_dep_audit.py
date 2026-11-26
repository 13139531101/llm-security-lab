"""ex11 · 依赖漏洞盘点 + 每日发布追踪

问两个问题：
  ① 我们锁定的这些版本，有哪些已被公开？（→ 命中清单 + 修复版本）
  ② **今天又新出了哪些？**（→ 与上次基线 diff）

数据源：OSV.dev（api.osv.dev），零第三方依赖，只发 HTTPS GET/POST。

用法：
    python ex11_dep_audit.py                 # 盘点当前状态
    python ex11_dep_audit.py --save          # 存基线（deps/baseline.json）
    python ex11_dep_audit.py --diff          # 与基线比：新增了哪些？
    python ex11_dep_audit.py --diff --since 7d   # 只看 7 天内新出的
    python ex11_dep_audit.py --pkg mcp        # 只看某一个包
    python ex11_dep_audit.py --list          # 看看监控了哪些包

**这个脚本只做「有没有被公开」，不做「我们中不中招」** ——
后者要看代码接没接线，那是 ex12–ex15 和人工判据的事。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).resolve().parents[1]
TARGET = Path(os.environ.get("PHA_TARGET_ROOT", r"I:\A2A\3\A2AServer"))
BASELINE = ROOT / "deps" / "baseline.json"

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"

# 监控名单：靶场 requirements*.txt 里出现过的包 + AI 生态里值得盯的包
WATCH = {
    # ---- 靶场直接依赖 ----
    "mcp": None, "fastmcp": None, "langchain": None, "langchain-core": None,
    "langchain-openai": None, "langchain-mcp-adapters": None, "langgraph": None,
    "langgraph-sdk": None, "langgraph-checkpoint": None, "langgraph-prebuilt": None,
    "a2a-sdk": None, "fastapi": None, "starlette": None, "uvicorn": None,
    "pydantic": None, "sqlalchemy": None, "psycopg": None, "redis": None,
    "httpx": None, "requests": None, "python-multipart": None, "pyyaml": None,
    "pyjwt": None, "authlib": None, "cryptography": None, "pillow": None,
    "numpy": None, "pandas": None, "openai": None, "langsmith": None,
    "sse-starlette": None, "httpx-sse": None, "jwcrypto": None,
    # ---- AI 生态（不在靶场但要盯，出了就是选题）----
    "litellm": None, "llama-index": None, "transformers": None, "torch": None,
    "vllm": None, "ollama": None, "chromadb": None, "gradio": None,
    "streamlit": None, "mlflow": None, "ray": None, "promptfoo": None,
    "openai-agents": None, "autogen": None, "crewai": None, "langfuse": None,
    "haystack-ai": None, "weaviate-client": None, "pinecone-client": None,
    "qdrant-client": None,
}


# ---------------------------------------------------------------- helpers

def parse_ver(v):
    out = []
    for part in str(v).split("."):
        num = ""
        for ch in part:
            if ch.isdigit():
                num += ch
            else:
                break
        out.append(int(num) if num else 0)
    while len(out) < 3:
        out.append(0)
    return tuple(out[:3])


def spans_of(aff):
    """把 affected 条目展开成 (introduced, fixed) 区间列表"""
    out = []
    for rng in aff.get("ranges", []):
        if rng.get("type") not in ("ECOSYSTEM", "SEMVER", "PYTHON"):
            continue
        intro = None
        for e in rng.get("events", []):
            if e.get("introduced") is not None:
                intro = e["introduced"]
            elif e.get("fixed") is not None:
                out.append((intro, e["fixed"]))
                intro = None
            elif e.get("last_affected") is not None:
                out.append((intro, None))
                intro = None
        if intro is not None:
            out.append((intro, None))
    return out


def version_hit(aff, version):
    """version 是否落在 affected 区间内。None = 判不了"""
    if version is None or not aff:
        return None
    v = parse_ver(version)
    for intro, fixed in spans_of(aff):
        if intro and intro != "0" and v < parse_ver(intro):
            continue
        if fixed and v >= parse_ver(fixed):
            continue
        return True
    return False


def earliest_fix(aff):
    if not aff:
        return None
    fixes = [f for _, f in spans_of(aff) if f]
    return min(fixes, key=parse_ver) if fixes else None


def osv_post(url, payload, timeout=45, retries=2):
    last = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "llm-security-lab/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = e
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    raise last


def osv_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "llm-security-lab/1.0"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return json.loads(r.read().decode())


# ---------------------------------------------------------------- 取我们的版本

REQ_FILES = [
    "requirements-v2.txt",
    "backend/requirements.txt",
    "backend/HealthAdvisor/requirements.txt",
    "backend/HealthRecordsManager/requirements.txt",
    "backend/MedicationReminder/requirements.txt",
    "backend/VisitSummaryGenerator/requirements.txt",
    "backend/AgentMemorySystem/requirements.txt",
]

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*([<>=!~]=?\s*[^#\s]+)?")
EXCLUDE_DIRS = ("node_modules", ".venv", "__pycache__", ".git", "site-packages")


def scan_declared():
    """扫靶场的 requirements*.txt → {包名: 声明约束}"""
    out = {}
    for rel in REQ_FILES:
        p = TARGET / rel
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.split("#")[0].strip()
            if not line or line.startswith("-"):
                continue
            m = REQ_LINE.match(line)
            if not m:
                continue
            name = m.group(1).lower().replace("_", "-")
            if name in ("python", "pip"):
                continue
            spec = (m.group(2) or "").strip()
            out.setdefault(name, [])
            if spec and spec not in out[name]:
                out[name].append(spec)
    return out


def scan_installed():
    """靶场 venv 里实际装了什么 → {包名: 版本}"""
    py = TARGET / ".venv" / "Scripts" / "python.exe"
    if not py.exists():
        return {}
    try:
        out = subprocess.run(
            [str(py), "-m", "pip", "freeze"],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
    except Exception:
        return {}
    if out.returncode != 0:
        return {}
    res = {}
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line or "==" not in line:
            continue
        name, ver = line.split("==", 1)
        res[name.lower().replace("_", "-")] = ver.strip()
    return res


# ---------------------------------------------------------------- 查 OSV

def fetch_all(pkg_filter=None, scope="target"):
    installed = scan_installed()
    declared = scan_declared()
    if scope == "target":
        # 只扫靶场自己声明/装了的包 —— 每天要看的就是这些，快。
        # 全生态（WATCH 里 torch/vllm/ray 那种几百条的大包）留给 --scope all 按需跑。
        names = sorted(set(declared) | set(installed))
    else:
        names = sorted(set(WATCH) | set(declared) | set(installed))
    if pkg_filter:
        names = [n for n in names if pkg_filter in n]

    # 只对有精确安装版本的包做带版本的查询；其余全量拉
    with_ver = {n: installed[n] for n in names if n in installed}
    rest = [n for n in names if n not in with_ver]

    vulns = {}

    def absorb(v, pkg):
        vid = v["id"]
        rec = vulns.get(vid)
        if rec is None:
            affs = v.get("affected", [])
            ours = [a for a in affs
                    if a.get("package", {}).get("name", "").lower() == pkg]
            rec = {
                "id": vid,
                "pkgs": [],
                "aliases": v.get("aliases", []),
                "summary": (v.get("summary") or "").strip(),
                "published": v.get("published", ""),
                "modified": v.get("modified", ""),
                "refs": [r.get("url", "") for r in v.get("references", [])][:6],
                "_ours": ours[0] if ours else None,
                "hit": None,
                "fix": None,
            }
            vulns[vid] = rec
        if pkg not in rec["pkgs"]:
            rec["pkgs"].append(pkg)
        rec["_ours"] = rec["_ours"] or (
            next((a for a in v.get("affected", [])
                  if a.get("package", {}).get("name", "").lower() == pkg), None)
        )
        return rec

    # 查询：带版本走单查（/v1/query 返回完整对象：affected/summary/published）。
    # 不用 querybatch —— 它的条目只有 id 和 modified，没有 affected，
    # 拿不到区间就判不出命中，会把「命中」误报成「未知」。
    # OSV 单查延迟不低 → 并发查，不然 70 个包要跑好几分钟。
    failed = []
    lock = threading.Lock()

    def query_one(n, ver):
        payload = {"package": {"name": n, "ecosystem": "PyPI"}}
        if ver:
            payload["version"] = ver
        return n, ver, osv_post(OSV_QUERY, payload)

    jobs = [(n, v) for n, v in with_ver.items()] + [(n, None) for n in rest]
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(query_one, n, v): (n, v) for n, v in jobs}
        for fut in as_completed(futs):
            n, ver = futs[fut]
            try:
                _, _, res = fut.result()
            except Exception as e:
                print(f"[warn] 跳过 {n}: {e}", file=sys.stderr)
                with lock:
                    failed.append(n)
                continue
            for v in res.get("vulns", []):
                rec = absorb(v, n)
                if ver:
                    rec["hit"] = version_hit(rec["_ours"], ver)
                    rec["fix"] = earliest_fix(rec["_ours"])

    for rec in vulns.values():
        if rec["hit"] is None:
            rec["fix"] = earliest_fix(rec["_ours"]) if rec["_ours"] else None
    return vulns, installed, declared, failed


# ---------------------------------------------------------------- 报告

def cve_of(rec):
    return next((a for a in rec["aliases"] if a.startswith("CVE")), "")


def print_table(vulns, installed, declared, only_hit=False, failed=()):
    rows = [r for r in vulns.values() if (not only_hit) or r["hit"] is True]
    rows.sort(key=lambda r: (r["published"] or ""), reverse=True)
    hits = [r for r in rows if r["hit"] is True]
    unknown = [r for r in rows if r["hit"] is None and r["pkgs"][0] in declared]
    if only_hit:
        unknown = []

    print("=" * 104)
    print(f"依赖漏洞盘点 · 命中我们锁定版本 {len(hits)} 条 · 需人工判 {len(unknown)} 条")
    print("=" * 104)
    if failed:
        # 查不到的包 ≠ 没有漏洞。宁可说「查不到」，也不能让网络抖动伪装成「干净」。
        print(f'\n⚠ 有 {len(failed)} 个包没查到（网络/超时）—— 下面这些包的结果**不完整**，别当干净：')
        print(f'   {", ".join(sorted(set(failed)))}')
    if hits:
        print("\n【命中我们的版本】")
        for r in hits:
            ver = installed.get(r["pkgs"][0], "?")
            print(f'\n  {r["published"][:10]}  {r["id"]}  {cve_of(r)}')
            print(f'    包: {r["pkgs"][0]}=={ver}   修复版本: {r["fix"]}')
            print(f'    {r["summary"][:200]}')
    if unknown:
        print("\n【声明了依赖但版本未知 · 需人工判是否落在区间内】")
        for r in unknown[:25]:
            print(f'  {r["published"][:10]}  {r["id"]}  {cve_of(r):<18} {r["pkgs"][0]:<22} fix={r["fix"]}')
            print(f'      {r["summary"][:150]}')
    if not hits and not unknown:
        print("\n（没有命中）")
    print()


def diff_against_baseline(vulns, baseline, since_days=None):
    base = baseline.get("vulns", {}) if baseline else {}
    new = [r for r in vulns.values() if r["id"] not in base]
    new.sort(key=lambda r: r["published"] or "", reverse=True)
    if since_days:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=since_days)).isoformat()
        new = [r for r in new if (r["published"] or "") >= cutoff]
    print("=" * 104)
    print(f"每日发布追踪 · 基线 {baseline.get('saved_at', '?')[:10] if baseline else '无'}"
          f" → 新增 {len(new)} 条")
    print("=" * 104)
    if not new:
        print("\n（自基线以来没有新的公开漏洞命中我们的监控名单）")
        return new
    for r in new:
        hitmark = {True: "★命中我们版本", False: "  未命中", None: " ?待判"}[r["hit"]]
        print(f'\n  {r["published"][:10]}  {hitmark}  {r["id"]}  {cve_of(r)}')
        print(f'    包: {", ".join(r["pkgs"])}   修复版本: {r["fix"]}')
        print(f'    {r["summary"][:200]}')
        if r["refs"]:
            print(f'    公告: {r["refs"][0]}')
    print()
    return new


def save_baseline(vulns, path):
    data = {
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "target_root": str(TARGET),
        "vulns": {
            r["id"]: {
                "pkgs": r["pkgs"], "aliases": r["aliases"],
                "summary": r["summary"], "published": r["published"],
                "hit": r["hit"], "fix": r["fix"],
            }
            for r in vulns.values()
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[saved] {path}  ({len(data['vulns'])} 条)")


def load_baseline(path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="依赖漏洞盘点 + 每日发布追踪")
    ap.add_argument("--pkg", help="只看包含该子串的包")
    ap.add_argument("--save", action="store_true", help="把当前状态存为基线")
    ap.add_argument("--diff", action="store_true", help="与基线比，看新增了哪些")
    ap.add_argument("--since", help="配合 --diff：只看 N 天内新增，如 7d")
    ap.add_argument("--hit-only", action="store_true", help="只列命中我们版本的")
    ap.add_argument("--baseline", type=Path, default=BASELINE, help="基线文件路径")
    ap.add_argument("--list", action="store_true", help="列出监控的包与我们的版本")
    ap.add_argument("--scope", choices=("target", "all"), default="target",
                    help="target=只扫靶场自己的依赖（默认，快）；all=连整个 AI 生态一起扫（慢）")
    args = ap.parse_args()

    installed = scan_installed()
    declared = scan_declared()

    if args.list:
        print("=" * 104)
        print("监控名单 · 我们声明的 vs 实际装着的")
        print("=" * 104)
        for n in sorted(set(WATCH) | set(declared)):
            d = ", ".join(declared.get(n, [])) or "-"
            i = installed.get(n, "-")
            flag = "★" if n in declared and i != "-" else " "
            print(f"  {flag} {n:<26} 声明={d:<22} 实装={i}")
        print()
        return

    vulns, installed, declared, failed = fetch_all(args.pkg, args.scope)

    if args.save:
        save_baseline(vulns, args.baseline)

    if args.diff:
        baseline = load_baseline(args.baseline)
        if not baseline:
            print(f"[!] 没有基线：{args.baseline}\n    先跑一次 --save")
            return
        since = None
        if args.since:
            since = int(args.since.rstrip("dD"))
        diff_against_baseline(vulns, baseline, since)
        return

    print_table(vulns, installed, declared, only_hit=args.hit_only, failed=failed)


if __name__ == "__main__":
    main()
