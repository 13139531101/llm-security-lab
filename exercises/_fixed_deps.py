"""共用工具：把「修复版本」的依赖装到一个独立目录，用 PYTHONPATH 切过去。

为什么需要它
------------
仓库的红→绿惯例是「同一条命令两端跑」：vuln-XXX 跑出红，fixed-XXX 跑出绿。
第三方库没法打 tag 对，就用「两个版本、同一段代码」达到同样的效果：

    红 → 靶场 venv 里现装的版本（本脚本默认）
    绿 → deps/fixed/ 下的修复版（--fetch-fixed 装好）

**沙箱里 pip 走不通**（pip 到 pypi 会卡住），但 curl 能通。
所以这里用 curl 拿 wheel，再 `pip install --no-index` 本地装 —— 不联网也能装。

用法：
    python exercises/_fixed_deps.py --spec authlib==1.9.1
    python exercises/_fixed_deps.py --spec mcp==1.30.0
    python exercises/_fixed_deps.py --list
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).resolve().parents[1]
FIXED_DIR = Path(os.environ.get("PHA_FIXED_DIR", ROOT / "deps" / "fixed"))
MANIFEST = Path(os.environ.get("PHA_FIXED_MANIFEST", ROOT / "deps" / "fixed.json"))


def _curl(url: str, out: Path) -> bool:
    cmd = ["curl", "-sSL", "-m", "180", "-o", str(out), url]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        return r.returncode == 0 and out.exists() and out.stat().st_size > 0
    except Exception as e:
        print(f"[curl fail] {url}: {e}", file=sys.stderr)
        return False


def wheel_url(pkg: str, version: str) -> str | None:
    url = f"https://pypi.org/pypi/{pkg}/{version}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "llm-security-lab/1.0"})
    with urllib.request.urlopen(req, timeout=45) as r:
        data = json.loads(r.read().decode())
    for u in data.get("urls", []):
        if u.get("packagetype") == "bdist_wheel":
            return u["url"]
    return None


def fetch_fixed(spec: str, force: bool = False) -> Path:
    """把 pkg==version 装到 deps/fixed/<pkg>==<version>/，返回该目录"""
    pkg, _, version = spec.partition("==")
    if not version:
        raise ValueError(f"spec 要写成 pkg==version：{spec}")
    dest = FIXED_DIR / f"{pkg}=={version}"
    if dest.exists() and (dest / pkg.replace("-", "_")).exists() and not force:
        print(f"[skip] 已在 {dest}")
        return dest

    FIXED_DIR.mkdir(parents=True, exist_ok=True)
    whl_dir = FIXED_DIR / "_wheels"
    whl_dir.mkdir(parents=True, exist_ok=True)

    print(f"[fetch] {spec}")
    url = wheel_url(pkg, version)
    if not url:
        raise RuntimeError(f"PyPI 上找不到 {spec} 的 wheel")
    whl = whl_dir / url.rsplit("/", 1)[-1]
    if not whl.exists():
        if not _curl(url, whl):
            raise RuntimeError(f"下载失败：{url}")

    # 装到独立目录（--no-index：只认本地 wheel，不再联网）
    dest.mkdir(parents=True, exist_ok=True)
    py = os.environ.get("PHA_VENV_PYTHON", sys.executable)
    # pip 要用临时目录；有些环境默认 temp 不可写 → 指到我们自己的目录
    tmp = FIXED_DIR / "_tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "PYTHONIOENCODING": "utf-8",
           "TMPDIR": str(tmp), "TEMP": str(tmp), "TMP": str(tmp)}
    r = subprocess.run(
        [py, "-m", "pip", "install", "--no-index", "--no-deps",
         "--target", str(dest), str(whl)],
        capture_output=True, text=True, timeout=180, env=env,
    )
    if r.returncode != 0:
        raise RuntimeError(f"pip install 失败：{r.stdout}\n{r.stderr}")

    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    man = {}
    if MANIFEST.exists():
        man = json.loads(MANIFEST.read_text(encoding="utf-8"))
    man[spec] = {"dir": str(dest), "url": url}
    MANIFEST.write_text(json.dumps(man, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[ok] {spec} → {dest}")
    return dest


def fixed_env(spec: str) -> dict:
    """返回切到修复版所需的 env（PYTHONPATH 指向 deps/fixed 下的目录）"""
    pkg, _, version = spec.partition("==")
    dest = FIXED_DIR / f"{pkg}=={version}"
    if not dest.exists():
        raise RuntimeError(f"修复版还没装：{spec}\n    先跑 python exercises/_fixed_deps.py --spec {spec}")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(dest) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def run_in_fixed(spec: str, argv: list[str]) -> int:
    """用修复版跑一段 python，返回退出码"""
    env = fixed_env(spec)
    py = os.environ.get("PHA_VENV_PYTHON", sys.executable)
    return subprocess.run([py] + argv, env=env).returncode


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", help="pkg==version")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        if MANIFEST.exists():
            print(MANIFEST.read_text(encoding="utf-8"))
        else:
            print("(还没装过任何修复版)")
    elif a.spec:
        fetch_fixed(a.spec, force=a.force)
