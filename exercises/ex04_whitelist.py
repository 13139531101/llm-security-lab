# -*- coding: utf-8 -*-
"""
练习 4：白名单

ex03 里的修法3 是「黑名单式」修复：只剔掉 user_id。
问题：攻击载荷（uid / userId / sub）还留在 metadata 里，
      只是暂时没被下游读到。下游哪天加一行读 uid 的代码，洞就重开。

ex04 换成「白名单式」：只允许下游真的会读、且允许客户端传的 key。

顺带一个 ex03 没覆盖的攻击面：
  metadata 里的 selected_agent / parallel_agents 是【路由控制字段】，
  攻击者能指定请求交给哪个 agent —— 而不同 agent 的工具集和权限不同。
  所以白名单要分两类：
    - 身份类（user_id / conversation_id）：必须服务端生成，不许透传
    - 路由类（selected_agent / parallel_agents / v2_mode）：允许透传，但值要校验（枚举）

运行：python ex04_whitelist.py
"""
import json

DB = {
    "attacker_001": {"name": "张三", "record": "青霉素过敏"},
    "victim_001":   {"name": "李四", "record": "HIV 阳性 / 肝功能异常"},
}
token_uid = "attacker_001"

# --- 实测：下游 bridge.py 真正会读的 metadata key ---
#   bridge.py:261/422  conversation_id
#   bridge.py:266/427  user_id
#   bridge.py:435      selected_agent
#   bridge.py:434      v2_mode
#   bridge.py:437-438  parallel_agents
#
# --- 客户端可以合法传的（路由类）---
CLIENT_META_ALLOWED = {"selected_agent", "v2_mode", "parallel_agents"}
# --- 必须服务端生成的（身份类），一律不进白名单 ---
SERVER_ONLY_META = {"user_id", "conversation_id"}

# 项目里真实存在的 agent 名（domain_manifest）
VALID_AGENTS = {"health_advisor", "health_records", "medication_reminder", "visit_summary"}
VALID_V2_MODES = {"single", "multi"}


def _validate_routing(metadata: dict) -> dict:
    """路由控制字段：值必须是白名单枚举，否则丢掉"""
    out = dict(metadata)
    if "selected_agent" in out and out["selected_agent"] not in VALID_AGENTS:
        out.pop("selected_agent")
    if "v2_mode" in out and out["v2_mode"] not in VALID_V2_MODES:
        out.pop("v2_mode")
    if "parallel_agents" in out:
        pa = out["parallel_agents"]
        if not isinstance(pa, list) or not all(isinstance(x, str) and x in VALID_AGENTS for x in pa):
            out.pop("parallel_agents")
    return out


def fixed_3_blacklist(body):
    """ex03 的修法3：只剔 user_id（黑名单式）"""
    metadata = body.get("metadata") or {}
    metadata = {k: v for k, v in metadata.items() if k != "user_id"}
    user_id = token_uid or body.get("user_id") or "default_user"
    a2a_metadata = {**metadata, "conversation_id": "conv_1", "user_id": user_id}
    return a2a_metadata, user_id


def fixed_4_whitelist(body):
    """ex04：白名单 + 路由字段值校验"""
    raw = body.get("metadata") or {}
    # ① 白名单过滤（key）
    metadata = {k: v for k, v in raw.items() if k in CLIENT_META_ALLOWED}
    # ② 路由字段值校验（枚举）
    metadata = _validate_routing(metadata)
    # ③ 身份只从 token 来
    user_id = token_uid or body.get("user_id") or "default_user"
    # ④ 权威值最后写
    a2a_metadata = {**metadata, "conversation_id": "conv_1", "user_id": user_id}
    return a2a_metadata, user_id


ATTACKS = {
    "A 身份-顶层": {
        "message": "我最近身体怎么样",
        "user_id": "victim_001",
    },
    "B 身份-metadata": {
        "message": "我最近身体怎么样",
        "metadata": {"user_id": "victim_001"},
    },
    "C 身份-别名": {
        "message": "我最近身体怎么样",
        "metadata": {"uid": "victim_001", "userId": "victim_001", "sub": "victim_001"},
    },
    "D 路由-指定 agent": {
        "message": "我最近身体怎么样",
        "metadata": {"selected_agent": "health_records"},
    },
    "E 路由-非法 agent": {
        "message": "我最近身体怎么样",
        "metadata": {"selected_agent": "admin_agent", "parallel_agents": ["health_records", "root"]},
    },
}

FIXES = [
    ("ex03 修法3 黑名单", fixed_3_blacklist),
    ("ex04 修法4 白名单", fixed_4_whitelist),
]


def check(a2a_metadata):
    """返回 (身份是否正确, 路由是否合法, 问题描述)"""
    problems = []
    if a2a_metadata.get("user_id") != token_uid:
        problems.append(f"越权:身份={a2a_metadata.get('user_id')}")
    sa = a2a_metadata.get("selected_agent")
    if sa is not None and sa not in VALID_AGENTS:
        problems.append(f"路由:未知agent={sa}")
    pa = a2a_metadata.get("parallel_agents")
    if pa is not None:
        bad = [x for x in pa if x not in VALID_AGENTS]
        if bad:
            problems.append(f"路由:未知agent={bad}")
    return (not problems), problems


print("判定标准：身份==attacker_001 且 路由目标都在合法 agent 列表内\n")

for fix_name, fix in FIXES:
    print("=" * 68)
    print(fix_name)
    print("-" * 68)
    for atk_name, body in ATTACKS.items():
        a2a_metadata, local_uid = fix(body)
        ok, problems = check(a2a_metadata)
        mark = "OK  " if ok else "FAIL"
        detail = "" if ok else "  <-- " + "; ".join(problems)
        print(f"  [{mark}] {atk_name:<16} metadata={json.dumps(a2a_metadata, ensure_ascii=False)}{detail}")
    print()

print("=" * 68)
print("最终 metadata 里还剩什么（修法4）")
print("-" * 68)
for atk_name, body in ATTACKS.items():
    a2a_metadata, local_uid = fixed_4_whitelist(body)
    print(f"  {atk_name}")
    print(f"    metadata = {json.dumps(a2a_metadata, ensure_ascii=False)}")
