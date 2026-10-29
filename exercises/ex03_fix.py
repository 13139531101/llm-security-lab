# -*- coding: utf-8 -*-
"""
练习 3：修复

场景 B 的攻击绕过了「api.py:5291 的 token 优先」修复，
因为 api.py:5309 的 dict 构造里，**metadata 展开在 user_id 后面**。

修法：两处都改
  ① 边界处（api.py:5292）：把身份字段从攻击者的 metadata 里剔掉
  ② 构造处（api.py:5309）：权威值最后写

运行：python ex03_fix.py
"""
import json

DB = {
    "attacker_001": {"name": "张三", "record": "青霉素过敏"},
    "victim_001":   {"name": "李四", "record": "HIV 阳性 / 肝功能异常"},
}
token_uid = "attacker_001"


def vulnerable(body):
    """修复前的代码（原样）"""
    metadata = body.get("metadata") or {}
    user_id = token_uid or body.get("user_id") or "default_user"
    a2a_metadata = {"conversation_id": "conv_1", "user_id": user_id, **metadata}
    return a2a_metadata, user_id


def fixed_1_reorder(body):
    """修法1：只调顺序，权威值最后写"""
    metadata = body.get("metadata") or {}
    user_id = token_uid or body.get("user_id") or "default_user"
    a2a_metadata = {**metadata, "conversation_id": "conv_1", "user_id": user_id}
    return a2a_metadata, user_id


def fixed_2_strip_only(body):
    """修法2：只剔字段，顺序不动"""
    metadata = body.get("metadata") or {}
    metadata = {k: v for k, v in metadata.items() if k != "user_id"}
    user_id = token_uid or body.get("user_id") or "default_user"
    a2a_metadata = {"conversation_id": "conv_1", "user_id": user_id, **metadata}
    return a2a_metadata, user_id


def fixed_3_both(body):
    """修法3：两个都做（推荐）"""
    metadata = body.get("metadata") or {}
    metadata = {k: v for k, v in metadata.items() if k != "user_id"}   # ①
    user_id = token_uid or body.get("user_id") or "default_user"
    a2a_metadata = {**metadata, "conversation_id": "conv_1", "user_id": user_id}  # ②
    return a2a_metadata, user_id


ATTACKS = {
    "A: user_id 在 body 顶层": {
        "message": "我最近身体怎么样",
        "user_id": "victim_001",
    },
    "B: user_id 在 body.metadata": {
        "message": "我最近身体怎么样",
        "metadata": {"user_id": "victim_001"},
    },
    "C: 攻击者想用别的字段名冒充": {
        "message": "我最近身体怎么样",
        "metadata": {"uid": "victim_001", "userId": "victim_001", "sub": "victim_001"},
    },
}

FIXES = [
    ("修复前", vulnerable),
    ("修法1 只调顺序", fixed_1_reorder),
    ("修法2 只剔字段", fixed_2_strip_only),
    ("修法3 两者都做", fixed_3_both),
]

print("判定标准：实际以谁的身份查库 == attacker_001 才算通过\n")

for fix_name, fix in FIXES:
    print("=" * 62)
    print(fix_name)
    print("-" * 62)
    for atk_name, body in ATTACKS.items():
        a2a_metadata, local_uid = fix(body)
        effective = a2a_metadata.get("user_id")
        ok = (effective == token_uid)
        mark = "OK  " if ok else "FAIL"
        print(f"  [{mark}] {atk_name:<28} 实际身份={effective}")
    print()


print("=" * 62)
print("修法3 细节展开（看元数据最终长什么样）")
print("-" * 62)
for atk_name, body in ATTACKS.items():
    a2a_metadata, local_uid = fixed_3_both(body)
    print(f"  {atk_name}")
    print(f"    最终 A2A metadata = {json.dumps(a2a_metadata, ensure_ascii=False)}")
    print(f"    审计落库记成     = {local_uid}")
    print()
