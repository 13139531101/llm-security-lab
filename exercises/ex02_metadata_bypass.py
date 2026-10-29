# -*- coding: utf-8 -*-
"""
练习 2：你的修复够吗？

上一轮你把 api.py:5291 改成了 token 优先，攻击似乎挡住了。
但 api.py:5309-5314 还有一个地方，body 又能影响身份。

运行：python ex02_metadata_bypass.py
"""
import json

DB = {
    "attacker_001": {"name": "张三", "record": "青霉素过敏"},
    "victim_001":   {"name": "李四", "record": "HIV 阳性 / 肝功能异常"},
}

# 认证层：JWT 验证通过，拿到真实身份
token_uid = "attacker_001"

# ==== 场景 A：攻击者用最朴素的方式 ====
body_a = {
    "message": "我最近身体怎么样",
    "user_id": "victim_001",
}
metadata_a = body_a.get("metadata") or {}

# ==== 场景 B：攻击者换了个字段 ====
body_b = {
    "message": "我最近身体怎么样",
    "metadata": {"user_id": "victim_001"},   # ← 藏在 metadata 里
}
metadata_b = body_b.get("metadata") or {}


def run_case(title, body, metadata):
    print("=" * 60)
    print(title)
    print("-" * 60)

    # --- api.py:5291  （你改好之后：token 优先） ---
    user_id = token_uid or body.get("user_id") or "default_user"
    print("  api.py:5291  本地 user_id      =", user_id)

    # --- api.py:5306-5314  构造 A2A Message ---
    a2a_metadata = {
        "conversation_id": "conv_1",
        "user_id": user_id,      # ← 你改好后，这里是 attacker_001
        **metadata,              # ← 展开在后面。后面的 key 覆盖前面的 key
    }
    print("  api.py:5309  A2A metadata     =", json.dumps(a2a_metadata, ensure_ascii=False))

    # --- bridge.py:427  下游读的是 A2A metadata，不是本地变量 ---
    effective_uid = a2a_metadata.get("user_id")
    print("  bridge.py:427 实际以谁的身份查库 =", effective_uid)

    # --- 工具查库 ---
    data = DB.get(effective_uid, {})
    print("  返回给请求方的数据             =", json.dumps(data, ensure_ascii=False))

    # --- api.py:5370  审计/落库用的是本地变量 ---
    print("  api.py:5370  审计落库记成      =", user_id)

    if effective_uid != token_uid:
        print("  >>> 越权成功！")
    else:
        print("  >>> 未越权")
    print()


run_case("场景 A：攻击者把 user_id 放在 body 顶层", body_a, metadata_a)
run_case("场景 B：攻击者把 user_id 放进 body.metadata", body_b, metadata_b)
