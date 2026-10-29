# 漏洞记录

> 每发现一个漏洞，追加一行。ID 自动分配（`record.py`）。
> 详细 PoC 放 `poc/`，或 A2AServer 的 `tests/`。
> 状态：`待修` / `已修` / `已复现` / `待验证`

| ID | 漏洞 | 位置 | 根因 | 修复 | 状态 |
|----|------|------|------|------|------|
| F-001 | body.user_id 覆盖 token → 越权读他人健康档案 | api.py:5291 | 请求体参与安全决策 | token 优先，`or` 顺序反转 | 已修 |
| F-002 | body.metadata.user_id 覆盖 → 绕过 F-001 的修复 | api.py:5309-5314 | `**metadata` 展开在 user_id 之后 | 边界剥离 + 权威值后写 | 待修 |
| F-003 | body.metadata 任意字段透传进 agent 元数据 | api.py:5292 | 未做字段白名单 | 白名单过滤 | 待修 |
| F-004 | A2A 请求 metadata.user_id 覆盖 JWT 派生身份 | server.py:127 | 同 F-001 的第二个副本 | JWT 优先 | 待确认 |
| F-005 | JWT 密钥硬编码兜底，漏配即等于无鉴权 | health_records_api.py:223, server.py:106 | 兜底值是字面量占位符 | 缺失即启动失败 | 待修 |
| F-006 | 授权表 default-allow，未命中即 guest | tool_permissions.py:94 | 授权默认值取最宽 | 默认取最严 | 待修 |
| F-007 | check_permission 未接入 MCP 工具调用链 | registry.py:202（唯一调用点） | 控制点覆盖率不足 | 接到执行链路 | 待修 |
| F-008 | user_id 只在缺失时注入，模型填错值则放行 | mcp_tool_adapter.py:557-564 | 优先级把不可信来源排最前 | 无条件覆盖 | 待修 |
| F-009 | analyze_symptoms 空 user_id 时返回全表数据 | diagnosis_tool.py:179-197 | WHERE 条件可选，fail-open | user_id 为空即拒绝 | 待修 |
| F-010 | 身份存于 os.environ / module 全局，并发串号 | server.py:111, v2_agent.py:423, mcp_tool_adapter.py:104 | 请求级状态存进程级 | 改 ContextVar + 读不到即报错 | 待修 |
| F-011 | selected_agent 等路由字段客户端可指定 → 自选 agent 触达更大工具集 | api.py:5293-5294, bridge.py:435-438 | 路由控制字段无枚举校验；与 F-007 组合成完整提权链 | 白名单+枚举校验，收口客户端可控输入 | 待修 |
| F-012 | metadata 白名单过滤点覆盖不全：body.selected_agent 绕过过滤 | api.py:5292-5294 | 过滤与添加分离，存在未受控入口 | 改为收口组装（单一入口） | 待修 |
