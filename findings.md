# 漏洞记录

> 每发现一个漏洞，追加一行。ID 自动分配（`record.py`）。
> 详细 PoC 放 A2AServer 的 `tests/security/`。
> 状态：`待修` / `已修` / `已复现` / `待确认`
> 证据：对应的 git tag 对（`vuln-XXX` 红 / `fixed-XXX` 绿）——没有证据标签的「已修」等于没修。

**靶场**：<https://github.com/13139531101/Multi-Intelligence-Medical-Companion>（分支 `security-lab`）

| ID | 漏洞 | 位置 | 根因 | 修复 | 状态 | 证据 |
|----|------|------|------|------|------|------|
| F-001 | body.user_id 覆盖 token → 越权读他人健康档案 | api.py:5291 | 请求体参与安全决策 | 身份只从 token 取，收口到 `request_identity` | 已修 | `vuln-001`/`fixed-001` |
| F-002 | body.metadata.user_id 覆盖 → 绕过 F-001 的修复 | api.py:5309-5314 | `**metadata` 展开在 user_id 之后 | 服务端字段最后写入（客户端在前） | 已修 | `vuln-001`/`fixed-001` |
| F-003 | body.metadata 任意字段透传进 agent 元数据 | api.py:5292 | 未做字段白名单 | key 白名单（只放行下游真会读的 3 个） | 已修 | `vuln-001`/`fixed-001` |
| F-004 | A2A 请求 metadata.user_id 覆盖 JWT 派生身份 | server.py:127 | 同 F-001 的第二个副本 | JWT 优先 | 待确认 | - |
| F-005 | JWT 密钥硬编码兜底，漏配即等于无鉴权 | health_records_api.py:223, server.py:106 | 兜底值是字面量占位符 | 缺失即启动失败 | 待修 | - |
| F-006 | 授权表 default-allow，未命中即 guest | tool_permissions.py:94 | 授权默认值取最宽 | 默认取最严 | 待修 | - |
| F-007 | check_permission 未接入 MCP 工具调用链 | registry.py:202（唯一调用点） | 控制点覆盖率不足 | 接到执行链路 | 待修 | - |
| F-008 | user_id 只在缺失时注入，模型填错值则放行 | mcp_tool_adapter.py:557-564 | 优先级把不可信来源排最前 | 无条件覆盖 | 待修 | - |
| F-009 | analyze_symptoms 空 user_id 时返回全表数据 | diagnosis_tool.py:179-197 | WHERE 条件可选，fail-open | user_id 为空即拒绝 | 待修 | - |
| F-010 | 身份存于 os.environ / module 全局，并发串号 | server.py:111, v2_agent.py:423, mcp_tool_adapter.py:104 | 请求级状态存进程级 | 改 ContextVar + 读不到即报错 | 待修 | - |
| F-011 | selected_agent 等路由字段客户端可指定 → 自选 agent 触达更大工具集 | api.py:5293-5294, bridge.py:435-438 | 路由控制字段无枚举校验；与 F-007 组合成完整提权链 | 取值按运行时 domain manifest 枚举校验，与 F-007 一起修 | 待修 | - |
| F-012 | metadata 白名单过滤点覆盖不全：body.selected_agent 绕过过滤 | api.py:5292-5294 | 过滤与添加分离，存在未受控入口 | 改为收口组装（单一入口） | 已修 | `vuln-001`/`fixed-001` |
| F-013 | conversation_id 客户端可控 → 越权覆盖他人会话的 answer | api.py:5288, 5381 + `consultations` ON CONFLICT | 把客户端可控的值当成授权凭据 | 写入前校验会话归属；或服务端生成不可猜测的 session id | 待修 | - |
| F-014 | HITL 危险判定漏项：`log_medication_taken` / `add_health_reminder` / `create_user_profile` 不被拦 | `dangerous_tools.py:23-37`（关键字判定）+ `:83`（`if cfg: return cfg` 吞掉硬编码兜底表） | 危险判定靠工具名子串匹配；manifest 分支与硬编码兜底表互斥而非合并 | 改成显式能力声明（工具自己声明 writes/egress），默认最严；manifest 与兜底表**合并**而不是互斥 | 待修 | `ex05_tool_audit.py` |
| F-015 | 出网目标由 LLM 填的 `agent_address` 决定 → SSRF + 健康数据外泄通道 | `HealthAdvisor/mcpserver/a2a_integration_tool.py:169,199,244`（`_resolve_endpoint` / `_fetch_agent_card` 直接信任 `agent_address`） | 出网目的地是模型可填的 tool 参数，等于把出网权交给不可信输入 | 出网目标改为服务端 manifest 枚举，LLM 只能选已知 agent；外发内容做字段级脱敏 | 待修 | `ex05_tool_audit.py` |

---

## 证据链怎么读

每个漏洞留一对 tag，同一份测试文件、同一条命令、两种结果：

```bash
git checkout vuln-001  && python tests/security/test_authz_idor.py   # 红：证明漏洞真实存在
git checkout fixed-001 && python tests/security/test_authz_idor.py   # 绿：证明修复真的有效
```

一个**从来没有红过**的测试不能证明任何修复——它可能只是在测一个恒真的东西。

| tag | 指向 | 测试结果 | 含义 |
|-----|------|---------|------|
| `vuln-001` | 等价重构后的**未修复**代码 + 红测试 | 4/5 FAIL | 漏洞真实存在 |
| `fixed-001` | 修复后的代码 + 同一份测试 | 5/5 PASS | 修复真的有效 |

CI 里配了 `tags: ['vuln-*', 'fixed-*']`，所以 **Actions 历史里也留着这次红→绿**。

> F-001/F-002/F-003/F-012 是同一处根因的四个切面，在一次修复里一起关掉了——
> 因为它们都由同一个「请求体参与安全决策」的错误造成，分开修没有意义。

---

## 修复落到产品分支了

修复不能只活在取证分支上。2026-11-01，修复已 cherry-pick 回 **`refactor/v2`**（产品分支）：

| | |
|---|---|
| 修复提交 | `75f71c8` fix(security): 身份只来自已验证的 token |
| 收口模块 | `A2AServer/v2/request_identity.py`（零依赖纯函数） |
| 门禁 | `tests/security/test_authz_idor.py` → CI 阻塞步骤 |
| CI 运行 | [Test (15 verify scripts) · success](https://github.com/13139531101/Multi-Intelligence-Medical-Companion/actions/runs/41296576820) |

产品分支上的门禁步骤：`Security gate: IDOR / identity (blocking)`，`continue-on-error: false`。
**下一个人随手加个 `**metadata`，CI 会当场红给他看** —— 这才叫修复完成。

产品分支上同样跑过一次本地红→绿对照（同一份门禁、两种状态）：

```
vuln-001  → 4/5 FAIL（exit 1）  漏洞真实存在
refactor/v2 → 5/5 PASS（exit 0）  修复真的有效
```

> 取证在 `security-lab` 分支的 tag 对上，落地在 `refactor/v2` 的提交上。
> 两件事分开做：前者证明「洞是真的、修的真的有用」，后者让洞在产品里真的关上。
