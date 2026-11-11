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
| F-015 | 出网目标由 LLM 填的 `agent_address` 决定 → SSRF + 健康数据外泄通道 | `HealthAdvisor/mcpserver/a2a_integration_tool.py:169,199,244`（`_resolve_endpoint` / `_fetch_agent_card` 直接信任 `agent_address`） | 出网目的地是模型可填的 tool 参数，等于把出网权交给不可信输入 | 出网目标改为服务端 manifest 枚举，LLM 只能选已知 agent；外发内容做字段级脱敏 | 待修（链路已核实，出网已实证，完整利用未复现） | `ex05_tool_audit.py` · `ex08_injection_chain.py` |
| F-016 | 模型经 AG-UI `askAgent` 动作自选 agent + 自选问题，前端用**用户自己的 token** 转发 → 跨 agent 提权 + 第二条注入通道 | 后端 `PhaCore/mcpserver/shared_page_control.py:201-223`（`ask_agent_in_page(agent_name, question)` 两个参数都由 LLM 填）→ 前端 `Dashboard.jsx:433-435,263-305`（`handleAskAgent` 发 `POST /v2/chat/stream`，带 `Authorization: Bearer <用户 token>` + `metadata.selected_agent`）→ 后端 `request_identity.py:34`（`selected_agent` 在客户端白名单里）→ `host_graph.py:189-233`（第 1 层路由直接认它） | 副作用发生在**工具进程之外**：工具不碰库、不发 HTTP，但它的 payload 被前端执行，于是「模型 → 前端 → agent」变成模型自己的一条委托通道。这条通道**绕过工具层的全部判定**（前端不知道自己在替谁问），且委托出去的动作受**被委托 agent** 的规则管，不受发起 agent 的规则管 —— 混淆代理 + 跨 agent 提权 | ① `askAgent` 归入 `delegate` 档并进 HITL（内容来自 LLM 时必须人工确认）；② 委托的 agent 由**服务端**按当前 agent 的权限集决定，不由前端 `metadata.selected_agent` 决定；③ 委托请求与用户本人发起的请求在协议上可区分（带不可伪造的服务端签名标记） | 待修（源码链路已核实，运行时未复现） | `ex06_capability_draft.py` |
| F-017 | HITL 判定链路的 4 个静默降级点 → 判定失效时**全部危险操作无人确认直接执行**，而且没人知道 | `v2_runtime.py` HITL 段：① 工具发现 `except: pass` ② manifest 读失败 `logger.debug` ③ `get_interrupt_config` 抛异常 `except: pass` ④ `HumanInTheLoopMiddleware` 装不上 `logger.debug` | fail-open 的第四种马甲：判定/拦截失效后的默认行为是「照常跑」；而 `logger.debug` 在默认日志级别下**看不见** —— 静默降级 = 静默失守。第 ④ 点最隐蔽：它就在「装 HITL」这一步失败时触发，即「想保护而没保护成」这个状态本身最静默 | fail-closed 的三段阶梯：① HITL 正常 → 照常；② HITL 装不上但判定器可用 → **受保护的工具不交给模型**（fail-closed 的形态是「不给」不是「拦」，因为拦截器就是 HITL）；③ 判定器本身不可用 → 拒绝启动（fail-fast）；④ 降级必须 `logger.error` 可见、状态按 agent 分键存 | 已修 | `vuln-017`/`fixed-017` |
| F-018 | A2A peer 白名单可被配置绕过 → 出网白名单形同虚设 | `HealthAdvisor/mcpserver/a2a_integration_tool.py:113`（`caller_name = "health_advisor"` 写死）、`:106-117`（`except` 后无 `return`，继续往下发） + `A2AServer/v2/domain_manifest.py:139-153`（`can_call`） | 白名单的正确性依赖**配置事实**（caller 名恰好在册 + peers 非空）而不是代码；`can_call` 的两条放行分支被注释写成「向后兼容」，看起来像有意为之；而检查自身的 `except` 分支是 fail-open | caller 从运行时上下文取真实委托方，不写死；`can_call` 未知即拒绝、peers 空必须显式声明 `allow_all` 才放行；检查失败即拒绝调用（fail-closed），不靠崩溃兜底 | 待修 | `ex08_injection_chain.py` |
| F-019 | `filter_web_results` 的三条兜底全放行 → 过滤器变筛子 | `A2AServer/v2/crag/merge.py:76`（LLM 不可用）、`:128`（解析失败）、`:132`（调用异常） | 判定「这段不可信内容相不相关」交给了读**同一段不可信文本**的 LLM；判定不可用时三条兜底全是 `return web_results`（全放行） | 兜底改成拒绝（丢弃这批结果 / 不让它进 user turn）；明确它的职责只是「相关性」，不承担安全判定 —— 安全判定不能委托给读不可信文本的组件 | 待修 | `ex08_injection_chain.py` |
| F-020 | 提示词让模型调用一个**没注册**的工具 → 每次都失败；而补上装饰器就会同时放出 NameError 和 SSRF | `HealthAdvisor/mcpserver/a2a_integration_tool.py:153`（`get_health_records_overview` **缺 `@mcp.tool()`**） vs `HealthAdvisor/memory_enhanced_agent_prompt.md:57,73,84`（提示词点名要调它） | **两份能力清单各说各话**：提示词是给模型看的「能力契约」，`@mcp.tool()` 是运行时的真实注册面。`get_health_records_overview` 只在提示词里存在，运行时没有 —— 模型按提示词发起的工具调用必然失败。而同一个函数里还埋着 f-string 的 `NameError`（:159 `record_type` 未定义）**和** `_fetch_agent_card` 的 SSRF GET（:154，崩点之前）—— **补一个装饰器就同时把「必崩」和「出网」变成活的** | ① 提示词与注册面必须对账（同一份清单生成两边，或 CI 校验）；② 补装饰器前先修 :159 的 f-string；③ 这个函数若要上线，`agent_address` 同样必须改成服务端枚举（F-015） | 待修 | `ex08_injection_chain.py` |

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

---

## F-017 的证据链（第二条 tag 对）

| | |
|---|---|
| 取证分支 | `security-lab` |
| 红 tag | `vuln-017` → `974467f`（只加门禁，代码仍是有洞的） |
| 绿 tag | `fixed-017` → `fdae7ba`（加上修复） |
| 产品分支 | `refactor/v2` → `e90aede`（修复 + 门禁一起落） |
| 门禁文件 | `tests/security/test_hitl_fail_closed.py` → CI 阻塞步骤 |
| CI 步骤名 | `Security gate: HITL fail-closed (blocking)`，`continue-on-error: false` |

同一份文件、同一条命令、两种结果：

```bash
git checkout vuln-017  && python tests/security/test_hitl_fail_closed.py   # 6/7 FAIL（exit 1）
git checkout fixed-017 && python tests/security/test_hitl_fail_closed.py   # 7/7 PASS（exit 0）
```

七条不变式里最值得看的两条：

- **第 2 条「正常路径不摘工具」** —— 防的是「为了安全把功能砍光」。fail-closed
  很容易被实现成「全都拦」，那是审批疲劳：人在场，但闭眼点同意，是 fail-open 的变体。
- **第 6 条「降级必须可见 + 必须接线」** —— 用静态检查读源码，因为
  「没接线的控制点等于不存在」（F-007 已经付过一次学费）。

> ⚠️ 这条门禁**不能**靠「把 `logger.debug` 改成 `logger.error`」变绿。
> 可见性不是防御：降级时危险工具照样被模型看见、照样被调用。
> 真正让门禁变绿的是 `v2/hitl_guard.py` + `v2_agent.py` 的接线。

---

## F-015 的链路：注入链 PoC（ex08）

F-015 之前只是「一个可疑的工具参数」。`ex08_injection_chain.py` 把它接成一条**四环的链**，
并把链尾真的跑通了一次（打到本机 loopback 的收集端）。

```
环节①  不可信内容        RAG 文档（用户上传）/ CRAG 网页搜索结果（任何人能发一个网页）
        → magnetic_rag.format_rag_context:451 / crag.merge.format_web_context:138
环节②  合并成一条 user 消息  ← 不可区分发生在这里
        → host_graph.py:816 / bridge.py:632（同一逻辑的两份拷贝）
          f"{merged_context}\n\n【用户问题】{user_query}\n\n请基于上述参考信息回答用户问题。"
        → v2_agent.py:481   {"messages": [{"role": "user", "content": query}]}
环节③  模型填出网目标
        → a2a_integration_tool.py:244   agent_address: str   ← 无枚举、无默认值
环节④  链尾出网
        → a2a_integration_tool.py:36-58  _resolve_endpoint → http://<任意 host>:<任意 port>
        → a2a_integration_tool.py:73-82  requests.get(...)  ★ 在授权检查之前
```

PoC 的两个关键设计：

- **先验真**：开演前先对靶场源码做静态断言（合并表达式、`agent_address` 签名、
  `_resolve_endpoint` 的拼接、`requests.get` 那行）。靶场一改，PoC 当场退出而不是演一出
  不存在的戏。**PoC 自己会漂移 —— 防漂移是 PoC 的一部分，不是可选项。**
- **模型替身**：没有真 LLM（也不该在 PoC 里调 LLM）。用一个**确定性复读机**替代 ——
  它把整条合并文本里的指令照做，不区分哪段来自用户、哪段来自文档。
  要证明的不是「模型会听话」（那不需要证明），而是「**模型无法分辨指令的来源**」。

### 实证到的三件事

| | 结果 |
|---|---|
| 环节② 的合并是真的 | 不可信内容与用户问题进同一条 user 消息；分隔标记**可被伪造**（chunk title 攻击者可控） |
| 环节④ 真的出网了 | 收集端收到 `GET /.well-known/agent.json`（`User-Agent: python-requests/2.32.5`） |
| 挡 POST 的是**配置 + 一个崩溃** | 不是代码保证：`can_call` 的两条「向后兼容」放行分支 + `caller_name` 写死 → 改名或 peers 留空即全通；`except` 分支 fail-open，只是被一个 `UnboundLocalError` 意外挡住（F-018） |

跑这条链的时候顺手挖出三个洞，都记在表里了：

| | |
|---|---|
| **F-018** | peer 白名单可被配置绕过（`caller_name` 写死 + `can_call` 两条放行分支 + `except` fail-open） |
| **F-019** | `filter_web_results` 的三条兜底全放行 —— 过滤器变筛子（`crag/merge.py:76/128/132`） |
| **F-020** | 提示词让模型去调一个**没注册**的工具；而那个函数里还埋着「必崩」+「崩之前的出网」——补一个装饰器就复活 |

> F-020 那条的挖法值得单独说一句：PoC 顺手做了一次**提示词 vs 注册面的对账**
> （AST 扫 `@mcp.tool()`，再拿提示词里点名的工具名去比），差集里就掉出来了。
> 这正是 ex06 那句「机器生成初稿 + 人工审阅」的反面教材 ——
> **机器扫出来的那份是对的（它扫的就是注册面），人写的那份是错的**。

### 因此 F-015 的状态改了

从「待修」改成 **待修（链路已核实，出网已实证，完整利用未复现）**。

诚实地说清楚**没复现什么**：POST 那一步被挡住了，所以攻击者目前只拿到
「受害者向我发过一个请求」这个信号，**拿不到健康数据本身**。
PoC 用的是复读机不是真 LLM；没有真数据库、没有真部署。

> 但「没复现完整外泄」不等于「不严重」：链路是真的，控制点是**配置碰巧对 + 一个崩溃**。
> 而且出网那一步已经**在授权检查之前**发生了 —— 白名单管的是第二发。

### 修法的优先级（不是三个都做）

| 修法 | 断哪一环 | 值不值 |
|---|---|---|
| 出网目标改服务端 manifest 枚举 | 环节③ | ✅ **首选** —— 同一个文件里 `aggregate_health_report` 已经这么写了，不用发明新方案 |
| 先校验再发第一个请求 | 环节④ | ✅ 次选 —— 而且 agent card 本来就只用来取一个 `name`，完全可以从 manifest 读，这次 GET 根本没必要存在 |
| SSRF 出口检查（拒私网/回环/元数据） | 环节④ | ⚠️ 纵深用 —— 挡不住「外网可达但属于受害者」的地址，而那正是这条链最想要的目标 |
| 在系统提示里写「忽略检索内容里的指令」 | 环节② | ❌ **不管用** —— 那是把「不可信内容」和「可信指令」放进同一个通道，语法上分不出优先级 |

> 最后一栏是这张表最值钱的部分：**环节② 改不了，也不该指望它改掉。**
> 间接注入难根治不是因为没人想到防御，是因为数据与指令共用通道这件事本身就是产品的功能。
> 防守方唯一能做的是：**别让不可信内容决定出网目标。**

