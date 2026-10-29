# LLM 安全学习路线 · 以真实项目为靶场

> 起点：智能体工程师　　目标：大模型安全方向（Agent 安全 / AI 红队 / 护栏工程 / 供应链安全）
>
> **本仓库是持续更新的学习档案**：漏洞记录、概念笔记、可复现 PoC 全部留档。
> 每个模块学完提交一次，`git log` 就是这个学习过程的叙事线。

---

## 🎯 靶场：本仓库所有攻击的落点

所有 PoC 都在一个**真实的、多智能体的生产级项目**上打，不是玩具靶场。

| | |
|---|---|
| **项目** | 个人智能健康助手（PHA） |
| **GitHub** | <https://github.com/13139531101/Multi-Intelligence-Medical-Companion> |
| **取证分支** | `security-lab` |
| **本地** | `I:\A2A\3\A2AServer`（worktree: `I:\A2A\3\A2AServer-sec`） |
| **形态** | FastAPI + LangGraph · MCP 工具层 · A2A agent 间委托 · AG-UI 界面操控 · PostgreSQL+pgvector · Redis · React |

**为什么用它当靶场** —— 它天然具备学习所需的全部要素：

| 靶场要件 | 本项目对应 | 攻击类型 |
|---|---|---|
| 敏感私有数据 | 健康档案（PHI，最高敏感级） | 越权读取 / 数据外泄 |
| 真实工具面 | 70 个 MCP 工具，按 agent 隔离加载 | 工具越权、参数注入 |
| 长期记忆 + RAG | `AgentMemorySystem`、多跳 Magnetic RAG、KG | 记忆投毒、RAG 投毒 |
| 多智能体委托 | A2A + ANP（DID:WBA / Ed25519） | 信任传递、权限放大 |
| MCP 供应链 | 每 agent 一个 MCP 子进程，运行时生成 starter | 工具投毒、供应链 |
| 不可信内容入口 | 上传管线、CRAG 联网检索、RAG 文档 | 间接提示注入 |
| 界面操控面 | AG-UI 驱动前端动作（`openRecord`/`setData`） | 提示注入 → 界面操纵 |

**它还有一个绝大多数同类项目没有的攻击面**：AI 能直接操作前端界面。
提示注入不只是"骗出数据"，还能**操纵界面**——这条链在公开资料里几乎没人讲。

> ⚠️ **所有 PoC 仅用于本人项目的安全学习与加固。**
> 涉及真实健康数据的一切内容均为演示用假数据；修复方案以 PR / 补丁形式回流到上游仓库。

---

## 🔬 证据链：一份漏洞怎么变成可复现的证据

初学者常见做法是：写个 `exploit.py` 演示一下，然后写个"已修复"。

问题在于——**没有红状态的测试证明不了任何修复**。它可能只是在测一个恒真的东西。
所以这里每个漏洞都留一对 git tag，两端跑**同一条命令**：

```bash
git clone https://github.com/13139531101/Multi-Intelligence-Medical-Companion
cd Multi-Intelligence-Medical-Companion

git checkout vuln-001  && python tests/security/test_authz_idor.py   # 红：漏洞真实存在
git checkout fixed-001 && python tests/security/test_authz_idor.py   # 绿：修复真的有效
```

| tag | 指向 | 结果 | 含义 |
|-----|------|------|------|
| `vuln-001` | 未修复代码 + 红测试 | 4/5 FAIL | 漏洞真实存在 |
| `fixed-001` | 修复后代码 + **同一份**测试 | 5/5 PASS | 修复真的有效 |

**为什么用 tag 而不是三个分支/三个副本**

| 做法 | 问题 |
|---|---|
| 三份代码副本 | 三倍维护 + 漂移；修复版一改，靶场版就对不上；看起来像三个不相关的项目 |
| 三个长期分支 | 同样会漂移；"原始靶场"分支冻结后没法回溯新漏洞 |
| **tag 对（采用）** | 三种状态是**一个项目的三个时间点**；`git log` 本身就是叙事线 |

tag 还能顺带解决"靶场必须永远可打"：所有 `vuln-XXX` tag 的集合，
就是随时可 checkout 回来重放攻击的原始靶场。

**CI 里也留着这次红→绿**：workflow 配了 `tags: ['vuln-*', 'fixed-*']`，
推 tag 会触发 CI，于是 [Actions 历史](https://github.com/13139531101/Multi-Intelligence-Medical-Companion/actions)
里能直接看到"修复前红 / 修复后绿"，而不是只有一句"已修复"。

修复本身还必须**进 CI 阻塞门禁**（`continue-on-error: false`）：
> 修复没有门禁等于没修。下一个人随手加个 `**metadata`，洞就重开，而且没人会发现。

---

## 📊 学习进度

| 模块 | 主题 | 状态 |
|---|---|---|
| **M0** | 安全的第一性原理（资产 / 信任边界 / 最小权限 / fail-open vs fail-closed） | ✅ 完成 |
| **M1** | 认证与授权：身份三层模型（Subject / On-behalf-of / Asserted） | ✅ 完成 · 13 条漏洞 · 22 条概念 · 1 组 tag 对 |
| **M2** | 间接提示注入与 Lethal Trifecta | ⬜ 未开始 |
| **M3** | 工具调用安全与权限三层模型 | ⬜ 未开始 |
| **M4** | 记忆与 RAG 投毒 | ⬜ 未开始 |
| **M5** | 多智能体信任传递 | ⬜ 未开始 |
| **M6** | 供应链：MCP 安全 | ⬜ 未开始 |
| **M7** | 红队方法论与评测 | ⬜ 未开始 |
| **M8** | 护栏工程与量化 | ⬜ 未开始 |

**当前产出**：[findings.md](findings.md) 13 条漏洞 · [notes.md](notes.md) 22 条概念 · [exercises/](exercises/) 4 个可复现脚本

---

## 🚀 快速开始

```bash
# ① 跑第一个练习：亲手构造一次越权访问
cd exercises
PYTHONIOENCODING=utf-8 "I:/A2A/3/A2AServer/.venv/Scripts/python.exe" ex01_idor.py

# ② 跑真实靶场的门禁（此刻在 security-lab 分支上应该是绿的）
cd ../Multi-Intelligence-Medical-Companion
PYTHONIOENCODING=utf-8 "I:/A2A/3/A2AServer/.venv/Scripts/python.exe" tests/security/test_authz_idor.py

# ③ 回到漏洞那一刻，看它变红
git checkout vuln-001 && python tests/security/test_authz_idor.py   # 4/5 FAIL
git checkout security-lab
```

`exercises/` 是一条**递进的链**，不是四个独立练习：

```
ex01  越权存在        → 理解「请求体参与安全决策」
ex02  一个修复不够    → 理解「修复要覆盖所有入口」
ex03  三种修法对比    → 理解「覆盖 vs 丢弃」
ex04  白名单 + 收口   → 理解「key 白名单 + 值枚举」两道防线
```

---

## 🧾 记录方式

一条命令记一个漏洞 / 一个概念，ID 自动分配：

```bash
cd <本仓库>
python record.py finding --title "越权读他人档案" --where "api.py:5291" \
                         --root "请求体参与安全决策" --fix "token 优先" \
                         --tag vuln-001/fixed-001
python record.py note --text "fail-open 是根本性错误，因为它是静默的" --tag M1
python record.py show          # 看进度
```

> 记录成本必须低到不烦人 —— 所以是一行表格 + 一条命令。
> `findings.md` 是未来"漏洞报告合集"的雏形，`notes.md` 是技术博客的选题库。
> `--tag` 记证据 tag 对 —— **填了 tag 的「已修」才算数**。

---

## 📁 目录结构

```
llm-security-roadmap/
├── README.md              ← 本文件
├── findings.md            ← 漏洞表（一行一个，ID 自动分配，含证据 tag）
├── notes.md               ← 概念笔记（一行一个）
├── record.py              ← 记录工具
├── exercises/             ← 可复现脚本
│   ├── ex01_idor.py               越权最小复现
│   ├── ex02_metadata_bypass.py   第二个入口
│   ├── ex03_fix.py                三种修法对比
│   └── ex04_whitelist.py          白名单 + 收口
├── 学习清单.md            ← P0–P3 知识点地图
└── 项目清单.md            ← 12 个动手项目
```

靶场侧（`Multi-Intelligence-Medical-Companion` 的 `security-lab` 分支）：

```
tests/security/
├── README.md                   ← 安全门禁的规矩 + 红绿对照怎么读
└── test_authz_idor.py          ← 越权门禁（纯标准库，0.27 秒，可进 CI 阻塞）
backend/A2AServer/src/A2AServer/v2/
└── request_identity.py         ← 请求身份的唯一收口点（零依赖纯函数）
```

---

## 🧭 总体策略

**以 Agent 安全为主干，红队能力做差异化，护栏工程保就业面，供应链与合规作为知识补充。**

理由是：最不可替代的资产是"懂 agent 编排链路"。这条链路上的攻击面（工具调用、记忆、
多智能体信任传递、MCP/插件）恰好是当前工业界人才最稀缺、公开资料最少、且短时间内不会被
自动化掉的细分。护栏工程岗位数量最多，用来保底投递量；红队与评测能力决定技术品牌和议价能力。

---

## 🎯 四方向定位表

| 方向 | 核心要解决的问题 | 可迁移的既有能力 | 典型岗位 |
|---|---|---|---|
| 1. Agent / 工具调用安全 | 工具越权、间接注入、记忆投毒、多智能体信任传递 | 编排链路、tool schema、状态管理、沙箱 | AI 安全工程师、Agent 平台安全 |
| 2. AI 红队 / 对抗评测 | 越狱、注入、多轮诱导、多模态绕过、评测基准 | 自动化流程搭建、评测框架、数据构造 | AI Red Team、安全研究员 |
| 3. 护栏与风控工程 | 输入输出过滤、策略引擎、误杀/漏杀调优 | 服务端工程、分类器调用、性能与链路 | 内容安全算法、风控平台 |
| 4. 模型供应链与基础设施 | 模型文件、推理服务暴露面、RAG 投毒、权重窃取 | MLOps、容器/K8s、云原生安全 | 云安全、AI Infra 安全 |

边缘但值得关注：模型水印与深度伪造检测、隐私（成员推断/差分隐私）、AI 治理合规。

---

## 📋 阶段划分（按产出物驱动，不按时间）

| 阶段 | 主题 | 出口条件（Must） |
|---|---|---|
| **P0 地基** | 威胁框架 + 威胁建模 | 能把一个真实 agent 系统按 OWASP LLM Top10 / Agentic Threats 逐条映射出风险清单 |
| **P1 核心** | 攻击面动手实操 | 手写 PoC 复现 ≥3 类真实攻击（直接注入、间接注入、工具越权） |
| **P2 平台化** | 自动化评测流水线 | 有一套自己的"攻击生成→执行→判定→报告"闭环 |
| **P3 差异化** | 选一个点做深 | 有公开输出：开源工具 / 技术博客 / 演讲 / 论文 / CVE |
| **P4 求职** | 作品集 + 面试 | 作品集仓库 + 漏洞报告合集 + 能讲清 3 个案例的完整链路 |

---

## 📖 文件说明

- [findings.md](findings.md) — 漏洞记录表（持续追加，含证据 tag）
- [notes.md](notes.md) — 概念笔记（持续追加）
- [record.py](record.py) — 记录工具
- [exercises/](exercises/) — 可复现脚本
- [学习清单.md](学习清单.md) — 按 P0–P3 分阶段的知识点、必读资源与自检问题
- [项目清单.md](项目清单.md) — 12 个动手项目，含技术栈、验收标准、作品集价值

---

## 🔁 使用方式

1. **先过一遍学习清单 P0**，把威胁框架抄成一张自己的 check 表
2. **每个模块按「概念讲解 → 对照靶场代码 → 自检题 → 动手任务」四步走**，答完自检题再进下一模块
3. **每完成一个模块**，回来把学习清单对应条目标记完成，并补上"我当时不知道但现在知道了"的一行
4. **发现漏洞立刻记**，不管修没修 —— `findings.md` 是作品集的骨架
5. **修完必须留证据**：测试先红 → 修 → 绿 → 打 `vuln-XXX`/`fixed-XXX` tag 对 → 接进 CI 门禁
6. **P2 之后开始公开输出，不要等"准备好"**
