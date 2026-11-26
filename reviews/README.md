# reviews/ · 遗忘曲线本身

这个目录由 `exercises/ex10_review.py` 生成，**每次复习都会变**。

| 文件 | 是什么 |
|---|---|
| `state.json` | 每道题的复习状态：阶段（stage）、上次得分、下次到期日、连续答错次数 |
| `日志.md` | 每次复习的流水：抽了哪几道、漏了哪条判据、什么时候排到下次 |

## 要不要提交？

**建议提交。** 理由和这个仓库别的东西一样 —— **没失败过的题不算验证过**：

- `日志.md` 就是你的「红→绿」记录。三个月后回看，能看到哪几道题你反复答漏。
  那是**你没真正掌握**的清单，比任何自评都准。
- `state.json` 是排期状态机。提交它 = 把「我今天复习了什么」也留进 git 时间轴，
  `git log` 就同时是学习档案和遗忘档案。
- 不提交也行 —— 加进 `.gitignore` 即可，脚本一样跑。
  但那就丢掉了「遗忘曲线可回溯」这一条。

> 复习节奏建议：**每天 15 分钟**。脚本默认抽 5 道题 + 2 张卡，跨模块交错。
> 一天一次比周末补 2 小时有效得多 —— 间隔效应靠的是**间隔**，不是**时长**。

## 怎么用

```bash
cd I:/llm-security-roadmap

# 日常：抽题 → 先答后看 → 自动排期
PYTHONIOENCODING=utf-8 "I:/A2A/3/A2AServer/.venv/Scripts/python.exe" exercises/ex10_review.py

# 今天该复习什么（答漏的排最前）
PYTHONIOENCODING=utf-8 "I:/A2A/3/A2AServer/.venv/Scripts/python.exe" exercises/ex10_review.py status

# 留存率 / 阶段分布 / 一直在忘的那几张
PYTHONIOENCODING=utf-8 "I:/A2A/3/A2AServer/.venv/Scripts/python.exe" exercises/ex10_review.py stats
```

**「已记住」的定义**：连续两次全对 **且** 阶段 ≥ 4。
按我们自己的规矩 —— 没失败过的题不算验证过 —— 所以脚本**故意**把答漏的题
永远顶到最前面，而不是把它们收进「已掌握」区。

**判分是逐条判的，不是整题对错**：一道题有 4 条判据，答对 3 条算「部分」，
下次间隔缩短并强制重现；一条不中就回到更早的阶段。这是为了防「知道个大概就以为会了」。
