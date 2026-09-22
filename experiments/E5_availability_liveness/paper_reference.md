# E5 论文原文定位

## 位置

- 主位置：`Paper1_Revised_Full_EN (5).pdf`, §6.9, p. 29
- 安全声明：P1/P2
- 支撑位置：§5.10

## 原文摘录

> each independent holder refuses to respond with probability alpha;

> an organization or all holders are simultaneously offline;

> an evidence provider returns incorrect, stale, or forged evidence;

> evidence becomes available before TTL expiry and, separately, after TTL
> expiry.

> every retrieval failure produces EVIDENCE_UNAVAILABLE or UNCONFIRMED, or
> REJECT(STALE_ALERT) after TTL expiry;

> no unavailability condition causes an invalid acceptance;

> independent-holder retrieval success follows 1 - (1 - alpha)^k;

> correlated failures are reported separately and are not mixed into the
> independent-failure curve.

## 实验实现对应

| 论文内容 | 实现位置 |
|---|---|
| independent holder curve | `experiment.py` holder curve |
| correlated/all-holder failure | failure taxonomy |
| stale/forged provider | bundle provider cases |
| TTL before/after recovery | deadline paths |
| typed outcomes | `results/latest/summary.json` |

## 解释边界

E5 不测网络或持久化实现。可用性失败可以阻止安全告警被确认，但不能把它转成
错误接受；论文的 conditional liveness 依赖 A6 和 A9。
