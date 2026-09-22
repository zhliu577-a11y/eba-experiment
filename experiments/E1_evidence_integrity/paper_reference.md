# E1 论文原文定位

## 位置

- 主位置：`Paper1_Revised_Full_EN (5).pdf`, §6.5, pp. 26-27
- 安全声明：T1a 与 T1b 的 conflicting-root 部分
- 支撑映射：§5.9；统计口径：§6.13

## 原文摘录

> E1 tests T1a and the conflicting-root portion of T1b using the manipulation
> classes supported by the prototype.

> modification, insertion, reordering, cross-direction replay, cross-session
> replay, and chain-head rollback are detected in every injected case within
> the experimental boundary;

> conflicting roots are always recorded as equivocation evidence;

> Truncation and multi-root coverage remain security-analysis properties and
> are not claimed as separately implemented E1 attacks.

## 实验实现对应

| 论文 manipulation class | `experiment.py` case |
|---|---|
| modification | `modification` |
| insertion | `insertion` |
| reordering | `reordering` |
| cross-direction replay | `cross_direction_replay` |
| cross-session replay | `cross_session_replay` |
| chain-head rollback | `rollback` |
| conflicting roots | `conflicting_roots` |

## 解释边界

E1 是有限的注入攻击实验，提供检测计数和 reason 分布，不是攻击不可能性的
证明。论文没有把 truncation 或多根覆盖列为单独 E1 实现攻击。
