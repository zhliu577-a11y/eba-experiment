# E4 论文原文定位

## 位置

- 主位置：`Paper1_Revised_Full_EN (5).pdf`, §6.8, pp. 28-29
- 安全声明：T4
- 支撑映射：§5.9

## 原文摘录

> E4 tests T4 by comparing the participant fast path with the non-participant
> retrieval path.

> the non-participant holds no session state;

> both paths invoke the same D9 verifier implementation in separate processes;

> the test covers complete evidence, missing evidence, a provider that returns
> incorrect evidence, a deterministic copy mismatch, and a forged anchor.

> for the same inputs, the participant and non-participant produce identical
> ACCEPT, REJECT, or UNCONFIRMED verdicts;

> the comparison does not claim agreement between independent D9
> implementations.

## 实验实现对应

| 论文要求 | 实现位置 |
|---|---|
| participant local path | `experiment.py` |
| non-participant separate process | `observer_subprocess.py` |
| 五个 scenario | `experiment.py` |
| verdict matrix | `results/latest/summary.json` |

## 解释边界

E4 证明的是同一实现跨 participant 和第三方的确定性行为，不是独立实现之间
的规范一致性，也不证明网络检索一定成功。
