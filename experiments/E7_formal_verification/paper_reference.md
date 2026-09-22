# E7 论文原文定位

## 位置

- 主位置：`Paper1_Revised_Full_EN (5).pdf`, §6.11, pp. 30-31
- 安全声明：T1-T4
- 支撑位置：§5.9、Appendix D

## 原文摘录

> E7 covers T1-T4. The positive queries are R1-R5. E7 verifies message-layer
> semantics under A3 and does not validate hardware attestation.

> R1: authentication and agreement;
> R2: chain binding;
> R3: acceptance implies valid evidence and a genuine rule violation;
> R4: non-repudiation;
> R5: sender binding on the third-party path.

> The pass criterion is that every positive query holds, every negative model
> fails as predicted, and each negative model produces a counterexample trace.

> The artifact archives the ProVerif version, model file, query text, command,
> execution log, and counterexample.

## 负模型映射

| ID | 修改 | 预期失败 |
|---|---|---|
| N1 | Shared session key | R5 |
| N2 | Remove `copy_hash` comparison | R3 |
| N3 | Remove anchor-window checking | freshness/expiry |
| N4 | Remove local rule re-evaluation | R3 |
| N5 | Permit single-sided root publication | truncation/equivocation coverage |
| N6 | Remove accuser-signature verification | R4 |

## 实验实现对应

| 论文内容 | 实现位置 |
|---|---|
| positive model | `model/eba_positive.pv` |
| R1-R5 query text | `queries/R1-R5.txt` |
| model mutations | `experiment.py::NEGATIVE_MODELS` |
| executed models | `results/latest/models/` |
| logs and counterexamples | `results/latest/traces/` |

## 解释边界

E7 的符号模型把 signed evidence 和 TEE quote 抽象为密码学对象。通过查询
不构成 TEE、SHA-256、Python 实现或完整密码学库的等价性证明。
