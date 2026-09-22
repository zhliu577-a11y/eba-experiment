# E0 论文原文定位

## 位置

- 主位置：`Paper1_Revised_Full_EN (5).pdf`, §6.4, pp. 25-26
- 支撑映射：§5.9, pp. 21-22
- 统计与复现：§6.13, pp. 31-32

## 原文摘录

> E0 does not test an attack. It establishes that all later experiments rest
> on the same canonical byte representation, the same error mapping, and the
> same verdict semantics.

> The pass criterion is that the reference vectors and the primary code paths
> produce the expected canonical bytes, signature-verification results, reason
> codes, and final verdicts for every vector.

> A minimal interoperability check exercises JCS and Ed25519 against independent
> library implementations. It does not implement D9, evidence retrieval, or a
> second full verifier.

## 实验实现对应

| 论文内容 | 实现位置 |
|---|---|
| JCS fixed test vectors | `experiment.py` |
| 独立 JCS/Ed25519 library checks | `interop/node_verify.mjs` |
| schema 和 reason code | `src/eba/protocol.py`, `src/eba/canonical.py` |
| 边界、乱序、rotation、GC、retraction | `experiment.py` |
| 逐项结果 | `results/latest/summary.json` |

## 解释边界

E0 的通过只表示规范向量和主代码路径一致。它不等于独立 D9 verifier 的
实现等价性证明，也不覆盖硬件 attestation。
