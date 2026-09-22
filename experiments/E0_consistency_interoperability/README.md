# E0 一致性与互操作性

## 实验目的

E0 不注入攻击。它验证后续 E1-E8 使用的 canonical bytes、schema、reason
code 和三态判定语义一致，并检查 JCS 与 Ed25519 的跨实现互操作。

论文位置和原文见 [paper_reference.md](paper_reference.md)。

## 运行

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --profile full --experiments E0
```

该实验没有 profile 参数，始终执行固定检查。

## 实现与输入

- `experiment.py`：固定向量、schema、边界行为与互操作检查；
- `interop/node_verify.mjs`：独立 Node.js JCS/Ed25519 检查；
- `results/latest/summary.json`：逐项 check 结果；
- `results/latest/summary.md`：通过项摘要。

## 当前结果

10/10 checks 通过，包括 JCS 固定向量、Python/Node.js 规范字节一致性、
Ed25519 验证、reason code、乱序缓冲、session rotation、证据 GC、
未知规则、时钟边界和 retraction 状态。

## 通过条件

- 每个固定向量产生预期 canonical bytes；
- Python 与独立 Node.js 检查结果一致；
- `ACCEPT`、`REJECT`、`UNCONFIRMED` 和 typed reason 映射正确；
- schema 缺字段、未知规则、不可用证据和边界时间不产生错误接受。

## 边界

该实验只覆盖 JCS 和 Ed25519 的独立库互操作，不实现第二套完整 D9
verifier，因此不声称独立 D9 实现等价。
