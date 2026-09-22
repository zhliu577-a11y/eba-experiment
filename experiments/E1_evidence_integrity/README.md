# E1 证据完整性

## 实验目的

E1 测试 T1a 和 T1b 的 conflicting-root 部分。实验逐类注入篡改，检查证据
是否被检测、拒绝或保持 `UNCONFIRMED`，并记录实际触发的检测机制。

论文位置和原文见 [paper_reference.md](paper_reference.md)。

## 运行

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --profile full --experiments E1
```

full profile 对每类执行 1000 次。

## 实现与输入

- `experiment.py`：篡改注入、D5/D7 验证与 reason 记录；
- 七类：modification、insertion、reordering、cross-direction replay、
  cross-session replay、chain-head rollback、conflicting roots；
- `results/latest/summary.json`：每类 trials、invalid accept 和 reason 分布；
- `results/latest/summary.md`：汇总结果。

## 当前结果

7 类各 1000 次，invalid accept 为 0。6 类篡改由 typed
`UNCONFIRMED(...)` 检测；conflicting roots 返回
`REJECT(EQUIVOCATION_DETECTED)`。

## 通过条件

- 每个已实现注入类都被检测；
- 不产生 invalid acceptance；
- conflicting roots 总是记录为 equivocation evidence；
- 返回明确 decision 和 reason，而不是无类型的通用失败。

## 边界

`truncation` 和 multi-root coverage 仍是安全分析性质，不是单独实现的
E1 攻击。alert-based case 可以由 event signature、sid、anchor、sequence
或 proof/event binding 提前失败，不要求每类都走到 chain-head 检查。
