# E5 可用性与 liveness

## 实验目的

E5 测试 P1/P2：证据持有者不可用时，系统是否保持 safety，且不可用条件是否
永远不会产生错误 `ACCEPT`。

论文位置和原文见 [paper_reference.md](paper_reference.md)。

## 运行

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --profile full --experiments E5
```

full profile 对每条 holder curve 执行 5000 次。

## 实现与输入

- `experiment.py`：独立 holder success model、correlated failure、
  stale/forged provider、TTL 前后恢复；
- k 为 `1, 2, 5`，alpha 为 `0.1, 0.5, 0.9, 1.0`；
- `results/latest/summary.json`：曲线、失败 taxonomy、safety 与 liveness；
- `results/latest/summary.md`：汇总结果。

## 当前结果

12 条 holder curve 在容差内符合 `1-(1-alpha)^k`，所有曲线均无 invalid
accept，不可用条件不产生 `ACCEPT`，TTL 后结果为
`REJECT(STALE_ALERT)`。

## 通过条件

- 检索失败产生 `EVIDENCE_UNAVAILABLE`、typed `UNCONFIRMED`，或在 TTL 后
  产生 `REJECT(STALE_ALERT)`；
- 不可用永远不产生 `ACCEPT`；
- 独立 holder 成功曲线符合 `1-(1-alpha)^k`；
- correlated failure 单独报告，不混入独立曲线；
- 满足 A6/A9 且 TTL 未过期时，有效告警最终不能永久停留在
  `UNCONFIRMED`。

## 边界

E5 使用 in-memory direct provider，不测网络延迟、持久化存储或生产级
availability。它测量 safety boundary 和模型化 liveness，不证明真实 federation
总有证据可用。
