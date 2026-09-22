# E4 第三方判定确定性

## 实验目的

E4 测试 T4。实验比较 participant fast path 与 non-participant retrieval
path，在相同输入上是否产生相同的三态判定和 reason。

论文位置和原文见 [paper_reference.md](paper_reference.md)。

## 运行

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --profile full --experiments E4
```

full profile 对每个场景执行 30 次。

## 实现与输入

- `experiment.py`：构造 participant 与第三方输入并比较结果；
- `observer_subprocess.py`：在独立 Python 进程中执行 non-participant path；
- 五个场景：complete evidence、missing evidence、incorrect evidence、
  deterministic copy mismatch、forged anchor；
- `results/latest/summary.json`：完整 verdict matrix 和一致性结果。

## 当前结果

5 个场景的 30 次重复中，participant 和 observer 的
`decision + reason` 完全一致；不可用证据不产生 `ACCEPT`。

## 通过条件

- 相同输入产生相同 `ACCEPT`、`REJECT` 或 `UNCONFIRMED`；
- 第三方路径没有 participant session state；
- 不可用条件在两条路径上都不产生 `ACCEPT`；
- 结果报告完整 verdict matrix，而不是只报告一个成功的有效案例。

## 边界

两条路径调用同一个 D9 verifier 实现，只是运行在独立进程中。实验不声称
两套独立 D9 实现等价，也不包含 provider delay 或网络调度。
