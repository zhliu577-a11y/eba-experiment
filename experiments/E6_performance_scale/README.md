# E6 性能与本地开销

## 实验目的

E6 回答 RQ1，测量本地对象处理延迟、组件 CPU 成本、序列化大小、第三方组合
路径和 alert flood 下的去重成本。

论文位置和原文见 [paper_reference.md](paper_reference.md)。

## 运行

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --profile full --experiments E6
```

full profile 使用 100000 次微基准、W1/W2 各 10000 interactions，以及
W3 每档 100000 alerts。

## 实现与输入

- `experiment.py`：微基准、W1-W3、第三方组合路径和 wire-size 测量；
- `requirements.txt`：仅声明本地运行依赖；
- `results/latest/summary.json`：延迟、CPU、吞吐、size、flood 与 publication
  cost；
- `results/latest/summary.md`：关键结果摘要。

## 当前结果

full 规模已完成。当前报告包含 AuditEvent construction/verification、
anchor、Merkle root/proof、rule re-evaluation、组合第三方路径、序列化对象
大小、W3 吞吐和 root publication amortized cost。

## 通过条件

- 所有预声明的微基准和端到端 workload 完成；
- 报告延迟、对象大小和本地 CPU cost，不只给单一聚合数字；
- latency 使用 p50/p95/p99，相关成本项报告 mean/std 或 median/IQR；
- W3 记录去重和本地处理成本；
- 不把网络、持久化或部署扩展时间混入本地对象处理数据。

## 边界

E6 使用单机 Python 3.13 和软件模拟 TEE 接口，不执行硬件 attestation
benchmark。实验不包含网络传输、persistent storage、transparency log、
gossip 或 deployment-scale 曲线，也不包含 batch verification。
