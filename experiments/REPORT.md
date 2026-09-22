# Full 实验结果报告

完整运行 manifest：`results/run_full.json`。本轮在 2026-09-22 重新执行
`E0-E8` full profile，所有实验均结束。E6 耗时约 `955.8 s`，E7 完成真实
ProVerif 验证。`smoke`、`standard` 和 `full` 三套 manifest 均覆盖
`E0-E8`。

## 总览

| 实验 | 结果 | 关键数据 |
|---|---|---|
| E0 | 10/10 checks 通过 | Python/Node.js JCS 规范字节一致；签名、schema、reason 和边界检查通过 |
| E1 | 7 类 x 1000 次，invalid accept = 0 | 6 类由 `UNCONFIRMED` 检测；conflicting roots 返回 `REJECT(EQUIVOCATION_DETECTED)` |
| E2 | 1000 次归因与伪造测试 | 合法归因率 1.0；peer forgery 拒绝率 1.0；N1 counterexample 出现 |
| E3 | 13 类攻击/控制 x 1000 次 | invalid accept = 0；有效对照 1000/1000 接受；typed reason rate = 1.0 |
| E4 | 5 个场景 x 30 次 | 同一 D9 verifier 在独立进程中的 `decision + reason` 100% 一致 |
| E5 | 12 条 holder 曲线 x 5000 次 | 经验成功率符合 `1-(1-alpha)^k`；不可用不产生 `ACCEPT`；TTL 后为 `STALE_ALERT` |
| E6 | full 规模完成 | W1/W2 各 10000 interactions；W3 每档 100000 alerts |
| E7 | ProVerif verified | 8/8 正向 query 成立；N1-N6 全部产生预期 counterexample |
| E8 | 扫描 10000 alerts | business、instruction-injection、designated executable marker 均为 0；可注入字段 0 个 |

## 安全判定

E3 的 Sybil pressure 为 `f=0.1/0.5/0.9/1.0`，四档均得到
`invalid acceptance = 0`。Sybil fraction 改变无效告警的数量，但没有改变
单条无效告警的接受概率。

E5 的曲线测试中，证据缺失、provider 错误和检索超时只产生
`UNCONFIRMED` 或 `STALE_ALERT`，没有出现由不可用导致的 `ACCEPT`。

这些结果是有限样本攻击实验，不是“攻击不可能”的证明。论文结论仍需限制在
测试边界和密码学假设内。

## ProVerif

E7 使用 ProVerif 2.05 Windows binary：

```text
.tools/proverif2.05/proverif.exe
```

正向模型 `EBA_positive.pv` 的 R1-R5、freshness、accuser verification 和
two-sided root coverage 共 8 个查询全部为 `true`。

N1-N6 结果：

| 负模型 | 预期失败 |
|---|---|
| N1 shared session key | R5 |
| N2 remove copy hash | R3 |
| N3 remove anchor window | freshness/expiry |
| N4 remove rule re-evaluation | R3 |
| N5 single-sided root | two-sided root coverage |
| N6 remove accuser signature | accuser verification 和 R4 |

可执行程序输出和反例 trace 保存在
`experiments/E7_formal_verification/results/latest/traces/`。

## 性能结果

软件模拟 TEE，单机 Python 3.13：

- W1 AuditEvent 构造 mean `0.1486 ms`，p95 `0.1912 ms`，p99
  `0.2753 ms`。
- W1 event verification mean `0.1494 ms`，p95 `0.1710 ms`，p99
  `0.2501 ms`。
- Anchor verification mean `0.7331 ms`，p95 `1.3039 ms`，p99 `2.0773 ms`。
- Merkle root 64 leaves mean `0.1338 ms`，p95 `0.2702 ms`。
- Inclusion proof generation 256 leaves mean `0.5859 ms`，verification
  mean `0.0114 ms`。
- 组合第三方路径 mean `1.2488 ms`，不包含网络传输。
- AuditEvent `545 B`、RevokeAdvice `535 B`、RootAttestation `352 B`、
  inclusion proof `39 B`、完整 bundle `2894 B`。
- W3 每档 100000 alerts 时吞吐约 `452-663 alerts/s`，invalid accept = 0。
- `r=1000` 时 root publication amortized cost 为 `0.358 B/event`；
  `r=1` 时为 `352 B/event`。

## 边界

当前 TEE quote/session key 是软件模拟接口。硬件 attestation 属于部署假设
A3，不在实验范围内，也不是待补实验；论文不包含硬件 TEE 校准要求。

E7 的模型是协议消息层抽象：Merkle proof 和 TEE quote 被建模为不可伪造的
signed evidence，不代表对 SHA-256 Merkle 实现或硬件 TEE 的形式化验证。

Retrieval 是进程内对象往返，不是网络传输。E0 的第二语言实现覆盖 JCS 和
Ed25519，但没有复刻完整 Node.js D9 reason mapping。E4 使用同一 D9
verification code 在独立 OS 子进程中执行，不声称两个独立实现等价。

E8 只检查指定 business marker、instruction-injection marker、designated
executable marker 和列出的 injectable 字段名，不执行通用 executable-content
检测，也不声明 anonymity 或 interaction-graph unlinkability。

## 文件组织

- 实验总说明：`experiments/README.md`
- 论文到实验映射：`experiments/paper_experiment_map.md`
- 每个实验的指导：`experiments/E*/README.md`
- 每个实验的论文原文定位：`experiments/E*/paper_reference.md`
- 每个实验的原始结果：`experiments/E*/results/latest/summary.json`
- 每个实验的可读摘要：`experiments/E*/results/latest/summary.md`
- E7 ProVerif traces：`experiments/E7_formal_verification/results/latest/traces/`
- 完整运行 manifest：`results/run_full.json`
- 共享协议代码：`src/eba/`
- 实验入口：`experiments/E*/experiment.py`
- 统一 runner：`scripts/run_experiments.py`
