# 实验目录说明

本目录是 `Paper1_Revised_Full_EN (5).pdf` 中 `E0-E8` 实验的唯一入口。
实验定位为部署假设 A3 下的协议层证据与指控评估。

论文文件 SHA-256：

```text
6A9477C48C40E9632D414838CFC8917F6BE7D854F26361FDF1CF1AC561282F8F
```

## 目录规范

每一个实验目录必须包含：

```text
repository/
  experiments/
    README.md                  # 总运行说明与状态
    paper_experiment_map.md    # 论文、声明、实验目录的总映射
    DESIGN.md                  # 全局实验设计
    REPORT.md                  # full profile 总报告
    common.py                  # 实验共享工具
    E*/
      README.md                # 本实验指导
      paper_reference.md       # 论文原文位置、摘录与实现映射
      experiment.py            # 本实验实现
      results/
        latest/
          summary.json         # 结构化结果
          summary.md           # 可读摘要
  scripts/
    run_experiments.py         # 统一 runner
    build_manifest.py          # artifact manifest
  src/eba/                     # 共享协议代码
```

`E0`、`E4`、`E7` 可以包含必要的辅助文件，但不得改变上述四类核心内容：
实验指导、实验实现、实验论文依据、实验结果。

## 运行方式

运行全部 full profile：

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --profile full
```

运行单个实验：

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --profile full --experiments E1
```

运行多个实验：

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --profile full --experiments E1 E4 E6 E8
```

`E0` 和 `E7` 使用固定协议，不随 profile 改变样本规模。其他实验支持：

| Profile | 用途 | 主要规模 |
|---|---|---|
| `smoke` | 快速连通性检查 | 小样本 |
| `standard` | 日常验证 | 中样本 |
| `full` | 论文结果 | `E1/E3` 每类约 1000 次，`E6` 微基准 100000 次 |

## 当前状态

`results/run_full.json` 中 `E0-E8` 均已 `completed`。当前 full 结果摘要：

| 实验 | 当前结论 | 结果位置 |
|---|---|---|
| `E0` | 10/10 checks 通过 | `E0_consistency_interoperability/results/latest/` |
| `E1` | 7 类各 1000 次，invalid accept = 0 | `E1_evidence_integrity/results/latest/` |
| `E2` | 归因与拒绝率均为 1.0，N1 反例出现 | `E2_attributability/results/latest/` |
| `E3` | invalid accept = 0，有效对照 1000/1000 | `E3_acceptance_soundness/results/latest/` |
| `E4` | 5 个场景，判定与原因完全一致 | `E4_third_party_determinism/results/latest/` |
| `E5` | 可用性曲线通过，TTL 后为 `STALE_ALERT` | `E5_availability_liveness/results/latest/` |
| `E6` | full 规模完成 | `E6_performance_scale/results/latest/` |
| `E7` | 8/8 正向查询通过，N1-N6 均出现预期反例 | `E7_formal_verification/results/latest/` |
| `E8` | 指定 payload/injection/executable marker 均为 0 | `E8_payload_privacy/results/latest/` |

详细全局结果见 [REPORT.md](REPORT.md)，论文映射见
[paper_experiment_map.md](paper_experiment_map.md)。

## 统一边界

硬件 TEE attestation 是部署假设 A3，不在实验范围内，也不是待补实验。
当前 artifact 没有 `E9`，不报告硬件校准、硬件 key confinement、网络传输、
持久化存储、transparency log 或 gossip。

`E4` 比较同一 D9 verifier 在独立进程中的行为，不声称两套独立实现等价。
`E7` 只验证 ProVerif 消息层符号语义，不证明 TEE、SHA-256 或完整密码学实现
与形式模型等价。`E8` 只检查论文列出的指定 marker 和字段名，不声明
anonymity、unlinkability 或通用 executable-content 检测。
