# 论文与实验目录映射

基准论文：`Paper1_Revised_Full_EN (5).pdf`

| 论文声明 | 研究问题 | 论文主位置 | 支撑位置 | 实验目录 | 当前结果 |
|---|---|---|---|---|---|
| A4、A5、A8 的规范前提 | 一致性基础 | §6.4, pp. 25-26 | §5.9 | `E0_consistency_interoperability/` | 10/10 checks 通过 |
| T1a 与 T1b 的 conflicting-root 部分 | RQ3 | §6.5, pp. 26-27 | §5.9, §6.13 | `E1_evidence_integrity/` | 7 类，invalid accept = 0 |
| T2 归因与不可否认性 | RQ3 | §6.6, p. 27 | §5.9, §6.11 | `E2_attributability/` | 归因/拒绝率 1.0，N1 反例出现 |
| T3 接受可靠性与 framing resistance | RQ4 | §6.7, pp. 27-28 | §5.9, §6.13 | `E3_acceptance_soundness/` | invalid accept = 0，有效对照全通过 |
| T4 第三方判定确定性 | RQ2 | §6.8, pp. 28-29 | §5.9 | `E4_third_party_determinism/` | 5 个场景，一致率 100% |
| P1/P2 可用性与条件 liveness | RQ4 | §6.9, p. 29 | §5.10 | `E5_availability_liveness/` | 不产生错误 `ACCEPT`，TTL 超时正确 |
| Q1 本地开销 | RQ1 | §6.10, p. 30 | §6.13 | `E6_performance_scale/` | full 规模完成 |
| T1-T4 的消息层符号验证 | RQ5 | §6.11, pp. 30-31 | Appendix D | `E7_formal_verification/` | 8/8 正向查询，6/6 负模型反例 |
| PR1 payload/object privacy | RQ6 | §6.12, p. 31 | §5.10, §6.13 | `E8_payload_privacy/` | 指定检查全部通过 |

## 公共章节

| 内容 | 位置 | 作用 |
|---|---|---|
| 原型、环境和 artifact | §6.2 | 定义 M1-M4、软件模拟 A3 和范围边界 |
| Workloads 与规则集 | §6.3 | 定义 W1-W3、`ALLOW-1` 等固定规则 |
| 统计与复现 | §6.13 | 定义样本规模、统计量、失败保留和有效性威胁 |
| 复现清单 | Appendix E | 规定源文件、模型、trace 和失败结果归档要求 |
| 安全结果到实验映射 | §5.9 | 定义 T1-T4、P1/P2、PR1 与 E0-E8 的对应 |

## 不属于实验目录的内容

以下内容在论文中没有对应的可执行实验目录，不应补造：

- 硬件 TEE attestation 与硬件校准；
- hardware key confinement 或 measured code；
- 网络传输、持久化存储和部署规模曲线；
- transparency log 与 gossip；
- 完整第二语言 D9 verifier 的等价性证明；
- 通用 executable-content 检测；
- anonymity 或 interaction-graph unlinkability。
