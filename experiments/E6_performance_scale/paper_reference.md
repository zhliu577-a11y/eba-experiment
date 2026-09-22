# E6 论文原文定位

## 位置

- 主位置：`Paper1_Revised_Full_EN (5).pdf`, §6.10, p. 30
- 统计与复现：§6.13, pp. 31-32
- 关联问卷：RQ1；结果映射：Q1

## 原文摘录

> Microbenchmarks measure these components separately:

> software-simulated TEE interface; hardware attestation excluded;

> AuditEvent construction, JCS canonicalization, hashing, and signing;

> inclusion-proof generation and verification;

> rule re-evaluation;

> single-signature verification.

> Microbenchmarks use 10^5 iterations. The report records warm-up policy and
> measurement boundaries.

> Local overhead is measurable ... Latency, object size, and component CPU cost
> are reported ...

> The report separates measured local object processing from network,
> persistent-storage, and deployment-scale effects, which are not tested in E6.

## 实验实现对应

| 论文内容 | 实现位置 |
|---|---|
| microbenchmarks | `experiment.py::_microbenchmarks` |
| W1/W2 workload | `experiment.py::_end_to_end` |
| W3 alert flood | `experiment.py::_end_to_end` |
| third-party combined path | `experiment.py::_third_party_path` |
| wire size/root publication | `experiment.py::_wire_and_root_publication` |
| full measurement | `results/latest/summary.json` |

## 解释边界

E6 的数值只描述当前机器上的软件模拟协议层实现。它不能外推为硬件 TEE
性能，也不是网络、存储或生产部署的性能结论。
