# E8 论文原文定位

## 位置

- 主位置：`Paper1_Revised_Full_EN (5).pdf`, §6.12, p. 31
- 安全声明：PR1
- 支撑位置：§5.10、§6.13

## 原文摘录

> E8 tests PR1:

> whether RevokeAdvice, root, proof, or retrieved-bundle objects contain a
> designated business-payload marker;

> whether those objects contain a designated instruction-injection marker that
> could inject adversarial text into a receiver's context;

> whether those objects contain a designated executable marker;

> whether any scanned object contains one of the listed injectable field names.

> no designated business-payload marker appears in alert, root, proof, or
> bundle objects;

> the result is described as payload/object privacy and never as anonymity or
> unlinkability.

> Generic executable-content detection is outside scope.

> E8 does not test transparency-log, gossip, network-metadata, or
> interaction-graph privacy.

## 实验实现对应

| 论文检查 | 实现位置 |
|---|---|
| business marker | `experiment.py::BUSINESS_MARKER` |
| instruction-injection marker | `experiment.py::INJECTION_MARKER` |
| executable marker | `experiment.py::EXECUTABLE_MARKER` |
| injectable field names | `experiment.py::INJECTABLE_FIELD_NAMES` |
| recursive object scan | `_contains_marker`, `_iter_object_keys` |
| structured result | `results/latest/summary.json` |

## 解释边界

E8 是指定 marker 和字段名的对象扫描。没有发现 marker 不等于通用恶意内容
检测，也不隐藏争议、时间、session 或其他可见 metadata。
