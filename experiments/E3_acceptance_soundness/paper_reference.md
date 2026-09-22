# E3 论文原文定位

## 位置

- 主位置：`Paper1_Revised_Full_EN (5).pdf`, §6.7, pp. 27-28
- 安全声明：T3
- 支撑映射：§5.9；统计口径：§6.13

## 原文摘录

> E3 tests T3 by breaking each acceptance condition in D9 separately. It is
> not sufficient to generate one generic "bad alert."

> zero invalid alerts are accepted;

> every valid control alert is accepted;

> the final verifier state is only REJECT or UNCONFIRMED for invalid
> candidates;

> a deterministic failure on an already verified object produces REJECT,
> whereas a malformed candidate supplied by an untrusted provider produces
> UNCONFIRMED until the TTL expires;

> increasing the Sybil fraction from f = 0.1 to f = 1.0 does not change the
> per-alert acceptance probability;

> A verifier that rejects every alert would also report zero invalid
> acceptances. The valid control set is therefore mandatory.

## 实验实现对应

| 论文类别 | 实现内容 |
|---|---|
| anchor/evidence/copy/proof | D9 对象绑定检查 |
| root conflict | `REJECT(EQUIVOCATION_DETECTED)` |
| accuser/retraction signature | 签名与 identity 绑定 |
| rule label/version | 本地规则复评和版本解析 |
| expired/misplaced time | TTL、anchor window 和 clock skew |
| missing evidence | typed `UNCONFIRMED`，TTL 后 `STALE_ALERT` |
| valid controls | 每个攻击矩阵中的对照路径 |
| Sybil pressure | `f in {0.1, 0.5, 0.9, 1.0}` |

## 解释边界

E3 是有限样本的接受可靠性测试，不是所有可能 alert 的形式证明。有效对照是
必需结果，不能只报告 zero invalid acceptance。
