# E2 论文原文定位

## 位置

- 主位置：`Paper1_Revised_Full_EN (5).pdf`, §6.6, p. 27
- 安全声明：T2
- 关联位置：§5.9；E7 N1 model

## 原文摘录

> E2 tests T2 with three positive experiments and one negative control.

> The sender denies a genuine event that it signed. The verifier must attribute
> the event through the session public key bound by the anchor and TEE quote.

> The receiver attempts to construct an event in the sender's name. The attempt
> must fail because the receiver lacks the sender's TEE-protected session
> private key.

> Modify the protocol so that both parties share one symmetric session key,
> then rerun R5 and the attribution experiment.

> The pass criterion is that every legitimate event is attributable to the
> correct identity and session, neither the peer nor a third party can forge a
> sender event, and the shared-key model cannot satisfy R5.

## 实验实现对应

| 论文内容 | 实现位置 |
|---|---|
| 合法事件归因 | `experiment.py` |
| peer forgery | `_forged_peer_event` |
| key substitution | anchor/session key replacement case |
| shared-key negative model | `_weakened_shared_key_check` |
| 形式模型对应 | `E7_formal_verification/` N1 |

## 解释边界

E2 的本地代码使用软件模拟 session key。它验证协议绑定关系，不证明 TEE
实际保护了 sender private key。
