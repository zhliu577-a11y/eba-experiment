# 实验设计

## 被测对象

实验实现论文中的 M1-M4：

- `AuditEvent`：按方向建立 SHA-256 hash chain，发送方使用 session key 签名。
- `SessionAnchor`：绑定双方 identity key、session public key、TEE quote、
  初始链头和有效期。
- `RootAttestation`：对单方向事件段生成 Merkle root，并由 participant 签名。
- `RevokeAdvice`：绑定 `anchor_ref`、事件位置、规则版本、`copy_hash`、
  `root_ref` 和 inclusion proof。
- D9 verifier：只返回 `ACCEPT`、`REJECT(reason)` 或
  `UNCONFIRMED(retry_reason)`。

判定优先级按论文执行：已验证对象上的确定性失败优先于临时不可用；不可信
provider 返回的坏候选被丢弃，不能单独造成最终 `REJECT`；TTL 到期后未完成的
`UNCONFIRMED` 转为 `REJECT(STALE_ALERT)`。

评估定位为 software-simulated A3 下的协议层证据与指控评估。硬件 attestation、
网络、持久化、transparency log 和 gossip 不在范围内。

## 样本档位

| Profile | 攻击/攻击类 | 系统条件 | 微基准 | W1/W2 交互 | W3 每档告警 | E5 每组 |
|---|---:|---:|---:|---:|---:|---:|
| `smoke` | 10 | 3 | 1000 | 100 | 1000 | 100 |
| `standard` | 100 | 30 | 10000 | 1000 | 10000 | 1000 |
| `full` | 1000 | 30 | 100000 | 10000 | 100000 | 5000 |

## E0：一致性与互操作

测试 JCS 固定向量、必需字段、Python 与 Node.js 的规范字节差异、Ed25519
验证、重复告警去重、乱序缓冲、session rotation、证据 GC、未知规则、时钟窗口
和撤回状态。

通过条件：所有 fixed checks 一致，且缺失证据只能是 `UNCONFIRMED`，未知规则
只能是 `REJECT(RULE_UNKNOWN)`。

## E1：证据完整性

实现攻击类包括 modification、insertion、reordering、cross-direction replay、
cross-session replay、chain-head rollback 和 conflicting roots，共 7 类。
`splicing` 和 `truncation` 不再是实现实验。

报告按实际观测到的检测机制记录。alert-based case 可以由 event signature、
sid、anchor、sequence 或 proof/event binding 更早失败，不声称每一类都走到
完整 D5 chain-head/direction 路径；rollback 由 D5 admission replay/order check
检测。通过条件：每类 0 次 invalid accept；冲突根返回
`REJECT(EQUIVOCATION_DETECTED)`。未验证 provider 提供的坏 bundle 返回
`UNCONFIRMED(...)` 也算检测成功。

## E2：归因与不可否认性

正向检查合法事件能否归因到 anchor 绑定的 sender；负向检查 peer 在没有
sender session private key 时能否伪造事件，以及替换 session public key 是否
导致 anchor 验证失败。共享密钥 weakened check 下应观察到 N1 counterexample。

## E3：接受可靠性与 framing resistance

逐项破坏 D9：

- forged anchor
- forged evidence
- altered copy
- incorrect inclusion proof
- conflicting roots
- forged accuser signature
- mislabeled rule
- missing rule version
- expired alert
- future/misplaced time
- forged retraction
- unavailable evidence

每类必须得到预设 typed reason。有效对照组必须全部 `ACCEPT`。Sybil fraction
为 `0.1/0.5/0.9/1.0`，只改变尝试量和成本，不改变 invalid acceptance 概率。

## E4：第三方判定确定性

participant 使用同一 D9 predicate 和本地 bundle；non-participant 在独立
Python 进程中只拿 anchor、roots、alert、direct-provider bundle 和 public
rules。场景包括 complete evidence、missing evidence、incorrect evidence、
deterministic copy mismatch 和 forged anchor；不包含未实现的 provider delay。

通过条件：相同输入下 `decision + reason` 完全一致；不可用条件绝不能得到
`ACCEPT`。这不是第二套独立 verifier 的实现等价性实验。

## E5：可用性与 liveness

对 `k in {1,2,5}`、`alpha in {0.1,0.5,0.9,1.0}` 模拟独立 holder。理论
retrieval success 为 `1-(1-alpha)^k`。另测所有 holder 离线、单块 provider、
一坏一好、TTL 前超时、TTL 后恢复。

通过条件：不可用产生 typed `UNCONFIRMED` 或 `STALE_ALERT`，坏 provider 不
覆盖好 provider，任何时刻不能因为不可用而接受。

## E6：性能与本地开销

微基准覆盖 session key、JCS、SHA-256、事件构造/验证、Merkle
leaf/internal/root、proof gen/verify、anchor、retrieval serialization、rule
replay 和 single signature。

W1 为 benign baseline；W2 的 violation rate 为 `0.25/0.5/1.0`；W3 的 Sybil
fraction 为 `0.1/0.5/0.9/1.0`。W1-W3 都是 single-session、两个 agent 的
prototype workload；W3 只测 deduplication 和本地 cost，不声称实现 rate
limiting。

端到端部分新增组合第三方路径 benchmark：direct provider、无 participant
local state，在一次调用中覆盖 anchor verification、bundle retrieval、proof
verification、signature verification 和 rule re-evaluation，网络传输不包含。
另记录 alert、root、proof、bundle bytes 及 root publication bytes。

## E7：ProVerif

正向查询 R1-R5 和负模型 N1-N6 已按论文分类归档。Runner 使用项目内
`.tools/proverif2.05/proverif.exe`，执行后解析 8 个 query result：

- R1 authentication and agreement
- R2 chain binding
- R3 acceptance implies valid evidence and rule violation
- R4 non-repudiation
- R5 sender binding on third-party path
- freshness/expiry
- accuser verification
- two-sided root coverage

负模型 N1-N6 必须产生预期 counterexample。ProVerif 原始输出保存在
`experiments/E7_formal_verification/results/latest/traces/`。

## E8：Payload privacy

每次生成包含唯一 business marker、instruction-injection marker 和 designated
executable marker 的 payload，再扫描 `RevokeAdvice`、root、proof 和 retrieval
bundle。另检查这些对象中是否出现 `payload`、`prompt`、`content`、`command`、
`script`、`executable`、`instructions` 等 injectable 字段名。

通过条件只覆盖 PR1：不泄露业务 payload，不携带指定 instruction/executable
marker 或 injectable field name。这里不执行通用 executable-content 检测。
metadata disclosure 单独列出；不声明 anonymity 或 unlinkability。
