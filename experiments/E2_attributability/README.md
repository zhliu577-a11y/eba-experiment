# E2 归因与不可否认性

## 实验目的

E2 测试 T2：合法事件能否归因到 anchor 绑定的 sender，peer 能否伪造 sender
事件，以及共享 session key 的削弱模型是否会导致 R5 失败。

论文位置和原文见 [paper_reference.md](paper_reference.md)。

## 运行

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --profile full --experiments E2
```

full profile 执行 1000 次归因与伪造测试。

## 实现与输入

- `experiment.py`：合法归因、peer forgery、key substitution 和 N1 负控制；
- `results/latest/summary.json`：归因率、拒绝率和负控制结果；
- `results/latest/summary.md`：可读摘要。

## 当前结果

合法归因率为 1.0，peer-forgery rejection rate 为 1.0，weak shared-key
模型观察到预期反例。

## 通过条件

- 每个合法事件归因到正确 identity 和 session；
- peer 或第三方不能伪造 sender 事件；
- 替换或重用 session public key 会导致 anchor-binding 或签名错误；
- shared-key negative model 不能通过 R5。

## 边界

实验验证事件签名、session key 和 anchor 绑定。TEE session private key 的
硬件保护仍是 A3 部署假设，不在本地实验中验证。
