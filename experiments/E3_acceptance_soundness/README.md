# E3 接受可靠性与 framing resistance

## 实验目的

E3 测试 T3。实验分别破坏 D9 的每项接受条件，并保留有效对照和 Sybil
pressure，防止“拒绝一切”被错误解释为 soundness。

论文位置和原文见 [paper_reference.md](paper_reference.md)。

## 运行

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --profile full --experiments E3
```

full profile 对每个攻击或失败类执行约 1000 次。

## 实现与输入

- `experiment.py`：D9 条件破坏、有效对照和 Sybil fraction；
- 覆盖 forged anchor/evidence、altered copy、incorrect proof、conflicting
  roots、accuser signature、rule、TTL/time、retraction 和 evidence
  availability；
- `results/latest/summary.json`：decision、reason、acceptance 和 Sybil 结果；
- `results/latest/summary.md`：汇总结果。

## 当前结果

invalid accept 为 0，有效对照接收 1000/1000，typed reason rate 为 1.0，
Sybil pressure 检查通过。

## 通过条件

- 每个无效候选都不能得到 `ACCEPT`；
- 每个有效对照必须得到 `ACCEPT`；
- 最终状态只允许确定的 `REJECT(reason)` 或暂时性的
  `UNCONFIRMED(retry_reason)`；
- 不可用候选在 TTL 到期后转为 `REJECT(STALE_ALERT)`；
- Sybil fraction 只改变尝试量和成本，不改变单条无效告警的接受概率。

## 边界

实验验证固定规则下的接受判定，不证明规则本身正确。它不覆盖 response
policy、containment、网络成本和证据存储成本。
