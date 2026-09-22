# E8 Payload 与对象隐私

## 实验目的

E8 测试 PR1。实验扫描 `RevokeAdvice`、root、proof 和 retrieved bundle，
检查指定 business marker、instruction-injection marker、executable marker
以及列出的 injectable field name 是否泄漏。

论文位置和原文见 [paper_reference.md](paper_reference.md)。

## 运行

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --profile full --experiments E8
```

full profile 扫描 10000 个 alert 及其关联对象。

## 实现与输入

- `experiment.py`：生成含指定 marker 的 payload，构造协议对象并递归扫描；
- `results/latest/summary.json`：marker occurrences、field names、schema 和
  metadata keys；
- `results/latest/summary.md`：当前结果摘要。

## 当前结果

业务 payload marker、instruction-injection marker、designated executable
marker 的 occurrence 均为 0；列出的 injectable field name 也均未出现。

## 通过条件

- alert、root、proof 或 bundle 中不出现指定 business-payload marker；
- 不出现指定 instruction-injection marker；
- 不出现指定 executable marker；
- 不出现论文列出的 injectable field name；
- 结果只描述 payload/object privacy。

## 边界

E8 不执行通用 executable-content detection，不测试 transparency log、gossip、
network metadata 或 interaction-graph privacy。它不声明 anonymity 或
unlinkability。
