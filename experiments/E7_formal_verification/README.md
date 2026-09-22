# E7 ProVerif 正负模型验证

## 实验目的

E7 覆盖 T1-T4，在 A3 下检查协议消息层语义。正向模型验证 R1-R5 和三项附加
性质；负模型 N1-N6 每个移除一个必要机制，并要求在执行指定 query 时失败。

论文位置和原文见 [paper_reference.md](paper_reference.md)。

## 运行

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --profile full --experiments E7
```

Runner 按以下顺序查找 ProVerif：

```text
PROVERIF_EXE
.tools/proverif2.05/proverif.exe
PATH
```

## 实现与输入

- `model/eba_positive.pv`：正向 ProVerif 模型；
- `queries/R1-R5.txt`：query 文本归档；
- `experiment.py`：构造 N1-N6 mutations、执行模型并解析结果；
- `results/latest/models/`：实际运行的正向和负向模型；
- `results/latest/traces/`：每个模型的 stdout/stderr 和反例 trace。

## 当前结果

正向模型的 8 个 query 全部为 `true`。N1-N6 均产生预期失败和反例 trace。

## 通过条件

- R1 authentication and agreement；
- R2 chain binding；
- R3 acceptance implies valid evidence and a genuine rule violation；
- R4 non-repudiation；
- R5 sender binding on the third-party path；
- freshness/expiry、accuser verification、two-sided root coverage 成立；
- N1-N6 精确在指定 query 上失败；
- 每个负模型保留 counterexample trace。

## 边界

E7 的 `OK` 只表示 ProVerif 消息层符号验证通过。它不代表 TEE 硬件、
SHA-256 Merkle 实现或完整密码学实现与模型等价，也不验证硬件 attestation。
E7 不证明主代码实现与 ProVerif 模型完全一致。
