# Evidence-Backed Accusation Experiments

本项目实现并运行 `Paper1_Revised_Full_EN (5).pdf` 中 Evidence-Backed
Accusation 的协议层可复现实验。实验按 `E0` 到 `E8` 归档，定位为：

> Protocol-level evidence and accusation evaluation under deployment
> assumption A3.

## 实验目录

实验统一放在 `experiments/`：

- `experiments/README.md`：目录规范、运行方式和当前状态；
- `experiments/paper_experiment_map.md`：论文位置到 E0-E8 的总映射；
- `experiments/DESIGN.md`：全局实验设计；
- `experiments/REPORT.md`：full profile 总报告；
- `experiments/E*/README.md`：每个实验的独立指导；
- `experiments/E*/experiment.py`：实验实现；
- `experiments/E*/paper_reference.md`：论文原文位置、摘录和实现映射；
- `experiments/E*/results/latest/`：该实验的结构化结果和可读摘要。

## 环境

项目使用工作区内的 Python 虚拟环境：

```powershell
$env:TEMP = (Resolve-Path -LiteralPath '.tmp').Path
$env:TMP = $env:TEMP
py -m venv --clear .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

依赖声明只包含 `cryptography`。E7 使用 ProVerif 2.05，第三方二进制不纳入
Git 仓库；将 `proverif.exe` 放到以下位置即可：

```text
.tools/proverif2.05/proverif.exe
```

也可以直接设置 `PROVERIF_EXE` 指向已有安装。Runner 会依次查找
`PROVERIF_EXE`、项目内 `.tools` 和系统 `PATH`。

## 运行

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --profile full
```

可单独运行实验：

```powershell
.\.venv\Scripts\python.exe scripts\run_experiments.py --profile full --experiments E1 E4 E6 E8
```

单元测试：

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## 评估范围

- `E0`：JCS、schema、状态码、边界条件和 JCS/Ed25519 interop。
- `E1`：modification、insertion、reordering、cross-direction replay、
  cross-session replay、chain-head rollback、conflicting roots。
- `E2`：attribution、peer forgery、key substitution、shared-key negative
  control。
- `E3`：D9 各类确定失败、有效对照和 Sybil pressure。
- `E4`：participant 与独立进程中的同一 D9 verifier 三态判定一致。
- `E5`：direct-provider holder availability、不可用不 `ACCEPT`、TTL 后
  `STALE_ALERT`。
- `E6`：本地组件微基准、single-session W1-W3、组合第三方验证路径、
  wire size 和 alert flood。
- `E7`：ProVerif 消息层 R1-R5 与 N1-N6。
- `E8`：alert、root、proof、bundle 的 payload/object privacy 和
  injectable-field 检查。

## 边界

当前 TEE quote 和 session key 是软件模拟接口。硬件 attestation 属于部署假设
A3，不在实验范围内，也不是待补实验。

网络传输、持久化存储、transparency log、gossip、完整第二语言 D9 verifier
和硬件 attestation 均不在评估范围内。`E4` 使用同一 verifier implementation
在独立进程中执行，不声称独立实现一致；`E5` 使用 in-memory direct provider；
`E6` 不包含网络、持久化或部署扩展曲线；`E8` 只声明 payload/object privacy，
不声明 anonymity 或 interaction-graph unlinkability。

`E8` 不执行通用 executable-content 检测，只检查指定 marker 和列出的
injectable 字段名。

## 结果

- `results/run_smoke.json`：smoke profile 结果。
- `results/run_standard.json`：standard profile 结果。
- `results/run_full.json`：`E0-E8` full profile 结果。
- `experiments/E*/results/latest/summary.json`：单实验结构化结果。
- `experiments/E7_formal_verification/results/latest/traces/`：ProVerif
  stdout/stderr 和反例 trace。
- `artifact_manifest.json`：项目文件 SHA-256 清单。

`E7` 实际执行 8 个正向查询，并检查 N1-N6 的预期失败。所有结果都以 JSON
结果和 SHA-256 manifest 归档，不依赖绘图脚本。
