# proofctl — 数学证明平台化改造计划

## 愿景

proofctl 成为数学证明类项目的通用认证基础设施平台。数学家提供：
1. 证明目标（`graph.json`，声明 DAG）
2. 领域 checker（任意语言的可执行程序）
3. 领域 policy（JSON，声明放行条件）

框架提供其余一切：DAG 管理、内容寻址存储、attestation 链、freshness 追踪、release gate、STATUS.json。

---

## 范围说明

- proofctl 是**认证基础设施**，不做数学推导
- weil-lower-bound 是第一个参考域实现
- 当前第一个目标域是 weil-class；未来可拓展

---

## Milestone 1 — 核心通用化 ✅

- T1: release conditions 数据驱动化 ✅
- T2: proofctl init 去除默认 policy 硬编码 ✅
- T3: ReleaseStatus 字段去 Weil 化 ✅

## Milestone 2 — CAP 领域支持 ✅

- T4: CAP checker 协议桥接器 ✅
- T5: weil-lower-bound proofctl 集成文件 ✅
- T6: 端到端验证 ✅

## Milestone 3 — 平台脚手架 ✅

- T7: proofctl init --domain cap ✅
- T8: proofctl domains list ✅

## Milestone 4 — 吸收 weil 经验，消除手动文件 ✅

- T9: STATUS.json 字段增强（as_of、claim_summary）✅
- T10: release-manifest.json 自动生成 ✅
- T11: proofctl replay 子命令（cold-start generator+checker pipeline）✅
- T12: negative test 脚手架（conftest.py、test_tamper_basic.py、README.md）✅
- T13: proofctl env 子命令（verify + snapshot）✅

## Milestone 5 — 性能与多域完善 ✅

### T14：proofctl verify --project 并行调度 ✅

- `dag.Levels()`：将 claim 按拓扑分层，同层内 claim 无互相依赖，可并发运行
- `--project` 模式按层并发调度，每层内 goroutine 池（默认 = CPU 核数）
- `--parallel N` flag 控制最大并发度
- weil odd/even sector 作为独立层并发验证，wall-clock 减半；CAS 缓存命中无竞争
- 输出按 claim ID 排序，结果确定性不受并发影响

### T15：lrat 域 policy 模板和 graph 模板 ✅

- `templates/lrat-policy.json`：3-claim policy（formula/unsat/verified），无 required_metadata_keys
- `templates/lrat-graph.json`：3 个占位 claim 的 DAG 模板（CNF+LRAT evidence）
- `proofctl init --domain lrat` 可用，`domains list` 显示 POLICY=yes GRAPH=yes

### T16：qmd 域 policy 模板和 graph 模板 ✅

- `templates/qmd-policy.json`：通用 policy，允许 `independent-review` assurance
- `templates/qmd-graph.json`：1 个占位 claim，说明由 `--adapter qmd` 自动从 QMD 提取
- `proofctl init --domain qmd` 可用，`domains list` 显示 POLICY=yes GRAPH=yes

---

## 关键设计约束

1. **checker 独立性不变：** bridge.py 是协议翻译层，绝不引入 generator 侧代码
2. **核心零领域知识：** `internal/` 下所有包继续零 Weil 依赖
3. **fail-closed 不变：** release gate 逻辑不松动

---

## 全部 M1–M5 已完成 ✅

---

## Milestone 6 — 打通 verify 端到端 ✅

### T17：`proofctl compile --fix-digests` ✅
### T18：`proofctl pin checker` ✅
### T19：`proofctl cas import` ✅

**端到端结果（weil-lower-bound）：**
```
PASS lem-path-a-primitives
PASS lem-path-b-primitives
PASS lem-ab-intersection
PASS lem-matrix-reconstruction
PASS lem-interval-ldlt
PASS thm-main-radius-030   ← 最终定理通过
```
5 个无 checker_policy 的推理性 claim（def-frozen-model, d1-d3, d5）需通过 attestation 手工确认，不是技术故障。

**目标：** `proofctl verify --project` 和 `proofctl release` 在 weil-lower-bound 中完整跑通，
不再需要任何手工 sha256 计算、CAS 导入或 statement digest 填写。

### T17：`proofctl compile --fix-digests` — statement digest 自动填充

**问题：** weil `graph.json` 里 12 个 claim 的 `statement.digest` 全是占位零。
proofctl 的缓存键依赖 statement digest，零值导致所有 claim 共享同一 cache key，
且 CAS verify 步骤会因 digest 不一致而失败。

**改造：** `proofctl compile` 新增 `--fix-digests` flag：
- 读取 source graph.json
- 对每个 `statement.digest` 为全零的 claim，计算 `sha256(statement.text)` 并原地回写
- 然后正常编译到 `.proofctl/graph.json`

### T18：`proofctl pin checker` — checker binary digest + Runtime.Cmd 固定

**问题：** weil `graph.json` 里 `checker_digest` 是占位零，且 `Runtime` 没有命令路径，
`NativeRunner` 无法找到要执行的 checker（当前 `LookPath("weil-cap-checker-v2")` 必然失败）。

**改造：**
- `ir.Runtime` 新增 `Cmd []string` 字段（`json:"cmd,omitempty"`）：native 类型的实际执行命令
- `NativeRunner` 更新：若 `Runtime.Cmd` 非空，使用 `Cmd[0]` 作为解释器，`Cmd[1:]` 作为脚本参数；
  digest 验证改为验证最后一个文件参数（脚本本身），而非解释器
- 新增 `proofctl pin checker --cmd "python3 adapters/cap/bridge.py" [--id <checker-id>]`：
  hash 指定脚本，更新 `checker_digest` 和 `Runtime.Cmd`，回写 graph.json

### T19：`proofctl cas import <file>` — evidence 导入 CAS + size 修正

**问题：** weil `.proofctl/cas/` 为空；`graph.json` evidence 的 `size` 字段均为 0。
`cas.Store.Verify` 会因 size 不匹配失败，导致 `proofctl verify` 无法运行。

**改造：** 新增 `proofctl cas import <file>` 子命令：
- 读取文件，计算 SHA-256，存入 `.proofctl/cas/`
- 在 `.proofctl/graph.json` 里找到 digest 匹配的 evidence 条目，更新 `size` 字段
- 支持多文件：`proofctl cas import certificates/030/primary/*.json`

---

## 任务顺序（M6）

```
T17 (fix-digests)  ──→ 独立，最先做（graph.json 正确后其他步骤才有意义）
T18 (pin checker)  ──→ 依赖 ir.Runtime.Cmd 新字段
T19 (cas import)   ──→ 独立（只操作 CAS + evidence size）
T17+T18+T19 完成后 ──→ proofctl verify --project 可在 weil-lower-bound 跑通
```

---

## Milestone 7 — 多 evidence replay 与路径可移植性

在对 weil-lower-bound 做深度适配时，发现 proofctl 存在三个阻止正确使用的问题。
M7 修复这三个问题，使 proofctl 能服务 weil 并可推广到更多数学证明场景。

### 问题背景

**问题 1：`proofctl replay` 不支持一个 claim 对应多个 evidence**

weil 的每个核心 claim 依赖两个证书（odd + even sector），各需独立生成并验证。
当前 `replay` 只接受一个 `--generator` + 一个 `<digest>`，且 attestation 文件名
固定为 `<claim-id>-replay.json`，第二次调用直接覆盖第一次。

这不是 weil 特有场景——任何多路独立证书（多参数、多 sector、多 prover）都会遇到。

**问题 2：graph.json 中 checker 路径是绝对路径，无法移植**

`"cmd": ["python3", "/Users/.../proofctl/adapters/cap/bridge.py"]`

换机器、换用户、换 CI 环境即失效。proofctl 没有提供相对路径或变量替换机制。

**问题 3：`proofctl release` 写的快照字段不足，无法替代手工 STATUS.json**

`gate.Release()` 写的快照缺少：`certified_radius`（来自 policy target）、
per-certificate 的 checker 元数据（pivot_ratio、witness count 等）。
weil-lower-bound 目前手工维护 STATUS.json，原因就在于此。

---

### T20：`replay` 支持多 evidence（multi-evidence replay）✅

**目标：** 一次 `proofctl replay` 调用可声明同一 claim 的多个 evidence 复现，
全部通过后才写一条 `exact-replay` attestation。

**接口设计（向后兼容）：**

```
proofctl replay \
  --claim thm-main-radius-030 \
  --evidence sha256:<odd-digest>  --generator "python -m src.gen --sector odd  --out {cert}" \
  --evidence sha256:<even-digest> --generator "python -m src.gen --sector even --out {cert}" \
  [--checker "python3 checker/check_certificate.py"]
```

- `--evidence <digest>` 与 `--generator <cmd>` 成对出现，顺序对齐（第 i 个 `--evidence` 对应第 i 个 `--generator`）
- 单 `--evidence` + 单 `--generator` 时行为与 M4/T11 完全一致（向后兼容）
- 全部 evidence 通过后，写一条 attestation，`metadata` 中每个 digest 的结果单独记录
- attestation 文件名保持 `<claim-id>-replay.json`（一个 claim 只有一条 replay 记录）

**实现要点：**
- `cmd_replay.go`：将 `--generator` 改为可重复 flag（`multiStringFlag`），与 positional `<digest>...` 对应
- 或改为 `--evidence <digest>` 可重复 flag + `--generator <cmd>` 可重复 flag，两者数量必须一致
- 循环执行每对（generator, digest），收集结果，全部通过才写 attestation
- attestation `metadata` 新增 `evidence_count`、`evidence_digests`（逗号分隔）字段

### T21：checker `cmd` 支持相对路径和 `${VAR}` 占位符 ✅

**目标：** `graph.json` 中的 checker `cmd` 可以写相对路径（相对项目 root）
或 `${ENV_VAR}` 占位符，由 proofctl 在运行时解析，不再需要绝对路径。

**接口设计：**

```json
"cmd": ["python3", "${PROOFCTL_ADAPTERS}/cap/bridge.py"]
```

或使用相对路径（相对于项目 root，即 `.proofctl/` 所在目录）：

```json
"cmd": ["python3", "adapters/cap/bridge.py"]
```

**实现要点：**
- `NativeRunner`（或 runner 初始化路径）：解析 `cmd` 数组时，对每个元素：
  1. 展开 `${VAR}` → `os.Getenv("VAR")`
  2. 若路径不是绝对路径，join 项目 root
- 不修改 graph.json 本身；解析发生在内存中
- 若展开后路径不存在，报明确错误：`checker cmd[1]: path "adapters/cap/bridge.py" not found (root: /...)`

**weil-lower-bound 适配：** graph.json 中 `cmd` 改为：
```json
"cmd": ["python3", "${PROOFCTL_ADAPTERS}/cap/bridge.py"]
```
并在 CI/CLAUDE.md 中说明 `PROOFCTL_ADAPTERS` 指向 proofctl 仓库的 `adapters/` 目录。

### T22：`release` 快照包含完整认证元数据 ✅

**目标：** `proofctl release`（非 dry-run）写出的快照文件包含足够信息，
使 weil-lower-bound 可以删除手工维护的 STATUS.json。

**快照字段增强：**
```json
{
  "release_target": "thm-main-radius-030",
  "certified_value": "3/10",
  "generated": "2026-08-03",
  "claims_accepted": 12,
  "evidence": [
    {
      "digest": "sha256:de3e...",
      "path_hint": "certificates/030/primary/odd.json",
      "metadata": { "pivot_radius_ratio": "3.3e8", "ldlt_passes": "true", ... }
    }
  ]
}
```

- `certified_value`：从 policy 的 `target` claim statement 中提取，或从 attestation metadata 中取
- `evidence[*].metadata`：从对应 claim 的 attestation `metadata` 字段聚合
- `gate.Release()` 返回后写到 `.proofctl/release-snapshot.json`（不覆盖用户文件）

---

### 任务顺序（M7）

```
T21 (路径可移植) ──→ 独立，影响 runner，最先做（修复后可在 weil 运行 verify）
T20 (multi replay) ──→ 独立，只改 cmd_replay.go
T22 (release 快照) ──→ 依赖 T20（replay metadata 是快照数据源之一）
T20+T21+T22 完成后 ──→ weil-lower-bound 可删除 scripts/replay_030.py 和 STATUS.json
```

