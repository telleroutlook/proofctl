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

