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

---

## Milestone 4 — 吸收 weil 经验，消除手动文件 ✅

目标：weil-lower-bound 不再需要手写 STATUS.json 和 release-manifest.json；
平台提供 replay、negative test、env 管理能力，所有 CAP 类项目受益。

### T9：STATUS.json 字段增强 ✅
### T10：release-manifest.json 自动生成 ✅
### T11：proofctl replay 子命令 ✅
### T12：negative test 脚手架 ✅

`internal/scaffold/templates/negative/` 包含：
- `conftest.py`：pytest fixture（cert_path、cert_data、checker_cmd）
- `test_tamper_basic.py`：5 个通用篡改用例
- `README.md`：如何运行和扩展的说明

### T13：proofctl env 子命令 ✅

---

## Milestone 5 — 性能与多域完善

### T14：proofctl verify --project 并行调度

**背景：** `proofctl verify --project` 当前按拓扑顺序串行调度所有 open claim。
对于 weil-class 项目，odd/even sector 完全独立（在 DAG 中不互相依赖），
可以并发运行，各自命中 CAS 缓存。

**改造：**
- 分析 DAG 找出可并发层（同一拓扑层内无边相连的 claim 集）
- 对每一层内的 claim 并发调用 `verify.Pipeline.Run`
- CAS 缓存已是线程安全的（content-addressed 读写），无需额外锁
- 新增 `--parallel N` flag（默认 = CPU 核数），控制最大并发度
- 输出顺序按 claim ID 排序，不因并发乱序

**收益：** weil odd + even sector 验证从串行变并发，wall-clock 减半。

### T15：lrat 域 policy 模板和 graph 模板

**背景：** `proofctl domains list` 显示 lrat 的 BRIDGE/POLICY/GRAPH 均为 no，
但 `internal/lrat/` 和 `adapters/lrat/` 已有完整实现，只缺脚手架文件。

**改造：**
- `internal/scaffold/templates/lrat-policy.json`：3-claim policy（formula/unsat/verified），
  无 required_metadata_keys（LRAT 不用 CAP bridge）
- `internal/scaffold/templates/lrat-graph.json`：3 个占位 claim 的 DAG 模板
- `scaffold.KnownDomains` lrat 条目填入 PolicyTemplate 和 GraphTemplate
- `proofctl init --domain lrat` 可用

### T16：qmd 域 policy 模板和 graph 模板

**背景：** qmd adapter 已完整实现（从 Pandoc JSON 提取 claim），只缺脚手架文件。

**改造：**
- `internal/scaffold/templates/qmd-policy.json`：通用 policy，允许 `independent-review`
  assurance，无 required_metadata_keys
- `internal/scaffold/templates/qmd-graph.json`：说明由 `proofctl compile --adapter qmd`
  自动从 QMD 文件生成，模板仅提供示意
- `scaffold.KnownDomains` qmd 条目填入 PolicyTemplate 和 GraphTemplate
- `proofctl init --domain qmd` 可用

---

## 任务顺序（依赖关系）

```
M1–M4 全部完成 ✅

T14 (verify 并行)      ──→ 独立，随时可做
T15 (lrat 脚手架)      ──→ 独立，可与 T16 并行
T16 (qmd 脚手架)       ──→ 独立，可与 T15 并行
```

1. **checker 独立性不变：** bridge.py 是协议翻译层，绝不引入 generator 侧代码
2. **核心零领域知识：** `internal/` 下所有包继续零 Weil 依赖
3. **fail-closed 不变：** release gate 逻辑不松动

---

## 任务顺序（依赖关系）

```
T9  (STATUS.json 增强)     ──→ 可并行
T10 (manifest 自动生成)    ──→ 依赖 T9（需要 ProjectRoot 字段）
T12 (negative test 脚手架) ──→ 可并行（纯模板，零 Go 改动）
T11 (proofctl replay)      ──→ T10 后（复用 manifest 结构）
T13 (proofctl env)         ──→ 独立，最后做
```
