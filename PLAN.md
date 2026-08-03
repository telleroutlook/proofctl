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

## 全部已完成 ✅

所有 Milestone（M1–M5）已实现并推送至 main。
