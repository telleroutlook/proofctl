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

## Milestone 4 — 吸收 weil 经验，消除手动文件

目标：weil-lower-bound 不再需要手写 STATUS.json 和 release-manifest.json；
平台提供 replay、negative test、env 管理能力，所有 CAP 类项目受益。

### T9：STATUS.json 字段增强

**问题：** weil 维护自己的 STATUS.json（`certified_radius`、`gates`、`as_of`），
与 proofctl 写出的 STATUS.json 并存，语义重叠，手动维护。

**改造：**
- `ReleaseStatus` 新增 `AsOf string json:"as_of"`（release 时间，RFC3339 date）
- `ReleaseStatus` 新增 `ClaimSummary json:"claim_summary"`
  （`accepted/blocked/open/rejected` 计数，替代 weil gates 的人工汇总）
- 目标：weil-lower-bound 可以删除手写 STATUS.json，用 proofctl 的代替

### T10：release-manifest.json 自动生成

**问题：** weil 手写 release-manifest.json（证书路径、SHA-256、checker_exit、margin_ratio），
这些数据全部来自 attestation.Metadata，完全可以自动生成。

**改造：**
- `Gate` 新增 `ProjectRoot string` 字段
- `Gate.Release()` 成功后自动写出 `<project-root>/release-manifest.json`
- 内容从 attestation.Metadata 提取（cap_format_version、pivot_radius_ratio 等）
  + Evidence 的 path_hint 和 digest
- `proofctl release --dry-run` 不写 manifest，只预览内容

### T11：proofctl replay 子命令

**问题：** weil 有 `scripts/replay_030.py`（D15 deliverable）：冷启动子进程重新生成
+ 独立验证证书，是最强的完整性保证。这个模式对所有 CAP 类项目都适用，
目前 proofctl 没有对应能力（verify 只调用 checker，不调用 generator）。

**改造：** 新增 `proofctl replay` 子命令：
```
proofctl replay \
  --generator "python -m src.generate_certificate --a 3/10 --sector odd --out {cert}" \
  --cert-out /tmp/cert-replay.json \
  <evidence-digest>
```
- 用 `{cert}` 占位符替换为实际临时路径
- 步骤：① 运行 generator → ② 计算 SHA-256 与 evidence digest 对比 → ③ 通过 bridge 调用 checker → ④ 记录 cold_replay_date
- 写出 replay attestation（assurance: `exact-replay`）
- 输出 replay report（digest 匹配结果、checker exit、时间）

### T12：negative test 脚手架

**问题：** weil 有完整的 `tests/negative/`（17 个篡改测试 + 结构拒绝测试），
是"checker 必须拒绝这些输入"的验证套件。对任何 CAP 域都是必要的，
目前 `proofctl init --domain cap` 不生成测试目录。

**改造：**
- `internal/scaffold/templates/negative/` 新增三个测试模板：
  - `test_tamper_basic.py`：5 个通用篡改用例（修改 conclusion、删除必需字段、注入未知字段、版本号错误、空 witnesses）
  - `conftest.py`：pytest fixture（从 `certificates/` 目录找证书）
  - `README.md`：说明如何运行和扩展
- `scaffold.go` 的 cap 域入口写出 `tests/negative/` 目录

### T13：proofctl env 子命令

**问题：** weil 的 `environment.lock` 固定了 Python 版本、python-flint 版本、flint 版本
和 OCI digest，但没有工具自动验证运行环境是否符合 lock。
CAP 类项目的 checker 可重现性依赖于精确的运行时环境。

**改造：** 新增 `proofctl env` 子命令：
- `proofctl env verify --lock environment.lock`：读取 lock 文件，检查当前 Python
  版本和关键包版本是否匹配，输出 PASS/FAIL 报告
- `proofctl env snapshot --checker python3 --out environment.lock`：
  自动抓取当前 Python 版本 + `pip freeze`，生成 lock 文件模板

---

## 关键设计约束

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
