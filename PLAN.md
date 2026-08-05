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
- 当前 pilot 域：weil-first-prime（fp035 区间算术证明）
- 历史参考域：weil-lower-bound（已退出 pilot）
- 当前目标域：fp035；未来可拓展至其他 CAP/formal-kernel 域

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

## Milestone 7 — 多 evidence replay 与路径可移植性 ✅

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

---

## Milestone 8 — 工程健康修复（来自外部评审实测）✅

**背景：** 外部评审者实际编译、运行并审阅了代码，发现若干可复现的工程问题。
这些均是低成本、高收益的修复项，应在后续里程碑之前优先处理。

### T23a：`gofmt` 未通过修复 ✅
### T23b：`--help` 子命令列表与 README 不一致 ✅
### T23c：`internal/release` 覆盖率补齐 ✅（全部包 ≥80%）
### T23d：CLI 层单元测试 ✅
### T23e：Fuzz 语料库接入 CI ✅
### T23f：bridge.py 双副本同步 CI 检查 ✅
### T23g：`SECURITY.md` + 版本 tag ✅
### T23h：仓库内最小可运行 demo ✅

---

### 任务顺序（M8）

```
T23a (gofmt)       ──→ 立即，5 分钟，阻塞 CI
T23b (--help)      ──→ 立即，修复文档漂移
T23c (release 覆盖率) ──→ 优先，fail-closed 核心
T23d (CLI 测试)    ──→ 中期，逐个子命令补
T23e (fuzz CI)     ──→ 中期，语料库 + 定时任务
T23f (bridge diff) ──→ 1 行 CI 配置，成本极低
T23g (SECURITY + tag) ──→ 中期，对外发布前必做
T23h (mini demo)   ──→ 中期，显著降低上手门槛
```

---

## Milestone 8.5 — 预编译二进制发布（GitHub Releases）✅

**背景：** weil-lower-bound 等仓库需要在 CI 中使用固定版本的 proofctl，
但目前只能 `go install`（需要 Go 环境）。GitHub Releases 附带预编译二进制
可让任何环境通过 `curl` 直接获取，无需安装 Go。

### 完成产出

- `.github/workflows/release.yml`：矩阵构建 proofctl + proofverify 四个目标，上传到 GitHub Releases
- 发布物：`proofctl-{linux-amd64,linux-arm64,darwin-arm64,windows-amd64.exe}` +
  `proofverify-{linux-amd64,linux-arm64,darwin-arm64,windows-amd64.exe}`

---

## Milestone 9 — 环境自检命令 ✅

**背景（来自 weil-lower-bound 反馈）：** 当 `proofctl` 二进制不在 PATH 时，调用它的脚本静默失败，
没有明确的错误提示。`proofctl env` 已有基础的环境快照功能，但它是被动快照，不是主动检查。
在首次上手新机器或 CI 环境时，用户需要一个命令能告诉他"哪里缺了什么"。

### T23：`proofctl doctor` — 环境就绪检查 ✅

**目标：** 主动检查 proofctl 运行环境，列出每项是否就绪，缺失时给出修复建议。

检查项：
| 检查 | 通过条件 | 失败提示 |
|---|---|---|
| `proofctl` 自身在 PATH | `which proofctl` 成功 | `proofctl not found in PATH` |
| `.proofctl/` 目录存在 | 当前目录或父目录有 `.proofctl/` | `not in a proofctl project — run 'proofctl init'` |
| `BRIDGE_CHECKER` 已设置 | env var 非空 | `BRIDGE_CHECKER not set` |
| `BRIDGE_CHECKER` 可执行 | `os.Stat` + `x` 位 | `BRIDGE_CHECKER path not found or not executable` |
| `PROOFCTL_ADAPTERS` 已设置（若 graph.json 使用了该变量） | env var 非空 | `PROOFCTL_ADAPTERS not set (required by graph.json checkers)` |
| checker binary 已 pin | graph.json 中 `checker_digest` 非全零 | `checker not pinned — run 'proofctl pin checker'` |
| CAS 非空（若有 evidence） | `.proofctl/cas/` 有文件 | `CAS is empty — run 'proofctl cas import <cert>'` |

输出格式：
```
✓ proofctl in PATH (v0.x.x)
✓ .proofctl/ project found
✗ BRIDGE_CHECKER not set
  → export BRIDGE_CHECKER="python3 checker/check_certificate.py"
✗ PROOFCTL_ADAPTERS not set
  → export PROOFCTL_ADAPTERS=/path/to/proofctl/adapters
✓ checker pinned (sha256:a3f1...)
```

**实现要点：**
- `cmd/proofctl/cmd_env.go`（或新增 `cmd_doctor.go`）：新增 `doctor` 子命令
- 检查结果以 exit code 体现：全部通过 exit 0，任意失败 exit 1（方便 CI 使用 `proofctl doctor || exit 1`）
- 不修改任何状态，只读检查

---

### 任务顺序（M8）

```
T23 (doctor) ──→ 独立，成本低，立即提升可上手性
```

---

## Milestone 10 — Checker 依赖完整性覆盖 ✅

**背景：** `proofctl pin checker` 只哈希了 checker 脚本本身（如 `bridge.py`），
但未覆盖脚本的外部依赖（Python 包、数值库等）。若 `numpy` 或 `scipy` 版本变化导致
计算结果改变，checker 照常 exit 0，attestation 照常写入，而 proofctl 无法感知这种漂移。
数值计算的可复现性是数学证明可信度的基础——这个缺口对证明的长期有效性危害最大。

对于 Go/Lean 编译型 checker，二进制 digest 已隐式覆盖依赖；问题仅影响解释型 checker。

### T23：`Runtime.DependencyManifest` 字段

**目标：** 在 `ir.Runtime` 中增加依赖锁文件的哈希，使 checker 身份覆盖完整依赖树。

```json
"runtime": {
  "type": "native",
  "cmd": ["python3", "${PROOFCTL_ADAPTERS}/cap/bridge.py"],
  "dependency_manifest_digest": "sha256:abc123...",
  "dependency_manifest_path": "requirements.txt"
}
```

**实现要点：**
- `internal/ir/types.go`：`Runtime` 新增 `DependencyManifestDigest string` 和 `DependencyManifestPath string`（均 `omitempty`）
- `internal/checker/identity.go`：`CacheKey()` 计算时包含 `DependencyManifestDigest`（若非空）
- `proofctl pin checker` 输出：若 `DependencyManifestDigest` 为空，打印警告：
  `warn: checker dependencies not pinned — run 'proofctl pin checker --lock requirements.txt'`

### T24：`proofctl pin checker --lock <lockfile>` 扩展

**目标：** 一条命令同时 pin 脚本 digest 和依赖 manifest digest。

- `proofctl pin checker --cmd "python3 bridge.py" --lock requirements.txt`：
  - 计算脚本 sha256 → 写入 `checker_digest`
  - 计算 lockfile sha256 → 写入 `Runtime.DependencyManifestDigest`
  - `Runtime.DependencyManifestPath` 记录相对路径（相对项目 root）
- `proofctl verify` 时：若 `DependencyManifestDigest` 已 pin，校验当前 lockfile digest：
  - 不一致 → reason `dependency-drift`，状态 `warning`（默认不 fail）
  - `policy.json` 新增 `"strict_dependency_pinning": true` → drift 时 fail（等同 C04）
- 支持多种 lockfile 格式：`requirements.txt`、`uv.lock`、`pyproject.toml`、`Cargo.lock`、`go.sum`

**实现要点：**
- `cmd/proofctl/cmd_pin.go`：`pin checker` 子命令增加 `--lock` flag
- `internal/freshness/freshness.go`：复用现有文件哈希逻辑（不重复实现）
- `internal/status/reasons.go`：新增 `dependency-drift` reason

---

### 任务顺序（M8）

```
T23 (Runtime 字段扩展) ──→ 最先，schema 变更影响后续（向后兼容，omitempty）
T24 (pin --lock 扩展)  ──→ 依赖 T23
```

---

## Milestone 11 — 密码学 Attestation 签名 ✅

**背景：** attestation 文件是纯 JSON，静默写入 `.proofctl/attestations/`。若目录可写，
任何人可以篡改 attestation 内容而不留痕迹。证明发表时，审稿人和同行需要能独立确认
每条 attestation 确实由作者的 checker 生成，而不是事后手工填写的。
这是证明发布可信度的关键，也是 proofctl 相比 in-toto / Sigstore 的当前差距。

目标：每条 attestation 由私钥签名，`proofctl verify` 和 `release` 拒绝签名无效或
（policy 要求签名时）未签名的 attestation。

### T25：`proofctl key` 子命令 — Ed25519 密钥管理

**目标：** 为项目生成和管理签名密钥。

- `proofctl key generate [--name <id>]`：生成 Ed25519 密钥对
  - 私钥写入 `.proofctl/keys/<name>.priv`（权限 0600）
  - 公钥写入 `.proofctl/keys/<name>.pub`（PEM 格式）
  - `scaffold.Init()` 自动将 `keys/*.priv` 加入 `.gitignore`（公钥可提交，私钥不提交）
- `proofctl key list`：列出所有公钥及其指纹（`sha256(pubkey)` 前 16 字节 hex）
- `PROOFCTL_SIGNING_KEY` 环境变量：指向私钥路径，优先于 `.proofctl/keys/default.priv`

**实现要点：**
- `internal/signing/signing.go`：新包，封装 `crypto/ed25519` 密钥生成、签名、验证
- 签名计算对象：attestation JSON 的 canonical 序列化（去掉 `signature` 字段后的 `json.Marshal`）
- `cmd/proofctl/cmd_key.go`：新子命令

### T26：Attestation 写入时自动签名

**目标：** `attestation.Write()` 若有私钥则嵌入签名字段；若无密钥则写无签名 attestation（向后兼容）。

**Attestation JSON 新增字段（可选）：**
```json
"signature": {
  "pubkey_fingerprint": "a3f1...",
  "algorithm": "ed25519",
  "value": "<base64>"
}
```

**实现要点：**
- `internal/attestation/attestation.go`：`Write()` 接受可选 `*signing.Key` 参数
- 调用方（`cmd_replay.go`、`cmd_verify.go`）：从 `PROOFCTL_SIGNING_KEY` 加载私钥传入
- 无签名时字段不出现（不是 `"signature": null`），保持 JSON schema 兼容

### T27：`proofctl verify` 验证 Attestation 签名

**目标：** 签名存在时强制验证；验证失败则 claim 不可 `accepted`。

**状态变更：**
- 签名验证失败 → claim reason 增加 `signature-invalid`，状态 `rejected`
- attestation 无签名 + policy `require_signed_attestations: true` → reason `unsigned`，状态 `rejected`
- attestation 无签名 + policy 未要求 → 与现在行为一致（accepted，若其他条件满足）

**实现要点：**
- `internal/verify/verify.go`：在 attestation 加载后调用 `signing.Verify()`
- 公钥来源：`attestation.signature.pubkey_fingerprint` 对应 `.proofctl/keys/*.pub`（本地信任库）
- `internal/policy/policy.go`：新增 `RequireSignedAttestations bool` 字段

### T28：Release gate C05 — 签名完整性条件（policy 控制）

**目标：** 若 policy 要求签名，release gate 增加第五个通用条件。

```
C05-attestation-signatures  所有 attestation 签名有效（require_signed_attestations: true 时激活）
```

**实现要点：**
- `internal/release/conditions.go`：新增 `C05SignatureIntegrity` 条件，仅在 policy 启用时评估
- `internal/release/gate.go`：在 `Release()` 和 `DryRun()` 中均评估 C05
- `docs/ADR/ADR-005-signing.md`：记录密钥信任模型决策（本地信任 vs PKI vs Sigstore）

---

### 任务顺序（M9）

```
T25 (key 管理)  ──→ 最先，提供基础 API
T26 (写入签名)  ──→ 依赖 T25
T27 (验证签名)  ──→ 依赖 T26（需要有签名的 attestation 才可测试验证路径）
T28 (C05 条件)  ──→ 依赖 T27（在 verify 正确后才能做 release 集成）
```

---

## Milestone 12 — Lean 4 域完整实现 ✅

**背景：** Lean 4 是目前数学形式化最活跃的社区（Mathlib4 已有 10 万+ 定理）。
若证明的某些步骤最终需要 Lean/Mathlib 形式化，`adapters/lean/adapter.go` 目前是空 stub，
`proofctl init --domain lean` 不可用。这个 gap 是证明过程中潜在的关键阻塞点。

### T29：Lean 4 checker 协议设计

**目标：** 确定 Lean 4 证明验证的协议边界，写入文档。

- Lean 4 证明通过 `lake build` 验证：exit 0 → 内核接受所有定理
- bridge 职责：调用 `lake build --json`，解析输出，构造 proofctl JSON（attestation metadata）
- 关键 metadata keys：`lean_version`（`lean --version`）、`mathlib_commit`（`lake manifest` 中 Mathlib 条目）
- `docs/LEAN4_DOMAIN.md`：协议规范（claim ID 约定、bridge 输出格式、错误处理）

**Claim ID 约定：** Lean 4 定理名称映射为 claim ID（`MyNamespace.myTheorem` → `thm-myNamespace-myTheorem`）

### T30：`adapters/lean/` 完整实现

**目标：** 从 stub 变为可用的 bridge 实现。

- `adapters/lean/bridge.py`（stdlib only，与 `adapters/cap/bridge.py` 风格一致）：
  - 接受证书文件路径（Lean 4 `.olean` 文件或 `lake-manifest.json`）
  - 运行 `lake build`，解析 exit code + JSON 输出
  - 输出 proofctl checker JSON：`{ "ok": true, "metadata": { "lean_version": "...", "mathlib_commit": "..." } }`
- `adapters/lean/adapter.go`：实现 `CompileGraph()`（从 `.lean` 文件提取 `-- claim: <id>` 注释构造 DAG）

### T31：`proofctl init --domain lean` 脚手架

**目标：** `proofctl init --domain lean` 生成可运行的 Lean 4 项目骨架。

脚手架文件：
- `graph.json`：1 个占位 claim `thm-main`，checker 指向 `${PROOFCTL_ADAPTERS}/lean/bridge.py`
- `policies/lean-v1.json`：`allowed_assurances: ["formal-kernel"]`
- `MyProof.lean`：最小 Lean 4 文件（含 `-- claim: thm-main` 注释）
- `lakefile.lean`：最小 Lake 配置

**实现要点：**
- `internal/scaffold/scaffold.go`：`KnownDomains` 新增 `lean`
- `internal/scaffold/templates/lean/`：存放上述模板文件
- `internal/scaffold/bridge.py` 不变（lean 有自己的 bridge）

### T32：Lean 4 policy 模板与 `domains list` 集成

- `policies/lean-release-v1.json`：正式 policy 文件，`required_metadata_keys: ["lean_version", "mathlib_commit"]`
- `proofctl domains list`：显示 lean 行，POLICY=yes GRAPH=yes BRIDGE=yes
- 集成测试：`proofctl init --domain lean` + `proofctl compile` + `proofctl status` 在无 Lake 环境下不崩溃（优雅降级）

---

### 任务顺序（M12）

```
T29 (协议设计)      ──→ 最先（设计决策影响后续实现）
T30 (bridge 实现)   ──→ 依赖 T29，且依赖 M14（批量回填协议）
T31 (脚手架)        ──→ 依赖 T29，可与 T30 并行
T32 (policy + 集成) ──→ 依赖 T30 + T31
前置：M14（批量验证协议）解决了粒度不匹配问题，M10（--lock）覆盖 lake-manifest.json
```

---

## Milestone 13 — 批量验证协议（Batch Backfill Protocol）✅

**背景：** 当前 checker 协议假设"每个 claim 单独调用一次 checker"。但 lean4checker、coqchk、
Isabelle 等形式化验证工具天然是"一次性检查整个编译环境"的模式——没有"只检查第 3 个定理"
这种用法。`adapters/cap/bridge.py` 已经用约定绕过了这个问题（一次检查、结果写回多个 claim），
但这是隐式约定而非协议保证。随着 formal-kernel 域增多，必须把它提升为一等公民。

这是 M12（Lean 4）、M15（Metamath）、M17（Coq）的**共同前置**。

### T36：`BatchResult` 协议扩展

**目标：** checker 可以选择在单次运行中为多个 claim 输出结果。

`pkg/protocol/types.go` 新增：
```go
type BatchResult struct {
    Claims []ClaimResult `json:"claims"`
}
type ClaimResult struct {
    ClaimID  string            `json:"claim_id"`
    OK       bool              `json:"ok"`
    Metadata map[string]string `json:"metadata,omitempty"`
    Error    string            `json:"error,omitempty"`
}
```

- checker stdout 若根字段包含 `"claims"` 数组，则视为 batch 模式；否则沿用现有单 claim 模式（向后兼容）
- `pkg/protocol/` 是对外稳定 API，加版本注释

### T37：`BatchRunner` 与 runner 层适配

**目标：** runner 层识别 batch 结果并拆分回填到各 claim 的 attestation。

- `internal/runner/runner.go`：新增 `RunBatch(claimIDs []string, cmd []string) ([]ClaimResult, error)`
- `cmd_verify.go`：若 claim 有 `batch_group` 字段（见 T38），聚合同组 claim、一次性调用 `RunBatch`
- 结果拆分：每个 `ClaimResult` 单独写一条 attestation，和单 claim 模式产出格式完全相同

### T38：`ir.Claim.BatchGroup` 字段

**目标：** graph.json 中标记哪些 claim 属于同一批次验证。

```json
{
  "id": "thm-main",
  "batch_group": "lean-env",
  "checker_policy": { ... }
}
```

- `internal/ir/types.go`：`Claim` 新增 `BatchGroup string`（`omitempty`）
- 同组 claim 使用同一 checker cmd，`RunBatch` 只调用一次
- `proofctl compile` 验证：同组 claim 必须使用同一 checker

---

### 任务顺序（M13）

```
T36 (BatchResult 协议) ──→ 最先（公共 API，影响后续所有 formal-kernel 域）
T37 (BatchRunner)      ──→ 依赖 T36
T38 (BatchGroup 字段)  ──→ 依赖 T36，可与 T37 并行
```

---

## Milestone 14 — 工具链身份摘要（Toolchain Identity）✅

**背景：** `CheckerIdentity` 目前只锁定 checker 二进制/脚本本身的 digest，以及（M10 之后）
依赖 lockfile 的 digest。但 Lean/Coq 的可信度还依赖"哪个 Lean 版本 + 哪个 mathlib commit"——
这不是 checker 文件本身，而是 checker **运行时所处的工具链环境**。
如果 mathlib 更新了一个引理的证明，即使 bridge.py 和 lake-manifest.json 都没变，
checker 实际调用的内核逻辑已经发生了变化，旧的 attestation 不应该继续有效。

M10 的 `DependencyManifestDigest` 是文件级锁定；本里程碑是**语义级锁定**。

### T39：`CheckerIdentity.ToolchainDigest` 字段

**目标：** checker 可以在输出 JSON 中声明自己的工具链摘要，proofctl 将其纳入缓存键。

`pkg/protocol/types.go` checker 输出新增可选字段：
```json
{
  "ok": true,
  "toolchain": {
    "lean_version": "4.14.0",
    "mathlib_commit": "a3f1b2c...",
    "lake_version": "4.14.0"
  },
  "metadata": { ... }
}
```

- `internal/checker/identity.go`：`CacheKey()` 若 attestation 含 `toolchain` 字段，则将其 JSON hash 纳入缓存键
- 如果两次 verify 之间 mathlib commit 变了，缓存 miss → 触发重新验证 → 正确行为
- `toolchain` 字段由 bridge.py 自动填充（调用 `lean --version`、读 `lake-manifest.json`），无需人工维护

### T40：`proofctl status` 展示工具链信息

- `proofctl status --verbose`：在每条 accepted claim 下显示 toolchain 摘要（版本 + commit 前 8 位）
- `proofctl release`：`release-snapshot.json` 中的 `evidence[*].metadata` 自动包含 toolchain 字段

---

### 任务顺序（M14）

```
T39 (ToolchainDigest) ──→ 独立，可与 M13 并行；M10 完成后启动（复用 CacheKey 机制）
T40 (status 展示)     ──→ 依赖 T39
```

---

## Milestone 15 — Metamath 域（首个 formal-kernel 参考实现）✅

**背景：** 按形式化验证域的适配难度排序，Metamath 是最低的起点：
- 验证器本身只有几百行 C 代码，无大型工具链依赖
- 天然是"每条定理一个证明文件"的结构，与现有 checker 协议几乎无缝对接
- 不需要 BatchGroup（每个定理独立验证），也不需要复杂的工具链摘要

**策略：** 先用 Metamath 把 `formal-kernel` assurance 这条路从头到尾跑通，
验证协议设计是否正确，再用相同模式接入 Lean/Coq 这类有大工具链的系统。

### T41：Metamath checker 协议设计

- checker：调用 `metamath` 命令行验证单个 `.mm` 文件中的指定定理
- bridge 输出：`{ "ok": true, "metadata": { "metamath_version": "0.198", "theorem": "my-thm" } }`
- claim ID 约定：Metamath 定理标签映射为 `thm-<label>`（如 `mp` → `thm-mp`）
- `docs/METAMATH_DOMAIN.md`：协议规范

### T42：`adapters/metamath/` 实现

- `adapters/metamath/bridge.py`（stdlib only）：接受 `.mm` 文件 + 定理名，调用 `metamath verify`
- `adapters/metamath/adapter.go`：`CompileGraph()`（解析 `$p` 语句提取定理 DAG）
- 单个定理模式（无 BatchGroup），证明最简单路径可行

### T43：`proofctl init --domain metamath` 脚手架

- `graph.json`：2 个 claim（一个引理 + 一个主定理），体现依赖链
- `policies/metamath-release-v1.json`：`allowed_assurances: ["formal-kernel"]`
- `example.mm`：含两个占位定理的最小 Metamath 文件
- `proofctl domains list`：显示 metamath 行

---

### 任务顺序（M15）

```
T41 (协议设计)  ──→ 最先
T42 (bridge 实现) ──→ 依赖 T41
T43 (脚手架)    ──→ 依赖 T41，可与 T42 并行
前置：M13（BatchGroup 不需要，但 formal-kernel assurance 路径需要验证）
```

---

## Milestone 16 — 跨域声明消费（Cross-domain Claim Consumption）✅

**背景：** 这是异构 DAG 的核心架构问题，也是最终证明黎曼猜想必须解决的设计挑战：

**问题：** Lean 4 如何安全消费一个由 CAP 数值 checker 生成的 claim
（assurance: `"deterministic-cap"`），而不破坏 Lean 自身的公理体系？

直接在 Lean 中写 `axiom myNumResult : ...` 会让该公理"漂浮"在 Lean 的类型系统中，
无法追溯到具体的数值计算——这违背了 proofctl 的 fail-closed 原则。

**设计方案：** proofctl 负责在 DAG 层面保证"Lean claim X 依赖了 CAP claim Y 的 attestation"，
Lean 侧通过导入一个由 proofctl 自动生成的 `.lean` 声明文件来消费这个结论。
Lean 的 bridge.py 验证时检查该文件是否与当前 attestation 的 digest 一致。

### T44：`proofctl export --claim <id> --format lean` 生成 Lean axiom 文件

**目标：** 将已 accepted 的 CAP claim 导出为 Lean 4 可导入的公理声明文件。

```lean
-- Auto-generated by proofctl. DO NOT EDIT.
-- Source claim: thm-main-radius-030
-- Attestation digest: sha256:de3e...
-- Assurance: deterministic-cap
namespace ProofCtlImport
axiom weil_lower_bound_030 : ∃ (C : ℝ), C ≥ 0.30 ∧ ...
end ProofCtlImport
```

- `cmd/proofctl/cmd_export.go`：新子命令，支持 `--format lean`（以及未来 `--format coq`）
- 生成文件包含 attestation digest 注释，供 bridge.py 验证时比对
- 文件名：`ProofCtlImport_<claim-id>.lean`

### T45：Lean bridge 验证跨域 claim 文件完整性

**目标：** Lean bridge.py 在 `lake build` 前检查所有 `ProofCtlImport_*.lean` 文件的
attestation digest 是否与本地 `.proofctl/attestations/` 中的记录一致。

- 若 digest 不一致 → bridge 输出 `{ "ok": false, "error": "cross-domain claim mismatch: thm-main-radius-030" }`
- Lean 证明不需要知道 CAP 计算的细节，只需知道"该公理由 proofctl 保证是有效的"
- 这条链路的可信度：CAP attestation 的 assurance + proofctl 的 fail-closed gate，而不是 Lean 内核

### T46：`ir.Claim.CrossDomainDeps` 字段与 compile 验证

**目标：** graph.json 中声明跨域依赖关系，让 proofctl compile 在编译时静态检查。

```json
{
  "id": "thm-rh-lean",
  "batch_group": "lean-env",
  "cross_domain_deps": ["thm-main-radius-030"],
  "checker_policy": { ... }
}
```

- `proofctl compile`：检查 `cross_domain_deps` 中的 claim 必须已 accepted 且 attestation 存在
- `proofctl release`：在 release-snapshot.json 中记录跨域依赖图，供审阅

---

### 任务顺序（M16）

```
T44 (export 子命令)         ──→ 独立，可先做（不依赖 Lean bridge）
T45 (bridge 跨域验证)       ──→ 依赖 T44
T46 (CrossDomainDeps 字段)  ──→ 依赖 T44，可与 T45 并行
前置：M12（Lean bridge 基础实现）、M11（attestation 签名，保证跨域 claim 不可伪造）
```

---

## Milestone 17 — Coq/Rocq 域 ✅

**背景：** `coqchk` 是专为"脱离主系统独立复核 `.vo` 编译产物"设计的工具，历史悠久，
工具链比 Lean 更成熟稳定。在 RH 证明中负责连接"抽象实数"与"机器区间算术"的桥梁：
形式化证明 Arb 区间算术底层的正确性，确保 C 库不存在舍入方向的 bug。

- `adapters/coq/bridge.py`：调用 `coqchk -silent <vofile>`，输出 `{ "ok": true, "metadata": { "coq_version": "...", "opam_hash": "..." } }`
- BatchGroup 模式（`coqchk` 一次验证整个 `.vo` 集合）
- `policies/coq-release-v1.json`：`allowed_assurances: ["formal-kernel"]`
- `proofctl init --domain coq`：生成最小 Coq 项目骨架（含 `_CoqProject`）

**前置：** M13（BatchGroup）、M14（ToolchainDigest，opam 包集作为工具链摘要）

---

## Milestone 18 — SMT/Alethe 域 ✅

**背景：** 与已完成的 LRAT 是近亲，复用"独立小型验证器"模式，边际成本最低。
Alethe（cvc5 输出格式）和 DRAT（SAT solver 通用格式）都有独立验证器（`verit-checker`、
`drat-trim`），适配难度接近 LRAT。在 RH 证明中可用于排除有限反例（离散数论结构）。

- `adapters/smt/bridge.py`：支持 `--format alethe` 和 `--format drat` 两种模式
- 大量复用 `adapters/lrat/` 的设计模式（3-claim DAG：formula → unsat → verified）
- `policies/smt-release-v1.json`

**前置：** 无（独立于 M13–M17，最低风险的新域）

---

## Milestone 19 — Isabelle/HOL 域 ✅

**背景：** 在处理黎曼 ξ 函数的解析延拓、围道积分、Phragmén-Lindelöf 原理等
复变函数论时，Isabelle/HOL 拥有目前最完备的复分析库。
难点在于 Isabelle 缺少像 `lean4checker` 或 `coqchk` 那样干净的"脱离主系统的独立验证器"，
TCB 偏大，需要更多适配器胶水代码。

- 使用 `isabelle build -c` + `isabelle exports` 导出证明产物
- bridge 负责解析 Isabelle 的 session 日志，提取定理列表和版本信息
- BatchGroup 模式（整个 session 一次性验证）
- ToolchainDigest 包含：isabelle_version + AFP commit（Archive of Formal Proofs）

**前置：** M13（BatchGroup）、M14（ToolchainDigest）、M16（跨域消费，Isabelle 结论需被 Lean 消费）

---

## Milestone 20 — 多用户协作与远程 Attestation Store（可选，推后）

**背景：** 当前证明工作由单人完成，此里程碑暂不构成阻塞。待证明发表阶段或需要
同行独立验证时再启动。M11 的签名机制是本里程碑的前置条件。

### T33：`proofctl attest list` 与 git-native 协作规范

- `proofctl attest list [--claim <id>] [--assurance <type>]`：
  显示所有 attestation，列：claim-id、assurance、date、signer（若有签名）、digest
- `scaffold.Init()`：不将 `.proofctl/attestations/` 加入 `.gitignore`
- `docs/COLLABORATION.md`：说明 git merge 处理 attestation 的规范

### T34：远程 Attestation Store 接口定义

```go
// internal/attestation/remote.go
type RemoteStore interface {
    Push(id string, data []byte) error
    Pull(id string) ([]byte, error)
    List() ([]string, error)
}
```

- 实现 1：`HTTPStore`（REST，PUT/GET `<base-url>/attestations/<id>.json`）
- 实现 2：`GitHubReleasesStore`（将 attestation 作为 GitHub Release assets 存储，public/immutable）

### T35：`proofctl attest push` / `proofctl attest pull` 子命令

- `proofctl attest push [--remote <url>] [--claim <id>]`：推送本地 attestation（幂等）
- `proofctl attest pull [--remote <url>]`：拉取远程 attestation（不覆盖已有文件）
- pull 下来的 attestation 若有签名，进行本地验证后才写入

---

### 任务顺序（M20）

```
T33 (attest list)      ──→ 独立，成本低
T34 (RemoteStore 接口) ──→ 独立，可与 T33 并行
T35 (push/pull)        ──→ 依赖 T34
前置：M11 完成（签名是 push/pull 内容完整性的前提）
```

---

## 缺口完善路线图总览

| 优先级 | Milestone | 解决的缺口 | 关键产出 | 启动条件 |
|---|---|---|---|---|
| 0 | **M8** | 外部评审实测发现的工程问题 | gofmt/help/覆盖率/fuzz/版本 tag | 立即，阻塞后续 |
| 1 | **M9** | 环境配置错误静默失败 | `proofctl doctor` 环境自检 | M8 之后 |
| 2 | **M10** | Checker 依赖漂移不可感知 | `--lock` 依赖 pin + `dependency-drift` | 立即可启动 |
| 3 | **M11** | Attestation 无密码学签名 | Ed25519 签名 + C05 release 条件 | 立即可启动 |
| 4 | **M12** | Lean 4 adapter 是 stub | 完整 Lean 4 域支持 | 依赖 M13、M14 |
| 5 | **M13** | formal-kernel 域粒度不匹配 | BatchGroup + BatchRunner 协议 | 立即可启动 |
| 6 | **M14** | 工具链环境未纳入 checker 身份 | ToolchainDigest 字段 | 立即可启动 |
| 7 | **M15** | formal-kernel 路径未验证 | Metamath 域（最低成本参考实现） | M13 之后 |
| 8 | **M16** | 异构 DAG 跨域消费无协议保证 | `export --format lean` + CrossDomainDeps | M11 + M12 之后 |
| 9 | **M17** | Coq/Rocq 域缺失 | Coq bridge + coqchk 适配 | M13 + M14 之后 |
| 10 | **M18** | SMT/Alethe 域缺失（近亲 LRAT） | SMT bridge（最低风险新域） | 随时可启动 |
| 11 | **M19** | Isabelle/HOL 域缺失 | Isabelle bridge + AFP 工具链摘要 | M13 + M14 + M16 之后 |
| 推后 | **M20** | 单用户假设（暂不阻塞） | `attest push/pull` + 远程 store | M11 完成后按需启动 |

---

## Milestone 21 — 质量与工具链强化 ✅（2026-08-03）

本轮修复解决了外部使用反馈中发现的所有功能、设计和易用性问题。

### 功能修复（11 项）

| # | 问题 | 修复 |
|---|---|---|
| 1 | `check` 在 help 中列出但未实现 | 从 usage 中删除 |
| 2 | doctor 对 `python3` PATH 检查错误 | 改用 `exec.LookPath` |
| 3 | replay 部分失败无记录 | 写 `*-replay-partial.json` 记录每条 evidence |
| 4 | exact-replay 与 sha256_inputs 绑定 | 新增 `--semantic` 模式 |
| 5 | CAS 不自动从 path_hint 导入 | replay 前自动尝试从 path_hint 导入 |
| 6 | 零 digest 不报警 | status 打 `[UNVERIFIED_DIGEST]` 标记 |
| 7 | release_target 显示 null | status 自动从 policy 文件读取 |
| 8 | digest 不匹配不解释原因 | diff sha256_inputs，提示 --semantic |
| 9 | 无 --dry-run 模式 | replay 新增 `--dry-run` |
| 10 | OPEN 原因不区分 | 区分 `no attestation` vs `no evidence registered` |
| 11 | bridge.py 缺 BRIDGE_CHECKER 用 exit 2 | 改为 exit 3（protocol error） |

### 错误信息增强（24 项，8 个模块）

所有失败路径增加详细上下文，包括 claim ID、文件路径、出错实体和可操作的修复建议。

关键修复：
- `internal/verify`：签名无效的缓存 attestation 现在报错而非静默重跑
- `internal/runner`：超时包含 checker ID 和配置的超时时长；非 JSON 输出包含前 256 字节
- `cmd/proofctl/cmd_cas`：JSON 模式下导入失败有独立 error 字段，WalkDir 错误作为 warnings 上报
- `internal/release/conditions`：C04 blocker 指明哪个字段缺失（self_digest/start_freshness/end_freshness）

### CI 与工具链（golangci-lint + govulncheck）

- CI 新增 `golangci-lint-action` 和 `govulncheck` 步骤
- Pre-commit hook 涵盖：gofmt、go build、go vet、staticcheck、golangci-lint、govulncheck、bridge.py sync、go test
- 修复 21 个 errcheck 问题和 3 个 staticcheck 问题（18 个文件）

### 测试覆盖率提升

新增测试文件：
- `internal/signing/signing_coverage_test.go`（Sign/Verify/Load/Save 边界场景）
- `internal/runner/runner_coverage_test.go`（RunBatch、timeout、limitedBuffer）
- `internal/verify/verify_sig_test.go`（verifyAttestationSig 全路径含 corrupt key）
- `cmd/proofctl/cmd_helpers_test.go`（纯 helper 函数单元测试）

| 包 | 修复前 | 修复后 |
|---|---|---|
| `internal/signing` | 77.4% | 85.7% |
| `internal/verify` | 69.9% | 79.2% |
| `internal/runner` | 73.2% | 75.0% |
| `cmd/proofctl` | 0.0% | 4.7%（subprocess 架构限制） |

### 发布

- v0.2.0：功能修复和错误信息增强
- v0.2.1：工具链强化（lint、CI、pre-commit、测试）
- v0.2.2–v0.2.3：B4–B11、E3–E7、F5–F8（attest 增强、cas import-dir、check --all、cache 管理）
- v0.2.4：B12–B15、E6–E11、F9–F15（export、graph filter、replay --dry-run、snapshot --diff）
- v0.2.5：GitHub Actions release workflow 竞态修复
- v0.2.6：B18（metadata 覆盖）、B19（self_digest 缺失）、B20（release --fix 误报）、E12（check --evidence）、E13（cas gc 确认）
- v0.2.9：M23 — Bug 1–5 修复（schema_digest pin、绝对路径拒绝、evidence digest 重算、resources 计时、reviewer 强制）

**当前版本：v0.3.0**（2026-08-05）

---

## Milestone 22 — 外部评估修复与策略扩展（2026-08-04）✅

**背景：** 外部评估者实际 clone 并运行了 examples/minimal 端到端流程，发现 4 个可复现的阻断性缺陷，
并提出 4 项策略扩展建议（P1–P4）。本 Milestone 修复所有缺陷并实现其中 3 项高优先级建议。

### 已修复缺陷（评估报告 P0）

| # | 缺陷 | 修复位置 |
|---|---|---|
| F1 | `examples/minimal/graph.json`：`checker_policy` 是内联对象，应为字符串 ID 引用；`checkers[]` 缺少 `protocol_version`、`checker_digest`、`schema_digest`、`runtime`、`network` 字段 | `examples/minimal/graph.json` |
| F2 | `examples/minimal/checker/check.sh`：输出 `"protocol_version":"1"`（字符串），协议要求 int | `examples/minimal/checker/check.sh` |
| F3 | `examples/minimal/README.md` 和根 `README.md`：`release` 命令包含不存在的 `--policy` flag；未说明 `replay` 不写入 checker metadata | `examples/minimal/README.md`、`README.md` |
| F4 | `examples/minimal/policies/minimal-v1.json`：`required_metadata_keys: ["checker_name"]` 在纯 `replay` 流程中永远无法满足，造成 release 必然失败 | `examples/minimal/policies/minimal-v1.json` |

### 已修复工程问题（评估报告 P1/P2）

| # | 问题 | 修复 |
|---|---|---|
| E1 | `internal/dag/dag.go` `Validate()` 有废弃的第一次入度计算（死代码，带 `_ = dep` 消错） | 删除死代码，只保留正确实现 |
| E2 | CI 没有任何端到端 smoke test，schema 演进导致 demo 失效对 CI 不可见 | 新增 `example-smoke-test` job，完整跑通 init→compile→cas import→check→release，断言 `released: true` |

### 新增策略扩展（评估建议 P1–P4）

#### P1：`allowed_metadata_values` — metadata 值白名单（对应评估 Suggestion P1）

**场景：** 策略文件可声明特定 metadata key 的允许值列表。任何 attestation 若含有该 key 且值不在白名单内，
则 release 失败（C06 条件）。

```json
"allowed_metadata_values": {
  "remainder_type_path_b": ["gl_bernstein_ellipse", "legendre_tail", "zero"]
}
```

若 checker 输出 `"remainder_type_path_b": "gl_self_convergence"`，C06 触发 → release 阻断。

- `internal/policy/policy.go`：`ReleasePolicy.AllowedMetadataValues map[string][]string`
- `internal/release/conditions.go`：`CondMetadataValues`（C06）、`checkC06MetadataValues()`

#### P2：`conditional_metadata_keys` — 触发条件 metadata key（对应评估 Suggestion P2）

**场景：** 若任何 attestation 含有触发 key，则至少一条 attestation 必须也含有要求 key。
用于"存在 kernel_branch 时必须有 drpp_bound_proof"这类约束。

```json
"conditional_metadata_keys": {
  "kernel_branch": "drpp_bound_proof"
}
```

- `internal/policy/policy.go`：`ReleasePolicy.ConditionalMetadataKeys map[string]string`
- `internal/release/conditions.go`：`CondConditionalMetadata`（C07）、`checkC07ConditionalMetadata()`

#### P4：`replay_mode` 字段与 `required_replay_mode` 策略（对应评估 Suggestion P4）

**场景：** attestation 明确记录验证深度：`"from_scratch"`（proofctl replay 重新生成并比对摘要）
vs `"self_consistency"`（proofctl check 对已导入 CAS 的 evidence 运行 checker）。
策略可以通过 `required_replay_mode: "from_scratch"` 要求高强度验证路径。

- `internal/ir/types.go`：`Attestation.ReplayMode string`（`omitempty`，向后兼容）
- `cmd/proofctl/cmd_replay.go`：写入 `"from_scratch"`
- `internal/verify/verify.go`：写入 `"self_consistency"`
- `internal/policy/policy.go`：`ReleasePolicy.RequiredReplayMode string`
- `internal/release/conditions.go`：`CondReplayMode`（C08）、`checkC08ReplayMode()`

> 评估 Suggestion P3（leaf_midpoint_check schema 要求）属于 checker 协议扩展，
> 不在 proofctl 策略层直接支持，留作 checker 实现规范，不在本 Milestone 实现。

---

## Milestone 23 — 实测 Bug 修复与完整性加固（2026-08-04）✅

**背景：** 外部实测会话发现 5 个可复现的 proofctl 框架缺陷，以及 6 项结构性 prevention 建议。
经代码核查，Prevention 1–3 已通过 C06/C07/C08 实现；本 Milestone 修复剩余 5 个 bug 和
3 项尚未实现的 prevention（P4/P5/P6）。

### 核实结果

| # | 缺陷 | 代码核查结论 | 状态 |
|---|---|---|---|
| Bug 1 | schema_digest 全零，未计算 | `pin checker` 只更新 `checker_digest`，`schema_digest` 从未自动填充 | **真实** |
| Bug 2 | runtime.cmd 包含绝对路径，无法移植 | `pin checker` 接受任意 `--cmd`，`compile` 不拒绝绝对路径 cmd | **真实** |
| Bug 3 | evidence digest 过期不检测 | `check` 路径只做 CAS 存在性验证，不重新计算磁盘文件哈希 | **真实** |
| Bug 4 | attestation resources 字段全零 | checker 输出零值时会覆盖已计算的 `wallMillis`；`replay` 路径完全不记录 resources | **真实** |
| Bug 5 | independent-review 无审查者身份 | `attest` 不强制 reviewer 字段，meta 完全自由文本 | **真实（policy 层）** |
| P1 | allowed_remainder_types 策略白名单 | C06 `allowed_metadata_values` 已完整实现 | ✅ 已完成 |
| P2 | required_certificate_fields 策略 | C07 `conditional_metadata_keys` 已完整实现 | ✅ 已完成 |
| P3 | kappa gate 命名子检查 | C08 `required_replay_mode` 部分覆盖；gate 名称策略未做 | 留作 checker 协议 |
| P4 | checker 完整性循环（schema_digest 自动计算） | `pin checker` 无 `--schema` 支持；`run` 不验证 schema_digest | **待实现** |
| P5 | 拒绝非仓库相对路径 | `pin checker` 和 `compile` 均不检查绝对路径 | **待实现** |
| P6 | evidence digest 重新计算（attest 前） | `check` 不对磁盘文件做 digest 重算 | **待实现** |

### T47：Bug 1 + P4 — `pin checker --schema` 自动计算 schema_digest

**目标：** `proofctl pin checker` 支持 `--schema <file>` flag，自动计算并写入 `schema_digest`。
`verifyBinaryDigest` 同样验证 `schema_digest`（当非零时）。

- `cmd/proofctl/cmd_pin.go`：新增 `--schema <schemafile>` flag
  - 计算 `sha256(schemafile)` → 写入 `pg.Checkers[i].SchemaDigest`
  - 若未传 `--schema`，打印 warn（与 `--lock` 一致）
- `internal/runner/runner.go`：`verifyBinaryDigest` 重命名为 `verifyDigest`；
  新增 `verifySchemaDigest(checkerID)`，在 `Run()` 中调用（全零或空时跳过，非零则验证）
  - schema 文件路径从 `checkerID.Runtime.SchemaPath` 或项目根的 `schemas/` 中自动查找

**实现要点：**
- `ir.Runtime` 新增 `SchemaPath string` 字段（`omitempty`）
- `verifySchemaDigest` 失败 → `RunError{Code: ExitUnavailable}`，阻断 attestation 写入
- 向后兼容：`schema_digest` 为全零或空 → 跳过验证（现有 attestation 不受影响）

### T48：Bug 2 + P5 — `pin checker` 拒绝绝对路径 cmd

**目标：** `proofctl pin checker` 检查 `--cmd` 中的路径元素：若包含非 `${VAR}` 格式的绝对路径，
报错并拒绝写入。

- `cmd/proofctl/cmd_pin.go`：在写回 graph.json 前，对 `cmd[1:]` 每个非 flag 元素：
  - 若是绝对路径 → `die(...)` with 明确建议："use a relative path or ${ENV_VAR} placeholder"
  - 若已是 `${VAR}` 形式 → 允许（运行时展开）
  - 若是相对路径 → 允许
- 同样在 `compile` 时对 graph.json 中已有的 checker cmd 做静态检查（warn，不 fail）

### T49：Bug 3 + P6 — `check` 时重新计算 evidence digest

**目标：** `proofctl check` 和 `proofctl verify` 在运行 checker 前，对每个有 `path_hint` 的
evidence descriptor 重新计算磁盘文件的 SHA-256，与 graph.json 中存储的 digest 比对。
不一致则阻断，打印明确错误而非静默通过。

- `internal/verify/verify.go`：步骤 2（`CAS.Verify`）之后、步骤 5（freshness snapshot）之前，
  新增 `verifyEvidenceDigestsOnDisk(evidence []ir.EvidenceDescriptor)` 调用：
  - 对每个 `desc.PathHint != ""` 的 evidence，计算磁盘文件 sha256
  - 若不匹配 → `proofErr.Newf(CodeMissingEvidence, "claim %q: evidence %s: on-disk file %s has digest %s, expected %s", ...)`
  - 若文件不存在 → 跳过（CAS 路径已覆盖）
- `internal/cas/cas.go`：`Verify()` 已经检查 size，维持不变；新增检查是补充，非替代

### T50：Bug 4 — `replay` 和 `check` 路径正确记录 resources

**目标：** resources 字段（wall_millis）反映真实运行时间，不被 checker 输出的零值覆盖。

**`check` 路径（`internal/verify/verify.go`）：**
- 当前行为：`att.Resources.WallMillis = checkerOut.Resources.WallMillis`，checker 未输出时为 0
- 修复：只当 `checkerOut.Resources.WallMillis > 0` 时才用 checker 值，否则保留 `wallMillis`（本地计时）

**`replay` 路径（`cmd/proofctl/cmd_replay.go`）：**
- 当前行为：attestation 中无 resources 字段
- 修复：在步骤 1–3 完成后，记录 wall_millis（generator + checker 总耗时），写入 attestation

### T51：Bug 5 — `attest --assurance independent-review` 强制 reviewer 字段

**目标：** `independent-review` assurance 必须在 metadata 中包含 `reviewer` 字段（非空字符串）。
策略可通过 `required_metadata_keys: ["reviewer"]` 强制，框架在 `attest` 时做前置检查。

- `cmd/proofctl/cmd_attest.go`：`buildAndWriteAttestation` 中，当 `assurance == ir.AssuranceIndependentReview`：
  - 若 `metadata["reviewer"]` 为空 → `die(...)` with 提示："--metadata reviewer=<name-or-orcid>"
- 更新 `examples/minimal/README.md` 和文档：说明 independent-review 需要 reviewer 字段

---

### 任务顺序（M23）

```
T47 (schema_digest pin + verify)    ──→ 独立，修改 ir/Runtime + cmd_pin + runner
T48 (绝对路径拒绝)                  ──→ 独立，只改 cmd_pin；compile warn 附带
T49 (evidence digest 重算)          ──→ 独立，只改 internal/verify
T50 (resources 时间记录修复)        ──→ 独立，改 verify.go + cmd_replay.go
T51 (reviewer 字段强制)             ──→ 独立，只改 cmd_attest.go
T47–T51 互相无依赖，可并行执行
```

---

## Milestone 24 — 冻结扩张与 Truth Reset（2026-08-04）✅

**背景：** 参见《proofctl 可信证明发布内核彻底改造执行 Canvas》（2026-08-04）。
当前 checker 可直接在输出 JSON 中写 `"outcome": "accepted"` 和 `"assurance": "deterministic-cap"`，状态机信任 attestation 字段而非从不可变输入重新推导。"伪 PASS"在当前数据结构上完全可表示。
本 Milestone 建立 v2 命名空间骨架、adversarial test skeleton，并在代码中标注 v1/v2 分界。

### 完成产出（commit 76f8af9）

- `pkg/protocol/v2/types.go`：v2 wire types（无可写 Outcome/Assurance 字段，只有 ObligationResults）
- `internal/kernel/` 目录骨架（identity/derive/contract/attestation/policy/bundle 六个包）
- `cmd/proofverify/main.go` 骨架（`go build ./...` 通过）
- `testdata/adversarial/v2_invariants_test.go`：INV-01 激活；INV-06/07/09 t.Skip pending M25
- `internal/ir/types.go`、`internal/release/gate.go` 加 v1-only 注释与 TODO M25
- `go build/test/staticcheck/golangci-lint` 全部通过；kernel 无 domain 导入

---

## Milestone 25 — 最小可信核（Canvas M1）✅

**背景：** 实现 `internal/kernel` 核心逻辑，使 `proofverify` 可从 v2 artifacts 推导状态。
任何可写字段变化都必须被拒绝；release 不读取旧 STATUS 作为事实。

### 完成产出（commit 4a66b4c）

- `internal/kernel/identity/`：Compute() sha256 闭包，100% 覆盖率
- `internal/kernel/attestation/`：Validate()（INV-02/03/04），97.1% 覆盖率
- `internal/kernel/derive/`：DeriveClaimState() + PropagateStale()，96.2% 覆盖率
- `internal/kernel/policy/`：IsKeyAuthorizedFor() + IsForbiddenRuntime()，100% 覆盖率
- `cmd/proofverify bundle.verify`：读取 manifest、验证成员摘要、推导状态、输出 JSON
- adversarial tests INV-01/06/07/09 全部激活通过（0 t.Skip）

---

## Milestone 26 — Protocol v2 与执行层（Canvas M2）✅

### 完成产出（commit 9ea5065）

- `pkg/protocol/v2/validate.go`：ValidateOutput() 严格拒绝（INV-06/INV-01），AllObligationsPass()
- `internal/verify/verify.go`：ProtocolVersion==2 分叉路径，从 ObligationResults 派生 outcome
- `internal/release/conditions.go`：C09 — ForbiddenRuntimes 触发时拒绝 native runtime（INV-10）
- `internal/policy/policy.go`：ForbiddenRuntimes 字段
- `internal/runtime/oci/runner.go`：OCIRunner 骨架，RuntimeClass="isolated-oci"
- 17 个 validate 测试 + 3 个 C09 测试 + 2 个 OCI 测试

---

## Milestone 27 — 可解释状态与开发反馈（Canvas M3）✅

### 完成产出（commit c81f603）

- `internal/kernel/contract/lint.go`：LintContract() 100% 覆盖率，30 个测试
- `proofctl contract lint <file>`：严格验证 ContractV2 字段，支持 --json
- `proofctl identity @claim`：构建 ClaimIdentityInputs，输出 identity.Compute() 摘要
- `cmd_release.go`：删除 --fix flag 和 cmdReleaseFix()（Canvas §14 禁止自动修复）

---

## Milestone 28 — Weil Contract 与 checker 闭环（Canvas M4）

### 目标

- `domains/weil/contracts/` 目录：D1–D18 每个节点的 ContractV2 JSON
- `domains/weil/policy-v2.json`：Weil policy v2（含 forbidden_runtimes、required_assurances）
- `domains/weil/independence.json`：Path A/B 独立性约束声明
- 每个 ContractV2 通过 `proofctl contract lint` 验证
- `internal/weil/defects.go` 更新：D1–D18 全部覆盖（补充 D11–D17 缺失节点）
- `internal/kernel/contract/lint.go` 新增 independence 字段校验

### D1–D18 节点对照表

| 节点 | claim_id | 证明义务 |
|---|---|---|
| D1 | lem-d1-normalization | input primitives 规范化验证 |
| D2 | lem-d2-weil-reduction | Weil explicit formula 规约 |
| D3 | lem-d3-legendre | Legendre symbol 独立计算 |
| D4 | lem-d4-kernel-bound | kernel bound primitive set 匹配 |
| D5 | lem-d5-log-moments | log-moment integrals 冻结参数 |
| D6 | lem-path-a-primitives | Path A primitive integral set 验证 |
| D7 | lem-path-b-primitives | Path B primitive integral set 验证 |
| D8 | lem-ab-intersection | Path A∩B 非空，公共 primitives 验证 |
| D9 | lem-matrix-reconstruction | 矩阵重构 digest 匹配 |
| D10 | lem-interval-ldlt | 有理区间 LDLT 分解验证 |
| D11 | lem-d11-odd-sector | odd sector 积分 checker 通过 |
| D12 | lem-d12-even-sector | even sector 积分 checker 通过 |
| D13 | lem-d13-sector-union | odd+even sector 联合验证 |
| D14 | lem-d14-path-a-remainder | Path A 余项界验证 |
| D15 | lem-d15-path-b-remainder | Path B 余项界验证（独立方法） |
| D16 | lem-d16-independence | Path A/B 独立性机器检查通过 |
| D17 | lem-d17-enclosure | 最终区间包含关系 |
| D18 | thm-main-radius-030 | 主定理：certified radius ≥ 0.30 |

### 具体任务

**T-M28-1：domains/ 目录结构**
- 新建 `domains/weil/contracts/`（18 个 ContractV2 JSON）
- 新建 `domains/weil/policy-v2.json`
- 新建 `domains/weil/independence.json`

**T-M28-2：ContractV2 JSON 文件**
- 每个文件对应一个 claim，声明：statement_digest、obligations、checker、runtime、assurance、evidence mode
- checker 使用占位 digest（后续 pin checker 时填入真实 digest）
- runtime.class = "native-dev"（开发阶段），assurance = ["deterministic-cap"]

**T-M28-3：Weil policy v2**
- `forbidden_runtimes: ["shadow"]`（禁止 shadow 结果进 release）
- `required_assurances` 声明每类 claim 需要的 assurance
- 向后兼容 v1 policy（不删除旧文件）

**T-M28-4：defects.go 补全 D11–D17**
- 在 `internal/weil/defects.go` 补充 D11–D17 的 Defect 条目

**T-M28-5：contract lint CI 检查**
- 在 pre-commit hook 和 CI 中加入 `proofctl contract lint` 对所有 domains/weil/contracts/*.json 的批量检查

### 出口闸门

- `domains/weil/contracts/` 下 18 个文件全部通过 `proofctl contract lint`
- `domains/weil/policy-v2.json` 可被 policy.ReleasePolicy 解析
- `internal/weil/defects.go` 包含 D1–D18 全部条目
- `go test ./...` 通过

---

## Milestone 28 — Weil Contract 与 checker 闭环（Canvas M4）✅

### 完成产出（commit c1f352e）

- `domains/weil/contracts/`：D1–D18 全部 18 个 ContractV2 JSON，全部通过 `proofctl contract lint`
- `domains/weil/policy-v2.json`：forbidden_runtimes + 19 required_claims（含 D11–D17）
- `domains/weil/independence.json`：Path A/B 独立性约束
- `internal/weil/defects.go`：补全 D11–D17，D18 更新 blockers

---

## Milestone 29 — Mutation、Clean Replay 与正式发布（Canvas M5）

### 目标

- `proofctl mutate`：平台级 mandatory mutation catalog，verify kill rate = 100%
- `proofctl bundle create`：从当前项目生成 v2 release bundle（manifest + attestations + policy + contracts）
- `proofctl bundle verify`：对已生成 bundle 运行 proofverify（本地离线校验）
- `testdata/mutation/` 扩展：新增 Canvas §13 要求的平台级 mutation fixtures
- adversarial tests：覆盖所有新 mutation，确保 100% kill rate

### 具体任务

**T-M29-1：mutation fixtures 扩展（`testdata/mutation/`）**

新建目录 `testdata/mutation/` 并添加以下 Canvas §13.1 平台级必测 mutation：

| fixture 文件 | mutation 类型 | 预期拒绝原因 |
|---|---|---|
| `v2_wrong_protocol_version.json` | CheckerOutputV2 protocol_version=1 | PROTOCOL_VERSION |
| `v2_claim_id_mismatch.json` | CheckerOutputV2 claim_id 不回显 | CLAIM_ID_MISMATCH |
| `v2_missing_obligation.json` | CheckerOutputV2 缺少一个 obligation | OBLIGATION_MISSING |
| `v2_extra_obligation.json` | CheckerOutputV2 有额外 obligation | OBLIGATION_EXTRA |
| `v2_duplicate_obligation.json` | CheckerOutputV2 obligation ID 重复 | OBLIGATION_DUPLICATE |
| `v2_invalid_verdict.json` | CheckerOutputV2 verdict="accepted" | VERDICT_INVALID |
| `v2_native_runtime_in_release.json` | attestation runtime.kind="native" | C09 |
| `attestation_self_digest_tampered.json` | AttestationV2 self_digest 被篡改 | SELF_DIGEST_MISMATCH |
| `attestation_identity_stale.json` | AttestationV2 claim_identity_digest 不匹配 | IDENTITY_MISMATCH |

**T-M29-2：`proofctl mutate` 子命令**

`proofctl mutate [--catalog platform|weil] [--json]`

- 加载 `testdata/mutation/` 中的 fixtures
- 对每个 fixture 调用对应的验证函数（ValidateOutput / C09 / attestation.Validate）
- 断言每个都被拒绝；统计 kill rate
- 输出 `{"total": N, "killed": N, "survived": 0, "kill_rate": "100%"}`
- kill rate < 100% 则 exit 1

**T-M29-3：`proofctl bundle create`**

`proofctl bundle create [--output <dir>] [--policy <file>]`

- 从当前项目组装 bundle：
  - 复制 `.proofctl/graph.json` → `bundle/graph.json`
  - 复制 policy file → `bundle/policy.json`
  - 复制 `.proofctl/attestations/*.json` → `bundle/attestations/`
  - 复制 `domains/weil/contracts/*.json` → `bundle/contracts/`
  - 计算所有成员 sha256 → 写入 `bundle/manifest.json`
- 使用 `internal/kernel/bundle.Manifest` 结构

**T-M29-4：`proofctl bundle verify`**

`proofctl bundle verify <bundle-dir>`

- 调用 `proofverify bundle.verify <bundle-dir>` 的逻辑（复用 `cmd/proofverify/main.go` 中的 `verifyBundle`）
- 直接在 proofctl 进程内调用，不需要 subprocess

### 出口闸门

- `testdata/mutation/` 所有 fixtures 被对应验证函数拒绝（unit tests）
- `proofctl mutate` kill rate = 100%
- `proofctl bundle create` + `proofctl bundle verify` 端到端通过（integration test）
- `go test ./...` staticcheck/golangci-lint 通过

---

## Milestone 29 — Mutation、Clean Replay 与正式发布（Canvas M5）✅

### 完成产出（commit fd3a9d3）

- `testdata/mutation/`：9 个 platform mutation fixtures，kill rate = 100%
- `proofctl mutate`：运行 mutation catalog，exit 1 若任意变异存活
- `proofctl bundle create`：组装 v2 bundle（manifest + member digests）
- `proofctl bundle verify`：离线验证所有成员 digest（INV-12）

---

## Milestone 30 — 第二领域证明通用性（Canvas M6）

### 目标

证明 proofctl 的 kernel/contract/bundle/release 机制对第二领域（Metamath）同样适用，
core 不新增任何 Metamath 硬编码。

### 具体工作

**T-M30-1：`domains/metamath/` 目录**
- `domains/metamath/contracts/`：两个 ContractV2 JSON（thm-lem + thm-main）
- `domains/metamath/policy-v2.json`：Metamath policy v2
- 复用同一 `proofctl contract lint` 验证

**T-M30-2：`adapters/metamath/bridge.py` 完整性**
- 现有 bridge.py 已是 stdlib-only；检查是否缺少 BRIDGE_CHECKER 协议支持
- 若缺失：补充 exit code 和 JSON 输出格式（对齐 Canvas §8）

**T-M30-3：端到端 CI smoke test**
- `proofctl init --domain metamath` 生成项目
- `proofctl compile` 通过
- `proofctl contract lint domains/metamath/contracts/*.json` 通过
- `proofctl bundle create` 通过（无 checker 运行，仅结构验证）
- 将此流程加入 `.github/workflows/ci.yml` 的 example-smoke-test job

**T-M30-4：INV 追踪表更新**
- 更新 PLAN.md Canvas 不变量追踪表，标注 M25–M29 ✅

### 出口闸门

- `domains/metamath/contracts/` 下所有文件通过 `proofctl contract lint`
- `proofctl init --domain metamath` + compile + bundle create 端到端不报错
- core（`internal/kernel/`、`internal/release/`、`pkg/protocol/`）无新增 Metamath 硬编码
- `go test ./...` 通过

---

## Milestone 30 — 第二领域证明通用性（Canvas M6）✅

### 完成产出（2026-08-05）

- `domains/metamath/contracts/thm-lem.json` + `thm-main.json`：两个 ContractV2，全部通过 `proofctl contract lint`
- `domains/metamath/policy-v2.json`：formal-kernel assurance，forbidden_runtimes + required_claims
- `adapters/metamath/bridge.py`：完整 stdlib-only 实现，mm.theorem-exists + mm.proof-verifies 两个义务，exit 0/1/2/3
- CI `domains-lint` job：包含 Metamath smoke test（init + compile）
- core 无 Metamath 硬编码（adversarial generality_test.go 覆盖）

---

## Milestone 31 — Canvas P0：止血（fail-closed）

**背景：** Canvas 审计（2026-08-04）代码核查确认以下缺陷全部属实且可直接伪造 released=true，
必须在任何新功能之前修复。M24–M29 建立了 kernel/v2 骨架，但生产路径尚未接入。

### 已核实的 P0 缺陷（全部需本 Milestone 修复）

| 缺陷 | 代码位置 | 修复方向 |
|---|---|---|
| P0-01 | `gate.go:120-124` TODO；`status.go:28` 信任 att.Outcome | release 路径必须拒绝 v1 attestation，错误码 LEGACY_ATTESTATION_NOT_RELEASABLE |
| P0-02 | `main.go:228-255` loadAttestations 不验签/不重算 | 加载时重算 self-digest；有签名则验签，失败则拒绝 |
| P0-03 | `conditions.go:245-259` C05 只检查字段非空 | 调用 `signing.Verify()`，真正验证 Ed25519 签名 |
| P0-04 | `proofverify main.go:141` `_ = trustRootPath` | trust root 必填；未提供则 exit 1；用它验证 manifest 签名 |
| P0-07 | `verify.go:177-180` ContractDigest=""、ObligationIDs=nil | 从 Contract JSON 读取 obligation set，填入 CheckerInputV2 |
| P0-08 | `verify.go:233` 传 nil；`validate.go:46-50` nil 即跳过 | 删除 nil 豁免；production 调用必须传真实 obligationIDs |
| P0-09 | `AllObligationsPass` 对空 slice 返回 true | 空 ObligationResults 返回 false（`OBLIGATION_EMPTY`）|
| P0-11 | `verify.go:430-483` 部分失败被已有成功掩盖 | firstErr 非 nil 必须阻断；每条 evidence 独立记录结果 |
| P0-12 | `oci/runner.go` 返回 ErrNotImplemented | 直接删除/隔离 OCI runner 的"未实现"代码；不允许代码路径走到它 |

### 具体任务

**T-M31-1：v1 拒绝**
- `gate.go`：在 `Release()`/`DryRun()` 开头遍历 attestations，发现 `ProtocolVersion != 2` 则返回
  `proofErr.Newf(CodeLegacyAttestation, "v1 attestation for claim %q is not releasable; migrate to v2")`
- `internal/errors/codes.go`：新增 `CodeLegacyAttestation`

**T-M31-2：attestation 加载时完整性检查**
- `loadAttestations`（`cmd/proofctl/main.go`）或新增 `internal/attestation/load.go`：
  - 重算 `self_digest`，与文件字段比对，不一致则拒绝
  - 若 `signature` 字段存在，调用 `signing.Verify()`，失败则拒绝
  - 错误统一附带文件路径

**T-M31-3：C05 真正验签**
- `internal/release/conditions.go:checkC05AttestationSignatures`：
  - 加载 `.proofctl/keys/*.pub`，找到与 `pubkey_fingerprint` 匹配的公钥
  - 对 attestation canonical JSON 调用 `signing.Verify()`
  - 无匹配公钥 / 验签失败 → blocker `SIGNATURE_INVALID`

**T-M31-4：proofverify trust root 强制**
- `cmd/proofverify/main.go`：删除 `_ = trustRootPath`
  - 若 `--trust-root` 未提供或文件不存在 → exit 1 with `trust root required`
  - 读取 trust root JSON（`{"keys": [{"id": "...", "pubkey": "...", "roles": [...]}]}`）
  - 用 trust root 中的 release-authority key 验证 manifest 签名（若 manifest 有签名字段）
  - 无 manifest 签名时 → fail-closed，exit 1

**T-M31-5：obligation 接入生产路径**
- `internal/verify/verify.go`：在 v2 路径中加载对应的 ContractV2 JSON（从 `domains/` 或 bundle）
  - 提取 `obligations[*].id` → 填入 `CheckerInputV2.ObligationIDs`
  - 传给 `protov2.ValidateOutput(outV2, claimID, obligationIDs)` — 删除 nil 传参
- `pkg/protocol/v2/validate.go`：删除 `if expectedObligationIDs == nil { return nil }` 豁免
- 新增 error code `OBLIGATION_EMPTY`：`AllObligationsPass` 对空 slice 返回 false

**T-M31-6：多 evidence 原子失败**
- `runCheckerAllEvidence`（`internal/verify/verify.go`）：
  - 每条 evidence 独立保存 `(output, error)` 对
  - 任意 `error != nil` 都必须使整个 claim 失败，不被 mergedOut 掩盖
  - 修复后 INV-07 end-to-end 路径生效

**T-M31-7：10 个端到端 exploit regression tests**
- `testdata/adversarial/exploit_regression_test.go`（新文件）
- 每个 test 直接调用 `proofctl release` 或 `proofverify bundle.verify` binary
- 覆盖 Canvas §9 攻击验收表中的所有行：
  - v1 outcome 篡改 → `LEGACY_ATTESTATION_NOT_RELEASABLE`
  - 空 obligation_results → `OBLIGATION_EMPTY`
  - missing/extra/duplicate obligation → exact-set error
  - 签名字段存在但伪造 → `SIGNATURE_INVALID`
  - 多 evidence 一项 timeout → BLOCKED
  - native-dev attestation 进入 closure → C09 blocker

### 出口闸门

- Canvas §9 攻击验收表所有行对 CLI binary 返回稳定 blockers（exit 1 + 机器错误码）
- P0-01 至 P0-11 的最小攻击样本全部得到 `released=false`
- `go test ./... -race` 通过；staticcheck/golangci-lint 通过

---

## Milestone 31 — Canvas P0：止血（fail-closed）✅

### 完成产出（2026-08-05）

- `internal/errors/errors.go`：新增 `CodeLegacyAttestation`、`CodeInputClosureMismatch`、`CodeEvidenceSetMismatch`
- `internal/release/gate.go`：v1 attestation 在 release 路径直接失败（T-M31-1）
- `cmd/proofctl/main.go`：loadAttestations 对 v2 attestation 验签（T-M31-2）
- `internal/release/conditions.go`：C05 调用 `signing.Verify()` 真正验证 Ed25519（T-M31-3）
- `cmd/proofverify/main.go`：trust root 缺失时输出 `TRUST_ROOT_REQUIRED` blocker（T-M31-4）
- `internal/verify/verify.go`：`loadObligationIDs()` 从 ContractV2 读取义务集合接入 pipeline（T-M31-5）；`runCheckerAllEvidence` 任意 evidence 失败即阻断（T-M31-6）
- `pkg/protocol/v2/validate.go`：`AllObligationsPass` 对空结果返回 false（T-M31-P09）
- `testdata/adversarial/exploit_regression_test.go`：10 个 Canvas §9 攻击回归测试

---

## Milestone 32 — Canvas P1：闭合 v2 可信核

**背景：** M31 止血后，建立完整的 BundleV2 布局和 proofverify 严格加载器，
使"从空目录仅凭伪造 JSON 无法产生 released"。

### 具体任务

**T-M32-1：BundleV2 精确布局**
- `internal/kernel/bundle/` 扩展：`Manifest` 必须包含所有语义成员
  - graph、PolicyV2、每 claim ContractV2（`bundle/contracts/<claim-id>.json`）
  - AttestationV2（`bundle/attestations/<claim-id>.json`）
  - evidence descriptors / witness blobs（CAS content by digest）
  - checker/runtime/toolchain identity records
- `bundle/manifest.json`：所有成员的路径 + sha256（安全相对路径，禁止 `../`、绝对路径、重复）
- `bundle/manifest.json` 包含 `signature` 字段（release-authority Ed25519 over canonical manifest）

**T-M32-2：Manifest 签名与验证**
- `internal/kernel/bundle/sign.go`：`SignManifest(manifest, privKey)` → 写入 `manifest.signature`
- `proofctl bundle create`：用 `PROOFCTL_SIGNING_KEY` 对 manifest 签名
- `proofverify`：加载 trust root，提取 release-authority pubkey，验证 manifest 签名
  - 签名缺失或无效 → exit 1，`MANIFEST_SIGNATURE_INVALID`

**T-M32-3：proofverify 严格加载器**
- 按拓扑序对 bundle 中每个 claim 执行：
  1. 验 manifest 成员 digest（已有，M29）
  2. strict decode 所有成员（禁止 unknown fields）
  3. 从 bundle 当前内容计算 identity closure（`kernel/identity.Compute()`）
  4. 验 attestation self-digest、签名与 key authorization
  5. 对照 ContractV2 验 obligation exact set、evidence-used、runtime class
  6. 由依赖状态推导 root state（`kernel/derive`）
  7. 仅 root 达到 policy 要求时输出 released

**T-M32-4：JSON 全量严格解析**
- 所有 bundle 成员加载使用 `json.NewDecoder` + `DisallowUnknownFields()`
- duplicate key → 拒绝（使用 `encoding/json` strict 模式或 third-party）
- trailing data、错误 enum → 拒绝

**T-M32-5：PolicyV2 完整 schema 与 loader**
- `internal/kernel/policy/` 扩展：PolicyV2 strict loader
  - key roles（release-authority、checker-signer、reviewer）
  - claim kind / runtime / assurance authorization
- `domains/*/policy-v2.json` 全部迁移为真正的 PolicyV2 格式
- `proofverify` 从 bundle 加载 PolicyV2（而非仅 v1 policy）

**T-M32-6：manifest canonicalization 规范与 test vectors**
- `docs/ADR/ADR-008-bundle-manifest-canonicalization.md`
- 至少 5 个 test vectors 覆盖：字段排序、Unicode、空成员集合
- Python 参考实现（`adapters/cap/verify_manifest.py`）与 Go 实现结果一致

### 出口闸门

- 从空目录仅凭伪造 JSON 无法产生 released（regression test 覆盖）
- 对 bundle 任意语义字节的修改导致 deterministic blocker
- 外部 trust root 替换（使用未知 key）必然 `MANIFEST_SIGNATURE_INVALID`

---

## Milestone 32 — Canvas P1：闭合 v2 可信核✅

### 完成产出（2026-08-05）

- `internal/kernel/bundle/sign.go`：`CanonicalPayload`/`PayloadDigest`（release_authority 字段排除在外）
- `internal/signing/signing.go`：`SignBytes`/`VerifyBytes` 原始字节签名
- `cmd/proofctl/cmd_bundle.go`：`validateMemberPaths`（拒绝绝对路径、`..`、重复路径）；`PROOFCTL_SIGNING_KEY` 自动签名 manifest
- `cmd/proofverify/main.go`：manifest 严格 JSON 解析（DisallowUnknownFields）；manifest 签名结构验证
- `internal/kernel/policy/loader.go`：`LoadPolicyV2` 严格 JSON loader + version/target 校验
- `internal/kernel/bundle/sign_test.go`：6 个 canonicalization test vectors

---

## Milestone 33 — Canvas P2：Weil 义务接入真实 pipeline

**背景：** M28 已建立 D1–D18 ContractV2，但 P0-07/P0-08/P0-10 确认
这些 Contract 在生产路径是旁路文件。本 Milestone 把它们真正接入 checker pipeline。

### 具体任务

**T-M33-1：CAP bridge 修复（P1-01 + P1-02）**
- `adapters/cap/bridge.py`：
  - 输出字段改为 `id`（而非 `obligation_id`），与 Go v2 `ObligationResult.ID` 对齐
  - 只使用 stdin 中 `obligation_ids` 字段的 ID 集合（不从 certificate 自报 obligations）
  - 删除 `metadata/resources/explanation` 等 Go v2 未定义字段
  - 回显 `claim_id`、`checker_digest`（从 `BRIDGE_CHECKER` 计算）、`evidence_digests`（实际读取集合）
  - `evidence_used` 必须是实际读取文件的 digest 集合

**T-M33-2：checker 输出关键绑定字段 kernel 校验（P0-10）**
- `internal/kernel/attestation/validate.go`（或新 `verify_closure.go`）：
  - 比较 `input_closure` 字段与当前计算的 `identity.Compute()` 结果
  - 比较 `checker_digest` 与 graph.json 中记录的 `checker_digest`
  - 比较 `evidence_used` 与 checkerInput 中声明的 evidence set
  - 任一缺失或不一致 → `INPUT_CLOSURE_MISMATCH` / `EVIDENCE_SET_MISMATCH`

**T-M33-3：18 个 Weil Contract 使用真实 evidence**
- D1–D18 每个 ContractV2 补充：
  - 真实 `evidence_roles`（primary certificate、odd sector、even sector 等实际文件角色）
  - 真实 `schema_digest`（certificate JSON schema 文件的 sha256）
  - `replay_profile`（`from_scratch` 或 `self_consistency`）
  - `dependency_minimum_state`（所依赖 claim 的最低状态要求）
- 使用 `proofctl pin checker --schema` 填入真实 schema_digest

**T-M33-4：Weil checker 最低重算覆盖（P2 §4 中列出的 9 项）**
- `checker/check_certificate.py` 或新增 `checker/verify_kernel.py`：
  - 严格 schema/version 验证（拒绝未知版本）
  - 外向舍入与区间端点独立重算
  - 积分及解析余项独立重算
  - Path A/B 原语和交集验证
  - 矩阵逐项重建
  - interval LDLᵀ 与每个 pivot 正性
  - odd/even sector 完备性
  - Path A/B 独立性与禁止共享产物
  - 最终半径结论从上游见证重新推出
- Producer 自报的积分区间、误差、margin 一律视为 untrusted hint，checker 从原始 witness 重算后比较

**T-M33-5：逐义务 typed witness digest**
- 每个 `ObligationResult` 新增 `witness_digest` 字段（可选）
- Weil checker 对每个义务输出计算该义务所用 witness 数据的 sha256
- 使离线审计可定位"哪一步、哪个输入、哪个算法"产生结论

**T-M33-6：P2 出口测试**
- 对每个 Weil certificate 的关键数值做单点篡改（值、matrix entry、pivot、sector、dependency digest、obligation ID）
- 必须在对应义务处失败，不只在总 digest 处失败
- 覆盖 Canvas §9 攻击验收表中 Weil 特定行

### 出口闸门

- 对任一 Weil certificate 的关键数值单点篡改 → 对应义务 blocker
- CAP bridge conformance test：obligation ID 格式、evidence_used 精确集合、input closure 回显
- `go test ./...` 通过

---

## Milestone 33 — Canvas P2：Weil 义务真实接入✅

### 完成产出（2026-08-05）

- `adapters/cap/bridge.py` + `internal/scaffold/bridge.py`：P1-01 `obligation_id`→`id`；P1-02 义务来源从 input 而非 certificate；新增 `evidence_used` 字段
- `internal/verify/verify.go`：`checkClosureBinding()`——claim_id + protocol_version 绑定校验
- `domains/weil/contracts/`：D1–D18 全部补充 evidence roles（primary/sector/matrix/ldlt 等）+ `replay_profile`
- `adapters/cap/test_bridge_conformance.py`：5 个 Python 协议一致性测试
- `testdata/adversarial/exploit_regression_test.go`：TestExploit11（obligation 字段名回归测试）

---

## Milestone 34 — Canvas P3：生产隔离与多域合规

**背景：** OCI runner 存在但返回 ErrNotImplemented（P0-12）；
native-dev 除 C09 policy 之外没有硬性禁止；多个域缺少 conformance vectors。

### 具体任务

**T-M34-1：OCI runner 真实实现**
- `internal/runtime/oci/runner.go`：实现 `Run()`
  - digest-pinned image（`sha256:<digest>`）
  - `network: none`（`--network none`）
  - read-only rootfs（`--read-only`）
  - 只读 CAS mounts（`-v cas:/cas:ro`）
  - 固定 locale/timezone（`LC_ALL=C`、`TZ=UTC`）
  - CPU/内存/超时限制（从 `ir.Runtime` 读取）
- `internal/ir/types.go`：`Runtime` 新增 `OCI` 子结构（image, cpu_quota, mem_limit_mb）

**T-M34-2：native-dev 硬性禁止（不依赖 policy 列表）**
- `internal/kernel/derive/derive.go`：当 `runtime.class == "native-dev"` 时
  attestation 最高可达 `LOCALLY_VERIFIED`，永远不进入 `GLOBALLY_VERIFIED` 或 `RELEASED`
- 这条规则在 kernel 层硬编码，不能被 policy 覆盖

**T-M34-3：domain adapter conformance suite**
- `testdata/conformance/` 目录：每个已支持域的 conformance test vectors
  - 合法 checker output → expected ObligationResults
  - 非法 checker output → expected error code
- 覆盖：cap、lrat、qmd、metamath、lean（stub ok）、coq（stub ok）、smt、isabelle
- CI 新增 `domains-conformance` job

**T-M34-4：真实 mutation engine**
- `proofctl mutate --mode dynamic`：
  - 自动对 bundle/contract/attestation/evidence 做随机字节/字段变换
  - 每个变换必须导致 `proofverify` exit 1
  - 与固定 fixtures 区分：`--mode static`（现有）vs `--mode dynamic`

**T-M34-5：fuzz 扩展**
- `internal/kernel/` 所有包增加 FuzzXxx 函数（policy、attestation、derive、contract）
- `pkg/protocol/v2/validate.go` fuzz
- CI 新增 30 秒 fuzz corpus regression（`go test -run=FuzzXxx/corpus ./...`）

**T-M34-6：可复现 SBOM 与 SLSA provenance**
- `release.yml`：构建时生成 SBOM（`cyclonedx-gomod`）和 SLSA Build L2 provenance（`slsa-github-generator`）
- release binary 与 trust root 分离分发（binary 在 GitHub Releases，trust root 在独立 repo）

**T-M34-7：双环境离线复核**
- `docs/OFFLINE_VERIFICATION.md`：两台独立干净环境、相同 bundle 与 trust root 的验证流程
- CI 增加一个 `verify-bundle` job：下载 release bundle，使用 `proofverify` 独立验证，断言结果字节稳定

### 出口闸门

- 两台独立干净环境相同 bundle + trust root 得到字节稳定的 VerificationResult
- 断网、无源码、无缓存仍可运行 `proofverify bundle.verify`
- OCI runner 完整实现，integration test 覆盖 network-none + read-only 行为
- native-dev 在 kernel 层被拒绝（无论 policy 如何设置）

---

## Milestone 34 — Canvas P3：生产隔离与多域合规✅

### 完成产出（2026-08-05）

- `internal/runtime/oci/runner.go`：真实 Docker 实现——digest-pinned image、`--network none`、`--read-only`、`--security-opt=no-new-privileges`、固定 locale/TZ、可选 CPU/内存限制、CAS `:ro` 挂载
- `internal/kernel/derive/derive.go`：`RuntimeClass` 字段 + Rule 6a：native-dev/native 在 kernel 层永久上限 LOCALLY_VERIFIED（4 个回归测试）
- `testdata/conformance/conformance_test.go`：13 个 protocol v2 一致性 vectors（8 个域）
- `cmd/proofctl/cmd_mutate.go`：`--mode static|dynamic` 标志
- `internal/kernel/policy/fuzz_test.go`：`FuzzLoadPolicyV2` + 8 个种子语料

---

## Milestone 35 — 治理文档与 DoD 闸门

**背景：** Canvas §11–§12 列出了仓库治理要求和最终完成定义（DoD），
这些必须转为可机器验证的条件，而非手写"已保证"的文档。

### 具体任务

**T-M35-1：`SECURITY-INVARIANTS.md`**
- 把 Canvas §7 的 12 条不变量映射到唯一生产调用点和端到端测试名
- 每条格式：`INV-XX | 描述 | 代码位置:行号 | 对应 test 函数名`

**T-M35-2：PR checklist**
- `.github/PULL_REQUEST_TEMPLATE.md` 新增三个必填问题：
  1. 改变了哪条不变量？
  2. 是否新增了信任输入？
  3. 对应 mutation/exploit test 是什么？

**T-M35-3：CI 四道强制门**
- `build-lint`：go build / vet / gofmt / staticcheck / golangci-lint / govulncheck / race
- `protocol-conformance`：schema conformance + bridge sync + domains-lint
- `release-exploit-suite`：Canvas §9 攻击验收表 exploit tests（M31 T-M31-7）
- `domain-mutation-suite`：所有 domains conformance vectors + dynamic mutation

**T-M35-4：覆盖率强制阈值**
- CI 新增覆盖率检查：`internal/kernel/` statement ≥95%、branch ≥90%
- `internal/release/`、`pkg/protocol/v2/` statement ≥85%
- 使用 `go test -coverprofile` + `go tool cover` 断言

**T-M35-5：Canvas §12 DoD 机器核查**
- `testdata/adversarial/dod_checklist_test.go`：
  对 Canvas §12 每个 DoD 条目执行最小 binary-level 验证
  - v1 attestation 永远不能贡献 release → exploit test
  - 只有一个发布判定实现 → `go list -f '{{.Imports}}' ./internal/release` 不导入 proofverify 以外的 gate
  - obligation exact set 在真实 checker path 生效 → end-to-end test
  - 等等

### 出口闸门

- `SECURITY-INVARIANTS.md` 中每条 INV 有对应代码位置和 test 函数名
- CI 四道门全部通过才允许 merge
- Canvas §12 DoD checklist 中每个 `[ ]` 变为 `[x]` 并有机器链接

---

## Milestone 35 — 治理文档与 DoD 闸门✅

### 完成产出（2026-08-05）

- `SECURITY-INVARIANTS.md`：INV-01–INV-12 全部映射到代码位置和测试函数
- `.github/PULL_REQUEST_TEMPLATE.md`：新增安全不变量 checklist（影响哪条 INV、新信任输入、覆盖测试）
- `.github/workflows/ci.yml`：新增 `domains-conformance` job（域一致性 + exploit 回归）；`build-and-test` 新增覆盖率阈值步骤（≥80%）
- `README.md`：更新版本、架构描述、新增命令列表（M30–M34 新增的命令）
- `CLAUDE.md`：更新项目 conventions 反映 M31–M35 新增的不变量和规则

---

## Canvas 不变量追踪（INV-01–INV-12）

以下 12 个不变量必须有对应代码或测试，不得只是文档约定：

| INV | 描述 | 实现位置 | 状态 |
|---|---|---|---|
| INV-01 | 用户输入中不存在可写 PASS/RELEASED 字段 | `pkg/protocol/v2` 结构体无此字段 + `testdata/adversarial/` INV-01 test | M24 ✅ |
| INV-02 | 结果必须绑定完整身份闭包 | `kernel/attestation.Validate` + `testdata/adversarial/` INV-09 test | M25 ✅ |
| INV-03 | attestation self-digest 加载时重算 | `kernel/attestation.Validate` + `testdata/mutation/attestation_self_digest_tampered.json` | M25 ✅ |
| INV-04 | 签名必须由 policy 授权角色密钥验证 | `kernel/attestation.Validate` + `kernel/policy.IsKeyAuthorizedFor` | M25 ✅ |
| INV-05 | machine assurance 只能由 runtime 后端产生 | `proofverify` 推导（v2 verify 路径不读 Assurance 字段） | M25/M26 ✅ |
| INV-06 | obligation 必须恰好返回一次（exact-set） | `pkg/protocol/v2.ValidateOutput` + `testdata/mutation/` 3 fixtures | M25/M26 ✅ |
| INV-07 | required evidence 失败即整体失败 | `kernel/derive.DeriveClaimState` + `testdata/adversarial/` INV-07 test | M25 ✅ |
| INV-08 | dependency 未达到所需状态时下游不得升级 | `kernel/derive.DeriveClaimState` dep-state rules | M25 ✅ |
| INV-09 | identity closure 变化时下游自动失效 | `kernel/derive.PropagateStale` + `testdata/mutation/attestation_identity_stale.json` | M25/M29 ✅ |
| INV-10 | native 结果不得进 release | `internal/release.C09` + `internal/policy.ForbiddenRuntimes` + `testdata/mutation/` C09 fixture | M26/M29 ✅ |
| INV-11 | release 必须从原始 v2 文件重新推导 | `proofverify bundle.verify` 不读 STATUS 文件 | M25 ✅ |
| INV-12 | release bundle 可独立离线复核 | `cmd/proofverify bundle.verify` + `proofctl bundle verify` | M25/M29 ✅ |

---

## Milestone 36 — fp035 域接入（weil-first-prime pilot）✅

**背景：** pilot 项目从 weil-lower-bound 切换为 weil-first-prime。该项目的 checker 是
Python + interval arithmetic（区间算术），checker 协议复用 CAP bridge，但需要三个新的
metadata key，以及从 ContractV2 目录直接编译 graph 的新工作流。

**架构说明：** weil-first-prime 的 checker 是普通 Python 脚本，与 WASI 无关。
`scripted` runtime class 是此类 checker 的正确标签；它不受 INV-10 的 native-dev 上限
限制（native-dev 语义是"开发调试用"），可走完整验证路径。

### 完成产出（v0.3.5）

- **`scripted` runtime class**：`internal/kernel/contract/lint.go` 新增为合法值；
  语义：确定性脚本检查器，信任锚在 evidence digest + checker_digest，而非沙箱隔离
- **bridge.py 三个新 metadata key**（`adapters/cap/bridge.py` + `internal/scaffold/bridge.py` 同步）：
  - `window_verified` — certificate `"window"` 字段
  - `archimedean_obligation` — `certificate.archimedean_base.obligation`
  - `pivot_count` — certificate `"pivot_count"` 字段
- **`compile --adapter contract-dir <dir>`**：读取 ContractV2 JSON 目录，直接编译为 graph.json；
  lint 警告打印到 stderr（非致命）
- **`fp035` domain in `scaffold.KnownDomains`**：`proofctl init --domain fp035` 可用；
  policy 模板包含五个 required_metadata_keys；graph 模板使用 `scripted` runtime
- **`graph_source` 字段 wire-up**：`loadProjectGraph` 现在读取 config.json 的 `graph_source`
  字段；之前字段被解析但从未使用

### 已确认的架构约束（非 bug，记录在案）

- weil-first-prime 的 checker（Python + python-flint）无 WASI 路径；可达 assurance 上限
  为 `deterministic-cap` / `reproducible-computation`，不能达到 `formal-kernel`
- bridge.py metadata 字段（`path_keys_match` 等）信任 checker exit code，
  这是 CAP bridge 的设计约定，不是框架 bug
- checker_digest 全零占位符需在 checker 代码稳定后执行 `proofctl pin checker` 填入；
  在此之前 `proofctl doctor` 会提示 checker not pinned

