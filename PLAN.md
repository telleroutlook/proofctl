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

## Milestone 8.5 — 预编译二进制发布（GitHub Releases）

**背景：** weil-lower-bound 等仓库需要在 CI 中使用固定版本的 proofctl，
但目前只能 `go install`（需要 Go 环境）。GitHub Releases 附带预编译二进制
可让任何环境通过 `curl` 直接获取，无需安装 Go。

### 目标

- 打 tag（`v*`）时，CI 自动 cross-compile 以下目标并上传到 GitHub Releases：
  - `proofctl-linux-amd64`
  - `proofctl-linux-arm64`
  - `proofctl-darwin-arm64`
  - `proofctl-windows-amd64.exe`
- 下游仓库可以固定版本：`curl -L https://github.com/telleroutlook/proofctl/releases/download/v0.1.0/proofctl-linux-amd64 -o proofctl`

### 实现

- `.github/workflows/release.yml`：监听 `push tags v*`，矩阵构建 + 上传 assets
- 无需 goreleaser，用标准 `go build -ldflags "-X main.version=$TAG"` 即可
- `main.go` 加 `--version` flag，打印版本号（来自构建时注入的 ldflags）

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

## Milestone 10 — Checker 依赖完整性覆盖

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

## Milestone 11 — 密码学 Attestation 签名

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

## Milestone 12 — Lean 4 域完整实现

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

## Milestone 13 — 批量验证协议（Batch Backfill Protocol）

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

## Milestone 14 — 工具链身份摘要（Toolchain Identity）

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

## Milestone 15 — Metamath 域（首个 formal-kernel 参考实现）

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

## Milestone 16 — 跨域声明消费（Cross-domain Claim Consumption）

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

## Milestone 17 — Coq/Rocq 域

**背景：** `coqchk` 是专为"脱离主系统独立复核 `.vo` 编译产物"设计的工具，历史悠久，
工具链比 Lean 更成熟稳定。在 RH 证明中负责连接"抽象实数"与"机器区间算术"的桥梁：
形式化证明 Arb 区间算术底层的正确性，确保 C 库不存在舍入方向的 bug。

- `adapters/coq/bridge.py`：调用 `coqchk -silent <vofile>`，输出 `{ "ok": true, "metadata": { "coq_version": "...", "opam_hash": "..." } }`
- BatchGroup 模式（`coqchk` 一次验证整个 `.vo` 集合）
- `policies/coq-release-v1.json`：`allowed_assurances: ["formal-kernel"]`
- `proofctl init --domain coq`：生成最小 Coq 项目骨架（含 `_CoqProject`）

**前置：** M13（BatchGroup）、M14（ToolchainDigest，opam 包集作为工具链摘要）

---

## Milestone 18 — SMT/Alethe 域

**背景：** 与已完成的 LRAT 是近亲，复用"独立小型验证器"模式，边际成本最低。
Alethe（cvc5 输出格式）和 DRAT（SAT solver 通用格式）都有独立验证器（`verit-checker`、
`drat-trim`），适配难度接近 LRAT。在 RH 证明中可用于排除有限反例（离散数论结构）。

- `adapters/smt/bridge.py`：支持 `--format alethe` 和 `--format drat` 两种模式
- 大量复用 `adapters/lrat/` 的设计模式（3-claim DAG：formula → unsat → verified）
- `policies/smt-release-v1.json`

**前置：** 无（独立于 M13–M17，最低风险的新域）

---

## Milestone 19 — Isabelle/HOL 域

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

