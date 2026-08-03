# proofctl — 数学证明平台化改造计划

## 愿景

proofctl 成为数学证明类项目的通用认证基础设施平台。数学家提供：
1. 证明目标（`graph.json`，声明 DAG）
2. 领域 checker（任意语言的可执行程序）
3. 领域 policy（JSON，声明放行条件）

框架提供其余一切：DAG 管理、内容寻址存储、attestation 链、freshness 追踪、release gate、STATUS.json。

**阶段目标：** 先全面支持 weil-class（Python checker + JSON 证书 + 区间算术），再向外拓展。

---

## 范围说明

- proofctl 是**认证基础设施**，不做数学推导
- "最少代码接入"指：新数学证明项目只需提供 checker 可执行文件 + graph.json + policy.json
- weil-lower-bound 是第一个参考域实现，其经验（D-defect 体系、certificate v2 格式、gate 测试模式）已被吸收进框架
- 当前第一个目标域是 weil-class；未来可拓展到其他数学证明类项目，不局限于 Riemann 相关问题

---

## Milestone 1 — 核心通用化 ✅

目标：消除所有 Weil 硬编码，让 release gate 对任意领域可配置。

### T1：release conditions 数据驱动化 ✅

- `policy.ReleasePolicy` 新增 `required_metadata_keys []string`
- `EvaluateConditions` 中原 C04–C12 Weil 专名常量全部删除，改为遍历 `RequiredMetadataKeys` 动态生成 `meta:<key>` 条件
- C01（全局状态）/ C02（无 assumption）/ C03（assurance 合规）/ C04（replay 一致性）保持为通用固定条件
- `policies/weil-release-v1.json` 新增 9 个 metadata key 声明

### T2：`proofctl init` 去除默认 policy 硬编码 ✅

- `config.Init()` 签名加入 `policyFile string` 参数，默认空字符串
- `proofctl init` 新增 `--policy <path>` 和 `--domain <name>` flag

### T3：`ReleaseStatus` 字段去 Weil 化 ✅

- `CertifiedRadius` → `ReleaseTarget`（`json:"release_target"`）
- STATUS.json 对所有领域语义正确

---

## Milestone 2 — CAP 领域支持 ✅

目标：让 weil-lower-bound 的 checker 能被 proofctl 直接驱动。

### T4：CAP checker 协议桥接器 ✅

新增 `adapters/cap/bridge.py`（Python stdlib only）：
- stdin 读 `CheckerInput` JSON → 调用 `BRIDGE_CHECKER <cert.json>` → stdout 写 `CheckerOutput` JSON
- exit 0 时从证书读取 `cap_format_version`、`margin_ratio`，从 claim_id 推断 odd/even sector，填充所有 metadata keys
- bridge 不做数学验证，只做协议翻译，永远 stdlib only

### T5：weil-lower-bound proofctl 集成文件 ✅

写入 weil-lower-bound 仓库：
- `graph.json`：12 claim DAG（D1–D10、D18 + def-frozen-model），含 SHA-256 evidence 引用
- `policies/weil-cap-v1.json`：12 required_claims + 9 required_metadata_keys
- `.proofctl/config.json`：指向 weil-cap-v1.json

### T6：端到端验证 ✅

- `proofctl status`：12 claim OPEN，DAG 拓扑正确
- `proofctl graph`：依赖关系完整
- `proofctl release --dry-run`：4 通用条件 + 9 metadata 条件全部数据驱动，fail-closed 正常工作

---

## Milestone 3 — 平台脚手架 ✅

### T7：`proofctl init --domain cap` 脚手架命令 ✅

`internal/scaffold/` 包（Go embed 内嵌所有模板和 bridge.py）：
- `--domain cap`：生成 `graph.json`（占位 claim）、`policies/cap-v1.json`（含 required_metadata_keys）、`adapters/bridge.py`（可直接运行）
- config.json 自动填好 `policy_file`
- 模板开箱即可 `proofctl compile --adapter json graph.json`

### T8：`proofctl domains list` ✅

列出所有内置领域（cap / lrat / qmd）及其 bridge、policy、graph 模板状态。

---

## 关键设计约束

1. **checker 独立性不变：** bridge.py 是协议翻译层，绝不引入 generator 侧代码，永远 stdlib only
2. **核心零领域知识：** `internal/` 下所有包继续零 Weil 依赖；Weil 知识只在 `adapters/weil/` 和 `internal/weil/`
3. **向后兼容：** 已有 `weil-release-v1.json` 用户只需添加 `required_metadata_keys` 字段即可升级
4. **fail-closed 不变：** release gate 逻辑不松动

---

## 下一步（未规划）

- 为 lrat / qmd 补充 policy 模板和 graph 模板，完善 `domains list`
- `proofctl verify` 驱动 bridge.py 完成实际 attestation 写入（当前 weil-lower-bound 仍需手动写 attestation）
- LICENSE 升级为 Apache 2.0 + CITATION.cff（学术引用格式）
- weil-lower-bound 的 `proofctl verify @thm-main-radius-030` 全流程打通
