# FEAT-IAM-005：自定义策略、条件与权限边界

- 状态：实施中；结构诊断、自定义策略创建/读取/显式关联及版本查询/创建/默认切换已实现并通过本地真实门禁；策略与版本删除、条件、边界和 UI 闭环未完成，整体未验收。
- 依赖：002、004、001 的目录。
- Owner：IAM 策略语言、分析器、版本与权限上限。

## 需求

| ID | 行为 |
| --- | --- |
| IAM-LANG-01 | 自定义 Policy CRUD，不可变版本、一个有效版本、版本查询/删除/切换 |
| IAM-LANG-02 | 文档严格校验，未知/重复字段、超限、非法 scope/action/resource 拒绝 |
| IAM-LANG-03 | 精确 Action、受限通配、精确资源/集合选择、默认拒绝和显式 Deny |
| IAM-LANG-04 | 有界的字符串等值、时间、IP 条件；每键来源/类型/缺失/集合语义确定 |
| IAM-LANG-05 | User/Role boundary set/get/remove，仅限制最大权限 |
| IAM-LANG-06 | 版本切换/修改附件/边界下次请求生效，决定记录实际版本 |
| IAM-LANG-07 | 可视化/JSON 同一语言；分析器提供字段位置和稳定错误/警告 |
| IAM-LANG-08 | 委派管理不允许通过创建/改版/附件或去除边界扩大自身许可 |

## 详细设计

本片先补齐发布入口所需的结构诊断基础，再交付自定义策略管理与真实授权路径，不把诊断函数视为本 FEAT 验收完成。`api/iam/v1/policy.go` 已拥有解码、语义验证和唯一 canonical/digest；分析器、版本发布和实际求值必须复用该拥有者，不复制一套 UI grammar 或宽松 JSON 解析器。

### 结构诊断与安全边界

当前语言的失败提供稳定 code 和 JSON Pointer；根文档位置为空字符串。诊断只引用固定字段及受预算限制的数组下标，不带用户提交的策略名称、资源 ID、原文或秘密。通用错误字符串仍保持安全且支持 `errors.Is(ErrInvalidPolicy)`。重复键、未知字段、类型错误、尾随文档和超限输入继续由现有严格 decoder 拒绝；不能为了精确位置改用宽松解码。暂不能可靠定位的 JSON 结构错误定位根文档，不伪造行列。

校验顺序固定为文档语言/scope/语句预算 → 按输入下标的语句字段/action/resource → action 与资源种类的完整覆盖。语义失败不产生 canonical 或 digest；有效文档的既有编码与摘要不变。JSON/可视化编辑器最终消费同一诊断语义；当前不开放新的匿名分析、发布权限或在线恢复入口。自定义管理和后续条件语法须继续扩展这个唯一验证路径，不能绕开当前未知字段失败关闭。

### 版本、条件与委派

首个管理纵向路径为原 Account Root 创建一份 CUSTOMER/TENANT Policy 和其初始默认版本 → 查询准确策略内容 → 沿既有附件关联给 User/Group → 业务请求实际按自定义权限允许或拒绝。创建不自动关联给创建者或任何主体。非 root 的高风险发布委派在防自助提权门禁完成前保持关闭；不能仅因为能查看目录或关联系统策略就取得编辑任意权限文档的能力。这是后续完整版本/边界管理的起点，不代替其需求。

- `POST /v1/policies` 使用 `iam.policy.create` / 当前 ACCOUNT；入参仅 displayName、document、requestId，Account、管理类型、scope 和 ID 不能由调用者指定。document 只能为 TENANT；平台动作、系统名称空间和服务 probe 拒绝。
- `GET /v1/policies/{policyId}` 使用 `iam.policy.read` / 精确 POLICY，返回策略与当前默认版本；只读取本账号 CUSTOMER 或可见的 TENANT 系统策略，不因主账号关系越过平台或其他账号。
- 创建的 Policy ID 绑定账号、actor 和原 requestId；初始 versionId 绑定 canonical digest。等值重放返回原创建结果，变体或后续修订冲突，不产生第二条成功事实。当前权限、原 root 关系和活跃凭据在实际事务内重检。
- 同账号 ACTIVE/CUSTOMER displayName 精确唯一，不以显示名派生 Policy ID；不同账号可以同名。创建上限为每账号 128 个活跃自定义策略，已有完整目录上限仍为 256 项。整个 HTTP 请求沿用 64 KiB 预算，不能因为策略文档本身有预算就无限扩大外层请求。创建使用现有 requestId 幂等身份，不新增平行的 Idempotency-Key 别名。
- `iam.policy.created` 是租户链的 IAM/USER 成功事实，target 为 POLICY，绑定真实 decision、request digest 和策略 ID。策略、初始版本与 outbox 同事务，非法文档、跨域或并发冲突不得留下半套对象。该路径不改 Audit canonical 编码或恢复能力。

JSON languageVersion 初版定义一次，PolicyVersion 以独立 versionId/digest 记录内容。对象最多五个管理可见版本作为初始产品容量，可在真实容量门禁后调大；当前有效/被边界与历史证明引用版本不能直接物理删除。五个不是策略终生发布次数：版本删除片必须在保留历史内容与证明的同时释放管理名额，不能让已有五个历史版本永久阻断演进。当前尚未实现版本删除，所有已创建版本均在管理视图。默认指针以 resourceVersion 原子切换，不就地改 JSON。

#### 版本发布事务

版本集合由所属 Policy 管理，不新增可脱离 Policy 授权的 version 资源命名空间。初始 CUSTOMER 版本已有 canonical digest 身份；后续版本沿用 `version-<digest>`，同一策略中相同内容不是另一份可变副本。所有版本写入先经当前 PDP，再锁内检查原 root、活跃 Account/USER 与该账号 CUSTOMER Policy；SYSTEM 策略不接受这些用户写入。

| 路由 | Action / 授权资源 | 行为 |
| --- | --- | --- |
| `GET /v1/policies/{policyId}/versions` | `iam.policy-version.list` / POLICY | 当前 CUSTOMER Policy 的最多五个不可变版本及当前元数据；不是可复用 permit |
| `GET /v1/policies/{policyId}/versions/{versionId}` | `iam.policy-version.read` / POLICY | 精确 owner+version 内容与同一快照元数据；版本不必是默认版本 |
| `POST /v1/policies/{policyId}/versions` | `iam.policy-version.create` / POLICY | document、resourceVersion、requestId；新增版本，Policy 修订 +1，不自动切换默认值或关联主体 |
| `POST /v1/policies/{policyId}:set-default-version` | `iam.policy.set-default-version` / POLICY | versionId、resourceVersion、requestId；显式原子切换并使 Policy 修订 +1，不修改版本文档 |

同意图重放只在该命令结果仍是当前 Policy 修订时返回原结果；变体、过时 resourceVersion 或命令后已有其他修订均冲突，不能把历史命令重放成新的切换。新 requestId 重复创建已存在内容，或选择当前默认版本，均冲突而不是悄悄制造新修订。并发操作按同一 Policy 锁和预期修订只产生一个有效结果。

成功事实分别为租户链 `iam.policy-version.created`、`iam.policy.default-version-set`，target 为所属 POLICY；原 request digest 绑定目标策略、预期修订及新 versionId/contentDigest，不记录策略正文。新增版本与 Policy 修订、历史决定、单一 outbox 同事务；切换后的新请求重读实际默认版本，已提交的旧决定仍使用其原版本证据。版本列表/精确版本读取的结果不能绕过另一次写入的当前授权与修订检查。

评估器处理类型化 Statement。条件缺失对匹配为 false；显式 Null 存在检查单独定义；否定条件也不能因属性缺失自动放行。多个条件同时满足，多值规则明确为 any/all；禁止隐式字符串类型转换。资源列表中每个必要资源都要通过，不以某个资源成功代替全部。

变更在 account → principal → policy → default pointer/attachment 锁顺序内检查管理者当前委派上限。首版可把高风险自定义授权限定为 root/明确 PolicyAdministrator 系统策略，不能用通用子集推理的假实现宣称安全委派。非 root 不得去除自身强制边界或为自己授予不可委派系统策略。

## 验收

Allow/Deny/边界交集表、条件缺失/类型/大小攻击、跨账号资源与 namespace、未知版本/Action、显式 Deny 全来源优先；真实数据库改版/附件/边界并发，旧 session 下次请求立即反映；旧事实仍可验证投递；UI 与 API 使用同一文档。fuzz 只证明当前 grammar 不崩溃且失败关闭，不快照实现细节。

### 当前首片证据与未完成边界

创建/读取首片的固定可审查点为 `7104b1de8f16ae82645e149b2c5376f983eae5cd`，其 [Verification 34814615083](https://github.com/xiak/matrix/actions/runs/34814615083) 已逐项核实精确 SHA、Go/authority-process/node-process 全部 completed/success。该固定对象不包含后续版本管理增量。

2026-09-14，本分支专属 PG18（1 CPU、768 MiB、128 PIDs、最多 64 连接）完成以下本地证据；不是发布安装或其他分支的验收状态：

- 原 `TestIAMPolicyAuthorityStoragePostgres` 当前空库、故障回滚、双次迁移、带数据重放、组/附件/凭据与历史不变量回归通过，106.23s。首片 HTTP 真实创建、读取、同名跨账号、精确重放/变体冲突、零隐式附件和精确资源授权在原 owner 内验证。
- 后续同 owner 的 `customer_policy_publication_and_current_authority` 聚焦真实 gate 通过，5.39s（含父门禁 13.78s）：所有当前 Action 的 SQL scope 校验、重复/未知字段与大小攻击、同意图并发单结果单事实、outbox 最后写失败全事务回滚，以及真实锁等待后的发布者停用拒绝。停用前的原创建事实继续通过 event-bound producer 校验；伪造目标、租户或请求摘要拒绝。
- 原 `TestIndependentIAMAuditAndPaaSProcesses` 通过，50.62s：真实受限 runtime 登录、两个 IAM 实例、PaaS 与 Audit；从 replica 创建 CUSTOMER 策略，经另一实例显式关联后 PaaS 只允许选定应用，撤销立即拒绝，创建成功事实由真实 dispatcher 进入租户链。保留既有跨租户业务/Operation/outbox、故障关闭及历史链回归。
- API 严格 schema/Go 文档验证、PolicyDetail 归属/默认版本/digest 检查以及 IAM/Audit/架构 race 通过；OpenAPI 重生成字节稳定。诊断 fuzz 有界 15s、2 workers 通过（31,516 次执行）；它不证明尚未实现的条件语法。

### 版本增量本地证据

同日沿原测试拥有者完成版本增量：

- 聚焦 PG18 `customer_immutable_versions_and_default_selection` 最后复验通过，2.96s（含父门禁 9.59s）：非默认版本创建/精确读取/完整目录、同命令重放、显式切换对现有会话的 Allow→Deny→Allow、旧命令冲突、旧决定 proof 保留、五版本预算、末尾 outbox 故障整体回滚，以及同预期修订并发创建只有一个赢家。跨账号 root 和普通已授权账号管理员仍不能发布/切换；路由命令后缀不能成为目录别名。
- 原独立双 IAM/Audit/PaaS 门禁通过，55.09s：同一用户 bearer 在不同 IAM 实例提交版本/切换，真实 PaaS 下一请求改变结果；原创建、一个版本创建、两次默认切换事实进入同一租户链。没有修改单一 canonical 编码或旧 hash。
- 对齐 CI 的本地串行真实数据库回归通过：Audit 数据层（含双 authority 当前形状/权限与保留记录）10.135s、Audit HTTP 3.969s、IAM 集成 198.018s、独立进程 43.658s、PaaS 数据层 5.473s。数据库均位于本任务专属受限 PG18；没有运行未发布 IAM 全历史升级链。
- 新请求/版本目录/非默认详情的 Go 与 JSON Schema 测试、相关 API/IAM/Audit/architecture race、生成稳定、全仓 Go 测试/vet、模块校验与 Linux IAM/Audit 构建通过。独立 CI 尚待本增量固定提交，不继承 `7104b1d` 的结果。

当前开发 readiness 为 IAM11/Audit8/PaaS1，仅反映实际函数与封闭 action 契约；安装发布 profile 未修改，不能据此组装或宣称跨版本可升级。当前没有对外诊断 endpoint、版本管理 capability 条目或自定义策略 UI 验收。LANG-01 的策略改名/删除及版本删除、LANG-03 的受限通配、LANG-04 条件、LANG-05 边界、LANG-07 编辑器以及 LANG-08 完整委派仍必须继续实现，不能将已完成的创建和版本切换路径当作 FEAT Accepted。
