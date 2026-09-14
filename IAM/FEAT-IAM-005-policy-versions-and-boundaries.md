# FEAT-IAM-005：自定义策略、条件与权限边界

- 状态：实施中；结构诊断、自定义策略 CRUD、显式关联及版本查询/创建/默认切换/退休已有固定 CI；IAM 权威时间条件已通过本地完整真库与独立进程，但候选 CI 因既有账号别名竞争失败，须修复后重新绑定固定提交验收。完整条件、边界和 UI 闭环未完成，整体未验收。
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

JSON languageVersion 初版定义一次，PolicyVersion 以独立 versionId/digest 记录内容。对象最多五个管理可见版本（包括一个默认版本）作为初始产品容量，可在真实容量门禁后调大；当前有效/被边界与历史证明引用版本不能直接物理删除。五个不是策略终生发布次数：非默认版本逻辑退休后保留历史内容与证明，但退出管理集合并释放一个名额。当前没有精确 version pin；普通附件引用 Policy 并跟随默认，不冒充非默认版本 pin。默认指针以 resourceVersion 原子切换，不就地改 JSON。

#### 版本发布事务

版本集合由所属 Policy 管理，不新增可脱离 Policy 授权的 version 资源命名空间。初始 CUSTOMER 版本保留已有 `version-<digest>` 身份；后续发布使用 `version-<digest>-<Policy结果修订>`，使相同内容的再次发布不复用已退休身份。内容仍不可变，ID 对客户端不透明，不能以名称/后缀推导权限。所有版本写入先经当前 PDP，再锁内检查原 root、活跃 Account/USER 与该账号 CUSTOMER Policy；SYSTEM 策略不接受这些用户写入。

| 路由 | Action / 授权资源 | 行为 |
| --- | --- | --- |
| `GET /v1/policies/{policyId}/versions` | `iam.policy-version.list` / POLICY | 当前 CUSTOMER Policy 的最多五个不可变版本及当前元数据；不是可复用 permit |
| `GET /v1/policies/{policyId}/versions/{versionId}` | `iam.policy-version.read` / POLICY | 精确 owner+version 内容与同一快照元数据；版本不必是默认版本 |
| `DELETE /v1/policies/{policyId}/versions/{versionId}` | `iam.policy-version.delete` / POLICY | resourceVersion、requestId；退休非默认版本，释放一个管理名额，返回默认内容不变的 PolicyDetail |
| `POST /v1/policies/{policyId}/versions` | `iam.policy-version.create` / POLICY | document、resourceVersion、requestId；新增版本，Policy 修订 +1，不自动切换默认值或关联主体 |
| `POST /v1/policies/{policyId}:set-default-version` | `iam.policy.set-default-version` / POLICY | versionId、resourceVersion、requestId；显式原子切换并使 Policy 修订 +1，不修改版本文档 |

同意图重放只在该命令结果仍是当前 Policy 修订时返回原结果；变体、过时 resourceVersion 或命令后已有其他修订均冲突，不能把历史命令重放成新的切换。新 requestId 重复创建管理集合中仍存在的内容，或选择当前默认版本，均冲突而不是悄悄制造新修订。退休内容再次发布是新意图、新身份，不恢复旧版本；普通精确读取和默认选择都拒绝退休版本。并发操作按同一 Policy 锁和预期修订只产生一个有效结果。

成功事实分别为租户链 `iam.policy-version.created`、`iam.policy.default-version-set`，target 为所属 POLICY；原 request digest 绑定目标策略、预期修订及新 versionId/contentDigest，不记录策略正文。新增版本与 Policy 修订、历史决定、单一 outbox 同事务；切换后的新请求重读实际默认版本，已提交的旧决定仍使用其原版本证据。版本列表/精确版本读取的结果不能绕过另一次写入的当前授权与修订检查。

#### 策略元数据生命周期

策略改名使用 `PATCH /v1/policies/{policyId}`，入参严格为 displayName、resourceVersion、requestId，返回当前默认 `PolicyDetail`。对应 `iam.policy.update` / 精确 POLICY，当前 PDP 与原 root/ACTIVE CUSTOMER 锁内约束均保留。显示名按账号内活跃 CUSTOMER 精确唯一；更新仅改变显示名、修订号和更新时间，不能改变稳定 ID、owner、默认版本、内容或附件。新意图的同名无变更、旧修订、重复活跃名称均冲突；精确重放仅在原结果修订仍当前时返回同一结果。成功事实为租户链 `iam.policy.updated`，只记录绑定意图摘要的 POLICY 目标，不记录正文。并发改名/默认切换/附件使用同一 Policy 修订锁；末尾 outbox 写失败必须全部回滚。

策略删除使用 `DELETE /v1/policies/{policyId}`，入参仅 resourceVersion、requestId，使用 `iam.policy.delete` / 精确 POLICY。当前 PDP 和原 root/ACTIVE Account/USER 检查后，锁定本账号 CUSTOMER Policy；SYSTEM 和跨账号拒绝。任何未撤销附件（包括停用 User 或组的附件）都使删除冲突，不能隐式解除关联。删除只把 Policy 置为不可恢复的 RETIRED，resourceVersion +1，返回终态 `Policy` 元数据；保留默认指针、全部不可变版本、已撤销附件、决定和 outbox。等值删除重放仅匹配原意图和终态修订；不同命令、错误版本、旧创建/改名/切换不得复活对象。成功事实为租户链 `iam.policy.deleted` / POLICY，与终态同事务。

普通管理目录只列 ACTIVE 策略，删除释放活跃 CUSTOMER 名额和显示名；原创建意图不能复用，但新创建意图可以使用相同显示名并得到新稳定 ID。删除后的普通内容读取、改名、发布/切换与重新关联均拒绝，历史事实按其原证据投递，不从当前目录反推历史是否存在。目录不提供未声明的回收站或历史查询 API；原始内容仍受不可变存储保护。真实门禁必须证明有超过目录预算的历史退休记录时仍能列出/创建当前策略，不能以扩大预算掩盖终生容量问题。附件创建与删除在同一 Policy 锁序列化；只有创建关联成功或策略终态成功之一，不能留下活跃的退休策略附件。

#### 版本删除与再次发布

版本删除退出管理集合并释放五版本名额，但不得物理移除旧授权证明内容。接口/事务、本地组合回归与独立 CI 已完成，尚待实际 UI 消费，不将该后端切片当作完整 LANG-01 验收。

- `DELETE /v1/policies/{policyId}/versions/{versionId}` 使用 `iam.policy-version.delete` / 所属 POLICY；请求只有 resourceVersion、requestId，版本 ID 来自路径，账号仍从当前身份推导。成功返回默认内容不变的 `PolicyDetail`，Policy 修订 +1。SYSTEM、跨账号、非原 root、退休 Policy 拒绝；当前默认版本不得删除，必须先显式切换。
- 在现有 `policy_versions` 加终态退休时间，保留原 ID、scope、document、canonical、digest 和创建时间不变，不新建平行内容库。该表的更新保护只允许一次 NULL→退休时间，禁止内容变更、取消退休、物理删除及 truncate；共享的决定/附件历史保护函数不放宽。默认指针不能指向退休版本。列表、普通精确读取、默认选择和五版本预算只使用未退休内容；历史决定/proof 继续读取原精确版本，不能加当前活跃过滤而丢掉旧证据。
- 同请求精确重放仅在其原结果修订仍当前时返回；错误版本、变体、后来已有其他修订或其他命令再次删除均冲突。成功事实为租户链 `iam.policy-version.deleted`，target 为所属 POLICY，原 request digest 绑定准确 versionId、Policy ID 和预期修订；退休、修订、授权决定与 outbox 同事务。
- 再次提交仍在管理集合的相同内容继续冲突；已退休的内容可用新请求重新发布，但必须形成新 versionId，不能清除旧退休状态。digest-only 的初始 ID 原样保留；新版本发布 ID 绑定 contentDigest 与本次 Policy 结果修订（单调 resourceVersion），不再将“内容相同”误当成“同一次发布”。ID 对客户端始终是不透明值，不允许客户端拼接或推导授权。内容 digest/canonical 算法不变，新发布不会自动成为默认或产生附件。
- 真实门禁：五项满额→退休非默认项→创建新内容以及再次发布已退休内容；活跃重复拒绝；退休版本的旧决定和 Audit proof 保留；旧创建/删除重放及 schema/bootstrap 重放不复活；删除与默认切换/新建/Policy 删除同修订竞争只有确定赢家；末尾 outbox 故障没有部分退休或名额变化。现有默认版本始终可读、目录只含最多五个可管理版本。后续 boundary 若引入精确版本引用，须在其 owning slice 将该活跃引用加入同锁删除约束，不能只依赖历史存在或静态检查。

#### 条件首片：IAM 权威时间

本纵向切片证明有时间窗口的自定义策略从发布、显式关联到实际业务鉴权；不是只增加一个解析函数。目前已接入现有校验、数据库发布、唯一求值器与 cursor 复核，完整验收尚未完成。该片是 LANG-04 的增量，不代替字符串、IP、标签或完整 CAT-05/产品接入。条件定义进入现有公共契约拥有者，来源声明按 001 管理；求值继续在单一 authority 中，不按产品名称分叉。

- Statement 增加可省略的 `conditions`，元素严格为 `key`、`operator`、`values`；旧无条件文档的 canonical bytes 保持不变。每语句最多 16 个条件，同 key/operator 重复拒绝，禁止空数组、未知字段和隐式类型转换。时间条件各只有一个值，不把多值含义交给实现偶然决定。
- 第一项键为 `iam.current-time`，类型为时间，来源仅 IAM 当前数据库事务时间；算子为 `DATE_GREATER_THAN_EQUALS` 与 `DATE_LESS_THAN`，分别表示闭合起点和开放终点。两个条件组合表示 `[start,end)`。值使用严格 UTC 时间格式和既有微秒精度约束；非法日期、非 UTC、空值和反向/空窗口在发布前拒绝。
- 首片只对目录明确声明支持此键的 TENANT/USER 授权启用。产品服务不能通过 authorization body/header/query 自报该时间，通用 attributes map 不开放。未知键、动作未声明条件能力或缺少必需权威上下文失败关闭，不能默默去掉条件求值。
- 条件先确定语句是否匹配，再汇总所有直接/组来源的 Allow/Deny；匹配 Deny 优先。窗口外的 Allow 不授权，窗口内的 Deny 能覆盖另一来源 Allow。读到损坏的任何有效策略仍使本次决定失败关闭，不以另一份 Allow 掩盖。
- 一次决定使用相同事务时间和权威快照，不在一条语句中多次读取本机时钟。等待中的事务按既有一致快照排序；这不是追溯取消已经接受的业务事务、运行中任务或长连接。历史决定保留其原版本/摘要和发生时间，窗口到期后历史 outbox 仍可投递，不用当前时间重新授权旧事实。条件是当前时间匹配，不是永久到期终态；数据库时钟回拨仍按实际权威时间，不能声称此片实现了单调时钟或时钟故障治理。
- 一个条件 Allow 到期不取消另一份合法 Allow。需要强制限制全部授权来源的期限必须作为后续权限边界，而不是将普通策略附件误作全局上限。恢复访问可以显式切换到已有合法非默认版本，或发布新版本再显式切换；不会通过清除退休状态、隐式更新默认值或改写旧文档恢复。
- 门禁覆盖边界前/等于起点/内部/等于终点/边界后，时区/精度/空窗口攻击，多条件 AND、显式 Deny、直接与继承来源；真实 HTTP 发布/关联后由独立 IAM/PaaS 决定，伪造时间字段拒绝，换版后的下一请求改变结果，原决定与链证据可重放。用有界的实际数据库时间等待证明运行语义，不靠只传入 mock 时间或扩大超时作为全片验收。

后续字符串/IP 条件仍使用同一条件结构，但必须先在目录冻结每键来源、类型、支持算子和缺失/多值规则，不能先接受任意键再补信任来源。来源 IP 不从未经信任的转发 header 或任意 PEP 字段取得；产品标签按 008 从已认证产品与真实业务对象提供。

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
- 新请求/版本目录/非默认详情的 Go 与 JSON Schema 测试、相关 API/IAM/Audit/architecture race、生成稳定、全仓 Go 测试/vet、模块校验与 Linux IAM/Audit 构建通过。版本增量固定 `aa28c39ca25ad0136b4a7042f1f1ae358d4f1429` 的 [Verification 34816605258](https://github.com/xiak/matrix/actions/runs/34816605258) 已核实精确 SHA 和 Go/authority-process/node-process 全部 completed/success；不继承 `7104b1d` 的结果。

### 策略改名增量证据

2026-09-14，既有 PG18 `customer_policy_metadata_lifecycle` 聚焦真库门禁通过，8.44s（含父门禁 34.71s）：稳定 ID/default/content、同意图重放、过时/变体/同名冲突、不同账号同名独立、非法字段、服务密钥不能冒充用户 bearer、普通已授权管理员/跨账号拒绝；两次改名及改名与默认切换的并发分别只有一个赢家。真实 publisher 锁等待后身份撤销返回 401，不留下元数据或成功事实；末尾 outbox 故障时元数据、决定与事实均回滚。后续修订后原改名事实仍通过 event-bound producer 校验。

同一独立 PG18（1 CPU、768 MiB、128 PIDs、64 连接）上的串行 CI 等价回归：Audit 数据层 18.484s、Audit HTTP 5.576s、IAM 集成 228.237s、独立进程 61.388s、PaaS 数据层 10.364s。实际两个 IAM 实例与 PaaS/Audit 证明 rename 后原应用仍可访问、其他应用仍拒绝，随后附件撤销生效，单一改名事实由真实 outbox 进入租户链；保留当前 schema 带数据重放、故障原子性、受限数据库身份、旧 Audit 字节和历史 proof 门禁。未运行未发布 IAM 从 schema 1 起的逐版升级链。

相关 API/IAM/Audit/architecture race、全仓 Go 测试/vet、模块校验、OpenAPI 稳定生成及 Linux IAM/Audit 构建通过。改名候选 `02fed1296d0f425e610812a870c85ed524295447` 的 [Verification 34819882669](https://github.com/xiak/matrix/actions/runs/34819882669) 最终为 failure：Go/node-process 成功，authority-process 中既有平台凭据保护测试只读取用户目录第一页，前置 Group 测试已创建超过 100 个用户，目标随机 ID 落在后页时误报缺关联。因此 02fed 不作为独立 CI 成功点；本地改名证据不替代修复后的完整 CI。

### 策略删除与分页门禁

旧平台凭据保护门禁改为使用服务返回的 opaque 签名 cursor 至多读取 10 页，每页仍由 UserList 校验限制为 100 项，重复 cursor 拒绝；不会解码/推导游标。仅此确定规模的测试使用页上限，生产保护继续由数据库检查全部有效关联。100 条排序靠前的停用主体仅作为分页数据，真实受保护用户仍由 HTTP 创建，确保单独运行也经过后页；它不证明这些批量数据完成了用户创建流程。PG18 聚焦 `platform_scope_protects_credentials_independently_of_policy_name` 修复后通过，14.34s（含父门禁 30.08s），保留 ACTIVE/退休系统策略/停用主体各阶段的原凭据保护断言。

PG18 聚焦 `customer_policy_terminal_deletion` 最终通过，3.18s（含父门禁 8.82s）：活跃 User、停用 User 与 Group 的未撤销附件均阻止删除；outbox 最后失败没有元数据/决定/事实残留；精确重放单一生命周期事实、旧创建/更新/版本/关联不能复活；同名新意图产生新 Policy ID；原版本与创建/删除历史 proof 保留。257 条退休内容仅作为目录容量数据，验证历史不占活跃管理目录；删除与附件创建竞争没有活跃的退休策略关联。改名/发布/默认切换/删除同修订四路竞争只有一项生效，未获胜操作不改变名称、默认版本、内容集合或终态；成功生命周期事实与实际获胜请求及已提交授权决定绑定，不把正常的授权决定审计误计为第二条生命周期事实。

当前完整 `TestIAMPolicyAuthorityStoragePostgres` 在同一限额的新数据库串行复验通过，86.46s，包含原 Group 规模/分页 46.39s、删除 3.33s、平台保护后页 5.92s，以及最终 schema/bootstrap 带数据重放、终态/撤权不复活和不可变证据攻击。一次与本机其他构建重叠的回归曾耗尽原两分钟总预算；该次不算通过，没有增大超时或削减 Group HTTP 创建/分页覆盖，以上为无并行重型构建的完整复验。

原独立双 IAM/PaaS/Audit 真实进程门禁通过，51.364s：从实际 HTTP 创建、发布、切换、改名、撤销附件到删除策略，真实 PaaS 权限仍正确拒绝，删除事实由 dispatcher 进入同一租户链。Audit 数据层 17.765s、Audit HTTP 4.405s、PaaS 数据层 5.848s 均通过；保留受限进程登录、租户/资源/Operation/outbox 隔离、当前身份失联失败关闭和历史链。该源码组合不是签名安装或 UI 验收。

最终 IAM 集成包 race 串行复验共 199.938s，通过上述策略权威、真实 IAM HTTP 94.02s、专用本地凭据恢复 16.52s，保留当前版本的改密/重置/恢复/退出/撤权并发与原意图重放。相关 API/IAM/Audit/architecture race、全仓 Go 测试/vet、模块校验、OpenAPI 稳定生成和 Linux IAM/Audit 构建均通过；本片独立 CI 仍须绑定提交核实。

策略删除固定 `0ac6445a33fb2e592fe94d2787a87cd7460ec4ae` 的 [Verification 34823234061](https://github.com/xiak/matrix/actions/runs/34823234061) 已核实精确 SHA，Go/authority-process/node-process 全部 completed/success，包含 02fed 旧后页门禁修复，不包含后续版本退休。该固定源码为 IAM13/Audit10/PaaS1，安装发布 profile 未修改。

### 版本退休与容量复用证据

2026-09-14，本分支新建专属受限 PG18（1 CPU、768 MiB、128 PIDs、64 连接），现有 `customer_immutable_versions_and_default_selection` 聚焦通过，6.19s（父门禁 11.33s）：五项满额、默认禁止删除、非默认退休释放槽位、活跃重复内容拒绝、退休内容新 ID 再次发布、新内容继续复用槽位、末尾 outbox 失败全回滚、旧命令不复活、历史 canonical/digest/proof 保留，及退休/默认切换/新版本/整策略删除四路同修订竞争单一赢家。原父门禁再次 apply/bootstrap 后比较真实退休内容、ID 和终态均不变。最终完整真库复验还包含“新内容不能以退休态插入”的存储攻击拒绝与严格响应校验。

当前版本退休开发 readiness 为 IAM14/Audit11/PaaS1，仅反映实际函数、退休列/保护与封闭 action 契约；安装发布 profile 未修改，不能据此组装或宣称跨版本可升级。当前没有对外诊断 endpoint、版本管理 capability 条目或自定义策略 UI 验收。LANG-03 的受限通配、LANG-04 条件、LANG-05 边界、LANG-07 编辑器以及 LANG-08 完整委派仍必须继续实现，不能将策略 CRUD 当作 FEAT Accepted。

完整回归中的 Audit 数据层 11.447s、Audit HTTP 3.286s、实际双 IAM/PaaS/Audit 进程 137.207s、PaaS 数据层 18.719s 通过；真实 PaaS 在非默认版本退休后保持原授权，版本退休/策略删除事实均经实际 dispatcher 入链。该次 IAM 包没有通过：十组串行流程共用的两分钟 context 在末尾凭据并发耗尽（策略父门禁 122.72s），后续保护检查因同一已过期 context 不能执行，不计为成功。现有测试 owner 改为每组两分钟、共享数据综合门禁四分钟，HTTP 请求也继承对应截止时间与取消；没有删除规模、并发或攻击用例，没有改变生产超时、资源上限和 CI 作业总上限。

上述调整后的新库完整 IAM integration race 最终通过，320.659s，包含完整策略存储/版本/组/凭据保护、IAM HTTP 155.29s 与本地原平台凭据恢复 37.59s，未跳过原有并发、撤权及重放检查。这是功能/隔离验收，不是容量/性能 SLO。相关 API/IAM/Audit/architecture race、全仓 Go 测试/vet、模块校验、OpenAPI 稳定生成与 Linux IAM/Audit 构建通过；最终测试预算与响应校验增量另经完整真库与聚焦 vet 验证。发布 profile、签名安装与 UI 仍未作为本片证据。

版本退休固定 `b99e082fa9ba8a6412eeb766387f4fbeb5df0aa3` 的 [Verification 34827144713](https://github.com/xiak/matrix/actions/runs/34827144713) 已核实精确 SHA，Go/authority-process/node-process 全部 completed/success；该固定对象不包含后续时间条件。

### 时间条件增量证据

2026-09-14，严格条件解析正向测试先因不支持条件失败，实现后通过；非法来源、未知算子、重复条件、空/反向窗口、非 UTC/非法日期/非微秒精度拒绝，无条件文档原 canonical/digest 与调用者输入保持。领域门禁覆盖 `[start,end)` 微秒边界、匹配 Deny 优先、来源顺序无关、无效权威时间失败关闭；现有 cursor owner 补窗口到期不能继续分页。

专属 PG18（1 CPU、768 MiB、128 PIDs、64 连接）的原版本门禁最终聚焦通过，9.47s（父门禁 18.33s，包 21.540s），包含实际 HTTP 发布/关联、当前数据库时间的五秒窗口到期拒绝、禁止 caller currentTime/conditions/attributes、到期前决定继续通过 producer proof、存储层非法来源/重复算子/日期攻击，以及原版本退休和带数据 replay。首轮测试忘记撤销其先前显式授予的账号管理员策略，过期后仍由另一无条件 Allow 授权；实际 policy_evidence 精确证明这一点。测试已通过原 HTTP 撤销该宽权限再观察唯一窗口授权，没有改变正确的权限并集语义来迁就用例。

真实独立双 IAM/PaaS/Audit 进程门禁通过，45.75s（包 48.644s）：同一 bearer 在实际数据库时间的六秒窗口内可读目标应用，到期后拒绝；发布无条件新版本仍拒绝，只有显式默认切换才使下一请求恢复允许，撤销附件再次拒绝。真实 dispatcher 投递旧时间决定及生命周期事实，原完整租户链、受限 runtime 身份、跨账号业务/Operation/outbox 与失联回归保留。

最终完整串行真实 PG18 回归通过：Audit 数据层 5.702s、Audit HTTP 3.326s、IAM integration race 246.989s、PaaS 数据层 6.202s。IAM 门禁进一步把时间授权改为真实组继承，检查窗口内证据精确绑定 PolicyVersion 和 Membership、窗口外无匹配授权来源；独立进程覆盖直接附件。保留原组规模/分页、版本生命周期、凭据并发、旧 canonical、schema/bootstrap 带数据重放及原平台恢复。全仓默认 Go 测试/vet、API/IAM/Audit/architecture race 与模块校验通过；默认跳过数据库的测试不替代上述真实运行。

最终带时间条件种子的诊断/canonical fuzz 通过：15 秒、2 workers、每次样本最小化限 1 秒，132,238 次执行；不以此声称性能或未实现语法正确。OpenAPI 重生成字节稳定，最终 API/authority race 与 Linux IAM/Audit 构建通过。全部本地进程结束后，专属 PG 容器、网络和合成数据卷按精确身份检查并清理，没有用户或其他任务数据变更。

时间条件当前源码 readiness 为 IAM15/Audit11/PaaS1；IAM 版本反映新的策略文档/发布验证语义，Audit 编码、ServiceIdentity、lookup_service、七列 claim 和安装发布 profile 未变。固定 `7218e1671378a227d78d020686a68d164982e2ac` 的 [Verification 34830294815](https://github.com/xiak/matrix/actions/runs/34830294815) 最终失败：Go/node-process 成功，authority-process 中时间条件和独立进程通过，但原账号别名竞争返回 503/200 而非 409/200。PG 日志证明同一 backend 的五次 `40001` 相隔约 9ms，原无等待整事务重试在竞争提交前耗尽；修复与竞争验收归 003。本地时间条件证据保留，但该候选不得作为 CI 成功对象，不继承 b99e082 的结论。
