# FEAT-IAM-002：策略权限权威替换

- 状态：实施中；未验收。策略语言/求值与持久化替换在同一功能切片内收口，不把纯函数测试当作迁移完成。
- 依赖：001 已验收的 CAT-01–04，固定安装消费者已对齐当前策略附件 wire；完整产品 Profile 的集成仍由 008 证明。
- Owner：IAM `authority`、`identityaccess`、PostgreSQL；Audit 只保存事实。

## 需求与详细设计

| ID | 需求 | 设计 |
| --- | --- | --- |
| IAM-POL-01 | 单一策略评估器 | 纯函数评估 typed statements；无旧 RoleAllows fallback |
| IAM-POL-02 | 系统管理策略 | 平台发布稳定 ID、不可变文档与默认版本；普通用户不可编辑 |
| IAM-POL-03 | 策略附件 | 账号/主体/策略 ID + 状态/修订；吊销是保留历史的终态 |
| IAM-POL-04 | 等价迁移 | 六种旧角色映射为明确权限集合；仅原有有效绑定成为有效附件，撤销历史仍撤销 |
| IAM-POL-05 | 决定证据 | 绑定 subject、原始主体、scope、Action/resources、policy version/profile revision 和 digest |
| IAM-POL-06 | 查询权限来源 | 区分直接/组/角色来源；隐藏无权查看的主体/策略详情 |

系统策略映射：ORGANIZATION_ADMIN → AccountAdministrator；PAAS_DEVELOPER → PaaSDeveloper；PAAS_VIEWER → PaaSViewer；AUDIT_READER → AuditReader。PLATFORM_OPERATOR 与 INSTALLATION_VERIFIER 使用各自封闭 scope 的系统策略，不能通过租户附件 API 授予。

以上六种只是旧安装的迁移对照，不是产品内置策略的固定数量，也不是外部 CAM 的策略分类。产品可按需求新增、替换或停用系统策略；策略内容与通用求值器分离。已有策略 ID 的内容变化必须产生新不可变版本，默认版本切换与附件影响必须显式审核、审计和验证；新增 Action 不自动修改既有版本或扩张已授权主体。下架不删除已提交决定引用的历史版本。

表目标为 policies、policy_versions、policy_attachments 与必要的不可变历史映射。迁移在一个 profile-bound 事务内保存原 ID/撤销证据，替换旧 put/revoke/load functions 并删除旧权威表和 API。策略语言版本、内容版本、SQL schema 与 release revision 各自验证。旧审计 `iam.role-binding.*` 保持既有 bytes 和证据语义，新附件事实使用新 Action。

## 用例/锁/接口

### 首版策略语言与求值

`PolicyDocument` 使用 `languageVersion=1`、`scope` 和 `statements`；每条语句有唯一 `sid`、`effect=ALLOW|DENY`、精确 Action 集合及资源选择器。选择器包含 `kind` 和 `match=EXACT|ANY_IN_AUTHORITY`；EXACT 必须有合法 ID，ANY_IN_AUTHORITY 禁止 ID。它仅匹配当前权威范围内的资源，不证明业务对象归属，真实归属仍由产品 PEP 验证。

首版上限为 64 KiB 文档、64 条语句、每语句 128 个动作和 64 个资源选择器。拒绝重复/未知字段、重复 sid/action/selector、未知动作、混合 scope、无对应动作的资源种类、未知语言版本以及未实现的条件/模式。自定义条件与通配扩展由 005 增补同一语言，不在此提前接受后忽略。

API owning codec 规范化语句/动作/选择器的集合顺序，输出唯一 JSON 和域分离内容摘要，不修改调用者对象。`PolicyVersion` 绑定 policyId、versionId、文档和摘要；版本 ID 与 languageVersion 独立。语法有效不代表任何人有权发布/关联此策略。

纯求值器检查整个输入状态后计算匹配语句：无 Allow 即拒绝，任意匹配 Deny 覆盖 Allow。未知或冲突版本、摘要不符、无效资源及目录不一致失败关闭。相同 policyId 的同一有效版本可经多个来源出现并去重，不同有效版本并存是权威状态冲突。输出命中的版本引用，用于下一步事务证据；它不是可缓存的 permit。多个 scope 的策略可以属于同一主体，但只参与该次 Action 对应 scope 的计算。

求值位于现有 `internal/authority`；策略 JSON/版本编码在 `api/iam/v1`。这两个新文件分别承载此前没有的策略语言边界与纯求值复杂度，不新增服务、框架或平行权限入口。

### 事务

控制台策略目录使用 `GET /v1/policies`（`iam.policy.list`，当前 Account 的 ORGANIZATION target）和 `GET /v1/platform-policies`（`iam.platform-policy.list`，封存 INSTALLATION target）。两者仅允许 IAM 作为调用服务，独立验证当前 USER 决定，不接受任何账号、安装、scope、排序或过滤 selector。平台目录读取不隐含租户目录读取或关联写入权限。

`PolicyList` 返回权威 accountId/scope（平台另有封存 installationId）和稳定 ID 排序的完整元数据列表，包含退休记录但不返回策略内容或授权许可。当前单次读取预算为 256 项，SQL 取 257 项检测超限；溢出整体失败，不提供伪造的完整目录或静默截断。大目录搜索/分页在 005 的策略管理读取面接入真实游标后扩充，当前不声称此目录满足无限容量。UI 仅允许选择 ACTIVE 条目，提交其真实 policyId/resourceVersion；未读取到目录时不硬编码版本或回退到旧角色菜单。新目录动作只显式加入对应系统管理策略的新不可变内容，种子重放不替换已有默认指针。

目录 API、用例、SQL 和生成 OpenAPI 已接通，仍属于未提交的整体替换候选。现有 `TestIAMPolicyAuthorityStoragePostgres` 在新建、1 CPU/768 MiB 的 PostgreSQL 18.4 数据库通过完整 race（32.31s）；目录子项 3.28s，补齐撤权及 outbox 断言后在另一新库专项复验 3.64s。真实受限 API 登录证明双租户同名自定义策略隔离、普通服务凭据不能作为 USER 读取、平台/租户目录分权、只读策略不能创建关联、退休策略仍返回当前元数据且不再授予读取权限、平台关联撤销后的下一请求拒绝。256 项完整返回，257 项整体 503，决定及 outbox 均无部分新增，另一账号不受该容量影响；旧决定不能作为下一事务或另一 scope 的读取许可，worker/本地恢复角色没有执行权限。HTTP 拒绝 query/body selector，严格输出 schema 排除内容、主体集合及 permit；账号 header 不改变权威结果。

目录增量后的 API/IAM/Audit owning packages 与架构默认无缓存 race、对应 vet、生成一致性及 diff 检查通过。真实固定 `5721b7b` executable 的保留数据升级/本地恢复/重启复验 20.37s，原权限与撤销历史不复活；这不证明跨 release-profile 安装准入。上述默认测试跳过的数据库用例不计作实跑。本轮专属 PG 容器、网络和一次性数据卷已核对归属后清理；其他 Phase、远端及 UX 的 MOCK 实例未改变。控制台源码已消费新目录和精确策略修订；真实浏览器、独立多服务和签名完整 Profile 门禁仍待完成。

直接 USER 关联管理使用 `POST /v1/policy-attachments` 与 `POST /v1/policy-attachments/{id}:revoke`；不保留旧 RoleBinding 路由。创建关联 ID 由账号、操作者及 requestId 的域分离摘要稳定生成，策略 ID/目标/预期策略版本进入输入摘要。仅相同未撤销关联和原输入可重放返回；改变输入、已撤销关联或另一现存有效关联冲突，不因重试分配新 ID 而复权。撤销检查预期关联版本；完成后仅原版本加一、相同输入和操作者的事实可精确重放，其余陈旧版本冲突。两种写入都在当前授权事务内验证目标 USER 与策略 scope、封存 installation、策略/关联修订和原 primary 保护。

新事实为 `iam.policy-attachment.created/revoked`（tenant chain）与 `iam.platform-policy-attachment.created/revoked`（installation chain），target 均为 POLICY_ATTACHMENT；必须有当前 USER 决定，不接受 SYSTEM、probe 或 target.tenantId 变体。平台关联 ID 的物理 owner 仍为调用身份的 home Account，不允许用跨账号 target ID 借平台权限修改其他租户。事实、关联和决定/outbox 同事务；公开命令不提供系统策略发布或服务主体授权旁路。

用例负责系统策略装配、附件授予撤销、当前来源收集和决定持久化。写入按 scope → principal → policy → attachment 锁序；撤销与密码/状态保护使用相同 principal 锁。账号级普通变更对 organization 使用共享锁，不把不同成员的所有写入串成独占队列；租户生命周期与安装 primary 恢复需要独占 scope。凭据变更继续按 principal → credential → session 加锁，退出先读取不可变主体引用，再按 principal → session 重新锁定当前记录。API/worker/verifier 无越权 DML，查询走 RLS/受限函数。安装恢复用例要查询新的显式平台附件，保持封存 primary tuple 与原 receipt。

任何未撤销 INSTALLATION scope 的 USER 关联均阻止普通租户管理员通过状态/密码接口接管该身份；保护不依赖策略显示名、某个预置策略 ID、策略是否仍 ACTIVE 或用户当前是否可登录。仅退休策略或先停用用户不能绕过，关联正式撤销后才恢复普通成员管理规则。离线恢复仍只消费原封存 platform attachment ID/修订及安装归属，不因此允许任意平台关联转化成恢复资格。

多实例的授权一致性依赖每次请求在权威库的同一事务中读取当前身份、关联和默认版本，再保存决定/outbox，不依赖进程内会话或缓存的 Allow。撤销提交并确认后开始的新请求必须拒绝；与撤销重叠的在途请求由事务串行化结果决定，不能声称已实时取消此前接受的业务 Operation 或长连接。事务因明确回滚的并发冲突重试时，必须重新读取整个身份/策略快照，不能沿用上次计算结果。未知提交结果不能按普通冲突重试。

如果后续加入策略编译缓存，只缓存精确 policy/version/contentDigest 对应的不可变内容，不缓存关联有效性、默认版本指针或可复用授权许可。没有已验证的一致性屏障前，不将异步只读副本用于当前权限决策。权威库不可用、关系损坏和预算溢出返回失败关闭的不可用结果，不能降级成旧 Allow；容量和故障实测归 011，不用这些设计声明代替 HA 验收。

### 读取结果进入评估器的契约

创建普通 USER 只创建身份、独立凭据和首次改密要求，不附带权限。旧 `CreateUserRequest.initialRole` 字段、其请求摘要字段和用例中的隐式 RoleBinding 写入已删除；严格解码拒绝该字段，而不是忽略后接受。账号开通对原 primary 的显式系统策略初始化是独立用例，不由普通成员创建承担。

该路径在现有 PG18 policy storage 门禁实跑通过：六种旧 initialRole 值均被 HTTP 400 拒绝，主体与 outbox 无部分新增；合法创建后的实际关联数为零。含既有密码竞争与策略存储检查的最新 race 整项 14.89s。新的关联请求 Go/schema 正反例、API/HTTP/usecase race、架构、vet 和生成一致性通过；该成员创建门禁不替代后文直接策略关联管理及完整场景的验收。

关联创建契约为 `CreatePolicyAttachmentRequest {target, policyId, policyResourceVersion, requestId}`；修订必须是正的安全整数。首个直接主体管理切片只接受 USER，GROUP/ROLE/SERVICE_ACCOUNT 的管理入口待各自 FEAT 的真实用例接入后才开放。`RevokePolicyAttachmentRequest {resourceVersion, requestId}` 绑定准确关联修订，旧版本冲突不能静默撤销当前状态。两者都不接受 account/tenant/installation/scope selector；数据库内的策略与关联决定动作的权威范围，传入平台策略 ID 本身不授予平台权限。请求校验、生成 schema、HTTP 路由、用例和 SQL 修订检查已接通，旧 RoleBinding 管理路由及实际写入用例已删除。当前 Go/OpenAPI 的 `BuiltinRole`、`RoleBinding` 对象和旧请求 DTO 均已删除；固定旧 executable 只由测试私有 wire 读取历史响应。保留的旧 Action/Target 与恢复 `platformBindingId` 只能验证已发布历史，不能进入当前求值或授予。当前进程、安装测试客户端和控制台 repository adapter 也已切到策略关联；完整组合门禁尚未实跑，不把局部管理门禁当作整个替换验收。

`Policy` 保存 management=SYSTEM/CUSTOMER、稳定 ID、显示名、scope、ACTIVE/RETIRED、默认版本 ID、资源修订与时间。CUSTOMER 必须属于一个 Account 且只能是 tenant scope；SYSTEM 无客户所有者并使用保留的 `system.` ID 命名空间。显示名不决定权限。退休仍保留默认版本和历史引用，不等于删除内容。

`PolicyAttachment` 保存 Account、稳定关联 ID、target(kind/id)、policy ID、scope、封存 installation ID（仅平台/probe）、修订和创建/更新/撤销时间。平台关联只接受 USER，probe 只接受 SERVICE_ACCOUNT；租户 target 的 USER/SERVICE_ACCOUNT/GROUP/ROLE 描述授权载体，不扩展可登录主体类型。已撤销关联必须有更新后的修订与一致撤销时间，不提供恢复为活跃状态的变体。

数据库的当前来源查询应返回 `AttachedPolicy`：关联、策略元数据和精确默认内容版本。`EvaluateAttachedPolicies` 先检查所有关系的 Account/主体/安装归属、状态和默认版本一致，再调用已有唯一语句评估器；任一损坏关系不能留下部分 Allow 或证据。当前直接主体路径拒绝未证明的 Group/Role 来源，继承证明由 004/006 接入后才启用。结果绑定准确关联 ID/修订以及命中的 policy/version/digest，按关联 ID 排序，不把允许权限重新解释为策略名称。

以上对象/严格解码与关系校验已实现于现有 API/domain owner。当前候选已将 Go loader、实际 Decide/DecideService 接到 policies、policy_versions、policy_attachments 的当前关系快照；生产鉴权不再通过旧角色名装配权限。管理路由已切换；控制台及完整消费者尚未原子切换，不能运行作交付版本。契约测试覆盖跨 Account、错主体、伪造安装、未证明继承、非默认版本、退休/撤销、摘要替换、重复关联、预算和 Deny 证据顺序；完整业务闭环仍是本 FEAT 的必要剩余项。

成员目录 `PrincipalAccess.policyAttachments` 返回同 Account、同 USER 的未撤销直接关联，替换旧 `roleBindings` 投影；不按策略名推断角色，不把元数据 RETIRED 或主体 DISABLED 当成关系撤销。每成员最多 256 条，SQL 读取 257 条用于检测溢出，不能静默截断关系。Go/schema 拒绝错误主体类型、跨账号/主体、重复关联或同策略重复有效关系、撤销关系及超预算结果。目录是管理快照，不是有效权限或可复用许可。

该目录与新管理路径在专属 PG18 的 `TestIAMPolicyAuthorityStoragePostgres` 通过 race（整项 23.20s）。实际 HTTP 证明关联 ID/修订/scope 投影一致，撤销后移出目录；重新显式授权分配新关联，旧撤销请求精确重放不能撤掉新关联。策略退休及 USER 停用不隐藏未撤销的平台保护关系。原有平台授权与密码重置/停用竞争已迁移到新接口并通过（4.20s），核对最终状态与成功授权不能同时落在被停用或待改密身份上；这不是 grant/revoke/local-recovery 全部锁顺序的控制调度证明，受控恢复/撤权的双向顺序证据见下文。全仓测试包编译通过，但空选择器不代表全仓运行验收。最新 API/IAM/Audit owning packages 与架构无缓存 race、对应 vet、生成稳定及 diff 检查通过；默认跳过的真实门禁不因此视为通过。本轮带唯一标签的 PG 容器、网络和数据卷已确认独占后清理，没有操作其他 Phase 或共享服务。

`lookup_session` 最后一列为 `policies jsonb`，服务读取使用 `lookup_service_policies`；主体验证只采用当前凭据和封存安装归属。快照严格解码并限制总字节与 256 条关联；SQL 最多返回 257 条用于检测溢出，不能截掉后面的 Deny。CurrentIdentity 以 `policyAttachments` 替换旧 `roles`，返回当前 USER 的关联引用而非可复用 permit；其 OpenAPI 和 Go 校验同步拒绝旧字段、跨账号/主体、重复或撤销关联。

领域求值结果将公开 AuthorizationDecision 与私有 PolicyEvidence 分开。新五参数 `record_authorization` 在同一事务核对关联 ID/修订、主体与 scope、当前默认版本/digest，并保存 `authorization_decisions.policy_evidence` 和原 outbox；没有证据的 Allow、重复/额外字段、错误关联或摘要失败关闭。决定及其证据禁止 UPDATE/DELETE/TRUNCATE。已有历史决定保留 NULL，不按迁移时的权限补造原始证据，也不重写原 decision document 或 Audit canonical bytes。新管理动作已接入，产品 Profile revision 的完整决定证据仍待后续同片完成；不宣称此列已覆盖全部最终证据字段。

2026-09-11 该契约增量通过 API/IAM 全部 owning packages 与 architecture 的无缓存 race、IAM/API vet、生成稳定及 Linux/amd64 IAM 构建；API/domain 连续三次聚焦 race 也通过。固定 `3b370ca2c3ab299ec80b554ef970e70d609e2b29` 的独立 Verification `34570914253` 已核实 completed/success。默认版本改为另一不可变内容后，同一关联产生对应的新求值结果与版本证据；坏记录位于有效 Allow 之后仍整体拒绝。这些固定契约证据不包含后续未提交的存储候选。

## 验收

### 已实现的求值核心；未完成的权威替换

策略语言、规范编码/摘要、不可变内容版本与唯一 deny-first 求值器已实现。当前候选的实际授权决定读取持久化策略及当前默认版本，已删除 `RoleAllows` 和旧绑定名到内容的运行时映射；在线管理 API、成员目录、进程测试客户端和控制台已切换到策略关联，旧公开请求 DTO 已删除。真实组合和发布消费者仍须门禁确认，不能仅凭源码切换声称整个代码库已完成替换。求值器不限制策略数量为六种，也不按策略名称判断权限。系统策略列出显式 Action 集合，新增目录动作不会自动加入。

当前 policies/versions/attachments 持久化、旧绑定迁移、实际读取求值和关联/内容版本证据落库已有未提交候选；控制台源码、严格 repository adapter、85 项前端测试及 59 个内嵌文件已完成替换并通过 2-worker 双次构建一致性检查。真实浏览器、完整产品 Profile 证据及组合回归仍未完成，因此本 FEAT 未 Accepted。候选服务与 SQL/readiness 为 IAM6/Audit4，发布 profile 尚未切换，不能将该混合中间态发布或启动作交付版本；最后已验证发布边界仍为原 4/3/1+r4，没有声明最终组合或签名发布可用。

既有完整 `TestIAMHTTPPostgresVerticalSlice` 已迁移到新关联管理和目录投影，在新的受限 PostgreSQL 18 数据库通过 race（88.28s）。成员创建不附带权限，测试必须另发显式策略关联命令；旧 initialRole 仍严格拒绝。实际覆盖两个租户同名用户/别名竞争、100 条目录分页、跨账号主体/关联 ID 拒绝、原 primary 保护及恢复、租户暂停/恢复、撤权后下一请求拒绝、密码/会话策略与并发、平台授予/凭据保护、IAM/PaaS/Audit 历史 producer 证明及物理 outbox owner/封存链分离。新 IAM 关联事实经过真实 HTTP producer 校验，摘要替换拒绝。安装 verifier 的服务关联不能通过 USER 管理路由撤销；后续存储撤销 fixture 只证明当前服务鉴权拒绝，不声明新的服务身份在线管理 API 已交付。独立服务进程、安装测试客户端和 UI 静态消费者已适配新接口，但完整组合尚未实跑；此结果不包含签名发布或真实浏览器。

现有 IAM integration owner 的 `TestIAMPolicyAuthorityStoragePostgres` 在专属 PostgreSQL 18.4、1 CPU/768 MiB、独立数据库和动态回环端口通过 race（末次 2.24s 用例时间）。它实际执行空库迁移、多次 Up、安装 bootstrap/等值重放、HTTP 登录/改密/当前身份和受限 API 登录下的 HTTP 鉴权，逐次核对实际持久化的关联/版本证据。验证不可变版本/决定、默认版本所属关系、默认切换后的 Deny 与重放保留、退休/撤销不复活、跨 Account 元数据/版本 RLS、伪造关联/决定证据及 runtime 角色拒绝直接读表。256 条当前关联仍能正常鉴权，第 257 条刻意放在最后且包含 Deny 时返回 503，不产生部分决定，不会截掉 Deny 后错误 Allow。测试中的管理状态变化由隔离数据库 fixture owner 构造，不证明新的在线策略 API 已实现；撤销前恢复可 Allow 的默认版本再验证拒绝，避免退休或 Deny 掩盖撤销缺陷。

既有 `TestIAMRetainedLocalRecoveryProcessUpgrade` 实际运行固定 `5721b7b` 旧 executable 产生权限与撤销历史，再执行候选迁移；当前客户端切换后，真实 `5721b7b`/`9fd45b0`/`a36` 三种固定旧 executable 保留数据升级分别通过 race（13.70s/10.06s/10.13s，整包 36.673s）。旧版本准备仅使用原测试内的私有旧 wire；当前程序只使用策略关联接口，不恢复旧公开请求类型。两种注入故障均保持旧权威不变且不暴露新策略表；正常双次迁移后关联 ID、主体类型、scope、封存安装、修订与全部时间字段精确保留，历史决定证据仍 NULL，旧 Audit canonical bytes 未变，旧 executable 拒绝新权威。当前 IAM6 程序随后完成保留会话读取、本地原 primary 凭据恢复、精确 receipt 重放及重启；旧密码、撤销会话和已撤成员权限没有复活。此门禁不覆盖完整 IAM/Audit/PaaS 组合或跨 release-profile 安装准入；当前发布 profile 与候选 IAM6/Audit4 尚不匹配，真实 profile 比较保持拒绝，不能弱化该检查来通过进程门禁。

本次候选 API/IAM/architecture 的默认无缓存 race、API 契约生成一致性与全仓测试包编译通过；全仓编译使用空测试选择器，不是全仓运行验收。安装测试 owner 已适配 CurrentIdentity、成员目录及显式策略关联创建/按修订撤销，未改变 release profile、发布准入或继承安装验收。

Audit 既有 `TestPostgresAuthorityIntegration` 已适配新 session 关系投影、IAM6 readiness 和五参数决定写入，在本任务限额 PostgreSQL 18.4 的新数据库通过 race（末次 2.25s 用例时间）。受限 IAM/Audit 登录不能直接读取策略/版本/关联/决定表；各目录动作的写入绑定精确关联与版本证据，installation probe 使用真实 SERVICE_ACCOUNT fixture 而不是伪造 USER Allow。平台关联撤销后，新决定被拒绝，原决定/策略证据/outbox 仍可读取，原事件通过 Audit 数据库 append、精确重放和变体拒绝，未改 canonical/chain。此门禁验证数据库契约和不可变证据，不是第二策略评估器，也不替代独立 HTTP producer admission、在线附件管理或完整多进程验收。

适配后 API/IAM/Audit 全部 owning packages 与 architecture 的默认无缓存 race、API/IAM/Audit vet 和 diff 检查通过；默认运行中需要独立 DSN 的门禁仍按原环境开关跳过，真实数据库证据仅限以上明确实跑项目。本轮任务专属 PostgreSQL 容器、网络和测试数据卷已核对归属后清理；没有修改其他 Phase 或共享运行环境。当前仍是未提交的整体替换候选，不继承旧固定提交的 CI 结果。

2026-09-11 本分支局部证据：默认全仓 `go test -race -p 2 ./...`、全仓 vet、模块校验和生成稳定通过。新 PG18 独立限额库中的 IAM HTTP/本地凭据恢复 race 通过（155.770s）；既有独立 IAM/Audit/PaaS 门禁加第二 IAM 实例，以及实际 5721 旧 executable 保留数据升级合计通过（56.307s）。相关架构、默认拒绝、Deny 优先、跨 scope、冲突版本、摘要变体、预算边界和实际 service/action 决定测试通过；这些证据只覆盖当前转换，不替代最终附件迁移。

纯求值基线在 Windows/amd64、Core Ultra 5 125H、GOMAXPROCS=2、20 Action 的策略文档、1/16/64 个有效版本下，单次有界测量分别约 5.6/126.6/564.6 µs，分配约 7.6/125.2/502.2 KB；不可变内容只编码一次但每次仍校验 digest。它不是端到端容量、SLO 或 HA 验收，负载/复杂条件/数据库路径需由 011 后续实测。

末次聚焦 API/authority/usecase/architecture 的无缓存 race 回归、Linux/amd64 全仓构建通过；同一 grammar 的有界双 worker fuzz 通过 192,454 次执行（12.173s 含收尾）。未启动其他 Phase 的环境或改变共享服务；本轮独立 PG 容器、网络和卷已清理。

### 策略发布与关联修订的并发证据

现有 policy storage 门禁新增真实 USER HTTP 与 fixture 发布事务的并发验证；不新增在线策略编辑旁路。以数据库实际等待状态确认请求已阻塞，再提交默认版本切换或退休：旧 `policyResourceVersion` 请求分别返回 409/403，关联、授权决定及成功事实均无部分写入。发布事务回滚后原修订正常授予；明确确认新修订的新请求可以创建关联，但有效权限由新的默认内容计算，不由“关联成功”推断 Allow。

切换至匹配 Deny 的版本后，下一次真实鉴权拒绝；决定保存精确 attachment ID、policy/version/digest。先前 Allow 的证据 bytes 保持不变。该用例在两份新 PG18 数据库通过 race（聚焦 2.51s，完整 storage 中 3.17s）；完整 `TestIAMPolicyAuthorityStoragePostgres` 26.31s，保留所有凭据竞争、平台保护、RLS、预算和不可变性门禁。发布侧仍是隔离 fixture owner，不将此证据写成自定义策略在线发布、并发编辑或完整默认版本管理 API 已交付。

租户原 primary 恢复的内部变更字段改为 `AttachmentID`/`PolicyAttachmentID`，新 ID 使用 attachment 命名；已发布离线恢复的 `platformBindingId`、封存 expected/receipt 和旧历史编码不变。

本次变更后 API/IAM、当前进程与安装测试客户端、架构的默认无缓存 race，以及对应 vet/diff 检查通过；默认跳过的真实场景不计为实跑。上述保留升级和策略测试使用的同一本任务专属 PG 容器、网络及卷已核对唯一标签、精确 ID 和独占挂载后清理，临时数据库不保留。没有停止其他 Phase 的服务或操作远端。

### 最终功能门禁

- 现有每个 role/action/service 允许拒绝矩阵在替换前后等价，新增无权限主体仍默认拒绝。
- 真实旧 binary 生成已授予/已撤销/已禁用状态后升级，两次迁移、bootstrap replay、重启不复活权限。
- 当前权限、historical proof 和原始 Audit 哈希各自正确；没有第二 evaluator 或旧在线 API。
- 并发 revoke/reset/status/grant、错误版本和跨 Account ID 无部分变更。
- PG18 受限登录、架构、security/race、独立进程与签名 profile 匹配门禁通过后 Accepted。

固定采用归既有 adoption。安装 owner 已冻结 IAM6/Audit4/PaaS5+r12；落地前仍须逐项核对实际 ABI，不能只分配一个数字。`/v1/authorize` 和严格 `{event}` 的 `/v1/audit-producer:resolve` 在切换片中与消费者原子适配；不留下旧组织 selector 旁路。

原始 bootstrap 的 primary/platform 关系保留为显式系统策略附件。旧 binding 的 ID、resourceVersion、created/revoked 历史必须确定性迁移；平台凭据恢复只能使用仍未撤销的等价平台附件。若改动私有 `LocalCredentialRecoveryExpected` 中的 binding 字段，须在同一候选中更新 API、安装消费者、SQL、签名 codec 和旧 receipt 迁移，不能并存两套授权状态。首次授权与撤销后重新授权不因重构获得入口。

## 保留数据与活跃权限的分离

迁移依据真实 `role_bindings` 的 `(tenant_id,id)`、principal、role、resourceVersion 和 created/updated/revoked 时间；不能以“当前还能登录”推断历史有效状态。原安装 primary 的 local-recovery expected/receipt 已封存具体平台 binding ID 与版本，附件继承同一身份而不重新分配；历史完成的查询不重新判断当前附件是否有效。

当前候选已将关联写入/撤销、本地恢复及密码/状态/退出路径调整为一致的 scope/主体优先锁序，不再让恢复和撤销先持有关联再等待主体。实际 SQL 与 Go 管理契约已切换；新接口的授予/凭据竞争及受控恢复/撤权双向顺序已有下述真实证据，默认版本切换/退休与关联修订竞争已由现有 fixture 发布门禁证明；完整在线消费者仍须补齐，不能以旧角色入口测试代替。

既有 `TestIAMLocalCredentialRecoveryPostgres` 已替换旧角色调用/状态读取，真实受限恢复角色与 API 登录使用当前策略关联。原 `platformBindingId`/修订仍是已发布私有 expected/receipt 的字段，内容指向保留原 ID 的附件，不重命名或重签历史记录。新请求对已经有效的同策略关联返回冲突，不伪装成等值授予；恢复先完成时目标处于强制改密状态，新授予拒绝。负向 SQL 事实使用事务内撤销附件证明资格失效，不删除受保护历史。

在专属 PG18、1 CPU/768 MiB 环境，两次新库整项 race 通过（19.59s、37.91s），涵盖实际恢复、严格能力/来源/目标及版本攻击、API/worker 越权拒绝、重复/不同意图并发、在线重置/租户恢复/授予/旧密码登录/改密/退出竞争。通过实际数据库等待观测控制恢复先和撤权先两种顺序；撤权先不得改变凭据，恢复先只执行一次凭据变更。bootstrap/迁移重放及原完成 receipt 重放不恢复撤权，也不覆盖后续密码。两个顺序之间仅通过真实强制改密和独立平台操作者的新显式关联重置前提，不复活旧附件。对应 integration vet 和 diff 检查通过；本轮独占 PG 容器、网络及卷已核对后删除。本门禁不证明跨 release profile 的安装升级许可，也不替代尚未实跑的完整多进程/真实浏览器门禁。

2026-09-11 同一 policy storage owner 在新的限额 PG18 库复用既有五组真实 HTTP 凭据竞争矩阵（change/reset/original-primary recovery/logout/old-password login），连同策略存储与拒绝门禁通过 race，整项 18.95s、竞争子项 13.60s。额外原生 fixture 系统策略采用不同于 PlatformOperator 的 ID，实际状态/重置 API 在其 ACTIVE、策略 RETIRED、USER DISABLED 三种情况下均拒绝且密码、generation、会话和成功事实无部分变化；撤销该附件后正常成员启用成功。锁序调整后的实际旧 5721 binary 保留数据升级/本地恢复/重启整项 race 复验 16.78s，IAM/Audit 双 schema 门禁复验 4.74s，相关 vet/diff 检查通过；本轮专属临时数据库容器、网络和卷已清理。此片不新增在线系统策略发布能力，不代表新的关联 HTTP API 或完整 HA 已验收。

### 当前切换片的数据库边界

`policies` 保存稳定身份、管理者类别、所属 Account（自定义策略必填，系统策略无用户所有者）、scope、默认版本及修订；`policy_versions` 保存不可变文档/语言版本/digest；`policy_attachments` 保存准确主体、权威范围、policy ID、原关联 ID/RV/时间与撤销状态。版本归属必须由复合外键和受限读取验证，不能以任意 version ID 拼接另一 Account 的策略。系统策略可复用内容不等于附件可跨 Account 生效。

种子文档使用现有 Go 策略编码拥有者生成，SQL 不复制第二套 Action 权限集合或摘要编码。第一次迁移显式确定每种旧绑定对应版本；后续发布新版本不因重放种子而切换已有默认版本。历史附件/决定引用的版本不能下架后物理删除；当前有效来源读取不能返回撤销附件或多个冲突默认版本。

IAM `migrations.Source()` 现在拥有一个实际 BEGIN/COMMIT 边界，包住全部现有权威 SQL 片段与最终 schema/权限验证；片段不再分别提交。角色 bootstrap 仍是独立安装前置，runtime 登录仍由原安装流程在 Up 成功后配置；本片没有改变共享 migration executor、发布 profile 或跨版本准入。

2026-09-11 的真实 5721 executable 保留数据门禁加入两种受限数据库故障：创建恢复入口时中断 DDL，以及 SQL 完成但故意留下不安全 RLS 供最终 verifier 拒绝。第一种反例在旧 Source 下确实失败（暴露部分迁移），修复后两种均通过；封存 receipt、组织/主体、凭据、会话、绑定、原授权决定与 outbox 保持原状态，新恢复表不暴露。含正常双次迁移/恢复/重启的该门禁通过 15.386s。它证明现有 schema3→4 的原子前置，不证明待实现的 IAM6 附件迁移或跨 release-profile 升级。

后续新权威结构/数据映射/函数替换/readiness 更新必须纳入同一事务，扩充此失败门禁。等值重放不能重建可写旧 RoleBinding 权威或导入迁移后才出现的旧写入；旧 executable/readiness 需失败关闭。

原 `local_credential_recoveries.expected_state` 保存了精确 `platformBindingId` 与版本，但没有指向旧 role_bindings 的外键；这是已发布完成证据，不是可删除字段。新附件继承原 ID/RV，当前恢复检查查询附件，历史 receipt 仍按原 bytes 独立返回，不重签已完成意图。SQL 保留数据资格不等于跨完整 release profile 的安装准入。

删除的是旧在线 RoleBinding 权限权威，不是不可变历史词汇。旧 Audit action/target、authorizations 和 receipt 的严格读取由原历史契约继续验证，不重编码、不新增授予能力。

当前候选的 API/领域/SQL 已区分活跃操作与历史决定：`iam.policy-attachment.create/revoke` 分别绑定 PRINCIPAL/POLICY_ATTACHMENT、tenant scope；`iam.platform-policy-attachment.create/revoke` 使用相同资源种类和 installation scope。这四个动作只属于 IAM 调用方；相应系统策略显式采用新动作，probe 不获得业务权限。策略与关联的真实 scope 决定后续管理用例使用哪个动作，调用方不能以 scope selector 选择授权。

四个旧 `iam.role-binding.put/revoke`、`iam.platform-role-binding.put/revoke` 只在封闭的历史定义中保留。AuthorizationDecision 的 Go/schema 读取接受其精确旧 resource/scope；AuthorizationRequest、策略编码、服务 admission 和实际求值均只用当前目录。SQL `record_authorization` 及 `assert_allowed_decision` 同样拒绝退休操作；最终迁移 verifier 检查新映射及旧映射关闭。不能通过 unknown action、混合/替换 scope、错资源类型或平台 SERVICE_ACCOUNT 扩张历史读取。旧在线路由/实际用例已删除，新关联接口和控制台只使用当前动作；仅实际固定旧 executable 的升级准备保留私有测试内的旧 wire，不能恢复退休动作让旧路径通过。

本次分离的 API/schema、领域与架构 race 通过，生成稳定、对应 vet/diff 检查通过。专属 PostgreSQL 18.4 的实际 IAM HTTP/策略存储 race 23.44s：旧动作返回既有语义错误 422，不产生新决定；保留凭据并发与平台保护。双 authority 数据库 race 6.30s：受限 IAM 登录对每个旧动作的新 Allow/Deny 写入均被 SQLSTATE 22023 拒绝，无 decision/outbox 部分效果；新目录写入与原审计证据仍可读取。实际固定 5721 旧 executable 保留数据升级/重放/本地恢复/重启 race 24.17s 通过。没有修改旧 Audit canonical/claim 或发布 profile；这些历史动作分离证据不替代后文的新在线关联管理门禁或尚未完成的完整组合验收。

`TestIAMCoreUsecasesBindCredentialsAndRecordClosedAuthorization` 已迁移到新关联用例和实际策略快照，不再借旧 RoleBinding 获得决定；API、核心用例、HTTP 与架构 race 通过。新的直接 USER 管理 HTTP 门禁在受限 PG18 登录上证明授权可读、撤销后新请求拒绝、CAS 冲突无部分效果、精确重放只有一份成功事实、旧创建不能复活撤销关联、普通成员和租户管理员不能自授权限或平台策略。平台关联事实使用独立 installation chain，并通过封闭 Audit 契约验证。相关双 authority 门禁通过（用例 2.93s）；实际旧 5721 executable 保留数据升级/本地恢复/重启通过（用例 16.14s）。这些是未提交候选的局部证据，不继承原 CI，也不代表完整进程/UI/安装验收。
