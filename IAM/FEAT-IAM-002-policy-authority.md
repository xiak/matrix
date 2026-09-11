# FEAT-IAM-002：策略权限权威替换

- 状态：实施中；未验收。策略语言/求值与持久化替换在同一功能切片内收口，不把纯函数测试当作迁移完成。
- 依赖：001 已验收的 CAT-01–04，固定安装/IAM5 消费者对齐；完整产品 Profile 的集成仍由 008 证明。
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

用例负责系统策略装配、附件授予撤销、当前来源收集和决定持久化。写入按 scope → principal → policy → attachment 锁序；撤销与密码/状态保护使用相同 principal 锁。API/worker/verifier 无越权 DML，查询走 RLS/受限函数。安装恢复用例要查询新的显式平台附件，保持封存 primary tuple 与原 receipt。

### 读取结果进入评估器的契约

`Policy` 保存 management=SYSTEM/CUSTOMER、稳定 ID、显示名、scope、ACTIVE/RETIRED、默认版本 ID、资源修订与时间。CUSTOMER 必须属于一个 Account 且只能是 tenant scope；SYSTEM 无客户所有者并使用保留的 `system.` ID 命名空间。显示名不决定权限。退休仍保留默认版本和历史引用，不等于删除内容。

`PolicyAttachment` 保存 Account、稳定关联 ID、target(kind/id)、policy ID、scope、封存 installation ID（仅平台/probe）、修订和创建/更新/撤销时间。平台关联只接受 USER，probe 只接受 SERVICE_ACCOUNT；租户 target 的 USER/SERVICE_ACCOUNT/GROUP/ROLE 描述授权载体，不扩展可登录主体类型。已撤销关联必须有更新后的修订与一致撤销时间，不提供恢复为活跃状态的变体。

数据库的当前来源查询应返回 `AttachedPolicy`：关联、策略元数据和精确默认内容版本。`EvaluateAttachedPolicies` 先检查所有关系的 Account/主体/安装归属、状态和默认版本一致，再调用已有唯一语句评估器；任一损坏关系不能留下部分 Allow 或证据。当前直接主体路径拒绝未证明的 Group/Role 来源，继承证明由 004/006 接入后才启用。结果绑定准确关联 ID/修订以及命中的 policy/version/digest，按关联 ID 排序，不把允许权限重新解释为策略名称。

以上对象/严格解码与关系校验已实现于现有 API/domain owner；尚未替换当前 SQL loader 或发布新的管理路由，也不是新的在线权限入口。其契约测试覆盖跨 Account、错主体、伪造安装、未证明继承、非默认版本、退休/撤销、摘要替换、重复关联、预算和 Deny 证据顺序；真实存储/迁移仍是本 FEAT 的必要剩余项。

2026-09-11 该契约增量通过 API/IAM 全部 owning packages 与 architecture 的无缓存 race、IAM/API vet、生成稳定及 Linux/amd64 IAM 构建；API/domain 连续三次聚焦 race 也通过。默认版本改为另一不可变内容后，同一关联产生对应的新求值结果与版本证据；坏记录位于有效 Allow 之后仍整体拒绝。没有以 mock、默认跳过 PG 的测试或仅类型存在宣称数据库已接入，也未更改当前 schema/profile。

## 验收

### 已实现的求值核心；未完成的权威替换

策略语言、规范编码/摘要、不可变内容版本与唯一 deny-first 求值器已实现。实际授权决定已删除 `RoleAllows` 路径，当前数据库的有效旧绑定暂经严格映射选择系统策略文档；新求值器不限制策略数量为六种，也不按策略名称判断权限。系统策略列出显式 Action 集合，新增目录动作不会自动加入。

当前仍未完成 policies/versions/attachments 持久化、旧管理 API/UI 替换与决定版本证据落库；因此 IAM-POL-01 的纯计算部分不等于本 FEAT Accepted。当前 wire、SQL/readiness 和 release profile 仍为原 4/3/1+r4；没有声明最终 IAM6 迁移或签名发布可用。

2026-09-11 本分支局部证据：默认全仓 `go test -race -p 2 ./...`、全仓 vet、模块校验和生成稳定通过。新 PG18 独立限额库中的 IAM HTTP/本地凭据恢复 race 通过（155.770s）；既有独立 IAM/Audit/PaaS 门禁加第二 IAM 实例，以及实际 5721 旧 executable 保留数据升级合计通过（56.307s）。相关架构、默认拒绝、Deny 优先、跨 scope、冲突版本、摘要变体、预算边界和实际 service/action 决定测试通过；这些证据只覆盖当前转换，不替代最终附件迁移。

纯求值基线在 Windows/amd64、Core Ultra 5 125H、GOMAXPROCS=2、20 Action 的策略文档、1/16/64 个有效版本下，单次有界测量分别约 5.6/126.6/564.6 µs，分配约 7.6/125.2/502.2 KB；不可变内容只编码一次但每次仍校验 digest。它不是端到端容量、SLO 或 HA 验收，负载/复杂条件/数据库路径需由 011 后续实测。

末次聚焦 API/authority/usecase/architecture 的无缓存 race 回归、Linux/amd64 全仓构建通过；同一 grammar 的有界双 worker fuzz 通过 192,454 次执行（12.173s 含收尾）。未启动其他 Phase 的环境或改变共享服务；本轮独立 PG 容器、网络和卷已清理。

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

当前旧恢复事务按 platform binding → organization → principal → credential 加锁，旧 revoke 也先锁实际 binding。目标的新锁序必须在 grant/revoke/reset/status/recover 全部路径中一起切换并做双向竞争门禁；不能只按本文件的目标顺序改一个函数。

### 下一切换片的数据库边界

`policies` 保存稳定身份、管理者类别、所属 Account（自定义策略必填，系统策略无用户所有者）、scope、默认版本及修订；`policy_versions` 保存不可变文档/语言版本/digest；`policy_attachments` 保存准确主体、权威范围、policy ID、原关联 ID/RV/时间与撤销状态。版本归属必须由复合外键和受限读取验证，不能以任意 version ID 拼接另一 Account 的策略。系统策略可复用内容不等于附件可跨 Account 生效。

种子文档使用现有 Go 策略编码拥有者生成，SQL 不复制第二套 Action 权限集合或摘要编码。第一次迁移显式确定每种旧绑定对应版本；后续发布新版本不因重放种子而切换已有默认版本。历史附件/决定引用的版本不能下架后物理删除；当前有效来源读取不能返回撤销附件或多个冲突默认版本。

IAM `migrations.Source()` 现在拥有一个实际 BEGIN/COMMIT 边界，包住全部现有权威 SQL 片段与最终 schema/权限验证；片段不再分别提交。角色 bootstrap 仍是独立安装前置，runtime 登录仍由原安装流程在 Up 成功后配置；本片没有改变共享 migration executor、发布 profile 或跨版本准入。

2026-09-11 的真实 5721 executable 保留数据门禁加入两种受限数据库故障：创建恢复入口时中断 DDL，以及 SQL 完成但故意留下不安全 RLS 供最终 verifier 拒绝。第一种反例在旧 Source 下确实失败（暴露部分迁移），修复后两种均通过；封存 receipt、组织/主体、凭据、会话、绑定、原授权决定与 outbox 保持原状态，新恢复表不暴露。含正常双次迁移/恢复/重启的该门禁通过 15.386s。它证明现有 schema3→4 的原子前置，不证明待实现的 IAM6 附件迁移或跨 release-profile 升级。

后续新权威结构/数据映射/函数替换/readiness 更新必须纳入同一事务，扩充此失败门禁。等值重放不能重建可写旧 RoleBinding 权威或导入迁移后才出现的旧写入；旧 executable/readiness 需失败关闭。

原 `local_credential_recoveries.expected_state` 保存了精确 `platformBindingId` 与版本，但没有指向旧 role_bindings 的外键；这是已发布完成证据，不是可删除字段。新附件继承原 ID/RV，当前恢复检查查询附件，历史 receipt 仍按原 bytes 独立返回，不重签已完成意图。SQL 保留数据资格不等于跨完整 release profile 的安装准入。

删除的是旧在线 RoleBinding 权限权威，不是不可变历史词汇。旧 Audit action/target、authorizations 和 receipt 的严格读取由原历史契约继续验证，不重编码、不新增授予能力。活跃请求不得调用已退役的 role-management 动作；历史校验不能作为第二条当前授权入口。具体 catalogue/record schema 的区分须由 API 与 SQL 同一候选实现，不能以放宽 unknown action 校验兼容旧记录。
