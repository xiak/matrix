# FEAT-IAM-004：用户组与授权委派

- 状态：首片后端与前端接口适配已实现并通过本地门禁；独立 CI 待确认，签名游标和组 UI 闭环未完成，整体未验收。
- 依赖：002、003。
- Owner：IAM Group、GroupMembership、组策略附件和组继承证据。

## 需求

| ID | 行为 |
| --- | --- |
| IAM-GRP-01 | Group 创建、列表、详情、名称/描述修改和永久删除；稳定 Group ID 与可变名称分离，同一 Account 的活跃名称唯一 |
| IAM-GRP-02 | GroupMembership 连接一个活跃 User 与一个 Group，支持精确创建、分页、移除、幂等重放和 resourceVersion 冲突 |
| IAM-GRP-03 | tenant Policy 可关联 Group；installation Policy、ServiceIdentity、Role、RootIdentity 和嵌套 Group 不能借该入口进入成员或授权关系 |
| IAM-GRP-04 | 当前有效权限由 User 直接附件与全部当前 Group 附件共同进入唯一 PDP；默认拒绝、显式 Deny、scope、版本和预算不变 |
| IAM-GRP-05 | 授权决定证据区分 DIRECT 与 GROUP，并绑定精确 GroupMembership、PolicyAttachment、PolicyVersion 及各自修订，不能只记录策略名 |
| IAM-GRP-06 | 移除成员、撤销组附件或删除组提交后开始的下一次受保护请求必须失权；不声称取消此前已接受的 Operation、长连接或后台任务 |
| IAM-GRP-07 | Group 无登录凭据、不成为 Subject、不拥有应用、数据库、配额、Operation 或 Audit；User 删除前由 003 统一撤销其成员关系 |
| IAM-GRP-08 | 委派动作是封闭 Action/Resource 契约；UI 只消费 actor-relative capability，不能按组名、策略名、角色名或业务服务名推断权限 |

公开产品中用户组、成员多对多和组策略继承的可观察事实由[访问管理来源分析](../doc/access-management/sources/tencent-cam-architecture-analysis.md#用户组)唯一维护。本 FEAT 只定义 Matrix 自研契约，不复制供应商 API 名称、配额或内部实现推测。

## 对象与 API

`Group` 包含 `accountId`、稳定 `id`、可变 `name`、可选 `description`、`resourceVersion` 和创建/更新时间。删除使用内部 tombstone；历史 Audit 始终引用 Group ID，名称可重复使用但不能改变旧事实含义。Group 没有 status、密码、会话、AccessKey、成员身份或资源所有权。

`GroupMembership` 包含稳定 `id`、`accountId`、`groupId`、`userId`、`createdBy`、`resourceVersion`、创建/更新时间；终态回执必须同时带 `removedAt` 和 `removedBy`。同一 User/Group 同时最多一个活跃关系；移除是终态。重新加入产生新关系，旧关系及 Audit 不复活。列表只返回活跃关系。首片只支持单项命令；批量操作保留为后续同一对象的有界 API，不通过循环调用伪装原子批量。

`PolicyGrantSource` 是当前授权快照中的来源联合：DIRECT 只绑定 User 的 PolicyAttachment；GROUP 还必须绑定当前 GroupMembership。它不是 permit，不能缓存或由调用方提交。`AuthorizationDecision` 保持现有公开形状；私有 `policy_evidence` 对 GROUP 来源增加 membership ID/version，Audit producer proof 仍验证事实发生时的不可变决定，而不是之后重新执行用户权限。

首片公开路由如下；Account 均由当前有效 session 推导，不接受 header、query、body 或 cursor 改写：

- `GET|POST /v1/groups`：分页目录与创建。
- `GET /v1/groups/{groupId}`、`POST /v1/groups/{groupId}:update`、`POST /v1/groups/{groupId}:delete`：详情、CAS 修改和删除。
- `GET|POST /v1/groups/{groupId}/memberships`：分页成员关系与单项加入。
- `POST /v1/groups/{groupId}/memberships/{membershipId}:remove`：按准确关系修订移除。
- 既有 `POST /v1/policy-attachments` 与 `POST /v1/policy-attachments/{attachmentId}:revoke` 接受 GROUP target；不新建第二套附件模型或 group-local evaluator。

请求只使用稳定 ID、明确字段、正的安全 resourceVersion 和 requestId。创建/移除的等值重放必须返回原结果且不追加第二条 success 事实；相同 command identity 的变体冲突。跨 Account 的资源/关系查找与变更以不泄露存在性的拒绝结果关闭。分页 `after` 只是当前 Account/Group 内的排序位置，不是授权令牌；传入外部 ID 也不得改变查询范围或返回其所属关系。

当前首片沿用既有目录的 ID keyset continuation；它不满足 000 的最终 opaque/MAC、账号/主体/查询/授权修订绑定游标要求。该要求仍是本 FEAT 最终验收前的待实现项，不能用已通过的 RLS/范围隔离测试替代。UI 把 continuation 当作原样回传值，不解析或拼接其内容。

创建只创建空 Group，成功后进入详情逐项添加成员/关联策略；没有 create-with-policy 或批量原子承诺。每步使用独立 requestId。组已创建而后续关联失败时，UI 保留组并明确显示未完成的步骤，不自动删组或撤销其他成功关系。未知结果保留原命令及载荷，等值重试后刷新权威详情；不能换 requestId 自动重发。CAS 冲突需刷新后由用户发起新意图。重放仍重新认证当前操作者：创建结果只在组尚未发生后续修改时等值返回，关系终态重放不复活关系；后续状态已变化时冲突，不把当前详情伪装为原回执。

GroupAccess（目录项及详情）带组的直接 policyAttachments 和完整目标能力集：组 read/update/delete、membership list/create、组附件 create，以及每条直接附件的 revoke。GroupMembership 单独分页，每项携带该稳定关系 ID/resourceVersion 与 remove capability。首片不提供成员总数，真实组目录省略该列，不加载全部成员推算，也不以已加载数量冒充总数。UI 不能按 User ID 或名称代替关系 ID 执行移除。

成员页当前以稳定 `userId` 标识成员，不提供用户显示名或状态快照。已有同 Account、精确 User ID 的目录摘要只能作可选展示增强；缺少摘要不代表用户不存在，不能据缓存状态开放命令。前端不逐行查询用户，也不把已加载 User 目录页当作全量目录。

## Action、能力与事实

IAM 调用方目录新增以下精确动作，不以字符串前缀或任意 action bag 推导：

- `iam.group.list|create` → ACCOUNT；`iam.group.read|update|delete` → GROUP。
- `iam.group-membership.list|create` → GROUP；`iam.group-membership.remove` → GROUP_MEMBERSHIP。
- `iam.group-policy-attachment.create` → GROUP；`iam.group-policy-attachment.revoke` → POLICY_ATTACHMENT。

`system.account-administrator` 的新不可变版本显式列出这些动作；其他系统策略不自动扩权。已有安装的默认版本指针不会因 migration/seed replay 自动切到新版本，版本发布由 005 单独验收。现有通用策略求值器和 ActionDefinition 目录继续是唯一权限语义 owner。管理页面按 action+resource kind/id 关联完整目标能力集合，不依赖数组顺序；缺失、额外、重复、错误 kind/id 或未知 restriction 整体失败关闭。

成功事实为 `iam.group.created|updated|deleted`、`iam.group-membership.created|removed`，target 分别是 GROUP 或 GROUP_MEMBERSHIP。组策略关联继续使用既有不可变 `iam.policy-attachment.created|revoked` 事实，具体 USER/GROUP 管理动作由关联时的 IAM decision 证明；不能为同一附件再造平行 Audit action。删除 Group 在一个事务中 tombstone Group，并终态移除活跃 membership、撤销活跃 tenant policy attachment；单一 group.deleted 事实是该封闭级联的权威原因，删除回执只返回非敏感计数。

## 持久化、求值与事务

`groups`、`group_memberships` 是 Account RLS 下的独立表。现有 `policy_attachments` 的内部主体列破坏性改名为通用 `target_id`，target kind 决定它引用 User、ServiceIdentity、Group 或后续 Role；不能增加并行 group attachment 表。实际旧 IAM 数据迁移必须保留所有直接附件 ID、修订、scope、installation、撤销时间和历史决定 bytes，未知/冲突关系失败关闭。

User session 的权威策略快照以有界 UNION 读取直接附件和当前成员关系可达的组附件。GROUP 来源必须同时满足：Account/User/Group 活跃且未删除、membership 未移除、attachment 未撤销、Policy ACTIVE、默认版本和 digest 一致。任何关系损坏、来源超过预算、membership 证据缺失或同 ID 冲突都拒绝整个决定；不能截断后面的 Deny。CurrentIdentity 用 `policySources` 展示直接/继承来源，User/Group 管理详情只返回各自直接附件。

写锁顺序固定为 Account → actor User → 按 ID 排序的 target User → Group → GroupMembership → Policy → PolicyAttachment。SERIALIZABLE 冲突重试必须重新认证和读取整个来源快照；未知提交结果不按普通冲突盲重试。创建 membership 拒绝 actor 把自己加入 Group，避免仅有成员管理动作时自助提权；平台 scope Policy 永不允许关联 Group。RootIdentity、已删除/停用 User、ServiceIdentity 和跨 Account User 在锁内再次拒绝。

User 删除沿 003 的 User principal 锁后终态移除其所有活跃 membership，避免 tombstone 留下继承路径。Group 删除与成员/附件 grant/revoke 使用同一锁序；失败、CAS 冲突或并发撤权时 Group、membership、attachment、decision evidence 和 outbox 均无部分变化。删除 Group/User 不转移或删除租户资源和已接受 Operation。

首片限制每页 100 项、每个 User 最多 100 个活跃 GroupMembership、一次决定最多 256 个直接+组 PolicyAttachment 和 4096 条语句。限制属于版本化产品契约并以超额失败关闭验证，不复制外部云固定配额；容量和 HA 的端到端 SLO 归 011 实测。

## 验收

真实 HTTP/PG18 至少创建两个 Account、同名 Group、每组多个 User：创建组→加成员→给组关联 PaaS tenant Policy→成员登录访问资源→移除成员后下一请求拒绝；直接附件仍可独立允许，组 Deny 必须压过直接 Allow。来源查询与保存决定分别证明 DIRECT/GROUP、准确 membership/attachment/version/digest，伪造、撤销或跨 Account 来源不能被 record/replay 接受。

负向矩阵覆盖跨 Account Group/User/Policy/membership/attachment ID，RootIdentity/ServiceIdentity/Role/Group 入组，self-add，停用或删除 User，installation Policy，错误/旧/最大 resourceVersion，重复/变体 requestId，101 个活跃组、257 个有效附件及坏记录位于有效 Allow 之后。并发 add/remove、Group delete/add、attach/delete、actor grant revoke 必须以最终状态和事实数证明无双活、无部分写入、无已撤来源复活。

当前 schema 的等值重放、带数据重启必须保持直接附件、历史 decision/Audit canonical bytes 和撤销状态。开发历史的升级起点按 [011 首版基线规则](./FEAT-IAM-011-acceptance.md#未发布阶段与首版基线) 选择，不要求本片从 schema 1 跑完整历史链；已做的固定旧 binary 实验是风险替换证据，不等于对全部开发版本承诺兼容。

独立 IAM/Audit/PaaS + dispatcher 门禁验证组授权可创建/读取租户资源且越租户、平台动作拒绝，移组不删除资源/Operation/outbox/Audit。控制台完成组目录、详情、成员和策略管理的鼠标闭环；键盘专项按用户优先级延期，不据此宣称已验收。签名发布与完整 Profile 仍由 011/安装 owner 证明，源码/SQL 门禁不能替代。

## 首片实现与证据

2026-09-14，本分支在独立 PostgreSQL 18、1 CPU/768 MiB/PID 128 数据库容器上串行验证。Go 使用 `GOMAXPROCS=2`、`-p 2`（多真实数据库包的组合命令用 `-p 1`）；没有使用其他任务的数据库、服务或远端机器。

- 现有 `TestIAMPolicyAuthorityStoragePostgres` 最新通过 race（32.87s，其中组继承子项 12.36s）：真实管理 HTTP、双 Account 同名组/同名成员、强制 RLS、外部 ID continuation 不改变范围、直接/组来源与 Deny、撤销/删除终态、并发关系/授权竞争、100/101 组和 256/257 来源预算。当前空库故意晚段 DDL 失败不暴露半套权威；已有组、移除、删除、附件、决定和 outbox 后连续重放两次保持原值，原删除回执仍等值返回。
- 既有 IAM HTTP 全流程修正测试中的旧内部列引用后，通过 race（64.197s）。本地平台凭据恢复原门禁通过（15.07s；与策略存储合计 50.807s），保留原 primary、封闭历史事实、凭据 generation、会话及 grant/revoke/reset/recover 竞争，不新增恢复权限。
- Audit 当前双 schema/保留旧链包通过（6.254s），Audit HTTP 通过（2.994s）；PaaS 数据库包通过（5.235s）。这些是本分支真实门禁，不继承其他 Phase 状态。
- 现有独立进程门禁通过 race（39.023s）：两个 IAM 实例、Audit、PaaS 与两类 dispatcher 使用实际受限登录。仅组授权的成员实际创建应用/Operation；另一实例移组后原实例下一请求失权；Audit 中断期间已接受的资源/outbox 保留，移组后历史证明仍投递，重放不增加成功事实，Audit 记录和链不串账号。直接授权可独立保留，删除组后资源归属不变，重启不复活已撤来源。
- 全仓无缓存 Go race/vet、模块校验、重复 API 生成稳定、Linux amd64 构建通过。前端 typecheck/lint/架构/20 组对比度、100 项测试通过；两次 2-worker 静态构建的 59 个内嵌文件一致。前端接口严格核对 Group/关系/附件/目标 capability，移除回执必须同时有 `removedAt`/`removedBy`，未知结果和 409 不自动换意图重发。

当前开发服务与实际数据库/readiness 为 IAM9/Audit6/PaaS1；既有签名发布 profile 未改写，组合门禁明确不把该开发 tuple 当作已可发布 profile。实际 IAM8 固定 binary 的保留数据实验仅为本次内部列替换的可选诊断，不使全部未发布版本成为默认升级义务。

首片只交付组 HTTP/数据库/授权闭环与前端 domain/wire/repository；未新增第二套组页面。组目录、详情、表单及真实鼠标闭环由既定 UX/UI owner 消费固定提交后完成。签名游标、更多成员分页/完整多成员 UI 矩阵、最终发布组合及 011 容量/HA 门禁仍需实施验证，本 FEAT 不因此标为 Accepted。
