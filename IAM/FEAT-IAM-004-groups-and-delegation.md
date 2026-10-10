# FEAT-IAM-004：用户组与授权委派

- 状态：Group 后端、前端接口适配、签名游标及非 root 同上限委派闭环已实现；固定 `882b7820b1a225f1a0a8b95cb07ac139b8f3ab0b` 的独立 Verification 38014293154 已有 17 项全部成功。既有 IAM81/Audit37/PaaS3、contractRevision29 签名 A/B 只运行了平台与直属 User 生命周期，没有创建 Group/GroupMembership，不能作为组对象保留证据；当前切片已把下述 Group 路径加入原签名生命周期 owner，仍须在固定提交上实跑。组 UI 由 UX/UI owner 独立验收，整体未验收。
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
| IAM-GRP-09 | 非 root 只能为全部活跃成员都受同一委派上限约束的 Group 创建或撤销 tenant Policy 附件；空组同样封存上限，后续成员必须匹配，成员边界不能在仍依赖该上限时被移除或替换 |

公开产品中用户组、成员多对多和组策略继承的可观察事实由[访问管理来源分析](../doc/access-management/sources/tencent-cam-architecture-analysis.md#用户组)唯一维护。本 FEAT 只定义 Matrix 自研契约，不复制供应商 API 名称、配额或内部实现推测。

## 对象与 API

`Group` 包含 `accountId`、稳定 `id`、可变 `name`、可选 `description`、`resourceVersion` 和创建/更新时间。删除使用内部 tombstone；历史 Audit 始终引用 Group ID，名称可重复使用但不能改变旧事实含义。Group 没有 status、密码、会话、AccessKey、成员身份或资源所有权。

`GroupMembership` 包含稳定 `id`、`accountId`、`groupId`、`userId`、`createdBy`、`resourceVersion`、创建/更新时间；终态回执必须同时带 `removedAt` 和 `removedBy`。同一 User/Group 同时最多一个活跃关系；移除是终态。重新加入产生新关系，旧关系及 Audit 不复活。列表只返回活跃关系。首片只支持单项命令；批量操作保留为后续同一对象的有界 API，不通过循环调用伪装原子批量。

`PolicyGrantSource` 是当前授权快照中的来源联合：DIRECT 只绑定 User 的 PolicyAttachment；GROUP 还必须绑定当前 GroupMembership。它不是 permit，不能缓存或由调用方提交。`AuthorizationDecision` 保持现有公开形状；私有 `policy_evidence` 对 GROUP 来源增加 membership ID/version，Audit producer proof 仍验证事实发生时的不可变决定，而不是之后重新执行用户权限。

Group 附件的公开 `PolicyAttachment` 形状不增加调用者可写的上限字段。数据库只在非 root 成功关联 Group 时封存内部 `delegation_ceiling_policy_id`；Root 创建的 Group 附件保持明确无该委派证明。该值不是新 Policy、permit、请求 selector 或通用属性，不能由客户端提交，也不能在 Root 历史附件上迁移补造。Group 另有数据库内部单调 `authorization_generation`，仅用于让成员与附件的并发写入在 SERIALIZABLE 重试后重新读取完整闭包；它不是公开 `resourceVersion`，不能被客户端推进。

首片公开路由如下；Account 均由当前有效 session 推导，不接受 header、query、body 或 cursor 改写：

- `GET|POST /v1/groups`：分页目录与创建。
- `GET /v1/groups/{groupId}`、`POST /v1/groups/{groupId}:update`、`POST /v1/groups/{groupId}:delete`：详情、CAS 修改和删除。
- `GET|POST /v1/groups/{groupId}/memberships`：分页成员关系与单项加入。
- `POST /v1/groups/{groupId}/memberships/{membershipId}:remove`：按准确关系修订移除。
- 既有 `POST /v1/policy-attachments` 与 `POST /v1/policy-attachments/{attachmentId}:revoke` 接受 GROUP target；不新建第二套附件模型或 group-local evaluator。

请求只使用稳定 ID、明确字段、正的安全 resourceVersion 和 requestId。创建/移除的等值重放必须返回原结果且不追加第二条 success 事实；相同 command identity 的变体冲突。跨 Account 的资源/关系查找与变更以不泄露存在性的拒绝结果关闭。分页 `after` 是下面定义的签名 continuation，不是授权令牌；原始资源 ID 不再被接受。

UI 把 continuation 当作原样回传值，不解析或拼接其内容，也不将它与资源 ID 比较排序。

### 签名分页

同一 IAM authority 的 Account、User、Group、GroupMembership 四类目录共同替换原始 ID continuation，保留 `after`/`nextAfter` 字段，不保留旧格式回退。每页固定 100 项、稳定 ID 升序；本片不提供服务端搜索或可变排序。客户端筛选只能明确作用于已加载页。数据库内部仍以精确 ID seek，游标不能改变 IAM 从有效 session 推导的 Account 或目标 Group。

IAM 自有 HMAC-SHA256 codec 使用独立 domain/version 和大小上限，绑定封存 installation、Account/Principal 修订、当前 session lineage、准确 action/resource、过滤/排序/页大小，以及全部当前有效 Policy/默认版本/digest/Attachment/GroupMembership 修订。先在同一事务内重新认证和执行唯一 PDP，再核对游标；不缓存 permit，不因游标有效而跳过当前权限。不同 session、账号、安装、查询或授权状态、错误 key、篡改、过期均以统一不含内部边界的错误关闭；撤权即使仍有另一条 Allow，也不能沿用撤权前的 continuation。数据库时间定义最多 15 分钟有效期，且不能越过当前 session 到期；这不是跨页数据库快照，不承诺并发增删时冻结全集。

公开 envelope 为最长 384 字节的 `ic1.` + 无 padding base64url；客户端只验证有界形状并透传，MAC/授权/期限核对仅在 IAM 内。请求格式非法返回既有 `400 iam.query.unsupported`；有 envelope 但签名、绑定或期限无效返回统一 `422 iam.argument.invalid`，不返回内部 ID 或失配原因。当前会话/权限本身无效仍按既有 401/403 关闭；数据库或 key 不可用为 503。UI 可让用户明确从首页刷新，不自动把旧 continuation 改成新权限意图。

游标中的安装归属来自同一事务的封存 bootstrap receipt，独立于主体的 `SubjectContext.InstallationID` 平台权限上下文。普通租户 User 的平台上下文仍为空，读取本安装事实不授予平台能力；未改全局 authenticateSession 或服务身份判定。

常驻 IAM 入口必须从 `MATRIX_IAM_CURSOR_KEY_FILE` 严格读取恰好 64 位小写 hex（32 字节），拒绝空白、多行、大写和错误长度。无随机进程内后备 key，不用 bearer 摘要或其他服务 key。多副本/重启共享同一安装的持久 key；更换 key 使旧游标失效，本片无双 key ring。仅离线恢复等不使用分页的工作流可不配置该 key，分页调用始终失败关闭。安装 owner 在最终 ABI 冻结后统一分发独立文件、挂载及签名拓扑，本片仅修改 IAM 入口与专属进程 fixture，不改旧发布 profile。

验收包括 100+1 个真实组及成员的无重复翻页、跨目录/Group/账号/会话、篡改/过期/错 key、主体或授权修订变化、撤销后重新授予、两个 IAM 进程和进程重启复用原 key；缺失或无效配置不得启动可服务的常驻入口。原 SQL/RLS seek 范围、当前权限失败关闭和历史 outbox 仍单独验证，不能被 MAC 测试替代。

### 组管理投影与命令

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

非 root 的 Group 附件完成证据使用封闭 `GROUP_BOUND` 目标状态，包含准确 ceiling Policy ID、发生时成员数量和按稳定关系/USER/边界证据计算的成员摘要。创建与撤销事实的 `authorityEvidenceDigest` 绑定原命令承诺和这份证据；它只证明发生时的封闭事务，不公开成员明细、不成为后续写入许可，也不替代每次成员变更对当前上限的重新验证。

## 持久化、求值与事务

`groups`、`group_memberships` 是 Account RLS 下的独立表。现有 `policy_attachments` 的内部主体列破坏性改名为通用 `target_id`，target kind 决定它引用 User、ServiceIdentity、Group 或后续 Role；不能增加并行 group attachment 表。实际旧 IAM 数据迁移必须保留所有直接附件 ID、修订、scope、installation、撤销时间和历史决定 bytes，未知/冲突关系失败关闭。

User session 的权威策略快照以有界 UNION 读取直接附件和当前成员关系可达的组附件。GROUP 来源必须同时满足：Account/User/Group 活跃且未删除、membership 未移除、attachment 未撤销、Policy ACTIVE、默认版本和 digest 一致。任何关系损坏、来源超过预算、membership 证据缺失或同 ID 冲突都拒绝整个决定；不能截断后面的 Deny。CurrentIdentity 用 `policySources` 展示直接/继承来源，User/Group 管理详情只返回各自直接附件。

公开写入先稳定锁定 Account。非 root Group 附件把 actor 与全部当前成员组成完整 USER 集合，membership 创建把 actor 与候选组成完整 USER 集合；两条路径都在一次查询中按稳定 USER ID 加锁，再依次锁定边界、Group、当前 membership、Policy 与 attachment。禁止先锁各自 actor 后再交叉等待对方 USER；数据库 deadlock 不能由事务重试掩盖。两条路径都在变更前后推进 Group 的内部授权代际，使较早 SERIALIZABLE 快照必须重试并重新读取闭包。User 边界移除或替换也会锁定该 User 当前活跃 Group 关系及带封存上限的附件；若仍有匹配关系依赖原上限则拒绝，必须先移除 membership 或撤销对应 Group 附件。SERIALIZABLE 冲突重试必须重新认证和读取整个来源快照；未知提交结果不按普通冲突盲重试。

创建 membership 继续拒绝 actor 把自己加入 Group，避免仅有成员管理动作时自助提权；平台 scope Policy 永不允许关联 Group。RootIdentity、已删除/停用 User、ServiceIdentity、带安装级附件的 USER、无边界 USER、不同边界 USER 和跨 Account User 在锁内再次拒绝。空组可由非 root 关联 tenant Policy，但该附件立即封存 actor 的 ceiling；以后加入的每个成员都必须精确匹配，而不是把“当时无成员”解释为无限上限。

User 删除沿 003 的 User principal 锁后终态移除其所有活跃 membership，避免 tombstone 留下继承路径。Group 删除与成员/附件 grant/revoke 使用同一锁序；失败、CAS 冲突或并发撤权时 Group、membership、attachment、decision evidence 和 outbox 均无部分变化。删除 Group/User 不转移或删除租户资源和已接受 Operation。

首片限制每页 100 项、每个 User 最多 100 个活跃 GroupMembership、一次决定最多 256 个直接+组 PolicyAttachment 和 4096 条语句。限制属于版本化产品契约并以超额失败关闭验证，不复制外部云固定配额；容量和 HA 的端到端 SLO 归 011 实测。

## 验收

真实 HTTP/PG18 至少创建两个 Account、同名 Group、每组多个 User：创建组→加成员→给组关联 PaaS tenant Policy→成员登录访问资源→移除成员后下一请求拒绝；直接附件仍可独立允许，组 Deny 必须压过直接 Allow。来源查询与保存决定分别证明 DIRECT/GROUP、准确 membership/attachment/version/digest，伪造、撤销或跨 Account 来源不能被 record/replay 接受。

负向矩阵覆盖跨 Account Group/User/Policy/membership/attachment ID，RootIdentity/ServiceIdentity/Role/Group 入组，self-add，停用或删除 User，installation Policy，错误/旧/最大 resourceVersion，重复/变体 requestId，101 个活跃组、257 个有效附件及坏记录位于有效 Allow 之后。委派矩阵还必须覆盖空组封存、准确同边界成员、无边界/不同边界/Root/平台绑定成员、成员边界移除或替换，以及 Root 创建但没有委派 ceiling 的 Group 附件。并发 add/remove、Group delete/add、attach/delete、attach/add-member、boundary/remove-member 与 actor grant revoke 必须以最终状态和事实数证明无双活、无部分写入、无已撤来源复活；还要构造 A 给含 B 的组关联策略、同时 B 把 A 加入该组的反向 USER 锁环，要求两个合法命令各提交一次且 `40P01` 计数为零。

当前 schema 的等值重放、带数据重启必须保持直接附件、历史 decision/Audit canonical bytes 和撤销状态。开发历史的升级起点按 [011 首版基线规则](./FEAT-IAM-011-acceptance.md#未发布阶段与首版基线) 选择，不要求本片从 schema 1 跑完整历史链；已做的固定旧 binary 实验是风险替换证据，不等于对全部开发版本承诺兼容。

独立 IAM/Audit/PaaS + dispatcher 门禁验证组授权可创建/读取租户资源且越租户、平台动作拒绝，移组不删除资源/Operation/outbox/Audit。控制台完成组目录、详情、成员和策略管理的鼠标闭环；键盘专项按用户优先级延期，不据此宣称已验收。签名发布与完整 Profile 仍由 011/安装 owner 证明，源码/SQL 门禁不能替代。

同完整 Profile 的签名门禁必须在保护备份前通过公开 API 创建 Group、准确 Membership 和 GROUP 策略附件，证明成员当前来源为该准确关系且能读取授权租户资源；故障升级自动回退、B 升级、显式回滚、指定备份恢复及外层引擎重启后逐次读取同一 Group/Membership/Attachment 并再次完成成员登录和业务授权。直属 USER 附件在备份前撤销且不得复活，GROUP 来源不得变成直属来源、跨 Account 归属或资源所有者。仅有表行、健康端点、Audit action 或通用平台生命周期通过均不能替代此路径。

## 实现与证据

2026-09-14，本分支在独立 PostgreSQL 18、1 CPU/768 MiB/PID 128 数据库容器上串行验证。Go 使用 `GOMAXPROCS=2`、`-p 2`（多真实数据库包的组合命令用 `-p 1`）；没有使用其他任务的数据库、服务或远端机器。

- 现有 `TestIAMPolicyAuthorityStoragePostgres` 通过最终 race 复验（56.32s，其中组继承子项 33.85s）：真实管理 HTTP、双 Account 同名组/同名成员、强制 RLS、100+1 活跃成员分页、跨目录/Group/账号/会话/篡改游标拒绝、撤销后重新授予仍不能沿用旧游标。直接/组来源与 Deny、并发关系/授权竞争、100/101 组和 256/257 来源预算继续通过。当前空库晚段 DDL 失败不暴露半套权威；带 Group/membership/attachment/decision/outbox 重放保持原值及终态。
- `TestIAMHTTPPostgresVerticalSlice` 通过 race（110.92s）：真实开通 101 个 Account 的 100+1 签名分页、100+ 用户目录、原始 ID 拒绝，以及原 root/租户生命周期、历史 producer proof、凭据 generation、会话与 grant/revoke/reset/recover 竞争；无 SQL/schema 变更，不新增恢复权限。
- `TestIndependentIAMAuditAndPaaSProcesses` 通过 race（42.94s）：两个 IAM 实例共享本任务独立 key 文件，跨副本继续 100+1 Group 页，重启后同一游标仍有效，跨账号/目录拒绝。保留实际受限登录、仅组授权创建应用/Operation、跨副本移组即时失权、Audit 中断后历史 outbox 投递及完整链；组创建事实也真实分页核对，不以第一页代替全部成功事实。
- 纯 authority/入口门禁通过：逐字节篡改、错 key/安装、有效但不同账号/主体/会话、权限/成员修订、期限边界、来源排序不影响结果、调用者清理原 key 不破坏 codec；空 key 无回退，文件严格拒绝宽松大小写/空白/多行/权限错误。
- 源码和内嵌产物稳定后的全仓 Go race/vet、架构检查、模块校验、生成一致性及 Linux amd64 构建通过。
- 前端 typecheck/lint/架构/20 组对比度、101 项测试通过；两次 2-worker 静态构建的 59 个内嵌文件一致。接口不解析游标、不与资源 ID 排序比较，拒绝原始 ID/换行/超长/重复 continuation；成员关系、目标 capability 和未知结果原意图边界继续保留。这是本地前端证据，不冒充独立前端 CI。

当前 Group 委派增量在本任务专属 PostgreSQL 18 新库完成本地验证：新增反向锁环在修复前确定触发一次 `40P01`，统一 USER-ID 锁序后 `TestIAMPolicyAttachmentChangePostgres` race 28.299s 通过；它同时覆盖空组封存、同 ceiling 成员、无边界/不同边界/Root/平台绑定攻击、成员边界变更阻断、Root 创建附件的受限撤销、创建与撤销的 `GROUP_BOUND` 证据，以及两个合法反向写入各一份关系/事实且无隐藏 deadlock。完整 `TestIAMPolicyAuthorityStoragePostgres` race 311.679s、`TestIAMHTTPPostgresVerticalSlice` race 127.828s、Audit HTTP race 4.505s 和独立 IAM 双副本/Audit/PaaS/dispatcher 进程 race 279.704s 继续通过。固定 IAM71 程序产生真实保留数据后升级至当前 IAM72 的 `TestIAMRetainedPredecessorProcessUpgrade` 最新 131.990s 通过，既有附件证据及 Audit 摘要保持，新增内部 ceiling 对保留行明确为 `NULL`。累计固定 `882b7820b1a225f1a0a8b95cb07ac139b8f3ab0b` 的 [Verification 38014293154](https://github.com/xiak/matrix/actions/runs/38014293154) 已核对精确 SHA，17 项全部 `completed/success`；这仍不是上述新增 Group 签名生命周期的运行证据，UX/UI 浏览器验收也由独立 owner 继续执行。

同一最终工作树通过全仓无缓存 `go test -race -p 2 ./...`（含 architecture）、`go vet -p 2 ./...`、模块校验、API 重新生成零差异及 Linux amd64/CGO 关闭的全仓构建；默认缺少外部 DSN 的 SKIP 不计真实运行证据。

当前准确 readiness、完整开发 Profile 与唯一滚动前驱由 [011](./FEAT-IAM-011-acceptance.md#未发布阶段与首版基线) 维护；本 FEAT 不复制会继续移动的版本数字。既有签名发布 profile 不会因源码 schema 数字变化自动获得升级许可，组合门禁也不把本地 SQL 可迁移解释为可发布。

本片交付组 HTTP/数据库/授权、同 ceiling 委派闭包、事件证据、签名分页和前端 domain/wire/repository；未新增第二套组页面。组目录、详情、表单及真实多成员鼠标闭环由既定 UX/UI owner 消费固定提交后完成。最终安装 key 分发/签名发布组合及 011 容量/HA 门禁仍需实施验证，本 FEAT 不因此标为 Accepted。

替换前已推送回滚点为 `0bd6dd9dd8166fe31c67edb8cd49cd523606a401`，精确 [Verification 34805149946](https://github.com/xiak/matrix/actions/runs/34805149946) 三项 success。签名分页固定实现为 `8117c54c112c842106d82fe934e460a280862549`；GitHub API 核实精确 [Verification 34808378047](https://github.com/xiak/matrix/actions/runs/34808378047) 的 Go、authority-process、node-process 全部 completed/success。本轮自有 PG18 容器、网络和合成测试数据卷已清理，不需要保留运行现场才能续作；未操作其他任务环境。
