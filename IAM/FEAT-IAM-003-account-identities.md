# FEAT-IAM-003：主账号、用户与凭据生命周期

- 状态：实现中；Account/RootIdentity/User 命名替换、现有生命周期、显式管理能力、用户详情/资料/安全删除已有真实候选验证；签名 Profile 仍未验收。
- 依赖：002。
- Owner：IAM 账号/身份与安装 primary 的接口协作。

## 需求

| ID | 行为 |
| --- | --- |
| IAM-ID-01 | Account 是现有 Organization 的统一名称，稳定 ID 和资源归属不变，不创建第二个 tenant |
| IAM-ID-02 | RootIdentity 指向原始 primary，不能转让、删除、入组或通过租户 API 获得平台权威 |
| IAM-ID-03 | 管理员为可撤销策略授权的 User；root 可恢复日常管理，日常交接不转让 root |
| IAM-ID-04 | 平台开通/查询/暂停/恢复账号，初始化原 root；不重新跑安装 bootstrap |
| IAM-ID-05 | User 创建、详情、分页、资料、停用/恢复/删除，初始无权限，允许不同账号同名 |
| IAM-ID-06 | `loginName@account-id-or-alias` 明确 realm；失败防枚举，认证后 scope 不可切换 |
| IAM-ID-07 | 改密/重置/恢复保持 generation 单调，forced 必撤其他临时会话，普通默认撤其他可选 |
| IAM-ID-08 | 删除/停用用户不改变已有资源、Operation 和审计归属；恢复不激活旧 session |
| IAM-ID-09 | 原 root 凭据恢复不换 owner、不授平台、不启用暂停账号；平台 primary 仍需离线限定能力 |

## 详细设计

复用现有 `login_index.account_owner` 所证明的原 primary、原 USER ID 与 credential generation，并迁移成显式、不可转让的 root relation；不把该旧索引布尔值继续当领域真相。Account 与 User 有独立 resourceVersion。不可撤销的 root 关系取代旧管理员 binding 保底，日常管理员附件可正常撤销。

### 对象与投影

`Account` 是唯一资源与安全归属聚合，直接包含稳定 `id`、展示名、状态、登录别名、`RootIdentity` 关系、资源版本和时间。`RootIdentity` 只投影原 primary 的稳定 `principalId` 与不可变登录名；它没有第二套凭据或主体 ID。`User` 是 Account 内可管理的日常 USER 投影，包含 `accountId`、稳定 `id`、登录名、展示名、状态、强制改密、资源版本和时间。服务主体不进入 User API。

RootIdentity 仍由底层 USER principal 承载认证，但不出现在日常 User 目录，也不能进入 User 状态、重置、删除、组或普通附件管理命令。Group 首片只接收 User；如果未来调用方提交 RootIdentity，服务端以稳定限制原因 `ROOT_IDENTITY_PROTECTED` 拒绝，不把 root 转换成普通成员。当前身份投影显式返回 `identityKind=ROOT_IDENTITY|USER`；不能由策略名称、是否管理员或 loginName 推断 root。管理员始终是获得管理策略附件的 User，不是第三种身份类型。

控制台不得从某个系统策略 ID、显示名、角色名或业务服务名推断管理能力。服务端返回 actor-relative `ActionCapability {action, resource, available, restrictionReason}`：当前身份投影承载集合/自身动作，User 与 Account 目录项承载准确目标动作。它只供界面解释和隐藏无效入口，不能缓存为 permit；提交时仍须重新认证、按当前策略鉴权并在同一事务锁内验证目标保护不变量。`AUTHORITY_REQUIRED`、强制改密、自保护、安装级权限保护、系统 Account 保护、目标停用及目标待改密使用封闭原因，不暴露策略名称。

能力集合是 API 契约而不是任意 action bag：当前身份必须完整返回账号目录读、账号创建、别名设置、用户目录读、用户创建和租户策略目录读；User 项必须返回详情读取、资料更新、删除、状态、密码、tenant/platform 附件创建和每个当前附件对应 scope 的撤销动作；Account 项必须返回状态和原 root 凭据恢复。缺项、额外项、重复项、错误资源种类或错误目标整体失败关闭。账号目录可读与账号创建是不同能力，不能因为能列出租户就显示开通入口。

腾讯云公开资料对产品作为受保护资源、产品作为调用者及控制台共用 Action 目录的证据和推演，由[访问管理来源分析](../doc/access-management/sources/tencent-cam-architecture-analysis.md#6-业务如何接入-cam)唯一维护。本 FEAT 只拥有 Matrix 当前 Account/User 管理契约，不复制供应商研究，也不把当前静态产品/系统策略集合写成最终接入模型；版本化产品 Profile 与服务角色由 008 拥有。

首个纵向替换只改变已有账号/用户闭环的当前契约，不抢先实现 Group、Role 或 AccessKey：

- 平台面：`GET|POST /v1/accounts`、`GET /v1/accounts/{accountId}`、`POST /v1/accounts/{accountId}:set-status`、`POST /v1/accounts/{accountId}:recover-root-credentials`。列表和详情返回 `AccountAccess`，把 Account 数据与该 actor 对该目标的状态/恢复能力分开。
- 当前账号面：`POST /v1/account:alias`；Account 只能由当前有效 session 推导，body/query 不接受 `accountId`。
- 用户面：`GET|POST /v1/users`、`GET /v1/users/{userId}`、`POST /v1/users/{userId}:update`、`POST /v1/users/{userId}:delete`、`POST /v1/users/{userId}:set-status`、`POST /v1/users/{userId}:reset-password`。详情返回与列表同形的 `UserAccess`；资料更新首片只允许显示名称，登录名与 Account 不可变。
- `GET /v1/auth/me` 返回 `Account`、当前 USER 投影、显式 identityKind、策略附件与完整当前能力集合；不再保留 `canCreateAccounts` 单一提示或任何角色枚举。

现有 `/v1/organizations*`、`/v1/organization:alias`、`/v1/principals*` 及对应 Organization/OrganizationAccount/Principal 管理 DTO 在切换提交中删除，不保留别名或双响应。Bootstrap、ServiceIdentity、AuthorizationDecision 和历史 Audit 中已经发布的 organization/tenant 字段属于历史或跨服务契约，不因管理面改名重编码；它们与新管理 DTO 的映射在单一 adapter 内完成。

当前 Action 目录使用 `iam.account.*` 与 `iam.user.*`；被替换的 `iam.organization.*`、`iam.principal.*` 只进入历史决定解码目录，不可用于新 Policy、请求或决定。现有 tenant lifecycle Audit bytes 不改写；新命令使用封闭的新事实名，不能在旧 action 上漂移含义。

删除 User 是明确的二步安全操作：目标必须先处于 `DISABLED`，再以最新 resourceVersion 删除；`TARGET_MUST_BE_DISABLED` 是稳定的能力限制原因。删除在 principal 行写入不可逆 `deleted_at` tombstone，保留 principal ID、Account、loginName、显示名、资源版本和审计关联；移除密码哈希，撤销全部会话/角色会话与未撤销附件。第一版永久保留 loginName 和 ID，不允许重用，避免历史人员混淆。返回的 `UserDeletion` 只含非敏感删除收据；已删除 User 不再出现在列表或详情。RootIdentity、当前 actor、拥有未撤销平台附件的主体和服务身份不进入普通 User 删除/重置流程。

Account 更新以 scope/account 锁序列化；User 安全变更在 principal 锁内再次检查平台附件并与并发授予互斥。根身份名与 Account alias 独立。系统 home Account 暂停在效果前拒绝，保证服务身份和平台恢复入口不会锁死。

账号写入锁序固定为 actor home Account → actor USER → target Account → target root USER → credential/session/attachment；同一 Account 内用户写入为 Account → actor USER → target USER → credential/session/attachment。平台附件 grant/revoke 与用户状态、重置、恢复和删除都服从相同 principal/attachment 顺序。任何 CAS、资格或审计校验失败时，账号、用户、凭据、session、附件、完成身份和 outbox 均不发生部分变化。

跨账号争用全局登录别名时，唯一保留记录决定归属；受控竞争门禁必须得到一个成功和一个明确冲突，失败方不改变原别名、资源版本或成功事实。Serializable 的 `40001` 与死锁 `40P01` 只允许重新执行完整事务，包括当前身份、权限和数据库时间读取；不能只重放最后一条 SQL 或复用旧 Allow。默认最多五次尝试，可重试失败之间采用有界抖动退避（首次 25–50ms，随后 50–100ms、100–200ms，单次上限 200ms），释放连接后等待并响应请求取消。成功、明确业务拒绝和最后一次失败不再等待；持续争用耗尽仍失败关闭，不能把未知结果伪装成 409，也不承诺任意负载下必然完成。

管理路由从旧 principal/organization 命名到目标 account/users 的替换与 schema、UI、生成契约原子收口；没有平行兼容别名。公开历史 Audit action 不重命名；新删除/身份命令定义新的封闭事实。

## 验收

两个 Account、各原 root/管理员 User/普通 User，同名登录、别名竞争、改密、退出、越租户 ID/cursor/body 攻击；平台与租户权限互不继承。错误版本、非原 root、并发状态/密码/平台授予无部分变更。旧 binary 状态升级、重放、重启和签名保留数据回滚通过，工作负载及 Audit 归属保持。

首个命名替换门禁还必须证明旧管理路径全部 404、严格解码拒绝旧 selector/字段、RootIdentity 不出现在 User 目录且不能被普通 User 命令命中、同名 User 只能经显式 realm 登录。能力门禁必须证明读/写拆分、self/installation/system/disabled/must-change/must-disable 限制，客户端拒绝缺失、额外、重复或错目标能力；增加产品、策略或角色名称不能要求通用 evaluator 或控制台新增名称分支。详情/资料/删除门禁还须证明跨 Account ID、RootIdentity、当前 actor、平台附件主体、错误版本和并发 status/update/delete 全部失败关闭；删除前失败或提交冲突时凭据、session、附件、tombstone 和 outbox 无部分变化，成功后旧密码/会话不能使用，登录名不能重建，Account 资源、Operation 与 Audit 归属不变。当前源码进程、OpenAPI、静态控制台和安装测试消费者必须在同一提交只使用新路由/DTO；残留扫描允许的旧词只限冻结的 Bootstrap、ServiceIdentity、历史决定/Audit 和迁移读取证据。

## 当前候选证据

固定回滚点 `79b37949300c686617694f52abff9a08626043e2` 已在独立 `feat/iam` 工作树完成当前管理面的破坏性替换：公开管理 DTO/路由只使用 Account、RootIdentity 和 User，旧 Organization/Principal 管理路由返回 404；Bootstrap、ServiceIdentity、AuthorizationDecision、旧 Audit 事实与 canonical bytes 保持冻结。数据库把旧 `login_index.account_owner` 迁移为强约束的 `account_roots`，并从封存 bootstrap receipt 为实际 9fd/a36 旧状态还原唯一 root；缺失或冲突关系失败关闭。该提交的 Verification `34599945505` 中 go、authority-process、node-process 三项均成功。

固定实现 `4201989773b6ca24829506b7e60dc3f9c4f20446` 以同一策略 evaluator 生成 action/resource 对，并以私有目标事实增加 self、installation、system account、disabled 和 must-change 限制；控制台只消费这些值，不读取 policy ID、policy name、role name 或业务 service name。API/OpenAPI、服务、受限 SQL、安装测试消费者和静态页面已原子切换到 `AccountAccess` 与完整能力集合。全仓 Go test/vet/race、API 生成一致性和架构测试通过；前端 type/lint/架构/20 组对比度、87 项测试及 59 个嵌入文件的 2-worker 静态导出一致性通过。独立 PostgreSQL 18.6、2 CPU/768 MiB 下，IAM HTTP 全量 race（67.932s）、策略存储 race、Audit 权威数据库（5.321s）及 IAM/Audit/PaaS 独立进程（35.740s）通过；真实用例覆盖账号读写能力分离、当前 User 自保护、停用/待改密目标、安装权威 User、系统 Account 和错误能力形状失败关闭。[Verification 34605172417](https://github.com/xiak/matrix/actions/runs/34605172417) 已核实精确 SHA，go、authority-process、node-process 全部 `completed/success`。

固定实现 `384d6d76b65498ed6b428ba9a2905ef67831b919` 在上述能力契约上增加 `GET /v1/users/{userId}`、显示名 CAS 更新和禁用后永久删除。API、OpenAPI、服务事务、受限 SQL、Audit 事实、静态控制台与既有测试 owner 已同步替换；IAM readiness 为 8、Audit readiness 为 5，PaaS 仍为 1。全仓 Go test/vet/race、API 生成稳定、Linux amd64 构建、前端 type/lint/架构/20 组对比度、90 项测试与 59 个嵌入文件一致性通过。独立 PostgreSQL 18.6、2 CPU/768 MiB 下，IAM HTTP 全量 race（66.814s）、Audit 权威数据库（5.757s）、Audit HTTP（2.950s）、实际 9fd 旧 IAM executable 保留升级（13.560s）、实际 a36 旧 IAM executable 保留升级（14.781s）及 IAM/Audit/PaaS + 双 dispatcher 五进程 race（35.749s）通过；后者实际证明删除成员前创建的应用、数据库、配额、Operation、outbox 与租户 Audit 归属不变。[Verification 34796922149](https://github.com/xiak/matrix/actions/runs/34796922149) 已核实精确 SHA，go、authority-process、node-process 全部 `completed/success`。

契约收口提交 `25202188f33ca5892880b72d6f6831e476c0bfb1` 将已实现的 `TARGET_MUST_BE_DISABLED` 纳入唯一 `CapabilityRestriction` 枚举 owner，并由同一值集生成校验器和 OpenAPI，补齐所有当前限制值的 schema 回归，未改变删除事务或运行语义。[Verification 34797635592](https://github.com/xiak/matrix/actions/runs/34797635592) 已核实精确 SHA，go、authority-process、node-process 全部 `completed/success`。因此本片最终可消费契约以 `25202188f33ca5892880b72d6f6831e476c0bfb1` 为准。

本任务独立浏览器以鼠标完成用户详情、显示名修改、禁用前隐藏删除、禁用后展示不可逆确认说明和删除后目录消失；未做已降优先级的键盘专项。最终破坏性确认没有在浏览器中代用户点击，而是在同一合成测试环境通过服务 API 执行：收据不含秘密，旧密码登录返回 401、详情不再可读、同名重建返回 409；数据库保留唯一 principal/login tombstone 和一条 `iam.user.deleted` 事实，密码、有效会话及未撤销附件均为零。浏览器使用的一次性本地进程和临时目录已清理，未占用共享或其他 Phase 服务。

上述用户资料/删除切片的源码 Profile 为 IAM8/Audit5/PaaS1；当时安装发布 Profile 保持最后已发布值并拒绝这个不匹配组合，未把 SQL 升级或源码进程门禁冒充签名发布、跨 profile 兼容或最终发布验收。最终发布 Profile 仍按 011 首版基线规则冻结。

### 别名竞争与事务退避

2026-09-14，时间条件候选的独立 CI 暴露原别名竞争门禁返回 503/200。PG 日志中同一 backend 在 36ms 内连续五次 `40001`，失败位于别名更新；原实现立即重试，在赢家提交前耗尽。修复只在现有完整事务重试拥有者增加有界抖动退避及等待取消，不增加 attempt、请求超时或数据库连接预算，不修改 API、SQL、schema/profile 和权限语义。

现有 service tests 使用虚拟时间证明可重试争用让出执行后重新观察到明确冲突；该用例与等待中取消用例先失败、修复后通过，race 重复 20 次通过。成功、业务冲突、禁止和 unavailable 不重试；配置上限 1/5/10 的耗尽仍返回可重试错误并由 HTTP 失败关闭，不伪造业务结果。虚拟时间只证明调度预算，不替代实际数据库验收。

专属受限 PG18（1 CPU、768 MiB、128 PIDs、64 连接）的原账号 HTTP 门禁扩为八轮不同账号争用同一个新别名：每轮严格一个 200、一个 409；失败方 Account/资源版本和别名保留记录不变，双方原 USER 与登录索引不变，赢家精确一条成功事实、失败方零条。原版本/requestId 重放返回 409，状态及成功事实数量不再改变；该 CAS 路由不承诺成功收据重放。测试连接只记录 `40001`/`40P01` 计数，不保留 SQL、参数或错误细节。聚焦门禁 70.43s（父门禁 73.33s、包 76.342s）通过，八轮中的七轮实际遇到 `40001` 并收敛，未放宽 503 为合格结果。

最终新增 USER/登录索引和 CAS 重放检查经完整串行真库回归通过：Audit 数据层 7.611s、Audit HTTP 3.083s、IAM integration race 233.732s、双 IAM/PaaS/Audit 独立进程 55.976s、PaaS 数据层 7.149s；保留现有时间策略、凭据并发、历史 proof、受限 runtime 身份和多租户隔离门禁。全仓 Go race/vet、模块校验、API 稳定生成及 Linux amd64 构建通过；默认跳过数据库的测试不替代前述真实门禁。未运行未发布 schema 全历史链，也不据此宣称容量 SLO、签名安装或新 UI 验收。全部本地测试客户端结束后，任务专属 PG 容器、网络和合成数据卷已按精确 ID/标签清理。

固定 `581ce7584527470e1fe377040eb98ffe161e83de` 的 [Verification 34833032924](https://github.com/xiak/matrix/actions/runs/34833032924) 已核实精确 SHA，Go/authority-process/node-process 全部 completed/success；该固定对象包含 005 的时间条件及本次事务竞争修复，不包含计划中的字符串条件。
