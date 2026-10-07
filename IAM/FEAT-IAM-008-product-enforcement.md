# FEAT-IAM-008：业务接入、服务角色与 ABAC

- 状态：实施中；版本化产品 Profile、PaaS/managedservice 的真实 PEP、请求与决定绑定及当前资源/Operation/outbox 租户隔离已有固定后端实现。服务受托已有账号同意关系、当前Account只读观察、managedservice真实资源绑定/解绑及服务会话发行/回执/当前PDP；累计固定`a464299b`已补严格服务来源的管理员目录/读取/代撤销并通过本地真实PG18、累计Role管理、独立多进程及14项独立CI。实例目录批量过滤、可信标签读写及Audit目录已有固定门禁。AccessKey产品消费已覆盖不可变资源图创建、实例读取、Deployment控制、Application声明标签和租户Audit读取，并累计到`91649497`的完整独立CI；其他签名动作、可信边缘、LIVE UI和最终发布组合仍未完成，整体未验收。
- 依赖：001、005、006。
- Owner：IAM Profile/Role，PaaS/managedservice/Audit 各自的真实资源与 PEP。

## 需求

| ID | 行为 |
| --- | --- |
| IAM-PEP-01 | 产品以版本化 Profile 声明 Action、resource kinds、scope、granularity、conditions、list/batch |
| IAM-PEP-02 | PEP 从当前业务对象和有效身份构造请求；caller 不能伪造 owner、tag、Action、原始主体 |
| IAM-PEP-03 | list/filter/cursor 与批量资源检查始终受当前 scope 和权限约束 |
| IAM-PEP-04 | create collection→最终 ID、Operation、配置、配额和 outbox 有封闭映射 |
| IAM-SVC-01 | 服务主体与目标 Account 中的 Role/同意分离；purpose/installation 不授任意租户权 |
| IAM-SVC-02 | 服务角色模板、服务相关角色、PassRole、工作负载绑定与短期凭据 |
| IAM-TAG-01 | 可信资源标签/请求标签 ABAC，创建时强制标签和标签写入本身授权 |
| IAM-TAG-02 | 共享 tag 更新与授权状态一致；不能自己改标签绕过资源权限 |

## 详细设计

Profile 的代码/签名发行由产品 owner 管理，IAM 只注册校验与求值。请求绑定精确 profileRevision/digest；缺版本/不兼容组合关闭。当前源码Profile与集合/实例的闭合声明由001拥有；集合整体准入与逐实例批量过滤是分别声明的能力，未声明批量能力的 PEP 不能获得细粒度 Permit。被授权资源和成功事实资源种类分别声明，父实例→子资源与集合→新资源均不能用结果ID反向扩大permit。

产品接入和服务受托是两条独立协议。前者登记产品动作、资源、粒度和可信属性，并在业务 PEP 执行当前决定；后者登记可验证的服务主体与角色模板，经账号显式授权后承担目标角色、取得短期会话。不能把“产品已接入”或“服务认证成功”解释为已取得客户资源权限。

通用 IAM 求值器和控制台不得按产品名称、服务名称、角色名称或六种旧角色枚举内置授权分支。产品新增动作/模板是相应 owner 的版本化声明；新增产品必须通过登记与契约验证，不修改求值算法或逐个扩展前端角色菜单。预置策略、服务角色模板可由可信产品发布，但内容、默认版本与同意关系分别管理；显示名改动不影响授权，新版本不能隐式扩张既有账号的授权。当前静态 Action catalog 是 001 的过渡实现，不是最终可扩展接入完成。

PaaS 先覆盖 Application、Configuration/Revision、Deployment、Operation；managedservice 覆盖 Offering/Region/Entitlement/Installation；Audit 保持 chain/query scope。平台主机/终端由既有 Phase owner 消费确认的公共契约，本任务不重做主机实现。

ServiceRoleTemplate 定义注册服务主体、用途、允许权限和生命周期；租户实例经明确同意创建。PassRole 必须同时验证 actor、目标 role、目标工作负载和 service purpose。关联资源存在时拒绝或按明确异步删除流程，不能删角色留下无限可用凭据。

标签来自产品数据库和已验证新建命令，IAM 自供时间/身份/session 属性。禁止通用 caller attributes map。授权决定与业务 payload 区别明确：IAM 不声称证明具体部署镜像、配置值等业务真实性，源事务/outbox 负责。

## 当前实现边界

本节只归纳本 FEAT 的实现状态；Profile 注册与策略编译的详细证据仍分别由 001、005 拥有，RoleSession 的详细证据由 006 拥有。

| 需求 | 当前状态 | 权威边界 |
| --- | --- | --- |
| IAM-PEP-01 | 已实现当前后端主体并由累计 CI 覆盖 | 固定 `1dc1079c` 已将 IAM、PaaS、managedservice、Audit、installation 的版本化 Profile、完整摘要、当前头及请求/决定绑定接入唯一契约并通过独立 CI。后继 PaaS Profile revision 3 增加 `request.source-ip`，固定 `94cc8d7f` 已有真实 PG18、独立进程及唯一前驱保留数据证据；该代码位于累计固定 `91649497` 的祖先链，并由其完整独立 CI 覆盖。当前仍是源码/开发 readiness，不是签名发布组合。 |
| IAM-PEP-02 | PaaS apphosting 与 managedservice 已实现 | HTTP owner 从真实 path/body 和实际 `RemoteAddr` 构造 Action、资源、集合用途及可信网络上下文；账号和主体来自当前 IAM 凭据。IAM 决定必须逐字段绑定原请求，业务事务再按数据库所属账号取数，query/body/header 不能选择另一账号。 |
| IAM-PEP-03 | 首个无游标目录已固定并由累计 CI 覆盖，发布未完成 | 固定`a7f2e83b`使managedservice先以`COLLECTION_LIST`完成目录准入，再从受信本地catalog取得真实候选，按ID排序后通过一次1–50项批量PDP逐实例过滤。两个账号同名/同 ID/key、伪造 tenant/cursor/after、错序/遗漏/替换决定、跨账号实例、撤权后下一请求及ROLE全拒绝已有行为或真实进程门禁；该代码位于累计固定`91649497`的祖先链并由其完整独立CI覆盖。租户资源cursor、其他产品目录和最终发布组合仍未完成。 |
| IAM-PEP-04 | 当前应用托管与 managedservice 路径已实现 | Application、Configuration、Revision、QuotaEntitlement、ServiceInstallation 的创建由封闭集合请求开始，最终资源、Operation 和 outbox 由同一业务事务建立；IAM 原决定只证明集合准入，不证明 caller 填写的最终 ID 或 payload。真实双账号门禁核对配额、Operation、幂等、拒绝无部分效果及 Audit 关联。 |
| IAM-SVC-01/02 | 最小产品运行闭环及管理员管理已固定并通过累计 CI，发布未完成 | ServiceIdentity自身仍不获得目标Account权限；只有不可变模板、精确系统策略上限、当前Account同意和真实workload binding同时有效时，IAM才发行目标Account的60秒RoleSession。managedservice用该临时身份经唯一PDP读取实际`ServiceInstallation`后立即自退出；服务home Account与目标Account分开保存，SERVICE与USER来源严格互斥。当前AccountAdministrator能以独立权限查询和终止服务会话，只有服务Role绑定管理权限的USER、服务凭据及ROLE自身均不能获得管理能力。真实PG18纵向、累计Role管理及209.46秒独立进程组合覆盖双副本list/read/revoke、解绑后历史观察、等值重放、跨Account拒绝与唯一Audit事实；累计固定`a464299b`及其14项成功的独立CI覆盖该后端闭环。最终签名发布组合和LIVE UI仍未完成。 |
| IAM-TAG-01/02 | Application创建、读取及标签写入已有固定实现，发布未完成 | PaaS Application创建从真实body构造`request.tag/environment`；读取及写入从PaaS数据库预读同一Application构造`resource.tag/environment`，设置/删除再绑定准确`request.tag/environment`。决定、资源版本、SQL效果、Operation及Audit证据精确关联，标签写入的并发CAS与跨Account隔离已有真实门禁。Role/User标签仍只是元数据；其他资源标签、LIVE UI和签名发布组合尚未实现。 |

`app/service/paas/internal/managedservice/port/security.go` 原 action→resource switch 是该产品适配器的封闭边界，不是通用求值器按产品名称分叉，但它重复了 release-owned Profile。本轮候选已删除这份重复映射：port 直接使用 IAM Action/ResourceKind 类型，通过 `NewAuthorizationRequest` 和 managedservice 当前 Profile 的完整引用/calling service 核对形状；IAM HTTP adapter不再执行第二次字符串翻译。七种合法集合/实例形状及其他产品、错资源、错集合用途/ID攻击的聚焦测试通过；全仓默认 race/vet、architecture、模块校验和 Linux amd64 构建通过，并由累计`a464299b`的独立CI覆盖。后继产品适配器同样应消费自己编译进发布物且已由 IAM Profile 摘要认证的声明，通用 IAM 求值器仍只解释统一 Profile/Policy 语义。

同片后继把 apphosting 的 PaaS→IAM 资源词汇翻译收敛到 port 的单一构造器，HTTP adapter不再维护第二份资源 switch，Action/资源形状、当前 Profile 引用、PAAS calling service 和可信 source IP 一次绑定。apphosting 仍保留14个路由动作的显式 PEP 子集：同一PaaS Profile中的平台主机/安装动作不能因“属于PaaS”进入应用托管。14条合法形状及同产品错PEP、其他产品、错资源/集合/source IP攻击的聚焦测试通过；同一全仓默认 race/vet、architecture、模块校验和 Linux amd64 构建通过，并由累计固定`a464299b`的独立CI覆盖。

## 当前纵向切片：账号同意的服务相关角色

下一片先完成一个真实产品、一个只读业务动作的完整协议，再扩展动作族；不先铺开任意跨账号委派或动态插件市场。

当前候选把 `ServiceRoleTemplateSpec` 的产品、服务 purpose、显示元数据、精确不可变 `PolicyVersion`、每种 workload 的 bind/unbind Action 与最大发行时长纳入域分隔摘要；`ServiceRoleTemplate` 的 ACTIVE/RETIRED 只控制后继同意/发行，不改写历史。workload 声明在编码前排序且拒绝重复，Action 必须来自同一产品、同一调用服务、同一资源种类及当前 Profile 的 USER 实例能力，通用 IAM 不按产品名称推导。严格解码拒绝 Account、Role、installation、service principal 等 selector 和重复字段。

当前后端登记一个 release-owned `managedservice.installation-reader` 模板及其精确 `system.managedservice-installation-reader` 策略版本。策略只允许 `managedservice.service-installation.read`，资源上限只覆盖目标 Account 内的 `SERVICE_INSTALLATION`；模板只接受 `PAAS` purpose、该 workload 的精确 bind/unbind Action 和最长十五分钟会话。模板查询必须提交完整 `{id,version,contentDigest}`，不能仅按 ID 跟随当前头。managedservice 当前 Profile 只为安装读取动作增加 ROLE；其他动作仍只允许 USER，ServiceIdentity 也不能直接求值。既有管理员、开发者和查看者策略未因新主体能力隐式扩权，服务模板使用独立的系统策略上限。

公共契约现有 `Role.management=SERVICE_LINKED`、非秘密 `ServicePrincipalReference`、`ServiceLinkedRole`、`WorkloadRoleBinding` 及聚合观察 `ServiceLinkedRoleAccess`。binding 只允许创建时 ACTIVE/revision 1及一次终态 REVOKED/revision 2，精确绑定 Account、Role、template版本/摘要和 workload `{kind,id}`；关系同时保留服务主体的物理 home Account、installation、principal、purpose 及不可变 PolicyVersion 上限。普通客户 Role 目录/详情拒绝 `SERVICE_LINKED`，现有更新、trust、附件和 boundary 入口均不能修改系统关系。PostgreSQL 的强制 RLS、不可变触发器、服务相关 Role 专属索引和受限 SECURITY DEFINER 入口共同承载这些不变量。

当前动作目录已将 IAM Profile 推进到 revision 8，新增模板/服务相关角色只读、创建服务相关Role、`iam.role.pass`及binding撤销六项能力；managedservice Profile revision 3只新增实际`SERVICE_INSTALLATION`的bind/unbind。八项能力全部要求当前USER，IAM六项还明确只接受LOGIN_SESSION；ROLE只能继续执行模板允许的安装读取，SERVICE_ACCOUNT不能直接求值。新`system.service-role-administrator`精确包含这八项且不自动附着，既有`AccountAdministrator`、`PaaSDeveloper`、`PaaSViewer`和安装读取策略均未扩权；具备原Policy附件管理权的管理员必须显式委派该职责。历史IAM revision 7、managedservice revision 1/2保持原能力。新增租户Audit事实`iam.service-linked-role.created`及`iam.workload-role-binding.created/revoked`只接受USER演员、准确目标和原IAM决定，不能由SYSTEM/服务主体或安装链伪造；三项事实同时进入Audit数据库的封闭append/query目录，Audit readiness推进到29，目录门禁先以公开Go契约验证fixture再证明SQL接受同一事件，避免API与存储目录静默漂移。聚焦API/Audit/authority/architecture race、生成、vet及负向门禁已本地通过；本任务独立限额PostgreSQL 18的`TestIAMPolicyAuthorityStoragePostgres`以225.31秒通过干净迁移原子性、Profile/系统策略注册重放、权限存储、附件并发和历史证据门禁；CI同形Audit存储、保留tenant链升级和HTTP门禁分别以16.52秒和4.67秒在新数据库通过。固定`2e2476ad`的独立CI已证明Go、Audit存储、Role及其余安全lane通过，但总体因保留数据门禁把当前IAM Profile头写死为历史revision 7而失败；该失败不回填为通过。当前门禁改为从唯一源码Profile取得精确revision、canonical document及digest，同时保留原前驱声明字节，并已在独立PostgreSQL 18上通过真实前驱升级158.97秒及真实备份恢复41.33秒；修复后的当前实现由累计`a464299b`的[Verification 36779942782](https://github.com/xiak/matrix/actions/runs/36779942782)再次覆盖，14项全部成功。该固定阶段只证明同意关系及内部创建，不包含后继服务承担；后继边界由006和下文继续拥有。

`GET /v1/service-role-templates` 已接到当前 USER 的真实账号 PDP：服务端只接受无 query/body 的 GET 和 LOGIN_SESSION，以 `iam.service-role-template.list` 对 IAM 推导的当前 Account 实例求值，随后才返回完整有序模板。原 `AccountAdministrator` 默认拒绝，显式附加 `system.service-role-administrator` 后允许，撤销附件后的下一次请求立即拒绝；ServiceIdentity 不能替代 USER。

`GET /v1/service-linked-roles` 与 `GET /v1/service-linked-roles/{roleId}` 现为当前 Account 的只读候选。列表只返回不可变关系、历史 binding 数量和当前 ACTIVE 数量；详情按 binding ID 返回包含 REVOKED 终态的完整历史页，不把所有 binding 重复塞入列表，也不把模板 ACTIVE 当成账号同意。`after` 是绑定当前安装、Account、USER Session、实时权限来源、Action 及详情 Role ID 的签名游标，原始 Role/binding ID 不能冒充游标。Account 只能由当前有效 USER 身份推导；query/body/header selector、ServiceIdentity 冒充 USER、跨 Account Role ID、普通 Role API 和撤权后的下一次读取均失败关闭。数据库入口重新核对当前 Account/USER/decision，受限 API 登录只能执行专用函数而不能直接读取关系表。

本轮本地候选新增 `POST /v1/internal/workload-role-bindings`。它只接受当前 PaaS ServiceIdentity 与当前 USER 两份凭据及 `{template, authorization}`，不接受 Account、Role、installation、principal 或 purpose selector。IAM 在一个 Serializable 事务中重新验证服务凭据、当前 USER session/MFA、实际 managedservice bind Action、`iam.service-linked-role.create` 和精确 Role 的 `iam.role.pass`，再创建或确认服务相关 Role、空客户 trust、不可变模板关系、workload binding 与两个 Audit outbox 事实。Role 与 trust 由 Account、模板和物理服务主体域分隔派生；binding 由 Account、模板、workload 和账号级 command identity 派生。actor 是不可变授权证据但不构成命令命名空间：等值重放返回原结果，同一 Account/request 被另一 actor 或变体复用时冲突，同 workload 的第二个活跃绑定也冲突。普通 Role 目录隐藏该 Role，详情、普通附件、边界和承担入口失败关闭。

上述候选已在本任务独占 PostgreSQL 18 中以现有 `TestIAMRoleAndManagementReferencesPostgres/roles` race 门禁真实执行：默认 AccountAdministrator 被拒绝并保留 denied decision，显式委派后创建和等值重放成功，错误 service purpose、服务凭据冒充 USER、同 request 变更 workload、重复 workload、跨 Account 同名同 ID、撤权即时生效、历史表更新/删除/截断以及 schema/bootstrap 等值重放均得到验证。原子性门禁还注入 Audit outbox 失败并证明 Role/关系/binding/决定/outbox 均无部分效果；两个管理员并发复用账号级 request、同 workload 不同 request 的竞争都只允许一个成功，失败意图无残留效果。实现通过服务主体→USER/session 的统一前置锁序消除了真实门禁曾发现的锁升级死锁；修复后的首次 PG18 race 通过用时 59.53 秒，约束补强后的最终聚焦门禁为 90.79 秒，且测试结束会拒绝任何被重试隐藏的 PostgreSQL deadlock。readiness 逐项验证强制 RLS、策略角色/表达式、template/relation/binding 的唯一约束与外键、索引列/谓词、触发器、私有 snapshot 和受限写函数授权，并以实际漂移逐项证明失败关闭；受限 API 登录不能直接读取私有表。

同一候选在七个独立 PG18 数据库串行通过完整 Role/STS/管理引用 race 回归 371.52 秒，覆盖既有 USER RoleSession、角色发现、管理、授权、安全及私有引用；最终约束树又以上述聚焦门禁验证新增漂移攻击。固定 IAM45 executable 产生真实保留数据后升级至源码 IAM54、双次迁移/等值 bootstrap/重启最终通过 158.77 秒。独立 IAM 双实例、Audit、PaaS 与双 dispatcher 的真实进程门禁最终通过 226.41 秒，保留受限数据库身份、readiness 实值、双账号资源/Operation/outbox、跨副本撤权和历史 Audit 关联。最终扫描只对已完整校验的 PaaS Operation 摘要/时间字段排除随机六位子串碰撞，完整六位值、任意文本中的验证码和所有长凭据仍失败关闭。全仓 `go test -race -p 2 ./...`、`go vet -p 2 ./...`、模块校验、全部 API 生成稳定、architecture race 及 Linux amd64 全仓构建通过。后继只读观察在本任务两个独占 PG18 数据库分别通过 HTTP/SQL 门禁 82.43 秒及 race 门禁 120.32 秒，覆盖空目录、实时计数、详情历史、双 Account、并发后计数、越权 selector/Role ID、撤权即时生效、受限函数、RLS/ACL/index/readiness 漂移；第三个独占 PG18 数据库以 207.67 秒通过当前迁移原子失败、apply-twice、等值 bootstrap 和策略存储回归。API/IAM/architecture 聚焦回归、全仓 race/vet、模块校验、生成稳定及 Linux amd64 构建通过。产品尚未发布，本片替换同一未发布 `000016_service_roles` 并保持 IAM54，readiness 按最终函数/索引形状失败关闭；这不是旧 IAM54 executable 的兼容声明，也不增加历史草稿升级矩阵。观察实现已固定推送为 `cb62ed2f6c307f5a50aa27480f89c8c58cf081ee`；其 [Verification 36677509802](https://github.com/xiak/matrix/actions/runs/36677509802) 当时仍为 queued，不能提前记为独立 CI 通过。该固定观察实现不含服务会话；后继IAM55/Audit30候选已实现内部发行/回执及当前Role PDP，但真实managedservice业务读取仍未实现，所以IAM-SVC-01/02仍不得标为完成；源码候选也不改变已发布installation profile或产生跨profile兼容许可。

模板目录与账号同意必须在API/UI上分层：`ServiceRoleTemplate.status`只表示平台发布的模板版本能否用于后继同意/发行，不能显示成目标Account已授权；`ServiceLinkedRole`和`WorkloadRoleBinding.status`才是该Account的同意及资源绑定状态。首个northbound目录仍由IAM向当前USER提供只读、非秘密模板/关系观察，实际绑定/解绑由managedservice面向真实`ServiceInstallation`的产品入口编排，浏览器不直接调用内部双凭据或服务会话入口。UI可以展示template ID/version/digest、product/purpose、workload kind、service principal、固定PolicyVersion和目标资源语义，但在bind/unbind/assume契约及真实后端固定前必须保持预览/禁用，不以模板ACTIVE渲染“已授权”。

managedservice 的首个 northbound bind 候选使用 `POST /managed-services/v1/service-installations/{installationId}/service-role-bindings`。公开 body 只有精确 `template {id,version,contentDigest}`，`Idempotency-Key` 经产品域分隔摘要生成账号级稳定 command identity；Account、Role、installation、service principal、purpose 和产品 AuthorizationRequest 均不能从 body/query/header 选择。产品先以当前 USER 对 path 中实际安装执行 `managedservice.service-installation.service-role.bind`，再由受限数据库读取证明该资源属于 IAM 决定推导的 Account；只有资源存在后，PaaS adapter 才以自身 ServiceIdentity 和同一 USER bearer 调用 IAM 内部入口。返回 `ServiceRoleBindingReceipt` 仅包含 workload、Role/binding ID、精确模板、ACTIVE 版本和创建时间；完整关系及历史仍由 IAM 目录拥有，不复制第二个权威模型。

该候选的 API、port、adapter、usecase 和 HTTP 聚焦 race 已通过。现有独立五进程门禁在本任务唯一标签的 PostgreSQL 18（2 CPU、1536 MiB、PIDs 256）上以 220.41 秒通过：两个 Account 使用同名安装和同一幂等键仍生成不同 Role/binding；默认管理员在显式委派前拒绝，等值重放返回原身份，同 command 变更模板、第二 command 绑定同一 workload、query/body selector、跨 Account workload/Role ID及撤权后的下一请求均失败关闭；成功结果由 IAM 列表/详情反查并各产生一次 `iam.service-linked-role.created` 与 `iam.workload-role-binding.created`，原 actor/decision/tenant链保持。第一次运行只发现跨 Account Role 在 PDP 层按现有契约返回 403 而测试误期望存储层404，未发生越权；门禁改为准确断言403后在全新数据库重跑通过。所有本轮容器、网络和卷在标签及唯一占用核对后已删除。该固定bind路径由下述后继产品消费候选继续使用；UI写操作仍须等待该后继固定及UI自身验收。

公开 unbind 候选使用 `DELETE /managed-services/v1/service-installations/{installationId}/service-role-bindings/{bindingId}`，要求 `Idempotency-Key`，body 只有固定当前 `resourceVersion: 1`。产品先对 path 中真实安装执行 unbind PEP 并确认当前 Account 归属，IAM 再从 binding 反查并锁定 Account、Role、template、workload 与物理服务主体，重新评估实际产品 unbind、`iam.workload-role-binding.revoke` 和 `iam.role.pass` 后，原子写入 `REVOKED` revision 2、Role `security_generation+1` 和单一 Audit outbox 事实。模板退役仍允许撤销，但 schema/bootstrap 重放不得重新激活模板。返回 `ServiceRoleUnbindingReceipt` 只有非秘密终态；回包不确定时必须以原请求和原幂等键重试，等值重放仍要求当前权限，或通过 IAM 当前 Account 关系详情读取历史，不能把旧 receipt 缓存成 permit。

该候选已在本任务独占 PostgreSQL 18 上通过 68.40 秒 Role race 门禁，覆盖错误账号/服务/USER/workload/Action、Audit 写失败整单回滚、退役模板后撤销、等值重放、变体/新意图冲突、Role 安全代际、不可变事实和迁移重放；同一独立 IAM 双实例、Audit、PaaS 与双 dispatcher 门禁以 204.25 秒通过公开 DELETE、两个 Account 同名安装、跨账号 binding ID、selector、终态目录、Audit 链及撤权后下一请求拒绝。聚焦 API/IAM/PaaS/architecture、生成稳定已通过；独立 CI 和全仓收口尚未完成，因此仍不得开放 LIVE UI 或把整个服务承担闭环标为验收。

服务承担使用`POST /v1/internal/service-role-sessions`和按原request的非秘密查询入口。IAM从当前PaaS服务凭据、封存installation、精确binding、目标Role、模板/PolicyVersion上限和workload推导全部范围；同一服务home Account可以在另一个目标Account的明确binding下承担，但不能用自身Account或installation覆盖目标归属。内部发行、等值重放、当前单PDP、错误producer/workload、跨Account lineage、Audit事实、解绑即时失效和发行/解绑并发已在独立PG18通过；完整数据、锁序及本地证据归[006的服务来源RoleSession](./FEAT-IAM-006-roles-and-sts.md#服务来源-rolesession与-008-协作)。这一入口仍是服务间能力，不是浏览器API。

当前后继候选在managedservice的公开bind成功或等值确认后，用binding ID和本次公开请求ID派生新的承担及业务读取意图，固定申请60秒会话。PaaS长期服务凭据只作为生产者认证，RoleSession秘密只在IAM HTTP adapter拥有，并仅作为`/v1/authorize`的subject carrier；use case只得到非秘密tenant/binding/Role/session/service/decision关联。adapter逐字段核对当前managedservice Profile、安装读取Action、真实path资源、ROLE主体、服务来源及目标Account；随后业务use case必须用该决定推导的Account开启第二个只读事务，读取同一`ServiceInstallation`并与USER已授权读取的语义对象一致，最后以准确ROLE bearer调用现有退出入口。业务层、公开回包、日志和Audit均不接触临时秘密，也没有第二PDP。

账号同意是已提交的跨服务事实，不能因后继读取或回包失败伪装成从未发生；失败时相同公开幂等键确认原binding，再以新的公开请求ID取得新的一次性会话重试。旧承担请求的等值重放不会返回秘密，不能被缓存为permit。adapter在授权拒绝、响应形状错误、读取失败及调用上下文取消时仍以最多6秒的独立有界上下文尝试自退出；若退出结果不确定则失败关闭，最长60秒自然到期。当前管理员候选提供另一条由USER独立授权的销毁路径，但不改变产品自退出义务。本片只证明一次真实只读资源消费，不声称长连接、后台任务或任意产品接入已经完成。

1. 产品 owner 在发布物中提供不可变、版本化的 `ServiceRoleTemplate`。模板至少绑定稳定 template ID、产品、服务 purpose、版本/摘要、允许的目标资源种类、可授权限上限和生命周期；它与普通 Policy 默认版本分离，不能由租户或请求方上传、改写或选择未登记版本。
2. 当前账号内持有明确管理 Action 的 USER 对模板执行显式同意，IAM 在同一事务中创建或确认一个 `SERVICE_LINKED` Role、模板版本关系、权限上限及不可变事实。显示名不参与安全身份；等值重放返回同一关系，变体冲突。普通角色 API 不能修改其 trust、扩大权限、换 template 或把它转换为 customer-managed Role。
3. 已认证 ServiceIdentity 只能以自身真实 installation、principal 和 purpose 请求承担目标账号中与其模板精确匹配的 Role。目标账号、Role 和 workload 必须来自已验证关系而不是通用 header/body selector；当前凭据失效、同意撤销、Role/账号停用、模板退役或 purpose 不匹配在下一次受保护请求失败关闭。
4. 短期身份继续进入唯一 Role 授权路径，不建立第二 PDP。公开业务主体必须保留 Role、临时会话和服务来源的稳定引用；既有 USER RoleSession 语义不得用伪 USER 承载服务来源。具体载体替换在 API/SQL 同片完成，旧别名或双实现不保留。
5. 首个消费者使用现有 managedservice 的只读实例动作证明目标账号授权：服务主体自身账号、installation 或“平台服务”标签均不产生目标账号权限。另一个账号、另一个 purpose、另一 workload、越过模板上限、撤销后旧凭据、probe 身份及伪造 selector 全部拒绝；允许路径读取的仍是业务数据库中目标账号资源。
6. 同意、发行、撤销和使用分别审计。IAM 只证明服务主体、模板、同意、Role 和临时身份；具体业务 payload 仍由产品事务/outbox 证明。删除有活跃 workload 的关系必须拒绝或走明确异步解绑，不能留下无限可用凭据。

本切片复用 006 的 Role、Role boundary、RoleSession、凭据发行和唯一策略求值器；只有服务来源、模板/同意及 workload 绑定构成新的安全边界。它不新增可由客户写入的产品目录、不把 ServiceIdentity 直接当租户管理员、不开放跨 installation 通配，也不把服务模板政策混入客户自定义 Policy。

### 对象与入口

| 对象 | 最小字段/关系 | 所有权与可变性 |
| --- | --- | --- |
| `ServiceRoleTemplate` | 稳定 template ID、product、service purpose、递增版本、完整摘要、精确系统 PolicyVersion、允许的 workload resource kinds、最大发行时长 | 产品发布物拥有；版本不可变，当前头由受信源码/发布注册。租户不能上传、改写或选择未登记版本 |
| `ServiceLinkedRole` | 复用 `Role`，`management=SERVICE_LINKED`；另存精确 template 版本/摘要、当前安装内的服务主体及权限上限 | 属于目标 Account；由显式同意创建。普通 Role 更新/trust/附件/boundary API只读或拒绝，不能转换为 `CUSTOMER` |
| `WorkloadRoleBinding` | binding ID、Account、Role、template 引用、精确 `{kind,id}` workload、状态、资源版本、创建/撤销时间 | 属于目标 Account；产品 PEP 证明真实 workload，IAM 原子保存同意关系。一个绑定只服务一个 workload，不以名称或 tag 关联 |
| `ServiceRoleSession` | 复用 Role 权限求值，但来源为精确 ServiceIdentity、binding、purpose、installation、服务凭据代际和短期会话 | IAM 发行；只显示一次秘密。当前 source/binding/Role/Account任一失效后下一请求拒绝，不缓存为 permit |

现有 USER `RoleSession` 历史和 Audit canonical 已有固定消费者，服务来源不能伪造 `sourceUserId`。公共 Role actor lineage 增加与 `sourceUserId` 严格二选一的 `sourceServicePrincipalId`，原USER编码因新增字段 `omitempty` 保持原字节；私有证据另保存 installation、purpose、binding、服务凭据代际和模板承诺。管理员目录必须准确区分 USER 与 SERVICE 来源，不能隐藏服务会话而使其不可撤销。若实现证明统一表会破坏现有锁序，可在同一 RoleSession owner内分开持久化生命周期，但公开身份、PDP和撤销语义仍只有一个，不保留两个求值器。

当前契约已把`RoleSession`、IAM `Subject`与Audit `ActorReference`的来源收敛为上述严格联合类型，并加入只含`{bindingId,durationSeconds?,requestId}`的封闭服务承担意图；Account、Role、installation、purpose、template、Policy及任意授权请求selector均由运行时解码和OpenAPI同时拒绝。既有USER RoleSession JSON与ROLE Audit canonical document/digest有精确字节回归。后继本地候选已经实现IAM发行事务、一次短期凭据、非秘密完成查询、当前单PDP、binding撤销即时失效、managedservice真实业务读取、服务来源自退出，以及管理员按严格USER/SERVICE来源查询和代撤销；详细事务与证据由006拥有。UI及发布组合仍未实现，不能据此开放LIVE写操作。

首个消费者由 managedservice product owner 暴露“给当前 ServiceInstallation 绑定/解绑服务角色”的业务入口，而不是让浏览器直接调用内部 IAM：

1. managedservice 以当前 USER bearer 对实际 `SERVICE_INSTALLATION` 做新增的精确 bind/unbind Action；从数据库确认该资源属于 IAM 推导的 Account。
2. PaaS 使用自己的 ServiceIdentity 和同一个 USER bearer 调用 IAM 的双凭据内部入口，提交规范化 product AuthorizationRequest、template 精确引用及 command ID。IAM 核对 calling service/profile，并在同一事务重新评估 workload Action、`iam.service-linked-role.create`（需要创建时）和精确 Role 的 `iam.role.pass`，不能只信任 caller 给出的 Allow 或 tenant。
3. IAM 等值重放返回同一 Role/binding；同 command 更换 template、workload、Role、产品请求或主体冲突。IAM 已提交而产品回包丢失时可按原 command查询非敏感完成，不重新选择当前模板或签发第二份关系。
4. 服务承担入口只接受当前 ServiceIdentity、binding ID、时长和 request ID；不接受 Account、Role、purpose、installation、Policy 或任意 AuthorizationRequest。IAM从binding反查全部目标并按当前状态发行短期凭据。完成查询只返回原会话身份/终态，不重放秘密。
5. 产品资源删除先进入不可新增效果的删除中状态，再撤销binding和全部来源会话，最后删除资源；撤销成功而业务删除失败保持安全关闭，可显式重新同意。不能先删资源再留下可发行会话的悬空binding。

建议入口形状如下；路径是当前服务契约而非要求拆出新的部署单元：

| 入口 | 调用凭据 | 作用 |
| --- | --- | --- |
| `GET /v1/service-role-templates` | 当前USER | 读取受信模板目录及精确版本，不返回安装服务秘密 |
| `GET /v1/service-linked-roles`、`/{roleId}` | 当前USER | 读取本Account的服务相关Role、template和binding摘要 |
| `POST /v1/internal/workload-role-bindings` | PaaS ServiceIdentity + 当前USER | 由真实产品PEP发起，原子创建/确认Role和binding |
| `DELETE /v1/internal/workload-role-bindings/{bindingId}` | PaaS ServiceIdentity + 当前USER | 重评实际workload与PassRole后撤销binding及其会话 |
| `POST /v1/internal/service-role-sessions` | 当前ServiceIdentity | 按binding承担Role并一次返回短期秘密 |
| `GET /v1/internal/service-role-sessions/by-request/{requestId}` | 当前ServiceIdentity | 仅查询本服务原意图的非敏感完成/终态 |

`iam.role.pass` 不授予业务资源权限；workload Action 也不授予承担任意Role。两者与模板、服务trust必须全部通过。模板升级默认不改变既有Role/binding；扩大权限必须以新版本重新同意，缩减或安全退役可让旧版本停止新发行但不改写历史事实。

事务锁序沿现有 Account→USER/当前Session→Role，再取得稳定binding；服务发行沿 Account→服务主体/凭据代际→Role→binding→会话配额。模板/PolicyVersion/历史决定不可变，只核对精确承诺。binding 撤销与发行使用同一 Role/binding锁序；任一顺序都不得在撤销后产生有效新会话，不能用数据库死锁重试隐藏两个都成功。Role/Account停用、模板退役、service credential撤销及binding撤销只终止后继访问和新发行，不删除租户业务资源或篡改已接受Operation/历史outbox。

新增租户事实分别命名为 `iam.service-linked-role.created`、`iam.workload-role-binding.created/revoked` 和服务来源的 session issued/revoked；不改变现有USER `iam.role-session.*` action含义。业务调用仍使用原产品事实，但ROLE actor lineage准确记录服务来源。Audit正文不含临时凭据、模板完整策略、服务长期凭据或私有代际证据。

本切片落地时只验证当前开发schema和一个确有数据意义的最近前驱；项目尚未发布，不建立从所有历史草稿逐版升级的组合矩阵。已固定的USER RoleSession/Audit历史字节、撤权不复活和真实产品资源数据仍必须保留；源码schema迁移通过不代表签名release profile可跨版本运行。

## 已固定纵向切片：实例目录批量过滤

本片只把 `managedservice.offering.read` 的真实发布目录从“集合全有或全无”推进为逐实例过滤，并建立可由其他产品复用的批量 PDP 契约；不同时引入资源标签、租户数据库分页或任意批量写入。managedservice Profile 以新 revision 仅为该 Action 声明 `instanceListBatch: true`，保留既有 revision 的原始声明与摘要。缺失该能力、只有 `INSTANCE`/`COLLECTION_LIST` 形状、Action 名称像 read/list，均不能调用批量入口。

`POST /v1/authorize:batch` 使用与单项授权相同的当前服务凭据和 USER/ROLE bearer，只接受 `AuthorizationBatchRequest{requests}`。`requests` 为 1–50 个完整 `AuthorizationRequest`，必须使用同一当前 Profile、Action、资源种类、`INSTANCE` 模式、空 collection usage、可信 network context 和 correlation ID；资源 ID 与 request ID 分别唯一，资源按 ID 严格升序。50项上限由当前合法最大长度请求及USER Allow响应均能留在原64KiB严格IAM传输内的契约测试约束，不为批量入口放宽全局body上限。请求没有 Account、主体、候选属性、标签或集合 selector。IAM 在一个事务中只认证一次调用服务和主体，固定同一事务时刻与同一当前权威快照，再对每个精确实例执行原唯一 PDP 并写入各自不可变决定和 `iam.authorization.decided` 事实；Deny 是正常逐项结果，任一权威/存储错误使整个批次回滚且不返回部分结果。

响应 `AuthorizationBatchDecision` 绑定本次已认证的 `tenantId`、严格主体、共同 `decidedAt`、Profile/Action/correlation 与按原顺序排列的完整决定。即使全部实例 Deny，envelope 也只返回调用者自己的已认证 Account/主体上下文，不能作为任一资源 permit；每个业务结果仍必须以其对应的 Allow 决定为准。PEP 逐项使用现有 `CheckAuthorizationDecisionForRequest` 后再消费，不能缓存批次、复用另一资源的 Allow，或从某一项 Allow 推导集合权限。

首个 PEP 的候选只能来自进程内受信、版本固定的 managedservice catalog，浏览器不能提交 ID 列表、分页位置或过滤表达式。当前最窄协议先保留原 `COLLECTION_LIST` 决定作为目录入口及已认证Account/主体上下文，再在业务读取真实目录后，对排序后的精确候选发出一次批量请求；所以一次列表请求固定为“一次集合准入 + 一次批量过滤”，不是单次IAM网络调用，也暂不支持只有实例权限而没有集合准入的目录发现。返回集合只保留准确 Allow 的目录项，全部 Deny 返回成功空目录，凭据无效仍为 401，IAM 不可用、遗漏/重复/乱序/错主体/错租户/错 Profile 的响应均为 503。详情读取继续走单实例授权，二者对同一实例必须得到相同当前结果。

本片验收覆盖：允许全部/部分/零项、显式 Deny 覆盖通配 Allow、USER 与 ROLE、另一 Account 同名策略、撤附件/边界/会话/binding 后下一请求、两个 IAM 副本、Profile 头漂移、批次中重复/变体/错序/超过预算、outbox写入失败整批回滚和重启不复活。真实 PG18 与独立 IAM/Audit/PaaS 进程必须证明每个列表请求只有一次集合决定和一次批量调用、每项唯一决定与 tenant chain；单项授权、AccessKey、安装 probe、服务承担、旧 Profile/Policy/Audit canonical 均保持。当前生产 catalog 只有一个 PostgreSQL offering，因此产品真实运行只能证明全Allow或全Deny；混合Allow/Deny由同一产品handler的多候选行为测试与IAM真实多资源事务证明，不虚构第二个已发布商品。该证据只完成首个无游标目录的批量过滤，不把租户资源 cursor、批量写、可信标签或最终发布组合标为完成。

2026-10-01本地候选已通过API生成器/JSON Schema、IAM HTTP/usecase及managedservice port/client/handler聚焦测试和相关包race。独占PG18的完整IAM HTTP race门禁94.029秒通过：两个精确实例共享同一事务时刻和已认证主体，每项分别保存不可变决定及Audit outbox；第二项故意复用决定ID触发末端失败时，整个批次留下零决定、零事实。当前Profile目录不可用时，内存owner也在第一项记录前整体失败关闭。

同一源码在另一独占PG18中以191.663秒通过独立双IAM、Audit、PaaS和双dispatcher进程门禁：两个Account各自的真实`/offerings`请求都只得到实际PostgreSQL商品，并准确保存一条集合准入和一条实例决定；服务来源ROLE对两个精确候选得到两条Deny及各自tenant Audit事实；查看者撤销附件后的下一次列表请求返回403。query中的tenant/cursor/after selector、平台凭据读取租户目录继续拒绝。固定IAM45实际程序产生账号、MFA、会话、恢复、撤权和历史证据后，当前IAM56的唯一最近前驱保留数据门禁以117.410秒通过双次迁移、等值bootstrap和重启；旧Profile/Policy、凭据及完成状态没有因当前managedservice revision 4复活或改写。全仓默认测试和architecture、`go vet -p 2`、模块校验、API生成前后diff摘要一致及Linux amd64全仓构建均通过。实现已固定推送为`a7f2e83bb69f059530a24151291f30469a977235`；其独立[Verification 36793770930](https://github.com/xiak/matrix/actions/runs/36793770930)尚未完成，不能写成独立CI或发布验收通过。

## 已固定纵向切片：可信创建请求标签

本片只把 PaaS Application 创建命令中的 `environment` 标签接入 ABAC，不同时开放既有资源标签、任意标签写入或通用 caller attributes。PaaS Profile revision 4为`paas.application.create`精确声明`request.tag/environment`、`STRING`和`CALLING_SERVICE_REQUEST_TAG`；产品PEP从已经过PaaS标签校验的完整创建body取值，只有Profile声明的键进入IAM，`team`等其他产品标签继续作为业务元数据保存。账号、主体、Action、Profile及目标集合仍来自当前凭据和封闭路由，浏览器不能提交AuthorizationRequest或另一个标签事实载体。

公开契约用排序的`requestTags[{key,value}]`保存受信事实：最多8项，键为1–63字节小写DNS label，值为1–128字节、不得带首尾Unicode空白或控制字符，键必须严格递增且唯一。`STRING_EQUALS`按一个条件内值OR、多个条件AND求值；缺失标签既不满足`STRING_EQUALS`，也不满足`STRING_NOT_EQUALS`，防止把“产品没有提供事实”解释为反向匹配。IAM决定必须逐项回显原标签，PEP在进入业务事务前核对决定，应用用例再把已绑定标签与最终写入的body标签核对；标签在授权后被替换不会产生资源或outbox。

持久化把当前决策契约推进到6、IAM开发schema推进到57：受限recorder只接受请求与决定完全相同、且由精确归档Profile声明的标签；v1–v5不能携带该字段，历史Audit producer按各自归档Profile读取合法v6事实，不借用当前Profile。独占PostgreSQL 18中，完整IAM HTTP纵向门禁以77.76秒通过；最终完整策略存储门禁以158.313秒通过真实Allow及策略/请求/决定的未声明键、错误运算符、重复键/值、空/null、额外字段、非字符串、Unicode控制字符、首尾空白和超长值攻击，失败均无部分decision/outbox效果。独立双IAM、Audit、PaaS及双dispatcher进程以223.74秒通过：真实PaaS body只把已声明`environment`带入v6决定，未声明`team`仍保存为业务元数据；数据库发布条件Deny后，`environment=restricted`的下一次真实创建返回403且资源不存在，同时保留既有账号、MFA、Role/服务承担、跨Account资源、Operation/outbox、失联回包、重启和Audit链回归。固定IAM45真实程序的唯一最近前驱保留数据门禁以118.84秒通过双迁移、等值bootstrap、当前重启和源码Profile r5演进测试；原会话、恢复资格、撤权、Policy/Profile字节及历史proof未复活或改写，不据此声称签名release跨profile兼容。聚焦API、求值器和PaaS PEP测试也已通过。实现已固定推送为`710c1557f48611179715671cac76ff4dfe447c1b`；其[Verification 36802729732](https://github.com/xiak/matrix/actions/runs/36802729732)在`authority-storage`真实发现Audit目录门禁仍以旧授权证据contract v5调用已经严格要求v6的当前recorder，因此该run不能标为通过。生产SQL没有接受降级证据；修复`49aaf21657ef71cb83b1b9b51d835f3600f6ce9d`只把五处现有Audit目录正向/负向fixture改为v6，不放宽recorder或保留v5旁路。其[Verification 36805096402](https://github.com/xiak/matrix/actions/runs/36805096402)已按精确SHA核实go及全部authority/node共14项job均completed/success。

本片不改变User、Group、Role、Policy等管理对象的元数据标签语义，也不提供标签管理权限。既有Application读取的resource-tag ABAC由下一节当前候选承载；后继标签更新仍必须使用独立Action，锁定真实资源及resourceVersion，在同一业务事务内重评当前标签、目标标签和写权限。UI可只读展示已发布Profile及PolicyVersion编译来源，但标签写入入口继续禁用。

## 当前纵向切片：既有 Application 资源标签读取

本片只把已持久化 Application 的 `environment` 标签接入 `paas.application.read`，不同时增加标签修改入口、把标签推广到其他资源，或让浏览器提交资源标签。PaaS Profile 下一修订只为该 Action 声明精确 `resource.tag/environment`、`STRING` 和 `CALLING_SERVICE_RESOURCE_TAG`；`team` 等未声明业务标签、User/Group/Role/Policy 元数据标签均不能成为该条件的事实。Policy 继续使用 `STRING_EQUALS` / `STRING_NOT_EQUALS`；缺失标签对二者都不匹配。

资源服务在读取标签前必须先取得当前凭据的最小账号上下文，但这个上下文不是授权结果。IAM 增加目的限定的内部 subject-resolution：调用方同时证明当前已登记服务凭据和 USER/ROLE bearer，并提交该服务的精确当前 Profile 引用；响应只返回由 IAM 推导的 Account、严格 Subject 与 Profile，不接受 Account、User、Role、Session、Action、资源或标签 selector，不返回 Policy、权限或可缓存 permit。RoleSession血缘严格二选一保留原USER或原服务主体；服务来源RoleSession还必须与调用服务身份完全匹配，不能在PaaS adapter或持久化时退化成USER。AccessKey不借用此入口，仍须走绑定原始HTTP请求的签名授权协议。

PaaS 用解析出的 Account 开启受RLS保护且数据库报告`transaction_read_only=on`的只读事务，按路径中的真实 Application ID读取当前资源及标签；资源不存在时仍对同一ID提交不带资源标签的实际授权请求，使无权限与不存在的响应顺序不因预读被反转。资源存在时，PEP只从完整、已校验的业务标签抽取Profile声明的键，构造严格排序的 `resourceTags`，再执行原唯一PDP。Allow之后必须在决定推导的同一Account内重新读取，并核对ID、resourceVersion和全部已声明标签与授权前快照一致后才能返回；漂移只能有界重试或失败关闭，不能使用旧Allow返回新标签状态。Deny、身份失效、IAM不可用、Profile漂移或第二次读取不一致均不返回资源。

当前授权证据会以新contract保存 `resourceTags`；请求与决定必须逐项相同，并由该决定绑定的归档Profile声明。旧contract不能携带新字段，历史Policy/Profile/Decision/Audit canonical不回填或重新解释。这个推进只使用当前开发schema和唯一滚动前驱，不建立未发布草稿的全版本兼容矩阵。

最低验收覆盖两个Account持有同ID但不同`environment`的Application、USER与ROLE、显式Deny、缺失标签、未声明`team`、伪造Profile/服务/主体、停用或撤权后的下一请求、跨Account路径、授权前后标签/resourceVersion竞争、IAM回包遗漏/替换标签和重启。真实PG18和独立IAM/Audit/PaaS进程必须证明标签只来自业务库、每次返回对应唯一当前决定、拒绝无业务副作用且tenant Audit链不串。标签写入/删除及其独立Action、CAS和Audit事实仍是后继切片；本片固定前UI继续禁用资源标签权限编辑。

当前本地候选把PaaS Profile推进到revision 5、授权决定契约推进到7、IAM开发schema推进到58。`POST /v1/internal/authorization-subject:resolve`只解析精确当前服务与USER/ROLE身份，不返回permit；PaaS随后在RLS只读事务内预读Application，以数据库中的`environment`构造请求，取得IAM决定后重读并核对ID、resourceVersion及全部已声明标签。缺失资源仍先对同一ID做无标签授权再返回404；caller header/body/query中的标签或Account selector不能进入该路径。

独占PostgreSQL 18上的完整IAM策略存储以`-race -p 1`用时237.069秒通过；PaaS存储门禁以5.840秒证明预读事务只读及Account RLS。独立双IAM/Audit/PaaS进程最终以`-race -p 1`用时245.500秒通过：两个Account持有同ID但分别为`production`/`staging`的Application，伪造另一Account header/query不能换标签或资源；同服务来源Role到达真实PDP并得到预期403而不是adapter 503；IAM决策落库事务中的确定性资源标签/resourceVersion变化使PaaS返回503且不泄露旧快照。IAM57真实前驱升级以`-race -p 1`用时131.412秒通过；实际旧二进制除账号、MFA、会话、设置和恢复事实外，还生成PaaS r4、contract6及`requestTags`决定，双迁移、等值bootstrap、当前重启后原Profile/Decision字节与Audit producer proof不变，不增加更早开发schema矩阵。聚焦及全仓race、架构、vet、模块校验、两次API生成摘要一致和Linux amd64构建通过。固定提交与独立CI尚未完成，因此本片仍是候选，UI继续不得开放资源标签写操作。

## 已固定纵向切片：Application 标签设置与删除

本片只开放已有Application的`environment`标签设置与删除，不建立中央标签数据库、批量标签任务、标签继承或其他资源的标签写入。标签继续由PaaS资源事务拥有，IAM只声明动作、可信条件来源并返回决定；后继增加标签键或资源种类必须由相应产品Profile声明，不能在通用求值器、IAM存储或控制台按产品名硬编码。

北向API使用两个显式动作而不是一个含隐式删除语义的通用PATCH：`PUT /v1/applications/{applicationId}/labels/{labelKey}`只接受精确`{"value":"..."}`，`DELETE`同一路径不接受body。首片`labelKey`只允许当前PaaS Profile声明的`environment`；两者都必须携带`If-Match`强ETag和`Idempotency-Key`，Account仍只由当前有效身份推导。成功返回终态`Operation`，`Location`指向Application，`Operation-Location`指向该Operation，响应`ETag`为提交后的资源版本；客户端随后按常规读取接口取得最新Application。设置为现值返回冲突且不产生Operation/Audit，新的删除请求遇到不存在的键返回未找到；已完成命令的等值重放返回原Operation及同一派生资源版本，变体重放返回幂等冲突。query/header/body中的Account、Subject、Profile、Action、当前标签或额外目标标签selector全部拒绝。

PaaS Profile下一修订增加`paas.application-label.set`和`paas.application-label.delete`两个独立实例动作，资源均为真实`APPLICATION`。两者同时绑定授权前数据库快照中的`resource.tag/environment`与请求意图：设置时`request.tag/environment`是新值；删除时它是即将解绑的当前键值对，而不是由caller补造的占位值。这样Policy可在同一Statement中同时限制“允许修改哪类当前资源”和“允许写入或解绑哪个标签值”。缺失当前标签不产生虚构的resource/request tag；删除缺失键不能借无标签决定变成成功。USER与服务来源/用户来源ROLE只有在各自当前凭据、血缘和Policy都有效时可执行，ServiceIdentity、平台身份或subject-resolution响应本身均不取得写权。

处理流程先以当前身份解析Account并只读取得Application快照，再按精确动作、Application ID、当前标签与目标请求标签调用唯一PDP。Allow之后，PaaS在Account作用域的Serializable事务中锁定该Application，依次核对`If-Match`、快照ID/resourceVersion、全部Profile声明的当前标签、决定中的resourceTags和requestTags以及命令指纹；任一漂移返回冲突或重新取得新决定，绝不能拿旧Allow修改新状态。资源版本递增、标签变化、幂等完成记录、产品Audit outbox事实必须在同一事务提交；Audit追加失败或提交结果不确定时不得出现只有标签已变而完成证据缺失的可观察状态。

命令身份至少绑定Account、真实Subject（ROLE包含完整RoleSession血缘）、动作、Application ID、标签键、目标值或删除意图、expected resourceVersion和Idempotency-Key。相同命令等值重放返回首次结果；同一key改变任一字段必须冲突。设置与删除分别产生封闭的`paas.application-label.updated`和`paas.application-label.deleted`租户事实，Target固定为真实Application；事实关联原IAM decision、request/correlation和PaaS outbox，不增加任意attributes，也不把标签值写进错误或凭据日志。首片只有一个可授权标签键，因此事实动作已能无歧义表达变化对象；扩展多个键前必须先在既有Audit契约owner中给出类型化、兼容旧canonical的表达，不能用自由属性绕过。

最低门禁覆盖两个Account同Application ID、USER与两种ROLE来源、当前production→目标staging、同值设置、删除、缺失键、显式Deny、撤权/停用后的下一请求、伪造当前/目标标签、未声明键、错误ETag、同key变体重放、并发设置/删除、授权后锁前漂移、Audit outbox故障和提交结果不确定。真实PG18必须证明RLS、行锁/CAS、资源与完成记录原子性、受限登录和重启；独立IAM/Audit/PaaS进程必须证明下一次资源读取立即按新标签重评、跨Account不串、旧permit不缓存。该门禁固定通过前，UI继续只读展示标签，不开放修改入口。

当前固定实现把PaaS Profile推进到revision 6，保留授权决定contract 7并把开发数据库形状推进到IAM59/Audit31/PaaS3；发布profile仍不匹配且继续在安装副作用前关闭。PaaS API角色没有取得表级UPDATE权限：目的限定的`load_application_for_update`只在当前事务Account内锁定真实Application，`update_application_label`再次核对expected resourceVersion、不可变字段以及恰好一个标签键的设置/删除差异，再原子写入新文档、终态Operation和Audit outbox。受限worker不能调用两个入口，直接额外修改第二个标签的攻击由数据库以`22023`拒绝。

本任务独占PostgreSQL 18中，PaaS迁移双次应用/verify及真实事务门禁以4.534秒通过同ID双Account、等值/变体重放、并发设置与删除只有一个成功、RLS、数据库第二标签攻击和故障注入整单回滚；Audit31完整catalog以11.939秒逐项接受新事实并验证USER、ROLE和AccessKey actor边界。独立IAM59/Audit31/PaaS3、双IAM和双dispatcher进程以223.721秒通过真实策略发布、`PUT`/`DELETE`、当前/目标标签决定证据、更新后下一次读取立即403、一次性Operation/Audit事实及链验证。唯一滚动前驱已替换为固定`e3c137ba0ed80d8d90f893192d343d89d2d917f5`的IAM58；实际旧binary产生requestTags、resourceTags、Profile/Decision、账号、MFA、会话和恢复事实后，IAM59双迁移、等值bootstrap和重启门禁以137.786秒通过，历史字节、proof和撤销状态未复活或改写，不再保留IAM57测试窗口。全仓默认测试、vet、模块校验、Linux amd64构建、聚焦race和两次API生成稳定均通过。实现固定推送为`e9ea19e65a4cc67a42edca05112221d195c18284`；最新独立CI尚未登记，因此UI仍只能使用MOCK验证交互，不能标记LIVE。

## 当前纵向切片：AccessKey签名创建Application

本片只把`POST /v1/applications`接入已固定的Matrix AccessKey签名与IAM当前PDP，不同时开放Application读取、标签修改、Configuration、Revision、Deployment、Operation或Audit查询。PaaS Profile revision 7仅将`paas.application.create`的USER认证方法声明为规范集合`[ACCESS_KEY, LOGIN_SESSION]`；其他动作的载体集合不变。签名入口必须命中精确method和内部route，产品前缀、任意resource kind或调用者提交的Action都不能扩大映射。

边缘必须删除caller提供的外部请求头，再覆盖实际NorthboundOrigin、原始request-target、直接source IP及[007拥有的用途隔离边缘断言](./FEAT-IAM-007-programmatic-credentials.md#当前纵向切片可信apisix北向入口与安装封存)。PaaS以显式文件/部署配置、可信边缘事实、实际内部路由和socket来源重建唯一`SignedRequest`，并核对外部`/api/paas/`到内部`/v1/`的逐字节映射；配置缺失、断言错误、来源/目标歧义、未覆盖的语义header或其他route均在调用IAM和业务用例前关闭。配置只定义部署权威，不授予调用者Account、主体或动作。

PaaS通过独立AccessKey authorizer调用IAM `POST /v1/authorize:access-key`；服务Bearer只证明当前PaaS服务，不能替代最终USER/key。adapter核对响应的request digest、Profile/Action/资源、USER及`accessKeyId`与原签名完全一致，不能在失败时回退登录bearer。Allow进入原Application创建事务，Account仍从决定推导；最终Operation、PaaS outbox及Audit actor保存同一USER和key ID，资源归Account而非key。业务幂等身份包含key ID：同一key的新nonce可重试原业务意图，另一把key不能借用原完成结果。

公开错误边界为：结构非法、未知key或错误MAC返回`401 UNAUTHENTICATED`且不泄漏key状态；有效MAC但当前策略拒绝返回`403 PERMISSION_DENIED`并消费nonce；已消费nonce返回`409 CONFLICT`且不进入业务；IAM不可用、回包不可信或绑定不完整返回`503 IDENTITY_UNAVAILABLE`。固定route上的非法业务JSON在IAM前返回400且不消费nonce，调用方修正body后须重新签名。PaaS不缓存Allow；key/User/Account/附件/策略变化在下一受保护请求由IAM当前状态判定。

固定`40adf6d828180050992a8a6c139f05a83afc753f`在独占PostgreSQL 18的PaaS存储race门禁以5.841秒通过新增USER+AccessKey约束、跨Account同ID和既有载体回归。独立双IAM、Audit、PaaS和双dispatcher进程以测试222.57秒、包226.037秒通过两个Account各自key签名创建同名同IDApplication、准确Operation归因、nonce重放409、PaaS outbox投递、租户Audit查询及链验证；普通bearer路径和既有标签/Role/服务会话回归仍在同一门禁执行，末端全库敏感信息扫描也通过。IAM58→59真实前驱门禁以109.25秒通过，最终全仓race、vet、模块校验、生成稳定和Linux amd64构建通过；[独立CI 36842829292](https://github.com/xiak/matrix/actions/runs/36842829292)因后继push并发取消，不登记为独立CI通过，累计实现由后继`63ab867d3`重新验证；真实APISIX覆盖和签名安装包仍未完成，因此控制台只能按契约准备交互而不能标记LIVE。

## 已固定纵向切片：AccessKey创建PaaS不可变资源图

PaaS Profile revision 8为`paas.configuration.create`、`paas.configuration-revision.create`、`paas.application-revision.create`和`paas.deployment.create`的USER逐项增加`ACCESS_KEY`，连同已固定的`paas.application.create`组成唯一允许签名的五条collection-create路由。每条声明保持原ResourceKind、TENANT scope、COLLECTION/CREATE形状和createdResourceKind；不改变ROLE、实例读写、Operation读取或平台动作载体。route映射同时绑定method、内部path和Action，真实handler若使用另一Action则在IAM前关闭。

这些Action没有资源标签预读，允许在完整HTTP签名通过结构检查后先调用IAM、再由原严格业务decoder和Account事务检查body。合法MAC但业务JSON或父资源引用非法时，nonce可以已消费但不得产生业务效果；结构级签名/route错误仍不产生IAM决定。ConfigurationRevision必须引用同Account Configuration，ApplicationRevision必须引用同Account Application，Deployment必须引用同Account Application及其Revision并遵守现有图不变量。collection决定、最终resource ID和payload真实性继续分别由IAM及PaaS事务/outbox证明，不扩张为IAM证明业务body。

固定`63ab867d30113b70a71e6ce6ddc5f16020380d36`已在独占PG18完成PaaS存储race（6.283秒），并以独立双IAM、Audit、PaaS和双dispatcher进程完成两个Account同名同ID完整资源图、每步USER+key Operation/Audit归因、跨Account父引用404且无部分业务状态、nonce重放及原LOGIN_SESSION/ROLE/标签/服务会话/租户链回归（测试239.85秒、包243.347秒）。IAM58→59唯一滚动前驱以测试132.58秒通过，最终全仓race、vet、模块校验、生成稳定和Linux amd64构建通过；[独立CI 36847285739](https://github.com/xiak/matrix/actions/runs/36847285739)未在后继推送前完成，不登记为独立CI成功。缺失父节点、另一key复用幂等键、末端outbox故障的细分覆盖由既有业务门禁提供但尚未在AccessKey专用路径逐项复跑，签名安装组合也未完成，因此仍不标LIVE。

## 当前纵向切片：AccessKey读取带标签Application

PaaS Profile下一revision只为`paas.application.read`的USER增加`ACCESS_KEY`，不顺带开放其他read/list、Operation或Audit动作。该实例动作需要真实`resource.tag/environment`，因此复用现有登录/ROLE读取的“账号解析→RLS只读预读→PDP→重读”业务边界，但使用独立、非permit的AccessKey签名主体解析契约；不能把签名header当bearer传给现有USER/ROLE解析器，也不能让IAM内部访问PaaS数据库。

内部解析结果必须绑定同一SignedRequest digest、当前PaaS Profile、Account、USER和key，只供本次预读；最终`authorize:access-key`仍是唯一权限决定及nonce消费点。PaaS在最终决定前不向调用方返回资源存在性、标签或Account，在决定后以决定中的同一Account重读并核对快照。合法MAC经解析后若IAM最终不可用或回包不确定，返回503且调用方不能假定nonce状态；PaaS不得自动改用登录bearer、缓存解析结果或重新签发Action。真实门禁必须用两个Account相同Application ID、不同environment和相反Policy结果证明标签来自凭据推导的Account，并证明预读/授权/重读任一漂移都失败关闭。

固定`b6d15c89a`将PaaS Profile推进到revision 9，仅为`paas.application.read`的USER增加`ACCESS_KEY`；Configuration读取、列表、Operation、Audit和标签修改仍保持原载体集合。`GET /v1/applications/{id}`只接受无query、无body的精确签名，内部解析回包须逐项匹配Profile、Account、USER、key和请求摘要，业务只从决定Account进入RLS只读事务。聚焦API/IAM/PaaS测试、真实PG18 AccessKey race 95.796秒、独立双IAM/Audit/PaaS及双dispatcher 216.715秒、IAM58→59前驱107.044秒，以及最终全仓race/p2、vet、模块校验、生成稳定和Linux amd64构建均通过。两个Account的同IDApplication分别带`production`/`staging`标签，真实Allow与显式Deny保存精确声明标签，未声明`team`不进入IAM证据；解析两次无状态、最终nonce只消费一次，原资源图和租户Audit链保持。[独立CI 36853816880](https://github.com/xiak/matrix/actions/runs/36853816880)在后继推送前完成6项成功但未取得整体终态，不登记为独立CI通过；签名安装尚未完成，UI不得标记LIVE。

## 当前纵向切片：AccessKey读取其余无属性实例

后继Profile只为`paas.configuration.read`、`paas.configuration-revision.read`、`paas.application-revision.read`、`paas.deployment.read`和`paas.operation.read`的USER增加`ACCESS_KEY`。对应PEP只接受六条精确GET：Configuration、两类Revision、Deployment、Deployment generation和租户Operation；Deployment generation仍授权Deployment ID，完整签名路径另行绑定generation。上述Action没有Profile声明的资源标签条件，因此直接在读取前完成一次最终AccessKey授权和nonce消费，再以决定Account进入原RLS读取；不得调用非permit resolver后就返回资源，也不得从路径、header或资源行反推Account。

列表、Deployment写入、Application标签写、平台Operation及Audit继续保持原载体集合。最低真实门禁逐route覆盖两个Account同ID资源、query/body/多段路径、route与Action替换、另一key重放、Allow/Deny、当前撤权和IAM失联，并核对Operation/Revision父引用不会改变授权资源或扩大权限；原Application读取的标签预读与重读仍单独执行，不能为统一代码而删去。

固定`35e15da22`将Profile推进到revision 10/digest `sha256:759bd751d03fc8ddceb69f6a5e827328401dcbd47d73a1e568a0b76c5a517256`，并以闭合route表把六条GET逐项映射到五个原read Action；Deployment generation完整路径绑定generation，但授权资源仍是Deployment。真实双Account进程门禁203.770秒逐项读取所属Configuration、两类Revision、Deployment、generation和Operation，核对真实父引用、期望状态、不可变generation、原Operation的USER/key归因以及决定/Audit链；同一个Operation签名重放409。AccessKey真库95.578秒、唯一revision 9前代164.012秒及最终全仓race/vet/生成/Linux构建通过。首次进程/前代运行只分别暴露过期Deny fixture和未来overlay变量名，均在全新数据库修正后通过，生产边界没有放宽。本片没有数据库迁移；[独立CI 36858924218](https://github.com/xiak/matrix/actions/runs/36858924218)仍在运行，安装和UI仍不得据此标LIVE。

## 已固定纵向切片：AccessKey控制Deployment

PaaS Profile下一revision只为`paas.deployment.update`、`paas.deployment.stop`和`paas.deployment.rollback`的USER增加`ACCESS_KEY`。PEP只接受精确`PUT /v1/deployments/{deploymentId}`和`POST /v1/deployments/{deploymentId}/rollback`；PUT在严格解码签名body后由`desiredState`选择update或stop，rollback保持固定动作。路径Deployment ID、完整body、`If-Match`和`Idempotency-Key`均由签名承诺，调用者不能提交Account、Subject、Action、resourceVersion或目标generation的旁路selector。

IAM Allow只证明当前程序主体能对精确Deployment执行该动作；PaaS仍在决定Account的Serializable事务中锁定真实Deployment，核对If-Match、当前Operation和业务图，再原子提交资源版本/generation、Operation、完成记录和outbox。合法签名的nonce与决定不能因后继PaaS冲突而回滚；PaaS失败不得留下部分业务效果。返回Operation及最终Audit actor必须保留USER与accessKeyId，业务幂等身份继续区分不同key。所有列表、标签写、平台动作、Audit及未登记路由保持关闭。

真实验收以两个Account的同ID Deployment证明三种变更只能作用于决定Account，覆盖另一key/Account、body/If-Match/route替换、nonce及幂等重放、并发版本冲突、撤权/停用、IAM未知结果、重启和完整Audit链；现有LOGIN_SESSION/ROLE、创建、读取和服务会话路径必须回归。该后端证据不替代APISIX可信边缘或签名安装组合。

固定`05336ad368996a500c0769fe62767204bd9333d0`将Profile推进到revision 11/digest `sha256:ba8b808cc72c4ff1eb34d9eb933b5cde4ee95dde0f1a5c361058c2dab6937b48`，没有新增SQL。2026-10-01独立PG18.6双Account五进程race门禁233.250秒真实执行update、stop、rollback及各自重放冲突，核对generation、源generation恢复、原USER/key、决定、Operation、outbox及tenant Audit链；AccessKey真库95.209秒和固定revision 10 executable保留数据门禁126.642秒通过。全仓race/p2、vet、模块校验、OpenAPI生成稳定及Linux amd64/CGO关闭构建通过。两次失败仅来自测试夹具的UTC规范化和pgx JSON参数类型，均在全新数据库修正后通过，生产实现未放宽。独立CI尚未终态；真实边缘、发布组合和UI仍由其owner另验。

## 已固定纵向切片：AccessKey管理Application声明标签

PaaS Profile下一revision只为`paas.application.label.set|delete`向USER增加`ACCESS_KEY`。闭合PEP只接收精确Application、Profile已声明的标签key、PUT值或DELETE当前值、If-Match及幂等键；AccessKey先解析为当前Account/User，再从决定Account读取真实当前标签，不能信任请求提供资源标签或Account。IAM Allow绑定当前资源标签和目标标签，PaaS Serializable事务在效果前重读Application并核对决定证据、resourceVersion与目标变化；任何漂移返回失败，不用旧快照写入。

双Account同ID/不同标签的真实进程门禁必须证明set/delete只影响决定Account，另一key/Account、标签key/value/body/path/If-Match替换、nonce与业务幂等重放、撤权/停用、IAM失联和并发标签变化均关闭；成功Operation/outbox/Audit保留原USER/accessKeyId。现有LOGIN_SESSION、AccessKey资源图创建/读取及Deployment控制全部回归。本片不新增标签DSL、批量API或资源列表。

固定实现`4433b7ac00fec3ae7e2fdae35fad4bbdc4cf9238`及门禁收紧`c83c38d7b91aa17003c2d217fd509eaba37d98d5`交付revision 12/digest `sha256:ec6ef98cd9b4939cbbdd05632c8fbd28ff8ce79d98466ce98103c3fae30699b6`，未新增数据库迁移。2026-10-01独立PG18.6 PaaS事务race 5.171秒、双Account五进程race 257.56秒及revision 11真实前驱升级112.17秒通过；同ID不同标签、跨Account复用同一业务幂等键、精确set/delete、资源/请求标签决定、USER/key Operation与Audit归因、body/path/key/If-Match/幂等键替换、nonce冲突和登录会话原路径均由真实HTTP/数据库证明。全仓普通/race、vet、模块校验、生成稳定及Linux amd64构建通过；独立CI尚未终态，可信边缘、签名发布组合和UI仍由其owner另验。

上述AccessKey产品路径及后继Audit租户读取、网络限制与使用观测累计进入`91649497a0c53be1174d8835326a2df51fe74a55`；其[Verification 37106511260](https://github.com/xiak/matrix/actions/runs/37106511260)已核实精确SHA并全部completed/success。该终态覆盖当前整仓、真实authority storage/runtime/process分片及node gate，接受当前已列出的产品消费后端；不表示未列动作自动获得ACCESS_KEY，不替代APISIX可信边缘、签名安装、LIVE UI或最终发布组合。

## 当前纵向切片：租户 Application 目录与安全游标

本片把`GET /v1/applications?after=<opaque>`作为首个有游标的租户资源目录，不顺带开放Configuration、Revision、Deployment或Operation目录，也不增加caller可选页大小、Account、Subject、Action、标签或排序selector。响应使用固定候选扫描预算50，按Application ID的`C`排序；`after`只接受本服务签发的续页值，空值表示首屏。候选必须从当前身份推导的Account中经PaaS强制RLS读取，不能先按全局ID取资源再靠IAM过滤。

一次页面读取先以同一当前凭据取得`paas.application.read`的`COLLECTION_LIST`决定，再对本页真实候选使用该Action的`INSTANCE`批量PDP。PaaS Profile的新revision必须同时声明集合形状和`instanceListBatch`，现有INSTANCE读取、声明标签条件、USER/ROLE及已发布认证载体不被改写。批量项从数据库快照取得精确ID、resourceVersion和Profile声明的`resource.tag/environment`；Allow后返回的资源仍与授权快照逐项核对，Deny只过滤对应项，任何遗漏、重复、错序、错Account/Subject/Profile/Action/标签或IAM不确定结果都使整页失败关闭。

游标由PaaS产品边界独立持有的每安装32-byte密钥认证，不复用IAM/Audit内部游标密钥、codec或包。载荷绑定安装、Account、严格Subject（ROLE包含完整session lineage，AccessKey包含key ID）、当前PaaS Profile引用、Action、固定查询形状、最后已扫描候选和15分钟失效时间；不能携带权限或业务对象正文。游标指向最后扫描候选而不是最后返回项，因此部分/全部Deny不会重复扫描；即使返回空页，只要固定预算后仍有候选也可返回续页。每页重新认证并执行集合和实例授权，游标不是permit；撤会话、撤Role/binding、停用User/Account、停用AccessKey、撤附件或推进Profile后，下一页必须按当前状态拒绝或重新过滤。

LOGIN_SESSION与ROLE继续使用现有`authorize`加`authorize:batch`协议。ACCESS_KEY不能把一个签名列表请求拆成多次`authorize:access-key`，而必须使用[007拥有的一次MAC、一次nonce、集合与实例决定共同引用同一请求证据的签名目录协议](./FEAT-IAM-007-programmatic-credentials.md#当前纵向切片accesskey签名目录批量授权)。未知提交结果保持不确定，产品不得改用登录bearer、换nonce自动重放业务请求，或把非permit的subject-resolution结果当作目录授权。

最低门禁覆盖两个Account拥有同ID/同名但不同标签的Application、USER、两类ROLE来源及ACCESS_KEY；全Allow、部分Allow、全Deny、显式Deny优先、零项、恰好50项和超过50项；伪造/过期/另一安装/另一Account/另一Subject/另一Profile/另一Action游标；游标指向未返回Deny项；第二页前撤权、停用或标签变化；批次错序/遗漏/替换；nonce重放、同key并发、IAM失联、outbox故障和进程重启。真实PG18须证明RLS、只读快照、签名请求证据唯一性、决定与tenant Audit链原子性；独立IAM/Audit/PaaS进程及签名安装组合须证明每安装游标密钥多副本一致、密钥缺失或错误时失败关闭。

固定`71c7882b4f8a1aa11ee1a2408b8ae111f375f25a`已将本片落到真实`GET /v1/applications?after=<opaque>`。PaaS先从当前凭据解析不可切换的Account，在强制RLS下按ID读取最多50个候选，再以一个collection和0–50个instance请求调用一次对应授权协议；只返回逐项Allow且重读版本/标签仍一致的资源。游标由PaaS安装密钥加密并绑定安装、Account、严格主体、Profile、Action、固定查询和最后扫描ID，15分钟到期。明文ID、重复`after`、额外query、大小写和percent-encoding路由别名均在IAM前拒绝；候选跨Account父引用、游标换Account/主体/Profile、第二页撤权、部分与全部Deny、零/一/五十/超过五十项、同nonce并发及重启由现有owner覆盖。聚焦PaaS race、全仓普通Go/vet及API生成稳定已本地通过；独立[Verification 37571650568](https://github.com/xiak/matrix/actions/runs/37571650568)已终态completed/failure，十三项job成功，但`authority-runtime`的过期滚动前驱/decision查询断言失败并使最终`authority-process`汇总失败。当前修复尚未取得新精确SHA的独立CI，签名安装组合也未完成，所以本节仍为当前切片而非最终验收。

## 验收

真实两个产品/两个 Account 的同名/同 ID/key、跨租户资源/cursor/配额/Operation、修改 tag 攻击、多个相关资源任一拒绝即无效果；服务跨租户请求必须有目标角色和用途；verifier probe 无业务写权。暂停之后的已提交事实可投递，新请求拒绝。独立 PG18/RLS/受限进程、真实部署和 UI 路径均通过才接受。

用不同名称的已登记产品/服务/角色证明统一流程；新增一份受信产品声明和角色模板即可通过相同登记、授权、承担和 PEP 协议，不给通用 evaluator 或 UI 增加名称分支。未知/未登记产品、伪造服务载体、缺少账号同意、错误目标角色/资源绑定及超出模板权限均拒绝。模板与预置策略变更验证旧版本和同意关系不被自动改写。
