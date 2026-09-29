# FEAT-IAM-008：业务接入、服务角色与 ABAC

- 状态：实施中；版本化产品 Profile、PaaS/managedservice 的真实 PEP、请求与决定绑定及当前资源/Operation/outbox 租户隔离已有固定后端实现。实例过滤/批量授权、服务受托和可信标签尚未实现，整体未验收。
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

Profile 的代码/签名发行由产品 owner 管理，IAM 只注册校验与求值。请求绑定精确 profileRevision/digest；缺版本/不兼容组合关闭。当前源码Profile与集合/实例的闭合声明由001拥有，集合列表只支持整体授权的 COLLECTION_LIST；实例过滤未实现，不能向未适配列表的 PEP 发细粒度 Permit。被授权资源和成功事实资源种类分别声明，父实例→子资源与集合→新资源均不能用结果ID反向扩大permit。

产品接入和服务受托是两条独立协议。前者登记产品动作、资源、粒度和可信属性，并在业务 PEP 执行当前决定；后者登记可验证的服务主体与角色模板，经账号显式授权后承担目标角色、取得短期会话。不能把“产品已接入”或“服务认证成功”解释为已取得客户资源权限。

通用 IAM 求值器和控制台不得按产品名称、服务名称、角色名称或六种旧角色枚举内置授权分支。产品新增动作/模板是相应 owner 的版本化声明；新增产品必须通过登记与契约验证，不修改求值算法或逐个扩展前端角色菜单。预置策略、服务角色模板可由可信产品发布，但内容、默认版本与同意关系分别管理；显示名改动不影响授权，新版本不能隐式扩张既有账号的授权。当前静态 Action catalog 是 001 的过渡实现，不是最终可扩展接入完成。

PaaS 先覆盖 Application、Configuration/Revision、Deployment、Operation；managedservice 覆盖 Offering/Region/Entitlement/Installation；Audit 保持 chain/query scope。平台主机/终端由既有 Phase owner 消费确认的公共契约，本任务不重做主机实现。

ServiceRoleTemplate 定义注册服务主体、用途、允许权限和生命周期；租户实例经明确同意创建。PassRole 必须同时验证 actor、目标 role、目标工作负载和 service purpose。关联资源存在时拒绝或按明确异步删除流程，不能删角色留下无限可用凭据。

标签来自产品数据库和已验证新建命令，IAM 自供时间/身份/session 属性。禁止通用 caller attributes map。授权决定与业务 payload 区别明确：IAM 不声称证明具体部署镜像、配置值等业务真实性，源事务/outbox 负责。

## 当前实现边界

本节只归纳本 FEAT 的实现状态；Profile 注册与策略编译的详细证据仍分别由 001、005 拥有，RoleSession 的详细证据由 006 拥有。

| 需求 | 当前状态 | 权威边界 |
| --- | --- | --- |
| IAM-PEP-01 | 已实现当前后端主体 | 固定 `1dc1079c` 已将 IAM、PaaS、managedservice、Audit、installation 的版本化 Profile、完整摘要、当前头及请求/决定绑定接入唯一契约并通过独立 CI。后继 PaaS Profile revision 3 增加 `request.source-ip`，固定 `94cc8d7f` 已有真实 PG18、独立进程及唯一前驱保留数据证据，独立 CI 尚未收口。当前仍是源码/开发 readiness，不是签名发布组合。 |
| IAM-PEP-02 | PaaS apphosting 与 managedservice 已实现 | HTTP owner 从真实 path/body 和实际 `RemoteAddr` 构造 Action、资源、集合用途及可信网络上下文；账号和主体来自当前 IAM 凭据。IAM 决定必须逐字段绑定原请求，业务事务再按数据库所属账号取数，query/body/header 不能选择另一账号。 |
| IAM-PEP-03 | 部分实现 | 当前集合列表只允许声明为 `COLLECTION_LIST` 的整体授权；两个账号同名/同 ID/key、伪造 tenant/cursor/after 及跨账号实例均有真实拒绝门禁。尚无“先取候选再逐实例过滤”的列表协议，也没有批量决定；因此不能把整体列表授权描述为细粒度过滤完成。 |
| IAM-PEP-04 | 当前应用托管与 managedservice 路径已实现 | Application、Configuration、Revision、QuotaEntitlement、ServiceInstallation 的创建由封闭集合请求开始，最终资源、Operation 和 outbox 由同一业务事务建立；IAM 原决定只证明集合准入，不证明 caller 填写的最终 ID 或 payload。真实双账号门禁核对配额、Operation、幂等、拒绝无部分效果及 Audit 关联。 |
| IAM-SVC-01/02 | 契约、发布模板、封闭动作目录及受权模板只读目录首片已实现，运行闭环未实现 | 当前 ServiceIdentity 只证明安装归属、服务主体及 purpose；不能承担目标账号 Role。已有不可变模板契约、一个 release-owned managedservice 安装只读模板/精确系统策略上限、当前 USER 的模板目录，以及账号同意所需的封闭 Action/系统策略/Audit 事实；仍没有 SQL 同意关系、产品 bind/unbind 路由、服务承担入口或短期凭据。现有 RoleSession 仍只允许同账号 USER 来源，TrustPolicy 也明确拒绝 SERVICE_ACCOUNT。 |
| IAM-TAG-01/02 | 未实现 | Role 的 `tags` 仍只是元数据，不能进入授权。产品资源标签、创建请求标签、标签写入授权和并发一致性尚无可信来源协议。 |

`app/service/paas/internal/managedservice/port/security.go` 原 action→resource switch 是该产品适配器的封闭边界，不是通用求值器按产品名称分叉，但它重复了 release-owned Profile。本轮候选已删除这份重复映射：port 直接使用 IAM Action/ResourceKind 类型，通过 `NewAuthorizationRequest` 和 managedservice 当前 Profile 的完整引用/calling service 核对形状；IAM HTTP adapter不再执行第二次字符串翻译。七种合法集合/实例形状及其他产品、错资源、错集合用途/ID攻击的聚焦测试通过；全仓默认 race/vet、architecture、模块校验和 Linux amd64 构建通过，尚待独立CI。后继产品适配器同样应消费自己编译进发布物且已由 IAM Profile 摘要认证的声明，通用 IAM 求值器仍只解释统一 Profile/Policy 语义。

同片后继候选把 apphosting 的 PaaS→IAM 资源词汇翻译收敛到 port 的单一构造器，HTTP adapter不再维护第二份资源 switch，Action/资源形状、当前 Profile 引用、PAAS calling service 和可信 source IP 一次绑定。apphosting 仍保留14个路由动作的显式 PEP 子集：同一PaaS Profile中的平台主机/安装动作不能因“属于PaaS”进入应用托管。14条合法形状及同产品错PEP、其他产品、错资源/集合/source IP攻击的聚焦测试通过；同一全仓默认 race/vet、architecture、模块校验和 Linux amd64 构建通过，尚待独立CI。

## 下一纵向切片：账号同意的服务相关角色

下一片先完成一个真实产品、一个只读业务动作的完整协议，再扩展动作族；不先铺开任意跨账号委派或动态插件市场。

当前候选已先落单一纯契约边界：`ServiceRoleTemplateSpec` 把产品、服务 purpose、精确不可变 `PolicyVersion`、允许绑定的 workload resource kinds 与最大发行时长纳入域分隔摘要；`ServiceRoleTemplate` 的 ACTIVE/RETIRED 只控制后继绑定/发行，不改写原同意。workload kinds 在编码前排序、重复拒绝，caller 顺序不成为权限；严格解码拒绝 Account/安装选择器和重复字段。该阶段没有注册可调用 Action、HTTP 路由、SQL、同意关系或凭据发行，因此不是 IAM-SVC-01/02 完成证据；后继必须把这一承诺接到同一片真实 managedservice 资源、IAM 原子关系和 Role PDP。

当前后端同时登记一个 release-owned `managedservice.installation-reader` 模板及其精确 `system.managedservice-installation-reader` 策略版本。策略只允许 `managedservice.service-installation.read`，资源上限只覆盖当前 Account 内的 `SERVICE_INSTALLATION`，模板只接受 `PAAS` purpose、该 workload kind 和最长十五分钟会话；模板查询必须提交完整 `{id,version,contentDigest}`，不能仅按 ID 跟随当前头。注册表返回隔离副本，caller 不能修改进程内权威。managedservice Profile revision 2 只为该安装读取动作增加 ROLE，原 revision 1 继续按原摘要归档且不获得 ROLE；其他 managedservice 动作仍只允许 USER，ServiceIdentity 也不能直接求值。既有 `PaaSDeveloper/PaaSViewer` 默认版本不因新主体能力被迁移或隐式扩权，服务模板使用独立的新系统策略。该模板已有受当前 Account 权限保护的只读目录，但尚无同意关系或发行入口，任何服务来源仍无法取得 RoleSession；完成账号同意和真实产品 PEP 后，才可把本片称为可用服务角色。

后继公共契约已经冻结 `Role.management=SERVICE_LINKED`、非秘密 `ServicePrincipalReference`、`ServiceLinkedRole`、`WorkloadRoleBinding` 及聚合观察 `ServiceLinkedRoleAccess` 的字段和严格编码。binding 只允许创建时ACTIVE/revision 1及一次终态REVOKED/revision 2，精确绑定Account、Role、template版本/摘要和workload `{kind,id}`；关系同时保留安装、服务principal、purpose及不可变PolicyVersion上限。普通客户Role目录/详情明确拒绝`SERVICE_LINKED`，不能借既有更新、trust、附件或boundary入口修改系统关系；组件schema与运行校验共同拒绝换Account/Role/template、未知purpose、空workload、伪终态及重复字段。模板已有独立只读northbound路径，关系与binding仍没有SQL、northbound路径或同意事务，因此当前只证明稳定关系契约，不证明租户已经能够授权服务。

当前动作目录后继将 IAM Profile 推进到 revision 8，新增模板/服务相关角色只读、创建服务相关Role、`iam.role.pass`及binding撤销六项能力；managedservice Profile revision 3只新增实际`SERVICE_INSTALLATION`的bind/unbind。八项能力全部要求当前USER，IAM六项还明确只接受LOGIN_SESSION；ROLE只能继续执行模板允许的安装读取，SERVICE_ACCOUNT不能直接求值。新`system.service-role-administrator`精确包含这八项且不自动附着，既有`AccountAdministrator`、`PaaSDeveloper`、`PaaSViewer`和安装读取策略均未扩权；具备原Policy附件管理权的管理员必须显式委派该职责。历史IAM revision 7、managedservice revision 1/2保持原能力。新增租户Audit事实`iam.service-linked-role.created`及`iam.workload-role-binding.created/revoked`只接受USER演员、准确目标和原IAM决定，不能由SYSTEM/服务主体或安装链伪造；三项事实同时进入Audit数据库的封闭append/query目录，Audit readiness推进到29，目录门禁先以公开Go契约验证fixture再证明SQL接受同一事件，避免API与存储目录静默漂移。聚焦API/Audit/authority/architecture race、生成、vet及负向门禁已本地通过；本任务独立限额PostgreSQL 18的`TestIAMPolicyAuthorityStoragePostgres`以225.31秒通过干净迁移原子性、Profile/系统策略注册重放、权限存储、附件并发和历史证据门禁；CI同形Audit存储、保留tenant链升级和HTTP门禁分别以16.52秒和4.67秒在新数据库通过。尚未取得修复后的独立CI，也没有因此产生SQL同意关系、同意/承担HTTP成功路径或可承担的服务会话。

`GET /v1/service-role-templates` 已接到当前 USER 的真实账号PDP：服务端只接受无query/body的GET和LOGIN_SESSION，以 `iam.service-role-template.list` 对IAM推导的当前Account实例求值，随后才从同一发布注册表返回完整有序模板；响应没有Account、installation或服务凭据选择器。原`AccountAdministrator`默认拒绝，显式附加`system.service-role-administrator`后允许，撤销附件后的下一次请求立即拒绝；ServiceIdentity不能替代USER。返回对象继续深拷贝并由严格codec校验，caller不能修改源码权威或把ACTIVE解释为账号同意。聚焦用例/HTTP测试及现有roles真实PostgreSQL 18 race门禁已通过，后者77.22秒同时保留角色并发、游标、边界、审计和不可变历史回归；独立CI尚未取得。这一目录只完成观察路径，不证明关系SQL、bind/unbind或服务承担。

模板目录与账号同意必须在API/UI上分层：`ServiceRoleTemplate.status`只表示平台发布的模板版本能否用于后继同意/发行，不能显示成目标Account已授权；`ServiceLinkedRole`和`WorkloadRoleBinding.status`才是该Account的同意及资源绑定状态。首个northbound目录仍由IAM向当前USER提供只读、非秘密模板/关系观察，实际绑定/解绑由managedservice面向真实`ServiceInstallation`的产品入口编排，浏览器不直接调用内部双凭据或服务会话入口。UI可以展示template ID/version/digest、product/purpose、workload kind、service principal、固定PolicyVersion和目标资源语义，但在bind/unbind/assume契约及真实后端固定前必须保持预览/禁用，不以模板ACTIVE渲染“已授权”。

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

## 验收

真实两个产品/两个 Account 的同名/同 ID/key、跨租户资源/cursor/配额/Operation、修改 tag 攻击、多个相关资源任一拒绝即无效果；服务跨租户请求必须有目标角色和用途；verifier probe 无业务写权。暂停之后的已提交事实可投递，新请求拒绝。独立 PG18/RLS/受限进程、真实部署和 UI 路径均通过才接受。

用不同名称的已登记产品/服务/角色证明统一流程；新增一份受信产品声明和角色模板即可通过相同登记、授权、承担和 PEP 协议，不给通用 evaluator 或 UI 增加名称分支。未知/未登记产品、伪造服务载体、缺少账号同意、错误目标角色/资源绑定及超出模板权限均拒绝。模板与预置策略变更验证旧版本和同意关系不被自动改写。
