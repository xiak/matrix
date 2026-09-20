# FEAT-IAM-009：登录保护与安全治理

- 状态：S1本人会话目录/逐个撤销已验收；S1b一键结束其他登录会话的后端切片也已验收，累计固定`7cf857bba48eb5d7da487162c43e8f52534db133`通过本地真库、保留数据、独立进程、全仓检查及五项独立CI。一般事务分组及失败证据归011，既有Role管理门禁的准备复用归006。当前源码IAM32/Audit19，未分配发布revision；UI与完整009尚未验收。S2/S3详细设计已固定`6fa39fda`，S2a首个内部TOTP/恢复码域基础片已实现并通过本地聚焦检查；完整S2及S3/S4未实施验收。下述HTTP、持久化和交付分工不是已开放API或已完成协作；材料托管、恢复与通知的发布前置尚未全部确认。
- 依赖：003、005、007。
- Owner：IAM 身份/凭据/会话治理，Audit evidence。

## 需求

| ID | 行为 |
| --- | --- |
| IAM-SEC-01 | Account 密码长度/复杂度/历史/到期/失败锁定规则，确定上限和错误文案 |
| IAM-SEC-02 | 会话列表、当前设备、单设备撤销、其他设备下线、idle/absolute expiry |
| IAM-SEC-03 | 本地可验的 TOTP MFA 绑定/挑战/解绑、恢复材料、敏感操作 step-up |
| IAM-SEC-04 | 登录/操作保护、可信来源网络规则、防枚举、速率限制 |
| IAM-SEC-05 | 闲置 User/Key 处理明确关闭哪项能力，恢复不隐式复活凭据 |
| IAM-SEC-06 | 权限来源、拒绝 reason/request ID、凭据活跃度、安全报告和下载 |
| IAM-SEC-07 | 账号恢复与日常凭据管理分界，平台离线恢复不能在线授予 |

## 详细设计

### S1：本人登录会话自管理

最小企业目标是：同一User在两个真实客户端登录，从其中一个有效登录会话查看本人的当前登录会话，准确辨认当前会话，结束另一会话；另一IAM副本在下一次受保护请求立即拒绝被结束的会话，当前会话不受影响，审计及原业务资源保留。这是IAM-SEC-02的首片，不以它替代其他设备一键下线、idle expiry、密码规则、MFA或完整009验收。

仍只有现有`Session`，复用其真实ID、Account/USER归属、credential generation、发行/到期和不可逆撤销状态。不新增Device实体、SessionStore、缓存权威或可换取登录凭据的包装。一个会话不等于一台物理设备；多个浏览器标签页可能共用同一会话，一台设备也可能多次登录。UI中的“当前”仅指本次有效bearer绑定的Session，不能由User-Agent、IP或caller提交的ID判断。没有真实采集的客户端、来源、最近活动或认证强度时不展示推测值，不声称“在线”。

仅当前有效LOGIN_SESSION认证的USER可以管理自己的会话，包括其实际RootIdentity关系所指的原USER；该关系不授予另一账号或平台权限。RoleSession、AccessKey、ServiceIdentity及其他用户均不进入本入口。自管理是类似改密/退出的身份内在能力，不借`iam.session.revoke`为普通User授予管理员跨用户权限，也不伪造USER业务Allow。既有管理员撤销路由及其PDP保持独立。

强制改密的当前有效临时会话允许这组只缩减本人访问面的安全补救，但仍不得访问业务、修改权限或清除forced-change。结束其他会话不改变密码、generation、must-change标志、策略或RootIdentity。NULL/失配generation、已撤销/到期的caller、停用User或暂停Account均失败关闭，不能为自管理“恢复”认证资格。原改密的默认撤销其他、forced强撤其他及锁内保留当前会话语义不变；当前会话的退出仍走既有logout。

#### 封闭入口

下列请求/响应及SQL形状已在S1独立编辑窗口确认，随同一实现切片验证；本节不是运行验收证据。007的固定`644fff09`已完成独立CI及交接，消费者无需等待S1。

| 入口 | 行为与边界 |
| --- | --- |
| `GET /v1/auth/sessions?after=...` | 本人当前有效登录会话，固定100项和稳定ID seek；响应`SessionList{apiVersion,kind,accountId,userId,currentSessionId,observedAt,items,nextCursor?}`。Account、User、当前Session均来自bearer；items复用现有Session，不借本片修改其已有wire字段。不接受user/account/session selector、任意排序或页大小 |
| `POST /v1/auth/sessions/{sessionId}:revoke` | 复用严格`RevokeSessionRequest{requestId}`，目标必须是同Account、同USER的另一登录会话；响应`RevokeOwnSessionResponse{outcome,revocation}`，outcome准确为APPLIED或EQUAL_REPLAY，revocation复用原非秘密Revocation。目标为当前Session时明确冲突，使用既有logout，不生成两套当前退出语义 |

目录不列已撤销、实际已到期或generation不再有效的历史记录；“当前有效会话”只表示认证资格，不代表它具有任何业务权限。历史记录仍在原Session和Audit owner保存，不在此增加管理员目录/回收站。返回的sessionId是资源引用，不是bearer；绝不返回lookup/verification digest、密码hash、credential generation内部证据或可兑换凭据。该目录不证明用户的RoleSession/AccessKey已退出。

items必须是非NULL数组、至多100项、同Account/USER、ID严格递增且无重复；每项均在observedAt时ACTIVE、未撤销且未到期。分页后的items不一定包含currentSessionId，不能据此判断当前会话已消失。只有实际读到第101条时才提供nextCursor，不凭固定页长猜测后续；末页可以因并发失效而变空。

分页复用原opaque cursor和独立安装key，增加封闭的本人Session目录绑定，不创造可由caller指定的通用purpose。每页先重新验证当前身份，再核对安装、Account/USER、当前Session、凭据代际、准确查询与固定页预算；旧游标不能跨用户、账号、登录会话或安全状态使用。继续使用数据库时间，游标不得越过当前会话的有效期。目录不是冻结快照；并发登录/退出与自然到期可改变后续页，不借游标维持已失效的身份或旧权限。

#### 事务、历史与并发

撤销目标的不可变归属必须在锁内验证；仅在事务外查出同USER不够。顺序沿现有Account→USER→凭据→Session；同USER命令共用真实principal屏障，多个Session按稳定ID取锁。当前bearer的真实session/generation、Account/User状态及目标资格在锁内重检；取得锁后以数据库当前时钟重新判断caller和target到期，不能沿用等待前的事务时间。原事实时间与canonical不因此改写。SERIALIZABLE重试重读整个身份，不能保留等待前的旧认证结果。缺失、跨用户、跨账号、Role/Key替换均无效果，也不泄露另一个目标是否存在。

精确重放绑定原USER、实际调用Session、目标Session、requestId和封闭输入承诺，只返回原完成信息，不再次更新状态或补第二个事实。已由其他意图、logout、改密/reset/recover撤销的目标不冒充本命令成功；已到期目标同样不是新的可执行撤销。更换bearer后复用相同requestId不能把原“保留当前、结束另一会话”的意图换成另一次操作。未知回包保留原意图；当前认证资格已经失效时不能凭旧请求ID取得新许可，需正常重新登录并由用户明确发起新意图。

先验证当前caller，再读取其Account/USER下的完成关联。准确完成优先于目标今天的到期状态，EQUAL_REPLAY仍返回原Revocation；它不表示目标今天仍可登录。只有原意图尚未完成时，才按当前目标资格执行新撤销。输入承诺使用本人撤销的封闭目的，包含实际actor Session、目标Session与requestId，不与logout或管理员命令互认。保留原Session的日常改密不把其旧游标变有效；仍有效的同一Session查询自己的原完成只读取历史，不重做副作用。

沿用`iam.session.revoked`的原租户事实含义，真实USER为actor、被结束的Session为target；自管理不填写伪造iamDecisionId。状态、不可变输入/完成关联及outbox必须同事务，旧canonical/hash和管理员事实保持。原终态和outbox没有原调用Session到请求意图的唯一绑定，不能把旧函数的`applied=false`当成准确重放；原Session SQL owner现以`session_self_revocations`保存仅用于本人撤销另一会话的不可变完成关联。它以Account/USER/requestId唯一，绑定真实caller/target Session、输入承诺、原Revocation与outbox事件，准确约束同USER归属和一个目标的一次完成。它不是可复用许可或第二个Session模型，不新增通用receipt服务。API/worker没有直接表读写权限；真实FK、强制RLS、不可变/禁止truncate及同事务完整性由数据库验证。当前记录、claim、service identity或K2 key证据都不因本设计而改变。

#### SQL形状与所有权

复用`000001_authority`的Session拥有者，不新增迁移目录或平行撤销器。当前`lookup_session(text)`保持原23个输出列的顺序，仅在末尾追加内部`credential_generation bigint`，供本人游标绑定；旧NULL代际行继续不可认证，不回填。新增`list_own_sessions(tenant text,user text,current_session text,after text)`只返回`id/status/issued_at/expires_at`四列，固定按ID取至多101条以生成100项页面，无秘密或caller可选limit。它在同一权威快照中核对当前Session和同User有效代际，适配器复用真实已认证Account/User构造原Session投影。

原`revoke_session(text,text,text,text,jsonb)`已在末尾追加真实`actor_session_id text`，返回仍为`resource_version/revoked_at/applied`。logout、管理员撤销与本人入口均传实际bearer对应的Session；删除旧五参函数并验证不存在，不留未重检当前会话的旁路。管理员分支仍要求原精确Decision且拒绝forced-change，logout仍只结束调用会话；无Decision的本人另一会话分支要求上述精确完成关联。管理员和目标不同User时按稳定ID同时锁定双方principal，再检查当前actor和目标，不能倒置原密码/状态/恢复锁序。旧logout或管理员的已撤销结果不是本人新意图的EQUAL_REPLAY。

本片冻结的源码版本为IAM31/Audit18，对应真实IAM函数/表/ACL/readiness变化。record9/contract4、evidence5、claim7、lookup_service5及旧canonical不变。此片不分配最终release contractRevision、不改发布profile；安装owner在实际消费者组合中另行冻结和验收，源码数字增加不产生升级许可。

结束登录会话不会删除资源、改策略、停应用或撤销独立AccessKey。以该登录会话为来源的RoleSession继续按006现有来源有效性约束关闭，不能另造“同时撤销所有凭据”的伪承诺；已接受Operation、后台任务和长连接是否继续沿原产品边界，不声称实现推送式实时断连。

#### S1验收与交付边界

并发按数据库实际先提交的一方验收，不能只证明某一种偶然调用顺序：

| 交错 | 必须成立的结果 |
| --- | --- |
| 同USER的A结束B、B结束A | 首个撤销成功后，后一个命令的caller已无效，不能再结束幸存会话；只有一个本人成功事实 |
| A结束B与A退出 | 退出先提交则另一命令不能使用失效A；本人撤销先提交则后续正常退出A，两个不同事实各一次 |
| A结束B与保留其他会话的日常改密 | 改密先提交时以锁内当前代际判定；撤销先提交时B不得随代际推进复活，A仍遵循原保留规则 |
| A结束B与默认/强制改密、reset、recover | 先结束的目标不冒充新意图成功；当前caller被撤销后旧命令拒绝，无部分完成或成功outbox |
| A结束B与User/Account停用 | 停用先提交后不能继续使用旧认证快照；撤销先提交的原事实仍可投递，资源/Operation不被删除或终止 |
| 等待真实锁期间caller或target到期 | caller已到期则无权执行；只有target到期则新意图冲突，不产生撤销或成功事实。独立静默数据库验证原事务未借序列化重试取得新时间 |
| 提交后回包丢失、重启再重放 | 原有效A只能取回同一完成；变体、换caller或新意图操作已结束目标均不能产生第二次完成 |

- 两Account、每个至少两个USER、同名登录与两个实际IAM副本：目录只含本人，当前标识来自实际bearer，另一会话结束后跨副本新请求拒绝，当前会话继续有效；普通无业务策略的User和forced-change会话均有上述最窄自管理能力，但仍不能访问业务。
- 真实101条会话的分页、时间到期、错误/跨用户/跨账号/跨Session cursor、伪current/user/account字段、Role/Key/SERVICE凭据与NULL/错误generation全部按当前契约拒绝。不能用字符串形状或mock Session证明归属。
- 撤销、准确重放、变体/新意图操作已撤销目标；并发相互撤销、logout、三种改密选项、reset、原root/platform恢复及Account/User停用，分别证明双方先提交的状态与失败无部分效果。forced-change的只减权补救不能使旧临时会话升级。
- 末端outbox失败整笔回滚；真正提交后丢失响应、当前认证随后撤销、重启与schema等值重放不重做原意图。Audit延迟投递保留原事实/归属/hash，不按当前登录资格重写历史。
- 真实PG18、受限登录/RLS与SQL越权、原unit/architecture/security/进程门禁及精确SHA独立CI归现有owner。UI全部交UX/UI工程师，在固定契约就绪后再接入并独立做浏览器闭环，不由本片替代。

沿用`api/iam/v1`契约/生成测试、`authority/cursor_test.go`、`identityaccess/service_test.go`和`nethttp/handler_test.go`证明封闭输入/响应、凭据分离、游标绑定及用例控制流。真实SQL/RLS、撤销竞争与旧函数消失归既有`integration/http_postgres_test.go`的附件/会话owner；其中锁内真实到期使用独立静默数据库，明确检查没有序列化重试或死锁掩盖原时间检查。跨副本、原TCP故障、Audit失联及重启归`test/authorityprocess/process_e2e_test.go`，不增加平行测试框架。先聚焦再累计回归，不修改现有单项时间、密码成本或规模来取得通过。保留数据验证使用实际固定`644fff09`的IAM30 executable/schema创建身份、正常/forced/已撤销会话，再验证IAM31的精确新形状、原事实和重启；NULL代际只作为明确的负向损坏样本，不伪称该旧程序发行。此片不要求为每个未发布中间schema维持永久升级链，也不证明跨release准入。

S1仅在本分支实施，release contractRevision不提前分配。不变更Phase3的PaaS/Audit查询PEP、edge解析、NorthboundOrigin/APISIX、source release Profile或安装工作，也不要求其等待S1。固定`c2fbd9e3`中S1所需会话类型/校验/生成器、IAM PostgreSQL、authentication/management与cursor和本分支固定`644fff09`相同；只核对固定对象，不导入其PaaS6、发布profile或文档。最终交接必须有本片精确SHA、独立CI及真实PG18保留数据/并发证据。

#### S1当前运行证据

2026-09-18在本任务干净Git导出上验证；真实PG18限1CPU/1GiB，Linux Go1.26.5 runner限2CPU/1536MiB、GOMAXPROCS=2，数据库门禁串行`-race -p 1`。不改生产密码成本、最小60秒Session TTL或单项时限。

| 门禁 | 当前结果与范围 |
| --- | --- |
| `TestIAMOwnSessionPostgres` | 91.88s通过；本人/跨账号/载体/101项分页、RLS及函数形状、末端失败原子性、22种已控制先后顺序的会话/密码/状态/原root与平台恢复竞争、真实自然到期与历史重放 |
| `TestIAMOwnSessionExpiryPostgres` | 62.28s通过；两个请求分别在等待真实principal锁期间caller或target到期，原事务无序列化重试/死锁，分别拒绝且无完成/状态/outbox副作用 |
| `TestIAMRetainedOwnSessionProcessUpgrade` | 10.25s通过；真实`644fff09` IAM30产生正常/forced/已撤销会话，IAM31双次迁移、原六字段bootstrap receipt、NULL代际拒绝、旧canonical/proof、准确本人完成及重启保持 |
| `TestIndependentIAMAuditAndPaaSProcesses` | 56.63s通过；受限实际数据库登录、两个IAM与Audit/PaaS/dispatcher、提交后真正断开TCP、重启/准确重放、Audit延迟投递/原链、PaaS资源及Operation归属保持 |
| 既有IAM累计回归 | 同一最终代码另用新数据库，策略权威164.44s、附件/会话竞争105.14s、AccessKey92.43s、账号HTTP142.97s、本地凭据恢复30.20s全部通过，包合计536.266s；保留原密码成本、所有场景和各自时限 |
| Role/STS累计回归 | `TestIAMRoleAndManagementReferencesPostgres`七个独立数据库全部通过，343.05s；保留原角色写入、承担/退出、发现、管理员会话管理、业务授权、安全竞争和私有引用门禁 |
| Audit/PaaS累计回归 | 双authority数据库及旧tenant记录保留升级包4.773s、Audit HTTP包2.124s、PaaS数据库包1.900s通过；审计测试遗漏的IAM30断言已替换为实际IAM31，初始化前/后ready状态、受限登录、RLS、历史及租约fence断言保留，没有Audit生产改动 |
| 既有固定前驱 | 原Role capability、Role authority和Policy三个真实前驱程序门禁分别9.68s/18.42s/22.10s通过，包51.231s；原策略/信任/历史/撤销不被新Session函数形状改写，不构成release兼容许可 |
| 全仓检查 | Windows Go1.26.3干净导出的全仓race（含architecture）、vet、模块校验、生成文件集合/字节一致、Linux amd64构建通过；不把通用Linux容器缺少真实machine-id导致的旧本机安装adapter失败称为整仓Linux通过 |
| 精确固定源码独立CI | `3080922f6ae1871f1c351d5ee30f03551fc3c605`的[Verification 35301228478](https://github.com/xiak/matrix/actions/runs/35301228478)，2026-09-18经GitHub API核实精确SHA，go、node-process、authority-storage、authority-runtime、authority-process全部completed/success；两个数据库lane按既有20分钟预算串行，汇总检查未替代实际运行 |

到期门禁有实际反例：仅恢复等待前`transaction_timestamp()`判定的SQL时，已到期caller仍返回200并执行撤销。原多写入矩阵未可靠识别这一错误，已由静默数据库、真实时间及无重试断言替换该到期证明；锁后使用`clock_timestamp()`的最终实现通过。原事实时间和Audit canonical没有重写。

既有附件/会话并发矩阵曾在本机原120秒预算超时，固定`644fff09`在同一限额中也出现120.07s失败。当前代码的CPU采样诊断在原预算100.31s通过，采样主要为Argon2与race检查、该次无CPU限流；这不证明先前超时的全部原因已解决，不降低成本、删场景或延长预算。其后同一最终代码的新数据库累计回归105.14s及上述固定源码独立CI均通过；后继成功不回填旧失败。以上仅S1后端证据，不证明UI、安装/profile兼容、容量/HA或完整009已验收。

### S1b：一键结束本人其他登录会话

本片生产实现固定`159bb302fed89161c4b60afeb4a6f41f9bd99820`，连同一般事务分组及Role准备修正后的累计固定`7cf857bba48eb5d7da487162c43e8f52534db133`已通过本地及五项独立CI，接受IAM-SEC-02的后端批量自助减权切片；不代替S2–S4、UI或完整009。已验证并推送的`3080922f`及受限容量回归`b6f57d01`保留为先前回滚点。Phase3与UX/UI owner均确认本片IAM/Audit公共窗口无冲突；消费者只按固定源对齐，UI仍按其既定优先级独立验收。

唯一新增入口为`POST /v1/auth/sessions:revoke-others`，严格复用`RevokeSessionRequest{requestId}`。当前Account、USER和保留的Session只从真实LOGIN_SESSION bearer取得；原root与forced-change自助减权可用，Role/AccessKey/ServiceIdentity、selector、目标列表和caller提供的当前Session均拒绝。不新增PDP权限或管理员能力。本人逐项撤销、目录和logout保持原契约。

响应`RevokeOtherSessionsResponse`含`apiVersion`、`kind=OtherSessionsRevocation`、`outcome=APPLIED|EQUAL_REPLAY`、`accountId/userId/currentSessionId/requestId`、`revokedCount`和`completedAt`。数量为实际原子终止的会话数，允许零；时间与数量在精确重放时保持原值。响应不返回目标秘密或无界Session数组，也不宣称物理设备、全部凭据或推送式断连。

复用Account→稳定USER→credential→稳定Session锁序及SERIALIZABLE重试；锁后以数据库当前时钟再次检查actor有效性。仅结束同USER、非当前、未撤销、未到期且与当前密码代际一致的登录Session。并发新登录按事务序列化次序解释，不用发行时间猜测其所属意图；一次命令只执行原一致快照中的集合，后继新登录不因原命令重放被终止。密码、generation、must-change、User/Account状态、策略、Key和业务资源均不变。派生Role、已接受Operation与长连接仍沿原拥有者边界。

原单目标`session_self_revocations`仍只证明逐项命令，不能把循环调用或其目标唯一键当成批量完成。原Session SQL owner新增目的限定的`session_other_revocations`完成关系及`session_other_revocation_targets`终态证据关系：完成以Account/USER/requestId唯一，绑定实际actor Session、封闭输入摘要、原时间/数量及单一outbox事件；目标关系绑定同Account/USER的实际Session、终态resourceVersion和完成归属。两者均强制RLS、不可变、不可truncate、受限角色无直接读写权限；FK与延迟完整性校验保证目标终态、准确数量和原事实一致。零目标也有完成和事实，避免网络重试误伤之后的新会话。不新增通用receipt服务、第二Session模型或Session epoch。

先重新认证并锁内验证actor，再读取该目的的原完成；只有相同USER、actor Session和输入承诺返回EQUAL_REPLAY。换caller重用requestId冲突；已失效caller不能通过原完成取得资格。新意图正常观察当时集合。末端写入/超时失败全部回滚，不能返回部分成功；数据库查询与原请求期限不放宽，也不静默截取前100项。

单一新增tenant事实为`iam.session.others-revoked`：source IAM、actor实际USER、target PRINCIPAL且ID等于actor、result SUCCEEDED；不允许decision、operation、Key/Role/SYSTEM actor、installation scope或target.tenantId。事件摘要仅绑定本封闭请求，目标集合和数量由IAM同事务不可变完成证据证明；IAM-source producer仍验证原已提交outbox，后续停用不丢失历史投递。零目标事实表示该意图已完成，不伪称结束了某个不存在的Session。旧事件canonical/hash、lookup_session24、lookup_service5、claim7、record9/contract4及evidence5不变。

新增`iam.revoke_other_sessions(text,text,text,jsonb)`返回`revoked_count bigint/completed_at timestamptz/applied boolean`，仅原API数据库角色可执行；原六参单项函数不变。候选源码IAM32/Audit19反映真实新表/函数和封闭Audit动作；readiness/verify核对形状、ACL和约束，不能只比较数字。产品Profile和发布revision不变，安装组合另验，不授跨版本发布许可。

验收沿既有contract、identityaccess、nethttp、PostgreSQL和authorityprocess owner：两账号/同名User及多真实会话、超过一页的完整集合、当前保留/其他主体不变；零目标/重复/换caller/新登录后重放；forced/root与拒绝载体；并发互相批量撤销、单项/logout/change/reset/recover和账号/成员状态的双向次序；锁内真实到期、末端故障回滚、真正提交后断链及重启/等值schema不重做；受限SQL/RLS/伪造目标和数量/事实拒绝，原Audit链及延迟历史投递。不得把默认无DSN的跳过、mock或单项旧门禁算成本片真实验收。保留数据以本片固定前驱`3080922f`的真实Session及单项完成为起点，不遍历所有未发布schema。UI及完整发布仍独立验收。

#### S1b当前运行证据

2026-09-18，下列本地源码门禁及累计回归已通过；累计固定`7cf857bba48eb5d7da487162c43e8f52534db133`的[Verification35324569376](https://github.com/xiak/matrix/actions/runs/35324569376)也已核对精确SHA及五项全部completed/success。实际日志确认本人Session三项package226.359s、保留数据及独立进程package148.830s均通过；此前失败及累计修正归[011运行约束](./FEAT-IAM-011-acceptance.md#运行约束)，后续通过不回填旧失败。以下本地真实PG18.4固定镜像限1CPU/1GiB/PIDs192，Linux Go1.26.5 runner限2CPU/1536MiB/PIDs256、GOMAXPROCS=2、GOMEMLIMIT=512MiB，串行`-race -p 1`；单项期限与生产密码成本未放宽。所有本地门禁终态成功、数据库无客户端且测试库已逐项释放后，已清理本轮专属临时PG及空网络；未操作其他任务资源。

| 门禁 | 已观察到的结果与范围 |
| --- | --- |
| `TestIAMOwnSessionBulkPostgres` | 76.89s；真实101个有效目标、NULL/错误代际排除、当前/其他用户/其他账号保持；零目标与后继新登录的精确重放、末端回滚、强制改密与原root；27组受控交错包含相互批量、单项、退出、三种改密、reset、停用、原root/平台恢复、同意图竞争及并发新登录。私有表/RLS、不可变目标、伪造数量/actor/target/digest/时间/决定/跨账号caller均被实际约束拒绝且无部分事实。 |
| `TestIAMOwnSessionPostgres` | 69.28s；提取复用的并发门禁仍完整执行原逐项撤销、分页、自然到期、22组安全交错及平台恢复；没有用批量场景替换旧断言。 |
| `TestIAMOwnSessionExpiryPostgres` | 最终61.83s；四个原事务在等待真实principal锁期间经历相同真实60秒到期：单项caller/target与批量caller到期均拒绝，仍有效caller的批量意图则完成空集，不计入已到期target、不修改Session。准确零目标完成及单一事实保持；无序列化重试或死锁替代锁后时钟证明，期限和最小会话寿命未改。 |
| `TestIAMRetainedOwnSessionProcessUpgrade` | 17.02s；实际固定`3080922f`的IAM31程序产生正常/forced/已撤销/NULL负向会话及原单项完成，IAM32双次迁移、六字段bootstrap receipt、原会话/附件/凭据和canonical/proof保持；新批量完成在重启后只精确重放，后继登录不被终止。不是跨release准入证明。 |
| `TestIndependentIAMAuditAndPaaSProcesses` | 59.14s；实际受限登录、两IAM及Audit/PaaS/dispatcher，批量提交后真正丢失TCP回包、重启、当前保留/被结束会话的下一业务请求拒绝；来源用户停用后历史仍投递一次，完整tenant链及应用/Operation归属保持。真实Role凭据不能调用该USER入口。 |
| Audit与PaaS聚焦回归 | 新闭合事实的双authority/SQL错误actor与目标约束3.56s、旧tenant记录保留0.15s、Audit HTTP1.08s、PaaS数据库0.84s通过。 |
| IAM累计回归 | 策略存储包153.432s、策略关联/会话96.72s、AccessKey81.11s、IAM HTTP与账号/凭据生命周期125.46s、平台本地凭据恢复26.56s通过；保留原密码成本、场景及各自期限。 |
| Role累计回归 | 角色管理35.47s、发行71.97s、发现11.34s、会话管理97.50s、业务授权34.50s、私有引用11.24s通过；最终安全交错63.17s，保留原36种并增加批量结束真实Role来源Session的双向次序，另保留交叠组删除。新场景证明当前caller保留、来源登录和Role下一请求均拒绝、先提交决定/事实准确且历史证明继续有效。 |
| 固定前驱累计保留数据 | 既有实际旧策略程序19.04s、Role能力程序9.71s、Role授权程序18.20s通过。仅证明所属FEAT明确的数据保留边界，不将开发schema序号自动纳入发布兼容。 |
| 静态及全仓检查 | Windows Go1.26.3干净导出的全仓race/architecture、vet、模块校验、API生成字节一致和Linux amd64构建通过。CI的10个既有Bash代码块、Session测试选择及原限额已核对，不把本机缺少YAML解析器称为解析通过。 |

失败边界保持明确：一轮新负向fixture将JSON字节按simple protocol传成bytea，先得到22P02，未触达期望的完整性约束；已改为真实JSON文本，随后同一攻击矩阵按准确23514/23503通过，未放宽生产校验。一次累计回归的建库准备因旧临时库累积填满本任务256MiB临时盘而中止；当时没有新的门禁在运行，不能计为通过。仅移除该已停止的自有临时实例，后续保持同限额、串行独立建库，并在每项完成且无连接后释放该项库；不提高磁盘/CPU/内存/期限，不操作共享引擎或其他任务资源。

### S2：本地TOTP、认证挑战与恢复

本节是可评审的详细设计稿，不是已存在接口或已开放公共实现窗口；不分配schema/profile/revision，也不作为S1或007消费者集成前置。最小完整路径是：本人验证密码并绑定真实TOTP认证器，保存一次性恢复材料，之后密码正确仍须完成TOTP才能得到登录Session；丢失认证器时经受限恢复重新绑定，再正常登录。最终还需覆盖RootIdentity、敏感操作再次认证及账号级强制要求，不能用普通User的可选绑定代替整个IAM-SEC-03。

本稿根据2026-09-20确认的设计方向细化，只增加S3所列两个安全配置授权动作的设计，不顺带增加管理员重置他人认证器的权限、客服系统、全局身份、组级安全策略语言、Refresh Token或新身份服务。现有密码恢复权限不扩展为MFA恢复权。UI交UX/UI owner，本文只约束数据、行为和交互结果；不另写一份平行页面设计或路线图。

固定`644fff09`中，Login在密码验证后直接发行Session，凭据目的仅有SESSION/SERVICE/ROLE_SESSION；尚无MFA挑战、因子状态、OTP消费或认证强度证据。现有密码重置、租户root恢复和平台离线恢复都不能因此被解释为MFA恢复。用户无手机号、邮件或微信也应能使用本地TOTP；短信、外部风险引擎和Passkey仍按012的前置处理。

#### S2a当前实施边界

用户已要求按本稿继续目标。先在既有`authority`域实现固定TOTP参数的秘密生成/纯校验和恢复码的用途/主体绑定验证；不开放MFA配置、挑战HTTP入口或改动原LoginResponse，不修改安装、UI、SQL、schema或发布profile。两项security-settings动作仍待完整S2c权限切片，不随本片提前授予。

`totp.go`及其测试是现有认证域内新增的算法/时间窗边界：当前password/opaque credential拥有者没有此边界，不建立新的service、store或通用因子框架。秘密使用原`iamv1.Secret`，生成复用原`CredentialIssuer`的受控熵源；恢复码生成和单向验证继续由现有`credential.go`/测试拥有。参数固定为20字节种子、HMAC-SHA1、6位ASCII码、30秒、当前前后各一步；不增加可由请求选择的算法或窗口。

TOTP校验只返回须在原子事务内消费的准确时间步，不持久化消费，不发行身份凭据。调用方未来必须在权威锁下传入数据库时刻和原因子已消费水位，并在同一成功事务推进；`-1`仅表示已证明从未消费，不能用于缺失/未知行。恢复码验证同样只证明持有原主体/批次下的材料，不证明其未消费、恢复资格或当前权限。该基础片的纯函数通过不等于跨副本一次性消费、真实MFA、托管、通知或恢复已验收。

本片验收使用RFC4226/6238向量、独立Node标准HMAC生成的边界/相邻碰撞向量、严格输入与秘密输出门禁、正常熵及中断熵，以及既有域/API回归、race/vet/architecture。真实PG、多副本、安装恢复和浏览器门禁归后继完整流程，不能以本片替代。

恢复码内部材料格式固定`mrc1.`加16随机字节的canonical unpadded Base64URL；不是通用bearer类型。单向验证域包含独立目的、封存installation、真实Account/USER、不可变批次/码ID；每段ID沿原严格校验且以NUL分界，秘密使用固定16字节原始值。不同用途、安装、主体、批次或码身份不能互用。该摘要不写入Audit，不可解密回显；只返回验证成功不证明码未消费。

本地聚焦证据：六个TOTP/恢复码行为测试通过race；原authority/API累计race及vet通过；20秒、最多2 worker的TOTP输入fuzz完成83581次执行且无失败。独立Node HMAC向量包括epoch、2038、最大支持日期和910737/910738相邻步的相同码，恢复码SHA256也按独立实现核对；均为公开合成材料，不是用户凭据或真实认证器浏览器验收。秘密仍由原Secret拒绝普通JSON/格式化输出。尚未据此声称材料托管、一次性SQL消费或MFA启用。

2026-09-20本片在干净源码导出、Go1.26.3 Windows/amd64下完成全仓默认`-race -p 2 -count=1`（含architecture）、vet和模块校验，GOMAXPROCS=2/GOMEMLIMIT=512MiB；Linux/amd64构建也通过。未改API生成物、现有SQL或对外运行路径，未启动PG/容器；默认因缺少DSN/运行环境而SKIP的门禁不计为真实运行证据。精确提交的独立CI仍需确认后才记为通过。

#### 不同状态不能混用

| 状态或材料 | 责任与限制 |
| --- | --- |
| Account的`security-settings` | 同Account单份有版本的安全配置；保存日常User的密码/MFA/会话要求，不表示某个人已经绑定因子，也不是授权Policy |
| USER的TOTP认证器 | 真实凭据，绑定Account/USER及不可重用因子身份；有受保护种子、当前绑定修订、终态和已消费时间步。不是新Principal、Role或物理Device |
| 未完成的认证挑战 | 保存已经验证的阶段、闭合目的、实际主体/代际、过期、尝试预算和消费状态；不能访问业务、承担角色或充当Session。它的随机持有凭据与现有三类凭据分域，不能放进Session表假装“低权限登录” |
| 登录Session的认证事实 | 只在实际完成所需因子后记录方法、认证时刻和对应权威修订；用户后来启用MFA，不能将原密码Session倒填成双因子。历史缺字段不猜测MFA已完成 |
| 恢复材料 | 一次性高熵秘密及不可变批次归属；用于受限重新绑定，不是主账号转让、密码替代或可缓存业务许可 |

仍在现有IAM进程内由身份用例组织事务，纯TOTP校验与存储副作用分开；不先拆Identity/STS新服务，不增加泛化ChallengeStore/SessionStore。挑战确有独立的期限、消费和权限边界，只有其接口/存储形状在实现窗口冻结后才增加必要模型。

#### 工程责任与运行权限

| Owner | 交付契约 | 不获得的权限 |
| --- | --- | --- |
| IAM | 状态机、本人/受保护身份校验、加密上下文、尝试预算、一次性消费、Session/Role有效性、原子事实与最小通知意图 | 不能读取安装私钥、直接恢复数据库或跨库查询业务资源 |
| 原installation交付owner | 独立材料生成/封存/分发、文件与挂载隔离、启动检查、升级准入、受支持备份恢复和恢复期间访问隔离 | 开发/执行安装程序不等于取得在线租户安全配置或因子管理权限 |
| Audit | 新事实的封闭actor/action/target与历史proof验证；旧canonical、租户链和投递归属保持 | 不解密因子，不把当前登录资格用于重新授权历史事实 |
| 通知owner（012的真实通道，尚待确认） | 已验证接收人、受限投递、重试/受理证据及失败告警 | 联系人不是Principal，投递身份不获得租户业务读写或认证器恢复权 |
| UX/UI owner | 真实绑定/挑战/恢复/设置交互、秘密一次性展示及失败反馈 | 不计算有效权限、不缓存秘密、不靠隐藏按钮保护入口 |

上述是协作交付物，不声称相关任务已接受新工作。IAM和installation共同证明材料错误时关闭、两副本一致、真实备份恢复不复活认证资格及原primary封存关系保持。保留原主账号身份不表示其密码、认证器或临时交付凭据永不轮换；永久身份关系与可撤销凭据分开。

#### 权威状态与最小数据形状

下表为拟定持久边界及关键字段，不是已迁移表。复用IAM现有SQL/事务owner；只有独立生命周期或唯一性约束所需的数据才落独立关系，不为每个名词生成repository/interface。

| 状态 | 最小持久信息及约束 |
| --- | --- |
| Account安全配置 | `accountId/resourceVersion/mfa.requiredForUsers`，后续密码与会话字段归S3；另有只增不减的登录资格修订。配置版本用于CAS，资格修订用于永久淘汰被收紧规则否定的旧Session，不能混用 |
| USER安全状态 | 原Account/USER、`enrollmentState=NEVER_BOUND\|BOUND\|REMOVED\|RECOVERY_REQUIRED`、单调`factorRevision`、当前factorId；是原USER的认证状态，不是第二主体。缺行/损坏不是NEVER_BOUND，只有新建或经过证明的迁移可建立该资格；REMOVED必须关联本人合法解绑的原子完成，不从因子缺行推断 |
| TOTP因子 | factorId、原Account/USER、`PENDING\|ACTIVE\|REVOKED`、格式/keyId/nonce/ciphertext、创建/确认/终止时间及最后消费时间步；每USER至多一个ACTIVE和一个未到期PENDING。替换生成新ID，REVOKED不原地启用；过期待确认行不能变ACTIVE |
| AuthenticationChallenge | challengeId、目的`LOGIN\|ENROLLMENT\|RECOVERY\|STEP_UP`、实际Account/USER、密码代际、factor/settings修订、已验证阶段、绝对期限、剩余额度、秘密lookup/verification digest。STEP_UP另绑定实际Session、固定操作、目标、输入承诺和预期版本 |
| Challenge终态 | `PENDING → CONSUMED\|CANCELLED\|EXPIRED`；只有STEP_UP允许`PENDING → PROVED → CONSUMED`。PROVED仍有期限，不是Session；由具体命令消费。不可回到PENDING或延长期限 |
| 恢复码批次 | Account/USER/batchId、每码随机公共引用及单向验证值、发行/消费/整批终止信息；默认候选10条、每条128位随机秘密，不能按用户名/时间派生或可解密回显 |
| Session认证事实 | 在原Session追加真实`authenticationMethods/authenticatedAt`和内部factor/settings资格修订；只在实际认证时写入。Role使用原来源Session约束，不复制一份可独立放行的MFA布尔值 |
| 尝试与命令完成 | S3的有界尝试保留/结果，及本目的不可变命令关联；绑定真实actor或challenge、requestId、非秘密输入、原完成和outbox。不是通用receipt服务，不向调用方发行新的授权能力 |

因子/恢复批次/challenge/完成关系通过复合外键绑定同Account和USER；强制RLS、禁止普通API/worker直接DML、只授目的限定函数。唯一ACTIVE、终态不可逆、一次消费、单调修订及成功事实关联需要数据库约束/锁内检查，不能只依赖Go预查。挑战、尝试的临时行按期限与有界保留规则清理；删除临时行不能清除USER共享预算或历史完成事实。

#### 登录、设置与恢复状态机

```text
realm解析 + 有界密码核对
  ├─ 错误/停用/未知 → 同一安全错误；不发行任何身份凭据
  ├─ 无MFA要求且NEVER_BOUND或合法REMOVED → 原登录Session路径
  ├─ 已绑定 → LOGIN挑战 → 新鲜TOTP
  │                       ├─ 必须改密 → 仅改密阶段 → 全部旧会话/挑战失效 → 重新登录
  │                       └─ 无改密要求 → 消费挑战与OTP → 新Session
  └─ 要求MFA且证明NEVER_BOUND或合法REMOVED → ENROLLMENT挑战
                          → 必要初始改密后重新开始 → 确认新因子
                          → 结束设置挑战 → 密码 + 未消费TOTP正常登录

LOGIN挑战 + 有效恢复码
  → 原子消费恢复码、终止丢失因子及旧Session/挑战
  → 新RECOVERY挑战（只能重新绑定）
  → 确认新因子 + 新恢复批次 → 结束挑战 → 正常重新登录
```

用户主动绑定因子后，即使Account未强制MFA，后续登录仍需该因子；Account管理员将要求改为false不删除用户因子。`RECOVERY_REQUIRED`、未经合法解绑而缺因子、密文损坏或资格未知都不能进入“密码即可首次设置”。普通替换在确认前保留旧因子；合法丢失恢复在签发受限重绑挑战时终止被报告丢失的因子，两条路径不混淆。

明确允许无因子的用户，可用当前密码和原有效因子的step-up完成主动解绑：同事务终止因子/恢复批次、撤销旧会话、推进factorRevision并记录REMOVED。它保留原绑定及解绑事实，不改回NEVER_BOUND。此后无强制要求时可以密码登录并主动重新绑定；要求后来收紧时，只有原合法解绑完成仍可证明的REMOVED才可进入受限ENROLLMENT，确认时创建新因子，绝不启用旧因子。解绑与要求收紧交错时在同一Account/USER锁序下决定，不能先预查false再越过新要求。

已明确处于RECOVERY_REQUIRED且仍有可验证恢复批次的USER，在密码验证后只取得`nextStep=RECOVER`的LOGIN挑战；它不能走普通TOTP成功分支，只能用另一条未消费恢复码继续受限恢复。未知/损坏的因子记录不自动获得这项资格；没有可证明恢复批次时保持拒绝并指向人工协调的受控恢复边界，不能用页面跳转代替授权。

恢复开始和完成各是一个原子步骤：开始时消费一条码、推进因子修订、撤销旧登录及派生资格并签发新RECOVERY挑战；完成时绑定新因子、作废原批次剩余码、生成新批次并结束恢复挑战。开始后丢失回包不能退还已用码；持有另一条未使用原批次码并再次验证密码，可以开启新的受限恢复意图，同时终止旧恢复挑战。所有码都丢失时不能降级为普通reset，进入下述另行确认的身份恢复边界。

#### 拟定HTTP契约

以下仅为本设计建议，待与消费者冻结后由原`api/iam/v1`生成owner一次替换类型、OpenAPI/schema/example和客户端；不保留“密码通过即成功”的兼容旁路。现有realm仍在loginName中解析，以下路径均不接受accountId/userId作为身份selector。

| 入口 | 输入/结果及认证边界 |
| --- | --- |
| `POST /v1/auth/login` | 保留`{loginName,password,requestId}`；响应改为严格互斥联合：`outcome=AUTHENTICATED`才有原`session/credential/mustChangePassword`；`CHALLENGE_REQUIRED`只有challenge和一次性challengeCredential，绝不同时有Session |
| `POST /v1/auth/challenges/{id}:verify` | `{requestId,challengeCredential,code}`，仅LOGIN/PENDING；成功要么发行一次Session，要么进入强制改密阶段；坏码消耗已保留的预算后返回统一认证错误 |
| `POST /v1/auth/challenges/{id}:password` | `{requestId,challengeCredential,newPassword}`；仅当前被允许的强制改密阶段，复用密码业务不变量，不伪造Session。推进generation并撤销全部旧Session/挑战后只返回`REAUTHENTICATE`，不接受保留其他会话选项 |
| `POST /v1/auth/challenges/{id}:recover` | `{requestId,challengeCredential,recoveryCode}`；仅密码已验证的LOGIN挑战，原挑战消费后换独立RECOVERY挑战。不允许caller改变purpose或目标USER |
| `GET /v1/auth/authenticators` | 有效本人LOGIN_SESSION下返回因子元数据、有效要求和可进行的本人操作；不返回种子、恢复码、内部digest，不授予Account配置完整读权 |
| `POST /v1/auth/totp/enrollments` | `{requestId,expectedFactorRevision,...}`；使用本人Session与相应再次认证证明，或ENROLLMENT/RECOVERY专用challenge，严格二选一。返回enrollmentId、期限及只展示一次的provisioning内容；替换须证明旧因子或合法恢复 |
| `POST /v1/auth/totp/enrollments/{id}:confirm` | `{requestId,code,...原认证上下文}`；验证新种子对应码及原意图后原子确认、消费时间步、保存恢复批次，返回一次性恢复码和`REAUTHENTICATE`；不发行普通Session |
| `POST /v1/auth/authenticators/{id}:remove` | 本人当前Session、预期因子修订及目标限定step-up；仅有效要求允许无因子时删除，撤销相关Session与恢复批次。强制要求下删除最后因子拒绝，转向替换/恢复 |
| `POST /v1/auth/recovery-codes:regenerate` | 本人Session及该操作的强认证证明；原子终止旧批次、只展示新批次一次。不改变当前密码或取消MFA |
| `POST /v1/auth/step-up`、`POST /v1/auth/step-up/{id}:verify` | 前者根据封闭操作及真实目标签发STEP_UP挑战；后者重新验证密码和TOTP后置PROVED。操作只允许本片的因子替换/移除、恢复码重发和security-settings更新，不接受任意业务Action/目标 |

表中的省略部分只指两种已声明认证载体的严格联合，不是自由attributes：Session分支从Authorization取得actor，秘密证明用明确Secret字段；challenge分支只接受challengeId/credential，不能同时带Session换主体。公开challenge只含id、purpose、expiresAt、服务器计算的nextStep，不含凭据代际、内部规则摘要或任意跳转URL。准备首次自助绑定使用本人Session加当前密码；替换等其余操作使用目标限定step-up。challengeCredential不进入通用Bearer认证器，不可用于`/authorize`、Role、Key、业务API或本人会话目录。

所有Secret输入采用现有严格解码、脱敏和专用编码，拒绝未知/重复/NULL字段及超预算请求；相关响应`Cache-Control: no-store`，不得进入URL/query或浏览器持久存储。公开ID不是持有凭据。没有Refresh Token、新cookie协议或记住设备能力；不为此添加刷新路由。

结构错误400、未认证/错误或过期证明401、当前已认证但权限/资格不足403、版本或不同意图冲突409、全局资源预算耗尽429、数据库/必要材料不可用503；与具体用户存在性相关的抑制不返回可枚举的剩余次数或专属冷却原因。状态码沿原Problem契约冻结，不用错误文本传秘密或恢复指令。已提交但回包丢失的secret响应不重发原秘密；只能通过持有原上下文查询非秘密完成，或重新认证发起新意图。完成查询不验证新的候选OTP，更不能把不同候选值当成原成功。该只读查询的路径/保留期限随具体命令一并冻结，不新增通用receipt API。

#### 事务、锁序与失败结果

复用当前SERIALIZABLE边界，但认证失败必须是可提交的业务结果。仓储callback返回错误会回滚；因此尝试已验证失败时先提交`REJECTED`及计数，用例在提交成功后映射401。数据库异常、提交未知或必要计数不能持久化时不发行Session，也不把未知结果当作可免费重试。

1. 密码等昂贵运算前，短事务保留S3定义的单次在途额度，绑定服务器attemptId、实际USER、原密码代际及期限；只有保留已确认成功才执行计算，不在数据库锁内长时间运行Argon2。
2. 验证结果进入最终事务，沿Account/安全配置→稳定USER→密码凭据→因子/恢复批次→稳定Session→challenge/step-up/尝试完成顺序重检。现有catalog/policy锁仍按原授权命令顺序；涉及新状态的登录、密码、附件授撤与恢复路径必须统一核对顺序，不能某条路径先锁Session再回头锁因子。
3. 读取当前账号配置使用共享锁，修改使用排他锁；不是每次登录独占整个Account。配置、主体、密码代际或因子状态改变时，旧计算不能落库。锁等待后使用数据库当前时钟重查到期/OTP窗口，不沿用等待前事务时间。
4. 成功发行将OTP消费、challenge终态、Session认证事实、尝试结果及outbox一起提交；因子/设置变更同样将修订、资格屏障、不可变完成和事实一起提交。失败不产生成功Session或成功事件。
5. SERIALIZABLE重试使用同一个已保留attempt，不重新获取免费猜测次数；已完成结果只查原非秘密完成。只有可证明事务已回滚的40001/40P01才能重试事务，网络断开/提交未知不得套用该策略。

step-up通过只证明本次再次认证，不等于PDP Allow，也不提升整个Session。其PROVED状态拟最多120秒，绑定当前Session、目标操作、非秘密输入承诺及版本；设置最终写入时再检查权限、未撤销平台附件保护和实际规则，成功时一次消费。因子、密码、会话或权限先改变会让旧证明失效。没有“最近做过一次MFA，之后任意操作都跳过”的全局缓存。

#### 绑定、替换与秘密托管

已有本人登录会话的主动首次绑定需重新验证当前密码；forced-change先沿既有密码流程完成，不能通过绑定清除must-change。账号强制MFA且无可用登录会话时的首次设置，走下述独立受限挑战，不绕过要求先发普通Session。待确认种子不能用于登录；必须证明持有该种子所产生的有效码，才在同一事务确认绑定并写入事实。替换需旧因子或合法恢复证明，加上新因子有效码；新因子确认前旧绑定仍生效，确认时原子终止旧绑定，不制造密码单独登录的空窗。

种子、provisioning URI/二维码和恢复码均属秘密，只经受保护连接的专用一次性响应传输，普通JSON、HTTP请求URL/query、审计、日志、support和浏览器持久缓存不得保存。provisioning URI内的种子参数仅是一次性内容，不能导航到第三方或发送给外部二维码服务。复制/打印是用户对恢复材料的显式操作，不自动下载到共享目录。创建回包未知只查询原非秘密完成；不重新展示种子或恢复码。无法继续持有原待绑定凭据时，明确废弃该待绑定意图后重新开始，不能悄悄创建替代秘密。

TOTP验证需要可用种子，不能仅存单向摘要；数据库应存目的、安装、Account/USER、因子身份和格式绑定的认证密文，只有IAM认证路径可解封。007的AccessKey私有keyring和envelope是单用途契约，不能把TOTP伪装成AccessKey以复用材料；密码hash、cursor key及离线恢复authority同样不是种子封装密钥。可复用受保护读取、秘密脱敏及标准密码学原语，具体独立材料/私有codec与安装、备份、readiness的衔接须另行冻结；没有真实托管证据不开放启用配置。

独立材料的拟定契约为安装封存的TOTP专用keyring：`installationId/keysetRevision/activeKeyId/keys`，每个keyId对应32字节随机包装密钥；私有格式使用独立kind/version，不能将其他用途文件改名后接受。一个安装内的IAM副本使用一致的受控keyset，不是各自生成密钥；不同安装和不同用途不共用材料。具体FILE环境名、路径、owner/权限及Compose挂载由installation在实现窗口冻结，本文不提供未经运行验证的命令。

种子密文候选采用标准AES-256-GCM与随机nonce；按独立目的通过HKDF-SHA256派生记录密钥，认证上下文包含格式、封存installationId、Account/USER、不可变factorId及keyId，使用唯一无歧义编码。状态、显示名和消费时间步不是密文身份，不能每次修改都重新定义AAD。Go标准原语和[RFC5869](https://www.rfc-editor.org/rfc/rfc5869.html)只作为算法依据，私有codec及互换攻击须实测，不能复制AccessKey编码器或新增通用密钥服务。恢复码为高熵随机值，仅保存目的/主体/批次绑定的单向验证值，不用这套可逆密文保存。

| 材料状态 | IAM及安装预期行为 |
| --- | --- |
| 新安装/新增副本 | 安装先提供准确材料，再启动支持本片契约的IAM；新副本核对安装归属、格式、keyset及实际数据所需keyId后才ready |
| 文件缺失、权限/owner错误、安装不匹配、keyId不可用 | 必要认证路径失败关闭；不得生成替代keyring、改用密码单因子或跳过已绑定状态。该发布profile要求的材料未就绪时实例不得报告ready |
| 正常重启、等值安装重放 | 原材料身份/字节保持，不借启动覆盖、重新初始化或清空不可解密的行 |
| 有计划的包装密钥轮换 | 先向全部副本分发含新旧key的受控集合，确认读能力后切换activeKeyId；新写用新key，旧密文按原keyId读取。重封装以原密文版本CAS，不改因子身份/OTP消费状态 |
| 退役旧key | 只有数据重封装、实际副本和仍受支持备份的解封要求全部得到验证才可移除；没有证据拒绝退役。轮换不是清除失败计数或恢复码消费的手段 |

材料只读挂给确需验证TOTP的IAM认证进程；Audit、PaaS、普通worker、浏览器、verifier及support不获得种子keyring或可遍历其父目录。内存仅短时持有解封种子，错误/日志不得输出材料。这里保护数据库只读泄漏与用途混用，不宣称抵御IAM认证进程、受信写入路径或本机root完全失陷；SQL边界仍需独立证明运行角色权限与状态不变量。

#### 登录与一次性消费

登录响应必须明确区分“已发行Session”与“需要继续认证”，不能在挑战分支返回半有效bearer。仅密码、账号和User当前状态验证成功后签发短期挑战，不在错误密码/未知realm时暴露是否绑定MFA。完成挑战时，在原Account→USER→凭据锁序下重新检查主体状态、密码代际、因子修订及挑战；密码改变、因子替换或挑战终止使旧阶段证明失效，不根据请求中的user/account字段换主体。原密码Session及不支持新响应的旧客户端不能绕过所需因子。

首次设置、合法解绑后重新设置与已绑定因子丢失是不同资格。账号要求MFA时，只有明确NEVER_BOUND或具备原合法解绑完成的REMOVED才能获得密码验证后的设置挑战；后者保留原历史，不改称“从未绑定”。因子行被删除、损坏或状态未知不能推导这两种资格。设置挑战只允许必要的初始改密和绑定，不允许读取业务、创建Key、承担Role或调整安全策略。初始改密仍须原子推进密码代际、撤销旧会话和挑战，再用新密码重新开始设置；不让旧挑战跨代际升级，也不通过设置清除must-change。绑定完成结束设置流程，正常重新登录并使用尚未消费的TOTP，才发行Session。它复用同一密码用例的不变量，但不是借现有普通Session或普通改密bearer冒充未完成认证。

账号强制要求与用户主动启用均从权威配置计算有效要求，客户端不能选择较弱登录模式。启用账号要求时，旧单因子Session及其派生Role不能继续以旧认证事实取得新请求许可；各副本在下一次受保护请求重查有效要求，不等待异步逐行撤销完成。收紧要求须在同一事务建立不可回退的会话资格屏障，不能仅临时读出不匹配，之后放宽又恢复旧会话；准确修订/谱系字段在实现窗口冻结。降低账号要求不删除用户已绑定因子、不复活已失效的Session；新Session按当时真实要求重新认证。强制配置的操作者、作用范围、版本冲突、初始设置资格和高权限恢复路径须一起冻结；仅凭显示名为管理员或静态布尔字段不能判定。

TOTP规范输入、默认30秒步长、成功后拒绝同一步重用及标准向量依据[RFC6238](https://www.rfc-editor.org/rfc/rfc6238.html#section-5.2)与[RFC4226](https://www.rfc-editor.org/rfc/rfc4226.html#section-5)。Matrix拟采用一个固定、可实测互通的参数集，不提供caller算法/位数/时钟selector；首个互通候选为HMAC-SHA1、6位ASCII数字、30秒步长和每因子独立20字节CSPRNG种子，正式冻结需独立客户端验证。保留前导零，拒绝Unicode数字/宽松整数解析；使用数据库权威时间及64位时间步。拟只接受当前及前后各一步，不动态扩大窗口或相信客户端时间。

因子修订内的已接受时间步单调推进；两个副本、多个挑战、登录和step-up共享同一消费权威，不能各自接受一次。若一个码恰好匹配多个候选步，任何仍在窗口内的匹配步已被消费则整次拒绝，不能改选较新匹配绕过；全部匹配尚未消费时以固定规则消费最高匹配步。已消费步骤、错误码计数、挑战终态和最终Session/安全命令事实按准确事务边界提交；已识别挑战的认证失败不能因最终HTTP错误而回滚尝试计数。有效码已提交但回包未知时，不重发旧Session秘密或生成另一个成功结果；客户端使用新挑战及未使用码重新认证。

挑战拟定5分钟绝对有效期、最多5次有效持有凭据下的校验尝试、每USER至多3条未到期登录挑战；这些是待真实门禁验证的Matrix产品预算，不是标准规定。还有跨挑战、跨副本的同USER/因子总预算，新建挑战、重启和切换副本不能重置它。错误挑战持有凭据不能借公开ID消耗另一用户预算，未知输入不分配无界行。滥用保护不通过停用User/Account或删除因子实现；具体渐进延迟、临时抑制及入口资源预算须与IAM-SEC-01/04一同冻结，缺少它们不能宣称MFA可用。

#### 敏感操作、凭据分离与恢复

step-up证明绑定原有效Session、Account/USER、闭合操作、目标、准确输入承诺和预期资源版本，并有短期限与一次消费；它只证明认证强度，不产生PDP Allow。因子校验成功不增加策略或越过Boundary。对于同一IAM权威内的敏感命令，命令事务核对当前权限、消费匹配证明并记录结果；已消费或提交未知的证明不能在后来授权改变后重用。无效结构/错误目的不得消费另一条合法证明。跨PaaS/Audit业务命令不与IAM共享数据库事务，需由真实产品PEP另行冻结请求/决定绑定、一次消费、原意图重试和历史证据；本片不声称跨服务原子执行，也不把step-up响应缓存为permit。敏感操作清单与各实际命令owner逐项冻结，不能以任意action字符串或“管理员”显示名打开通用升权入口。

绑定启用、替换、解绑或因子恢复需要显式结束受影响登录会话，并使其派生RoleSession按原来源约束关闭；不默认保留一个尚未具有新认证事实的旧Session。日常改密的既有“保留当前/选择其他会话”语义不被这项MFA状态变更悄悄替换。账号要求MFA时不得简单删除最后一个有效因子，须走已验证的替换/恢复路径。AccessKey仍独立管理，不能凭User“已经绑定MFA”给key、服务或角色请求标记为完成MFA；若Role trust或业务动作要求认证强度，只能使用当次受信来源的实际认证事实，不能接受header/body自报。

恢复码拟为每条至少128位CSPRNG秘密，数据库只保存目的/Account/USER/批次绑定的单向验证值及一次消费状态；不采用参考文档中可解密回显的恢复码存储。保存恢复码使用单向函数、OTP需要共享的一次使用与尝试限制、以及OTP不具备抗钓鱼性，可参见[NIST SP800-63B的OTP及恢复章节](https://pages.nist.gov/800-63-4/sp800-63b.html#recovery)。这些来源不证明Matrix通过NIST认证或满足某一AAL，TOTP也不替代012的抗钓鱼因子。

恢复码必须与当前密码及准确恢复目的一起验证，成功只允许在短期受限流程中证明并绑定新认证器，不能直接发行普通Session、关闭强制MFA或重置密码。原码一次消费；重新生成批次必须通过有效强认证，明确终止旧批次且只返回新秘密一次。回包丢失保留原意图、只返回非秘密完成，不能重发秘密或把已消费码恢复为未用。恢复完成后正常进行新登录；丢失所有因子及恢复码是另一条受审计身份恢复，不得通过普通密码reset隐式绕过。

RootIdentity仍是原Account的原USER，恢复不能转让root、启用暂停账号或附加INSTALLATION权限。具有未撤销平台附件的USER不能由租户管理员接管因子；平台恢复继续在安装本地能力边界。现有原root/平台密码恢复只证明其已冻结的密码操作，不自动取得因子恢复权。开启这些身份的强制MFA之前，须与相应恢复owner明确最小新目的、当前资格/封存来源、并发撤权和单一审计事实，并实跑防锁死/防绕过路径；这一缺口未解决前不宣称完整MFA或安全治理验收。

#### 受支持备份恢复与防回滚边界

本节只覆盖产品提供的受控备份/恢复，不声称抵抗root将数据库、所有磁盘、密钥和封存历史一起回滚。密钥用途隔离保护秘密，事务保护同一次提交；二者都不使数据库外的时间自动单调。将T1已消费/撤销的状态恢复到T0，会重新出现历史有效行；数据库内新增generation、消费表或与数据库一同备份的Audit均不能独立阻止。PostgreSQL的[PITR说明](https://www.postgresql.org/docs/18/continuous-archiving.html)只证明可恢复到选定时点，不提供认证资格不回退的保证。

安全要求是：受支持恢复重新开放访问前，恢复可信的最新安全状态，或作废所有无法确认的认证资格并通过经过证明的受限路径重建。受影响入口包括登录、挑战、已有Session、派生Role及其他可能绕过该限制的发行/管理入口，不只关闭UI。历史资源、Operation和Audit不因此删除；已接受工作负载和历史outbox沿原产品边界处理。

| 恢复阶段 | 必须成立的条件与失败结果 |
| --- | --- |
| 准入 | 核对完整release profile、封存installation/原primary、备份真实性、配套keyset及受支持安全恢复方案；材料匹配不等于状态足够新。不满足时在恢复副作用前拒绝，不能加force跳过 |
| 先隔离访问 | installation建立不随本次旧库恢复回退的恢复意图及关闭状态，并确认全部相关副本/直连入口已隔离；不能只撤掉负载均衡后留下可直连旧实例 |
| 恢复数据库与材料 | 始终保持关闭；进程重启、安装器崩溃和旧journal出现均不得提前ready。副本须确认同一恢复意图，不能各自判断“库能连接就健康” |
| 验证安全状态 | 若有备份之外可信且完整的消费/撤销证明，可按封闭契约恢复；不能拿最大时间戳、链本身完整、outbox已空或旧bootstrap receipt冒充最新证明 |
| 无法确认时 | 不采信旧恢复码、因子、Session和challenge。作废/重新绑定方案必须有独立验证过的当前恢复资格，且不复活被撤销的权限。只有旧备份/旧凭据而无可信资格时保持关闭，不新建临时全权管理员 |
| 再开放 | 原子安全状态及完成证据持久化、必要通知意图建立、所有副本确认后，installation才封存开放结果；丢失回包只续跑原意图，不重新清空状态或签发恢复能力 |

本版选定的保守准入是：没有上述证明的MFA备份恢复组合不开放。隔离状态的存放与认证方式、全部副本栅栏、备份外安全证明或受控作废方案、受保护身份恢复能力及完成顺序必须由installation与IAM共同冻结并真实运行；不是本文凭空声明已有一个外部防回滚系统。现有封存来源只证明原安装/原USER，不自动证明备份之后没有撤权；既有密码恢复入口不能用来绕过这个缺口。

#### 封闭审计事实与必要安全通知

本片只为实际安全变化设计新事实，不为每个HTTP步骤创建事件类型。下表是拟定action目录，实施时在原`api/audit/v1`、IAM outbox/proof和Audit SQL拥有者同步验证，旧canonical编码不改写。

| 拟定事实 | actor/target/scope与证明 |
| --- | --- |
| `iam.authenticator.bound` / `iam.authenticator.replaced` / `iam.authenticator.removed` | tenant链；实际USER为actor，PRINCIPAL target等于同一USER；精确关联已确认的本人Session或用途限定认证挑战及因子修订，不允许SERVICE/ROLE、他人目标或伪造业务Decision |
| `iam.authenticator.recovery-started` / `iam.authenticator.recovered` | tenant链；密码+有效恢复码证明的实际USER，自助开始/新因子确认分别一个事实；原完成保存阶段与归属，不将只验证密码的未知请求归为成功恢复 |
| `iam.recovery-codes.regenerated` | tenant链；实际USER与本人target，强认证证明、原/新批次及原子终态由IAM私有完成关联证明，不在事件中写恢复码或其验证值 |
| `iam.security-settings.updated` | tenant链；当前PDP允许的实际USER为actor、真实ACCOUNT为target；关联原决定及设置旧/新版本，不能以平台身份默认管理另一租户 |

正常发行仍用原`iam.session.issued`，认证事实保留在发行的私有证明中，不能给旧事件补MFA。敏感请求摘要只编码必要非秘密字段；密码、OTP、种子、恢复码、challenge持有凭据及其可离线猜测的摘要不入Audit。IAM-source投递继续核对已提交事实，后续因子撤销、账号暂停或Session到期不丢失历史。

错误密码/坏challenge没有已认证USER，不能为了统一日志伪造USER决定或泛化SYSTEM actor。本片由持久尝试结果与受限脱敏指标证明失败预算，不承诺把每个匿名失败HTTP请求写入不可变租户链；有当前Session的权限拒绝沿既有决定事实。若后续要求匿名失败入Audit，须单独冻结准确来源/actor和抗写放大预算，不借本片自动增加actor范围。受保护身份的离线因子恢复同样需要独立目的限定事实，不能复用现有密码恢复的SYSTEM action。

必要安全通知覆盖首次绑定、替换/移除、恢复开始/完成、恢复码重发及安全配置变更。IAM在成功事务内保存非秘密投递意图，绑定原eventId、Account、目标USER或已指定安全接收人及其已验证地址修订。它与Audit投递职责不同；不把原Audit claim七列改作邮件队列，也不使通知消费者拥有所有租户查询权。具体适配器由012的真实通知owner提供，不新建通用消息中心或假订阅API。

投递观察状态为`PENDING/RETRY_WAIT/ACCEPTED/FAILED/UNKNOWN`；只有渠道真实提供回执时才记录DELIVERED，绝不声称已读。先记录尝试身份再调用渠道，使用eventId加接收人修订去重；响应丢失先查询渠道证据，渠道无法幂等/查询时允许可识别重复告警而不声称恰好一次。失败有限重试、持久告警，不回滚已经完成的凭据撤销或重新执行恢复。通知里没有秘密、临时登录链接或恢复授权。

接收地址必须来自已验证且当前可用的归属来源；恢复申请不能临时提供一个地址就把告警只发给它。没有已配置渠道/可信接收人时，新增绑定、恢复和强制MFA的发布前置不满足；运行中短暂投递故障则保留已提交安全变更及待投递，不把已撤销因子恢复有效。现有受损访问的退出/撤销不能因通知渠道不可用而被阻止。通知是本片未完成依赖，不把Audit成功、入队或测试收件箱的mock作为真实交付。[NIST恢复与通知要求](https://pages.nist.gov/800-63-4/sp800-63b.html#recovery)是安全参考，不因此宣称NIST认证或AAL合规。

#### S2验收与未冻结衔接

- 既有credential/authority测试使用RFC标准向量及独立实现生成的所选参数向量；真实认证器完成绑定和登录。覆盖前导零、时步边界/超2038、前后窗口、错种子/主体、同一步重复、合法码跨目的/挑战/副本及相同码多步碰撞。
- 两个真实IAM副本证明密码正确但MFA未完成时不存在可用Session；错误码预算持久、并发成功只消费一次，认证/outbox末端失败无部分Session或成功事实。提交后断开真实TCP、重新登录、重启和等值schema重放不重发秘密、不复活挑战。
- 账号强制MFA下新User的初始改密/首次设置、合法解绑后的重新设置、已有因子丢失和状态损坏分别走准确路径；旧挑战不能因改密获得新资格。启停要求与解绑、普通/Role请求双向竞争，旧密码会话不能等待异步任务期间继续放行；弱化配置不能复活已失效会话或挑战。
- 绑定/替换/恢复与change/reset/logout、User/Account停用、平台附件写入双向竞争；旧单因子Session不升级、旧Role来源关闭、独立AccessKey不被虚假MFA事实放行。因子缺失/损坏/代际未知失败关闭，不按时间猜测认证强度。
- 实际受限PG登录、RLS/函数越权、种子跨安装/主体互换、仅IAM材料挂载与日志/审计/支持输出秘密扫描；恢复码单向存储、一次性返回/消费、批次更换和备份回退攻击。
- UX/UI owner完成真实绑定、登录挑战、换码等待、丢失回包、合法恢复和权限拒绝流程；不通过假OTP服务、空页面或截图代替运行。原密码/Session/Role/K2历史和canonical回归保留。

#### 验收矩阵、分片与未决交付

| 门禁/现有owner | 必须证明的结果 |
| --- | --- |
| `api/iam/v1`契约/生成测试 | 登录两分支严格互斥；challenge不能当Session；未知字段/两认证载体同时提交/跨目的/秘密普通marshal拒绝；仅两项安全配置新授权动作 |
| `authority`、`identityaccess`、`nethttp`原测试 | 标准向量、秘密隔离、纯状态规则、正确错误映射及失败提交；不把假事务中的计数当成PG证据 |
| IAM原`integration/http_postgres_test.go` | 两Account同名User；真实RLS/ACL/唯一性、同码两副本只有一次消费、重建challenge不返预算；配置CAS和错误码后计数保持；真实锁等待后的到期与因子替换检查 |
| 并发矩阵 | 双验证、验证对改密/reset/recover/logout、因子替换对验证/恢复码消费、设置收紧/放宽对Session/Role请求、平台附件grant/revoke对目标凭据操作；分别控制两种提交次序，无部分状态/秘密或多余成功事实 |
| 原authorityprocess | 两真实IAM和Audit/PaaS/dispatcher、实际受限PG登录；提交前崩溃/提交后断TCP、数据库失联与重启、旧客户端、真实资源请求；已失效Session/Role立即拒绝且已提交Operation及历史链保持 |
| 安装/恢复owner | 同部署两副本一致keyset、错安装/错key/缺key不ready、重启不重建；T0有效备份→T1消费/撤销→T2恢复，先隔离且旧资格不接受；在每个恢复阶段中断仍不提前开放；无可信恢复资格明确拒绝 |
| 通知owner | 真实已验证接收人和实际渠道；跨租户/新地址替换拒绝，受理未知/重复/失败重试与告警；Audit、入队、受理、送达不混淆，不因投递失败复活凭据 |
| UX/UI owner | 独立真实认证器完成主动绑定、首次强制设置、登录挑战、过期/等待新码、秘密回包丢失、合法重绑及设置权限拒绝；浏览器不能读取持久缓存中的秘密 |
| 原011容量owner | 明确副本/CPU/内存/连接/数据及尝试预算，错误登录与复杂PDP并行时没有无界队列；不提前宣称生产QPS、公平性SLO或数据库HA |

实现顺序在本FEAT内细分，不新建重复FEAT：

1. S2a：冻结私有材料、挑战/失败结果、现有锁序和消费者联合响应；补纯契约/域门禁，尚不开放MFA。
2. S2b：实际PG共享尝试预算、TOTP消费及本人绑定/登录/受限重绑纵向闭环；具备完整安全条件后才开放对应能力，不把恢复留到加固阶段。
3. S2c：S3两项security-settings权限、配置CAS、强制初始设置及Session/Role资格屏障；与原主账号/平台恢复owner完成受保护身份边界后验收全范围。
4. S2d：真实安装材料、备份恢复与必要通知；与后端并行对齐，但未完成不能作为可发布MFA。
5. S2e：UX/UI真实浏览器和完整固定消费者发布门禁；S3其余密码/期限规则及S4仍按各自需求独立验收。

允许先审查/实现不对外启用的基础片，但不能降低本节承诺。实施前仍需确认：installation的材料与恢复隔离契约、原主账号/未撤销平台主体丢失全部因子的目的限定恢复、012通知渠道/接收人owner、UX/UI登录联合响应，以及S3内置策略发布版本。这些是准确的依赖，不以“以后完善”换取MFA已验收。具体SQL函数/输出列形状、源码schema/Audit版本和最终release profile在对应实现切片分配，本文不预占数字。

未发布中间schema不从1逐版重跑。保留数据测试选实际最近受影响固定程序创建的状态，证明旧NULL认证事实不被补造为MFA、封存primary/历史事实保持及新状态重启不复活；最终首版基线与真实已发布消费者按011执行。数据升级实验证据不替代签名release准入。设计改动仅归本文及原adoption，不改变S1/S1b证据、其他Phase或任何运行环境。

### S3：账号安全规则、认证预算与期限

本节细化IAM-SEC-01/02/04的后继目标，不改变当前规则、公共接口或schema。最小可验路径是：账号管理员设置本账号日常User的密码规则，两个IAM副本一致执行创建/改密/重置，有限次数的真实错误认证不能通过并发、realm别名、重启或事务回滚取得额外尝试；另一账号和业务鉴权仍受独立预算保护。密码规则不是005的授权Policy，不能参与Allow/Deny或授予密码重置权。

固定`644fff09`的事实与差距如下，不能把已有HTTP timeout当成安全治理：

| 现有owner | 当前行为 | 本需求缺口 |
| --- | --- | --- |
| `authority/password.go` | 固定Argon2id 64MiB/3次/并行1；新密码14–128 UTF-8字节、四类至少三类、拒绝空白/控制字符；Verify按保存格式核对原完整秘密 | 无账号规则、历史/常见密码检查；Hash同时负责固定规则，需区分产品规则与不可由租户降低的哈希成本 |
| `authentication.go` / `lookup_login` | 当前realm解析后验证真hash或dummy hash；错误结果结束事务，成功直接发行Session | 无已持久化的认证失败预算；不能在同一回滚分支顺便写计数后宣称限流生效 |
| `user_credentials` | 当前hash、真实changed_at及单调credential_version | 无历史密码集合或已验证规则版本；不能从hash推测长度/复杂度，也不能补造旧密码历史 |
| `service.go` / `issue_session` / `lookup_session` | 默认8小时绝对期限，用例配置允许1分钟至24小时；数据库时间、撤销和密码代际参与资格 | 无账号会话期限配置、可信last-activity或idle expiry；HTTP连接IdleTimeout不等于Session闲置过期 |

#### 规则归属与变更

账号安全配置是Account内单份有resourceVersion的治理状态，首片不另建可附件到Group/Role的安全策略语言或任意用户例外。`Policy/PolicyVersion`负责谁能操作资源，`security-settings`是该授权所管理的资源；两个对象不能合并。普通User仅可在其已验证身份下取得设置自己新密码所需的有效约束，不取得全账号安全报告或其他用户状态。未认证登录响应不公开按realm变化的配置。

本次拟定权限与入口如下；只形成详细设计，不在代码中提前注册或授予。

| 项目 | 设计 |
| --- | --- |
| 读取动作 | `iam.security-settings.read`，TENANT scope，原`ACCOUNT`实例资源且ID必须等于已认证Account；不另造一对一安全配置resource ID |
| 修改动作 | `iam.security-settings.update`，相同scope/资源；不附带User认证器、密码reset、会话管理员、platform或其他Account的权限 |
| 可用身份载体 | 当前实际USER的LOGIN_SESSION，包含原root但仍需原权限求值；首片不接受RoleSession、AccessKey、ServiceIdentity。SELF不是新增AuthorityScope或万能角色 |
| 读取入口 | `GET /v1/account/security-settings`，Account从当前身份推导，没有URL/body/header selector；返回`AccountSecuritySettings{apiVersion,kind,accountId,resourceVersion,mfa,updatedAt}`的非秘密配置 |
| 修改入口 | `PUT /v1/account/security-settings`，严格`{requestId,expectedResourceVersion,mfa:{requiredForUsers},stepUpProof}`；本片完整替换已支持的mfa段，没有任意JSON merge或用户例外数组 |
| 成功结果 | `outcome=APPLIED\|EQUAL_REPLAY`、原非秘密设置/版本和`reauthenticationRequired`；新执行的输入变体、版本冲突、权限或证明失效均无部分写入。精确完成只在当前caller仍有权限且原输入一致时返回，不要求已消费证明重新可执行，不重复消费或递增版本 |
| 完成读取 | `GET /v1/account/security-settings/changes/{requestId}`；当前LOGIN_SESSION、当前read权限、同Account且原actor为同一USER，允许该USER重新登录后只读原版本/完成时间/结果。不返回证明秘密、不重做写入，不存在或不属于caller均不泄露其他意图 |
| 后继字段 | 密码及Session期限随S3相应实现统一增加到实际schema和UI；尚未实现的字段拒绝，不返回伪默认值或预留可写空对象 |

当前首片只有TOTP，故不提供算法、允许因子清单、宽限期、按组例外或平台底线开关；新Account的`requiredForUsers=false`只是未强制日常User，不关闭用户主动绑定的因子。已有安装安全配置只能从实际可信旧状态迁移，不能以默认false覆盖生效决定；缺少应存在的行不得在读取时临时生成。用户NEVER_BOUND的首次设置、具备合法解绑完成的REMOVED重新设置及因子丢失必须区分。

新动作进入IAM产品Profile和策略编译器，不由handler比较角色名称。现有系统策略版本保持不可变；具体新内置版本及其生效范围归002，在实现窗口明确验证，不因为目录新增Action就自动给所有旧附件补权。自定义策略可按已有发布/附件流程显式授予这两个动作，不能跳过Boundary或Deny；平台操作员的安装权限不隐含租户设置权限。

修改的准入顺序为：确认真实Session及Account → 当前PDP → 当前受保护身份/配置规则 → 操作专属step-up → resourceVersion CAS → 原子变更/事实。顺序是语义条件，具体取锁仍遵守既有锁序。最终事务按**修改前当前有效规则、不可降低的产品底线和该操作自身要求**重检；本片所有设置修改均需近期密码及TOTP的目标限定证明，即使拟提交`requiredForUsers=false`也不能用该新值省略MFA。尚未绑定的操作者应先完成本人合法绑定与正常登录，不以这项权限代替绑定资格。

false→true收紧时，最小方案单调推进本Account日常User的登录资格修订，保守地要求该范围内既有Session全部重新认证，包括先前已完成MFA的会话及当前日常操作者；不需要在事务内遍历全部用户/会话。两副本在下一次请求比较Session真实修订，派生Role按来源关闭；成功响应明确重新登录。true→false不降低资格修订、不复活旧Session，也不删除任何个人因子。原root/未撤销平台主体不受租户管理员此字段控制，其独立底线和恢复前置按S2执行。

更新后caller被要求重新登录时，旧Session不得为重放而豁免认证。未知回包先正常重新认证、读取当前配置及上述原非秘密完成；不自动用新resourceVersion与新证明重做原命令。读取历史完成与执行写入是两件事；只有update而没有read权限的主体不因此获得查询权，须保留未知结果并经现有授权流程处理，不能猜测失败后自动重写。

租户可配置范围是本账号日常User，不可通过规则修改间接接管、锁死RootIdentity或拥有未撤销INSTALLATION附件的USER；这些身份的固定底线及恢复另属已声明root/installation边界。平台保护根据未撤销附件而非“当前可登录/有效Allow”判断，与附件授撤共用principal锁序。主体后来进入/退出受保护范围不能删除其原历史、清除已消费预算或复活会话；资格和实际规则切换须有明确的锁内行为，不通过配置开关绕过已有凭据保护。

创建/修改配置、原请求完成关联和封闭Audit事实同事务；相同resourceVersion并发只有确定赢家。设置新密码的命令在写入前验证当前规则修订、主体/凭据代际及准确历史集合，不能依赖UI预检查或事务外缓存。状态变更、密码reset/recover与规则收紧交错时，过期验证结果不能落库。普通管理员规则不改变服务凭据、AccessKey、离线capability或RoleSession的密码语义；但Role仍受其原登录来源失效约束，不存在借Role绕过来源收紧的例外。

#### 密码设置与历史

拟定新默认值以长口令和可用的密码管理器为基础：最短15个Unicode码点，允许至多128个码点并有512 UTF-8字节硬上限；允许普通空格，不截断、trim或自动变换大小写。复杂度组合可作为显式账号要求，但不默认把字符种类当作强度证明；定期到期默认关闭，仅明确配置时按数据库时间执行。账号规则不得降低底线或选择哈希算法/盐长度/内存成本。上述为Matrix的待验证产品值，不回填为当前行为，也不宣称符合某一认证等级。[NIST密码验证要求](https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver)强调长度、常见/泄露密码拦截和尝试限制，明确不采用额外字符组合规则或例行周期轮换；本产品为企业显式要求保留这两类配置，不把它们说成NIST要求。外部产品的参数不直接成为本系统默认值。

长度按码点而非字节/视觉字形计算，新口令规范化若改变验证字节必须有独立明确格式；本片不对旧hash隐式加入NFC或宽松匹配。已有密码仍按原格式验证完整秘密，不能先用新设置规则拒绝旧密码而使用户无法正常改密。长度/字符规则默认约束后续创建、改密、reset及相应受支持恢复写入；修改规则不证明所有存量密码已经合规，也不自动生成批量改密事实。已启用的到期要求按真实changed_at判定，缺失必要历史时失败关闭，不用迁移执行时间假装刚改过密码。

历史只保存各次真实密码的盐化慢hash及凭据代际/变更关联，不保存明文、可逆密文或快速无盐指纹。总是拒绝把当前密码重新设为“新密码”；额外历史数量拟限定0–24、默认1，0只关闭更早历史检查。新增、改密、重置和恢复应执行各自主体当前有效规则，不给管理员临时密码留无审计旁路；没有可证明历史时只保留当前已知状态，不生成24条占位证据。

历史校验按固定上限串行使用原慢hash，有独立高成本工作预算；不能用并行24次散列放大内存，也不能在预算不足时跳过比较而接受密码。若把昂贵计算放在数据库写事务外，写入事务必须重新核对账号规则修订、USER状态、原credential generation和历史head，任一变化均不得使用旧验证结果。不得跨多个SQL事务保存半个新密码/半份历史；只有原子成功才轮换历史、推进generation、执行现有会话撤销规则和写outbox。

常见/泄露密码拦截必须有固定、可离线提供、经过授权且版本/摘要可核对的数据源和有界比较，不能把待设置密码发送给第三方或在日志记录匹配明文。词表格式/来源、变更回退和容量门禁尚未选定；没有它不能声称已完成弱密码拦截。恢复码、OTP和AccessKey秘密不是用户口令，不受此词表或复杂度设置控制。

#### 认证尝试的持久预算

必须分清三种限制：进程/入口预算保护CPU、内存和连接；当前实际USER/凭据预算限制猜测；Account公平预算避免一个账号占满认证资源。前者可以有每副本本地上限，但不能冒充集群级尝试上限；后两者需要共享权威状态，所有IAM副本按相同数据库时间核对。安装/edge的限额是补充，不授权IAM失联时回退到内存计数或旧Allow。

计数主体来自真实realm解析结果，不是caller的accountId或原loginName字符串；同一User的账号ID/别名登录共享预算，不同账号的同名User隔离。未知realm/用户不创建无限主体或原始登录名计数行，而在有硬容量界限的入口预算下执行适当的dummy核对；不能通过选不同别名绕开，或在公共返回体泄露是否存在/剩余次数。未知与错误密码、暂停/停用的外部语义需一起验收，不能声称仅使用dummy hash就已经消除所有时序侧信道。

登录、改密时的旧密码重验，以及绑定/step-up/受限恢复中的密码核对共享该USER及密码代际的猜测预算，不能通过切换认证目的获得免费尝试。新密码规则校验或管理员设置临时密码不冒充本人密码认证成功；MFA码的因子预算和完整认证预算各按其目的保留，任何单一阶段成功不能清空所有限制。

仅在昂贵验证后递增失败数不足以约束并发：执行前须在共享权威下保留有上限的在途尝试资格，绑定真实USER/credential generation及服务器生成的单次尝试身份。它不发行Session，也不是caller可重复使用的permit。进程中断或响应未知不退还同一次猜测资格；取消、过期与回收必须有明确数据库规则，不能通过重新连接恢复全部预算。正确密码不能绕过已生效的抑制，错误请求也不能靠反复复用requestId获得免费核对。

已验证失败以非异常结果完成失败计数事务，再映射稳定HTTP错误；不能让现有`withinTransaction`收到认证错误后回滚计数。成功的最终认证才按冻结规则处理连续失败状态，并与发行结果原子关联；MFA尚未完成不能重置完整认证预算。并发中旧代际失败不扣新凭据额度，但不能因此抹掉已经发生的入口资源消耗；成功不会清除其他仍在途的尝试资格。未知完成只按原尝试状态处理，不重做密码核对或返还额度。

首个有界实现的尝试状态为`RESERVED → SUCCEEDED|REJECTED|ABANDONED`，结果不可逆。过期RESERVED转ABANDONED只释放并发槽，不返还该窗口已经消耗的猜测次数；不能通过断开HTTP或杀进程刷额度。相同attempt最终提交最多一次，任何重试都不能先发行凭据后补计数。验证码错误属于REJECTED而非使整个计数事务回滚的异常；未知challenge持有凭据不能按其公开ID锁死另一个用户。

候选产品预算：每挑战绝对5分钟/最多5次提交、每USER最多3个活跃登录挑战；共享密码核对每USER同时最多1个昂贵尝试。跨挑战OTP/密码窗口、渐进抑制、Account公平配额及全局crypto队列须在011受限容量/抗锁死门禁中给出具体可发布值，未冻结不得上线，仅给每challenge计数不能通过S2验收。这些均不是租户可无限放大的参数，也不要求新增Redis；PostgreSQL是首个共享权威，IAM本地信号量只保护单副本资源。

临时抑制不是停用User/Account，不删除凭据、不终止工作负载、不影响历史投递；具体失败阈值、窗口、最大抑制和逐步恢复需以容量与抗锁死测试冻结，不直接照搬外部厂商的“一小时锁定”。健康探针、服务身份与业务PDP有各自预算，不能被错误密码洪泛无限挤占，也不能给其普通API添加跳过认证预算的开关。全局过载可返回明确有界退避；用户存在性相关的冷却信息不得在未认证响应中枚举。验证码/邮件等外部手段仍按012，没有通道不造假。

来源IP只有经过安装/edge owner确认的可信代理链才能用于规则；007的外部origin/request-target header不证明客户端IP，caller的Forwarded/X-Forwarded-For也不是权威。登录网络规则属于身份入口，005的IP条件属于业务PDP，两者不能混为一条“可信来源”布尔值。真实来源尚未提供时保持IP规则不可启用，不用IAM所看到的代理地址冒充最终用户地址。

#### 到期与会话期限

密码过期不等于User停用，也不删除资源；最小恢复路径是在当前密码与所需MFA核对后，仅进入受限改密流程，不能先发具备业务权限的Session。强制改密必须继续撤销其他临时会话，旧阶段证明不跨密码代际；旧正常会话不能凭缺少存储must-change标记绕过当前过期规则。普通会话、已过期凭据及S2设置挑战的准确公共返回和恢复能力须一起冻结，不保留两个可绕过彼此的密码入口。

Session绝对期限在发行时有上限且不能滑动；idle期限依赖服务端实际观察到的有效LOGIN_SESSION认证请求，不接受浏览器自报活动时间。它表示认证请求闲置，不表示人是否坐在设备前；Role、AccessKey、服务/worker活动不暗中刷新原登录会话。允许哪些请求更新活动、是否排除控制台后台轮询及并发touch预算需要实际消费者对齐，不默认一次健康检查即可续命。超过idle或absolute后不能被迟到touch、改配置、重启或异步任务复活；续期只能重新认证。S1的会话目录不因此提前显示尚未采集的last-active或设备在线状态。

#### S3验收与衔接

- 两账号同名用户、ID/别名两种realm、两个IAM副本，真实验证同USER预算共享/不同USER隔离、设置归属、受限规则读取及配置越权；root和未撤销平台附件保护不能通过停用后重试绕过。
- 密码边界、Unicode码点/字节/空格/组合字符、旧hash准确验证、常见密码来源和历史0/1/上限、所有写入口、错误版本和缺历史；并发改密/重置/恢复/规则变更无部分hash、代际、会话或成功事实。
- 实际失败HTTP响应后从另一副本观察已消费额度，容量边界内并发只获得有限资格；真实进程中断/取消/数据库失联和重启不重置，未知用户洪泛不形成无界存储。MFA完成前不能刷新完整登录预算。
- 实际过期前正向、数据库时间过期后拒绝、闲置touch边界/并发/迟到/换副本、配置放宽与重启不复活；不伪造时钟或缩减已冻结密码成本取得通过。
- 有限CPU/内存下分别测正常登录、最大历史比较、错误密码洪泛与并行业务鉴权，真实记录等待/拒绝和另一账号的可服务性；证据归011容量owner，不以两进程启动或纯函数benchmark代替。

本稿已给出security-settings的两项Action、资源/载体及HTTP提案；产品Profile/内置策略的准确版本、最终共享尝试预算和后继密码/期限字段仍须在实现切片冻结。匿名失败记录边界按S2，不把已解析用户名写成已认证USER、不伪造SYSTEM或业务Decision、不将原始密码/失败候选放入Audit。仍沿现有credential、usecase、HTTP、PG和authorityprocess门禁，不新增通用限流服务或可替换Redis授权权威。共享实现窗口未开放前仅保留设计和固定来源决定。

### S4：安全报告、权限诊断与闲置治理

本节细化IAM-SEC-05/06，不新增运行入口。最小路径是：有当前权限的账号安全人员查看本账号User/Key状态、真实使用证据和明确缺口，生成/下载同一份有界报告，选择目标后以当前权限显式处置；另一账号、已撤权用户和平台运营身份不能借reportId、cursor或下载地址读到内容。自动闲置处置是后继执行切片，不因能下载报表而取得后台全租户修改权，完整009仍需实现其已启用治理规则并实跑。

固定`644fff09`已有CurrentIdentity的直接/组PolicySources、PermissionBoundary、非权威ActionCapability，以及不可变决定与outbox；公开DecisionReason仅ALLOWED/DENIED。AccessKey元数据只有身份、状态、resourceVersion及创建/修改时间，没有lastUsed；没有安全报告、详细拒绝诊断或闲置调度实现。不能把已有目录、元数据更新时间或Audit链完整等同于这些功能完成。

#### 观测事实及完整性

| 指标 | 可用的权威事实 | 不能推出的结论 |
| --- | --- | --- |
| 最近成功登录 | 已提交Session发行及其真实USER/Account/发生时间 | 本人仍在线、已经访问业务、客户端物理设备 |
| 最近认证活动 | 真实载体被核验且完成相应受保护入口的权威记录；需覆盖管理、自助及业务请求，不只采集Allow | 更新User资料、报告生成时间或不存在记录可代替last-active |
| Key使用 | 已通过MAC并提交的准确key谱系/决定；Allow与Deny分列，坏MAC和nonce重放不冒充新使用 | Key启用、改显示名或创建时间就是最近使用；Allow就是业务执行成功 |
| Role活动 | 承担事实与RoleSession业务请求分别记录原USER和真实Role身份 | 角色创建/改信任就是承担；角色活动自动续期原登录会话 |
| 业务结果 | 各真实产品已验证的事务/outbox事实及其精确决定关联 | IAM Allow、Operation受理或缺少结果表示部署已经成功/失败 |
| 未观察到使用 | 已知采集起点、准确范围与水位内确实没有匹配记录 | 从未使用、跨产品全覆盖、可以安全删除或自动停用 |

报告明确observedAt、覆盖Account/对象/产品/载体、窗口、采集起点和各来源水位。分别表达有值、窗口内未观察到、信息不完整/未知、能力不适用；不把NULL变成零次、false或“从未”。MFA/网络风险等未启用能力显示尚无数据能力，不制造“已通过检查”或风险分。当前状态快照与历史统计并列，原报告不是后续权限/资格来源。

只可从IAM自有权威或经所属上下文认证的闭合查询取得数据，禁止跨库扫Audit/PaaS表。IAM本地一致快照不代表三个服务在同一时刻的联合快照；不能用最大的event time或单次outbox pending=0充当所有生产者完整水位。迟到/乱序/重放按不可变事实身份去重，已封存报告不被后台重写；数据补齐需要新报告和新观测时间。历史缺少Key/Role谱系时保持未知，不从今天的主体关系倒填。

最小报告先只承诺实际IAM权威能证明的覆盖。业务结果和Audit统计必须由产品/Audit owner冻结对应受限查询与水位后才能标完整；报告权限不隐含原始Audit读权，IAM的安装级服务身份也不因此得到任意tenant查询权。范围缺口保留为显式验收项，不用少量抽样代替完整报告。活动投影如果用于自动处置资格，必须与其真实认证/命令事务一致或有可验证的完整水位；普通异步展示数据不能成为撤权的唯一依据。

#### 生成、读取和下载

报告是账号内有界、不可变的观测制品，复用当前IAM事务/存储边界；不先造独立报表服务、通用数据仓库或导出任务框架。生成、查看/下载及详细权限诊断需要明确封闭Action和Profile支持的真实身份载体，不按“管理员”显示名放行。读取和下载每次重验当前账号、身份、会话及权限，reportId只是引用；报告存在或生成时曾有权限不是今天的permit。租户报告不展开installation附件、平台主机或另一账号事实。

生成请求绑定原Account、实际actor、明确范围/过滤、requestId及格式版本；准确重复只取原报告，不用同一个ID重新生成新内容。报告固定摘要、生成时刻、行数/覆盖及到期，有硬查询/行数/字节/执行时间预算；超出已支持容量明确拒绝或标记不完整，不能悄悄截断并称全量。查询分页用原签名cursor绑定准确报告/账号/当前身份/查询；按多个可变目录页面拼接的结果不能宣称同一快照。

首个下载形态为版本化CSV，字段只取明确的非秘密投影；有稳定资源类型和ID，不把Key永久写死为Key1/Key2列，也不把字段缺失填成无风险。编码处理分隔符、引号、换行和公式开头字符，用户显示名/标签一律不作为公式；安全导出后的显示文本与原始值区别需要在格式中说明。必须在声明支持的电子表格程序验证首次打开及保存再打开，单纯给字段加引号并不能证明安全；[OWASP的CSV注入说明](https://community.owasp.org/attacks/CSV_Injection)也明确不同程序不存在通用无损转义保证。未通过安全门禁不开放该导出，而非把风险交给用户忽略警告。

秘密、hash、digest校验材料、MFA种子、恢复码、raw签名、会话bearer及私有PDP证据均不进入报告；仅列必须的公共资源引用和有权限的状态。制品不进入公开目录、静态CDN或免鉴权分享URL，下载响应no-store并经受保护连接；保留/到期清理仅删除报告投影，不清理原Audit/决定/资源。内部持久制品的访问、备份保护和容量由实际存储/安装owner一并验证，不以测试目录文件作为生产托管。

报告生成/下载受理事实记录实际身份、范围和reportId，不记录正文；HTTP发送完成也不证明用户已保存文件。流式传输开始后撤权的中断边界与其他长请求一样明确，不声称已传出的字节可收回。当前尚无这些新的Audit action，不借泛化SYSTEM或现有业务action冒充报告事实。

#### 权限来源和拒绝诊断

当前权限来源复用直接附件、组成员/附件、角色、Boundary和SessionPolicy的真实修订及单一求值器；不维护第二套“有效权限列表”作为PDP。条件、动态资源和显式Deny存在时，展开动作名称不是最终Allow。已有ActionCapability仅为UI提示，诊断结果也不进入授权接口、承担角色或资源命令。

历史拒绝以原decisionId/requestId及当时封存证据解释，不用今天的策略重新计算并覆盖旧理由。当前预检查另标“当前”，必须限定真实Action/资源和有权查看的账号范围，不伪造用户会话、可执行Decision或签名Key请求。详细理由需要区分显式Deny、缺Allow及上限不满足等实际求值分支；当前仅ALLOWED/DENIED不足，准确安全理由/证据投影在实施时冻结。不从错误信息泄露另一租户对象是否存在，不自动生成并附加“修复用全权限策略”。

#### 闲置发现和处置

闲置资格必须绑定规则修订、对象resourceVersion、真实活动修订和完整观察窗口。采集缺口、审计积压/死信、对象新建后不足阈值或仅没有浏览器登录时都不能断言User/Key闲置；程序Key和Role的真实活动必须按准确主体归因，不能忽略非浏览器使用。阈值以数据库时间和已冻结产品范围计算，不借外部地域/风险来源造结论。

首片人工确认后仍调用现有User/Key生命周期命令，以当下真实权限和目标版本为准，报告建议不能代替它们。若动作明确声明“仅当仍闲置时停用”，写事务必须按Account→稳定principal→credential/key锁序重新核对活动修订和范围水位，与真实认证/使用写入串行化；看过旧报告不算这一证明。新活动先提交则旧建议冲突，停用先提交则下一请求关闭；两个后台执行者不能因同一发现产生重复成功事实。未知完成按原准确意图核对，不生成新意图重做。

停用Key只关闭该程序凭据的新请求，不删除User或业务资源；停用User影响其各认证载体，但不停止已接受工作负载或销毁Operation/outbox。启用是新的显式当前管理操作，不复活原登录/Role会话，不撤销删除终态；人工决定长期Key重新启用不等于自动恢复旧签名报文。RootIdentity及有未撤销平台附件的USER不由普通闲置任务接管，受保护身份不能通过先停用再恢复绕过。

自动执行需要账号显式启用的闭合规则、执行目的/目标范围、当前有效执行身份与撤销边界，不能把创建规则者的过期Session存入worker、伪造USER决定或复用verifier权限。执行者、账号同意和服务受托仍服从008的边界；没有对应当前权限证明时只报告、不变更。不先添加一个拥有所有租户写权的通用治理服务主体；安装purpose本身不授予目标tenant权限。

#### S4验收与衔接

- 真实两账号、同名/同ID资源、当前与过期权限，报告生成/目录/cursor/ID/下载逐项隔离；生成后撤权或账号暂停，新下载拒绝，不能用缓存文件绕过。查询/容量超限和传输失败没有假完整结果。
- 登录、Role承担、Key正确签名Allow/Deny、坏MAC/重放及真实产品成功/失败分别产生准确指标；字段修改不算使用。人为延迟本任务outbox、乱序重放和缺谱系旧事实显示真实水位/未知，不能得出“从未使用”。
- 直接/组/角色/Boundary/SessionPolicy组合的当前来源和原决定解释，变更策略后不篡改历史；诊断无授权效果、无新会话、无跨账号存在性泄露。
- CSV恶意显示名、分隔符/双引号/换行/全角公式字符、受支持程序打开/再次保存打开、秘密扫描及下载审计；无外部分享或免鉴权静态文件旁路。UI和实际电子表格验收交所属owner，不以纯文本快照代替。
- 新活动与停用、修改规则、停用执行者/账号及两个执行副本的双向竞争；旧发现不能覆盖新状态，未知回包/重启/恢复不重做已完成意图。所有资源、既有任务和历史Audit归属保持。

报告字段/预算/保留、各来源查询与水位、精确Action/Audit事实及后台委托资格仍待各owner冻结，均未实现/未验收。继续使用原IAM/Audit与authorityprocess门禁；制品只是可重建投影，不能新增平行权限权威或第二套审计链。

## 验收

真实浏览器双 session 改密选项、forced-change、登出/重置/recover 竞争，TOTP 时钟边界、重放和错主体挑战，安全设置旧行升级失败关闭；报告 Account 隔离与秘密扫描；用户/Key 停用即时有效且资源不被删除。Passkey 生产可信 origin 与硬件设备门禁条件见 012。
