# FEAT-IAM-009：登录保护与安全治理

- 状态：S1本人会话目录/逐个撤销已验收；S1b一键结束其他登录会话的后端切片也已验收，累计固定`7cf857bba48eb5d7da487162c43e8f52534db133`通过本地真库、保留数据、独立进程、全仓检查及五项独立CI。一般事务分组及失败证据归011，既有Role管理门禁的准备复用归006。当前源码IAM32/Audit19，未分配发布revision；UI与完整009尚未验收。S2本地MFA、S3安全规则/认证预算、S4安全报告/闲置治理仍仅设计，尚未冻结全部材料、权限和公共契约，未实施/未验收。
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

本节为后继目标和实现前的安全设计，不是已存在接口或已开放公共窗口；不分配schema/profile/revision，也不作为S1或007消费者集成前置。最小完整路径是：本人验证密码并绑定真实TOTP认证器，保存一次性恢复材料，之后密码正确仍须完成TOTP才能得到登录Session；丢失认证器时经受限恢复重新绑定，再正常登录。最终还需覆盖RootIdentity、敏感操作再次认证及账号级强制要求，不能用普通User的可选绑定代替整个IAM-SEC-03。

固定`644fff09`中，Login在密码验证后直接发行Session，凭据目的仅有SESSION/SERVICE/ROLE_SESSION；尚无MFA挑战、因子状态、OTP消费或认证强度证据。现有密码重置、租户root恢复和平台离线恢复都不能因此被解释为MFA恢复。用户无手机号、邮件或微信也应能使用本地TOTP；短信、外部风险引擎和Passkey仍按012的前置处理。

#### 不同状态不能混用

| 状态或材料 | 责任与限制 |
| --- | --- |
| USER的TOTP认证器 | 真实凭据，绑定Account/USER及不可重用因子身份；有受保护种子、当前绑定修订、终态和已消费时间步。不是新Principal、Role或物理Device |
| 未完成的认证挑战 | 保存已经验证的阶段、闭合目的、实际主体/代际、过期、尝试预算和消费状态；不能访问业务、承担角色或充当Session。它的随机持有凭据与现有三类凭据分域，不能放进Session表假装“低权限登录” |
| 登录Session的认证事实 | 只在实际完成所需因子后记录方法、认证时刻和对应权威修订；用户后来启用MFA，不能将原密码Session倒填成双因子。历史缺字段不猜测MFA已完成 |
| 恢复材料 | 一次性高熵秘密及不可变批次归属；用于受限重新绑定，不是主账号转让、密码替代或可缓存业务许可 |

仍在现有IAM进程内由身份用例组织事务，纯TOTP校验与存储副作用分开；不先拆Identity/STS新服务，不增加泛化ChallengeStore/SessionStore。挑战确有独立的期限、消费和权限边界，只有其接口/存储形状在实现窗口冻结后才增加必要模型。

#### 绑定、替换与秘密托管

已有本人登录会话的主动首次绑定需重新验证当前密码；forced-change先沿既有密码流程完成，不能通过绑定清除must-change。账号强制MFA且无可用登录会话时的首次设置，走下述独立受限挑战，不绕过要求先发普通Session。待确认种子不能用于登录；必须证明持有该种子所产生的有效码，才在同一事务确认绑定并写入事实。替换需旧因子或合法恢复证明，加上新因子有效码；新因子确认前旧绑定仍生效，确认时原子终止旧绑定，不制造密码单独登录的空窗。

种子、provisioning URI/二维码和恢复码均属秘密，只经受保护连接的专用一次性响应传输，普通JSON、HTTP请求URL/query、审计、日志、support和浏览器持久缓存不得保存。provisioning URI内的种子参数仅是一次性内容，不能导航到第三方或发送给外部二维码服务。复制/打印是用户对恢复材料的显式操作，不自动下载到共享目录。创建回包未知只查询原非秘密完成；不重新展示种子或恢复码。无法继续持有原待绑定凭据时，明确废弃该待绑定意图后重新开始，不能悄悄创建替代秘密。

TOTP验证需要可用种子，不能仅存单向摘要；数据库应存目的、安装、Account/USER、因子身份和格式绑定的认证密文，只有IAM认证路径可解封。007的AccessKey私有keyring和envelope是单用途契约，不能把TOTP伪装成AccessKey以复用材料；密码hash、cursor key及离线恢复authority同样不是种子封装密钥。可复用受保护读取、秘密脱敏及标准密码学原语，具体独立材料/私有codec与安装、备份、readiness的衔接须另行冻结；没有真实托管证据不开放启用配置。

#### 登录与一次性消费

登录响应必须明确区分“已发行Session”与“需要继续认证”，不能在挑战分支返回半有效bearer。仅密码、账号和User当前状态验证成功后签发短期挑战，不在错误密码/未知realm时暴露是否绑定MFA。完成挑战时，在原Account→USER→凭据锁序下重新检查主体状态、密码代际、因子修订及挑战；密码改变、因子替换或挑战终止使旧阶段证明失效，不根据请求中的user/account字段换主体。原密码Session及不支持新响应的旧客户端不能绕过所需因子。

首次设置与已绑定因子丢失不是同一资格。账号要求MFA时，只有明确处于允许首次设置状态的USER才能获得密码验证后的设置挑战；历史因子被移除、损坏或状态未知不得被当作“从未绑定”而进入此路径。设置挑战只允许必要的初始改密和绑定，不允许读取业务、创建Key、承担Role或调整安全策略。初始改密仍须原子推进密码代际、撤销旧会话和挑战，再用新密码重新开始设置；不让旧挑战跨代际升级，也不通过设置清除must-change。绑定完成结束设置流程，正常重新登录并使用尚未消费的TOTP，才发行Session。它复用同一密码用例的不变量，但不是借现有普通Session或普通改密bearer冒充未完成认证。

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

数据库回退还可能使已用恢复码、已终止因子和旧挑战重新出现。仅增加数据库generation或消费表不能证明跨备份不回退；备份/恢复owner须提供明确的非回退资格或在恢复效果前拒绝不安全组合。不能从旧快照补造“最新”修订，也不声称能抵御本地root回滚全部磁盘和密钥。现有签名安装证据不覆盖这项新材料/消费边界，必须在MFA发布前补真实保留恢复门禁。

#### S2验收与未冻结衔接

- 既有credential/authority测试使用RFC标准向量及独立实现生成的所选参数向量；真实认证器完成绑定和登录。覆盖前导零、时步边界/超2038、前后窗口、错种子/主体、同一步重复、合法码跨目的/挑战/副本及相同码多步碰撞。
- 两个真实IAM副本证明密码正确但MFA未完成时不存在可用Session；错误码预算持久、并发成功只消费一次，认证/outbox末端失败无部分Session或成功事实。提交后断开真实TCP、重新登录、重启和等值schema重放不重发秘密、不复活挑战。
- 账号强制MFA下新User的初始改密/首次设置、已有因子丢失和状态损坏分别走准确路径；旧挑战不能因改密获得新资格。启停要求与普通/Role请求双向竞争，旧密码会话不能等待异步任务期间继续放行；弱化配置不能复活已失效会话或挑战。
- 绑定/替换/恢复与change/reset/logout、User/Account停用、平台附件写入双向竞争；旧单因子Session不升级、旧Role来源关闭、独立AccessKey不被虚假MFA事实放行。因子缺失/损坏/代际未知失败关闭，不按时间猜测认证强度。
- 实际受限PG登录、RLS/函数越权、种子跨安装/主体互换、仅IAM材料挂载与日志/审计/支持输出秘密扫描；恢复码单向存储、一次性返回/消费、批次更换和备份回退攻击。
- UX/UI owner完成真实绑定、登录挑战、换码等待、丢失回包、合法恢复和权限拒绝流程；不通过假OTP服务、空页面或截图代替运行。原密码/Session/Role/K2历史和canonical回归保留。

API闭合响应/路由、Authenticator/Challenge的实际最小字段、因子秘密托管、认证事实传播、封闭Audit action/actor、尝试预算及高权限恢复能力均需后续公共窗口逐项冻结。不得用泛化SYSTEM事件或伪USER决定省略证明；本设计未新增入口、权限、数据库表或依赖，不能据此标记S2完成。

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

账号安全配置是Account内单份有resourceVersion的治理状态，首片不另建可附件到Group/Role的安全策略语言或任意用户例外。管理员查看/更新需要各自封闭Action及当前PDP，准确权限与Profile在窗口内一并冻结，不能借`account.set-status`或密码reset权限顺带修改。普通User仅可在其已验证身份下取得设置自己新密码所需的有效约束，不取得全账号安全报告或其他用户状态。未认证登录响应不公开按realm变化的配置。

租户可配置范围是本账号日常User，不可通过规则修改间接接管、锁死RootIdentity或拥有未撤销INSTALLATION附件的USER；这些身份的固定底线及恢复另属已声明root/installation边界。平台保护根据未撤销附件而非“当前可登录/有效Allow”判断，与附件授撤共用principal锁序。主体后来进入/退出受保护范围不能删除其原历史、清除已消费预算或复活会话；资格和实际规则切换须有明确的锁内行为，不通过配置开关绕过已有凭据保护。

创建/修改配置、原请求完成关联和封闭Audit事实同事务；相同resourceVersion并发只有确定赢家。设置新密码的命令在写入前验证当前规则修订、主体/凭据代际及准确历史集合，不能依赖UI预检查或事务外缓存。状态变更、密码reset/recover与规则收紧交错时，过期验证结果不能落库。普通管理员规则不改变服务凭据、AccessKey、离线capability或RoleSession的密码语义。

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

规则范围/公共Action、匿名认证失败的Audit actor/target、持久尝试最小存储/回收、工作预算及状态码尚未冻结。不把已解析用户名写成已认证USER、不伪造SYSTEM或业务Decision、不将原始密码/失败候选放入Audit。仍沿现有credential、usecase、HTTP、PG和authorityprocess门禁，不新增通用限流服务或可替换Redis授权权威。共享实现窗口未开放前仅保留设计和固定来源决定。

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
