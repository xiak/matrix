# FEAT-IAM-009：登录保护与安全治理

- 状态：设计；S1的本人登录会话目录、逐个撤销及精确重放语义已与公共消费者对齐；其IAM30/PaaS5固定集成期间，S1公共实现窗口尚未开放，函数形状/源码版本仅为提案。S2已补TOTP挑战/恢复设计及当前源码缺口，尚未冻结材料、恢复和公共契约。均未实施/未验收，不并入007的K2固定交接，也不作为其消费者接入前置。
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

#### 拟定的封闭入口

下列是实施前提交给公共契约消费者的提案，不是已存在API；实际请求/响应、SQL签名与schema须在独立窗口一并冻结。007的固定`644fff09`已完成独立CI及交接，消费者无需等待S1。

| 入口 | 行为与边界 |
| --- | --- |
| `GET /v1/auth/sessions?after=...` | 本人当前有效登录会话，固定100项和稳定ID seek；响应`SessionList{apiVersion,kind,accountId,userId,currentSessionId,observedAt,items,nextCursor?}`。Account、User、当前Session均来自bearer；items复用现有Session，不借本片修改其已有wire字段。不接受user/account/session selector、任意排序或页大小 |
| `POST /v1/auth/sessions/{sessionId}:revoke` | 复用严格`RevokeSessionRequest{requestId}`，目标必须是同Account、同USER的另一登录会话；响应`RevokeOwnSessionResponse{outcome,revocation}`，outcome准确为APPLIED或EQUAL_REPLAY，revocation复用原非秘密Revocation。目标为当前Session时明确冲突，使用既有logout，不生成两套当前退出语义 |

目录不列已撤销、实际已到期或generation不再有效的历史记录；“当前有效会话”只表示认证资格，不代表它具有任何业务权限。历史记录仍在原Session和Audit owner保存，不在此增加管理员目录/回收站。返回的sessionId是资源引用，不是bearer；绝不返回lookup/verification digest、密码hash、credential generation内部证据或可兑换凭据。该目录不证明用户的RoleSession/AccessKey已退出。

items必须是非NULL数组、至多100项、同Account/USER、ID严格递增且无重复；每项均在observedAt时ACTIVE、未撤销且未到期。分页后的items不一定包含currentSessionId，不能据此判断当前会话已消失。只有实际读到第101条时才提供nextCursor，不凭固定页长猜测后续；末页可以因并发失效而变空。

分页复用原opaque cursor和独立安装key，增加封闭的本人Session目录绑定，不创造可由caller指定的通用purpose。每页先重新验证当前身份，再核对安装、Account/USER、当前Session、凭据代际、准确查询与固定页预算；旧游标不能跨用户、账号、登录会话或安全状态使用。继续使用数据库时间，游标不得越过当前会话的有效期。目录不是冻结快照；并发登录/退出与自然到期可改变后续页，不借游标维持已失效的身份或旧权限。

#### 事务、历史与并发

撤销目标的不可变归属必须在锁内验证；仅在事务外查出同USER不够。顺序沿现有Account→USER→凭据→Session；同USER命令共用真实principal屏障，多个Session按稳定ID取锁。当前bearer的真实session/generation、Account/User状态及目标资格在锁内重检；SERIALIZABLE重试重读整个身份，不能保留等待前的旧认证结果。缺失、跨用户、跨账号、Role/Key替换均无效果，也不泄露另一个目标是否存在。

精确重放绑定原USER、实际调用Session、目标Session、requestId和封闭输入承诺，只返回原完成信息，不再次更新状态或补第二个事实。已由其他意图、logout、改密/reset/recover撤销的目标不冒充本命令成功；已到期目标同样不是新的可执行撤销。更换bearer后复用相同requestId不能把原“保留当前、结束另一会话”的意图换成另一次操作。未知回包保留原意图；当前认证资格已经失效时不能凭旧请求ID取得新许可，需正常重新登录并由用户明确发起新意图。

先验证当前caller，再读取其Account/USER下的完成关联。准确完成优先于目标今天的到期状态，EQUAL_REPLAY仍返回原Revocation；它不表示目标今天仍可登录。只有原意图尚未完成时，才按当前目标资格执行新撤销。输入承诺使用本人撤销的封闭目的，包含实际actor Session、目标Session与requestId，不与logout或管理员命令互认。保留原Session的日常改密不把其旧游标变有效；仍有效的同一Session查询自己的原完成只读取历史，不重做副作用。

沿用`iam.session.revoked`的原租户事实含义，真实USER为actor、被结束的Session为target；自管理不填写伪造iamDecisionId。状态、不可变输入/完成关联及outbox必须同事务，旧canonical/hash和管理员事实保持。现有终态和outbox没有原调用Session到请求意图的唯一绑定，不能把旧函数的`applied=false`当成准确重放；因此拟在原Session SQL owner增加仅用于本人撤销另一会话的不可变完成关联。它以Account/USER/requestId唯一，绑定真实caller/target Session、输入承诺、原Revocation与outbox事件，准确约束同USER归属和一个目标的一次完成。它不是可复用许可或第二个Session模型，不新增通用receipt服务。API/worker没有直接表读写权限；真实FK、强制RLS、不可变/禁止truncate及同事务完整性由数据库验证。当前记录、claim、service identity或K2 key证据都不因本设计而改变。

#### SQL形状与所有权提案

复用`000001_authority`的Session拥有者，不新增迁移目录或平行撤销器。当前`lookup_session(text)`保持原23个输出列的顺序，仅在末尾追加内部`credential_generation bigint`，供本人游标绑定；旧NULL代际行继续不可认证，不回填。新增`list_own_sessions(tenant text,user text,current_session text,after text)`只返回`id/status/issued_at/expires_at`四列，固定按ID取至多101条以生成100项页面，无秘密或caller可选limit。它在同一权威快照中核对当前Session和同User有效代际，适配器复用真实已认证Account/User构造原Session投影。

原`revoke_session(text,text,text,text,jsonb)`拟在末尾追加真实`actor_session_id text`，返回仍为`resource_version/revoked_at/applied`。logout、管理员撤销与本人入口均传实际bearer对应的Session；删除旧五参函数并验证不存在，不留未重检当前会话的旁路。管理员分支仍要求原精确Decision且拒绝forced-change，logout仍只结束调用会话；无Decision的本人另一会话分支要求上述精确完成关联。管理员和目标不同User时按稳定ID同时锁定双方principal，再检查当前actor和目标，不能倒置原密码/状态/恢复锁序。旧logout或管理员的已撤销结果不是本人新意图的EQUAL_REPLAY。

提议的源码版本为IAM31/Audit18，仅对应真实IAM函数/表/ACL/readiness变化；尚未冻结或修改实现。record9/contract4、evidence5、claim7、lookup_service5及旧canonical不变。此片不分配最终release contractRevision、不改发布profile；安装owner在实际消费者组合中另行冻结和验收，源码数字增加不产生升级许可。

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
| 提交后回包丢失、重启再重放 | 原有效A只能取回同一完成；变体、换caller或新意图操作已结束目标均不能产生第二次完成 |

- 两Account、每个至少两个USER、同名登录与两个实际IAM副本：目录只含本人，当前标识来自实际bearer，另一会话结束后跨副本新请求拒绝，当前会话继续有效；普通无业务策略的User和forced-change会话均有上述最窄自管理能力，但仍不能访问业务。
- 真实101条会话的分页、时间到期、错误/跨用户/跨账号/跨Session cursor、伪current/user/account字段、Role/Key/SERVICE凭据与NULL/错误generation全部按当前契约拒绝。不能用字符串形状或mock Session证明归属。
- 撤销、准确重放、变体/新意图操作已撤销目标；并发相互撤销、logout、三种改密选项、reset、原root/platform恢复及Account/User停用，分别证明双方先提交的状态与失败无部分效果。forced-change的只减权补救不能使旧临时会话升级。
- 末端outbox失败整笔回滚；真正提交后丢失响应、当前认证随后撤销、重启与schema等值重放不重做原意图。Audit延迟投递保留原事实/归属/hash，不按当前登录资格重写历史。
- 真实PG18、受限登录/RLS与SQL越权、原unit/architecture/security/进程门禁及精确SHA独立CI归现有owner。UI全部交UX/UI工程师，在固定契约就绪后再接入并独立做浏览器闭环，不由本片替代。

沿用`api/iam/v1`契约/生成测试、`authority/cursor_test.go`、`identityaccess/service_test.go`和`nethttp/handler_test.go`证明封闭输入/响应、凭据分离、游标绑定及用例控制流。真实SQL/RLS、撤销竞争与旧函数消失归既有`integration/http_postgres_test.go`的附件/会话owner；跨副本、原TCP故障、Audit失联及重启归`test/authorityprocess/process_e2e_test.go`，不增加平行测试框架。先聚焦再累计回归，不修改现有单项时间、密码成本或规模来取得通过。保留数据验证只选择实际受支持固定前驱及明确受影响的会话证据，不要求为每个未发布中间schema维持永久升级链。

S1仅设计先行，源码版本/函数形状提案尚待公共窗口确认，release contractRevision不提前分配。不变更Phase3的PaaS/Audit查询PEP、edge解析、NorthboundOrigin/APISIX、source release Profile或安装工作，也不要求其等待S1。

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

### 安全策略、报告与运营治理

状态变更在 principal/credential/session 锁内验证并发，安全设置的 Account 默认与每用户有效配置区别明确。查看安全报告需要专门 Action，不暴露 key secret/MFA seed/密码 hash。报告声明采样时刻，不把报表作为 PDP 数据源。

持久报告/下载有账号查询绑定、数量限制和审计；后台闲置处理使用 database time、明确阈值、版本条件和一次性状态变更，失败不能升级权限。远端地理/IP 风险引擎没有数据源时保留需求，不编造风险分。

## 验收

真实浏览器双 session 改密选项、forced-change、登出/重置/recover 竞争，TOTP 时钟边界、重放和错主体挑战，安全设置旧行升级失败关闭；报告 Account 隔离与秘密扫描；用户/Key 停用即时有效且资源不被删除。Passkey 生产可信 origin 与硬件设备门禁条件见 012。
