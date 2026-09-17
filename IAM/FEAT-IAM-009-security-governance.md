# FEAT-IAM-009：登录保护与安全治理

- 状态：设计；S1的本人登录会话目录、逐个撤销及精确重放语义已与公共消费者对齐；其IAM30/PaaS5固定集成期间，S1公共实现窗口尚未开放，函数形状/源码版本仅为提案，未实施/未验收。不并入007的K2固定交接，也不作为其消费者接入前置。
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

### 后续安全治理

TOTP 使用成熟密码学实现和标准测试向量，有挑战 TTL、尝试次数、成功一次消费和 generation 绑定。绑定成功前验证一次有效码，解绑/重置会撤销受影响认证会话。用户无手机号/邮件/微信环境也能使用本地 TOTP；短信/社交验证延期到 012，不冒充发送成功。

状态变更在 principal/credential/session 锁内验证并发，安全设置的 Account 默认与每用户有效配置区别明确。查看安全报告需要专门 Action，不暴露 key secret/MFA seed/密码 hash。报告声明采样时刻，不把报表作为 PDP 数据源。

持久报告/下载有账号查询绑定、数量限制和审计；后台闲置处理使用 database time、明确阈值、版本条件和一次性状态变更，失败不能升级权限。远端地理/IP 风险引擎没有数据源时保留需求，不编造风险分。

## 验收

真实浏览器双 session 改密选项、forced-change、登出/重置/recover 竞争，TOTP 时钟边界、重放和错主体挑战，安全设置旧行升级失败关闭；报告 Account 隔离与秘密扫描；用户/Key 停用即时有效且资源不被删除。Passkey 生产可信 origin 与硬件设备门禁条件见 012。
