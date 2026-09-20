# FEAT-IAM-012：外部身份、通知与组织治理

- 状态：最小安全邮件通知S1已获用户授权；S1a封闭模板/SMTP传输已通过本地协议、独立Postfix真实邮箱及固定提交独立CI。S1b的私有配置/验证码材料已实现，完整地址验证、持久投递/重试、安装配置及真实USER端到端通知尚未实现/验收；其余外部身份、完整通知/订阅、短信与组织治理保持Deferred。
- Owner：IAM负责S1的地址验证、目的限定通知意图/投递和重试；installation负责受保护SMTP及必要私有材料配置，UX/UI负责本人交互。其他外部来源与计费保持各自业务边界。
- S1a不等于完整S1或其他外部能力已实现；缺少前置时不提供假入口或伪成功。

## 需求、前置与验收

| ID | 完整需求 | 当前前置缺口 | 启用条件与真实验收 |
| --- | --- | --- | --- |
| IAM-EXT-01 | 用户 SAML SSO，既有 User 映射、metadata/cert 轮换、签名/assertion/replay/logout | 无获准运行的企业 IdP/正式域名 | 有隔离 Keycloak/ADFS/Okta 之一与受信 TLS；双账号错误 issuer/audience/recipient/时窗/重放均拒绝 |
| IAM-EXT-02 | 用户 OIDC SSO，authorization code+PKCE、state/nonce、账号映射 | 无获准 IdP/client registration | 正式 issuer/JWKS/redirect 注册和轮换，CSRF/mix-up/坏 JWT/失效账户测试 |
| IAM-EXT-03 | 角色 SAML/OIDC SSO，外部声明→Role trust→STS，无长期本地密码 | EXT-01/02 与 Role/STS | 真实企业用户断言、多角色选择和短期会话，原始身份审计，错 claim 不得任意选角色 |
| IAM-EXT-04 | 微信/企业微信关联导入、范围、解除、登录保护 | 第三方企业主体、审核凭据、回调/消息通道 | 获准沙箱/企业账号；真实导入/撤销/断联、账号绑定证明与隐私最小化 |
| IAM-EXT-05 | Passkey/WebAuthn 登录与管理 | 正式可信 origin/RP ID 与真实设备 | 注册/认证/跨 origin 拒绝/删除、设备丢失恢复及浏览器硬件门禁；不以纯 mock 通过 |
| IAM-EXT-06 | 跨账号协作者和角色承担，外部主体确认与信任双边撤销 | 本轮先关闭跨账号信任 | 两个真实账号、受邀同意、错主体/外部 ID、任一侧撤销、原始身份和资源归属完整 |
| IAM-EXT-07 | NotificationContact、消息订阅、手机号/邮件验证与短信 MFA | S1a传输已有下述独立实收证据；USER可信接收地址、持久投递和正式安装通道仍缺；完整订阅/短信仍延期 | S1按下述真实门禁；未验证地址不绑定，联系人不能认证/授权，邮件不替代MFA因子 |
| IAM-EXT-08 | 组织树、Account 管理、SCP 类上限继承 | 跨账号组织与可信所有者未建设 | 真实组织层次、上限交集/显式 Deny、成员移动与并发撤销、root 与服务例外封闭定义 |
| IAM-EXT-09 | 跨账号资源策略/ACL、匿名访问 | 没有声明支持的业务资源 owner | 至少一个真实产品声明协议，两侧许可、ACL 组合、匿名限制和列举隔离完整 |
| IAM-EXT-10 | 支付/账单/实名/账号关闭/销毁审批 | 本产品无商业计费和销毁编排 | 独立业务权威、可审计批准/延迟删除、资源保留和法律要求确认 |
| IAM-EXT-11 | 多地域策略分发、缓存水位与撤销 SLA | 无多故障域部署/复制机制 | 真实断网/延迟/分区/旧缓存攻击，撤销承诺和失败关闭；不能用本机缓存模拟宣称公有云规模 |
| IAM-EXT-12 | 自定义外部 MFA、风险地理/异常登录引擎 | 缺可信因子/风险数据来源 | 因子专用认证、重放/时效/失联策略、真实数据与申诉机制 |
| IAM-EXT-13 | 特殊 Agent/企业中心身份类型 | 产品语义和凭据生命周期未公开/未定义 | 独立确认主体来源、权限/凭据/删除语义，不能按外部 API 枚举臆造 |

## S1：最小安全邮件通知

最小目标是为009的绑定、替换/移除、恢复、恢复码重发和账号安全配置变化提供真实安全邮件：本人建立经过验证的接收地址，IAM原安全事务保存准确投递意图，受限投递器使用已配置SMTP通道，保留受理、未知、失败和重试结果。不实现消息中心、任意模板/收件人API、短信MFA、营销订阅或管理员代改他人接收地址。

该能力是已批准的IAM增量，不新增身份服务。安全接收地址属于真实Account/USER的非认证联系状态，不是Principal、Role、登录realm或恢复凭据。日常本人管理必须使用当前LOGIN_SESSION和该操作所需的再次认证；已有MFA时不能以更弱方式换走原可信地址。首次强制MFA设置尚无Session时，只允许009已证明NEVER_BOUND/合法REMOVED且密码已验证的当前ENROLLMENT挑战建立第一条地址；must-change尚未完成、已存在可信地址、丢失因子、损坏/未知状态及恢复旧备份均不能借此更换地址。它是受限设置的一个子步骤，不发行普通Session，也不将challenge放宽为用户资料bearer。地址验证码只证明该地址的当前持有，不允许登录、重置密码、移除MFA、切换账号或授予权限。初次验证、修改后验证和原地址告警的状态/API、受保护身份约束及并发规则先在本owner冻结，不能把普通User资料修改权扩展为安全接收地址控制权。

IAM负责验证期限/共享尝试预算、验证码一次消费、地址修订、原安全事件与通知意图的原子关联、受限领取/完成及有界重试；SMTP适配器只负责实际传输与结果归一化。installation负责SMTP配置和凭据的私有文件、用途/安装绑定、校验、最小挂载与启动/恢复行为；不能把服务器/端口/凭据交给业务请求选择，不能让普通API或Audit worker取得通道凭据。私有格式由下述S1b纯契约拥有；数据库角色、运行FILE及部署入口尚未实施，不生成空接口或占位服务。

地址验证邮件与安全告警邮件必须分开：前者可携带只用于原验证意图的秘密，后者不携带密码、种子、OTP、恢复码或可授予登录/恢复能力的链接。异步地址验证所需秘密必须有用途限定的受保护交付契约，不能明文放在普通JSON/outbox/support，也不能复用TOTP/AccessKey/离线恢复材料。下述独立包装契约不代替持久预算、当前身份及一次消费；这些前置未完成前不创建可用验证入口。

地址写入不是无限发信许可：验证发起须受当前USER/Account及目标地址的有界发送预算约束，另有共享验证码尝试/在途额度；更换地址、challenge、副本或重启不返还额度。邮件subject/body及验证用途由封闭模板生成，不接受任意正文、链接、header或SMTP目标，避免成为垃圾邮件/信头注入入口。邮箱所有权未知、是否已被别的主体使用不能通过公开错误枚举；确切语法范围、预算数值、TLS/通道配置、租约和私有投递材料将在可实跑切片中冻结，不以普通资料校验器或测试SMTP代替。

安全告警只从已提交的封闭安全事件产生，绑定原Account/USER、事件与可信接收地址修订，不从客户端body取得任意收件人或邮件内容。原意图重试不换地址、不再执行安全变更；地址变更对原/新地址的必要告警与历史投递处理需明确，不能以变更收件地址消除已经产生的安全告警。恢复旧数据库时，历史“已验证”地址也不是当前归属证明；可信接收状态须纳入009/安装恢复的关闭与重新开放条件。

SMTP成功最多证明渠道受理，不能冒充最终送达或已读；无可靠回执时保持准确观察。连接/提交结果未知不直接写失败并无条件重复，按提供者可证明能力核对；没有幂等/查询能力时明确允许可识别重复，但不能声称恰好一次。失败有限重试并持久告警；临时投递故障不回滚已经完成的身份安全变更，缺少第一条真实通道则仍阻塞完整MFA发布。

验收沿现有IAM/API/PG/authorityprocess、安装及UX/UI owner：跨账号地址/验证意图拒绝、旧会话/旧地址修订不能确认、同验证码并发一次消费、错误返回后预算保留、地址变化与凭据/账号停用交错、原事件与投递意图失败原子性、受限角色与秘密不泄漏、受理后失联/重启/租约冲突及真实邮件接收。协议fixture只能证明SMTP协议行为，不能代替用户授权的实际通道、已验证地址和收信证据。下述专属Postfix实收仅证明传输到合成测试邮箱；尚无真实USER已验证地址或正式安装通道，不复制私密邮箱凭据或自行使用个人邮箱。

本S1不重新开放其他延期能力，也不预分配schema/release revision。具体接口、来源采用记录及发布兼容在实现切片冻结；009拥有哪些安全事件必须通知，本文件拥有通知/地址验证机制，installation拥有配置与恢复交付。

### S1a：封闭邮件与SMTP传输

先在IAM原authority/data边界实现可独立验证的真实网络传输，不提前开放地址验证HTTP或因子绑定。新增SMTP adapter是该上下文此前不存在的邮件副作用边界，不增加消息中心、通用渠道接口或服务。私有文件/安装挂载、投递数据库身份、持久意图/重试及USER端到端通知仍归后续同一S1；本片不编辑installation的备份窗口或部署共享邮件服务。

收件地址首片只接受单个ASCII dot-atom邮箱与DNS域名，不接受显示名、地址列表、注释、引号local-part、地址literal、SMTPUTF8或CR/LF。保留local-part大小写，不悄悄改变用户地址；域名用规范小写。地址验证邮件仅携带本意图的8位ASCII验证码及明确期限，不能携带登录/恢复链接；这只是传输格式，未实现一次消费/验证预算前不生成可用验证码入口。安全告警只允许009列出的七种事件模板，无任意subject/body/header/附件/CC/BCC。邮件对象与通道配置默认格式化脱敏、普通JSON拒绝；发送时才显式编码，不把邮件正文作为错误或日志。

SMTP目标、发件地址与认证材料只来自受保护部署配置的后续消费者，不能来自业务请求；适配器构造时先验证完整配置。只支持验证服务器证书的STARTTLS或implicit TLS，最低TLS1.2、独立可信CA可选；不支持明文、跳过证书校验或TLS失败回退。AUTH PLAIN仅在实际已验证TLS后发送，须由服务器明确声明，不把内网/localhost自动当成可信例外。单次投递只有一个收件人、一条SMTP会话，最多30秒、连接建立5秒、服务器整个连接输入128KiB；TLS后的认证/信封/DATA回复每行最多512字节且完整CRLF。客户端同时最多2次且无本地等待队列；预算不是生产吞吐或通用互联网MTA承诺。

结果只描述本次SMTP观察：最终DATA终止后收到准确250为ACCEPTED，不代表DELIVERED/已读；明确4xx/5xx为REJECTED并保留非秘密三位码；完成DATA可能已发送而回包缺失/异常为UNKNOWN；效果前连接/协议/TLS故障及本地容量不足为UNAVAILABLE。正文写完不是成功，QUIT失败不推翻已经收到的250。适配器不自动重试，未知结果不能偷偷生成第二次投递。稳定Message-ID来自安装与持久通知ID，使用固定保留域后缀，不因SMTP目标或发件地址变化而换标识；它不是SMTP幂等保证，接收方仍可能重复投递。[RFC5321](https://www.rfc-editor.org/rfc/rfc5321.html#section-4.2.5)的受理语义和[RFC3207](https://www.rfc-editor.org/rfc/rfc3207.html)的STARTTLS规则作为协议依据，不能把一次成功连接当实际收信。

本片门禁在原IAM测试owner使用真实loopback TCP/TLS，覆盖证书/名称错误、缺STARTTLS/AUTH、认证及收件人拒绝、DATA终态失联/坏响应、250后失联、超时/取消/输入上限/并发容量、信头注入与秘密脱敏。它是协议行为证据；实际Postfix邮箱由同owner的独立opt-in门禁补充，两者都不证明持久重试或完整MFA。生产配置不绑定该测试供应商或邮箱。

2026-09-20本地门禁：Go1.26.3、GOMAXPROCS=2/GOMEMLIMIT=512MiB，SMTP实际TCP/TLS和域聚焦race/vet通过；最终测试强化实际DATA接收后取消及额外连接探测，三次连续race通过（包3.230s）。地址输入20秒/2 worker fuzz完成936289次、无失败；这不是吞吐承诺。相同生产代码的干净Git导出完成全仓默认race/architecture、vet、模块校验、120个API文件生成集合与SHA256完全一致及Linux amd64构建；默认外部环境SKIP不计PG/邮件交付验收。协议门禁曾实际暴露超长回复被截成`250`而误判受理，当前完整CRLF/有界回复门禁覆盖并拒绝该行为，不以扩大读取预算取得通过。

同日本任务新建独立、带唯一标签的Debian13/Postfix3.10.13服务，2CPU/768MiB/Pids128、独立网络、随机宿主端口且仅绑定127.0.0.1；不使用共享SMTP、真实私人邮箱或外部收件人。基础镜像固定`debian@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132`。实际`TestSecurityMailPostfixMailbox` race通过（用例3.22s/包5.560s）：验证服务器证书的STARTTLS及真实SASL认证后，验证码与安全告警均落入接收用户的真实Maildir，正文/收件人/模板目的吻合且无SMTP口令；错误口令535、外部转发5xx。主动重复同一安全通知确实产生两封具有相同Message-ID的邮件，证明不能把稳定ID当成SMTP恰好一次。门禁只接受本地Docker端点、精确完整容器ID、匹配标签、明确限额及loopback映射，仅读该容器的公钥证书/邮箱；未配置时SKIP不能称已验收。这是实际邮件传输/本地邮箱证据，不是联系人验证、MFA安全事件原子通知或最终用户已读证明。

最终相同源码再次干净导出，协议及真实邮箱连续两轮race通过（实收5.39s/6.57s，包15.906s），全部IAM/architecture的race与vet通过，回写前核对四个代码/测试文件SHA256与受验导出完全相同。邮件队列为空后仅删除本任务的临时容器与网络，未停止其他对象或重启Docker。本片未改数据库、公开API、发布profile或安装窗口，因此不重复执行无关的完整PG门禁，也不借此前PG证据宣称尚不存在的通知持久事务已验收。

固定`841ebe89aa55121ac4686dc469006ed10b47f0eb`的[Verification35496641320](https://github.com/xiak/matrix/actions/runs/35496641320)已在2026-09-20以GitHub API核实精确SHA；go、node-process、authority-storage、authority-runtime、authority-process全部completed/success。它证明该固定片保留已有数据库/进程回归，不将S1b尚未实现的联系人或通知事务列为已验收。

### S1b：本人邮箱验证与持久投递详细设计

本节定义下一纵向切片；其纯材料/私有codec增量已实施并进入下述门禁，HTTP/持久事务/worker尚未实现或验收。先交付真实完整LOGIN_SESSION的本人首条邮箱验证和真实邮件投递；同一模型随后接入009的强制ENROLLMENT/STEP_UP与已有地址替换，不另建realm、联系人身份服务或通用消息中心。前置未完成的分支明确拒绝，不能把它们作为兼容的弱认证入口。

#### 当前权威与增量边界

| 当前固定实现 | 复用与必须改变之处 |
| --- | --- |
| `285706e3`的真实Session、credential generation、Account/USER/Session锁及TOTP custody | 主体只能从当前LOGIN_SESSION或后继明确允许的ENROLLMENT挑战推导；RoleSession、AccessKey、ServiceIdentity不可管理该联系状态。已有准备版拒绝因子行的保护不能被联系人接口绕过 |
| `reserve_password_attempt`、`consume_password_attempt` | 当前只有LOGIN/PASSWORD_CHANGE。新增本人邮箱操作必须有封闭目的并绑定实际意图，不伪装成PASSWORD_CHANGE；密码失败预算仍与登录/改密共用，不加独立可轮换猜测额度 |
| `841ebe89`的SecurityMail及SMTP观察 | 投递器只消费持久意图，不接收外部任意SecurityMail。原STARTTLS/证书/模板/结果边界保持；SMTP客户端不接管事务、重试或地址资格 |
| IAM原事务、不可变完成和Audit outbox | 联系人成功变化与相应事实、告警意图同事务；不复用Audit claim给投递器查任意事件或秘密。SMTP不可放在数据库事务/身份锁内 |

最小数据由原IAM PostgreSQL拥有，只有不同生命周期或权限边界才独立保存：每USER当前联系状态及只增修订；有绝对期限的一次验证意图；共享发送/输入尝试预算；不可变通知意图与受限投递尝试/租约。联系状态与意图以真实Account/USER复合外键绑定并强制RLS。API和邮件worker均不取得直接表DML；仅授对应目的函数，worker无用户密码、Session、TOTP、权限管理、bootstrap/recovery或Audit投递函数权限。

#### 本人验证路径

1. 读取只返回本人当前状态`NONE|VERIFIED`、联系修订，以及确实存在的本人待处理意图元数据。`NONE`只表示没有安全接收地址，不表示User不存在、无需MFA或可恢复身份；不从其他账号地址推断身份。地址可供本人确认，不能进入租户成员公共列表、Audit、日志或support。
2. 发起首条验证要求Account及USER可用、真实LOGIN_SESSION仍有效、当前凭据代际准确、must-change已完成、没有当前可信地址，并重新验证当前密码。首片不提供替换/删除已有地址的旁路。密码计算前提交原共享预算；密码正确后最终事务重新验证原Session/代际/联系修订和闭合用途，再建立验证码意图及投递任务。
3. 验证码为安全随机生成的8位ASCII十进制，固定10分钟，不取决于用户名/时钟；不存在可登录或可恢复的链接。一个USER至多一个有效待验证意图，新意图原子终止旧意图，发送和失败预算不随其清零。返回验证ID、明确期限及`PENDING`观察，不返回验证码或“已送达”。
4. 确认仅接受原意图ID、验证码、请求ID和原认证载体。Account/USER、发起Session、密码代际、联系修订、意图绝对期限及后继的factor/settings修订都在锁内重验；调用者不能以新body、URL或别的Session接管原意图。正确码的消费、联系修订推进、原不可变完成及成功事实同事务；同码并发最多一个变化。
5. 错码是必须提交预算的业务拒绝，不能用回滚异常返还次数。确认回包丢失时，本人可查询原意图的非秘密完成；查询不再次提交候选码、不重新判定为一次成功。不同请求意图或密码/地址代际变化不能复用旧完成授予新资格。新密码登录、重建challenge或切换副本不复活终止意图。

拟定HTTP由`api/iam/v1`原生成owner统一实现和交接后才冻结：`GET /v1/auth/notification-contact`、`POST /v1/auth/notification-contact/verifications`、`GET /v1/auth/notification-contact/verifications/{id}`、`POST /v1/auth/notification-contact/verifications/{id}:confirm`。不接受accountId/userId/SMTP服务器/发件人/任意模板selector。普通Session分支与后继ENROLLMENT分支严格互斥；首片只开放前者，不能预先接受一个尚无真实状态机的challenge凭据。读取原完成仍须证明本人，不是全局command查询。所有秘密请求走原严格解码、专用编码与`no-store`，不会放入URL或浏览器持久化。

后继已有地址替换必须证明当前密码及已绑定因子对应的目标限定STEP_UP；变更要求按操作前有效规则判断。旧地址在新地址实际确认前继续接收安全告警，新地址不能消除已创建的原地址通知。确认替换后旧/新地址各有封闭通知，原通知目的/收件修订保持。强制ENROLLMENT只允许已经证明NEVER_BOUND/合法REMOVED的首次地址子步骤，不允许丢失因子或旧备份借此换走既有地址。相关新模板/事实须与这条实际变更一起加入，不能用七种现有模板冒充地址替换；本设计不授权管理员代换、在线MFA恢复或邮件登录。

#### 有界尝试与防滥用

发送预算与猜码预算分开，前者在建立意图前扣除，后者在比较前扣除；两者都跨副本持久化。首片采用数据库当前时钟锚定的固定窗口：同USER最多3次/10分钟、同Account最多100次/小时、同目标地址最多5次/小时、整安装最多1000次/小时；同USER验证码失败预算最多5次/10分钟且最多一个在途验证。允许窗口边界的有界突发，不声称滑动窗口或生产容量SLA。目的地址的预算键是私有用途摘要，不成为公开邮箱目录；同地址可属于多个USER，不能以全局唯一约束暴露他人关系。

本人的预算拒绝可以返回原Problem约定的有界重试提示，但不得返回“此邮箱已使用”、其他主体ID、目标地址的剩余额度或特定持有状态；公共错误不区分未知/他人邮箱。目标地址及安装预算不足不能先产生可用验证码或成功事实。过期/新意图/换Session不返还原USER窗口内的猜测额度。崩溃、数据库提交不确定、持久预算不可用均不能继续宽松验证；只有可证明事务已回滚的40001/40P01沿原重试规则处理。

预算行按主体/地址窗口有界保留，过期临时意图与秘密可清除，但清理不能删除当前窗口计数、不可变成功或原投递完成。具体函数/约束和定量门禁随持久实现冻结，不添加无消费者的通用限流服务，也不把进程内两条SMTP连接当共享预算。

#### 目的限定材料与安装交接

以下私有命名及单向隔离已由installation owner确认不与同快照consumer冲突；本固定增量只实现IAM纯契约/材料，未因此增加部署进程、运行FILE、迁移、schema/profile或发布revision：

| 材料/进程 | 拟定最小契约与暴露范围 |
| --- | --- |
| `SecurityMailSMTPChannel` | `apiVersion/kind/purpose=IAM_SECURITY_MAIL_SUBMISSION/scope{installationId,bootstrapDigest}/host/port/tlsMode/username/password/from/可选trustedCaPem`；唯一私有codec，不接受URL、客户端路径、TLS关闭或跳过证书选项。仅邮件投递进程持有；IAM API、Audit/PaaS、verifier/support不持有 |
| `EmailVerificationKeyring` | `purpose=IAM_EMAIL_VERIFICATION_WRAPPING`、同封存scope、修订/activeKeyId及受限有序key集合；每key格式1、独立32字节随机材料及非秘密承诺。只供IAM与邮件投递进程保护原验证意图；不是TOTP/AccessKey/离线恢复材料或通用消息加密服务 |
| `matrix-iam-notification-dispatcher` | 独立受限数据库登录`matrix_iam_notification_worker_login`及role`matrix_iam_notification_worker`；只领取/完成已提交通知，单实例最多2个在途。不是用户或服务principal，不获取通用PDP/原Audit worker权限 |

后继IAM运行片的编辑边界已对齐：IAM拥有其API/Audit、原迁移library/`matrix-iam-migrate`、通知worker及对应真实测试；专用迁移FILE冻结为`MATRIX_MIGRATION_IAM_NOTIFICATION_DSN_FILE`，仅允许在共享migrationprocess中实施第六个受保护IAM角色文件直接要求的精确形状/测试，不能变成任意FILE或权限入口。installation继续独占layout、localmachine、topology、release/releasebuild、FEAT-005及签名离线门禁，只在后继固定生产提交及精确CI之后集成文件挂载和发布profile。本次窗口许可不等于这些消费者、角色或函数已经实现，也不授权把当前准备版profile改标为通知可用。

验证码按独立AES-256-GCM/HKDF用途密封；上下文绑定封存安装/bootstrap、Account、USER、原验证ID、确切接收地址、联系修订、密码代际、原签发/到期及keyId/格式。通知私有持久行只存秘密的认证密文，不存明文或可离线遍历的短码无密钥摘要；生命周期比较时仍重验当前权威，能够解密不等于可以确认。普通JSON、原Audit outbox、Audit、错误和support不输出原码、密文或keyring。重试使用原已保存密文和同一意图，不生成新码、不延长有效期。受控恢复须终止备份中的未完成验证及未发送验证邮件；具备历史密钥不自动赋予恢复后重发资格。

独立部署材料不能各副本自行生成。缺文件/错安装/未知key/不一致承诺必须关闭相关路径，不能复用另一个purpose或自动重置联系状态。原BootstrapDigest与长度分界原语仍单一拥有；私有codec可复用严格解码/Secret/标准密码原语，不能把新材料伪装成TOTP以继承其scope、备份或恢复验收。保留旧key与在途引用的真实核对、轮换及恢复约束随实际消费者验证；本片不宣称自动退役/跨profile兼容。

#### 纯契约和验证码材料增量

`api/iam/v1/security_mail.go`拥有SMTP私有文件及`EmailVerificationBinding`的唯一格式1上下文；`email_verification_wrapping.go`隔离验证码包装材料，与TOTP、AccessKey和恢复authority不是同一种文件。新增文件分别保护跨进程安装输入与独立秘密用途，原contract测试仍拥有验证，不新增测试框架。ASCII邮箱语法从S1a authority移动到唯一纯契约owner，原authority/SMTP直接消费，不保留第二校验器或旧别名；SMTP行为和稳定Message-ID不变。

SMTP文件最多32768字节，口令最多1024字节，CA集合最多16384字节/8项；CA为无额外文字/header、LF编码且不重复的规范PEM证书，明确CA约束，不把宿主路径当信任内容。只提供`Encode/DecodeSecurityMailSMTPChannel`私有codec；普通JSON及格式化不能输出凭据。结构校验不是当前安装归属证明，后继消费者仍要与封存scope准确核对。

EmailVerificationKeyring最多8192字节、1至8个按keyId严格递增的格式1密钥，材料是规范无padding Base64URL的独立32字节值，修订在1至MaxInt64、active必须存在。`Encode/DecodeEmailVerificationKeyring`是唯一私有codec；`EmailVerificationKeyMaterialCommitment`只绑定独立用途/安装/bootstrap/keyId/格式/材料，`EmailVerificationKeysetDigest`另绑定整个有序集合和修订/active。集合扩大不能改变原key承诺；这两个摘要都不证明历史单调、引用安全、退役资格或备份恢复权。

原`CredentialIssuer`新增均匀拒绝采样的8位随机码生成；比较只接受相同的8位ASCII码，用常量时间比较。`EmailVerificationCipherContext`复用已有uint32BE字段分界原语，但使用独立HKDF-info/AAD域；真实安装/bootstrap、Account/USER、验证ID、邮箱的local-part大小写、generation/联系修订、UTC微秒签发与10分钟内到期、keyId/格式全部绑定。原authority中的密封/解封只接受该目的8字节明文、随机12字节nonce和24字节认证密文，错误不返回部分秘密；调用方key缓冲不被修改。纯密码学不消费验证码、不维护失败计数、不发Session，也不自动检查当前SQL资格。后继原子事务未完成前仍不开放验证入口或MFA启用。

2026-09-20本增量的干净Git导出通过全仓默认`race`/architecture、`vet`、模块校验、122个API文件生成集合及SHA256完全一致、Linux amd64构建；Go1.26.3、GOMAXPROCS=2/GOMEMLIMIT=512MiB，六个代码/测试文件与受验导出逐一核对相同。原contract/domain门禁覆盖规范私有codec、用途/安装/原意图绑定、错密钥和移植密文、熵失败、长度/时间/CA边界、秘密格式化及普通JSON拒绝。两个私有codec各20秒/2 worker fuzz通过（keyring197481次、SMTP368684次）；不是性能承诺。独立CI待该固定增量确认，不用S1a成功回填。本片没有SQL或运行FILE变化，默认数据库/真实邮箱SKIP不计新验收；已有Postfix证据只证明S1a传输，不能代替上述尚未实现的本人验证和持久投递。

#### 投递、重试与事实

原事务保存不可变通知ID、封闭kind、Account/USER、固定收件地址及修订、原安全事件/验证意图、内容版本和签发时间；安全告警来自已提交权威事实，不重新执行原用户当前权限。USER或Account后来停用不抹掉已完成安全变化的历史告警；验证邮件则必须同时满足当前原验证意图仍有效。两条规则不能混成“停用就删除所有通知”或“历史验证码仍可继续验证”。

领取使用原IAM数据库当前时间、有界批量和`FOR UPDATE SKIP LOCKED`；每次保存attemptId、单调fence、期限，再释放事务后执行SMTP。完成只接受持有的未过期lease及闭合结果，旧worker不能覆盖新尝试。进程崩溃后原lease过期记为UNKNOWN而不是未发送，原意图仍保持固定；接收者可能已经收信，不能强称仅一次。

状态区别是`PENDING/IN_FLIGHT/RETRY_WAIT/ACCEPTED/FAILED/EXPIRED`，并独立保留每次`ACCEPTED/REJECTED/UNKNOWN/UNAVAILABLE`观察、数值SMTP码和时间；不存服务器原错误文本。最终250才置ACCEPTED；明确5xx终止，4xx或效果前不可用有界重试；UNKNOWN必须显式记录可能重复，再按同一通知ID重试，不把它伪装成一次新通知。首片最多5次，间隔30秒、2分钟、5分钟、15分钟，验证邮件另受原10分钟期限约束；已接受不能被迟到失败覆写或再领取。没有最终送达/已读回执就不提供相应状态。

失败告警不得通过同一个已坏SMTP通道无限自发邮件。首片提供受限投递器的稳定失败类别/计数及原通知完成观察，安装运维可以据此识别通道异常；具体用户安全通知仍要真实邮件接收证明。若需要新的管理读取权限，应单独对齐最窄动作，不借租户管理员或平台身份默认读取所有人的联系地址和正文。

#### 本片验收

沿原contract/domain/usecase/PG18/authorityprocess及SMTP实收owner证明：两Account/同名USER的意图和地址互不接管；Session/密码/联系版本改变后确认拒绝且无部分写入；5次错误额度跨两副本/重启/新意图保留；并发同码只一次成功；原请求回包丢失仅查询已完成结果，换地址/密码/候选码不能被视作原成功。新目的不能消费LOGIN或PASSWORD_CHANGE的密码保留，也不能反向使用。

真库验证发送预算及租约/fence、恶意直接DML/越租户ID、跨安装/USER/意图/地址/期限密文互换、缺key/错key、成功事实与通知任务原子性；真实进程使用受限登录和受保护文件。实际Postfix完成验证码邮件到邮箱、取码经真实HTTP确认、已提交安全通知实收、4xx/5xx/失联/进程中断后的状态/重复语义。不得用测试直接改验证码摘要/联系人状态、mock邮箱确认或只读队列行替代该路径。UI由UX/UI owner在固定API后完成，不在本任务重写页面。

## 其他延期能力的架构预留

复用 Principal/ExternalIdentity、IdentityProvider、TrustPolicy、RoleSession 和统一策略语言。每个 provider 使用专门 adapter，输入断言在验证前不可信。保留接口责任和字段语义说明即可，不先生成无消费者的接口、空表、fake provider 或 UI 全套占位。

微信/企业微信、IdP 品牌和供应商 API 仅属于 adapter；自研产品不借外部品牌定义 Account/User/Role。延期能力进入实现时要在本 FEAT 拆出有独立验收的切片，补固定来源、release/profile 和运行环境约束后才由 Deferred 改为 Implementing。
