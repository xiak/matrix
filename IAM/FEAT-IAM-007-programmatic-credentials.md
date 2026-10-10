# FEAT-IAM-007：访问密钥与程序访问

- 状态：实施中；K1管理及K2内部验签、原子拒绝/防重放与历史证据的累计后端固定`644fff09446fc8ffb003cc53cf2fb55d4f58828a`已通过本地真实PG18、固定前驱保留数据、独立进程、最终全仓检查及五项独立CI。实际产品消费已累计到`efe12e824b6534e7b6912c6ed9900c7f0c53e3e9`：PaaS已覆盖已列明的创建、实例读取、Deployment控制和Application声明标签，Audit覆盖精确租户记录查询、完整性验证及可信外部source IP。Account/key网络限制和不可变使用摘要固定于`472596b1`及后继Audit修正，并由累计`91649497`的完整独立CI确认；当前签名APISIX安装、受保护入口托管、同Profile升级/回滚、指定备份恢复、外层引擎重启及旧凭据永久围栏已由下述固定组合实跑。LIVE UI、跨Profile兼容及最终发布仍未完成，整体未验收。
- 依赖：003、005；临时凭据与 006 协作。
- Owner：IAM credential；各产品 HTTP 签名消费归其 PEP。

## 需求

| ID | 行为 |
| --- | --- |
| IAM-KEY-01 | User 长期 key create/list/disable/enable/delete/rotate；Secret 只返回一次 |
| IAM-KEY-02 | 类型化签名协议绑定 method/path/query/body digest/time/nonce/audience；拒绝重放 |
| IAM-KEY-03 | key 只有主体当前权限；不能绕 forced-change、状态、boundary 或租户归属 |
| IAM-KEY-04 | key 使用时间/结果/安全摘要，失败尝试不泄密 |
| IAM-KEY-05 | Account 和 key 网络限制有明确组合语义和可信 source IP |
| IAM-KEY-06 | 长期 key 与 RoleSession credential 分开，停用/删除即时生效 |

## 详细设计

### 产品对象与最小纵向交付

AccessKey 是真实 User 的程序认证凭据，不是 User、ServiceIdentity、登录 Session 或 RoleSession 的另一种名字。Account 仍拥有资源；key ID 仅定位凭据，不能由调用者选择 Account、主体或平台 scope。秘密只用于每个 HTTP 请求的签名，不作为浏览器 bearer，不兑换可重复使用的登录会话或通用 USER permit。

| 切片 | 可验收结果 | 不得提前宣称的能力 |
| --- | --- | --- |
| K1 密钥管理与托管 | 当前登录 USER 经精确权限管理同账号 User 的 key；真实受限数据库中的一次性秘密、生命周期、并发和审计闭环 | 只有创建/列表不等于程序能访问业务；秘密配置必须真实接入安装边界 |
| K2 签名与业务授权 | 独立客户端签名，经真实产品 HTTP PEP、IAM 验签/防重放/当前 PDP，完成 PaaS 读写与 Audit 查询/关联 | 不把只验 HMAC 或模拟 USER 当作业务接入；不自动开放平台、probe、服务或角色承担 |
| K3 使用治理与网络限制 | 可信来源 IP、Account/key 限制组合、带观测时间的使用摘要及相应攻击/重启门禁 | 009 的完整治理与外部网络/VPC 接入仍分别验收，不复制供应商网络 ID |

首片只支持同账号非 root USER，不为 Account Root、ROLE、SERVICE_ACCOUNT 创建长期 key。具有未撤销平台权限绑定的 User 不能通过租户凭据接口获得或被接管程序凭据；这一保护必须与实际平台绑定写入在同一锁序下证明，不能只在 UI 或事务外检查当前有效权限。其他 User 的管理者仍须有精确 key 管理许可，不能由用户目录可读或管理员名称推导。

KeyCreate 在主体锁内检查目标当前状态、允许的凭据类型和数量，写入材料、元数据、原意图与 outbox；创建 key 不附加权限或清除 forced-change。每用户最多两把未删除key，ENABLED和DISABLED都占名额；只有显式删除才释放名额，不能先禁用积存任意数量再恢复。支持创建第二把、业务迁移、确认新 key 使用、禁用旧 key、再删除的交叠轮换；创建与启用必须在同一真实主体/配额锁内检查，不能由两副本各算一个名额。管理凭据来自实际有效登录 bearer，并在锁内重检，不能把 key 自己的签名当成修改自身安全设置的额外权限。

删除为不可逆终态，后续不重新使用其 ID；停用/启用是显式管理操作，启用不恢复任何已撤销登录/角色会话。长期 key 的启停不能套用临时 RoleSession 的永久失效代际语义。当前的会话撤销实现不能被误称为已撤销未来 AccessKey。不提供尚未解决回包丢失的一步“覆盖原 Secret 并立即停旧 key”；交叠轮换也不能仅靠没有最近使用记录就断定旧 key 可安全删除。

创建成功只在专用一次性响应返回秘密。原意图查询/精确重放只返回非敏感完成元数据，不重发旧秘密、不生成替代 key。回包丢失保留原 requestId；确认已创建但秘密丢失后，显式废弃原 key 再创建新意图。不得把加密可用材料当作允许再次展示 Secret 的理由。

### K1管理入口与原子事实

这些入口已在本分支候选实现，不是已发布API。只接受当前有效登录Session的USER及其真实管理权限，不要求物理浏览器或检查User-Agent；不允许ROLE、AccessKey或服务凭据充当管理者，也不存在隐含的“本人当然可管理key”权限。Account只从Session取得，路径中的userId/keyId只是必须核对同账号归属的资源引用，不接受body/header/cursor中的账号selector。

| HTTP入口 | 请求/结果边界 | 精确Action及授权目标 |
| --- | --- | --- |
| GET `/v1/users/{userId}/access-keys` | 最多两把未删除key的非秘密列表；无全局目录或分页cursor | `iam.access-key.list`，USER INSTANCE |
| POST 同一集合 | `{userResourceVersion,requestId}`；新ID/Secret；APPLIED经一次性encoder返回Secret，EQUAL_REPLAY只返回原非秘密完成信息 | `iam.access-key.create`，USER INSTANCE；最终创建ACCESS_KEY |
| GET `/v1/users/{userId}/access-keys/{accessKeyId}` | 当前非秘密元数据，不提供Secret/ciphertext导出 | `iam.access-key.read`，ACCESS_KEY INSTANCE |
| POST 同一key的 `:set-status` | `{accessKeyResourceVersion,requestId,status}`；status准确为ENABLED或DISABLED | `iam.access-key.set-status`，ACCESS_KEY INSTANCE |
| POST 同一key的 `:delete` | `{accessKeyResourceVersion,requestId}`；新意图只删除DISABLED key | `iam.access-key.delete`，ACCESS_KEY INSTANCE |

创建/启用检查目标User和Account均ACTIVE、无forced-change、非root及无未撤销INSTALLATION附件。读取、禁用及删除可以由具有精确权限的有效管理员作用于停用/待改密的普通User；平台身份的锁内保护继续适用。相同状态的新意图冲突，准确原意图仅重放原结果。首次响应设置`Cache-Control: no-store`且不记录响应体；普通JSON拒绝Secret序列化。候选源码IAM Profile使用r5添加这些TENANT/USER动作，保留r1–r4的原字节、默认策略和显式授权要求，不能自动为既有用户补权。

管理投影沿用现有ActionCapability，不引入另一许可模型。`AccessKeyList`包含真实accountId/userId、当前`userResourceVersion`、准确一个create能力及最多两条按ID排序的`AccessKeyAccess`；每条准确包含read/set-status/delete三个服务端提示。列表不是分页，禁用key仍占名额；create所需用户版本在这个已授权目录内提供，不强迫调用者另有user.read。能力是当前提示，命令仍重新鉴权和锁内检查。创建返回`{outcome,key,secret?}`，精确重放的key是原始版本1/ENABLED元数据，不是今天的可用性声明；状态变更返回原完成版本，删除返回不带可逆状态或材料的`AccessKeyDeletion`。任何读取、列表、重放、删除结果都没有Secret、ciphertext、安装ID或wrappingKeyId。

在现有迁移owner增加`000011_access_keys`，因为密文的一次性落库、永久wrapping登记和非秘密完成意图有独立的持久不变量，不能放进Role/STS表或伪装为Session。创建先在同一事务占用不可复用的随机key ID，然后才封装；延迟约束保证未封装/未完成意图不能提交。actor与目标User按ID顺序持有NO KEY UPDATE锁，再检查当前会话/平台附件及配额，沿用现有平台授权锁序。Serializable事务等待主体锁不等于刷新旧快照；管理事务按既有写入顺序先共享锁定actor当前USER/GROUP附件及Boundary引用的全部Policy，再锁定USER及actor来源GROUP授权代际。Policy锁覆盖不推进附件代际的默认版本变更及Deny来源；已提交的变更迫使旧快照重试，后到的变更等待本管理事务提交。这里只复用权威变化的MVCC屏障，不推进代际、不把它写入key，也不将长期key解释为RoleSession。原意图、key、不可变事实与outbox同事务提交；原意图只存非秘密结果。上述顺序已有真实数据库双向竞争证据，发布组合仍须独立验收。

审计只增加四个封闭租户事实：`iam.access-key.created/enabled/disabled/deleted`，由真实USER、原精确决定和ACCESS_KEY target关联；不提供泛化status-set事实或自由attributes。User删除在同一事务内为最多两把key各形成一次`iam.access-key.deleted`，随后原User删除事实；其授权证明只允许原`iam.user.delete`的USER INSTANCE决定映射到事务中证实属于该User的key，不扩大为任意key删除许可。create/delete集合或User决定不承诺最终key payload；源事务/outbox证明真实创建/级联归属。失败不得留下部分材料、删除或成功事实。

K1不改变公开Subject、ServiceIdentity、record8/evidence5/claim7或既有Audit canonical。候选新增函数和存储由IAM29/Audit17承载，源码IAM产品Profile为r5；真实进程同时核对PaaS2及实际readiness。发布profile/revision没有修改，源码数字不能作为安装兼容证明。

### K1生命周期与其他凭据的关系

以下生命周期约束区分K1管理候选和后续K2程序请求，不以管理门禁推导签名已可用。ENABLED仅表示key自身未被禁用；可用性还需要每次请求的真实Account、User、强制改密、权限/Boundary和产品认证载体支持，不能用这个状态绕过PDP。

| 操作或当前状态 | Key自身状态/材料 | 对下一次程序请求的含义 |
| --- | --- | --- |
| 创建 | 仅当前ACTIVE、非root、非服务、无未撤销INSTALLATION附件且已完成强制改密的User可创建；新ID、新Secret、ENABLED、资源版本1 | 仍没有新增业务权限；Secret只在首次明确提交成功时返回 |
| 普通改密、保留/撤销其他登录会话、退出或到期 | 不隐式轮换/删除/禁用独立AccessKey，不把密码generation当作key发行代际 | 登录/角色会话的原约束保持；key依据自身状态和当前权限重新判定。界面不能将“退出登录设备”描述为回收所有程序凭据 |
| 管理员重置密码、其他合法操作设置forced-change | 不改变key自身状态，也不暗增reset接口的key管理权限 | forced-change期间拒绝程序请求；完成真实强制改密后，按原key状态及当前策略重新判定。疑似key泄露仍需单独显式禁用/删除，不能声称改密已处理 |
| User停用/Account暂停 | 不删key、不改资源归属或停止既有工作负载 | 当前请求拒绝；恢复后ENABLED key可按当前权限发起新签名，旧已拒绝签名的nonce不能重放 |
| key显式禁用/启用 | 按当前resourceVersion做ENABLED/DISABLED转换；同意图重放不增版本 | 禁用后拒绝；显式启用只恢复该key未来签名资格，不恢复旧Session/RoleSession或旧nonce |
| key删除 | 必须先DISABLED；保留不可复用ID及最小历史归因/完成记录，移除可解密材料，形成不可逆删除终态 | 永久拒绝该ID；重放创建/启用/删除原意图都不能重建材料或回显Secret |
| User删除 | 与原User删除同事务，所有key进入不可逆删除终态并移除材料；失败则全部回滚 | 旧key、会话均不可用；历史决定/outbox仍由原证据证明，不追查今天的key |
| User获得未撤销INSTALLATION附件 | 不通过key获得平台认证载体，原租户凭据修改保护继续成立 | 首片程序认证整体关闭该目标；撤销附件后仍须当前User/key/策略通过，不能据附件状态返回旧许可 |

账号暂停时不提供在线key变更旁路。目标User停用或待改密时，具有准确权限的当前有效管理者仍能读取非秘密元数据、禁用及删除已有key；不能创建或启用。root/服务主体/未撤销平台附件的凭据变更保护在真实锁内检查，不能通过先停用目标再修改其key绕过。原root恢复与平台离线恢复不接受AccessKey目标，不新增恢复key秘密的入口。

同一意图重放返回的是**原完成事实**，不是当前key为ENABLED的证明；当前状态通过独立授权读取。已有完成意图先核对当前actor和相同管理动作权限、原actor/目标/requestId与输入承诺，然后返回非秘密事实；不因后续key停用/删除再进行一次创建。新意图则完整检查目标、版本和配额。错误版本、目标/actor替换、提交未知、末端outbox失败、两个IAM实例的最后名额竞争与停启/删除交错必须在原真库/进程owner证明，不用纯状态枚举测试代替。

### 秘密材料与安装责任

保留公开 key ID + 一次性 Secret 的 HMAC-SHA256 产品语义，不为了免除秘密托管而偷偷换成公钥注册。签名使用标准库算法，不自创密码原语。HMAC 验证需要受保护的可用材料；仅保存单向 hash 不能满足验签，原 opaque bearer 的 lookup/verification digest 不能当作 HMAC key。

采用安装托管的独立32字节高熵封装密钥（KEK），通过HKDF-SHA256为每个AccessKey记录及封装版本派生独立32字节AES密钥，再用标准AES-256-GCM保护至少32字节CSPRNG生成的Secret。KEK不能直接作为全表共享AES密钥。数据库仅存格式版本、wrappingKeyId、nonce和ciphertext/tag；派生上下文与AAD绑定installation、Account、User、key ID、目的和材料版本，交换归属/材料必须失败关闭。封装材料与数据库分离，普通 API 数据库登录不能读取明文或调用数据库解密函数；PaaS、Audit、worker、verifier 和浏览器不能取得解密材料。IAM API 是当前验签/解封装边界，不声称能在其进程完全失陷后保护全部可解密材料。

安装 owner 负责受保护文件、同安装多实例配置、完整备份/恢复配对、密钥版本与轮换，以及签名发行/启动准入；IAM 负责格式验证、目的/归属绑定、受限使用和缺失/不匹配时关闭。禁止复用 bootstrap 密码、cursor HMAC、签名发行私钥或离线恢复 authority。重启时随机生成新封装密钥会毁坏已有 key，不能作为默认行为；也不能从数据库备份自行猜测密钥版本或跨安装重绑定。

跨IAM/installation的不可逆秘密托管边界归[ADR-0004](../docs/architecture/ADR-0004-access-key-trust-boundary.md)。下述文件契约已与安装owner冻结；纯codec固定点不涉及schema或Profile，也不是文件权限、数据库匹配或真实安装证据。K1候选的源码变化不改变现有发布准入。

### 私有keyring与逐密钥承诺

唯一FILE环境名为`MATRIX_IAM_ACCESS_KEY_WRAPPING_KEYRING_FILE`，容器路径`/run/matrix/iam-access-key-wrapping-keyring.json`，安装内相对路径`secrets/authority/iam-access-key-wrapping-keyring.json`。仅IAM API取得只读文件挂载；migration、dispatcher、PaaS、Audit、worker、verifier和本地恢复入口均不得挂载文件或其父目录。安装owner负责父目录0700、常规非链接文件0600、有界读取及原子持久写入。秘密不进入环境值、Compose文本、签名包、manifest、数据库、journal、support或Audit。

私有文档准确为`apiVersion/kind=AccessKeyWrappingKeyring/purpose=IAM_ACCESS_KEY_SECRET_WRAPPING/scope{installationId,bootstrapDigest}/activeWrappingKeyId/keys[{wrappingKeyId,formatVersion,keyMaterial}]`。K1准确一把active key，格式1、43字符严格无填充base64url编码的32字节CSPRNG材料；不以格式验证冒充随机性来源证明。文件最多4096字节，原字节必须与唯一encoder输出完全一致；拒绝重复/未知/缺失/类型错误、字段重排、别名转义、空白/末尾换行/第二文档及非规范base64。不提供多格式兼容、热重载、目录扫描或caller路径selector。

现有`api/iam/v1`新增`access_key_wrapping.go`拥有安装私有codec和纯编码；这是不能混入公开AccessKey DTO的秘密文件边界，不新增包/服务/通用文件框架。仅显式`EncodeAccessKeyWrappingKeyring`与`DecodeAccessKeyWrappingKeyring`可写读材料，普通JSON双向拒绝、格式化隐藏材料，错误归一化为`ErrInvalidAccessKeyWrappingKeyring`。显式临时byte buffer及时清理；Go字符串和内部库副本不保证物理擦除。安装和IAM不复制codec，公开OpenAPI不暴露该类型。

`AccessKeyWrappingKeyCommitment(document,wrappingKeyId)`先验证完整私有文档和准确key，再输出`sha256:<lowerhex>`。它不是整文件摘要或授权能力；输入准确为uint32大端长度封装的domain `matrix.iam.access-key-wrapping-key.commitment.v1`、purpose、installationId、bootstrapDigest、wrappingKeyId、单字节formatVersion和解码后的32字节KEK。它不绑定active selector、数组次序或其他key，使未来增加密钥不改变旧key的承诺。单个包内长度编码原语同时供commitment和`AccessKeySecretContext`使用；不开放caller自定义domain/字段列表的通用canonicalizer。原authority中的上下文编码器被移除，格式1原info/AAD字节保持。

K1候选数据库提供不可改的wrapping-key登记：installation+wrappingKeyId唯一，首次材料写入同事务插入或精确匹配commitment；冲突全部回滚。API登录无直接DML；只要被使用过，登记及ID/材料对应关系永不因User/key全部删除而删除或重绑定。启动/readiness读取全部历史登记，K1只能是零条或当前文件对应的一条；进程对bootstrap digest与材料commitment使用常量时间比较，SQL使用唯一约束及精确匹配。零条仅证明尚无已提交key，不授予创建或在线管理权限。真实数据库已覆盖登记保留与错误材料拒绝；安装备份配对仍需安装owner实跑。

网络入口必须配置冻结的FILE，先用唯一codec核对实际bootstrap，再在数据库bootstrap收敛前后核对封存receipt/全部历史registry。原有受保护读取器承担绝对路径、常规文件、有界及稳定读取；IAM额外要求可见POSIX文件准确0600，并核对读取前后同一文件。只加载一次，构造Authority时复制并封闭材料，调用方之后修改配置不能改变进程KEK；不热重载。安装owner仍负责宿主目录0700、文件身份及仅IAM API的只读挂载，容器内文件读取不冒充这些验证。没有wrapping配置的本地恢复用例不取得密钥能力，也不能宣告网络READY。

IAM启动同时核对私有文件、实际bootstrap和数据库封存receipt（复用唯一`BootstrapDigest`）；任何文件缺失/损坏/权限错误、安装或commitment不符都使整个IAM不READY，不只隐藏某个endpoint。新安装或显式支持的前驱升级仅生成一次；等值重放验证原文件，已经持久化后不得因丢失而生成替代。回滚保留材料，旧release仅忽略它。当前仅同安装root保留材料：数据库备份保留registry，安装owner在受保护backup兼容承诺中绑定所需逐key摘要，在数据效果前核对，启动再核对；raw KEK不进入backup产物。K1不实现KEK轮换/移除、跨机密钥托管/KMS或整机root回退防护。实际安装和备份门禁仍由各自owner完成后才能验收。

### HTTP 签名与业务接入

公开 wire/唯一编码 owner 为 `api/iam/v1`；HTTP 提取在各产品 PEP，认证/防重放/当前授权在 IAM。发布有版本且有界的 Matrix 签名规范，明确大写 method、唯一 escaped path、严格 percent-encoding 排序且保留重复项的完整 query、实际 body SHA-256、所有影响请求语义的 header、signedAt、至少128-bit随机 nonce、key ID、算法及固定 audience 的唯一编码。query签名保留重复项不等于某个业务参数允许多值；业务自身的单值/未知字段校验仍执行。重复安全 header、歧义 path、异常编码、错误 body、过期/过早、跨服务或跨安装均拒绝；不把 Secret 放在 URL。

#### K2 请求签名基础

唯一协议基础放在现有`api/iam/v1`，新增`access_key_signing.go`仅拥有与私有KEK文件不同的跨产品请求wire/编码边界；HMAC验证仍在现有IAM credential owner。它不发行决定、不消费nonce、不开放HTTP路由，也不证明程序请求已可执行。

Authorization的唯一格式为`Matrix-HMAC-SHA256-V1 KeyId=<id>,Installation=<id>,Audience=<product>,SignedAt=<unix-seconds>,Nonce=<base64url>,Signature=<base64url>`。参数顺序固定，逗号后无空格；不接受其他算法、重复/未知/缺失参数、引号、空白别名或多个Authorization值。Nonce为16字节随机数的严格无填充base64url，Signature为32字节HMAC的相同编码；格式校验不冒充随机性来源证明。签名密钥是`mak1.`后解码的原32字节，不是整个Secret文本、摘要或KEK。秘密、原签名和nonce只允许显式传输编码，普通JSON/格式化不得泄露。

规范请求准确覆盖参数中的key ID、installation、audience、SignedAt、nonce，以及实际method、HTTP scheme、authority、escaped path、完整query、Content-Type、Idempotency-Key、If-Match和body SHA-256。长度前缀编码复用现有私有原语，各UTF-8字段使用uint32大端字节长度；domain为`matrix.iam.access-key-http-signature.v1`，字段顺序为协议scheme、key ID、installation、audience、十进制SignedAt、nonce、method、HTTP scheme、authority、escaped path、raw query、content type、idempotency key、if match、body digest。HTTP scheme准确为`http`或`https`，服务端不得按caller转发header猜测；协议能表示HTTP不等于批准明文生产部署。空header也作为空字段绑定；正文摘要为`sha256:<lowerhex>`，包括零字节正文。HMAC-SHA256直接覆盖这些规范字节，结果常量时间比较；请求摘要为同一字节的SHA-256，不是业务payload真实性或可缓存许可。

path最多2048字节、query最多4096字节且64项；仅接受规范UTF-8/RFC3986百分号编码，hex必须大写，不允许把unreserved字符编码成别名。path拒绝空/点段、重复或末尾斜杠（根路径除外）、编码斜杠/反斜杠/百分号及控制字符。query每项必须为非空name加`=`及value，按编码后的name递增；**相同name的原顺序保留并参与签名**，不按value排序以免改变first/last语义。不修复收到的不规范请求；单值参数的重复拒绝仍归实际PEP。纯wire的authority使用小写ASCII DNS/规范IP，可带规范十进制端口；省略端口与显式默认端口是不同签名输入，不能自动删补。真实部署另由安装owner的NorthboundOrigin要求显式端口并精确匹配。不接受userinfo、zone或转发header猜测。三个业务header逐字节覆盖，拒绝控制字符和首尾空白；不把大小写/空白归一化当作请求等价证明。

签名请求的Content-Type首片准确为`application/json`或无正文时的空值，不能借宽松media-type参数改变解释。PEP对Cookie、Matrix-Subject-Credential、Content-Encoding、X-HTTP-Method-Override、未覆盖的语义header、trailer及重复security header在实际入口拒绝；Content-Length/Transfer-Encoding不签，实际body受原产品上限和HTTP解析约束。这里的纯编码无法证明HTTP提取正确。

安装入口显式接收唯一规范`NorthboundOrigin`，不能从Host、Listener、节点地址或caller转发头学习。当前直接APISIX拓扑只接受`http`且显式端口必须等于发布监听端口；TLS终止和可信多级代理需要另一份可验证拓扑契约，不能在本片虚报`https`。origin作为安装身份的一部分进入sealed journal、等值重放和拓扑摘要；升级、回滚、备份恢复不得换origin。APISIX将`/api/paas/`、`/api/audit/`重写为内部路径前删除caller的`Forwarded`、`X-Forwarded-For`、`X-Real-IP`、`Matrix-Subject-Credential`及三个Matrix edge header，再分别覆盖恰好一个安装origin、原始`$request_uri`和直接`$remote_addr`。PEP严格拆解后重新编码必须与实际内部EscapedPath/RawQuery逐字节一致；尾随空`?`、双`?`、fragment和absolute-form拒绝。API继续只拥有scheme/authority/escapedPath/rawQuery四字段及唯一编码，不拥有安装模板。标准`X-Real-IP`和`X-Forwarded-For`不参与HMAC，但必须各只有一个且与Matrix source完全相同，`Forwarded`必须不存在；这阻止内部调用者只伪造Matrix专用头绕过可信边缘。真实签名安装的运行证据仍由下述当前切片提供，纯配置和单测不能提前标记LIVE。

程序入口必须按method+route template+action/resource闭合，不按产品prefix泛化开放。首片限定现有tenant application/configuration/revision/deployment/operation，以及外部`/api/audit/v1/records:query`、`/api/audit/v1/integrity:verify`；managed-services、terminal、node/host/platform、probe/installation verify、Audit ingest和IAM管理/AssumeRole均不开放。固定动作可在真实body capture后先IAM再业务decode；已有`PUT /v1/deployments/{id}`按DesiredState选择update/stop，允许capture后用原严格DeploymentSpec契约做一次无副作用完整解析，选择准确动作，再单次IAM，最终业务复用同一已解码值。该结构解析失败不验证签名、不消费nonce；不得以部分JSON扫描、宽泛许可、两次PDP或授权后另一decoder替代。路由/头/body大小先检查；其他动态动作必须逐项审计并对齐。

数据库权威时间窗口为过去300秒/未来30秒，端点包含；有效窗口只参与认证，不能替代当前key/USER/Account/PDP或持久nonce事务。标准HTTP歧义及重放风险参考[RFC9421安全边界](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.5)和[RFC3986编码](https://www.rfc-editor.org/rfc/rfc3986.html#section-2)，这是Matrix的有界协议，不宣称实现整个RFC9421。

纯协议、载体与策略兼容候选的最终干净源码树`26715a9bd17e6caf2ed372cb20679d1b83c37220`在Go2/512MiB下通过全仓race/p2（含架构）、vet、模块校验、契约生成文件集合及字节不变、Linux amd64构建。API/authority完整race为16.450/5.443秒。Node独立UTF-8长度前缀/SHA-256/HMAC向量同时覆盖JSON写请求和零正文GET，四个可为空的HTTP字段仍须显式存在；错误Secret格式、显示文本冒充原32字节key、16类字段替换、URI/重复query次序/非规范编码及数据库时间窗口分别关闭。签名wire的原2-worker/20秒模糊门禁21.946秒、566025次执行通过，之后生产编码未改。冻结编译模糊门禁加入载体兼容及错误摘要检查，2-worker/20秒预算实际22.077秒、751193次执行通过；全部现有声明的USER目标模式、32组载体/Effect组合和不匹配资源上的旧Deny均在原测试owner检查，主体扩展、未使用条件/目标形状变化仍被新路径拒绝，原登录路径不被改写。该纯基础固定点没有HTTP入口、nonce行、决定、公开actor/Operation字段、schema/profile或安装配置；这些只证明纯基础，不是K2业务或生产接入验收。

PEP 必须从它实际处理的请求取得字段并计算 body digest，不能接受 caller 提交的“已规范请求”替代真实 method/path/body，也不能只把 Authorization 文本转交 IAM。PaaS 的 Idempotency-Key 等影响行为的 header 必须被绑定；反向代理公开 authority/路径的转换、body 大小和一次读取后的安全重用由真实消费者明确。IAM 保留当前服务凭据的独立认证，核对其封存安装、purpose 与已登记产品能力，不能把 caller audience 当作已认证服务归属。

有效签名只证明持有 key 并承诺这次请求；IAM 仍检查当前 Account、User、forced-change、key 状态、适用策略/Boundary 与动作/资源。signedAt用数据库权威时间判断准确过去/未来窗口。有效签名的nonce按key在数据库中原子唯一消费，只存摘要且保留超过最大签名窗口；包括最终Allow、Deny及当前key受限的结果，防止原拒绝包在后来授权改变后重放。错误签名/未知key不产生攻击者可放大的nonce行。拒绝结果与nonce需要提交，不能因为用例最后返回认证/权限错误而回滚防重放状态。

多实例使用同一持久权威去重，不能用本机 map/粘性路由或异步 Redis 失效代替撤销保证。重复消息与产品业务幂等是两个边界：客户端重试需新签名/nonce，但保留原业务requestId/idempotency；相同 nonce 的两个并发业务请求不能都获得许可。内部 RPC 重试、IAM 已提交但响应未知、nonce 保留/清理时限需要与真实 PEP 一起冻结，不通过放宽重放或返回旧permit来避免处理未知结果。

允许决定必须匹配实际请求及签名证据，业务只消费这次结果，不将其缓存为用户许可。身份始终是原 USER，认证载体明确为ACCESS_KEY；公开Decision/PaaS/Audit只增加最小accessKeyId归因，签名证据仍留IAM。哪些当前动作支持程序载体须由产品已登记能力和真实 PEP 共同决定，不能在通用求值器写死产品名或把 `subjectTypes=USER` 推断成所有认证方法均可用。具体字段形状及旧USER无key分支的兼容解释在公共API切换前冻结。

#### K2 原子授权与受保护历史

后端工作树已实现内部入口`POST /v1/authorize:access-key`，只以当前服务Bearer认证调用服务，不接受Matrix-Subject或主体/租户selector。请求准确为`{authorization,signedRequest}`，前者是原AuthorizationRequest，后者复用唯一显式签名wire。封闭结果为`{apiVersion,kind:AccessKeyAuthorization,decision,signedRequestDigest}`；摘要必须从实际通过MAC的规范字节产生，PEP独立核对该摘要、原请求/决定和key归因。不是JSON wire摘要，不含原签名，不提供结果重用或nonce查询接口。实际HTTP严格检查方法、无query/主体selector、单一服务Bearer、准确JSON媒体类型和无内容编码；公开schema来自同一契约owner，私有证据和材料不进入OpenAPI。

防重放归原decision事务：新增私有一对一`access_key_authorization_evidence`，主键/外键为`(tenant_id,decision_id)`，仅由原`record_authorization`写入。typed列绑定真实AccessKey、当时resourceVersion/formatVersion、wrappingKeyId与永久材料commitment、封存安装、实际调用服务、audience、signedRequestDigest、nonceDigest及signedAt；不把FK/唯一性只放进opaque JSON。`UNIQUE(access_key_id,nonce_digest)`永久保留，前提是原AccessKey全局ID及索引唯一性实际成立。表无PUBLIC/API/worker直接ACL，有不可变及禁止truncate保护；它不是第二个授权服务或可重放permit。key定位索引只负责RLS前的ID到真实tenant定位，owner-only、永久唯一、不可改，并精确FK到原key tombstone。迁移只为真实既有行登记；冲突、缺失registry或不一致全部回滚，不补key或改归属。

先认证实际服务并验证结构及安装/服务目的/audience，再定位key。格式合法且MAC有效的请求，无论当前Account/User/key状态、forced-change、策略/Boundary、载体能力或时间窗口是否允许，均形成同事务的ALLOW或DENY及原outbox，永久消费nonce。**过早/过期但合法MAC也记录DENY**，避免后来进入时间窗口再使用原包。结构非法、服务身份/请求绑定不成立、未知key、已删除材料或错误MAC不写nonce/决定；对外不区分key存在与状态。重复nonce永远拒绝，不返回原ALLOW/DENY，不另写决定或成功事实；新传输重试使用新nonce并保留业务幂等键。只有确认未提交的事务失败可整事务有界重试，提交未知不自动重发原nonce。

锁序按真实物理身份排序：全部涉及的Account先按ID全局排序，再所有principal按`(tenant_id,id)`排序，然后依固定类别取得service credential、Policy、USER/GROUP授权代际及AccessKey锁。读取使用能与状态/撤权更新冲突的SHARE，不以KEY SHARE冒充；Serializable等待后遇到旧版本须重开事务，不能继续旧快照。原密码Session不进入AccessKey上下文，当前策略/Boundary仍复用唯一PDP。记录器9参在末尾接收严格nullable key evidence，显式contract4；旧8参删除，不保留旁路。当前源码IAM30/Audit18的实际函数/列/ACL/readiness已有下述真实PG验证，PaaS仍为2；产品Profile及发布profile/revision未修改，源码数字不构成发布或兼容证明。

当前服务凭据没有独立credential ID/version，不补固定版本。其真实历史身份为`home account + principal + purpose + lookup digest + verification digest + created_at`，另绑定sealed installation。记录SQL仅接收已认证调用的lookup digest，在锁内经原service_credential_index重新定位并读取完整元组，不接受应用自报整个元组。原身份列必须不可改，只允许revoked_at从NULL单调撤销；两张原服务凭据表的身份/索引不得UPDATE、DELETE或TRUNCATE，迁移先核对真实行/index/FK一致，不修补或猜测历史。lookup_service仍五列，ServiceIdentity不加字段；材料摘要只在私有证据中。将来轮换需独立真实凭据模型，不能覆盖这组历史身份。

当前有效策略快照会过滤RETIRED策略，不能从它推断“没有受保护平台附件”。K2必须在相同USER/来源代际锁内直接查询所有未撤销INSTALLATION附件，独立返回并在record9重检保护事实；私有读取缺字段或与实际策略快照矛盾均失败关闭。策略退休不是撤销，编译结果和UI提示也不是附件历史。record9只在严格非空、MAC已验证且归属/服务/目的/audience/时间与nonce结构已绑定的key evidence分支接受停用Account/User/key等已知限制的DENY，原子消费nonce并记录事实；无key evidence的LOGIN_SESSION、ROLE和SERVICE分支保留原ACTIVE条件。SQL CHECK/readiness和真实PG必须分别证明分支互斥，不能只凭Go调用路径验收。未知key、已删除材料、错误MAC及无效服务绑定不取得这一例外。

contract4的载体矩阵闭合为：LOGIN_SESSION USER无keyId/key evidence；ACCESS_KEY ALLOW的USER keyId与私有证据相同；ACCESS_KEY DENY的公开决定仍无subject/tenant，但私有证据必须存在；ROLE只带原Role evidence，SERVICE_ACCOUNT没有两种USER凭据证据。公开keyId仅是现有Subject/Actor末尾omitempty字段，经PaaS原嵌套RequestedBy传播，不新增顶层重复字段。`read_audit_evidence`可保持五列，但内部须验证一对一证据、永久key归属/registry、原服务元组、请求摘要和原outbox一致；不要求今天key/User/service有效或密文仍存在。原LOGIN_SESSION/ROLE事件及canonical bytes不改变，claim7不变。

`userAuthenticationMethods`由原Profile owner承载，是请求载体准入而非另一许可。它只解释USER，闭合值为LOGIN_SESSION/ACCESS_KEY；历史缺字段只表示LOGIN_SESSION，新改写声明显式给出规范集合。key请求必须满足当前Profile显式支持、实际闭合PEP和同一USER的当前policy/Boundary三层。旧USER compilation不能靠忽略digest复用：唯一`CheckAccessKeyPolicyCompilationRequest`先复用原完整编译/引用/目标检查，再以同一规范编码比较请求动作的全部原语义。产品、调用服务、scope、resourceKind、全部shape/usage、subjectTypes、条件及创建结果必须相同；除已含ACCESS_KEY的集合原样保持外，只允许缺省/LOGIN_SESSION增加ACCESS_KEY且保留LOGIN_SESSION，不允许同时删除另一载体。仅本地比较投影不绑定revision；两份真实完整引用和策略摘要仍先分别验证，投影不返回、不登记。其他变更失败关闭，需要显式重发策略；不因Deny尚未匹配资源/条件而略过，LOGIN_SESSION保留既有解释。冻结动作族不吸收新动作，不参与本次动作的完整策略仍不贡献许可。新决定须同时保留当前请求Profile和原策略归档证据，历史proof使用当时两份声明重验，不改旧bytes或倒灌当前head。共用PDP与历史证明已接入后端；当前源码Profile仍只开放LOGIN_SESSION，须与实际产品PEP一同采用新revision才能验收签名Allow路径。

网络准入仅使用产品实际连接IP，或installation明确配置的可信代理链。Account限制与key限制取交集，不直接相信任意X-Forwarded-For，不把客户端VPC/网络名当权威。网络片未完成时不开放假配置面，也不宣称IAM-KEY-05通过。

#### K2 后端实现与当前证据

现有000011及PostgreSQL适配器已增加owner-only永久key定位、严格私有上下文与按序SHARE锁；不接受账号/用户selector、不伪造Session、不返回访问许可。服务purpose与audience通过当前已注册Profile对应，不在求值器写死产品名。完整平台保护事实来自未撤销附件，和过滤退休策略的有效策略列表分开。Account/User/key已知限制保留给后继MAC验证与DENY事务，删除材料和不匹配安装/服务返回不可用身份。原USER Boundary解码复用单一拥有者。

原000001服务凭据以真实tuple和三列locator外键保护历史，只允许revoked_at一次单调变化，不新增假credential ID/version。迁移先核对所有既有行；受事务DDL锁保护的owner校验完成后恢复FORCE RLS，不暴露运行期绕过窗口。真实带数据重放曾因过早恢复FORCE RLS导致外键校验失败，调整顺序后完整重跑通过，没有修补历史内容。

2026-09-17，专属受限PG18、实际API登录、Go2/512MiB/race-p1的原`TestIAMAccessKeyPostgres`累计76.50秒通过：真实HMAC及过早/过期签名提交Deny、两个IAM实例的nonce唯一竞争、末端outbox失败整笔回滚、四类受限身份提交Deny及恢复后的原包重放拒绝。record9的有效对照、旧ABI/版本、SQL NULL、角色与key混用、归属/版本/材料/服务替换及伪造actor均按真实SQL检查；缺少一对一证据的决定在延迟提交约束处失败且无残留。原key删除后、新nonce的已签包在调用服务仍有效时被拒；随后撤销当时的PaaS服务凭据，双次迁移及等值bootstrap不复活它，当前有效IAM producer仍可证明原已提交key事实。原六个上下文锁交错、24个管理竞争、配额、RLS/ACL/FK/不可变约束与历史投递门禁继续通过。实际SQL证据来自IAM受信任的验签/决策事务，不声称数据库独立验证HMAC、证明最终业务payload或抵御IAM进程完全失陷。

同轮原Audit owner在新专属PG18累计通过双authority存储5.68秒、固定9fd旧tenant记录升级0.31秒和真实HTTP1.56秒：全部封闭action的key actor正负向、同用户不同key/原无key过滤隔离、USER/ROLE/key混合链与旧hash保留，原受限登录、无key USER/SERVICE的record9及独立链并发继续执行。IAM API/Audit API/authority/usecase/HTTP完整race分别34.928/4.979/9.173/10.697/2.403秒通过。新增接口/schema测试检查明确空字段、签名编码、媒体类型、载体和响应无秘密；不将结构验证当作验签，跨字段及URI语义仍由唯一codec检查。此前测试误用自动约束名、raw SQL对照未转UTC和旧Audit fixture仍调record8造成的失败均修正后真实复跑，没有放宽生产检查。

原`TestIndependentIAMAuditAndPaaSProcesses`在另一新专属PG18上累计66.79秒通过：两个实际IAM进程/受限登录处理真实签名，同一用户的登录载体已有真实Allow，而源码Profile未开放的key载体提交Deny；坏MAC及用户/错误purpose调用不产生key决定。相同nonce并发只有一个Deny及一个409；真实IAM提交后故意关闭TCP响应，另一进程重试仍为409，不重发旧决定。Audit失联时提交签名事实，随后删除key和User；恢复投递后按实际USER/key/租户查询、原事件重放/原hash、错误key归因及混合链均通过。IAM重启仍拒绝原nonce与已删除材料，只为有效未删除key的新签名产生新Deny；六次有效签名准确对应六组决定/私有证据/outbox。既有K1、账号/组/策略/Role、PaaS/Operation和受限运行登录检查一起执行。此处传输故障只证明内部RPC提交未知，不是假装已接通产品PEP或任意数据库故障。

累计真库回归使用原限额与全部场景。Linux Go1.26.3、2CPU/1GiB/PIDs192 runner及独立1CPU/768MiB/PIDs128 PG18下，Audit存储/旧tenant保留4.951秒、HTTP2.171秒、IAM主矩阵565.886秒、Role/管理引用367.413秒及PaaS数据库2.318秒串行通过。IAM主矩阵包含完整策略、附件/会话、AccessKey、账号HTTP和离线恢复；Role包含全部七组，真实最小TTL到期、管理并发和安全矩阵均执行。原窗口下曾发生到期场景先阻塞60秒导致后续预算耗尽，现只提前发行该会话并在独立场景执行期间自然到期，保留全部到期与历史断言；另一次Windows管理矩阵120秒超时仍是失败，不据Linux通过推断根因、稳定性或容量，不放宽时限/密码/规模/重试。

原固定前驱保留数据与真实进程包累计135.218秒通过：角色能力前驱11.99秒、角色历史权威20.71秒、策略解释前驱27.38秒及双IAM/Audit/PaaS72.10秒。第一次迁移比较因整行JSON新增`access_key_id:null`失败；修正后逐项保持原字段/事实字节，并独立要求旧locator为NULL、subject无key且无key evidence，不能只排除新字段而不检查虚构归因。实际前驱产生的旧contract2/3、两次迁移、旧解释与历史投递均保留。未启用的其他历史binary及浏览器项为SKIP，不纳入本轮通过结论；不把源码数据保留当作跨release升级准入。

最终干净源码树`692e11027d666ea162ea6666f8ab316f60909385`在Go2/512MiB下通过全仓race/p2（含架构）、vet、模块校验、API生成文件集合/字节一致和Linux amd64构建；无DSN的默认测试不替代上面的独立真库门禁。累计固定`644fff09446fc8ffb003cc53cf2fb55d4f58828a`的[Verification35184409378](https://github.com/xiak/matrix/actions/runs/35184409378)已于2026-09-17通过GitHub API核实精确SHA，go、node-process、authority-storage、authority-runtime、authority-process五项全部completed/success。上述证据只证明本增量后端及既有回归，不是真实签名业务Allow、安装、UI、容量或发布验收。既有未声明AccessKey的Profile继续拒绝程序许可；不以测试临时开启源码Profile代替实际PEP消费。

### 材料保护纯函数

现有 `authority/credential.go` 复用原CSPRNG issuer与`iamv1.Secret`，不新增keyring服务或把AccessKey注册成opaque bearer。Secret文本为`mak1.`加32字节随机数的无填充、严格base64url；这个前缀只区分材料格式，不构成认证许可。封装的是原32字节，解封装只重建同一Secret，不生成登录凭据。普通格式化/JSON不能输出Secret，私有封装对象也拒绝普通JSON和格式化展开；数据库接入将显式传递字段，不能因此开放导出接口。

封装格式1的唯一算法如下；采用标准[HKDF上下文绑定](https://www.rfc-editor.org/rfc/rfc5869.html#section-3.2)和[Go随机nonce AES-GCM](https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce)，不自造密码原语：

| 输入/输出 | 固定格式 |
| --- | --- |
| IKM / salt / 输出长度 | IKM为32字节高熵KEK；salt为固定公开UTF-8字节`matrix.iam.access-key-secret.hkdf-salt.v1`；HKDF-SHA256输出32字节 |
| info与AAD的唯一编码 | 每字段使用uint32大端**字节长度**及原始字节；顺序为domain、`ACCESS_KEY_SECRET`、单字节格式版本、installationId、accountId、userId、accessKeyId、wrappingKeyId。版本1字段准确为`00 00 00 01 01`，无末尾或额外字段 |
| 分域 | info的domain是`matrix.iam.access-key-secret.kdf-info.v1`，AAD的domain是`matrix.iam.access-key-secret.aad.v1`；共享编码算法，不共享或误用同一结果buffer |
| 私有envelope | `FormatVersion=1`、wrappingKeyId、12字节nonce、48字节ciphertext（32字节材料+最后16字节tag）。采用结构化字段，不提供内部JSON解码；普通JSON编码与解码均拒绝 |

scope逐项沿用现有ID验证、保持大小写，不trim、case-fold或Unicode规范化；AccountID就是已统一命名的原Organization.ID/TenantID，不增加归属实体。预期scope来自权威行，不从密文自称取得。使用Go标准库`NewGCMWithRandomNonce`产生nonce，不接受调用方提供加密nonce。打开前拒绝未知版本、错误引用/长度，所有材料错误统一失败关闭；wrappingKeyId即使错误映射到相同KEK bytes也不能换名打开。

每个`accessKeyId + wrappingKeyId`派生密钥的应用加密调用上限为**一次**，不是标准随机nonce所允许的理论2^32上限。首次创建必须先在当前事务中通过服务端CSPRNG ID的数据库唯一占位，再Seal；有界事务重试持有同一ID、Secret和sealed output，只重写原材料。等值重放只读非秘密完成记录，不能再次Seal或再次展示Secret。碰撞必须先换全新ID，不能用现有ID加密另一Secret；进程崩溃/新请求不能证明持有原sealed output时也重新生成ID，调用者永远不能指定ID。纯函数没有持久化或调用计数；K1候选在真实事务中验证了先占位、40001后的相同completion材料、碰撞换ID及有界耗尽，而不是从密码函数单测推断这些保证。

wrappingKeyId永久对应唯一KEK原材料，移除后也不得复用该ID。rewrap不在本片；未来必须迁向全新wrappingKeyId及KEK，事务重试复用其原sealed output。不能在同版本重加密、换KEK、降级旧版本或在无法证明原调用结果时盲重试；旧key缺失必须关闭，不能静默略过记录。Secret/keyring在进程失陷下的泄露以及Go内存中的完全擦除不是本函数可保证的边界。

2026-09-17，现有credential测试改用Node.js `crypto.hkdfSync`及`crypto.createCipheriv("aes-256-gcm")`独立产生的固定公开向量；直接KEK草稿对新向量首先真实失败，替换为单一派生实现并补齐各字段canonical拒绝后，聚焦race/p2门禁1.947秒通过。向量逐字节覆盖salt/info/AAD/派生密钥/nonce/ciphertext/tag及完整结构化envelope；另验证同KEK不同key ID派生不同key、确定性、字段长度边界、随机nonce、所有归属替换、格式/长度/密文/tag破坏、错误key、熵源失败、JSON拒绝及调用方buffer不变。Node独立解封装同样拒绝installation/account/user/key/wrapping引用、格式、nonce、ciphertext与tag九类替换。

最终纯材料源码的干净Git树`cb24bb005426c54d48ae5eb44100c2d65fb95307`在Go2/512MiB下通过全仓race/p2（含架构）、vet、模块校验、契约重新生成逐文件字节一致及Linux amd64构建。API/domain/usecase/HTTP的聚焦race分别14.441/7.332/7.613/2.132秒通过；最终全仓也包含相同owner。固定`be4974e68fc167b418c9eee00c96aaf1b844693f`的[Verification35142407084](https://github.com/xiak/matrix/actions/runs/35142407084)已通过GitHub API核实准确SHA和go/authority-process/node-process三项completed/success。这里只使用公开人工固定字节，没有新的运行入口、API/SQL或schema；本地材料验证没有启动真实数据库，也不把无DSN的数据库跳过项当作验收。CI的既有进程回归不等于新增AccessKey运行闭环；这些不是HTTP签名、数据库事务、安装托管或007功能验收。

2026-09-17，私有codec/逐key commitment及唯一context owner的干净源码树`fa03b9a808d1313ac9ee813ef699f491a6f2d8d8`通过全仓race/p2（含架构）、vet、模块校验、生成文件集合及字节一致、Linux amd64构建。API/authority聚焦race为2.371/1.247秒，完整API/authority回归为14.974/7.456秒。2-worker、20秒预算的私有文件fuzz实际21.871秒通过813143次执行；模糊测试最初的脚本转义错误已修正后在同一源码树实跑，不记为首次成功。Node独立SHA-256向量核对全部七个绑定字段，原info/AAD/密文向量保持；未知/重复/错类型/非规范字节、超限/底层读取失败及普通JSON/公开schema泄露分别拒绝。固定`bc7d059571b55ee84c58b62adf1d794cf63ff9a6`的[Verification35145879997](https://github.com/xiak/matrix/actions/runs/35145879997)已由GitHub API核对精确SHA及go/authority-process/node-process三项success；该固定点只证明私有契约，不证明后继K1运行候选。

### K1后端运行证据与未完成边界

2026-09-17，专属PG18、真实受限API连接、Go2/512MiB/race-p1下，现有`TestIAMAccessKeyPostgres`累计41.59秒通过。24个双向场景覆盖平台grant、目标/actor停用及重置、退出、保留当前会话的日常改密、直接附件撤销、组成员移除、组附件撤销、Boundary限制和默认版本切换。先前真实暴露的平台grant旧快照201及默认版本不等待已写key的问题，分别由现有来源代际与按序Policy锁修复；不能只靠主体锁。没有隐藏deadlock，失败无部分key/intent/成功事实。

同一门禁还证明：首次完成被真实40001回滚后，两次数据库completion的key ID/格式/nonce与ciphertext承诺相同；两个已完成PDP的副本竞争最后名额仅一个成功；禁用仍占额、同版本竞争、一次性秘密/精确重放、删除与User级联、错误父引用、迁移双重重放和历史登记保留。真实TCP在create/disable/delete提交后中断响应，另一副本只能取回原非秘密完成且各有一个成功事实；这证明HTTP回包未知，不声称测试了任意数据库网络故障。已删除ID碰撞先换新ID，四次碰撞耗尽后无效果；即使有格式正确密文，没有准确创建意图也无法通过延迟提交约束。真实API登录不能直接读取密文/意图/registry、DML、调用私有函数或切换owner/migrator。缺失或不匹配custody拒绝READY；实际RLS、列授权、FK、唯一索引、ALWAYS/deferred触发器及函数权限/形状破坏均被检测，历史登记/意图/终态不能DML复活。

既有`TestIndependentIAMAuditAndPaaSProcesses`在新专属PG18上累计60.45秒通过：当前IAM两个真实进程读取同安装私有文件，缺失/损坏文件在bootstrap或outbox效果前退出；双账号同名用户经显式策略管理密钥，跨账号ID/路径/query及把Secret当bearer均拒绝。Audit失联期间完成启停、删除、User级联并撤销管理者权限，恢复后四类原事实精确投递并通过租户链/cursor隔离；IAM进程重启不重发Secret。有真实registry后，第三个进程分别使用相同wrapping ID的错误材料及不同ID的正确材料，均在独立空闲端口上启动失败且不改历史登记/密文/意图，不能以端口冲突冒充拒绝。原runtime登录身份、PaaS资源/Operation及既有角色路径继续执行。两个旧断言原先误把全租户删除/策略事实总数当单资源证据，新增合法事实使其失败；现已精确核对目标、来源、请求及唯一事实，不依赖无关操作顺序。此为源码组合门禁，不是签名安装、K2请求签名或UI验收。

候选干净源码树`6d2fb41dd6c6ab72e0193ebc2fe29b932b267ce7`通过全仓race/p2（含架构）、vet、模块校验、生成文件集合/字节一致及Linux amd64构建。此后仅将既有IAM HTTP fixture按当前网络契约显式提供同bootstrap的wrapping配置，并复用原Key fixture；实际IAM HTTP race86.306秒、双authority权限/保留Audit数据回归7.850秒、Audit HTTP3.634秒通过。实际固定R1角色executable保留数据到当前源码门禁12.89秒通过，原SYSTEM策略/默认版本不自动增加当前能力；这不是完整未发布schema1链或跨release升级许可。

首次全仓检查发现三组旧测试把新目录动作等同于系统默认授权；已改为真实显式策略求值，并独立证明五个新动作不被原内置策略授予。固定`caca31d065063963f1ef4189f46e45e775bab332`的[Verification35157659630](https://github.com/xiak/matrix/actions/runs/35157659630)精确SHA经GitHub API核实：Go和node-process成功，authority-process在20分钟job总限时后cancelled，不标记通过。日志中的Audit PG/HTTP、主IAM组、Role/References组分别6.504/1.989/543.700/390.357秒成功；末尾真实process组仍执行时被取消，缺少其终态证据。不得用本地进程通过替代独立失败，不自动重跑掩盖问题。安装文件生成/挂载/备份与UI由各自owner以固定对象独立验收，当前不标记K1或整体007完成。

独立workflow修复`a435195dcbb7197556e5671a45a51769fb7eee8b`只拆分原有数据库/HTTP和真实进程两组，按`max-parallel=1`串行执行；每组仍20分钟，原20个DSN绑定、全部命令、race-p1及单项context/lock时限不变。两组分别使用唯一标签、运行/尝试ID数据库、随机端口和受限PG18；原`authority-process`检查以`if:always()`保留，只有两组都成功才通过。actionlint1.7.12、10段Bash语法、原数据库绑定/创建集合一致及汇总成功/失败/取消/跳过/空值五种状态已验证。[Verification35160554567](https://github.com/xiak/matrix/actions/runs/35160554567)已核对精确SHA：go、node-process、authority-storage成功，authority-runtime及汇总失败。这次是实际测试失败，不是总时限取消。

失败位于原`TestIAMRetainedPolicyProcessUpgrade`的后继Profile真实程序启动：fixture只在二进制路径等于currentBinary时传入keyring，后继overlay构建的futureBinary因此缺少必填FILE。固定a435在专属PG18原样复现21.68秒失败；临时诊断仅输出封闭启动阶段，确认CONFIGURATION。原测试owner已显式区分predecessor与current/future环境；旧程序不接收不存在的契约，新程序共用完整custody配置。两处未迁移拒绝门禁也提供完整新配置，避免缺文件提前退出伪装schema拒绝；没有放宽生产schema/readiness或加入调试入口。

最终累计源码固定`ebe4c2d49d04359e44cec6a9968ee36dc4e9a11d`的[Verification35163801371](https://github.com/xiak/matrix/actions/runs/35163801371)已经GitHub API核实精确SHA，go、node-process、authority-storage、authority-runtime、authority-process五项全部completed/success。本地同源码干净树`de4810595ee2ac0c5c5e6d821c9adae3f19e9da6`在原限额及新隔离数据库上串行通过：Audit PG/HTTP7.787/3.643秒、IAM主存储329.366秒、管理引用270.288秒、PaaS DB5.286秒；真实角色能力前驱11.77秒、来源权威前驱20.18秒、策略解释前驱25.48秒及双IAM/Audit/PaaS60.97秒（进程包121.543秒）。针对本次改动的旧账户/会话fixture另以真实9fd/a36程序通过11.05/11.26秒，未启用的local-recovery旧程序和浏览器项仍为SKIP，不能算通过。此固定点验证K1后端组合，不证明K2签名业务、安装生产托管/备份、UI或跨发布profile兼容；原失败结果不回填。

### 当前源码约束与替换边界

IAM保留原登录`SubjectContext`约束，并用独立`AccessKeyContext`进入同一权限求值，不构造Session。PaaS与Audit只在各自已冻结的精确路由重建边缘请求并调用同一`authorize:access-key`；原Bearer和RoleSession路径仍走既有入口。未声明动作、平台scope、产品前缀或任意新路由都不因产品已经接入AccessKey而自动开放。

身份策略求值继续只有一个 owner；将 User/Account/策略/Boundary 的授权输入与已验证认证载体分离，登录 Session、AccessKey 和 RoleSession 各自证明当前有效性，不能构造假的 Session.ID/到期/密码 generation 满足旧接口。原登录/改密/角色承担/私有 actor-session 写入保护保持，不借新增 key 绕过它们，也不为每种凭据复制 PDP。

历史证明要关联当时真实 key、用户、签名请求与决定；key 后来停用/删除、User 后来退出/撤权不应使已提交业务 outbox 永久丢失。既有 USER 决定没有 key 谱系，不能回填或冒称已包含。原 `record_authorization`、私有 evidence 与 producer proof 的确切扩展应在当前 owner 内冻结；不全局放开 USER actor、不伪造登录决定、不改变旧 canonical/hash，也不另建通用凭据 receipt 服务。该证明不覆盖业务最终 payload 的真实性；后者仍由产品实际事务/outbox承担。

### 后续集成与未完成边界

- 安装owner仍需实际文件生成/挂载、备份恢复配对和发布准入；文件/codec、单次封装及不可重绑定登记已有固定后端基线，不等于生产托管已验收。
- 原子验签/拒绝、nonce与历史证据已通过累计回归、独立进程和精确CI，固定`644fff09`被当前PaaS消费者选择性采用。K1继续使用真实无key的USER登录管理决定，不因新增程序载体取得额外权限。
- 当前PaaS Profile revision 12只为本文已固定的资源图创建、实例读取、Deployment控制和Application声明标签动作声明USER可使用`ACCESS_KEY`与`LOGIN_SESSION`；Audit Profile revision 4只为`audit.record.read`和`audit.integrity.verify`声明相同载体及`request.source-ip`条件。各PEP只在精确method/route重建外部请求并调用专用AccessKey authorizer；其他route、平台动作或route/Action错配在用例前拒绝，不以产品前缀泛化开放。
- PaaS与Audit从配置的NorthboundOrigin和边缘覆盖的`X-Matrix-External-Origin`/`X-Matrix-External-Request-Target`取得签名字段，并从唯一`X-Matrix-External-Source-IP`取得独立、规范的网络事实；请求方不能提交AuthorizationRequest、Account、Subject或已规范摘要。源IP不被事后伪装成HMAC字段，而是由边缘覆盖后进入IAM当前决定，决定同时回绑实际request digest、Action、资源集合、network context、USER和key ID。PaaS的Operation、outbox、Audit actor与业务幂等身份继续保留同一key ID；相同USER的另一把key不能借用原业务幂等完成结果。
- 当前安装候选已生成并封存NorthboundOrigin，APISIX为PaaS/Audit精确路由删除并覆盖可信边缘头，PEP同时核对标准转发头。只有签名A/B真实安装以网关CIDR限制的key通过、caller伪造头被覆盖、停用即时拒绝且生命周期保持同一origin后，才可把它记为签名安装验收；当前普通/聚焦Go门禁不是该运行证据。Account/key网络限制、使用摘要及UI仍分别保留原验收，不以header转交、HMAC通过或Policy示例代替。
- Application读取、列表和标签变更继续先安全解析Account并预读当前资源；其他实例动作与Audit租户集合动作只使用各自已声明的真实资源形状。Audit平台查询/验链、Audit写入、安装验证及其余动作继续拒绝AccessKey。后继扩展逐动作修改同一Profile和PEP，不建立平行消费者或宽泛兼容层。

后端组合、业务消费、生产托管及最终发布是不同验收边界；继续使用现有owner，不建立第二套服务、文档或测试框架，也不将剩余需求移出目标。

### 已固定纵向切片：PaaS不可变资源图创建

在Application创建的精确入口固定后，本片只增加四个不需要资源预读的collection-create：`POST /v1/configurations`、`POST /v1/configuration-revisions`、`POST /v1/application-revisions`和`POST /v1/deployments`。每个route映射到自己的冻结Action与createdResourceKind；没有把所有POST、所有collection或整个PaaS前缀解释为AccessKey可用。现有Application创建保持原声明，PaaS Profile revision 8逐项增加四个USER的`[ACCESS_KEY, LOGIN_SESSION]`载体集合，ROLE和其他动作的解释不改变。

签名覆盖完整body，因此父Configuration/Application/Revision ID、镜像、值、部署期望状态及最终资源ID都不能在IAM决定后替换。IAM的collection决定只证明当前主体可发起该类创建，不证明body引用的父资源存在或属于Account；PaaS必须在决定推导的同一Account事务内验证全部引用、配额和唯一性，再将最终资源、Operation、完成记录及outbox原子提交。跨Account同ID父资源、缺失父资源或资源图不一致只能得到业务拒绝且无部分资源/Operation/outbox；合法MAC的nonce已经由IAM消费，调用方修正意图必须使用新nonce，业务幂等键只对原完整命令有效。

HTTP边界保存route预期Action并在实际handler调用authorizer时核对，防止路由新增或重构后把签名上下文借给另一动作。五个已开放创建route共用同一外部请求重建器、独立AccessKey authorizer和既有业务用例，不复制签名codec/PDP或创建第二套写入事务。最低真实门禁以两个Account各自key建立同名同ID的完整Application→Configuration→双Revision→Deployment图，核对每步Operation/actor/key、PaaS outbox、Audit target/链及同key新nonce业务重放；另一Account父ID、另key复用幂等键、nonce重放、route/action替换和IAM失联均失败关闭。

固定`63ab867d30113b70a71e6ce6ddc5f16020380d36`在独占PostgreSQL 18中通过PaaS真实存储race门禁（6.283秒）。独立双IAM、Audit、PaaS和双dispatcher进程以测试239.85秒、包243.347秒通过上述双Account资源图、同ID隔离、跨Account父Application引用404且无Configuration/Operation/outbox部分效果、五类Operation及Audit USER/key归因和完整链；IAM collection决定保持target=`collection`，没有冒充已经证明最终body或父资源。唯一滚动前驱IAM58→59以测试132.58秒、包136.119秒通过，生成稳定、最终全仓race、vet、模块校验和Linux amd64构建通过。[独立CI 36847285739](https://github.com/xiak/matrix/actions/runs/36847285739)未在后继推送前完成，不登记为独立CI或签名安装验收通过；累计实现由下述后继重新验证。

### 当前纵向切片：AccessKey安全预读与Application读取

`GET /v1/applications/{applicationId}`需要从PaaS真实资源取得`resource.tag/environment`后再做当前PDP，不能拿collection创建决定、caller租户header或全局资源ID跳过预读。为此在现有IAM credential与PaaS PEP owner内增加目的限定的内部`POST /v1/internal/access-key-subject:resolve`：请求严格为当前PaaS Profile与本次完整`AccessKeySignedRequest`，响应只返回由当前服务、安装、audience、key和MAC绑定的Account/USER/key、Profile及`signedRequestDigest`。请求与响应使用唯一私有codec，普通JSON、日志和错误不得展开签名、nonce或秘密；不接受Action、resource、Account或Subject selector。

该入口只建立本次请求的账号作用域，不产生permit、IAM决定、Audit事实或nonce消费，也不返回可缓存令牌。IAM在同一只读身份事务中验证当前服务、Profile、安装归属、key材料封装、MAC和数据库时间窗，并检查身份记录的结构/来源完整性；停用、forced-change、平台绑定、Policy和Boundary仍由后续`authorize:access-key`在当前锁内重新判断。PaaS只能以返回Account进入现有RLS只读事务预读Application标签，随后用同一SignedRequest、精确Application ID、可信source IP及真实标签调用一次`authorize:access-key`；IAM重新验证全部当前状态、消费nonce并记录Allow/Deny。两次结果的Profile、Account、USER、key及签名摘要任一不一致都返回503且不读出资源。

PaaS取得Allow后仍在新的Account只读事务重读Application，并核对ID、resourceVersion和全部已声明标签；预读后修改、删除或跨Account同ID都不能复用旧决定。不存在的Application先以同一Account和空标签取得当前决定，再返回404，不能借404枚举其他Account。最低验收覆盖：两个Account同Application ID但不同标签策略、未知/禁用key、坏MAC/过期时间、解析后撤权或停用、解析与授权之间资源漂移、解析回包丢失、IAM授权回包丢失、相同SignedRequest并发、跨route/action替换、重启及历史事实；只有最终授权阶段可消费nonce，任何解析结果都不能单独调用业务读取。

固定`b6d15c89a`已实现上述契约。专属PostgreSQL 18上的`TestIAMAccessKeyPostgres`以95.796秒通过；解析同一签名两次不产生决定/evidence/outbox或消费nonce，随后最终授权只允许一次，坏MAC、未知key、错误installation或错误服务均无状态，停用key/User、forced-change及平台绑定则只在最终授权形成Deny并消费nonce。独立双IAM、Audit、PaaS及双dispatcher进程以216.715秒通过两个Account同Application ID、`production`/`staging`相反策略、同签名预读无副作用、最终Allow/Deny、重放冲突、精确`environment`证据及未声明`team`不入IAM证据；跨route、selector及原资源图、Operation、Audit链回归保持。

固定`e3c137ba0ed80d8d90f893192d343d89d2d917f5`的IAM58真实前驱产生保留数据后，当前IAM59双迁移、等值bootstrap及重启门禁以107.044秒通过。最终全仓race/p2、vet、模块校验、两次OpenAPI生成字节一致及Linux amd64构建通过；本片没有新增数据库迁移或改写历史Profile/Decision/Audit字节。[独立CI 36853816880](https://github.com/xiak/matrix/actions/runs/36853816880)在后继推送前完成6项成功但未取得整体终态，不登记为独立CI通过；累计实现由下述后继重新验证。签名安装、其余实例动作及UI仍未验收，不得由本地证据扩张宣称。

### 当前纵向切片：其余PaaS无属性实例读取

Configuration、ConfigurationRevision、ApplicationRevision、Deployment和租户Operation的实例读取当前没有Profile声明的资源属性条件，不需要为了获得Account而再调用一次主体解析。后继PaaS Profile只为它们现有的五个精确read Action向USER增加`ACCESS_KEY`，PEP在最终业务读取前直接以签名请求、真实路径ID和source IP调用唯一`authorize:access-key`；IAM返回的Account才是RLS读取作用域。Deployment generation继续使用`paas.deployment.read`和Deployment资源ID，但签名request-target必须包含真实generation，因此不能将一个generation的决定借给另一个路径。

只开放六条精确GET路由：Configuration、两类Revision、Deployment、Deployment generation和Operation；不开放列表、Application标签写、Deployment变更、平台Operation、Audit或产品前缀通配。query或body、嵌套路径多段、无效ID/generation、route/Action替换在IAM前关闭；有效签名的Allow/Deny仍在最终授权消费nonce，成功后业务读取只能使用决定Account。最低真实门禁以两个Account的同ID资源图和Operation证明每个route只读本Account，另一key/Account、跨route重放、撤权、停用、IAM失联和重启失败关闭，并保留Application带标签预读、创建图、LOGIN_SESSION/ROLE及Audit链回归。

本地固定`35e15da22`把PaaS Profile推进到revision 10，canonical digest为`sha256:759bd751d03fc8ddceb69f6a5e827328401dcbd47d73a1e568a0b76c5a517256`；IAM开发schema仍为59。专属PostgreSQL 18的AccessKey race以95.578秒通过，独立双IAM、Audit、PaaS及双dispatcher进程在全新数据库以203.770秒通过两个Account同ID资源图、六条精确读取、Operation同签名重放冲突、USER/key决定及完整Audit链。首个进程库只暴露旧fixture仍把Configuration read当成预期Deny，迁到仍未开放的Deployment update后全新数据库通过；没有放宽生产授权。

唯一前驱替换为固定`b6d15c89af64587d0c5eff64f9b07b1da09b43f5`的Profile revision 9/schema59真实程序。第一次前代门禁在全部恢复与数据检查后只因未来Profile overlay仍寻找revision 9变量而失败；将该测试owner推进到revision 10后，全新数据库以164.012秒通过等值迁移/bootstrap、重启、账号/MFA/会话/恢复、历史字节及未来Profile防伪。最终全仓race/p2、vet、模块校验、OpenAPI二次生成字节一致及Linux amd64构建通过；本片未新增迁移。[独立CI 36858924218](https://github.com/xiak/matrix/actions/runs/36858924218)仍在运行，不把这些本地证据写成发布验收。

### 已固定纵向切片：AccessKey控制Deployment

本片只为现有`paas.deployment.update`、`paas.deployment.stop`和`paas.deployment.rollback`三个实例动作向USER增加`ACCESS_KEY`，并只开放`PUT /v1/deployments/{deploymentId}`与`POST /v1/deployments/{deploymentId}/rollback`。`PUT`的真实动作由已签名并经严格解码的`DeploymentSpec.desiredState`决定：`STOPPED`只能映射stop，其余合法变更只能映射update；调用者不能另传Action。rollback始终映射rollback。完整method/path/body、`If-Match`、`Idempotency-Key`及签名语义头均进入原SignedRequest承诺，不能把一次Allow借给另一Deployment、版本、目标状态或generation。

PEP继续使用唯一`authorize:access-key`、当前Account/User/key/Policy/Boundary判断和nonce消费；Allow进入原Deployment事务，资源版本、generation、Operation、幂等完成和outbox仍由PaaS原子提交。业务拒绝或并发版本冲突不回滚已经提交的IAM决定/nonce，也不产生部分Deployment/Operation/outbox；调用方必须用新nonce重新签名。成功Operation及Audit保留同一USER和accessKeyId，另一把key不能复用原业务幂等完成。列表、Application标签写、平台Operation、Audit和其他PUT/POST继续在PEP前拒绝。

最低门禁覆盖两个Account同ID Deployment、update/stop/rollback三条成功路径、USER/key归因、generation与父引用保持、nonce重放、另一key复用幂等键、错误If-Match、跨route/Action/body替换、撤权/停用、IAM失联及并发写入。普通LOGIN_SESSION/ROLE流程与既有创建、读取、标签、服务会话和Audit链必须继续通过；真实网关与签名安装仍是独立发布边界。

固定`05336ad368996a500c0769fe62767204bd9333d0`将PaaS Profile推进到revision 11/digest `sha256:ba8b808cc72c4ff1eb34d9eb933b5cde4ee95dde0f1a5c361058c2dab6937b48`，不新增数据库迁移。2026-10-01在本任务独立PostgreSQL 18.6（2CPU/2GiB/PIDs512）和Go2/768MiB下，双Account五进程race门禁233.250秒通过三条真实签名变更、幂等冲突、Operation/outbox和Audit链；AccessKey真库95.209秒、固定revision 10 executable保留数据迁移126.642秒通过。全仓race/p2、vet、模块校验、OpenAPI生成前后字节一致及Linux amd64/CGO关闭构建通过。首次两轮五进程只暴露测试夹具时间未显式UTC及`[]byte`被pgx编码为`bytea`，修正夹具后使用全新数据库通过，生产权限和事务边界未放宽。独立CI仍待远端结果；APISIX可信边缘、签名安装和UI不据本地证据标LIVE。

### 已固定纵向切片：AccessKey管理Application声明标签

本片只为既有`paas.application.label.set|delete`增加USER `ACCESS_KEY`，只接受精确`PUT|DELETE /v1/applications/{applicationId}/labels/{declaredKey}`。Application ID、声明标签key、PUT完整body、`If-Match`和`Idempotency-Key`进入SignedRequest；DELETE必须承诺空body且不能通过query补selector。PEP以当前有效key解析精确Account/User，再在同一Account只读事务读取现有Application标签与resourceVersion；IAM决定同时绑定当前资源标签及目标标签。PaaS写事务必须重读并核对决定中的当前标签、If-Match和请求标签，漂移、缺失标签、另一Account同ID、错误声明key、重放或IAM不确定一律失败关闭且无部分Operation/outbox。

真实门禁覆盖两个Account同ID但标签不同、set/delete成功与原USER/key归因、另一key复用幂等键、body/path/key/If-Match替换、授权后标签或resourceVersion漂移、撤权/停用、nonce重放、重启及完整Audit链；LOGIN_SESSION原路径和此前所有AccessKey创建、读取、Deployment变更必须回归。本片不开放任意标签key、批量标签、Application列表或调用者提供Action。

固定实现`4433b7ac00fec3ae7e2fdae35fad4bbdc4cf9238`和门禁收紧`c83c38d7b91aa17003c2d217fd509eaba37d98d5`将PaaS Profile推进到revision 12/digest `sha256:ec6ef98cd9b4939cbbdd05632c8fbd28ff8ce79d98466ce98103c3fae30699b6`，没有新增SQL。2026-10-01在本任务独立PostgreSQL 18.6（2CPU/2GiB/PIDs512）中，PaaS事务race 5.171秒、双Account五进程race 257.56秒、固定revision 11 executable保留数据升级112.17秒通过；真实签名set/delete保留当前资源标签、目标标签、USER/key、Operation/outbox和tenant Audit链，两个Account复用同一业务幂等键不串租户，body、path/key、If-Match和幂等键替换八条攻击均在效果前拒绝，登录会话恢复原标签后既有条件拒绝继续成立。全仓普通与race测试（`GOMAXPROCS=2`、`-p 2`）、vet、模块校验、OpenAPI生成稳定及Linux amd64/CGO关闭构建通过。独立CI仍待远端结果；本证据不开放任意标签、列表或可信边缘LIVE声明。

### 当前纵向切片：AccessKey查询租户Audit与验证完整性

本片只为`audit.record.read`和`audit.integrity.verify`向USER增加`ACCESS_KEY`，只接受`POST /v1/records:query`与`POST /v1/integrity:verify`。Audit Profile revision 3的canonical digest为`sha256:83a1c4665b2363af22d882202f318f1ebb7ed16d33244723d18183ee3a404186`；revision 2固定为`sha256:d59fe726e2aaa4857b395da04ef79906305e56137974dfea5c96a26b32fdfa55`并保留原字节。没有新增SQL、凭据对象、permit缓存或第二套canonical编码。

PEP从已配置的installation、NorthboundOrigin和边缘覆盖的external target重建完整签名请求，正文摘要绑定页大小、时间/action/actor过滤、cursor及验链范围。IAM在每次请求核对当前Account/User/key/Policy/Boundary并原子消费nonce；Audit只用决定中的TenantID选择链，body、cursor、path或header都不能改变授权范围。成功查询和验链继续在所选租户链追加原有封闭access fact，actor准确保留USER与`accessKeyId`；ROLE来源仍保留原User或ServiceAccount谱系。失败游标、坏MAC、重放、已删除key或不确定IAM结果不产生成功access fact。

平台记录/验链、事件写入和installation验证明确不接受AccessKey。`/v1/platform/*`即使携带合法租户key也在IAM前返回统一认证失败；不能由平台操作员角色、AuditReader名称或产品audience推导跨租户能力。跨Account游标攻击使用目标Account自己的合法MAC仍由cursor链身份拒绝，证明隔离不依赖“攻击者不会重新签名”。

实现固定`620960989`在2026-10-01通过Audit契约/usecase/IAM-client/HTTP/integration及IAM authority/architecture聚焦测试和race；本任务独立PostgreSQL 18.6上的双IAM、Audit、PaaS及两个dispatcher真实进程门禁以199.714秒通过。该门禁覆盖两个Account、签名查询/验链、同租户cursor继续、跨Account cursor 422、body/path/platform替换401、nonce重放409、key删除后下一请求401，以及access fact与IAM决定的USER/key/tenant归因。固定前一源码`76048c52db248da2619d9d3e662394551e6f1ab1`的真实IAM executable产生r2及既有身份/凭据/决定数据，当前源码双迁移、等值bootstrap、重启和完整保留门禁以117.547秒通过；r2字节未改写，r3精确成为head。最终全仓、独立CI和签名APISIX安装仍待本片收口，因此此处不标记K2或FEAT完成。

### 已固定纵向切片：可信外部来源与Audit网络条件

本片只建立AccessKey后继网络限制必须依赖的权威来源事实，不提前增加Account/key CIDR字段、使用摘要或网关安装声明。唯一外部请求边界要求边缘各提供一次`X-Matrix-External-Source-IP`，使用公共规范地址解析器接受无端口、无zone且非mapped/unspecified/multicast的IPv4或IPv6；缺失、重复、非法或同时出现`Forwarded`、`X-Forwarded-For`、`X-Real-IP`均在IAM前统一认证失败。该值不是调用者签名字段：HMAC仍承诺客户端实际可见的method/origin/target/headers/body，边缘来源由安装owner独立覆盖并作为IAM `networkContext.sourceIp`求值，二者不能互相替代。

PaaS继续使用既有Profile revision 12，但签名路径不再错误使用内部服务连接的`RemoteAddr`；普通Bearer路径保持原socket来源。Audit Profile推进到revision 4/digest `sha256:b79c5d540609731bbb65acb704bdd73e98cf35fb53332ec015d5252f303be0bd`，只给两个租户Action增加`request.source-ip`，平台查询/验链不获得该条件；revision 3/digest `sha256:83a1c4665b2363af22d882202f318f1ebb7ed16d33244723d18183ee3a404186`作为即时历史解释保留，r2也不改写。Audit PEP把边缘事实绑定进同一次AccessKey AuthorizationRequest，响应及数据库不可变决定必须精确回绑；缺少来源不能到达IAM或写入Audit访问事实。

固定实现`efe12e824b6534e7b6912c6ed9900c7f0c53e3e9`及唯一前驱门禁`adeb2a710`在2026-10-01通过API、边缘边界、PaaS/Audit HTTP与usecase、IAM authority和architecture聚焦测试。独占PostgreSQL 18.6（2 CPU、2 GiB、PIDs512）上的双Account五进程race门禁289.124秒通过：两个来源各自允许，相同合法签名上下文替换成`198.51.100.250`后由真实`NOT_IP_ADDRESS` Policy形成403/Deny，决定文档精确保存错误来源且不产生成功Audit访问事实；正常PaaS资源图、Operation/outbox、Audit游标与链继续隔离。固定`0c688302b9dea1050653eded2b9442a6b1322155`的真实IAM executable产生r3和既有数据，当前r4双迁移、等值bootstrap、重启与保留门禁134.561秒通过。全仓普通/race、vet、模块校验、两次生成字节一致及Linux amd64/CGO关闭构建通过；独立CI与真实APISIX覆盖仍待完成，不能据此标记网络限制或签名安装LIVE。

### 当前纵向切片：Account/AccessKey 网络限制与使用观测

本片不建立供应商VPC、代理链或另一套Policy。公开值`AccessKeyNetworkRestrictions`准确只有显式非空数组字段`allowedSourceCidrs`；数组可以为空，表示该层不限制，最多16个严格规范、无zone、非IPv4-mapped的IPv4/IPv6 CIDR，必须按规范文本升序且不重复。Account限制与单Key限制采用AND组合，各层列表内部为OR：两个列表都为空才是全来源，任一非空层不匹配即拒绝。`0.0.0.0/0`或`::/0`只分别覆盖一种地址族，不能被实现偷偷等价成空列表。

Account值归现有`AccountSecuritySettings.accessKeyNetwork`，不是授权Policy或新的Account包装。当前设置、更新意图和StepUp必须携带完整显式值；旧不可变完成缺字段只在历史验证器中解释为当时不限制，不能让当前更新省略字段。它沿用`iam.security-settings.read/update`、完整替换、当前版本、重新认证及原Session终止契约；更新不会启用Account、恢复User/key或改变任何Policy。单Key值归`AccessKey.networkRestrictions`，创建请求必须显式给出；后继精确入口`PUT /v1/users/{userId}/access-keys/{accessKeyId}/network-restrictions`接受`{accessKeyResourceVersion,requestId,networkRestrictions}`并使用独立`iam.access-key.set-network-restrictions`，不得借`set-status`、本人身份或目录读取放行。变更返回同一非秘密Key投影并推进resourceVersion；原意图等值重放返回原完成，另一意图的等值值仍是冲突而非伪造成功事实。

限制只约束AccessKey载体，不改变LOGIN_SESSION、ROLE或ServiceIdentity。IAM在成功MAC、当前服务与完整请求核对后，用边缘认证的`networkContext.sourceIp`同时检查Account和Key；来源不匹配是已知凭据限制，形成真实Deny并永久消费nonce，不回滚成可重试认证错误。缺失/非法边缘来源、坏MAC、未知或已删除key仍统一认证失败，不产生使用记录或泄露是哪一层不匹配。Account设置更新、Key限制更新和签名授权沿现有Account→principal→Policy→AccessKey锁序串行；提交后的下一次受保护请求必须使用新值，不能用事务外预查或缓存permit保留旧限制。

`AccessKeyAccess`增加非秘密`usage`，准确包含服务端`observedAt`及可选`lastAuthorization`；后者只来自已通过MAC并原子写入的AccessKey授权证据，包含服务端`evaluatedAt`、`allowed`、冻结Action、Product和当时可信`sourceIp`。从未完成签名授权时省略`lastAuthorization`，不能用创建/列表时间冒充使用。坏MAC和未知key不写摘要，合法签名形成的Allow或Deny都可成为最后一次观测；UI不得把观测时间当实时水位或把最后一次Allow当当前许可。

使用观测复用不可变`access_key_authorization_evidence`和原决定，不在`access_keys`上按请求更新`last_used_at`制造热行。迁移为既有证据从对应决定的服务端时间保留一次`evaluated_at`并建立按Account/key/时间读取的受限索引；新证据与决定同事务追加。授权证据还绑定当时Account security-settings版本和Key resourceVersion，使SQL完成守卫可独立拒绝伪造Allow；历史验证使用当时不可变完成链，不用今天的CIDR回写旧决定。摘要只经原AccessKey read/list权限返回，不开放全局使用目录、任意时间范围扫描或失败凭据枚举。

最低门禁必须覆盖：规范IPv4/IPv6及空层组合；错误排序、重复、mapped/zone/非规范CIDR；Account-only、Key-only、双层交集和跨地址族；合法MAC错误来源的Deny/nonce消费/无业务副作用；坏MAC与未知key无摘要；限制更新与签名、禁用、删除、Account设置更新的双向并发；两Account同CIDR/key ID攻击；使用摘要Allow→Deny顺序、观测时间、重启及直接前驱保留数据。真实APISIX必须另证caller同名头和forwarding头被清除并由网关覆盖；进程门禁不能替代安装验收。

2026-10-02当前工作树候选在本任务独占PostgreSQL 18.4（1 CPU、768MiB、PIDs256、随机loopback端口）和GOMAXPROCS2下完成首轮真实门禁。`TestIAMAccessKeyPostgres`的完整原矩阵加网络限制/使用摘要以race-p1通过109.241秒：Account和Key限制更新后下一请求立即生效，合法MAC的错误来源形成Deny并永久消费nonce，Allow→Deny摘要只从原不可变决定读取；原跨账号、锁序、配额、密文、删除/停用和producer proof回归保留。`TestIAMSecuritySettingsPostgres`以race-p1通过110.457秒：完整Account网络值进入StepUp、版本和完成事实，改变网络意图、错误版本及并发更新均无部分效果。

固定前驱`0c688302b9dea1050653eded2b9442a6b1322155`的真实IAM59二进制产生保留数据，当前IAM60双迁移、等值bootstrap、重启门禁以race-p1通过127.50秒（package 130.949秒）。已完成的旧设置事实保持原字节；未绑定新网络字段的旧PROVED StepUp只保留为不可变历史，在当前读取为not-found且不能消费，必须由当前完整StepUp重新认证后才可修改设置。该门禁同时保留密码/Session、MFA绑定/替换/恢复、原receipt/canonical/proof与冻结Profile，不把开发滚动前驱实验称为跨发布profile兼容。

另一空白数据库上的`TestIndependentIAMAuditAndPaaSProcesses`以race-p1通过252.76秒（package 256.255秒）：两个真实IAM副本、Audit、PaaS及dispatcher覆盖双Account资源/Operation/outbox、程序签名body/path/If-Match/幂等键篡改、可信来源与重放、设置回包丢失/重启、MFA恢复及停用USER历史投递。聚焦API/authority/usecase/HTTP/PostgreSQL race、architecture和vet以及全仓普通`go test -p 2 ./...`、`go vet ./...`通过；OpenAPI二次生成字节稳定。上述本地证据先对应首次固定候选，不替代精确SHA独立CI、签名APISIX、安装备份或真实浏览器验收。

首次固定`472596b1e`的[Verification 36895737155](https://github.com/xiak/matrix/actions/runs/36895737155)不能标为通过：`authority-storage`在通用Audit catalog真库门禁拒绝新事实，精确错误为`closed sanitized Audit event is invalid`。本任务在新的限额PG18空库按相同命令复现，确认公开Go contract已有新action/ACCESS_KEY target，而Audit SQL封闭action、query过滤及IAM outbox decision-required列表遗漏该值；修复只补同一action的四处封闭映射，不放宽actor、target、result或decision。修复后新的Audit存储/HTTP真库门禁10.713秒/4.163秒及完整AccessKey真库race-p1 99.07秒（package 102.743秒）通过，全仓普通测试/vet也通过；后继固定SHA和独立CI仍须另验，原失败不回填。

后继Audit目录修正已累计进入`91649497a0c53be1174d8835326a2df51fe74a55`；其[Verification 37106511260](https://github.com/xiak/matrix/actions/runs/37106511260)已核实精确SHA并全部completed/success，当前真实PG18、双IAM/Audit/PaaS与恢复门禁均覆盖网络更新事实、Allow/Deny使用摘要及即时生效。原`472596b1`失败保持历史失败，不回填；该成功只接受K3后端切片，不替代签名APISIX、安装备份托管、LIVE UI或最终发布。

### 当前纵向切片：AccessKey签名目录批量授权

产品目录不能为一个已签名HTTP请求重复调用单项`authorize:access-key`。当前nonce证据按`(access_key_id, nonce_digest)`唯一，重复单项调用要么错误冲突，要么诱使实现放宽防重放；两者都不能作为目录协议。新增目的限定的内部`POST /v1/authorize:access-key-list`，请求只包含一个`COLLECTION_LIST`授权请求、0–50个严格升序的同Action/ResourceKind `INSTANCE`请求和同一`AccessKeySignedRequest`。集合与实例必须使用同一当前Profile、network context及correlation ID，各request ID唯一；Profile同时声明集合形状、实例形状、`instanceListBatch`和USER `ACCESS_KEY`，否则在写入任何状态前拒绝。

IAM在一个事务中认证调用服务、验证一次MAC和当前AccessKey状态，并只消费一次nonce。签名请求证据按请求保存一次；集合决定与实例决定分别保存并引用同一证据，不能为每项复制nonce记录，也不能仅给第一项留凭据来源。集合Deny提交集合Deny和唯一证据，返回空实例结果；集合Allow才对全部候选使用同一事务时刻和权威快照逐项求值。任一决定、证据或Audit outbox失败使整批回滚且不返回部分结果；并发同nonce最多一个事务提交。现有单项`authorize:access-key`也应使用同一规范化请求证据关系，避免长期保留两套防重放模型。

响应绑定已认证Account、严格USER/accessKeyId、完整Profile/Action/ResourceKind/correlation、集合决定、按请求顺序的0–50个实例决定及`signedRequestDigest`。每项Allow仍只是该实例的permit；集合Allow不能推导实例Allow，实例Allow也不能绕过集合Deny。subject-resolution继续只是同一签名请求的非授权预读上下文。提交结果不确定时，产品不能改用LOGIN_SESSION、替换nonce自动重放同一业务请求，或缓存部分结果。

存储替换遵循pre-v1最新前驱原则：只保留当前schema到下一schema的一次真实数据迁移，把现有一对一AccessKey决定证据无损正规化为“签名请求证据＋决定引用”；不维护所有未发布开发草稿的兼容矩阵。原决定、Audit canonical、nonce已消费状态、使用观测与AccessKey撤销状态必须保留，迁移/等值重放/备份恢复不能让旧nonce重新可用。最低门禁覆盖零/一/五十项、集合Deny、部分/全部实例Deny、重复/乱序/错Profile/Action/标签、同nonce并发、事务提交未知、撤权/停用竞争、两个IAM副本、重启和直接前驱保留数据。产品候选、RLS、游标及返回资源核对由[008](./FEAT-IAM-008-product-enforcement.md#下一纵向切片租户-application-目录与安全游标)拥有。

固定`71c7882b4f8a1aa11ee1a2408b8ae111f375f25a`已把一次MAC、一次nonce、集合与实例决定共同引用同一请求证据的协议接入真实Application目录。IAM批量事务覆盖0–50个严格候选、集合Deny、逐项Allow/Deny、证据正规化、历史保留及重放/并发攻击；产品读取、RLS、游标和返回资源核对的实现状态与证据只归[008的当前目录切片](./FEAT-IAM-008-product-enforcement.md#当前纵向切片租户-application-目录与安全游标)，不在本FEAT复制。独立[Verification 37571650568](https://github.com/xiak/matrix/actions/runs/37571650568)已终态completed/failure：十三项job成功，`authority-runtime`因[011记录的两项过期测试断言](./FEAT-IAM-011-acceptance.md#开发期升级兼容窗口)失败，最终`authority-process`汇总随之失败；没有取消或跳过。其他lane成功不能覆盖该失败，因此该固定对象不能登记为独立CI通过；当前修复仍须以新精确SHA重跑真实前驱和独立进程门禁。

### 当前纵向切片：可信APISIX北向入口与安装封存

安装命令新增且只在首次安装接受`--northbound-origin`；值必须是规范小写authority、显式端口的`http` origin，且端口与当前APISIX监听端口完全相同。当前拓扑没有TLS证书或可信上游代理配置，因此拒绝`https`，不把“签名协议能表达https”偷换成部署已经提供https。安装成功将origin与release、installation和安全邮件承诺一并封存到journal；同命令重放必须精确相同，非install命令不能注入另一个origin。升级、回滚、恢复及配置重建从sealed journal取得原值，source/target topology任一不一致都在停止服务或改journal之前拒绝。此拓扑不提供运行期可编辑origin，也不接受Host或转发头作为替代配置。

APISIX现有六条API路由与UI路由统一删除caller的`Matrix-Subject-Credential`、`Forwarded`、`X-Forwarded-For`、`X-Real-IP`、三个`X-Matrix-External-*`头及`X-Matrix-Edge-Assertion`。只有普通PaaS与租户Audit路由随后设置封存origin、原始`$request_uri`和直接`$remote_addr`；IAM、installation verify、managed-services和UI不会因此获得程序签名能力。PaaS/Audit PEP除了核对三个Matrix事实，还要求APISIX标准`X-Real-IP`和`X-Forwarded-For`各恰好一个并等于同一规范source，且`Forwarded`不存在。

仅靠这些可预测头不能证明请求实际经过APISIX，因为同一控制网络内的另一个进程可以构造相同文本。本安装因此生成两份互不相同的256位随机边缘断言，分别限定给PaaS和Audit；每份只读挂载给APISIX与对应目标服务，不挂载给IAM、worker、dispatcher、UI或另一产品。APISIX先由`proxy-rewrite`删除caller值，再由低优先级的rewrite后置函数从受保护文件取得对应值并覆盖头；文件缺失、超长或非规范小写十六进制时返回503。目标进程启动时通过受保护文件读取同一值，构造边界后立即清除明文，只保留摘要，并在解析签名、调用IAM或消费nonce前以常量时间核对恰好一个断言头。PaaS断言不能用于Audit，Audit断言也不能用于PaaS。

这是一条当前单机Compose拓扑内、用途隔离的边缘到服务通道凭据，不冒充逐请求签名或mTLS。所有容器继续`cap_drop: ALL`，只有APISIX发布端口；该边界拒绝没有对应文件的控制网络进程直接伪造请求，但不声称能抵抗APISIX、目标进程或宿主root本身失陷。未来改为TLS终止、独立节点或服务网格时，应替换为具备同等用途和安装绑定的认证通道，而不是保留静态头作为兼容旁路。

真实安装门禁在现有Phase1 owner内创建普通租户成员及显式key管理员Policy，给成员创建只允许APISIX控制网络gateway精确CIDR的AccessKey。客户端请求同时伪造公有source、标准转发头、Matrix origin/target/source、边缘断言和用户载体；只有APISIX删除并用实际origin/target/source及正确产品断言重建后，签名Application目录才返回本Account唯一资源。签错target必须401，随后停用key的新nonce必须立即403，最后删除key并撤销临时管理附件；历史事实进入原租户Audit链。升级、回滚、备份恢复和进程重启继续核对sealed origin与两份受保护断言，不能因重建配置恢复caller头、交换产品断言或复活key。

本切片自身不增加IAM/Audit/PaaS数据库schema；其入口契约现已随当前发布组合推进到IAM81/Audit37/PaaS3、`contractRevision=29`。固定`bcd4e3d308e51957275cf7b2b31dab73726f838a`通过全仓无缓存race/p2（含architecture与authorityprocess）、全仓vet、模块校验及diff检查。相同固定源码由唯一`matrix-release`路径组装并逐包验签为A=`matrix-v0.1.0-iam.r29.19-bcd4e3d308e5`、B=`matrix-v0.1.0-iam.r29.20-bcd4e3d308e5`；任务独立、network-none、2 CPU/4 GiB/PIDs 768的Docker27.5.1经典存储引擎在539.93秒完成安装、失败升级自动回退、B升级、显式回滚和指定备份恢复，外层引擎重启并等待所有平台容器healthy后又以71.08秒完成状态、身份与清理复验。

该真实APISIX路径使用普通租户User及显式key管理权限创建AccessKey，并通过封存origin、可信source IP和产品用途隔离的边缘断言完成签名Application访问；调用方伪造的转发、Matrix边界及断言字段不能替代网关重建值。原key在失败升级、成功升级及显式数据保留回滚后仍可签名。指定受保护备份恢复后，非秘密key元数据继续存在以供审计和显式退休，但原secret被`authentication_recovery_access_key_fences`永久围栏，签名请求返回401；外层引擎重启不复活它，最终管理员仍可禁用、删除该元数据并撤销临时custodian附件。`ENABLED`因此只表达资源状态，不能作为当前认证可用性的证明。该门禁不宣称跨Profile升级、任意历史N-1、宿主root回滚抵抗或LIVE UI已完成。

## 验收

标准签名正负向量、body/path/query/header 替换、过期/未来时间/重放与错服务；并发 disable/rotate/request、双账号同名用户隔离；普通 JSON/错误/日志/审计无 key material；真实 PaaS 读写与 Audit 的程序身份可关联，重启仍拒绝旧 key。

- 客户端与服务端的签名向量独立验证；真实 HTTP body/幂等 header 被改变、代理 authority/路径不一致及转交伪摘要均拒绝，不能只做同一编码器的 round-trip。
- 创建最后名额、改密/退出/reset/停用/平台绑定、轮换/删除与签名请求分别验证双方先提交的交错，失败无部分材料、意图、关系或成功事实；明确哪些生命周期恢复允许新签名，哪些终态不能复活。
- 数据库实际权限、密文归属互换、封装文件缺失/错误/跨安装、API/worker/verifier 挂载隔离及恢复配对；普通读取和支持输出无秘密。应用不使用生产调试解密端点证明这些约束。
- 两 IAM 实例与重启后的 nonce 去重、撤销/同意图处理；真实 IAM/PaaS/Audit 的签名读写、当前拒绝、未知响应、历史投递与旧 canonical 保留。签名源码/协议单测不替代签名安装组合验收。
