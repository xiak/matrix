# FEAT-IAM-007：访问密钥与程序访问

- 状态：实施中；K1管理后端累计固定`ebe4c2d49d04359e44cec6a9968ee36dc4e9a11d`已通过本地真实PG18/独立进程及五项独立CI，可作为后续源码集成基线；生产安装托管/备份及UI仍须各自验收。K2协议、纯HMAC、认证载体及冻结策略兼容基础实施中，真实签名业务尚未接通。未发布，整体未验收。
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

安装owner已只读确认现有APISIX将`/api/paas/`、`/api/audit/`重写为内部路径，且没有原authority保真证据。已对齐后续ingress契约：边缘删除caller的`X-Matrix-External-Origin`和`X-Matrix-External-Request-Target`后，各覆盖恰好一个实际外部origin及原始request-target；它们不是edge签名。PEP严格拆解后重新编码必须与原值相同，origin再精确匹配显式配置的唯一NorthboundOrigin；该配置由安装owner后续实现，不由Host学习、不借Listener或节点Public-Origin代替。target只允许准确的`/api/paas/`或`/api/audit/`前缀转换，结果与真实内部EscapedPath/RawQuery逐字节一致；尾随空`?`、双`?`、fragment和absolute-form拒绝。API继续只拥有scheme/authority/escapedPath/rawQuery四字段及唯一编码，不拥有内部header常量。真实APISIX的覆盖、原始编码/重复query保真及后端映射门禁尚未实现；这些header不证明可信来源IP。

程序入口必须按method+route template+action/resource闭合，不按产品prefix泛化开放。首片限定现有tenant application/configuration/revision/deployment/operation，以及外部`/api/audit/v1/records:query`、`/api/audit/v1/integrity:verify`；managed-services、terminal、node/host/platform、probe/installation verify、Audit ingest和IAM管理/AssumeRole均不开放。固定动作可在真实body capture后先IAM再业务decode；已有`PUT /v1/deployments/{id}`按DesiredState选择update/stop，允许capture后用原严格DeploymentSpec契约做一次无副作用完整解析，选择准确动作，再单次IAM，最终业务复用同一已解码值。该结构解析失败不验证签名、不消费nonce；不得以部分JSON扫描、宽泛许可、两次PDP或授权后另一decoder替代。路由/头/body大小先检查；其他动态动作必须逐项审计并对齐。

数据库权威时间窗口为过去300秒/未来30秒，端点包含；有效窗口只参与认证，不能替代当前key/USER/Account/PDP或持久nonce事务。标准HTTP歧义及重放风险参考[RFC9421安全边界](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.5)和[RFC3986编码](https://www.rfc-editor.org/rfc/rfc3986.html#section-2)，这是Matrix的有界协议，不宣称实现整个RFC9421。

纯协议、载体与策略兼容候选的最终干净源码树`26715a9bd17e6caf2ed372cb20679d1b83c37220`在Go2/512MiB下通过全仓race/p2（含架构）、vet、模块校验、契约生成文件集合及字节不变、Linux amd64构建。API/authority完整race为16.450/5.443秒。Node独立UTF-8长度前缀/SHA-256/HMAC向量同时覆盖JSON写请求和零正文GET，四个可为空的HTTP字段仍须显式存在；错误Secret格式、显示文本冒充原32字节key、16类字段替换、URI/重复query次序/非规范编码及数据库时间窗口分别关闭。签名wire的原2-worker/20秒模糊门禁21.946秒、566025次执行通过，之后生产编码未改。冻结编译模糊门禁加入载体兼容及错误摘要检查，2-worker/20秒预算实际22.077秒、751193次执行通过；全部现有声明的USER目标模式、32组载体/Effect组合和不匹配资源上的旧Deny均在原测试owner检查，主体扩展、未使用条件/目标形状变化仍被新路径拒绝，原登录路径不被改写。当前没有新增HTTP入口、nonce行、决定、公开actor/Operation字段、schema/profile或安装配置；这些只证明纯基础，不是K2业务或生产接入验收。

PEP 必须从它实际处理的请求取得字段并计算 body digest，不能接受 caller 提交的“已规范请求”替代真实 method/path/body，也不能只把 Authorization 文本转交 IAM。PaaS 的 Idempotency-Key 等影响行为的 header 必须被绑定；反向代理公开 authority/路径的转换、body 大小和一次读取后的安全重用由真实消费者明确。IAM 保留当前服务凭据的独立认证，核对其封存安装、purpose 与已登记产品能力，不能把 caller audience 当作已认证服务归属。

有效签名只证明持有 key 并承诺这次请求；IAM 仍检查当前 Account、User、forced-change、key 状态、适用策略/Boundary 与动作/资源。signedAt用数据库权威时间判断准确过去/未来窗口。有效签名的nonce按key在数据库中原子唯一消费，只存摘要且保留超过最大签名窗口；包括最终Allow、Deny及当前key受限的结果，防止原拒绝包在后来授权改变后重放。错误签名/未知key不产生攻击者可放大的nonce行。拒绝结果与nonce需要提交，不能因为用例最后返回认证/权限错误而回滚防重放状态。

多实例使用同一持久权威去重，不能用本机 map/粘性路由或异步 Redis 失效代替撤销保证。重复消息与产品业务幂等是两个边界：客户端重试需新签名/nonce，但保留原业务requestId/idempotency；相同 nonce 的两个并发业务请求不能都获得许可。内部 RPC 重试、IAM 已提交但响应未知、nonce 保留/清理时限需要与真实 PEP 一起冻结，不通过放宽重放或返回旧permit来避免处理未知结果。

允许决定必须匹配实际请求及签名证据，业务只消费这次结果，不将其缓存为用户许可。身份始终是原 USER，认证载体明确为ACCESS_KEY；公开Decision/PaaS/Audit只增加最小accessKeyId归因，签名证据仍留IAM。哪些当前动作支持程序载体须由产品已登记能力和真实 PEP 共同决定，不能在通用求值器写死产品名或把 `subjectTypes=USER` 推断成所有认证方法均可用。具体字段形状及旧USER无key分支的兼容解释在公共API切换前冻结。

#### K2 原子授权与受保护历史

此节是后端增量的已对齐设计，尚非实现证据。内部入口为`POST /v1/authorize:access-key`，只以当前服务Bearer认证调用服务，不接受Matrix-Subject或主体/租户selector。请求准确为`{authorization,signedRequest}`，前者是原AuthorizationRequest，后者复用唯一显式签名wire。封闭结果为`{apiVersion,kind:AccessKeyAuthorization,decision,signedRequestDigest}`；摘要必须从实际通过MAC的规范字节产生，PEP独立核对该摘要、原请求/决定和key归因。不是JSON wire摘要，不含原签名，不提供结果重用或nonce查询接口。

防重放归原decision事务：新增私有一对一`access_key_authorization_evidence`，主键/外键为`(tenant_id,decision_id)`，仅由原`record_authorization`写入。typed列绑定真实AccessKey、当时resourceVersion/formatVersion、wrappingKeyId与永久材料commitment、封存安装、实际调用服务、audience、signedRequestDigest、nonceDigest及signedAt；不把FK/唯一性只放进opaque JSON。`UNIQUE(access_key_id,nonce_digest)`永久保留，前提是原AccessKey全局ID及索引唯一性实际成立。表无PUBLIC/API/worker直接ACL，有不可变及禁止truncate保护；它不是第二个授权服务或可重放permit。key定位索引只负责RLS前的ID到真实tenant定位，owner-only、永久唯一、不可改，并精确FK到原key tombstone。迁移只为真实既有行登记；冲突、缺失registry或不一致全部回滚，不补key或改归属。

先认证实际服务并验证结构及安装/服务目的/audience，再定位key。格式合法且MAC有效的请求，无论当前Account/User/key状态、forced-change、策略/Boundary、载体能力或时间窗口是否允许，均形成同事务的ALLOW或DENY及原outbox，永久消费nonce。**过早/过期但合法MAC也记录DENY**，避免后来进入时间窗口再使用原包。结构非法、服务身份/请求绑定不成立、未知key、已删除材料或错误MAC不写nonce/决定；对外不区分key存在与状态。重复nonce永远拒绝，不返回原ALLOW/DENY，不另写决定或成功事实；新传输重试使用新nonce并保留业务幂等键。只有确认未提交的事务失败可整事务有界重试，提交未知不自动重发原nonce。

锁序按真实物理身份排序：全部涉及的Account先按ID全局排序，再所有principal按`(tenant_id,id)`排序，然后依固定类别取得service credential、Policy、USER/GROUP授权代际及AccessKey锁。读取使用能与状态/撤权更新冲突的SHARE，不以KEY SHARE冒充；Serializable等待后遇到旧版本须重开事务，不能继续旧快照。原密码Session不进入AccessKey上下文，当前策略/Boundary仍复用唯一PDP。记录器9参拟在末尾接收严格nullable key evidence，显式contract4；旧8参删除，不保留旁路。实际IAM30/Audit18须待函数/列/ACL/readiness验收后才成立；此设计不分配或修改发布profile。

当前服务凭据没有独立credential ID/version，不补固定版本。其真实历史身份为`home account + principal + purpose + lookup digest + verification digest + created_at`，另绑定sealed installation。记录SQL仅接收已认证调用的lookup digest，在锁内经原service_credential_index重新定位并读取完整元组，不接受应用自报整个元组。原身份列必须不可改，只允许revoked_at从NULL单调撤销；两张原服务凭据表的身份/索引不得UPDATE、DELETE或TRUNCATE，迁移先核对真实行/index/FK一致，不修补或猜测历史。lookup_service仍五列，ServiceIdentity不加字段；材料摘要只在私有证据中。将来轮换需独立真实凭据模型，不能覆盖这组历史身份。

contract4的载体矩阵闭合为：LOGIN_SESSION USER无keyId/key evidence；ACCESS_KEY ALLOW的USER keyId与私有证据相同；ACCESS_KEY DENY的公开决定仍无subject/tenant，但私有证据必须存在；ROLE只带原Role evidence，SERVICE_ACCOUNT没有两种USER凭据证据。公开keyId仅是现有Subject/Actor末尾omitempty字段，经PaaS原嵌套RequestedBy传播，不新增顶层重复字段。`read_audit_evidence`可保持五列，但内部须验证一对一证据、永久key归属/registry、原服务元组、请求摘要和原outbox一致；不要求今天key/User/service有效或密文仍存在。原LOGIN_SESSION/ROLE事件及canonical bytes不改变，claim7不变。

`userAuthenticationMethods`由原Profile owner承载，是请求载体准入而非另一许可。它只解释USER，闭合值为LOGIN_SESSION/ACCESS_KEY；历史缺字段只表示LOGIN_SESSION，新改写声明显式给出规范集合。key请求必须满足当前Profile显式支持、实际闭合PEP和同一USER的当前policy/Boundary三层。旧USER compilation不能靠忽略digest复用：唯一`CheckAccessKeyPolicyCompilationRequest`先复用原完整编译/引用/目标检查，再以同一规范编码比较请求动作的全部原语义。产品、调用服务、scope、resourceKind、全部shape/usage、subjectTypes、条件及创建结果必须相同；除已含ACCESS_KEY的集合原样保持外，只允许缺省/LOGIN_SESSION增加ACCESS_KEY且保留LOGIN_SESSION，不允许同时删除另一载体。仅本地比较投影不绑定revision；两份真实完整引用和策略摘要仍先分别验证，投影不返回、不登记。其他变更失败关闭，需要显式重发策略；不因Deny尚未匹配资源/条件而略过，LOGIN_SESSION保留既有解释。冻结动作族不吸收新动作，不参与本次动作的完整策略仍不贡献许可。新决定须同时保留当前请求Profile和原策略归档证据，历史proof使用当时两份声明重验，不改旧bytes或倒灌当前head。当前只有纯检查实现，实际PDP/历史接线未完成。

网络准入仅使用产品实际连接IP，或installation明确配置的可信代理链。Account限制与key限制取交集，不直接相信任意X-Forwarded-For，不把客户端VPC/网络名当权威。网络片未完成时不开放假配置面，也不宣称IAM-KEY-05通过。

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

当前 `authority.SubjectContext` 与 `validateSubjectContext` 强制包含登录 Session；PaaS `port.AuthorizationRequest` 只传 Credential 字符串，其 `iamhttp.Client` 仅解析 bearer。这些是需要替换的真实边界，不代表程序访问已经存在。

身份策略求值继续只有一个 owner；将 User/Account/策略/Boundary 的授权输入与已验证认证载体分离，登录 Session、AccessKey 和 RoleSession 各自证明当前有效性，不能构造假的 Session.ID/到期/密码 generation 满足旧接口。原登录/改密/角色承担/私有 actor-session 写入保护保持，不借新增 key 绕过它们，也不为每种凭据复制 PDP。

历史证明要关联当时真实 key、用户、签名请求与决定；key 后来停用/删除、User 后来退出/撤权不应使已提交业务 outbox 永久丢失。既有 USER 决定没有 key 谱系，不能回填或冒称已包含。原 `record_authorization`、私有 evidence 与 producer proof 的确切扩展应在当前 owner 内冻结；不全局放开 USER actor、不伪造登录决定、不改变旧 canonical/hash，也不另建通用凭据 receipt 服务。该证明不覆盖业务最终 payload 的真实性；后者仍由产品实际事务/outbox承担。

### 后续集成与未完成边界

- 安装owner仍需实际文件生成/挂载、备份恢复配对和发布准入；文件/codec、单次封装及不可重绑定登记已有固定后端基线，不等于生产托管已验收。
- 按上述已对齐HTTP/载体/锁序/防重放设计实现原子授权和历史证据；实际函数、ACL、readiness及消费者验收后才改变对应版本。K1仍沿用原USER管理决定，不提前伪造程序凭据谱系。
- 产品PEP、APISIX和NorthboundOrigin由所属owner在明确窗口消费累计固定对象；当前纯协议不改变它们。可信来源IP、Account/key网络限制、使用摘要及UI分别保留原验收，不以header转交或HMAC通过代替。

后端组合、业务消费、生产托管及最终发布是不同验收边界；继续使用现有owner，不建立第二套服务、文档或测试框架，也不将剩余需求移出目标。

## 验收

标准签名正负向量、body/path/query/header 替换、过期/未来时间/重放与错服务；并发 disable/rotate/request、双账号同名用户隔离；普通 JSON/错误/日志/审计无 key material；真实 PaaS 读写与 Audit 的程序身份可关联，重启仍拒绝旧 key。

- 客户端与服务端的签名向量独立验证；真实 HTTP body/幂等 header 被改变、代理 authority/路径不一致及转交伪摘要均拒绝，不能只做同一编码器的 round-trip。
- 创建最后名额、改密/退出/reset/停用/平台绑定、轮换/删除与签名请求分别验证双方先提交的交错，失败无部分材料、意图、关系或成功事实；明确哪些生命周期恢复允许新签名，哪些终态不能复活。
- 数据库实际权限、密文归属互换、封装文件缺失/错误/跨安装、API/worker/verifier 挂载隔离及恢复配对；普通读取和支持输出无秘密。应用不使用生产调试解密端点证明这些约束。
- 两 IAM 实例与重启后的 nonce 去重、撤销/同意图处理；真实 IAM/PaaS/Audit 的签名读写、当前拒绝、未知响应、历史投递与旧 canonical 保留。签名源码/协议单测不替代签名安装组合验收。
