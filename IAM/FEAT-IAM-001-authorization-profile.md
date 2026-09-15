# FEAT-IAM-001：业务授权能力目录

- 状态：CAT-01–04 首片已验收（固定 `3b11eb9`）；CAT-05 已实现源码Profile、不可变注册、当前一致性及请求/决定绑定，后者正在收口独立验证；PolicyVersion 编译内容持久化尚未完成，本 FEAT 整体未验收。
- 依赖：[产品契约](./FEAT-IAM-000-product-contract.md)。
- Owner：IAM 公共契约与现有 authority；产品拥有其业务词汇。
- 首片：把现有已接受的动作、允许调用服务、资源种类和 scope 收敛为一份不可变目录，所有当前验证和决定路径消费该目录。

## 需求

| ID | 行为 |
| --- | --- |
| IAM-CAT-01 | 已注册动作有唯一产品、调用服务、资源种类和权限范围；未知或缺定义拒绝 |
| IAM-CAT-02 | IAM/PaaS/managedservice/Audit/installation 通过显式登记拥有动作，不按字符串前缀猜权威 |
| IAM-CAT-03 | 租户动作、平台动作、安装 verifier probe 独立；probe 不能成为业务许可 |
| IAM-CAT-04 | 校验器、生成 schema、授权服务使用同一目录；返回副本不能修改全局定义 |
| IAM-CAT-05 | 后续 Profile 明确声明 revision、digest、资源粒度、创建/列表/批量和可信条件来源；未声明的能力不能启用 |

## 首片详细设计

在现有 `api/iam/v1` 建立值类型 `ActionDefinition` 与只读 lookup，包含 Action、Product、CallingService、ResourceKind、AuthorityScope。保留现有 Action 字面量、顺序与 schema；用新目录替代 `allActions`、资源映射 switch、平台 scope switch 和 ServiceCanRequest 的前缀分支。`INSTALLATION_PROBE` 保持现有 verifier 的 home-tenant decision 语义，只有现有固定入口可以消费。

这里只声明代码已证明的事实，不把 application-create collection ID 当最终实例，也不声称所有 read Action 已支持实例过滤。Profile 的粒度、条件、动态注册/管理 API 在真实产品 PEP 片补齐。首片不引入客户自由上传的产品定义，不变化 SQL 函数形状或 wire schema 数字。

控制台的目录展示和保守可用性提示归 010；静态登记不等于某个用户的 `allowedActions`，不能绕过资源/条件判断。

005 的时间条件增量在本 owner 声明 `iam.current-time`：类型 TIME，来源 IAM_TRANSACTION_TIME。当前目录中 TENANT 动作声明该键，INSTALLATION 与 INSTALLATION_PROBE 不声明；未知动作/键无能力。只读 `LookupActionConditionDefinition` 返回值副本，静态校验、生成 schema 与唯一评估器使用同一来源定义；没有通用调用者属性 map。该局部来源声明不等于已交付完整签名 AuthorizationProfile、revision/digest、资源粒度或业务属性接入，CAT-05 仍未完成。时间算子、窗口与事务/历史语义由 005 唯一规定。

005 字符串切片在同一目录增加 `iam.account-id` 与 `iam.principal-id`：类型 STRING，来源 IAM_AUTHENTICATED_IDENTITY。分别绑定当前 IAM 权威身份的 Account 和主体稳定 ID，仅对 TENANT/USER 启用；不接受产品请求自报的值，不将 Group/策略/资源的归属误作当前调用者身份。它们是 IAM 内置身份条件，不按产品名称分叉，也不开放租户自行注册来源。契约与唯一求值器已经接入，运行证据、算子、集合、缺失和 canonical 行为归 005；完整 Profile 与业务条件仍按 CAT-05/008 验收。

## 事务与权限

### CAT-05：可验证的产品 Profile

该切片以源码登记的 Profile 替换原平铺动作目录；当前授权校验和条件能力读取它的确定投影，保留既有动作顺序、scope、caller、resource与prefix语义，尚未改变授权请求/结果及决定记录函数形状。之后须在实际决定中绑定不可变 revision/contentDigest，再由005消费冻结的动作集合；不能先在求值器加入字符串 Action 前缀匹配，最后补历史证明。

产品 Profile 必须同时约束产品标识、允许调用的已认证服务、Action、scope、资源种类、请求目标模式、集合行为与可信条件能力。产品名或 Action 字符串只作为标识，不能推导调用权限或粒度。内容不可变、同产品同 revision 不得对应另一 digest；digest 覆盖所有影响授权解释的字段。返回副本不能修改注册目录。注册来源仍由可信产品发布/服务组合控制，不开放租户上传 Profile 或借此注册平台动作。

产品目录不是商品上架目录，也不是租户授权关系。产品研发 owner 提交动作、资源、条件与实际 PEP 的版本化声明；IAM owner 校验命名空间、调用服务、能力和版本不变性；受信发布流程决定组合中采用的准确声明。产品声明必须与对应业务实施一同通过门禁，不能只注册元数据就宣称业务已接入。租户管理员只消费已发布的只读目录来编写策略，不持有产品注册或发布权；一般平台运营者的租户/主机管理权限也不隐含产品发布权。首片以受审查源码发行作为注册权威，不新增在线产品管理接口或任意运行时上传入口。未来内部接入 API 应替换发行适配方式，不能在通用求值器增加产品名称分支。服务受托与账号同意仍由008单独拥有。

纯声明编码由 `api/iam/v1/authorization_profile.go` 唯一拥有，不复制 Policy/Audit 编码。`AuthorizationProfile` 包含 `apiVersion/kind/product/revision/callingService/actions`；每个动作显式给出 `resourceKind/scope/resourceShapes/conditions`，末尾可声明 `resultResourceKind`。后者与授权目标正交：既可表达集合创建，也可表达对父Account实例授权后创建User/Group/Policy。`INSTANCE` 可以声明租户实例前缀；`COLLECTION` 只能声明 `COLLECTION_LIST` 或 `COLLECTION_CREATE`，不支持 prefix、filter 或 batch。集合创建必须声明动作级result；含集合LIST时不得声明创建结果，不允许同动作LIST+CREATE。结果仅是成功事实种类，不是API返回载荷、最终ID或payload证明，不能替换原decision资源。shape不接受result字段或兼容别名。

`DecodeAuthorizationProfile` 沿现有严格 JSON owner 拒绝重复/未知/大小写别名字段，输入与程序内声明都受64KiB、128动作上限约束。动作/形状/条件分别按集合排序，输入保持不变；`CanonicalizeAuthorizationProfile` 使用 `matrix.iam.authorization-profile.v1` 域分隔摘要，`CheckAuthorizationProfileReference` 精确比较 `product/revision/contentDigest`，不接受“更新版本即可兼容”。可选条件省略、null、空集合都规范为不声明任何条件能力；来源仍复用唯一 IAM 封闭定义。产品/服务标识的语法允许未来产品，但语法通过、摘要匹配均不构成注册、签名认证或授权。

现有 `enums.go` 是源码登记owner，按产品组合的Profile声明是当前唯一数据源。`AllActions`、`ActionDefinition`、资源/scope/service admission、条件能力及生成器从它派生；不存在第二份可编辑的action map。源码登记每产品只有一个当前revision，缺项/无效声明/重复产品会在服务启动前关闭，公开读取深拷贝所有嵌套集合，不能修改授权目录。历史已退休动作只保留原有不可变决定解码边界，不进入当前Profile。声明注册不代表产品已取得目标Account权限；历史保存和同revision变体拒绝归下述注册事务，签名发行与线上决定/策略绑定仍需后续验收。

目标模式不能只有一个从动作后缀推断的 INSTANCE 标记。当前真实调用者至少存在三种情况，必须在首片全部覆盖：

| 当前拥有者与动作 | 必须登记并验证的语义 |
| --- | --- |
| IAM `iam.user.create` / `iam.group.create` / `iam.policy.create` | 对当前父Account实例授权；成功资源分别为User/Group/Policy，不能反过来拿子资源替代Account授权 |
| IAM `iam.group-membership.create` | 对实际父Group实例授权，成功关系为GroupMembership；归属仍由原事务验证 |
| PaaS `paas.application.create` | HTTP owner先检查集合，成功事实再绑定最终 Application；集合授权不是最终ID/payload证明 |
| PaaS `paas.application.read` | 精确实例ID；已验证的资源前缀只对该入口声明支持，不替代数据库tenant隔离 |
| managedservice `managedservice.offering.read` | 同一动作的列表入口检查集合、详情入口检查实例；列表当前是整体授权，不支持按策略实例过滤 |

以上映射来自现有 apphosting/managedservice HTTP owner，不能用更改动作名称或假装拆成两个已经存在的 API 绕过混合模式。Profile 可声明同一动作允许的多个闭合目标模式；实际调用必须明确选择并被对应 PEP 校验。未知模式、未实现的 FILTERED 或 batch 能力、错服务/产品/scope、同 ResourceKind 的另一动作均关闭。

本分支已按固定 `be3c4a96b4381426c01cd6315eaa3713c2855982` 适配完整12项平台动作、NODE_ENROLLMENT及对应约束/系统策略显式新版本，PaaS Profile使用完整首版声明。其实际PEP证明 pool.create/target.register 对body实际ID做INSTANCE授权，pool.read/target.read兼有集合列表与实例详情；此片只适配IAM/Audit拥有的公共能力，不导入host实现。node-enrollment.create的collection→ExecutionTarget历史映射来自该固定树已包含的 `ca7f6940159e53fbae183b7b6d5f379705a0cba1`，其余enrollment操作仍为exact实例。本片局部门禁见下；最终ABI尚未验收。

### 平台产品目录补齐的最小验收切片

以下均属于已认证 PAAS 调用服务及 INSTALLATION 权限范围，不开放租户条件、实例前缀或 verifier 业务许可。动作前缀均为 `paas.`；表中的结果资源只描述成功事实，不替代授权目标。

| 动作 | 授权资源 | 实际目标模式 | 成功事实结果 |
| --- | --- | --- | --- |
| `execution-pool.create` | EXECUTION_POOL | INSTANCE，实际请求 ID | EXECUTION_POOL |
| `execution-pool.read` | EXECUTION_POOL | INSTANCE / COLLECTION_LIST | 无创建结果 |
| `execution-target.register` | EXECUTION_TARGET | INSTANCE，实际请求 ID | EXECUTION_TARGET |
| `execution-target.read` | EXECUTION_TARGET | INSTANCE / COLLECTION_LIST | 无创建结果 |
| `execution-target.drain` | EXECUTION_TARGET | INSTANCE | 不声明创建结果 |
| `execution-target.activate` | EXECUTION_TARGET | INSTANCE | 不声明创建结果 |
| `execution-target.remove` | EXECUTION_TARGET | INSTANCE | 不声明创建结果 |
| `node-enrollment.create` | NODE_ENROLLMENT | COLLECTION_CREATE | EXECUTION_TARGET |
| `node-enrollment.read` | NODE_ENROLLMENT | INSTANCE | 无创建结果 |
| `node-enrollment.revoke` | NODE_ENROLLMENT | INSTANCE | 不声明创建结果 |
| `node-enrollment.regenerate` | NODE_ENROLLMENT | INSTANCE | 不声明创建结果 |
| `platform-operation.read` | OPERATION | INSTANCE | 无创建结果 |

初次运行时注册使用已收敛的每产品唯一 revision1；不登记或保留错误旧草案，Git 保存其历史。真正已登记/发布的 Profile 必须同revision异digest拒绝，后续内容变化必须新revision。平台 SYSTEM 策略形成新的不可变内容版本。最终支持的 predecessor be3 原 RolePlatformOperator 已有完整平台集合，因此首次 role→policy 切换须创建与其完整权限等价的 SYSTEM 默认版本，逐条迁移未撤销和已撤销绑定，保留原允许/拒绝结果；这不是新增权限，也不能要求操作者重新授权原有能力。新建最终安装使用同一完整版本。未发布的旧5项CAM开发库不是最终支持基线，不为它增加兼容发行通道。最终发布之后新增、predecessor从未拥有的动作，才适用追加不可变版本但不自动切换已有SYSTEM默认值的规则；明确受权采用由相应发行边界实施，不借此增加在线恢复或首授权接口。

当前开发readiness为 IAM21/Audit13/PaaS1；IAM包含不可变目录注册、当前一致性及版本化决定记录，Audit保持现有封闭事实，不能因其他函数签名相同沿用旧兼容声明。现有独立进程门禁必须读取三服务实际版本并与sourceProfile逐项比较，同时继续证明已发布installation profile与此组合不同，在副作用前拒绝未发布组合。不修改CurrentDatabaseProfile、不开放安装或跨profile升级；001–010冻结后由安装owner组合实际IAM/Audit和其PaaS5，验证确切predecessor及最终发行。

实际验收须覆盖全部12项的 API/SQL/caller/scope 一致性、TENANT/错误服务/probe 拒绝、未声明 prefix/condition 拒绝、新 SYSTEM 版本在唯一求值器中的逐项允许与旧版本仍拒绝新增动作。当前带数据迁移重放后，旧 canonical、版本 ID、默认指针及已撤销附件不变；新版本不能暗改旧决定。独立 PG18 的真实授权、producer 及 Audit 投递分别证明直接 target.register 的精确 ID 与 enrollment.create 的原 collection 证据；错误原动作、资源种类、集合 ID、actor、request/correlation、installation 及其他目标变更均拒绝。collection 证据不证明最终业务 payload/ID 的真实性，该关联仍依赖 PaaS 已提交事务/outbox，不能将它推广为任意 target 变更许可。此分支不导入主机运行实现或继承其验收；公共 SQL/wire/发行组合须先与其 owner 冻结后实施。

首片的实质门禁是两个真实产品通过同一注册/校验路径，IAM实际决定与持久化证据绑定精确 Profile，PEP拒绝不匹配的回包；修改或增加 Profile 不能改变已经固定的旧版本解释。新增产品声明不得要求通用求值器按产品名称增加分支。未声明来源的条件不能启用；当前IAM自供身份/事务时间继续独立于产品属性，不增加任意 caller attributes map。

历史决定和 outbox 使用发生时的不可变 Profile/PolicyVersion 证据，当前生产者凭据仍需有效；不能在重放时拿最新注册目录重新扩张或重新授权。对外请求/结果的精确字段、持久化形状和消费者切换须在这组语义完成代码核对后统一冻结，当前不提前改schema/profile数字。真实旧消费者无法原子切换时单列支持或拒绝边界，不用未发布schema编号相等作兼容证明。

在线绑定契约：AuthorizationRequest 必填精确 `profile` 引用与 `resourceMode`；COLLECTION 必填 `collectionUsage` 且 `resource.id` 固定为 `collection`，INSTANCE 禁止集合用途并使用实际资源 ID。不能从 ID 或动作后缀反推模式；同名为 `collection` 的真实实例也必须显式声明 INSTANCE。该组合必须由相应 Profile 声明，调用服务从当前有效凭据取得。Allow/Deny 都回绑完整请求目标与 Profile，PEP 逐字段核对；这些字段进入原 request digest 和不可变决定。源码已切换新结构，旧发行消费者不承诺混跑。

Audit 的租户/平台 record.read 与 integrity.verify 均对当前权威的完整集合操作：统一声明 COLLECTION/COLLECTION_LIST，verify 的动作表示完整链验证而非选择某条链实例；资源种类仍分别为 AUDIT_RECORD/AUDIT_CHAIN，scope仍分别为TENANT/INSTALLATION，调用服务为AUDIT，不声明result。Audit未发布首版Profile直接修正该语义。线上 `records`/`chain` sentinel 的替换须与新wire及受保护legacy loader一起落地，不改旧事件target、canonical或链身份。

历史兼容只由受保护的既有数据库行身份认定：迁移给迁移前完整旧形状的决定记录契约标记，不改原 JSON、outbox 或链字节；缺少新字段本身不是 legacy 资格。新 HTTP、记录函数及在线响应校验不允许旧形状或部分绑定；历史 loader 只能按对应记录的原契约读取旧 sentinel。不可变 Profile 内容和受信当前选择由迁移角色在单一事务登记，禁止普通 USER/API/worker 注册或切换；旧服务与新服务不承诺混跑，版本不匹配失败关闭。PolicyVersion 的作者文档、冻结产品引用与逐语句解析结果由005拥有，注册、SQL、wire和实际PEP须共同通过后才完成 CAT-05。

### CAT-05 注册与源码一致性切片

本片实施不可变注册及实际运行中的源码目录一致性检查，不提前改变AuthorizationRequest/Decision和PolicyVersion wire；它不替代后续模式绑定、编译内容持久化与legacy marker切换。拥有者仍为既有IAM authority迁移、postgres适配器及identityaccess用例，不新建注册服务、在线发布API或独立迁移框架。

`authorization_profiles` 以(product,revision)唯一保存canonical_document/content_digest/created_at；canonical/digest来自唯一Go契约编码，数据库核对内容摘要、封闭外层身份和大小。相同tuple同字节/摘要重放不改created_at，任何变体使整次迁移回滚；已写内容禁止更新、删除及truncate。`authorization_profile_heads` 只保存product/revision/adopted_at，FK指向archive；种子显式分别指定archive和heads，不取遍历最后一项或最大revision作为隐含当前选择。同revision重放不改时间，已存在head不得降级，只能选择明确的新revision；对应archive必须先成功写入。后续源发行必须保留所需历史种子，不能依赖某个安装刚好已有旧行。初次真正登记后，相同revision的内容不再属于可任意替换草案。

API数据库角色仅能经封闭current与精确historical lookup读取非敏感定义，无直接表权限；worker/recovery/verifier不增加注册或枚举权。精确lookup要求product+revision+digest，不接受latest/fallback；历史archive中非current行不构成目录漂移。当前lookup锁定head直到所属事务完成，Go适配器核对完整源码current集合的product/revision/digest/canonical，缺失、多余或不同内容均失败关闭。当前授权记录、管理决定、CurrentIdentity/capability及readiness消费该检查；登录、自助凭据撤销与已提交producer/outbox历史投递不因current目录变化被重新授权。只允许同一事务内复用已核对的快照，不把它缓存为跨请求permit。

迁移整体仍为一个事务；真实门禁沿既有IAM/PG与authorityprocess owner覆盖新装/等值重放、同revision冲突无部分变更、archive不可修改、head/源码不匹配拒绝当前请求但原历史可读取、精确lookup错digest拒绝、受限runtime无DML及当前与历史集合分离。实际开发readiness推进IAM20，Audit13/PaaS1不变；安装CurrentDatabaseProfile保持原发布边界，不能以此新建或升级发行包。新wire记录函数的独立数据库proof约束仍未实施，不把适配器一致性检查宣称为该完整边界。

### CAT-05 请求、决定及历史契约切换

下一片按已对齐的IAM21实施，Audit13/PaaS1与发布profile不变。新AuthorizationRequest必填profile/resourceMode，集合额外必填collectionUsage；AuthorizationDecision的Allow与Deny均返回相同profile/mode/usage/resource/requestId/correlationId。未知、非current、错摘要或畸形目标模式属于不能建立可信上下文，错误返回且不记录普通策略Deny。当前可信Profile下的策略判断保留Deny优先；策略冻结Profile不兼容不得跳过原Deny。所有新解码和SQL记录只允许完整新契约，不暴露legacy selector。

既有authorization_decisions以contract_version受保护行元数据区别1/2：无默认值、NOT NULL；v1的Profile/mode/usage列必须NULL，v2必须完整保存product/revision/digest/resource_mode及按模式决定的collection_usage，与document逐项一致，并由精确archive验证action/kind/shape。迁移在同一DDL事务持有旧表锁，首次加nullable列时仅标记加列前真实完整旧行，再收紧约束及不可变保护并替换记录函数；新函数显式写2，撤销旧签名，缺字段不构成旧行资格，后续重放不回填。原JSON/outbox字节不变，不能通过UPDATE旧记录补造Profile。

read_audit_evidence保留原四列顺序，末尾增加decision_contract_version；没有decision的IAM自身事实可NULL，有decision只允许1/2。历史适配器按受保护元数据严格解码：1走只读原契约，2经product/revision/digest精确读取archive并核对canonical及完整绑定。任何元数据/JSON矛盾失败关闭，历史投递不查current head。readiness/verify核对列、约束、新记录签名、旧签名消失、五列evidence及ACL；claim7、ServiceIdentity、lookup_service与Audit canonical不变。

新记录函数固定为`iam.record_authorization(text,text,jsonb,jsonb,jsonb,jsonb,integer)`：第3参`input_authorization`为严格内部`{request,decision}`命令载体，第7参`input_contract_version`只接受显式2。用例传真实原请求与实际求值结果，适配器禁止从决定重建请求；SQL逐项核对action/resource/profile/mode/usage/requestId/correlationId及tenant/principal/outbox重复事实，仅把decision写原document列。envelope不进入持久化document/Audit或日志，不是新北向模型。旧六参同事务删除，不保留alias/default/overload。请求摘要仍由唯一`digestSanitized`对完整原请求编码，authorization与installation-verification域分离，SQL不复制JSON规范编码或摘要算法。

目标匹配复用唯一Profile owner的CheckAuthorizationProfileTarget，显式检查精确引用、action/kind、INSTANCE或COLLECTION及其用途；纯函数不登记产品、不认证服务或产生权限。真实PEP逐入口选定模式，不能由动作名称或resource.id反推。IAM账号开通/目录、Audit完整集合的新授权目标统一为collection；旧accounts/records/chain只保留在受保护原决定读取边界。源码API、求值器、业务适配器和SQL已切换；实际进程与历史门禁见本owner证据，不等于发布组合验收。

IAM私有assert_allowed_decision由6参替换为8参，追加显式resource_mode/collection_usage；旧签名删除，无API/PUBLIC/worker/recovery调用权。当前事务只消费contract2、精确当前Profile及原actor/action/kind/id/模式/用途/事务时间一致的决定。相同kind/id=collection不允许INSTANCE、COLLECTION_LIST与COLLECTION_CREATE互换；contract1仅供历史evidence，不进入当前管理消费。请求重复字段由真实原request与decision的记录事务核对，assert不重建请求或重新签发许可。

验收沿现有契约、authority、IAM/PG和authorityprocess owner：定义重排的稳定摘要、变体/重复/未知能力拒绝、注册副本隔离、两产品集合/实例正反例、实际不同服务与scope拒绝、同账号/跨账号同ID、旧决定在目录更新后的精确重放。011的当前数据重放与受限runtime门禁保留；完整签名Profile发行、list过滤、batch和业务标签未证明前不得声明CAT-05/008整体完成。

005 的资源前缀切片在同一 `ActionDefinition` 增加 `ResourcePrefixAllowed`，默认 false；当前只为已验证传入精确实例 ID 的 `paas.application.read` 声明 true。语法验证、生成 schema 和唯一 PDP 均读取该能力，不依据服务名称、Action 后缀或 ResourceKind 推断。create/list/collection、platform/probe 以及新加入但未声明的动作均不支持 PREFIX；其他实例能力须随真实 PEP/粒度门禁逐项登记。SQL 发布不变量由既有存储 owner 执行，并以所有当前 Action 的真实 PG 正/负校验对照该目录，不把手写 SQL 约束声称为另一可编辑目录。此声明不是完整 Profile/granularity 或所有业务前缀能力验收。

目录是发布源码常量，读取无副作用；既有 IAM 当前凭据、SERIALIZABLE 决定持久化和 outbox 事务不变。后续可写 Profile 发布必须受产品注册权威管理，不能由租户管理员声明新的 platform Action。

## 验收

- 所有已知 Action 在 API 校验、资源映射、service admission、platform 分类上结果一致。
- 租户、平台、verifier 的代表性实际允许/拒绝矩阵通过；未知服务/动作、错资源和错 scope 失败关闭。
- 修改返回集合后，后续查询和真实决定不受影响。
- 既有 unit、API schema/生成、architecture/security、PG18 IAM/Audit HTTP 和独立进程回归通过，精确 SHA CI 独立确认。
- CAT-05 的完整 Profile 能力要在 FEAT-IAM-008 通过后才可声明全部 Accepted。

## 采用与证据

复用 owner 和固定源见 [adoption](../docs/adoption/FEAT-006-platform-authorities.md)。

### 请求、决定及受保护历史契约

2026-09-15，本分支独占PG18.6固定镜像`postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280`，1CPU/768MiB/PIDs128、64连接、专属网络/卷及loopback端口；Go限GOMAXPROCS2/GOMEMLIMIT768MiB，重型真库门禁串行race-p1。尚未完成精确提交的独立CI，不将本地证据宣称为发布验收。

- 当前API、PDP与实际PEP共同绑定Profile/product/revision/digest、action/resource、mode/usage、requestId/correlationId；Allow/Deny均逐字段核对。严格解码拒绝重复、未知、缺失、null及INSTANCE中多出的usage；真实未知/错版本请求不能记录成普通Deny。原请求摘要仍走唯一领域编码，域分离与字段变化测试保留。
- 新装及带数据重放、真实Allow/Deny后对受限API记录函数的攻击通过：缺原request、变体envelope、错profile/action/resource/request/correlation/mode/usage、显式1/NULL版本与旧六参入口均拒绝，决定/outbox无部分事实。同SERVICE_INSTALLATION/id=collection的INSTANCE、COLLECTION_LIST、COLLECTION_CREATE三条真实决定，分别在同事务记录并由私有assert消费；仅精确自身可用，所有交叉组合拒绝。该测试以owner调用私有函数验证不变量，不声称API获得了该函数权限。
- 真库逐项篡改schema保护：contract_version默认值/可空、缺CHECK、不可变触发器关闭、记录/evidence函数搜索路径或ACL改变，readiness/verify失败关闭；等价安全搜索路径格式允许。旧签名消失、新签名/第五输出列、无默认/不可变约束与私有函数权限均核对。完整策略存储回归141.764s，最终聚焦绑定/模式/目录门禁19.621s通过。
- 目录推进前由真实HTTP产生PaaS创建和Audit列表决定；原附件随后撤销、策略退役，PaaS head推进到不同revision，当前鉴权拒绝。原v2决定仍按精确archive投递，两类事实摘要及原document/outbox不变。历史callingService来自冻结Profile而非当前目录；自洽但声明另一caller的历史Profile也不能借当前caller权限。源业务payload/最终创建ID真实性仍由源事务/outbox承担，本证明不覆盖该payload。
- 既有process owner运行真实固定`384d6d76b65498ed6b428ba9a2905ef67831b919`旧程序生成决定、业务authority、策略附件、撤权与会话，再迁移/重放/重启当前IAM。原document/outbox/policy evidence不变，仅新增contract1和NULL Profile/mode/usage；旧源本来没有的boundary_evidence保持NULL，不能伪造。原业务事实在重启后继续验摘要，撤销权限/会话不复活。缺reason、null reason或预先夹带profile的旧行使整次切换回滚，schema8和原数据保持。最终14.167s通过；这不是普通跨profile发行升级许可，也不是重复所有未发布schema编号的兼容矩阵。
- IAM真实HTTP90.795s、双authority数据库6.604s、Audit真实HTTP/PG4.066s通过。双authority逐一覆盖每个已声明Action/target shape、原策略/边界证据和受限数据库身份；Audit HTTP的IAM依赖是受控fixture，不冒充独立IAM运行。
- 独立双IAM/Audit/PaaS及双dispatcher最后复验82.358s通过，保留实际受限runtime登录、双租户应用/配置/Operation/outbox、目录游标、撤权/重启和安装verifier历史事实；读取真实sourceProfile21/13/1，与已发布安装profile不同且保持效果前拒绝。平台host事实是authority协议fixture，不代表本分支不存在的真实主机实现。
- 全仓race、vet、模块验证、API再次生成稳定与Linux amd64构建通过；最终变更的测试/历史校验owner另做聚焦race及真库复验。无UI、ServiceIdentity/lookup_service/claim7/Audit canonical、安装profile或其他Phase工作区/环境变更。PolicyVersion编译持久化及CAT-05整体仍未完成。
- 所有客户端退出后，按精确ID与任务标签停止/移除本轮唯一PG容器、专属网络和仅含可再生合成数据库的卷；未清理其他任务对象或操作远端。

### 不可变注册与当前源码一致性

2026-09-15，本分支专属PG18.6（固定镜像 `postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280`，1CPU/768MiB/PIDs128、64连接、loopback随机端口），Go限GOMAXPROCS2/GOMEMLIMIT768MiB，真实门禁串行race-p1：

- 既有策略存储owner增加同tuple合法变体碰撞：在首个注册前注入另一份有效声明，真实迁移拒绝且schema/主体/策略/目录均无部分提交。原晚期迁移故障门禁同时检查目录表不存在；正常新装及带数据重放不改archive内容、created_at或head/adopted_at。完整策略回归包87.963s通过，保留组继承、权限边界、默认选择、不可变版本、撤权与凭据竞争。
- 真实owner/API/worker/recovery角色分别验证archive更新/删除/truncate、head删除/同revision更新、runtime直接读写和越权函数调用拒绝；未登记revision不能成为head，错误摘要不能入archive。精确历史lookup对错product/revision/digest不回退。非current archive可保留并通过schema重放，不会被误判为源码current漂移。
- 当前授权事务完成前持有head共享行锁，另一真实事务推进head受到PostgreSQL锁超时拒绝；原事务结束后受信fixture才可推进。旧源码随后对readiness、CurrentIdentity、成员目录及当前授权返回503，不写半个决定；旧迁移/verify拒绝降级且完整目录不变。历史Profile及原bootstrap事实仍可精确读取/producer投递，原outbox字节不变；用户自助退出保持可用。最终聚焦复验包8.365s通过（父门禁5.56s），包括完整新装/碰撞/重放和上述实际HTTP，不是mock结果。
- 独立双IAM/Audit/PaaS及双dispatcher 46.33s（包49.196s）通过：真实受限runtime登录、双租户资源/配置/Operation/outbox、当前撤权与进程重启、历史证明保持；实际readiness20/13/1与源码组合一致，已发布安装profile仍不同并保持效果前拒绝。该门禁不代表主机PEP或新Profile-bound wire已完成。
- IAM HTTP 72.82s（包75.642s），双authority数据库3.09s（包5.606s）通过，保留同名用户/别名竞争、平台与租户生命周期、原主账号恢复、会话generation并发、七列outbox及不可变Audit链边界。
- 全仓 `go test -race -p 2 ./...`、`go vet -p 2 ./...`、模块校验、API再次生成字节稳定及Linux amd64全仓构建通过。上述本地结果与后续精确提交的独立CI分开记录，不把默认跳过的数据库测试当真实运行证据。
- 本轮零客户端后按精确ID与标签移除唯一PG容器、网络及仅含九个合成测试数据库的卷；数据为可重新生成的fixture，无用户数据、其他任务对象或远端操作。没有UI、公开请求结构、ServiceIdentity、lookup_service、七列claim、Audit canonical或安装profile改动。CAT-05完整请求/决定及策略编译绑定仍未完成。

固定注册实现 `eb1aea493b6131cec4c0e6bca90adbb111cc41cb` 的 [Verification 34927744424](https://github.com/xiak/matrix/actions/runs/34927744424) 已由GitHub API核实精确SHA及go、authority-process、node-process全部completed/success。

注册函数边界补充由同一verify/PG owner拥有：按配置键及PostgreSQL标识符语义解析proconfig，要求唯一有效search_path按序仅为pg_catalog、pg_temp，不快照数组空格。仅函数owner和API可有显式EXECUTE，API不能获得GRANT OPTION；worker/recovery/PUBLIC及任何额外grantee均拒绝。两个SECURITY DEFINER函数的业务表全部显式iam限定。真库事务故意改变搜索路径/顺序、授予PUBLIC或worker权限、授予API转授权，verify均失败且回滚后恢复；等价空格配置允许，把整条列表引号化为单个namespace仍拒绝。受限API直接exact lookup返回的canonical_document与源存档逐字节相等。独立同限额PG18最终聚焦包8.732s（父门禁5.88s）通过，IAM/architecture race、IAM vet及Linux构建通过；此补充不变schema/函数形状或发布profile。零客户端后精确清理该补充专属容器/网络及四个合成数据库的卷。

2026-09-11 本分支首片证据：

- `TestIAMActionDefinitionsDeclareProductServiceAndScope`、`TestIAMCatalogReadsCannotModifyAuthority` 和 `TestCatalogConfinementIsEnforcedByActualDecisions` 先因目录缺失失败，实现后通过。它们验证真实决定的调用服务/资源/scope、未知动作失败关闭及返回值不可修改目录，不快照 SQL 或文件布局。
- `go generate ./api/...` 后生成 JSON 没有差异；API、IAM、Audit、architecture 的 race 与 vet 通过。原有动作、公开 wire、ServiceIdentity、lookup_service、七列 claim、canonical 和 SQL schema/profile 均未改变。
- 独立 PG18 固定镜像 `postgres@sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a`，1 CPU/768 MiB/PIDs192；专属网络、卷、loopback 随机端口及六个一次性数据库。串行 `-race -p 1 -count=1` 实跑 IAM HTTP/本地恢复事务（100.449s）、Audit HTTP（3.373s）、双 authority 数据库权限/不可变性（5.811s）、独立服务进程与实际固定 `5721b7b` 旧 executable 保留升级（77.444s）。
- 进程门禁保留受限 runtime 身份探针、双租户业务/Operation/outbox、实时权限撤销、安装 verifier、producer 历史证明与原 local-recovery 事实。没有把默认跳过的数据库测试当真实门禁，也未声明新的签名包或其他 Phase 验收。

- 提交前全仓 `go test -race -p 2 ./...`、`go vet -p 2 ./...`、`go mod verify` 和 Linux amd64 全仓构建通过。任务专属 PG 容器、六个 fixture 数据库所在卷及网络已按精确标签清理；不涉及用户数据或其他任务对象。

- 固定实现 `3b11eb9dbabd70211e665c00e4e665658b461bd1` 已推送；GitHub API 核实 [Verification 34565145241](https://github.com/xiak/matrix/actions/runs/34565145241) 的精确 SHA 与 go、authority-process、node-process 全部 `completed/success`。独立 Linux PG18 job 还复跑了既有各旧版本保留升级门禁；这不等于新增跨 profile 签名升级许可。

2026-09-15 CAT-05 源码登记与当前目录投影门禁：

- 既有 `api/iam/v1/contract_test.go` 验证产品声明与当前admission/条件能力一致、嵌套返回值不可修改目录、未知产品不被注册、重复/错命名空间声明启动前拒绝、父实例与集合创建结果分离、混合read形状和精确引用。使用不同名称的产品通过相同纯投影路径，不能修改全局目录或取得权限；没有依赖产品名称分支。
- API、IAM、Audit、PaaS 与 architecture 的 `-race -p 2` 回归、对应 vet、API生成稳定及 Linux amd64 构建通过；包含父实例/集合创建种子的2-worker、20s规范往返 fuzz 通过94701次执行。原Action枚举与生成wire未变化。
- 独立 PG18 固定镜像 `postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280`，1CPU/768MiB/PIDs128、max_connections64；三个专属数据库与loopback随机端口。串行 `-race -p 1` 实跑 IAM HTTP（82.52s；包85.579s）、独立 IAM/Audit/PaaS 与双dispatcher（56.47s；包59.724s）、策略存储门禁（141.91s；包145.201s）。保留实际受限runtime登录、两租户资源/Operation/outbox、组继承、边界竞争、条件与SQL目录一致性、当前撤权和历史证据不可修改。
- 本轮容器、网络及包含三个临时数据库的卷已按精确ID/标签清理，连接归零后删除；不涉及其他任务资源。本片没有 SQL/线上请求结果/安装 profile 变化。以上真实运行证明当前目录替换不回归，不证明决定已携带Profile、历史Profile持久化、签名发布或最终12项PaaS目录；这些仍按001/008后续门禁完成。
- 固定 `8afc1f94c47671c9b4d01081099572ed6183953b` 的 [Verification 34921642856](https://github.com/xiak/matrix/actions/runs/34921642856) 已通过 GitHub API 核实精确 SHA；go、authority-process、node-process 全部 `completed/success`。该独立结果只验收此源码目录替换切片，不将 CAT-05 整体改为完成。

CAT-05、策略替换及最终组合仍分别按 owning FEAT 实施。

2026-09-15 完整平台目录增量的本分支证据：

- `TestPaaSProfileDeclaresCompletePlatformProduct` 验证12项闭合资源/形状/结果、PAAS调用来源、平台范围及无prefix/条件能力，精确引用不能以数值更高的revision替代。现有唯一求值器的全Action/系统策略矩阵和API schema验证覆盖新增动作；enrollment负向proof拒绝read/revoke/regenerate原决定、错kind/集合ID及drain/activate/remove目标事实。API/IAM/Audit/architecture race已通过。
- 专属PG18.6固定镜像 `postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280`，1CPU/768MiB/PIDs128、64连接、loopback随机端口，串行 `-race -p 1`。IAM HTTP通过101.14s（包104.374s），包含实际平台决定与producer映射攻击、原凭据竞争、tenant生命周期和七列outbox所有权；双authority存储通过3.52s（包6.203s），逐项验证所有当前IAM/Audit动作与受限数据库权限、不可变记录及查询。
- 独立IAM双实例/Audit/PaaS及双dispatcher通过51.26s（包54.320s）。对12项按已声明的目标形状发送真实IAM请求，验证现有身份、显式平台附件授予/撤销、另一IAM实例和进程重启后的Allow/Deny；实际受限runtime登录仍由数据库探针确认。节点接入登记及三种target生命周期事实通过真实producer/Audit入链，在操作者撤权及Audit重启后保持原记录与等值重放；篡改installation/producer拒绝。此为authority协议门禁，合成的host事实不是本分支不存在的真实PaaS主机Operation或纳管验收，也不证明请求已携带Profile模式字段。
- 进程门禁首轮因新增fixture复用既有Operation ID收到409；PG明确报告 `records_paas_operation_uq` 冲突。修正为每个独立fixture使用自己的Operation ID后在新库通过，没有放宽生产唯一性、鉴权或重试行为。实际sourceProfile19/13/1与服务readiness相符，已发布安装profile仍不同且保持副作用前拒绝。
- 同一限额下的新数据库策略存储完整回归通过110.85s（包114.052s）：默认版本/内容不变性、来源证据、组继承、用户边界与策略竞争、平台凭据保护、事务失败回滚和当前带数据schema/bootstrap重放保持。此当前源码回归不替代最终be3保留数据的完整权限parity与签名发行验收。
- 收口全仓 `go test -race -p 2 ./...`、`go vet -p 2 ./...`、模块校验、API再次生成字节稳定及Linux amd64全仓构建通过。连接归零后按精确ID/标签清理本轮唯一PG容器、网络和包含五个临时数据库的卷；无UI/安装/PaaS生产变更，无其他Phase资源操作。固定 `2bcbe50afaa025380c76c9cd232cd204d87b67a3` 的 [Verification 34923411012](https://github.com/xiak/matrix/actions/runs/34923411012) 已经 GitHub API 核实精确SHA及go、authority-process、node-process全部completed/success；Profile绑定决定/策略版本、历史注册及001/008整体仍未完成。
