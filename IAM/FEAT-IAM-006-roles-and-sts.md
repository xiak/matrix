# FEAT-IAM-006：角色、信任与 STS

- 状态：R1 信任内容纯契约已实现，管理事务/HTTP/真实运行待实施验收。首个运行切片为同账号自定义角色管理，后续必须完成真实角色会话与业务授权，不能以管理目录代替本 FEAT 验收。
- 依赖：005。
- Owner：IAM Role、TrustPolicy、RoleSession、凭据发行；业务服务消费临时身份。

## 需求

| ID | 行为 |
| --- | --- |
| IAM-ROLE-01 | Role CRUD、标签、描述、信任版本、权限附件、最长会话期限 |
| IAM-ROLE-02 | 同账号 User 承担 Role，调用者 AssumeRole Action 与目标 TrustPolicy 双边通过 |
| IAM-ROLE-03 | Role 无密码/长期密钥，STS 只返回短期凭据和精确到期 |
| IAM-ROLE-04 | 当前会话权限仅来自 Role+Boundary+SessionPolicy，不并入原用户权限 |
| IAM-ROLE-05 | 原始主体、直接承担者、Role、trust revision、source session 可审计 |
| IAM-ROLE-06 | 主体/角色/信任/附件/边界撤销影响下次请求，不延长或复活旧会话 |
| IAM-ROLE-07 | console 切换显式提示账号/角色和到期；恢复原身份需要原有效 session |

## 详细设计

### 对象与分阶段交付

Role 是 Account 内可承担的虚拟身份，不是 User 的别名、用户组、资源所有者或旧 BuiltinRole。RootIdentity 关系和平台权限保持独立。角色不写入用户密码、长期服务凭据或登录会话表来假装可登录；角色 ID、登录 User ID 和 RoleSession ID 分开解释。名称只用于展示和账号内唯一性，授权只使用稳定 ID。

| 切片 | 实际交付 | 必须保留的未完成边界 |
| --- | --- | --- |
| R1 角色管理 | 原 Account Root 经当前 PDP 创建/读写/停启/删除自定义 Role，管理完整信任版本与租户策略附件；真实 HTTP/PG/Audit | 不发行角色凭据、不开放 AssumeRole，不将 Role 元数据声称为可用临时身份 |
| R2 承担与实际授权 | 同账号 USER 登录会话双边承担，Role boundary 与 SessionPolicy 交集、当前撤销、独立 IAM/PaaS/Audit 业务与历史证明 | 无服务/跨账号/IdP/角色链承担；不以本地角色求值单测代替实际 PEP |
| R3 管理闭环 | RoleSession 查询/显式撤销、完整角色/来源展示和真实 UI；容量/故障回归 | UI 由010 owner实现，最终容量/部署证据归011，不把两个进程共享单库当完整HA |

R2 的现会话退出与来源会话撤销是发行凭据的前置验收，不延后给 R3。服务角色、服务相关角色和工作负载受托归008；跨账号、SAML/OIDC和角色链归012。不为延期类型注册可调用动作、接受任意 provider 名称或造成功返回。首片只接受 `management=CUSTOMER` 的服务端归类，调用者不能选择管理者/来源产品。

### R1 数据与信任文档

Role 元数据包含 id、accountId、name、description、tags、management、status、maxSessionDurationSeconds、resourceVersion、currentTrustVersionId、createdAt、updatedAt。名称复用组名称的1–64 UTF-8字节规则，description最多512字节；ACTIVE/DISABLED共用账号内名称唯一约束，删除后可用同名创建新ID，不能复活旧ID。tags是最多50项的有界字面键值集合，同键拒绝，键1–64/值0–256 UTF-8字节、无控制字符；本片只是元数据，不能用这些标签或请求tags充当已认证条件来源。Role最大时长首版允许60–43200秒、默认3600秒；这不是服务吞吐指标，也不保证来源登录会话足够长。

`TrustPolicyDocument{languageVersion,statements}` 单独表达承担准入，初版 languageVersion="1"，每个 statement 仅 sid、effect、principals。effect为ALLOW/DENY；principals仅精确 `{type:"USER",id}`，Account来自Role而非文档。Root原primary也是USER，可被精确引用但不会转让root。首版至多8语句、每句32主体，总访问预算256，完整文档最多16KiB；SID及单句主体不重复。空statements表示默认不信任任何人，不能借空对象或缺字段启用全账号信任。匹配Deny优先；未知类型、`*`、账号通配、Group、ServiceIdentity、Role、显示名、外部ID、任意条件和资源/动作字段均拒绝。

信任编辑必须在同账号内确认每个目标为真实未删除USER；允许引用已停用USER，但停用者不能承担。该判断不创建用户，不改变其状态、密码、附件或主账号关系。信任命中并不授予任何业务权限，必须另有调用者承担动作许可和目标角色权限。之后支持其他载体时应增加已验证的判别分支与来源证明，不能把主体解释变为自由字符串或服务名称前缀。

TrustPolicy与005身份权限文档不是一个可互换的DSL。复用api/contractjson的严格JSON边界；在api/iam的角色契约owner中唯一规范化信任集合与摘要，域分隔为`matrix.iam.role-trust.v1`，不调用身份策略编码器来吞掉principal，也不复制Audit编码。RoleTrustVersion的wire为`{apiVersion,kind,id,accountId,roleId,document,contentDigest,createdAt}`，内容不可变。版本ID不透明；相同内容不等于同一次编辑。摘要只承诺完整document，不承诺其被哪一Role选中、Account归属或当前承担许可；这些关系必须由权威读取及事务验证。

信任PUT在一个事务产生新不可变版本并显式选择它，无另一个尚未实现的默认切换接口。每次带resourceVersion和原requestId；当前内容无变化的新意图冲突，精确重放只在原结果修订仍当前时返回原结果，后续编辑后旧命令不能重新切回。旧信任内容保留供历史事实读取，普通分页/精确查询仍要求当前Role读权限。

### R1 API与权限边界

下表的管理范围已与消费者对齐，不代表已注册、实现或可调用。所有请求先走当前有效USER/Account的PDP，所有写入再经原root关系、当前会话与版本的锁内复核；Root不是授权旁路，非root即使有动作Allow也不能新增/编辑高风险角色授权。读取可由实际租户策略授权。当前身份的Role列表/创建能力与Role详情逐资源能力由服务器计算，不在UI猜角色名称或全局allowedActions。

| 路由 | Action / 授权资源 | 输入或返回 |
| --- | --- | --- |
| `GET /v1/roles` | `iam.role.list` / 当前ACCOUNT INSTANCE | 原MAC cursor，每页最多100；`RoleList{apiVersion,kind,accountId,items,nextAfter?}` |
| `POST /v1/roles` | `iam.role.create` / 当前ACCOUNT INSTANCE，结果ROLE | name、description、tags、maxSessionDurationSeconds、trustPolicy、requestId；不自动附加权限 |
| `GET /v1/roles/{roleId}` | `iam.role.read` / 精确ROLE INSTANCE | RoleAccess：元数据、当前完整信任版本、实际租户附件、逐资源capabilities |
| `PATCH /v1/roles/{roleId}` | `iam.role.update` / ROLE | 完整可编辑元数据、resourceVersion、requestId；不混入信任、附件、状态或账号 |
| `POST /v1/roles/{roleId}:set-status` | `iam.role.set-status` / ROLE | ACTIVE或DISABLED、resourceVersion、requestId |
| `PUT /v1/roles/{roleId}/trust-policy` | `iam.role-trust.set` / ROLE | document、resourceVersion、requestId |
| `GET /v1/roles/{roleId}/trust-versions`及`/{versionId}` | `iam.role.read` / 所属ROLE | 原cursor分页/精确历史信任版本，不能选择另一Role/Account |
| 既有`POST /v1/policy-attachments` | `iam.role-policy-attachment.create` / ROLE | 仅本账号Role+可见ACTIVE/TENANT策略；原Policy修订与requestId |
| 既有附件`:revoke` | `iam.role-policy-attachment.revoke` / POLICY_ATTACHMENT | 服务端由实际ROLE附件决定action，不接受caller scope |
| `DELETE /v1/roles/{roleId}` | `iam.role.delete` / ROLE | resourceVersion、requestId；返回终态RoleDeletion |

Role停用不隐式撤销策略附件，便于管理员调整配置后恢复；它与暂停Account一样不停止既有工作负载。删除不可恢复，关闭该Role全部未撤销附件并保留历史；以后存在资源/服务所有权引用的Role，必须由008加入明确删除准入，不擅自解除业务绑定。只读角色列表不能取得承担、修改信任或平台权限。Root写保护、Policy范围和版本都在写入事务重检，不把capability或先前读响应当permit。

R1对应租户IAM/USER事实为`iam.role.created/updated/disabled/enabled/trust-set/deleted`，target为新的ROLE kind和实际roleId；disabled/enabled均由原`iam.role.set-status`动作产生，明确区分实际状态。所有事实只使用真实USER和原IAMDecisionID，target.tenantId不放开。role.create的原decision资源为父ACCOUNT，成功事实的最终ROLE只由已提交IAM事务/outbox证明，原decision不证明完整最终payload。附件沿用原created/revoked事实，但新增两项精确原action映射与ROLE目标归属校验。没有SYSTEM或新角色actor，不记录Trust正文、密码或临时材料；普通授权决定仍走原immutable owner。旧tenant canonical、source/eventId重放和七列claim不变。

### R1 持久化与发行窗口

在现有IAM authority内增加roles和role_trust_versions；Role关系有真实Account外键、名称唯一、不可逆墓碑、不可变信任及指针归属约束。扩展原policy_attachments的ROLE目标约束，不把ROLE伪装成USER或GROUP，不平行建立角色附件表。API只获封闭函数执行权，worker/recovery/verifier不能管理角色，所有表仍受现有owner/RLS隔离。

沿现有adapter形状设计`list_roles/read_role`各4参、`list_role_trust_versions/read_role_trust_version`各5参；封闭写函数`create_role/set_role_trust_policy`各9参、`update_role/set_role_status`各8参、`delete_role`7参，均返回jsonb。所有Role写函数末尾是私有`actor_session_id text`，只能由实际已认证bearer的Session.ID提供。公共固定参数始终包含IAM推导的account、actor、decision；其他只为准确Role/预期修订/闭合元数据或信任承诺/单一event，不能是任意SQL命令。最终完整逐参类型、ACL和proconfig随实施固定，不以参量数当兼容证明。

现有授权决定不保存SessionID，`assert_allowed_decision`不能用于重建调用会话。先按稳定ID锁actor及涉及的USER目标，再检查指定Session的真实Account/USER、ACTIVE/未撤销/未过期、非临时改密及与user_credentials相同generation；空、NULL、其他USER或代际不符一律拒绝。不得任选actor的另一有效session，不把私有SessionID加入北向request、AuthorizationRequest/decision、摘要、outbox或历史proof，也不追称旧决定包含该lineage。

因此现有附件ABI也在同一IAM24迁移中直接替换，末参同为私有SessionID；旧9/6参重载删除，无default、overload或兼容旁路。新增原Account Root规则仅ROLE分支，原USER/GROUP授权、平台USER附件与Root受保护关系保持。新形状为`create_policy_attachment(text,text,text,text,text,bigint,text,text,jsonb,text) -> jsonb`、`revoke_policy_attachment(text,text,bigint,text,text,jsonb,text) -> (resource_version bigint,revoked_at timestamptz,applied boolean)`。原record_authorization7/evidence5、ServiceIdentity、lookup_service、claim7不变。

开发IAM schema24/Audit14窗口已确认，用于新增对象、受限函数和闭合事实；在实现前源码仍为23/13，不提前修改数字或发布profile。IAM产品Profile追加r2，不能覆盖已登记r1；当前SYSTEM默认值、已撤销附件和旧信任/决定不能由schema/bootstrap重放改写。新装使用新源码声明与系统种子；已有数据是否能调用新Role action仍取决于明确当前附件，不因注册目录而授予权限。保留数据正向资格由原root显式发布/关联当前TENANT策略证明，不暗改旧SYSTEM默认或重做安装bootstrap。完整release兼容仍由最终累计组合及安装owner验收，不为本管理切片单独分配发行revision。

锁序必须基于实际现有Account/主体/Policy/附件事务核对，不能仅照一条概念箭头实现。复用现有SERIALIZABLE和有界重试，跨对象先后顺序与实际管理、附件和删除路径保持一致；同类批量锁按稳定ID取得，写root关系、当前会话、预期修订与对象范围在锁内重查。不得把Account读锁误称为独占串行化全部授权变更。同resourceVersion的状态/信任/删除竞争只可一个结果，末尾outbox失败全部回滚。未来R2需把source session、RoleSession与credential generation加入同一已验证顺序。

### R2发行、当前权限与历史边界

发行只接受当前有效同账号USER登录会话；先证明调用者的`iam.role.assume`许可，再检查目标Role的当前信任，不伪造一个用户decision来表达角色权限。登录bearer、服务凭据和角色临时凭据使用不同目的的索引/验证摘要；复用既有CSPRNG和不透明秘密，不引入可以离线长期放行的JWT。role-as-subject的公开结构、SQL记录/evidence及跨服务actor映射须另行冻结，R1不会提前扩大现有installation.verify的service-as-subject例外。

RoleSession必须绑定account、role、原USER、直接承担者、source session、原credential generation、信任version/digest、Role安全generation、发行/到期、撤销状态及不可变SessionPolicy承诺。首片禁止角色链，因此原始主体等于直接承担USER，但仍不能用会话显示名称替代稳定身份或接受caller sourceIdentity。源会话被保留并升级到新credential generation，不会自动把旧RoleSession升级过去。

实际expiresAt明确取数据库时间加请求时长、Role最大时长、source session到期三者最早；到期不可被元数据更新、幂等重放或重新启用延长。角色显示名称/描述/纯元数据tags变更不改变身份；信任选择、角色停启或最大时长改变推进单调安全generation，旧会话不能在“停用再启用/撤信任再加回”后复活。已提交工作和历史投递不因当前撤销被删除或永久阻断。

每次角色业务请求重新验证Account、原USER、source session/代际、Role/安全generation、RoleSession与当前信任，及原USER当前承担该Role的资格；这里重查的是承担资格，不把原用户业务Allow并入角色权限。角色权限、角色Boundary、不可变SessionPolicy通过同一个005求值器求交，适用Deny优先。缺失边界/信任/来源状态失败关闭，不能当作无限制。历史决定保留当时完整角色与原始承担证据，producer proof验证原不可变事实，不重新授权后来过期/停用的用户。旧User/Service事实字节不变，不以伪USER或SERVICE身份掩盖角色调用。

会话秘密只在发行成功的专用响应流转，不进入普通Role详情、Audit、日志或journal。发行幂等与丢失回包处理必须与一次性秘密生命周期一起冻结；不能为了重放返回把明文永久入库，也不能把已提交但回包未知当作失败再发另一凭据。R2在上述事务/秘密/历史边界明确前不开放发行。

## 实现拥有者与复用

沿现有`api/iam/v1`数据/严格编码、`authority`纯规则、`identityaccess`用例事务、postgres受限函数、nethttp、生成器及integration/authorityprocess测试拥有者实施。角色/信任契约如需独立源文件，是为区分承担准入与身份权限文档的编码和安全边界，不建立新服务、通用身份框架或另一套PDP。固定来源与REUSE/ADAPT/REFERENCE/REJECT决策归现有FEAT-006 adoption；UI和第三方provider没有运行时依赖。

当前纯契约位于`api/iam/v1/role.go`：严格`TrustPolicyDocument`/`RoleTrustVersion`读取、静态校验及唯一`CanonicalizeTrustPolicyDocument(document) (canonical,contentDigest,error)`。规范化只排序副本，保留空`[]`，拒绝空缺/null、未知字段、重复/大小写歧义、未实现载体、权限文档字段和超预算输入。OpenAPI仅增加数据schema，没有Role HTTP路由、Action、subject、SQL、发行profile或schema数字变化。

2026-09-16聚焦契约与JSONSchema、全仓`go test -race -p 2 -count=1 ./...`、`go vet -p 2 ./...`、模块校验、API生成字节稳定和Linux amd64构建通过（Go2/768MiB）。测试明确区分16KiB reader预算、Go语义及JSONSchema结构：schema不证明SID跨语句唯一、摘要相等、实际Account/USER或当前选中关系。该证据只覆盖纯契约与现有默认回归；本地未启动PG/独立进程/浏览器，不构成R1事务、R2承担或整个006验收。

## 验收

- R1：两个真实Account可有同名Role；同名User/Role不混用。Root当前授权成功，普通用户/服务/platform-only/另一账号/过期或forced-change会话拒绝；读许可不能写或承担。真实同账号信任、Role策略附件、版本重放与并发更新/删除/撤权，所有失败无部分Role、信任、附件或成功事实。角色没有任何长期凭据或登录能力。
- R1：运行数据库验证Role/信任/附件的范围、不可变性、RLS、函数形状/ACL、失联与当前Profile漂移；原root/current authority、source registry、User/Group/Boundary、平台凭据保护、claim及旧canonical回归保持。产品Profile追加不自动放大旧策略默认/附件；原数据重放、重启后删除和撤权不复活。
- R1：旧SYSTEM默认下原Root的新Role动作在显式发布/关联TENANT策略前拒绝，原policy管理路径仍可达；非Root即使普通策略Allow仍被写保护拒绝。删除或停用User不改写旧Trust版本；新信任写入不接受已删除User。附件只接受真实同账号ROLE discriminator，不扩大原User/Group/Service或平台附件面。
- R1：新的私有会话参数与Role/USER/GROUP/平台USER附件共同通过当前身份、logout、change(true/false/forced)、reset/recover、停用/撤权的并发锁序门禁；旧9/6调用机械失败，新函数ACL/proconfig/readiness形状准确，所有失败不产生部分关系或成功事实。不得靠有界重试掩盖actor/target的反向锁序。
- R2：双边任一缺失拒绝；角色边界/SessionPolicy不能扩权；管理员承担只读Role后不能用原用户Allow写入。错误Role/Account/token/source/generation、会话过期/撤销、并发assume/revoke/delete/change/reset/logout失败关闭。反复停启、撤信任再恢复及原命令重放均不能复活旧RoleSession。
- R2/R3：真实独立IAM/PaaS/Audit临时会话业务路径、原始actor与不可变Audit关联；身份变化后原outbox继续投递但当前producer凭据仍须有效；进程重启/两IAM路由无关、数据失联失败关闭。真实UI显示当前角色、账号、原身份与到期；退出角色不创建或复活原登录会话。
- unit、架构/security、PG18、独立进程、UI及最终release/容量各按自己范围验收。没有外部环境的跨账号或IdP路径不以mock声称完成；也不把R1管理接口或后续纯规则通过当成R2/整套006已验收。
