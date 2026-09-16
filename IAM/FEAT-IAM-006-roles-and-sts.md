# FEAT-IAM-006：角色、信任与 STS

- 状态：R1 同账号自定义 Role 管理事务/HTTP/审计已完成本地真实运行、整仓回归及独立 CI 验收，固定提交 bf7e8fbbdffe96b8af5b250edd1ed746c5b99265；尚不作为完整角色/STS 产品交付。后续必须完成 R2 真实角色会话、业务授权及 R3/UI，不能以管理目录代替本 FEAT 验收。原审计查询竞争的已验证回滚点为 f9ca482df5bde3c8689e9d105f382e178a6abdab / Verification35054751383，三项独立 CI 全部通过。
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

Role 元数据包含 id、accountId、name、description、tags、management、status、maxSessionDurationSeconds、resourceVersion、currentTrustVersionId、createdAt、updatedAt。名称复用组名称的1–64 UTF-8字节规则，description最多512字节；ACTIVE/DISABLED共用账号内名称唯一约束，删除后可用同名创建新ID，不能复活旧ID。tags是最多50项的有界字面键值集合，同键拒绝，键1–64/值0–256 UTF-8字节、无控制字符；name、description与全部tag键值合计最多4096 UTF-8字节，保证100项目录及JSON转义后的响应有界。本片只是元数据，不能用这些标签或请求tags充当已认证条件来源。Role最大时长首版允许60–43200秒、默认3600秒；这不是服务吞吐指标，也不保证来源登录会话足够长。

`TrustPolicyDocument{languageVersion,statements}` 单独表达承担准入，初版 languageVersion="1"，每个 statement 仅 sid、effect、principals。effect为ALLOW/DENY；principals仅精确 `{type:"USER",id}`，Account来自Role而非文档。Root原primary也是USER，可被精确引用但不会转让root。首版至多8语句、每句32主体，总访问预算256，完整文档最多16KiB；SID及单句主体不重复。空statements表示默认不信任任何人，不能借空对象或缺字段启用全账号信任。匹配Deny优先；未知类型、`*`、账号通配、Group、ServiceIdentity、Role、显示名、外部ID、任意条件和资源/动作字段均拒绝。

信任编辑必须在同账号内确认每个目标为真实未删除USER；允许引用已停用USER，但停用者不能承担。该判断不创建用户，不改变其状态、密码、附件或主账号关系。信任命中并不授予任何业务权限，必须另有调用者承担动作许可和目标角色权限。之后支持其他载体时应增加已验证的判别分支与来源证明，不能把主体解释变为自由字符串或服务名称前缀。

TrustPolicy与005身份权限文档不是一个可互换的DSL。复用api/contractjson的严格JSON边界；在api/iam的角色契约owner中唯一规范化信任集合与摘要，域分隔为`matrix.iam.role-trust.v1`，不调用身份策略编码器来吞掉principal，也不复制Audit编码。RoleTrustVersion的wire为`{apiVersion,kind,id,accountId,roleId,document,contentDigest,createdAt}`，内容不可变。版本ID不透明；相同内容不等于同一次编辑。摘要只承诺完整document，不承诺其被哪一Role选中、Account归属或当前承担许可；这些关系必须由权威读取及事务验证。

信任PUT在一个事务产生新不可变版本并显式选择它，无另一个尚未实现的默认切换接口。每次带resourceVersion和原requestId；当前内容无变化的新意图冲突，精确重放只在原结果修订仍当前时返回原结果，后续编辑后旧命令不能重新切回。旧信任内容保留供历史事实读取，普通分页/精确查询仍要求当前Role读权限。

### R1 API与权限边界

下表为 R1 已实现的封闭管理 API。所有请求先走当前有效USER/Account的PDP，所有写入再经原root关系、当前会话与版本的锁内复核；Root不是授权旁路，非root即使有动作Allow也不能新增/编辑高风险角色授权。读取可由实际租户策略授权。当前身份的Role列表/创建能力与Role详情逐资源能力由服务器计算，不在UI猜角色名称或全局allowedActions。

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

现有USER/GROUP/平台USER附件ABI已在IAM24事务中直接替换，末参为私有SessionID；旧9/6参重载删除，无default、overload或兼容旁路。实际会话到期在取得主体锁后按数据库时钟检查，不沿用事务开始时尚未到期的判断。原USER/GROUP授权、平台USER附件与Root受保护关系保持；原Account Root附加规则仅作用于新的ROLE分支。当前形状为`create_policy_attachment(text,text,text,text,text,bigint,text,text,jsonb,text) -> jsonb`、`revoke_policy_attachment(text,text,bigint,text,text,jsonb,text) -> (resource_version bigint,revoked_at timestamptz,applied boolean)`。原record_authorization7/evidence5、ServiceIdentity、lookup_service、claim7不变。

当前开发源码为IAM24/Audit14/PaaS1，新增Role对象、受限函数和闭合审计事实；发布profile不变。IAM产品Profile追加r2，并保留已登记r1的原始声明；当前SYSTEM默认值、已撤销附件和旧信任/决定不能由schema/bootstrap重放改写。新装使用新源码声明与系统种子；已有数据是否能调用新Role action仍取决于明确当前附件，不因注册目录而授予权限。保留数据正向资格由原root显式发布/关联当前TENANT策略证明，不暗改旧SYSTEM默认或重做安装bootstrap。完整release兼容仍由最终累计组合及安装owner验收，不为本管理切片单独分配发行revision，也不把开发中相同schema数字视为可跨二进制兼容。

锁序必须基于实际现有Account/主体/Policy/附件事务核对，不能仅照一条概念箭头实现。复用现有SERIALIZABLE和有界重试，跨对象先后顺序与实际管理、附件和删除路径保持一致；同类批量锁按稳定ID取得，写root关系、当前会话、预期修订与对象范围在锁内重查。不得把Account读锁误称为独占串行化全部授权变更。同resourceVersion的状态/信任/删除竞争只可一个结果，末尾outbox失败全部回滚。未来R2需把source session、RoleSession与credential generation加入同一已验证顺序。

### R2发行、当前权限与历史边界

发行只接受当前有效同账号USER登录会话；先证明调用者的`iam.role.assume`许可，再检查目标Role的当前信任，不伪造一个用户decision来表达角色权限。登录bearer、服务凭据和角色临时凭据使用不同目的的索引/验证摘要；复用既有CSPRNG和不透明秘密，不引入可以离线长期放行的JWT。ROLE公开结构、SQL记录/evidence及跨服务actor按下述已冻结的R2契约同片切换；R1不会提前扩大现有installation.verify的service-as-subject例外。

RoleSession必须绑定account、role、原USER、直接承担者、source session、原credential generation、信任version/digest、Role安全generation、发行/到期、撤销状态及不可变SessionPolicy承诺。首片禁止角色链，因此原始主体等于直接承担USER，但仍不能用会话显示名称替代稳定身份或接受caller sourceIdentity。源会话被保留并升级到新credential generation，不会自动把旧RoleSession升级过去。

实际expiresAt明确取数据库时间加请求时长、Role最大时长、source session到期三者最早；到期不可被元数据更新、幂等重放或重新启用延长。角色显示名称/描述/纯元数据tags变更不改变身份；信任选择、角色停启或最大时长改变推进单调安全generation，旧会话不能在“停用再启用/撤信任再加回”后复活。已提交工作和历史投递不因当前撤销被删除或永久阻断。

每次角色业务请求重新验证Account、原USER、source session/代际、Role/安全generation、RoleSession与当前信任，及原USER当前承担该Role的资格；这里重查的是承担资格，不把原用户业务Allow并入角色权限。角色权限、角色Boundary、不可变SessionPolicy通过同一个005求值器求交，适用Deny优先。缺失边界/信任/来源状态失败关闭，不能当作无限制。历史决定保留当时完整角色与原始承担证据，producer proof验证原不可变事实，不重新授权后来过期/停用的用户。旧User/Service事实字节不变，不以伪USER或SERVICE身份掩盖角色调用。

会话秘密只在发行成功的专用响应流转，不进入普通Role详情、Audit、日志或journal。发行幂等与丢失回包处理必须与一次性秘密生命周期一起冻结；不能为了重放返回把明文永久入库，也不能把已提交但回包未知当作失败再发另一凭据。R2在上述事务/秘密/历史边界明确前不开放发行。

#### R2 实施契约与集成准入

R2从已验证R1固定`bf7e8fbbdffe96b8af5b250edd1ed746c5b99265`继续。以下身份/记录器和tenant PaaS消费窗口已与Phase 3对齐；这只是实施契约，不是已运行的发行能力。第一步在原纯规则与凭据owner实现有界载体判断、到期上限、第三种凭据目的与严格AssumeRoleRequest/schema组件；暂不在OpenAPI或HTTP声明可调用发行路由，不把规则通过当作AssumeRole验收，也不提前改变当前schema或发布profile。

同账号USER信任匹配必须先完整验证Role、当前RoleTrustVersion与来源身份的归属和摘要；未知/损坏文档不能因前面有Allow而被跳过。匹配Deny优先，空信任/无匹配均不信任；暂停Account、停用/forced USER、失效来源会话和停用Role不能承担。这个载体判断只证明Trust一侧，不授予`iam.role.assume`或任何业务许可。发行用例还必须在同一真实事务核对当前Assume决定和实际bearer的generation。

到期取同一数据库时间加请求时长、Role最大时长和来源登录会话到期三者最早。请求范围60–43200秒、默认3600秒；Role上限或来源剩余时间较短时明确返回较短的实际到期，不修改来源会话。到期相等即失效，缺失/非UTC/非微秒时刻失败关闭。独立不透明凭据使用既有CSPRNG和唯一摘要owner，目的为`ROLE_SESSION`；与`SESSION`、`SERVICE`任一目的或绑定ID都不能互换，无新token算法、内存权威或第二种可长期离线放行的签名凭据。

拟定发行入口为`POST /v1/roles/{roleId}:assume`，仅接收resourceVersion、durationSeconds、可选SessionPolicy及requestId。账号、原USER、source session、generation和信任版本由IAM取出，不能由body/header指定。SessionPolicy只接受005作者文档，在发行事务从受信当前Profile编译、保存不可变内容；不创建普通Policy、不进入可变默认指针，也不复用005版本ID伪装成附件。使用唯一编译/canonical owner和相同求值器，缺失明确表示没有额外上限，显式null/空对象/非法内容不当作省略。

发行意图按真实Account+来源USER+原requestId唯一，绑定Role、预期修订、规范请求及实际source session/generation；来源改变不能把同requestId变成新发行。首个提交只返回一次秘密，数据库仅存目的隔离的查找/验证摘要。同请求重放返回EQUAL_REPLAY非敏感结果，不返回旧秘密、不发新秘密、不延长到期；输入变体冲突。`GET /v1/auth/role-sessions/by-request/{requestId}`仅凭当前有效原USER会话查自己的非敏感已提交结果，失去Assume许可后仍可查/撤自己的会话，但不能取得另一USER结果或任何业务许可。NOT_FOUND不证明旧请求已终止；客户端保留原意图，未知结果不得自动换requestId、另取当前expected或重新发行。确定已有发行但秘密丢失后，先撤销原RoleSession，再以明确新意图承担；没有新增通用receipt/重放秘密存储服务。

公开允许决定使用独立ROLE分支：`{type:"ROLE",id:roleId,roleSession:{sessionId,sourceUserId}}`。原始主体就是直接承担USER，不接受角色链或caller sourceIdentity。sourceSessionId、信任版本/digest、credential/security generation、授权向量及SessionPolicy承诺全部只属IAM私有evidence，不传播到PaaS/Audit/Operation、日志或普通响应。PaaS主体/Operation/outbox与Audit actor由决定逐字段映射，不回填假USER或用RoleSessionID冒充Role ID；USER/SERVICE/AGENT/SYSTEM_USER不得携带角色引用，旧编码/哈希不变。角色引用参与业务幂等和创建者身份比较，另一RoleSession不能以相同Role ID重放原会话命令；资源归属仍是Account。当前PaaS数据库仅接受原主体类型，必须在同一纵向片验证存储、HTTP与历史proof，不能只放宽Go枚举。

产品接入沿001的唯一`AuthorizationProfileAction.subjectTypes`能力，类型集合排序、唯一、有界，进入完整canonical/digest与005编译相容检查；不按产品名、scope或第二张许可白名单临时判断ROLE可调用动作。受保护的旧Profile缺字段才沿冻结旧语义解释：INSTALLATION_PROBE仅SERVICE_ACCOUNT，其他仅USER；不改旧bytes或回填字段。新IAM r3管理/Assume明确USER，PaaS r2 tenant业务动作及Audit r2 tenant query明确USER+ROLE，平台/probe仍原主体类型。旧编译版本不能随新目录获得ROLE，必须显式发布并选择新编译默认；新声明也不改旧SYSTEM默认或附件。当前USER使用旧策略的非扩权相容性与新ROLE拒绝必须分别验证。

开发schema冻结为IAM25/Audit15，只有实际SQL/消费切换后才改变readiness。单一`record_authorization`直接7→8参，旧重载删除；所有新决定显式存储contract3。末参是必填角色证据，USER/SERVICE必须显式JSON null并存SQL NULL；ROLE必须有完整分离证明。原principal_id仅用于历史1/2及新USER/SERVICE，ROLE为NULL，不能用原USER占位冒充角色决定；新受保护subject_type、role_id和source_principal_id分别绑定真实ROLE与来源USER的同Account外键。Denied不公开Subject，但私有metadata仍准确绑定actor。

`read_audit_evidence`保持原五列，在原SQL owner内新增角色历史证据校验：发行receipt、session、sourceUSER/session/generation、信任、安全generation、两侧授权/边界/会话限制及冻结Profile引用逐项和原发生时证据一致。任一缺失/篡改拒绝，不查current状态/head、不重授权；旧contract不接受ROLE。claim7、ServiceIdentity、lookup_service及唯一CanonicalizeEvent不改；PaaS开发schema按自己实际输入/存储形状验证，最终不继承另一分支的数字或发布profile。

R2同片实现原Root+当前PDP守护的RoleBoundary read/set/remove，不引用不可管理的隐藏上限。RoleBoundary是必须存在的独立上限；remove明确使Role不可承担并使旧会话永久失效，不解释为无限权限。Role附件、RoleBoundary与可选SessionPolicy使用同一求值器求交，Deny全来源优先；来源USER的业务Allow/平台权限不并入。普通User边界的NONE语义不变，不能将角色边界的缺失关闭反向套用到User。初始同时限制每source USER 16、每Role 128、每Account 1024条未撤销且未到期会话；已因来源变化失去业务资格但尚未撤销/到期的行保守计入，显式自撤销释放名额。配额在真实发行事务、精确范围锁内计算，不靠单实例内存限流或清除不可变历史绕过。数字是初始产品上限，不是吞吐或HA验收结果。

同片提供source USER显式revoke-by-request与ROLE bearer self-logout：精确身份只能撤自己的RoleSession，失去Assume许可不阻止退出，不签发新USER session或伪造Assume decision。封闭tenant IAM事实区分issued（真实USER+原Assume decision）、source revoke（真实USER自服务、无伪业务decision）、self exit（ROLE+精确公开引用）；target均为ROLE_SESSION。ROLE事实仅开放这些自退出、contract3授权决定、已声明PaaS tenant业务与Audit tenant查询映射，平台、probe、安装恢复及R1原root管理仍拒绝；语法能解析不等于历史证据已证明。

| R2 接口 | 认证及权限边界 | 严格命令/结果 |
| --- | --- | --- |
| `POST /v1/roles/{roleId}:assume` | USER当前`iam.role.assume` / ROLE，加当前Trust与必需RoleBoundary | 原Role修订、durationSeconds、可省略sessionPolicy、requestId；首次专用秘密响应，等值EQUAL_REPLAY无秘密 |
| `GET /v1/auth/role-sessions/by-request/{issuanceRequestId}` | 当前同Account原USER；不要求仍可Assume | 只返回自己的原发行身份、到期和当前终态，含秘密/私有来源字段的回包非法 |
| `POST /v1/auth/role-sessions/by-request/{issuanceRequestId}:revoke` | 当前原USER自服务，仅该USER原发行结果 | 新撤销requestId；末尾outbox与终态原子，未知发行不当作成功撤销 |
| `GET /v1/auth/role-session` | 目的匹配的ROLE bearer，仅自身身份投影 | Role/Account/sourceUserId/RoleSession ID、到期与状态；不是USER CurrentIdentity或缓存permit |
| `POST /v1/auth/role-session:logout` | 精确ROLE bearer持有证明，仅撤自身；不要求业务Allow | requestId；`iam.role-session.exited`，不返回新凭据或原USER session |
| `GET /v1/roles/{roleId}/permission-boundary` | USER当前`iam.role.read` / ROLE | 原Role修订和明确边界引用或null；null表示不可承担 |
| `PUT /v1/roles/{roleId}/permission-boundary` | 原Root及当前`iam.role.permission-boundary.set` / ROLE | policyId、policyResourceVersion、resourceVersion、requestId；跟随该Policy默认，不能自动关联正向权限 |
| `DELETE /v1/roles/{roleId}/permission-boundary` | 原Root及当前`iam.role.permission-boundary.remove` / ROLE | resourceVersion、requestId；解除上限关系并关闭承担，不复活旧会话 |

三类会话事实准确命名为`iam.role-session.issued/revoked/exited`。RoleBoundary管理事实为`iam.role.permission-boundary.set/removed`，真实USER+原管理decision、target ROLE；两种自撤销无业务decision，不能与issued共用来源契约。新动作/事实/actor仅在完整契约、SQL与真实消费切换中开放；当前纯请求组件不提供这些HTTP能力。

**撤销后再授权不得复活旧角色会话。** 当前Assume资格仍须每次重算；此外绑定发行时的授权来源修订承诺，至少包含实际附件及修订、成员关系身份/修订、Policy修订/默认精确版本、边界关系/修订和User修订。只有“当前Allow”或当前内容digest不足以识别默认指针切走再切回。复用原目录快照中已经验证的修订素材，不复用cursor作为permit；完整来源的保守失效可能要求重新承担，即使仍有另一条Allow，也不能自动更新旧RoleSession的承诺。Role安全generation覆盖信任选择、状态、期限及角色授权/边界变更；来源credential generation单独固定。显示元数据变化与安全变更区分，最终通过真实ABA/并发和两实例门禁证明，不能仅靠字段命名声称完成。

## 实现拥有者与复用

沿现有`api/iam/v1`数据/严格编码、`authority`纯规则、`identityaccess`用例事务、postgres受限函数、nethttp、生成器及integration/authorityprocess测试拥有者实施。角色/信任契约如需独立源文件，是为区分承担准入与身份权限文档的编码和安全边界，不建立新服务、通用身份框架或另一套PDP。固定来源与REUSE/ADAPT/REFERENCE/REJECT决策归现有FEAT-006 adoption；UI和第三方provider没有运行时依赖。

角色契约位于`api/iam/v1/role.go`：严格`TrustPolicyDocument`/`RoleTrustVersion`读取、静态校验及唯一`CanonicalizeTrustPolicyDocument(document) (canonical,contentDigest,error)`。规范化只排序副本，保留空`[]`，拒绝空缺/null、未知字段、重复/大小写歧义、未实现载体、权限文档字段和超预算输入。R1沿此拥有者增加Role元数据、目录/详情/历史、输入输出校验和生成OpenAPI；使用原用例事务、PostgreSQL adapter及nethttp，不增加第二套编码器、PDP、会话存储或独立服务。数据库`role_contract_ready()`由迁移验证和实时readiness共用，核对全部九项公开函数、私有会话末参、完整ACL/proconfig、真实表归属/RLS、信任外键及不可变性保护；相同数字的schemaVersion不替代这些检查。

固定`1bcaa62bf6b11c20a7b34458408a221ed0aa633c`的聚焦契约与JSONSchema、全仓`go test -race -p 2 -count=1 ./...`、`go vet -p 2 ./...`、模块校验、API生成字节稳定和Linux amd64构建通过（Go2/768MiB）；[Verification35047801568](https://github.com/xiak/matrix/actions/runs/35047801568)精确SHA的go/authority-process/node-process三项均success。测试明确区分16KiB reader预算、Go语义及JSONSchema结构：schema不证明SID跨语句唯一、摘要相等、实际Account/USER或当前选中关系。纯契约本地没有新增PG/进程/浏览器fixture，独立CI也不构成尚未实现的Role管理或承担验收。

附件会话基础沿原仓储/事务接口传递实际bearer的Session.ID，没有新增SessionStore、Redis依赖、北向selector或审计字段。私有`policy_attachment_contract_ready()`由迁移验证与实时readiness共用，检查唯一10/7参入口、精确返回列、无默认/可变参数、owner/ACL、SECURITY DEFINER、易变性/并行属性和安全search_path；元数据漂移失败关闭。新的输入缺失/错误引用门禁使用真实PDP及PostgreSQL适配器，仅在测试事务入口替换私有Session引用；过期/旧代际/NULL行是显式合成存储攻击，不声称为旧binary来源证据。

2026-09-16受限PG18.6（1CPU/768MiB/128PIDs/64连接，Go2/768MiB、真实门禁串行race/p1）通过原策略保留数据门禁与附件会话门禁，合计301.225s。两者沿用同一integration owner，但使用独立数据库和原4分钟/2分钟预算，避免会话矩阵的测试用户混入策略目录/101成员规模fixture；CI在既有authority-process job运行两项，不放宽超时、密码成本或规模断言。附件矩阵包含用户、组、平台用户共48个安全变更先提交的可控交错：退出、改密省略/true/false、保留当前会话、重置/forced及停用/撤权；保留会话仍可写，失效会话拒绝，关系和成功事实无部分效果。双次迁移及等值bootstrap重放后再次检查原会话/撤权结果，原receipt不变、旧权限不复活。平台身份不可在线重置/停用继续由原凭据保护门禁验收，本矩阵不绕过它。

18个私有引用用例覆盖缺失/畸形/未知/另一USER/已撤销/过期/旧或NULL代际及正常引用；四项北向selector注入拒绝。旧9/6参调用返回未定义函数，权限和入口配置漂移关闭readiness。原IAM HTTP/本地凭据恢复门禁141.053s，Audit双schema/HTTP分别11.384s/3.448s，独立IAM/Audit/PaaS进程77.478s通过，保留实际受限数据库登录、双账号资源/Operation/outbox和历史proof。全仓race/p2、vet/p2、模块校验、API生成字节稳定及Linux amd64构建通过；默认跳过的外部fixture不计为真实运行证据。此前原实现已能在两项退出竞争中经SERIALIZABLE重试拒绝，不把该回归声称为已复现漏洞；新参数提供显式数据库入口保证。此证据仍不是Role/STS、Redis替换、HA或发布验收；Role写入与原root恢复的竞争、写入先提交的Role交错及完整角色闭环按R1/R2继续完成。

### R1 本地真实运行证据

2026-09-16，本任务独立PG18.4（1CPU/768MiB/128PIDs/64连接；Go2/768MiB、真实门禁race/p1串行）完成：

- 原IAM HTTP完整回归106.296s，新增R1聚焦回归36.857s：双Account同名Role、原Root与真实当前PDP、非Root显式Allow仍不能写、服务/forced/跨账号拒绝；CRUD、信任版本及精确/冲突重放、100项目录和101版历史、跨用户/账号/目录/Role及伪造游标拒绝。角色不会产生USER凭据。
- 五类Role写入与USER/ROLE附件共81项私有会话引用检查11.345s：缺失、畸形、未知、另一USER、撤销、过期、旧/NULL generation失败关闭，有效引用通过；北向session selector拒绝。此为真实PDP之后对私有参数的负向故障注入，不把合成会话行称为旧binary来源证据。
- 原附件会话完整回归66.139s，保留USER/GROUP/平台USER的48项可控安全变更交错，并包含上述81项私有引用及原重放检查；未以新增Role聚焦检查替代现有授权与会话回归。
- 十项数据库可观测交错包含logout、日常改密省略/true/false/保留当前、原Root恢复/强制改密、Account暂停先提交，以及Role写入先提交后logout/恢复。前者拒绝失效请求、保留的有效会话可继续；后者保留单一成功事实，旧会话和原命令不能重新生效。还验证同修订更新/停用/信任/删除竞争，以及删除与附件赋予/撤销竞争；没有活动孤儿附件。末尾outbox失败使Role、信任版本、附件与对应事实一并回滚。
- Role函数授权、search_path、security模式、额外重载、表RLS、信任保护与外键漂移关闭readiness；Role墓碑和历史不可改。停用USER仍可被明确写入信任，删除USER不改旧Role/Trust，新的已删除USER引用拒绝且无部分状态（额外HTTP聚焦14.090s）。
- 独立IAM两实例/Audit/PaaS及真实dispatcher进程53.475s：六种ROLE事实及附件经真实outbox入正确tenant chain；Audit断线期间提交、原操作会话退出后继续投递/精确重放，伪造目标/账号拒绝；两IAM及重启不复活Role。受信任USER的登录会话不继承角色策略，Role ID不能登录，未实现的STS入口关闭；原USER应用/Operation归属保持。此项不证明R2临时凭据或角色业务授权。
- 固定IAM21解释前驱`1dc1079c4e7bec80f5345d06929875b492ba9a86`真实binary保留数据门禁24.775s：迁移/重启保留原SYSTEM默认、字节、receipt、会话与历史proof；原Root的新Role动作先拒绝，显式发布/关联当前TENANT策略后成功，撤销与Role墓碑在再次迁移/重启后保持。仅这个明确解释边界，不恢复从schema1开始的整条未发布开发升级链，也不证明跨release-profile准入。Audit双schema与HTTP分别7.999s/4.017s通过。

准确Git候选源码的独立干净导出通过全仓race/p2、架构、vet/p2、模块校验、API生成字节稳定与Linux amd64构建；工作目录中遗留的验收源码副本未作为产品源码导入，原架构检查未放宽。固定`bf7e8fbbdffe96b8af5b250edd1ed746c5b99265`已推送；GitHub API核实[Verification35060352506](https://github.com/xiak/matrix/actions/runs/35060352506)精确SHA、go/authority-process/node-process三项全部completed/success。上述证据不是RoleSession、完整006、UI、发布或公有云HA验收。

### R2 发行意图与纯规则基础证据

2026-09-16，既有API/authority测试新增严格AssumeRoleRequest与schema接受矩阵、来源/当前信任关系、空信任与Deny优先、服务/暂停/forced/撤销拒绝、三重到期上限和微秒边界。相同熵、相同ID在SESSION/SERVICE/ROLE_SESSION三种目的之间交叉查找/验证均不能互换；不把随机内容恰好不同当作目的隔离证明。请求编解码拒绝caller账号、主体、source session/generation、trust、编译物、重复字段、null限制和超限；纯信任匹配不会给原USER增加业务Allow。目的常量与schema组件补齐前的缺失测试先失败，接入后通过；这不是复现了既有运行权限漏洞。

精确Git候选的独立干净导出通过全仓`go test -race -p 2 -count=1 ./...`（含架构）、`go vet -p 2 ./...`、模块校验、API生成字节稳定及Linux amd64构建。Go2/768MiB，现有请求round-trip fuzz为15秒/2workers/1秒最小化预算，通过120526次执行。该基础片没有新增本地PG、浏览器或运行发行进程；默认跳过的外部fixture不记为真实R2证据。当前HTTP仍无AssumeRole、ROLE业务身份或会话发行/撤销入口，record8/contract3及角色历史证据尚未实现；subjectTypes增量由001/005拥有，实际R2源码Profile切换尚未发生。开发源码仍24/14/1，发布profile不改。固定6ae975d9a65569d5215fca26ef65a16722d2cd13的Verification35063652730首轮Go/节点成功，但authority-process超过旧10分钟job预算后取消，不能记为全绿；整体作业预算与再次精确源码验证归011。

### 当前管理门禁的独立测试范围

角色管理和私有会话引用矩阵分别使用独立、全新PostgreSQL数据库，不再嵌套消耗原账号HTTP和附件会话矩阵的剩余总时限。沿用同一integration文件、原业务断言和受限runtime，每个新增独立fixture有120秒总预算；角色竞争的锁等待、密码成本、48项附件交错与81项私有引用均未减少或放宽。每个fixture末尾保留双次schema重放、等值bootstrap receipt及实际Role状态不变检查。

2026-09-16，精确候选Git树`e496908ecea855d6300ad8e549774719f1d46b6a`的干净导出在独立PG18.4（1CPU/768MiB/PIDs128/64连接，Go2/512MiB、race/p1）通过原账号HTTP、附件会话及上述两项独立矩阵，合计263.159秒。同一干净导出随后通过全仓race/p2（含架构）、vet/p2、模块校验及Linux amd64构建。固定`d45402d91c89a5bb23f52fcfde65491435cd0f55`的[Verification35069879250](https://github.com/xiak/matrix/actions/runs/35069879250)已按精确SHA核实Go、authority-process、node-process全部completed/success。这只证明测试范围拆分后的当前R1及主体能力回归，不包含RoleBoundary/RoleSession。

## 验收

- R1：两个真实Account可有同名Role；同名User/Role不混用。Root当前授权成功，普通用户/服务/platform-only/另一账号/过期或forced-change会话拒绝；读许可不能写或承担。真实同账号信任、Role策略附件、版本重放与并发更新/删除/撤权，所有失败无部分Role、信任、附件或成功事实。角色没有任何长期凭据或登录能力。
- R1：运行数据库验证Role/信任/附件的范围、不可变性、RLS、函数形状/ACL、失联与当前Profile漂移；原root/current authority、source registry、User/Group/Boundary、平台凭据保护、claim及旧canonical回归保持。产品Profile追加不自动放大旧策略默认/附件；原数据重放、重启后删除和撤权不复活。
- R1：旧SYSTEM默认下原Root的新Role动作在显式发布/关联TENANT策略前拒绝，原policy管理路径仍可达；非Root即使普通策略Allow仍被写保护拒绝。删除或停用User不改写旧Trust版本；新信任写入不接受已删除User。附件只接受真实同账号ROLE discriminator，不扩大原User/Group/Service或平台附件面。
- R1：新的私有会话参数与Role/USER/GROUP/平台USER附件共同通过当前身份、logout、change(true/false/forced)、reset/recover、停用/撤权的并发锁序门禁；旧9/6调用机械失败，新函数ACL/proconfig/readiness形状准确，所有失败不产生部分关系或成功事实。不得靠有界重试掩盖actor/target的反向锁序。
- R2：双边任一缺失拒绝；角色边界/SessionPolicy不能扩权；管理员承担只读Role后不能用原用户Allow写入。错误Role/Account/token/source/generation、会话过期/撤销、并发assume/revoke/delete/change/reset/logout失败关闭。反复停启、撤信任再恢复及原命令重放均不能复活旧RoleSession。
- R2/R3：真实独立IAM/PaaS/Audit临时会话业务路径、原始actor与不可变Audit关联；身份变化后原outbox继续投递但当前producer凭据仍须有效；进程重启/两IAM路由无关、数据失联失败关闭。真实UI显示当前角色、账号、原身份与到期；退出角色不创建或复活原登录会话。
- unit、架构/security、PG18、独立进程、UI及最终release/容量各按自己范围验收。没有外部环境的跨账号或IdP路径不以mock声称完成；也不把R1管理接口或后续纯规则通过当成R2/整套006已验收。
