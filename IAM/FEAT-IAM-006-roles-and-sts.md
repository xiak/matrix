# FEAT-IAM-006：角色、信任与 STS

- 状态：R1 角色管理固定 `bf7e8fbbdffe96b8af5b250edd1ed746c5b99265`、R2 同账号承担及 tenant PaaS/Audit 真实授权闭环固定 `0752c602ab4ce6d73a21094c8e9f75a1c8750183` 均已完成本地真实运行、整仓与独立 CI 验收。R3 自服务发现/当前角色显示、管理型会话目录及 UX/UI、容量和发布仍未完成，整体006未验收；不以R2后端通过代替最终页面与发布验收。
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

R1固定源码为IAM24/Audit14/PaaS1，新增Role对象、受限函数和闭合审计事实；发布profile不变。IAM产品Profile追加r2，并保留已登记r1的原始声明；当前SYSTEM默认值、已撤销附件和旧信任/决定不能由schema/bootstrap重放改写。新装使用新源码声明与系统种子；已有数据是否能调用新Role action仍取决于明确当前附件，不因注册目录而授予权限。保留数据正向资格由原root显式发布/关联当前TENANT策略证明，不暗改旧SYSTEM默认或重做安装bootstrap。完整release兼容仍由最终累计组合及安装owner验收，不为本管理切片单独分配发行revision，也不把开发中相同schema数字视为可跨二进制兼容。

锁序必须基于实际现有Account/主体/Policy/附件事务核对，不能仅照一条概念箭头实现。复用现有SERIALIZABLE和有界重试，跨对象先后顺序与实际管理、附件和删除路径保持一致；同类批量锁按稳定ID取得，写root关系、当前会话、预期修订与对象范围在锁内重查。不得把Account读锁误称为独占串行化全部授权变更。同resourceVersion的状态/信任/删除竞争只可一个结果，末尾outbox失败全部回滚。未来R2需把source session、RoleSession与credential generation加入同一已验证顺序。

### R2发行、当前权限与历史边界

发行只接受当前有效同账号USER登录会话；先证明调用者的`iam.role.assume`许可，再检查目标Role的当前信任，不伪造一个用户decision来表达角色权限。登录bearer、服务凭据和角色临时凭据使用不同目的的索引/验证摘要；复用既有CSPRNG和不透明秘密，不引入可以离线长期放行的JWT。ROLE公开结构、SQL记录/evidence及跨服务actor按下述已冻结的R2契约同片切换；R1不会提前扩大现有installation.verify的service-as-subject例外。

RoleSession必须绑定account、role、原USER、直接承担者、source session、原credential generation、信任version/digest、Role安全generation、发行/到期、撤销状态及不可变SessionPolicy承诺。首片禁止角色链，因此原始主体等于直接承担USER，但仍不能用会话显示名称替代稳定身份或接受caller sourceIdentity。源会话被保留并升级到新credential generation，不会自动把旧RoleSession升级过去。

实际expiresAt明确取数据库时间加请求时长、Role最大时长、source session到期三者最早；到期不可被元数据更新、幂等重放或重新启用延长。角色显示名称/描述/纯元数据tags变更不改变身份；信任选择、角色停启或最大时长改变推进单调安全generation，旧会话不能在“停用再启用/撤信任再加回”后复活。已提交工作和历史投递不因当前撤销被删除或永久阻断。

每次角色业务请求重新验证Account、原USER、source session/代际、Role/安全generation、RoleSession与当前信任，及原USER当前承担该Role的资格；这里重查的是承担资格，不把原用户业务Allow并入角色权限。角色权限、角色Boundary、不可变SessionPolicy通过同一个005求值器求交，适用Deny优先。缺失边界/信任/来源状态失败关闭，不能当作无限制。历史决定保留当时完整角色与原始承担证据，producer proof验证原不可变事实，不重新授权后来过期/停用的用户。旧User/Service事实字节不变，不以伪USER或SERVICE身份掩盖角色调用。

会话秘密只在发行成功的专用响应流转，不进入普通Role详情、Audit、日志或journal。发行幂等与丢失回包处理必须与一次性秘密生命周期一起冻结；不能为了重放返回把明文永久入库，也不能把已提交但回包未知当作失败再发另一凭据。R2在上述事务/秘密/历史边界明确前不开放发行。

#### R2 实施契约与集成准入

R2从已验证R1固定`bf7e8fbbdffe96b8af5b250edd1ed746c5b99265`继续。以下身份/记录器和tenant PaaS消费窗口已与Phase 3对齐。原纯规则、凭据、用例和受限数据库owner共同实现有界载体、到期、目的隔离、严格发行HTTP与真实业务权限；不能把其中的纯规则或身份读取通过当作完整AssumeRole验收。当前工作区实际开发schema为IAM25/Audit15/PaaS2，发布profile未改变；新增源码能力不得作为旧发布二进制或跨profile兼容证据。

同账号USER信任匹配必须先完整验证Role、当前RoleTrustVersion与来源身份的归属和摘要；未知/损坏文档不能因前面有Allow而被跳过。匹配Deny优先，空信任/无匹配均不信任；暂停Account、停用/forced USER、失效来源会话和停用Role不能承担。这个载体判断只证明Trust一侧，不授予`iam.role.assume`或任何业务许可。发行用例还必须在同一真实事务核对当前Assume决定和实际bearer的generation。

到期取同一数据库时间加请求时长、Role最大时长和来源登录会话到期三者最早。请求范围60–43200秒、默认3600秒；Role上限或来源剩余时间较短时明确返回较短的实际到期，不修改来源会话。到期相等即失效，缺失/非UTC/非微秒时刻失败关闭。独立不透明凭据使用既有CSPRNG和唯一摘要owner，目的为`ROLE_SESSION`；与`SESSION`、`SERVICE`任一目的或绑定ID都不能互换，无新token算法、内存权威或第二种可长期离线放行的签名凭据。

发行入口为`POST /v1/roles/{roleId}:assume`，仅接收resourceVersion、durationSeconds、可选SessionPolicy及requestId。账号、原USER、source session、generation和信任版本由IAM取出，不能由body/header指定。SessionPolicy只接受005作者文档，在发行事务从受信当前Profile编译、保存不可变内容；不创建普通Policy、不进入可变默认指针，也不复用005版本ID伪装成附件。使用唯一编译/canonical owner和相同求值器，缺失明确表示没有额外上限，显式null/空对象/非法内容不当作省略。

发行意图按真实Account+来源USER+原requestId唯一，绑定Role、预期修订、规范请求及实际source session/generation；来源改变不能把同requestId变成新发行。首个提交只返回一次秘密，数据库仅存目的隔离的查找/验证摘要。同请求重放返回EQUAL_REPLAY非敏感结果，不返回旧秘密、不发新秘密、不延长到期；输入变体冲突。`GET /v1/auth/role-sessions/by-request/{requestId}`仅凭当前有效原USER会话查自己的非敏感已提交结果，失去Assume许可后仍可查/撤自己的会话，但不能取得另一USER结果或任何业务许可。NOT_FOUND不证明旧请求已终止；客户端保留原意图，未知结果不得自动换requestId、另取当前expected或重新发行。确定已有发行但秘密丢失后，先撤销原RoleSession，再以明确新意图承担；没有新增通用receipt/重放秘密存储服务。

公开允许决定使用独立ROLE分支：`{type:"ROLE",id:roleId,roleSession:{sessionId,sourceUserId}}`。原始主体就是直接承担USER，不接受角色链或caller sourceIdentity。sourceSessionId、信任版本/digest、credential/security generation、授权向量及SessionPolicy承诺全部只属IAM私有evidence，不传播到PaaS/Audit/Operation、日志或普通响应。PaaS主体/Operation/outbox与Audit actor由决定逐字段映射，不回填假USER或用RoleSessionID冒充Role ID；USER/SERVICE/AGENT/SYSTEM_USER不得携带角色引用，旧编码/哈希不变。角色引用参与业务幂等和创建者身份比较，另一RoleSession不能以相同Role ID重放原会话命令；资源归属仍是Account。本片同时替换PaaS存储与HTTP身份约束，并以真实业务及历史proof验证；Go枚举不构成独立接入完成。

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
| `POST /v1/auth/role-session:logout` | 精确ROLE bearer持有证明，仅撤自身；不要求业务Allow | 原LogoutRequest仅requestId；返回非秘密RoleSession终态，`iam.role-session.exited`，不返回新凭据或原USER session |
| `GET /v1/roles/{roleId}/permission-boundary` | USER当前`iam.role.read` / ROLE | 原Role修订和明确边界引用或null；null表示不可承担 |
| `PUT /v1/roles/{roleId}/permission-boundary` | 原Root及当前`iam.role.permission-boundary.set` / ROLE | policyId、policyResourceVersion、resourceVersion、requestId；跟随该Policy默认，不能自动关联正向权限 |
| `DELETE /v1/roles/{roleId}/permission-boundary` | 原Root及当前`iam.role.permission-boundary.remove` / ROLE | resourceVersion、requestId；解除上限关系并关闭承担，不复活旧会话 |

三类会话事实准确命名为`iam.role-session.issued/revoked/exited`。RoleBoundary管理事实为`iam.role.permission-boundary.set/removed`，真实USER+原管理decision、target ROLE；两种自撤销无业务decision，不能与issued共用来源契约。exited只接受ROLE，完整actor引用中的sessionId必须等于目标ROLE_SESSION；仅该IAM事务原子提交的outbox可证明事实，不能用原Assume决定代替。必须随完整R2契约、SQL与真实业务消费验证后统一交付，不单独发布当前发行增量。

角色自退出使用专用的私有持有证明读取，不调用当前业务身份查询：USER/服务秘密不能定位ROLE_SESSION索引，既有唯一验证器还要核对该秘密与实际RoleSession ID。来源会话退出、改密、User/Role停用或删除、Account暂停、角色到期与权限撤销不阻止销毁自己仍持有的凭据。读取只用于自退出，不提供北向查询或业务permit；mutation再次由相同目的摘要定位不可变归属，并按Account共享锁→来源USER排他锁→RoleSession排他锁串行化，不重新启用任何身份、变更授权或修改到期。受限入口及完整ACL/函数形状纳入readiness。

退出幂等限定于完整RoleSession身份与原requestId/请求摘要。精确重放返回原撤销时间，不新增事实；另一个退出意图或已被来源USER撤销时返回冲突，不冒充自己的成功。不同RoleSession可独立使用同一requestId，但不能修改或重放对方的结果。单向revokedAt与唯一成功outbox同事务；提交后回包丢失可凭原ROLE秘密和原意图重放，不能据此取得登录会话或再次承担。

#### 发行记录与原意图自服务

发行响应为`AssumeRoleResponse{outcome,session,credential?}`，outcome只允许APPLIED/EQUAL_REPLAY；前者必须有一次性credential，后者连空credential字段也不允许。普通JSON编码不能输出Secret，唯一显式发行响应编码器负责允许的输出，HTTP设no-store。`RoleSession{apiVersion,kind,id,accountId,roleId,sourceUserId,status,issuedAt,expiresAt,revokedAt?}`是非敏感发行记录，不是登录会话或当前业务permit；ACTIVE只表示尚未显式撤销，不证明未过期、当前来源有效或仍有业务权限。当前有效身份投影另走ROLE自身入口。

原意图查询只允许当前有效原USER。公开结果不含sourceSessionId、credential/security generation、信任版本或授权证据。新登录可以查询和撤销自己的旧发行记录，但用新来源Session或已保留而升级generation的登录重放原Assume请求必须冲突。已撤销/删除Role或后来失去Assume许可不妨碍原USER查询、撤销；等值重放只返回原记录，不能重新校验后把旧命令变成新发行。返回NOT_FOUND不取得新的发行授权。

发行事务沿Account→来源USER→credential/实际Session→Role取得锁；发行专用的Account排他锁串行化16/128/1024三层会话名额，普通登录/业务授权不取得这个排他锁。计数包含尚未过期且未显式撤销的已失效会话，不因安全变更自动释放名额或发替代凭据。当前Assume决定、信任、必需边界、精确Role修订与单调代际在锁内重查，SQL再核对三重到期上限；记录、目的隔离索引和成功outbox一起提交。

`role_sessions`保存不可变发行身份、原决定、来源和Role授权素材、可选SessionPolicy的原编译承诺；`role_session_index`只承担秘密摘要定位。引用现有Account/USER/源Session/Role/TrustVersion/Decision真实外键，不插入Principal或用户凭据。除单向撤销时间外，发行记录不可更新、删除或截断。Role附件/边界关系、Policy修订/默认和编译内容属于私有历史证明，不进入北向响应或Audit事件正文。发行读写、按原意图查询/撤销的四个受限入口及表、索引、外键、ACL与触发器纳入同一`role_contract_ready()`；不增加通用会话仓储、第二PDP或秘密重放服务。

当前身份读取沿同一owner的受限`lookup_role_session(text) -> jsonb`及`GET /v1/auth/role-session`：目的隔离摘要只定位原发行记录，实际Account/USER/source Session/credential generation、Role/security generation/当前Trust、完整来源与角色修订素材全部重新核对。Account→USER→credential/session→Role使用共享锁，不获取发行配额的Account排他锁；取得锁后再以数据库时钟检查源会话及角色会话到期。原来源的时间条件仍由唯一PDP重算，不能把向量相等或身份查询响应缓存为业务permit。私有源Session定位仅在IAM事务内复用既有登录上下文解码，不把角色秘密交给USER认证路径。

`Subject`公开类型与登录`PrincipalType`分离，ROLE必须携带且仅携带`roleSession.sessionId/sourceUserId`；USER/SERVICE_ACCOUNT连显式null的roleSession字段也拒绝。旧USER/SERVICE公开bytes不变，只有实际产品Profile声明及策略编译支持后才可产生ROLE Allow。当前工作区PaaS/Audit声明、record8/contract3与业务消费者已接入完整ROLE引用；平台、probe和未声明产品仍关闭ROLE。角色边界及SessionPolicy读取使用现有冻结版本/编译器，不造PolicyVersion ID或引入另一编码器。PaaS的Operation/事务outbox、创建者比较和幂等摘要均保留精确角色会话，另一RoleSession不能重放前一会话命令；资源归属仍是Account。Audit actor过滤使用完整引用，cursor绑定完整过滤条件而非查询者身份，同账号有权查询者仍可继续相同过滤页；不同会话过滤或不同Account不能复用该游标。

**撤销后再授权不得复活旧角色会话。** 当前Assume资格仍须每次重算；此外绑定发行时的授权来源修订承诺，至少包含实际附件及修订、成员关系身份/修订、Policy修订/默认精确版本、边界关系/修订和User修订。只有“当前Allow”或当前内容digest不足以识别默认指针切走再切回。复用原目录快照中已经验证的修订素材，不复用cursor作为permit；完整来源的保守失效可能要求重新承担，即使仍有另一条Allow，也不能自动更新旧RoleSession的承诺。Role安全generation覆盖信任选择、状态、期限及角色授权/边界变更；来源credential generation单独固定。显示元数据变化与安全变更区分，最终通过真实ABA/并发和两实例门禁证明，不能仅靠字段命名声称完成。

### R3 自服务发现与角色显示上下文

本节为下一后端切片的目标，不属于R2已实现接口。UX/UI工程师已确认：普通USER可能具有Assume权限却没有Role管理目录/read权限；角色模式也不能依赖切换前偶然保留的名称缓存。先补这两个权威投影和详情能力，再由010接入真实页面。管理型RoleSession目录/代他人撤销仍是后续独立验收项，不能拿当前by-request自服务或MOCK Sessions tab冒充完成。

`GET /v1/auth/assumable-roles`是当前有效USER的同账号自服务发现，不要求`iam.role.list/read`，不接受caller account/user/source-session selector。仅返回当次读取中USER的精确Assume权限、Trust、Role状态及必需边界检查通过的候选；不能把本账号所有Role加一个forbidden字段暴露给无目录权限的人。沿现有纯求值/信任/边界拥有者复用规则，不创建第二PDP或新增业务许可，不生成一次虚构的Assume成功决定。

结果绑定真实accountId/sourceUserId，items只含roleId/accountId/name/status/maxSessionDurationSeconds/resourceVersion和精确`iam.role.assume` capability；无Trust、Policy、附件、秘密或未授权总数。每次读取有固定候选扫描和响应预算，复用既有签名游标owner，绑定实际账号/来源USER、用途和查询顺序。稀疏授权允许空items仍有nextAfter；客户端以nextAfter是否存在判断结束，不无限自动翻页。每页重新检查当前资格，cursor和availability不是permit；发行仍检查当前版本/来源/边界/时长/请求策略及会话配额。只读发现不走发行配额或Account排他锁，不能把全账号串行化当成分页实现。

现有`GET /v1/auth/role-session`在R3直接替换为严格`CurrentRoleIdentity{apiVersion,kind,session,account,role,sourceUser}`：account仅id/displayName，role仅id/name，sourceUser仅id/loginName/displayName；各ID与session精确一致，由同一次当前IAM权威读取推导。RoleSession发行记录和该当前身份投影不是同一种结果；按pre-v1规则不保留旧形状兼容分支或平行别名入口，固定消费者须同步适配。完整Account/RootIdentity、平台绑定、Trust/Policy、sourceSessionId、代际和秘密均不公开。

资格失效或权威不可用时该当前投影仍返回401/503，不为Header放行失效身份。页面可保留此前已验证的非敏感显示副本，明确显示失效并使用原ROLE秘密自退出；不能用显示副本授权。原USER bearer与ROLE秘密使用独立内存槽，返回原身份必须重新验证原USER会话，退出角色不发行或复活任何USER登录。一次性秘密和未知结果仍严格沿R2的原意图规则。

`RoleAccess.capabilities`增加精确`iam.role.assume`，和self目录共用服务端资格计算，不套用只允许原root写Role的管理保护。读取详情不意味着能够承担；权限/信任/边界或目标状态阻止承担时投影封闭restriction，损坏/不确定则整体失败关闭。`RoleListing`保持管理用途，不另加一套列表快捷承担判断；无管理目录权限的普通成员从self目录发现角色。

本片必须用当前真实HTTP/PG与独立进程证明：只有Assume而无list/read的普通成员可发现并承担；少任一侧、缺边界、停用/暂停、旧会话与跨账号均不泄露候选；稀疏分页、空页继续、不同USER/Account/用途cursor及页面后撤权均正确。详情的非root承担能力与root管理能力分别验证。显示上下文完整绑定且无私有字段，不使会话失效的Role显示名称修改后重新读取获得当前名称；来源USER或Account修订改变仍按R2原规则失效，不为显示信息复活旧会话，来源撤权后返回拒绝而非旧permit；自退出仍可用。新只读函数的范围、ACL、readiness与锁边界沿现有owner验证，实际形状确定后推进开发schema，不改发布profile或记录器/claim/历史canonical契约。

## 实现拥有者与复用

沿现有`api/iam/v1`数据/严格编码、`authority`纯规则、`identityaccess`用例事务、postgres受限函数、nethttp、生成器及integration/authorityprocess测试拥有者实施。角色/信任契约如需独立源文件，是为区分承担准入与身份权限文档的编码和安全边界，不建立新服务、通用身份框架或另一套PDP。固定来源与REUSE/ADAPT/REFERENCE/REJECT决策归现有FEAT-006 adoption；UI和第三方provider没有运行时依赖。

角色契约位于`api/iam/v1/role.go`：严格`TrustPolicyDocument`/`RoleTrustVersion`读取、静态校验及唯一`CanonicalizeTrustPolicyDocument(document) (canonical,contentDigest,error)`。规范化只排序副本，保留空`[]`，拒绝空缺/null、未知字段、重复/大小写歧义、未实现载体、权限文档字段和超预算输入。R1沿此拥有者增加Role元数据、目录/详情/历史、输入输出校验和生成OpenAPI；使用原用例事务、PostgreSQL adapter及nethttp，不增加第二套编码器、PDP、会话存储或独立服务。数据库`role_contract_ready()`由迁移验证和实时readiness共用，核对当前公开函数形状、各类实际会话参数、完整ACL/proconfig、真实表归属/RLS、范围外键及不可变性保护；相同数字的schemaVersion不替代这些检查。

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

该纯规则基础片的精确Git候选在独立干净导出通过全仓`go test -race -p 2 -count=1 ./...`（含架构）、`go vet -p 2 ./...`、模块校验、API生成字节稳定及Linux amd64构建。Go2/768MiB，现有请求round-trip fuzz为15秒/2workers/1秒最小化预算，通过120526次执行。该固定片没有发行HTTP、ROLE业务身份或record8/contract3，也没有新增本地PG/浏览器/发行进程证据；不能把它代替下述R2工作区的真实运行门禁。固定6ae975d9a65569d5215fca26ef65a16722d2cd13的Verification35063652730首轮Go/节点成功，但authority-process超过旧10分钟job预算后取消，不能记为全绿；整体作业预算与再次精确源码验证归011。

### 当前管理门禁的独立测试范围

角色管理和私有会话引用矩阵分别使用独立、全新PostgreSQL数据库，不再嵌套消耗原账号HTTP和附件会话矩阵的剩余总时限。沿用同一integration文件、原业务断言和受限runtime，每个新增独立fixture有120秒总预算；角色竞争的锁等待、密码成本、48项附件交错与81项私有引用均未减少或放宽。每个fixture末尾保留双次schema重放、等值bootstrap receipt及实际Role状态不变检查。

2026-09-16，精确候选Git树`e496908ecea855d6300ad8e549774719f1d46b6a`的干净导出在独立PG18.4（1CPU/768MiB/PIDs128/64连接，Go2/512MiB、race/p1）通过原账号HTTP、附件会话及上述两项独立矩阵，合计263.159秒。同一干净导出随后通过全仓race/p2（含架构）、vet/p2、模块校验及Linux amd64构建。固定`d45402d91c89a5bb23f52fcfde65491435cd0f55`的[Verification35069879250](https://github.com/xiak/matrix/actions/runs/35069879250)已按精确SHA核实Go、authority-process、node-process全部completed/success。这只证明测试范围拆分后的当前R1及主体能力回归，不包含RoleBoundary/RoleSession。

### R2 当前累计本地证据

2026-09-16的真实门禁使用独立PG18.4（1CPU/768MiB/PIDs128/64连接），Go2/512MiB、race/p1串行；每项使用全新专属数据库。以下是当前R2的行为与证据，不将纯规则、身份投影或开发schema重放当作完整STS/发布验收。

- **发行和原意图**：HTTP/受限API登录/真实事务证明USER的Assume许可与Trust必须同时通过，缺少RoleBoundary拒绝；秘密目的隔离，首次唯一秘密、精确重放仅非敏感结果、输入变体和新来源Session/generation冲突。同意图并发只发行一次，来源USER第16个名额的竞争只允许一个成功；末尾outbox故障使发行、索引、决定和成功事实共同回滚。发行/管理/私有会话引用聚焦门禁59.744秒通过。16/128/1024是初始产品上限；这里没有声称128/1024规模容量已验收。
- **实际角色授权**：12.978秒真库门禁证明ROLE业务不继承来源USER写入或平台权限，8参记录器原子保存contract3、完整公开actor和私有来源证明；原决定、边界、会话、来源、代际、信任及编译内容的16类替换均拒绝。授权与安全聚焦门禁合计56.862秒另证实Role附件∩必需边界∩省略/Allow子集/显式Deny会话策略的实际交集，各来源Deny分别生效，SessionPolicy不能扩大资源前缀；身份条件使用Role ID而非来源USER。Allow和Deny都核对原存储证明。
- **撤权不复活**：同一56.862秒门禁包含12类HTTP ABA：来源/Role策略及边界默认切换、直接/组/Role附件撤销再关联、退组重入、User/Role边界解除再设、信任清空恢复及期限改回。旧会话保持未到期/未显式撤销仍永久失效；原意图只回原记录，明确新发行才重新获得业务Allow。schema重放不改原失效和已提交事实；纯显示元数据更新不使会话失效。
- **32项真实安全交错**：安全变更和ROLE业务各先行一次；本数据库最终outbox的有界屏障配合pg_blocking_pids确认实际后端锁等待。覆盖logout、改密省略/true/false、reset、停用后删除USER、原Root恢复、Account暂停、Role停用/删除/信任清空、来源/Role撤附件、移除Role边界、来源撤销和ROLE自退出。安全先提交则无ROLE决定/成功事实；业务先提交则保留精确Allow和单一事实。之后旧凭据拒绝，历史proof继续有效；每次仍受原5秒预算约束，不以并发发起顺序冒充锁序证据。
- **角色退出与到期**：79.202秒真库门禁包含实际60秒最短TTL，按数据库时钟等到期后当前身份拒绝、自退出成功，不回填行/改系统时钟。来源退出/改密/reset/停用/删除、Role停用/删除、来源撤权和Account暂停后仍只撤自己持有的发行。精确退出重放保留原时间，变体冲突；相同/不同退出意图及来源撤销竞争只提交一个终态。outbox失败不部分撤销，不改用户/登录/密码/Account/Role/附件；错误凭据、私有lookup、actor/target、伪业务决定及caller selector拒绝。
- **独立进程真实业务**：完整authority-process本轮87.896秒通过，包含两IAM实例、PaaS、Audit和dispatcher以及下述两项固定旧binary。ROLE实际创建/读取应用、配置与Operation；同会话精确重放、另一RoleSession相同幂等键冲突，资源仍属Account。tenant/角色会话过滤cursor隔离；ROLE不能调用USER管理、平台Audit或未声明的ManagedService。真实受限runtime登录、IAM失联关闭、两实例撤销一致及进程重启保持终态。Audit断线期间已提交的事实在来源撤权后继续投递、精确重放；另一完整角色引用/目标伪造拒绝，真实dispatcher提交唯一exited事实和完整链。
- **数据库/Audit边界**：本轮Audit双authority数据6.835秒、Audit HTTP3.714秒、PaaS数据4.662秒通过。Audit封闭catalog区分issued真实USER决定、source revoke无伪决定、exited精确ROLE+session目标；完整actor过滤不混会话。PaaS真实Operation/outbox行的回滚内形状攻击证明USER/ROLE合法结构通过，缺失/跨类型/私有字段拒绝；此合成攻击不冒充IAM权限证明。IAM/Audit/PaaS现有readiness检查实际函数ABI/ACL/search_path/security、表RLS/范围外键与不可变性漂移，非仅核对schema数字。
- **保留解释边界**：固定IAM21 `1dc1079c4e7bec80f5345d06929875b492ba9a86`真实binary聚焦23.893秒通过：旧端使用其真实注册Profile，新端保持自己的严格校验；迁移仅给旧决定新增NULL角色字段，旧SYSTEM默认、原字段/bytes、凭据、receipt、outbox与canonical保持。源码未来声明门禁只改新的当前声明，保留历史声明和冻结动作族/条件，不自动扩权。
- **旧编译不会获得ROLE**：固定R1 `d45402d91c89a5bb23f52fcfde65491435cd0f55`实际binary聚焦14.226秒通过：它真实生成并关联USER-only编译，当前schema不自动授予新Assume权限；同一旧版本对USER可用，对ROLE失败关闭，叠加新Allow也不能忽略不相容旧来源。原Root显式关联新管理权限、重编译业务策略并撤销旧ROLE附件后，新发行可访问，两个旧发行均失效。双迁移/重启保持旧Policy/default/compilation；没有手造legacy标记或恢复整条未发布schema1链。

contract3历史证明只核对原authority/actor/action/request及不可变发行证据，不签署或重建业务最终payload；payload真实性由来源事务/outbox保证。未来USER/Role/Account状态、会话过期或策略默认不能替代发生时证据；当前producer凭据仍必须有效。旧USER/SERVICE事件的canonical/hash不变。

USER recorder真库聚焦9.556秒及完整策略回归119.373秒通过：contract3的USER行必须没有ROLE私有字段，允许结果、内部决定和审计事实绑定同一身份；拒绝结果不公开用户/租户，内部仍保留精确归属。原请求/决定/Profile/资源/用途/关联字段的替换、缺失与旧调用ABI均拒绝，没有为新ROLE放宽原USER规则。

准确候选Git树 `71d240364ce3095e3218860cd5f35ee127617a83` 的干净导出通过全仓race/p2（含架构）、vet/p2、模块校验、API生成逐字节稳定与Linux amd64构建；外部真库由上述独立门禁证明，不把默认跳过的测试当成真实运行。固定源码另通过Assume请求及产品Profile canonical各15秒/2worker/1秒最小化预算的既有fuzz门禁。

累计实现 `0752c602ab4ce6d73a21094c8e9f75a1c8750183` 已推送，[Verification35096275242](https://github.com/xiak/matrix/actions/runs/35096275242)已通过GitHub API核实精确SHA，go、authority-process、node-process全部completed/success。此为R2后端运行闭环；UI、容量/HA和签名发布按各自owner继续，不改变发布profile，不把SQL解释保留门禁当成跨release-profile准入。

## 验收

- R1：两个真实Account可有同名Role；同名User/Role不混用。Root当前授权成功，普通用户/服务/platform-only/另一账号/过期或forced-change会话拒绝；读许可不能写或承担。真实同账号信任、Role策略附件、版本重放与并发更新/删除/撤权，所有失败无部分Role、信任、附件或成功事实。角色没有任何长期凭据或登录能力。
- R1：运行数据库验证Role/信任/附件的范围、不可变性、RLS、函数形状/ACL、失联与当前Profile漂移；原root/current authority、source registry、User/Group/Boundary、平台凭据保护、claim及旧canonical回归保持。产品Profile追加不自动放大旧策略默认/附件；原数据重放、重启后删除和撤权不复活。
- R1：旧SYSTEM默认下原Root的新Role动作在显式发布/关联TENANT策略前拒绝，原policy管理路径仍可达；非Root即使普通策略Allow仍被写保护拒绝。删除或停用User不改写旧Trust版本；新信任写入不接受已删除User。附件只接受真实同账号ROLE discriminator，不扩大原User/Group/Service或平台附件面。
- R1：新的私有会话参数与Role/USER/GROUP/平台USER附件共同通过当前身份、logout、change(true/false/forced)、reset/recover、停用/撤权的并发锁序门禁；旧9/6调用机械失败，新函数ACL/proconfig/readiness形状准确，所有失败不产生部分关系或成功事实。不得靠有界重试掩盖actor/target的反向锁序。
- R2：双边任一缺失拒绝；角色边界/SessionPolicy不能扩权；管理员承担只读Role后不能用原用户Allow写入。错误Role/Account/token/source/generation、会话过期/撤销、并发assume/revoke/delete/change/reset/logout失败关闭。反复停启、撤信任再恢复及原命令重放均不能复活旧RoleSession。
- R2/R3：真实独立IAM/PaaS/Audit临时会话业务路径、原始actor与不可变Audit关联；身份变化后原outbox继续投递但当前producer凭据仍须有效；进程重启/两IAM路由无关、数据失联失败关闭。真实UI显示当前角色、账号、原身份与到期；退出角色不创建或复活原登录会话。
- unit、架构/security、PG18、独立进程、UI及最终release/容量各按自己范围验收。没有外部环境的跨账号或IdP路径不以mock声称完成；也不把R1管理接口或后续纯规则通过当成R2/整套006已验收。
