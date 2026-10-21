# FEAT-IAM-010：IAM 控制台

- 状态：实施中；当前已接受的签名产品源码为`5935fa5005529b2c4e1da943b98f49300430ba10`，IAM87/Audit39/PaaS7、`contractRevision=37`。精确独立CI、同源签名A/B完整离线生命周期及重启后复验均已通过，发布证据归FEAT-005。页面仅采纳本文件各自固定版本的真实证据：User资料/状态、Group Membership、Account安全设置及Group附件恢复已覆盖相应路径，固定9621另证明Group删除和GROUP/USER附件撤销的可见回执与权限/Audit后验。附件CREATE的新回执、Role附件、日常改密及矩阵其余非Deferred路径仍须逐项实跑。当前签名通过不继承或补造新版本浏览器验收，整个FEAT仍为实施中。
- 依赖：各后端 FEAT 先通过对应真实路径；在现有控制面 UI owner 内增量替换。
- Owner：UX/UI 工程师统一负责 IAM 页面、客户端交互、样式与浏览器验收；IAM 工程师负责后端契约、服务端权限及真实进程支持。全局导航/视觉体系沿用控制台 FEAT-007，不平行实现另一套 UI。

## 需求

| ID | 可操作路径 |
| --- | --- |
| IAM-UI-01 | 平台开通账号/初始化主账号、列表/详情/暂停恢复，与租户页面明确区分 |
| IAM-UI-02 | 当前 Account/root/User/RoleSession 清晰；同名不同 realm 登录、强制改密/退出 |
| IAM-UI-03 | Users、Groups、Membership、附件和权限来源管理 |
| IAM-UI-04 | 系统/自定义策略、版本、JSON/可视化编辑、语法错误、边界 |
| IAM-UI-05 | Role/trust/AssumeRole、会话时长/原始身份/返回身份 |
| IAM-UI-06 | AccessKey 一次性展示、状态/删除/轮换、登录安全/TOTP/session 下线 |
| IAM-UI-07 | 正常成员看到允许的真实业务资源；拒绝和过期可恢复，不泄露其他账号 |
| IAM-UI-08 | 未交付 SSO/微信等显示明确未启用信息，不展示可成功提交的假表单 |
| IAM-UI-09 | 按当前身份与精确资源能力展示导航、页面和操作；产品发现、读取、写入及业务前置条件分离 |
| IAM-UI-10 | 无权限、功能不可用、临时读取故障、真正空目录与结果未知有不同的说明和恢复动作 |
| IAM-UI-11 | 个人安全入口不依赖全账号管理权限；仅有精确资源读取权时仍能通过已知目标进入 |
| IAM-UI-12 | 权限变化、切换身份和迟到响应不保留旧 Allow，不丢失既有原命令和完成回执 |

### 当前交付矩阵

| ID | 当前结论 | 仍需闭合或明确延期的边界 |
| --- | --- | --- |
| IAM-UI-01 | LIVE平台Account目录、Root初始化、受保护详情及停复用/恢复控件已接入；本地真实进程已证明三类命令的跨来源UNKNOWN恢复，固定IAM86+r36签名APISIX已证明Account开通和停用的完整页面组合，并证明原Root凭据恢复的单写响应半断、第二来源只读恢复、强制改密及权威状态/Audit边界 | 原Root凭据恢复的纯页面最终提交与UNKNOWN呈现仍须实跑；恢复启用的受控收尾不能冒充另一条UNKNOWN门禁 |
| IAM-UI-02 | realm登录、强制改密、退出及Account/Root/User/Role身份已接入；固定IAM86+r36签名页面由真实`admin`登录并读取当前Root/Account、准确权限来源和有效Session，且明确Session不等于设备；策略最终创建时遇到已过期Session会回到登录且不产生部分效果；后继独立真实浏览器已从普通User首次登录完成纯页面强制改密，并验证仅保留调用Session、撤销另一受限Session、旧密码失效和新密码重新登录 | 日常主动改密的可选会话处置、其他敏感写入的过期会话及权威异常恢复仍需组合门禁 |
| IAM-UI-03 | Users、Groups、Membership、附件和权限来源均为LIVE；IAM87+r37已通过前端/嵌入构建与独立CI。User资料/停用以原意图只读恢复，Membership添加/移除只显式等值重放原命令，Group附件CREATE/REVOKE已有响应丢失与下一请求权限效果。固定9621页面进一步证明Group删除的1+1级联及准确可见回执，以及GROUP/USER附件撤销的一次提交、一次原回执读取、零再写、明确完成导航与唯一outbox/Audit；User、Policy及不在级联范围内的资源保持 | 当前CREATE回执及直接Role附件仍缺页面证据；ROLE/REVOKE本轮只到最终确认，未提交且已收尾，不计通过。日常关系隔离不能替代这些写路径；批量User不在本轮需求 |
| IAM-UI-04 | 系统/自定义策略、版本、JSON/可视化编辑和边界客户端已接入；固定IAM86+r36签名页面读取八项系统Policy及`AuditReader`默认版本、摘要、冻结产品声明、结构化statement和原始JSON，从纯页面创建一个未关联身份的自定义策略并读取首个默认版本，另在零附件测试策略上从页面发布第二个不可变版本；缺少statement的文档在页面审阅阶段失败且未产生Policy/Version。后继候选UI已在同一r36后端从页面创建零附件Policy、改名并整策略退役，稳定ID/默认版本/摘要及不可变版本保持，活动目录移除且三条outbox/Audit事实和完整租户链均已核对；独立真实浏览器门禁进一步证明改名与整策略退役各自在响应半断后的双标签排他、关闭持锁标签和完全相同原命令恢复 | 默认版本的纯页面最终切换、边界、其余语法/语义错误、冲突、附件授权和结果恢复仍需完整浏览器门禁；AuthorizationProfile不得伪装成租户策略；当前签名组合已通过，但不能替代所列纯页面写路径 |
| IAM-UI-05 | Role/trust/AssumeRole、原始身份/当前身份和返回入口已接入并已有真实承担/退出证据；固定IAM86+r36签名页面按权威空目录显示零Role。当前后端与真实PG已证明Role附件变化使原RoleSession失效，显式新承担才按新授权求值，历史发行记录不被改写。后继候选选择性采用UX固定c5f858d、3ddbd991及ad8cd9c，在原身份owner中处理业务/Audit的401并保护跨Session恢复原意图；七文件282项本地回归通过，消费者固定e1a96db的19项CI全部成功，Issue #4已按精确消费者证据关闭 | 业务/Audit的401及跨Session意图保护修正已进入当前5935签名源码，同源签名生命周期已通过；管理员撤销、Role凭据精确业务读取和显式返回来源身份的真实页面门禁仍未完成。跨Account、角色链、服务/外部身份trust明确Deferred |
| IAM-UI-06 | AccessKey、可信联系人、TOTP、恢复码和本人Session均为LIVE；IAM86+r36签名页面读取已验证通知地址、本人TOTP状态和有效Session，并对缺少读取权限显示真实拒绝。固定`a119ffdb`的独立真实浏览器已证明普通User首次绑定、换绑、主动移除、重新绑定、四次MFA登录及跨浏览器撤销其他Session，准确因子/恢复码代次和Audit证据由[本人安全与会话](#live-本人安全与会话浏览器闭环)拥有；这不是强制MFA或签名APISIX页面验收。后继最小权限普通User已完成Account安全设置的真实TOTP step-up、完整版本替换、旧Session围栏和重新登录后权威读取 | 账号强制MFA下普通User首次绑定及受限重新绑定、AccessKey全生命周期、恢复码再生/自助恢复及其他敏感用途step-up仍缺完整浏览器门禁；已接受的普通TOTP路径仍缺当前签名APISIX页面组合证据。受保护Root/平台身份丢失全部因子后的目的限定恢复与强制重新绑定、外部物理认证器及WebAuthn明确Deferred |
| IAM-UI-07 | 四个真实产品、协议、授权/撤权、错误矩阵和五类命令恢复已有分层证据；固定IAM86+r36签名页面又以`offline.alpha.primary`从真实RabbitMQ配额创建`iam-r36-terminate-test`并观察QUEUED→INSTALLING→RUNNING和AMQP端点，同一签名运行时已证明终止单写响应丢失、跨来源结果恢复、物理清理与配额归还 | 终止的纯页面最终提交与UNKNOWN呈现仍须实跑；不支持跨主体恢复，查无结果不得推断原写未发生 |
| IAM-UI-08 | 固定IAM86+r36签名入口再次证明角色SSO、用户SSO和跨账号协作直达路由只有明确“尚未接入后端”EmptyState且没有提交控件 | 企业微信/外部IdP、Passkey/WebAuthn、跨账号与角色链保持禁用和Deferred；新增Deferred入口仍须沿同一边界验收 |

## 详细设计

复用当前组件和客户端契约生成。页面可见性是上下文绑定的保守提示，服务端每个请求仍真实鉴权。删除全局 roles → allowActions 的本地权威判断，以 resource/profile/version 绑定的能力或实际请求响应驱动。

编辑保留输入但在版本冲突时明确刷新，不静默选另一个账号、角色或资源。敏感创建流程说明一次性材料，普通提示和错误不持久存储秘密。角色会话的 Account/有效身份/原始身份显示分开。

### 权限感知控制台架构

本增量的最小目标是：当前普通成员、只读管理员及精确资源操作者看到可用而准确的控制台；没有权限不会被表现为系统故障，未知状态不会被表现为拒绝或空目录。沿既有 IAM 权威、客户端 provider/scene/renderer 与 `@ui/xiak` 交付，不新增菜单权限、前端 PDP、通用 permission endpoint、审批系统或第二套控制台。

参考原则来自 [Tencent CAM 概览](https://cloud.tencent.com/document/product/598/17848)的模块级展示、[Google Console 权限查询](https://docs.cloud.google.com/iam/docs/testing-permissions)的当前主体/具体资源判断，以及 [Cloudscape 禁用与只读](https://cloudscape.design/patterns/general/disabled-and-read-only-states/)的状态区分；这些是设计依据，不是本产品运行证据，也不要求复制云厂商的角色名或整套产品。

[Google Cloud 权限申请](https://docs.cloud.google.com/iam/docs/request-missing-permissions)在拒绝信息中提供申请入口：已配置联系人及通知时可发送请求，否则复制请求交给已有受理渠道；[Microsoft Entra](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-request-access)则以管理员预先发布的访问包和相应申请规则承接请求。它们证明“拒绝后给出可执行的求助路径”，不代表任意403都能申请或自动获权。本片不新增审批系统；未接入真实受理渠道时明确联系管理员并提供安全诊断。

```text
当前有效 Session / repository owner
    └─ IAM 当前权威快照 + 单一 PDP
         ├─ CurrentIdentity.capabilities：固定且有界的入口/账号动作
         └─ 已授权具体资源读取：该资源当前 ActionCapability
                  ↓ 严格解析、准确 Account/actor/resource、丢弃迟到响应
控制台 provider → scene → 现有导航/页面/组件
                  ↓ 用户显式发起真实请求
产品/IAM 用例重新鉴权 + 状态校验 + 原子事务/既有审计
```

三个轴必须分开：

| 轴 | 真值与消费者 | 禁止推断 |
| --- | --- | --- |
| 功能及产品可用性 | 客户端是否有已接入适配器；真正的服务开通/委派状态由现有产品接口提供 | `supportsLive*` 不是当前用户权限，也不证明后端健康；404/未知路由不等于产品未开通 |
| 当前操作能力 | IAM 对准确 action/resource 的 `available` 与封闭 `restrictionReason`；服务端仍是最终权威 | 读允许不推出写允许，SELF 不推出 AccessKey 权限，角色名不推出菜单；能力不是可缓存的操作许可 |
| 当前读取结果 | loading、ready、成功且为空、forbidden、unsupported、unavailable；凭据失效仍归现有身份 owner | 权限查询失败不是 DENY，目录失败不是零行，旧成功结果不是当前授权；UNKNOWN 写入不是可重新提交的读取错误 |

导航保留产品发现与本人入口。账号级管理菜单只消费准确入口能力；已知精确目标的详情读取不得依赖目录可见性，目录拒绝也不能证明该类型所有实例都不可读。AccessKey 的本人入口查询准确当前 USER；其他 USER 从已授权目录或已知目标进入，不能要求全局 User.list、扫描所有用户来推断权限，或把本人拒绝放大为对所有用户的拒绝。已知User的“查看密钥”只是读取入口：选择后调用实际目标的Key目录，分别处理loading、403和成功；User.read不证明Key.list。创建能力继续由成功的 `AccessKeyList.capabilities` 唯一提供，每把Key的操作由其 `AccessKeyAccess` 提供；不在 `UserAccess` 复制Key能力。安全报告的生成是 ACCOUNT 动作，读取/下载是准确 SECURITY_REPORT 动作；分析器的创建/列表是 ACCOUNT 动作，读取/更新是准确 ACCESS_ANALYZER 动作，不能伪造一个 account-global read 能力。服务角色模板目录和当前账号关系目录分别授权，任何一块可用时保留该块，不以 AND 依赖整页关闭。

CurrentIdentity 的固定入口集合沿既有十项增加九项，最终共十九项：当前 USER 的 `iam.access-key.list`；当前 ACCOUNT 的 `iam.access-analyzer.list/create`、`iam.security-report.create`、`iam.service-role-template.list`、`iam.service-linked-role.list`、`iam.security-settings.read/update`、`iam.policy.create`（斜线表示两个既有独立动作）。wire 名称与现有 action catalog 完全一致，不能为 UI 添加业务权限。服务端与客户端同时严格校验完整集合、重复项、目标归属和拒绝原因；缺失字段或非法响应使投影不可用，不填充 false 或 Allow。新集合只进行有界纯 PDP 求值，复用一次已认证权威快照，不逐菜单调用接口、不读取业务资源、不生成新的授权决定或成功审计事实。

具体资源上的写操作由现有资源读取 owner 提供独立准确能力；缺少能力时不得从 read 成功、系统策略名、资源状态或“创建过该对象”猜测。Analyzer、Finding、SecurityReport 的精确能力投影与持久业务对象、不可变报告正文/digest 和原完成回执分离；不将短暂 UI 权限写入历史快照、数据库或 Audit canonical。没有真实目标 ID 时不构造任意或通配目标来试探。

P2 的只读响应边界沿现有 GET 详情扩展：`AccessAnalyzerDetail` 包含 analyzer 与固定的 update、set-disposition、access-finding.list 能力；`AccessFindingDetail` 包含 finding 与 archive/unarchive 能力；`AccountSecurityReportDetail` 包含 report 与 download 能力。每项使用内层真实对象 ID，仍先执行该详情原有 read 授权。列表、持久对象、所有变更响应和原完成回执保持原业务事实；只在选中对象后读取对应详情，不逐行请求能力。详情成功不授予其关联目标的修复权限，归档也不等于处置底层资源。业务状态、资源版本及发布内容检查继续独立执行，能力只是不绕过这些条件的当前权限提示。

策略页面同样不能从已接入客户端方法推断发布或编辑权。当前 ACCOUNT 的 `iam.policy.create` 保留现有受限发布的主体前置条件；已授权 POLICY 的 GET 返回 `PolicyAccess {apiVersion,kind,detail,capabilities}`，提供更新、删除、版本列表/读取/创建/删除及默认版本切换的七项准确能力。版本操作的授权目标仍是 POLICY，不发明 POLICY_VERSION 权限。系统策略、非本账号对象、不可变版本和委派发布约束继续适用；普通委派主体须有当前有效权限上限且无活动安装级附件，不能编辑自己的上限策略。正向授权仍独立必需；实际发布内容、目标被引用状态及并发修订由原写事务重新检查，当前能力不保证这些业务条件全部满足。不扩张现有业务授权，不将动态能力写入 PolicyDetail 原完成事实或版本正文。User/Group/Role/AccessKey 已有的具体能力继续复用。客户端只接受最终十九项和四类完整详情，不保留十项或十八项兼容路径；后端候选不能单独作为可发布控制台。

主视图和标签保持稳定标题，加载仅作用于数据区域；每个失败区域最多一个主状态和一个适用恢复动作。403 提供返回、已知安全上下文、授权后显式重新检查，不持续自动 Retry；临时故障提供唯一读取 Retry；unsupported 明确功能当前不可用，不宣称未开通。只有权威开通或委派结果才能显示对应引导。真正空目录才使用空状态和准确创建能力。当前有效 bearer 的401交给已有Session/RoleSession owner；密码/OTP错误不自行触发全局退出。隐藏入口不替代直接URL的友好拒绝，拒绝页不得泄露未经授权的目标名称、其他账号数据或确认对象存在。

404 不能仅按状态码全部归为功能未接入。现有 `iam.route.notfound` 与 `iam.access-analyzer.not-found`、`iam.access-finding.not-found`、`iam.security-report.not-found` 等封闭错误码已区分路由与目标：明确路由缺失才显示功能不可用；具体目标404只说明当前目标不可用，请核对标识或访问范围，不确认其存在、已删除或未开通，也不据此重发原UNKNOWN命令。前端不得读取任意错误detail来推断原因。

诊断复用现有 Problem 的稳定 code、status 和经过语法/长度校验的 requestId，以及客户端已经拥有的当前身份、当前账号与实际请求 action/resource；不展示任意 detail、原始响应、Bearer、Secret、OTP、cursor 或策略正文。没有真实权限申请渠道时只提供联系管理员和复制诊断，不生成假审批。正常 LIVE 页面移除“未回退 MOCK”等工程验收文案；显式预览标识、一次性秘密提示、危险操作说明及 UNKNOWN 结果警告继续保留。

授权或身份变化后重新读取能力；不同 Account、User、RoleSession、Session 修订及 repository 之间不得共享旧结果。能力未知时禁用写入并显示正在确认/读取失败，不先显示可操作再闪退。既有非秘密原意图、UNKNOWN 围栏和完成回执独立保留；菜单改变、401/403、详情失败及重新登录不能清掉它们，更不能把“重新检查”实现成重放写请求。已完成操作的回执不因为后续资源读取失败而改写为失败。

显式权限重查也覆盖正在展示的精确资源：即使十九项入口能力逐项不变，资源的更新或下载权仍可能已撤销，不能仅比较入口布尔值而保留旧详情能力。重查待完成期间关闭新写入，成功后重新读取当前目标的准确能力；旧读取迟到不得覆盖新结果。该失效边界只属于显式权限重查或身份变化，不把无关目录的分页/重试升级为全局重置，不丢失原命令和已完成回执。

Finding的已知目标读取使用现有analyzerId与findingId二元路径，不要求Analyzer目录、父Analyzer详情或Finding目录权限；仍由准确Finding read及返回的archive/unarchive能力决定可读可操作范围。原UNKNOWN命令的后续等值请求即使收到403/409，也不能据此判定首次未生效或清除原requestId；首次确定拒绝与未知后的拒绝须区分，不能恢复为可提交全新意图的状态。

### 权限感知增量需求与切片

P0–P2 已选择性接入 UX/UI 固定源码，后端投影及最终十九项客户端完成下述本地检查；P3 的权限感知与受影响退役恢复真实页面均已通过。固定9062的独立CI已完成精确SHA、十九项job及全部必需日志核对并封存；本权限感知增量接受，不扩张为整个010、IAM-UI-01–08其余页面或新签名发布完成。本表不重开或扩大此前已接受页面路径。

| 切片 | 需求和实现 owner | 必须通过的结果 |
| --- | --- | --- |
| UX-P0 语义状态 | IAM-UI-10；UX/UI 在现有 HTTP、读取边界、Analysis/AccessKey/服务授权 renderer 和消息 owner 替换重复实现 | 403 不再显示临时故障或双 Retry；局部失败不遮蔽可用内容；安全 requestId 可复制，恶意/缺失值不透传；空数据、未知路由、503、过期严格区分 |
| UX-P1 入口投影 | IAM-UI-09/11；IAM 用例/API/生成 owner 提供固定能力，UX/UI 严格解析并接入现有导航 | 普通User、只读委派、显式Deny、边界限制和受保护Root结果准确；本人Key无需User目录；模板和关系可局部访问；不能凭Read推断Write |
| UX-P2 精确操作与身份刷新 | IAM-UI-09/11/12；各既有资源读取及对应UI owner | 已知ID不依赖目录；Analyzer/Finding/Report准确能力不污染持久对象和历史digest；撤权后新请求拒绝；切换身份丢弃迟到响应，UNKNOWN原意图与完成回执保持 |
| UX-P3 组合验收 | 测试负责人复用既有 unit/contract、HTTP/PG、authorityprocess 与浏览器 owner | 最小权限普通用户、只读/可写、服务局部授权、直接URL、授权/撤权、503和真实空态逐条闭合；记录固定SHA/精确CI与可见页面证据，清理不再使用的自有临时资源 |

P1 固定 `3826eaf4b5628945dd210419fb96f743a5e13da1` 的十八项入口前置通过[独立 Verification39364150243](https://github.com/xiak/matrix/actions/runs/39364150243) attempt1，当前终态为 `completed/success`。现有 `service_test.go` 逐项证明无授权拒绝、准确 Allow、显式 Deny、边界限制、强制改密、他人目标不扩权、Root 密钥保护以及投影不持久化额外决定。API/usecase/authority/HTTP/architecture 本地测试及相关 vet 已通过。既有 `TestIAMAccessKeyPostgres` 在专属受限 PostgreSQL18 上真实通过 83.86s，其中新增跨副本入口矩阵 1.28s：SELF 无 Allow 拒绝，只有他人目标时本人入口仍拒绝，模板读取不授予关系目录读取，本人仅 list 能读取真实空目录而没有 create/User.list，撤权后另一副本的 me 与实际请求同时关闭。该证据只覆盖前置后端候选；最终客户端必须一次性消费十九项，不能继承未执行的新组合浏览器验收，也不能单独发布十八项后端。

P2 固定 `12f706780a1400068e85cb9481e111d566c5ba31` 在原 API/OpenAPI、用例和 GET owner 完成最终十九项以及四类具体资源投影；完整数组、重复/替换动作、错误目标类别和矛盾拒绝原因均由 Go 与发布 schema 检查，跨字段真实 ID 绑定仍由严格运行时校验负责。Policy 创建/管理能力另证明正向 Allow、委派权限上限和安装身份保护互相独立；策略正文、报告 canonical/digest/CSV 与原变更回执不含当前 UI 权限。相关 API/usecase/HTTP/architecture、全仓编译、vet 和聚焦 race 均通过；数据库/readiness/发布 profile 未变。[Verification39367958497](https://github.com/xiak/matrix/actions/runs/39367958497) attempt1 已独立封存为 `completed/success`：精确SHA、十九项job、十四lane的57个实际根及33个JSON包均通过，1164个Test的JSON/plain终态一致。该固定源码的前端仍为77文件1999项，不混入后继本地2010项；Postfix缺失的七个邮件子例与默认关闭的十四个浏览器根不计真实运行。不得用本片CI代替最终十九项客户端、组合浏览器或5935之后的新签名验收。

专属 PostgreSQL18 的完整 `TestIAMSecurityReportPostgres` 通过7.90s，新增精确读取路径0.25s：仅 read 可读取已知报告但没有生成或下载能力，精确 download 授予/撤销改变当前能力而正文逐字不变，实际下载及跨报告请求继续拒绝。`TestIAMPolicyAuthorityStoragePostgres` 的发布、元数据更新和终态删除三条受影响流程在新库定向通过56.49s，证明已知 Policy ID 的读取不依赖目录、read 不授予版本/修改权、撤权即时生效及既有并发/回滚边界。首轮全量探针中两个旧 GET 测试消费者未适配新包装而失败；修复后上述定向复验通过，不将首轮记为全量成功。该证据不是新 UI、完整 P2 独立 CI 或签名发布组合的验收。

`TestIAMAccessAnalyzerPostgres` 使用同一专属 PostgreSQL18、Windows 真实后台 worker 和任务专属 SSH 转发；新增精确 Analyzer/Finding 读取子用例通过21.73s，证明没有目录权限仍能读取准确对象，读取不授予更新/归档或底层目标操作，撤权后的下一请求关闭且持久 finding 不变。但父门禁在末尾持久状态核对触及原有三分钟期限，180.02s失败，不能登记为整项通过。未提高期限、缩减原断言或将其当作已定位的生产缺陷。固定12f的[原生Ubuntu门禁](https://github.com/xiak/matrix/actions/runs/39367958497/job/118451321647)另有独立完整证据：Policy全根367.22s及194个子例均通过；Analyzer全根55.33s、精确读取子例1.80s通过；Report全根11.05s、精确读取子例0.58s通过。JSON/plain已逐项核对，不回填Windows探针或旧消费者首轮结果。后台进程和任务专属连接必须先结束，再清理不再使用的临时数据库、容器及转发。

最终消费源码为已推送的`9062f83bc114c1f79e829fb2018e0b94f6bd651b`，父提交为已接受的后端P2。完整固定来源及`ADAPT/REFERENCE/REJECT`边界由[既有adoption owner](../docs/adoption/FEAT-007-control-plane-console.md)拥有。保留本分支测试差异，删除被替换的目录失败组件，不保留十/十八项或裸详情兼容实现；生成资产只从本分支完整源码重建。该片不修改API、SQL/readiness、安装或发布profile，不继承donor验收或当前签名产品的发布状态。

Policy新写必须通过当前精确能力、目标版本及对应版本目录检查；重查期间保留草稿但暂停派发，取得异步Web Lock后再次检查当前围栏。原UNKNOWN恢复独立于新写：已提交退役使既有ACTIVE-only详情不可读，不应因此堵住严格原请求的恢复。重核完成且当前Session/actor owner有效后，只能显式等值重试原requestId、目标、版本及内容承诺，仍由既有后端执行当前授权及原结果判定；不新增回执API，不以当前状态读取冒充完成证明。版本的只读观察不要求写能力。必要修正为`a453890e9`和`dae784524`，不能单独采用会堵住退役恢复的`a13e336f7`。

| 验收边界 | 本分支实际证据 | 结论限制 |
| --- | --- | --- |
| 聚焦源码 | 四文件353项221.39s；最终异步锁hook32项5.45s；typecheck/full lint、architecture及234组主题对比通过 | 历史中间候选的测试数量不累加为当前覆盖 |
| 构建与嵌入 | Node22.22.2/2GiB、两worker生产unset/0各生成59页，324文件逐字一致；8项Node边界通过3.58s；嵌入同步核对通过 | 不导入donor资产，不等于重新验收签名发布 |
| Go消费者与夹具 | 最终嵌入Go UI race13.945s；architecture race3.348s；完整无数据库authorityprocess race3.998s及vet通过；监听/探针/relay三根race3.750s通过 | 默认跳过的外部数据库/browser根不计真实运行 |
| 独立CI | [Verification39559359986](https://github.com/xiak/matrix/actions/runs/39559359986) attempt1绑定准确9062，十九项job及全部必需日志已独立核对封存；前端2057 Vitest、8 Node及双导出/嵌入324一致 | 逐根证据及默认跳过边界归[011](FEAT-IAM-011-acceptance.md#当前独立ci)，不继承5935的签名发布验收 |
| 权限感知真实页面 | 同一9062源码的`TestIAMPermissionAwareConsoleBrowser`376.61s、race包380.128s通过，UX/UI owner完成下述可见观察 | 不以marker、API准备或组件测试代替页面；不是额外Finding worker正向或签名APISIX验收 |
| 受影响退役恢复页面 | 同一9062源码的`TestIAMPolicyMutationRecoveryConsoleBrowser` RETIRE模式719.44s、race包722.991s通过 | 只接受下述准确原意图恢复；不代替默认版本、其他Policy动作或签名APISIX门禁 |

真实页面使用本机专属PostgreSQL18.6（2CPU/1GiB/Pids128）、真实受限IAM/Audit/PaaS、双dispatcher和嵌入控制台；Go并发与内存沿既有限额。仅两个准确GET注入各一次503，成功数据、身份和授权均来自实际服务，不注入Bearer、成功payload或导航脚本。

| 阶段 | 可见页面与真实后验 |
| --- | --- |
| 初始最小权限 | 独立Policy深链接读取准确策略/默认版本/摘要后关闭；Analysis主会话读取已知Analyzer90天、ACTIVE、REVIEW_ONLY，写控件禁用。Finding目录403只影响该区域；缺失Analyzer和已知双ID Finding显示不确认对象存在的404。本人Key首次503、唯一读取重试后真实空且不可创建；模板目录可读、关系目录不可读；已知Report只读且不可下载。无需User/Policy/Analyzer目录权限 |
| 同会话授权 | 恰好两次初始登录后，只走应用内可见导航/原SPA history。显式Recheck后me、Analyzer、Report和LinkedRoles200；页面仅一次把窗口90改14，保持ACTIVE/REVIEW_ONLY。POST成功后的首个GET503不覆盖“已更新”，唯一Retry只读得到revision2/14天 |
| 精确写权撤销 | 独立撤销Analyzer写附件，十九项入口能力逐项不变。停留原页面Recheck，准确详情重新读取，revision2/14天保留，更新/处置/保存禁用；下一实际更新请求403，无额外页面写入 |
| 最终撤权 | 仍使用原Analysis Session重核；本人Key入口消失，已知Report显示当前会话无权。未退出、未重新登录，未用另一既有Session代替 |
| 其他准确User | 完成原会话撤权观察后，才第三次独立深链接登录：已授权他人Key目录真实空且不可创建，侧栏仍无本人Key/User目录入口。此登录不是权限刷新证据 |

relay只保存封闭路径/状态/阶段计数，并用不输出、不持久化的内存摘要证明整个授权/撤权仍来自原Analysis Session；不保存认证输入、Bearer或回包正文。五个marker严格在观察后创建；后端另证唯一Analyzer版本推进和成功outbox/Audit、准确附件终态、其余资源与不可变Report不变、原Session有效及完整Account链。各阶段浏览器console warn/error为零。已知不存在Finding的测试只证明精确路径可达与目标404负向边界，不伪造Finding或声称分析worker的新正向验收。

受影响退役恢复复验另用全新数据库及两个同源标签页。二者先正常登录并读取准确测试Policy的ACTIVE/revision1及零消费者；A从页面只提交一次整策略退役，后端成功但代理保持半段回包，A进入UNKNOWN并持续持有Web Lock。B尝试同一原命令只显示忙态，没有排队或额外写。关闭A后，B明确读取当前目标得到403，页面仍保留原requestId、目标、版本和UNKNOWN恢复区；只有再显式点击等值重试才返回活动目录，目录恰有八项系统Policy且无测试目标。原request为`ui-policy-metadata-a4509209836cd0af673766519cf59823`。浏览器console warn/error为零；只在这些可见观察后创建完成marker。后端证明总共只有初始提交和一次byte-identical replay、Policy仅推进一次、不可变版本保持、唯一outbox成功事实及完整租户Audit链准确。这直接验证ACTIVE-only详情不可读不会阻断原已提交意图恢复；不把403当作原请求未生效或重新创建请求的理由。

失败观察保留原结果：Windows经SSH访问远端PG的首探74.94s停于PaaS安装验证HTTP期限；原生Linux首轮630.09s因夹具错误要求所有深链接共享一次登录而主动停止，第二轮370.00s暴露探针错误使用`/auth/session`而非真实`/auth/login`；工作中断的一轮1800.03s超时。9062本机首轮因浏览器整页跳转丢失内存Session，零写/零marker，主动终止于438.16s；随后从全新数据库完整重跑才得到上述376.61s通过。未放宽产品鉴权或HTTP期限，后继成功不回填旧失败。

清理仅限本任务对象：旧超时运行的两只容器和空网络已按准确身份删除，可重建传输包约71MiB及依赖副本约15MiB已清理。上述本机复验结束后，子进程退出、临时目录由夹具回收，PG外部客户端为零；按准确ID与任务标签正常停止并删除唯一PG容器，其tmpfs中的三份合成数据库一并清除，没有遗留持久卷或新增网络。结果日志保留；没有重启远端机器、共享Docker或其他任务服务。

### 有效凭据失效与角色返回

产品资源、服务开通状态及Audit查询/完整性校验的受保护请求返回401时，必须使发起请求且仍为当前所有者的有效凭据失效；不能只展示局部“会话过期”却继续使用该凭据。复用现有Session与RoleSession上下文，不另建身份状态机。Role凭据失效进入`role-expired`并阻断业务请求，来源User保持独立；禁止自动重新承担角色或静默退回来源User。用户明确返回后仍须重新验证来源User，不能因持有旧来源凭据而推定其有效。

请求所有者同时包含其有效凭据、来源User凭据、当前Session修订/Role身份及repository边界，并通过Session owner的稳定谓词核对当前来源。组件局部ref不能独自证明请求仍有效：身份变化重挂子树后，旧Promise仍持有已卸载组件的旧ref。成功、失败及收尾都必须先核对实际来源和有效身份；旧请求迟到的401或成功回包不得使后来身份退出、删除其持久化待核对原意图或覆盖新页面状态。403表示当前身份没有业务权限，不等于凭据失效；显式重新承担后得到的403也不能被解释成旧RoleSession重新可用。返回来源User或新承担不能重放先前的业务写入。

该处理只适用于证明请求Bearer无效的认证失败；当前密码、TOTP、恢复码或用途限定step-up校验失败的401，不足以证明Bearer已撤销，仍由各自认证流程处理。验收沿现有真实消费者测试，覆盖当前Role的401、旧请求迟到401、403不升级为退出、显式返回及来源验证失败；组件测试不替代管理员撤权后的真实Role业务页面与权威后验。

本分支选择性采用UX固定`c5f858d64ddb7ea4355fec794d950401e85edb1d`及必要后继`3ddbd9911eb144f36eeecb4bbf8596df286b8ed9`的九个既有源码/测试/消息路径，保留本分支renderer原交互，不导入对方生成物或验收状态。消费者复核先在c5上证明两条真实组件回归：同Bearer替换repository后，旧请求迟到401错误退出当前User；USER模式保留的旧失效回调在Role生效后错误清除来源User。前者在固定父实现通过，两条原样回归在3dd修复后均通过。当前请求必须同时匹配repository、Session修订及actor owner；共享失效回调读取提交后的当前USER/ROLE归属，而非调用闭包捕获的旧模式。

本分支本地Node22.22.2、2GiB heap、单worker的七文件282项相关回归以64.72秒通过，覆盖Role/Session、ControlPlane、Audit、服务开通及专用TOTP路径。类型/lint/架构、234组样式对比度及八项静态导出Node测试通过；2-worker生产构建的preview unset/0两种模式逐字等价，324项嵌入资产由本分支重新生成并匹配。Go UI/architecture/authorityprocess默认race分别7.303/2.398/3.941秒及相关vet通过，未开启的外部数据库/浏览器门禁不计真实运行。命令与后续资源读取保持分离：当前401使身份失效且不重放已完成命令；403/503/协议错误保留各自拒绝或不可用语义。未改变后端API/SQL/完整Profile。此证据不等于后继候选精确CI、签名发布或真实Role撤权页面已验收。

固定消费提交`5384e4421877069f9ad4bc4e47ca219d46be9798`后的消费者复核发现[Issue #4](https://github.com/xiak/matrix/issues/4)：旧创建请求挂起、同User重新登录并恢复UNKNOWN后，旧401或成功回包仍清除新Session保留的非秘密原意图；当前身份和内存UNKNOWN未丢失不代表持久恢复边界安全。本分支仅选择性消费UX固定`ad8cd9c3cd846d8556d0c3974826ff49bc4fc32d`的两个生产文件，父blob均与本分支一致，保留两条原始消费者断言和本地测试布局。两条回归在修改前1.94秒确定失败，修改后1.81秒原样通过，同时证明原requestId/UNKNOWN/持久化记录保持且没有第二次创建调用。未引入新Session模型或持久凭据。

修复固定为`e1a96db06142f62508a26870edd8ce36cdc32780`，精确[Verification 39258833606](https://github.com/xiak/matrix/actions/runs/39258833606) attempt 1于2026-10-19 13:48:00 UTC完成，19项job全部成功。独立消费者复核核对了两个采用生产路径及其父blob、保留的正常`it.each([401, success])`和无筛选Vitest入口；本轮目标文件48/48、完整77文件1973/1973及八项Node测试实际通过。默认日志只给文件级事件，不编造两条参数化用例的独立CI耗时。Issue #4于13:52:57 UTC按该精确固定缺陷证据关闭；完整CI日志/根用例审计仍由011拥有，关闭该问题不接受尚未运行的真实Role页面或新签名发布。

真实Role页面沿现有附件fixture的ROLE/REVOKE组合验收，不新增测试账号模型或第二套框架。两个标签各持独立的内存Session：普通User从`/console/access/role-access/`显式发现、审阅并承担只信任自己的Role，在`/console/applications/`通过Role读取真实PaaS目录；管理员在精确Role详情内联撤销原附件，响应丢失后只读核对原requestId的不可变回执。普通User标签再读同一业务资源必须得到401并进入全局BLOCKED，不得静默用来源User重试；点击“验证并返回用户模式”后由IAM重新验证来源，成功后才返回USER，业务读取应呈现真实403且不确认其他资源存在。角色、主体、附件与原请求都必须对应同一fixture；完成上述可见状态后才能创建已有结束标记。标记后的旧Role401、原发行记录、新显式承担和唯一Audit属于后台后验，不能替代页面动作。UX/UI固定源码走查确认这些路由和操作已具备，MOCK交互及源码检查本身仍不算真实验收。

准备该门禁时发现原浏览器relay缺少`/api/paas/`，应用请求会错误落到UI上游。固定`176097677b5f73b63f3d47c7b4f218585feb050a`在原`authorityprocess` owner提取既有路由装配并补齐该前缀，保留IAM/Audit/managed-services/UI原映射；短回归先证明PaaS路径错误返回UI的200，再证明准确上游、方法、cursor原字节、原Bearer及401/403响应保持且无注入tenant selector，相关response-loss race门禁3.749秒及vet通过。该测试使用loopback测试上游，只验证fixture转发，不冒充真实PaaS权限或浏览器已通过；没有改变生产APISIX、API或安装契约。

本轮在同一个ROLE/REVOKE入口补充浏览器专属观察：只有经过实际页面relay的一次明确承担、准确Account/User/Role的发行结果、该Role凭据的业务200、管理员撤权后原Role401、同一来源User的重新验证及业务403才满足后验。独立API准备/前后承担仍可证明后端资格，但不能通过这个观察器；无页面承担、替换来源/角色凭据、未经来源验证的业务回退或再自动承担均拒绝。只保存有界计数及不输出的内存凭据摘要，一次性发行响应有界观察后清除临时字节，不存正文或Bearer。观察器不注入身份、不改变成功payload，也不代替UX对BLOCKED与明确返回按钮的可见检查。

### 当前身份的权限上限投影

现有 `/console/access` 客户端严格消费 `CurrentIdentity.permissionBoundary`，匹配当前 Account、User 和 User resourceVersion；缺失字段、错误归属/修订或非法版本摘要直接使当前身份读取失败，不能降级为无边界。原 Account Root 仅允许明确无边界。页面独立展示“租户权限上限”及精确 Policy/默认版本 ID，不把它加入正向附件或从名称推导权限。

无边界不等于拥有权限，有边界不等于获得授权；目录和按钮继续消费服务端逐资源 capability/实际响应，不在浏览器实现策略求值。无 Policy 读取权限时仍可展示自身的版本引用，但不能因此读取正文或另一个账号的内容。刷新重新读取当前状态；失败清除该投影，不以旧的 null 或引用当作当前事实。User 边界设置/替换/移除由下节管理交互拥有；策略编辑和 Role 页面的当前实现与缺口以交付矩阵为准，当前身份展示不替代它们的真实浏览器验收。

### User 边界管理交互

沿现有 User 详情和后端三条 permission-boundary 路由增量接入，不创建顶层边界目录或全局管理许可。UserAccess 的能力集合增加精确 USER 的 set/remove：由当前 PDP 与同事务读取的原 Account Root 关系共同计算，普通管理员即使具有动作 Allow 仍提示不可写；主账号目标保护，停用普通 User 不隐式禁用边界管理。能力仅说明主体可尝试该动作，不承诺所选 Policy、修订或当前关系仍有效，实际写入继续完整锁内验证。

详情独立读取当前边界；未成功读取不显示“无边界”，当前 User 修订与边界修订不一致时先刷新，不把任一值覆盖到另一个请求。策略选择只取已授权可见的 ACTIVE/TENANT 目录，保留选中 Policy ID 与 resourceVersion；替换明确说明上限变化，移除明确说明其他正向授权可能重新生效，均需显式提交。停用/恢复、凭据和正向附件不能作为该表单的副作用。

同一次提交保留 requestId、目标和全部预期修订；网络/503/不确定回包不能自动生成另一意图重试。页面显示待核对状态，通过准确原请求重试或当前状态刷新处理，不以客户端显示判断服务端是否提交。401 清除敏感管理状态，403 不猜跨账号对象，409 保留输入并要求刷新/重新确认，未知或非法响应不得显示成功。当前 User 边界表单不等于完整 Policy 编辑器、安全委派或 Role 边界。

### AccessKey 变更的原意图恢复

沿用[007 的 K1 契约](FEAT-IAM-007-programmatic-credentials.md#k1管理入口与原子事实)，在既有 provider/renderer 内补齐状态变更、网络限制修改和删除的恢复流程，不新增通用回执接口、秘密恢复能力或第二套凭据模型。固定消费者`f31267814e6449772ded8c785aed897531329533`已修正离页或重新登录丢失原意图、已提交删除的key从目录消失后不能恢复的问题。后继固定消费者`2d853754ab0f1f0608355665fbb9011315b3779f`在其基础上选择性采用固定`fd3cf32c70f608b4048749a5289750e473975825`的准确User导航、原意图所属User读取和一次性Secret离页保护；具体采用边界归既有adoption owner。[Issue #5](https://github.com/xiak/matrix/issues/5)仍保持打开，独立CI状态归[011](FEAT-IAM-011-acceptance.md#当前控制台与发布门禁)，三类变更的真实浏览器故障注入及后验见[本轮恢复证据](#本轮消费者与真实恢复证据)，不等于正常创建与轮换已验收。

待核对意图只保存非敏感的Account、actor、目标User/key、预期资源版本、操作、冻结输入、requestId及阶段；严格解析，不保存Secret、Bearer、OTP或密文。真正没有记录与存储不可读、畸形或错误绑定必须区分；后三者不得被当作空闲状态允许新写，发送前必须成功持久化原意图，清除失败不得解锁。离页、重挂载和同actor重新登录必须保留原意图，其他Account/actor不得消费它。UNKNOWN期间禁止自动重试或新意图替代；操作者只能明确重放完全相同的原请求，不能编辑原CIDR、状态或版本后继续沿用requestId。

该恢复允许既有POST返回`APPLIED`或`EQUAL_REPLAY`，并不要求所有操作都使用只读GET回执。重放结果只证明原完成事实，不能补发Secret、代替当前key状态或把历史`CURRENT`覆盖今天的`RECOVERY_FENCED`。收到完成后进入“已完成、待重新读取”，独立GET/list成功后才解除操作锁；回读失败只允许重新读取，不自动再次写入。完成态只要求当前读取权限，不得因原写权限已撤销而禁用只读回查；UNKNOWN的原写重放仍由后端按当前授权判断。原key已不在目录时，恢复入口仍由冻结意图提供，不要求从已消失的行重新打开表单；实际权限继续由服务器在当前请求判定，目录无行或一次拒绝不能独自证明原命令完成。

创建意图与后续变更意图必须正确衔接：为处理未取得Secret的已创建key，仍允许对其准确目标进行显式禁用/删除。只有该key的删除完成事实及后续权威读取均成功，才能解除对应的recovered-create锁，不能因目录暂时无行或其他key删除成功而解锁。所有成功、失败和收尾还须经过现有精确来源Session围栏，旧Session迟到的成功、401或finally不得清理新Session保留的意图。

本分支保留原renderer用例及登录交互，未导入对方生成物或验收状态。既有四条独立消费者回归继续覆盖存储读失败、写失败、畸形记录仍派发新写，以及completed状态错误依赖原写权限：前一候选7.72秒确定失败、必要修正上原样8.37秒通过。本轮另在旧消费者证明四条页面连接回归失败，采用修正后原样通过；旧client清理用例保持通过。增加的三条负向用例证明exact-owner读取失败或返回错误User时保留原锁、零密钥写入，以及旧client的迟到User回包不能打开新身份的目录。七个生产文件与固定fd3cf32c逐字一致；两个完整测试文件285项85.99秒通过。Node22.22.2、单worker、2GiB heap下类型/lint/架构、234组对比度及八项导出Node测试通过，两个2-worker生产构建的324项资产逐字一致并由本分支重新嵌入。Go UI/architecture/default authorityprocess race分别7.277/2.342/3.910秒，vet及Linux UI编译通过；未启用的数据库和浏览器用例不计真实运行。这些证据不等于LIVE命令效果、Audit唯一性或签名发布验收。后端API、SQL和IAM87/Audit39/PaaS7+r37完整Profile没有变化。

真实生产入口复核发现，仅前端消费`tab`仍不完整：Go静态服务在用户详情HTML与Next文本预取上拒绝`tab=keys/policies`，浏览器实际返回400 `INVALID_REQUEST`。固定消费者`0a79a9cd35ca96dd9ce9755ff228aee1ad1cd706`选择性采用`14dccb1df71952fed5f6eb5581114a82c3da6ad1`的唯一生产文件修正，前后blob均与固定donor匹配，保留本分支四条原样红例：修复前2.532秒失败，修复后3.505秒通过。仅用户详情、单一非空id与现有六种页签组合可用，未知/重复页签、其他路由和authority selector继续拒绝；返回内容和CSP不受查询参数影响。完整UI/architecture/default authorityprocess race分别7.300/2.340/3.962秒及vet通过，不改变前端生成物、API、SQL或发布Profile。

既有authorityprocess owner新增可选AccessKey浏览器恢复入口，选择SET_STATUS、NETWORK或DELETE之一，API只准备可丢弃User、密钥及显式Policy/Attachment；冻结bootstrap策略不能隐式取得新增密钥权限。响应丢失后必须实际操作页面，沿原意图精确重放一次并另做授权目录读取；结束标记只触发原版本单增、唯一完成/outbox/Audit及租户完整链的后验，标记本身不构成验收。默认observer回归拒绝变化的请求体、来源、目标、失败重放、额外写以及重放前的读取。该门禁不声称浏览器创建密钥、保存一次性Secret或程序访问已完成。

此前Windows服务经SSH访问远端数据库的准备在PaaS installation verify处71.75秒超时；改为同机独立PG18.4后修正夹具遗漏的显式密钥授权，没有放宽产品权限。该2CPU/4GiB、Go1.26.3/GOMAXPROCS2的非race运行仅取得登录页证据，SET_STATUS最终以1800.02秒浏览器超时失败（package1800.038秒、exit1、OOM=false）；不接受UNKNOWN或密钥效果，也不能据此断言产品命令失败。已核对身份并关闭转发、删除该轮独占runner/PG/空网络；先前工具拒绝删除的源码、依赖和SDK归档仍保留，不计已清理。后继本机新鲜空库的三类成功页面证据由下表拥有，不回填这次失败；签名组合仍独立验收。

最小验收沿原provider/repository/renderer及真实进程owner，不另建测试框架：

- 三类命令分别覆盖UNKNOWN→离页/重挂载→同actor新登录→显式原请求重放；替换Account、actor、目标、版本或冻结输入均不得执行另一意图。
- 覆盖旧Session迟到成功/401及并发收尾，原requestId和后来Session的待核对状态保持。
- 覆盖recovered-create→删除已提交丢包→目录无key→原删除重放→权威回读后解锁；回读失败保留完成状态且不再写。
- User详情已消费`policies`/`keys`目标区块；原意图的User不在当前目录页或目录失败时，明确操作沿既有exact getUser/loadUser读取准确目标，失败保持锁定而非重放命令。一次性Secret使用既有内部离页保护，Session/client改变仍立即清除秘密，不受离页确认阻挡。这三项当前已有组件证据，仍须真实浏览器验证；Access Analysis只有keyId时不得猜测owner或伪造精确深链。
- 分别证明一次性Secret清除、完成事实与当前状态分离、命令效果及Audit唯一性。组件红绿、独立CI与真实浏览器证据分开记录，任何一层都不能冒充其他层已通过。

### AccessKey与Role本轮闭环

本轮从已验证固定`9062f83bc114c1f79e829fb2018e0b94f6bd651b`继续，只完成IAM-UI-05/06中长期程序凭据与同账号用户角色的可操作路径。007拥有密钥生命周期和签名规则，006拥有Role/Trust/RoleSession规则；本文件只定义它们的控制台组合验收，不复制PDP、秘密托管或角色会话模型。UI仍由UX/UI owner实现，IAM owner提供真实服务、原测试夹具及权威后验。

| 切片 | 真实可操作结果 | 不可替代的证据 |
| --- | --- | --- |
| UI-K1 正常密钥与轮换 | 已授权操作者进入准确普通User，页面创建第一把Key、观察一次性Secret并明确结束展示；离页/重进只能读非秘密元数据。创建第二把后，两把分别用于真实PaaS签名请求；明确禁用、启用、再禁用并删除旧Key，新Key保持可用 | 两把未删除Key的上限及删除释放名额、每次当前授权与立即失效；Secret不进入日志、持久浏览器状态或Audit。只在测试进程内存使用真实创建响应的材料，不从数据库解密或伪造用户凭据 |
| UI-K2 原命令恢复 | 现有SET_STATUS、NETWORK、DELETE三种操作各在独立空库完成单写响应丢失、UNKNOWN、离页/同actor新登录、一次完全相同原命令恢复及独立当前读取 | 原request/actor/目标/版本/冻结输入、单次效果/完成/outbox/Audit；目录无行不能确认删除，历史完成不能清除恢复围栏，失败回读不能重发写。API预建Key不算UI创建或Secret验收 |
| UI-R1 创建与显式承担 | 当前获授权的同账号管理员从已有Role工作区创建CUSTOMER Role、审阅准确Trust及权限上限、显式关联租户Policy；被信任普通User从自服务入口承担，并在真实业务页面验证Role范围内Allow/Deny及身份/来源/期限显示 | Trust命中、承担许可、Role正向授权与boundary分别成立；角色不继承来源User业务权限。准备User和可见Policy可用API，所宣称的Role创建/关联/承担必须实际从页面提交 |
| UI-R2 撤权与退出 | 沿现有ROLE/REVOKE夹具完成管理员附件撤销UNKNOWN及只读原回执，原Role下一受保护请求401进入BLOCKED；仅显式重新验证来源后返回USER，来源没有业务权时应用读取呈现403。已有精确Role会话工作区另验证单Session撤销 | 不自动重新承担、静默换用来源身份或重放业务写；原发行/历史事实保持，重新授予不能复活旧RoleSession，完成回执不等于当前权限 |

先复用已具备的UI-K2和UI-R2夹具，再在原`test/authorityprocess` owner补UI-K1/UI-R1缺失的观察和效果断言，不另造浏览器框架或生产调试端点。默认单元/契约/组件门禁证明输入围栏和迟到响应，独立真实PG/HTTP门禁证明当前授权和事务；它们与真实浏览器分别登记。每条旅程必须有可见页面观察和准确数据库/Audit后验，完成marker只触发后验。测试日志不得保存Secret、Bearer、认证输入或完整敏感响应。

本轮不引入SSO、WebAuthn、跨Account承担、角色链、服务身份信任或完整签名发布；也不将未执行的Role资料/Trust后续编辑/停复用/删除、密码/MFA与其他010矩阵路径自动标绿。现有错误或缺少消费者能力先在原owner修复并固定，再实跑相关路径；不得用新的权限绕过掩盖页面缺口。固定代码的必要CI与独立开发并行，涉及契约/安全失败先修正。每次重型运行串行且限额，结束后确认进程与连接归零，清理不再使用的自有容器、空网络、数据库及临时包；保留精简真实日志，不触碰其他任务或保留的安装现场。

#### 本轮消费者与真实恢复证据

本分支选择性采用UX固定`d11da0ce92617d677ec62077975eb15910be9a15`的四个既有源码/测试路径。Role客户端只依赖LIVE repository及经验证的身份owner，不再要求目录或创建权限；目录仍独立要求list，已知Role详情直接执行准确read。消费者新回归在修复前因错误的目录门禁失败，原样修复后通过，并证明不发生Role目录读取或显示创建入口。另补AccessKey准确read的路径、Bearer、no-store和返回归属断言；不增加权限、API或兼容分支。

四文件558项组件/客户端回归以161.51秒通过；Node22.22.2、2GiB/单worker，类型、lint、架构、234组对比度及八项Node边界通过。明确以本机Node22执行两次2-worker生产导出，preview unset/0的324文件逐字一致并重新同步Go嵌入；先前未确认终态的构建不作证据，误经npm包解析使用Node26的那次导出也不算Node22验收。最终Go UI/architecture/default authorityprocess race分别7.414/2.743/3.943秒及vet通过；外部数据库和浏览器的默认跳过不计真实运行。Role观察器另有十三条输入/凭据转换场景和有界响应透明转发回归，仍不替代实际页面。

UI-K2沿现有入口分别使用新鲜独立数据库，真实IAM/Audit/PaaS、双dispatcher、受限数据库登录及嵌入控制台。数据库为本机PostgreSQL18.6、2CPU/1GiB/Pids128、tmpfs；Go使用GOMAXPROCS2、`-p 2`及race。UX观察完成后才触发后验，不用marker或API准备替代页面。

| 操作 | 实际页面结果及精确原请求 | 后验 |
| --- | --- | --- |
| SET_STATUS | 禁用后UNKNOWN，SPA离页/返回，当前目录已DISABLED但原意图仍保留；明确重试`ui-access-key-status-4c91bf42ad877f046b9cf9b11793541e`一次，再读当前状态并解除恢复围栏 | 218.61秒、race222.308秒通过；初始提交及一次相同重放只推进版本1→2一次，唯一完成/outbox/Audit与完整租户链 |
| NETWORK | 设置`192.0.2.0/24`后UNKNOWN，同actor正常重新登录恢复原key/version1/网络输入；明确重试`ui-access-key-network-446571fe1a5eeea8d83cd31295c7ef14`一次，另读ENABLED及准确网络限制 | 249.04秒、race252.934秒通过；一次版本推进及唯一原意图/成功事实/完整链 |
| DELETE | 已禁用Key由页面一次删除后UNKNOWN，SPA离页/返回时目录已无Key但原意图仍锁定；明确重试`ui-access-key-delete-a659c3b83899106c9ec5896d5e4cd676`一次，独立读零Key目录后才解除围栏并释放名额 | 407.70秒、race411.236秒通过；唯一效果/完成/outbox/Audit及完整租户链。此前准备后中断的尝试无成功终态，仍不计通过 |

前两条运行使用固定9062的嵌入消费者与本轮测试源码；DELETE使用随后固定为`640f0f59045b194466807329a12f7bc6c6b58a08`的消费者和测试源码，未包含后继正常Key生命周期夹具。Role修正后的生成物不能倒推为前两条的运行版本。浏览器整页重载仍清除内存Session并要求正常登录，不为恢复体验持久化Bearer。上述结果不证明UI-K1的页面创建、一次性Secret和实际签名使用，也不证明UI-R1/R2或签名发布；剩余切片按原矩阵继续。

UI-K1在同一authorityprocess owner增加独立opt-in正常旅程：准备无Key普通User及准确管理/业务授权，七条写命令必须来自页面，依次为创建两把、禁用/启用/再禁用第一把、删除第一把、创建替代Key。各阶段可见观察后，独立真实PaaS签名读取验证两把重叠、禁用403、删除401与其他Key继续200；两把未删除上限由实际拒绝第三把及删除后真实新建证明。测试relay只在内存有界捕获创建响应材料以签名，最终清理，不从数据库解密、不记录Secret或Bearer；普通详情/目录严格拒绝秘密字段。各命令准确actor/target/request、单调版本、完成/outbox和Audit链独立核对。此设计和默认观察器回归不等于已完成实际页面验收。

选择性接入UX固定`7a704f5f2f3deb25e7972015a495a503288f4733`的两个既有测试文件增量，保留本分支准确owner读取和拒绝分类回归。状态化Key组件测试从空目录连续创建两把、明确结束Secret展示、卸载重挂载后无Secret，使用第一把的准确版本1/2/3停启停、版本4删除，再由权威目录释放名额并创建替代Key；每条命令的requestId和确认绑定分别核对。原RoleSession UNKNOWN恢复测试增加另一条服务会话，证明只移除准确目标，Sibling仍未撤销且不调用Role/附件/上限变更。消费分支两文件54项以21.42秒通过，Node22.22.2、2GiB、单worker，typecheck及两文件ESLint通过；默认process/architecture race3.980/2.510秒及vet通过，默认opt-in跳过不计真实运行。未改生产代码或嵌入产物，不替代K1真实签名/浏览器及R1/R2实际会话撤销验收。

K1后验区分同一原request的授权决定与密钥变更事实，不能把合法`iam.authorization.decided`误计为重复变更或当成变更已完成。只接受同Account、IAM来源、原USER管理者的ALLOWED决定，且target必须是其准确decisionId；密钥成功事实仍严格匹配原action/key/actor，跨分页重复成功、错误归属或其他action都失败。原判定在三条合法决定顺序/仅决定场景以race2.433秒确定失败，修正后19种Audit归因场景及15种页面命令/非秘密读取场景以race3.474秒通过，默认process/architecture race3.955/2.688秒和vet通过。没有修改生产权限、Audit契约、SQL或秘密处理；这不替代尚未完成的真实创建及双Key页面运行。

固定640f消费者的首条ROLE/REVOKE页面旅程发现导航缺口：普通成员真实承担成功，但没有可见入口从当前IAM工作区进入应用；整页改地址会清除内存凭据，不能替代同Role的业务读取。未进行附件撤销，数据库核对原附件仍未撤销；既有观察器因缺少真实Role业务200及后继转换以361.16秒失败（race363.704秒），子进程随后正常清理。该失败不补填为验收，也不以注入链接、直接API调用或持久化Bearer绕过；由原UX/UI导航owner修复后再新库实跑。

后继选择性采用UX固定`ceb38eab2cb3075573dcea640d9ca5d38e097a3e`的九个源码/测试路径，六个最终blob相同，保留消费分支Shell测试及两份消息文件的既有差异。平台工作区与受管产品发现的边界归FEAT-007，未向受管目录注册假的Applications/IAM/Audit。消费侧先只加入原样回归：目录pending时进入Applications及同Role跨工作区两项均在旧实现缺少链接，以10.01秒失败；接入修正后8.69秒通过。三文件174项49.90秒、type/lint/architecture、234组对比度及8项Node边界通过。Node22、2GiB/单测试worker、两个构建worker的双导出324文件逐字一致并从本分支重建嵌入，Go UI/architecture/default process race分别7.376/1.797/3.909秒及vet通过。这些是消费者组件/构建证据，新的真实Role旅程尚未完成，也不继承donor验收。

固定`da9426f608a99d564d573d3d4153714ba1198ada`的新库R2页面已观察到同Role的真实应用行、单次撤权UNKNOWN、只读原回执、独立零附件视图、BLOCKED和显式来源返回后的应用拒绝，但旧探针以400.18秒失败（race402.669秒），不计整条通过。探针只接受Applications401；现有ControlPlaneProvider实际在打开产品目录的GET401就清除被拒绝的Role有效凭据，之后不应再发送该凭据。修正只在既有测试owner认可应用读取、准确受管服务目录或当前Role身份这三个实际GET消费者的同一发行Role401，仍要求先前业务200、已发生撤权、随后原来源核验200及应用403；403/503、其他方法/路由/凭据和撤权前401均不能替代。新增两条正向顺序在旧探针确定失败，补正后27种场景及有界响应race3.453秒、完整默认process/architecture race4.001/2.428秒和vet通过。只增加封闭布尔/计数及路由诊断，不记录秘密或任意请求。固定`0884b4e8d3a144ba586dc1cd126a5b9fa8d44cd5`的后继新库仅完成承担及撤权前应用读取，最终撤销没有提交；因执行端浏览器确认限制，主动停止本轮准确UI进程，门禁以`browser UI exited during observation`、716.88秒（race719.354秒）失败收口，没有写完成marker。原附件仍版本1且未撤销，进程和数据库外部连接归零。完整新库实际观察仍是验收前提，不从客户端代码推断旧运行中未保存的网络证据。

UI-R1与UI-R2单Session撤销复用同一个新鲜进程旅程，减少重复启动：API只准备普通User、一个真实应用和可选Policy，页面创建CUSTOMER Role及准确USER Trust、设置PaaSViewer上限并显式关联允许应用与Audit读取的租户Policy。随后才为成员授予该实际Role的精确assume权限；成员从页面承担，以应用200/Audit403证明正向授权与上限的交集。管理员最终只撤销该页面发行的准确RoleSession，原角色下一请求401/BLOCKED、显式验证来源后业务403，另一条独立发行的Sibling Session继续200。原Role、Trust和附件不变，五类原命令唯一outbox/Audit及完整链分别核对；默认观察器覆盖错误Session、等值回执冒充首次撤销、缺失拒绝观察等负向路径。此夹具当前只通过编译/默认检查，实际页面仍未验收。

新增正常Key/Role夹具的最终默认进程race3.971秒、架构race2.683秒及vet通过；Key观察器十五种场景、Role观察器十九种场景及响应有界/透明转发在原owner执行。浏览器根默认opt-in跳过，不计实际生命周期通过。首次K1准备因夹具使用非规范应用名返回400，未进入页面；修正后另一空库成功启动，但创建密钥的具体浏览器确认未完成，以1800.06秒观察超时结束（race1802.516秒）。数据库仍零Key，进程、监听和外部连接均归零后删除该独占库，不能视为产品创建失败或页面通过。新鲜正常生命周期仍需实际提交及后验。

## 验收

单独端口、独立 IAM/Audit/PaaS+PG18 的真实浏览器完成平台→root→管理员→成员→资源路径，涵盖授权、撤销、组继承、policy/version、role、key、TOTP、改密与多设备下线。资源路径必须创建当前产品目录实际支持的 PostgreSQL 18 托管实例，等待真实 worker 将其调谐到 READY 并完成 SQL 读写；目录可见、配额可见、命令进入 QUEUED/PENDING、伪造 endpoint 或仅数据库行存在都不是资源接入成功。403/401/409/503 对应页面状态，无空白/健康页代替业务。

前端类型/lint/组件测试/构建、正常桌面和 360px 路径随片验证。用户已将键盘专项降优先级，记录待补但不阻塞高优先级安全和业务流程；不得据此宣称键盘已验收。不得使用其他 Phase 的固定端口或运行实例。

### 当前身份边界消费证据

2026-09-14，使用固定后端 `119f232e` 的当前响应结构更新原 HTTP 客户端测试，旧解析器因不接受 permissionBoundary 的三项正向流程先失败；修复后该 owner 的25项测试通过。新增门禁同时拒绝字段缺失、null 外层、错误 Account/User/User 修订、root 带边界、非法 Policy/版本/digest、额外正文/permit/selector；明确 null 不产生授权，合法引用也不加入 policySources。页面测试证明无普通授权时展示边界不会开放用户/策略目录，默认版本刷新、移除与读取失败分别替换或清除当前投影，不从边界策略名称计算许可。

本片全前端103项测试、类型检查、lint、架构及20组样式对比度检查通过；两次使用2 workers的静态导出一致，59个生成文件与 Go 嵌入交付物逐文件匹配。Go UI/架构 race、UI vet 与 Linux amd64 UI 构建通过。只变更现有 auth 客户端/domain/scene/renderer 和其嵌入产物，没有修改全局页面结构、样式、IAM API/SQL 或其他任务工作区。当前证据是客户端和组件/构建检查，不是独立真实浏览器、User 边界管理表单或完整 IAM-UI-04 验收。

固定 `ef51b1d509e7e38dfb2146416c7e057a97638765` 的 [Verification 34850453837](https://github.com/xiak/matrix/actions/runs/34850453837) 已通过 GitHub API 核实精确 SHA，Go、authority-process、node-process 全部 completed/success。该对象仅当前身份消费，不包含后续边界管理表单。

### 完整控制台快照集成

UX/UI owner固定`d7d6b09a4c056c5380d6e0c1d87b9fc97ab9a9e5`后，没有把其844个历史提交或后端/安装/文档状态并入本分支。隔离候选`db13087079b98d10dfcc544bc26d11b64d3df318`以独立CI全绿的`b377d34a282e581fb8cbdbc6461e7da31c10aaf5`为唯一父提交，只用同一树快照替换`app/ui/paas/**`：652个路径，范围外差异为0；候选UI树`e44e128e4c4776f37bdfd5af20a8a1712d7cf148`与UX固定源逐字一致。常规receive-pack两次得到GitHub 500后，候选通过Git Data API从IAM根树替换准确子树；取回后再次核对父提交、根树、UI树、路径范围和内容。当前分支以带来源记录的`74e3c0983`消费该候选，没有移动或改写任一原分支。

候选在IAM基线的独立临时检出中通过typecheck、lint、架构检查、228组多主题对比度、63/63文件共1155/1155项测试和3项归一化测试；Next 16.3.3生成47个静态页面、规范化45个分段，259个嵌入文件逐字一致；全仓`go test ./...`与`go vet ./...`通过。独立DEV在1280、390×844和320×720检查无页面横向溢出，移动操作收敛到统一Page actions，新建Account在内容区而非伪Dialog，320px详情保留身份事实，浏览器warning/error为0。临时预览、快照和归档均已删除，原UX MOCK预览未被替换。首次用工作区外`node_modules` Junction构建被Turbopack拒绝，改用候选目录内`npm ci`后上述生产构建通过；不能把该环境失败写成代码通过，也不能手改可重复生成的minified产物。

Account开通、状态与原主身份恢复客户端严格要求原`requestId`及目标`resourceVersion`，成功只消费裸`Account`；目标GET只表示当前状态/capability，不冒充命令完成回执。UNKNOWN冻结完整非秘密原意图并禁止重发写请求；同一原actor可以在当前来源，或在另一个浏览器/Session显式导入摘要后，以原`requestId`、operation和版本边界调用唯一completion GET。结果必须逐字段匹配，404、409或当前目标状态均不得推断成功，也不授权替换意图；401只失效准确Session。root恢复不改变Account状态或角色。未有真实endpoint的能力继续保持独立MOCK或失败关闭，不能借完整页面快照宣称后端已经实现。

### User 边界管理增量证据

UserAccess 的九项基础能力与附件撤销能力由同一事务的当前 PDP、准确 Account Root 关系和目标构造；每页仅读取一次 root 所属关系，不逐用户额外查询。新 set/remove 能力绑定 USER ID，缺失任一能力的严格契约/客户端投影拒绝。可用性只表示管理者可以尝试，不把“尚未设置边界”或所选 Policy 状态猜成写入成功条件。

专属 PG18（1 CPU、768 MiB、PIDs128、64连接）的原边界流程聚焦通过2.57s（父7.39s、包9.993s）：主账号实际 GET User 返回可管理，普通管理员在明确授予管理动作且边界允许后仍返回不可管理、实际移除仍403；停用目标后主账号能力保持且移除不启用。没有改变已有写事务、schema、函数形状、Audit action 或安装 profile。该聚焦能力检查不替代以下完整相关回归或后续真实浏览器，也不能用这些提示替代服务端授权。

同一专属 PG18 的全新独立数据库上，完整 IAM integration race 通过182.539s，保留组/策略容量分页、当前 schema/bootstrap 带数据重放、凭据/会话/恢复并发及平台保护；独立双 IAM/PaaS/Audit 真实进程 race 通过44.791s，保留两应用边界交集、下一请求撤权、真实受限登录和双租户资源/Operation/outbox/历史链。未运行未发布 schema1 逐版升级矩阵。全仓 Go race/vet、模块校验及 Linux amd64 构建通过；数据库门禁与广域构建串行。测试结束确认精确对象 ID/标签与零客户端后，仅删除本轮专属容器、网络和合成数据卷，没有用户或其他任务资源变更。

最终前端109项测试、类型/lint/架构/20组对比度通过；两次2-worker导出逐文件匹配59项嵌入产物。真实 HTTP 客户端测试覆盖 GET/PUT/DELETE 的方法/目标、无 Account selector、精确修订、错误归属/结果/版本拒绝，以及原请求重试字节一致。组件覆盖设置/替换/移除前确认、已授权目录选择、移除扩大权限的提示、读取失败不猜 NONE、陈旧 User 修订不提交、503 不报告成功且保留原 requestId、刷新后权限撤销停用确认、401 清除管理场景。最初重试测试复用了已经消费的 Response body，修正为每次返回新的测试响应后通过，未放宽生产解析。

固定 `6292fa09ad286960a1098ad3383a896c9374bffe` 的 [Verification 34853775664](https://github.com/xiak/matrix/actions/runs/34853775664) 已通过 GitHub API 核实精确 SHA，Go、authority-process、node-process 全部 completed/success。源码保持 IAM18/Audit12/PaaS1，UserAccess 新闭合能力集合需要客户端随固定对象同步，不能凭相同 schema 数字声称旧客户端兼容。仍不是完整 IAM-UI-04/010、安全委派或 Role 边界验收。

### User 边界真实浏览器验收

沿现有 authorityprocess 启动与安全门禁增加显式 opt-in `TestIAMConsoleBrowser`，使用全新合成数据库、实际受限 runtime 登录、IAM/Audit/PaaS 与两个 dispatcher 和嵌入 UI 进程。仅测试用 loopback 路由转发真实 API，不注入凭据、tenant selector 或授权响应；不代表 APISIX、签名安装或正式 release profile 验收。默认自动门禁不等待浏览器；手工 fixture 最多30分钟，超时失败，正常结束检查实际 set/replace/remove Audit 事实、当前明确无边界与完整链。页面行为必须另外观察，不能只凭 completion marker 或测试 PASS 宣称视觉通过。

首轮真实浏览器观察完成主账号设置 A、替换 B、明确移除，以及同一成员会话刷新后对应 A/B/无边界，正向 PaaSDeveloper 附件没有被当作边界或删除。普通 AccountAdministrator 能读成员，但边界区显示无操作权限且不提供设置/移除控件。受限 PG18 与独立进程 fixture 最终通过585.15s（包586.466s），两个设置事实和一个移除事实已投递且 Audit 链验证通过。此轮360px截图发现长 Policy/版本 ID 被裁切，未将该轮记为窄屏通过。

在原 auth renderer 的 detail/note 文本容器补可断行规则，109项前端测试、type/lint/架构/20组对比度通过，两次2-worker嵌入构建逐文件匹配59项。全新数据库与重建 UI 的第二轮浏览器，在实际360×800视口完成设置 A、替换 B、移除和同一成员会话刷新；截图显示完整换行，详情边界容器 clientWidth/scrollWidth均212，自身投影均262，右边界均在视口内。fixture通过154.51s（包155.986s），实际事实和 Audit 链再次验证通过。只证明该边界交互，不包括完整策略编辑器、所有错误页面或整个010验收。

集成后的工作树重新执行`npm ci`并从头通过`npm run check`：typecheck、lint、架构、228组对比度、63/63文件共1155/1155项测试、3项归一化、47页生产构建、45项规范化和259文件嵌入一致性均成功；随后以`GOMAXPROCS=2`通过`go test -count=1 -p 2 ./...`与`go vet -p 2 ./...`。本机Node 23.11.1不在项目声明的受支持engine范围，因此这些是组合回归证据，不是正式Node运行时或release验收。该快照当时尚未实跑平台→root→管理员→成员→资源的真实IAM进程浏览器路径；当前`0d9d0b12`已补足下述首个真实产品资源闭环，但慢响应/故障注入、completion receipt、跨浏览器reload后的UNKNOWN恢复、APISIX或签名安装仍未覆盖，不能把本次资源闭环扩大解释为IAM-UI-01–08整体通过。

固定`448400628734d4c708d7859492fba1cf1b663284`在原Verification工作流增加独立`console`作业，使用受支持的Node 22.22.2、固定npm 11.6.4执行干净`npm ci`、完整`npm run check`，并要求源码与259个嵌入文件无生成差异；后端原串行门禁及资源预算未变。[Verification 37644376405](https://github.com/xiak/matrix/actions/runs/37644376405)首轮中`authority-replacement`和`authority-replacement-qualification`因GitHub runner连续五次获取失败而在零runner、零步骤状态结束，其余实际执行作业（包括`console`）均成功；整轮终态后仅通过官方failed-jobs入口重跑这两项及依赖汇总。attempt 2已核对精确SHA、16项全部completed/success，两个替换作业均取得runner并真实通过，最终`authority-process`成功。该证据接受受支持Node运行时上的独立控制台构建/测试门禁，不替代上述真实IAM浏览器、故障恢复、APISIX或签名发布缺口。

### 当前 UX owner 快照集成

2026-10-11，当前 IAM 分支选择性采用 UX/UI owner 的固定代码`76a0dcfb7912061977e3805c87d881bfdd35a0dc`，经本分支既有产品运行时与控制台源码合并后形成`0b7823265c3ec0da64976210bd47019ed43b8b0a`。采用范围仅为本 FEAT 与`app/ui/paas/**`的产品目录、实例详情、终止流程和生成资产；没有导入 UX 分支的后端、API、SQL、安装状态或 checkpoint，也没有把本分支的 UI 工作反向写入 UX/UI 工作区。
- 2026-10-12 继续选择性采用 UX/UI owner 的固定修复`be5f383ba517de90dcba71a6f884f34d8f4290f6`，只合入资源阶段与 Operation 阶段的合法配对、负向契约及相应控制台源码；嵌入资产由本分支自身源码重新生成，没有直接搬运 UX/UI 分支的生成物或工作区状态。
- 2026-10-12 继续 `ADAPT` UX/UI owner 的固定修复`01f5241ee2d4b604a13c7fae05b2e301c9b15d9b`：安装目录只以`service-installations`作为必需读取，`offerings`、`regions`与`quota-entitlements`各自失败关闭为缺少辅助显示信息而不阻塞稳定资源ID和精确详情入口；详情仍须独立读取真实实例，不能复用目录摘要。固定源中的旧服务角色Action测试数据同时替换为当前契约命名。没有导入其已被本分支后继替换的终止轮询、Operation阶段解释或生成资产；嵌入资产只从本分支最终源码重新生成。
- 2026-10-13 继续 `ADAPT` UX/UI owner 的固定`b28ef9c565e4e382302a67b62ceb4a6c1d6e2475`。其父`e14dec6351b759327cffc22105a0e1276b77ab8e`的`app/ui/paas/_frontend/src`与本分支固定`44b4ac334c0486feb32cf325b992f03b03723a60`逐字一致；只采用既有 auth application/domain/renderer/repository、消息、Wizard和重生成嵌入资产，不导入对方后端、API、SQL、FEAT或checkpoint。Root-only LIVE User创建冻结当前Account、调用Session、完整输入和requestId，显式`permissionBoundary:null`，严格核对创建响应后精确重读；不确定结果只能由同一Session重放原请求，换Session/repository清除秘密。首次通知地址严格接受`FIRST_ADDRESS`与`expectedResourceVersion=0`，不再沿用缺少purpose/version的旧wire；`REPLACEMENT`仍要求其正版本，二者不能互换。
- 2026-10-13 继续 `ADAPT` UX/UI owner 的固定`1fa26c88469ae6f77960e381ca852fe1e7c029a7`；其父即已采用的`b28ef9c565e4e382302a67b62ceb4a6c1d6e2475`。只采用六个既有auth domain/repository/renderer/application源码与由该源码生成的319项嵌入资产，逐路径核对固定对象一致；不导入对方后端、API、SQL、FEAT或checkpoint。TOTP首次绑定只接受服务端`INITIAL_ENROLLMENT`，重新绑定只接受`REPLACEMENT`；错误或缺失purpose整体拒绝，不能把首次绑定误判为非法响应，也不能放宽替换语义。
- 2026-10-14 继续 `ADAPT` UX/UI owner 的固定`11151a06aa920438ae9d9f55252ec203a1f491d8`，其父`ca08dcc4fac9c85e29b89524f103a1e0d2a882fd`与本分支父`2566c22d7ab03e7bcbfd4ef8891af3427033018d`在所选17个auth源码、测试和消息路径上逐项相同；只采用这些路径及其完整生成资产树，不导入对方后端、API、SQL、FEAT、adoption或checkpoint。集成固定`d02c43c31861ba5639da12a416f654a9da9c92a4`的`frontend/src`树为`06cb3f1ddfabbd5a7bd1517bd7a791a6bace09d2`、当时采用的嵌入资产树为`41d4fc1eb54f5ec4cc908bfcd30dadb60bb16605`，均与UX固定对象精确相同；GitHub固定对象共17个所选源码条目和299个有变化的生成资产条目，该嵌入资产树实际为319个文件。LIVE交互明确区分`REMOVED`与从未绑定，换绑/移除操作以原Session、原意图和请求开始阶段围栏迟到响应；移除后的同一USER仅能凭当前密码与已验证地址重新开始`INITIAL_ENROLLMENT`，不会恢复旧因子或旧恢复码，也不会把强制绑定误作普通换绑。
- 上述集成已在本分支使用Node 22.22.2通过四个相关测试文件387项、typecheck和架构检查，并从仓库根目录通过`GOMAXPROCS=2 go test -count=1 -p 2 ./app/ui/paas/...`与`go vet -p 2 ./app/ui/paas/...`；UX固定源另有70个文件1439项、lint、228组主题检查、生产构建及319项嵌入等价证据。两者都不替代换绑/移除/重新绑定的真实浏览器、SMTP、Audit和签名发布门禁。`d02c43c`的独立Verification真实发现嵌入资产漂移；修复固定`06a51099d9e99325b171d2b5692dbfc56a952cf8`从同一`frontend/src`树在干净Node 22.22.2构建后只重新生成完整319文件边界，产生1个99%相似度chunk重命名和234个引用文件更新，新资产树为`b738209ec6e7c53e84fa1e330c3ac1e3f0ef02b1`；没有前端源码、API、SQL或后端改动，本地嵌入等价与Go UI test/vet通过。包含该修复、后继个人安全浏览器门禁及CI预检编排的固定`ad83baa59a599d5b24675b4990c21590e27984eb`之[Verification 38551998246](https://github.com/xiak/matrix/actions/runs/38551998246)已核实精确SHA，Go、console、node、PostgreSQL HA、十二项authority lane及最终汇总共18项全部`completed/success`；默认CI仍不运行显式opt-in浏览器fixture。
- 本分支增加一条缓存命中回归：若安装目录请求已经提交，而后续导航使原prepare失去当前revision，目录结果仍可进入缓存，但下一次进入安装目录必须启动尚未成功加载的三个辅助请求，不能因必需目录已命中而永久遗漏。本片定向4文件274条、完整63文件1189条及3条导出归一化用例通过；typecheck、lint、architecture、228组主题对比、47页生产导出、259个embedded文件等价和Go UI test/vet通过。完整Vitest仍报告若干既有测试未等待React `act`的警告，已交UX/UI owner清理，不能把本结果记为“无警告门禁”。只具备installation目录与精确详情权限、明确缺少三个辅助目录权限的真实PostgreSQL浏览器路径仍须在集成后独立实跑。
- 当前托管产品运行时契约固定到 IAM 产品实现来源 `4dea30e79cfd6693df149ea40eaa876c113814eb`，包含 `postgresql-18`、`mysql-8.4`、`elasticsearch-8.19` 与 `rabbitmq-4.1` 四个正式 offering；其准确版本分别为 PostgreSQL 18、MySQL 8.4 LTS、Elasticsearch 8.19.23 与 RabbitMQ 4.1.8。控制台与隔离 MOCK 必须用正式产品名称、版本、规格和产品类型说明同一信息架构，不得标为示例、占位或即将上线；LIVE 目录仍只渲染产品服务实际返回的项，不能用 MOCK 补齐。实例严格读取要求 `resourceVersion` 与 `operation.kind=PROVISION|TERMINATE`，资源阶段和操作阶段按两套状态机显式配对：PROVISION 的 `PENDING / PROVISIONING / READY / FAILED / ROLLBACK_FAILED` 分别对应操作 `PENDING / PROVISIONING / READY / FAILED / FAILED`；TERMINATE 的 `TERMINATION_PENDING / TERMINATING / TERMINATION_FAILED / TERMINATED` 分别对应操作 `PENDING / PROVISIONING / FAILED / READY`。因此 `TERMINATED + TERMINATE/READY` 是终止操作成功完成的合法形状，不得误判为协议错误；任何缺失、未知或其他矛盾组合整体失败关闭。
- 实例终止消费产品侧 `POST /managed-services/v1/service-installations/{installationId}/termination`，浏览器只发送当前 bearer 与冻结的 `Idempotency-Key`，不发送 Account、资源版本或请求体。允许从 `READY | ROLLBACK_FAILED | TERMINATION_FAILED` 发起；内容区先核对准确实例、产品、区域、观察到的资源版本和幂等请求，并要求输入实例 ID，永远不使用 Dialog。`TERMINATION_PENDING | TERMINATING` 只表示平台已接受并异步清理，不能显示为删除完成或提前归还配额；`TERMINATED` 后产品会物理删除容器、网络、持久化数据和托管凭据，并从权威目录移除实例、归还配额。网络或协议未知结果冻结原实例与幂等键，只允许以该公开键查询准确的 `INSTALLATION_TERMINATE` 完成结果；恢复读取不重发终止、不由回执补造当前实例状态，查无结果也不解锁新的写入意图。401、403、404、409 与无效输入局部失败且不改写意图。轮询 404 只有在同一个正在终止的实例上才解释为需要重读权威目录，不能因另一实例正在终止而吞掉普通创建／读取错误。
- UNKNOWN恢复只保存经过严格解码的非秘密原意图并绑定当前Account和有效身份；同源浏览器可保留该意图，不同浏览器来源只能显式导入完整摘要，再以原公开`Idempotency-Key`读取结果，禁止重新提交写请求。固定`964d7c85d2e9249541996d22b9b2d9b9189922ab`替换未接受的早期后端候选并实现服务端能力：`GET /managed-services/v1/command-results/{commandType}`只接受`QUOTA_ACTIVATE`、实例创建/终止和服务Role绑定/解绑五类命令，结果限最近七天、最多100项，且只返回原公开`idempotencyKey`、命令类型、服务端不透明输入承诺、`IN_PROGRESS|SUCCEEDED|FAILED`、非秘密目标、可选Operation/Binding及完成时间。公开幂等键独立于按动作域确定性派生的IAM私有request ID；浏览器只按原始键关联，绝不复制私有派生算法或把私有ID当作原始键。直接前驱中的服务Role命令没有保存可证明的原始键，因此默认不出现在查询中；只有同一当前主体、动作、目标和原始键在当前授权下精确重放，且前驱document/digest完全匹配，才可在不改写旧事实、摘要或终态的条件下关联该键。查无结果不表示可用新意图重发。Account和当前USER/ROLE身份都由当前IAM凭据推导；USER不能读取同Account另一USER的结果，ROLE只能以同一Role和原始主体谱系读取前三类命令，服务Role变更仍只允许原USER。Role历史由当前PaaS服务凭据调用IAM私有入口并逐项核对安装归属、用途、binding与不可变事实；不得以caller selector、平台身份、通用命令名或404推断原命令未提交。该接口不是授权permit，也不是通用回执框架；页面消费和真实跨来源门禁由下述切片验收。

- 完整Profile仍为IAM85/Audit39/PaaS7、`contractRevision=35`；本次是首版发布前对同一未接受形状的替换，不再增加schema/revision。早期候选五进程运行暴露了“把IAM私有派生ID误标成公开幂等键”的语义缺陷，不能继续作为UNKNOWN恢复验收。固定`964d7c85d2e9249541996d22b9b2d9b9189922ab`已在本任务专属PostgreSQL 18通过93.555秒完整IAM HTTP纵向门禁和55.529秒Role门禁；包含该修复的基线`c108dff3069c90bfd0c49eb868276d8d617face8`之[Verification 38406821134](https://github.com/xiak/matrix/actions/runs/38406821134)已核实18项全部成功。`355815f3d992edaf4f677374d7407554bd96ec7f`补齐页面和真实跨浏览器门禁，但其[Verification 38504465450](https://github.com/xiak/matrix/actions/runs/38504465450)最终为cancelled：16项业务作业成功，`authority-recovery-window`在测试未产生PASS/FAIL前被外部取消，依赖汇总正确失败；不得登记为精确SHA整轮通过。后继`91af2972fb16d6727845fc06c9485f8ea62ca80c`的[Verification 38511351736](https://github.com/xiak/matrix/actions/runs/38511351736)已核实18项全部成功；同Profile签名A/B、APISIX后端消费者和离线生命周期也已由下述固定门禁验收，但页面只完成签名入口增量路径，不能提前登记整个FEAT发布通过。

该终止修复在本分支通过完整前端门禁：typecheck、lint、架构、228组多主题对比度、63个测试文件共1188项测试、3项归一化、47页生产构建、45项规范化和259文件嵌入一致性全部成功；`GOMAXPROCS=2`下`go test -count=1 -p 2 ./app/ui/paas/...`与`go vet -p 2 ./app/ui/paas/...`也通过。本机Node 23.11.1超出项目声明的受支持范围，只作为组合回归。精确提交`a06de4c8b82ddc1ed43221bc5745bb60850d85d8`的独立`console`、`go`、`node-process`和`installation-postgres-ha`作业成功，但同一[Verification 38158014907](https://github.com/xiak/matrix/actions/runs/38158014907)中的`authority-managed-products`与`authority-runtime`失败，汇总作业随之失败并使整轮终态为cancelled；因此不能把局部成功写成精确SHA独立CI验收。后继测试证据提交仍需以自身完整独立CI收口。

同一精确源码的[Verification 38107642768](https://github.com/xiak/matrix/actions/runs/38107642768) attempt 1没有通过：`authority-runtime`的“保留数据与真实authority进程”步骤以exit 1失败，依赖汇总随之失败，其余15项成功；匿名日志只提供退出码，不能推断业务原因。本任务随后在独立、限额PG18上以相同选择器完整复跑该lane，restricted DSN、IAM82→83保留数据、独立IAM/Audit/PaaS进程、容量归因及调度、明文检查和TOTP备份进程均通过，package为411.519秒；这份本地结果不回填attempt 1。整轮终态后只通过GitHub官方failed-jobs入口重跑失败lane和汇总，attempt 2的`authority-runtime`两段均真实执行并通过，最终17项全部`completed/success`。该独立CI接受受支持Node上的console构建和当前后端组合门禁，仍不替代下述LIVE浏览器路径。

同一精确源码已组装并验签当前`83/37/3+r31` A/B，在本任务独立离线Docker引擎完成效果型生命周期和引擎重启后的只读复验。该运行的唯一事实与边界由[FEAT-005当前UX快照发布消费者门禁](../docs/features/FEAT-005-offline-platform-lifecycle.md#current-ux-snapshot-release-consumer-gate)维护；这里只确认嵌入控制台是实际签名发布内容，不把安装通过写成页面业务通过。

该快照集成轮次没有取得受支持的受控浏览器驱动通道，fixture在产生完成标记前停止并清理，未把静态页面观察冒充验收。后继`0d9d0b12`已用受控浏览器完成下述真实产品资源路径；该后继证据只关闭精确资源闭环，不回填此前中止的运行，也不替代其余页面、故障和恢复场景。

### LIVE Account、Root 与 User 浏览器闭环

固定UX/UI对象`b28ef9c565e4e382302a67b62ceb4a6c1d6e2475`应用后，本分支聚焦运行User创建、HTTP解析、renderer与Wizard四个测试文件共280项通过；typecheck、lint、architecture和228组主题对比通过。该本地预检使用Node 23.11.1，不在声明的正式Node范围，因此不替代后继精确SHA的独立`console`门禁；固定源报告的完整68文件1299项、59页/57段导出及319项嵌入等价也只作为donor审查输入，不能替代本分支验收。

本分支新增显式opt-in `TestIAMIdentityConsoleBrowser`，沿既有authorityprocess owner启动独立PostgreSQL 18、真实受限IAM/Audit/PaaS、dispatchers与嵌入UI，只省略已被重型门禁接受的托管产品worker和四产品provisioning。测试仅通过API预种另一个Account内的同名User；目标`browser-live-account`、不可转让Root `browser.live.root`和普通User `browser.live.user`必须由浏览器页面创建。测试用同源loopback只转发真实API，不注入credential、Account selector或授权结果，不是APISIX。

2026-10-13，全新专属PG18数据库上的真实浏览器从平台`admin`进入租户目录，页面开通`browser-live-account`并显示ACTIVE与Root；Root初始凭据真实到达强制改密页，改密因浏览器安全边界由同一真实IAM HTTP接口完成后，以正式密码进入当前Account。Root随后通过三步LIVE向导显式选择无权限边界，创建零策略、零组、零AccessKey的`browser.live.user`；用户目录显示待改密，子账号以`browser.live.user@browser-live-account`真实到达强制改密页，改密同样由真实IAM HTTP接口完成后通过UI重登。账号菜单显示准确Account、USER和主体ID，零授权用户读取控制面被真实403拒绝。

完成标记后，门禁独立拒绝Root/User旧密码和无realm同名登录，验证另一个Account同名User只能以其自身realm登录且主体ID不同；读取目标Account、Root/User、无附件/无边界、Root不可列平台Account目录和PaaS Application拒绝，并等待`iam.user.created`进入目标租户Audit链后完成链验证。fixture通过215.79秒，package通过219.306秒。该证据接受IAM-UI-01/02中上述精确路径，但不把浏览器最终改密提交、资源授权、APISIX或签名发布写成已验收；TOTP、通知地址和多会话撤销由下述独立后继切片验收。

### LIVE 本人安全与会话浏览器闭环

UX/UI固定`1fa26c88469ae6f77960e381ca852fe1e7c029a7`在当前集成树上的四个相关测试文件共318项通过；其严格解析`INITIAL_ENROLLMENT`与`REPLACEMENT`，前者允许首个TOTP认证器以`expectedResourceVersion=0`开始，后者要求已有正版本，错误purpose失败关闭。本分支的真实浏览器门禁沿用已完成改密的`browser.live.user@browser-live-account`，通过真实IAM HTTP注册并验证`browser.live.user@matrix.test`，开始和确认TOTP绑定，逐次显示10个恢复码并明确确认后清除，再分别完成两次密码+TOTP登录。会话页显示两个准确的`PASSWORD_TOTP`会话；第二个会话执行“结束其他登录会话”后，页面报告撤销1个并保留当前会话，第一个浏览器窗口在下一次受保护请求立即回到登录页，第二个窗口继续读取本人安全设置且显示通知地址`VERIFIED`、认证器`BOUND`修订2。

显式opt-in `TestIAMPersonalSecurityConsoleBrowser`使用全新专属PostgreSQL 18数据库、真实受限IAM/Audit/PaaS、dispatchers和嵌入UI；fixture通过216.41秒，package race通过220.238秒。浏览器完成标记后，门禁直接读取权威状态，核对通知地址修订1、唯一已绑定TOTP认证器修订2、一个仍有效和一个已撤销的`PASSWORD_TOTP`会话、准确请求前缀及安全Audit事实；同时继续拒绝无realm同名登录、另一个Account身份混用、零授权User读取平台Account目录或PaaS Application，并验证目标租户Audit链。首次运行到TOTP登录前暴露测试fixture在同一`pgx.Conn`仍有活动Rows时查询时钟的错误；修复为先收集并关闭Rows再生成验证码，重新从空数据库全程通过，没有改变生产事务或契约。

测试通过受保护的本机握手读取IAM数据库时钟并用同一标准TOTP算法生成一次性验证码，只证明真实challenge、重放边界、会话和Audit契约，不是SMTP投递，也不是外部手机认证器验收。其余慢响应或故障矩阵、APISIX入口及签名离线安装后的浏览器路径仍未由本切片覆盖；跨浏览器UNKNOWN由下述独立切片证明，已验签包包含嵌入控制台仍不能替代页面效果门禁。

2026-10-14，扩展后的同一显式opt-in门禁在全新专属PostgreSQL 18数据库上通过：fixture为1296.36秒，race package为1299.901秒。浏览器A完成通知地址验证、首次TOTP绑定及第一次MFA登录；不同`localhost`来源的浏览器B完成第二次MFA登录，并通过“结束其他会话”原子保留当前会话、结束另一个会话，产生唯一`iam.session.others-revoked`事实。B随后用当前密码和原因子完成用途限定证明，换绑到新因子并重新登录；再主动移除该因子，验证密码登录只恢复当前身份、不复活旧因子或恢复码，最后用已验证通知地址和当前密码重新绑定第三个因子并完成第四次MFA登录。

门禁最终核对通知地址修订1、TOTP状态修订5、三代因子中一项ACTIVE/两项REVOKED、三批恢复码中一批有效/两批撤销、唯一当前`PASSWORD_TOTP`会话且没有有效纯密码会话，以及contact/bound/replaced/removed/session-others-revoked事实的准确数量和完整租户Audit链。测试遵守服务端共享的五次/十分钟TOTP尝试预算，在真实窗口到期后继续，没有改数据库时钟、预算行或业务状态；观察器只跟踪尚未过期的登录challenge，并按因子代次复用对应测试码，不能把重试误记成后续因子。该证据接受普通换绑、主动移除和移除后的受限重新绑定，不替代真实SMTP、外部认证器、受保护Root/平台身份丢失全部因子后的目的限定恢复与强制重新绑定，或当前签名APISIX页面门禁。

### 真实产品资源闭环

产品目录当前正式接入 PostgreSQL 18、MySQL 8.4 LTS、Elasticsearch 8.19.23 与 RabbitMQ 4.1.8；它们不是示例或占位数据。控制台只消费 LIVE 产品目录返回的真实 offering 和实例，不用隔离 MOCK 补齐；各产品的签名镜像、真实协议读写、凭据文件边界、生命周期销毁与配额归还证据由 [FEAT-IAM-008](FEAT-IAM-008-product-enforcement.md) 和 [FEAT-IAM-011](FEAT-IAM-011-acceptance.md) 所有。本 FEAT 验证同一套正式对象可被发现、创建、精确重读、授权和终止，且前端不写死单一数据库服务或产品数量。

普通 User 必须通过当前 Policy/Group/Role 之一取得该精确资源的读取许可并真正读取实例；目录行只提供定位摘要，进入详情后必须通过 `GET /managed-services/v1/service-installations/{installationId}` 对该实例重新鉴权。精确读取成功前不得显示旧快照中的 endpoint、阶段、状态或管理入口；拒绝、未找到和不可用只在详情数据区失败，并只能原位重试同一实例。撤销来源后，下一次相同业务请求必须拒绝，而实例、数据和租户归属保持不变。Allow/Deny 决定均需由同一 User、动作和真实资源 ID 关联到不可变 IAM Audit 记录，PaaS created/ready 事实进入同一租户链并通过验证。

固定`0d9d0b12e9f95e9a2110697021d591916552da9a`在全新PostgreSQL 18控制数据库上以显式浏览器入口运行`TestIAMConsoleBrowser`，package通过368.546秒，fixture为366.41秒。管理员从控制台创建真实`localpostgres`实例`iam-browser-pg-bbea9b402e4f`，实际受限Linux worker将其调谐至RUNNING/READY；浏览器读取到真实endpoint`127.0.0.1:39399`，后端在该实例完成PostgreSQL 18探测及`preserved`行写入读取，并核对固定完整镜像。普通成员仅经Group策略获得目录与精确实例读取，在第二个窗口撤销Group成员关系后，不重新登录或整页刷新便再次点击同一实例；稳定标题保留，精确GET返回无权限，旧endpoint、状态和操作入口均未泄露。两个窗口warning/error均为0；后端同时核对Allow与后继Deny决定、唯一`managedservice.service-installation.ready`事实及完整租户Audit链。结束后只按本轮标签删除控制数据库和测试资源，既有4317预览未被操作。该证据接受IAM-AC-08，不扩大为APISIX、签名安装、跨浏览器UNKNOWN恢复或整个FEAT验收。

2026-10-12 的后继门禁把浏览器与后端改为两阶段握手：浏览器先完成真实READY观察，后端才核对不可变镜像、受保护凭据和实际SQL读写，并以不可覆盖的单次标记放行页面终止；浏览器确认终止后，后端再验收权威TERMINATED结果。全新独立PG18控制库上的fixture通过641.51秒，package通过645.007秒。LIVE产品目录实际显示 PostgreSQL 18、MySQL 8.4 LTS、Elasticsearch 8.19.23 和 RabbitMQ 4.1.8 四项正式产品；本轮从页面创建并效果验证 PostgreSQL 18 `iam-browser-pg-d86afec72faa`，真实endpoint为`127.0.0.1:38380`。后端完成SQL写入读取之前，浏览器不能获得终止放行标记。

同一轮由Group组合目录级定位许可与该实例精确读取许可；普通成员在offering、region和quota辅助上下文均不可读时仍能看到被授权的实例列表和详情，证明辅助失败局部降级而非依赖广域产品权限。管理员移除成员后，原成员会话再次读取同一实例即被拒绝，页面保留稳定标题但不泄露endpoint、状态或操作入口。随后管理员在LIVE页面输入准确实例ID确认终止；页面接受`TERMINATED + TERMINATE/READY`的合法完成形状，显示已终止且不再展示endpoint，没有协议解析错误。后端独立验证容器、网络、数据、托管凭据和endpoint均已删除，配额归还，终止Operation完成，IAM/PaaS outbox投递、Allow→Deny决定及租户Audit链完整。该运行使用测试专属loopback代理，不是APISIX或签名安装浏览器验收；未覆盖跨浏览器UNKNOWN恢复，也不把一个真实PostgreSQL页面流程冒充四种产品各自的浏览器效果门禁，其他三种产品的真实协议与销毁由其既有产品验收owner维护。

固定`62b9705202a6b0b91fe93e5a9cf73d28349b3930`是上述Account/Root/User、本人安全/会话和真实资源切片的组合实现点；其[Verification 38367748687](https://github.com/xiak/matrix/actions/runs/38367748687) attempt 1已按精确SHA核对为18/18个job成功，165个实际步骤成功、168个矩阵非适用步骤按设计跳过，受支持Node运行时的`console`、真实四产品`authority-managed-products`和最终`authority-process`汇总均成功。默认CI仍不启用需要人工浏览器观察的显式opt-in fixture，因此独立CI与真实页面效果证据不能互相替代。跨浏览器UNKNOWN由下述后继闭合；APISIX入口、当前完整Profile签名离线安装后的浏览器路径及其余故障矩阵仍是未验收边界。

`0b7823265`已把`installations`作为实例页唯一必需集合独立读取，offering、region、quota分别作为失败可降级的辅助上下文；任一辅助读取返回403、空结果或不可用时，实例目录和稳定标题仍可使用。进入详情后仍必须通过精确实例GET重新鉴权，目录摘要不能泄露 endpoint、操作状态或管理入口；不得通过授予广域目录权限掩盖身份缺权。

### LIVE 跨浏览器不确定结果恢复

当前分支只从UX/UI owner固定`3876516a902fd020d1ab1cd4be8f339f9a9034b1`采用九个既有application/domain/renderer/repository源码与测试文件；固定源父提交与本分支对应九个blob逐项相同，没有覆盖双方独立修改，也没有导入对方文档或验收状态。服务Role页面不再写死模板版本：它只接受稳定模板ID、ACTIVE状态、产品/purpose/workload及bind/unbind语义完全匹配的当前头，并在原意图中冻结服务端返回的正安全整数版本和摘要。导入器拒绝错误模板、非法版本/摘要、额外秘密字段或另一个身份；UNKNOWN恢复只调用结果GET，不调用bind/unbind写接口。

受支持Node 24.19上的六个相关测试文件282/282通过，typecheck、全量lint、architecture及228组主题对比度通过；59页生产导出、57项路径规范化和319项Go嵌入文件由本分支重建，并与固定UX对象逐文件一致。`app/ui/paas` Go test/vet及嵌入等价检查通过。本地默认Node 23不在项目engine范围，已停止其停滞进程且不把结果计作证据。后继`91af2972`的独立`console`作业已在受支持Node 22上通过69个文件、1391项测试、architecture及228组主题对比度；默认CI明确跳过显式opt-in浏览器fixture，故该结果仍不替代本节的真实跨来源页面证据。

显式opt-in `TestIAMManagedServiceCommandRecoveryConsoleBrowser`使用全新限额PostgreSQL 18、受限IAM/Audit/PaaS、dispatcher、真实托管PostgreSQL 18 worker和嵌入控制台。固定`4c8b25d4c91ba8841b8e2bbdf99f83ef20a74562`在同一既有测试owner内增加封闭选择器，仅接受配额激活、实例创建、实例终止、服务Role绑定和服务Role解绑五类现有命令；空值保持原绑定场景，非法值在启动业务流程前失败。后继固定`2ab6eaa489a72fa3b70211fe2524f0a53d6a6584`移除配额/实例命令不需要的ServiceRoleAdministrator过度授权，仅绑定/解绑拥有该权限；响应丢失后代理记录整个`/api/managed-services/`写面而不只记录选中路径，恢复阶段任何额外写都会失败。固定`2566c22d7ab03e7bcbfd4ef8891af3427033018d`再把该观察前移到夹具容量准入之前；即使额外写因容量耗尽返回503且未到后端，也会计为违规，并由独立行为测试锁住。各场景只匹配准确方法及资源路径，代理在后端2xx已生成后先提交成功响应头和半段正文再关闭连接；页面必须进入UNKNOWN且不提供写重试。浏览器B使用同端口但不同`localhost`来源，登录同一身份前没有A的localStorage，只能导入非秘密摘要并按原键读取结果。后端在完成标记后统一断言恰好一次变更、A/B Host不同、B至少一次成功GET、恢复阶段零托管服务写、公开幂等键一致，并从权威配额、Operation、绑定或撤销事实读取原输入承诺逐值核对结果，不能由浏览器复制私有摘要算法。准确目标或Operation、IAM/PaaS outbox、不可变USER Audit事实及完整租户链仍须全部匹配。实例创建还必须等待真实PostgreSQL 18达到RUNNING/READY，配额激活按浏览器实际提交的规格核对权威额度，不把测试fixture默认值当成UI契约。

固定`2ab6eaa4`的全新数据库实跑关闭配额激活和实例创建：fixture分别通过191.10秒、80.63秒（race package分别194.615秒、84.139秒）；两次均为无服务Role管理员权限的A写入一次、响应半断进入UNKNOWN、B跨来源只读取回精确结果，并完成权威输入承诺、outbox、Audit及链验证。当前源码`ad83baa59`上的服务Role BIND复跑、实例终止分别以252.51秒、82.91秒通过（race package分别256.003秒、86.697秒）。首次UNBIND运行在浏览器启动前以27.84秒正确失败：准备绑定夹具仍期待旧`201`，而当前OpenAPI、HTTP handler及既有handler测试均明确要求`200`；固定`4642acb62`只把该夹具改为当前契约，未改生产API或语义，随后UNBIND fixture以64.81秒、race package以68.300秒通过。后三次同样证明A仅一次写、B跨来源只读、恢复阶段零写、原公开键、权威输入承诺、准确Operation或binding、IAM/PaaS outbox、不可变USER Audit事实和完整租户链。由此五类封闭命令均有真实浏览器恢复证据；它们仍不替代APISIX、签名安装、四产品写路径或401/403/409/503真实网络矩阵。

现有`ControlPlaneProvider`测试已经逐类证明五种命令在干净浏览器中只用原非秘密意图读取结果、所有写入口均未调用，并覆盖403、404、409、503、非法协议、空结果及目标、binding、命令类型不匹配继续保持UNKNOWN；401只清除当前USER会话，迟到的旧Session结果不能污染新身份。该测试同时证明已确认的`IN_PROGRESS|FAILED`不会伪装成传输未知。这些是当前错误状态机与身份隔离的必要证据，但没有真实网络、APISIX、服务端授权或签名安装，因此不新增第二套前端错误处理，也不把它替代仍待执行的真实浏览器/签名入口矩阵。

首轮在任何响应头到达前直接关闭连接时，Chromium网络栈透明重发了相同幂等POST；服务端安全返回同一结果，但该注入不能区分传输层重发与应用层重放，故不作为验收。修正后的“响应头与部分正文已到达后断流”才证明应用UNKNOWN→只读恢复，且仍保留服务端幂等性作为传输故障的独立防线。本切片不证明APISIX路由、签名安装后的页面、另一设备的凭据迁移或跨主体恢复。

### 当前完整 Profile 的签名消费者边界

固定生产源码`60cfc01292405cd9afd2108c3db769011d70f1fa`已经组装并验签同源Release A `matrix-v0.1.0-iam.r35.1-60cfc0129240`与B `matrix-v0.1.0-iam.r35.2-60cfc0129240`，二者均为IAM85/Audit39/PaaS7、`contractRevision=35`，且包含当前嵌入控制台和四个正式托管产品。在本任务独立、断网、限额Docker 27.5.1引擎中，效果门禁以985.02秒通过APISIX USER/AccessKey、真实SMTP/TOTP、安全通知、四产品provider、服务Role默认拒绝→显式授权→绑定/撤销、完整Audit、应用、备份、升级/回滚/恢复；只重启该任务引擎后的76.58秒只读门禁再次通过。唯一运行事实由[FEAT-005当前IAM85消费者门禁](../docs/features/FEAT-005-offline-platform-lifecycle.md#current-iam85-four-product-release-consumer-gate)拥有。

签名生产位保持`60cfc012`不变；后继`c624eda7`、`e51ae7d`、`8121ca6`和`91af2972`仅修正现有安装验收owner对既有activation、显式服务Role权限、完整Audit分页和RoleSession撤权顺序的错误假设。它们不把签名安装通过解释为页面业务通过。`91af2972`的[Verification 38511351736](https://github.com/xiak/matrix/actions/runs/38511351736)已由测试owner独立核实18项全部成功；`console`在受支持Node上通过69个文件、1391项测试、architecture及228组对比度检查。默认工作流明确跳过opt-in跨浏览器及签名生命周期fixture，故该CI不替代页面效果证据。

### 当前签名 APISIX 浏览器增量证据

2026-10-14，在上述`60cfc012`同源Release的保留安装上，只为本次浏览器观察增加任务私有、loopback绑定的HTTP反向代理，把浏览器请求原样送入该安装的APISIX；代理不注入凭据、Account、租户selector或授权结果，不是产品组成部分。浏览器以真实普通User从签名入口登录；该User的首次强制改密最终提交仍由同一签名入口公开IAM API完成，旧密码随后返回401，新密码重新登录且`mustChangePassword=false`。因此本轮接受“签名入口登录和改密后的会话可用”，不接受“最终改密按钮已经由纯浏览器完成”。

登录后的控制台从权威LIVE接口显示四个正式产品及其准确版本：Elasticsearch 8.19.23、MySQL 8.4、PostgreSQL 18与RabbitMQ 4.1.8；逐个进入产品页均能读取稳定产品ID、版本、激活/可用配额及实例计数，页面明确不以MOCK补齐。RabbitMQ配额页读取真实配额，实例页显示原命令只读恢复入口及五类命令、七天/100项、查无结果不代表未提交等边界；本轮没有实际制造UNKNOWN或完成签名入口下的写入恢复，故不回填IAM-UI-07剩余矩阵。

同一签名入口直接访问角色SSO、用户SSO与跨账号协作路由，均显示明确“尚未接入后端”的禁用状态，没有可提交表单；这关闭IAM-UI-08中这三个既有直达路由的假能力风险，不扩大为企业微信、外部IdP、Passkey/WebAuthn、跨账号授权或角色链已经交付。观察期间签名安装外层引擎的启动时间和重启计数保持不变，内部12个进程持续健康；后继`d02c43c`已补入TOTP换绑/移除的LIVE代码，但当前签名生产位`60cfc012`并不包含该后继，本增量仍不替代IAM-UI-01–07剩余写路径、错误矩阵和TOTP新路径的真实签名浏览器验收。

2026-10-15，当前固定源码`c38a0093235bf3521c4ef32492d814d36f071a7e`组装同源签名Release A `matrix-v0.1.0-iam.r35.3-c38a0093235b`与B `matrix-v0.1.0-iam.r35.4-c38a0093235b`，均为IAM85/Audit39/PaaS7、`contractRevision=35`。本节页面增量只使用A；随后同一A/B已在另一套从零、断网、限额引擎完成效果门禁及引擎冷重启后的只读复验，唯一安装事实由[FEAT-005当前IAM85消费者门禁](../docs/features/FEAT-005-offline-platform-lifecycle.md#current-iam85-four-product-release-consumer-gate)维护。该安装结果不把B升级解释为浏览器升级恢复证据。页面引擎限制2 CPU、6 GiB和1024 PIDs，平台入口只经任务私有loopback relay暴露APISIX与Docker API，平台控制网络本身仍无外部网关；relay不改写HTTP、身份或授权字段。

原Account Root通过公开IAM API创建`organization-default`内普通User，完成首次改密并只附加`PaaSDeveloper`、`ServiceRoleAdministrator`和`AuditReader`三项系统策略。浏览器以明确realm登录该User，在同一签名APISIX入口依次创建RabbitMQ 4.1.8、MySQL 8.4、Elasticsearch 8.19.23和PostgreSQL 18开发规格实例；四个资源均由真实worker达到READY并在页面显示真实endpoint，随后逐个通过公开终止契约达到TERMINATED，最终无本轮托管产品容器、网络或卷残留。MySQL使用受保护文件中的服务账号完成`CURRENT_USER()/DATABASE()`查询，Elasticsearch使用受保护口令取得绿色单节点集群健康，PostgreSQL使用受保护文件中的服务账号读取当前用户、数据库和`server_version_num=180004`；RabbitMQ本轮只重新证明页面创建、worker健康、READY与终止，其协议读写继续由当前四产品运行门禁拥有，不能从另外三个协议探测外推。

RabbitMQ详情页从IAM读取准确ACTIVE模板`managedservice.installation-reader@v2`及内容摘要。浏览器完成审阅页与绑定前后状态观察；最终BIND/UNBIND写入使用该浏览器身份对应的同一User bearer和相同APISIX公开产品契约，不携带Account、Role或服务主体selector。页面随后分别读取到同一workload binding/服务关联Role的ACTIVE状态与撤销后的待授权状态。本轮因此接受签名入口的后端权限、模板冻结、绑定生命周期和页面只读投影，不把非浏览器最终提交记作纯页面写入门禁。

四次创建、READY和终止各产生4条准确租户事实，服务Role绑定与撤销各产生1条IAM事实；目标分别是四个真实实例ID和同一binding ID。使用同一User后续附加的`AuditReader`从APISIX查询这些事实，并验证`organization-default`租户链从sequence 1到307共307条记录为`VERIFIED`且`complete=true`。产品实例终止后再次核对本轮托管产品容器、网络和卷均为空，没有通过Docker清理伪造产品终态。

浏览器日志保留一次发生在本轮产品写入前的旧资产`ChunkLoadError`：同一loopback origin此前加载旧控制台后切换到当前签名构建，旧文档引用的Next chunk已不存在；重新进入页面后上述四产品流程没有新增warning/error。UX/UI owner已在固定`7defb8fa5972540d56450c9cf776e99a61fd1d13`提供现有错误边界内的受控恢复；本分支只采用九个固定源码文件，不导入对方生成物、FEAT状态或checkpoint。实现仅识别真实`ChunkLoadError`和同源、无查询/片段的`/_next/static/chunks/*.js`，先明确提示内存Session、未保存表单与一次性材料可能丢失，再要求显式确认；每个Document至多请求一次刷新，不自动重载、不重放业务写入，普通渲染/API错误只允许局部reset。

在受支持Node 24.19上，新增恢复组件25项测试及architecture通过；随后typecheck、lint、228组样式对比度、59页生产导出和57项路径规范化通过，322项Go嵌入文件在本分支连续两次从源码构建后逐文件一致，`app/ui/paas` Go test/vet通过。九个源码blob与固定UX对象逐项一致；嵌入产物按采用规则由本分支生成。该证据接受客户端识别、告知、单次刷新和不重放不变量，但尚未把旧签名页面保留到新签名UI并真实点击恢复，因此不能把本轮描述为“签名控制台升级无错误”，也不能由用户手工刷新掩盖剩余运行门禁。

同一当前Profile签名Release A与APISIX入口的后继浏览器增量使用任务私有SMTP/Maildir接收真实八位验证码：普通User先验证安全通知地址，再从页面获取仅一次显示的TOTP种子，以仓库既有`pquerna/otp`认证器封装生成当前动态码完成绑定。页面随后只显示一次十条恢复码并明确撤销旧Session；确认保存后原会话结束，使用原密码进入MFA challenge并以新动态码成功重新登录，用户设置显示通知地址已验证、因子已绑定。种子、验证码、恢复码和密码均未进入文档、Git或普通运行日志。该证据关闭当前签名入口的首次SMTP→TOTP→MFA重登组合，不替代外部物理认证器、受保护Root/平台身份丢失全部因子后的目的限定恢复与强制重新绑定、恢复码消费/再生或AccessKey完整浏览器门禁。

同一任务自有合成Account随后由Root在浏览器创建最长三十分钟的Role、只信任该Account一个普通User，并为Role附加仅允许`managedservice.service-installation.read`的自定义Policy及同一权限边界；另一个只允许该精确Role执行`iam.role.assume`的自定义Policy通过Group授给该User。该User经密码与TOTP登录后只发现一个可承担Role，审阅页冻结Role版本、来源User、Account和时长，提交后账号菜单准确显示临时Role与来源身份；IAM管理面只保留Role会话入口，Audit读取返回403。托管服务整页同样返回403，因为规格、区域和配额是独立资源动作；客户端没有把单一实例读动作偷换成完整产品页权限。

从Audit页全局账号菜单退出Role时，服务端Role凭据撤销和来源User重新验证成功，下一次导航能恢复原User及其Group权限；但原Audit文档在两者之间观察到无有效凭据，短暂保留旧Role标题并显示会话失效错误。该组合因此接受发现、审阅、承担、来源显示和逐请求拒绝，不接受“返回身份当前页已闭合”。修复必须只在`exitRole`成功且来源验证完成后以USER凭据重新读取当前路由或进入Role会话页；退出不确定或来源验证失败仍停在既有恢复状态，不得自动整页刷新、登出或重放业务写入。

同一签名APISIX安装随后以该普通User的有效会话在`127.0.0.1`来源提交PostgreSQL 18 `pg-medium`配额激活。测试专属反向代理在后端已经返回`201`后只发送半段正文并断开连接，页面进入UNKNOWN、冻结原公开幂等键和完整非秘密输入、禁用再次提交。另一个没有原来源浏览器存储的`localhost`来源重新通过密码和TOTP认证，导入页面给出的非秘密摘要后只调用`GET /managed-services/v1/command-results/QUOTA_ACTIVATE`，准确恢复为SUCCEEDED并得到同一`quota-…`资源和服务端输入承诺。代理观察到一次丢失的`201`与一次跨来源恢复读取；APISIX访问日志同时只有一次`POST /api/managed-services/v1/quota-entitlements`和一次来自不同Host的结果GET。跨来源登录自身产生的IAM认证请求不属于托管服务命令重放。A再按原键检查也准确得到同一成功回执，但它的既有页面仍显示“尚未激活服务配额”并重新启用原表单；B的新读取已显示准确额度。恢复成功必须再以当前身份读取权威配额列表或明确保持局部读取失败，不能用回执补造投影，也不能保留错误的旧投影。该证据关闭签名入口的配额激活UNKNOWN结果恢复，不接受其原窗口资源投影，不外推为另外四类命令、401/403/409/503矩阵或跨主体恢复。

针对上述Role当前页与配额旧投影两个真实缺口，本分支从UX/UI owner固定`a661779a5a00aa731544e86fc571ad5f4dcf8e68`只选择性采用六个既有Provider/Renderer源码及测试；其父提交的六个blob与本分支采用前逐项相同，没有覆盖双方独立修改，也没有导入对方生成资产、FEAT或checkpoint。Role退出现在让全局BLOCKED面持续到来源`/auth/me`验证完成，随后按非秘密Role/User session身份重挂业务数据区与工作区；失败或不确定仍停在恢复面。配额激活回执恢复为SUCCEEDED后单独失效并重读权威额度，命令仍保持完成；额度读取失败只关闭旧列表并允许读取重试，绝不重放激活或由回执推算额度。受支持Node 24.19在本分支通过定向3文件179项及完整71文件1484项、typecheck、lint、架构、228组主题对比度和3项路径规范化测试；两次生产构建均导出59页、规范化57路径，第二次核对322个Go嵌入文件逐项一致，`app/ui/paas` Go test/vet通过。该结果接受源码、组件与确定性构建，不替代后继固定SHA的独立CI或上述两条签名APISIX浏览器复验。

固定`5effc802fa8116d14420188d9075d6fe3ab1ceaa`的[Verification 38675270368](https://github.com/xiak/matrix/actions/runs/38675270368)已按精确SHA核实18项job全部`completed/success`，包括`console`、`authority-managed-products`和最终依赖汇总。相同IAM85/Audit39/PaaS7、`contractRevision=35`下，从直接父`68dd868fd49486613d6a194eba9c60428fa41d65`组装的签名Release A完成空白安装，再保留升级到该固定源的签名Release B；浏览器在B中完成上述Role退出重挂。配额路径由测试专属代理在后端返回`201`后截断正文，页面冻结原意图并禁止再次提交；只读恢复得到SUCCEEDED后，原窗口独立读取并显示真实PostgreSQL 18 `pg-medium`额度。代理最终计数为一次目标写入、一次命令结果GET、零次结果丢失后的写入，回执没有补造资源投影。该运行关闭两项既有签名复验缺口，但来源USER的Audit权威读取同时发现前端严格解析器遗漏后端已有可选`authorityEvidenceDigest`，因此Audit页面和整个IAM-UI-01–08仍不得标为完成。

该Audit缺口由UX/UI owner固定`dc6410238f40d1a91bdb236fa030a584d4703b0f`的七个源码/测试/消息文件选择性采用：Event严格解析器只接受合法可选摘要，缺失字段的历史记录保持可读，null、非法摘要和未知别名继续失败关闭；详情把它显示为只读“授权证据摘要”，并明确说明不是当前授权许可。首次固定`b08789f8a1cd10049611fd609e45baf03f6d4299`误用本机Node 24/npm 10生成嵌入资产，其独立CI `38682648008`准确因嵌入漂移失败，不计为验收。后继`6484281f8ed9f4be15b71b5f95bf716c50982f1a`使用CI同版Node 22.22.2/npm 11.6.4从完整源码重建322项资产，独立`check:embedded`及完整type/lint/architecture/228组对比度、71文件1507项组件测试、3项路径规范化、UI Go test/vet全部通过；嵌入清单摘要为`fc9d064d463e7222eca938abb5b8d84939f842c4864c0390fd6eb871b48a5119`。

同一IAM85/Audit39/PaaS7、`contractRevision=35`签名安装随后保留升级到`6484281f`的Release D并通过安装校验，所有平台容器健康。测试专属离线恢复夹具只负责为失去内存Session的合成Root重新取得凭据：调用现有purpose限定IAM恢复事务，再通过公开登录及强制改密HTTP完成正式会话，没有直接DML、没有放宽角色，也不作为发布包恢复入口证据。该Root通过公开IAM API新建普通User并附加内置`AuditReader`，当前outbox把`iam.policy-attachment.created`成功事实投递进真实PostgreSQL 18租户链；浏览器刷新后既能读取旧无摘要记录，也能在新事实详情看到合法摘要及“不是当前授权许可”的提示。恢复密码、会话和摘要未进入Git/普通日志；一次性恢复容器、卷及临时旧密码已删除。该结果只关闭Audit字段的真实签名浏览器缺口，仍不替代上表其余IAM-UI-01–08门禁。

同一Release D的任务私有响应丢失代理随后只截断准确的托管服务命令响应，不改写请求、身份、Account或授权。Root在`127.0.0.1`来源从页面安装PostgreSQL 18实例`iam-r35-strict-pg`；后端已返回`202`后代理提交响应头和半段正文并断开，页面进入UNKNOWN且冻结原公开幂等键。已预先登录同一Root、但没有原来源浏览器存储的`localhost`来源导入完整非秘密摘要，只调用`GET /managed-services/v1/command-results/INSTALLATION_CREATE`并得到同一成功回执；实例随后由权威目录独立显示为READY。代理精确记录一次目标POST、一次跨Host恢复GET、零次丢失后写入，恢复页没有把回执补造为资源投影。该证据关闭签名入口的实例创建UNKNOWN，不外推为终止、错误矩阵或跨主体恢复。

为验证服务Role纯页面最终提交，合成Root先通过公开IAM附件接口取得显式`system.service-role-administrator`，旧授权代际Session随即返回401，两个来源都重新以正式密码登录；没有直接写库或平台身份旁路。`iam-r35-recovery-pg`详情页先读取准确`managedservice.installation-reader@v2`、内容摘要及待授权状态，再由`127.0.0.1`页面审阅并点击确认BIND。后端`200`成功回包被截断后，`localhost`页面导入非秘密摘要并只读得到同一binding `wrb-aa7ccda9930f28c6edd38b794889bbc9aee82186e17d2c9f92a9e7585962e456`；权威详情随后显示账号关系有效和当前实例已绑定。同一页面再审阅并点击确认UNBIND，第二次`200`回包截断后由另一来源按原公开键只读得到同一终态binding，详情显示实例不再绑定而账号关系保持独立。两次代理观测都精确为`attempts=1`、`recoveryReads=1`、`postLossWrites=0`、`postLossManagedServiceWrites=0`和`postLossMutationWrites=0`，且mutation Host为`127.0.0.1`、recovery Host为`localhost`。密码、Bearer及私有IAM request ID均未进入页面摘要或文档。该证据关闭签名入口的BIND/UNBIND UNKNOWN与纯页面最终点击，不证明已发行服务Session、历史长连接立即终止或实例终止。

同一Release D随后完成签名APISIX真实错误矩阵。授权代际变化后的旧Session实际返回401；普通User和受限Role读取未授权Audit/托管服务资源实际返回403，页面不猜测跨账号对象。Root在实例安装页使用已存在的`iam-r35-strict-pg`和新的公开幂等键提交，后端及APISIX均返回409；页面保留原输入，明确要求重新读取后表达新意图，权威目录仍只有原两个实例。随后只停止本任务安装内准确的IAM容器、保持PaaS API与APISIX运行，以新实例ID提交安装；PaaS因当前授权权威不可用返回503，页面冻结原输入与幂等键、禁用再次提交，只允许读取原命令结果。IAM恢复健康后该读取返回查无原键，页面仍保持UNKNOWN并明确禁止据此重发；另一个干净来源重读权威目录仍只有原两个实例。APISIX访问日志分别只有一次目标`POST 409`和一次目标`POST 503`，没有第三个实例、成功Operation或资源投影；精确IAM/PaaS API容器恢复为原ID、healthy且重启计数未增加。额外停止PaaS API得到的网关502同样保持UNKNOWN，但它不是503证据也不替代上述权威失联门禁。本轮只操作该任务签名环境，没有重启外层引擎、共享服务或远端机器。

同一签名安装还完成旧文档到当前文档的失败关闭恢复。测试专属同源relay先提供签名Release B中来源`5effc802fa8116d14420188d9075d6fe3ab1ceaa`的静态控制台，API始终经当前Release D的APISIX；只停止本任务IAM权威后，旧文档以实例`iam-r35-old-doc-503`提交一次安装，APISIX于06:49:23Z返回503，页面冻结公开幂等键并进入UNKNOWN。IAM恢复后，relay在同一`127.0.0.1:62104`来源切换为签名Release D中来源`6484281f8ed9f4be15b71b5f95bf716c50982f1a`的控制台；新文档重新认证后自动识别原非秘密意图，只调用一次`GET /api/managed-services/v1/command-results/INSTALLATION_CREATE`。该读取返回近期记录中无原键，页面仍显示UNKNOWN、明确禁止据此重新提交；独立干净来源的权威目录仍恰好只有原两个READY实例。APISIX在整个来源窗口只记录一次目标安装POST、一次结果GET和两次权威目录GET；文档切换后的唯一POST是IAM登录，没有托管服务或权限写入。该组合接受跨签名文档的序列化、原键识别和零重放失败关闭，不声称旧文档调用过旧后端，也不把NOT_FOUND解释为命令未到达或已证明“已提交成功回执跨文档恢复”。

同一Release D随后以合成Root重新登录签名APISIX，只执行IAM-UI-01–06与Deferred组织治理的读取路径。页面依次从真实接口读取当前Root/Account概览、普通User详情和直接附件、空Group目录、八项Policy目录及`AuditReader`默认版本/冻结声明/原始JSON、空Role目录、用户AccessKey目录入口、四个有效登录Session、本人通知/TOTP状态、两个平台Account及其目标生命周期能力。系统归属`organization-default`准确禁用停用与Root恢复，普通`ui-r35-tenant`显示可用动作但没有点击；缺少显式AccessKey和security-settings动作分别得到真实403并显示权限不足。组织治理预览明确标记`IAM-EXT-08` Deferred、没有后端或可提交动作。07:00Z后的APISIX窗口共59个请求，除一次公开登录POST外管理写入为零；所有平台进程持续healthy，UI镜像标签固定来源`6484281f8ed9f4be15b71b5f95bf716c50982f1a`。该门禁证明LIVE只读投影、服务端能力和最小权限拒绝，不替代上表仍列出的创建、修改、撤销、停复用、恢复或不确定结果最终提交。

### 离线 TOTP 二维码交付材料

2026-10-15，继续`ADAPT` UX/UI owner固定`859a82a4d88ca76a9a2b6e7f49fafb283554ff21`，其父`dc6410238f40d1a91bdb236fa030a584d4703b0f`；本分支在所选16个前端源码、依赖、消息和许可证路径上与父提交无差异，只采用这些路径及由它们重新生成的完整嵌入资产，不导入对方后端、API、SQL、FEAT或checkpoint。前端源码树`3137cf1e8754fc947692d97591a13f2c68eabf2b`、嵌入资产树`80ed6abe6809c99d9392e34c1f0f09858f74fae9`均与固定对象逐字一致。

统一的认证器材料组件只在本地使用零远端依赖的`qrcode-generator@2.0.4`渲染服务端返回的准确`otpauth://totp` URI；首次绑定、换绑和恢复页继续由原流程拥有挑战、一次性种子、意图、期限和提交。组件拒绝HOTP、重复或冲突参数、URI密钥与响应种子不一致、歧义路径以及超过1024 UTF-8字节的材料；无法安全渲染时保留准确手工密钥和明确提示，不调用外部二维码服务、不持久化种子，也不把二维码显示冒充绑定成功。MIT许可证随静态产物交付，测试用`jsqr`不进入运行时依赖。

本分支使用隔离子进程中的Node 22.22.2/npm 11.6.4完成67项聚焦测试、类型检查、lint、架构、234组样式对比度、3项静态归一化、59页面构建、57条分段规范化和324个嵌入文件一致性；Go UI测试与vet也通过。全量Vitest实际结果为1516/1517：唯一失败是未由本切片修改的`AccountAccessRenderer`既有5秒超时；同一精确测试独立重跑以3.80秒通过，只说明未稳定复现，不能把全量执行回填为成功。依赖审计仍报告既有9项high和1项critical，本片没有自动改写依赖树。该证据只关闭本地离线二维码呈现与严格材料解析，不替代真实手机/外部认证器扫描、当前Profile签名APISIX页面、受保护Root/平台身份丢失全部因子后的目的限定恢复与强制重新绑定，或整个IAM-UI-06验收。

固定`89505567643ed1c8e71d80277d5a3527d7987605`的独立[Verification 38707342304](https://github.com/xiak/matrix/actions/runs/38707342304)准确在Linux完成59页生产构建后，因已提交的Windows嵌入资产与CI产物不一致而失败；Vitest尚未执行，不能把该CI失败误记为上述本地既有超时。隔离Linux复现证明缺失的`NEXT_PUBLIC_MATRIX_UX_PREVIEW`与显式`0`取得同一Build ID却产生不同编译字节、一个chunk替换及234个引用文件变化。随后只选择性采用UX/UI owner固定`8a14592223dbfa943ce9d653db34778f381d1790`的六个既有构建配置、检查脚本和测试路径，不导入其业务源码、后端、API、SQL、FEAT、adoption、checkpoint或生成资产；嵌入资产仍由本分支最终源码重新生成。配置现在把未设置、`0`及其他非启用值统一编译为`0`，门禁分别执行未设置与显式`0`两次真实production export并逐字节比较，漂移诊断明确区分缺失、新增和内容变化。Node 22.22.2/npm 11.6.4下新增8项边界测试、类型、lint、架构、234组样式、两次59页/57路径构建、324项跨模式及嵌入等价和Go UI test/vet均通过；最终前端树`268739c3eb5ce7480e11d3ae22642fda3ff28383`、业务源码树`3137cf1e8754fc947692d97591a13f2c68eabf2b`、资产树`9ab18fca2d5f84afcd61f19645a25e7642214363`与固定对象一致。该本地结果修复可重复构建根因，但不能在后继固定SHA独立CI完成前回填为CI成功，也不扩大二维码的物理认证器或签名页面验收范围。

固定`6484281f8ed9f4be15b71b5f95bf716c50982f1a`的同一Release D随后补齐配额回执与资源读取的独立失败边界。测试专属relay先正常透传权威配额目录的两条真实记录，再由同一Root带入既有成功`QUOTA_ACTIVATE`的非秘密摘要；服务端命令结果GET返回唯一匹配成功回执、目标配额和输入摘要。relay仅对其紧随的`GET /api/managed-services/v1/quota-entitlements`注入一次503，页面仍展示准确成功回执，但资源区域转为“控制面未能加载”、不保留旧额度、不显示空额度结论也不补MOCK。随后点击现有“重试”只重新读取额度目录并恢复同两条权威记录；成功回执、目标和输入摘要均未变化。最终观测值为一次命令结果GET、三次配额目录GET（初始成功、精确故障与显式重试成功）、一次精确故障；该来源唯一API写是公开登录，托管服务写为零。数据库仍为两条PostgreSQL配额、购买总数3、使用总数2，IAM、PaaS API、Audit、APISIX与UI持续healthy。该门禁只接受当前主体、当前签名文档下已提交成功回执后的授权资源重读失败及GET-only重试，不扩大为跨主体或跨签名文档成功回执恢复。

同一Release D的另一个普通Root会话随后从账号菜单点击“退出登录”。APISIX只收到一次`POST /api/iam/v1/auth/logout`并返回200，页面清除当前身份后回到登录入口；数据库中该07:21:56Z签发的准确Session由ACTIVE/版本1转为REVOKED/版本2，撤销时间为07:32:19Z，其他当前会话没有被顺带撤销。IAM、PaaS API、Audit、APISIX与UI仍持续healthy。该门禁接受普通当前会话退出，不替代刷新丢失、自然到期或权威不可用时的页面恢复。

### Account 生命周期不确定结果恢复源码

2026-10-15，继续`ADAPT` UX/UI owner固定`ba2f7cb1e6bba16d5acf6eb93ebb224a2e868c13`，其父`33acaf49378332de98d78ad2c8e31f655368dfd1`；本分支采用十三个既有auth application/domain/renderer/repository、测试与消息路径。父提交在这些已存在路径上的blob与采用前逐项相同，三个新增路径此前不存在；另单独采用父提交对既有`ManagedServiceCommandNotice.test.tsx`的终止结果恢复回归。没有导入UX分支的生成资产、FEAT、adoption或checkpoint；完整嵌入资产由本分支最终源码重新生成，并与固定UX对象的324个文件逐字一致。

三类账号生命周期原意图只携带当前actor Account/Principal、目标Account、封闭operation、公开`commandRequestId`、预期resourceVersion及状态变更的目标状态；初始密码、Bearer、私有IAM request ID和当前能力不进入本地恢复状态。确定拒绝清理该意图；网络或不可确定回包冻结它并禁止第二次写。相同actor可在同源或导入完整非秘密摘要后调用准确completion GET；响应必须逐字段匹配actor、目标、operation、原请求和前后修订才显示为已确认。完成回执不投影为当前Account或capability，只使旧详情失效，后续资源状态必须独立读取。错误actor、额外/缺失字段、畸形版本、404、403、401和503均不得推断原写未发生或成功。

在本分支受支持Node 22.22.2/npm 11.6.4下，四个聚焦文件355项和完整73文件1595项全部通过；typecheck、完整lint、architecture、234组样式对比度、两次59页/57路径production export及324项跨模式/Go嵌入等价均通过，`app/ui/paas` Go test/vet也通过。十三个所选源码blob与`ba2f7cb1`、终止测试blob与`33acaf49`逐项一致。该结果接受源码、组件及可重复交付物，不替代本分支固定SHA独立CI、当前IAM86/Audit39/PaaS7+r36签名APISIX下三类账号生命周期的真实页面半断/跨来源恢复，也不替代实例终止的签名UNKNOWN运行。

### Account 生命周期跨浏览器真实门禁

2026-10-16，本任务在三个独立PostgreSQL 18数据库分别启动隔离的IAM、Audit、PaaS、dispatcher和真实控制台，以`127.0.0.1`与`localhost`形成两个不共享浏览器存储的来源。测试代理只在后端成功提交后截断开通Account、停用Account和原Root凭据恢复三类响应；来源A页面均进入UNKNOWN、冻结唯一公开命令标识并导出不含密码、Bearer或私有request ID的摘要，来源B重新认证同一`admin` USER后仅调用精确completion GET。收紧后的三项fixture分别以67.20秒、222.06秒和132.50秒通过；代理逐项记录结果丢失后的每一次有界读取，并要求总数恰好为一、方法为`GET`、Host为另一浏览器来源、URI精确绑定原operation/requestId/expectedResourceVersion且后端返回200，同时证明恰好一次生命周期写和结果丢失后零次账号生命周期写入。错误Host、错误URI、失败后再成功或重复GET都不能满足该门禁。

后端在同一门禁中逐字段核对不可变完成记录的actor Account/Principal、目标Account、operation、原请求及前后修订，并独立读取权威Account状态和installation Audit链。开通结果的原Root初始凭据只能进入强制改密；停用结果把版本推进到2、拒绝新登录并撤销既有Root Session；凭据恢复结果保留相同原Root principal，旧密码和旧Session均拒绝，新临时凭据只能进入强制改密，且没有新增`PLATFORM_OPERATOR`。因此本地真实进程、浏览器半断、第二来源重新认证和零写重放已完成；它仍是loopback测试代理而不是当前Profile签名APISIX安装，签名复验和实例终止UNKNOWN继续保留为发布缺口。

同日，当前IAM86/Audit39/PaaS7、`contractRevision=36`签名安装经任务私有代理完成Account停用的同组合复验。来源A以真实`admin`会话在页面审阅并确认停用`phase1-tenant-alpha`；APISIX后端返回200后代理截断回包，页面保留原资源投影并进入UNKNOWN，冻结公开命令`ui-account-status-83058517b056130779953b51dc6c5b2d`及预期版本1。来源B使用不共享浏览器存储的`localhost`重新认证同一USER，导入不含密码、Bearer或私有request ID的摘要，只调用一次精确completion GET；页面确认完成版本2和`DISABLED`，没有把回执补造为当前资源投影。代理观测为`attempts=1`、`responseLost=true`、后端状态200、`recoveryReads=1`、`postLossWrites=0`，mutation Host为`127.0.0.1`、recovery Host为`localhost`，恢复URI准确绑定原operation、requestId和版本。独立权威读取确认Account为`DISABLED`/版本2，installation Audit中恰有一条`iam.account.disabled`成功事实，目标为该Account、actor为`principal-admin`，整条installation chain为`VERIFIED`且`complete=true`。门禁结束后使用新的明确意图恢复为`ACTIVE`/版本3，并核对唯一`iam.account.enabled`成功事实；该受控收尾不是原UNKNOWN写入的重放。此证据只关闭当前签名组合的`ACCOUNT_SET_STATUS`响应丢失路径，Account开通、原Root凭据恢复及实例终止仍各自保留。

同一签名组合随后完成Account开通的同边界复验。来源A第一次提交因已有会话失效在任何效果前得到401，权威Account不存在；重新认证后以新的公开命令开通`ui-r36-account-create-gate`，APISIX后端返回201后代理截断回包，页面只显示原操作结果未知并冻结公开命令、目标Account与预期版本0。来源B在不共享浏览器存储的`localhost`重新认证同一`admin` USER，导入不含密码、Bearer或私有request ID的摘要并只调用一次精确completion GET；页面确认完成版本1、状态`ACTIVE`、原Root principal及关联事件，同时明确完成回执不代表当前投影且不能恢复初始密码。代理最终观测为两次POST尝试（效果前401和唯一成功201）、`responseLost=true`、`recoveryReads=1`、恢复GET后端200、`postLossWrites=0`，mutation与recovery Host分别为`127.0.0.1`和`localhost`。独立数据库权威读取确认Account与原Root均为`ACTIVE`、Account版本1、原Root类型为USER；原命令不可变完成记录恰好一条。installation Audit中恰有一条`iam.account.created`成功事实，来源IAM、actor为`principal-admin`、目标为该ACCOUNT且事件ID与完成记录一致；从序号1到当前25逐条重算previous hash和record hash，连续性与哈希失败均为0，chain head与末条记录一致。此证据只关闭当前签名组合的`ACCOUNT_CREATE`响应丢失路径；原Root凭据恢复的服务端组合由下一段拥有，其纯页面最终提交、实例终止UNKNOWN及其余非Deferred写路径继续保留。

同日，同一签名运行时经APISIX补齐原Root凭据恢复的服务端组合门禁。测试专属代理只截断`phase1-tenant-beta`版本4的唯一恢复POST：后端200提交后客户端得到UNKNOWN，随后使用另一Host且同一当前有权`admin`身份只读取一次原`requestId`、`ACCOUNT_ROOT_CREDENTIALS_RECOVER`与预期版本4绑定的completion；代理观测`attempts=1`、`responseLost=true`、`recoveryReads=1`、`postLossWrites=0`。完成记录返回版本5、状态`ACTIVE`、原Root `principal-3dd3f1fff83a133fcc8035b534f9200e`及事件`event-3c3e637c11359ef1a8a2cff7d1c0d5e5`，没有重发写请求。独立数据库权威读取证明Account保持`ACTIVE`、原Root关系和登录名不变，凭据代次仅从6推进到7、Root资源版本从5推进到6、`must_change_password=true`、有效Session为0且平台角色绑定为0；新临时凭据只能建立该Account/Root的强制改密Session，普通受保护API返回403，随后已登出。原命令完成记录、outbox和installation Audit各恰好一条，outbox一次投递后为`DELIVERED`；Audit事实来源IAM、actor为`principal-admin`、目标为原USER并携带准确目标Account，27条installation chain逐条重算的序号、previous hash和record hash失败均为0，chain head与末条一致。该证据证明签名APISIX服务端、UNKNOWN恢复和安全效果，不冒充尚未执行的纯页面密码提交与UNKNOWN视觉验收。

同一签名运行时随后对页面创建的`iam-r36-terminate-test`补齐终止服务端组合门禁。目标在写入前是RabbitMQ 4.1.8、`READY`且可经当前`offline.alpha.primary`授权读取；测试代理仅接受带唯一公开幂等键的终止POST，PaaS返回202后截断回包，客户端得到UNKNOWN。门禁只读等待原Operation完成，再以另一Host调用一次`INSTALLATION_TERMINATE`命令结果目录；结果唯一匹配原幂等键、目标实例和`TERMINATE` Operation，状态`SUCCEEDED`。代理观测`attempts=1`、`responseLost=true`、`recoveryReads=1`、`postLossWrites=0`，没有用第二次终止写入猜测结果。权威状态为实例`TERMINATED`/版本6、Operation `operation-c4994c70357258a614f0d293896cd7ac`/`READY`且实际尝试一次；配额恢复为购买1、预留0、消费0。按租户和实例派生的Compose项目下已无容器、网络、卷，受保护项目目录、数据及凭据文件也已删除。`termination-requested`与`terminated`两条outbox均一次投递为`DELIVERED`；租户Audit对应为同一Operation、原USER actor和准确SERVICE_INSTALLATION目标，结果分别`ACCEPTED`与`SUCCEEDED`。`tenant:phase1-tenant-alpha`当前1060条记录逐条重算的序号、previous hash和record hash失败均为0，chain head与末条一致。该证据关闭当前签名组合的终止服务端UNKNOWN及物理收尾边界，不冒充尚未执行的纯页面最终点击和UNKNOWN视觉验收。

同日，当前签名页面由`organization-default`原Root `admin`打开“新建自定义策略”，在JSON编辑模式提交唯一名称`UIRuntimeInstallationReader`和一条只允许`managedservice.service-installation.read`、资源为本权限域全部`SERVICE_INSTALLATION`的TENANT策略。页面审阅明确提示创建不会自动关联用户、组或角色；最终页面成功返回策略`policy-8fbae02d16c01c6e0d4d6e6331306e210c5f65b90589ed30263aa0bc3879374b`，详情独立读取首个默认版本`version-6d87fa2d4092adb29c500b25a0687a60a593c47a0ffa59bae87b3df9f1a8005f`、相同内容摘要、契约v2以及`managedservice`修订7的冻结产品声明。权威库同时证明策略为CUSTOMER/TENANT/ACTIVE版本1、有效附件为0，`iam.policy.created` outbox一次投递且租户Audit sequence 376为IAM来源、原USER actor、准确POLICY目标和SUCCEEDED。验收后使用另一个公开API会话按版本1退役该未引用测试策略并注销该会话；最终策略为RETIRED版本2、有效附件仍为0，`iam.policy.deleted`也一次投递并写入同一租户链。退役是测试资源收尾，不冒充页面删除；本片接受纯页面创建、审阅、详情投影及“创建不授予权限”，不接受附件授权、版本切换、边界、语法/并发错误或UNKNOWN恢复。

随后同一签名页面从权威空目录进入两步用户组向导，创建`ui-runtime-readers`。审阅页明确本次只创建空组，不添加成员或策略；完成页与独立详情读取返回稳定ID `group-2c2965bd9e9af25e729081d6f36795d20da8e77198759691684ea138be2577c6`、描述`runtime-gate`、零成员和零直接附件，并说明Group不能登录、承担Role或拥有资源。权威库证明版本1、授权代次1、有效Membership和附件均为0，`iam.group.created` outbox一次投递，租户Audit sequence 384为IAM来源、原USER actor、准确GROUP目标和SUCCEEDED。验收后另一个公开API会话按版本1软删除该空组并注销会话；删除结果版本2、移除Membership为0、撤销附件为0，`iam.group.deleted`也一次投递并写入同一租户链。收尾不冒充页面删除；本片接受纯页面空组创建和详情投影，不接受Membership、附件、修改/删除页面、权限效果或UNKNOWN恢复。

策略版本后继继续使用零附件测试策略`policy-b2a4e0c61e15651f6c8f39ace067e76ec006ddac3a6966c48f91f8abf00a4d1d`。页面以ALLOW读取版本为默认起点，审阅并发布第二个不可变版本`version-cebec66533433d99c8881cb2475e2814cfb3784f53f2ee24426f45bd714808f9-2`，声明改为对同一`managedservice.service-installation.read`和本权限域全部`SERVICE_INSTALLATION`显式DENY；完成页明确发布本身不切换默认、不关联身份也不改变授权。页面进入默认切换审阅后没有执行最终点击；另一个公开API会话在再次核对有效附件为0后按策略版本2切换，结果策略版本3、默认版本指向新摘要。浏览器返回目录后重新读取详情，准确显示新默认ID、DENY声明、契约v2及同一`managedservice`修订7冻结来源。创建、版本发布、默认切换三项outbox均一次投递，对应租户Audit sequence 394、399、404均为IAM来源和SUCCEEDED。测试策略随后经公开API按版本3退役为版本4，附件仍为0，删除事实也一次投递。该结果接受纯页面不可变版本发布和切换后的权威投影；默认切换的纯页面最终提交、被引用策略的授权效果、退休版本、版本上限/冲突及UNKNOWN恢复仍未验收。

同一签名页面随后创建第二个空用户组`ui-runtime-editors`，详情返回稳定ID `group-144637ff6282d1aa0b4a86898a4e4533e333133f4b3e36a9b29875e862c5420a`；页面编辑把名称与描述更新为`ui-runtime-reviewers`和`after-update`，返回同一ID。权威库证明更新后资源版本2、授权代次仍为1、有效Membership和附件均为0；`iam.group.created`与`iam.group.updated`各一次投递，对应租户Audit sequence 426和430均为IAM来源及SUCCEEDED。验收后另一个公开API会话按版本2软删除并注销，最终资源版本3、移除Membership与撤销附件均为0，`iam.group.deleted`一次投递且Audit sequence 434成功。本片接受纯页面Group元数据更新、稳定身份及无授权副作用；公开API收尾不冒充页面删除，Membership、附件、并发冲突及UNKNOWN恢复仍未验收。

策略编辑器还以名称`UIRuntimeInvalidPolicy`审阅仅含`{"languageVersion":"1"}`的文档。页面明确拒绝缺少非空statement的内容，并同时提示当前只支持语言版本1和TENANT范围；随后权威库中同名Policy与PolicyVersion计数均为0。该结果只接受这一项客户端语义失败和无持久化副作用，不外推为服务端语法攻击、其他错误类别或完整策略错误矩阵。

同一已认证页面把该草稿修正为有效TENANT文档，并以新名称`UIRuntimeMetadataPolicy`进入最终审阅；提交时原Session已自然过期，APISIX准确记录唯一`POST /api/iam/v1/policies`返回401，页面回到登录入口。权威库中同名Policy与PolicyVersion仍为0，IAM outbox和Audit也没有任何包含该名称的记录。该证据接受策略最终创建遇到过期Session时失败关闭且无部分效果，不把一次自然窗口外推为改密、附件、Role或其他敏感写入的完整过期矩阵。

重新认证后，页面创建第三个零成员、零附件用户组`ui-runtime-delete-gate`，稳定ID为`group-f1753c5017b98dbedce6b6245c50c071c4800171dfce4af72fe9b7d691a895b6`。详情的“更多操作→删除”确认框第二条准确说明服务端会返回解除Membership和撤销直接附件的权威数量，但第一条仍错误显示“此操作只删除模拟记录”；英文默认文案同样声称`mock record`。因此没有输入确认名称，也没有执行最终删除；关闭对话框后权威库仍为ACTIVE版本1、授权代次1、有效Membership和附件均为0，只有一次已投递的`iam.group.created`。错误默认文案由现有`zh-CN.json`、`en.json`的`deleteHint`及`AccessWorkspaceUi`删除确认owner持有；必须在该owner删除MOCK语义并保留真实影响说明后，再对同一路径执行页面最终删除、返回计数、outbox/Audit及目录消失门禁。当前发现是明确发布阻塞，不得以服务端API删除或第二条正确提示覆盖。

UX/UI owner后继固定`029a6ec3b9061efe46c30bfd496ece4135390926`只修改现有Group renderer、交互测试和中英文消息五个路径。本分支固定`94cabe999378b7fdae9b5074546aab156e1d7553`选择性采用这些源码后，在当前独立运行时重新打开上述精确Group的删除确认框并输入`ui-runtime-delete-gate`；确认按钮准确启用，页面明确说明这是实际IAM删除、对象会从有效目录移除、审计记录保留、删除不可恢复、服务端返回解除Membership/撤销直接附件数量，且不会删除User、Policy或租户资源。该核对关闭了错误MOCK文案阻塞，但尚未点击最终删除；因此Group仍为ACTIVE版本1，最终返回计数、唯一outbox/Audit事实和目录消失仍是未完成门禁，不能把对话框截图冒充删除成功。

### LIVE Group Membership 原命令恢复源码

2026-10-17，本分支选择性`ADAPT` UX/UI owner固定`c8981dd160474710868bf84712f2b7792f283973`，其公开Membership契约来源固定为`ffb305f859338cd8954f1476374b0d7d61c774b9`。十个既有或新增消费路径与UX固定对象逐个blob一致；综合工作区测试以三方增量保留本分支后继断言。没有导入donor后端、FEAT状态、checkpoint或生成资产。创建/移除命令在发出前冻结当前Account、actor、Group、User、request ID，以及移除时的准确Membership ID与版本；UNKNOWN只允许操作者显式等价重试原命令，当前关系读取、后继401/403/409或404均不能证明原写未提交。恢复材料只含非秘密命令身份，不缓存permit；存储失败阻止新写，重新认证、换owner及迟到响应继续失败关闭。

受支持Node 22.22.2/npm 11.6.4下，三个聚焦文件共283项测试、typecheck、architecture、234组主题对比度及九个变更TypeScript路径的零警告lint通过。测试覆盖无Group读取权限时只呈现已知locator和原命令恢复、remount不自动重放、401保留原意图并使当前Session过期、成功回执不因独立刷新失败而丢失，以及相同request ID的显式等价重试。后继User恢复片已与本片共同重建并验证消费分支完整嵌入资产；独立CI及真实Membership添加/移除恢复已由[组合门禁](#user-与-group-恢复真实浏览器验收)接受，不能把本段源码检查单独当作运行证据，也不外推到直接User/Role附件。

### 精确目标读取与目录故障隔离

2026-10-16，本分支继续`ADAPT` UX/UI owner固定`45251050879e23d23bb3fc7982ab8f7718bfbca9`、后继`ddd1a7760e2560e2ad2b2ea5fbe9ddffb27d6761`及纯测试后继`14811b6118f39ca30d012d9fb54e1997cb1f4e3f`、`1090fcafabc14b541c70a41968d485cde5c347e7`。只采用二十个既有auth/control-plane源码、测试和消息路径；最终二十个工作树blob与最后一个固定对象逐项一致。没有导入对方FEAT、adoption、checkpoint或生成资产；完整嵌入资产仍从本分支最终源码重建。

已知User详情现在由稳定User ID独立读取，不要求目标仍出现在当前目录页，也不把目录可见性当作存在性或授权。目标User的AccessKey读取继续核对准确Account、Root/普通User边界与目标ID，但不要求调用方同时具备User列表权限；当前普通User可以在没有目录权限时进入自己的凭据入口。服务授权保留独立导航和模板/关系读取，不再依赖普通Role目录是否可见。以上变化没有新增后端契约、客户端授权判断或调用方Account selector。

直接策略附件的计数、筛选和空态现在明确只表示直接来源；空直接附件不得抹掉已知Group来源或冒充有效权限结论。控制台登录和编程访问开关在权威读取不可用时显示“不可用”，不能伪装成已关闭。可选User、Account和各策略来源读取各自失败关闭：失败区域清除旧行和提示性命令快照，仅暴露该读取的重试；旧callback、并发中的过期精确读取和另一来源的重试均不能恢复已失效数据或重放业务写。当前身份读取仍是强制边界，当前Session得到401仍使整个会话失效；Analyzer、报告和命令结果继续由各自owner读取。

`14811b61`只把服务模板加载/搜索/筛选/详情/分页及密码重置回执恢复拆为独立交互用例；`1090fcaf`再把完整User向导的校验、草稿导航和最终创建，以及账号规则UNKNOWN的路由保锁与因子替换保护分到独立用例。原fixture规模、输入、断言和单用例五秒预算均未放宽，生产源码没有变化。该切片只修正IAM-UI-02/03/05/06的读取组合与失败隔离，不替代当前签名APISIX的Account开通、原Root恢复、RabbitMQ终止UNKNOWN或其余写路径验收。

UX/UI owner后继固定`6083f30008a6d57e1073b506f14e3c0fb42ee830`只提交其分支生成资产和FEAT证据；其完整前端源码tree与`1090fcaf`相同。本分支没有复制该分支专属build identity，而是从上述二十个最终源码blob重建324个嵌入文件。聚焦的目录/详情/服务授权及新增向导/UNKNOWN用例、typecheck、完整lint、architecture、234组对比度、生产导出/嵌入一致性、Go UI test/vet均已通过。

该候选尚未通过完整前端门禁，不能标为发布可用。UX/UI owner在独占单worker、原五秒预算下的默认fork运行于`AccessWorkspace`出现一个未改业务用例5715ms超时；相同固定归档的threads对照出现另外两个未改业务用例6338ms和5048ms超时。随后本分支在Node22.22.2/npm11.6.4、配置内`maxWorkers=1`和默认fork下独立运行，又在`AccountAccessRenderer`的188项中得到185项通过、三个不同未改业务用例分别5763ms、5362ms和5037ms超时，发现失败后主动停止。三个运行的失败集合不相同，且两个pool均不能稳定通过；因此没有把它解释成新增功能回归或某个执行器的已证实问题，也没有提高超时、删除断言、缩小fixture或改生产代码。测试执行/异步稳定性须由既有测试owner查明并使全部当前文件在冻结预算下通过；聚焦成功、生成稳定或旧提交全绿均不能替代该门禁。

上述选择性采用及本分支重建固定为`2c60db2dabff618cc7841a7cefc3b253b13bc618`；其[Verification 38865790823](https://github.com/xiak/matrix/actions/runs/38865790823)已按精确SHA核实十九项作业全部`completed/success`，包括受支持Node上的`console`、独立`authority-capacity`及最终汇总。`console`实际运行73/73个Vitest文件、1636/1636项测试和8/8项Node测试并通过，仍输出33条既有React `act`警告，不能写成零警告门禁。该次通过只证明这一次Linux运行得到成功终态，不能覆盖前述相同源码在隔离运行中已观察到的多处五秒边缘超时，也不能把后继尚未固定的测试owner调整倒推为本候选已经稳定。因此该CI接受本提交的后端、生成物和一次完整控制台回归证据，但完整前端稳定性及签名浏览器剩余写路径继续保持未验收。

`94cabe9`的独立[Verification 38889687143](https://github.com/xiak/matrix/actions/runs/38889687143)在Vitest前准确失败：从UX/UI分支固定`06198d737851eea032c2a15750a83fa3c5a721f7`取得的生成物携带该分支完整`src`树的build identity，而本分支有五个未采用的测试文件差异，导致三项manifest及292个内容文件与本分支重新导出不一致。这不是Group业务源码失败，也不是Windows/Linux生成差异；生成资产不能跨分支直接复制。本分支随后只从最终源码在受支持的Node 22.22.2/npm 11.6.4 Linux环境重新生成295个嵌入文件，固定为`d7f182be308b63bfa7867b0bfdc16577faae16f2`。

`d7f182b`的[Verification 38892035119](https://github.com/xiak/matrix/actions/runs/38892035119)已按精确SHA核实十九项作业全部`completed/success`。`console`实际通过73/73个Vitest文件、1640/1640项测试和8/8项Node测试，未设置与显式`0`两次生产导出的324个文件逐字一致，提交的嵌入资产与导出一致；仍有33条既有React `act`警告。该结果接受当前Group删除文案源码、生成资产和一次完整Linux控制台回归，不覆盖此前Windows完整套件的五秒边缘超时，不代表页面已执行最终删除；同一CI明确跳过七项需要专属Postfix的真实邮件子测试，也不能登记真实SMTP已验收。

### Policy 元数据与整策略退役

当前后继选择性采用UX/UI owner固定`a0ade1100d1a009d57bcdb519b796093efa7293c`的十三个既有auth源码、测试和消息路径；十二个路径与固定child逐字一致，`AccountAccessRenderer.test.tsx`三方保留本分支既有交互拆分和登录fixture。入口只约束CUSTOMER/TENANT/ACTIVE及当前Account的适用性，Root和委派主体均调用公开`PATCH/DELETE /v1/policies/{policyId}`并由服务端PDP判定。改名审阅冻结旧/新名称、原resourceVersion和requestId，响应必须保留稳定Policy/defaultVersion/contentDigest；整策略退役须准确输入原名称，由后端拒绝仍有引用的目标，不自动解绑、不删除不可变历史，也没有恢复入口。成功后独立重新读取Policy目录与详情，读取未完成时旧详情不能启用后继写操作。

目的限定的`policyMutation`拥有跨路由工作流，`policyMutationRecoveryStorage`隔离真实localStorage/Web Locks副作用；没有第二套通用回执框架。持久记录只保存同Account、同actor的原命令元数据，禁止凭据、Session、正文或proof；每个主体只有一个槽，Web Lock不排队且持有至请求结束，协调或存储不可用即关闭。UNKNOWN只能显式等值重试原命令；重登使用当前有效bearer，旧Session/repository的迟到响应不得清除原记录。后续401/403/409和非法响应均不能把原UNKNOWN改判为确定失败/成功，当前Policy读取也不是完成证明。显式放弃仅删除匹配的本地待核对记录，必须说明服务端效果可能已经发生。

本分支四个聚焦文件411项、typecheck、变更owner lint和architecture已通过；该聚焦预检使用本机Node23.11.1，不替代受支持Node的独立CI。独立Linux Node22.22.2/npm11.6.4在2 CPU/4 GiB/PIDs512限额内通过234组对比度、8项构建边界测试和两次59页生产导出，未设置/显式0模式及提交嵌入资产的324个文件逐字一致；UI-only Go test/vet通过，web包1.648秒。全部生成物来自消费分支最终源码，donor生成物和文档状态未导入。

固定源码`a12093895ca7461c15f50b8ca0ff5ddbe01e7803`编译的候选UI只替换当前r36签名安装中的静态UI容器，十个既有后端容器的ID、启动时间和重启计数未变。真实页面创建`UIRuntimePolicyA120`后将其改名为`UIRuntimePolicyA120Renamed`，再用精确原名称确认整策略退役；权威数据库显示同一Policy从resourceVersion 1推进至2、3并最终为`RETIRED`，唯一不可变版本、默认版本和内容摘要保持，活动附件始终为零，活动目录回到八项系统Policy。创建、改名、退役三条IAM outbox均为`DELIVERED`，对应`iam.policy.created`、`iam.policy.updated`、`iam.policy.deleted`事实分别进入租户Audit序列477、480、485；页面随后把当前租户序列1–488校验为完整且到达链尾。该证据接受正常改名/退役页面效果及审计关联，不接受尚未实跑的双标签竞争、关闭持锁标签、跨刷新/重登原意图恢复，也不把候选UI容器解释为新的完整签名release。

固定`f529279db3911e4c104d14d00f2c186dde306e0a`在既有`authorityprocess` owner增加显式opt-in的Policy mutation恢复门禁，不改变生产API、数据库或发布Profile。两个各自从空库开始的专属PostgreSQL 18运行均使用真实受限IAM/Audit/PaaS、双dispatcher与嵌入控制台：标签页A分别提交显示名修改和整策略退役；代理在后端2xx后提交响应头和半段正文并保持连接，使页面进入UNKNOWN且Web Lock持续持有。已单独登录同源标签页B尝试恢复时只得到“当前浏览器仍有请求在处理”，代理确认没有排队或额外写；关闭A后，B显式重放原method、path、Host、requestId、resourceVersion和body完全相同的命令。每次运行的代理最终都只观察初始请求和一次等值重放，初始提交已产生的Policy状态没有第二次推进；UPDATE保持稳定ID、默认版本、内容摘要和唯一不可变PolicyVersion，RETIRE使活动目录准确回到八项系统Policy并保留同一不可变版本。两次运行各自恰有一条outbox事实、一条准确actor/scope/target的成功Audit记录及完整租户链。UPDATE fixture/race package分别通过179.86/183.424秒，RETIRE分别通过209.35/212.884秒；聚焦回归、完整无数据库包、vet和diff检查随后通过。[Verification 38936057920](https://github.com/xiak/matrix/actions/runs/38936057920)已通过GitHub API核实精确SHA，19个job全部`completed/success`。该证据接受Policy UPDATE/RETIRE的真实响应丢失恢复，不替代默认CI明确跳过的opt-in浏览器场景之外的发布门禁。

### Policy默认版本的页面结果恢复

沿既有Policy mutation浏览器fixture增加`SET_DEFAULT`场景，不新建套件。测试对象为同Account的零附件CUSTOMER Policy，且没有User/Role权限边界引用；两个已经发布的不可变版本分别为同一业务读取的ALLOW与DENY。页面从版本表审阅当前/目标版本、摘要和预期Policy修订，最终选择目标版本；创建这些测试版本不授予任何主体权限。

响应丢失按[005的版本事务合同](FEAT-IAM-005-policy-versions-and-boundaries.md#版本发布事务)验收，不冒充附件的只读完成查询：首个POST真实提交后丢回包，页面冻结UNKNOWN及原意图；只允许操作者显式重试完全相同的method/path/Host/requestId/version/body一次。两个POST必须对应一个Policy修订变化和一条成功outbox/Audit，原结果修订仍当前时才能确认；当前状态GET或冲突都不证明原意图完成。页面确认后独立重读版本目录，目标为当前默认，两个版本的内容/编译声明及零授权引用保持。后继修订后的历史结果恢复没有新接口，本片不扩张为不可变completion GET或通用receipt框架；原数据/Audit后验与页面观察必须同时通过，才登记该路径验收。

测试候选`83d7c42cf665296d10de5fec15cf5ea26feb8dd7`已完成本地默认/race/架构/vet及原生Linux编译，但2026-10-19的真实页面仅到最终审阅：浏览器owner的工具要求人类逐次确认，未执行最终点击。独立PostgreSQL18.4中Policy仍为修订2、默认V1，只有准备阶段的创建/发布事实；没有完成marker、切换事实或Go PASS。该次专属进程主动停止，零数据库客户端后清理其PG容器、卷、网络、转发与临时目录。默认切换及响应丢失恢复仍未验收，不能以审阅截图、编译通过或进程停止成功替代。

独立源码审查发现该准备版本的写观察范围是单个Policy路径，会漏计同ID的`:set-default-version`重试，导致正确页面效果仍被后验判为失败。既有ResponseLoss表复用真实fixture的唯一配置构造后，旧范围准确得到`post_loss_writes=0 want=1`，并暴露UPDATE/RETIRE漏计其他Policy写；这属于测试接线假红，不是已观察到的生产漏洞。当前范围改为集合根`/api/iam/v1/policies`，同时覆盖集合创建、目标冒号动作和其他Policy写，仍排除相邻`policies-archive`、登录及GET/HEAD/OPTIONS；没有降低主门禁的计数1、两次等值账本、准确path/Host或原预算。十二个既有ResponseLoss入口的race通过3.733秒，完整默认authorityprocess/architecture race为3.954/2.583秒，vet通过；这些廉价回归只证明观察器，不替代仍缺的真实页面提交。

### User资料与状态原结果恢复源码

2026-10-17，本分支从已固定UX/UI源码`343622a11d0ce4c65c763de0e717505e0b8dae9a`（父`c8981dd160474710868bf84712f2b7792f283973`）选择性`ADAPT`十五个frontend路径，不导入donor文档、生成资产或验收状态。显示名更新与启停在发送前持久化原Account、actor、User、operation、request ID、expected resource version及非秘密目标值；UNKNOWN只允许以当前有效Session读取准确`UserManagementCompletion`，不得重新POST、自动换request ID或用当前User状态猜测原结果。完成回执与独立当前详情读取分离，404/403/409/503不释放原意图，401只失效准确旧Session；Account、actor、User、repository和Session换主均围栏迟到响应。存储不可读写或后端未提供completion client时，页面在网络写入前降为只读。无消费者的旧泛型`update-user`分支及Preview死路径同步删除，隔离MOCK继续使用其原工作区命令。

消费分支以三方增量保留本分支renderer测试，并与前述Membership切片共同在Node22.22.2/npm11.6.4下通过五个聚焦文件、772项测试、typecheck、architecture、234组主题对比度和二十个变更TypeScript路径的零警告lint。随后完整门禁通过77个Vitest文件、1954项测试及8项Node导出边界测试；两次59页production export在未设置与显式`0`预览模式下得到324个逐字一致文件，本分支重建的嵌入资产与最终导出完全一致，Go UI test/vet通过。UX固定源的1967项结果属于其完整分支；本分支保留既有三方测试owner且不继承donor测试计数。该选择性集成、生产构建和嵌入交付已由固定`741dceb`的独立CI接受；真实User写入与Membership响应丢失恢复由下一节的独立浏览器门禁拥有，二者都不能单独冒充签名IAM浏览器组合。

### User 与 Group 恢复真实浏览器验收

固定产品源码`741dceb6f0092fbc33706842862980816fe72d15`已通过[Verification 39012317180](https://github.com/xiak/matrix/actions/runs/39012317180)：十九项作业全部`completed/success`，其中`console`在Node 22.22.2/npm 11.6.4下通过77个Vitest文件、1954项测试、8项Node边界、234组对比度及两次324文件逐字一致的production export/嵌入核对。该固定源随后组装IAM87/Audit39/PaaS7+r37同源签名A/B并完成完整离线生命周期与重启后复验；本节的后继只增加现有`authorityprocess`真实浏览器门禁，不改变产品代码、API、SQL或发布Profile。

四个场景分别从全新数据库启动受限runtime登录、真实IAM/Audit/PaaS、双dispatcher和嵌入控制台。`USER_UPDATE`和`USER_SET_STATUS`都只允许第一个目标POST到达后端；代理在2xx提交后丢弃响应，页面保持UNKNOWN。刷新同源页面和重新认证不会被计作目标命令重放，浏览器只调用一次绑定原operation/requestId/expected resourceVersion的completion GET。显示名场景的原完成结果保持版本3，后继另一次资料修改不会改写它；停用场景在下一受保护请求拒绝旧Session，随后以新意图恢复User也不复活该Session。收紧后的代理以整个User写集合而非目标User路径统计丢包后写入，完成读取、登录和相邻非User路径不误报，任何User的更新、启停或删除都计为违规。两条最新fixture/package分别为154.76/157.054秒和129.70/132.145秒；每条原request在同租户、同action范围的outbox和已查询Audit记录中恰有一个事实，不只是目标筛选后看似唯一，租户链完整；该固定证据不证明跨action唯一性或未读取分页中的数量。

`GROUP_MEMBERSHIP CREATE`和`REMOVE`同样在第一个POST成功后丢弃响应，但Membership没有completion读接口；页面冻结原Group/User/Membership/version/requestId并只允许操作者显式等值重放一次。代理逐字核对两个请求的method、path、Host、body及原requestId完全相同，拒绝自动重试、当前目录推断或改变目标。CREATE最终只有一个活动Membership且下一次PaaS读取从403变为200；REMOVE只推进同一Membership至移除状态且下一次PaaS读取从200变为403。两条最新fixture/package分别为140.24/142.661秒和150.75/153.032秒；数据库按精确Account/Group/User始终只有一行，每条request在同租户、同action范围的outbox和已查询Audit记录中恰有一个事实，业务效果和租户链准确；不将该范围扩大为跨action或未读分页的唯一性。

这组证据接受IAM-UI-03的User资料/状态和Membership响应丢失恢复，不把本地真实进程入口冒充新的签名安装运行，也不扩展为Group删除或其他写路径已经验收。UX观察到UNKNOWN页的重复警告、“取消”易被误读以及移除成员页仍写“继续添加”等非阻断文案缺口，继续由UX/UI owner处理；服务端安全结论不依赖这些文案。

当前Policy、User、Membership与Policy附件的既有浏览器门禁统一读取所选action的全部Audit分页后统计原request，并在变量/错误中明确`action_request`范围；不把requestId改造成跨action的全局幂等契约。该测试后继不倒推改变以上固定运行的取证范围；浏览器原请求账本、权威状态、租户链及独立页面观察仍分别必需。

同一测试owner的`TestIAMPolicyAttachmentRecoveryConsoleBrowser`覆盖Group策略附件命令。CREATE在独立空白数据库通过真实页面：对含普通User的Group关联系统`PaaSViewer`，代理在唯一POST提交后丢弃响应；UNKNOWN页面只GET一次原request的不可变完成结果，之后整个附件集合没有写入。最终只有一条准确Account/Group/Policy附件和一条原命令完成记录，普通成员下一次PaaS读取从403变为200；唯一outbox/Audit事实与完整租户链匹配。fixture/race package分别为172.10/175.626秒。

REVOKE使用固定`77923f7839633002eb2a6c732c35fec6bea19436`的同一owner，先把新增模式接入既有30分钟浏览器观察窗，不改变生产HTTP五秒期限、密码成本或原断言。在任务专属原生Linux、2CPU/2GiB进程限额及独立2CPU/2GiB/PIDs256 PostgreSQL 18中，从空白数据库启动全部真实进程。浏览器只撤销一次原附件，响应丢失后只查询一次原request `37bc573c-d58d-470e-9f1c-d87f6615e853`，没有第二次POST；完成后同一附件终态版本2、唯一完成记录、成员下一次PaaS读取403、全request唯一outbox/Audit及完整租户链均通过。fixture/race package为1379.77/1380.839秒，包含等待浏览器确认的时间，不作为响应性能。此前Windows进程经跨机数据库转发的尝试在PaaS installation verify的原五秒HTTP期限前失败、尚未打开浏览器；不计入通过，也未延长期限来掩盖它。

当前生产`9621bb6e66b1076576649d3f6b224725a60d6848`与测试`26deca2ae9df57cf2913a4868bca47f9332dd7c4`已于2026-10-19在独立PostgreSQL18.4和受限原生Linux进程上重新完成GROUP/REVOKE页面门禁，403.43秒通过。浏览器只撤销测试Group的唯一`PaaSViewer`附件，在真实提交后丢失回包，UNKNOWN保留原意图；一次原结果查询展示不可变回执，准确request为`d64f31f6-686f-45c4-b451-dd73a076ec94`、operation为REVOKE、结果版本2并带完成时间。操作者明确完成后才独立读取同一Group，直接附件为0，Group和成员仍在。整条路径只有一次原提交、一次原回执GET、零丢包后写入；成员下一次PaaS请求403，唯一完成/outbox/Audit及完整租户链通过。回执明确不代表当前授权或Audit投递状态；这些后验由真实服务另外证明。该运行关闭当前GROUP撤销的可见回执与完成导航缺口，未回填旧UI或CREATE的可见回执证据；耗时含页面观察，不作为产品延迟。该一次性数据库在客户端归零后删除。

原`TestIAMPolicyAttachmentRecoveryConsoleBrowser`用仅测试配置`MATRIX_IAM_POLICY_ATTACHMENT_RECOVERY_TARGET`选择`GROUP`（默认）、`USER`或`ROLE`，仍使用同一个CREATE/REVOKE和响应丢失owner，不另造流程或套件。USER用真实普通登录会话检查下一次PaaS请求；ROLE只信任一个真实来源User，其User正向策略仅允许承担该精确Role，Role boundary限定为PaaSViewer。Role策略附件变化使原RoleSession的发行授权快照失效：CREATE和REVOKE之后，旧凭据在身份与PaaS入口都必须401，不能分别期待旧凭据200或403。原非敏感发行记录保持；只有来源User显式重新承担同一Role后，新RoleSession才分别得到业务200或403，重新承担也不能复活旧凭据。命令前后来源User均不得继承角色业务权限。三类目标共用精确Account/target/policy/version/request、唯一完成/outbox/Audit、一次原回执读取和零丢包后写入断言。这里的重新承担是fixture独立后验，不冒充浏览器已执行角色切换。

上述Role后验修正只改测试，不放宽生产会话资格。既有`TestIAMRoleAndManagementReferencesPostgres/role_authorization/role-attachment`沿真实HTTP writer补验：撤销后旧RoleSession关闭，新承担的无业务授权RoleSession仍能读取自身身份但业务决定为Deny；重新关联后，这条无授权阶段发行的凭据也关闭，只有再明确承担才取得新的Allow。旧发行、历史proof及schema等值重放断言保持。2026-10-19独立PostgreSQL18.4（1 CPU/768 MiB/PIDs192）、受限Linux Go进程（2 CPU/2 GiB/Tasks128）实跑该子例2.96秒、父门禁23.56秒、race包24.646秒通过；本地authorityprocess/architecture race分别3.978/1.813秒，相关vet通过。这是后端真实资格与测试修正证据，不是ROLE附件页面最终提交或完整浏览器门禁通过。

同一当前生产/测试固定源的USER/REVOKE已在另一空白数据库完成页面与权威后验，578.23秒通过。测试普通User只撤销一条直接`PaaSViewer`附件；UNKNOWN冻结原request `ui-user-revocation-2ad1716892937a9aea04282018aa421f`，只读查询一次后保留原目标、策略、附件、REVOKE、结果关系版本2及完成时间。明确“完成并重新读取”后User仍正常、直接附件为0，未修改登录安全、凭据或权限边界。后端证明原附件只推进一次、原User会话下一次PaaS读取403、唯一完成/outbox/Audit和完整链准确，且零丢包后写入。测试结束确认零客户端后删除该一次性数据库。该结果接受直接User附件撤销，不代替其CREATE或ROLE页面路径。

### Group删除真实页面与完成回执

当前生产源码`9621bb6e66b1076576649d3f6b224725a60d6848`、测试固定`26deca2ae9df57cf2913a4868bca47f9332dd7c4`的既有`TestIAMGroupDeletionConsoleBrowser`已在2026-10-19完成真实页面和权威后验。独立PostgreSQL18.4限1 CPU/768 MiB/PIDs192，原生Linux进程组限2 CPU/2 GiB/Tasks256，Go1.26.3、GOMAXPROCS2、构建`-p 2`；未改变产品权限、SQL、期限或页面源码。

UX/UI owner从LIVE详情确认测试组`Browser deletion operators`恰有一个普通成员和一条`PaaSViewer`附件，审阅真实级联影响、输入准确名称并只提交一次。页面保留的不可变完成回执明确显示原request `4b6b253a-57dd-4327-8fbf-2990e6f48cd0`、结果版本2、解除Membership 1、撤销直接附件1及删除时间；只有点击“完成并返回用户组列表”才独立读取目录，随后稳定显示零组。没有用API替代页面提交，也没有从空目录补造原结果。

IAM后验先核对同一request和Group的2/1/1状态，再结束原fixture。完整门禁通过699.49秒：两个关系只推进一次且终态时间与Group一致，原User仍ACTIVE、原成员Session的身份读取仍200，而下一次PaaS请求由200变403；系统Policy仍ACTIVE。原命令恰有一个决定绑定的删除outbox/Audit事实，完整租户链验证通过。耗时包含浏览器观察，不作为产品延迟指标。结束后子进程退出、数据库客户端归零，才删除该一次性合成数据库；保留的专属PG用于下一份独立数据库，不声称全部资源已清理。

这关闭当前Group删除的可见权威回执、明确完成导航及1+1级联缺口，不扩大为附件UNKNOWN、直接User/Role附件或签名APISIX页面验收。不得在展示回执时再次删除或把级联范围扩大到User、Policy及业务资源。

### 完成回执与重新登录说明集成

本分支从UX/UI固定`dbe5add33d8ef1cac663f2186e965f8fff041671`及其封闭修正`323d7417ae230cf20d83d3903429b2492c0efb7f`选择性采用十八个既有frontend源码、测试和消息路径，不带入donor生成物、文档状态或后端变更。十六个消费blob与最终donor相同，两个renderer测试保留本分支既有差异。UNKNOWN只显示一条准确警告；“稍后查询/处理”不暗示取消已提交命令；Membership添加和移除使用各自选择说明。Group/Role附件审阅绑定真实目标、Policy/附件修订和原request，原结果恢复成功后保留不可变完成回执，操作者明确完成后才返回详情；回执不冒充当前授权或Audit投递证明。

Group删除沿用原严格结果校验，并在对话框卸载后保留独立回执页：实际Group稳定ID/name、原命令request ID、结果修订、解除Membership/撤销附件数量及删除时间均取自本次命令与经验证的响应。只有明确“完成并返回用户组列表”才触发普通受保护导航及独立目录读取，不从空目录补造结果。Account安全设置的正常apply成功仍只清理准确调用Session的本地上下文，并向登录页传递非秘密原request说明；只读历史完成查询不退出后来建立的有效Session，真实401仍只失效准确当前认证所有者。没有扩展邮箱登录/MFA、手机能力、通用恢复框架、API/SQL或发布Profile。

旧消费源码`28f2da7e15c4720c262cae241f3425ada200ca9e`的[Verification 39193669814](https://github.com/xiak/matrix/actions/runs/39193669814) attempt 1失败不回填；后继会话测试修正及独立CI的准确结论归011。该源的独立Group浏览器复验只到最终确认、没有提交，随后停止专属进程；新REVOKE回执复验未启动，两者均不计通过。不能继承donor全量结论或把旧741页面的效果验收视为新UI已验收；同Profile签名release也仍保留独立发布门禁。

后继选择性`ADAPT`固定`b99849623eb673dcfc6167e8a33978e70802a617`的八个现有源码、测试和消息增量，不导入其生成物或验收状态。直接User附件命令及完成查询绑定当前repository、已认证view和Session；旧所有者的成功、401、检查结果及finally均不得清除新所有者的UNKNOWN意图、结束其pending或让其退出。Role客户端在发送前和接收后验证同一所有者，替换身份时重新建立页面工作区；权限仍由服务端判断。User附件恢复回执补齐原operation/request ID、完成时间、目标User、Policy、附件及结果版本，必须显式完成后才返回；回执不证明当前授权。

消费前置`101dc339f9ad368f293f95a3834b5613e5a6d669`曾通过本地77个Vitest文件/1961项测试、8项Node边界、类型/lint/架构/234组对比度、双模式导出和Go UI检查；固定源码审查仍发现USER直接附件在新repository身份尚未验证时可发请求。该事实是前端请求围栏缺口，不是已证明的后端越权。为避免继续消耗已拒绝候选的重门禁，主任务主动取消其[Verification 39199323432](https://github.com/xiak/matrix/actions/runs/39199323432) attempt 1；准确终态为`completed/cancelled`，15项成功、3项取消、汇总因取消失败，不能登记为整轮通过或新增后端断言失败。

后继从固定`82954bcefe2abcad4d3f1d9c2189e0d5e6408a66`及测试专用`64311a0b14e9bb2fd5f9fe9ef21b412e89fe505c`选择性采用三个既有源码/测试路径；两个生产blob与donor逐字一致，既有消费分支renderer差异保留。`ownsVerifiedUserPolicyChange`统一要求当前repository/view owner及该组合已验证的身份，在begin附件、begin撤销、submit和UNKNOWN inspect的存储/网络副作用之前失败关闭；只禁用关系区域控件，不冻结整页。原UNKNOWN意图、显式只读核查和已确认回执保持；原成功/401/finally的迟到响应围栏不变。共享本地记忆函数仍只检查原owner/request，不能误称它本身新增了身份核验。

本分支先仅加入两项pending-identity回归，未修改生产源码时两项均以错误enabled状态失败；接入修复后相同两项通过。User/Role两个相关文件随后267项通过（78.96秒），测试专用后继再补不依赖生产按钮disabled的Context探针；补强后的四项聚焦全部通过（7.59秒），覆盖新repository身份pending而目标User读取已完成时禁止开始关系命令及读取原UNKNOWN结果，核验后显式正常提交/只读恢复继续可用。使用Node22.22.2/npm11.6.4、单Vitest worker和2GiB堆，通过typecheck、三个变更路径ESLint、architecture、234组对比度与8项Node边界。两个构建worker的59页/57分段路径导出在未设置与显式0模式下得到324个逐字相同文件，并由本分支重建匹配的嵌入产物；Go UI/architecture race、UI vet及Linux amd64 UI构建也通过。未重跑无关后端真库矩阵，也未把donor的247项结果或本地组件检查当作后继精确SHA的独立CI、User/Role真实浏览器操作或新签名组合验收。

消费源码固定为`9621bb6e66b1076576649d3f6b224725a60d6848`，保持IAM87/Audit39/PaaS7+r37；准确[Verification 39203431655](https://github.com/xiak/matrix/actions/runs/39203431655) attempt 1已核实`completed/success`。console实际通过77个文件1965项Vitest测试和8项Node测试，类型/lint/架构/234组对比度、CI三个worker的双模式导出及324项embedded逐字匹配均通过；仍有33条既有React act警告。完整独立门禁由011拥有；这关闭本候选的组件、构建与CI缺口，不自动关闭真实页面或新签名组合。

### 首次登录强制改密

固定`6298e7532`在既有`authorityprocess` owner增加显式opt-in的首次登录改密浏览器门禁，不改变生产API、SQL或发布Profile。全新专属PostgreSQL 18以1.5 CPU、1 GiB、PIDs 256运行真实受限IAM/Audit/PaaS、双dispatcher与嵌入控制台；测试先为普通User签发另一条受限Session，随后浏览器以`username@account-id`和初始密码登录，从纯页面提交当前初始密码、新密码及确认值并进入所请求的IAM概览。数据库证明User和credential generation各只推进一次至版本2，`must_change_password=false`；另一条受限Session终态为REVOKED版本2且仍保留旧credential generation，浏览器调用Session是唯一ACTIVE会话并在同一事务提升至新generation。旧密码真实登录返回401且不泄露输入，新密码重新登录后`CurrentIdentity`仍为原Account/User且不再要求改密；唯一`ui-password-*`成功事实以本人USER为actor/target进入完整租户Audit链。fixture/race package分别通过76.68/80.216秒。结束前数据库外部客户端为0，按任务标签只删除本轮容器、网络和卷，未动共享或其他任务资源。

该证据接受普通User首次登录强制改密的纯页面最终提交及会话代次边界；它不外推为日常主动改密的“保留当前/全部下线”选择、TOTP强制绑定、改密响应丢失恢复、其他敏感写入的过期Session矩阵或签名release组合验收。

固定`18c115fe5007e36b7369e74f1c5c065952c0df32`选择性采用UX/UI owner固定`db4ce3f51febf30975ca616bbff221e30a11f031`中Group删除的五个源码、测试和消息路径，由本分支最终源码重新生成324项嵌入资产；没有导入donor生成物、FEAT、checkpoint或账号安全设置WIP。删除客户端只接受与当前Account、Group、名称、下一resourceVersion、非负级联计数及合法删除时间完全匹配的权威回执；busy/draft guard卸载后才进行普通受保护导航，目录独立重读，403/409/503、非法回执和跨Session/repository迟到结果均不得导航或显示成功。[Verification 38984154633](https://github.com/xiak/matrix/actions/runs/38984154633)已由测试owner按精确SHA核实19个job全部`completed/success`：受支持Node22.22.2/npm11.6.4实际通过75个Vitest文件、1703项测试和8项Node边界测试，234组对比度、两次59页/57路径生产导出及324项嵌入逐字一致；其中ConsoleNavigation的20项包含准确删除回执、导航和负向竞争用例。该CI默认跳过8个opt-in真实浏览器根，因此只接受Group组件/生成物和首次改密fixture的编译回归，不能替代Group最终页面删除或上述首次改密的本地真实浏览器证据；7个需要专属Postfix的邮件子测试也按既定边界跳过。

### 普通用户日常改密

本分支继续`ADAPT` UX/UI owner固定`3079bf6749f68857ad6fab048311fba0cf468a99`的九个既有认证源码、测试和中英文消息路径；九个消费blob与固定对象逐项一致，没有导入其FEAT、生成资产或尚未固定的Account安全设置。普通User从本人安全设置进入改密，只提交当前密码、新密码和明确的`revokeOtherSessions`；日常默认撤销其他会话但允许显式关闭，首次登录强制改密不显示该选项且始终强制撤销其他会话。当前Session只能由已经认证的同一bearer保留，页面不提供Account、User或Session selector，也不把改密成功变成新的认证事实。

请求pending时禁止重复写；401、409、422和非法回包不得显示成功或切换到首次登录流程。无法确认结果时立即清除密码字段并锁住同一Session的后续改密，repository替换和迟到响应不得解除；只有新的正常认证所有者才能清除该非敏感阻断状态。成功后仍在当前内容区展示结果，不写入浏览器存储、不退出当前Session、不导航；明示`false`只请求保留服务端判定仍有效的其他会话，不能复活已过期或已撤销会话。

当前消费者`5935fa5005529b2c4e1da943b98f49300430ba10`的SessionProvider、PasswordChangeForm、iamRepository和httpIamRepository四个生产blob均与UX/UI固定`14dccb1df71952fed5f6eb5581114a82c3da6ad1`一致，没有新的UI实现缺口或补丁。本分支独立运行现有SessionProvider、LoginRenderer和httpIamRepository三个测试文件，在Node22.22.2、单worker、2GiB堆下306项22.58秒通过，typecheck及四个生产路径ESLint通过；不继承另一分支的测试结果。

这些用例证明省略/true/false的准确wire、强制模式两层固定true、同一认证所有者的重复/UNKNOWN写阻断，以及更换Session/repository后丢弃迟到成功与401。HTTP成功只接受严格的changedAt与bootstrapFileRetirable，不接受伪Session或额外字段；提示不推断其他Session的撤销数量，不把bootstrapFileRetirable变成普通用户权限。精确独立CI与签名组合状态由011拥有；这里的组件和HTTP适配结果不替代真实改密页面提交或数据库后验。

既有`authorityprocess` owner提供同一个显式opt-in日常改密浏览器门禁。`MATRIX_IAM_DAILY_PASSWORD_REVOKE_OTHER_SESSIONS`省略或为`true`时检查默认退出其他会话，为`false`时要求页面显式取消该选项；其他值拒绝。两个模式各用独立空库，先准备同一普通User的两个有效generation-2 Session及一个已正常退出的Session，再由浏览器建立准确调用Session并提交下一密码，不另造套件或生产开关。

两种选择都必须证明User/credential generation只推进一次、调用Session保持ACTIVE并迁移到新代次、原退出Session的状态/版本/generation/退出时间完全不变且其bearer继续401。`true`要求两个有效旧Session各只撤销一次且下一请求401；`false`要求两者继续ACTIVE、各只推进一次至新代次，下一请求仍返回原Account/User。精确Session总数和调用者集合不允许多出会话，旧密码拒绝、新密码正常登录、唯一本人`ui-password-*`成功事实及完整租户Audit链保持。当前仅默认测试、编译和静态检查通过；两种模式都未完成页面最终提交，不能记为真实浏览器通过，也不继承当前签名A/B的周边生命周期结论。

### Account安全设置编辑

当前切片选择性`ADAPT` UX/UI owner固定`7ebc8700a5e23651047222e8e7f5f414b854342a`的九个既有Account安全设置源码、测试和中英文消息路径；其中八个路径以其父提交`3079bf6749f68857ad6fab048311fba0cf468a99`为本分支准确基线并逐字采用，`AccountAccessRenderer.test.tsx`只合入对应增量以保留本分支后继Policy和日常改密断言。没有导入donor FEAT、checkpoint、后端、API、SQL或生成资产；324项嵌入资产由消费分支最终源码重新生成。

页面编辑Account级强制MFA、密码长度/字符/历史/期限及到期动作、Session空闲期限和AccessKey来源CIDR，并以完整替换、当前Account resourceVersion和精确step-up意图提交。输入先进入只读审阅；当前密码与六位验证码只驻留于当前表单，Session或repository换主即清除。step-up签发、验证和最终应用各自区分明确拒绝、冲突、过期及结果未知；UNKNOWN只允许检查或以完全相同意图恢复，不能自动生成新requestId、沿用其他Session的证明或显示成功。dirty/busy guard在未提交草稿、审阅和在途阶段阻止误导航；读取失败不会把未知设置伪装成默认值。

本分支在Node22.22.2/npm11.6.4下通过相关七个文件535项测试、typecheck、全量lint、architecture、234组对比度、59页/57路径production export、未设置与`0`两种预览输入的324项逐字一致及Go UI test/vet；固定产品源码`741dceb6f0092fbc33706842862980816fe72d15`又通过完整前端、独立CI和同Profile签名A/B生命周期。该证据接受当前组件、状态机、嵌入生成物及发布组合构建；正常完整替换的真实浏览器效果由下段拥有，并发冲突及分阶段UNKNOWN仍由API/并发和组件门禁持有，不冒充额外浏览器旅程。

既有`authorityprocess` owner另有显式opt-in的Account安全设置浏览器门禁：在独立Account内创建只拥有精确读写与审计读取权限的普通User，先通过真实API验证通知地址并绑定TOTP，再由浏览器完成PASSWORD_TOTP登录、完整设置审阅、当前Session step-up和最终替换。门禁要求MFA、密码、Session和AccessKey CIDR恰好推进一个Account设置版本，全部旧Session在下一次受保护请求因旧设置代次失败关闭，重新MFA登录只能读取原完成回执，唯一成功事实携带原USER、Account目标及原授权决定并进入完整租户Audit链，同时生成绑定原事实与已验证联系人的单一通知任务。

该门禁已在全新PostgreSQL 18数据库和真实浏览器中通过：普通User使用当前密码与TOTP完成一次step-up，把完整设置替换为强制MFA、最小长度21、必须小写字母与数字、历史3、最长90天、`ADMIN_RESET`、空闲20分钟及`10.0.0.0/8`和`2001:db8::/32`两项CIDR。旧设置代次的既有Session在下一请求全部失败关闭；重新认证产生且仅产生一个版本2活动Session，页面再读版本2后才完成门禁。设置只推进一次，原完成结果、通知任务、授权决定、outbox、Audit事实和完整租户链准确；fixture/package分别通过213.10/215.358秒。该证据接受IAM-UI-06的正常完整替换路径，不外推为并发冲突或分阶段UNKNOWN浏览器旅程。当前固定候选`9621bb6e`的页面已明确四部分规则完整替换及原调用Session结束后的重新登录原因；历史回执不会退出后来登录的Session。这些文案与交互修正已在原owner完成，不再列为实现缺口，也不扩大上述真实浏览器证据。

固定测试提交`b958698db797595b81a4f819526627f4a823d907`的独立[Verification 39061146360](https://github.com/xiak/matrix/actions/runs/39061146360)有17项成功、`authority-runtime`及汇总失败：最终秘密扫描把合法`authorityEvidenceDigest`里随机出现的六位数字误判为TOTP泄露。后继固定`a79ca1454401e24427c0bbef667b4d43b2db1522`只在通过source/action/target契约验证的Audit事件中把该字段按既有`requestDigest`结构摘要处理；错误action、未证明JSON、完整摘要、畸形摘要和真实凭据继续失败。确定性正负用例、默认包回归、`go vet`及全新PG18五进程race门禁282.07秒已通过；其[Verification 39118086883](https://github.com/xiak/matrix/actions/runs/39118086883) attempt 1已按精确SHA核实十九项作业全部`completed/success`。这接受该固定测试源码的IAM-AC-09，不回填前次失败，也不覆盖默认CI跳过的浏览器或真实邮件路径。
