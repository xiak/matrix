# FEAT-IAM-010：IAM 控制台

- 状态：实施中；在既有控制台接入固定 IAM 契约，完整 IAM 页面与发布验收尚未完成。
- Owner：UX/UI 工程师负责页面、客户端、公共组件和独立浏览器验收；IAM 工程师负责后端契约、鉴权及真实进程支持。
- 全局导航、视觉体系、响应式布局和隔离 MOCK 体验由 [FEAT-007](../docs/features/FEAT-007-control-plane-console.md) 拥有；固定来源由 [adoption review](../docs/adoption/FEAT-007-control-plane-console.md) 拥有。不引入另一套 IAM UI。
- 当前 IAM 集成基线固定为 `04041d2d3f7ed55225a5164bc2bc05251d25a6f1`（Verification `35485632542` completed/success）。该来源只固定当前 API 与权威对象，不把 IAM 各 FEAT 的未完成验收继承为 UI 验收。
- 权限能力目录的 CAT-06 固定契约为 `40407e2710a45ee1000552146cd362740074369a`，对应 IAM 累积来源 `a36a35c2eddbeb7c76a8d7c140e180b24a169aab`。它只固定只读目录及其错误边界，不接受租户注册产品、目录生命周期或策略作者发布能力。

## 需求

| ID | 可操作路径 |
| --- | --- |
| IAM-UI-01 | 平台开通账号、初始化主账号及受保护生命周期，与租户用户管理区分 |
| IAM-UI-02 | 当前 Account、主身份、User、RoleSession 清晰；登录 realm、改密、退出不混淆 |
| IAM-UI-03 | Users、Groups、Membership、直接附件与组继承来源分别管理 |
| IAM-UI-04 | 系统/自定义策略、真实版本、JSON/可视化编辑、语法错误及权限边界 |
| IAM-UI-05 | Role、trust、AssumeRole、会话时长、原始身份与返回身份 |
| IAM-UI-06 | 凭据一次性材料、状态及撤销，与登录安全和会话下线区分 |
| IAM-UI-07 | 成员访问允许的真实业务资源；拒绝、过期、冲突可恢复，不泄露跨账号信息 |
| IAM-UI-08 | 未交付能力明确未接入；MOCK 不伪装成真实鉴权、授权或凭据签发 |

## 详细设计

### 真实管理快照与隔离体验

沿原 repository → provider → scene → renderer 接入，不从策略名称、列表读取成功或 MOCK 求值结果推导权限。当前身份决定可请求的目录；目标详情和每项操作消费准确 action/resource 的服务端 capability。缺失、重复、外来或未知能力使响应失效，不能猜成管理员许可。可用性只避免死胡同点击，实际请求仍由 IAM 重新鉴权。

Account/RootIdentity 与日常 User 分开。主身份展示资源所有者说明，不因没有普通策略附件显示为未授权，也不进入普通 User 的授权、禁用、删除或边界设置流程。创建 User 不开通另一个 Account。

`AccountPolicy`、`PolicyDirectory` 和 `UserPolicyAttachment` 替代旧的内置角色投影；新 User 默认无业务授权。Tenant/installation 策略目录独立读取与授权，各为稳定 ID 有序、最多 256 项的完整元数据快照；仅 403 是局部不可用，其他失败关闭对应真实场景。缺少 installation 策略元数据时展示稳定 Policy ID，不隐藏有效直接附件，也不由元数据制造正文、继承、边界或最终允许结果。

当前在线授权权威只有 `Policy`、`PolicyVersion` 与 `PolicyAttachment`；历史 `RoleBinding` 标识只服务旧事实或迁移证据，不能形成兼容授权页、只读入口或第二套客户端模型。真正的 `Role` / `RoleSession` 拥有独立信任策略、承担检查与有界临时会话，不得与旧枚举角色混淆。目标 MOCK 同样不再显示“平台内置角色”并行入口。

签名目录 continuation 原样传递，不当作资源 ID 或许可。搜索、分页和全选明确覆盖已加载记录，不捏造全局总数，也不为装饰表格逐行查询 User。同账号缓存摘要仅装饰成员关系中的 User ID，不证明存在性或操作权限。组成员关系、直接组附件、直接 User 附件与 policySources 保留各自来源和修订。

关联/撤销携带所选 Policy 或当前附件修订；选择后 Policy 变化须清空并显式重选。新建组只创建组；成员关系和直接策略变更各为一个版本化关系命令。不确定结果保留同一 requestId 和完整 payload，冲突读取最新状态、关闭旧编辑并要求新的意图。组不作为登录身份、资源所有者或最终授权结果。

Role、身份提供商、联合身份、企业账号和 API 密钥均为详情优先的管理对象：目录名称只负责打开准确详情，编辑、状态、导入与危险操作统一由详情标题栏承载。目录不重复逐行操作列；小屏由公共页面操作菜单收纳次要命令。User 独有的批量选择仍按其单独契约处理，不能据此向其他目录伪造批量后端能力。

高级体验仓库仍只通过一键 MOCK 入口选择。真实角色、策略编写、SSO、密钥或模拟器未接入时明确说明；真实失败不调用体验仓库兜底。UI 原型与后端固定契约逐片衔接，不能据此发布一个尚未整合后端的安装版本。

身份安全概览与报告继续归 IAM-009 S4 的真实治理契约所有。当前控制台只从隔离体验仓库派生本地建议，明确区分“需复核、已配置、不适用、状态未知”，且把设置开关与认证器绑定证据分开；缺少认证器、最近使用或采集水位时必须为未知，不能猜成 `false`、安全或从未使用。报告只导出字段白名单中的 MOCK 快照，不建立真实报告 API、风险分或自动处置能力。

### 本人安全通知地址的隔离体验

本人第一条安全通知地址遵循 IAM-012 S1b 的固定设计来源 `8ccc632796727261563c952a89e4dfd3ce947144`，但该来源尚未固定公开 HTTP，也未交付持久化或发送 worker。因此控制台只在 DEV 体验仓库提供独立、明确标记的页内 MOCK：本人输入地址与当前密码，完成八位邮件验证码确认后查看本页状态；刷新即丢失，不调用 IAM、不写浏览器存储，也不发送真实邮件。

该地址只承载安全通知，不是登录名、恢复通道、MFA 因子或授权依据。第一片不提供替换、删除、管理员代绑、Account/User/SMTP/模板选择器。体验文案保留 `PENDING`、`IN_FLIGHT`、`RETRY_WAIT`、`ACCEPTED`、`FAILED`、`EXPIRED` 的语义，其中 `ACCEPTED` 只表示通知通道接受了请求，不能呈现为已投递、已送达或已读。真实客户端只能在 IAM-012 固定公开 HTTP 后另片接入；任何网络、5xx、协议或 404 结果都不得回退这个 MOCK。

该流程是设置页中的独立业务区块，不并入个人认证器或 Account 安全策略。进入、返回、取消和完成拥有自己的焦点生命周期；固定标题与说明立即渲染，只有将来真实读取的数据区才允许使用局部延迟反馈，不以整页骨架替换静态结构。

### 账号级 MFA 要求的隔离体验

账号级 MFA 要求遵循 IAM-009 S2/S3 的固定设计来源 `8ccc632796727261563c952a89e4dfd3ce947144`，但该来源尚未固定公开 HTTP。因此设置页把它作为独立于本人认证器、恢复代码与安全通知地址的 Account 安全规则呈现：编辑后先审阅准确的 Account 目标、适用身份和会话影响，再完成仅绑定本次规则变更的密码加 TOTP step-up，最后写入隔离 DEV 体验仓库。step-up 只证明认证强度，不授予 IAM 权限；真实保存仍须由后端重新鉴权，任何真实读取或写入失败都不得回退 MOCK。

规则只覆盖普通 IAM User。Account Root 与仍由平台管理关系保护的身份不适用；收紧规则会使不再满足要求的普通 User 会话重新认证，放宽规则不会恢复已经失效的会话，也不会删除个人已经绑定的认证器或恢复代码。审阅页必须固定并复述上述范围，不能用一个通用确认替代目标和副作用。

在 IAM-009 固定相应契约前，控制台不公开密码长度、会话时长或任意“敏感操作”选择器，也不把 step-up 票据抽象成通用提权令牌。当前预览只验证信息架构、审阅与焦点体验，不声称 Account 安全规则已由真实 IAM 保存或执行。

### 只读权限能力目录

策略工作区以独立“权限能力目录”页签消费 `GET /api/iam/v1/authorization-profiles`。请求不携带 Account、修订、分页、历史或正文 selector；客户端严格验证完整列表、产品顺序、Action 命名空间、scope、资源 shape、可信条件组合及内容摘要格式，并再次核对响应 Account。目录描述平台登记的产品能力，不是当前身份权限，也不是租户产品发布入口；浏览器不重算后端权威摘要，也不从目录推导最终 Allow。

目录不加入 IAM 初始场景的组合读取。只有首次打开页签才局部加载，快速响应不会先闪整页骨架；需要等待的表格区域沿公共 `TableSkeleton` 延迟反馈。401 只过期发起请求的当前会话；403、路由不匹配、5xx、网络、协议或 Account 不一致只关闭该目录并提供本地重试，不清空策略页面、不回退 MOCK、不伪装为空成功。

产品详情在同一内容区展示完整当前声明，并保留目录搜索、公共表格、分页、移动堆叠和进入/返回焦点。`INSTALLATION` 与 `INSTALLATION_PROBE` 只作为平台范围元数据展示，不能在租户 CUSTOMER 作者流程中选择。DEV 体验仓库提供同结构的隔离示例，但显式标记 MOCK、示例摘要不可信且不授予真实权限。

### 当前身份的权限上限投影

严格消费必需的 `CurrentIdentity.permissionBoundary`，匹配当前 Account、User 和 User resourceVersion。缺字段、错误归属/修订、非法引用或摘要使读取失败；只有明确 `policy: null` 表示无边界。RootIdentity 只允许明确无边界。

概览独立展示 Policy ID、默认版本引用和内容摘要，不加入正向 policySources。无边界不等于有权限，有边界不等于获得授权。无 Policy 正文读取权仍可以展示自身引用，但不能因此读取正文或其他 Account。重新读取失败不把旧引用或 null 作为当前事实。

### User 边界管理

沿 User 内容区详情使用现有 GET/PUT/DELETE permission-boundary 契约，不增加顶层边界目录、通用注册功能或客户端求值器。UserAccess 的九项基础能力包含精确 USER 的 set/remove；普通管理员即使有动作 Allow 也不能据此绕过后端原 Account Root 关系约束。

进入详情独立读取 User 和边界，归属及 User 修订必须一致。失败不显示“无边界”。策略选择只使用已授权可见、ACTIVE/TENANT、系统或同 Account 的目录记录；目录无权不可选新策略。目标停用状态与边界管理可用性不能互相推导。

设置、替换、移除均先审阅后显式确认。冻结 Policy ID/修订、目标 User 修订、默认版本引用及 requestId；移除说明其他正向授权可能重新生效。它不修改附件、启用状态、凭据或用户组。

| 结果 | 客户端行为 |
| --- | --- |
| 等待写入 | 立即反馈，阻止重复提交和离开待提交场景 |
| 网络/503/非法成功回包 | 不确定状态；锁定意图，只能显式重试完全相同的请求，不生成新 requestId |
| 409 | 保留选择，重新读取最新修订，再审阅并表达新的提交意图；不自动写入 |
| 400/403 | 明确失败，不猜跨账号对象，不提交替代选择 |
| 401 | 只过期发起请求的当前 bearer；清除私人管理状态，迟到的旧请求不能撤销新登录 |
| 已确认写入、后续读取失败 | 保留确认结果，锁定编辑；只重试读取，不重发已成功写入 |
| 完成并重新读取 | 仅更新当前 User 详情、边界和 capability，不重新加载全局 IAM 目录或 Header |

长 Policy/版本/摘要使用原公共排版和主题系统，窄屏完整换行。加载、空状态、操作及审阅继续复用现有公共组件。页面路由与客户端详情 query 的划分、静态入口及滚动归 [FEAT-007](../docs/features/FEAT-007-control-plane-console.md) 所有。

### 剩余接入边界

真实 PolicyVersion 正文、服务器编译快照和默认版本变更需要独立接入及浏览器验收；当前目录元数据和边界引用不能替代它。只读权限能力目录客户端已经接入固定契约，但仍需与固定 IAM 真实进程执行独立浏览器验收；产品声明管理不是租户策略功能。在真实作者契约和发布验证完成前，不开放可成功提交的真实可视化作者表单。

Role/trust/STS、SSO、高级凭据与登录安全专项按各自固定后端契约接入。本片不宣称其真实功能、全部错误页面或完整访问管理已验收，也不改变用户暂缓正式登录验证专项、保留 MOCK 验收入口的安排。

## 验收

每片通过类型、lint、组件、架构、主题对比度、生产静态导出及 Go 嵌入边界检查；后端鉴权不能被 UI mock 测试替代。生产导出关闭体验入口，DEV MOCK 独立保留。

独立 PG18、IAM/Audit/PaaS 和 dispatcher，搭配本分支完整静态 UI 宿主与导出，使用现有合成测试身份完成真实浏览器路径。不注入 bearer、Account selector 或授权响应。固定后端 CI 只能证明该后端，不继承它的 UI、导出、视觉或浏览器结果；这个联调环境不是 APISIX、安装升级或完整 release 验收。

User 边界片需 root 设置 A → 替换 B → 移除；同一成员的当前身份投影相应变化，普通管理员保持只读，正向附件不被删除。桌面与 360px 验证长引用、内容区操作和目录返回；fixture 最终检查实际两个设置事实、一个移除事实、明确无边界与 Audit 链。completion marker 不能代替页面观察。组件行为测试覆盖进入内联编辑、审阅返回和取消恢复焦点；真实浏览器键盘专项仍待补，不宣称已验收。

### User 权限边界片的开发联调证据

2026-09-16，UI 固定来源为已推送的
[`7e01a4176764ffff2fc9b81db8f059e334ac9c76`](https://github.com/xiak/matrix/commit/7e01a4176764ffff2fc9b81db8f059e334ac9c76)，
搭配固定 IAM 后端 `f15cc983a69092528a66eb49b0509b760392187c`；固定来源和取舍归
[FEAT-007 adoption](../docs/adoption/FEAT-007-control-plane-console.md) 所有。

- `TestIAMConsoleBrowser` 在新的隔离 PG fixture 中以 race 模式通过，包耗时 447.178 秒；该耗时包含编译、初始化及人工页面观察，不是点击或 API 延迟。完整 Go UI 二进制从本 UX 来源编译，不继承后端分支的渲染器、CSS、静态导出或浏览器结果。
- root 经现有合成身份登录，从目录打开 `browser.member`：设置 A、替换 B、移除，使 User resourceVersion 从 2 依次变为 3、4、5。原 PaaSDeveloper 直接附件始终保留。
- 同一成员分别重新登录/读取，CurrentIdentity 显示 A、B、明确无边界；正向策略来源独立保留，没有因自身边界引用而获得 IAM 管理目录或 Policy 正文读取权。
- 普通 `browser.admin` 可读取 User 详情，但边界保持只读、无编辑入口。当前浏览器为深色；360 × 900 验证三次边界操作及长引用完整换行，边界区域 clientWidth 与 scrollWidth 均为 276；1280 × 900 验证桌面详情、长版本引用及直接静态详情 query。
- 返回目录、浏览器后退重新读取 User revision 5、前进回到目录均完成；root/member 页面捕获的 error 日志为空。
- 页面观察结束后才写 completion marker。fixture 最终核对真实的两个设置事实、一个移除事实、明确 `policy: null` 及 Audit `VERIFIED`，随后通过；不是仅靠 marker 或 API 调用替代 UX 验收。临时数据库环境及其合成数据已清理，不是用户安装验收。
- 严格 HTTP/组件用例覆盖不确定提交、409 新意图、迟到旧凭据的 401 和成功写入后读取失败；本次浏览器未执行这些故障注入，不把自动化用例标为浏览器证据。
- 隔离 MOCK 已删除 User 权限页的“平台内置角色”并行入口；直接策略、组继承、权限边界与真实 Role/RoleSession 保持不同语义。关系与详情表格使用共享的可选移动堆叠契约；`360px` DEV Role 目录保留原生表格语义与逐值列标签，页面和表格均无横向溢出。该结果只接受信息架构与响应式体验，不代表真实 Role/STS 后端已交付。
- Role、角色 SSO、联合身份映射、企业账号与 API 密钥目录已移除重复行内操作；行为测试要求先进入准确详情，再从稳定标题栏执行编辑、导入、状态或删除。桌面 Role 目录只保留四个信息列，`360px` 目录仍无页面或表格横向溢出，详情次要操作由公共 `…` 菜单承载。
- 真实 User 权限边界的内容区编辑现在完整拥有焦点生命周期：打开和从审阅返回时聚焦新挂载的边界选择器，取消或确认关闭后聚焦稳定的“修改权限边界”触发器；键盘行为测试使用 `Enter` 进入和取消，并证明取消不会发送写命令。该自动化证据不替代固定 IAM 后端的真实浏览器键盘验收。
- 隔离 MOCK 概览将重复的安全指引与下载卡合并为主信息列中的身份安全快照；六项证据先展示状态、范围和下钻，再由一个“导出报告”菜单提供白名单快照。桌面和 `360 × 800` 页面均无横向溢出，菜单关闭后焦点返回触发器，建议可直接进入准确的密钥/用户/设置页面。该结果不代表 IAM-009 已提供报告、认证器或最近使用 API。

### 权限能力目录片的开发验收证据

2026-09-20，前端实现固定在已推送的
[`c1c01217736e234fb7c61f653c157dbdb31736c5`](https://github.com/xiak/matrix/commit/c1c01217736e234fb7c61f653c157dbdb31736c5)，
契约来源为本文件记录的 CAT-06 固定提交。

- 严格 HTTP 用例验证唯一无参数 GET、完整字段保留及空/超限、乱序/重复、额外字段、非法摘要、命名空间、scope/shape/condition/result 组合全部失败关闭；Provider 用例验证首次切页才读取、Account 不一致拒绝及 403/404/5xx 局部错误。
- 组件行为验证产品详情在内容区展开而非 Dialog，进入聚焦详情标题，返回聚焦并带回原产品；策略目录状态在页签切换后保留。隔离 DEV 目录使用同一组件与契约形状，同时明确声明 MOCK 不可信、不授权。
- 同一提交的完整前端、主题、生产导出、嵌入等价及 Go UI 宿主门禁证据由 [FEAT-007 current development evidence](../docs/features/FEAT-007-control-plane-console.md#current-shared-navigation-development-evidence) 唯一拥有；本节只接受目录契约和 IAM 交互结果。
- DEV 浏览器在桌面和 `360 × 800` 验证页签切换无整页骨架闪动、详情进入/返回、移动堆叠与焦点滚动；小屏 document/body 均为 `clientWidth == scrollWidth == 360`，无 Dialog，控制台 warning/error 为空。该结果是隔离 MOCK UX 验收，不冒充固定 IAM 真实进程浏览器验收。

### 本人安全通知地址 MOCK 的开发验收证据

2026-09-20，前端实现固定在已推送的
[`9842533d7ba2b719c9a58d3cfa09464aef1822e3`](https://github.com/xiak/matrix/commit/9842533d7ba2b719c9a58d3cfa09464aef1822e3)，
设计来源为本文件记录的 IAM-012 S1b 固定提交。

- 原重复占位项被独立安全通知区块替换；本人可在内容区完成地址/当前密码、八位验证码和确认摘要三步，不打开 Dialog，也不改变个人 MFA 或 Account 安全策略状态。
- 创建页面内验证意图后只显示 `PENDING` 与“等待投递器处理”；因为 MOCK 未调用 SMTP，它不能显示 `ACCEPTED` 或暗示渠道已受理。后续真实读取只能按后端权威观察更新状态。
- 行为用例证明错误密码、错误验证码、取消与完成边界；完成只保存在当前页面实例，并明确显示 MOCK、无 IAM 写入、无真实 SMTP，以及 `ACCEPTED` 不等于已投递或已读。
- 进入流程聚焦标题，取消恢复稳定触发器，完成聚焦确认摘要；桌面和 `360 × 800` DEV 浏览器均无页面横向溢出，紧凑页面 document/body 均为 `clientWidth == scrollWidth == 360`，无 Dialog，控制台 warning/error 为空。
- 完整前端、主题、生产导出、嵌入等价及 Go UI 宿主门禁由 [FEAT-007 current development evidence](../docs/features/FEAT-007-control-plane-console.md#current-shared-navigation-development-evidence) 唯一拥有；本证据不宣称 IAM-012 已有公开 HTTP、持久化、发送 worker 或真实投递验收。

### 账号级 MFA 要求 MOCK 的开发验收证据

2026-09-20，前端实现固定在已推送的
[`3f247bdaa214a055bb89b4f961a5dfd678b2e530`](https://github.com/xiak/matrix/commit/3f247bdaa214a055bb89b4f961a5dfd678b2e530)，
设计来源为本文件记录的 IAM-009 S2/S3 固定提交。

- Account 安全规则使用独立语义组件，不再混入本人认证器与安全通知；编辑、准确目标审阅、作用域 step-up 和预览保存均在内容区完成，不打开 Dialog。
- 审阅固定展示 `org-xiak`、普通 IAM User、受保护 Root/平台托管身份及收紧/放宽规则的会话影响。step-up 组件由本人安全操作和 Account 规则复用，但操作类型、目标和输入绑定保持显式，不产生通用提权能力。
- 行为用例覆盖密码/TOTP 失败后保留输入并重试、从 step-up 返回审阅、取消与完成的焦点恢复；完成只写当前 DEV 体验仓库。任何真实失败不回退 MOCK。
- 默认桌面与 `360 × 800` DEV 浏览器均无页面横向溢出、Dialog 或控制台 warning/error；小屏 document/body 均保持 `clientWidth == scrollWidth == 360`，规则目标和副作用仍完整可见。
- 完整前端、主题、生产导出、嵌入等价及 Go UI 宿主门禁由 [FEAT-007 current development evidence](../docs/features/FEAT-007-control-plane-console.md#current-shared-navigation-development-evidence) 唯一拥有；本证据不宣称 IAM-009 已有公开 HTTP、真实持久化、会话失效或后端执行验收。

公共 UI、生产导出、完整前端及 Go 回归证据只归
[FEAT-007](../docs/features/FEAT-007-control-plane-console.md#current-user-boundarynavigation-development-evidence)
所有。真实 PolicyVersion/授权目录作者流程、Role/trust/STS、SSO、高级凭据，以及本边界片的浅色/混色浏览器与键盘专项尚未完成。仍需与固定后端原子整合并执行相应发布门禁；本 UX 分支独立运行不等于完整 IAM 安装候选已验收。
