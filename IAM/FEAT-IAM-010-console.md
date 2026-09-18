# FEAT-IAM-010：IAM 控制台

- 状态：实施中；既有账号控制台正在消费新 IAM 契约，尚未完成本 FEAT 的完整页面与真实浏览器验收。
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

## 详细设计

复用当前组件和客户端契约生成。页面可见性是上下文绑定的保守提示，服务端每个请求仍真实鉴权。删除全局 roles → allowActions 的本地权威判断，以 resource/profile/version 绑定的能力或实际请求响应驱动。

编辑保留输入但在版本冲突时明确刷新，不静默选另一个账号、角色或资源。敏感创建流程说明一次性材料，普通提示和错误不持久存储秘密。角色会话的 Account/有效身份/原始身份显示分开。

### 当前身份的权限上限投影

现有 `/console/access` 客户端严格消费 `CurrentIdentity.permissionBoundary`，匹配当前 Account、User 和 User resourceVersion；缺失字段、错误归属/修订或非法版本摘要直接使当前身份读取失败，不能降级为无边界。原 Account Root 仅允许明确无边界。页面独立展示“租户权限上限”及精确 Policy/默认版本 ID，不把它加入正向附件或从名称推导权限。

无边界不等于拥有权限，有边界不等于获得授权；目录和按钮继续消费服务端逐资源 capability/实际响应，不在浏览器实现策略求值。无 Policy 读取权限时仍可展示自身的版本引用，但不能因此读取正文或另一个账号的内容。刷新重新读取当前状态；失败清除该投影，不以旧的 null 或引用当作当前事实。User 边界设置/替换/移除由下节管理交互拥有，完整策略编辑和 Role 页面尚未交付；当前身份展示不替代真实浏览器验收。

### User 边界管理交互

沿现有 User 详情和后端三条 permission-boundary 路由增量接入，不创建顶层边界目录或全局管理许可。UserAccess 的能力集合增加精确 USER 的 set/remove：由当前 PDP 与同事务读取的原 Account Root 关系共同计算，普通管理员即使具有动作 Allow 仍提示不可写；主账号目标保护，停用普通 User 不隐式禁用边界管理。能力仅说明主体可尝试该动作，不承诺所选 Policy、修订或当前关系仍有效，实际写入继续完整锁内验证。

详情独立读取当前边界；未成功读取不显示“无边界”，当前 User 修订与边界修订不一致时先刷新，不把任一值覆盖到另一个请求。策略选择只取已授权可见的 ACTIVE/TENANT 目录，保留选中 Policy ID 与 resourceVersion；替换明确说明上限变化，移除明确说明其他正向授权可能重新生效，均需显式提交。停用/恢复、凭据和正向附件不能作为该表单的副作用。

同一次提交保留 requestId、目标和全部预期修订；网络/503/不确定回包不能自动生成另一意图重试。页面显示待核对状态，通过准确原请求重试或当前状态刷新处理，不以客户端显示判断服务端是否提交。401 清除敏感管理状态，403 不猜跨账号对象，409 保留输入并要求刷新/重新确认，未知或非法响应不得显示成功。当前 User 边界表单不等于完整 Policy 编辑器、安全委派或 Role 边界。

## 验收

单独端口、独立 IAM/Audit/PaaS+PG18 的真实浏览器完成平台→root→管理员→成员→资源路径，涵盖授权、撤销、组继承、policy/version、role、key、TOTP、改密与多设备下线。403/401/409/503 对应页面状态，无空白/健康页代替业务。

前端类型/lint/组件测试/构建、正常桌面和 360px 路径随片验证。用户已将键盘专项降优先级，记录待补但不阻塞高优先级安全和业务流程；不得据此宣称键盘已验收。不得使用其他 Phase 的固定端口或运行实例。

### 当前身份边界消费证据

2026-09-14，使用固定后端 `119f232e` 的当前响应结构更新原 HTTP 客户端测试，旧解析器因不接受 permissionBoundary 的三项正向流程先失败；修复后该 owner 的25项测试通过。新增门禁同时拒绝字段缺失、null 外层、错误 Account/User/User 修订、root 带边界、非法 Policy/版本/digest、额外正文/permit/selector；明确 null 不产生授权，合法引用也不加入 policySources。页面测试证明无普通授权时展示边界不会开放用户/策略目录，默认版本刷新、移除与读取失败分别替换或清除当前投影，不从边界策略名称计算许可。

本片全前端103项测试、类型检查、lint、架构及20组样式对比度检查通过；两次使用2 workers的静态导出一致，59个生成文件与 Go 嵌入交付物逐文件匹配。Go UI/架构 race、UI vet 与 Linux amd64 UI 构建通过。只变更现有 auth 客户端/domain/scene/renderer 和其嵌入产物，没有修改全局页面结构、样式、IAM API/SQL 或其他任务工作区。当前证据是客户端和组件/构建检查，不是独立真实浏览器、User 边界管理表单或完整 IAM-UI-04 验收。

固定 `ef51b1d509e7e38dfb2146416c7e057a97638765` 的 [Verification 34850453837](https://github.com/xiak/matrix/actions/runs/34850453837) 已通过 GitHub API 核实精确 SHA，Go、authority-process、node-process 全部 completed/success。该对象仅当前身份消费，不包含后续边界管理表单。

### 本人登录会话的固定 UI 交接

已只读核对`feat/cloud-console-ux`的固定`8e8b0f608827fb00c9a0e677e78ec12a7e047315`及其后继`ec5e832ad42cafea31cd731cfdbaa046b3537229`。前者实现本人会话页面、严格列表/撤销适配器、当前会话标识和未知结果保留原意图，消费后端固定`3080922f6ae1871f1c351d5ee30f03551fc3c605`；后者是全服务导航修复，不代替会话功能。此次只确认固定源交接，没有导入其 UI、嵌入产物或验收状态。

其前端检查、MOCK和DEV浏览器证据由[该固定对象的 FEAT-007](https://github.com/xiak/matrix/blob/8e8b0f608827fb00c9a0e677e78ec12a7e047315/docs/features/FEAT-007-control-plane-console.md#current-shared-navigation-development-evidence)拥有；明确没有执行真实会话撤销。IAM-UI-06/S1仍缺真实IAM+PG的双登录、A撤销B后B下一受保护请求被拒且A保持、实际当前退出，以及forced-change/分页/未知结果的组合验收。页面、确认框或模拟响应不能代替这些行为。UX/UI当前人工优先级保留MOCK入口并暂不启动最终登录验证，因此保持此门禁未验收，不擅自启用真实登录或操作其环境；后续按明确安排使用既有独立受限fixture。MFA及密码规则仍是各自未完成切片，不计入这次S1前端交付。

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

按用户分工，后续 UI 实现和浏览器验收交由 UX/UI 工程师继续。当前这次样式/fixture改动尚无自身独立CI；原自动独立进程回归已启动，但执行句柄后来不可用且没有取得终态输出，不能列为通过。交接固定对象保留上述证据与缺口，接收方在自己的分支复核，不继承整体验收状态。
