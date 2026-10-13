# FEAT-IAM-010：IAM 控制台

- 状态：实施中；UX/UI owner 的精确实例详情重新鉴权固定代码`24eedefe51a60ce2ca9805cba69901d923a6feef`已选择性集成为`0d9d0b12e9f95e9a2110697021d591916552da9a`，终止成功状态配对修复`be5f383ba517de90dcba71a6f884f34d8f4290f6`已选择性集成为`a06de4c8b82ddc1ed43221bc5745bb60850d85d8`；安装目录与三个辅助目录的权限解耦继续选择性采用固定`01f5241ee2d4b604a13c7fae05b2e301c9b15d9b`。受控真实浏览器已完成正式 PostgreSQL 18 产品的创建、READY、SQL读写、Group授权、同会话撤权后拒绝、页面终止、物理删除及完整Audit链，并完成平台开通Account、Root首次登录、Root以LIVE向导创建零授权User、User首次登录和同名realm隔离；同一User的后继安全链已完成通知地址验证、TOTP绑定、恢复码一次性展示、两次MFA登录、只撤销其他会话以及旧会话下一次受保护请求失败，LIVE目录同时展示已正式接入的 MySQL、Elasticsearch 和 RabbitMQ，不是样例或占位。IAM-AC-08及上述IAM-UI-01/02/06精确切片据此通过。轻量资源授权、真实SMTP/外部认证器、慢响应/故障注入、跨浏览器未知结果恢复、APISIX与签名安装浏览器路径及完整IAM-UI-01–08仍有缺口，因此整个FEAT仍未验收。
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

单独端口、独立 IAM/Audit/PaaS+PG18 的真实浏览器完成平台→root→管理员→成员→资源路径，涵盖授权、撤销、组继承、policy/version、role、key、TOTP、改密与多设备下线。资源路径必须创建当前产品目录实际支持的 PostgreSQL 18 托管实例，等待真实 worker 将其调谐到 READY 并完成 SQL 读写；目录可见、配额可见、命令进入 QUEUED/PENDING、伪造 endpoint 或仅数据库行存在都不是资源接入成功。403/401/409/503 对应页面状态，无空白/健康页代替业务。

前端类型/lint/组件测试/构建、正常桌面和 360px 路径随片验证。用户已将键盘专项降优先级，记录待补但不阻塞高优先级安全和业务流程；不得据此宣称键盘已验收。不得使用其他 Phase 的固定端口或运行实例。

### 当前身份边界消费证据

2026-09-14，使用固定后端 `119f232e` 的当前响应结构更新原 HTTP 客户端测试，旧解析器因不接受 permissionBoundary 的三项正向流程先失败；修复后该 owner 的25项测试通过。新增门禁同时拒绝字段缺失、null 外层、错误 Account/User/User 修订、root 带边界、非法 Policy/版本/digest、额外正文/permit/selector；明确 null 不产生授权，合法引用也不加入 policySources。页面测试证明无普通授权时展示边界不会开放用户/策略目录，默认版本刷新、移除与读取失败分别替换或清除当前投影，不从边界策略名称计算许可。

本片全前端103项测试、类型检查、lint、架构及20组样式对比度检查通过；两次使用2 workers的静态导出一致，59个生成文件与 Go 嵌入交付物逐文件匹配。Go UI/架构 race、UI vet 与 Linux amd64 UI 构建通过。只变更现有 auth 客户端/domain/scene/renderer 和其嵌入产物，没有修改全局页面结构、样式、IAM API/SQL 或其他任务工作区。当前证据是客户端和组件/构建检查，不是独立真实浏览器、User 边界管理表单或完整 IAM-UI-04 验收。

固定 `ef51b1d509e7e38dfb2146416c7e057a97638765` 的 [Verification 34850453837](https://github.com/xiak/matrix/actions/runs/34850453837) 已通过 GitHub API 核实精确 SHA，Go、authority-process、node-process 全部 completed/success。该对象仅当前身份消费，不包含后续边界管理表单。

### 完整控制台快照集成

UX/UI owner固定`d7d6b09a4c056c5380d6e0c1d87b9fc97ab9a9e5`后，没有把其844个历史提交或后端/安装/文档状态并入本分支。隔离候选`db13087079b98d10dfcc544bc26d11b64d3df318`以独立CI全绿的`b377d34a282e581fb8cbdbc6461e7da31c10aaf5`为唯一父提交，只用同一树快照替换`app/ui/paas/**`：652个路径，范围外差异为0；候选UI树`e44e128e4c4776f37bdfd5af20a8a1712d7cf148`与UX固定源逐字一致。常规receive-pack两次得到GitHub 500后，候选通过Git Data API从IAM根树替换准确子树；取回后再次核对父提交、根树、UI树、路径范围和内容。当前分支以带来源记录的`74e3c0983`消费该候选，没有移动或改写任一原分支。

候选在IAM基线的独立临时检出中通过typecheck、lint、架构检查、228组多主题对比度、63/63文件共1155/1155项测试和3项归一化测试；Next 16.3.3生成47个静态页面、规范化45个分段，259个嵌入文件逐字一致；全仓`go test ./...`与`go vet ./...`通过。独立DEV在1280、390×844和320×720检查无页面横向溢出，移动操作收敛到统一Page actions，新建Account在内容区而非伪Dialog，320px详情保留身份事实，浏览器warning/error为0。临时预览、快照和归档均已删除，原UX MOCK预览未被替换。首次用工作区外`node_modules` Junction构建被Turbopack拒绝，改用候选目录内`npm ci`后上述生产构建通过；不能把该环境失败写成代码通过，也不能手改可重复生成的minified产物。

Account开通、状态与原主身份恢复客户端严格要求原`requestId`及目标`resourceVersion`，成功只消费裸`Account`；目标GET只表示当前状态/capability，不冒充命令完成回执。UNKNOWN只允许原owner/session/client精确重放，409重读不推断成功，401只失效准确Session；root恢复不改变Account状态或角色。未有真实endpoint的能力继续保持独立MOCK或失败关闭，不能借完整页面快照宣称后端已经实现。

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
- 本分支增加一条缓存命中回归：若安装目录请求已经提交，而后续导航使原prepare失去当前revision，目录结果仍可进入缓存，但下一次进入安装目录必须启动尚未成功加载的三个辅助请求，不能因必需目录已命中而永久遗漏。本片定向4文件274条、完整63文件1189条及3条导出归一化用例通过；typecheck、lint、architecture、228组主题对比、47页生产导出、259个embedded文件等价和Go UI test/vet通过。完整Vitest仍报告若干既有测试未等待React `act`的警告，已交UX/UI owner清理，不能把本结果记为“无警告门禁”。只具备installation目录与精确详情权限、明确缺少三个辅助目录权限的真实PostgreSQL浏览器路径仍须在集成后独立实跑。
- 当前托管产品运行时契约固定到 IAM 产品实现来源 `4dea30e79cfd6693df149ea40eaa876c113814eb`，包含 `postgresql-18`、`mysql-8.4`、`elasticsearch-8.19` 与 `rabbitmq-4.1` 四个正式 offering；其准确版本分别为 PostgreSQL 18、MySQL 8.4 LTS、Elasticsearch 8.19.23 与 RabbitMQ 4.1.8。控制台与隔离 MOCK 必须用正式产品名称、版本、规格和产品类型说明同一信息架构，不得标为示例、占位或即将上线；LIVE 目录仍只渲染产品服务实际返回的项，不能用 MOCK 补齐。实例严格读取要求 `resourceVersion` 与 `operation.kind=PROVISION|TERMINATE`，资源阶段和操作阶段按两套状态机显式配对：PROVISION 的 `PENDING / PROVISIONING / READY / FAILED / ROLLBACK_FAILED` 分别对应操作 `PENDING / PROVISIONING / READY / FAILED / FAILED`；TERMINATE 的 `TERMINATION_PENDING / TERMINATING / TERMINATION_FAILED / TERMINATED` 分别对应操作 `PENDING / PROVISIONING / FAILED / READY`。因此 `TERMINATED + TERMINATE/READY` 是终止操作成功完成的合法形状，不得误判为协议错误；任何缺失、未知或其他矛盾组合整体失败关闭。
- 实例终止消费产品侧 `POST /managed-services/v1/service-installations/{installationId}/termination`，浏览器只发送当前 bearer 与冻结的 `Idempotency-Key`，不发送 Account、资源版本或请求体。允许从 `READY | ROLLBACK_FAILED | TERMINATION_FAILED` 发起；内容区先核对准确实例、产品、区域、观察到的资源版本和幂等请求，并要求输入实例 ID，永远不使用 Dialog。`TERMINATION_PENDING | TERMINATING` 只表示平台已接受并异步清理，不能显示为删除完成或提前归还配额；`TERMINATED` 后产品会物理删除容器、网络、持久化数据和托管凭据，并从权威目录移除实例、归还配额。网络或协议未知结果冻结原实例与幂等键，只能原样重试；401、403、404、409 与无效输入局部失败且不改写意图。轮询 404 只有在同一个正在终止的实例上才解释为需要重读权威目录，不能因另一实例正在终止而吞掉普通创建／读取错误。
- 当前UX owner的慢请求/UNKNOWN增量只承诺同源浏览器恢复：localStorage只保存经过严格解码的非秘密原意图，绑定当前Account及有效身份，并以相同`Idempotency-Key`和逐字节等值业务输入重放；不同浏览器配置或设备没有完成证明，不能显示成功或把查无结果解释为可重新发起。跨浏览器恢复是后继服务端能力，覆盖配额激活、实例创建/终止和服务Role绑定/解绑五类命令；应采用按命令类型封闭的Account范围查询或带标签的Operation投影，而不是通用回执接口。共同结果只包含`requestId`、命令类型、输入摘要、`IN_PROGRESS|SUCCEEDED|FAILED`、非秘密目标、可选Operation及完成时间，各命令再返回最小成功标识；Account和当前身份由服务端推导。RoleSession发起的命令还必须绑定原有效Role/主体，超过明确保留期仍为UNKNOWN。该段是已对齐的后继契约，不是当前UI或后端已经实现的证据。

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

测试通过受保护的本机握手读取IAM数据库时钟并用同一标准TOTP算法生成一次性验证码，只证明真实challenge、重放边界、会话和Audit契约，不是SMTP投递，也不是外部手机认证器验收。当前切片也不包括TOTP替换/删除、慢响应或故障注入、跨浏览器UNKNOWN恢复、APISIX入口及签名离线安装后的浏览器路径；已验签包包含嵌入控制台只能证明交付内容，不能替代这些页面效果门禁。

### 真实产品资源闭环

产品目录当前正式接入 PostgreSQL 18、MySQL 8.4 LTS、Elasticsearch 8.19.23 与 RabbitMQ 4.1.8；它们不是示例或占位数据。控制台只消费 LIVE 产品目录返回的真实 offering 和实例，不用隔离 MOCK 补齐；各产品的签名镜像、真实协议读写、凭据文件边界、生命周期销毁与配额归还证据由 [FEAT-IAM-008](FEAT-IAM-008-product-enforcement.md) 和 [FEAT-IAM-011](FEAT-IAM-011-acceptance.md) 所有。本 FEAT 验证同一套正式对象可被发现、创建、精确重读、授权和终止，且前端不写死单一数据库服务或产品数量。

普通 User 必须通过当前 Policy/Group/Role 之一取得该精确资源的读取许可并真正读取实例；目录行只提供定位摘要，进入详情后必须通过 `GET /managed-services/v1/service-installations/{installationId}` 对该实例重新鉴权。精确读取成功前不得显示旧快照中的 endpoint、阶段、状态或管理入口；拒绝、未找到和不可用只在详情数据区失败，并只能原位重试同一实例。撤销来源后，下一次相同业务请求必须拒绝，而实例、数据和租户归属保持不变。Allow/Deny 决定均需由同一 User、动作和真实资源 ID 关联到不可变 IAM Audit 记录，PaaS created/ready 事实进入同一租户链并通过验证。

固定`0d9d0b12e9f95e9a2110697021d591916552da9a`在全新PostgreSQL 18控制数据库上以显式浏览器入口运行`TestIAMConsoleBrowser`，package通过368.546秒，fixture为366.41秒。管理员从控制台创建真实`localpostgres`实例`iam-browser-pg-bbea9b402e4f`，实际受限Linux worker将其调谐至RUNNING/READY；浏览器读取到真实endpoint`127.0.0.1:39399`，后端在该实例完成PostgreSQL 18探测及`preserved`行写入读取，并核对固定完整镜像。普通成员仅经Group策略获得目录与精确实例读取，在第二个窗口撤销Group成员关系后，不重新登录或整页刷新便再次点击同一实例；稳定标题保留，精确GET返回无权限，旧endpoint、状态和操作入口均未泄露。两个窗口warning/error均为0；后端同时核对Allow与后继Deny决定、唯一`managedservice.service-installation.ready`事实及完整租户Audit链。结束后只按本轮标签删除控制数据库和测试资源，既有4317预览未被操作。该证据接受IAM-AC-08，不扩大为APISIX、签名安装、跨浏览器UNKNOWN恢复或整个FEAT验收。

2026-10-12 的后继门禁把浏览器与后端改为两阶段握手：浏览器先完成真实READY观察，后端才核对不可变镜像、受保护凭据和实际SQL读写，并以不可覆盖的单次标记放行页面终止；浏览器确认终止后，后端再验收权威TERMINATED结果。全新独立PG18控制库上的fixture通过641.51秒，package通过645.007秒。LIVE产品目录实际显示 PostgreSQL 18、MySQL 8.4 LTS、Elasticsearch 8.19.23 和 RabbitMQ 4.1.8 四项正式产品；本轮从页面创建并效果验证 PostgreSQL 18 `iam-browser-pg-d86afec72faa`，真实endpoint为`127.0.0.1:38380`。后端完成SQL写入读取之前，浏览器不能获得终止放行标记。

同一轮由Group组合目录级定位许可与该实例精确读取许可；普通成员在offering、region和quota辅助上下文均不可读时仍能看到被授权的实例列表和详情，证明辅助失败局部降级而非依赖广域产品权限。管理员移除成员后，原成员会话再次读取同一实例即被拒绝，页面保留稳定标题但不泄露endpoint、状态或操作入口。随后管理员在LIVE页面输入准确实例ID确认终止；页面接受`TERMINATED + TERMINATE/READY`的合法完成形状，显示已终止且不再展示endpoint，没有协议解析错误。后端独立验证容器、网络、数据、托管凭据和endpoint均已删除，配额归还，终止Operation完成，IAM/PaaS outbox投递、Allow→Deny决定及租户Audit链完整。该运行使用测试专属loopback代理，不是APISIX或签名安装浏览器验收；未覆盖跨浏览器UNKNOWN恢复，也不把一个真实PostgreSQL页面流程冒充四种产品各自的浏览器效果门禁，其他三种产品的真实协议与销毁由其既有产品验收owner维护。

固定`62b9705202a6b0b91fe93e5a9cf73d28349b3930`是上述Account/Root/User、本人安全/会话和真实资源切片的组合实现点；其[Verification 38367748687](https://github.com/xiak/matrix/actions/runs/38367748687) attempt 1已按精确SHA核对为18/18个job成功，165个实际步骤成功、168个矩阵非适用步骤按设计跳过，受支持Node运行时的`console`、真实四产品`authority-managed-products`和最终`authority-process`汇总均成功。默认CI仍不启用三个需要人工浏览器观察的显式opt-in fixture，因此本轮独立CI只接受当前固定代码的组合回归，真实页面效果继续由`262d46ad83d471d8c848501a9d1a49886d15c49c`、`a6f9b0d439cf579128723bc1b0d54bb0b09751a8`与`0d9d0b12e9f95e9a2110697021d591916552da9a`的受控浏览器运行证明；两类证据不能互相替代。APISIX入口、签名离线安装后的浏览器路径、慢响应/故障注入及跨浏览器UNKNOWN恢复仍是未验收边界。

`0b7823265`已把`installations`作为实例页唯一必需集合独立读取，offering、region、quota分别作为失败可降级的辅助上下文；任一辅助读取返回403、空结果或不可用时，实例目录和稳定标题仍可使用。进入详情后仍必须通过精确实例GET重新鉴权，目录摘要不能泄露 endpoint、操作状态或管理入口；不得通过授予广域目录权限掩盖身份缺权。
