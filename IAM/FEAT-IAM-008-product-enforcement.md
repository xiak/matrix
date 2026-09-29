# FEAT-IAM-008：业务接入、服务角色与 ABAC

- 状态：实施中；版本化产品 Profile、PaaS/managedservice 的真实 PEP、请求与决定绑定及当前资源/Operation/outbox 租户隔离已有固定后端实现。实例过滤/批量授权、服务受托和可信标签尚未实现，整体未验收。
- 依赖：001、005、006。
- Owner：IAM Profile/Role，PaaS/managedservice/Audit 各自的真实资源与 PEP。

## 需求

| ID | 行为 |
| --- | --- |
| IAM-PEP-01 | 产品以版本化 Profile 声明 Action、resource kinds、scope、granularity、conditions、list/batch |
| IAM-PEP-02 | PEP 从当前业务对象和有效身份构造请求；caller 不能伪造 owner、tag、Action、原始主体 |
| IAM-PEP-03 | list/filter/cursor 与批量资源检查始终受当前 scope 和权限约束 |
| IAM-PEP-04 | create collection→最终 ID、Operation、配置、配额和 outbox 有封闭映射 |
| IAM-SVC-01 | 服务主体与目标 Account 中的 Role/同意分离；purpose/installation 不授任意租户权 |
| IAM-SVC-02 | 服务角色模板、服务相关角色、PassRole、工作负载绑定与短期凭据 |
| IAM-TAG-01 | 可信资源标签/请求标签 ABAC，创建时强制标签和标签写入本身授权 |
| IAM-TAG-02 | 共享 tag 更新与授权状态一致；不能自己改标签绕过资源权限 |

## 详细设计

Profile 的代码/签名发行由产品 owner 管理，IAM 只注册校验与求值。请求绑定精确 profileRevision/digest；缺版本/不兼容组合关闭。当前源码Profile与集合/实例的闭合声明由001拥有，集合列表只支持整体授权的 COLLECTION_LIST；实例过滤未实现，不能向未适配列表的 PEP 发细粒度 Permit。被授权资源和成功事实资源种类分别声明，父实例→子资源与集合→新资源均不能用结果ID反向扩大permit。

产品接入和服务受托是两条独立协议。前者登记产品动作、资源、粒度和可信属性，并在业务 PEP 执行当前决定；后者登记可验证的服务主体与角色模板，经账号显式授权后承担目标角色、取得短期会话。不能把“产品已接入”或“服务认证成功”解释为已取得客户资源权限。

通用 IAM 求值器和控制台不得按产品名称、服务名称、角色名称或六种旧角色枚举内置授权分支。产品新增动作/模板是相应 owner 的版本化声明；新增产品必须通过登记与契约验证，不修改求值算法或逐个扩展前端角色菜单。预置策略、服务角色模板可由可信产品发布，但内容、默认版本与同意关系分别管理；显示名改动不影响授权，新版本不能隐式扩张既有账号的授权。当前静态 Action catalog 是 001 的过渡实现，不是最终可扩展接入完成。

PaaS 先覆盖 Application、Configuration/Revision、Deployment、Operation；managedservice 覆盖 Offering/Region/Entitlement/Installation；Audit 保持 chain/query scope。平台主机/终端由既有 Phase owner 消费确认的公共契约，本任务不重做主机实现。

ServiceRoleTemplate 定义注册服务主体、用途、允许权限和生命周期；租户实例经明确同意创建。PassRole 必须同时验证 actor、目标 role、目标工作负载和 service purpose。关联资源存在时拒绝或按明确异步删除流程，不能删角色留下无限可用凭据。

标签来自产品数据库和已验证新建命令，IAM 自供时间/身份/session 属性。禁止通用 caller attributes map。授权决定与业务 payload 区别明确：IAM 不声称证明具体部署镜像、配置值等业务真实性，源事务/outbox 负责。

## 当前实现边界

本节只归纳本 FEAT 的实现状态；Profile 注册与策略编译的详细证据仍分别由 001、005 拥有，RoleSession 的详细证据由 006 拥有。

| 需求 | 当前状态 | 权威边界 |
| --- | --- | --- |
| IAM-PEP-01 | 已实现当前后端主体 | 固定 `1dc1079c` 已将 IAM、PaaS、managedservice、Audit、installation 的版本化 Profile、完整摘要、当前头及请求/决定绑定接入唯一契约并通过独立 CI。后继 PaaS Profile revision 3 增加 `request.source-ip`，固定 `94cc8d7f` 已有真实 PG18、独立进程及唯一前驱保留数据证据，独立 CI 尚未收口。当前仍是源码/开发 readiness，不是签名发布组合。 |
| IAM-PEP-02 | PaaS apphosting 与 managedservice 已实现 | HTTP owner 从真实 path/body 和实际 `RemoteAddr` 构造 Action、资源、集合用途及可信网络上下文；账号和主体来自当前 IAM 凭据。IAM 决定必须逐字段绑定原请求，业务事务再按数据库所属账号取数，query/body/header 不能选择另一账号。 |
| IAM-PEP-03 | 部分实现 | 当前集合列表只允许声明为 `COLLECTION_LIST` 的整体授权；两个账号同名/同 ID/key、伪造 tenant/cursor/after 及跨账号实例均有真实拒绝门禁。尚无“先取候选再逐实例过滤”的列表协议，也没有批量决定；因此不能把整体列表授权描述为细粒度过滤完成。 |
| IAM-PEP-04 | 当前应用托管与 managedservice 路径已实现 | Application、Configuration、Revision、QuotaEntitlement、ServiceInstallation 的创建由封闭集合请求开始，最终资源、Operation 和 outbox 由同一业务事务建立；IAM 原决定只证明集合准入，不证明 caller 填写的最终 ID 或 payload。真实双账号门禁核对配额、Operation、幂等、拒绝无部分效果及 Audit 关联。 |
| IAM-SVC-01/02 | 未实现 | 当前 ServiceIdentity 只证明安装归属、服务主体及 purpose；不能承担目标账号 Role。现有 RoleSession 只允许同账号 USER 来源，TrustPolicy 也明确拒绝 SERVICE_ACCOUNT。没有模板、账号同意、PassRole、工作负载绑定或服务短期凭据。 |
| IAM-TAG-01/02 | 未实现 | Role 的 `tags` 仍只是元数据，不能进入授权。产品资源标签、创建请求标签、标签写入授权和并发一致性尚无可信来源协议。 |

`app/service/paas/internal/managedservice/port/security.go` 原 action→resource switch 是该产品适配器的封闭边界，不是通用求值器按产品名称分叉，但它重复了 release-owned Profile。本轮候选已删除这份重复映射：port 直接使用 IAM Action/ResourceKind 类型，通过 `NewAuthorizationRequest` 和 managedservice 当前 Profile 的完整引用/calling service 核对形状；IAM HTTP adapter不再执行第二次字符串翻译。七种合法集合/实例形状及其他产品、错资源、错集合用途/ID攻击的聚焦测试通过；API/PaaS 全包 race、对应 vet 和 architecture 门禁通过，尚待独立CI。后继产品适配器同样应消费自己编译进发布物且已由 IAM Profile 摘要认证的声明，通用 IAM 求值器仍只解释统一 Profile/Policy 语义。

同片后继候选把 apphosting 的 PaaS→IAM 资源词汇翻译收敛到 port 的单一构造器，HTTP adapter不再维护第二份资源 switch，Action/资源形状、当前 Profile 引用、PAAS calling service 和可信 source IP 一次绑定。apphosting 仍保留14个路由动作的显式 PEP 子集：同一PaaS Profile中的平台主机/安装动作不能因“属于PaaS”进入应用托管。14条合法形状及同产品错PEP、其他产品、错资源/集合/source IP攻击的聚焦测试通过；API/PaaS 全包 race、对应 vet 和 architecture 门禁通过，尚待独立CI。

## 下一纵向切片：账号同意的服务相关角色

下一片先完成一个真实产品、一个只读业务动作的完整协议，再扩展动作族；不先铺开任意跨账号委派或动态插件市场。

1. 产品 owner 在发布物中提供不可变、版本化的 `ServiceRoleTemplate`。模板至少绑定稳定 template ID、产品、服务 purpose、版本/摘要、允许的目标资源种类、可授权限上限和生命周期；它与普通 Policy 默认版本分离，不能由租户或请求方上传、改写或选择未登记版本。
2. 当前账号内持有明确管理 Action 的 USER 对模板执行显式同意，IAM 在同一事务中创建或确认一个 `SERVICE_LINKED` Role、模板版本关系、权限上限及不可变事实。显示名不参与安全身份；等值重放返回同一关系，变体冲突。普通角色 API 不能修改其 trust、扩大权限、换 template 或把它转换为 customer-managed Role。
3. 已认证 ServiceIdentity 只能以自身真实 installation、principal 和 purpose 请求承担目标账号中与其模板精确匹配的 Role。目标账号、Role 和 workload 必须来自已验证关系而不是通用 header/body selector；当前凭据失效、同意撤销、Role/账号停用、模板退役或 purpose 不匹配在下一次受保护请求失败关闭。
4. 短期身份继续进入唯一 Role 授权路径，不建立第二 PDP。公开业务主体必须保留 Role、临时会话和服务来源的稳定引用；既有 USER RoleSession 语义不得用伪 USER 承载服务来源。具体载体替换在 API/SQL 同片完成，旧别名或双实现不保留。
5. 首个消费者使用现有 managedservice 的只读实例动作证明目标账号授权：服务主体自身账号、installation 或“平台服务”标签均不产生目标账号权限。另一个账号、另一个 purpose、另一 workload、越过模板上限、撤销后旧凭据、probe 身份及伪造 selector 全部拒绝；允许路径读取的仍是业务数据库中目标账号资源。
6. 同意、发行、撤销和使用分别审计。IAM 只证明服务主体、模板、同意、Role 和临时身份；具体业务 payload 仍由产品事务/outbox 证明。删除有活跃 workload 的关系必须拒绝或走明确异步解绑，不能留下无限可用凭据。

本切片复用 006 的 Role、Role boundary、RoleSession、凭据发行和唯一策略求值器；只有服务来源、模板/同意及 workload 绑定构成新的安全边界。它不新增可由客户写入的产品目录、不把 ServiceIdentity 直接当租户管理员、不开放跨 installation 通配，也不把服务模板政策混入客户自定义 Policy。

## 验收

真实两个产品/两个 Account 的同名/同 ID/key、跨租户资源/cursor/配额/Operation、修改 tag 攻击、多个相关资源任一拒绝即无效果；服务跨租户请求必须有目标角色和用途；verifier probe 无业务写权。暂停之后的已提交事实可投递，新请求拒绝。独立 PG18/RLS/受限进程、真实部署和 UI 路径均通过才接受。

用不同名称的已登记产品/服务/角色证明统一流程；新增一份受信产品声明和角色模板即可通过相同登记、授权、承担和 PEP 协议，不给通用 evaluator 或 UI 增加名称分支。未知/未登记产品、伪造服务载体、缺少账号同意、错误目标角色/资源绑定及超出模板权限均拒绝。模板与预置策略变更验证旧版本和同意关系不被自动改写。
