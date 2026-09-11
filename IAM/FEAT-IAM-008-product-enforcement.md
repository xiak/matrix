# FEAT-IAM-008：业务接入、服务角色与 ABAC

- 状态：设计；未实施/未验收。
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

Profile 的代码/签名发行由产品 owner 管理，IAM 只注册校验与求值。请求绑定精确 profileRevision/digest；缺版本/不兼容组合关闭。集合动作声明 COLLECTIVE 或 FILTERED，不能向未适配列表的 PEP 发细粒度 Permit。

产品接入和服务受托是两条独立协议。前者登记产品动作、资源、粒度和可信属性，并在业务 PEP 执行当前决定；后者登记可验证的服务主体与角色模板，经账号显式授权后承担目标角色、取得短期会话。不能把“产品已接入”或“服务认证成功”解释为已取得客户资源权限。

通用 IAM 求值器和控制台不得按产品名称、服务名称、角色名称或六种旧角色枚举内置授权分支。产品新增动作/模板是相应 owner 的版本化声明；新增产品必须通过登记与契约验证，不修改求值算法或逐个扩展前端角色菜单。预置策略、服务角色模板可由可信产品发布，但内容、默认版本与同意关系分别管理；显示名改动不影响授权，新版本不能隐式扩张既有账号的授权。当前静态 Action catalog 是 001 的过渡实现，不是最终可扩展接入完成。

PaaS 先覆盖 Application、Configuration/Revision、Deployment、Operation；managedservice 覆盖 Offering/Region/Entitlement/Installation；Audit 保持 chain/query scope。平台主机/终端由既有 Phase owner 消费确认的公共契约，本任务不重做主机实现。

ServiceRoleTemplate 定义注册服务主体、用途、允许权限和生命周期；租户实例经明确同意创建。PassRole 必须同时验证 actor、目标 role、目标工作负载和 service purpose。关联资源存在时拒绝或按明确异步删除流程，不能删角色留下无限可用凭据。

标签来自产品数据库和已验证新建命令，IAM 自供时间/身份/session 属性。禁止通用 caller attributes map。授权决定与业务 payload 区别明确：IAM 不声称证明具体部署镜像、配置值等业务真实性，源事务/outbox 负责。

## 验收

真实两个产品/两个 Account 的同名/同 ID/key、跨租户资源/cursor/配额/Operation、修改 tag 攻击、多个相关资源任一拒绝即无效果；服务跨租户请求必须有目标角色和用途；verifier probe 无业务写权。暂停之后的已提交事实可投递，新请求拒绝。独立 PG18/RLS/受限进程、真实部署和 UI 路径均通过才接受。

用不同名称的已登记产品/服务/角色证明统一流程；新增一份受信产品声明和角色模板即可通过相同登记、授权、承担和 PEP 协议，不给通用 evaluator 或 UI 增加名称分支。未知/未登记产品、伪造服务载体、缺少账号同意、错误目标角色/资源绑定及超出模板权限均拒绝。模板与预置策略变更验证旧版本和同意关系不被自动改写。
