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

PaaS 先覆盖 Application、Configuration/Revision、Deployment、Operation；managedservice 覆盖 Offering/Region/Entitlement/Installation；Audit 保持 chain/query scope。平台主机/终端由既有 Phase owner 消费确认的公共契约，本任务不重做主机实现。

ServiceRoleTemplate 定义注册服务主体、用途、允许权限和生命周期；租户实例经明确同意创建。PassRole 必须同时验证 actor、目标 role、目标工作负载和 service purpose。关联资源存在时拒绝或按明确异步删除流程，不能删角色留下无限可用凭据。

标签来自产品数据库和已验证新建命令，IAM 自供时间/身份/session 属性。禁止通用 caller attributes map。授权决定与业务 payload 区别明确：IAM 不声称证明具体部署镜像、配置值等业务真实性，源事务/outbox 负责。

## 验收

真实两个产品/两个 Account 的同名/同 ID/key、跨租户资源/cursor/配额/Operation、修改 tag 攻击、多个相关资源任一拒绝即无效果；服务跨租户请求必须有目标角色和用途；verifier probe 无业务写权。暂停之后的已提交事实可投递，新请求拒绝。独立 PG18/RLS/受限进程、真实部署和 UI 路径均通过才接受。
