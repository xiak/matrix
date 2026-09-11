# FEAT-IAM-003：主账号、用户与凭据生命周期

- 状态：设计；旧多租户能力已由 FEAT-006 验收，本次新模型未验收。
- 依赖：002。
- Owner：IAM 账号/身份与安装 primary 的接口协作。

## 需求

| ID | 行为 |
| --- | --- |
| IAM-ID-01 | Account 是现有 Organization 的统一名称，稳定 ID 和资源归属不变，不创建第二个 tenant |
| IAM-ID-02 | RootIdentity 指向原始 primary，不能转让、删除、入组或通过租户 API 获得平台权威 |
| IAM-ID-03 | 管理员为可撤销策略授权的 User；root 可恢复日常管理，日常交接不转让 root |
| IAM-ID-04 | 平台开通/查询/暂停/恢复账号，初始化原 root；不重新跑安装 bootstrap |
| IAM-ID-05 | User 创建、详情、分页、资料、停用/恢复/删除，初始无权限，允许不同账号同名 |
| IAM-ID-06 | `loginName@account-id-or-alias` 明确 realm；失败防枚举，认证后 scope 不可切换 |
| IAM-ID-07 | 改密/重置/恢复保持 generation 单调，forced 必撤其他临时会话，普通默认撤其他可选 |
| IAM-ID-08 | 删除/停用用户不改变已有资源、Operation 和审计归属；恢复不激活旧 session |
| IAM-ID-09 | 原 root 凭据恢复不换 owner、不授平台、不启用暂停账号；平台 primary 仍需离线限定能力 |

## 详细设计

复用 tenant_accounts.primary_principal_id、原 USER ID 与 credential generation；用显式 root relation 表达所有权。Account 与 User 有独立 resourceVersion。不可撤销的 root 关系取代旧管理员 binding 保底，日常管理员附件可正常撤销。

删除 User 使用不可再认证的 tombstone 保存 principal ID、历史归属与审计关联；禁用所有凭据、撤销所有会话/角色会话和有效附件。是否允许重用 loginName 必须显式规则：第一版保留原名字，避免历史人员混淆。主账号、拥有未撤销平台附件的主体和服务身份不进入普通 User 删除/重置流程。

Account 更新以 scope/account 锁序列化；User 安全变更在 principal 锁内再次检查平台附件并与并发授予互斥。根身份名与 Account alias 独立。系统 home Account 暂停在效果前拒绝，保证服务身份和平台恢复入口不会锁死。

管理路由从旧 principal/organization 命名到目标 account/users 的替换与 schema、UI、生成契约原子收口；没有平行兼容别名。公开历史 Audit action 不重命名；新删除/身份命令定义新的封闭事实。

## 验收

两个 Account、各原 root/管理员 User/普通 User，同名登录、别名竞争、改密、退出、越租户 ID/cursor/body 攻击；平台与租户权限互不继承。错误版本、非原 root、并发状态/密码/平台授予无部分变更。旧 binary 状态升级、重放、重启和签名保留数据回滚通过，工作负载及 Audit 归属保持。
