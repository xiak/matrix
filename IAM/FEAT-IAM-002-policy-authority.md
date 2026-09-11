# FEAT-IAM-002：策略权限权威替换

- 状态：设计；未实施/未验收。
- 依赖：001 已验收的 CAT-01–04，固定安装/IAM5 消费者对齐；完整产品 Profile 的集成仍由 008 证明。
- Owner：IAM `authority`、`identityaccess`、PostgreSQL；Audit 只保存事实。

## 需求与详细设计

| ID | 需求 | 设计 |
| --- | --- | --- |
| IAM-POL-01 | 单一策略评估器 | 纯函数评估 typed statements；无旧 RoleAllows fallback |
| IAM-POL-02 | 系统管理策略 | 平台发布稳定 ID、不可变文档与默认版本；普通用户不可编辑 |
| IAM-POL-03 | 策略附件 | 账号/主体/策略 ID + 状态/修订；吊销是保留历史的终态 |
| IAM-POL-04 | 等价迁移 | 六种旧角色映射为明确权限集合；仅原有有效绑定成为有效附件，撤销历史仍撤销 |
| IAM-POL-05 | 决定证据 | 绑定 subject、原始主体、scope、Action/resources、policy version/profile revision 和 digest |
| IAM-POL-06 | 查询权限来源 | 区分直接/组/角色来源；隐藏无权查看的主体/策略详情 |

系统策略映射：ORGANIZATION_ADMIN → AccountAdministrator；PAAS_DEVELOPER → PaaSDeveloper；PAAS_VIEWER → PaaSViewer；AUDIT_READER → AuditReader。PLATFORM_OPERATOR 与 INSTALLATION_VERIFIER 使用各自封闭 scope 的系统策略，不能通过租户附件 API 授予。

表目标为 policies、policy_versions、policy_attachments 与必要的不可变历史映射。迁移在一个 profile-bound 事务内保存原 ID/撤销证据，替换旧 put/revoke/load functions 并删除旧权威表和 API。策略语言版本、内容版本、SQL schema 与 release revision 各自验证。旧审计 `iam.role-binding.*` 保持既有 bytes 和证据语义，新附件事实使用新 Action。

## 用例/锁/接口

用例负责系统策略装配、附件授予撤销、当前来源收集和决定持久化。写入按 scope → principal → policy → attachment 锁序；撤销与密码/状态保护使用相同 principal 锁。API/worker/verifier 无越权 DML，查询走 RLS/受限函数。安装恢复用例要查询新的显式平台附件，保持封存 primary tuple 与原 receipt。

## 验收

- 现有每个 role/action/service 允许拒绝矩阵在替换前后等价，新增无权限主体仍默认拒绝。
- 真实旧 binary 生成已授予/已撤销/已禁用状态后升级，两次迁移、bootstrap replay、重启不复活权限。
- 当前权限、historical proof 和原始 Audit 哈希各自正确；没有第二 evaluator 或旧在线 API。
- 并发 revoke/reset/status/grant、错误版本和跨 Account ID 无部分变更。
- PG18 受限登录、架构、security/race、独立进程与签名 profile 匹配门禁通过后 Accepted。

固定采用归既有 adoption。安装 owner 已冻结 IAM6/Audit4/PaaS5+r12；落地前仍须逐项核对实际 ABI，不能只分配一个数字。`/v1/authorize` 和严格 `{event}` 的 `/v1/audit-producer:resolve` 在切换片中与消费者原子适配；不留下旧组织 selector 旁路。

原始 bootstrap 的 primary/platform 关系保留为显式系统策略附件。旧 binding 的 ID、resourceVersion、created/revoked 历史必须确定性迁移；平台凭据恢复只能使用仍未撤销的等价平台附件。若改动私有 `LocalCredentialRecoveryExpected` 中的 binding 字段，须在同一候选中更新 API、安装消费者、SQL、签名 codec 和旧 receipt 迁移，不能并存两套授权状态。首次授权与撤销后重新授权不因重构获得入口。

## 保留数据与活跃权限的分离

迁移依据真实 `role_bindings` 的 `(tenant_id,id)`、principal、role、resourceVersion 和 created/updated/revoked 时间；不能以“当前还能登录”推断历史有效状态。原安装 primary 的 local-recovery expected/receipt 已封存具体平台 binding ID 与版本，附件继承同一身份而不重新分配；历史完成的查询不重新判断当前附件是否有效。

当前旧恢复事务按 platform binding → organization → principal → credential 加锁，旧 revoke 也先锁实际 binding。目标的新锁序必须在 grant/revoke/reset/status/recover 全部路径中一起切换并做双向竞争门禁；不能只按本文件的目标顺序改一个函数。

删除的是旧在线 RoleBinding 权限权威，不是不可变历史词汇。旧 Audit action/target、authorizations 和 receipt 的严格读取由原历史契约继续验证，不重编码、不新增授予能力。活跃请求不得调用已退役的 role-management 动作；历史校验不能作为第二条当前授权入口。具体 catalogue/record schema 的区分须由 API 与 SQL 同一候选实现，不能以放宽 unknown action 校验兼容旧记录。
