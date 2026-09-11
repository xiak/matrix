# FEAT-IAM-006：角色、信任与 STS

- 状态：设计；未实施/未验收。
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

roles、role_trust_versions、role_sessions 保持当前 authority reload。短期凭据使用已有 CSPRNG/digest 方式，不为公有云规模引入本地可无限离线验权的 JWT。expiresAt 不超过调用 session 剩余期限与 role maxDuration；SessionPolicy 内容和 origin 绑定不可变。第一版禁 Role 链式承担和跨账号承担，完整需求由 012 承接。

AssumeRole 在 account → user → source session → role 锁中复核凭据/信任/权限，记录 issued/denied fact。信任删除后未过期 session 也不再通过当前请求；历史 Audit proof 不重新检查当前用户。普通用户不能自报 originalPrincipal 或服务主体名称。

## 验收

双边任一缺失拒绝；角色边界/SessionPolicy 不能扩权；管理员承担只读角色后写入拒绝；错误 Role/Account/Token、会话过期/撤销、并发 assume/revoke/delete 失败关闭；真实 IAM/PaaS/Audit 临时会话业务路径及原始 actor 关联，重启不复活。跨账号或无 IdP 环境不使用 mock 声称验收。
