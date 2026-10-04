# 能力地图

访问管理能力围绕身份、凭据、授权、委派、联合、治理和业务接入七个域组织。能力地图表达完整产品范围，不表示交付阶段或实现优先级。

| 能力域 | 一级能力 | 关键子能力 | 主要产品对象 |
| --- | --- | --- | --- |
| 账号与身份 | 账号所有权 | 根身份、账号别名、安全联系人、恢复 | Account、RootIdentity |
| 账号与身份 | 人员身份 | 本地用户、企业目录用户、协作者、启停与删除 | User、ExternalIdentity |
| 账号与身份 | 用户组 | 成员关系、批量授权、组生命周期 | Group、Membership |
| 凭据与认证 | 交互式认证 | 密码、MFA、登录限制、操作保护、会话 | PasswordCredential、MfaFactor、Session |
| 凭据与认证 | 编程式认证 | 访问密钥、签名、轮换、禁用、网络限制 | AccessKey、CredentialPolicy |
| 授权 | 策略 | 预置/自定义策略、身份/资源策略、绑定 | Policy、PolicyVersion、Attachment |
| 授权 | 求值 | 默认拒绝、明确拒绝、条件、变量、多资源 | AuthorizationRequest、Decision |
| 授权 | 权限上限 | 用户边界、角色边界、组织护栏 | PermissionBoundary、Guardrail |
| 委派 | 角色 | 信任策略、权限策略、承担、会话时长 | Role、TrustPolicy、RoleSession |
| 委派 | 服务访问 | 服务角色、服务关联角色、资源角色、PassRole | ServiceRole、RoleBinding |
| 联合 | 用户 SSO | SAML/OIDC、账号映射、登录入口 | IdentityProvider、FederatedUser |
| 联合 | 角色 SSO | SAML/OIDC 断言、角色映射、STS | FederationAssertion、RoleSession |
| 属性授权 | ABAC | 主体/会话/资源/请求标签、标签创建约束 | Attribute、Tag、Condition |
| 多账号治理 | 跨账号访问 | 双边授权、跨账号角色、资源策略 | AccountTrust、CrossAccountSession |
| 多账号治理 | 组织治理 | 账号层级、集中身份、权限护栏 | Organization、OrganizationalUnit |
| 业务接入 | 产品能力 | 动作目录、资源类型、条件键、授权粒度 | AuthorizationProfile |
| 业务接入 | 执行集成 | 网关认证、产品资源解析、决定 API | PEP、PIP、PDP |
| 分析与审计 | 权限分析 | 策略 lint、模拟、有效权限、未使用权限 | PolicyFinding、PermissionSnapshot |
| 分析与审计 | 凭据态势 | 最后使用、闲置身份、密钥风险、报告 | CredentialFinding、SecurityReport |
| 分析与审计 | 责任追踪 | 认证、承担、决定、业务操作关联 | AuditEvent、DecisionEvidence |

## 横切能力

- 配额与限流：约束用户、组、角色、策略、版本、绑定、密钥和 API 调用。
- 版本与兼容：策略、产品授权能力、API、审计事件和令牌格式均具备版本。
- 安全恢复：根身份、break-glass、MFA 恢复、凭据撤销和误授权回滚。
- 可观测性：认证失败、授权拒绝、PDP 延迟、缓存修订、STS 发行和审计积压。
- 数据保护：凭据秘密最小保存、敏感属性脱敏、密钥托管和审计访问控制。

完整能力范围同时覆盖用户、访问密钥、用户组、角色、身份提供商、策略、权限边界、故障排除和安全分析报告；管理 API 按用户、策略、角色和身份提供商等领域分组。[^1][^2]

## Sources

[^1]: 腾讯云，“[访问管理用户指南](https://cloud.tencent.com/document/product/598/17848)”，访问于 2026-09-10；完整子菜单见[来源导航](../sources/tencent-cam-navigation.md)。
[^2]: 腾讯云，“[API 概览](https://cloud.tencent.com/document/product/598/33155)”，访问于 2026-09-10。
