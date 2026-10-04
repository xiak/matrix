# 管理 API

管理 API 以资源生命周期为中心。所有写操作执行调用者授权、输入校验、乐观并发、幂等处理和审计；返回的资源包含稳定 ID、revision、创建/更新时间和状态。

## 用户与组

```text
CreateUser / GetUser / ListUsers / UpdateUser / SetUserStatus / DeleteUser
CreateGroup / GetGroup / ListGroups / UpdateGroup / DeleteGroup
AddUserToGroup / RemoveUserFromGroup / ListGroupsForUser / ListUsersForGroup
```

用户删除要求凭据、会话和关键绑定已处理。组成员操作幂等，批量操作提供逐项结果或原子语义。

## 访问密钥与认证

```text
CreateAccessKey / ListAccessKeys / UpdateAccessKeyStatus / RevokeAccessKey
GetAccessKeyLastUsed / PutAccessKeyNetworkRestriction
GetPasswordPolicy / PutPasswordPolicy
RegisterMfaFactor / VerifyMfaFactor / DeleteMfaFactor
ListSessions / RevokeSession / RevokeAllSessions
```

CreateAccessKey 是唯一返回 Secret 的管理调用。凭据状态收紧拥有优先处理预算。

## 策略与绑定

```text
CreatePolicy / GetPolicy / ListPolicies / DeletePolicy
CreatePolicyVersion / ListPolicyVersions / GetPolicyVersion
SetDefaultPolicyVersion / DeletePolicyVersion
AttachPolicy / DetachPolicy / ListPolicyAttachments
AnalyzePolicy / SimulatePolicy / GetEffectivePermissions
```

绑定目标用 `{principal|group|role|resource}` 类型与稳定 ID 表达。删除默认版本或仍被引用策略返回冲突。

## 角色与边界

```text
CreateRole / GetRole / ListRoles / UpdateRole / DeleteRole
PutTrustPolicy / PutRoleSessionSettings
PutPermissionBoundary / GetPermissionBoundary / DeletePermissionBoundary
ListRoleSessions / RevokeRoleSession
```

信任策略更新与权限策略绑定分别授权。服务关联角色使用独立产品生命周期 API，避免普通角色接口绕过依赖检查。

## 身份提供商

```text
CreateSamlProvider / UpdateSamlProvider / GetSamlProvider / DeleteSamlProvider
CreateOidcProvider / UpdateOidcProvider / GetOidcProvider / DeleteOidcProvider
PutUserSsoConfiguration / PutRoleSsoConfiguration / TestIdentityProvider
```

更新采用新配置修订，测试成功后切换；删除前检查用户映射、角色信任和活动会话。

## STS

```text
AssumeRole
AssumeRoleWithSaml
AssumeRoleWithOidc
GetFederationToken
RevokeRoleSession
```

STS 响应只返回短期凭据、实际过期时间、角色会话标识和受控主体信息。

## 产品接入

```text
RegisterAuthorizationProfile
GetAuthorizationProfile
ListAuthorizationProfiles
ValidateAuthorizationProfileCompatibility
PublishAuthorizationProfileRevision
```

注册要求产品发布身份或安装系统权限，并校验签名/摘要、兼容性和引用闭包。

管理操作覆盖用户、用户组、访问密钥、策略版本/绑定、角色/边界和身份提供商。[^1]

## Sources

[^1]: 腾讯云，“[API 概览](https://cloud.tencent.com/document/product/598/33155)”，访问于 2026-09-10；全部接口菜单见[来源导航](../sources/tencent-cam-navigation.md)。
