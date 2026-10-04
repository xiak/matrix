# API 概览

访问管理 API 分为管理 API、认证与令牌 API、授权决定 API、分析 API 和产品接入 API。所有接口通过 TLS 提供，使用版本化 JSON 协议、稳定错误码、请求 ID、幂等键与明确限流维度。

API 按用户、策略、角色、身份提供商和其他接口分组，并为各接口公布频率限制。[^1]

## API 分组

| 分组 | 主要资源或操作 |
| --- | --- |
| 账号与安全 | AccountSummary、PasswordPolicy、LoginPolicy、MFA、Session |
| 用户 | User、UserAttribute、UserStatus、UserCredential |
| 用户组 | Group、Membership、GroupPolicyAttachment |
| 访问密钥 | AccessKey、LastUsed、NetworkRestriction、Rotation |
| 策略 | Policy、PolicyVersion、Attachment、Simulation、Finding |
| 角色 | Role、TrustPolicy、RoleSession、PassRole、PermissionBoundary |
| 身份提供商 | SAMLProvider、OIDCProvider、UserSSO、RoleSSO |
| STS | AssumeRole、FederatedSession、SessionCredential、RevokeSession |
| 授权决定 | Decide、BatchDecide、ExplainDecision |
| 产品接入 | AuthorizationProfile、Action、ResourceKind、ConditionKey |
| 分析与报告 | EffectivePermission、CredentialPosture、SecurityReport |

## 端点

服务可提供全局就近接入点与显式地域接入点。端点地域表示 API 处理位置，不必等同目标资源地域；请求中的资源地域仍由产品参数和规范资源名决定。[^2]

## 通用请求头

```text
Authorization: IAM-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...
Content-Type: application/json
X-IAM-Action: CreateUser
X-IAM-Version: 2026-09-10
X-IAM-Timestamp: 1789015200
X-IAM-Region: region-a
X-Request-Id: client-generated-uuid
Idempotency-Key: uuid-for-mutating-request
```

SDK 构造签名和重试；业务参数放入 JSON 正文。客户端不能用自定义头直接指定已认证主体、角色或授权结果。

## 通用响应

```json
{
  "request_id": "req-123",
  "data": {},
  "error": null
}
```

错误响应包含稳定 code、面向人的 message、请求 ID、是否可重试和可选字段路径。调用方依赖 code，不依赖可能变化的 message。[^3]

## 分页

列表 API 使用不透明 cursor，返回 `items` 与 `next_cursor`。cursor 绑定账号、过滤器、排序和调用主体，设置过期时间；不得允许修改 cursor 枚举其他账号数据。

## 版本

协议版本固定请求/响应字段含义。新增可选字段兼容；删除字段、改变默认值或安全语义使用新版本。资源本身使用 revision/ETag 实现乐观并发，不把 API 版本当数据版本。

## Sources

[^1]: 腾讯云，“[API 概览](https://cloud.tencent.com/document/product/598/33155)”，访问于 2026-09-10。
[^2]: 腾讯云，“[请求结构](https://cloud.tencent.com/document/product/598/33157)”，访问于 2026-09-10。
[^3]: 腾讯云，“[返回结果](https://cloud.tencent.com/document/product/598/43332)”，访问于 2026-09-10。
