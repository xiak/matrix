# 错误、幂等与限流

## 错误结构

```json
{
  "request_id": "req-123",
  "data": null,
  "error": {
    "code": "Policy.ConditionTypeMismatch",
    "message": "Condition value does not match the registered key type.",
    "retryable": false,
    "field": "statements[0].conditions.ip_in.request.source_ip"
  }
}
```

调用方依赖稳定 code。message 用于人类诊断，可以改进文案；不得以解析 message 驱动自动化。每个处理过的请求都返回 request ID。

## HTTP 语义

| 状态 | 含义 |
| ---: | --- |
| 200 | 查询或幂等读取成功 |
| 201 | 资源创建成功 |
| 202 | 异步任务已接受 |
| 204 | 删除或无正文更新成功 |
| 400 | 输入、schema 或签名结构错误 |
| 401 | 凭据无效或过期 |
| 403 | 主体已认证但授权拒绝 |
| 404 | 资源不存在，或按防枚举策略隐藏 |
| 409 | 状态冲突、仍被引用或幂等键冲突 |
| 412 | revision/ETag 前置条件失败 |
| 429 | 超出限流或配额 |
| 500/503 | 内部错误或暂时不可用 |

返回体区分固定错误码、可变错误消息和 Request ID；产品客户端依赖稳定码。[^1]

## 错误命名

错误码按领域和原因分层，例如：

- `Auth.InvalidCredential`
- `Auth.SignatureMismatch`
- `Auth.SessionExpired`
- `Authorization.ExplicitDeny`
- `Authorization.NoMatchingAllow`
- `Policy.InvalidSyntax`
- `Policy.ConditionTypeMismatch`
- `Role.TrustDenied`
- `Role.StillInUse`
- `Federation.InvalidAudience`
- `Quota.LimitExceeded`
- `Request.Throttled`

安全错误对公开调用者做适当合并，详细原因只进入受控审计。

## 幂等

创建、状态修改、绑定、解绑、撤销和异步删除接受 `Idempotency-Key`。服务保存键、调用者、动作、规范请求摘要和结果；同键同请求返回原结果，同键不同请求返回冲突。幂等记录有足够保留期覆盖 SDK 最大重试窗口。

AddMember、RemoveMember、AttachPolicy 和 DetachPolicy 等集合操作在资源语义上也保持幂等。

## 乐观并发

更新策略、角色信任、IdP、权限边界和安全设置要求 `If-Match` 或 revision。并发写入旧修订返回前置条件失败，调用者重新读取并合并，避免后写覆盖安全收紧。

## 限流

限流维度可以组合 API、地域、账号、主体、凭据和来源网络。读取、普通写入、认证、STS 和紧急安全收紧使用不同预算。响应返回重试等待时间与限流范围，SDK 使用带抖动的指数退避。

## 重试

- 只自动重试标记 retryable 的错误。
- 非幂等请求没有幂等键时不自动重试。
- 401/403、策略语义错误和配额上限不通过重试解决。
- 429/503 遵循 Retry-After 并限制总重试时间。
- 客户端在重试中复用幂等键，但为每次传输生成新的追踪信息。

## Sources

[^1]: 腾讯云，“[返回结果](https://cloud.tencent.com/document/product/598/43332)”，访问于 2026-09-10；另见“[错误码](https://cloud.tencent.com/document/product/598/33168)”。
