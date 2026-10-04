# 授权决定 API

授权决定 API 是业务产品与策略决定点之间的内部高可信接口。调用者必须是已注册产品执行点；普通客户端不能提交自选主体获取正式允许。

## Decide

### 请求

```json
{
  "request_id": "req-123",
  "subject_context": {
    "account_id": "account-a",
    "principal_id": "user-1",
    "session_id": "session-1",
    "original_principal_id": "user-1",
    "authentication_strength": "mfa"
  },
  "product_id": "database",
  "profile_revision": "2026-09-10.1",
  "action": "database.instance.modify",
  "resources": [
    {
      "kind": "database.instance",
      "name": "crn:database:region-a:account-a:instance/db-1",
      "revision": "42"
    }
  ],
  "context": {
    "request.source_ip": "203.0.113.10",
    "request.time": "2026-09-10T10:00:00Z"
  }
}
```

SubjectContext 由认证层签名或通过受信进程边界传递。产品提供动作、资源和业务属性；PDP 根据 Profile 验证字段来源。

### 响应

```json
{
  "decision_id": "dec-123",
  "result": "deny",
  "reason_code": "BOUNDARY_EXCLUDES",
  "evaluated_at": "2026-09-10T10:00:00.012Z",
  "revisions": {
    "authorization_profile": "2026-09-10.1",
    "policies": ["policy-a:v4"],
    "boundaries": ["boundary-b:v2"]
  },
  "public_context": {
    "action": "database.instance.modify",
    "resource_count": 1
  }
}
```

正式响应不返回可被产品误用的“部分允许”。多资源请求要么每资源返回独立决定，要么整批按照 Profile 声明的原子语义拒绝。

## BatchDecide

BatchDecide 接受共享主体和上下文下的一组动作/资源项，逐项返回决定。每一项有自己的 decision ID；限额防止用批量接口枚举资源。调用顺序不影响求值结果。

## ExplainDecision

解释接口以 decision ID 查询：适用身份、组和角色策略，命中的允许/拒绝，边界与护栏交集，条件比较和所用修订。返回内容按调用者的策略读取权限脱敏，不能向普通用户泄露其他账号策略。

## 缓存

允许缓存键包含账号、主体、会话、动作、资源及资源修订、条件摘要、策略修订和 Profile 修订。拒绝缓存周期更短，避免刚授权后长期拒绝；安全撤销通过主体/凭据/策略版本使缓存失效。

## TOCTOU

对权限依赖资源状态或标签的写操作，产品在同一事务或带 revision 的乐观并发中验证资源。若资源在决定后变化，业务写入失败并重新解析与授权，不使用陈旧决定。

## 服务等级

- 决定延迟按产品风险与策略规模设定分位目标。
- 超时和未知修订关闭失败。
- 认证失败与授权拒绝不调用业务执行。
- 每个决定可靠地产生审计事件。
- 决定 ID 可在业务操作与审计系统间全链路传播。

该 API 将统一策略判断逻辑与各产品动作/资源授权能力连接为内部执行契约。[^1][^2]

## Sources

[^1]: 腾讯云，“[策略评估逻辑](https://cloud.tencent.com/document/product/598/10605)”，访问于 2026-09-10。
[^2]: 腾讯云，“[支持 CAM 的业务接口](https://cloud.tencent.com/document/product/598/67350)”，访问于 2026-09-10。
