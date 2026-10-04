# 操作审计与责任追踪

访问管理审计覆盖身份认证、凭据、用户/组、策略、角色、联合、授权决定和业务操作。目标是从一次资源变化追溯到实际人员或工作负载，而不是只记录临时角色名称。

角色审计记录本地用户、IdP 用户或身份中心用户承担角色后的原始身份；操作记录支持按主体、资源与来源网络查询事件。[^1][^2]

## 事件类型

- 认证：登录成功/失败、MFA、step-up、退出和会话撤销。
- 凭据：密码重置、密钥创建/禁用/删除、IdP 密钥轮换。
- 身份管理：用户、组、成员关系和主体属性变化。
- 策略管理：草稿分析、版本发布、默认版本切换和绑定。
- 角色：创建、信任变更、PassRole、承担、会话撤销和删除。
- 授权：允许/拒绝、理由码、命中版本、边界和护栏。
- 业务操作：目标产品动作、资源、结果和关联决定 ID。
- 治理：报告导出、配额变化、组织结构和跨账号信任变化。

## 通用事件结构

```yaml
event_id: evt-...
event_type: authorization.decision
occurred_at: 2026-09-10T10:00:00Z
account_id: account-resource
request_id: req-...
decision_id: dec-...
actor:
  principal_id: role-session-...
  original_principal_id: user-...
  role_id: role-...
  identity_provider_id: idp-...
action: database.instance.modify
resources:
  - crn:database:region:account-resource:instance/db-1
source:
  ip: 203.0.113.10
  client: sdk-name/version
result: allow
revisions:
  policy: [policy-a:v4]
  authorization_profile: database:2026-09-10.1
```

## 责任链

角色和联合身份事件同时记录会话主体、直接承担者、最初人员/工作负载、IdP 与外部主体。服务代表用户调用另一个产品时，源业务任务、服务角色会话和目标产品操作使用 request/decision/trace ID 关联。

## 完整性

- 事件追加写入，普通管理员不能修改或删除。
- 生产者签名或通过受信通道投递，消费者检测序列缺口。
- 在线业务事务通过 outbox 或等价机制可靠产生事件。
- 时间戳来自同步时钟，并记录接收时间以诊断延迟。
- 审计投影可重建，原始事件是唯一事实来源。

## 查询与留存

支持按时间、账号、主体、原始主体、角色、IdP、动作、资源、来源 IP、结果和决定 ID 查询。留存按安全、合规和成本分层；导出到客户控制的存储时保持完整性摘要。审计读取和导出均写审计，敏感字段按权限脱敏。

## 告警

高优先级事件包括根身份使用、管理员无 MFA 登录、密钥创建、IdP 或角色信任放宽、权限边界解绑、组织护栏变化、跨账号访问和持续明确拒绝。告警保留事件引用，不复制完整秘密或联合断言。

## Sources

[^1]: 腾讯云，“[角色审计](https://cloud.tencent.com/document/product/598/115890)”，访问于 2026-09-10。
[^2]: 腾讯云，“[查看员工腾讯云操作记录](https://cloud.tencent.com/document/product/598/73795)”，访问于 2026-09-10。
