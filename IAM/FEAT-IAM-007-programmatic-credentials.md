# FEAT-IAM-007：访问密钥与程序访问

- 状态：设计；未实施/未验收。
- 依赖：003、005；临时凭据与 006 协作。
- Owner：IAM credential；各产品 HTTP 签名消费归其 PEP。

## 需求

| ID | 行为 |
| --- | --- |
| IAM-KEY-01 | User 长期 key create/list/disable/enable/delete/rotate；Secret 只返回一次 |
| IAM-KEY-02 | 类型化签名协议绑定 method/path/query/body digest/time/nonce/audience；拒绝重放 |
| IAM-KEY-03 | key 只有主体当前权限；不能绕 forced-change、状态、boundary 或租户归属 |
| IAM-KEY-04 | key 使用时间/结果/安全摘要，失败尝试不泄密 |
| IAM-KEY-05 | Account 和 key 网络限制有明确组合语义和可信 source IP |
| IAM-KEY-06 | 长期 key 与 RoleSession credential 分开，停用/删除即时生效 |

## 详细设计

发布 Matrix 自有签名规范，复用标准 HMAC/SHA-256 实现；不复制供应商 header 或把 secret 放在 URL。请求 body hash、规范路径、重复 query/header、编码、时间窗口和 nonce 去重有唯一规则。协议在 wire owner 冻结后客户端与服务端独立向量验证。

HMAC 验证需要受保护的可用 key material：不能宣称只存单向 hash 就能验证 HMAC。先选择安装托管封装密钥或转为标准非对称公钥认证并明确产品语义；秘密存储方案在这片 ADR/详细实现前定稿，普通 API DB 不能明文列出所有 key。不得复用用户密码作为 API secret。

KeyCreate 在 principal 锁内检查允许的凭据类型/数量与状态，写入材料引用/元数据/outbox；Delete 是终态，Enable 不恢复旧 session。root 长期 key 默认不开放，日常程序使用 User 或 Role。

## 验收

标准签名正负向量、body/path/query/header 替换、过期/未来时间/重放与错服务；并发 disable/rotate/request、双账号同名用户隔离；普通 JSON/错误/日志/审计无 key material；真实 PaaS 读写与 Audit 的程序身份可关联，重启仍拒绝旧 key。
