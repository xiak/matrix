# FEAT-IAM-012：外部身份与组织治理延期需求

- 状态：Deferred，由用户允许的环境/生态限制触发；需求仍保留。
- Owner：IAM 联合身份/组织治理；具体外部来源、通知与计费由相应业务 owner 负责。
- 不计为已实现；无必要环境时本轮不提供假入口或伪成功。

## 需求、前置与验收

| ID | 完整需求 | 当前前置缺口 | 启用条件与真实验收 |
| --- | --- | --- | --- |
| IAM-EXT-01 | 用户 SAML SSO，既有 User 映射、metadata/cert 轮换、签名/assertion/replay/logout | 无获准运行的企业 IdP/正式域名 | 有隔离 Keycloak/ADFS/Okta 之一与受信 TLS；双账号错误 issuer/audience/recipient/时窗/重放均拒绝 |
| IAM-EXT-02 | 用户 OIDC SSO，authorization code+PKCE、state/nonce、账号映射 | 无获准 IdP/client registration | 正式 issuer/JWKS/redirect 注册和轮换，CSRF/mix-up/坏 JWT/失效账户测试 |
| IAM-EXT-03 | 角色 SAML/OIDC SSO，外部声明→Role trust→STS，无长期本地密码 | EXT-01/02 与 Role/STS | 真实企业用户断言、多角色选择和短期会话，原始身份审计，错 claim 不得任意选角色 |
| IAM-EXT-04 | 微信/企业微信关联导入、范围、解除、登录保护 | 第三方企业主体、审核凭据、回调/消息通道 | 获准沙箱/企业账号；真实导入/撤销/断联、账号绑定证明与隐私最小化 |
| IAM-EXT-05 | Passkey/WebAuthn 登录与管理 | 正式可信 origin/RP ID 与真实设备 | 注册/认证/跨 origin 拒绝/删除、设备丢失恢复及浏览器硬件门禁；不以纯 mock 通过 |
| IAM-EXT-06 | 跨账号协作者和角色承担，外部主体确认与信任双边撤销 | 本轮先关闭跨账号信任 | 两个真实账号、受邀同意、错主体/外部 ID、任一侧撤销、原始身份和资源归属完整 |
| IAM-EXT-07 | NotificationContact、消息订阅、手机号/邮件验证与短信 MFA | 无受支持通知/短信投递服务 | 真实已验证地址、发送/回执/失败恢复、未验证地址不绑定，联系人不能认证/授权 |
| IAM-EXT-08 | 组织树、Account 管理、SCP 类上限继承 | 跨账号组织与可信所有者未建设 | 真实组织层次、上限交集/显式 Deny、成员移动与并发撤销、root 与服务例外封闭定义 |
| IAM-EXT-09 | 跨账号资源策略/ACL、匿名访问 | 没有声明支持的业务资源 owner | 至少一个真实产品声明协议，两侧许可、ACL 组合、匿名限制和列举隔离完整 |
| IAM-EXT-10 | 支付/账单/实名/账号关闭/销毁审批 | 本产品无商业计费和销毁编排 | 独立业务权威、可审计批准/延迟删除、资源保留和法律要求确认 |
| IAM-EXT-11 | 多地域策略分发、缓存水位与撤销 SLA | 无多故障域部署/复制机制 | 真实断网/延迟/分区/旧缓存攻击，撤销承诺和失败关闭；不能用本机缓存模拟宣称公有云规模 |
| IAM-EXT-12 | 自定义外部 MFA、风险地理/异常登录引擎 | 缺可信因子/风险数据来源 | 因子专用认证、重放/时效/失联策略、真实数据与申诉机制 |
| IAM-EXT-13 | 特殊 Agent/企业中心身份类型 | 产品语义和凭据生命周期未公开/未定义 | 独立确认主体来源、权限/凭据/删除语义，不能按外部 API 枚举臆造 |

## 架构预留

复用 Principal/ExternalIdentity、IdentityProvider、TrustPolicy、RoleSession 和统一策略语言。每个 provider 使用专门 adapter，输入断言在验证前不可信。保留接口责任和字段语义说明即可，不先生成无消费者的接口、空表、fake provider 或 UI 全套占位。

微信/企业微信、IdP 品牌和供应商 API 仅属于 adapter；自研产品不借外部品牌定义 Account/User/Role。延期能力进入实现时要在本 FEAT 拆出有独立验收的切片，补固定来源、release/profile 和运行环境约束后才由 Deferred 改为 Implementing。
