# 联合身份、角色会话与凭证

## 认证方式不等于资源授权

控制台密码、长期 API 密钥、联合身份登录与临时角色凭证解决的是“以什么身份访问”。某个身份能够认证，不表示它已获业务资源权限。身份与授权的关系见 [身份主题](identities.md)。

SSO 应归入身份提供商／联合身份能力，而不是与密码强度、MFA、敏感操作校验混为一个“身份安全”功能。它们可以协作，但维护的是不同配置与流程。

## 用户 SSO 与角色 SSO

腾讯官方将用户 SSO 与角色 SSO 分开。用户 SSO 映射既有子用户名；角色 SSO 经身份提供商和角色信任关系进入角色身份，不要求逐个镜像员工为 CAM 子用户。[^1]

| 方式 | 进入的身份 | 官方概览中的入口特征 |
| --- | --- | --- |
| 用户 SAML SSO | 已有子用户 | 支持控制台，支持 SP／IdP 发起 |
| 用户 OIDC SSO | 已有子用户 | 支持控制台，支持 SP／IdP 发起 |
| 角色 SAML SSO | 角色会话 | 支持控制台，IdP 发起 |
| 角色 OIDC SSO | 角色临时凭证 | 概览列为不支持控制台登录 |

这个表是腾讯当前文档的产品能力区分，不是 SAML/OIDC 协议本身对所有实现的限制。Matrix 是否支持某种入口，需要独立设计，不能从腾讯表格推出协议不具备相应能力。[^1]

CreateUserOIDCConfig 还写明仅能创建一个用户 OIDC 提供商，创建后自动关闭用户 SAML SSO 提供商；角色 OIDC 则具有名称、客户端 ID 列表等独立字段。这是切换登录配置时需要提示影响的具体例子，不是两个普通表单互不相关。[^2][^3]

## 身份提供商配置的意义

SAML 配置提供元数据与信任信息；创建接口返回 ProviderArn。OIDC 角色配置包括发行者 URL、客户端 ID、公钥及自动轮转配置，用户 OIDC 还涉及授权端点、映射字段、响应模式等。[^2][^3][^4]

字段校验不等于已完成联合登录：一个格式正确的 URL 或 Base64 文档，不能证明发行者、签名、受众、主体映射和登录回调在真实环境中正确。Matrix 的正式 MOCK 与真实认证边界见 [FEAT-007](../../../features/FEAT-007-control-plane-console.md)，本研究没有执行真实 SSO 启用或接入测试。

## STS 是临时会话，不是长期密钥换个名称

普通 AssumeRole 用目标角色标识和会话名称申请临时凭证；SAML 与 OIDC 使用不同的断言／令牌交换接口。返回的是临时 SecretId、SecretKey、Token 及到期信息。CAM 管理角色，STS 签发会话凭证，这两个契约面不应混淆。[^5][^6][^7]

AssumeRole 输入还包含可选的 Policy、ExternalId、会话标签、来源身份及 MFA 相关参数。该接口允许长期或临时凭证调用，不能由此推断所有 STS 接口的认证要求均相同；SAML/OIDC 的接口认证说明也不能泛化到普通管理 API。[^5]

本次未完整验证会话策略与所有资源策略、边界的组合公式，也未测试撤销现有临时凭证的传播行为。不能把角色配置更改、退出前端会话和云端临时凭证立即失效视为同一件事。

## 长期密钥的生命周期

腾讯文档说明 SecretKey 仅在创建时提供，后续不可再次查询。创建密钥、停用密钥、删除密钥、最近使用情况，都是不同的状态或操作。CreateAccessKey 还明确列出每个账户最多两个密钥，以及子用户不能操作主账号密钥等错误边界。[^8][^9]

因此，UI 中“查看密钥”不应意味着随时找回完整 SecretKey。一次性凭证交付需要明确警告、保存确认和失败处理；不得将秘密放入 URL、普通日志或长期浏览器缓存。后半句是 Matrix 的安全设计建议，不是腾讯客户端实现调查结论。

“最近使用”也不一定实时：腾讯文档区分列表中前一日更新的数据与更多访问记录中的当日数据。界面应标明数据时效，而不是用最近使用字段推定某个密钥绝对无人使用。[^10]

## 网络限制是另一个控制面

腾讯密钥网络访问限制仅覆盖永久访问密钥，不覆盖控制台登录或 STS 临时凭证；部分产品也不支持。配置密钥级规则时，它替代账户级网络规则，而非二者叠加或取交集。该能力的文档还注明白名单开放范围及分钟级传播延迟。[^11]

不能把所有名称包含“策略”的设置都交给同一个通用合并公式。排查无权限时，应分别看认证、网络来源、主体授权、资源侧授权和适用限制；建议的 Matrix 边界见 [设计参考](../matrix/design-reference.md)。

## 注释

[^1]: 腾讯云，[SSO 概览](https://cloud.tencent.com/document/product/598/96014)。
[^2]: 腾讯云，[CreateUserOIDCConfig](https://cloud.tencent.com/document/api/598/72091)。
[^3]: 腾讯云，[CreateOIDCConfig](https://cloud.tencent.com/document/api/598/73473)。
[^4]: 腾讯云，[CreateSAMLProvider](https://cloud.tencent.com/document/api/598/34567)。
[^5]: 腾讯云，[AssumeRole](https://cloud.tencent.com/document/api/1312/48197)。
[^6]: 腾讯云，[AssumeRoleWithSAML](https://cloud.tencent.com/document/api/1312/48196)。
[^7]: 腾讯云，[AssumeRoleWithWebIdentity](https://cloud.tencent.com/document/api/1312/73070)。
[^8]: 腾讯云，[主账号访问密钥管理](https://cloud.tencent.com/document/product/598/40488)。
[^9]: 腾讯云，[CreateAccessKey](https://cloud.tencent.com/document/api/598/82370)。
[^10]: 腾讯云，[查看访问密钥活跃时间](https://cloud.tencent.com/document/product/598/120122)。
[^11]: 腾讯云，[访问密钥网络访问限制策略](https://cloud.tencent.com/document/product/598/131331)。

来源日期及阅读范围见 [来源记录](../evidence/reading-map.md)。
