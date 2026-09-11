# 来源覆盖与产品文档映射

## 导航完整性

2026-09-10 从腾讯云访问管理产品详情页解析完整左侧导航。原导航包含 13 个一级节点、202 个目录节点、706 个页面节点，共 908 个唯一节点，最深 5 层。所有节点按原父子关系保存在[腾讯云访问管理完整来源导航](./tencent-cam-navigation.md)。

| 腾讯云一级栏目 | 页面 | 目录 | 本地产品文档归属 |
| --- | ---: | ---: | --- |
| 公告 | 3 | 1 | [产品变更与兼容性管理](../00-announcements/product-change-management.md) |
| 产品简介 | 7 | 1 | [产品简介](../01-product-introduction/README.md) |
| 购买指南 | 1 | 0 | [服务规格、配额与容量](../02-purchase-guide/service-limits-and-capacity.md) |
| 快速入门 | 3 | 1 | [快速入门](../03-quick-start/README.md) |
| 用户指南 | 110 | 25 | [用户指南](../04-user-guide/README.md) |
| 支持角色的业务 | 92 | 59 | [业务角色接入模型](../05-role-enabled-products/role-integration-model.md) |
| 支持 CAM 的业务接口 | 277 | 85 | [业务授权接入架构](../06-access-management-enabled-apis/product-authorization-integration.md)与[能力声明模型](../06-access-management-enabled-apis/authorization-capability-model.md) |
| 实践教程 | 17 | 4 | [实践教程](../07-practices/README.md) |
| 商用案例 | 33 | 9 | [典型业务集成模式](../08-commercial-cases/business-integration-patterns.md) |
| API 文档 | 156 | 16 | [API 文档](../09-api/README.md) |
| 常见问题 | 5 | 1 | [常见问题](../10-faq/faq.md) |
| 联系我们 | 1 | 0 | [支持与安全事件协作](../11-contact/support-and-security-escalation.md) |
| 词汇表 | 1 | 0 | [访问管理词汇表](../12-glossary/glossary.md) |
| **合计** | **706** | **202** | **908 个来源节点** |

## 用户指南子树映射

| 来源子树 | 产品文档 |
| --- | --- |
| 用户、主账号、子用户、协作者、消息接收人、用户设置 | [账号、用户与生命周期](../04-user-guide/users/accounts-users-and-lifecycle.md)、[登录与操作保护](../04-user-guide/users/login-and-operation-protection.md) |
| 访问密钥 | [访问密钥生命周期](../04-user-guide/access-keys/access-key-lifecycle.md) |
| 用户组 | [用户组与批量授权](../04-user-guide/groups/groups-and-bulk-authorization.md) |
| 角色、基于资源的服务角色、角色审计 | [角色文档](../04-user-guide/roles/README.md) |
| 用户 SSO、角色 SSO、SAML/OIDC 身份提供商 | [单点登录与身份联合](../04-user-guide/identity-providers/sso-and-identity-federation.md) |
| 策略定义、语法、评估、资源、变量、条件、版本、分析器 | [策略文档](../04-user-guide/policies/README.md) |
| 权限边界 | [权限边界与委派管理](../04-user-guide/permission-boundaries/permission-boundaries-and-delegation.md) |
| 排除故障 | [授权故障诊断](../04-user-guide/troubleshooting/authorization-troubleshooting.md) |
| 安全分析报告 | [安全分析报告](../04-user-guide/security-analysis-report.md) |

## 抽象口径

- 来源页面用于识别产品能力、领域关系、协议、安全语义、业务接入维度和运维场景。
- 本地正文使用供应商中立的产品语言重新组织，不依赖任何既有代码库或实施阶段。
- 腾讯云特有账号编号、QCS 字符串、控制台文案、接口名和截图只保留在来源链接，不成为本地产品契约。
- 相同技术能力在大量产品页面中重复时，统一抽象为角色接入或授权能力声明，不为每个云产品复制一份正文。
- 来源导航逐节点保留，因此所有子菜单均可反查到原页面；产品文档按能力域合并，避免把厂商页面切分方式误当领域边界。

## 主要架构来源

1. 腾讯云，“[CAM 概述](https://cloud.tencent.com/document/product/598/10583)”。
2. 腾讯云，“[基本概念](https://cloud.tencent.com/document/product/598/54591)”。
3. 腾讯云，“[策略语法](https://cloud.tencent.com/document/product/598/10604)”。
4. 腾讯云，“[策略评估逻辑](https://cloud.tencent.com/document/product/598/10605)”。
5. 腾讯云，“[角色基本概念](https://cloud.tencent.com/document/product/598/19421)”。
6. 腾讯云，“[SSO 概览](https://cloud.tencent.com/document/product/598/96014)”。
7. 腾讯云，“[权限边界](https://cloud.tencent.com/document/product/598/48770)”。
8. 腾讯云，“[ABAC 概述](https://cloud.tencent.com/document/product/598/74876)”。
9. 腾讯云，“[支持角色的业务](https://cloud.tencent.com/document/product/598/85165)”。
10. 腾讯云，“[支持 CAM 的业务接口](https://cloud.tencent.com/document/product/598/67350)”。
11. 腾讯云，“[API 概览](https://cloud.tencent.com/document/product/598/33155)”。
12. 腾讯云，“[完整访问管理文档](https://cloud.tencent.com/document/product/598)”。
