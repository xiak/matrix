# 阅读覆盖与来源目录

## 范围与阅读等级

本集合的资料核对日期为 **2026-09-10**。来源以腾讯云中国站 CAM 产品文档和 `2019-01-16` 管理 API 为主；角色临时会话补充 STS 文档。下表日期指页面显示的最近更新时间，不代表整页的每一条规则都在该日变更，也不代表实测日期。

当前核对了 CAM API 概览中的 **95 个接口条目**，其中详细阅读 **23 个关键 CAM 接口**；另详细阅读 **3 个 STS 接口**。这不是“95 个接口参数全部精读”，也不是“CAM 全站已读完”。概念、指南与剩余接口的范围分别列在下方。

| 阅读等级 | 能够支持什么 | 不能证明什么 |
| --- | --- | --- |
| 目录核对 | 当前入口、名称、分类及简述 | 完整参数、错误语义、运行行为 |
| 正文／相关章节已读 | 对应概念、流程、限制及示例 | 全部链接的递归覆盖、生产验证 |
| 接口契约详读 | 参数、结果、相关示例与业务错误 | 私有控制台实现、跨接口事务保证 |
| 局部核对 | 明确标出的字段或安全说明 | 整份参考页已读 |
| 界面观察 | 实际看见的布局、信息和未提交交互 | 保存、权限变更和真实资源访问成功 |

## 目录与公共契约

全部来源的发布者均为**腾讯云**；链接指向原始页面，未使用转载作为技术证据。

| 来源 | 页面更新时间 | 阅读范围 |
| --- | --- | --- |
| [CAM 文档首页](https://cloud.tencent.com/document/product/598) | 目录无统一适用日期 | 导航入口与相关章节定位，非递归全站覆盖 |
| [CAM API 概览](https://cloud.tencent.com/document/product/598/33155) | 2026-06-24 | 95 个条目：其他 1、用户 38、策略 19、角色 21、身份提供商 16 |
| [公共参数](https://cloud.tencent.com/document/api/598/33158) | 2024-11-15 | 签名 v3 的公共头、版本、时间、Token、地域等；未逐行验证旧签名实现 |
| [数据结构](https://cloud.tencent.com/document/api/598/33167) | 未记录 | 局部字段核对；不计入完整详读 |
| [STS API 概览](https://cloud.tencent.com/document/api/1312/48207) | 2026-02-16 | 7 个条目的目录；详读范围仅以下三项会话接口 |

## 概念与指南来源

这一节拥有来源元数据；结论归相应主题，避免把索引再写成第二份报告。

### 身份与产品边界

| 来源 | 页面更新时间 | 已读范围／用途 |
| --- | --- | --- |
| [访问管理概述](https://cloud.tencent.com/document/product/598/10583) | 2024-03-04 | 产品定位与身份、资源访问控制概述 |
| [产品功能](https://cloud.tencent.com/document/product/598/10586) | 2023-04-27 | 功能说明，特别是最终一致性 |
| [使用限制](https://cloud.tencent.com/document/product/598/10609) | 2026-08-19 | 账号、组、角色、策略与关联配额；未转成 Matrix 常量 |
| [用户类型](https://cloud.tencent.com/document/product/598/13665) | 2023-08-25 | 子用户、协作者、消息接收人等差异 |
| [新建用户组](https://cloud.tencent.com/document/product/598/14985) | 2024-10-12 | 基本信息、关联策略、审阅等流程 |
| [角色概述](https://cloud.tencent.com/document/product/598/19420) | 2024-10-12 | 角色身份及使用场景 |
| [基本概念：角色](https://cloud.tencent.com/document/product/598/19421) | 2026-05-09 | 信任、权限、服务角色和服务相关角色；旧入口跳转到此 |
| [支持角色的业务](https://cloud.tencent.com/document/product/598/85165) | 2026-09-08 | 服务相关角色说明与选定目录条目；不是全部角色能力测试 |
| [批量计算服务相关角色](https://cloud.tencent.com/document/product/598/90384) | 2026-09-10 | 角色、载体、预设策略及跨产品动作示例；未真实授权 |
| [日志服务匿名分享服务相关角色](https://cloud.tencent.com/document/product/598/103362) | 2026-08-25 | 场景、载体和权限示例；未启用匿名分享 |
| [SSO 概览](https://cloud.tencent.com/document/product/598/96014) | 2025-11-18 | 用户／角色 SSO、SAML／OIDC 能力比较 |

### 策略、资源与评估

| 来源 | 页面更新时间 | 已读范围／用途 |
| --- | --- | --- |
| [权限与策略](https://cloud.tencent.com/document/product/598/10600) | 2025-06-09 | 权限、策略类型、默认授权与资源所有者 |
| [策略概念](https://cloud.tencent.com/document/product/598/38503) | 2025-08-01 | 身份策略、资源策略、ACL 与跨账号区别 |
| [语法结构](https://cloud.tencent.com/document/product/598/10604) | 2026-06-05 | 策略字段、语法与上下文限制 |
| [资源描述方式](https://cloud.tencent.com/document/product/598/10606) | 2026-04-10 | QCS 各段、所有者与通配范围 |
| [策略变量](https://cloud.tencent.com/document/product/598/10607) | 2024-10-11 | 变量使用位置与示例 |
| [评估逻辑](https://cloud.tencent.com/document/product/598/10605) | 2024-10-11 | 默认拒绝、允许、显式拒绝及评估顺序 |
| [生效条件概述](https://cloud.tencent.com/document/product/598/73088) | 2024-10-11 | 条件组合、集合与缺失键语义 |
| [条件键和条件运算符](https://cloud.tencent.com/document/product/598/10608) | 2024-07-24 | 通用键、类型、运算符与限制 |
| [基于标签的访问控制](https://cloud.tencent.com/document/product/598/74876) | 2024-10-10 | 标签授权概念和适用范围 |
| [使用角色实现基于属性的访问控制](https://cloud.tencent.com/document/product/598/76175) | 2024-02-29 | 角色／会话属性与资源、请求标签示例 |
| [权限边界](https://cloud.tencent.com/document/product/598/48770) | 2024-10-10 | 权限上限、不直接授予权限与列表限制 |
| [权限策略中的 deny 不生效的场景](https://cloud.tencent.com/document/product/598/73561) | 2024-10-11 | 列表、COS 与财务等例外 |
| [支持 CAM 的业务接口／授权粒度](https://cloud.tencent.com/document/product/598/98576) | 2026-09-08 | 服务级、操作级、资源级定义；未逐产品逐动作验证 |
| [支持 CAM 的业务接口概览](https://cloud.tencent.com/document/product/598/67350) | 2026-09-09 | 产品简称、粒度、控制台与标签支持维度及选定目录入口 |
| [批量计算接口授权](https://cloud.tencent.com/document/product/598/99236) | 2026-08-07 | 操作分类、逐动作粒度、资源模板和 IP 支持的差异 |
| [对象存储接口授权](https://cloud.tencent.com/document/product/598/69901) | 2026-08-07 | 基本信息与选定对象、桶、向量接口的资源模板；不声称完整 COS 动作覆盖 |
| [重要预设策略说明](https://cloud.tencent.com/document/product/598/105584) | 2026-08-07 | 全局预设、专用条件与特定历史版本说明 |
| [策略相关问题](https://cloud.tencent.com/document/product/598/18795) | 2026-06-12 | 只读、关联依赖、资源列表与授权粒度常见问题 |

### 创建、版本与安全操作

| 来源 | 页面更新时间 | 已读范围／用途 |
| --- | --- | --- |
| [通过策略生成器创建自定义策略](https://cloud.tencent.com/document/product/598/37739) | 2026-04-29 | 服务、操作、资源、条件及关联流程 |
| [按标签创建策略](https://cloud.tencent.com/document/product/598/80788) | 2026-04-29 | 请求／资源标签、组合匹配、额外授权与拆分限制 |
| [策略版本控制](https://cloud.tencent.com/document/product/598/37301) | 2024-10-22 | 新建修订、默认版本、回滚与版本配额 |
| [策略分析器](https://cloud.tencent.com/document/product/598/107704) | 2024-06-26 | 正文与错误、警告、建议检查列表；不是授权模拟器实测 |
| [主账号访问密钥管理](https://cloud.tencent.com/document/product/598/40488) | 2026-05-09 | 局部核对安全说明、一次性 SecretKey 和配额；未逐个执行操作流程 |
| [查看访问密钥活跃时间](https://cloud.tencent.com/document/product/598/120122) | 2026-04-27 | 数据时效、更多记录与轮换说明 |
| [访问密钥网络访问限制策略](https://cloud.tencent.com/document/product/598/131331) | 2026-07-06 | 正文与配置范围、规则覆盖、网络来源和传播限制 |
| [跨账号访问角色](https://cloud.tencent.com/document/product/1312/48171) | 2024-09-27 | STS 跨账号委派场景；未实际配置跨账号角色 |

## CAM 接口详读清单

以下 **23 项**核对了公开入参、出参及相关业务错误；没有发起有副作用的云 API。具体设计含义归 [管理 API 契约](../api/contracts.md)，不在此重复。

### 用户、用户组与密钥：4 项

| 接口原文 | 页面更新时间 | 契约关注点 |
| --- | --- | --- |
| [AddUser](https://cloud.tencent.com/document/api/598/34595) | 2025-09-12 | 创建身份、访问方式与返回值 |
| [CreateGroup](https://cloud.tencent.com/document/product/598/34582) | 2025-09-12 | 创建组与标识 |
| [AddUserToGroup](https://cloud.tencent.com/document/api/598/34594) | 2025-09-12 | 成员关联、批量结构与限制 |
| [CreateAccessKey](https://cloud.tencent.com/document/api/598/82370) | 2025-09-12 | 目标身份、敏感结果与操作边界 |

### 策略：12 项

| 接口原文 | 页面更新时间 | 契约关注点 |
| --- | --- | --- |
| [ListPolicies](https://cloud.tencent.com/document/api/598/34570) | 2026-07-08 | 分页、范围、关键词与列表摘要 |
| [GetPolicy](https://cloud.tencent.com/document/api/598/34574) | 2025-12-26 | 文档、元数据与类型 |
| [CreatePolicy](https://cloud.tencent.com/document/api/598/34578) | 2025-12-26 | 新建策略与文档校验 |
| [UpdatePolicy](https://cloud.tencent.com/document/api/598/34569) | 2025-10-29 | 默认版本原位更新、定位字段 |
| [DeletePolicy](https://cloud.tencent.com/document/api/598/34577) | 2025-12-25 | 批量删除契约及未说明的边界 |
| [CreatePolicyVersion](https://cloud.tencent.com/document/api/598/43842) | 2025-10-29 | 新建修订、是否设为默认 |
| [DeletePolicyVersion](https://cloud.tencent.com/document/api/598/43841) | 2025-09-12 | 删除版本与默认版本限制 |
| [ListPolicyVersions](https://cloud.tencent.com/document/api/598/43839) | 2025-09-12 | 版本 ID、时间与默认标识 |
| [SetDefaultPolicyVersion](https://cloud.tencent.com/document/api/598/43838) | 2025-09-12 | 生效版本切换 |
| [ListAttachedUserAllPolicies](https://cloud.tencent.com/document/api/598/67728) | 2025-09-12 | 直接与组继承授权来源 |
| [ListEntitiesForPolicy](https://cloud.tencent.com/document/api/598/34571) | 2025-09-12 | 策略关联主体反查 |
| [AttachUserPolicy](https://cloud.tencent.com/document/api/598/34579) | 2025-09-12 | 策略与用户的关联命令 |

### 角色：4 项

| 接口原文 | 页面更新时间 | 契约关注点 |
| --- | --- | --- |
| [CreateRole](https://cloud.tencent.com/document/product/598/36225) | 2025-09-12 | 信任文档、会话与登录参数 |
| [UpdateAssumeRolePolicy](https://cloud.tencent.com/document/api/598/36219) | 2025-09-12 | 角色信任更新 |
| [DeleteServiceLinkedRole](https://cloud.tencent.com/document/api/598/43710) | 2025-09-12 | 异步删除任务 |
| [GetServiceLinkedRoleDeletionStatus](https://cloud.tencent.com/document/product/598/43709) | 2025-09-12 | 任务状态、失败与关联资源 |

### 身份提供商：3 项

| 接口原文 | 页面更新时间 | 契约关注点 |
| --- | --- | --- |
| [CreateUserOIDCConfig](https://cloud.tencent.com/document/api/598/72091) | 2026-01-30 | 用户映射、单一提供商与 SAML 切换影响 |
| [CreateOIDCConfig](https://cloud.tencent.com/document/api/598/73473) | 2026-07-01 | 角色 OIDC 提供商参数与轮转 |
| [CreateSAMLProvider](https://cloud.tencent.com/document/api/598/34567) | 2025-09-12 | 元数据、名称与提供商标识 |

## STS 补充详读：3 项

这些接口不计入上面的 23 个 CAM 接口。详细说明归 [联合身份与凭证](../concepts/federation-and-credentials.md)。

| 接口原文 | 页面更新时间 | 契约关注点 |
| --- | --- | --- |
| [AssumeRole](https://cloud.tencent.com/document/api/1312/48197) | 2025-09-12 | 信任与扮演授权、会话参数和临时凭证 |
| [AssumeRoleWithSAML](https://cloud.tencent.com/document/api/1312/48196) | 2025-09-12 | SAML 断言、提供商、角色与凭证交换 |
| [AssumeRoleWithWebIdentity](https://cloud.tencent.com/document/api/1312/73070) | 2026-02-16 | OIDC 身份令牌、提供商与角色会话 |

## 界面观察来源

访问前提是已登录的腾讯云控制台；页面可能因账号、语言、权限与灰度版本不同而变化。已有详细观察及 Matrix 实现契约归 [FEAT-007](../../../features/FEAT-007-control-plane-console.md)，本集合不建立第二份验收记录。

| 页面 | 本集合使用的观察范围 | 证据边界 |
| --- | --- | --- |
| [策略目录](https://console.cloud.tencent.com/cam/policy) | 策略表格与权限级别分类 | 观察窗口为 2026-09-09 至 2026-09-10；未复制私人账号库存 |
| [AdministratorAccess 详情](https://console.cloud.tencent.com/cam/policy/detail/1&AdministratorAccess&2&All) | 预设策略文档、摘要、版本与关联视角 | 只读，不修改预设或授权 |
| 策略目录中的自定义策略入口 | CVM 服务、操作分类、资源范围、条件与标签表单 | 未提交；具体接口行为另以官方文档为据 |
| [快速创建用户](https://console.cloud.tencent.com/cam/user/create?systemType=FastCreateV2) | 2026-09-10 策略选择弹层：左右候选／已选表格、全选与增量加载、批量限制及风险提示 | 临时选择后取消，原草稿无权限；未创建用户、应用权限或执行安全验证；机制归[访问管理 UX](../ux/access-management.md) |

## 未覆盖项与继续阅读入口

剩余 **72 个 CAM 接口**目前只核对目录，不将用户删除、所有组／角色关联、所有安全配置等未经详读的接口参数补写成事实。继续接入时，从 [CAM API 概览](https://cloud.tencent.com/document/product/598/33155) 打开对应接口，再更新本页阅读等级；不需要先读完全部接口。

产品级授权仍需按服务核对 [授权粒度入口](https://cloud.tencent.com/document/product/598/98576)，特别是每个 Action 是否支持资源、条件和列表过滤。本集合没有完整收录全云产品动作目录。

STS 的 GetFederationToken 等剩余接口、完整 SDK 与签名实现、企业组织／SCP 完整评估规则，以及真实 SSO、会话撤销和跨区域传播测试均未完整覆盖。矛盾和不能外推的结论归 [证据限制](caveats.md)，不能以某个相关页面已读来填补这些空白。
