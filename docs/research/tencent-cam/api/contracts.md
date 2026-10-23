# CAM 管理 API 契约与状态流程

## API 分类不等于领域边界

当前 CAM API 概览包含用户、策略、角色、身份提供商和其他接口。目录同时混合身份生命周期、安全设置、凭证管理和关联查询，因此不能把目录分类直接复制成数据库结构或后端限界上下文。完整目录与详细阅读范围见 [覆盖记录](../evidence/reading-map.md)。[^1]

本文记录公开管理契约及其设计含义，不推断腾讯控制台实际使用的私有接口。公开 ListPolicies 的 Keyword 文档描述为策略名搜索；控制台若提供更广的检索体验，也不能直接证明该公开参数能搜索任意正文。[^2]

## 列表、详情与授权来源

| 操作 | 公开契约要点 | 对界面的含义 |
| --- | --- | --- |
| ListPolicies | Page/Rp 分页；Scope 区分全部、预设、自定义；Keyword | 筛选状态与查询缓存应分开 |
| GetPolicy | 文档、类型、描述、更新时间、备注、标签等 | 详情不是将列表行无限展开 |
| ListAttachedUserAllPolicies | 直接／随组关联筛选，保留来源组 | 同一策略可显示多条授权路径 |
| ListEntitiesForPolicy | 反查关联 User／Group／Role | 修改、删除前可以解释影响对象 |

这些接口共同说明“列表摘要”“策略内容”“谁在使用”“授权从哪里来”是不同查询视角。反向关联一个用户组，不意味着返回值已枚举该组全部受影响成员；是否展开间接影响，应由明确的查询语义决定。[^2][^3][^4][^5]

## 创建与关联是不同管理命令

CreatePolicy 返回新 PolicyId；AttachUserPolicy 再把该策略关联到用户。CreateGroup 返回 GroupId；AddUserToGroup 建立成员关系。新建用户 AddUser 的控制台登录、是否生成 API 密钥和重置密码选项，也不是资源权限配置。[^6][^7][^8][^9][^10]

控制台将“创建对象 → 加入用户组 → 关联策略”包装成一个向导，不表示这些公开 API 跨步骤原子成功。Matrix 如果需要一次提交的体验，应明确服务端用例的事务或部分失败规则，而不是让浏览器发完多个请求后统一显示成功。

例如对象已创建但授权失败，结果页应指出已完成对象及失败步骤，提供安全重试。超时也不等于失败：创建、发行凭证等副作用不能无条件自动重发。幂等与恢复行为应写入 Matrix 自己的契约，不能从本接口目录推定腾讯已有某个幂等参数。

## 策略修订与默认版本

腾讯控制台版本指南描述编辑策略形成新修订、可切换默认版本以回滚，并限制最多保留五个版本；版本号不因删除而重新连续编号。[^11]

但公开 UpdatePolicy 明确说明：存在版本时直接更新默认版本，不创建新版本；没有版本时才创建默认版本。它与“创建修订再启用”不是相同命令。PolicyName 在该接口中可以用于定位策略，不应未经确认就当作重命名字段。[^12]

| 意图 | 对应公开接口 | 不能混淆的状态 |
| --- | --- | --- |
| 新建一个修订 | CreatePolicyVersion | SetAsDefault 决定是否同时启用 |
| 查看修订清单 | ListPolicyVersions | 浏览历史不会激活 |
| 切换生效修订 | SetDefaultPolicyVersion | 与创建新版本分离 |
| 删除历史修订 | DeletePolicyVersion | 与删除整条策略分离 |
| 修改现有默认内容 | UpdatePolicy | 不保证保留旧文档为新历史版本 |
| 删除策略对象 | DeletePolicy | 公开接口支持批量策略 ID |

各接口存在版本不存在、默认版本、组织策略禁止操作、语法错误等业务错误。DeletePolicy 文档没有完整解释所有关联场景下的清理、原子性和部分成功行为，不能编造“自动解除所有授权”或“必须先解绑”的统一事实。[^6][^12][^13][^14][^15][^16][^17]

## 角色与异步生命周期

CreateRole 接收角色名、信任 PolicyDocument、可选控制台登录和会话时长；角色权限关联是另一项职责。UpdateAssumeRolePolicy 单独修改信任文档。[^18][^19]

DeleteServiceLinkedRole 返回 DeletionTaskId，而不是已经删除成功的证明。GetServiceLinkedRoleDeletionStatus 再返回 NOT_STARTED、IN_PROGRESS、SUCCEEDED、FAILED，以及失败原因等。成功接受命令与完成任务必须区分。[^20][^21]

## 传播、错误与可观测性

腾讯产品功能文档明确说明跨区域复制和缓存会造成最终一致性。保存策略成功不等于所有鉴权节点已经使用新规则；网络访问限制更明确说明分钟级全局生效延迟。不要把这两份文档变成对全部操作统一的精确时延保证。[^22][^23]

API 的 RequestId 用于定位请求，不能当作任务 ID 或策略版本。公共参数说明推荐签名 v3、支持临时凭证 Token，并区分接口契约版本和地域是否需要。它们是腾讯云对接方式，不代表 Matrix 浏览器应持有腾讯长期密钥或自行签名。[^24]

对 Matrix 的交互建议是：先显示页面或弹层及局部加载状态，再查询数据；提交后分别表达处理中、已保存、待传播、失败与结果未知。只在后端确实能确认时才显示“已生效”。详细交互分析见 [UX 主题](../ux/access-management.md)。

## 注释

[^1]: 腾讯云，[CAM API 概览](https://cloud.tencent.com/document/product/598/33155)。
[^2]: 腾讯云，[ListPolicies](https://cloud.tencent.com/document/api/598/34570)。
[^3]: 腾讯云，[GetPolicy](https://cloud.tencent.com/document/api/598/34574)。
[^4]: 腾讯云，[ListAttachedUserAllPolicies](https://cloud.tencent.com/document/api/598/67728)。
[^5]: 腾讯云，[ListEntitiesForPolicy](https://cloud.tencent.com/document/api/598/34571)。
[^6]: 腾讯云，[CreatePolicy](https://cloud.tencent.com/document/api/598/34578)。
[^7]: 腾讯云，[AttachUserPolicy](https://cloud.tencent.com/document/api/598/34579)。
[^8]: 腾讯云，[CreateGroup](https://cloud.tencent.com/document/product/598/34582)。
[^9]: 腾讯云，[AddUserToGroup](https://cloud.tencent.com/document/api/598/34594)。
[^10]: 腾讯云，[AddUser](https://cloud.tencent.com/document/api/598/34595)。
[^11]: 腾讯云，[策略版本控制](https://cloud.tencent.com/document/product/598/37301)。
[^12]: 腾讯云，[UpdatePolicy](https://cloud.tencent.com/document/api/598/34569)。
[^13]: 腾讯云，[CreatePolicyVersion](https://cloud.tencent.com/document/api/598/43842)。
[^14]: 腾讯云，[ListPolicyVersions](https://cloud.tencent.com/document/api/598/43839)。
[^15]: 腾讯云，[SetDefaultPolicyVersion](https://cloud.tencent.com/document/api/598/43838)。
[^16]: 腾讯云，[DeletePolicyVersion](https://cloud.tencent.com/document/api/598/43841)。
[^17]: 腾讯云，[DeletePolicy](https://cloud.tencent.com/document/api/598/34577)。
[^18]: 腾讯云，[CreateRole](https://cloud.tencent.com/document/product/598/36225)。
[^19]: 腾讯云，[UpdateAssumeRolePolicy](https://cloud.tencent.com/document/api/598/36219)。
[^20]: 腾讯云，[DeleteServiceLinkedRole](https://cloud.tencent.com/document/api/598/43710)。
[^21]: 腾讯云，[GetServiceLinkedRoleDeletionStatus](https://cloud.tencent.com/document/product/598/43709)。
[^22]: 腾讯云，[产品功能：最终一致性](https://cloud.tencent.com/document/product/598/10586)。
[^23]: 腾讯云，[访问密钥网络访问限制策略](https://cloud.tencent.com/document/product/598/131331)。
[^24]: 腾讯云，[公共参数](https://cloud.tencent.com/document/api/598/33158)。

来源日期及阅读范围见 [来源记录](../evidence/reading-map.md)。
