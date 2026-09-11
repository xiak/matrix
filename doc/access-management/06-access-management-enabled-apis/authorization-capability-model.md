# 授权能力声明模型

授权能力声明是业务产品与访问管理之间的版本化契约。它既驱动运行时校验，也驱动策略编辑、静态分析、文档生成、SDK 类型和产品接入测试。

## 示例

```yaml
api_version: iam.product/v1
product_id: object-storage
revision: 2026-09-10.1
display_name: Object Storage
authorization:
  console_access: true
  granularity: resource
  ip_conditions: true
  resource_tags: true
  request_tags: true
resources:
  - kind: bucket
    name_template: "crn:object-storage:{region}:{account}:bucket/{bucket}"
    parent: account
  - kind: object
    name_template: "crn:object-storage:{region}:{account}:bucket/{bucket}/object/{key}"
    parent: bucket
actions:
  - id: object-storage.object.read
    access_level: read
    resources: [object]
    condition_keys: [request.source_ip, resource.tag.project]
  - id: object-storage.object.create
    access_level: write
    resources: [bucket]
    creates: object
    condition_keys: [request.tag.project]
list_operations:
  - action: object-storage.object.list
    mode: server_side_resource_filter
roles:
  service_principal: object-storage.service
  supports_service_linked_role: false
```

## 产品元数据

- `product_id`：全局稳定且不可复用。
- `revision`：每次语义变化生成新修订。
- `console_access`：控制台入口是否受统一授权。
- `granularity`：服务、动作或资源级的最高实际能力。
- `ip_conditions`：哪些动作支持可信来源网络条件。
- `resource_tags` / `request_tags`：读取与创建时标签授权能力。

## 动作目录

每个动作声明 ID、读/写/列表/权限管理等访问级别、适用资源类型、必需资源数量、条件键、是否创建资源和风险等级。动作删除或改变语义是不兼容变更；新动作默认不因旧策略通配符自动获得允许，除非策略明确选择动态通配语义并通过风险提示。

## 资源目录

资源类型声明规范名称模板、所属账号、地域语义、父类型、可用动作、标签能力和资源解析方式。资源 ID 中的用户输入在生成规范名之前转义和验证。

## 条件目录

产品条件键声明类型、数据所有者、允许操作符、敏感性、缺失行为和可用于哪些动作。通用条件由 IAM 注册，产品不得用同名键改变含义。

## 授权粒度

- **服务级**：只能允许或拒绝整个产品入口。
- **动作级**：可以区分 API 动作，但不能限制具体资源。
- **资源级**：动作可绑定一个或多个规范资源。

一个产品可以按动作声明不同粒度；产品总体页面展示最低安全事实，而不是把部分动作的资源级能力推广到全部动作。

## 兼容规则

| 变更 | 兼容性 |
| --- | --- |
| 新增动作 | 兼容，但默认不授权 |
| 新增可选条件键 | 兼容 |
| 动作新增必需资源 | 不兼容 |
| 改变资源所属账号语义 | 不兼容 |
| 将资源级降为服务级 | 安全不兼容 |
| 修改条件键类型 | 不兼容 |
| 提升授权粒度 | 兼容迁移，需策略影响分析 |

## 注册与验证

Profile 随产品构建签名或内容寻址。安装与升级先验证 schema、兼容性、动作唯一性、资源引用闭包和条件类型，再原子注册。产品只有在 Profile 可用后进入就绪状态；PDP 记录每次决定使用的修订。

## 文档生成

产品授权参考表由 Profile 生成，至少包含 API、动作、访问级别、资源类型、是否支持资源级、条件键、IP 条件、标签条件和角色要求。机器可读能力声明是接入文档的单一来源。[^1]

## Sources

[^1]: 腾讯云，“[CloudBase 支持 CAM 的业务接口](https://cloud.tencent.com/document/product/598/98174)”，访问于 2026-09-10；产品目录见[完整来源导航](../sources/tencent-cam-navigation.md)。
