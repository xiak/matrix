# 员工资源隔离

员工资源隔离把组织职责映射为产品动作与资源范围，使不同部门、项目或环境只能访问自己的资源。常见方法是按资源 ID 授权和按标签授权，两者可以组合。

员工资源隔离可以分别通过资源 ID 和标签实现。[^1]

## 按资源 ID 授权

适合资源数量少、边界稳定、例外明确的场景。策略直接列出资源或资源路径：

```json
{
  "effect": "allow",
  "actions": ["compute.instance.read", "compute.instance.start"],
  "resources": [
    "crn:compute:region-a:account-1:instance/i-team-a-01",
    "crn:compute:region-a:account-1:instance/i-team-a-02"
  ]
}
```

优点是权限清晰且不依赖标签治理；缺点是新资源需要更新策略，资源频繁变化时容易产生遗漏。

## 按标签授权

适合资源规模大、项目属性稳定的场景。主体具有 `project=alpha` 属性，资源具有同名标签，策略比较二者：

```yaml
effect: allow
actions: [compute.instance.read, compute.instance.start]
resources: ["crn:compute:*:account-1:instance/*"]
conditions:
  equals_ref:
    resource.tag.project: principal.tag.project
```

新资源只要在创建事务中写入正确标签即可进入权限范围。标签修改是安全敏感操作，不能让普通用户通过修改标签扩大自己的访问。

## 组合边界

资源 ID 限定账号、地域或父资源，标签再限定项目与环境。例如：只允许账号 A 的生产区域中 `project=alpha` 的实例。明确拒绝可以保护共享基础设施或安全资源。

## 列表与控制台

资源隔离必须覆盖列表、详情、监控、日志、关联资源和批量 API。产品在服务端过滤无权资源，并防止通过总数、名称搜索、错误差异或关联对象泄露资源存在性。

## 生命周期

1. 入职时为员工或组设置部门/项目属性。
2. 资源创建时强制写入所有权标签。
3. 产品 Profile 声明哪些动作支持资源和标签条件。
4. 策略同时覆盖主资源与必要的关联资源。
5. 项目调动先改变权限，再按流程迁移资源所有权标签。
6. 离职时撤销用户会话和密钥，组成员关系自动失效。

## 验证矩阵

隔离测试至少包含同项目允许、跨项目拒绝、无标签资源拒绝、修改标签拒绝、列表不侧漏、批量混合资源拒绝和关联资源越权。

## Sources

[^1]: 腾讯云，“[支持员工间资源隔离访问概述](https://cloud.tencent.com/document/product/598/74104)”，访问于 2026-09-10；另见“[按照资源 ID 授权](https://cloud.tencent.com/document/product/598/74183)”与“[按照标签授权](https://cloud.tencent.com/document/product/598/74184)”。
