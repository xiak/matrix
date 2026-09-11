# FEAT-IAM-001：业务授权能力目录

- 状态：实施中，未验收。
- 依赖：[产品契约](./FEAT-IAM-000-product-contract.md)。
- Owner：IAM 公共契约与现有 authority；产品拥有其业务词汇。
- 首片：把现有已接受的动作、允许调用服务、资源种类和 scope 收敛为一份不可变目录，所有当前验证和决定路径消费该目录。

## 需求

| ID | 行为 |
| --- | --- |
| IAM-CAT-01 | 已注册动作有唯一产品、调用服务、资源种类和权限范围；未知或缺定义拒绝 |
| IAM-CAT-02 | IAM/PaaS/managedservice/Audit/installation 通过显式登记拥有动作，不按字符串前缀猜权威 |
| IAM-CAT-03 | 租户动作、平台动作、安装 verifier probe 独立；probe 不能成为业务许可 |
| IAM-CAT-04 | 校验器、生成 schema、授权服务和能力展示使用同一目录；返回副本不能修改全局定义 |
| IAM-CAT-05 | 后续 Profile 明确声明 revision、digest、资源粒度、创建/列表/批量和可信条件来源；未声明的能力不能启用 |

## 首片详细设计

在现有 `api/iam/v1` 建立值类型 `ActionDefinition` 与只读 lookup，包含 Action、Product、CallingService、ResourceKind、AuthorityScope。保留现有 Action 字面量、顺序与 schema；用新目录替代 `allActions`、资源映射 switch、平台 scope switch 和 ServiceCanRequest 的前缀分支。`INSTALLATION_PROBE` 保持现有 verifier 的 home-tenant decision 语义，只有现有固定入口可以消费。

这里只声明代码已证明的事实，不把 application-create collection ID 当最终实例，也不声称所有 read Action 已支持实例过滤。Profile 的粒度、条件、动态注册/管理 API 在真实产品 PEP 片补齐。首片不引入客户自由上传的产品定义，不变化 SQL 函数形状或 wire schema 数字。

## 事务与权限

目录是发布源码常量，读取无副作用；既有 IAM 当前凭据、SERIALIZABLE 决定持久化和 outbox 事务不变。后续可写 Profile 发布必须受产品注册权威管理，不能由租户管理员声明新的 platform Action。

## 验收

- 所有已知 Action 在 API 校验、资源映射、service admission、platform 分类上结果一致。
- 租户、平台、verifier 的代表性实际允许/拒绝矩阵通过；未知服务/动作、错资源和错 scope 失败关闭。
- 修改返回集合后，后续查询和真实决定不受影响。
- 既有 unit、API schema/生成、architecture/security、PG18 IAM/Audit HTTP 和独立进程回归通过，精确 SHA CI 独立确认。
- CAT-05 的完整 Profile 能力要在 FEAT-IAM-008 通过后才可声明全部 Accepted。

## 采用与证据

复用 owner 和固定源见 [adoption](../docs/adoption/FEAT-006-platform-authorities.md)。本片当前尚无新增运行验收证据。
