# FEAT-IAM-001：业务授权能力目录

- 状态：CAT-01–04 首片已验收（固定 `3b11eb9`）；CAT-05 未实施，本 FEAT 整体未验收。
- 依赖：[产品契约](./FEAT-IAM-000-product-contract.md)。
- Owner：IAM 公共契约与现有 authority；产品拥有其业务词汇。
- 首片：把现有已接受的动作、允许调用服务、资源种类和 scope 收敛为一份不可变目录，所有当前验证和决定路径消费该目录。

## 需求

| ID | 行为 |
| --- | --- |
| IAM-CAT-01 | 已注册动作有唯一产品、调用服务、资源种类和权限范围；未知或缺定义拒绝 |
| IAM-CAT-02 | IAM/PaaS/managedservice/Audit/installation 通过显式登记拥有动作，不按字符串前缀猜权威 |
| IAM-CAT-03 | 租户动作、平台动作、安装 verifier probe 独立；probe 不能成为业务许可 |
| IAM-CAT-04 | 校验器、生成 schema、授权服务使用同一目录；返回副本不能修改全局定义 |
| IAM-CAT-05 | 后续 Profile 明确声明 revision、digest、资源粒度、创建/列表/批量和可信条件来源；未声明的能力不能启用 |

## 首片详细设计

在现有 `api/iam/v1` 建立值类型 `ActionDefinition` 与只读 lookup，包含 Action、Product、CallingService、ResourceKind、AuthorityScope。保留现有 Action 字面量、顺序与 schema；用新目录替代 `allActions`、资源映射 switch、平台 scope switch 和 ServiceCanRequest 的前缀分支。`INSTALLATION_PROBE` 保持现有 verifier 的 home-tenant decision 语义，只有现有固定入口可以消费。

这里只声明代码已证明的事实，不把 application-create collection ID 当最终实例，也不声称所有 read Action 已支持实例过滤。Profile 的粒度、条件、动态注册/管理 API 在真实产品 PEP 片补齐。首片不引入客户自由上传的产品定义，不变化 SQL 函数形状或 wire schema 数字。

控制台的目录展示和保守可用性提示归 010；静态登记不等于某个用户的 `allowedActions`，不能绕过资源/条件判断。

## 事务与权限

目录是发布源码常量，读取无副作用；既有 IAM 当前凭据、SERIALIZABLE 决定持久化和 outbox 事务不变。后续可写 Profile 发布必须受产品注册权威管理，不能由租户管理员声明新的 platform Action。

## 验收

- 所有已知 Action 在 API 校验、资源映射、service admission、platform 分类上结果一致。
- 租户、平台、verifier 的代表性实际允许/拒绝矩阵通过；未知服务/动作、错资源和错 scope 失败关闭。
- 修改返回集合后，后续查询和真实决定不受影响。
- 既有 unit、API schema/生成、architecture/security、PG18 IAM/Audit HTTP 和独立进程回归通过，精确 SHA CI 独立确认。
- CAT-05 的完整 Profile 能力要在 FEAT-IAM-008 通过后才可声明全部 Accepted。

## 采用与证据

复用 owner 和固定源见 [adoption](../docs/adoption/FEAT-006-platform-authorities.md)。

2026-09-11 本分支首片证据：

- `TestIAMActionDefinitionsDeclareProductServiceAndScope`、`TestIAMCatalogReadsCannotModifyAuthority` 和 `TestCatalogConfinementIsEnforcedByActualDecisions` 先因目录缺失失败，实现后通过。它们验证真实决定的调用服务/资源/scope、未知动作失败关闭及返回值不可修改目录，不快照 SQL 或文件布局。
- `go generate ./api/...` 后生成 JSON 没有差异；API、IAM、Audit、architecture 的 race 与 vet 通过。原有动作、公开 wire、ServiceIdentity、lookup_service、七列 claim、canonical 和 SQL schema/profile 均未改变。
- 独立 PG18 固定镜像 `postgres@sha256:3a82e1f56c8f0f5616a11103ac3d47e632c3938698946a7ad26da0df1334744a`，1 CPU/768 MiB/PIDs192；专属网络、卷、loopback 随机端口及六个一次性数据库。串行 `-race -p 1 -count=1` 实跑 IAM HTTP/本地恢复事务（100.449s）、Audit HTTP（3.373s）、双 authority 数据库权限/不可变性（5.811s）、独立服务进程与实际固定 `5721b7b` 旧 executable 保留升级（77.444s）。
- 进程门禁保留受限 runtime 身份探针、双租户业务/Operation/outbox、实时权限撤销、安装 verifier、producer 历史证明与原 local-recovery 事实。没有把默认跳过的数据库测试当真实门禁，也未声明新的签名包或其他 Phase 验收。

- 提交前全仓 `go test -race -p 2 ./...`、`go vet -p 2 ./...`、`go mod verify` 和 Linux amd64 全仓构建通过。任务专属 PG 容器、六个 fixture 数据库所在卷及网络已按精确标签清理；不涉及用户数据或其他任务对象。

- 固定实现 `3b11eb9dbabd70211e665c00e4e665658b461bd1` 已推送；GitHub API 核实 [Verification 34565145241](https://github.com/xiak/matrix/actions/runs/34565145241) 的精确 SHA 与 go、authority-process、node-process 全部 `completed/success`。独立 Linux PG18 job 还复跑了既有各旧版本保留升级门禁；这不等于新增跨 profile 签名升级许可。

CAT-05、策略替换及最终 IAM6 组合仍分别按 owning FEAT 实施。
