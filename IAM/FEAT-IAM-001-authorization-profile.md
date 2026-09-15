# FEAT-IAM-001：业务授权能力目录

- 状态：CAT-01–04 首片已验收（固定 `3b11eb9`）；CAT-05 已实现源码登记的 Profile 及当前目录投影，实际决定/PolicyVersion 的版本绑定与历史注册尚未实施，本 FEAT 整体未验收。
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

005 的时间条件增量在本 owner 声明 `iam.current-time`：类型 TIME，来源 IAM_TRANSACTION_TIME。当前目录中 TENANT 动作声明该键，INSTALLATION 与 INSTALLATION_PROBE 不声明；未知动作/键无能力。只读 `LookupActionConditionDefinition` 返回值副本，静态校验、生成 schema 与唯一评估器使用同一来源定义；没有通用调用者属性 map。该局部来源声明不等于已交付完整签名 AuthorizationProfile、revision/digest、资源粒度或业务属性接入，CAT-05 仍未完成。时间算子、窗口与事务/历史语义由 005 唯一规定。

005 字符串切片在同一目录增加 `iam.account-id` 与 `iam.principal-id`：类型 STRING，来源 IAM_AUTHENTICATED_IDENTITY。分别绑定当前 IAM 权威身份的 Account 和主体稳定 ID，仅对 TENANT/USER 启用；不接受产品请求自报的值，不将 Group/策略/资源的归属误作当前调用者身份。它们是 IAM 内置身份条件，不按产品名称分叉，也不开放租户自行注册来源。契约与唯一求值器已经接入，运行证据、算子、集合、缺失和 canonical 行为归 005；完整 Profile 与业务条件仍按 CAT-05/008 验收。

## 事务与权限

### CAT-05 下一纵向切片：可验证的产品 Profile

该切片以源码登记的 Profile 替换原平铺动作目录；当前授权校验和条件能力读取它的确定投影，保留既有动作顺序、scope、caller、resource与prefix语义，尚未改变请求/结果/SQL形状。之后须在实际决定中绑定不可变 revision/contentDigest，再由005消费冻结的动作集合；不能先在求值器加入字符串 Action 前缀匹配，最后补历史证明。

产品 Profile 必须同时约束产品标识、允许调用的已认证服务、Action、scope、资源种类、请求目标模式、集合行为与可信条件能力。产品名或 Action 字符串只作为标识，不能推导调用权限或粒度。内容不可变、同产品同 revision 不得对应另一 digest；digest 覆盖所有影响授权解释的字段。返回副本不能修改注册目录。注册来源仍由可信产品发布/服务组合控制，不开放租户上传 Profile 或借此注册平台动作。

纯声明编码由 `api/iam/v1/authorization_profile.go` 唯一拥有，不复制 Policy/Audit 编码。`AuthorizationProfile` 包含 `apiVersion/kind/product/revision/callingService/actions`；每个动作显式给出 `resourceKind/scope/resourceShapes/conditions`，末尾可声明 `resultResourceKind`。后者与授权目标正交：既可表达集合创建，也可表达对父Account实例授权后创建User/Group/Policy。`INSTANCE` 可以声明租户实例前缀；`COLLECTION` 只能声明 `COLLECTION_LIST` 或 `COLLECTION_CREATE`，不支持 prefix、filter 或 batch。集合创建必须声明动作级result；含集合LIST时不得声明创建结果，不允许同动作LIST+CREATE。结果仅是成功事实种类，不是API返回载荷、最终ID或payload证明，不能替换原decision资源。shape不接受result字段或兼容别名。

`DecodeAuthorizationProfile` 沿现有严格 JSON owner 拒绝重复/未知/大小写别名字段，输入与程序内声明都受64KiB、128动作上限约束。动作/形状/条件分别按集合排序，输入保持不变；`CanonicalizeAuthorizationProfile` 使用 `matrix.iam.authorization-profile.v1` 域分隔摘要，`CheckAuthorizationProfileReference` 精确比较 `product/revision/contentDigest`，不接受“更新版本即可兼容”。可选条件省略、null、空集合都规范为不声明任何条件能力；来源仍复用唯一 IAM 封闭定义。产品/服务标识的语法允许未来产品，但语法通过、摘要匹配均不构成注册、签名认证或授权。

现有 `enums.go` 是源码登记owner，按产品组合的Profile声明是当前唯一数据源。`AllActions`、`ActionDefinition`、资源/scope/service admission、条件能力及生成器从它派生；不存在第二份可编辑的action map。源码登记每产品只有一个当前revision，缺项/无效声明/重复产品会在服务启动前关闭，公开读取深拷贝所有嵌套集合，不能修改授权目录。历史已退休动作只保留原有不可变决定解码边界，不进入当前Profile。声明注册不代表产品已取得目标Account权限；历史Profile保存、同revision变体的持久拒绝、签名发布及线上版本绑定仍须后续注册事务证明。

目标模式不能只有一个从动作后缀推断的 INSTANCE 标记。当前真实调用者至少存在三种情况，必须在首片全部覆盖：

| 当前拥有者与动作 | 必须登记并验证的语义 |
| --- | --- |
| IAM `iam.user.create` / `iam.group.create` / `iam.policy.create` | 对当前父Account实例授权；成功资源分别为User/Group/Policy，不能反过来拿子资源替代Account授权 |
| IAM `iam.group-membership.create` | 对实际父Group实例授权，成功关系为GroupMembership；归属仍由原事务验证 |
| PaaS `paas.application.create` | HTTP owner先检查集合，成功事实再绑定最终 Application；集合授权不是最终ID/payload证明 |
| PaaS `paas.application.read` | 精确实例ID；已验证的资源前缀只对该入口声明支持，不替代数据库tenant隔离 |
| managedservice `managedservice.offering.read` | 同一动作的列表入口检查集合、详情入口检查实例；列表当前是整体授权，不支持按策略实例过滤 |

以上映射来自现有 apphosting/managedservice HTTP owner，不能用更改动作名称或假装拆成两个已经存在的 API 绕过混合模式。Profile 可声明同一动作允许的多个闭合目标模式；实际调用必须明确选择并被对应 PEP 校验。未知模式、未实现的 FILTERED 或 batch 能力、错服务/产品/scope、同 ResourceKind 的另一动作均关闭。

本分支当前PaaS声明只包含已有5个平台动作，不是最终PaaS公共产品目录。固定 `be3c4a96b4381426c01cd6315eaa3713c2855982` 的实际PEP证明 pool.create/target.register 对body实际ID做INSTANCE授权，pool.read/target.read兼有集合列表与实例详情；此片只引用其形状，不导入host实现。最终ABI前须按该固定源适配完整12项平台动作、NODE_ENROLLMENT及对应约束/系统策略显式新版本，推进PaaS Profile revision/digest。node-enrollment.create的collection→ExecutionTarget历史映射和其余exact enrollment请求必须保留；中间5项目录不得冒充最终验收。

首片的实质门禁是两个真实产品通过同一注册/校验路径，IAM实际决定与持久化证据绑定精确 Profile，PEP拒绝不匹配的回包；修改或增加 Profile 不能改变已经固定的旧版本解释。新增产品声明不得要求通用求值器按产品名称增加分支。未声明来源的条件不能启用；当前IAM自供身份/事务时间继续独立于产品属性，不增加任意 caller attributes map。

历史决定和 outbox 使用发生时的不可变 Profile/PolicyVersion 证据，当前生产者凭据仍需有效；不能在重放时拿最新注册目录重新扩张或重新授权。对外请求/结果的精确字段、持久化形状和消费者切换须在这组语义完成代码核对后统一冻结，当前不提前改schema/profile数字。真实旧消费者无法原子切换时单列支持或拒绝边界，不用未发布schema编号相等作兼容证明。

验收沿现有契约、authority、IAM/PG和authorityprocess owner：定义重排的稳定摘要、变体/重复/未知能力拒绝、注册副本隔离、两产品集合/实例正反例、实际不同服务与scope拒绝、同账号/跨账号同ID、旧决定在目录更新后的精确重放。011的当前数据重放与受限runtime门禁保留；完整签名Profile发行、list过滤、batch和业务标签未证明前不得声明CAT-05/008整体完成。

005 的资源前缀切片在同一 `ActionDefinition` 增加 `ResourcePrefixAllowed`，默认 false；当前只为已验证传入精确实例 ID 的 `paas.application.read` 声明 true。语法验证、生成 schema 和唯一 PDP 均读取该能力，不依据服务名称、Action 后缀或 ResourceKind 推断。create/list/collection、platform/probe 以及新加入但未声明的动作均不支持 PREFIX；其他实例能力须随真实 PEP/粒度门禁逐项登记。SQL 发布不变量由既有存储 owner 执行，并以所有当前 Action 的真实 PG 正/负校验对照该目录，不把手写 SQL 约束声称为另一可编辑目录。此声明不是完整 Profile/granularity 或所有业务前缀能力验收。

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

2026-09-15 CAT-05 源码登记与当前目录投影门禁：

- 既有 `api/iam/v1/contract_test.go` 验证产品声明与当前admission/条件能力一致、嵌套返回值不可修改目录、未知产品不被注册、重复/错命名空间声明启动前拒绝、父实例与集合创建结果分离、混合read形状和精确引用。使用不同名称的产品通过相同纯投影路径，不能修改全局目录或取得权限；没有依赖产品名称分支。
- API、IAM、Audit、PaaS 与 architecture 的 `-race -p 2` 回归、对应 vet、API生成稳定及 Linux amd64 构建通过；包含父实例/集合创建种子的2-worker、20s规范往返 fuzz 通过94701次执行。原Action枚举与生成wire未变化。
- 独立 PG18 固定镜像 `postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280`，1CPU/768MiB/PIDs128、max_connections64；三个专属数据库与loopback随机端口。串行 `-race -p 1` 实跑 IAM HTTP（82.52s；包85.579s）、独立 IAM/Audit/PaaS 与双dispatcher（56.47s；包59.724s）、策略存储门禁（141.91s；包145.201s）。保留实际受限runtime登录、两租户资源/Operation/outbox、组继承、边界竞争、条件与SQL目录一致性、当前撤权和历史证据不可修改。
- 本轮容器、网络及包含三个临时数据库的卷已按精确ID/标签清理，连接归零后删除；不涉及其他任务资源。本片没有 SQL/线上请求结果/安装 profile 变化。以上真实运行证明当前目录替换不回归，不证明决定已携带Profile、历史Profile持久化、签名发布或最终12项PaaS目录；这些仍按001/008后续门禁完成。

CAT-05、策略替换及最终组合仍分别按 owning FEAT 实施。
