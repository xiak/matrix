# FEAT-IAM-011：交付与需求验收

- 状态：设计；整体未验收。
- Owner：IAM 组合验收；安装命令/签名/profile admission 与既有 FEAT-005/008 owner 协作。

## 验收定义

| ID | 最终门禁 | 证据拥有者 |
| --- | --- | --- |
| IAM-AC-01 | 000 的本轮需求 ID 全部分配到已实现接口/用例/测试，无无主需求 | 各 IAM FEAT；本文件只汇总结论 |
| IAM-AC-02 | 单元、architecture、security、fuzz/并发测试覆盖当前不变量 | 现有 test/architecture 与相应 owning tests |
| IAM-AC-03 | PostgreSQL 18 真数据库、受限 runtime 登录、RLS/函数越权攻击 | 现有 IAM/Audit integration 与 authorityprocess |
| IAM-AC-04 | 双账号 root/admin/member/role/service 完整业务与拒绝矩阵 | authorityprocess，真实 IAM/Audit/PaaS 进程 |
| IAM-AC-05 | 已提交审计/outbox、hash chain、重放、暂停和历史证据关联 | Audit 与各 source owner |
| IAM-AC-06 | 当前基线带数据重放/重启，撤销/凭据/原 root 不复活；只有明确支持的数据保留起点才增加旧 binary 升级门禁 | 当前 IAM integration/authorityprocess；明确的历史起点另行冻结 |
| IAM-AC-07 | 同完整 profile 签名 A/B 安装、保留升级/回滚/备份恢复；跨 profile 效果前拒绝 | 原安装 gate，与安装 owner 固定交接 |
| IAM-AC-08 | IAM 控制台和真实授权资源的浏览器闭环 | 010 与 FEAT-007 |
| IAM-AC-09 | 精确 SHA 独立 CI，固定提交、采用记录、可审查变更和回滚点 | 本分支 |
| IAM-AC-10 | 延期能力有 requirement、原因、依赖、启用条件、验收方法，没有 fake/mocks 冒充 | 012 |
| IAM-AC-11 | 多 IAM 实例、受限容量、撤权一致性及过载/故障边界有真实证据；部署未支持的数据库 HA 单独列缺口 | authorityprocess 与原安装 owner；指标归本文件 |

## 高风险测试矩阵

- Tenant/Account：相同用户名、组名、策略名、资源 ID/key，错误 header/body/path/cursor 不能切换。
- Permission：直接、组、Role、boundary、SessionPolicy 组合；显式 Deny；scope 错误；属性缺失；平台不读租户数据。
- Credential：login/logout/change/reset/recover/key/TOTP 并发；当前会话保留条件；NULL generation；禁用/删除终态。
- Transaction：同 resourceVersion 并发只有确定赢家；失败无新密码/附件/session/success fact 部分效果。
- Producer：事实发生时的证明与当前服务凭据分开；暂停/撤权后历史 outbox 可完成；伪造 tenant/source/purpose/digest 拒绝。
- Resource：成员生命周期不改变工作负载、Operation、配额、审计所有者；已接受后台任务执行边界明确。
- Schema：当前空库安装、带数据重放、失败原子性、schema/function/readiness 实际形状与签名 profile 一致；bootstrap 不补权。历史升级只覆盖明确支持的发布/数据保留起点。

## 未发布阶段与首版基线

用户确认本次 IAM 尚未上线，计划以功能收敛后的最终 schema 作为首个受支持发布基线。开发期间的 schema 1、2、3 等编号、Git 回滚点和其他任务的联调固定提交，不自动成为必须永久支持的生产升级版本；不要求每个 FEAT 从 schema 1 逐版跑完整历史升级链。

未发布迁移可以在风险替换前保存已验证并推送的 Git 回滚点后合并、改写或删除，不在工作树保留废弃实现作为兼容层。默认门禁是最终结构的空库安装、等值重放、带真实数据的重启/恢复、迁移失败无部分效果，以及当前版本的 RLS、受限身份、撤权和 Audit/outbox 不变量。它们不能因免除开发历史兼容而取消。

只有明确要求保留某个现存安装的数据，或存在无法同次替换的真实消费者时，才冻结其准确起点和迁移/拒绝边界；无需补测未声明支持的中间版本。已运行的旧 binary 实验仍可作为一次风险替换的历史证据，但不是所有后续切片的默认完整回归矩阵。联调消费者在各自工作区使用固定提交原子对齐，不擅自清空对方环境。

首版发布冻结实际完整 schema/profile、安装器和服务二进制；从该正式基线之后才维护已声明支持的升级、回滚和备份兼容窗口。首版产品版本不等于必须立即把当前各服务 schema 数字改成 1；发布前是否压缩/重编号要与安装及产品消费者一次性对齐。测试范围调整不授权删除用户数据，也不授予跨 profile 安装准入。

## 可用性与容量门禁

- 两个独立 IAM 进程使用同一受限权威库，交错登录/授权/撤销；撤权已确认后到另一进程的新请求必须拒绝。停掉本任务其中一个进程后，另一进程继续处理已有会话，不要求重新登录、不复活权限；只证明服务副本能力。
- 在本任务限额环境分别测量密码认证、普通策略授权、复杂策略/组继承和混合管理流量，记录硬件/CPU/内存、数据与策略规模、并发、吞吐、P50/P95/P99、错误率、连接/队列/锁等待及 outbox 积压。纯函数 benchmark 不代替 HTTP+PG 容量结论。
- 一个账号超载时，另一账号仍可取得受预算保护的服务；超额明确拒绝，不能无限排队、无限创建连接或多层放大重试。固定策略大小/语句/附件预算要有边界与攻击测试。
- IAM 与数据库连接中断时不得返回旧 Allow；未知写结果只核对原意图。恢复连接后已提交撤权仍有效，已提交 outbox 可恢复投递。
- 数据库真实主备切换的 RPO/RTO、确认提交保留、旧主 fencing 与失败关闭，只能在安装 owner 提供的独立受限部署上验收；无该部署时保留显式未验收项，不重启共享服务、不以单库重连冒充主备切换。

AC-11 当前仅服务副本子项有证据：2026-09-11 现有 `TestIndependentIAMAuditAndPaaSProcesses` 在本任务独立 PG18 下通过，两个真实 IAM 进程分别使用最多 2 连接的受限登录。原实例会话可在另一实例使用，跨副本 grant/revoke 与 session revoke 生效；原实例停止后另一实例仍正确允许租户读取并拒绝已撤平台权限；仅副本登录 NOLOGIN+断开该登录连接期间返回 503，恢复后继续工作。原 5721 保留升级与该组合门禁合计 56.307s。没有负载均衡自动切换、数据库主备切换、容量/公平性 SLO 或完整 HA 验收结论，AC-11 尚未满足。

## 固定消费者的集成检查

最终可发布组合尚未冻结，须在功能收敛后按首版基线规则与安装 owner 重新核对实际 schema、函数契约和二进制。开发阶段的联调版本不能提前作为最终发布 profile，也不能把不同分支的 PaaS 版本混为一谈。以下既有消费者必须在切换候选中通过真实数据检查；中间源码、同 schema 数字或静态编译不能替代：

- `lookup_service` 五列与 `ServiceIdentity` 安装/purpose 语义；`claim_audit_event` 七列及物理 owner 的租约/完成身份。
- `CanonicalizeEvent`、旧 tenant/installation bytes/hash/cursor/链与严格 event-bound producer proof。
- `BootstrapDigest`、封存 receipt/home organization/original primary；原 platform binding 到附件的确定性迁移及不可复权。
- `matrix-iam-local-recovery` 的 FILE/固定退出码、commandId/inputCommitment/精确历史重放、专用登录和无秘密输出；修改私有 ABI 必须一起迁移安装消费者。
- 固定主机消费者的 node-enrollment create/read/revoke/regenerate、target register/read/drain/activate/remove、pool 与 platform-operation 均保持 platform-only。enrollment 派生的 registered 事实只能沿对应历史 enrollment 证明，直接登记仍需精确 target register 决定；不放宽为任意 create 证明。
- 固定消费者中的 terminal-session create/close 仍是租户业务权限，不能因主机管理权限而开放；PaaSDeveloper 的已有授权、PaaSViewer/PlatformOperator 的拒绝和终端历史 actor/source 证明一并回归。

安装 owner 的源快照和候选固定 SHA 归 adoption；其既有 host 证据不复制成本分支新版本验收。

## 运行约束

只使用本工作区、任务标签和唯一命名的数据库/容器/网络/卷/端口。Go 默认 GOMAXPROCS=2、-p 2；PG/引擎 CPU/内存/PID 限额；重型门禁串行。不得重启任何远端机器或共享服务，不使用其他 Phase 的运行实例。未运行命令不进入 runbook。

独立 `authority-process` 作业总预算为20分钟，包含runner/PG准备、已发布安装器构建、Audit历史、IAM当前事务/并发、固定解释前驱、独立多进程及PaaS数据库串行门禁。该预算不改变Go单包默认10分钟、IAM组流程120秒/策略聚合240秒、各锁等待/HTTP/进程预算、CPU/内存或fixture规模。固定6ae975d9的Verification35063652730首轮在10分钟旧作业上限取消：Go/节点成功，Audit数据库4.471秒/HTTP1.963秒完成，随后IAM包尚未完成；GitHub annotation明确为job exceeded maximum execution time。该轮不是独立验收成功，后续必须按新精确SHA重新验证全部门禁，不能把增加作业预算当作场景或性能通过。

固定7b597101的Verification35067085558使用20分钟作业预算后，IAM包仍因两个测试聚合上下文到期失败：新增角色流程嵌在原180秒HTTP用例内，新增私有引用矩阵嵌在原120秒附件用例内。修复只在原integration owner把这两组拆到独立干净数据库并显式接入同一CI作业；保留原测试及每个独立矩阵120秒预算，不增大单包10分钟上限、并发、资源、重试或场景等待。263.159秒本地真库回归证据归006；修复固定`d45402d91c89a5bb23f52fcfde65491435cd0f55`的Verification35069879250三项全部success，不把旧失败或默认无DSN的SKIP改写为成功，也不改变原容量/HA未验收边界。

固定`960416dd85adab225bd97ee89509df04173f978b`的[Verification35110913530](https://github.com/xiak/matrix/actions/runs/35110913530)已核实精确SHA：Go和node-process成功，authority-process失败。日志为IAM integration整个进程累计600.108秒到期，当时最后的原HTTP矩阵运行82秒，账号子流程78秒；不是已经证明了某个锁等待超时或死锁。独立进程包103.467秒与Audit/PaaS数据另已完成，不将本轮记为全绿。当前作业将原Role/STS矩阵和其余IAM矩阵按互补的`-run/-skip`拆为串行调用，保留全部fixture、原场景/锁预算、单进程10分钟及20分钟作业上限；不加并发或弱化密码/规模。执行拆分及后续安全修复已通过006记录的本地完整真库/独立进程组合；累计固定`1ebab37aef4bce12b963f52d3919748a9d50d4c6`的[Verification35123738141](https://github.com/xiak/matrix/actions/runs/35123738141)已核实精确SHA及三项completed/success。该结果不回填旧失败，也不能当成性能、容量或整套IAM验收。

## 完成条件

001–010 所有本轮需求通过本分支相应证据，AC-01–11 的本轮门禁满足且数据库 HA 等前置缺口如实列明，签名交付边界明确，才将总 goal Complete。局部测试绿、固定源可读、目录有 FEAT 或纯设计提交均不等于实现验收。旧 FEAT-006 的已接受状态不会替代此组合验收。

当前无本轮完整运行证据；各里程碑在相应 FEAT 更新，不新建重复报告或实现日记。
