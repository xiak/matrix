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
| IAM-AC-06 | 固定旧 binary 留存数据→迁移/重放/重启，撤销/凭据/原 root 不复活 | authorityprocess retained upgrade |
| IAM-AC-07 | 同完整 profile 签名 A/B 安装、保留升级/回滚/备份恢复；跨 profile 效果前拒绝 | 原安装 gate，与安装 owner 固定交接 |
| IAM-AC-08 | IAM 控制台和真实授权资源的浏览器闭环 | 010 与 FEAT-007 |
| IAM-AC-09 | 精确 SHA 独立 CI，固定提交、采用记录、可审查变更和回滚点 | 本分支 |
| IAM-AC-10 | 延期能力有 requirement、原因、依赖、启用条件、验收方法，没有 fake/mocks 冒充 | 012 |

## 高风险测试矩阵

- Tenant/Account：相同用户名、组名、策略名、资源 ID/key，错误 header/body/path/cursor 不能切换。
- Permission：直接、组、Role、boundary、SessionPolicy 组合；显式 Deny；scope 错误；属性缺失；平台不读租户数据。
- Credential：login/logout/change/reset/recover/key/TOTP 并发；当前会话保留条件；NULL generation；禁用/删除终态。
- Transaction：同 resourceVersion 并发只有确定赢家；失败无新密码/附件/session/success fact 部分效果。
- Producer：事实发生时的证明与当前服务凭据分开；暂停/撤权后历史 outbox 可完成；伪造 tenant/source/purpose/digest 拒绝。
- Resource：成员生命周期不改变工作负载、Operation、配额、审计所有者；已接受后台任务执行边界明确。
- Upgrade：固定旧状态、schema/function/readiness 实际形状、旧 bytes、签名 release tuple+revision；bootstrap 不补权。

## 固定消费者的集成检查

最终组合冻结为 IAM6/Audit4/PaaS5+r12。以下既有消费者必须在切换候选中通过真实数据检查；中间源码、同 schema 数字或静态编译不能替代：

- `lookup_service` 五列与 `ServiceIdentity` 安装/purpose 语义；`claim_audit_event` 七列及物理 owner 的租约/完成身份。
- `CanonicalizeEvent`、旧 tenant/installation bytes/hash/cursor/链与严格 event-bound producer proof。
- `BootstrapDigest`、封存 receipt/home organization/original primary；原 platform binding 到附件的确定性迁移及不可复权。
- `matrix-iam-local-recovery` 的 FILE/固定退出码、commandId/inputCommitment/精确历史重放、专用登录和无秘密输出；修改私有 ABI 必须一起迁移安装消费者。
- 固定主机消费者的 node-enrollment create/read/revoke/regenerate、target register/read/drain/activate/remove、pool 与 platform-operation 均保持 platform-only。enrollment 派生的 registered 事实只能沿对应历史 enrollment 证明，直接登记仍需精确 target register 决定；不放宽为任意 create 证明。

安装 owner 的源快照和候选固定 SHA 归 adoption；其既有 host 证据不复制成本分支新版本验收。

## 运行约束

只使用本工作区、任务标签和唯一命名的数据库/容器/网络/卷/端口。Go 默认 GOMAXPROCS=2、-p 2；PG/引擎 CPU/内存/PID 限额；重型门禁串行。不得重启任何远端机器或共享服务，不使用其他 Phase 的运行实例。未运行命令不进入 runbook。

## 完成条件

001–010 所有本轮需求通过本分支相应证据，AC-01–10 满足，签名交付边界明确，才将总 goal Complete。局部测试绿、固定源可读、目录有 FEAT 或纯设计提交均不等于实现验收。旧 FEAT-006 的已接受状态不会替代此组合验收。

当前无本轮完整运行证据；各里程碑在相应 FEAT 更新，不新建重复报告或实现日记。
