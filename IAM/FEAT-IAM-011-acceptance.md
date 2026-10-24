# FEAT-IAM-011：交付与需求验收

- 状态：实施中；当前已接受的签名产品源码`95a343ae2f4efb4c9845c9af25d0225e722f870c`为IAM87/Audit39/PaaS7、`contractRevision=37`，唯一滚动数据前驱仍是固定`08e1dc4a6ce81386ea7223e62d03356f82aeee58`的IAM86/Audit39/PaaS7+r36。当前源码已通过十九项独立CI、同Profile签名A/B完整离线生命周期和容器级重启后复验；真实恢复保留Analyzer的`RESTORE_GAP`，前台会话活动入口随冻结UI构建进入同源包。后继真实浏览器又闭合前台Session活动、GROUP/USER/ROLE三类附件CREATE/REVOKE完整恢复矩阵、Role资料/Trust/停复用/删除、Account Root凭据恢复、受管实例终止、CUSTOMER Policy作为普通USER权限边界时的默认版本切换与响应丢失恢复，以及账号强制MFA下的首次绑定、自助恢复和既有`RECOVERY_REQUIRED`流程取代边界；固定`024ff4d0c`还在当前签名安装内闭合AccessKey页面创建、一次性Secret、精确来源、程序访问和停用组合。页面仍只采纳010中各自固定版本的实际操作与数据库/Audit证据，签名通过不把未执行的LIVE旅程自动标绿。因此整体目标仍未完成，生产账号公平性SLO与安装级数据库HA继续因缺少真实部署前提明确Deferred。
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
| IAM-AC-08 | IAM 控制台创建当前目录实际支持的 PostgreSQL 18 托管实例；真实 worker 调谐至 READY、SQL 读写、成员允许/撤权后下一请求拒绝、资源不销毁及 Audit 链均由同一浏览器业务闭环证明 | 010 与 FEAT-007 |
| IAM-AC-09 | 精确 SHA 独立 CI，固定提交、采用记录、可审查变更和回滚点 | 本分支 |
| IAM-AC-10 | 延期能力有 requirement、原因、依赖、启用条件、验收方法，没有 fake/mocks 冒充 | 012 |
| IAM-AC-11 | 多 IAM 实例、受限容量、撤权一致性及过载/故障边界有真实证据；部署未支持的数据库 HA 单独列缺口 | authorityprocess 与原安装 owner；指标归本文件 |

### 总目标完成审计

| 用户目标 | 权威证据 | 当前结论 |
| --- | --- | --- |
| 独立 IAM 目录与阅读入口 | `IAM/README.md`只提供001–012、采用记录和产品参考链接 | 已完成；没有在README复制状态或设计 |
| 对象命名与归属逻辑 | [000对象命名与归属](FEAT-IAM-000-product-contract.md#对象命名与归属)及各对象所属FEAT | 设计已完成；Account、RootIdentity、User、Group、Policy/Version、Role/RoleSession、Credential/Session及产品授权对象边界明确 |
| 产品需求及延期需求 | [000全量需求分解](FEAT-IAM-000-product-contract.md#全量需求分解)与[012](FEAT-IAM-012-external-integrations.md) | 已完成需求归属；SSO/外部组织等能力有启用前置与真实验收要求，未用假接口冒充实现 |
| 总体架构、高可用与容量边界 | [000总体架构](FEAT-IAM-000-product-contract.md#总体架构)及其可用性、容量与一致性段落，跨产品边界由ADR-0002拥有 | 设计已完成；当前多IAM副本、失败关闭、受限容量与数据库切换夹具已有证据，部署尚不支持的完整数据库HA继续明确列为缺口，不虚构SLO |
| 详细设计与API约定 | 001–010各自拥有行为、锁序、事务、API/schema及验收；000只拥有公共wire/版本/分页约定 | 已完成当前范围设计；没有新增平行模型、通用receipt框架或第二套API文档 |
| 分解为可验收FEAT | 001–011覆盖本轮实现与组合验收，012保存满足前置后才启动的外部集成 | 已完成分解；每项有唯一owner，固定来源采用记录仍由既有adoption文件拥有 |
| 实现所有本轮FEAT | 001–009当前后端、真实PG18/多进程及同Profile签名生命周期证据；010拥有控制台 | **未完成总目标**：固定`95a343ae`的IAM87+r37后端、当前单前驱、19项独立CI、同Profile签名A/B、完整离线生命周期和重启复验已经实现并通过；真实恢复保留Analyzer恢复缺口且旧Session/AccessKey失败关闭。User资料/状态、Group Membership、Account安全设置正常完整替换、Group/User删除、普通User日常改密、前台Session活动、Role资料/Trust/停复用/删除、用途限定恢复码重新生成、账号策略强制MFA下普通User首次绑定、保存恢复码后的认证器丢失自助恢复、既有`RECOVERY_REQUIRED`流程取代，以及GROUP/USER/ROLE三类附件CREATE/REVOKE完整恢复矩阵已有真实证据；当前签名AccessKey创建、一次性Secret、精确来源、200/401/403/409边缘语义和停用组合也已通过。CUSTOMER Policy作为普通USER权限边界时的默认版本切换已完成UNKNOWN精确重放、同Session下一请求即时拒绝、历史Allow证据保留与唯一Audit后验；直接USER附件消费者下的版本发布、显式切换、同Session下一请求效果、旧版本退休、发布并发409恢复及Root五版本容量恢复也已有完整页面与权威后验。Account服务开通、Root凭据恢复和受管实例终止已完成一次写入、UNKNOWN停写、跨来源只读恢复及权威后验。外部物理认证器，以及受保护Root/平台身份丢失全部因子后的目的限定恢复与强制重新绑定继续按设计延期；010矩阵中Group/Role附件引用Policy、User/Role权限边界其他组合、RoleSession失效、非Root委派容量、发布/退休响应丢失、其他敏感用途step-up和其余当前签名APISIX组合仍须闭合 |
| 验收与可交付证据 | IAM-AC-01–11、FEAT-005签名生命周期、精确SHA独立CI、010/FEAT-007真实浏览器 | **未完成总验收**：IAM-AC-07由固定`95a343ae2f4efb4c9845c9af25d0225e722f870c`的IAM87+r37同源签名A/B、完整离线生命周期和容器级重启复验接受；测试owner固定`024ff4d0c`又对相同签名包完成AccessKey页面组合、993.40秒效果门禁和95.96秒冷重启后复验。各固定代码的IAM-AC-09证据与限制归[当前独立CI](#当前独立ci)，不继承旧签名结论。权限感知、受影响原Policy恢复、普通USER权限边界默认版本切换、直接USER附件Policy版本完整页面生命周期、真实并发409恢复与Root五版本容量恢复、前台Session活动、附件完整恢复矩阵、Root凭据恢复、实例终止及AccessKey签名组合页面均由010按各自固定源码和真实后验拥有；Account服务开通及结果不确定恢复由FEAT-008拥有。Issue #4仍按其原固定消费者关闭；Issue #5的剩余范围复核与Issue #6的Observe超时根因保持打开。IAM-AC-11只接受已记录的受限容量、业务隔离、恢复和受控数据库切换边界。其余IAM-UI-01–08非Deferred页面效果尚未完成，生产账号公平性SLO和安装级数据库HA保持Deferred |

只有上表仍列出的未完成边界均获得其owner的真实证据后，才能把000及本总目标标为Accepted。设计文件齐全、静态页面、组件测试、健康端点、另一个分支的浏览器结果或局部CI成功都不能改变这一判定。

### 当前控制台与发布门禁

当前签名接受与最新代码验收是两条独立边界，不能相互继承：

| 边界 | 固定对象与当前结论 |
| --- | --- |
| 已接受签名组合 | `95a343ae2f4efb4c9845c9af25d0225e722f870c`，IAM87/Audit39/PaaS7+r37；同源A/B完整离线生命周期4197.458秒、容器级重启后复验435.593秒通过，准确包、信任根、限额、失败尝试和观察约束由[FEAT-005](../docs/features/FEAT-005-offline-platform-lifecycle.md#current-iam87-foreground-session-and-recovery-gap-release-consumer-gate)拥有 |
| 当前签名AccessKey页面组合 | 测试owner固定`024ff4d0c5ea56aa65f103392f901deb783bb619`，不改签名生产包、Profile或后端语义；浏览器在当前`95a343ae` Release A经APISIX创建精确CIDR Key、确认一次性Secret、完成首次200、错误目标401、同nonce重放409、页面停用后新nonce403及旧重放仍409，随后公开API清理。页面事实归[010](FEAT-IAM-010-console.md#当前签名-apisix-浏览器增量证据)，完整993.40秒效果门禁和95.96秒重启复验归[FEAT-005](../docs/features/FEAT-005-offline-platform-lifecycle.md#current-iam87-foreground-session-and-recovery-gap-release-consumer-gate)；不外推网络编辑、页面删除或响应丢失恢复 |
| Policy版本页面生命周期、冲突与容量 | 生产交互修正固定`5255a6ed188e49436ca00a8042358af596804f97`、`a508bfa7bf6530069c69ee49488f176170e74a35`与`2678cc3078b54e112e60966339cc6bb313ccfac1`；完整页面生命周期、真实并发409恢复及Root五版本容量测试分别固定`6ae11ab43468e0de5a27fb20bb3df67bce3ffc07`、`a48255c2c57b91d9755c1c3ad13d347499e6f330`与`9b04835bb8cc252366d57f09b74132743fca6432`。三套独立PG18页面旅程分别证明非默认发布/显式切换/同Session效果/退休旧版本，旧修订单次409/草稿保留/双投影对齐后显式重审，以及5/5原位禁用/非默认退休/精确重授权/补位回5/5且默认不变；准确页面、数据库及Audit证据归[010](FEAT-IAM-010-console.md#policy版本冲突与完整页面生命周期)。不外推Group/Role附件、非Root委派容量或响应丢失恢复；并发与容量准确SHA的[Verification 40128613010](https://github.com/xiak/matrix/actions/runs/40128613010)、[Verification 40131286149](https://github.com/xiak/matrix/actions/runs/40131286149)均已核实`completed/success`且各十九项job全部成功 |
| 最近完整日志审计通过源码 | `e22d7481fec9ecaa33d0cdfe6df7942cabc6c064`，完整Profile不变；准确SHA的十九项job及全部必要日志已由测试owner独立核验，十四条authority lane的57个必跑根均实际通过。只接受各自准确版本的证据，不继承5935的签名发布或未执行的浏览器结论 |
| Role生命周期与删除 | 固定消费提交`fe6e5220efc602fbe7744f416078288527a9fcd9`选择性采用UX `f0dbf742cb14bd5ff20d928c63798dd1b0e623f7`的删除回执；后继固定`d8d75b849b553ad114f0e8aee9f3daf61ca59f1b`在原Role真实浏览器门禁完成资料/时长更新、Trust替换、停用/启用及最终删除，权威墓碑、级联附件数、旧Sibling拒绝、Audit链和完整前端导出均通过；其[Verification 40104721580](https://github.com/xiak/matrix/actions/runs/40104721580)由GitHub官方API核实精确SHA、整轮`completed/success`且十九项job全部成功。页面证据由[010](FEAT-IAM-010-console.md#role删除的服务器完成回执)拥有；Profile不变，不继承donor、签名APISIX或其他旅程的接受状态 |
| User删除回执源码 | 固定消费提交`b2ae60f17ce8e4d7e8e33dcb7b6be4b3db3fa97f`采用UX固定`8c40091ec1d48ecb81281c4ffa55d8bcd5b9ee9d`及`09640c6cefce7361574206753fdb0b2bd1133847`、`3dec632876828d87a785319043881ff65f00ce5e`，保留消费端协议负向回归，嵌入`matrix-a6f26f9b65bd7e6b26c1`；准确回执、同标签页UNKNOWN保护、本地冲突零副作用及红绿/双构建证据归[010](FEAT-IAM-010-console.md#user删除回执与同标签页未知结果保护)。本地门禁通过，精确SHA的[Verification39794059308](https://github.com/xiak/matrix/actions/runs/39794059308) attempt1及十九项job已全部核实completed/success。后继固定`3afe9624808d323e2d8988dfd033d8544509183a`分别在两套全新PG18.6上以真实浏览器各一次POST完成NORMAL与RESPONSE_LOSS：前者显示准确回执并独立回读目录，后者在真实提交后截断响应并经导航、reload、同owner重新登录保留原UNKNOWN意图且零重发、零完成查询；两条墓碑/凭据/附件/资源/Role/Audit后验全部通过，包分别283.297秒和391.715秒。两套任务专属PG均已清理，因此User删除的该组真实浏览器门禁已接受 |
| 最近已确认的CI终态 | `024ff4d0c5ea56aa65f103392f901deb783bb619`的[Verification40123301994](https://github.com/xiak/matrix/actions/runs/40123301994)精确SHA、整轮completed/success且十九项job全部成功；本次核实官方run/job终态，不据此补造完整日志审计或默认工作流未执行的opt-in浏览器结论。当前签名AccessKey页面证据仍由上述独立真实门禁拥有 |
| 前一候选的实际产品证据 | `7d6db51b0bbb676c446e08f82af0bf50ccc33a5b`的[Verification39743005047](https://github.com/xiak/matrix/actions/runs/39743005047) attempt1十九项job全部成功；测试owner核验短容器门禁1.45秒、完整四产品128.51秒和Analyzer41.08秒。十六份日志完整、三份仅局部，不冒充全量日志审计或其他版本通过 |
| 唯一滚动数据前驱 | `08e1dc4a6ce81386ea7223e62d03356f82aeee58`，IAM86/Audit39/PaaS7+r36；该保留数据门禁不授予跨Profile签名升级许可 |
| 真实页面 | 只接受[010交付矩阵](FEAT-IAM-010-console.md#当前交付矩阵)逐项记录的页面效果，不由签名包、组件测试或其他分支结果推导 |

#### 当前独立CI

固定`024ff4d0c5ea56aa65f103392f901deb783bb619`的[Verification40123301994](https://github.com/xiak/matrix/actions/runs/40123301994)已由GitHub官方API核实准确head SHA、整轮`completed/success`及十九项job全部成功，没有失败、取消或未决终态。该固定源码只在既有签名生命周期测试owner增加当前Release AccessKey页面组合，并修正测试对正式重放合同的断言：错误目标401、首次正确签名200、已消费nonce重放409、停用后新nonce403且旧重放仍409；没有修改生产API、数据库、Profile或授权实现。默认CI没有提供显式opt-in环境，因此没有执行安装中浏览器旅程；其993.40秒效果门禁和95.96秒重启复验仍只由010与FEAT-005的独立真实运行拥有。本段接受准确源码的IAM-AC-09，不把绿色CI冒充签名APISIX页面、完整日志审计或其他未运行旅程。

固定`a15623010460e507489ab041e8ddd6b387cc4e27`的[Verification40118253393](https://github.com/xiak/matrix/actions/runs/40118253393)已由GitHub官方API核实准确head SHA、整轮`completed/success`及十九项job全部成功：Go、console、node-process、installation-postgres-ha四项前置，十四条authority lane和最终`authority-process`汇总均无失败、取消或未决终态。该固定源码只在既有Policy浏览器测试owner增加普通USER权限边界消费者的默认版本切换、即时业务拒绝、不可变历史决定及唯一Audit后验；没有修改生产API、SQL、Profile或授权实现。默认CI不运行显式opt-in真实浏览器入口，实际页面与PostgreSQL 18证据仍只由010拥有，本段仅接受准确源码的IAM-AC-09，不能冒充当前签名APISIX或其他未运行旅程。

固定`95a343ae2f4efb4c9845c9af25d0225e722f870c`的[Verification40085311144](https://github.com/xiak/matrix/actions/runs/40085311144) attempt1已经由GitHub官方API核实：head SHA准确，整轮`completed/success`，十九项job全部成功且无其他终态。该固定源码包含冻结UX构建、前台Session活动消费、离线生命周期调用点，以及恢复后Analyzer覆盖谱系修正；默认CI没有执行opt-in签名生命周期或真实浏览器入口。IAM-AC-07采用FEAT-005记录的独立network-none签名运行，IAM-AC-09采用本段CI终态，两类证据不互相冒充。

固定`9bb412e10eeec1878ea3365b30c2d1f1f18947b1`的[Verification40114978232](https://github.com/xiak/matrix/actions/runs/40114978232)已由GitHub公开run页核实准确源码与`Success`终态：Go、console、node-process、installation-postgres-ha四项前置及十四条authority lane全部完成。该固定源码只扩展既有personal-security浏览器测试owner，证明账号强制MFA且普通User已经处于`RECOVERY_REQUIRED`时的丢失流程取代、replacement因子、恢复码代次、Session围栏、零隐式授权和Audit后验；没有修改生产API、SQL、Profile或Root权限。默认CI仍不执行该opt-in真实浏览器入口，页面与PostgreSQL 18实际运行证据归010；本段仅接受准确源码的IAM-AC-09，不继承当前签名APISIX或其他未运行旅程。

固定`56e3e9c3bbb0b1e4ca45a84f73a70056ea974cc8`的[Verification39936868627](https://github.com/xiak/matrix/actions/runs/39936868627) attempt1由GitHub官方run页核实精确SHA、`Success`终态及30分51秒总时长：Go、console、node-process、installation-postgres-ha四项前置成功，十四条authority lane全部完成，最终`authority-process`汇总成功。该固定源码包含FEAT-008的服务开通UNKNOWN浏览器门禁、UX/UI owner固定源码的选择性消费，以及后验查询对managedservice当前outbox契约的修正；默认CI没有执行opt-in真实浏览器入口，因此页面效果只采用FEAT-008在独占PG18.6上的实际运行证据。本段接受该源码的IAM-AC-09，不继承旧签名发布、完整日志审计或尚未执行页面的结论。

固定`571692dd277317091af077beba79fe13f509738d`的[Verification39808302366](https://github.com/xiak/matrix/actions/runs/39808302366) attempt1于2026-10-23通过GitHub API核实精确SHA、整轮completed/success及十九项job全部成功：十四条authority lane、Go、console、node-process、installation-postgres-ha及最终authority-process汇总。该固定增量只在原process owner补User删除夹具及其负向观察、fresh decode和精确停用403/删除401断言；默认关闭的浏览器入口不因CI绿色变成已运行。此处仅封存run/job终态，没有完成该轮全量日志审计，不据此补造根测试时长或真实页面结论。

固定`3afe9624808d323e2d8988dfd033d8544509183a`只修正User删除验收探针必填的显式空权限边界；NORMAL与RESPONSE_LOSS真实浏览器和权威后验均已由010接受。其仅改文档的后继`2df38c8b863e57ea52feb94180c157107a5902c7`已由[Verification39895467786](https://github.com/xiak/matrix/actions/runs/39895467786) attempt1核实准确SHA、整轮及十九项job全部completed/success，因此相同生产/测试树的独立CI门禁闭合；本次没有读取或封存完整日志，不外推必跑根明细、真实页面或签名发布。生产Profile与已接受签名组合不变。

同日独立核对固定`b2ae60f17ce8e4d7e8e33dcb7b6be4b3db3fa97f`的[Verification39794059308](https://github.com/xiak/matrix/actions/runs/39794059308) attempt1，准确SHA、整轮及十九项job全部为completed/success，包括`authority-managed-products`119880681664；原状态不一致已消除，没有重新运行。K1/K2/R1/R2及独立SET_DEFAULT页面仍按010各自固定源码和实际后验接受，不继承为User删除。2026-10-23最终收尾重新核对标签、任务标识、网络成员、卷引用和绝对路径边界后，以Docker原生命令删除五个本任务容器、四个独占网络和一个匿名卷；十一项本任务临时路径移入Windows回收站并从原位置验证不存在。未使用`prune`、通配或父目录删除，也未操作共享、远端或其他任务资源。

固定`fe6e5220efc602fbe7744f416078288527a9fcd9`的[Verification39775416795](https://github.com/xiak/matrix/actions/runs/39775416795) attempt1于2026-10-22 21:39:56+08通过GitHub API核实准确SHA、整轮completed/success及十九项job全部成功，包括十四条authority lane、Go、console、node-process、installation-postgres-ha和最终authority-process汇总。本次没有读取或封存完整日志，不能把终态扩为所有必跑根日志已审计、真实Role删除浏览器或后继User删除已接受；发布Profile和已接受签名组合不变。

固定`b3bd03958f7e3b6f251d78693abdad1b5d23cbcc`的[Verification39761561748](https://github.com/xiak/matrix/actions/runs/39761561748) attempt1于2026-10-22 18:43:23+08通过GitHub API核实精确SHA、整轮completed/success及十九项job全部成功，包括十四条authority lane、Go、console、node-process、installation-postgres-ha与最终authority-process汇总。API返回370个step：175成功、195跳过，没有失败、取消或未决step。当前工作流仍通过原必跑选择器拒绝根测试未RUN、SKIP或缺少PASS；角色真实PG根及最终汇总的准确step终态已核对。该轮完整日志尚未封存，不据job/step状态补造每个测试的时长、数量或日志审计结论。K1/K2/R1/R2分别由010的准确源码、真实页面和独立后验接受，不回填旧失败，也不接受其余IAM矩阵或新签名发布。此次新R2环境已清理；历史工具拒删残留仍未清理，资源清理未全部完成。

固定`b3c3d157fd58af0743f4ef4721123b27de05abf8`的[Verification39746740451](https://github.com/xiak/matrix/actions/runs/39746740451) attempt1已于2026-10-22 16:56:58+08通过GitHub API再次核实精确SHA、`completed/success`和十九项job全部成功。测试owner已完整读取并校验四份前置日志，共186,134字节；其中Go93包、前端79文件2062项Vitest及八项Node检查通过。authority日志尚未完成独立核验，不能由job状态或前一候选的详细结果补作全量日志审计。此片仅修正R1准备后的Role查询，实际浏览器证据仍由010分别判定，发布Profile不变。

固定`7d6db51b0bbb676c446e08f82af0bf50ccc33a5b`的[Verification39743005047](https://github.com/xiak/matrix/actions/runs/39743005047) attempt1已于2026-10-22 16:17:47+08通过GitHub API核实精确SHA、`completed/success`和十九项job全部成功。测试owner核验`TestManagedWorkerPrivateInputsContainer`实际RUN/PASS各一次、1.45秒（package2.502秒），`TestManagedProductProviderProcesses`实际RUN/PASS各一次、128.51秒（package129.562秒），JSON与文本终态一致；固定linux/amd64客户端标记和四产品完整效果摘要各精确出现一次。摘要与该提交process文件blob`fe1403573f4a077c9d4f9cf35c0be00ad81f3683`一致。`TestIAMAccessAnalyzerPostgres`实际PASS41.08秒亦已核验。这些证据接受本固定版本对应根的真实运行，不证明旧Engine或迁移失败的唯一根因。

该7d6轮370个step为175成功、195项矩阵设计跳过；十六份日志已完整核验，另storage、runtime、recovery-storage仅有局部读取。原日志读取会话随后丢失，全量审计仍未封存；不得将已观察根扩大为全部根已核验，也不重复获取已封存的旧失败日志或为取证重跑CI。上述两轮绿色终态均不回填22591等旧失败，真实页面只按010的准确旅程证据接受，也不继承新签名发布结论。

固定`22591d3a52285c98ed269cd4a41643872d0b30c3`的[Verification39736548709](https://github.com/xiak/matrix/actions/runs/39736548709) attempt1已确认`completed/failure`：十九项job为十六成功，storage、managed-products和派生汇总失败。测试owner已完成十九份日志核验并封存；Analyzer失败后另六个storage根未RUN，不能只由job清单补作通过。两项原始失败保持以下结论，不重复获取已关闭日志。

[产品job119686270746](https://github.com/xiak/matrix/actions/runs/39736548709/job/119686270746)的短输入根实际通过0.42秒（package1.480秒），另两条存储根通过0.46/0.50秒（package2.022秒）；完整provider根却以46.09秒失败（package46.161秒）。它已越过HTTP200等待，随后在容器挂载检查报`managed worker exposes an unexpected host directory or volume`；固定client验证标记与四产品完成摘要均为零，不能当作产品通过或旧Engine超时。本job完整78,174字节已由测试owner核验，不重复获取。固定DinD镜像实际声明`/var/lib/docker`卷；在原短容器门禁新增相同边界的实际mount检查后，本机以1.90秒复现拒绝（race包4.466秒），不是推测为资源抖动。

当前候选只在原测试/workflow owner替换为官方`docker:27.5.1-cli-alpine3.21@sha256:f56779b4e86550493153cc8642c9c8e40b5d934e43cb5b4ea463aea5245c5c01`。镜像解析仍核对真实linux/amd64 image ID，并在创建前拒绝任何声明卷或缺失Config；短门禁实际执行27.5.1 CLI、检查无意外bind/volume，保留私有输入消费和无新输入第二次执行失败关闭。完整worker的原Engine、物理volume、受限数据库身份、loopback边界、2CPU/512MiB/PIDs128及三秒/五秒预算不变，不白名单匿名卷或放宽断言。准确已核对归属的测试容器删除同时回收其匿名卷，不清理其他对象。默认镜像负例在修正前以race2.604秒失败，修正后镜像/输入/真实短门禁合计race5.394秒通过；最终加入CLI执行检查后，process/architecture/IAM integration默认race分别7.500/1.959/1.706秒及vet通过。完整YAML语义比较只改变一个固定镜像，24段Bash语法通过。

原`ef909e1`的Linux源UID归属问题由22591的三文件流式archive修正：只传worker、受限DSN和catalog，明确root归属及0700/0600，不改变host权限、增加CHOWN或留下秘密archive；取消会收回管道写入者，bootstrap仅输出封闭阶段码。Windows真实短门禁及Linux UID1001运行已分别通过，且本轮CI短输入根确已执行成功；这些证据不覆盖完整worker挂载或四产品效果，也不解释旧Engine/Observe超时。

[storage job119686270764](https://github.com/xiak/matrix/actions/runs/39736548709/job/119686270764)的`TestIAMAccessAnalyzerPostgres`在末端schema重放以50.07秒失败（package50.150秒），原错误只有`apply IAM migration: PostgreSQL migration apply failed`，没有SQLSTATE或底层锁证据。本机在workflow相同PostgreSQL镜像实际18.4、独占2CPU/1GiB/PIDs128/tmpfs的新库，以Windows Go1.26.3/race-p1原样通过40.760秒；不能反推Linux CI根因。当前候选仅复用既有SQLSTATE-only trace，在该admin连接和准确replay处记录去敏错误码及context状态；不记录SQL/参数/错误细节，不改变迁移、扫描器、重试或期限。另一新库通过37.192秒，但存储CI失败仍未确定根因，不能称已经修复。

本机Elasticsearch内核前提仍不足且未修改；本机短容器和PG检查不证明完整Linux四产品，独立CI证据以上述准确版本和实际核验范围为准。新短容器均由原cleanup回收；新PG及其独占网络清理被工具策略拒绝，旧拒删残留未重试，不宣称全部资源清理完成。生产代码、API、SQL、UI及发布profile均未改变。

固定`08e0d76bbea2d63c59b790e61c2870162d928c19`的[Verification 39711834716](https://github.com/xiak/matrix/actions/runs/39711834716) attempt1于2026-10-22由测试owner核对为`completed/failure`，全部十九份job日志核验后仍为十七成功、managed-products及派生汇总两项失败。[实际失败job](https://github.com/xiak/matrix/actions/runs/39711834716/job/119607098586)的唯一原始失败为`TestManagedProductProviderProcesses`：运行43.43秒、package43.497秒后失败，worker在预期HTTP200就绪前exit1，封闭码为`PAAS_WORKER_EXECUTION_PROFILE_DOCKER_ENGINE_TIMEOUT`；另两条产品存储根通过0.47/0.41秒，但四产品完整效果摘要为零次，不能接受真实四产品旅程。新增观测记录`Start`调用耗时460.219微秒、`Start`返回到`Wait`返回3.021389335秒、系统报告的进程user/system CPU为66.865/57.404毫秒。它们不是Docker CLI自身的起止、内核精确退出时间或daemon CPU，也未提供探针时刻的资源/OOM及底层响应证据；不能从根测试时长或初始化/清理成功反推原因。此前固定958d5b4的[Verification 39646488455](https://github.com/xiak/matrix/actions/runs/39646488455) attempt1同为十九项中十七成功、该产品根与汇总失败，已封存，不重复获取旧日志或回填终态。

该码只定位现有`docker info --format {{json .}}`探测路径，不能区分CLI启动/调度、Docker daemon响应或资源原因。生产worker、localmachine adapter、execution-profile用例和workflow与已通过的e22逐文件无差异；这也不能证明其一定是环境抖动。现有三秒CLI/五秒Observe预算和失败关闭行为不变；不盲目重跑、扩大超时或将新失败冒充[Issue #6](https://github.com/xiak/matrix/issues/6)旧Observe失败的唯一根因。后续修复或受控复现需要新的准确证据，旧失败终态不回填。

08e0d76的测试专用增量仅在原`authorityprocess`子进程owner记录`Start`调用前后与`Wait`返回的观测时间；就绪前退出时补充这些时间、相应耗时及系统报告的user/system CPU时间，不增加环境、参数、凭据或Docker原始输出。终态通过原完成channel发布，重复poll/wait不能重写原观测；`Wait`返回时间不是内核精确退出时间，进程CPU也不能单独解释探针原因。成功/失败子进程回归在Windows race通过1.51秒，默认process/architecture race通过5.171/1.966秒、vet与diff检查通过；同一测试在network-none、2CPU/512MiB/PIDs128的Linux容器通过0.03秒。另用未改的真实`DockerHostProbe`在相同限额的Linux容器只读访问本机Docker29.6.2引擎，Docker27.5.1 CLI下两次观测共0.31秒通过；这只说明本地未复现，不等于CI修复或四产品通过，默认跳过的PG/浏览器也不计运行证据。生产探针、预算、重试、workflow及release profile保持不变，Issue6继续开放；上述独立CI已确认该增量尚未解决原超时。

固定`e22d7481fec9ecaa33d0cdfe6df7942cabc6c064`的[Verification 39604675084](https://github.com/xiak/matrix/actions/runs/39604675084) attempt1已由测试owner独立封存为`completed/success`，精确SHA及十九项job全部成功，2026-10-21 13:33:26UTC终态。370个step为175成功、195项矩阵设计跳过，没有其他跳过、失败或取消。十九份必要日志共74,585,478字节、156段，连续Range、长度、严格UTF-8及保留BOM重编码均核验一致；十四条authority lane的57个必跑根均实际RUN/PASS一次。1164个Test身份的JSON/plain终态及Test耗时一致：1157通过、7个真实邮件子例因缺少专用Postfix明确跳过，不能据此接受真实邮件投递。33次JSON包调用全通过；包级两种显示口径有10处1毫秒、2处2毫秒差异，分别保留，不混同于Test终态差异。

本准确源码的独立进程根234.29秒、Profile推进15.28秒、TOTP备份16.03秒、IAM HTTP163.36秒及三条Session52.72/52.16/37.71秒均通过。单前驱48.04秒，IAM86→87保留数据完整摘要精确出现一次；四产品provider100.24秒，真实协议、终止清理、授权撤销、隔离和Audit完整摘要精确出现一次。容量31条指标、3100样本、零失败，已记录的三个OOM计数均零；这仍只是受限夹具证据，不是生产SLO，也不证明Issue #6旧Observe超时的唯一根因已解决。

前端79文件2062项组件测试、8项Node检查、234组对比度以及双production/嵌入324文件一致性通过；33条既有act警告保留。Go93包、node进程及安装PG夹具均通过，14个Stop和36个Post步骤全部成功；CI清理步骤不替代独立现场清点。此tuple全量取证闭合，不重复读取同attempt日志。该片只修复test-only源码改变build fingerprint后遗漏重建交付的问题，没有改变生产交互/API/SQL/profile；旧失败终态不回填。本CI未执行真实浏览器或签名opt-in门禁，不接受010中尚未完成的Key/Role及精确Session页面路径，也不继承5935的签名发布。

固定`4760581e035ec299003ef8f777b777feda38a218`的[Verification 39599299467](https://github.com/xiak/matrix/actions/runs/39599299467) attempt1已独立封存为`completed/success`，2026-10-21 12:55:34UTC终态，十九项job全部成功。370个step中175成功、195项为矩阵设计跳过，没有其他跳过、失败或取消；十四条lane的57个必跑根均实际通过。十九份必要日志共74,580,732字节完成连续Range、长度、严格UTF-8及BOM重编码校验，其中storage的56,009,188字节全文及11根通过结果完整核对。1164个Test身份的JSON/plain一致：1157通过、7个真实邮件子例因缺少专用Postfix明确跳过，不能据此声称真实邮件投递已验收；33个JSON包全通过。容量31指标、3100样本、零失败，三个OOM计数均零；这是受限夹具结果而非生产SLO。全部14个Stop及36个Post步骤成功，job/step计时独立复算无差异。本tuple取证闭合，不重复读取同attempt日志。

476只把storage编排上限20→25分钟，保留全部测试、单项deadline、数据库限额、串行执行和失败关闭汇总；完整YAML语义比较及24个Bash步骤通过，默认process/architecture race3.948/2.591秒及vet通过。原固定`da9426f608a99d564d573d3d4153714ba1198ada`的[Verification 39593652955](https://github.com/xiak/matrix/actions/runs/39593652955)仍为`completed/cancelled`：check119204314631明确超过20分钟job期限，19分07秒测试步骤虽成功，清理时跨过总期限。没有人工/并发取消证据，原部分storage日志不算完整验收；新run成功不改写旧run结论。

后继固定`2888c9c0812eb84abb755239e1d8938d41829b91`的[Verification 39603659401](https://github.com/xiak/matrix/actions/runs/39603659401) attempt1为`completed/failure`，不得算通过。console job119234220810在完整导出一致性检查拒绝旧嵌入：test-only源码仍参与现有build fingerprint，此提交遗漏重新导出。该失败发生在Vitest步骤之前，不能称组件断言失败或CI组件通过；Go、node-process及安装PG夹具成功，authority matrix因前置失败跳过，最终汇总失败。010拥有本分支重新生成及精确比较的修正证据；后继准确源码仍需新独立CI，不改写此终态，也不从476推导浏览器或新调度验收。

固定`640f0f59045b194466807329a12f7bc6c6b58a08`的[Verification 39586936643](https://github.com/xiak/matrix/actions/runs/39586936643) attempt1已由测试owner独立封存为`completed/success`：终态时间2026-10-21 11:18:38 UTC。十九项job全部成功；370个step为175成功、195项矩阵预期跳过，十四条lane的57个实际根均恰好RUN/PASS一次、没有根跳过。33个JSON包全部通过，1164个Test身份的JSON/plain终态一致，其中1157通过、7个真实邮件子例因缺少Postfix明确跳过。十九份必需日志共74,598,595字节完成连续范围、长度及严格UTF-8校验；三处读取超时仅补缺失尾段，没有重跑CI或回填旧失败。

前端79文件2059项Vitest以332.52秒通过，8项Node、234组对比度，以及双模式导出/嵌入324项逐字一致；33条既有React act警告仍如实保留。Go93包通过。组件测试不代替真实页面；权限感知、原Policy恢复及AccessKey/Role的准确版本和实际效果由[010](FEAT-IAM-010-console.md#本轮消费者与真实恢复证据)拥有，640f的Role导航失败不被绿色CI覆盖。

独立进程根214.61秒、Profile推进16.85秒、TOTP备份17.76秒、IAM HTTP156.96秒、三条Session51.85/51.78/36.54秒和单前驱53.75秒通过；唯一86→87保留数据摘要完整。31条容量记录合计3100样本、失败为零，原始错误对象为空且没有firstFailure，去重后的三个OOM计数均零；max计数不等于OOM。四产品117.75秒及其准确效果摘要通过，不将旧Observe超时根因改写为已解决。整轮墙钟32分59秒，14个Stop及36个Post全部成功；这些受限运行不构成生产公平性SLO。12次JSON/plain耗时各差1毫秒已单独核对，不宣称显示格式完全相同。

默认关闭的15个浏览器、13个响应丢失入口及签名入口，以及缺少实际Postfix时跳过的邮件子例均不计真实运行。CI的Stop/Post步骤不代替独立现场清点，不外推生产公平性SLO、数据库HA或签名发布。已封闭的5935、P1、P2及9062流水保留原Actions/Git记录，不重复取证或并列成另一套当前矩阵。

#### 当前行为证据与未关闭缺口

既有Session并发测试的固定修正`38a2cda69ec547c9e8d9d557bf61a3bcd992335c`保留原API、SQL、密码成本、期限和Profile。最终成功的Serializable重试可纳入并发期间已提交的新登录，断言必须核对精确Session集合、版本及终态，而非固定只撤销一个。专属PG18.4的真实40001先使旧断言以`APPLIED/revoked=2/want=1`失败，再证明B+C精确目标、caller保留、原回执重放及完成后新登录不受影响；聚焦52.48秒、三库串行race package267.261秒及默认integration/architecture race、vet通过。PG与Go runner各2CPU/2GiB、Go1.26.3、GOMAXPROCS2/GOMEMLIMIT1024MiB、`-p 1`。这不把原[39193669814](https://github.com/xiak/matrix/actions/runs/39193669814)失败回填为成功，也不将本地PG18.4等同于CI的PG18.6。

User资料/状态、Group Membership及Group附件恢复、Account安全设置正常替换已有真实浏览器证据；当前9621另完成Group删除、GROUP/USER附件撤销的可见回执、导航、下一请求权限与唯一完成/outbox/Audit后验。准确请求、唯一性查询范围和代码采用归010，不扩大为跨action唯一性。AccessKey正常生命周期与三类原命令恢复、Role创建/承担/准确Session撤销及附件REVOKE恢复已有010的逐条真实证据；后继USER/CREATE和ROLE/CREATE完成后，GROUP/USER/ROLE三类附件的CREATE/REVOKE恢复矩阵已闭合。固定`d8d75b849`又在新库从页面完成Role资料/时长更新、Trust替换、停用/启用及最终删除，并验证权威墓碑、旧Sibling拒绝和完整Audit链。当前3afe的两个独立PostgreSQL 18.6页面门禁分别完成日常改密默认撤销其他会话及显式保留其他会话：调用Session均保留并迁移代次，旧有效Session按选择准确终结或升级，已退出Session不复活，旧密码拒绝、新密码登录和唯一Audit事实均通过。固定`49bbada39`又在全新PostgreSQL 18上以1298.24秒真实页面旅程完成恢复码重新生成，证明用途限定证明、四批次一有效/三撤销、唯一通知/outbox/Audit及独立MFA后验，并保留生产五次/十分钟预算。固定`3e9324389`在另一全新PostgreSQL 18上以67.43/69.570秒完成账号策略强制MFA后的受限联系人验证、首次TOTP绑定、十条恢复码确认、重新认证及正常MFA登录；权威后验同时证明旧纯密码Session已围栏、零隐式授权、realm隔离和完整Audit链。固定`5ef1c4dec`随后以保存的恢复码完成认证器丢失自助恢复、新因子绑定、新恢复码交付和强制重新认证；固定`9bb412e10`又从账号强制MFA且普通User已经处于`RECOVERY_REQUIRED`的权威状态，用第二条旧恢复码显式取代丢失的第一流程及其pending因子，绑定第二replacement因子、交付新恢复码并正常MFA重登。两者的因子/恢复码代次、Session围栏、零隐式授权和Audit后验由010拥有。Policy边界/冲突、其他敏感用途step-up、当前签名APISIX组合及010其余非Deferred路径仍未全部闭合；最终审阅、完成marker或后台后验不能替代页面最终提交。

[Issue #4](https://github.com/xiak/matrix/issues/4)仅按010所列固定消费者、原样红绿和独立CI关闭，不扩张为Role页面验收。[Issue #5](https://github.com/xiak/matrix/issues/5)仍按原范围审阅：010已记录SET_STATUS、NETWORK、DELETE三条独立真实页面响应丢失恢复与权威后验，不能再描述为均未执行；旧1800.02秒超时仍不回填。正常Key生命周期、Role页面及其剩余缺口统一由[010的本轮真实证据](FEAT-IAM-010-console.md#本轮消费者与真实恢复证据)维护；API预建密钥不证明recovered-create的页面路径。运行资源按确切身份清理，工具拒绝的清理不计完成。

[Issue #6](https://github.com/xiak/matrix/issues/6)保持打开。原`ef10d51bfbf120ec521e665bac9d54b14fa26c0d`的[Verification 39284297226](https://github.com/xiak/matrix/actions/runs/39284297226)仍为failure；唯一失败根`TestManagedProductProviderProcesses`39.94秒，在取得HTTP200前以exit1/`PAAS_WORKER_EXECUTION_PROFILE_OBSERVE_TIMEOUT`退出。日志不足以确定底层命令或连接原因，不能归为网络或资源抖动。5935的封闭超时诊断由FEAT-007拥有，保留原3秒CLI/5秒Observe预算、API/SQL/Profile及重试；固定95a的独立CI、四产品真实协议及4197.458秒签名生命周期均通过，但仍不能反向证明旧超时的唯一原因。签名生命周期的大包处理限制只归FEAT-005及[Issue #3](https://github.com/xiak/matrix/issues/3)，不得并入本CI或页面接受。

## 高风险测试矩阵

- Tenant/Account：相同用户名、组名、策略名、资源 ID/key，错误 header/body/path/cursor 不能切换。
- Permission：直接、组、Role、boundary、SessionPolicy 组合；显式 Deny；scope 错误；属性缺失；平台不读租户数据。
- Credential：login/logout/change/reset/recover/key/TOTP 并发；当前会话保留条件；NULL generation；禁用/删除终态。
- Transaction：同 resourceVersion 并发只有确定赢家；失败无新密码/附件/session/success fact 部分效果。
- Producer：事实发生时的证明与当前服务凭据分开；暂停/撤权后历史 outbox 可完成；伪造 tenant/source/purpose/digest 拒绝。
- Resource：成员生命周期不改变工作负载、Operation、配额、审计所有者；已接受后台任务执行边界明确。目录/配额/QUEUED 或 PENDING 不是产品接入证据，至少一个当前受支持 provider 必须产生 READY 实例并完成真实协议读写。
- Schema：当前空库安装、带数据重放、失败原子性、schema/function/readiness 实际形状与签名 profile 一致；bootstrap 不补权。历史升级只覆盖明确支持的发布/数据保留起点。

## 未发布阶段与首版基线

用户确认本次 IAM 尚未上线，计划以功能收敛后的最终 schema 作为首个受支持发布基线。开发期间的 schema 1、2、3 等编号、Git 回滚点和其他任务的联调固定提交，不自动成为必须永久支持的生产升级版本；不要求每个 FEAT 从 schema 1 逐版跑完整历史升级链。

未发布迁移可以在风险替换前保存已验证并推送的 Git 回滚点后合并、改写或删除，不在工作树保留废弃实现作为兼容层。默认门禁是最终结构的空库安装、等值重放、带真实数据的重启/恢复、迁移失败无部分效果，以及当前版本的 RLS、受限身份、撤权和 Audit/outbox 不变量。它们不能因免除开发历史兼容而取消。

开发期升级门禁采用滚动的单前驱窗口：当前版本加一个明确固定的必要前驱，不按每项FEAT累积各自的旧binary/schema路径。窗口前移时在同一切片替换被淘汰的固定源码、schema断言和格式夹具，不增加兼容别名或多版本参数。当前唯一直接前驱为固定`08e1dc4a6ce81386ea7223e62d03356f82aeee58`的IAM86/Audit39/PaaS7、`contractRevision=36`，当前源码候选为IAM87/Audit39/PaaS7、`contractRevision=37`。直接前驱已有四产品、五类产品命令完成投影、USER/ROLE及Account lifecycle完成事实、完整Operation/outbox和服务Role事实；当前迁移只增加普通User资料更新与状态命令的不可变完成记录、封闭只读函数和公开GET。它不回填前驱成功命令的结果快照，因为历史事实不包含可验证的原事务返回值；旧成功requestId仍由原Audit历史保持消费，不能成为新意图。新记录与成功Audit/outbox同事务提交，错误actor/Account/目标/操作/版本、当前撤权、表权限漂移及receipt/Audit/decision篡改均失败关闭，后续User变更或进程重启不改写原结果，旧Audit canonical不变。更早的IAM85完整profile及IAM84→85等门禁只保留为已完成组件证据，不能再充当当前完整profile前驱或让测试矩阵继续向更老开发快照扩张。

固定前驱`9cf500095ae9a9cf98d322711c58a5862b899fa1`曾作为IAM82→IAM83开发期数据保留起点；其[Verification 38075029627](https://github.com/xiak/matrix/actions/runs/38075029627)终止为`completed/cancelled`，不能登记为独立CI成功。对应真实migrator/runtime运行结果只保留为下述历史组件证据；产品尚未发布且当前完整profile直接前驱已前移后，CI不再构建该旧源码或保留重复的密码/MFA/恢复夹具。IAM82发布准入仍只由已接受固定源码`147586689a9f0bcad3254f743b11c51dba35c1b5`及其签名运行证据拥有，不能回填当前完整profile兼容结论。

2026-10-11在本任务独立PostgreSQL18.6上，实际`9cf5000` IAM82 migrator/runtime→IAM83 migrator/runtime曾以108.96秒通过，覆盖账号、Session、MFA/恢复、Role/Trust/boundary、服务Role、AccessKey围栏、格式2安全报告、访问分析及不可变Audit事实。该结果证明当时的开发期组件迁移，不是当前CI、IAM83同Profile签名发布或跨profile升级许可；其源码构建入口已由当前schema不变量门禁替换，历史细节继续由Git固定对象保存。

固定`4dea30e79cfd6693df149ea40eaa876c113814eb`完成当前四产品纵向实现，固定`36fb8d20df9e0790e1e78d38d0523f3a13249e55`补齐官方Elasticsearch Docker v2 manifest list的严格归档验证；未知media type、无关source digest及内容篡改继续失败关闭。本地真实多进程门禁创建四个实例并分别完成SQL、HTTP文档和AMQP持久消息读写，随后通过公开终止入口物理删除容器、网络、数据和凭据并归还配额；精确Group授权、撤Membership后的下一请求拒绝、另一Account同ID隐藏、Operation/outbox/Audit链与终止重放/冲突同门禁通过。干净`36fb8d20d`实际组装并逐文件复验`matrix-v0.4.0-iam-products.1-36fb8d20df9e`，其IAM83/Audit38/PaaS5+r33清单包含12个文件和10个镜像；组装私钥随后清除。该结果证明真实provider和签名制品组合，不证明制品已经安装运行、同Profile A/B生命周期、HA/集群形态或LIVE UI；当前独立Verification仍须取得精确终态。

后继固定`745a5c43a9c25ed4a2901d7338872bb463218798`在原`phase1e2e` owner加入四产品效果型门禁，并从同一干净源码组装IAM83/Audit38/PaaS5+r33的签名A=`matrix-v0.4.0-iam-products.2-745a5c43a9c2`与B=`matrix-v0.4.0-iam-products.3-745a5c43a9c2`。全新network-none Docker27.5.1引擎在2 CPU、6 GiB、1024 PIDs限制下从零容器/镜像/卷开始，692.78秒完成A安装、四产品公共API创建、签名portable image identity、逐产品受保护凭据、PostgreSQL/MySQL SQL、Elasticsearch认证HTTP文档、RabbitMQ AMQP持久消息的实际写读、Operation/配额/Audit链、公开终止及容器/网络/数据/凭据清除；随后通过失败升级自动回退、B升级、显式回滚、指定备份恢复、旧AccessKey围栏、应用回滚/停止和支持去敏。只停止并启动该专属引擎后，62.91秒只读复验通过AccessKey退役、MFA新登录、双Account主账号恢复/撤权、status/verify与完整生命周期。首次运行在Elasticsearch凭据检查处发现门禁把所有产品误写为0600；生产适配器基于官方容器固定`uid 1000/gid 0`明确使用0700项目目录内的0640只读源文件，测试固定`3e0c96a72142ff7225ea260d150671ee334f8e2f`改为逐产品精确模式并额外核对0700外层目录，聚焦race/vet及上述全量重跑均通过。这接受本地签名安装与真实产品生命周期，不替代精确后继独立CI、LIVE UI、HA/集群形态或整体IAM验收。

固定生产源码`c27888fdd6f465e51fd7963e8d6ec153c21ef23f`的签名A=`matrix-v0.1.0-iam.r31.3-c27888fdd6f4`与直接后继B=`matrix-v0.1.0-iam.r31.4-c27888fdd6f4`，已在全新、外层限2 CPU/4 GiB/PIDs 768且无外部路由的Docker27.5.1引擎完成512.05秒效果型生命周期及仅重启该引擎后的61.48秒只读复验。A安装、受限数据库身份、真实SMTP/TOTP、双Account身份与撤权、AccessKey、访问分析、两代应用、Audit链、保护备份、失败升级自动回退、B升级、显式回滚、指定备份恢复及凭据围栏、应用回滚/停止、支持去敏和重启恢复均通过。签名目录当前为空是尚未随产品发布额外Profile/模板的真实状态，因此该运行证明目录传输和空seed，不冒充额外产品已上线；非空目录的动态Profile/ceiling/template效果由008真库门禁证明。包哈希、权限复验、无产品效果的私有输入权限fixture失败及资源清理由[FEAT-005当前IAM83发布门禁](../docs/features/FEAT-005-offline-platform-lifecycle.md#current-iam83-product-authorization-release-gate)唯一维护。测试专用后继`651ef0c64974d23d96e1e95417fa8627e6872e1f`未改变生产包内容，修正了真实进程门禁对服务Role上限与签名目录输入的消费；[Verification 38086980171](https://github.com/xiak/matrix/actions/runs/38086980171)已核对精确SHA，17项全部completed/success，因此IAM83现登记为当前接受发布组合，但不扩张为额外产品、跨profile、LIVE UI或整体IAM已验收的结论。

测试专用后继`f7d76d53b988ead3e15a4fa8061376e286a999fb`仍未改变上述生产包内容，只扩展既有`phase1e2e` owner：GROUP策略附件创建后先经公共完成查询验证封存回执，随后在失败升级回退、B升级、显式回滚、所选备份恢复及重启后的每次状态核对中逐字段读取同一结果；对应tenant Audit成功事实必须具有合法非空`authorityEvidenceDigest`并保留在原哈希链。相同归档在另一全新、network-none、2 CPU/4 GiB/PIDs 768的Docker27.5.1经典存储引擎完成474.53秒效果型门禁及仅重启该任务引擎后的64.85秒只读复验。该结果关闭当前GROUP完成证据的签名运行缺口，不新增生产ABI、跨profile许可或UI结论；其独立[Verification 38096855001](https://github.com/xiak/matrix/actions/runs/38096855001)已核对精确 SHA，17 项全部`completed/success`。

本任务专属PostgreSQL 18.6上的固定生产源码`147586689a9f0bcad3254f743b11c51dba35c1b5`已通过：格式2安全报告真库race 10.877秒，证明缺失或JSON `null` 的`credentialState`即使重算规范摘要也失败关闭；AccessKey真库race 89.600秒，证明新意图缺失或`null`状态以SQLSTATE 23514拒绝；实际IAM81 executable→IAM82迁移/运行race 110.090秒，证明围栏前create完成回放`CURRENT`、围栏后status完成回放`RECOVERY_FENCED`，两份旧结果字节不变，当前新写显式保存围栏状态；三库受支持备份恢复race 170.494秒，证明当前读/列表/格式2报告为`RECOVERY_FENCED`，禁用再启用和重启不清除围栏，旧Secret真实签名仍401。第一次恢复复跑因未向测试进程提供已存在的任务自有PG18工具容器而在`pg_dump`启动前失败；绑定完整容器ID和`matrix.task=iam82-b5f5`后在三份全新数据库通过，不把工具链失败回填为产品成功。相同源码的双IAM/Audit/PaaS/dispatcher真实进程race以253.748秒通过；全仓无缓存race、vet、模块校验、OpenAPI生成前后字节一致和Linux amd64/CGO关闭构建通过。

同一源码的签名A=`matrix-v0.1.0-iam.r30.1-147586689a9f`和直接后继B=`matrix-v0.1.0-iam.r30.2-147586689a9f`均为IAM82/Audit37/PaaS3、`contractRevision=30`及相同拓扑摘要。新的network-none Docker27.5.1经典存储引擎在2 CPU/4 GiB/PIDs 768限制下从零镜像、零容器、零卷开始，以617.76秒实跑A安装、受限数据库身份、IAM/AccessKey、格式2报告、真实SMTP/TOTP、两代应用、Audit链、受保护备份、失败升级自动回退、B升级、显式回滚及选定恢复；恢复后的当前读/列表/报告准确为`RECOVERY_FENCED`，旧Secret签名401且停用再启用不清围栏。删除私密SMTP输入后只重启该任务引擎，84.01秒的只读门禁通过围栏、MFA新登录、租户主账号/撤权、status/verify、支持去敏和完整生命周期。A/B交付归档重新解包后逐路径、SHA-256和模式一致，无链接；A、B、公钥摘要依次为`d1f3fbfe5a7757b9b42272109182b9ad4a55f010540be142560fecf8d04e7b55`、`7852187a50248b67ac5bdf0810c0c6681d66d050562a7f923fc2be9e41631c03`、`22646ddc7a202c1285a1f804cbaed1acacafcaba1cbb007a5ba94f968c40409f`。

精确生产源码的[Verification 38049893217](https://github.com/xiak/matrix/actions/runs/38049893217)中`authority-roles`因测试只读Role目录第一页而未找到随机排序在后页的对象，`authority-runtime`因受管服务确定性SHA-256退出请求ID偶然包含一个测试OTP的六位子串而失败；前者后续证明篡改失败均是目标对象未建立后的级联，不作为产品通过。该run随后由后继推送按同分支并发策略结束为`cancelled`，不能把其他已成功job回填为整轮成功。仅测试提交`f25977b6f8385341d9b62fa9c62b756f9ddec83d`改为有界遍历真实cursor，并要求服务Role退出请求同时具备固定服务主体、对应session签发事实、固定算法派生及IAM原文/规范副本一致后才把哈希内六位子串认作结构性碰撞；精确六位值、任意caller requestId、错误来源和篡改副本继续拒绝。本任务重新创建的独立PG18在1 CPU/768 MiB/PIDs 192限制下，Role race以74.04秒、完整五进程race以234.94秒通过，扫描器race以3.527秒通过；资源随后按任务标签全部删除。[Verification 38055454202](https://github.com/xiak/matrix/actions/runs/38055454202)已由GitHub API核实为精确`f25977b6f8385341d9b62fa9c62b756f9ddec83d`，Go、console、node、PostgreSQL HA、十二项串行authority门禁及最终汇总共17项全部`completed/success`。`f25977b6f`没有生产文件变化，因此不重打或冒充另一套A/B。

格式2表格兼容门禁使用当前生产`EncodeAccountSecurityReportCSV`生成覆盖Account、两个User及AccessKey状态的代表性755字节CSV，经同一公开validator和摘要校验后由本机Microsoft Excel 16.0打开。首次打开及另存XLSX、关闭并重新打开均为5行×19列，第19列名为`credential_state`、AccessKey值为`CURRENT`、公式数0，未导出被排除的自由文本；探针源码和临时CSV/XLSX在核对后删除。该结果证明当前格式2编码可由声明的真实表格程序安全往返，不替代LIVE UI组合验收。

IAM82/Audit37/PaaS3、`contractRevision=30`的完整签名运行证据统一由[固定消费者的集成检查](#固定消费者的集成检查)维护。固定`147586689a9f0bcad3254f743b11c51dba35c1b5`已在原owner覆盖Group、Role、AccessKey、恢复围栏和格式2报告的效果型路径，并明确区分普通发布替换中的凭据保留与受保护备份恢复后的永久凭据围栏，因此它是最近同Profile接受点；当前IAM83/Audit37/PaaS3、`contractRevision=31`不能继承该签名结论。跨Profile继续在副作用前拒绝，LIVE UI、数据库HA和整体IAM验收不因任一结果完成。

固定`b54397e31a08367a0433412f9588a6f3f1846218`保留 IAM74 PolicyVersion 草稿委派的完整本地证据；其 [Verification 37872357458](https://github.com/xiak/matrix/actions/runs/37872357458) 已有 `authority-runtime` 失败且整轮未成功，不能作为独立 CI 验收点。固定`f62943fadf44f31b8bc04c2bf60f1861f3f45cfc`的 IAM75 后继在新库通过非 root 默认切换聚焦 race 19.69s、完整策略存储 race 306.50s、IAM HTTP race 118.73s、Audit HTTP race 1.47s及独立 IAM 双副本/Audit/PaaS/dispatcher 进程 race 273.23s；同一 CI runtime 组合中的真实备份进程另在最终源码通过 38.51s。门禁证明当前 direct USER 和 Group 闭包在同一 ceiling 下完整切换，Group 新成员竞争触发整事务重试，移除竞争在真实锁上序列化；无边界、平台绑定、Root/旧前驱证明、Role 附件、User/Role boundary 引用、并发登出/ceiling 移除及完成记录故障均失败关闭或完整回滚。精确已提交命令只返回原结果，缺失/篡改闭包完成和原 decision/outbox 关联不会重建历史；Root 既有默认切换路径保持。[Verification 37878838338](https://github.com/xiak/matrix/actions/runs/37878838338) 已按精确 SHA 核实 completed/success，17 个 job 全部成功；仍没有相同完整 profile 的签名 A/B 生命周期，因此不得解释为跨 profile 发布兼容或整体验收。N+1 也不通过构造另一个假想 schema 提前测试。

同一 IAM75 工作树已通过全仓无缓存 `go test -race -count=1 -p 2 ./...`（含 architecture）、`go vet -p 2 ./...`、模块校验、API 重新生成零差异、Linux amd64/CGO 关闭的全仓构建和 diff 检查。默认缺少外部 DSN 的 SKIP 不计真实运行门禁；这些本地结果仍与固定提交后的独立 CI 分开认定。

只有明确要求保留某个现存安装的数据，或存在无法同次替换的真实消费者时，才增加例外并记录准确固定起点、现实消费者、不能原子迁移的原因和退出条件；不能用曾经做过一次实验代替这些证据。已发布Audit记录的编码/哈希和安装器的效果前拒绝，仍是当前必须保持的合同，不与未发布IAM中间版本测试混同。旧binary实验的历史运行证据保留在Git及其原交付记录，不作为后续默认完整矩阵。联调消费者在各自工作区使用固定提交原子对齐，不擅自清空对方环境。

清理以当前行为价值而非测试数量为准：重复场景、废弃对象/接口和偶然实现快照删除；跨账号越权、撤权/会话不复活、MFA事实不补造、失败原子性、历史完成及Audit/outbox保留为当前门禁。产品声明变更不能自动扩大既有策略、不可忽略不兼容Deny等独立规则，须从旧版本外壳中移回当前产品行为测试，不能随历史路径一起丢掉。源码兼容、产品声明推进、同版本重放和受支持备份恢复是不同边界，不构造其全组合笛卡尔积。每个owner在自己分支审查并实跑保留门禁，不能为了通过失败测试或继承其他分支状态而删减。

当前71个前端测试文件的结构审计没有发现`.snap`、快照API或读取源码文本的实现快照，也没有足够证据删除现行响应丢失、容量拒绝、TOTP、Audit、CSP、离线HTTP或嵌入等价测试。确认的重复仅在CI执行范围：必需的全仓Go/race门禁已运行`test/authorityprocess`纯单元，`authority-runtime`又因缺少`-run`重复运行同一批单元。当前源码保留全部测试，把runtime步骤的required清单和锚定选择器收窄为`TestIAMAuthorizationProfileAdvanceProcess`、`TestIndependentIAMAuditAndPaaSProcesses`和`TestIAMTOTPBackupProcesses`三个真实进程根；原数据库、race、`-p 1`、预算及选择脚本的RUN/非SKIP/PASS检查不变。该调整只消除纯单元重复，不声称缩短自然窗口或重型进程本身；固定`08e1dc4a`的十九项独立CI已确认该形状。

首版发布冻结实际完整 schema/profile、安装器和服务二进制；从该正式基线之后才维护已声明支持的升级、回滚和备份兼容窗口。首版产品版本不等于必须立即把当前各服务 schema 数字改成 1；发布前是否压缩/重编号要与安装及产品消费者一次性对齐。测试范围调整不授权删除用户数据，也不授予跨 profile 安装准入。

### 开发窗口收敛的固定证据

2026-09-24按用户要求在原authorityprocess owner收敛，先保存本地真库验证并推送的`09fac913`回滚点。固定`aefe4f786242d7d6816f253b6389d5c94c314a75`删除9个过时IAM升级入口及仅供它们使用的旧RoleBinding wire、schema分支和夹具；CI从7条IAM前驱路径收敛为1条，同时移除6个额外数据库及对应DSN配置。保留原受限身份、当前IAM/Audit/PaaS业务、Purpose/OTP/恢复、并发、秘密检查及所有原期限/成本，不删失败安全断言、不放宽版本/profile判断。精确源码的[Verification35972120363](https://github.com/xiak/matrix/actions/runs/35972120363)已由GitHub API核实completed/success，go、authority-process、authority-storage、authority-runtime、authority-step-up、authority-recovery-window和node-process七项全部通过；本测试窗口清理已验证，不代表后续S2c或整个IAM目标已验收。

原`TestIAMRetainedPredecessorProcessUpgrade`及仅为它存在的固定源码提取、旧恢复、设置和MFA夹具已在当前替换片删除；它们证明过的开发期版本保留在Git历史，不再让当前CI重复验证已淘汰schema。仍属于当前契约的服务Role模板防篡改已迁入注册产品真库owner，Profile族演进已迁入当前schema真实进程owner；密码、Session、MFA、恢复和角色各自由现有专项真库/进程门禁继续拥有。

当前`TestIAMAuthorizationProfileAdvanceProcess`从当前schema和当前可执行程序建立Policy、决定及producer proof，再由明确的acceptance-only build tag只改变产品声明：新动作注册不扩大已编译策略、仅发布新版本不切默认、显式切换后才允许，旧声明/决定/proof保持，不兼容Deny不能因资源不匹配被忽略，重启与撤权继续有效。这不是假想schema升级或生产新增PaaS接口；普通及发布构建仍只使用恒等变换，测试不再读取固定旧源码、解析变量名或改写Go AST。该门禁使用独立`MATRIX_IAM_PROFILE_ADVANCE_POSTGRES_TEST_DSN`，与完整profile直接前驱和其他运行数据库彼此隔离。

同一最终测试源在另一独立空白PG18.6数据库运行`TestIndependentIAMAuditAndPaaSProcesses`，143.49s（包146.678s）通过：实际受限runtime登录、IAM双副本和PaaS/Audit/dispatcher、双账号资源/Operation/outbox，绑定/强制改密/恢复/step-up提交后真正丢TCP回包、重启与原意图核对，跨副本OTP仅成功一次，停用USER后的原历史投递/重放均保持。SMTP没有在本轮实际投递，不能用联系地址/通知夹具代替；亦未重跑签名发布或浏览器。PG使用Windows Job硬限2逻辑CPU/1GiB/24进程、16连接、64MiB shared_buffers、4MiB work_mem和零并行worker，重型门禁串行；确认零其他客户端后正常停止，只保留数据，没有清理其他任务或重启共享/远端服务。

最终源码的全仓`go test -race -count=1 -p 2 ./...`（含architecture）及`go vet -p 2 ./...`通过，使用同一Go1.26.7/GOMAXPROCS2/GOMEMLIMIT512MiB。默认外部门禁SKIP不计为真实环境验收；真库范围仅为上述已运行的两项。gofmt与diff检查通过，本片没有生产API/SQL/schema/profile、安装器或UI变更。

后继固定`8dee0a2c1b85b080657064b9f4ecffda9301ad7d`只扩展现有`phase1e2e` owner：备份前直接读取策略附件CREATE/REVOKE完成回执，封存原非敏感结果，并要求后续每次租户状态核对使用原actor的新有效Session逐字段读取同一结果；关系终态、服务健康或Audit存在都不能替代该回执。其[Verification 37665764059](https://github.com/xiak/matrix/actions/runs/37665764059)已由GitHub API核实精确SHA，Go、node、console、十二项串行authority门禁及最终汇总共十六项全部`completed/success`。该独立CI不运行外部`MATRIX_PHASE1_E2E`签名生命周期，不能据此声称当前Profile的安装、升级、回滚、所选备份恢复和重启已执行新增断言；该真实运行仍是单独的发布门禁。

## 可用性与容量门禁

### 当前CI任务分配

固定`21b3de3a`的[Verification36462106282](https://github.com/xiak/matrix/actions/runs/36462106282)中，storage的HTTP纵向用例在184.76s失败，平台grant/reset/status的尾部检查及后继bootstrap重放已超过原三分钟context；不能将前段通过算作完整验收。相同固定生产/测试源码在本任务独立PG18.4（1CPU/768MiB/PIDs192/max_connections24）及Go1.26.5 runner（2CPU/1536MiB/PIDs256、GOMAXPROCS2/512MiB）实际复现201.84s失败：账号场景128.56s、密码Session规则41.60s通过，后尾密码/平台竞争耗尽原context。没有证据将此解释为新的授权错误，也不能放宽期限忽略它。

当前修正将原101个用户和99个账号的HTTP分页准备及全部分页/跨账号/跨目录cursor断言移到同一integration文件的`TestIAMDirectoryPaginationPostgres`，使用独立空库；原纵向用例保留身份、生命周期、全部密码与平台竞争、等值重放和outbox检查。两部分串行执行，均有三分钟context；这是独立行为夹具的分离，不是把一次事务或认证期限续长。新增入口复用原受限运行身份和真实bootstrap/登录/改密，所有分页对象仍经真实HTTP创建，不复制原200条准备、不伪造hash或授权行。原storage lane二十分钟、PG/runner限额、密码成本、分页上限和生产期限均不变；CI的编译枚举必须实际选择新入口且有配套DSN，不能以默认SKIP通过。

相同固定生产源码加测试Go blob`dc7d27b1dbee3a3b491590a26f7c38e6961c63e2`，在同限额PG18.4/Go1.26.5的两个新空库串行race-p1复验：独立分页83.92s（包85.005s），原HTTP纵向139.98s（包141.094s）全部通过。原change/reset/recover/logout/旧密码登录五组竞争、平台grant与reset/status/历史停用三组、原bootstrap/schema重放和outbox物理owner/链均实际到达并通过；不是删掉超时尾部或缩短密码历史。专属编译缓存被复用，不能将差异声称为生产性能优化。最终固定`047f669490278fee978e0e11208a241ac7eac6df`的[Verification36470362108](https://github.com/xiak/matrix/actions/runs/36470362108)于2026-09-29经GitHub API核实精确SHA、十二项执行job及汇总全部completed/success；storage与capacity均有实际成功结果，不回填21b3或9df的失败，不包含后续未提交密码到期增量。

工作流选择核对另发现十个解绑fixture虽然已在两个专门lane运行，却仍被storage枚举后因缺DSN而SKIP。修正只将这十个准确名称排除出storage，专门lane的实际命令和场景不变，不使用会吞掉未来新测试的宽泛前缀。原编译清单的40个顶层IAM fixture与全部选择器联合核对，每个恰有一个实际执行位置；storage为9项，新增分页具备独立DSN。YAML及19段Bash语法校验、API/IAM integration/architecture默认race和对应vet通过；缺外部环境的默认SKIP不计真实证据。确认零其他数据库客户端后正常停止本轮PG，已删除三个自有容器、两个源码/编译缓存卷和空网络；合成数据不保留，没有操作其他任务或远端资源。

固定`4ded2a806e612047b969a3eb22df2e54f244f1bf`的[Verification36579738335](https://github.com/xiak/matrix/actions/runs/36579738335)中，`authority-runtime`的本人会话/锁后到期步骤从14:30:10Z运行到14:41:11Z后以exit 1失败，后继保留数据及实际进程步骤被跳过；不能用同一run中已通过的Go、node、storage和roles覆盖。匿名job页不给测试日志，但固定源码的完整原选择器在本任务独立PG18（1CPU/768MiB/PIDs192、随机loopback端口）、Go1.26.3/GOMAXPROCS2/GOMEMLIMIT512MiB下实际全部通过，package为553.963s，已逼近Go默认十分钟总计时器。当前修正不删除或缩小测试：原九个真实数据库fixture按生命周期分成两个串行Go进程，Session/密码组package332.147s（墙钟334.729s），TOTP/通知组package208.819s（墙钟212.348s）；各fixture自己的context、数据库、race、密码成本、lane二十分钟及`max-parallel=1`不变。这只消除无业务含义的共享package计时器耦合，不回填失败run；固定提交和独立CI仍待完成。本轮唯一标签容器、空网络及临时固定源码副本已核对后删除，未动其他任务或远端资源。

容量lane不能依赖`setup-go`恰好命中完整模块缓存。固定`9df45126`的[Verification36455507556](https://github.com/xiak/matrix/actions/runs/36455507556)中，`authority-capacity`在测试package准备阶段因`/modules/cache/download`只读且缺依赖而失败；没有容量样本，不能解释为容量通过或IAM业务断言失败。当前workflow在挂载前显式执行`go mod download`和`go mod verify`，测量容器仍只读使用该缓存，保留原镜像、限额、两个测试入口及全部期限。2026-09-29在本任务独立空缓存、固定Go1.26.5镜像中实际复现只读失败；按同一下载/校验顺序准备后，断网且GOPROXY关闭的容器成功加载authorityprocess的完整测试依赖并通过模块校验。YAML及19段Bash语法检查通过。这仅验证冷缓存准备修正，不替代完整容量运行或后继独立CI，也不回填原失败。

数据库门禁按既有测试owner串行分片，不按开发schema叠加兼容矩阵。固定`fa27b0fbf54e94e21da38d32763dcaf89f370538`的[Verification36318553704](https://github.com/xiak/matrix/actions/runs/36318553704)不能标为通过：storage测试步骤19分25秒内全部success，但整项任务含准备/清理超过20分钟；GitHub明确注记`The job has exceeded the maximum execution time of 20m0s`，storage最终cancelled，汇总检查failure。其余Go、node、runtime、step-up、replacement、replacement-qualification、recovery-window七项success不代替该缺口。

固定`42035189eb823e388509f54525889c1a18c6b79d`将原`TestIAMRoleAndManagementReferencesPostgres`及其七个独立数据库/DSN从storage一次性移至`authority-roles`，不复制测试。该入口在上述CI实测344.607秒，独立任务上限15分钟；storage仍20分钟，原每fixture两分钟及所有锁等待/密码成本不变。数据库lane继续`max-parallel=1`、PG1CPU/768MiB/PIDs192，其他原任务限额不变；汇总检查仍要求全部lane成功，取消、跳过或失败均关闭。该固定切片的数据库总集合和场景不增加，只有执行分组调整；本地YAML解析、17段Bash语法及调整前后DSN集合/无重复检查通过。[Verification36367216408](https://github.com/xiak/matrix/actions/runs/36367216408)已于2026-09-28重新通过GitHub API核实精确SHA、九个执行job及汇总全部completed/success，不能回填旧超时为通过。

主动解绑切片增加独立`authority-removal`与`authority-removal-security`源码lanes，十个专属数据库入口均来自原TOTP/设置测试owner，顺序运行当前解绑、可证明重绑及安全竞争，不添加开发历史版本矩阵。两项分别上限15分钟，保持原数据库限额、`max-parallel=1`和全lane失败关闭汇总。固定18bdcd9a的[Verification36382998585](https://github.com/xiak/matrix/actions/runs/36382998585)中，removal成功，但removal-security将六个fixture共用一个Go进程，在600.087s触发默认10分钟总超时；此时最后的Account fixture仅运行12秒，不能称其通过或据此断言死锁。后继改为原Authority/Sessions/Mutations和Factors/Recovery/Account两组串行调用，每组保持默认10分钟、各fixture原3/5分钟及job15分钟不变；六个精确入口和DSN无增删/重复，不放宽密码成本或真实OTP时间。独立更换lane的失败及修正归[009](FEAT-IAM-009-security-governance.md)；旧失败不因后继通过而回填。

后继工作流本地解析及19段Bash语法通过；相对于原固定分组，六个精确测试名均只选中一次，DSN集合、资源、串行矩阵与job期限保持一致。旧18的CI最终failure，其中recovery-window于2026-09-28 07:18:50 UTC completed/success；此前三项失败不回填。修复固定在已推送ba17e702，累计固定3178b649f6e61c59786f6d0b14828ff3196876f3的[Verification36391053858](https://github.com/xiak/matrix/actions/runs/36391053858)已于2026-09-28核对精确SHA、completed/success及全部12项成功。该累计后端通过不包含后继密码规则候选的验收；后继失败与修复证据归009。

### 运行验收要求

009设置竞争和放宽的双向验码检查沿原integration入口/专属数据库，在现有`authority-step-up`内串行调用。十项设置竞争包含仅密码规则的两个次序，原三分钟期限保留；设置放宽也保持原三分钟。两个入口各启动独立Go进程，避免与七分钟proof fixture共用原10分钟包计时器；不扩张任何单项或包期限，lane仍20分钟、原PG限额及`max-parallel=1`不变。实际OTP跨窗口拒绝及四组运行结果归009，不增加历史schema组合。YAML及19段shell语法检查、调整前后四个顶层fixture精确各选择一次、原DSN/执行条件/串行策略/作业预算一致性已验证；固定`08e1dc4a`的`authority-step-up`及总汇已经通过。工作流中单独注册与一般事务排除必须配对，不能重复运行或靠缺DSN的SKIP冒充通过。

- 两个独立 IAM 进程使用同一受限权威库，交错登录/授权/撤销；撤权已确认后到另一进程的新请求必须拒绝。停掉本任务其中一个进程后，另一进程继续处理已有会话，不要求重新登录、不复活权限；只证明服务副本能力。
- 在本任务限额环境分别测量密码认证、普通策略授权、复杂策略/组继承和混合管理流量，记录硬件/CPU/内存、数据与策略规模、并发、吞吐、P50/P95/P99、错误率、连接/队列/锁等待及 outbox 积压。纯函数 benchmark 不代替 HTTP+PG 容量结论。
- 一个账号超载时，另一账号仍可取得受预算保护的服务；超额明确拒绝，不能无限排队、无限创建连接或多层放大重试。固定策略大小/语句/附件预算要有边界与攻击测试。
- IAM 与数据库连接中断时不得返回旧 Allow；未知写结果只核对原意图。恢复连接后已提交撤权仍有效，已提交 outbox 可恢复投递。
- 数据库真实主备切换的 RPO/RTO、确认提交保留、旧主 fencing 与失败关闭，只能在安装 owner 提供的独立受限部署上验收；无该部署时保留显式未验收项，不重启共享服务、不以单库重连冒充主备切换。

### PostgreSQL受控切换基础夹具

当前候选从固定`a11ea2df77bd6be0f99b2229380e9d2d76d084d6`选择性采用现有installation测试owner中的三份夹具、最窄架构依赖例外和独立CI任务，不导入该分支的发布Profile、FEAT状态或checkpoint。夹具只接受已拉取并解析为完整`sha256:`身份的PostgreSQL 18镜像和唯一任务标签；两个数据库节点分别限制为0.5CPU、512MiB内存/无额外swap、128 PIDs，使用物理复制、`synchronous_commit=remote_apply`和固定同步standby身份。切换先关闭稳定端点并终止已有连接，再核对单主/备库角色和已确认LSN回放，删除旧主容器形成fence后才提升备库、切换端点并重新探测；角色、回放、fence或路由任一证据不确定时保持端点关闭。旧主只能删除原数据卷后从新主重建为只读standby。清理只删除同时匹配准确task/slice标签的容器、卷和网络。

基础门禁写入一个真实确认事务，保存primary flush与standby replay LSN，要求切换后记录仍恰好存在、相对该checkpoint的`ConfirmedRPOBytes=0`、fence→promote→switch→ready时间顺序成立且本轮RTO不超过45秒；另一路故意使standby角色不可观察，要求切换拒绝、稳定端点不可写且健康原主不被误删。donor后继固定`3fa5e8959d8c41bf51d41698df0fff73cafa089a`的[Verification 37555449639](https://github.com/xiak/matrix/actions/runs/37555449639)中该独立`installation-postgres-ha`任务实际completed/success，但同一run的authority-runtime及最终汇总失败，因此这里只把该任务当作夹具来源证据，不继承整个提交验收。当前分支本地无Docker服务；在配置拒绝、package/architecture聚焦race、vet、workflow YAML/Bash语法和diff检查之外，精确当前源码`8e633f23050e4418ad6617b7792ea24aa050efa5`的[Verification 37684632276](https://github.com/xiak/matrix/actions/runs/37684632276)已实际运行基础复制/切换5.55秒及不确定角色失败关闭3.88秒，新增独立任务本身为`completed/success`。同一workflow后续已全部到达终态：除下述已定位的`authority-runtime`外，其他十五个执行任务全部`completed/success`；最终`authority-process`汇总按设计因依赖失败而失败。因此该run仍不是整轮CI成功，但没有发现第二个独立失败。

该夹具不是产品HA实现：稳定端点是测试进程内TCP转发器，没有自动选主、跨故障域、签名安装拓扑或生产代理；基础marker场景本身也不能证明authority运行语义。因此它只关闭可重复物理复制/fencing基础环境缺口，不能把AC-11数据库HA标记为通过。

当前后继候选在既有`test/authorityprocess` owner中让两个真实IAM、Audit和IAM dispatcher通过该端点使用各自受限数据库登录：root与普通User完成真实登录/改密，普通User先由系统策略附件取得PaaS读取权限；停止dispatcher后撤销附件并保存CREATE/REVOKE完成回执与待投递outbox，再取得同步checkpoint。切换期间持续以被撤主体请求授权，唯一可接受结果是当前Deny、明确503或传输不可用，任何旧Allow或其他状态都失败；调用方不把未知响应当成permit，也不自动重放为写成功。切换后重新建立管理连接，核对两个IAM仍拒绝、原完成回执逐字段不变、待投递事实仍在；新的受限worker完成投递后，每个IAM outbox event在Audit恰好一条并完成租户链验证。旧主删除原卷、从新主重建为只读standby后仍不能复权。

本候选在`GOMAXPROCS=2`下通过全仓无缓存race、vet、模块校验、architecture、格式、workflow YAML/Bash语法及diff检查；默认测试明确SKIP需要Docker的双节点路径，不能把编译通过当成运行通过。上述精确CI独立任务已经把当前两个IAM、Audit、dispatcher与双PostgreSQL18真实运行39.48秒：日志记录`confirmed_rpo_bytes=0`、数据库切换RTO 625毫秒、从故障探测到IAM/Audit恢复3199毫秒；原CREATE/REVOKE回执、撤权Deny、待投递outbox、受限登录、单次Audit记录、完整租户链和旧主删卷重建只读standby均由同一用例断言，任务清理成功。该数值只是本次GitHub托管runner和测试端点的观测，不是生产SLO；门禁也不提供自动选主、生产代理、跨故障域或匹配Profile的签名安装拓扑，这些仍须安装owner另行交付和验收。

同一精确CI不能记作整轮成功：`authority-runtime`在实际多进程路径完成主要业务断言后，凭据明文扫描器把当前六位TOTP与Audit服务端随机生成的`audit.platform-records.read` request/correlation ID中的相同子串判为泄露并失败。该结果不被回填；固定`ea39b029e`把低熵结构例外收窄到数据库中`source=AUDIT`的四个封闭读/验链事实、合法SourceAudit事件、`request-<32hex>`形状及相同correlation，其他数据库来源、错误action、非标准ID、错配correlation、精确验证码和所有长凭据继续失败。该修复已通过全仓无缓存race、全仓vet、architecture及专属正反例，但新的精确独立CI成功前仍不能代替远端真实门禁。

精确修复SHA `8e2c82ca8edddcc036db3780d832a160ee0adbc0`的[Verification 37701822012](https://github.com/xiak/matrix/actions/runs/37701822012)再次在`authority-runtime`失败，但失败已前移为扫描器将`audit.canonical.AUDIT`的canonical envelope当成原始`AuditEvent`严格解码，报告`invalid Audit access plaintext inspection source`；原业务流程和第一组会话/密码/TOTP门禁均已通过。同一run的`authority-capacity`不是第二个容量或权限失败：`TestIAMCapacityProcesses`先以151.50秒完整通过，`TestIAMPasswordHistoryCapacityProcesses`也完成单次控制、100次对照登录、100次完整历史改密和100次并行登录，全部观测均为期望状态且`failures=0`，只在295.26秒末尾执行同一明文扫描时以相同错误失败。该run随后完整到达终态：十六个执行job中其余十四个均`completed/success`，包括22分40秒的真实恢复码窗口；最终`authority-process`汇总按设计因两个依赖失败而失败，没有发现第三个独立缺口。旧run仍必须记为失败，但这两项失败共享同一测试扫描器根因，不能据此否定已经完成的容量业务观测或将其冒充通过。

后继修正不复制canonical解码器：数据库查询为同一Audit记录的原文与canonical行同时携带该行权威`event_document`，严格解码且验证SourceAudit后，原文要求逐字节相同，canonical则由唯一`auditv1.CanonicalizeEvent`重建并逐字节相同，才能从原事件的封闭action与服务端ID推导低熵结构值。错配原文、改写canonical、canonical反向冒充权威事件及无效SourceAudit均失败关闭；非Audit来源仍无例外。修正后专属正反例、整个authorityprocess/architecture race、全仓race及vet通过；本地无Docker/PG18，故仍需新的精确远端真库成功证据。

该真库证据已由生产代码修正`120c74945b27a1d863ab978ab174787b8bfdcb6b`及其精确证据头`1ef064768b4c06de7149a2711bac0c364130dcb2`的[Verification 37715120172](https://github.com/xiak/matrix/actions/runs/37715120172)关闭：attempt 1共十六个执行job及最终`authority-process`汇总，十七项均`completed/success`。原失败路径`authority-runtime`在20分25秒内完成，`TestIndependentIAMAuditAndPaaSProcesses`以236.75秒通过，`TestAuthorityPlaintextInspection`及其原文/canonical权威来源、错配、伪装和无效来源正反例以0.06秒通过；`authority-capacity`在8分29秒内完成，原容量与密码历史容量分别以132.57秒和278.54秒通过。日志不再出现`invalid Audit access plaintext inspection source`或原低熵误报。该结果接受当前固定源码的扫描器回归及其PG18门禁，不替代IAM67/Audit35/PaaS3+`contractRevision=15`的签名A/B生命周期或LIVE UI验收。

AC-11 的服务副本首片证据：2026-09-11 现有 `TestIndependentIAMAuditAndPaaSProcesses` 在本任务独立 PG18 下通过，两个真实 IAM 进程分别使用最多 2 连接的受限登录。原实例会话可在另一实例使用，跨副本 grant/revoke 与 session revoke 生效；原实例停止后另一实例仍正确允许租户读取并拒绝已撤平台权限；仅副本登录 NOLOGIN+断开该登录连接期间返回 503，恢复后继续工作。原 5721 保留升级与该组合门禁合计 56.307s。该首片本身没有负载均衡自动切换、数据库主备切换、容量/公平性 SLO 或完整 HA 结论；后继受限容量、开放环过载和受控数据库切换证据见下文。

### 受限运行测量首片

当前目标是在既有`test/authorityprocess/process_e2e_test.go`的真实进程fixture内增加独立容量入口，不修改IAM、Audit或产品的生产契约，不新建压测框架。它使用自己的空白PG18数据库、两个受限IAM登录与真实Audit/PaaS/dispatcher；正常功能门禁和浏览器fixture仍走原路径，不以测量替换安全场景。数据全由当前HTTP建立，不能直接插入授权或省略生产密码计算。

固定工作集为两个被测Account及同名User，每账号分别使用直接策略和8个Group继承的自定义策略；复杂路径还须有真实条件、显式Deny和User权限边界。分别以并发1、2测量登录和简单/复杂PDP，另外测业务读取、管理写入与授权混合、错误密码与另一账号授权配对，以及确认撤权后的双副本拒绝。各类至少100个请求；固定数量的同步批次属于闭环负载，不当作无限到达速率或饱和吞吐。配对的对等请求数由测试客户端保证，只观察干扰，不证明服务端租户公平调度。超时、错误状态/响应/归属不能被剔除或自动重试，期望的Deny/错误密码拒绝与服务错误分开统计。Deny必须保持不返回账号/主体，其真实归属和原请求由测量外的不可变决定核对，不能为了测量放宽公开响应。

从完整HTTP请求到受限PostgreSQL及真实结果计算样本数、成功吞吐、错误数、P50/P95/P99与最大延迟。请求体、bearer、密码和原始响应不进入结果；新登录的Session及凭据不得重复，全部新凭据在计时区间外逐个经另一IAM副本的当前身份接口证明可用及原USER归属，并参与既有进程输出脱敏检查。单个请求保持原5秒时限，整个fixture保持原6分钟预算；Go2、runner最多2CPU/1536MiB/PIDs256、每IAM最多2个数据库连接，PG另有显式限额，不用放宽成本、时限或无界并发取得通过。

测量进程只读采样当前数据库连接/活动/锁等待计数与outbox积压，同时读取本轮runner的cgroup限额、CPU/限流及内存指标。采样峰值不是连续观测，也不能推算总锁等待时长；尚无进程池等待观测时明确为未知，不用0代替。数据库动态/累计统计的采样及事务缓存限制遵循[PostgreSQL18统计说明](https://www.postgresql.org/docs/18/monitoring-stats.html)。实际身份、响应归属、下一请求撤权及积压最终投递仍须独立断言。通过测量只增加当前工作集的基线，不完成过载公平预算、开放环容量SLO、故障自动切换或整个AC-11。

#### 独立账号干扰测量增量

在原2000次配对请求之外，增加一个正常账号的100次复杂授权对照，以及另一个账号100次连续错误密码请求与该正常账号100次复杂授权的独立发送。正常授权的计划间隔为100ms；每个账号最多一个在途请求，总并发仍不超过2，两副本交错使用。发送方不等待另一账号完成，不新增无限队列、重试或生产限流实现。若发送滞后，仍保留全部样本并记录相对计划的滞后及端到端完成延迟，不能丢弃或补造“准时”到达。

同时记录每个账号真实发送窗口、独立吞吐、请求延迟及处于另一账号负载窗口内的样本数；干扰组必须有实际重叠，不能将错开的串行执行算作隔离证据。原配对组、5秒请求/6分钟fixture期限、CPU/内存/连接/PID上限、不可变决定归属、审计投递与链验证全部保留。调度器的默认测试只证明发送约束，不能替代真实HTTP/PG测量。

本增量已实现并通过下面的本地真实测量和精确固定源独立CI。它用于区分客户端配对造成的等待与服务端实际干扰；即使全部正确响应，也不证明开放环饱和容量、租户预算、公平限流或HA，AC-11的这些缺口仍保留。

2026-09-18，在原固定`4e868004`加测试Go blob`0937e73110c3b2dbcde6fc6bfcf68764fd5e548b`的干净源码导出上，完整容量门禁通过104.91s（package105.956s）。固定Go1.26.5、runner2CPU/1536MiB/PIDs256/GOMAXPROCS2、GOMEMLIMIT512MiB；独立PG18.4为1CPU/768MiB/PIDs192、512MiB临时数据、无宿主端口，均无额外swap。原10个阶段完整保留，合计12阶段/23条账号观测/2300次请求，失败0；400个真实新凭据经另一副本逐个认证，1400份计时授权决定与存储的原账号/主体/请求完整匹配，最终outbox和两条租户链全部验证。预计的错误密码401及撤权Deny不当作服务失败或排除样本。

| 独立场景 | 样本/预期状态 | P50/P95/P99 ms | 发送滞后P99 ms | 从计划发送至完成P99 ms | 独立窗口请求/s | 在另一账号窗口内发出的样本 |
| --- | --- | --- | --- | --- | --- | --- |
| B复杂授权对照 | 100/200 | 15.55/18.54/19.11 | 1.21 | 19.75 | 10.08 | 不适用 |
| A持续错误密码时B复杂授权 | 100/200 | 12.90/16.70/18.35 | 1.19 | 18.63 | 10.09 | 99 |
| A持续错误密码 | 100/401 | 108.71/122.10/165.09 | 不适用 | 不适用 | 9.00 | 90 |

B的独立窗口约9.913s，A约11.114s；不能用两边共有的阶段墙钟时间计算后，就宣称它们获得相同吞吐或公平份额。B按计划每100ms发送一次，A每次完成后继续发送；窗口内发出不表示请求的全部处理时间都与对方重叠。对照略慢不能解读为攻击改善性能，这不是随机化或生产性能实验。12个阶段观测到的runner累计memory.peak最高1470734336字节（含客户端/编译/子进程）、IAM连接峰值4/活动2、outbox峰值134，未采到锁等待；没有总pool/lock等待或生产内存余量结论。默认调度测试另外验证独立推进、原配对屏障、并发上限、定时发送不提前、取消不泄漏请求及非法计划拒绝，不用这些本地HTTP测试代替上述真实进程证据。

同一测试Go blob的原`TestIndependentIAMAuditAndPaaSProcesses`在另一空白PG18.4数据库通过56.37s（package57.415s），保留原业务、隔离、当前身份/撤权、故障及审计场景。Windows/amd64的干净源码导出、Go1.26.3/GOMAXPROCS2通过全仓`go test -race -p 2 -count=1 ./...`（含architecture）、`go vet -p 2 ./...`及模块校验；默认外部SKIP不作为真库证据。本片只修改原测试owner与本验收文档，不修改生产权限/接口/SQL、安装/profile、UI、CI预算或发布兼容边界。

固定`7f02d419`的独立Verification35338576115最终五项检查全部success。实际日志确认Audit数据/HTTP为7.206s/2.328s，五项IAM一般事务package分别135.828s、79.270s、71.217s、110.576s、23.928s，完整Role/STS为272.855s，PaaS数据库2.904s，未漏跑后续门禁。本人Session三项198.778s、带数据/独立进程130.012s、发布安装器效果前拒绝0.015s、实际Linux节点观测25.64s均通过；这些不等于本轮签名发布或其他分支验收。主Go门禁1.26.8，受限容量仍为原固定1.26.5及2CPU/1536MiB/PIDs256，未放宽预算。

CI容量通过155.24s（package156.272s），23条账号观测恰好覆盖12阶段、原2000加新增300次请求，失败0。B对照/干扰的P50/P95/P99分别11.45/76.01/121.29ms与17.85/38.02/54.21ms，发送滞后P99为72.41/2.81ms，从计划到完成P99为172.40/54.85ms；这些滞后和尾部样本均保留。A错误密码P50/P95/P99为98.15/110.77/137.44ms，B有100次、A有98次在对方窗口内开始；正常账号不再被测试客户端强制等待另一账号。不同运行及对照之间的差异不能解释为生产改善或公平预算。累计memory.peak原值1610813440字节、IAM连接/活动峰值4/2、outbox峰值122，未采到锁等待；不裁剪内存原值，不推算池/锁总等待、稳定内存余量或HA。这一片只验收声明的独立调度测量增量；AC-11当前首版结论还需结合后续开放环与受控故障证据，不能由本片单独推导。

#### 密码历史上限的成本与干扰缺口

009新增的密码历史0–24是当前真实规则，原容量工作集只覆盖密码登录，不能证明完整历史下的改密成本。最小补充目标沿本文件已有真实进程/独立发送/采样owner完成，不另建压测框架、不扩张开发历史升级矩阵。先通过真实HTTP改密建立24条不同历史，再由真实MFA及操作限定证明将Account历史规则设为24；不能直接插入hash、修改规则行或借受保护root的固定历史底线代替普通USER。

测量使用两个独立Account：A在同一IAM实例顺序执行有不同requestId和新口令的实际成功改密，B在同一实例独立发送正常密码登录；对照先只运行B。每类保留至少100个请求以及全部超时、拒绝和错误样本，不以被失败预算快速拒绝的请求冒充24次历史比较。成功改密后须核对真实generation、24条历史上限、当前会话保留与旧会话处置、单一成功事实；B的每个新凭据仍须在另一IAM实例证明实际身份。密码/hash/凭据不进入观测结果，原outbox及链核对保留。

沿用每请求5秒、fixture6分钟、总并发2、runner2CPU/1536MiB/PIDs256及独立PG限额。若完整历史请求超时，应记录该资源/负载下不满足要求，不能缩短历史、降低Argon2id成本、跳过样本或放大超时取得通过。工作树已在同一进程fixture新增`TestIAMPasswordHistoryCapacityProcesses`及专属数据库入口，复用原发送/观测器；它不是新的历史版本门禁。单次无干扰的完整历史改密只作成本对照，不用一个样本推导分位数；正常登录对照和双账号混合组仍各保留准确样本。当前尚未验收，不据此宣称账号公平预算已经实现。

首次本地运行使用固定`0fa1ff828086b316f6b6034994e74d39d11c4bc0`生产源码、测试Go blob`699c88c6f3d27c32a36370132782358fe8366869`及与原容量相同的限额，109.72s失败。B单独100次登录全部200；混合场景首个A改密在5000.97ms超时，真库仍为原generation25/24条历史且零成功改密事实。后续预排的依赖口令序列出现401/429，B为80次200、20次429；它们全部保留，但首个结果未知后这些依赖请求不是100次成功完整历史比较，也不能单独证明正常负载的账号公平性失败。测试没有重试、改时钟、降低历史/哈希成本或延长5秒。原run失败不回填；后续增加单次成本对照定位干扰，不能用一次暖缓存通过消除本次缺口。

同一固定生产源码、测试Go blob`2da78ec2f04c68479bbb587e4284a59e4d0c3c52`在另一空白库增加单次无干扰对照后，完整历史改密为3078.42ms/200，B单独100次登录全部200（P50/P95/P99为117.98/124.28/131.01ms）。混合工作集在原6分钟fixture期限失败（360.03s）；终止后只读检查证明98条测量改密成功事实、generation124及24条历史，不等于100个HTTP结果已收到。该次未输出混合组的部分观测，不能从数据库成功数推造HTTP分位数或遗漏请求的结果。相同专属编译缓存被复用，不能把差异归因于生产优化。现有发送/观测owner补充超时的`INCOMPLETE`输出：分开计划数、实际观察数、未观察结果及仅已观察响应的延迟，未观察不解释为未执行；原失败仍失败，不放宽时间、资源或密码安全要求。

最终测试Go blob`8ef4b3cd71a40b079846247bf07a3cc61e4bc170`还要求原改密响应经验证后才发下一次依赖写入：拒绝、坏响应、断线未知或取消停止该账号，不重做原意图；另一账号独立继续。原调度测试用真实本地HTTP覆盖五种结果，默认authorityprocess/architecture race及vet通过。相同固定生产源码、限额、原请求/fixture期限在另一个空白PG18.4数据库串行race-p1通过356.62s（包357.672s）；单次完整历史对照3045.57ms，B独立对照100次200。混合组的A完整历史改密100次200，P50/P95/P99为3034.80/3439.51/3493.88ms；B登录100次200，为129.01/141.52/156.68ms，99个B请求在A窗口内开始。全部200个B凭据跨副本校验，A最终generation126/24条真实历史、当前会话保留/旧会话撤销及100条唯一成功事实成立；最终381条IAM outbox与381条Audit记录逐一相符且全部DELIVERED，所有进程结束后其他数据库客户端0。

这次仍复用专属编译缓存，runner累计memory.peak为616026112字节；它包含客户端/编译/全部服务，不代表单IAM常驻内存或生产余量。此前仅观测输出修改的blob`035bfb19`也在新库通过343.81s，但不替代最终调度源码。两次通过不回填冷缓存请求超时或另一轮fixture超时；356.62s接近原预算，不能据此承诺冷启动、持续到达、公平配额或容量SLO。新增工作流分片的YAML及19段Bash解析、数据库集合/原预算/无重复选择核对通过；容量增量尚未独立CI验收，不包含在已推送0fa修复中。

#### 当前密码规则源码的容量复验

2026-09-28，固定`4c6cf48e4ac195abb71d1490dfd6e414f7c01912`的原容量门禁在全新PG18.4通过159.93s，12阶段/23条观测/2300请求均无非预期失败。结束后只读核对却发现1条`iam.authorization.decided`仍为RETRY：最后的链查询本身产生了新授权事实，原投递检查发生在该查询之前。原结果可证明测量中的业务响应及当时已核对的事实，不能证明退出时全部已提交事实已投递；不能把这条收尾缺口解释为产品丢失审计。

原测试owner将全量事实逐一比对移至链查询之后，并再次等待IAM outbox完成；不新增重试、放宽超时或改生产API。相同固定生产源码加测试Go blob`9a34111770152ca9354996584457e9853d58b90f`在另一个空白数据库串行race-p1通过118.15s（包119.191s）。仍为12阶段/2300请求、失败0，400个新凭据逐个跨副本认证、1400份测量决定保留原请求归属；最终2413条IAM outbox与2413条Audit IAM记录逐一相符，进程退出后另行只读核对IAM/PaaS/managedservice未投递均0、其他数据库客户端0。

两次均使用原固定Go1.26.5、GOMAXPROCS2/GOMEMLIMIT512MiB；runner2CPU/1536MiB/PIDs256，PG1CPU/768MiB/PIDs192、512MiB临时数据，禁止额外swap和宿主端口。第二次复用本轮专属编译缓存，不能把118.15s或较低内存解释为生产性能优化。其runner累计memory.peak为1026338816字节，连接/活动峰值4/2、outbox采样峰值131；未采到锁等待不代表无等待。B复杂授权对照/干扰的P99分别24.03/18.52ms，99个B样本在A错误密码窗口内开始；此结果不是容量SLO或公平预算。当前工作集仍未包含上述24条历史的改密成本。

同一测试修改的默认authorityprocess及architecture race、authorityprocess vet与diff检查通过；无外部DSN的SKIP不算真实数据库验收。修复与该本地证据尚待固定提交的独立CI，不继承旧容量切片或其他分支的发布状态。

#### 较早固定源的真实测量证据

2026-09-18，以固定`3080922f6ae1871f1c351d5ee30f03551fc3c605`生产源码及当前测试文件Git blob`6c5490447d9cd8717685243a96c00e722688c532`构成干净导出，`TestIAMCapacityProcesses`通过98.00s（race测试客户端，生产进程为原构建方式）。运行环境是共享Docker Desktop Linux x86_64/WSL2，宿主引擎可见18逻辑CPU、16,562,409,472字节内存，不是专用硬件。独立runner实际cgroup为2CPU/1536MiB、禁止额外swap、PIDs256、Go1.26.5/GOMAXPROCS2；PostgreSQL18.6独立为1CPU/1GiB/PIDs128、512MiB临时数据卷，无宿主发布端口。资源限额未放宽，测量期间未并跑本任务其他Go门禁。

10个阶段各200次、每账号100次，共2000次计时请求，全部状态、响应和归属校验通过，无超时或自动重试。400个新登录凭据全部唯一并在测量外经另一IAM副本验证实际USER；1200个PDP结果逐条与不可变账号/actor/request决定一致。预期Deny和错误密码401是正确处理的请求，不伪装成服务故障或从延迟样本排除。6个原应用仍可读，IAM/PaaS outbox最终投递，IAM已提交事实与Audit一一同内容，两账号链完整。

下面A/B是两个不同Account，不是两个服务实例。延迟列分别是该账号100样本的P50/P95/P99毫秒；不把两个分位数求均值作为合并分位数。最后一列是**每账号**已验证请求数除以整个阶段墙钟时间，两账号相等源于客户端固定配对；同类阶段的合计吞吐才是该值两倍，不是服务端公平调度证据。

| 场景/并发 | A：P50/P95/P99 ms | B：P50/P95/P99 ms | 每账号已验证请求/s |
| --- | --- | --- | --- |
| 密码登录/1 | 123.29/130.45/135.67 | 121.75/130.66/138.23 | 4.19 |
| 直接策略/1 | 7.88/17.74/21.22 | 7.84/11.10/21.85 | 52.23 |
| 组继承+条件+Deny+边界/1 | 20.08/31.01/42.15 | 19.66/27.66/34.14 | 22.54 |
| 密码登录/2 | 165.00/185.73/297.01 | 165.48/185.80/295.97 | 5.77 |
| 直接策略/2 | 10.30/40.68/43.79 | 10.74/42.39/46.61 | 58.97 |
| 组继承+条件+Deny+边界/2 | 22.04/55.52/58.39 | 21.68/54.84/56.73 | 32.10 |
| PaaS实际读取/2 | 11.82/45.12/48.95 | 11.82/46.62/49.12 | 57.72 |
| A建组、B复杂授权/2 | 81.46/93.68/107.28 | 16.37/20.99/41.60 | 12.73 |
| A错误密码、B复杂授权/2 | 131.98/153.90/204.42 | 17.21/20.58/20.90 | 7.40 |
| A撤权后Deny、B仍Allow/2 | 6.70/40.63/47.16 | 8.66/44.53/46.10 | 73.36 |

测量输出同时保留各阶段原始CPU增量、当前/峰值内存及100ms数据库采样。runner累计峰值965,767,168字节，包含编译、客户端及全部子进程，不是单IAM常驻内存。并发2登录阶段发生112次CPU限流、累计391,954微秒；其他阶段未观测该计数增加。数据库采样峰值4个IAM连接、2个活动连接、IAM待投递119条；未采到Lock等待不等于没有锁等待，pool/lock等待总时长均明确未知。尚无持续到达负载、饱和点、攻击配额或自动故障转移证据，不能据此发布TPS/HA承诺。

未计为通过的前置测试问题已在原owner修正：最初错误要求Deny公开账号/主体、把仅适合bootstrap的“恰好1条”断言用于完整负载，以及一次使用错误IAM outbox列名的已主动停止运行。它们不证明服务容量失败，也不能记为成功；前一完整测量97.16s通过后，本次又补了全部新bearer的跨副本实证并重新运行。独立CI使用精确提交归档和同一受限runner入口，不复用本机数据库或把本地结果冒充CI。

相同测试源码的原`TestIndependentIAMAuditAndPaaSProcesses`在另一空白PG18数据库通过57.57s，证明新增测量模式没有替换原业务/隔离/撤权/故障场景。全仓回归必须用支持本地主机探测的正常环境和干净源码：精简Go容器缺机器标识，导致3个原主机探测测试失败；原工作区中被Git忽略的旧源码副本被架构遍历检查命中，也不能记为源归档门禁通过。不伪造机器标识、不删改用例或扩大架构排除规则来取得通过。

最终同一测试源码的Windows/amd64干净导出在Go1.26.3、GOMAXPROCS2下通过`go test -race -p 2 -count=1 ./...`（含architecture）、`go vet -p 2 ./...`和`go mod verify`；工作流YAML及新增Bash步骤解析通过，原20分钟lane预算/max-parallel1未改。默认无DSN的测试不冒充数据库验收，真实进程/PG范围仅为上列已运行门禁。本片没有生产API、SQL、schema/profile、UI或安装变更；固定源及独立CI状态见本文件顶部，不能继承此前S1的CI结果。

固定`f6cfe47d`的独立CI中，Go、node及原保留数据/独立进程步骤通过，但存储作业被原20分钟上限取消；各组输出`ok`不能覆盖最终取消。容量步骤在连接空白数据库时因自动容器长名称无法解析而失败，负载尚未开始，不是容量测量通过或服务性能失败的证据。修正只在原两个串行lane之间移动本人Session与静默到期两项测试及其各自数据库，仍精确运行一次；数据库连接采用并校验[Actions服务标签对应的网络别名](https://docs.github.com/en/actions/tutorials/use-containerized-services/create-postgresql-service-containers)，不使用生成的容器名称或共享宿主端口。原测试、哈希成本、TTL、请求/fixture/作业预算和并发/资源限额不变。YAML/Bash及前后语义核对证明原6条测试命令、23项DSN和24个唯一数据库未删减，IAM整合测试的三个互补筛选各覆盖原用例一次。

该寻址修正在本任务独立PG18.4重现了同样的122字符容器名失败，随后使用同网络的真实`postgres`别名通过完整容量门禁84.09s（package85.140s），2000样本全部符合预期；没有改动测试Go blob或生产源码。runner仍为2CPU/1536MiB/PIDs256，PG使用与CI相同固定镜像且为1CPU/768MiB/PIDs192、禁止额外swap和宿主端口；不把这一复验与上表不同PG配置的测量混算。原工作流的标签/单网络/别名准入也在该真实容器上通过，错误owner标签在任何fixture变更前拒绝。随后串行运行移组后的原本人Session及静默锁内到期测试，分别通过75.18s、61.85s（package138.082s），使用各自空白数据库和原race/期限/用例。本地通过不覆盖已失败的独立CI或完整容量/HA缺口。

固定`b6f57d01`的独立CI已逐项核实Go、node-process、authority-storage、authority-runtime及最终authority-process均成功。存储步骤16分33秒，原Audit数据/HTTP、IAM一般事务（package544.543s）、Role/STS（368.699s）和PaaS数据库均实际执行；移组后的本人会话/到期package140.471s、保留数据及原独立进程package147.921s均通过。容量测试通过143.34s（package144.403s），日志恰有10阶段×2账号×100样本，2000次全部符合预期、无剔除或客户端重试；400新凭据、1200历史决定及最终outbox/链检查仍由同一已核对的测试源码执行。

CI实际记录Go1.26.5、GOMAXPROCS2、CPU quota/period=200000/100000、memory.max=1610612736、PIDs256。累计memory.peak原值为1610915840字节，采样current峰值1610461184字节，均不裁剪、混成单IAM常驻内存或解释成尚有生产余量；计数覆盖编译、客户端及全部子进程。IAM连接采样峰值4、活动2、待投递116；未获得池/锁总等待、持续到达的饱和点、过载公平性或数据库主备切换证据。该独立通过只接受声明的有界工作集与回归，不构成生产容量/SLO或整个AC-11完成。

## 固定消费者的集成检查

上一已实跑的签名发布基线以固定源码`bcd4e3d308e51957275cf7b2b31dab73726f838a`冻结为IAM81/Audit37/PaaS3+`contractRevision=29`；A=`matrix-v0.1.0-iam.r29.19-bcd4e3d308e5`，B=`matrix-v0.1.0-iam.r29.20-bcd4e3d308e5`。二者由仓库唯一`matrix-release`路径在真实Docker27.5.1构建并由组装器逐包验签；运行卷只含公开trust、签名包、测试二进制和受保护邮件输入，不含签名私钥，Linux卷权限恢复为owner-only。任务独立、无外部路由、2 CPU/4 GiB/PIDs 768的Docker27.5.1经典存储引擎以539.93秒通过A安装、受限数据库身份、APISIX下的USER/AccessKey、双Account主/子身份撤权、真实Postfix联系人、TOTP/MFA与安全通知、访问分析、Group/Role/RoleSession、两代应用、租户及安装Audit链、保护备份、失败升级自动回退、B升级、显式回滚、指定备份恢复、应用回滚/停止、容量释放和support零秘密。当前IAM82/Audit37/PaaS3+r30尚未取得同Profile签名A/B结果，本段不对其发布准入作结论。

普通失败升级、成功升级和显式数据保留回滚逐次保持原AccessKey签名可用；指定受保护备份恢复则保留其非秘密元数据并永久围栏恢复前secret，真实APISIX签名请求返回401，不能把`ENABLED`投影误解为可认证。外层引擎只重启这一精确任务；在全部内层平台容器healthy后，71.08秒门禁再次证明旧key未复活，并由管理员禁用、删除保留元数据和撤销临时custodian附件。相同重启阶段还复验Group/Role、MFA、双Account、status/verify及完整离线生命周期。该候选只证明相同完整Profile的升级、数据保留回滚和指定备份恢复；其他完整Profile仍必须在任何副作用前拒绝，IAM80→81 SQL数据保留不能冒充跨Profile发布兼容。以下既有消费者必须继续在该固定组合中保持真实数据检查；中间源码、同schema数字或静态编译不能替代：

固定源码的[Verification 37540304178](https://github.com/xiak/matrix/actions/runs/37540304178)不能记为成功：`authority-runtime`的两组业务步骤分别在12分07秒和6分40秒完成，但连同准备和清理于20分钟编排上限被GitHub标记`cancelled`；其余串行lane仍继续执行。修正不增加任何fixture的业务context、Go测试期限、密码成本或数据库并发，只把该job外层预算从20分钟调为25分钟，为已成功测试后的确定清理保留边界。只读测试审计没有发现可安全删除的整项测试；它发现从通用storage排除的专用selector在零匹配或顶层SKIP时仍可能以Go退出码0假绿，因此这些lane改由单一CI helper核对每个预期顶层测试确有`run`和`pass`且没有`skip`，容量容器同样使用该门禁。helper的正常、零匹配和显式SKIP三条本地行为已验证。最终`b377d34a`的[Verification 37620326080](https://github.com/xiak/matrix/actions/runs/37620326080)中，`authority-runtime`从12:55:15Z运行到13:15:54Z并成功，实际执行本人会话/锁后到期、保留数据及独立进程路径；其余专用lane及最终`authority-process`汇总也全部成功，因此只接受修正后的编排与选择器门禁，不回填原cancelled run。

- `lookup_service` 五列与 `ServiceIdentity` 安装/purpose 语义；`claim_audit_event` 七列及物理 owner 的租约/完成身份。
- `CanonicalizeEvent`、旧 tenant/installation bytes/hash/cursor/链与严格 event-bound producer proof。
- `BootstrapDigest`、封存 receipt/home organization/original primary；原 platform binding 到附件的确定性迁移及不可复权。
- `matrix-iam-local-recovery` 的 FILE/固定退出码、commandId/inputCommitment/精确历史重放、专用登录和无秘密输出；修改私有 ABI 必须一起迁移安装消费者。
- 固定主机消费者的 node-enrollment create/read/revoke/regenerate、target register/read/drain/activate/remove、pool 与 platform-operation 均保持 platform-only。enrollment 派生的 registered 事实只能沿对应历史 enrollment 证明，直接登记仍需精确 target register 决定；不放宽为任意 create 证明。
- 固定消费者中的 terminal-session create/close 仍是租户业务权限，不能因主机管理权限而开放；PaaSDeveloper 的已有授权、PaaSViewer/PlatformOperator 的拒绝和终端历史 actor/source 证明一并回归。

当前控制台组合的事实分属既有owner：`ffdedcde2f324e121f9a643b679a06530fd23a5d`的精确UX子树、前端与嵌入回归及原LIVE缺口，以及后继`0d9d0b12e9f95e9a2110697021d591916552da9a`的精确详情重新鉴权与真实产品资源浏览器证据，均由[010](FEAT-IAM-010-console.md#当前-ux-owner-快照集成)维护；`83/37/3+r31`签名A/B安装、升级、回滚、指定备份恢复与引擎重启证据由[FEAT-005](../docs/features/FEAT-005-offline-platform-lifecycle.md#current-ux-snapshot-release-consumer-gate)维护。本文件据前者接受IAM-AC-08、据后者接受IAM-AC-07的当前组合候选，但不把任一结论扩大为跨Profile兼容或总goal完成。

当前发布消费者固定于源码`5935fa5005529b2c4e1da943b98f49300430ba10`的IAM87/Audit39/PaaS7+r37同源签名A/B。任务专属断网引擎中的完整效果门禁和仅重启该引擎后的复验通过受限数据库身份、APISIX身份、真实SMTP/TOTP、四产品、服务Role、Audit、备份、升级/回滚/恢复、容量释放与凭据围栏；准确清单、信任根摘要、资源限制和未声明边界由FEAT-005对应当前消费者门禁拥有。据此IAM-AC-07只接受当前同Profile生命周期；滚动单前驱的数据升级由其独立门禁证明，不授予跨Profile签名升级、任意历史N-1、生产数据库HA或浏览器接受。User资料/状态与Group Membership恢复先前在固定`741dceb6`上另由四个全新数据库的真实浏览器门禁证明：两类User命令只读取一次原完成结果且零目标写重放，两类Membership命令只显式等值重放一次；下一请求权限/Session效果、唯一outbox/Audit和完整租户链均准确。该本地真实进程证据不是签名APISIX运行，准确范围和剩余非Deferred页面缺口由[010](FEAT-IAM-010-console.md#user-与-group-恢复真实浏览器验收)拥有。

此前IAM86+r36的签名Release D又完成真实错误矩阵：授权代际变化后的旧Session返回401，普通User/受限Role的未授权资源读取返回403；已存在实例的新意图由PaaS和APISIX共同返回409，页面保留输入且不创建资源；只停止任务内IAM权威、保持PaaS API/APISIX运行时，同一安装请求返回503，页面冻结原幂等键、禁止再次提交并只允许读取结果。权威恢复后原结果查无记录仍保持UNKNOWN，干净来源的实例目录保持原两项。任务内IAM与PaaS API均恢复原容器ID及healthy，外层引擎、共享服务和远端机器未重启。准确页面与访问日志证据归010；本段只接受此前签名401/403/409/503缺口，不把它继承给IAM87+r37，也不把网关502、查无回执或当前实例列表解释成命令从未到达的一般证明。

签名Release B静态控制台与当前Release D API组合还补充跨文档失败关闭门禁：旧文档在IAM权威不可用时只发出一次实例安装POST并取得503，冻结原公开幂等键；同一浏览器来源切到D静态控制台后自动恢复该非秘密意图，只发出一次结果GET，NOT_FOUND继续保持UNKNOWN，升级后没有托管服务或权限写。独立来源的权威目录仍只有原两个READY实例。准确签名来源、时间、路径、限制及“不证明已提交成功回执跨文档恢复”的边界归010；本文件据此关闭旧文档序列化和零重放缺口，不把静态文档切换说成旧B后端到D后端的发布升级。

同一Release D还完成IAM-UI-01–06与组织治理Deferred入口的签名只读巡检：Root/Account、User、直接附件、Group、Policy默认版本和原始声明、Role、AccessKey入口、本人Session/通知/TOTP、平台Account目录与准确目标能力均由LIVE接口返回；无显式AccessKey/security-settings权限时真实403且页面不提升本地权限。系统归属Account保护与普通Account可用能力分开，组织治理页面没有后端或提交入口。该窗口除一次公开登录外没有管理写，准确路径和仍未完成的写入边界归010；因此本文件只接受当前只读投影与最小权限失败关闭，不将其扩大为IAM-UI-01–06完整验收。

UX/UI owner固定`859a82a4d88ca76a9a2b6e7f49fafb283554ff21`的离线TOTP二维码组件已按16个准确源码/依赖/消息/许可证路径选择性采用，重新生成的前端与324项嵌入资产树均与固定对象一致。组件只接受服务端准确`otpauth://totp`材料，拒绝歧义、冲突、HOTP和超限输入，失败时只保留手工密钥，不调用远端服务或持久化一次性种子。聚焦67项、类型/lint/架构/234组样式、归一化、生产构建和Go UI测试/vet通过；全量Vitest为1516/1517，唯一既有5秒超时虽在独立重跑中通过，仍不回填全量为成功。准确路径、依赖审计和限制归010；本文件据此接受本地二维码呈现的实现证据，但外部物理认证器、签名APISIX二维码页面、受保护Root/平台身份丢失全部因子后的目的限定恢复与强制重新绑定，以及IAM-UI-06整体仍未验收。

该二维码固定源的首个本分支提交`89505567643ed1c8e71d80277d5a3527d7987605`未取得独立CI验收：Verification 38707342304只证明Linux嵌入资产等价检查失败且未进入Vitest，不能据此把唯一根因归结为某一个环境变量差异。后续修复统一了生产预览变量未设置与显式`0`的构建输入；010已记录从UX/UI owner固定`8a14592223dbfa943ce9d653db34778f381d1790`选择性采用的六路径修复、两次真实production export和本分支324项逐字节等价证据。该修复现已包含在固定`08e1dc4a`且其`console`与总汇通过，因此离线二维码构建切片具有当前独立CI证据，但这仍不替代签名APISIX二维码呈现、外部物理认证器验收，也不将后续修复倒推为旧失败的唯一已证明根因。

Release D的配额恢复还证明命令回执与资源读取相互独立：既有成功配额意图只读匹配唯一服务端结果后，测试专属relay对随后的权威配额目录GET精确返回一次503；页面保留成功回执，却移除额度投影并显示控制面不可用，没有重发命令、沿用陈旧额度或补MOCK。显式重试只新增一次额度GET并恢复同一权威列表，命令结果仍只读一次、成功回执不变。数据库配额事实不变，窗口唯一API写为登录。准确计数和适用限制归010；本文件据此关闭IAM-UI-07的签名额度读取失败隔离及GET-only重试缺口，不外推跨主体或跨签名文档成功回执恢复。

同一签名页面还从账号菜单执行一次普通退出：IAM logout返回200，页面回到登录入口，准确Session从ACTIVE版本1转成REVOKED版本2且其他会话保持原状态。准确时间与适用限制归010；本文件接受当前会话的正常退出，不把它扩大为自然到期、刷新丢失或权威故障恢复。

签名位之后的测试owner修正固定到`91af2972fb16d6727845fc06c9485f8ea62ca80c`，不改变生产镜像或profile；其[Verification 38511351736](https://github.com/xiak/matrix/actions/runs/38511351736)已核实18项、333个步骤终态为165 success、168个非适用矩阵步骤按设计skip，零失败/取消/未完成；自然窗口的TOTP恢复耗尽门禁实际运行1241.46秒并通过，`console`为69个文件、1391项测试全过。由此接受该测试后继的IAM-AC-09，但默认CI明确跳过opt-in跨浏览器与签名生命周期fixture，不能替代各自本地运行证据。前一`355815f`运行中console、go、runtime、roles、managed-products等16项业务作业成功，但`authority-recovery-window`被外部取消、依赖汇总失败，整轮终态为cancelled，不能用局部成功覆盖。

固定源码`c38a0093235bf3521c4ef32492d814d36f071a7e`的[Verification 38612137181](https://github.com/xiak/matrix/actions/runs/38612137181)在attempt 1完成：18项job全部success，333个step为165 success、168个非适用矩阵step按设计skip，零失败、取消或未完成。`console`实际匹配319个嵌入文件并通过70个测试文件、1439项测试；Role真库、独立authority进程、四产品provider、受限容量和真实恢复码窗口均实际运行成功。默认CI仍明确跳过浏览器与签名生命周期opt-in入口，故IAM-AC-09只据此接受该固定源码；页面和签名运行仍分别使用010与FEAT-005的真实证据。

当前固定源码`08e1dc4a6ce81386ea7223e62d03356f82aeee58`的[Verification 38840517569](https://github.com/xiak/matrix/actions/runs/38840517569)在attempt 1完成，`go`、`console`、`node-process`、`installation-postgres-ha`及十五项authority数据库/进程lane（含最终汇总）共十九项均为`completed/success`。这接受当前源码的IAM-AC-09以及各lane实际拥有的行为；默认工作流仍跳过显式浏览器和签名生命周期入口，后二者继续分别使用010与FEAT-005的效果证据。

后继候选`68dd868fd49486613d6a194eba9c60428fa41d65`的[Verification 38667273078](https://github.com/xiak/matrix/actions/runs/38667273078) attempt 1最终为`completed/failure`：16项执行作业成功，`authority-managed-products`中PaaS worker于初始execution-profile刷新阶段以封闭码`PAAS_WORKER_EXECUTION_PROFILE_REFRESH`退出，最终`authority-process`汇总按依赖正确失败；该候选相对`c38a0093`在PaaS worker、local-machine adapter和`authorityprocess`测试源码上没有差异，不能把失败归因于UI，也不能以其他作业成功覆盖。GitHub官方failed-jobs入口随后只重跑该业务作业及依赖汇总，原16项成功作业未重跑；attempt 2仍在同一测试、同一初始化阶段和同一封闭码失败，因此不再盲目重跑。相同固定源码在新的任务专属PostgreSQL 18、1.5 CPU/1536 MiB/PIDs 256和四个相同不可变产品镜像上执行原CI选择器，`TestManagedProductProviderProcesses`以148.34秒、package以151.755秒通过，并完成四产品真实协议、终止清理、撤权、隔离及Audit。该新库结果只说明本地未复现，不回填任一次CI为成功或把环境波动当作根因。后继固定候选在不改变刷新行为、公开契约或Profile的前提下保留规范化adapter cause，并把Observe timeout/unavailable/rejected及Validate、Load、Build、Save、Transaction压缩成不含宿主、路径、DSN或凭据的封闭进程码；unexpected仍落回原通用码，聚焦PaaS、架构和vet已通过。精确新SHA仍须取得自己的CI；若再次失败，必须先按封闭子阶段修复或登记明确缺口。复验容器、网络和临时日志已按任务标签删除。

原快照源码的[Verification 38107642768](https://github.com/xiak/matrix/actions/runs/38107642768)保留两次attempt的准确边界：attempt 1中`authority-runtime`的“本人会话与锁后到期”通过，后继“保留数据与真实authority进程”以exit 1失败，最终汇总正确失败；其余15项成功。公开annotation没有测试日志，本任务独立PG18上的同选择器复跑以411.519秒全部通过，不能替代原失败。整轮终态后经GitHub官方failed-jobs入口只重跑`authority-runtime`及依赖汇总；attempt 2两段均真实执行成功，最终精确SHA、17项作业和汇总均`completed/success`。这接受原快照IAM-AC-09的精确源码CI证据，不回填attempt 1；IAM-AC-08由后继`0d9d0b12`的独立真实资源浏览器门禁接受，而不是由该旧CI推断。

安装 owner 的源快照和候选固定 SHA 归 adoption；其既有 host 证据不复制成本分支新版本验收。

固定`2b8dc42f9294614f9e2e0bb57b4f3ca84594704d`把managedservice配额超售检查从内存仓库的全局互斥假并发替换为两个真实PostgreSQL Serializable事务：同一份购买量1的QuotaEntitlement只有一个创建赢家，另一条事务在取得数据库锁后观察到最新修订并以`ErrQuotaExhausted`关闭；最终只有一个Installation、一次配额修订及一条创建Audit/outbox。当前journey与直接前驱门禁在受限独立PostgreSQL 18中以race选择器3.915秒通过，任务容器、网络和卷均已清理。该证据关闭单个配额的并发超售测试缺口，但没有测量持续到达、公平调度、产品多副本或数据库故障转移，不能据此把IAM-AC-11标为完成；对应独立CI仍须由该固定后继自身取得。

## 开放环过载与账号公平性后继

现有容量门禁的配对批次和两条独立 lane 都是有界闭环：客户端等待本 lane 的上一个请求完成后才继续，最多两个请求同时在途。它们能够证明当前工作集的正确性、跨副本一致性和有限干扰，但不能产生持续到达积压，也不能测出饱和点、过载恢复或账号公平保护。后继不得只提高原闭环样本数、缩短哈希成本或把客户端调度延迟解释成服务端排队。

第一片只扩展既有 `TestIAMCapacityProcesses` 及其 `authority-capacity` owner，使用相同双 IAM 进程、受限 PostgreSQL 和当前生产密码成本。新增调度必须按单调时钟在固定间隔发出请求，不等待前一请求完成；同时设置固定样本数、最长阶段时间和在途上限，所有已发出请求都保留结果，未观察到终态的请求明确记为 `UNKNOWN`，不得重试、丢弃尾部或扩大超时取得通过。客户端连接池必须高于 IAM 的本地密码工作槽，避免把客户端 `MaxConnsPerHost=2` 冒充服务端准入。

负载至少分成三个准确阶段：单账号错误密码开放环用来找到当前受限环境的首次过载和恢复；该压力下另一账号的普通业务 PDP/资源读取必须继续正确并保持撤权下一请求生效；两个账号同时提交错误密码，用各自 `401/429` 的实际密码计算准入判断是否缺少账号公平保护，避免并发签发同一USER的有效Session把主体自身尝试抑制混入账号间比较。密码入口只允许真实 `401` 或封闭 `429 iam.authentication.busy`，不得出现 `200` 错主体、`5xx`、泄漏剩余额度或无界等待；业务授权不占密码工作槽，不能被错误密码洪泛拖入同一队列。压力停止后，两个真实 IAM 副本都必须在固定恢复窗口内接受新的正常登录，并保持共享尝试预算、Session、Audit/outbox及账号归属不变。

观测同时记录计划到达率、实际开始滞后、在途峰值、各状态计数、从计划时间到完成的分位数、runner CPU/内存、数据库连接/活动/锁等待和 outbox 积压。一次固定资源运行只建立该工作集的饱和与恢复证据，不发布通用 QPS、可用性百分比或硬件外推。若另一账号有效登录在单账号压力下只能得到同样的过载拒绝，则将其作为产品缺口保留并在后继实现账号级准入；不能把重跑中的偶然成功定为公平性保证。

生产改动须由上述实测触发，而不是预先增加 Redis、通用队列或租户可配置限额。首选边界仍是 PostgreSQL 中的共享身份/尝试预算负责安全语义，各 IAM 副本的有界无队列工作槽负责本地 CPU/内存保护；若需要账号公平调度，必须先冻结跨副本语义、未知账号/dummy hash 的防枚举路径、总预算和每账号保留份额，并证明不能通过大量账号名绕过总上限。它不得影响业务 PDP、服务身份、健康探针或把 `429` 当作认证失败消费猜测额度。

数据库主备切换不属于这一测试片。只有安装 owner 提供真实独立故障域、复制/选主、连接重建和一致 profile 部署后，才在同一 AC-11 下实跑主库失联、在途安全事务结果未知、故障转移、撤权后读以及恢复旧主不复权；两个 IAM 进程共享一个 PostgreSQL 主库仍不能称为数据库 HA。

本地候选证据（2026-10-03）：既有调度器增加第三种明确的 `open-loop-bounded-inflight` 模式，按每 lane 单调计划时间启动、最多16个在途请求，禁止无间隔和依赖前项确认的工作；本地HTTP race门禁证明8个计划请求不等待前一响应、实际峰值严格为4、全部结果准确归位，并拒绝零间隔、确认依赖和17并发。它没有改变IAM生产入口、密码成本或本地两槽实现。

第一次受限真运行在全新PG18数据库执行到完整开放环矩阵后以232.376秒失败：A错误密码压力下，B的100次有效密码登录得到2个泛化401、2个200和96个429。原因是同一个B USER的100次并发有效登录把该主体自身的共享尝试抑制混入账号间公平比较；该结果不能解释为A跨账号消费了B的安全预算，也不能当作公平性通过。门禁改为两个Account分别提交错误密码，以401表示实际取得密码计算槽、429表示本副本明确过载；有效密码仅在压力完成后验证恢复，没有放宽401/429契约或删除原失败。

修正后的同一完整测试在另一个全新PG18数据库、固定Go1.26.5 Linux runner中通过199.462秒。runner为2CPU/1536MiB/PIDs256、GOMAXPROCS2/GOMEMLIMIT512MiB，PG为1CPU/768MiB/PIDs192，独立网络、无宿主端口。单账号开放环每5毫秒计划100次、在途8，得到8次401和92次封闭429；双lane业务隔离中A为22次401/78次429，B复杂PDP为100/100正确，虽计划完成P99约2.89秒且CPU限流6.31秒，仍无5xx、错主体或业务队列串扰。双账号密码准入各100次且全局在途16，A为3次401/97次429、B为4次401/96次429；这一次近似对等样本只证明观测器和当前运行结果，**不证明**生产已有账号保留份额或公平SLO。压力后两个IAM副本分别完成新正常登录，凭据在另一副本读取到准确Account/USER；后继撤权、全部原测量决定、outbox及Audit链检查随原门禁通过。结束前数据库客户端为0，本轮唯一容器、网络及两个卷按标签核对后已删除，没有操作其他任务资源。该增量最终固定于`b377d34a`，其[Verification 37620326080](https://github.com/xiak/matrix/actions/runs/37620326080)的独立`authority-capacity`从13:24:08Z运行到13:34:41Z并成功，最终15项汇总全部成功；据此接受该受限工作集的有界开放环观察、业务隔离与恢复证据，但不把单次近似对等样本升级为生产账号公平份额或SLO。

结合前述双IAM副本撤权一致性、数据库失联失败关闭、开放环过载的明确`429`、业务PDP隔离、压力后恢复，以及受控物理复制切换中的确认数据零丢失、旧主fence和撤权不复活，IAM-AC-11当前首版门禁已满足。它承诺的是本文件准确记录的受限硬件与工作集，不发布通用QPS、可用性百分比、账号保留份额或自动选主指标。生产账号公平性SLO、生产代理/自动选主、跨故障域及签名安装拓扑下的数据库HA均因缺少真实部署前提明确Deferred；启用前必须由安装owner提供真实拓扑并重新实跑，不能从测试夹具推断。

前一固定`598b07543b6318c4dbb0caa4bd7d4c83e381d503`的[Verification 37612663234](https://github.com/xiak/matrix/actions/runs/37612663234)不能记为成功：`authority-runtime`的明文扫描发现平台Audit测试夹具把64字符边缘断言同时用作合成`requestDigest`正文，正确报告`audit.document $.requestDigest (credential)`，后继串行lane被取消，最终汇总失败。这不是生产凭据泄漏，也不能通过放宽扫描器解决。`b377d34a`改为散列独立的固定请求材料，并增加“完整凭据被用作digest正文时仍必须命中”的负向回归；聚焦race、全仓race/vet、稳定生成、Linux构建和模块校验在本地通过，随后上述独立CI的实际`authority-runtime`及全汇总成功，旧失败不回填。

固定`93d5a97d6151aee4bc6f79c54e7b515ac90f833a`的[Verification 38740174740](https://github.com/xiak/matrix/actions/runs/38740174740)虽然GitHub API将19个job全部标为success，但不能作为整轮成功：`authority-storage`日志中的`TestIAMPolicyAttachmentSessionPostgres`实际FAIL，原shell在未启用`pipefail`时把`go test | tee`的末端`tee`状态当作命令成功，最终汇总只聚合了错误的job状态。后继`4db9a2455`删除这条手写pipeline，统一使用已有`run-go-test-selection.sh`的`set -euo pipefail`和逐顶层RUN/PASS/非SKIP核对；同时按006当前owner把缺少ceiling boundary的旧fixture替换为USER、GROUP和平台三项独立数据库矩阵，并核对保留Session的Serializable重试保存改密后USER修订。该修正已包含在固定`08e1dc4a`且其真实`authority-storage`与总汇成功；旧`93d5a97d`的伪绿色仍保持失败记录，不被后继结果回填。

## 运行约束

固定`6298e7532`的显式opt-in浏览器门禁已在全新受限PostgreSQL 18和真实IAM/Audit/PaaS进程上完成普通User首次登录强制改密：浏览器用初始密码建立受限Session，从纯页面提交最终密码并进入IAM概览；数据库证明credential generation单调前进、另一条受限Session撤销、仅调用Session保留且同步到新generation，旧密码401、新密码可重新登录，唯一本人密码变更事实进入完整租户Audit链。fixture/race package分别为76.68/80.216秒，任务资源在零外部客户端后精确清理。该本地证据关闭IAM-UI-02的首次登录最终改密页面缺口，不替代日常主动改密选择、响应丢失、TOTP、签名release或当前候选独立CI。

UX/UI owner固定`8c19204f469a4d67c0a90d91753ca2c45f2ee322`记录的消费代码源`3afe96248`又在两个独立PostgreSQL 18.6空库上完成普通User日常改密的两种页面选择。`revokeOtherSessions=true`的测试/包82.26/84.624秒通过，两个旧有效Session各只撤销一次；`false`的测试/包67.03/68.973秒通过，两个旧有效Session各只迁移一次并继续返回原Account/User。两轮都证明调用Session保留、原退出Session不变、User/credential generation单调推进一次、旧密码401、新密码登录成功、唯一本人成功事实进入完整租户Audit链；任务容器在精确标签和空挂载核对后删除。该证据接受正常日常改密选择，不代替UNKNOWN恢复、签名release或当前候选独立CI。

后继固定`18c115fe5007e36b7369e74f1c5c065952c0df32`包含上述首次改密门禁、Group级联删除fixture、从UX固定`db4ce3f51febf30975ca616bbff221e30a11f031`选择性采用的Group回执/导航客户端及本分支重建的324项嵌入资产，不改变后端API、SQL或发布Profile。[Verification 38984154633](https://github.com/xiak/matrix/actions/runs/38984154633)已由测试owner核实19个job、370个step全部终态，19项均success；14个authority lane的57个顶层根实际RUN/PASS，容量3100个样本无失败。`console`在Node22.22.2/npm11.6.4通过75个文件、1703项Vitest、8项Node测试、234组对比度和两次324文件确定性导出；Group导航20项包含busy guard卸载、准确回执计数以及403/409/503、非法回执和迟到响应的失败关闭。本轮默认CI未设置8个browser flag，不能把组件成功解释为真实Group删除、首次改密或签名APISIX页面验收；7个真实邮件子测试因无专属Postfix明确SKIP，也不接受真实SMTP。

只使用本工作区、任务标签和唯一命名的数据库/容器/网络/卷/端口。Go 默认 GOMAXPROCS=2、-p 2；PG/引擎 CPU/内存/PID 限额。每条重型数据库门禁内部保持`-race -p 1`串行、独立runner/PG、原期限和清理边界；CI允许最多八条彼此隔离的GitHub-hosted runner lane并行，十四条门禁按最近固定运行的job墙钟耗时优先安排较长任务，容量门禁进入首批。不增加任一runner内的数据库并发，不缩短真实时间窗口或跳过门禁。失败lane一旦给出明确证据即可在其现有owner聚焦修复，不等待无关lane完成；最终候选仍以全部lane及汇总成功为准。不得重启任何远端机器或共享服务，不使用其他 Phase 的运行实例。未运行命令不进入 runbook。

排序以[Verification39593652955](https://github.com/xiak/matrix/actions/runs/39593652955)的job API耗时作有界调度估算：同样八个执行槽，matrix排队总长由25分28秒估算为22分04秒，减少3分24秒；这不包含前置Go/console或公共runner调度噪声，storage仍保留该run的取消结论，也不承诺新CI实际总耗时。修改前后完整YAML语义比较证明只改变十四项include的顺序，所有lane成员、期限、DSN、选择器、汇总及并发上限不变，24段Bash语法通过。独立CI必须在准确后继源码再次证明全部门禁成功，不能将这个排序推算作为运行验收。

准确后继e22的上述独立CI已通过十九项job；job API确认容量检查与其余七条较长lane均于13:11:25UTC首批启动，十四lane末项于13:33:18UTC结束，实测矩阵跨度21分53秒。workflow从13:03:34UTC创建至13:33:26UTC终态为29分52秒。该单次观测验证了调度落实和当前整轮成功，不证明相对不同runner运行的全部差值均由排序导致，也不是固定时长或生产SLO承诺。

固定`9a030943386d693276fcea53ac706e8cc4269f1f`的[Verification36588874836](https://github.com/xiak/matrix/actions/runs/36588874836)已明确失败：`authority-runtime`的保留数据及真实进程步骤返回exit 1，不能用同run中已通过的Go、node、storage和roles覆盖。当前源码在本任务独立PG18容器（2CPU/1536MiB/PIDs256、随机loopback端口）、Go GOMAXPROCS2/GOMEMLIMIT1024MiB下重现：真实IAM45前驱首次绑定因子时，测试夹具提交上一30秒窗口的OTP，恰好跨入下一窗口后服务按生产`±1`窗口正确返回401。修正仅在真实进程测试取码器中要求上一窗口至少保留10秒再返回，不扩大生产时钟偏差、防重放或尝试预算。修正后唯一前驱门禁单独通过127.094s；另三套全新数据库执行完整`go test -v -race -p 1 -count=1 ./test/authorityprocess`通过362.275s，其中前驱105.14s、双IAM/Audit/PaaS进程214.12s、真实备份/恢复程序39.50s。容量和浏览器因使用独立入口而明确SKIP，不计本次验收；精确修复SHA及独立CI仍待确认。

容量增量固定候选`082c172e91882389e7218a3b39afa57d40575f14`将原容量步骤从runtime移至独立`authority-capacity`，并在同一15分钟job内串行执行原工作集与完整历史工作集，各自空白数据库、独立Go进程和原6分钟fixture；不复制原工作集或延长它的期限。原runtime已接近20分钟总预算；未包含该分组的固定0fa/[Verification36441090890](https://github.com/xiak/matrix/actions/runs/36441090890)，其runtime最终在2026-09-28T15:46:45Z为cancelled，GitHub annotation明确超过20分钟作业上限。该job的本人会话/锁后到期包517.207s及保留数据/实际进程包304.564s已分别成功，最后独立容器容量阶段从15:42:41Z执行到15:46:41Z被总预算截断，不能记为容量通过，也不是已经证实的业务拒绝或死锁。候选十个数据库lane的实际选择由原`.github/workflows/verification.yml`拥有：storage/runtime/step-up/replacement各20分钟，roles/capacity/replacement-qualification/removal/removal-security各15分钟，recovery-window为30分钟。全部`max-parallel=1`，各有独立受限PG；新分片仍待精确固定源的独立CI，不以原job中通过的包覆盖cancelled。

耗尽门禁需要不可压缩的两个真实十分钟窗口，保持27分钟Go进程和25分钟上下文；不修改生产时钟、预算、密码成本或已有fixture期限。`authority-process`仍只是2分钟汇总，全部数据库lane成功才成功，失败、取消或跳过均不能放行。Go和node-process保持独立。

IAM的一般事务从实际编译测试目录枚举，除在runtime/自然窗口lane有准确入口的fixture及独立Role/STS外，每个顶层fixture以精确`-run`单独串行调用。枚举编译失败或没有任何一般事务测试均失败关闭；编译清单与三个选择入口联合核对，不能漏跑或把无DSN的SKIP当作该fixture验收。各自独立数据库及完整场景不变。除上述新增真实窗口门禁外，保持原Go单进程默认10分钟、IAM独立组矩阵120秒/策略聚合240秒，以及原锁等待、HTTP、进程预算和fixture规模；不增大并发、资源或重试，不弱化密码计算。真实会话到期可在同一矩阵执行其他独立案例期间自然流逝，但到期前正向控制、数据库时间、到期后拒绝、历史证据及后续账号停用顺序都必须验证，不改TTL或伪造时钟。锁内到期另用原owner下的静默数据库、生产最小TTL及120秒预算，要求原事务没有序列化重试掩盖时间检查；该数据库也串行运行，不借另一个矩阵的写入获得偶然正确的结果。

调整分组时，以当前实际编译清单和所有选择入口联合核对无漏跑、无重复；不保留已被替代的历史测试数量作为当前契约。各自然窗口的实际运行证据归009，不以工作流语法或选择集合检查宣称独立CI通过。

固定`159bb302fed89161c4b60afeb4a6f41f9bd99820`的[Verification35318292984](https://github.com/xiak/matrix/actions/runs/35318292984)在IAM一般事务包600.109s时触发Go默认10分钟总计时器。此时平台恢复fixture仅运行22秒，尚未达到自身3分钟期限；Role/STS与PaaS数据库后续命令没有执行，不能记为通过。失败说明五个独立fixture仍共用一个包计时器，不证明恢复并发死锁，也不能据此降低密码成本或放宽单项/20分钟作业期限。该run最终为failure：Go、node和runtime lane成功，其中本人会话三项package213.561s、保留数据/独立进程package137.821s、容量129.82s通过；汇总检查仍正确拒绝，不用其他作业成功覆盖storage失败。

修正固定`2cd045b01a27e85617f8272e5f55491fd311aaca`仅将这五项按实际编译测试目录拆成串行进程，生产代码、测试体、数据库和资源限额不变。本地编译枚举核对9个顶层测试恰好分为5项一般事务、1项Role/STS和3项本人会话，各运行一次；工作流12个Bash入口语法检查通过，未声称YAML解析。使用真实编译清单对原Bash循环作命令替身检查，证明选择准确，枚举失败、空清单及测试失败均传播为非零退出；该流程检查不是数据库验收。

该固定源的[Verification35320384077](https://github.com/xiak/matrix/actions/runs/35320384077)确认五项一般事务全部实际通过，package分别195.624s、115.918s、102.317s、160.149s和35.688s；原包计时器不再截断恢复fixture。整次CI仍为failure：后续Role管理子组触达自身120秒期限，PaaS数据库未运行，具体准备开销与修正归[006管理会话门禁](./FEAT-IAM-006-roles-and-sts.md#r3管理会话本地证据)，不能增加期限或把503计为正确业务结果。Go、node及runtime lane成功，本人会话package228.908s、保留数据/独立进程package150.818s、容量142.62s；容量日志为10阶段、20行、每行100样本且失败请求0。原失败与新候选验收分开，不用通过的作业覆盖失败作业。

累计修正固定`7cf857bba48eb5d7da487162c43e8f52534db133`的[Verification35324569376](https://github.com/xiak/matrix/actions/runs/35324569376)已核实精确SHA，go、node-process、authority-storage、authority-runtime及最终authority-process五项全部completed/success。实际日志中五项IAM一般事务分别192.299s、105.885s、93.644s、145.385s和32.371s，完整Role/STS包333.093s，Audit数据/HTTP6.240s/2.320s，PaaS数据库2.418s，均实际执行；本人Session三项226.359s及保留数据/独立进程148.830s也通过。容量140.29s（package141.349s），10阶段×2账号×100样本全部符合预期、failures为0；原400次凭据发行、1200份历史决定与outbox/链检查由同一测试owner保持。主Go门禁为1.26.8，容量仍使用固定Go1.26.5镜像和2CPU/1536MiB/PIDs256限额，不混成新的资源基线或完整HA证据。

这些分组只管理验收流程，不构成容量或HA结论。固定版本的成功和失败证据归各功能FEAT；后续通过不回填旧失败，增加作业预算也不证明场景正确或性能达标。

## 完成条件

001–010 所有本轮需求通过本分支相应证据，AC-01–11 的本轮门禁满足且数据库 HA 等前置缺口如实列明，签名交付边界明确，才将总 goal Complete。局部测试绿、固定源可读、目录有 FEAT 或纯设计提交均不等于实现验收。旧 FEAT-006 的已接受状态不会替代此组合验收。

当前尚无覆盖本轮全部需求的组合发布证据；各里程碑在相应 FEAT 更新，不新建重复报告或实现日记。
