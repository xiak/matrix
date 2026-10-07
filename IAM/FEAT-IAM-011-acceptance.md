# FEAT-IAM-011：交付与需求验收

- 状态：实施中；AC-11的服务副本、受限容量测量及有界开放环过载/恢复观察已通过各自门禁。容量增量固定`b377d34a282e581fb8cbdbc6461e7da31c10aaf5`的[独立CI37620326080](https://github.com/xiak/matrix/actions/runs/37620326080)已核对精确SHA，15项全部completed/success；后继控制台组合固定`448400628734d4c708d7859492fba1cf1b663284`的[独立CI37644376405](https://github.com/xiak/matrix/actions/runs/37644376405)在定向恢复两项GitHub runner获取故障后，attempt 2的16项全部completed/success。它们只接受下述固定资源工作集、业务隔离、恢复及独立控制台门禁证据，不宣称通用QPS、账号公平SLO或数据库HA。原独立账号干扰测量`7f02d419`及配对首片`b6f57d01`的既有证据保持；旧失败不回填。完整容量/公平性/HA、当前Profile签名发布、LIVE UI及整体需求仍未验收。
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

开发期升级门禁采用滚动的单前驱窗口：当前版本加一个明确固定的必要前驱，不按每项FEAT累积各自的旧binary/schema路径。窗口前移时在同一切片删除被替代的入口、夹具、环境变量和条件分支，不以常规SKIP、别名或可选旧版本列表保留测试仓库。最近已经实际通过的窗口仍是固定`9044bd6610b8f2c0cfe0887daf45e8ccf9a4ff90`的IAM65真实程序到IAM66：双Account、身份、策略、撤销、会话、认证恢复及历史事实经双迁移、等值bootstrap和重启，149.47s通过（包152.950s）。旧认证恢复qualification因系统策略/授权投影推进而明确失败关闭，IAM66重新取得有界qualification后才能完成；旧snapshot、闭合资格或等值重放不能取得新能力。`policy_attachment_changes`不为IAM65命令猜测回填，原会话/凭据/撤销历史、旧canonical和proof保持；迁移只采用准确IAM65系统策略默认版本，后继显式默认版本不能被等值重放覆盖。

当前源码已把唯一窗口前移为固定`0f06607398f643311c5a284cf0867e931ed33d9b`的IAM66到IAM67，并把完整源码组合推进为IAM67/Audit35/PaaS3、`contractRevision=15`。固定前驱的受限源码归档及IAM/migrator在本任务当前Go环境中能够独立构建，但这不是数据保留证据；[Verification 37571650568](https://github.com/xiak/matrix/actions/runs/37571650568)已按精确`71c7882b4f8a1aa11ee1a2408b8ae111f375f25a`终态completed/failure：十三项job成功，`authority-runtime`失败并使最终`authority-process`汇总失败，没有取消或跳过，故不能登记通过。认证job日志把根失败收窄为两个测试owner错误：滚动门禁已经执行IAM66前驱，却仍按IAM65断言前驱没有`policy_attachment_changes`完成记录；独立进程门禁另有四处把只存在于不可变decision document的`correlationId`误当成关系列查询。当前修正从IAM66真实程序读取并类型化保存旧viewer创建/撤销及request-tag developer创建三条完成结果，迁移后逐条比较且要求无额外回填、旧事实及内置策略版本保持；批量决定查询统一使用`document->>'correlationId'`，不增加兼容列、不改生产SQL/API/schema/profile。修正后的默认全仓race（含authorityprocess编译和architecture）、vet、模块校验、API生成稳定和Linux/amd64构建已通过；本机当前没有可连接的Docker/PostgreSQL18运行时，故尚未取得这两个真库入口或新独立CI的成功证据。前一窗口的成功不回填当前失败，后续新CI也必须实际执行而不能以相同schema数字、SQL重放或静态编译代替；N+1仍不是每轮构造另一个假想schema，跨完整release profile准入继续另验。

只有明确要求保留某个现存安装的数据，或存在无法同次替换的真实消费者时，才增加例外并记录准确固定起点、现实消费者、不能原子迁移的原因和退出条件；不能用曾经做过一次实验代替这些证据。已发布Audit记录的编码/哈希和安装器的效果前拒绝，仍是当前必须保持的合同，不与未发布IAM中间版本测试混同。旧binary实验的历史运行证据保留在Git及其原交付记录，不作为后续默认完整矩阵。联调消费者在各自工作区使用固定提交原子对齐，不擅自清空对方环境。

清理以当前行为价值而非测试数量为准：重复场景、废弃对象/接口和偶然实现快照删除；跨账号越权、撤权/会话不复活、MFA事实不补造、失败原子性、历史完成及Audit/outbox保留为当前门禁。产品声明变更不能自动扩大既有策略、不可忽略不兼容Deny等独立规则，须从旧版本外壳中移回当前产品行为测试，不能随历史路径一起丢掉。源码兼容、产品声明推进、同版本重放和受支持备份恢复是不同边界，不构造其全组合笛卡尔积。每个owner在自己分支审查并实跑保留门禁，不能为了通过失败测试或继承其他分支状态而删减。

首版发布冻结实际完整 schema/profile、安装器和服务二进制；从该正式基线之后才维护已声明支持的升级、回滚和备份兼容窗口。首版产品版本不等于必须立即把当前各服务 schema 数字改成 1；发布前是否压缩/重编号要与安装及产品消费者一次性对齐。测试范围调整不授权删除用户数据，也不授予跨 profile 安装准入。

### 开发窗口收敛的固定证据

2026-09-24按用户要求在原authorityprocess owner收敛，先保存本地真库验证并推送的`09fac913`回滚点。固定`aefe4f786242d7d6816f253b6389d5c94c314a75`删除9个过时IAM升级入口及仅供它们使用的旧RoleBinding wire、schema分支和夹具；CI从7条IAM前驱路径收敛为1条，同时移除6个额外数据库及对应DSN配置。保留原受限身份、当前IAM/Audit/PaaS业务、Purpose/OTP/恢复、并发、秘密检查及所有原期限/成本，不删失败安全断言、不放宽版本/profile判断。精确源码的[Verification35972120363](https://github.com/xiak/matrix/actions/runs/35972120363)已由GitHub API核实completed/success，go、authority-process、authority-storage、authority-runtime、authority-step-up、authority-recovery-window和node-process七项全部通过；本测试窗口清理已验证，不代表后续S2c或整个IAM目标已验收。

唯一`TestIAMRetainedPredecessorProcessUpgrade`在限额的原生PG18.6、Go1.26.7/GOMAXPROCS2/GOMEMLIMIT512MiB、串行race-p1下通过37.13s（包40.525s）。实际前驱程序创建双Account/同名User、已撤附件、正常/撤销/NULL代际Session、本人完成、待验证邮件和原MFA/恢复历史；当前版本在真实末端DDL故障时完整回滚，再双次迁移、重放、重启及原恢复完成，旧凭据/完成不复活。测试依据非事务sequence确认注入故障确已到达，不读取或透传迁移器已刻意抹除的底层错误。

原旧策略升级外壳中的产品声明行为移到上述当前权威阶段：构建仅改变产品声明的后继程序，实际证明新动作注册不扩大已编译策略、仅发布新版本不切默认、显式切换后才允许、旧声明/决定/producer proof保持、不兼容Deny不能因资源不匹配被忽略，以及重启/撤权有效。这不是另一个假想schema升级或生产新增PaaS接口。后继程序由明确的 acceptance-only build tag 在产品声明汇合点产生；普通及发布构建只使用恒等变换，不再读取固定源码路径、解析变量名或改写 Go AST，因此当前目录的文件布局和修订变量命名不是门禁契约。YAML及14段Bash语法校验通过，常规前驱仅一个环境入口，原四lane的串行/失败收集设置保持；独立CI按上述精确固定SHA核实，不继承其他分支结果。

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

009设置竞争和放宽的双向验码检查沿原integration入口/专属数据库，在现有`authority-step-up`内串行调用。十项设置竞争包含仅密码规则的两个次序，原三分钟期限保留；设置放宽也保持原三分钟。两个入口各启动独立Go进程，避免与七分钟proof fixture共用原10分钟包计时器；不扩张任何单项或包期限，lane仍20分钟、原PG限额及`max-parallel=1`不变。实际OTP跨窗口拒绝及四组运行结果归009，不增加历史schema组合。YAML及19段shell语法检查、调整前后四个顶层fixture精确各选择一次、原DSN/执行条件/串行策略/作业预算一致性已验证；新分组仍待独立CI。工作流中单独注册与一般事务排除必须配对，不能重复运行或靠缺DSN的SKIP冒充通过。

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

AC-11 的服务副本证据：2026-09-11 现有 `TestIndependentIAMAuditAndPaaSProcesses` 在本任务独立 PG18 下通过，两个真实 IAM 进程分别使用最多 2 连接的受限登录。原实例会话可在另一实例使用，跨副本 grant/revoke 与 session revoke 生效；原实例停止后另一实例仍正确允许租户读取并拒绝已撤平台权限；仅副本登录 NOLOGIN+断开该登录连接期间返回 503，恢复后继续工作。原 5721 保留升级与该组合门禁合计 56.307s。没有负载均衡自动切换、数据库主备切换、容量/公平性 SLO 或完整 HA 验收结论，AC-11 尚未满足。

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

CI容量通过155.24s（package156.272s），23条账号观测恰好覆盖12阶段、原2000加新增300次请求，失败0。B对照/干扰的P50/P95/P99分别11.45/76.01/121.29ms与17.85/38.02/54.21ms，发送滞后P99为72.41/2.81ms，从计划到完成P99为172.40/54.85ms；这些滞后和尾部样本均保留。A错误密码P50/P95/P99为98.15/110.77/137.44ms，B有100次、A有98次在对方窗口内开始；正常账号不再被测试客户端强制等待另一账号。不同运行及对照之间的差异不能解释为生产改善或公平预算。累计memory.peak原值1610813440字节、IAM连接/活动峰值4/2、outbox峰值122，未采到锁等待；不裁剪内存原值，不推算池/锁总等待、稳定内存余量或HA。只有声明的独立调度测量增量获得验收，完整AC-11仍未满足。

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

最近一次已实跑的签名发布基线以固定源码`8abbea36da422fdb758233b68221ad8139b00904`冻结为IAM66/Audit35/PaaS3+`contractRevision=13`，IAM授权Profile revision14；A/B分别为`matrix-v0.1.0-iam-r13.1-8abbea36da42`和`matrix-v0.1.0-iam-r13.2-8abbea36da42`。任务独立、无外部路由、2CPU/4GiB/PIDs768的Docker27.5.1经典存储引擎从零镜像/容器/卷完成609.38秒效果型门禁：A安装、受限数据库身份、APISIX下的双Account/IAM、真实SMTP联系人、TOTP/MFA、安全通知、访问分析显式处置、两代应用、Audit链、保护备份、失败候选自动回退、B升级、显式平台回滚、选定备份恢复、应用回滚/停止/容量释放和support零秘密均通过。删除运行现场的私密SMTP输入后，只重启同一任务外层引擎，68.40秒只读门禁再次通过新鲜MFA登录、双Account主身份/恢复/撤权保留及status/verify/完整生命周期。发布构建同时以真实Docker27证明registry manifest digest、digest-qualified构建引用及portable config image ID彼此分离，mutable tag、错仓库或错digest不能进入签名包。该源码后继的CI编排及安全门禁已经由下述`b377d34a`独立CI全绿证明，但旧签名二进制和完整Profile没有因此变成当前发布候选。该历史基线只允许相同完整profile的升级、数据保留回滚和选定备份恢复；其他完整profile必须在副作用前拒绝，IAM65→66 SQL数据保留不能冒充跨profile发布兼容。当前IAM67/Audit35/PaaS3+`contractRevision=15`尚未构建并实跑签名A/B，不能继承本段安装结论。以下既有消费者必须在新的匹配候选中通过真实数据检查；中间源码、同schema数字或静态编译不能替代：

固定源码的[Verification 37540304178](https://github.com/xiak/matrix/actions/runs/37540304178)不能记为成功：`authority-runtime`的两组业务步骤分别在12分07秒和6分40秒完成，但连同准备和清理于20分钟编排上限被GitHub标记`cancelled`；其余串行lane仍继续执行。修正不增加任何fixture的业务context、Go测试期限、密码成本或数据库并发，只把该job外层预算从20分钟调为25分钟，为已成功测试后的确定清理保留边界。只读测试审计没有发现可安全删除的整项测试；它发现从通用storage排除的专用selector在零匹配或顶层SKIP时仍可能以Go退出码0假绿，因此这些lane改由单一CI helper核对每个预期顶层测试确有`run`和`pass`且没有`skip`，容量容器同样使用该门禁。helper的正常、零匹配和显式SKIP三条本地行为已验证。最终`b377d34a`的[Verification 37620326080](https://github.com/xiak/matrix/actions/runs/37620326080)中，`authority-runtime`从12:55:15Z运行到13:15:54Z并成功，实际执行本人会话/锁后到期、保留数据及独立进程路径；其余专用lane及最终`authority-process`汇总也全部成功，因此只接受修正后的编排与选择器门禁，不回填原cancelled run。

- `lookup_service` 五列与 `ServiceIdentity` 安装/purpose 语义；`claim_audit_event` 七列及物理 owner 的租约/完成身份。
- `CanonicalizeEvent`、旧 tenant/installation bytes/hash/cursor/链与严格 event-bound producer proof。
- `BootstrapDigest`、封存 receipt/home organization/original primary；原 platform binding 到附件的确定性迁移及不可复权。
- `matrix-iam-local-recovery` 的 FILE/固定退出码、commandId/inputCommitment/精确历史重放、专用登录和无秘密输出；修改私有 ABI 必须一起迁移安装消费者。
- 固定主机消费者的 node-enrollment create/read/revoke/regenerate、target register/read/drain/activate/remove、pool 与 platform-operation 均保持 platform-only。enrollment 派生的 registered 事实只能沿对应历史 enrollment 证明，直接登记仍需精确 target register 决定；不放宽为任意 create 证明。
- 固定消费者中的 terminal-session create/close 仍是租户业务权限，不能因主机管理权限而开放；PaaSDeveloper 的已有授权、PaaSViewer/PlatformOperator 的拒绝和终端历史 actor/source 证明一并回归。

安装 owner 的源快照和候选固定 SHA 归 adoption；其既有 host 证据不复制成本分支新版本验收。

## 开放环过载与账号公平性后继

现有容量门禁的配对批次和两条独立 lane 都是有界闭环：客户端等待本 lane 的上一个请求完成后才继续，最多两个请求同时在途。它们能够证明当前工作集的正确性、跨副本一致性和有限干扰，但不能产生持续到达积压，也不能测出饱和点、过载恢复或账号公平保护。后继不得只提高原闭环样本数、缩短哈希成本或把客户端调度延迟解释成服务端排队。

第一片只扩展既有 `TestIAMCapacityProcesses` 及其 `authority-capacity` owner，使用相同双 IAM 进程、受限 PostgreSQL 和当前生产密码成本。新增调度必须按单调时钟在固定间隔发出请求，不等待前一请求完成；同时设置固定样本数、最长阶段时间和在途上限，所有已发出请求都保留结果，未观察到终态的请求明确记为 `UNKNOWN`，不得重试、丢弃尾部或扩大超时取得通过。客户端连接池必须高于 IAM 的本地密码工作槽，避免把客户端 `MaxConnsPerHost=2` 冒充服务端准入。

负载至少分成三个准确阶段：单账号错误密码开放环用来找到当前受限环境的首次过载和恢复；该压力下另一账号的普通业务 PDP/资源读取必须继续正确并保持撤权下一请求生效；两个账号同时提交错误密码，用各自 `401/429` 的实际密码计算准入判断是否缺少账号公平保护，避免并发签发同一USER的有效Session把主体自身尝试抑制混入账号间比较。密码入口只允许真实 `401` 或封闭 `429 iam.authentication.busy`，不得出现 `200` 错主体、`5xx`、泄漏剩余额度或无界等待；业务授权不占密码工作槽，不能被错误密码洪泛拖入同一队列。压力停止后，两个真实 IAM 副本都必须在固定恢复窗口内接受新的正常登录，并保持共享尝试预算、Session、Audit/outbox及账号归属不变。

观测同时记录计划到达率、实际开始滞后、在途峰值、各状态计数、从计划时间到完成的分位数、runner CPU/内存、数据库连接/活动/锁等待和 outbox 积压。一次固定资源运行只建立该工作集的饱和与恢复证据，不发布通用 QPS、可用性百分比或硬件外推。若另一账号有效登录在单账号压力下只能得到同样的过载拒绝，则将其作为产品缺口保留并在后继实现账号级准入；不能把重跑中的偶然成功定为公平性保证。

生产改动须由上述实测触发，而不是预先增加 Redis、通用队列或租户可配置限额。首选边界仍是 PostgreSQL 中的共享身份/尝试预算负责安全语义，各 IAM 副本的有界无队列工作槽负责本地 CPU/内存保护；若需要账号公平调度，必须先冻结跨副本语义、未知账号/dummy hash 的防枚举路径、总预算和每账号保留份额，并证明不能通过大量账号名绕过总上限。它不得影响业务 PDP、服务身份、健康探针或把 `429` 当作认证失败消费猜测额度。

数据库主备切换不属于这一测试片。只有安装 owner 提供真实独立故障域、复制/选主、连接重建和一致 profile 部署后，才在同一 AC-11 下实跑主库失联、在途安全事务结果未知、故障转移、撤权后读以及恢复旧主不复权；两个 IAM 进程共享一个 PostgreSQL 主库仍不能称为数据库 HA。

本地候选证据（2026-10-03）：既有调度器增加第三种明确的 `open-loop-bounded-inflight` 模式，按每 lane 单调计划时间启动、最多16个在途请求，禁止无间隔和依赖前项确认的工作；本地HTTP race门禁证明8个计划请求不等待前一响应、实际峰值严格为4、全部结果准确归位，并拒绝零间隔、确认依赖和17并发。它没有改变IAM生产入口、密码成本或本地两槽实现。

第一次受限真运行在全新PG18数据库执行到完整开放环矩阵后以232.376秒失败：A错误密码压力下，B的100次有效密码登录得到2个泛化401、2个200和96个429。原因是同一个B USER的100次并发有效登录把该主体自身的共享尝试抑制混入账号间公平比较；该结果不能解释为A跨账号消费了B的安全预算，也不能当作公平性通过。门禁改为两个Account分别提交错误密码，以401表示实际取得密码计算槽、429表示本副本明确过载；有效密码仅在压力完成后验证恢复，没有放宽401/429契约或删除原失败。

修正后的同一完整测试在另一个全新PG18数据库、固定Go1.26.5 Linux runner中通过199.462秒。runner为2CPU/1536MiB/PIDs256、GOMAXPROCS2/GOMEMLIMIT512MiB，PG为1CPU/768MiB/PIDs192，独立网络、无宿主端口。单账号开放环每5毫秒计划100次、在途8，得到8次401和92次封闭429；双lane业务隔离中A为22次401/78次429，B复杂PDP为100/100正确，虽计划完成P99约2.89秒且CPU限流6.31秒，仍无5xx、错主体或业务队列串扰。双账号密码准入各100次且全局在途16，A为3次401/97次429、B为4次401/96次429；这一次近似对等样本只证明观测器和当前运行结果，**不证明**生产已有账号保留份额或公平SLO。压力后两个IAM副本分别完成新正常登录，凭据在另一副本读取到准确Account/USER；后继撤权、全部原测量决定、outbox及Audit链检查随原门禁通过。结束前数据库客户端为0，本轮唯一容器、网络及两个卷按标签核对后已删除，没有操作其他任务资源。该增量最终固定于`b377d34a`，其[Verification 37620326080](https://github.com/xiak/matrix/actions/runs/37620326080)的独立`authority-capacity`从13:24:08Z运行到13:34:41Z并成功，最终15项汇总全部成功；据此接受该受限工作集的有界开放环观察、业务隔离与恢复证据，但不能把整个AC-11、公平份额或HA标为验收。

前一固定`598b07543b6318c4dbb0caa4bd7d4c83e381d503`的[Verification 37612663234](https://github.com/xiak/matrix/actions/runs/37612663234)不能记为成功：`authority-runtime`的明文扫描发现平台Audit测试夹具把64字符边缘断言同时用作合成`requestDigest`正文，正确报告`audit.document $.requestDigest (credential)`，后继串行lane被取消，最终汇总失败。这不是生产凭据泄漏，也不能通过放宽扫描器解决。`b377d34a`改为散列独立的固定请求材料，并增加“完整凭据被用作digest正文时仍必须命中”的负向回归；聚焦race、全仓race/vet、稳定生成、Linux构建和模块校验在本地通过，随后上述独立CI的实际`authority-runtime`及全汇总成功，旧失败不回填。

## 运行约束

只使用本工作区、任务标签和唯一命名的数据库/容器/网络/卷/端口。Go 默认 GOMAXPROCS=2、-p 2；PG/引擎 CPU/内存/PID 限额；重型门禁串行。不得重启任何远端机器或共享服务，不使用其他 Phase 的运行实例。未运行命令不进入 runbook。

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
