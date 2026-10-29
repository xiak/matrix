# 安装与维护 Matrix

这份指南供负责平台的运维人员使用。普通成员从[首次登录](../user-guide/getting-started.md)开始。
下面沿用已执行过的安装与维护命令；适用版本和验收范围由
[平台交付功能记录](../features/FEAT-005-offline-platform-lifecycle.md)维护。
主线代码不等于已经通过完整交付验证的安装包。

开始前先核对[当前主线的本地安装结果](../features/FEAT-005-offline-platform-lifecycle.md#当前主线本机-docker-安装复核)。
安装、首次使用与维护均须以对应交付版本的实际结果为准。
不能把历史版本的验证结果当作新包的完整生命周期保证。

## 安装前准备

先向交付负责人领取配套材料，确认版本、主机和访问地址后再开始：

| 需要准备 | 本文示例位置或要求 |
| --- | --- |
| 安装主机 | 独立的 Linux/amd64 主机或虚拟机，已安装 Docker Engine 与 Compose 插件 |
| 安装工具 | 已验证来源的 `mx`，放在 `/usr/local/sbin/mx` |
| 完整离线发布包 | `/srv/matrix-release`，与安装工具配套 |
| 发布信任文件 | `/etc/matrix/release-trust.json`，由可信交付渠道提供 |
| 安全邮件配置 | `/etc/matrix/security-mail.json`，由交付人员准备并保护，供安全通知与验证码使用 |
| 安装目录 | `/var/lib/matrix`，首次安装必须为空，由 root 独占访问 |
| 网络与支持渠道 | 事先确认受限访问方式、控制台完整地址和负责故障处理的人员 |

示例路径可以按交付约定替换，后续维护始终使用同一安装目录。
发布包、信任文件和邮件配置放在安装目录之外。
诊断文件则必须输出到本安装的 `support/` 子目录，见[导出支持信息](#导出支持信息)。
仓库中的源码、演示页面或某个单独镜像不能代替完整发布包。

领取材料时请交付人员同时给出发布标识、校验方式、邮件服务的连通性确认和支持联系人。
邮件配置需要真实可用的服务器、认证信息及 TLS 信任材料；不能拿空文件或示例密码代替。
没有配套发布包时，先由发布人员完成构建与交付，不要求普通用户从源码拼装安装材料。
通过 Windows 中转文件时，须保留目录结构，并按已验证的发布清单恢复可执行权限。

**不需要另起 DinD 容器才能安装。** 当前部署使用主机上的 Docker Engine，
通过本机 `/var/run/docker.sock` 管理工作负载。远程 Docker、Rootless Docker、
Kubernetes 和多节点控制平面不属于本页的安装流程。

**访问入口须提前隔离。** 当前安装只接受 HTTP 和显式端口 `8080`；
示例地址为 `http://127.0.0.1:8080`。安装参数里的地址用于请求校验，
不是监听绑定；服务仍监听 `0.0.0.0:8080`。
安装器不会替你配置防火墙，不能因此假定只有本机能够访问。
请由部署人员事先提供网络隔离与访问方式；当前流程不能直接当作公网 HTTPS 部署。
安装前还会检查节点接入端口 `8443` 是否空闲；仅确认 `8080` 空闲还不够。

主机资源是否足够，以交付包声明的要求与安装前检查为准。
本文不提供未经验证的最低配置，也不提供可直接套用的邮件账号或发布信任文件。

### Windows 与 Docker Desktop

下面的安装命令在 Linux 中执行，不能直接粘贴到 Windows PowerShell。
Windows 上能运行 Docker，并不意味着 Linux 安装工具及其文件路径已经准备好。

本次本机验证使用普通 Linux 工具容器，连接 Docker Desktop 的同一个 Docker Engine，
没有启动嵌套 Docker daemon。安装文件放在 Linux 文件系统，并保证工具容器与 Docker 主机
看到相同的绝对路径。安装器还会访问本机回环地址，因此这条验证路线需要启用
Docker Desktop 的主机网络功能并重启 Docker Desktop。

这条路线的安装、页面首用和维护结果，范围限定于上述功能记录中的配套版本与配置。
准备正式环境时，请按本页使用交付负责人确认过的 Linux 主机或虚拟机。
不把工具容器已启动当作平台已安装；仍须取得安装与验证命令的成功结果。

交付人员须同时交付工具容器名称、容器内安装目录、配套 `mx` 路径和受保护材料的位置。
在 PowerShell 中可用 `docker exec <工具容器名称> <mx绝对路径>` 替代下文的
`/usr/local/sbin/mx`，后续参数与路径均按容器中的实际位置填写。
不要把 Windows 盘符路径直接传给 Linux 安装工具，也不要重建另一套 Docker 引擎。

## 安装平台

### 1. 进入安装身份并检查主机

运维人员先用自己的 Linux 账号登录，再执行一次 `sudo -i`。
下文 `admin$`、`root#` 是提示符，不要复制；出现 `root#` 后的命令都由 root 执行。
无需给 root 新设密码，也无需开放 root 远程登录。

```console
admin$ sudo -i
root# umask 077
root# install -d -o root -g root -m 0700 /var/lib/matrix
root# test -S /var/run/docker.sock
root# docker version
root# docker compose version
```

Docker 客户端与服务端均能正常响应，Compose 能显示版本后，继续安装。
检查失败时先由主机管理员处理；安装器不会安装或修改 Docker。
安装目录已有内容时，先确认是否存在原安装，不能清空后重试。

### 2. 执行安装

核对下面的文件路径与现场一致，并确认示例入口符合已准备好的访问方案：

```console
root# /usr/local/sbin/mx --format json platform install \
  --bundle /srv/matrix-release \
  --root /var/lib/matrix \
  --trust-key /etc/matrix/release-trust.json \
  --security-mail-configuration /etc/matrix/security-mail.json \
  --northbound-origin http://127.0.0.1:8080
```

等待命令结束。安装会核验发布包、准备平台并验证服务；命令须退出成功、
返回 `status: SUCCEEDED` 且 `result.state: READY`，才可继续。
保存结果中的发布标识与关联编号，不记录秘密文件内容。

安装失败或终端中断时，按[安装或维护中断](#安装或维护中断)处理。
不要手动启动另一套 Compose、删除卷或修改安装目录来让检查通过。

### 3. 验证并交接

```console
root# /usr/local/sbin/mx --format json platform verify --root /var/lib/matrix
root# /usr/local/sbin/mx --format json platform status --root /var/lib/matrix
```

确认验证成功、平台状态就绪，再用交付的访问方式打开控制台。
首次安装生成的管理登录名为 `admin`，初始密码保存在受保护文件
`/var/lib/matrix/secrets/operator/initial-admin-password` 中。
由安装负责人按组织的秘密交付方式读取并交给指定管理员，避免复制进普通日志或工单。
该文件不代表用户改密后的当前密码。

交付给使用者前，应完成以下核对：

1. 从实际使用网络可以打开真实控制台，页面没有 MOCK 标识。
2. 指定管理员能够登录、完成首次改密并重新登录。
3. 在 IAM 概览中确认当前账号与身份，能读取其应有的资源。
4. 发放完整地址、登录名、初始密码交付方式和支持渠道。

首次改密成功应直接进入控制台，再正常退出并用新密码验证登录。
平台验证成功不能代替这一步交付检查，见[首次使用说明](../user-guide/getting-started.md#3-完成首次改密)。

## 日常检查

继续用安装时的 root 身份和同一 `--root` 目录执行命令。
`--root` 表示安装目录，不是切换 Linux 用户。
当前完整签名生命周期采用 root；非 root 和 Rootless 的完整交付流程尚未验收。

```console
root# /usr/local/sbin/mx --format json platform status --root /var/lib/matrix
```

`status` 用于只读查看平台状态。需要确认安装完整性和服务协作是否正常时，再运行：

```console
root# /usr/local/sbin/mx --format json platform verify --root /var/lib/matrix
```

`verify` 会执行实际健康与应用探测，并非只读取状态。
验证失败时保留错误码与关联编号，再导出支持信息；不能仅凭容器正在运行就认定平台正常。

安装后的目录与托管文件始终保持原所有者和受保护权限。
不要通过改变 owner 切换操作身份，也不要在该目录存放个人文件。

### 主机重启后

1. 等待主机与 Docker 恢复，再用原目录运行 `status`。
2. 平台恢复后执行 `verify`，并从实际用户网络验证登录与资源读取。
3. 核对原有实例及未完成任务的状态，再通知用户继续操作。
4. 平台未恢复时，记录错误并导出支持信息；保留原安装，不重新执行全新安装或删除数据卷。

## 升级回滚与恢复

### 先创建平台备份

在升级或有影响的平台维护前，安排维护窗口并通知使用者保存未完成的工作。

```console
root# /usr/local/sbin/mx --format json platform backup --root /var/lib/matrix
```

等待成功，记录返回的 `backupId`、发布版本和备份时间，按组织要求保管受保护的备份资料。
没有成功结果与备份编号，不能按“已备份”继续。

**平台备份不包含托管数据库里的业务数据。** 它保护平台状态，并核对托管资源清单；
PostgreSQL、MySQL、Elasticsearch、RabbitMQ 等实例的数据必须另有备份与恢复方案。
也不能仅凭一个备份编号承诺从主机磁盘丢失或异机迁移中恢复整个平台。

### 升级到配套的新版本

交付负责人应确认新包明确支持从当前版本升级，并提供配套的工具与邮件配置。
不能跳版本或混用不同交付组合。

```console
root# /usr/local/sbin/mx --format json platform upgrade \
  --bundle /srv/matrix-release-next \
  --root /var/lib/matrix \
  --security-mail-configuration /etc/matrix/security-mail.json
```

升级流程还会自行创建并验证备份。完成后运行前述 `verify` 与 `status`，
确认版本和状态，再验证登录及关键业务读取，最后通知使用者恢复操作。
浏览器需要重新登录时，先核对先前提交的操作结果，再继续工作。

### 选择回滚还是恢复备份

| 情况 | 处理方式 |
| --- | --- |
| 升级命令失败 | 先检查状态；安装器会尝试回到前一版本，运维人员仍须确认结果 |
| 已升级成功，需要退回受支持的上一版本 | 使用版本回滚，保留升级后写入的数据；只支持符合契约的直接前驱 |
| 需要把平台数据恢复到某份已验证备份 | 使用备份恢复，会覆盖平台数据并影响登录；先确认业务影响与备份兼容性 |
| 原操作中断或结果不明 | 先核对并恢复原操作，不立刻发起另一个升级、回滚或恢复 |

回滚命令：

```console
root# /usr/local/sbin/mx --format json platform rollback --root /var/lib/matrix
```

备份恢复命令中，必须把占位符替换为本安装中已经验证的真实备份编号：

```console
root# /usr/local/sbin/mx --format json platform recover \
  --root /var/lib/matrix \
  --backup backup-REPLACE_WITH_VERIFIED_ID
```

恢复前先确认没有其他平台变更正在进行，并通知用户停止提交写操作。
恢复过程会关闭认证入口，完成安全核对后才重新开放。
若提示托管资源清单与备份不一致，停止并联系交付负责人；不能靠手动删容器或卷来对齐清单。
备份后的账号、成员、凭据或授权变更，也可能使该备份不再满足恢复条件；
修改成员显示名称会推进用户版本，同样在核对范围内。
出现 `OWNERSHIP_CONFLICT` 时，先检查这些变化，不删除校验记录，也不修改数据库绕过。
旧版备份不一定能供当前版本恢复，不能把回滚理解为任意降级。

回滚或恢复完成后，再运行 `verify`、`status`，确认资源、权限和关键读取结果。
通知用户重新登录；旧会话、已撤销密钥不会因为恢复旧数据就被当作重新有效。
托管服务业务数据的恢复仍由对应服务的数据方案负责。

首次交接时应在示例账号上演练一次恢复：先备份，再激活一项未使用的服务配额，
恢复后确认配额回到备份时刻，并用当前有效凭据重新登录。
同时单独连接已有托管数据库，确认实例仍可使用；不能把平台资料回退当作业务数据已回退。
不要在这次演练期间修改 IAM 资料、权限或凭据，也不要新增或终止托管实例。

### 安装或维护中断

1. 记录原命令、发布包版本、安装目录、错误码和关联编号；不附带秘密文件内容。
2. 执行 `status`，确认原操作是否仍在进行、已经结束或需要人工处理。
3. 对仍可恢复的原操作，由运维人员核对后使用**相同命令与相同输入**继续。
4. 出现冲突、证据不匹配或要求人工介入时，停止变更并联系交付负责人；
   只有满足[支持导出条件](#导出支持信息)时才导出诊断文件。

按实际结果决定下一步：

| 提示或状态 | 如何处理 |
| --- | --- |
| `START_VERIFICATION_FAILED` | 平台服务未通过启动检查。保留原命令与错误，不发放登录信息；先由交付人员定位失败服务 |
| `ROLLBACK_OUTCOME_UNKNOWN`／`ROLLING_BACK` | 回滚还没有确认完成。核对阻塞原因后，用相同安装命令与相同输入继续原回滚，不清空目录重装 |
| 首次安装失败后，`status` 返回 `PLATFORM_NOT_INSTALLED` | 当前没有成功提交的安装。即使目录仍有文件，也不能开始备份、升级或首次登录；保留原目录供定位 |
| `INSTALLATION_COMMAND_CONFLICT` | 有其他操作或原操作的输入不一致。先核对原操作，不更换输入反复提交 |

继续原命令可能只是完成失败后的回滚，仍会返回原来的失败码。
这不等于重装成功；根因未处理前，不要反复发起新的安装尝试。

不要删除安装锁、日志或状态文件来强制解锁；也不要给同一个操作换一份发布包。
当前没有供用户直接使用的通用卸载或异机恢复流程。

## 导出支持信息

本命令要求平台已经成功安装，且没有另一项生命周期操作正在进行。
首次安装尚未成功或刚回滚到未安装状态时，当前工具不能生成这份支持报告；
请提供原命令、发布标识、发生时间、错误码和可取得的关联编号，由交付人员定位。

```console
root# /usr/local/sbin/mx --format json platform support \
  --root /var/lib/matrix \
  --output /var/lib/matrix/support/matrix-support.json
```

输出必须位于 `--root` 对应目录下的 `support/` 中，并使用普通 `.json` 文件名。
输出到 `/var/tmp` 等其他目录会返回 `SUPPORT_OUTPUT_INVALID`。
只有命令成功且文件已生成，才有可交付的诊断报告；不能把失败结果当作导出完成。

将生成的诊断文件与发生时间、错误码、关联编号交给部署团队指定的支持人员。
该导出按产品契约排除秘密、配置值、数据库行和任意原始日志。
另外附加的截图或日志仍需自行检查，不发送安全邮件配置、初始密码文件或整份备份。

## 命令验证依据

本页命令的签名生命周期、主机重启及版本兼容证据统一由
[FEAT-005](../features/FEAT-005-offline-platform-lifecycle.md)拥有。
本机安装、首次使用、实例读写、诊断以及备份恢复分别记录实际结果，
未通过的步骤不能因其他步骤成功而标记为可用。
