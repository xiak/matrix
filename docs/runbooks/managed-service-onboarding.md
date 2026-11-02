# 受管产品接入验证：Logstash 与 Kibana

本运行手册负责可执行检查与排错命令。接入顺序见[产品接入手册](../product-guide/managed-service-onboarding.md)，
合同、验收要求和实际结果由 [FEAT-007](../features/FEAT-007-control-plane-console.md#产品团队接入契约)维护。

真实门禁需要 Linux/amd64 进程、同一主机上的 Docker Engine、Docker Compose 与 Go 1.26。
使用宿主机 Docker，不启动 DinD。执行前按安装运行手册完成
[托管服务主机参数检查](platform-installation.md#检查托管服务的主机参数)。
测试目录必须能被测试进程和 Docker Engine 以**同一绝对路径**访问，并具有 Linux 文件权限语义。
Windows 用户使用下文的 Docker Desktop 工具容器流程。

## 契约检查

从仓库根目录执行：

```sh
go test -count=1 ./api/adapter/managedservice/v1 ./test/managedserviceonboarding ./app/service/paas/internal/managedservice/usecase/reconcileinstallation ./test/architecture
```

这一步不启动产品。`TestElasticRuntime` 的跳过提示是预期结果，不能把它当作真实验收。
文件权限和符号链接检查最终须在 Linux 上通过。

## 准备固定制品

显式联网准备三种样例镜像，然后核对本地可用性：

```sh
go run ./test/managedserviceonboarding/cmd/prepare -pull
go run ./test/managedserviceonboarding/cmd/prepare
```

`-pull` 只用于准备阶段；不带它时工具不会下载。工具读取唯一的
[固定摘要清单](../../test/managedserviceonboarding/artifacts.json)，检查 Linux/amd64 镜像，输出非秘密的制品引用和本地身份。
离线环境由交付方先导入这些准确制品，再执行不带 `-pull` 的检查。
此检查不等于完整离线发布包验收。

## 真实运行验收

在原生 Linux Docker 主机上，从仓库根目录执行。下面的临时目录属于当前验收；
程序只在其中创建独立运行目录，不接管既有产品实例。

```sh
export MATRIX_ONBOARDING_ROOT="$(mktemp -d /tmp/matrix-onboarding.XXXXXX)"
export MATRIX_ONBOARDING_REPORT="$MATRIX_ONBOARDING_ROOT/acceptance.json"
MATRIX_ONBOARDING_RUNTIME=1 go test -count=1 -timeout=20m -v ./test/managedserviceonboarding
cat "$MATRIX_ONBOARDING_REPORT"
```

判定必须同时满足：测试退出码为零，报告 `status` 为 `PASSED`，包含 L、K 两组共十一项运行检查。
其中 Logstash 包含两个租户作用域的网络、数据、凭据、重启及独立删除检查。
报告写 `INCOMPLETE` 时，常见原因是仅运行了某个子测试；不能交付为完整样例验收。
`platformAndReleaseGates` 保持 `NOT_RUN`，不表示平台目录、IAM、浏览器或签名发布包已经验收。

门禁创建独立实例身份，验证结束后调用产品自己的 `Delete`，确认数据、凭据和运行资源删除。
门禁会先从当前源码编译并构建隔离入口的临时镜像，再交给 Logstash 适配器；产品
镜像仍须提前准备，适配器不会自行构建或下载。临时入口镜像按本次归属标签清理。
Kibana 的 Elasticsearch 依赖先被证明仍在，再由依赖自身的清理流程删除。
无法证明精确清理成功时，测试失败并保留本次运行目录，不全局清理 Docker。

## Docker Desktop 上执行

这条流程在 PowerShell 中准备工具容器，工具容器使用宿主机的 Docker socket。
需先启用 Docker Desktop 的主机网络功能；工具容器没有独立 Docker daemon。
所有命令都从仓库根目录执行，每一步成功后再继续。

先完成前面的契约检查和制品准备。工具镜像与 Go 工具链另行准备：

```powershell
$dockerToolImage = 'docker@sha256:f56779b4e86550493153cc8642c9c8e40b5d934e43cb5b4ea463aea5245c5c01'
$goToolImage = 'golang@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d'
docker pull $dockerToolImage
docker pull $goToolImage
```

为本次验证选择独立名称，创建带归属标签的数据卷，读取它在 Docker Engine 中的真实位置。
工具容器必须将这个卷挂载到相同路径，产品的绑定挂载才能找到配置和数据。

```powershell
$taskName = 'matrix-onboarding-' + (Get-Date -Format 'yyyyMMddHHmmss')
$taskVolume = $taskName + '-data'
$taskOperator = $taskName + '-operator'
docker volume create --label "com.xiak.matrix.onboarding=$taskName" $taskVolume
$taskVolumeRoot = docker volume inspect $taskVolume --format '{{.Mountpoint}}'
docker run --rm --mount "type=volume,source=$taskVolume,target=$taskVolumeRoot" --entrypoint sh $goToolImage -c "mkdir -p '$taskVolumeRoot/toolchain' '$taskVolumeRoot/runs'; cp -a /usr/local/go/. '$taskVolumeRoot/toolchain/'"
docker run -d --name $taskOperator --label "com.xiak.matrix.onboarding=$taskName" --network host --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock --mount "type=volume,source=$taskVolume,target=$taskVolumeRoot" --mount "type=bind,source=$($PWD.Path),target=/workspace,readonly" --env "GOMODCACHE=$taskVolumeRoot/modcache" --env "GOCACHE=$taskVolumeRoot/gocache" --env "PATH=$taskVolumeRoot/toolchain/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" --env CGO_ENABLED=0 --workdir /workspace --entrypoint sh $dockerToolImage -c 'exec sleep infinity'
```

工具链和模块缓存写入专用卷，仓库只读挂载。确认工具容器里的契约检查也通过，再执行真实门禁：

```powershell
docker exec $taskOperator go test -count=1 ./api/adapter/managedservice/v1 ./test/managedserviceonboarding ./app/service/paas/internal/managedservice/usecase/reconcileinstallation ./test/architecture
docker exec $taskOperator go run ./test/managedserviceonboarding/cmd/prepare
docker exec --env MATRIX_ONBOARDING_RUNTIME=1 --env "MATRIX_ONBOARDING_ROOT=$taskVolumeRoot/runs" --env "MATRIX_ONBOARDING_REPORT=$taskVolumeRoot/acceptance.json" $taskOperator go test -count=1 -timeout=20m -v ./test/managedserviceonboarding
New-Item -ItemType Directory -Force .cache/product-onboarding | Out-Null
docker cp "${taskOperator}:$taskVolumeRoot/acceptance.json" .cache/product-onboarding/runtime-evidence.json
```

保存报告后，先确认门禁通过且产品清理无错误，再回收本次工具容器和缓存卷。
核对标签不符时停止，不删除别人的对象：

```powershell
$operatorOwner = docker inspect $taskOperator --format '{{index .Config.Labels "com.xiak.matrix.onboarding"}}'
$volumeOwner = docker volume inspect $taskVolume --format '{{index .Labels "com.xiak.matrix.onboarding"}}'
if ($operatorOwner -ne $taskName -or $volumeOwner -ne $taskName) { throw '资源归属不匹配，停止回收' }
docker rm -f $taskOperator
docker volume rm $taskVolume
```

## 失败时如何处理

| 现象 | 处理顺序 |
| --- | --- |
| `TestElasticRuntime` 为 `SKIP` | 确认显式设置运行开关；只跑普通单测没有执行产品安装 |
| 镜像缺失或架构不符 | 重新执行准备工具；网络中断后可以再次显式使用 `-pull`，保留准确摘要，不换成浮动 tag |
| Elasticsearch 主机参数不满足 | 在 Docker Engine 所在主机检查参数；在普通工具容器里改参数不能代替修改实际主机 |
| 绑定挂载找不到文件 | 核对测试进程与 Docker Engine 的路径；Windows 盘符目录不能冒充 Linux 引擎路径 |
| Kibana 健康检查成功但没有宿主机端口 | 核对是否只连接了 internal 网络；样例保留产品自己的网络用于本机端点，依赖网络单独接入 |
| Kibana HTTP 为 200，但状态仍非 `available` | 等待真实产品就绪；样例检查状态内容，HTTP 成功本身不构成可用证明 |
| 配置漂移被拒绝 | 保留旧实例；审阅制品、配置和依赖修订的变化。不要删除绑定记录强行重放 |
| 子测试失败或报告为 `INCOMPLETE` | 根据明确失败项修复，再跑完整门禁；不修改报告结论 |
| 精确清理失败 | 保留本次运行目录，核对准确实例身份、所有权及运行对象，再通过 owning provider 处理；不运行全局 prune 或删除业务卷 |

提交问题时附上代码提交、制品引用、失败子测试名称与非秘密报告。
原生配置、事件数据和原生日志可能含有敏感内容，不作为默认交付附件。

## CI 复核

[Product onboarding 工作流](../../.github/workflows/product-onboarding.yml)在相关 PR 上执行独立的
Linux 契约和真实运行门禁，使用宿主机 Docker，并保存非秘密报告。
全仓生成、架构、vet/race 等通用检查继续由既有 Verification 工作流负责。
本机报告和 CI 报告都应对应交付源码；平台正式上架还需完成 owning FEAT 的 P1/P2。
