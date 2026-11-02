# 产品团队接入 Matrix：以 Logstash、Kibana 为例

这份手册给准备把自己的产品交给 Matrix 纳管的研发与交付团队使用。
目标是交付能够安装、验证、恢复和删除的产品实现，并给平台团队一份可复核的验收材料。
普通用户开通已经发布的产品，请看[托管服务使用手册](../user-guide/services-and-applications.md)。

本仓库提供两个可执行接入样例。它们通过与 PG、MySQL 相同的部署接口运行，
使用真实 Logstash、Kibana 制品。**样例没有进入默认产品目录，也没有发布 L/K 的租户管理 API。**
完成样例测试后，还须由平台团队完成正式集成和发布验收。

## 1. 先分清双方交付什么

```mermaid
flowchart LR
  A[产品团队：规格、配置、制品] --> B[实现公开部署契约]
  B --> C[真实运行与故障测试]
  C --> D[交付证据给平台团队]
  D --> E[目录、权限、配额、页面集成]
  E --> F[签名发布包验收]
  F --> G[用户开通与使用]
```

| 产品团队负责 | 平台团队负责 |
| --- | --- |
| 产品版本、规格、固定配置、依赖和凭据需求 | 校验当前租户、权限、配额及受信配置来源 |
| 安装、就绪判断、重复执行、失败恢复和精确删除 | 接收命令、记录任务、调度 worker、保存权威状态与审计 |
| 真实协议验证、数据保留与删除行为 | 控制台、目录发布、制品交付、平台升级和恢复组合 |
| 交付源码、制品身份、测试结果与维护联系人 | 复核证据，决定是否进入发布目录 |

要求和验收条件的唯一规范在 [FEAT-007 产品团队接入契约](../features/FEAT-007-control-plane-console.md#产品团队接入契约)。
下文带你按顺序完成交付，不另设一套验收标准。

## 2. 从可运行样例开始

先按[运行手册](../runbooks/managed-service-onboarding.md)准备本机 Docker、固定镜像和测试目录，
完成一次原样运行。这样可以先确认自己的环境具备验收条件，再调整产品实现。

| 示例 | 它实际证明什么 | 实现入口 |
| --- | --- | --- |
| Logstash | 带认证的 HTTP 输入被处理并写入持久文件；重启后数据保留 | [Logstash 样例](../../test/managedserviceonboarding/logstash.go) |
| Kibana | 连接准确的同租户 Elasticsearch 依赖；通过真实接口创建、读取数据视图 | [Kibana 样例](../../test/managedserviceonboarding/kibana.go) |

Logstash 样例不依赖 Elasticsearch。Kibana 验收临时准备自己的 Elasticsearch，
用于证明依赖管理及删除边界；不要将它替换成生产数据库。
两种产品都验证平台部署契约，业务协议验证是其中一个环节。

参考实现固定为 `8.19.23`，镜像摘要统一由
[制品清单](../../test/managedserviceonboarding/artifacts.json)维护。实际镜像在准备阶段加载，
产品安装阶段使用本地不可变镜像，不临时拉取或构建。
上游配置依据为 Elastic 的 [Logstash Docker 配置](https://www.elastic.co/guide/en/logstash/8.19/docker-config.html)
和 [Kibana 配置](https://www.elastic.co/guide/en/kibana/8.19/settings.html)；支持范围以 Matrix 自己的契约和实测为准。

## 3. 实现产品部署契约

产品团队直接引用 [公开适配契约](../../api/adapter/managedservice/v1/README.md)，
无需引用平台服务的 `internal` 包。示例的真实测试也只通过这个公开接口驱动实例。

| 你需要实现的方法 | 从用户结果看，什么才算完成 |
| --- | --- |
| `Ready` | 这个产品当前具备部署前提；检查本身不创建实例 |
| `Ensure` | 实例已经真正可用；重复调用或中途断线恢复不会多建一个实例 |
| `Delete` | 指定实例及约定的数据、凭据已经删除；重复调用仍能得到确定结果 |

输入中的租户、实例、版本、区域和规格由平台传入。输出只返回业务端点与凭据引用。
密码不会通过部署结果直接交给页面。产品的版本识别、健康检查、数据目录和实际协议
由产品团队负责；不能只用“容器正在运行”证明产品已经可用。

先阅读 [MySQL 正式适配器](../../app/adapter/managedservice/localmysql/provisioner.go)，
再对照 L/K 样例。共同执行能力由现有本地容器适配层提供；产品实现负责自己的配置和语义。

## 4. 明确产品配置与依赖

开始编码前，双方应确认配置中哪些内容属于用户选择、哪些必须由平台解析。
样例的[配置与绑定实现](../../test/managedserviceonboarding/configuration.go)采用固定修订，
第一次安装后不能悄悄改写同一实例的配置。

**Logstash 示例**采用 `http-json-file-v1`：输入协议、输出位置和处理步骤固定。
平台生成输入认证材料，保护配置文件；测试发送一条数据，并验证处理结果落盘。
输入请求中的认证头不会写入示例输出数据。

**Kibana 示例**采用 `elasticsearch-ui-v1`：明确依赖实例、所属租户、版本及修订。
受信交付方提供专用服务身份的凭据引用，Kibana 不使用 Elasticsearch 管理员作为
自己的后台连接身份。删除 Kibana 必须保留依赖实例及其中的数据。

本例通过受信构造参数提供这些信息。正式接入需要可编辑配置或依赖选择时，平台团队
还要把相应的有界字段、不可变配置引用、依赖读取权限和恢复行为接入业务 API 与持久化。
**样例构造参数不是可以直接添加到租户请求中的 JSON 字段。**

例如，准备支持更多 Pipeline 时，应先确定允许的配置结构、校验、版本与秘密引用，
再实现配置生命周期。不要把任意原生 DSL、URL、镜像或宿主机路径作为通用透传字段。

## 5. 跑测试，再查看验收结果

按运行手册依次执行[契约检查](../runbooks/managed-service-onboarding.md#契约检查)
和[真实运行验收](../runbooks/managed-service-onboarding.md#真实运行验收)。

契约检查会覆盖身份、规格和依赖错误，以及重复执行、配置漂移与秘密处理。
真实运行会启动产品，用真实协议验证，并经历重启、结果丢失恢复和删除。
测试结束会检查实例的数据、凭据及运行资源已经清理；Kibana 删除后还会验证依赖仍可用。

结果文件只有非秘密的版本、制品身份、时间、检查项和结论。
确认测试命令成功、结果为 `PASSED`，且两个产品的预期检查项齐全。
默认的普通单元测试会跳过 Docker 运行；出现 `SKIP` 不能填写真实运行验收通过。
实际样例运行必须显式开启运行门禁，缺少镜像或环境会失败。

结果中的 `platformAndReleaseGates` 仍标记 `NOT_RUN`，表示该报告仅证明产品团队样例。
源码、接口或模拟测试成功，都不能替代后续真实用户权限和签名发布包验收。

## 6. 把合格实现交给平台团队

交付时应附上以下材料，并让接收方能用同一源码与制品复跑：

- 源码提交、产品版本、镜像摘要及配置修订。
- 支持的规格、依赖要求、秘密交付方式。
- 契约检查结果、真实运行报告，以及未通过或未执行的检查。
- 数据放在哪里、重启保留什么、删除会删除什么。
- 超时或结果未知时如何恢复，谁负责定位产品内部故障。
- 维护负责人和下一步正式集成的责任人。

平台集成时逐项核对现有 owner：

| 集成点 | 代码或规范入口 |
| --- | --- |
| 产品定义、规格与开通/实例契约 | [managed-service API](../../api/managedservice/v1/README.md)、[目录](../../app/service/paas/internal/managedservice/domain/catalog.go) |
| 配置解析、依赖授权与持久化 | [managedservice 业务实现](../../app/service/paas/internal/managedservice)、[权限接入要求](../features/iam/FEAT-IAM-008-product-enforcement.md) |
| 目录与运行实现一一对应 | [worker 组装](../../app/service/paas/cmd/matrix-paas-worker/main.go)、[注册校验](../../app/service/paas/internal/managedservice/usecase/reconcileinstallation/providers.go) |
| 产品入口与真实页面 | [产品路由定义](../../app/ui/paas/_frontend/src/features/control-plane/domain/managedServiceProduct.ts)、[控制台 owner](../features/FEAT-007-control-plane-console.md) |
| 固定制品、安装与恢复 | [发布组装](../../deploy/releasebuild)、[生命周期 owner](../features/FEAT-005-offline-platform-lifecycle.md) |

只新增目录项会被运行实现校验拒绝。只放入镜像或增加页面，也不能完成接入。
需要新增字段时，应一并更新生成的契约、校验、幂等摘要、存储与恢复测试。

## 7. 完成平台验收后再发布

双方按 FEAT-007 中的 **P1 平台集成**、**P2 发布验收**提交证据。
产品团队继续支持真实协议和故障复现，平台团队验证真实 IAM、配额、任务恢复、审计、
浏览器使用以及签名包生命周期。全部必要检查通过后，产品才能进入正式目录。

以下状态应分别记录：**样例已验证 → 集成待验收 → 发布已验收**。
本手册提供的 L/K 样例只负责第一阶段的可执行交付。
HA、产品引擎升级、业务数据备份和任意 Pipeline 编辑需要各自的明确接入范围。
