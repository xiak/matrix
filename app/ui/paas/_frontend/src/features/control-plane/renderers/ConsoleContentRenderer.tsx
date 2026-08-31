import Link from "next/link";
import { AccountAccessRenderer } from "@/features/auth/renderers/AccountAccessRenderer";
import {
  ArrowRight,
  Activity,
  Box,
  CheckCircle2,
  Container,
  Cpu,
  Database,
  Gauge,
  HardDrive,
  MemoryStick,
  MapPin,
  PackageCheck,
  PackageSearch,
  Server,
  SquareTerminal
} from "lucide-react";
import {
  Badge,
  Button,
  Card,
  ContentLayout,
  Typography
} from "@ui/xiak";
import type {
  ConsoleContentScene,
  HostMeasurementScene,
  HostScene,
  InstallationScene,
  SceneStatus
} from "../scenes/consoleScene";
import styles from "./ConsoleContentRenderer.module.css";

const metricIcons: Record<string, typeof Database> = {
  offerings: PackageSearch,
  quota: Gauge,
  services: Database,
  regions: MapPin
};

function phaseLabel(value: string): string {
  const labels: Record<string, string> = {
    PENDING: "等待处理",
    PROVISIONING: "安装中",
    READY: "运行中",
    FAILED: "失败",
    AVAILABLE: "可用",
    UNAVAILABLE: "不可用",
    STALE: "待复检",
    UNKNOWN: "未知",
    DEGRADED: "降级",
    ACTIVE: "可调度",
    DRAINING: "排空中",
    PLACING: "调度中",
    APPLYING: "部署中",
    STOPPING: "停止中",
    STOPPED: "已停止",
    RUNNING: "运行中"
  };
  return labels[value] ?? value;
}

function EmptyState({
  description,
  title
}: {
  description: string;
  title: string;
}) {
  return (
    <div className={styles.empty}>
      <Box aria-hidden="true" />
      <Typography.Title as="h3" level={3}>{title}</Typography.Title>
      <Typography.Text tone="muted">{description}</Typography.Text>
    </div>
  );
}

function InstallationRows({ items }: { items: InstallationScene[] }) {
  if (items.length === 0) {
    return (
      <EmptyState
        description="激活配额后，可以从服务实例页发起第一个 PostgreSQL 安装。"
        title="还没有服务实例"
      />
    );
  }
  return (
    <div aria-label="服务实例列表" className={styles.tableWrap} role="region" tabIndex={0}>
      <table className={styles.table}>
        <thead>
          <tr><th>实例</th><th>区域</th><th>状态</th><th>端点</th><th>最近观察</th></tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <td><strong>{item.name}</strong><small>{item.engine}</small></td>
              <td>{item.regionName}</td>
              <td><Badge status={item.status}>{phaseLabel(item.phase)}</Badge></td>
              <td><Typography.Code>{item.endpoint ?? "尚未分配"}</Typography.Code></td>
              <td>{item.observedAt}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function OverviewContent({ scene }: { scene: Extract<ConsoleContentScene, { kind: "overview" }> }) {
  return (
    <ContentLayout>
      <ContentLayout.Main>
        <section className={styles.metricGrid} aria-label="平台指标">
          {scene.metrics.map((metric) => {
            const Icon = metricIcons[metric.id] ?? Box;
            return (
              <Card className={styles.metric} key={metric.id}>
                <Card.Body>
                  <div className={styles.metricHeading}>
                    <span>{metric.label}</span>
                    <Icon aria-hidden="true" data-status={metric.status} />
                  </div>
                  <strong>{metric.value}</strong>
                  <p>{metric.detail}</p>
                </Card.Body>
              </Card>
            );
          })}
        </section>

        <Card>
          <Card.Header>
            <div>
              <Typography.Title as="h2" level={3}>最近服务实例</Typography.Title>
              <Typography.Text tone="muted">安装任务与运行端点</Typography.Text>
            </div>
            <Link className={styles.textLink} href="/console/installations/">
              查看全部 <ArrowRight aria-hidden="true" />
            </Link>
          </Card.Header>
          <InstallationRows items={scene.recentInstallations} />
        </Card>
      </ContentLayout.Main>

      <ContentLayout.Aside>
        <Card className={styles.featureCard}>
          <Card.Body className={styles.featureCardBody}>
            <div className={styles.databaseIcon}><Database aria-hidden="true" /></div>
            <Typography.Eyebrow>Default managed database</Typography.Eyebrow>
            <Typography.Title as="h2" level={2}>
              {scene.offering?.name ?? "PostgreSQL"}
            </Typography.Title>
            <p>{scene.offering?.description ?? "服务目录尚未返回可用产品。"}</p>
            <div className={styles.featureMeta}>
              <span><PackageCheck aria-hidden="true" /> 固定发布制品</span>
              <span><HardDrive aria-hidden="true" /> 持久化存储</span>
              <span><CheckCircle2 aria-hidden="true" /> 平台托管凭据</span>
            </div>
            <Link className={styles.primaryLink} href="/console/catalog/">
              浏览服务目录 <ArrowRight aria-hidden="true" />
            </Link>
          </Card.Body>
        </Card>
      </ContentLayout.Aside>
    </ContentLayout>
  );
}

function CatalogContent({ scene }: { scene: Extract<ConsoleContentScene, { kind: "catalog" }> }) {
  if (scene.offerings.length === 0) {
    return <EmptyState title="服务目录不可用" description="平台没有返回任何可真实安装的产品。" />;
  }
  return (
    <div className={styles.catalogGrid}>
      {scene.offerings.map((offering) => (
        <Card className={styles.productCard} key={offering.id}>
          <Card.Body className={styles.productCardBody}>
            <div className={styles.productTopline}>
              <div className={styles.databaseIcon}><Database aria-hidden="true" /></div>
              <Badge status={offering.available ? "success" : "neutral"}>
                {offering.available ? "可激活" : "不可用"}
              </Badge>
            </div>
            <Typography.Eyebrow>{offering.engine}</Typography.Eyebrow>
            <Typography.Title as="h2" level={2}>{offering.name}</Typography.Title>
            <p className={styles.productDescription}>{offering.description}</p>
            <dl className={styles.productFacts}>
              <div><dt>引擎版本</dt><dd>{offering.version}</dd></div>
              <div><dt>配额规格</dt><dd>{offering.shapeCount} 种</dd></div>
              <div><dt>可选规格</dt><dd>{offering.shapeSummary}</dd></div>
            </dl>
          </Card.Body>
          <Card.Footer>
            <Typography.Text tone="subtle">配额激活不涉及付款</Typography.Text>
            <Link className={styles.primaryLink} href="/console/quotas/">
              配置配额 <ArrowRight aria-hidden="true" />
            </Link>
          </Card.Footer>
        </Card>
      ))}
    </div>
  );
}

function QuotaContent({ scene }: { scene: Extract<ConsoleContentScene, { kind: "quotas" }> }) {
  if (scene.entitlements.length === 0) {
    return (
      <EmptyState
        title="尚未激活服务配额"
        description="从右侧订单面板选择 PostgreSQL 规格和实例数量。平台只记录真实额度，不模拟支付。"
      />
    );
  }
  return (
    <div className={styles.cardList}>
      {scene.entitlements.map((item) => {
        const status: SceneStatus = item.available > 0 ? "success" : "warning";
        return (
          <Card key={item.id}>
            <Card.Body className={styles.quotaRow}>
              <div className={styles.quotaIdentity}>
                <Database aria-hidden="true" />
                <div><strong>{item.offeringName}</strong><span>{item.shapeName} · {item.resourceSummary}</span></div>
              </div>
              <div className={styles.quotaNumbers}>
                <div><small>已激活</small><strong>{item.purchased}</strong></div>
                <div><small>使用中</small><strong>{item.inUse}</strong></div>
                <div><small>可用</small><strong>{item.available}</strong></div>
              </div>
              <div className={styles.quotaStatus}>
                <Badge status={status}>{item.available > 0 ? "可安装" : "额度已用尽"}</Badge>
                <small>{item.activatedAt}</small>
              </div>
            </Card.Body>
          </Card>
        );
      })}
    </div>
  );
}

function InstallationContent({ scene }: { scene: Extract<ConsoleContentScene, { kind: "installations" }> }) {
  return (
    <Card>
      <Card.Header>
        <div>
          <Typography.Title as="h2" level={3}>组织服务实例</Typography.Title>
          <Typography.Text tone="muted">状态来自真实安装 Operation</Typography.Text>
        </div>
        <Badge status="info">{scene.installations.length} 个实例</Badge>
      </Card.Header>
      <InstallationRows items={scene.installations} />
    </Card>
  );
}

function RegionContent({ scene }: { scene: Extract<ConsoleContentScene, { kind: "regions" }> }) {
  if (scene.regions.length === 0) {
    return <EmptyState title="尚未配置区域" description="请先由平台安装器登记本机区域绑定。" />;
  }
  return (
    <div className={styles.regionGrid}>
      {scene.regions.map((region) => (
        <Card key={region.id}>
          <Card.Body className={styles.regionCard}>
            <div className={styles.regionIcon}><MapPin aria-hidden="true" /></div>
            <div className={styles.regionHeading}>
              <div><Typography.Title as="h2" level={3}>{region.name}</Typography.Title><span>{region.profile}</span></div>
              <Badge status={region.status}>{phaseLabel(region.state)}</Badge>
            </div>
            <div className={styles.regionFacts}>
              <span><Cpu aria-hidden="true" /> {region.capacity}</span>
              <span><Server aria-hidden="true" /> 最近检查：{region.inspectedAt}</span>
            </div>
            <p>浏览器只显示归一化能力；Docker socket、主机路径和机器凭据由安装器保管。</p>
          </Card.Body>
        </Card>
      ))}
    </div>
  );
}

function HostMeasurement({
  icon: Icon,
  label,
  measurement
}: {
  icon: typeof Cpu;
  label: string;
  measurement: HostMeasurementScene;
}) {
  return (
    <div className={styles.hostMeasurement}>
      <div className={styles.hostMeasurementHeading}>
        <span><Icon aria-hidden="true" />{label}</span>
        <Badge status={measurement.status}>{measurement.stateLabel}</Badge>
      </div>
      <strong>{measurement.value}</strong>
      {measurement.progress === null ? null : (
        <progress aria-label={`${label}占用率`} max={100} value={measurement.progress} />
      )}
      <small>{measurement.detail}</small>
    </div>
  );
}

function HostCard({ host }: { host: HostScene }) {
  return (
    <Card className={styles.hostCard}>
      <Card.Header>
        <div className={styles.hostIdentity}>
          <div className={styles.regionIcon}><Server aria-hidden="true" /></div>
          <div>
            <Typography.Title as="h2" level={3}>{host.name}</Typography.Title>
            <Typography.Code>{host.id}</Typography.Code>
          </div>
        </div>
        <div className={styles.hostBadges}>
          <Badge status={host.sampleStatus}>{host.sampleState}</Badge>
          <Badge status={host.status}>{phaseLabel(host.health)}</Badge>
        </div>
      </Card.Header>
      <Card.Body className={styles.hostBody}>
        <dl className={styles.hostFacts}>
          <div><dt>平台</dt><dd>{host.platform}</dd></div>
          <div><dt>执行池</dt><dd><Typography.Code>{host.executionPoolId}</Typography.Code></dd></div>
          <div><dt>适配来源</dt><dd>{host.source}</dd></div>
          <div><dt>期望状态</dt><dd>{phaseLabel(host.desiredState)}</dd></div>
          <div><dt>标称容量</dt><dd>{host.capacity}</dd></div>
        </dl>

        <div className={styles.hostMetricGrid}>
          <HostMeasurement icon={Activity} label="CPU" measurement={host.cpu} />
          <HostMeasurement icon={MemoryStick} label="内存" measurement={host.memory} />
        </div>

        <section className={styles.filesystems} aria-label={`${host.name} 文件系统`}>
          <div className={styles.filesystemHeading}>
            <div><HardDrive aria-hidden="true" /><strong>文件系统</strong></div>
            <Badge status={host.filesystems.length > 0 ? "info" : "neutral"}>{host.filesystemsState}</Badge>
          </div>
          {host.filesystems.length === 0 ? (
            <p>该采样没有可展示的文件系统数值。</p>
          ) : host.filesystems.map((filesystem) => (
            <div className={styles.filesystemRow} key={filesystem.id}>
              <div className={styles.filesystemIdentity}>
                <strong>{filesystem.mountPoint}</strong>
                <span>{filesystem.device} · {filesystem.filesystemType}{filesystem.readOnly ? " · 只读" : ""}</span>
              </div>
              <div className={styles.filesystemUsage}>
                <span><strong>{filesystem.value}</strong><Badge status={filesystem.status}>{filesystem.stateLabel}</Badge></span>
                {filesystem.progress === null ? null : (
                  <progress aria-label={`${filesystem.mountPoint}占用率`} max={100} value={filesystem.progress} />
                )}
                <small>{filesystem.detail}</small>
              </div>
            </div>
          ))}
        </section>

        <div className={styles.hostTimestamps}>
          <span>主机健康观测：{host.observedAt}</span>
          <span>资源采样：{host.usageObservedAt}</span>
          <span>有效至：{host.validUntil}</span>
        </div>
      </Card.Body>
    </Card>
  );
}

function HostContent({ scene }: { scene: Extract<ConsoleContentScene, { kind: "hosts" }> }) {
  if (scene.hosts.length === 0) {
    return <EmptyState title="尚未纳管主机" description="由平台安装器登记并验证主机后，资源采样才会出现在这里。" />;
  }
  return (
    <div className={styles.hostList}>
      {scene.hosts.map((host) => <HostCard host={host} key={host.id} />)}
    </div>
  );
}

function DeploymentContent({
  onSelect,
  scene
}: {
  onSelect(deploymentId: string): void;
  scene: Extract<ConsoleContentScene, { kind: "deployments" }>;
}) {
  if (scene.deployments.length === 0) {
    return <EmptyState title="当前租户没有部署" description="部署由应用交付流程创建；控制台不会扫描主机或导入未知容器。" />;
  }
  const selected = scene.deployments.find((item) => item.selected) ?? null;
  return (
    <div className={styles.deploymentLayout}>
      <Card className={styles.deploymentInventoryCard}>
        <Card.Header>
          <div>
            <Typography.Title as="h2" level={3}>租户部署</Typography.Title>
            <Typography.Text tone="muted">最多展示当前有序页中的 100 个资源</Typography.Text>
          </div>
          <Badge status={scene.truncated ? "warning" : "info"}>{scene.deployments.length} 个部署</Badge>
        </Card.Header>
        <Card.Body className={styles.deploymentList}>
          {scene.deployments.map((deployment) => (
            <button
              aria-pressed={deployment.selected}
              className={styles.deploymentItem}
              data-selected={deployment.selected ? "true" : undefined}
              key={deployment.id}
              onClick={() => onSelect(deployment.id)}
              type="button"
            >
              <span className={styles.deploymentItemIcon}><Container aria-hidden="true" /></span>
              <span className={styles.deploymentItemIdentity}>
                <strong>{deployment.name}</strong>
                <Typography.Code>{deployment.id}</Typography.Code>
                <small>{deployment.componentSummary}</small>
              </span>
              <span className={styles.deploymentItemState}>
                <Badge status={deployment.status}>{phaseLabel(deployment.phase)}</Badge>
                <small>{deployment.readiness}</small>
              </span>
            </button>
          ))}
          {scene.truncated ? <p className={styles.deploymentNotice}>当前仅展示前 100 个部署；本切片不会在浏览器中自动扫描后续页。</p> : null}
        </Card.Body>
      </Card>

      <Card className={styles.runtimeCard}>
        <Card.Header>
          <div>
            <Typography.Title as="h2" level={3}>{selected ? `${selected.name} 运行态` : "部署运行态"}</Typography.Title>
            <Typography.Text tone="muted">来源时间由执行节点给出，控制面不会在读取时重新盖章</Typography.Text>
          </div>
          {scene.runtime ? <Badge status={scene.runtime.status}>{scene.runtime.stateLabel}</Badge> : <Badge status="neutral">正在读取</Badge>}
        </Card.Header>
        <Card.Body className={styles.runtimeBody}>
          {scene.runtime ? (
            <>
              <dl className={styles.runtimeFacts}>
                <div><dt>部署代次</dt><dd>{scene.runtime.generation ?? "不可用"}</dd></div>
                <div><dt>应用修订</dt><dd><Typography.Code>{scene.runtime.revisionId ?? "不可用"}</Typography.Code></dd></div>
                <div><dt>执行目标</dt><dd><Typography.Code>{scene.runtime.executionTargetId ?? "不可用"}</Typography.Code></dd></div>
                <div><dt>来源观测</dt><dd>{scene.runtime.observedAt}</dd></div>
                <div><dt>有效至</dt><dd>{scene.runtime.validUntil}</dd></div>
                <div><dt>资源采样</dt><dd><Badge status={scene.runtime.resources.status}>{scene.runtime.resources.stateLabel}</Badge></dd></div>
                <div><dt>资源来源</dt><dd>{scene.runtime.resources.observedAt}</dd></div>
                <div><dt>资源有效至</dt><dd>{scene.runtime.resources.validUntil}</dd></div>
              </dl>
              {scene.runtime.instances.length === 0 ? (
                <div className={styles.runtimeEmpty}>
                  <Container aria-hidden="true" />
                  <div><strong>没有可证明的当前容器实例</strong><span>停止中的部署或尚未完成首次采样时，这是正常状态。</span></div>
                </div>
              ) : (
                <div aria-label="部署容器实例" className={styles.runtimeInstances}>
                  {scene.runtime.instances.map((instance) => (
                    <div className={styles.runtimeInstance} key={instance.id}>
                      <div className={styles.runtimeInstanceHeader}>
                        <div className={styles.runtimeInstanceIdentity}>
                          <Container aria-hidden="true" />
                          <span><strong>{instance.componentName}</strong><Typography.Code>{instance.id}</Typography.Code></span>
                        </div>
                        <div className={styles.runtimeInstanceStatus}>
                          <Badge status={instance.status}>{instance.stateLabel}</Badge>
                          <span>{instance.healthLabel}</span>
                          {instance.exitCode === "—" ? null : <span>退出码 {instance.exitCode}</span>}
                        </div>
                      </div>
                      {instance.resources ? (
                        <dl aria-label={`${instance.componentName} 资源使用`} className={styles.runtimeResourceGrid}>
                          {([
                            ["CPU", instance.resources.cpu],
                            ["内存", instance.resources.memory],
                            ["网络累计", instance.resources.network],
                            ["块设备累计", instance.resources.blockIo],
                            ["存储", instance.resources.storage]
                          ] as const).map(([label, measurement]) => (
                            <div key={label}>
                              <dt><span>{label}</span><Badge status={measurement.status}>{measurement.stateLabel}</Badge></dt>
                              <dd><strong>{measurement.value}</strong><small>{measurement.detail}</small></dd>
                            </div>
                          ))}
                        </dl>
                      ) : (
                        <p className={styles.runtimeResourceUnavailable}>该实例尚无可证明的资源采样。</p>
                      )}
                    </div>
                  ))}
                </div>
              )}
              <div className={styles.terminalBoundary}>
                <div><SquareTerminal aria-hidden="true" /><span><strong>短时终端</strong><small>将在下一纵向切片加入受审计、限时、按部署授权的会话。</small></span></div>
                <Button disabled size="small" variant="secondary"><SquareTerminal aria-hidden="true" />暂不可用</Button>
              </div>
            </>
          ) : (
            <div className={styles.runtimeEmpty}>
              <Container aria-hidden="true" />
              <div><strong>正在读取所选部署</strong><span>只请求当前选中资源，不扫描其他租户、主机或容器。</span></div>
            </div>
          )}
        </Card.Body>
      </Card>
    </div>
  );
}

export function ConsoleContentRenderer({
  onSelectDeployment = () => {},
  scene
}: {
  onSelectDeployment?(deploymentId: string): void;
  scene: ConsoleContentScene;
}) {
  if (scene.kind === "access") return <AccountAccessRenderer />;
  if (scene.kind === "overview") return <OverviewContent scene={scene} />;
  if (scene.kind === "catalog") return <CatalogContent scene={scene} />;
  if (scene.kind === "quotas") return <QuotaContent scene={scene} />;
  if (scene.kind === "installations") return <InstallationContent scene={scene} />;
  if (scene.kind === "hosts") return <HostContent scene={scene} />;
  if (scene.kind === "deployments") return <DeploymentContent onSelect={onSelectDeployment} scene={scene} />;
  return <RegionContent scene={scene} />;
}
