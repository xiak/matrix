"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Boxes,
  ChartNoAxesCombined,
  CheckCircle2,
  ChevronDown,
  CloudCog,
  Database,
  GitBranch,
  Layers3,
  PackageSearch,
  Search,
  Server,
  ShieldCheck,
  Workflow
} from "lucide-react";
import { Badge, Card, ContentLayout, Input, Select, Typography } from "@ui/xiak";
import type {
  AlertScene,
  ConsoleContentScene,
  ExperienceIconKind,
  MetricScene,
  OperationScene,
  UnifiedResourceScene
} from "../scenes/consoleScene";
import styles from "./ExperienceContentRenderer.module.css";

export type ResourceScope = {
  projectId: string;
  regionId: string;
};

const productIcons = {
  foundation: CloudCog,
  paas: Layers3,
  devops: GitBranch,
  observability: ChartNoAxesCombined,
  security: ShieldCheck
} satisfies Record<ExperienceIconKind, typeof Boxes>;

const metricIcons: Record<string, typeof Boxes> = {
  "all-resources": Boxes,
  "healthy-resources": CheckCircle2,
  "active-operations": Activity,
  "active-alerts": AlertTriangle,
  "pipeline-success": CheckCircle2,
  "pipeline-running": Workflow,
  "lead-time": Activity,
  "deployment-frequency": GitBranch,
  "service-health": Server,
  availability: CheckCircle2,
  "alert-firing": AlertTriangle,
  ingestion: ChartNoAxesCombined
};

function EmptyState({ title, description }: { title: string; description: string }) {
  return (
    <div className={styles.empty}>
      <PackageSearch aria-hidden="true" />
      <Typography.Title as="h2" level={3}>{title}</Typography.Title>
      <Typography.Text tone="muted">{description}</Typography.Text>
    </div>
  );
}

function MetricGrid({ metrics }: { metrics: MetricScene[] }) {
  return (
    <section aria-label="关键指标" className={styles.metricGrid}>
      {metrics.map((metric) => {
        const Icon = metricIcons[metric.id] ?? Boxes;
        return (
          <Card className={styles.metricCard} key={metric.id}>
            <Card.Body>
              <div className={styles.metricHeader}>
                <span>{metric.label}</span>
                <span className={styles.metricIcon} data-status={metric.status}><Icon aria-hidden="true" /></span>
              </div>
              <strong>{metric.value}</strong>
              <p>{metric.detail}</p>
            </Card.Body>
          </Card>
        );
      })}
    </section>
  );
}

function ProductGrid({ products, compact = false }: {
  products: Extract<ConsoleContentScene, { kind: "products" }>["products"];
  compact?: boolean;
}) {
  if (products.length === 0) {
    return <EmptyState title="产品体验未启用" description="当前构建只连接真实可用的控制面产品。" />;
  }
  return (
    <div className={compact ? styles.productGridCompact : styles.productGrid}>
      {products.map((product) => {
        const Icon = productIcons[product.icon];
        return (
          <Link className={styles.productCardLink} href={product.href} key={product.id}>
            <Card className={styles.productCard}>
              <Card.Body className={styles.productCardBody}>
                <div className={styles.productTopline}>
                  <span className={styles.productIcon} data-product={product.icon}><Icon aria-hidden="true" /></span>
                  <Badge status={product.status}>{product.statusLabel}</Badge>
                </div>
                <div>
                  <Typography.Eyebrow>{product.eyebrow}</Typography.Eyebrow>
                  <Typography.Title as="h3" level={3}>{product.name}</Typography.Title>
                </div>
                <p>{product.description}</p>
                {!compact ? (
                  <ul className={styles.capabilityList}>
                    {product.capabilities.map((capability) => <li key={capability}>{capability}</li>)}
                  </ul>
                ) : null}
                <div className={styles.productFooter}>
                  <span>{product.resourceCount} 个关联资源</span>
                  <ArrowRight aria-hidden="true" />
                </div>
              </Card.Body>
            </Card>
          </Link>
        );
      })}
    </div>
  );
}

function ResourceTable({ resources, scope, compact = false }: {
  resources: UnifiedResourceScene[];
  scope?: ResourceScope;
  compact?: boolean;
}) {
  const scoped = resources.filter((resource) => (
    (!scope || scope.projectId === "all" || resource.projectId === scope.projectId) &&
    (!scope || scope.regionId === "all" || resource.regionId === scope.regionId || resource.regionId === "all")
  ));
  if (scoped.length === 0) {
    return <EmptyState title="当前范围没有资源" description="切换项目或区域，或者清除资源搜索条件。" />;
  }
  return (
    <div aria-label="统一资源列表" className={styles.tableWrap} role="region" tabIndex={0}>
      <table className={styles.table}>
        <thead>
          <tr>
            <th>资源</th><th>产品</th>{compact ? null : <th>项目</th>}<th>区域</th><th>状态</th><th>更新</th>
          </tr>
        </thead>
        <tbody>
          {scoped.map((resource) => (
            <tr key={resource.id}>
              <td><Link className={styles.resourceLink} href={resource.href}>{resource.name}</Link><small>{resource.id} · {resource.kind}</small></td>
              <td>{resource.productName}</td>
              {compact ? null : <td>{resource.projectName}</td>}
              <td>{resource.regionName}</td>
              <td><Badge status={resource.status}>{resource.stateLabel}</Badge></td>
              <td>{resource.updatedAt}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function OperationSummary({ operation }: { operation: OperationScene }) {
  return <>
    <span className={styles.operationMarker} data-status={operation.status} aria-hidden="true" />
    <div className={styles.operationMain}>
      <div className={styles.operationHeading}>
        <div><strong>{operation.action}</strong><span>{operation.target}</span></div>
        <Badge status={operation.status}>{operation.stateLabel}</Badge>
      </div>
      {operation.status === "info" ? <progress aria-label={`${operation.action}进度`} max={100} value={operation.progress} /> : null}
      <div className={styles.operationMeta}>
        <span>{operation.productName}</span><span>{operation.actor}</span><span>{operation.startedAt}</span>
      </div>
    </div>
  </>;
}

function operationGuidance(operation: OperationScene): string {
  if (operation.status === "info") return "任务仍在执行；刷新后可查看控制面返回的最新进度。";
  if (operation.status === "success") return "任务已完成；操作标识和发起人可用于后续审计追踪。";
  if (operation.status === "danger") return "任务执行失败；请先核对目标资源状态，再从所属产品重新提交。";
  return "当前状态尚未终结；请刷新后再决定下一步操作。";
}

function OperationList({ operations, compact = false }: { operations: OperationScene[]; compact?: boolean }) {
  if (operations.length === 0) {
    return <EmptyState title="还没有操作记录" description="创建资源或运行交付任务后，进度会显示在这里。" />;
  }
  return (
    <div className={styles.operationList}>
      {operations.map((operation) => compact ? (
        <article className={styles.operationRow} key={operation.id}>
          <div className={styles.operationCompactSummary}><OperationSummary operation={operation} /></div>
        </article>
      ) : (
        <details className={styles.operationRow} key={operation.id}>
          <summary aria-label={`${operation.action}：${operation.target}，${operation.stateLabel}，查看详情`} className={styles.operationSummary}>
            <OperationSummary operation={operation} />
            <span className={styles.operationDetailCue}>详情<ChevronDown aria-hidden="true" /></span>
          </summary>
          <div className={styles.operationDetails}>
            <p data-status={operation.status}>{operationGuidance(operation)}</p>
            <dl>
              <div><dt>操作标识</dt><dd><Typography.Code>{operation.id}</Typography.Code></dd></div>
              <div><dt>执行进度</dt><dd>{operation.progress}%</dd></div>
              <div><dt>发起人</dt><dd>{operation.actor}</dd></div>
              <div><dt>所属产品</dt><dd>{operation.productName}</dd></div>
              <div><dt>目标</dt><dd>{operation.target}</dd></div>
              <div><dt>开始时间</dt><dd>{operation.startedAt}</dd></div>
            </dl>
          </div>
        </details>
      ))}
    </div>
  );
}

function AlertList({ alerts }: { alerts: AlertScene[] }) {
  if (alerts.length === 0) {
    return <div className={styles.clearState}><CheckCircle2 aria-hidden="true" /><span>当前没有待处理告警</span></div>;
  }
  return (
    <div className={styles.alertList}>
      {alerts.map((alert) => (
        <article className={styles.alertRow} key={alert.id}>
          <span className={styles.alertIcon} data-status={alert.status}><AlertTriangle aria-hidden="true" /></span>
          <div><strong>{alert.title}</strong><span>{alert.serviceName} · {alert.owner} · {alert.startedAt}</span></div>
          <Badge status={alert.status}>{alert.severityLabel}</Badge>
        </article>
      ))}
    </div>
  );
}

function CloudOverview({ scene, scope }: {
  scene: Extract<ConsoleContentScene, { kind: "cloud-overview" }>;
  scope?: ResourceScope;
}) {
  return (
    <div className={styles.pageStack}>
      <section className={styles.welcomeCard}>
        <div>
          <Typography.Eyebrow>Private cloud · Ready</Typography.Eyebrow>
          <Typography.Title as="h2" level={2}>欢迎回来，平台管理员</Typography.Title>
          <p>基础平台运行正常。当前有 {scene.operations.filter((item) => item.status === "info").length} 个任务执行中，{scene.alerts.length} 个告警需要关注。</p>
        </div>
        <div className={styles.quickActions}>
          <Link className={styles.primaryAction} href="/console/products/">创建云资源 <ArrowRight aria-hidden="true" /></Link>
          <Link className={styles.secondaryAction} href="/console/resources/">查看全部资源</Link>
        </div>
      </section>

      <MetricGrid metrics={scene.metrics} />

      <ContentLayout>
        <ContentLayout.Main>
          <Card>
            <Card.Header>
              <div><Typography.Title as="h2" level={3}>常用产品</Typography.Title><Typography.Text tone="muted">围绕交付与运营组织云能力</Typography.Text></div>
              <Link className={styles.textLink} href="/console/products/">全部产品 <ArrowRight aria-hidden="true" /></Link>
            </Card.Header>
            <Card.Body><ProductGrid compact products={scene.products.slice(0, 4)} /></Card.Body>
          </Card>
          <Card>
            <Card.Header>
              <div><Typography.Title as="h2" level={3}>最近资源</Typography.Title><Typography.Text tone="muted">跨产品、项目与区域的统一视图</Typography.Text></div>
              <Link className={styles.textLink} href="/console/resources/">资源中心 <ArrowRight aria-hidden="true" /></Link>
            </Card.Header>
            <ResourceTable compact resources={scene.recentResources} scope={scope} />
          </Card>
        </ContentLayout.Main>
        <ContentLayout.Aside>
          <Card>
            <Card.Header><div><Typography.Title as="h2" level={3}>待处理事项</Typography.Title><Typography.Text tone="muted">告警与运行任务</Typography.Text></div></Card.Header>
            <Card.Body className={styles.attentionBody}>
              <AlertList alerts={scene.alerts} />
              <div className={styles.asideDivider} />
              <OperationList compact operations={scene.operations} />
            </Card.Body>
          </Card>
          <Card className={styles.readinessCard}>
            <Card.Body>
              <div className={styles.readinessTop}><span className={styles.readinessIcon}><CloudCog aria-hidden="true" /></span><Badge status="success">基础平台就绪</Badge></div>
              <Typography.Title as="h3" level={3}>2 个私有云区域</Typography.Title>
              <p>计算、存储与网络能力已完成最近检查，可承载平台服务。</p>
              <Link className={styles.textLink} href="/console/regions/">查看区域状态 <ArrowRight aria-hidden="true" /></Link>
            </Card.Body>
          </Card>
        </ContentLayout.Aside>
      </ContentLayout>
    </div>
  );
}

function Products({ scene }: { scene: Extract<ConsoleContentScene, { kind: "products" }> }) {
  return (
    <div className={styles.pageStack}>
      <div className={styles.sectionLead}>
        <div><Typography.Title as="h2" level={3}>按工作场景探索</Typography.Title><p>产品保持独立边界，控制台提供统一入口、范围与资源发现体验。</p></div>
        <Badge status="info">{scene.products.length} 个产品域</Badge>
      </div>
      <ProductGrid products={scene.products} />
    </div>
  );
}

function Resources({ scene, scope }: {
  scene: Extract<ConsoleContentScene, { kind: "resources" }>;
  scope?: ResourceScope;
}) {
  const [query, setQuery] = useState("");
  const resources = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase("zh-CN");
    if (!normalized) return scene.resources;
    return scene.resources.filter((item) => [item.name, item.id, item.kind, item.productName, item.projectName, item.regionName]
      .some((value) => value.toLocaleLowerCase("zh-CN").includes(normalized)));
  }, [query, scene.resources]);
  return (
    <Card>
      <Card.Header className={styles.resourceHeader}>
        <div><Typography.Title as="h2" level={3}>全部资源</Typography.Title><Typography.Text tone="muted">筛选继承顶部项目与区域范围</Typography.Text></div>
        <label className={styles.tableSearch}><Search aria-hidden="true" /><span className={styles.visuallyHidden}>搜索资源</span><Input onChange={(event) => setQuery(event.target.value)} placeholder="名称、ID、类型或产品" value={query} /></label>
      </Card.Header>
      <ResourceTable resources={resources} scope={scope} />
    </Card>
  );
}

function Operations({ scene }: { scene: Extract<ConsoleContentScene, { kind: "operations" }> }) {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<"all" | "info" | "success" | "danger">("all");
  const operations = useMemo(() => {
    const normalized = query.trim().toLocaleLowerCase("zh-CN");
    return scene.operations.filter((operation) => (
      (status === "all" || operation.status === status) &&
      (!normalized || [operation.id, operation.action, operation.target, operation.productName, operation.actor, operation.stateLabel]
        .some((value) => value.toLocaleLowerCase("zh-CN").includes(normalized)))
    ));
  }, [query, scene.operations, status]);

  return (
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>最近操作</Typography.Title><Typography.Text tone="muted">跨产品保留一致的执行状态与责任人上下文</Typography.Text></div><Badge status="info">{scene.operations.filter((item) => item.status === "info").length} 个执行中</Badge></Card.Header>
      <Card.Body>
        <div className={styles.operationToolbar}>
          <label className={styles.operationSearch}><Search aria-hidden="true" /><span className={styles.visuallyHidden}>搜索操作</span><Input onChange={(event) => setQuery(event.target.value)} placeholder="操作、目标、ID 或发起人" value={query} /></label>
          <Select aria-label="筛选操作状态" onChange={(event) => setStatus(event.target.value as typeof status)} value={status}>
            <option value="all">全部状态</option>
            <option value="info">执行中</option>
            <option value="danger">失败</option>
            <option value="success">已完成</option>
          </Select>
          <span aria-live="polite" className={styles.operationCount}>{operations.length} 个结果</span>
        </div>
        {operations.length || scene.operations.length === 0 ? <OperationList operations={operations} /> : <EmptyState title="没有匹配的操作" description="调整关键词或状态筛选条件。" />}
      </Card.Body>
    </Card>
  );
}

function DevOps({ scene }: { scene: Extract<ConsoleContentScene, { kind: "devops" }> }) {
  return (
    <div className={styles.pageStack}>
      <MetricGrid metrics={scene.metrics} />
      <Card>
        <Card.Header>
          <div><Typography.Title as="h2" level={3}>最近流水线</Typography.Title><Typography.Text tone="muted">提交、验证、制品与环境发布保持一条可追踪链路</Typography.Text></div>
          <span className={styles.headerHint}><span className={styles.liveDot} /> 实时状态</span>
        </Card.Header>
        {scene.pipelines.length === 0 ? <EmptyState title="DEVOPS 体验未启用" description="当前构建没有连接研发效能数据源。" /> : (
          <div aria-label="流水线运行列表" className={styles.tableWrap} role="region" tabIndex={0}>
            <table className={styles.table}>
              <thead><tr><th>流水线</th><th>代码</th><th>环境</th><th>状态</th><th>耗时</th><th>触发时间</th></tr></thead>
              <tbody>{scene.pipelines.map((pipeline) => (
                <tr key={pipeline.id}>
                  <td><strong>{pipeline.name}</strong><small>{pipeline.repository}</small></td>
                  <td><strong>{pipeline.branch}</strong><small>{pipeline.commit}</small></td>
                  <td>{pipeline.environment}</td><td><Badge status={pipeline.status}>{pipeline.stateLabel}</Badge></td><td>{pipeline.duration}</td><td>{pipeline.triggeredAt}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </Card>
      <section className={styles.deliveryGrid} aria-label="交付环境">
        {[{ name: "生产环境", detail: "4 个服务 · 版本一致", status: "success" as const }, { name: "预发环境", detail: "3 个服务 · 1 个发布中", status: "info" as const }, { name: "测试环境", detail: "6 个服务 · 1 个失败任务", status: "warning" as const }].map((environment) => (
          <Card key={environment.name}><Card.Body className={styles.environmentCard}><span className={styles.environmentIcon}><Server aria-hidden="true" /></span><div><strong>{environment.name}</strong><span>{environment.detail}</span></div><Badge status={environment.status}>{environment.status === "success" ? "稳定" : environment.status === "info" ? "发布中" : "需关注"}</Badge></Card.Body></Card>
        ))}
      </section>
    </div>
  );
}

function Trend({ values, label }: { values: number[]; label: string }) {
  const width = 180;
  const height = 48;
  const points = values.map((value, index) => `${(index / Math.max(1, values.length - 1)) * width},${height - (value / 100) * height}`).join(" ");
  return (
    <svg aria-label={label} className={styles.trend} preserveAspectRatio="none" role="img" viewBox={`0 0 ${width} ${height}`}>
      <polyline fill="none" points={points} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

function Observability({ scene }: { scene: Extract<ConsoleContentScene, { kind: "observability" }> }) {
  return (
    <div className={styles.pageStack}>
      <MetricGrid metrics={scene.metrics} />
      <ContentLayout>
        <ContentLayout.Main>
          <Card>
            <Card.Header><div><Typography.Title as="h2" level={3}>服务健康</Typography.Title><Typography.Text tone="muted">关键 SLI 与最近 60 分钟趋势</Typography.Text></div><span className={styles.headerHint}><span className={styles.liveDot} /> 每 30 秒刷新</span></Card.Header>
            <Card.Body className={styles.healthList}>
              {scene.services.map((service) => (
                <article className={styles.healthRow} key={service.id}>
                  <div className={styles.healthIdentity}><span className={styles.serviceIcon}><Server aria-hidden="true" /></span><div><strong>{service.name}</strong><span>{service.productName}</span></div></div>
                  <Trend label={`${service.name}健康趋势`} values={service.trend} />
                  <dl className={styles.healthFacts}><div><dt>可用性</dt><dd>{service.availability}</dd></div><div><dt>P95 延迟</dt><dd>{service.latency}</dd></div><div><dt>错误率</dt><dd>{service.errorRate}</dd></div></dl>
                  <Badge status={service.status}>{service.stateLabel}</Badge>
                </article>
              ))}
            </Card.Body>
          </Card>
        </ContentLayout.Main>
        <ContentLayout.Aside>
          <Card>
            <Card.Header><div><Typography.Title as="h2" level={3}>当前告警</Typography.Title><Typography.Text tone="muted">按影响优先级排列</Typography.Text></div></Card.Header>
            <Card.Body><AlertList alerts={scene.alerts} /></Card.Body>
          </Card>
          <Card className={styles.signalCard}><Card.Body><span className={styles.signalIcon}><Database aria-hidden="true" /></span><div><strong>采集链路正常</strong><span>指标、日志与事件均在预算内</span></div><Badge status="success">健康</Badge></Card.Body></Card>
        </ContentLayout.Aside>
      </ContentLayout>
    </div>
  );
}

export function ExperienceContentRenderer({ scene, scope }: {
  scene: Extract<ConsoleContentScene, { kind: "cloud-overview" | "products" | "resources" | "operations" | "devops" | "observability" }>;
  scope?: ResourceScope;
}) {
  if (scene.kind === "cloud-overview") return <CloudOverview scene={scene} scope={scope} />;
  if (scene.kind === "products") return <Products scene={scene} />;
  if (scene.kind === "resources") return <Resources scene={scene} scope={scope} />;
  if (scene.kind === "operations") return <Operations scene={scene} />;
  if (scene.kind === "devops") return <DevOps scene={scene} />;
  return <Observability scene={scene} />;
}
