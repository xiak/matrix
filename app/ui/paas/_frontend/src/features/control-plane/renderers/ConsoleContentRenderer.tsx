import Link from "next/link";
import {
  ArrowRight,
  Box,
  CheckCircle2,
  Cpu,
  Database,
  Gauge,
  HardDrive,
  MapPin,
  PackageCheck,
  PackageSearch,
  Server
} from "lucide-react";
import {
  Badge,
  Card,
  ContentLayout,
  Typography
} from "@ui/xiak";
import type {
  ConsoleContentScene,
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
    STALE: "待复检"
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

export function ConsoleContentRenderer({ scene }: { scene: ConsoleContentScene }) {
  if (scene.kind === "overview") return <OverviewContent scene={scene} />;
  if (scene.kind === "catalog") return <CatalogContent scene={scene} />;
  if (scene.kind === "quotas") return <QuotaContent scene={scene} />;
  if (scene.kind === "installations") return <InstallationContent scene={scene} />;
  return <RegionContent scene={scene} />;
}
