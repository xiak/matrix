"use client";

import { useMemo, useState } from "react";
import { ConsoleLink as Link } from "../routes/ConsoleNavigation";
import { useFormatter, useTranslations } from "next-intl";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  CloudCog,
  Database,
  Server
} from "lucide-react";
import { Alert, Table, TableToolbar, EmptyState, Badge, Button, Card, Progress, ContentLayout, Typography } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import type {
  AlertScene,
  ConsoleContentScene,
  OperationScene,
  UnifiedResourceScene
} from "../scenes/consoleScene";
import { CommonServiceLinks } from "./ServiceDirectory";
import { useConsoleUiStore } from "../application/consoleUiStore";
import styles from "./ExperienceContentRenderer.module.css";
import { ConsoleMetrics } from "./ConsoleMetrics";
import { useConsoleFormat } from "./useConsoleFormat";

export type ResourceScope = {
  regionId: string;
};

function ResourceTable({ resources, scope, compact = false }: {
  resources: UnifiedResourceScene[];
  scope?: ResourceScope;
  compact?: boolean;
}) {
  const t = useTranslations("CloudExperience");
  const scopeMessages = useTranslations("RegionScope");
  const resourceKinds = useTranslations("GlobalSearch.resourceKinds");
  const format = useConsoleFormat();
  const scoped = resources.filter((resource) => (
    (!scope || scope.regionId === "all" || resource.regionId === scope.regionId || resource.regionId === "all")
  ));
  if (scoped.length === 0) {
    return <EmptyState title={scopeMessages("emptyTitle")} description={scopeMessages("emptyHint")} />;
  }
  return (
    <Table aria-label={t("resourceTable")}>
        <thead>
          <tr>
            <th scope="col">{t("resource")}</th><th scope="col">{t("product")}</th>{compact ? null : <th scope="col">{t("project")}</th>}<th scope="col">{t("region")}</th><th scope="col">{t("state")}</th><th scope="col">{t("updated")}</th>
          </tr>
        </thead>
        <tbody>
          {scoped.map((resource) => (
            <tr key={resource.id}>
              <td><Link className={styles.resourceLink} href={resource.href}>{resource.name}</Link><small>{resource.id} · {resourceKinds(resource.kind)}</small></td>
              <td>{resource.productName}</td>
              {compact ? null : <td>{resource.projectName}</td>}
              <td>{resource.regionId === "all" ? t("globalRegion") : resource.regionName}</td>
              <td><Badge status={resource.status}>{t(`resourceStates.${resource.state}`)}</Badge></td>
              <td>{format.timestamp(resource.updatedAt)}</td>
            </tr>
          ))}
        </tbody>
      </Table>
  );
}

function OperationSummary({ operation }: { operation: OperationScene }) {
  const t = useTranslations("CloudExperience");
  const format = useConsoleFormat();
  return <>
    <span className={styles.operationMarker} data-status={operation.status} aria-hidden="true" />
    <div className={styles.operationMain}>
      <div className={styles.operationHeading}>
        <div><strong>{operation.action}</strong><span>{operation.target}</span></div>
        <Badge status={operation.status}>{t(`operationStates.${operation.state}`)}</Badge>
      </div>
      {operation.status === "info" ? <Progress aria-label={t("progressLabel", { name: operation.action })} max={100} value={operation.progress} /> : null}
      <div className={styles.operationMeta}>
        <span>{operation.productName}</span><span>{operation.actor}</span><span>{format.timestamp(operation.startedAt)}</span>
      </div>
    </div>
  </>;
}

function OperationList({ operations, compact = false }: { operations: OperationScene[]; compact?: boolean }) {
  const t = useTranslations("CloudExperience");
  const format = useConsoleFormat();
  if (operations.length === 0) {
    return <EmptyState title={t("operationsEmpty")} description={t("operationsEmptyHint")} />;
  }
  return (
    <div className={styles.operationList}>
      {operations.map((operation) => compact ? (
        <article className={styles.operationRow} key={operation.id}>
          <div className={styles.operationCompactSummary}><OperationSummary operation={operation} /></div>
        </article>
      ) : (
        <details className={styles.operationRow} key={operation.id}>
          <summary aria-label={t("operationSummary", { name: `${operation.action} · ${operation.target} · ${t(`operationStates.${operation.state}`)}` })} className={styles.operationSummary}>
            <OperationSummary operation={operation} />
            <span className={styles.operationDetailCue}>{t("details")}<ChevronDown aria-hidden="true" /></span>
          </summary>
          <div className={styles.operationDetails}>
            <Alert status={operation.status === "danger" ? "danger" : operation.status === "success" ? "success" : "info"}>{t(`guidance.${operation.state}`)}</Alert>
            <dl>
              <div><dt>{t("operationId")}</dt><dd><Typography.Code>{operation.id}</Typography.Code></dd></div>
              <div><dt>{t("progress")}</dt><dd>{format.number(operation.progress / 100, { style: "percent" })}</dd></div>
              <div><dt>{t("actor")}</dt><dd>{operation.actor}</dd></div>
              <div><dt>{t("owningProduct")}</dt><dd>{operation.productName}</dd></div>
              <div><dt>{t("target")}</dt><dd>{operation.target}</dd></div>
              <div><dt>{t("started")}</dt><dd>{format.timestamp(operation.startedAt)}</dd></div>
            </dl>
          </div>
        </details>
      ))}
    </div>
  );
}

function AlertList({ alerts }: { alerts: AlertScene[] }) {
  const t = useTranslations("Notifications");
  const format = useFormatter();
  if (alerts.length === 0) {
    return <EmptyState compact icon={<CheckCircle2 />} title={t("noAlerts")} />;
  }
  return (
    <div className={styles.alertList}>
      {alerts.map((alert) => (
        <article className={styles.alertRow} key={alert.id}>
          <span className={styles.alertIcon} data-status={alert.status}><AlertTriangle aria-hidden="true" /></span>
          <div><strong>{alert.title}</strong><span>{alert.serviceName} · {alert.owner} · {format.dateTime(new Date(alert.startedAt), { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZoneName: "short" })}</span></div>
          <Badge status={alert.status}>{t(`severities.${alert.severity}`)}</Badge>
        </article>
      ))}
    </div>
  );
}

function CloudOverview({ scene, scope }: {
  scene: Extract<ConsoleContentScene, { kind: "cloud-overview" }>;
  scope?: ResourceScope;
}) {
  const directory = useTranslations("ServiceDirectory");
  const t = useTranslations("CloudExperience");
  const setHeaderPanel = useConsoleUiStore((state) => state.setHeaderPanel);
  const ready = scene.regionCount > 0 && scene.readyRegions === scene.regionCount;
  return (
    <div className={styles.pageStack}>
      <section className={styles.welcomeCard}>
        <div>
          <Typography.Eyebrow>{t("welcomeEyebrow")}</Typography.Eyebrow>
          <Typography.Title as="h2" level={2}>{t("welcome")}</Typography.Title>
          <p>{t("runningSummary", { count: scene.metrics.find((item) => item.id === "active-operations")?.value ?? 0 })} {t("pendingSummary", { count: scene.metrics.find((item) => item.id === "active-alerts")?.value ?? 0 })}</p>
        </div>
        <div className={styles.quickActions}>
          <Button aria-haspopup="dialog" onClick={() => setHeaderPanel("products")}>{t("createResources")} <ArrowRight aria-hidden="true" /></Button>
          <Button asChild variant="secondary"><Link href="/console/resources/">{t("viewResources")}</Link></Button>
        </div>
      </section>

      <ConsoleMetrics metrics={scene.metrics} />

      <ContentLayout>
        <ContentLayout.Main>
          <Card>
            <Card.Header>
              <div><Typography.Title as="h2" level={3}>{directory("common")}</Typography.Title><Typography.Text tone="muted">{directory("commonHint")}</Typography.Text></div>
              <Button aria-haspopup="dialog" onClick={() => setHeaderPanel("products")} size="small" variant="ghost">{t("allProducts")} <ArrowRight aria-hidden="true" /></Button>
            </Card.Header>
            <Card.Body><CommonServiceLinks /></Card.Body>
          </Card>
          <Card>
            <Card.Header>
              <div><Typography.Title as="h2" level={3}>{t("recentResources")}</Typography.Title><Typography.Text tone="muted">{t("recentResourcesHint")}</Typography.Text></div>
              <Link className={styles.textLink} href="/console/resources/">{t("resourceCenter")} <ArrowRight aria-hidden="true" /></Link>
            </Card.Header>
            <ResourceTable compact resources={scene.recentResources} scope={scope} />
          </Card>
        </ContentLayout.Main>
        <ContentLayout.Aside>
          <Card>
            <Card.Header><div><Typography.Title as="h2" level={3}>{t("attention")}</Typography.Title><Typography.Text tone="muted">{t("attentionHint")}</Typography.Text></div></Card.Header>
            <Card.Body className={styles.attentionBody}>
              <AlertList alerts={scene.alerts} />
              <div className={styles.asideDivider} />
              <OperationList compact operations={scene.operations} />
            </Card.Body>
          </Card>
          <Card className={styles.readinessCard}>
            <Card.Body>
              <div className={styles.readinessTop}><span className={styles.readinessIcon}><CloudCog aria-hidden="true" /></span><Badge status={ready ? "success" : "warning"}>{t(ready ? "platformReady" : "platformAttention")}</Badge></div>
              <Typography.Title as="h3" level={3}>{t("regionCount", { count: scene.regionCount })}</Typography.Title>
              <p>{t("regionsReadyHint", { count: scene.readyRegions })}</p>
              <Link className={styles.textLink} href="/console/regions/">{t("viewRegionState")} <ArrowRight aria-hidden="true" /></Link>
            </Card.Body>
          </Card>
        </ContentLayout.Aside>
      </ContentLayout>
    </div>
  );
}

function Resources({ scene, scope }: {
  scene: Extract<ConsoleContentScene, { kind: "resources" }>;
  scope?: ResourceScope;
}) {
  const toolbarLabels = useTableToolbarLabels();
  const t = useTranslations("CloudExperience");
  const resourceKinds = useTranslations("GlobalSearch.resourceKinds");
  const [query, setQuery] = useState("");
  const resources = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return scene.resources.filter((item) => (!scope || scope.regionId === "all" || item.regionId === scope.regionId || item.regionId === "all") && (!normalized || [item.name, item.id, item.kind, resourceKinds(item.kind), t(`resourceStates.${item.state}`), item.productName, item.projectName, item.regionName]
      .some((value) => value.toLowerCase().includes(normalized))));
  }, [query, scene.resources, resourceKinds, t, scope]);
  return (
    <Card>
      <TableToolbar labels={toolbarLabels} search={{ label: t("searchResources"), placeholder: t("resourcesPlaceholder"), value: query, onChange: setQuery }} status={t("resultCount", { count: resources.length })} />
      <ResourceTable resources={resources} scope={scope} />
    </Card>
  );
}

function Operations({ scene }: { scene: Extract<ConsoleContentScene, { kind: "operations" }> }) {
  const t = useTranslations("CloudExperience");
  const toolbarLabels = useTableToolbarLabels();
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<"all" | OperationScene["state"]>("all");
  const operations = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return scene.operations.filter((operation) => (
      (status === "all" || operation.state === status) &&
      (!normalized || [operation.id, operation.action, operation.target, operation.productName, operation.actor, t(`operationStates.${operation.state}`)]
        .some((value) => value.toLowerCase().includes(normalized)))
    ));
  }, [query, scene.operations, status, t]);

  return (
    <Card>
      <TableToolbar labels={toolbarLabels} search={{ label: t("searchOperations"), placeholder: t("operationsPlaceholder"), value: query, onChange: setQuery }} filters={[{ id: "state", label: t("filterOperationState"), value: status, onChange: (value) => setStatus(value as typeof status), options: [{ value: "all", label: t("allStates") }, ...(["RUNNING", "FAILED", "SUCCEEDED"] as const).map((state) => ({ value: state, label: t(`operationStates.${state}`) }))] }]} status={t("resultCount", { count: operations.length })} tools={<Badge status="info">{t("runningCount", { count: scene.operations.filter((item) => item.state === "RUNNING").length })}</Badge>} />
      <Card.Body>
        {operations.length || scene.operations.length === 0 ? <OperationList operations={operations} /> : <EmptyState title={t("noMatchingOperations")} description={t("noMatchingOperationsHint")} />}
      </Card.Body>
    </Card>
  );
}

function DevOps({ scene }: { scene: Extract<ConsoleContentScene, { kind: "devops" }> }) {
  const t = useTranslations("CloudExperience");
  const format = useConsoleFormat();
  const environments = [...new Set(scene.pipelines.map((pipeline) => pipeline.environment))].map((name) => {
    const runs = scene.pipelines.filter((pipeline) => pipeline.environment === name);
    const status = runs.some((run) => run.state === "FAILED") ? "warning" : runs.some((run) => run.state === "RUNNING") ? "info" : "success";
    return { name, count: runs.length, status } as const;
  });
  if (scene.pipelines.length === 0) return <EmptyState title={t("pipelinesEmpty")} description={t("pipelinesEmptyHint")} />;
  return (
    <div className={styles.pageStack}>
      {!scene.view ? <ConsoleMetrics metrics={scene.metrics} /> : null}
      {scene.view !== "environments" ? <Card>
        <Card.Header>
          <div><Typography.Title as="h2" level={3}>{t("recentPipelines")}</Typography.Title><Typography.Text tone="muted">{t("pipelinesHint")}</Typography.Text></div>
          <span className={styles.headerHint}>{t("mockSnapshot")}</span>
        </Card.Header>
        <Table aria-label={t("pipelinesTable")}>
              <thead><tr><th scope="col">{t("pipeline")}</th><th scope="col">{t("code")}</th><th scope="col">{t("environment")}</th><th scope="col">{t("state")}</th><th scope="col">{t("duration")}</th><th scope="col">{t("triggered")}</th></tr></thead>
              <tbody>{scene.pipelines.map((pipeline) => (
                <tr key={pipeline.id}>
                  <td><strong>{pipeline.name}</strong><small>{pipeline.repository}</small></td>
                  <td><strong>{pipeline.branch}</strong><small>{pipeline.commit}</small></td>
                  <td>{pipeline.environment}</td><td><Badge status={pipeline.status}>{t(`operationStates.${pipeline.state}`)}</Badge></td><td>{format.duration(pipeline.durationSeconds)}</td><td>{format.timestamp(pipeline.triggeredAt)}</td>
                </tr>
              ))}</tbody>
            </Table>
      </Card> : null}
      {scene.view !== "pipelines" ? <section className={styles.deliveryGrid} aria-label={t("deliveryEnvironments")}>
        {environments.map((environment) => (
          <Card key={environment.name}><Card.Body className={styles.environmentCard}><span className={styles.environmentIcon}><Server aria-hidden="true" /></span><div><strong>{environment.name}</strong><span>{t("environmentRuns", { count: environment.count })}</span></div><Badge status={environment.status}>{t(environment.status === "success" ? "stable" : environment.status === "info" ? "deploying" : "needsAttention")}</Badge></Card.Body></Card>
        ))}
      </section> : null}
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
  const t = useTranslations("CloudExperience");
  const format = useFormatter();
  const health = <Card>
            <Card.Header><div><Typography.Title as="h2" level={3}>{t("serviceHealth")}</Typography.Title><Typography.Text tone="muted">{t("serviceHealthHint")}</Typography.Text></div><span className={styles.headerHint}>MOCK</span></Card.Header>
            <Card.Body className={styles.healthList}>
              {scene.services.length === 0 ? <EmptyState title={t("healthEmpty")} description={t("healthEmptyHint")} /> : null}
              {scene.services.map((service) => (
                <article className={styles.healthRow} key={service.id}>
                  <div className={styles.healthIdentity}><span className={styles.serviceIcon}><Server aria-hidden="true" /></span><div><strong>{service.name}</strong><span>{service.productName}</span></div></div>
                  <Trend label={t("healthTrend", { name: service.name })} values={service.trend} />
                  <dl className={styles.healthFacts}><div><dt>{t("availability")}</dt><dd>{format.number(service.availability, { style: "percent", maximumFractionDigits: 2 })}</dd></div><div><dt>{t("latency")}</dt><dd>{format.number(service.latencyMs)} ms</dd></div><div><dt>{t("errorRate")}</dt><dd>{format.number(service.errorRate, { style: "percent", maximumFractionDigits: 2 })}</dd></div></dl>
                  <Badge status={service.status}>{t(`resourceStates.${service.state}`)}</Badge>
                </article>
              ))}
            </Card.Body>
          </Card>;
  const alerts = <Card>
            <Card.Header><div><Typography.Title as="h2" level={3}>{t("currentAlerts")}</Typography.Title><Typography.Text tone="muted">{t("alertsHint")}</Typography.Text></div></Card.Header>
            <Card.Body><AlertList alerts={scene.alerts} /></Card.Body>
          </Card>;
  if (scene.view === "health") return health;
  if (scene.view === "alerts") return alerts;
  return <div className={styles.pageStack}>
    <ConsoleMetrics metrics={scene.metrics} />
    <ContentLayout>
      <ContentLayout.Main>{health}</ContentLayout.Main>
      <ContentLayout.Aside>
        {alerts}
        {scene.services.length > 0 ? <Card className={styles.signalCard}><Card.Body><span className={styles.signalIcon}><Database aria-hidden="true" /></span><div><strong>{t("collectionHealthy")}</strong><span>{t("collectionHint")}</span></div><Badge status="success">{t("resourceStates.HEALTHY")}</Badge></Card.Body></Card> : null}
      </ContentLayout.Aside>
    </ContentLayout>
  </div>;
}

export function ExperienceContentRenderer({ scene, scope }: {
  scene: Extract<ConsoleContentScene, { kind: "cloud-overview" | "resources" | "operations" | "devops" | "observability" }>;
  scope?: ResourceScope;
}) {
  if (scene.kind === "cloud-overview") return <CloudOverview scene={scene} scope={scope} />;
  if (scene.kind === "resources") return <Resources scene={scene} scope={scope} />;
  if (scene.kind === "operations") return <Operations scene={scene} />;
  if (scene.kind === "devops") return <DevOps scene={scene} />;
  return <Observability scene={scene} />;
}
