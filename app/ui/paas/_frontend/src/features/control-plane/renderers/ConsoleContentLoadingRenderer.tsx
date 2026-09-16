"use client";

import { useTranslations } from "next-intl";
import { Card, PageSkeleton, TableSkeleton, Typography } from "@ui/xiak";
import type { ControlPlaneRouteSelection } from "../domain/selection";
import styles from "./ConsoleContentLoadingRenderer.module.css";

function DataPanel({ description, label, title }: { description?: string; label: string; title: string }) {
  return <Card>
    <Card.Header>
      <div>
        <Typography.Title as="h2" level={3}>{title}</Typography.Title>
        {description ? <Typography.Text tone="muted">{description}</Typography.Text> : null}
      </div>
    </Card.Header>
    <TableSkeleton header={false} label={label} labelVisible={false} rows={5} />
  </Card>;
}

// Route identity and stable page chrome render synchronously. Only the region
// whose rows/cards still depend on a provider uses delayed placeholder paint.
export function ConsoleContentLoadingRenderer({ label, selection }: { label: string; selection: ControlPlaneRouteSelection }) {
  const managed = useTranslations("ManagedService");
  const cloud = useTranslations("CloudExperience");
  const logs = useTranslations("LogService");
  const navigation = useTranslations("ServiceNavigation");
  const { section, view } = selection;

  if (section === "installations") {
    return <DataPanel description={managed("installationStateHint")} label={label} title={managed("organizationInstances")} />;
  }
  if (section === "applications" || section === "resources") {
    return <DataPanel label={label} title={cloud("resourceTable")} />;
  }
  if (section === "operations") {
    return <DataPanel label={label} title={navigation("items.operations.label")} />;
  }
  if (section === "messages") {
    return <DataPanel label={label} title={navigation("items.messages.label")} />;
  }
  if (section === "devops") {
    if (view === "environments") return <PageSkeleton label={label} labelVisible={false} layout="cards" />;
    return <DataPanel description={cloud("pipelinesHint")} label={label} title={cloud("recentPipelines")} />;
  }
  if (section === "observability") {
    const alerts = view === "alerts";
    return <DataPanel description={cloud(alerts ? "alertsHint" : "serviceHealthHint")} label={label} title={cloud(alerts ? "currentAlerts" : "serviceHealth")} />;
  }
  if (section === "logs") {
    if (view === "topics" || view === "collection") {
      const collection = view === "collection";
      return <DataPanel description={logs(collection ? "collectionHint" : "topicsHint")} label={label} title={logs(collection ? "collectionTitle" : "topicsTitle")} />;
    }
    if (view === "search") return <PageSkeleton label={label} labelVisible={false} layout="table" />;
    return <div className={styles.stack}>
      <section className={styles.identity}>
        <div>
          <Typography.Eyebrow>Matrix · Log Service</Typography.Eyebrow>
          <Typography.Title as="h2" level={2}>{logs("overviewTitle")}</Typography.Title>
          <p>{logs("overviewHint")}</p>
        </div>
      </section>
      <DataPanel description={logs("recentHint")} label={label} title={logs("recent")} />
    </div>;
  }
  if (section === "catalog" || section === "quotas" || section === "regions") {
    return <PageSkeleton label={label} labelVisible={false} layout="cards" />;
  }
  return <PageSkeleton label={label} labelVisible={false} layout={section === "overview" ? "dashboard" : "table"} />;
}
