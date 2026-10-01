"use client";

import { useTranslations } from "next-intl";
import { Card, CardGridSkeleton, TableSkeleton, Typography } from "@ui/xiak";
import type { ControlPlaneRouteSelection } from "../domain/selection";
import styles from "./ConsoleContentLoadingRenderer.module.css";

function DataPanel({ description, label, title }: { description?: string; label: string; title: string }) {
  return <Card aria-label={title}>
    <Card.Header>
      <div>
        <Typography.Title as="h2" level={3}>{title}</Typography.Title>
        {description ? <Typography.Text tone="muted">{description}</Typography.Text> : null}
      </div>
    </Card.Header>
    <TableSkeleton header={false} label={label} labelVisible={false} rows={5} />
  </Card>;
}

function CardCollection({ label, title }: { label: string; title: string }) {
  return <section aria-label={title}><CardGridSkeleton cards={3} label={label} labelVisible={false} /></section>;
}

function TableRegion({ label, title }: { label: string; title: string }) {
  return <Card aria-label={title}><TableSkeleton header={false} label={label} labelVisible={false} rows={5} /></Card>;
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
    if (view === "environments") return <CardCollection label={label} title={cloud("deliveryEnvironments")} />;
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
    if (view === "search") return <TableRegion label={label} title={navigation("items.search.label")} />;
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
  if (section === "audit") return <DataPanel description={navigation("items.audit.hint")} label={label} title={navigation("items.audit.label")} />;
  if (section === "catalog" || section === "quotas" || section === "regions") {
    return <CardCollection label={label} title={navigation(`items.${section}.label`)} />;
  }
  if (section === "overview") return <DataPanel description={managed("recentHint")} label={label} title={managed("recentInstances")} />;
  const item = section === "access" && !view ? "access" : view ?? section;
  return <TableRegion label={label} title={navigation(`items.${item}.label`)} />;
}
