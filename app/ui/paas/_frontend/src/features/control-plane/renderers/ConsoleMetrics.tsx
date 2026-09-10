"use client";

import { useFormatter, useTranslations } from "next-intl";
import { Activity, AlertTriangle, Boxes, ChartNoAxesCombined, CheckCircle2, Database, Gauge, GitBranch, MapPin, PackageSearch, Server, Workflow } from "lucide-react";
import { Statistic } from "@ui/xiak";
import type { MetricScene } from "../scenes/consoleScene";
import styles from "./ConsoleMetrics.module.css";

const icons: Record<MetricScene["id"], typeof Boxes> = {
  offerings: PackageSearch, quota: Gauge, services: Database, regions: MapPin,
  "all-resources": Boxes, "healthy-resources": CheckCircle2,
  "active-operations": Activity, "active-alerts": AlertTriangle,
  "pipeline-success": CheckCircle2, "pipeline-running": Workflow,
  "lead-time": Activity, "deployment-frequency": GitBranch,
  "service-health": Server, availability: CheckCircle2,
  "alert-firing": AlertTriangle, ingestion: ChartNoAxesCombined
};

export function ConsoleMetrics({ metrics }: { metrics: MetricScene[] }) {
  const t = useTranslations("ConsoleMetrics");
  const format = useFormatter();
  return <section aria-label={t("label")} className={styles.grid}>
    {metrics.map((metric) => {
      const Icon = icons[metric.id];
      const value = metric.id === "pipeline-success" || metric.id === "availability"
        ? format.number(metric.value, { style: "percent", maximumFractionDigits: 2 })
        : metric.id === "lead-time"
          ? format.number(metric.value, { style: "unit", unit: "minute", unitDisplay: "short" })
          : metric.id === "ingestion" ? `${format.number(metric.value)} GB/h` : format.number(metric.value);
      return <Statistic key={metric.id} label={t(`items.${metric.id}.label`)} value={value}
        hint={t(`items.${metric.id}.hint`, { count: metric.detailCount ?? 0 })} status={metric.status} icon={<Icon />} />;
    })}
  </section>;
}
