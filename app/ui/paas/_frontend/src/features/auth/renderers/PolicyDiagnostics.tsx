"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { Badge, Button, Tabs } from "@ui/xiak";
import type { PolicyDiagnostic } from "../domain/policyDocument";
import styles from "./PolicyWorkspace.module.css";

const severityTabs = [
  { id: "security-warning", label: "securityWarning", status: "warning" },
  { id: "error", label: "error", status: "danger" },
  { id: "warning", label: "warning", status: "warning" },
  { id: "suggestion", label: "suggestion", status: "info" }
] as const;
type Severity = (typeof severityTabs)[number]["id"];
const severityPriority: Severity[] = ["error", "security-warning", "warning", "suggestion"];

export function PolicyDiagnostics({ diagnostics, pristine, onLocate }: {
  diagnostics: readonly PolicyDiagnostic[]; pristine: boolean; onLocate(path: string): void;
}) {
  const t = useTranslations("PolicyWorkspace"), w = useTranslations("IamWorkspace");
  const [selected, setSelected] = useState<Severity>();
  const active = selected ?? severityPriority.find((severity) => diagnostics.some((entry) => entry.severity === severity)) ?? "error";
  return <section className={styles.diagnostics} aria-label={t("analyzer")}>
    <strong>{t("analyzer")}</strong><p className={styles.note}>{t("analyzerHint")}</p>
    {pristine ? <p className={styles.note}>{t("analysisPending")}</p> : <Tabs.Root value={active} onValueChange={(value) => setSelected(value as Severity)}>
      <Tabs.List aria-label={t("analyzer")} className={styles.diagnosticTabs}>{severityTabs.map((severity) => <Tabs.Trigger key={severity.id} value={severity.id}>{t(severity.label)} <Badge status={severity.status}>{diagnostics.filter((entry) => entry.severity === severity.id).length}</Badge></Tabs.Trigger>)}</Tabs.List>
      {severityTabs.map((severity) => <Tabs.Content key={severity.id} value={severity.id}>
        <p className={styles.severityHint}>{t(`severityHints.${severity.label}`)}</p>
        <ul className={styles.diagnosticList}>
        {diagnostics.filter((entry) => entry.severity === severity.id).map((entry) => <li key={entry.path + entry.code}>
          <span>{entry.severity === "error" ? w(`errors.${entry.code}`) : t(entry.code)}</span>
          <Button variant="ghost" size="small" aria-label={t("locate", { path: entry.path })} onClick={() => onLocate(entry.path)}><code>{entry.path}</code></Button>
        </li>)}
      </ul>{!diagnostics.some((entry) => entry.severity === severity.id) ? <p className={styles.note}>{severity.id === "error" ? t("analysisPassed") : t("diagnosticCount", { count: 0 })}</p> : null}</Tabs.Content>)}
    </Tabs.Root>}
  </section>;
}
