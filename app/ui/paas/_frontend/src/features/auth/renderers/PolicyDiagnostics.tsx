"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { Badge, Button, Tabs } from "@ui/xiak";
import type { PolicyDiagnostic } from "../domain/policyDocument";
import styles from "./PolicyWorkspace.module.css";

export function PolicyDiagnostics({ diagnostics, pristine, onLocate }: {
  diagnostics: readonly PolicyDiagnostic[]; pristine: boolean; onLocate(path: string): void;
}) {
  const t = useTranslations("PolicyWorkspace"), w = useTranslations("IamWorkspace");
  const [selected, setSelected] = useState<string>();
  const severities = ["error", "warning", "suggestion"] as const;
  const active = selected ?? severities.find((severity) => diagnostics.some((entry) => entry.severity === severity)) ?? "error";
  return <section className={styles.diagnostics} aria-label={t("analyzer")}>
    <strong>{t("analyzer")}</strong><p className={styles.note}>{t("analyzerHint")}</p>
    {pristine ? <p className={styles.note}>{t("analysisPending")}</p> : <Tabs.Root value={active} onValueChange={setSelected}>
      <Tabs.List aria-label={t("analyzer")}>{severities.map((severity) => <Tabs.Trigger key={severity} value={severity}>{t(severity)} <Badge>{diagnostics.filter((entry) => entry.severity === severity).length}</Badge></Tabs.Trigger>)}</Tabs.List>
      {severities.map((severity) => <Tabs.Content key={severity} value={severity}><ul className={styles.diagnosticList}>
        {diagnostics.filter((entry) => entry.severity === severity).map((entry) => <li key={entry.path + entry.code}>
          <span>{entry.severity === "error" ? w(`errors.${entry.code}`) : t(entry.code)}</span>
          <Button variant="ghost" size="small" aria-label={t("locate", { path: entry.path })} onClick={() => onLocate(entry.path)}><code>{entry.path}</code></Button>
        </li>)}
      </ul>{!diagnostics.some((entry) => entry.severity === severity) ? <p className={styles.note}>{severity === "error" ? t("analysisPassed") : t("diagnosticCount", { count: 0 })}</p> : null}</Tabs.Content>)}
    </Tabs.Root>}
  </section>;
}
