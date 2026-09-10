"use client";

import { useTranslations } from "next-intl";
import { Badge } from "@ui/xiak";
import { policyStatementKey, type PolicyDocument } from "../domain/policyDocument";
import { ConditionSummary, PolicyActionsSummary, PolicyResourcesSummary } from "./PolicyDocumentViewer";
import styles from "./PolicyWorkspace.module.css";

export function PolicyDocumentChanges({ before, after }: { before: PolicyDocument; after: PolicyDocument }) {
  const t = useTranslations("PolicyWorkspace"), w = useTranslations("IamWorkspace");
  const oldKeys = new Set(before.statement.map(policyStatementKey)), newKeys = new Set(after.statement.map(policyStatementKey));
  const removed = before.statement.filter((statement) => !newKeys.has(policyStatementKey(statement)));
  const added = after.statement.filter((statement) => !oldKeys.has(policyStatementKey(statement)));
  return <section className={styles.reviewSection} aria-label={t("changes")}><h3>{t("changes")}</h3><p className={styles.note}>{t("diffHint")}</p>
    {!removed.length && !added.length ? <p>{t("noStatementChanges")}</p> : <div className={styles.changeColumns}>{([{ key: "removedStatements", statements: removed }, { key: "addedStatements", statements: added }] as const).map(({ key, statements }) => statements.length ?
      <section key={key} className={styles.reviewSection} aria-label={t(key)}><h3>{t(key)} · {statements.length}</h3>{statements.map((statement, index) => <div className={styles.stack} key={index}>
        <Badge className={styles.effectBadge} status={statement.effect === "deny" ? "danger" : "success"}>{w(statement.effect)}</Badge>
        <PolicyActionsSummary actions={statement.action} /><PolicyResourcesSummary resources={statement.resource} /><ConditionSummary value={statement.condition} />
      </div>)}</section> : null)}</div>}
  </section>;
}
