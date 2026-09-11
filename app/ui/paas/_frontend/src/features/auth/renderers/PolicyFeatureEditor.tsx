"use client";

import { useMemo, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Checkbox, SearchInput } from "@ui/xiak";
import { policyActions, policyServices } from "../domain/policyLanguage";
import type { PolicyDocument } from "../domain/policyDocument";
import styles from "./PolicyAuthoringWizard.module.css";

export function canEditPolicyFeatures(document: PolicyDocument) {
  // A convenience editor must never erase Deny, conditions, specific resources,
  // or wildcard expressions whose future meaning differs from explicit actions.
  return document.statement.every((statement) => statement.effect === "allow" && !statement.condition &&
    statement.resource.length === 1 && statement.resource[0] === "*" &&
    statement.action.every((id) => policyActions.some((action) => action.id === id)));
}

/** Product/function selection projects into the existing statement contract. */
export function PolicyFeatureEditor({ document, onChange }: { document: PolicyDocument; onChange(document: PolicyDocument): void }) {
  const t = useTranslations("PolicyWizard"), r = useTranslations("PolicyRules");
  const [query, setQuery] = useState("");
  const selected = new Set(document.statement.flatMap((statement) => statement.action));
  const products = useMemo(() => {
    const words = query.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean);
    return policyServices.flatMap((service) => {
      const actions = policyActions.filter((action) => action.service === service && words.every((word) =>
        `${r(`services.${service}`)} ${r(`actionNames.${action.id}`)} ${action.id}`.normalize("NFKC").toLowerCase().includes(word)));
      return actions.length ? [{ service, actions }] : [];
    });
  }, [query, r]);
  function select(ids: string[], checked: boolean) {
    const next = new Set(selected);
    for (const id of ids) { if (checked) next.add(id); else next.delete(id); }
    const statement: PolicyDocument["statement"] = policyServices.flatMap((service) => {
      const action = policyActions.filter((entry) => entry.service === service && next.has(entry.id)).map((entry) => entry.id);
      return action.length ? [{ effect: "allow" as const, action, resource: ["*"] }] : [];
    });
    onChange({ version: "1", statement });
  }
  return <div className={styles.stack}>
    <Alert>{t("featureScopeHint")}</Alert>
    <SearchInput aria-label={t("featureSearch")} placeholder={t("featureSearch")} value={query} onChange={(event) => setQuery(event.target.value)} />
    <p className={styles.note}>{r("selectedActions", { count: selected.size })}</p>
    <div className={styles.featureGrid}>
      {products.map(({ service, actions }) => {
        const all = actions.every((action) => selected.has(action.id));
        return <section className={styles.featureSection} key={service} aria-label={r(`services.${service}`)}>
          <header><Checkbox checked={all} aria-checked={all ? true : actions.some((action) => selected.has(action.id)) ? "mixed" : false} ref={(input) => { if (input) input.indeterminate = !all && actions.some((action) => selected.has(action.id)); }} onChange={(event) => select(actions.map((action) => action.id), event.target.checked)}>{r(`services.${service}`)}</Checkbox></header>
          {actions.map((action) => <Checkbox key={action.id} checked={selected.has(action.id)} onChange={(event) => select([action.id], event.target.checked)}>
            <span className={styles.featureCopy}><span>{r(`actionNames.${action.id}`)}</span><small>{r(`actionDescriptions.${action.id}`)}</small></span>
          </Checkbox>)}
        </section>;
      })}
    </div>
    {!products.length ? <p className={styles.note}>{r("noActions")}</p> : null}
  </div>;
}
