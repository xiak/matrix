"use client";

import { useId } from "react";
import { useTranslations } from "next-intl";
import { Badge } from "@ui/xiak";
import styles from "./ServiceAuthorizationChain.module.css";

type BoundaryState = {
  label: string;
  tone?: "neutral" | "success" | "warning" | "danger";
};

/**
 * Shared information boundary for public-cloud service authorization.
 * A template, an account relation, and an exact workload binding are separate
 * facts; callers supply observed labels only and this component never derives
 * a later state from an earlier one.
 */
export function ServiceAuthorizationChain({ template, account, binding }: {
  template: BoundaryState;
  account: BoundaryState;
  binding: BoundaryState;
}) {
  const t = useTranslations("ServiceAuthorizationChain");
  const titleId = useId();
  const stages = [
    { id: "template", state: template },
    { id: "account", state: account },
    { id: "binding", state: binding }
  ] as const;

  return <section className={styles.root} aria-labelledby={titleId}>
    <div className={styles.heading}>
      <h3 id={titleId}>{t("title")}</h3>
      <p>{t("hint")}</p>
    </div>
    <ol className={styles.stages}>
      {stages.map(({ id, state }, index) => <li key={id}>
        <span className={styles.index} aria-hidden="true">{index + 1}</span>
        <div className={styles.copy}>
          <strong>{t(`${id}.title`)}</strong>
          <small>{t(`${id}.hint`)}</small>
        </div>
        <Badge status={state.tone ?? "neutral"}>{state.label}</Badge>
      </li>)}
    </ol>
  </section>;
}
