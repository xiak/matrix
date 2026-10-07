"use client";

import { useId, type ReactNode } from "react";
import { useTranslations } from "next-intl";
import { Badge } from "@ui/xiak";
import styles from "./AuthorizationOwnershipFlow.module.css";

type OwnershipStatus = "info" | "warning" | "success" | "neutral";

export type AuthorizationOwnershipStep = {
  id: string;
  badge: string;
  title: string;
  hint: string;
  status?: OwnershipStatus;
  action?: ReactNode;
};

/**
 * Shared ownership boundary for product declarations, IAM publication and
 * tenant consumption. It deliberately renders no command on its own.
 */
export function AuthorizationOwnershipFlow({ title, hint, steps }: {
  title: string;
  hint: string;
  steps: AuthorizationOwnershipStep[];
}) {
  const titleId = useId();

  return <section aria-labelledby={titleId} className={styles.root}>
    <div className={styles.heading}>
      <h3 id={titleId}>{title}</h3>
      <p>{hint}</p>
    </div>
    <ol className={styles.stages}>
      {steps.map((step, index) => <li key={step.id}>
        <span className={styles.index} aria-hidden="true">{index + 1}</span>
        <div className={styles.copy}>
          <strong>{step.title}</strong>
          <small>{step.hint}</small>
          {step.action ? <div className={styles.action}>{step.action}</div> : null}
        </div>
        <Badge status={step.status ?? "neutral"}>{step.badge}</Badge>
      </li>)}
    </ol>
  </section>;
}

export function ServiceAuthorizationResponsibility() {
  const t = useTranslations("ServiceAuthorizationPreview.directory.responsibility");
  const owners = ["product", "iam", "tenant"] as const;
  return <AuthorizationOwnershipFlow
    title={t("title")}
    hint={t("hint")}
    steps={owners.map((owner) => ({
      id: owner,
      badge: t(`${owner}.state`),
      title: t(`${owner}.title`),
      hint: t(`${owner}.hint`)
    }))}
  />;
}
