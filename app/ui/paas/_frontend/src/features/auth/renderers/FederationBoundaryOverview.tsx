"use client";

import { useId } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge } from "@ui/xiak";
import styles from "./AccountAccessRenderer.module.css";

export type FederationBoundaryFocus = "provider" | "user" | "role";

const modes = ["provider", "user", "role"] as const;

/**
 * Shared read-only projection of the federation boundary. It deliberately
 * separates protocol trust, User sign-in and Role session issuance without
 * defining an IdentityProvider wire contract or a writable lifecycle.
 */
export function FederationBoundaryOverview({ current }: { current: FederationBoundaryFocus }) {
  const t = useTranslations("IamWorkspace.federationBoundary");
  const titleId = useId();

  return <section aria-labelledby={titleId} className={styles.federationBoundary}>
    <div className={styles.federationBoundaryHeading}>
      <div>
        <h2 id={titleId}>{t("title")}</h2>
        <p>{t("hint")}</p>
      </div>
      <Badge status="warning">{t("state")}</Badge>
    </div>
    <Alert status="info">{t("boundary")}</Alert>
    <div className={styles.federationModes}>
      {modes.map((mode) => {
        const headingId = `${titleId}-${mode}`;
        const selected = current === mode;
        return <article aria-current={selected ? "step" : undefined} aria-labelledby={headingId} className={styles.federationMode} key={mode}>
          <div className={styles.federationModeHeading}>
            <strong id={headingId}>{t(`modes.${mode}.title`)}</strong>
            <Badge status={selected ? "info" : "neutral"}>{t(selected ? "current" : "concept")}</Badge>
          </div>
          <p>{t(`modes.${mode}.description`)}</p>
          <dl>
            <div><dt>{t("input")}</dt><dd>{t(`modes.${mode}.input`)}</dd></div>
            <div><dt>{t("result")}</dt><dd>{t(`modes.${mode}.result`)}</dd></div>
            <div><dt>{t("authorization")}</dt><dd>{t(`modes.${mode}.authorization`)}</dd></div>
          </dl>
        </article>;
      })}
    </div>
  </section>;
}
