"use client";

import { useId } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge } from "@ui/xiak";
import styles from "./PolicyAuthoringWizard.module.css";

const stages = ["resourceFacts", "policyConditions", "requestTagChanges", "metadataTags"] as const;

/**
 * Keeps tag-based policy authoring honest about which labels are authorization
 * facts. This is shown while editing and again at review because a resource-tag
 * mutation can change future access even when the policy document is unchanged.
 */
export function PolicyTagAuthorizationBoundary() {
  const t = useTranslations("PolicyWizard");
  const titleId = useId();
  return <section className={styles.tagBoundary} aria-labelledby={titleId}>
    <div className={styles.tagBoundaryHeading}>
      <h3 id={titleId}>{t("tagBoundary.title")}</h3>
      <p>{t("tagBoundary.hint")}</p>
    </div>
    <ol className={styles.tagBoundaryStages}>
      {stages.map((stage, index) => <li key={stage} className={styles.tagBoundaryStage}>
        <span className={styles.coverageNumber} aria-hidden="true">{index + 1}</span>
        <div>
          <div className={styles.tagBoundaryStageHeading}>
            <strong>{t(`tagBoundary.stages.${stage}.title`)}</strong>
            <Badge status={stage === "requestTagChanges" ? "warning" : stage === "metadataTags" ? undefined : "success"}>{t(`tagBoundary.stages.${stage}.state`)}</Badge>
          </div>
          <p>{t(`tagBoundary.stages.${stage}.hint`)}</p>
        </div>
      </li>)}
    </ol>
    <p className={styles.tagBoundaryFailClosed}>{t("tagBoundary.failClosed")}</p>
    <Alert status="warning">{t("tagBoundary.mutationWarning")}</Alert>
  </section>;
}
