"use client";

import { useId } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Typography } from "@ui/xiak";
import {
  accessFindingRecoveryState,
  hasAccessRecoveryGap,
  type AccessFindingRecoveryEvidence,
  type AccessObservationCoverage
} from "../domain/accessAnalysis";
import { WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

type EvidenceSource = "live" | "mock";

export function AccessFindingRecoveryBoundary({ evidence, source }: {
  evidence: AccessFindingRecoveryEvidence;
  source: EvidenceSource;
}) {
  const t = useTranslations("IamWorkspace.accessAnalysis.recovery");
  const titleId = useId();
  const state = accessFindingRecoveryState(evidence);
  return <section aria-labelledby={titleId} className={styles.stack}>
    <div className={styles.securityCheckHeading}>
      <Typography.Title as="h3" id={titleId} level={3}>{t("title")}</Typography.Title>
      <Badge status={state === "POST_RECOVERY" ? "warning" : "neutral"}>{t(`states.${state}`)}</Badge>
    </div>
    <dl className={styles.facts}>
      <div><dt>{t("epoch")}</dt><dd>{evidence.recoveryEpoch}</dd></div>
      <div><dt>{t("windowStartedAt")}</dt><dd><WorkspaceTime value={evidence.windowStartedAt} /></dd></div>
      {state === "POST_RECOVERY" ? <>
        <div><dt>{t("commandId")}</dt><dd><code>{evidence.recoveryCommandId}</code></dd></div>
        <div><dt>{t("completedAt")}</dt><dd><WorkspaceTime value={evidence.recoveryCompletedAt!} /></dd></div>
      </> : null}
    </dl>
    <Alert status={state === "POST_RECOVERY" ? "warning" : "info"}>{t(state === "POST_RECOVERY" ? `${source}PostRecoveryBoundary` : "baselineBoundary")}</Alert>
  </section>;
}

export function AccessRecoveryGapBoundary({ coverage }: { coverage: readonly AccessObservationCoverage[] }) {
  const t = useTranslations("IamWorkspace.accessAnalysis.recovery");
  if (!hasAccessRecoveryGap(coverage)) return null;
  return <Alert status="warning"><div className={styles.confirmation}><strong>{t("gapTitle")}</strong><span>{t("gapBoundary")}</span></div></Alert>;
}
