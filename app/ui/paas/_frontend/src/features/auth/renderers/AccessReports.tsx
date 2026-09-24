"use client";

import { useState } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { ArrowRight } from "lucide-react";
import { ActionMenu, Alert, Badge, Button, Card, Typography } from "@ui/xiak";
import type { AccountAccessView } from "../domain/accounts";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { SessionSummary } from "../domain/session";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { buildAccessActivityObservations, buildAccessReport, buildAccessSecuritySnapshot, type AccessSecurityCheckState } from "../scenes/accessReport";
import styles from "./AccountAccessRenderer.module.css";

const badgeStatus: Record<AccessSecurityCheckState, "warning" | "success" | "neutral" | "info"> = {
  review: "warning",
  configured: "success",
  notApplicable: "neutral",
  unknown: "info"
};

export function AccessReports({ workspace, scene, currentSession = null, onNavigate }: {
  workspace: AccessWorkspace;
  scene: AccountAccessScene;
  currentSession?: SessionSummary | null;
  onNavigate(view: AccountAccessView): void;
}) {
  const t = useTranslations("IamWorkspace");
  const format = useFormatter();
  const [failed, setFailed] = useState(false);
  const snapshot = buildAccessSecuritySnapshot(workspace, scene.directoryComplete);
  const scopedSession = currentSession?.principalId === scene.currentUserId ? currentSession : null;
  const activity = buildAccessActivityObservations(workspace, scopedSession);

  function download(kind: "credentials" | "security") {
    try {
      const report = buildAccessReport(kind, workspace, scene, new Date().toISOString(), scopedSession);
      const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `matrix-mock-${kind}-report.json`;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }

  return <Card>
    <Card.Header>
      <Typography.Title as="h2" level={3}>{t("securityOverview")}</Typography.Title>
      <Badge status="info">{t("mockEvidence")}</Badge>
    </Card.Header>
    <Card.Body className={styles.securityReportBody}>
      <p className={styles.note}>{t("securityOverviewHint")}</p>
      <dl className={styles.securityReportSummary} aria-label={t("securityStatusSummary")}>
        {(["review", "configured", "unknown", "notApplicable"] as const).map((state) => <div key={state}>
          <dt>{t(`securityStates.${state}`)}</dt>
          <dd>{snapshot.counts[state]}</dd>
        </div>)}
      </dl>
      <div className={styles.securityEvidenceHeading}>
        <strong>{t("securityEvidenceCoverage")}</strong>
        <span>{t("securityEvidenceHint")}</span>
      </div>
      <dl className={styles.securityReportSummary} aria-label={t("securityEvidenceStatusSummary")}>
        {(["observed", "incomplete", "unobserved", "notApplicable"] as const).map((state) => <div key={state}>
          <dt>{t(`securityEvidenceStates.${state}`)}</dt>
          <dd>{snapshot.evidenceCounts[state]}</dd>
        </div>)}
      </dl>
      <ul className={styles.securityChecks}>
        {snapshot.checks.map((check) => {
          const title = t(`securityChecks.${check.id}.title`);
          return <li key={check.id}>
            <div className={styles.securityCheckCopy}>
              <div className={styles.securityCheckHeading}>
                <strong>{title}</strong>
                <Badge status={badgeStatus[check.state]}>{t(`securityStates.${check.state}`)}</Badge>
              </div>
              <p>{t(`securityChecks.${check.id}.hint`, { count: check.count ?? 0 })}</p>
              <span className={styles.securityEvidenceState}>{t("securityEvidenceLabel")}: {t(`securityEvidenceStates.${check.evidence}`)}</span>
            </div>
            {check.target ? <Button aria-label={t("reviewSecurityCheck", { name: title })} size="small" variant="ghost" onClick={() => onNavigate(check.target!)}>
              {t("view")}<ArrowRight aria-hidden="true" />
            </Button> : null}
          </li>;
        })}
      </ul>
      <div className={styles.securityEvidenceHeading}>
        <strong>{t("activityEvidenceTitle")}</strong>
        <span>{t("activityEvidenceHint")}</span>
      </div>
      <dl className={styles.activityEvidence} aria-label={t("activityEvidenceTitle")}>
        {activity.map((observation) => <div key={observation.id}>
          <dt>{t(`activityObservations.${observation.id}.title`)}</dt>
          <dd><Badge status={observation.state === "observed" ? "info" : "neutral"}>{t(`activityStates.${observation.state}`)}</Badge>
            <span>{t(`activityObservations.${observation.id}.${observation.state}`, {
              time: observation.occurredAt ? format.dateTime(new Date(observation.occurredAt), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : ""
            })}</span>
          </dd>
        </div>)}
      </dl>
      <p className={styles.note}>{t("activityCoverageHint", { accountId: workspace.accountId })}</p>
      {failed ? <Alert status="danger">{t("errors.unavailable")}</Alert> : null}
    </Card.Body>
    <Card.Footer>
      <p className={styles.note}>{t("reportHint")}</p>
      <ActionMenu label={t("exportReports")} actions={[
        { id: "credentials", label: t("credentialReport"), onSelect: () => download("credentials") },
        { id: "security", label: t("securityReport"), onSelect: () => download("security") }
      ]} />
    </Card.Footer>
  </Card>;
}
