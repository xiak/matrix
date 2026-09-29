"use client";

import { useState, type RefObject } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { ArrowRight } from "lucide-react";
import { ActionMenu, Alert, Badge, Button, Card, Typography } from "@ui/xiak";
import type { AccountAccessView } from "../domain/accounts";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { SessionSummary } from "../domain/session";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { buildAccessActivityObservations, buildAccessReport, buildAccessSecuritySnapshot, buildUnusedAccessFindingPreview, type AccessSecurityCheckState, type UnusedAccessFindingPreview } from "../scenes/accessReport";
import { WorkspaceCollection, WorkspaceDetail, WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

const badgeStatus: Record<AccessSecurityCheckState, "warning" | "success" | "neutral" | "info"> = {
  review: "warning",
  configured: "success",
  notApplicable: "neutral",
  unknown: "info"
};

const findingStatus: Record<UnusedAccessFindingPreview["status"], "warning" | "neutral" | "success"> = {
  active: "warning",
  archived: "neutral",
  resolved: "success"
};

export function UnusedAccessReviewPreview({ workspace, scene, onBack, onNavigate }: {
  workspace: AccessWorkspace;
  scene: AccountAccessScene;
  onBack(): void;
  onNavigate(view: AccountAccessView, id?: string): void;
}) {
  const t = useTranslations("IamWorkspace.unusedAccessReview");
  const [selected, setSelected] = useState<UnusedAccessFindingPreview | null>(null);
  const findings = buildUnusedAccessFindingPreview(workspace, scene);
  if (selected) return <WorkspaceDetail key={selected.id} title={t("detailTitle", { name: selected.name })} onBack={() => setSelected(null)}>
    <Alert status="info">{t("sampleEvidence")}</Alert>
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{selected.name}</Typography.Title><Typography.Text tone="muted">{selected.subjectId}</Typography.Text></div><Badge status={findingStatus[selected.status]}>{t(`statuses.${selected.status}`)}</Badge></Card.Header>
      <Card.Body className={styles.detail}>
        <dl className={styles.facts}>
          <div><dt>{t("findingType")}</dt><dd>{t(`types.${selected.findingType}`)}</dd></div>
          <div><dt>{t("principalType")}</dt><dd>{t(`subjects.${selected.subjectKind}`)}</dd></div>
          <div><dt>{t("lastObserved")}</dt><dd><WorkspaceTime value={selected.lastObservedAt} /></dd></div>
          <div><dt>{t("reviewWindow")}</dt><dd>{t("days", { count: selected.windowDays })}</dd></div>
          <div><dt>{t("findingCreated")}</dt><dd><WorkspaceTime value={selected.generatedAt} /></dd></div>
          <div><dt>{t("evidenceCoverage")}</dt><dd>{t("completeSample")}</dd></div>
        </dl>
        <section aria-labelledby="unused-access-recommendation" className={styles.stack}>
          <Typography.Title as="h3" id="unused-access-recommendation" level={3}>{t("recommendationTitle")}</Typography.Title>
          <p className={styles.note}>{t(`recommendations.${selected.findingType}`)}</p>
          <Alert status="warning">{t("noAutomaticAction")}</Alert>
        </section>
      </Card.Body>
      <Card.Footer><Button onClick={() => onNavigate(selected.target.view, selected.target.id)}>{t("reviewTarget")}<ArrowRight aria-hidden="true" /></Button></Card.Footer>
    </Card>
  </WorkspaceDetail>;

  const statusCounts = findings.reduce<Record<UnusedAccessFindingPreview["status"], number>>((counts, finding) => {
    counts[finding.status] += 1;
    return counts;
  }, { active: 0, archived: 0, resolved: 0 });
  return <WorkspaceDetail key="unused-access-directory" title={t("title")} onBack={onBack}>
    <Alert status="info">{t("previewBoundary")}</Alert>
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{t("sampleAnalyzer")}</Typography.Title><Typography.Text tone="muted">{t("sampleAnalyzerHint")}</Typography.Text></div><Badge status="info">{t("mock")}</Badge></Card.Header>
      <Card.Body className={styles.securityReportBody}>
        <dl className={`${styles.securityReportSummary} ${styles.unusedAccessSummary}`} aria-label={t("statusSummary")}>
          {(["active", "archived", "resolved"] as const).map((status) => <div key={status}><dt>{t(`statuses.${status}`)}</dt><dd>{statusCounts[status]}</dd></div>)}
        </dl>
        <p className={styles.note}>{t("sampleWindow", { count: 90 })}</p>
      </Card.Body>
    </Card>
    <WorkspaceCollection embedded title={t("findings")} description={t("directoryHint")} items={findings}
      columns={[t("principal"), t("findingType"), t("lastObserved"), t("status")]}
      keywords={(finding) => `${finding.subjectId} ${finding.findingType} ${finding.status}`}
      filter={{ label: t("status"), options: (["active", "archived", "resolved"] as const).map((value) => ({ value, label: t(`statuses.${value}`) })), matches: (finding, value) => finding.status === value }}
      row={(finding) => <><td><button className={styles.userLink} onClick={() => setSelected(finding)}>{finding.name}</button><small>{finding.subjectId}</small></td><td>{t(`types.${finding.findingType}`)}</td><td><WorkspaceTime value={finding.lastObservedAt} /></td><td><Badge status={findingStatus[finding.status]}>{t(`statuses.${finding.status}`)}</Badge></td></>}
      footerNote={t("directoryHint")} />
  </WorkspaceDetail>;
}

export function AccessReports({ workspace, scene, currentSession = null, onNavigate, onOpenUnusedReview, unusedReviewTriggerRef }: {
  workspace: AccessWorkspace;
  scene: AccountAccessScene;
  currentSession?: SessionSummary | null;
  onNavigate(view: AccountAccessView, id?: string): void;
  onOpenUnusedReview?(): void;
  unusedReviewTriggerRef?: RefObject<HTMLButtonElement | null>;
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
      <div className={styles.actions}><Badge status="info">{t("mockEvidence")}</Badge>{onOpenUnusedReview ? <Button ref={unusedReviewTriggerRef} size="small" variant="ghost" onClick={onOpenUnusedReview}>{t("unusedAccessReview.open")}<ArrowRight aria-hidden="true" /></Button> : null}</div>
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
