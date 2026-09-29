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
  const selectedFinding = selected?.accountId === workspace.accountId ? selected : null;
  if (selectedFinding) return <WorkspaceDetail key={selectedFinding.id} title={t("detailTitle", { name: selectedFinding.name })} onBack={() => setSelected(null)}>
    <Alert status="info">{t("sampleEvidence")}</Alert>
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{selectedFinding.name}</Typography.Title><Typography.Text tone="muted">{selectedFinding.subjectId}</Typography.Text></div><Badge status={findingStatus[selectedFinding.status]}>{t(`statuses.${selectedFinding.status}`)}</Badge></Card.Header>
      <Card.Body className={styles.detail}>
        <dl className={styles.facts}>
          <div><dt>{t("account")}</dt><dd><code>{selectedFinding.accountId}</code></dd></div>
          <div><dt>{t("findingType")}</dt><dd>{t(`types.${selectedFinding.findingType}`)}</dd></div>
          <div><dt>{t("principalType")}</dt><dd>{t(`subjects.${selectedFinding.subjectKind}`)}</dd></div>
          <div><dt>{t("lastObserved")}</dt><dd><WorkspaceTime value={selectedFinding.lastObservedAt} /></dd></div>
          <div><dt>{t("reviewWindow")}</dt><dd>{t("days", { count: selectedFinding.windowDays })}</dd></div>
          <div><dt>{t("findingCreated")}</dt><dd><WorkspaceTime value={selectedFinding.generatedAt} /></dd></div>
          <div><dt>{t("evidenceCoverage")}</dt><dd>{t("completeSample")}</dd></div>
        </dl>
        <section aria-labelledby="unused-access-recommendation" className={styles.stack}>
          <Typography.Title as="h3" id="unused-access-recommendation" level={3}>{t("recommendationTitle")}</Typography.Title>
          <p className={styles.note}>{t(`recommendations.${selectedFinding.findingType}`)}</p>
          <Alert status="warning">{t("noAutomaticAction")}</Alert>
        </section>
      </Card.Body>
      <Card.Footer><Button onClick={() => onNavigate(selectedFinding.target.view, selectedFinding.target.id)}>{t("reviewTarget")}<ArrowRight aria-hidden="true" /></Button></Card.Footer>
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

export function AccessReportPreview({ kind, workspace, scene, currentSession = null, onBack }: {
  kind: "credentials" | "security";
  workspace: AccessWorkspace;
  scene: AccountAccessScene;
  currentSession?: SessionSummary | null;
  onBack(): void;
}) {
  const t = useTranslations("IamWorkspace.reportPreview");
  const workspaceT = useTranslations("IamWorkspace");
  const [generatedAt] = useState(() => new Date().toISOString());
  const scopedSession = currentSession?.principalId === scene.currentUserId ? currentSession : null;
  const report = buildAccessReport(kind, workspace, scene, generatedAt, scopedSession);
  const members = report.users.map((user) => ({ ...user, id: user.loginName, name: user.loginName }));
  const accessLabel = (value: boolean | string) => t(value === true ? "enabled" : value === false ? "disabled" : value === "NOT_APPLICABLE" ? "notApplicable" : "unknown");
  const passwordLabel = (value: boolean | string) => t(value === true ? "resetRequired" : value === false ? "current" : value === "NOT_APPLICABLE" ? "notApplicable" : "unknown");
  const coverageLabels: Record<string, string> = {
    COMPLETE: t("coverage.COMPLETE"), PARTIAL: t("coverage.PARTIAL"),
    UNOBSERVED: t("coverage.UNOBSERVED"), UNAVAILABLE: t("coverage.UNAVAILABLE")
  };
  const actions = { secondary: [{ id: "export", label: t("exportCsv"), disabledReason: t("exportUnavailable"), onSelect: () => undefined }] };
  return <WorkspaceDetail key={`report:${kind}:${workspace.accountId}`} title={workspaceT(kind === "credentials" ? "credentialReport" : "securityReport")} onBack={onBack} actions={actions}>
    <Alert status="info">{t("previewBoundary")}</Alert>
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{t("coverageTitle")}</Typography.Title><Typography.Text tone="muted">{t("coverageHint")}</Typography.Text></div><Badge status="info">{t("mock")}</Badge></Card.Header>
      <Card.Body className={styles.detail}>
        <dl className={styles.facts}>
          <div><dt>{t("account")}</dt><dd><code>{report.accountId}</code></dd></div>
          <div><dt>{t("generatedAt")}</dt><dd><WorkspaceTime value={report.generatedAt} /></dd></div>
          <div><dt>{t("directory")}</dt><dd>{coverageLabels[report.coverage.directory]}</dd></div>
          <div><dt>{t("authenticator")}</dt><dd>{coverageLabels[report.coverage.authenticatorEnrollment]}</dd></div>
          <div><dt>{t("activityWindow")}</dt><dd>{coverageLabels[report.coverage.activityWindow]}</dd></div>
          <div><dt>{t("collectionStart")}</dt><dd>{report.coverage.collectionStart ? <WorkspaceTime value={report.coverage.collectionStart} /> : t("unavailable")}</dd></div>
        </dl>
        <section className={styles.stack} aria-labelledby="report-source-watermarks">
          <Typography.Title as="h3" id="report-source-watermarks" level={3}>{t("sourceWatermarks")}</Typography.Title>
          <dl className={styles.activityEvidence}>
            {(["successfulLogin", "accessKeyUse", "roleUse", "businessOutcome"] as const).map((source) => <div key={source}><dt>{workspaceT(`activityObservations.${source}.title`)}</dt><dd>{report.coverage.sourceWatermarks[source] ? <WorkspaceTime value={report.coverage.sourceWatermarks[source]} /> : t("unavailable")}</dd></div>)}
          </dl>
        </section>
      </Card.Body>
    </Card>
    <WorkspaceCollection embedded title={t("members")} description={t("membersHint")} items={members}
      columns={[t("member"), t("status"), t("accessMethods"), t("credentialEvidence"), t("directPolicies"), t("accessKeys")]}
      keywords={(user) => `${user.status} ${String(user.consoleAccess)} ${String(user.programmaticAccess)}`}
      row={(user) => <><td><strong>{user.loginName}</strong></td><td>{t(`states.${user.status}`)}</td><td><span>{t("consoleAccess")} · {accessLabel(user.consoleAccess)}</span><small>{t("programmaticAccess")} · {accessLabel(user.programmaticAccess)}</small></td><td><span>{t("password")} · {passwordLabel(user.passwordResetRequired)}</span><small>{t("authenticator")} · {accessLabel(user.authenticatorEnrollment)}</small></td><td>{user.directPolicyIds.length}</td><td><span>{t("keyCount", { count: user.accessKeys.active })}</span><small>{t("keyTotal", { count: user.accessKeys.total })}</small></td></>}
      footerNote={t("membersHint")} />
    {kind === "security" && report.checks && report.activity ? <Card>
      <Card.Header><Typography.Title as="h2" level={3}>{t("securityEvidence")}</Typography.Title></Card.Header>
      <Card.Body className={styles.securityReportBody}>
        <ul className={styles.securityChecks}>{report.checks.map((check) => <li key={check.id}><div className={styles.securityCheckCopy}><div className={styles.securityCheckHeading}><strong>{workspaceT(`securityChecks.${check.id}.title`)}</strong><Badge status={badgeStatus[check.state]}>{workspaceT(`securityStates.${check.state}`)}</Badge></div><span className={styles.securityEvidenceState}>{workspaceT("securityEvidenceLabel")}: {workspaceT(`securityEvidenceStates.${check.evidence}`)}</span></div></li>)}</ul>
        <dl className={styles.activityEvidence} aria-label={workspaceT("activityEvidenceTitle")}>{report.activity.observations.map((observation) => <div key={observation.id}><dt>{workspaceT(`activityObservations.${observation.id}.title`)}</dt><dd><Badge status={observation.state === "observed" ? "info" : "neutral"}>{workspaceT(`activityStates.${observation.state}`)}</Badge>{observation.occurredAt ? <WorkspaceTime value={observation.occurredAt} /> : <span>{t("unavailable")}</span>}</dd></div>)}</dl>
      </Card.Body>
    </Card> : null}
  </WorkspaceDetail>;
}

export function AccessReports({ workspace, scene, currentSession = null, onNavigate, onOpenUnusedReview, onOpenReport, unusedReviewTriggerRef, reportTriggerRef }: {
  workspace: AccessWorkspace;
  scene: AccountAccessScene;
  currentSession?: SessionSummary | null;
  onNavigate(view: AccountAccessView, id?: string): void;
  onOpenUnusedReview?(): void;
  onOpenReport?(kind: "credentials" | "security"): void;
  unusedReviewTriggerRef?: RefObject<HTMLButtonElement | null>;
  reportTriggerRef?: RefObject<HTMLButtonElement | null>;
}) {
  const t = useTranslations("IamWorkspace");
  const format = useFormatter();
  const snapshot = buildAccessSecuritySnapshot(workspace, scene.directoryComplete);
  const scopedSession = currentSession?.principalId === scene.currentUserId ? currentSession : null;
  const activity = buildAccessActivityObservations(workspace, scopedSession);
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
    </Card.Body>
    <Card.Footer>
      <p className={styles.note}>{t("reportHint")}</p>
      {onOpenReport ? <ActionMenu triggerRef={reportTriggerRef} label={t("reviewReports")} actions={[
        { id: "credentials", label: t("credentialReport"), onSelect: () => onOpenReport("credentials") },
        { id: "security", label: t("securityReport"), onSelect: () => onOpenReport("security") }
      ]} /> : null}
    </Card.Footer>
  </Card>;
}
