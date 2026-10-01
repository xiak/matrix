"use client";

import { useState, type RefObject } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { ArrowRight } from "lucide-react";
import { ActionMenu, Alert, Badge, Button, Card, Tabs, Typography } from "@ui/xiak";
import type { AccountAccessView } from "../domain/accounts";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { SessionSummary } from "../domain/session";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { buildAccessActivityObservations, buildAccessAnalysisPreview, buildAccessReport, buildAccessSecuritySnapshot, type AccessAnalysisTrustEntry, type AccessSecurityCheckState, type UnusedAccessFindingPreview } from "../scenes/accessReport";
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

const trustEntryStatus: Record<AccessAnalysisTrustEntry["configuration"], "info" | "warning" | "neutral"> = {
  configured: "info",
  incomplete: "warning",
  disabled: "neutral"
};

export function AccessAnalysisPreview({ workspace, scene, onBack, onNavigate }: {
  workspace: AccessWorkspace;
  scene: AccountAccessScene;
  onBack(): void;
  onNavigate(view: AccountAccessView, id?: string): void;
}) {
  const t = useTranslations("IamWorkspace.accessAnalysis");
  const [section, setSection] = useState<"external" | "unused">("external");
  const [selectedTrustEntry, setSelectedTrustEntry] = useState<AccessAnalysisTrustEntry | null>(null);
  const [selectedUnusedFinding, setSelectedUnusedFinding] = useState<UnusedAccessFindingPreview | null>(null);
  const analysis = buildAccessAnalysisPreview(workspace, scene);
  const selectedTrust = selectedTrustEntry?.accountId === workspace.accountId ? selectedTrustEntry : null;
  const selectedUnused = selectedUnusedFinding?.accountId === workspace.accountId ? selectedUnusedFinding : null;

  if (selectedTrust) return <WorkspaceDetail key={selectedTrust.id} title={t("external.detailTitle", { name: selectedTrust.name })} onBack={() => setSelectedTrustEntry(null)}>
    <Alert status="info">{t("external.configurationEvidence")}</Alert>
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{selectedTrust.name}</Typography.Title><Typography.Text tone="muted">{selectedTrust.principal}</Typography.Text></div><Badge status={trustEntryStatus[selectedTrust.configuration]}>{t(`external.states.${selectedTrust.configuration}`)}</Badge></Card.Header>
      <Card.Body className={styles.detail}>
        <dl className={styles.facts}>
          <div><dt>{t("account")}</dt><dd><code>{selectedTrust.accountId}</code></dd></div>
          <div><dt>{t("external.entryType")}</dt><dd>{t(`external.kinds.${selectedTrust.kind}`)}</dd></div>
          <div><dt>{t("external.principal")}</dt><dd><code>{selectedTrust.principal}</code></dd></div>
          <div><dt>{t("external.role")}</dt><dd>{selectedTrust.roleName}<small>{selectedTrust.roleId}</small></dd></div>
          <div><dt>{t("external.source")}</dt><dd>{selectedTrust.sourceName}{selectedTrust.sourceId !== selectedTrust.sourceName ? <small>{selectedTrust.sourceId}</small> : null}</dd></div>
          <div><dt>{t("external.createdAt")}</dt><dd><WorkspaceTime value={selectedTrust.createdAt} /></dd></div>
          <div><dt>{t("external.evidenceCoverage")}</dt><dd>{t("external.configurationOnly")}</dd></div>
        </dl>
        <section aria-labelledby="external-access-recommendation" className={styles.stack}>
          <Typography.Title as="h3" id="external-access-recommendation" level={3}>{t("external.recommendationTitle")}</Typography.Title>
          <p className={styles.note}>{t(`external.recommendations.${selectedTrust.kind}`)}</p>
          <Alert status="warning">{t("external.noEffectiveAccessConclusion")}</Alert>
        </section>
      </Card.Body>
      <Card.Footer><Button onClick={() => onNavigate(selectedTrust.target.view, selectedTrust.target.id)}>{t("external.reviewTarget")}<ArrowRight aria-hidden="true" /></Button></Card.Footer>
    </Card>
  </WorkspaceDetail>;

  if (selectedUnused) return <WorkspaceDetail key={selectedUnused.id} title={t("unused.detailTitle", { name: selectedUnused.name })} onBack={() => setSelectedUnusedFinding(null)}>
    <Alert status="info">{t("unused.sampleEvidence")}</Alert>
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{selectedUnused.name}</Typography.Title><Typography.Text tone="muted">{selectedUnused.subjectId}</Typography.Text></div><Badge status={findingStatus[selectedUnused.status]}>{t(`unused.statuses.${selectedUnused.status}`)}</Badge></Card.Header>
      <Card.Body className={styles.detail}>
        <dl className={styles.facts}>
          <div><dt>{t("account")}</dt><dd><code>{selectedUnused.accountId}</code></dd></div>
          <div><dt>{t("unused.findingType")}</dt><dd>{t(`unused.types.${selectedUnused.findingType}`)}</dd></div>
          <div><dt>{t("unused.principalType")}</dt><dd>{t(`unused.subjects.${selectedUnused.subjectKind}`)}</dd></div>
          <div><dt>{t("unused.lastObserved")}</dt><dd><WorkspaceTime value={selectedUnused.lastObservedAt} /></dd></div>
          <div><dt>{t("unused.reviewWindow")}</dt><dd>{t("unused.days", { count: selectedUnused.windowDays })}</dd></div>
          <div><dt>{t("unused.findingCreated")}</dt><dd><WorkspaceTime value={selectedUnused.generatedAt} /></dd></div>
          <div><dt>{t("unused.evidenceCoverage")}</dt><dd>{t("unused.completeSample")}</dd></div>
        </dl>
        <section aria-labelledby="unused-access-recommendation" className={styles.stack}>
          <Typography.Title as="h3" id="unused-access-recommendation" level={3}>{t("unused.recommendationTitle")}</Typography.Title>
          <p className={styles.note}>{t(`unused.recommendations.${selectedUnused.findingType}`)}</p>
          <Alert status="warning">{t("unused.noAutomaticAction")}</Alert>
        </section>
      </Card.Body>
      <Card.Footer><Button onClick={() => onNavigate(selectedUnused.target.view, selectedUnused.target.id)}>{t("unused.reviewTarget")}<ArrowRight aria-hidden="true" /></Button></Card.Footer>
    </Card>
  </WorkspaceDetail>;

  const statusCounts = analysis.unusedFindings.reduce<Record<UnusedAccessFindingPreview["status"], number>>((counts, finding) => {
    counts[finding.status] += 1;
    return counts;
  }, { active: 0, archived: 0, resolved: 0 });
  return <WorkspaceDetail key="access-analysis" title={t("title")} onBack={onBack}>
    <Alert status="info">{t("previewBoundary")}</Alert>
    <Tabs.Root value={section} onValueChange={(value) => setSection(value as "external" | "unused")}>
      <Tabs.List aria-label={t("sections")}><Tabs.Trigger value="external">{t("tabs.external")} ({analysis.trustEntries.length})</Tabs.Trigger><Tabs.Trigger value="unused">{t("tabs.unused")} ({analysis.unusedFindings.length})</Tabs.Trigger></Tabs.List>
      <Tabs.Content className={styles.stack} value="external">
        <Card>
          <Card.Header><div><Typography.Title as="h2" level={3}>{t("external.coverageTitle")}</Typography.Title><Typography.Text tone="muted">{t("external.coverageHint")}</Typography.Text></div><Badge status="info">{t("mockConfiguration")}</Badge></Card.Header>
          <Card.Body className={styles.securityReportBody}>
            <dl className={styles.activityEvidence} aria-label={t("external.coverageTitle")}>{analysis.coverage.map((item) => <div key={item.id}><dt>{t(`external.coverage.${item.id}.title`)}</dt><dd><Badge status={item.state === "mockObserved" ? "info" : "neutral"}>{t(`external.coverageStates.${item.state}`)}</Badge><span>{t(`external.coverage.${item.id}.hint`)}</span></dd></div>)}</dl>
          </Card.Body>
        </Card>
        <WorkspaceCollection embedded title={t("external.entries")} description={t("external.directoryHint")} items={analysis.trustEntries}
          columns={[t("external.entry"), t("external.principal"), t("external.source"), t("external.role"), t("external.status")]}
          keywords={(entry) => `${entry.name} ${entry.principal} ${entry.roleName} ${entry.sourceName}`}
          filter={{ label: t("external.entryType"), options: (["roleSsoMapping", "serviceWorkload"] as const).map((value) => ({ value, label: t(`external.kinds.${value}`) })), matches: (entry, value) => entry.kind === value }}
          row={(entry) => <><td><button className={styles.userLink} onClick={() => setSelectedTrustEntry(entry)}>{entry.name}</button><small>{t(`external.kinds.${entry.kind}`)}</small></td><td><code>{entry.principal}</code></td><td>{entry.sourceName}{entry.sourceId !== entry.sourceName ? <small>{entry.sourceId}</small> : null}</td><td>{entry.roleName}<small>{entry.roleId}</small></td><td><Badge status={trustEntryStatus[entry.configuration]}>{t(`external.states.${entry.configuration}`)}</Badge></td></>}
          footerNote={t("external.directoryHint")} />
      </Tabs.Content>
      <Tabs.Content className={styles.stack} value="unused">
        <Card>
          <Card.Header><div><Typography.Title as="h2" level={3}>{t("unused.sampleAnalyzer")}</Typography.Title><Typography.Text tone="muted">{t("unused.sampleAnalyzerHint")}</Typography.Text></div><Badge status="info">{t("unused.mock")}</Badge></Card.Header>
          <Card.Body className={styles.securityReportBody}>
            <dl className={`${styles.securityReportSummary} ${styles.unusedAccessSummary}`} aria-label={t("unused.statusSummary")}>
              {(["active", "archived", "resolved"] as const).map((status) => <div key={status}><dt>{t(`unused.statuses.${status}`)}</dt><dd>{statusCounts[status]}</dd></div>)}
            </dl>
            <p className={styles.note}>{t("unused.sampleWindow", { count: 90 })}</p>
          </Card.Body>
        </Card>
        <WorkspaceCollection embedded title={t("unused.findings")} description={t("unused.directoryHint")} items={analysis.unusedFindings}
          columns={[t("unused.principal"), t("unused.findingType"), t("unused.lastObserved"), t("unused.status")]}
          keywords={(finding) => `${finding.subjectId} ${finding.findingType} ${finding.status}`}
          filter={{ label: t("unused.status"), options: (["active", "archived", "resolved"] as const).map((value) => ({ value, label: t(`unused.statuses.${value}`) })), matches: (finding, value) => finding.status === value }}
          row={(finding) => <><td><button className={styles.userLink} onClick={() => setSelectedUnusedFinding(finding)}>{finding.name}</button><small>{finding.subjectId}</small></td><td>{t(`unused.types.${finding.findingType}`)}</td><td><WorkspaceTime value={finding.lastObservedAt} /></td><td><Badge status={findingStatus[finding.status]}>{t(`unused.statuses.${finding.status}`)}</Badge></td></>}
          footerNote={t("unused.directoryHint")} />
      </Tabs.Content>
    </Tabs.Root>
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

export function AccessReports({ workspace, scene, currentSession = null, onNavigate, onOpenAccessAnalysis, onOpenReport, accessAnalysisTriggerRef, reportTriggerRef }: {
  workspace: AccessWorkspace;
  scene: AccountAccessScene;
  currentSession?: SessionSummary | null;
  onNavigate(view: AccountAccessView, id?: string): void;
  onOpenAccessAnalysis?(): void;
  onOpenReport?(kind: "credentials" | "security"): void;
  accessAnalysisTriggerRef?: RefObject<HTMLButtonElement | null>;
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
      <div className={styles.actions}><Badge status="info">{t("mockEvidence")}</Badge>{onOpenAccessAnalysis ? <Button ref={accessAnalysisTriggerRef} size="small" variant="ghost" onClick={onOpenAccessAnalysis}>{t("accessAnalysis.open")}<ArrowRight aria-hidden="true" /></Button> : null}</div>
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
