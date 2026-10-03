"use client";

import { useMemo, useState, type RefObject } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { ArrowRight } from "lucide-react";
import { ActionMenu, Alert, Badge, Button, Card, ContentPage, EmptyState, Tabs, Typography } from "@ui/xiak";
import type { AccountAccessView } from "../domain/accounts";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { SessionSummary } from "../domain/session";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { accountSecurityReportLimits, accountSecurityReportLimitViolation, buildAccessActivityObservations, buildAccessAnalysisPreview, buildAccessSecuritySnapshot, buildAccountSecurityReportDirectoryPreview, buildCredentialReport, createAccountSecurityReportPreview, type AccessAnalysisRulePreview, type AccessAnalysisTrustEntry, type AccessSecurityCheckState, type AccountSecurityReportDirectoryEntry, type AccountSecurityReportDirectoryStatus, type AccountSecurityReportPreview as AccountSecurityReportPreviewModel, type UnusedAccessFindingPreview } from "../scenes/accessReport";
import { AccessAnalysisDispositionWorkflow, AccessAnalysisRulesPanel, AccessAnalysisRuleWorkflow, type AccessAnalysisRuleSavedKind } from "./AccessAnalysisRulePreview";
import { WorkspaceCollection, WorkspaceDetail, WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

const badgeStatus: Record<AccessSecurityCheckState, "warning" | "success" | "neutral" | "info"> = {
  review: "warning",
  configured: "success",
  notApplicable: "neutral",
  unknown: "info"
};

const trustEntryStatus: Record<AccessAnalysisTrustEntry["configuration"], "info" | "warning" | "neutral"> = {
  configured: "info",
  incomplete: "warning",
  disabled: "neutral"
};

const unusedFindingStatus: Record<UnusedAccessFindingPreview["lifecycle"], "warning" | "neutral" | "success"> = {
  ACTIVE: "warning",
  ARCHIVED: "neutral",
  RESOLVED: "success"
};

const accountSecurityReportFailureBoundaries = ["overLimit", "retainedReportLimit", "expired", "revoked"] as const;

const reportDirectoryStatus: Record<AccountSecurityReportDirectoryStatus, "success" | "warning" | "neutral"> = {
  available: "success",
  expiringSoon: "warning",
  expired: "neutral"
};

type UnusedFindingReviewOverride = {
  lifecycle: Extract<UnusedAccessFindingPreview["lifecycle"], "ACTIVE" | "ARCHIVED">;
  occurredAt: string;
};

function unusedFindingKey(finding: Pick<UnusedAccessFindingPreview, "accountId" | "id">) {
  return `${finding.accountId}:${finding.id}`;
}

function UnusedFindingLifecycleWorkflow({ finding, nextLifecycle, onBack, onApply }: {
  finding: UnusedAccessFindingPreview;
  nextLifecycle: UnusedFindingReviewOverride["lifecycle"];
  onBack(): void;
  onApply(nextLifecycle: UnusedFindingReviewOverride["lifecycle"]): void;
}) {
  const t = useTranslations("IamWorkspace.accessAnalysis.unused");
  const archive = nextLifecycle === "ARCHIVED";
  return <WorkspaceDetail title={t(archive ? "transition.archiveTitle" : "transition.reopenTitle", { name: finding.name })} onBack={onBack}>
    <Alert status="info">{t("transition.previewBoundary")}</Alert>
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{finding.name}</Typography.Title><Typography.Text tone="muted">{finding.subjectId}</Typography.Text></div><Badge status="info">{t("mockSample")}</Badge></Card.Header>
      <Card.Body className={styles.detail}>
        <dl className={styles.facts}>
          <div><dt>{t("findingId")}</dt><dd><code>{finding.id}</code></dd></div>
          <div><dt>{t("transition.currentStatus")}</dt><dd><Badge status={unusedFindingStatus[finding.lifecycle]} title={finding.lifecycle}>{t(`lifecycle.${finding.lifecycle}`)}</Badge></dd></div>
          <div><dt>{t("transition.nextStatus")}</dt><dd><Badge status={unusedFindingStatus[nextLifecycle]} title={nextLifecycle}>{t(`lifecycle.${nextLifecycle}`)}</Badge></dd></div>
          <div><dt>{t("principalType")}</dt><dd>{t(`subjects.${finding.subjectKind}`)}</dd></div>
        </dl>
        <Alert status="warning">{t(archive ? "transition.archiveMeaning" : "transition.reopenMeaning")}</Alert>
        <Alert status="info">{t("transition.noObjectChange")}</Alert>
      </Card.Body>
      <Card.Footer><div className={styles.actions}><Button onClick={() => onApply(nextLifecycle)}>{t(archive ? "transition.confirmArchive" : "transition.confirmReopen")}</Button><Button variant="secondary" onClick={onBack}>{t("transition.cancel")}</Button></div></Card.Footer>
    </Card>
  </WorkspaceDetail>;
}

export function AccessAnalysisPreview({ workspace, scene, onBack, onNavigate }: {
  workspace?: AccessWorkspace;
  scene: AccountAccessScene;
  onBack?(): void;
  onNavigate(view: AccountAccessView, id?: string): void;
}) {
  const t = useTranslations("IamWorkspace.accessAnalysis");
  const [section, setSection] = useState<"external" | "unused" | "rule">("external");
  const [selectedTrustEntry, setSelectedTrustEntry] = useState<AccessAnalysisTrustEntry | null>(null);
  const [selectedUnusedFinding, setSelectedUnusedFinding] = useState<UnusedAccessFindingPreview | null>(null);
  const [editingRule, setEditingRule] = useState<AccessAnalysisRuleSavedKind | null>(null);
  const [ruleOverride, setRuleOverride] = useState<AccessAnalysisRulePreview | null>(null);
  const [ruleSaved, setRuleSaved] = useState<AccessAnalysisRuleSavedKind | null>(null);
  const [unusedReviewOverrides, setUnusedReviewOverrides] = useState<Record<string, UnusedFindingReviewOverride[]>>({});
  const [unusedTransition, setUnusedTransition] = useState<UnusedFindingReviewOverride["lifecycle"] | null>(null);
  const [unusedTransitionNotice, setUnusedTransitionNotice] = useState<{ key: string; lifecycle: UnusedFindingReviewOverride["lifecycle"] } | null>(null);
  const analysis = useMemo(() => workspace ? buildAccessAnalysisPreview(workspace, scene) : null, [scene, workspace]);
  const unusedFindings = useMemo(() => (analysis?.unusedFindings ?? []).map((finding) => {
    const overrides = unusedReviewOverrides[unusedFindingKey(finding)] ?? [];
    const latest = overrides.at(-1);
    if (!latest) return finding;
    return {
      ...finding,
      lifecycle: latest.lifecycle,
      lifecycleEvidence: [...finding.lifecycleEvidence, ...overrides.map((override) => ({
        lifecycle: override.lifecycle,
        occurredAt: override.occurredAt,
        source: "SYNTHETIC_HUMAN_REVIEW" as const
      }))]
    };
  }), [analysis, unusedReviewOverrides]);
  const rule = ruleOverride?.accountId === workspace?.accountId ? ruleOverride : analysis?.rule ?? null;
  const selectedTrust = selectedTrustEntry?.accountId === workspace?.accountId ? selectedTrustEntry : null;
  const selectedUnusedId = selectedUnusedFinding && selectedUnusedFinding.accountId === workspace?.accountId ? selectedUnusedFinding.id : null;
  const selectedUnused = selectedUnusedId
    ? unusedFindings.find((finding) => finding.id === selectedUnusedId) ?? null
    : null;

  if (!workspace || !analysis) return <div className={styles.stack}>
    <ContentPage.Heading title={t("title")} scrollKey="access-analysis-live" />
    <Alert status="info">{t("liveBoundary")}</Alert>
    <EmptyState title={t("liveUnavailableTitle")} description={t("liveUnavailableHint")} />
  </div>;

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

  if (editingRule === "analyzer" && rule) return <AccessAnalysisRuleWorkflow rule={rule} onBack={() => setEditingRule(null)} onApply={(next) => { setRuleOverride(next); setRuleSaved("analyzer"); setEditingRule(null); setSection("rule"); }} />;

  if (editingRule === "disposition" && rule) return <AccessAnalysisDispositionWorkflow rule={rule} onBack={() => setEditingRule(null)} onApply={(next) => { setRuleOverride(next); setRuleSaved("disposition"); setEditingRule(null); setSection("rule"); }} />;

  if (unusedTransition && selectedUnused) return <UnusedFindingLifecycleWorkflow finding={selectedUnused} nextLifecycle={unusedTransition} onBack={() => setUnusedTransition(null)} onApply={(nextLifecycle) => {
    const key = unusedFindingKey(selectedUnused);
    setUnusedReviewOverrides((current) => ({ ...current, [key]: [...(current[key] ?? []), { lifecycle: nextLifecycle, occurredAt: new Date().toISOString() }] }));
    setUnusedTransitionNotice({ key, lifecycle: nextLifecycle });
    setUnusedTransition(null);
  }} />;

  if (selectedUnused) {
    const selectedKey = unusedFindingKey(selectedUnused);
    const lifecycleAction = selectedUnused.lifecycle === "RESOLVED" ? undefined : {
      id: selectedUnused.lifecycle === "ACTIVE" ? "archive" : "reopen",
      label: t(selectedUnused.lifecycle === "ACTIVE" ? "unused.transition.archiveAction" : "unused.transition.reopenAction"),
      onSelect: () => setUnusedTransition(selectedUnused.lifecycle === "ACTIVE" ? "ARCHIVED" : "ACTIVE")
    };
    return <WorkspaceDetail key={selectedUnused.id} title={t("unused.detailTitle", { name: selectedUnused.name })} onBack={() => { setSelectedUnusedFinding(null); setUnusedTransitionNotice(null); }} actions={{
      primary: lifecycleAction,
      secondary: [
        { id: "target", label: t("unused.reviewTarget"), onSelect: () => onNavigate(selectedUnused.target.view, selectedUnused.target.id) },
        { id: "analyzer", label: t("unused.reviewAnalyzer"), onSelect: () => { setSelectedUnusedFinding(null); setSection("rule"); } }
      ]
    }}>
    {unusedTransitionNotice?.key === selectedKey ? <Alert status="success">{t(unusedTransitionNotice.lifecycle === "ARCHIVED" ? "unused.transition.archived" : "unused.transition.reopened")}</Alert> : null}
    <Alert status="info">{t("unused.sampleEvidence")}</Alert>
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{selectedUnused.name}</Typography.Title><Typography.Text tone="muted">{selectedUnused.subjectId}</Typography.Text></div><span className={styles.badgeRow}><Badge status="info">{t("unused.mockSample")}</Badge><Badge status={unusedFindingStatus[selectedUnused.lifecycle]} title={selectedUnused.lifecycle}>{t(`unused.lifecycle.${selectedUnused.lifecycle}`)}</Badge></span></Card.Header>
      <Card.Body className={styles.detail}>
        <dl className={styles.facts}>
          <div><dt>{t("unused.findingId")}</dt><dd><code>{selectedUnused.id}</code></dd></div>
          <div><dt>{t("unused.analyzerId")}</dt><dd><code>{selectedUnused.analyzerId}</code></dd></div>
          <div><dt>{t("account")}</dt><dd><code>{selectedUnused.accountId}</code></dd></div>
          <div><dt>{t("unused.findingType")}</dt><dd>{t(`unused.types.${selectedUnused.findingType}`)}</dd></div>
          <div><dt>{t("unused.status")}</dt><dd>{t(`unused.lifecycle.${selectedUnused.lifecycle}`)}<small className={styles.factMeta}>{selectedUnused.lifecycle}</small></dd></div>
          <div><dt>{t("unused.principalType")}</dt><dd>{t(`unused.subjects.${selectedUnused.subjectKind}`)}</dd></div>
          <div><dt>{t("unused.lastObserved")}</dt><dd><WorkspaceTime value={selectedUnused.lastObservedAt} /></dd></div>
          <div><dt>{t("unused.reviewWindow")}</dt><dd>{t("unused.days", { count: selectedUnused.windowDays })}</dd></div>
          <div><dt>{t("unused.observedWindow")}</dt><dd><WorkspaceTime value={selectedUnused.observedFrom} /> – <WorkspaceTime value={selectedUnused.observedThrough} /></dd></div>
          <div><dt>{t("unused.findingCreated")}</dt><dd><WorkspaceTime value={selectedUnused.generatedAt} /></dd></div>
          <div><dt>{t("unused.evidenceCoverage")}</dt><dd>{t("unused.completeSample")}</dd></div>
        </dl>
        <Alert status="info">{t("unused.correlationBoundary")}</Alert>
        <section aria-labelledby="unused-lifecycle-evidence" className={styles.stack}>
          <Typography.Title as="h3" id="unused-lifecycle-evidence" level={3}>{t("unused.lifecycleEvidenceTitle")}</Typography.Title>
          <ol className={styles.securityChecks}>{selectedUnused.lifecycleEvidence.map((event, index) => <li key={`${event.lifecycle}:${event.occurredAt}:${index}`}>
            <Badge status={unusedFindingStatus[event.lifecycle]} title={event.lifecycle}>{t(`unused.lifecycle.${event.lifecycle}`)}</Badge>
            <div className={styles.securityCheckCopy}><strong>{t(`unused.lifecycleEvents.${event.lifecycle === "ACTIVE" && event.source === "SYNTHETIC_HUMAN_REVIEW" ? "REOPENED" : event.lifecycle}`)}</strong><p><WorkspaceTime value={event.occurredAt} /> · {t(`unused.lifecycleSources.${event.source}`)}</p></div>
          </li>)}</ol>
          <Alert status="info">{t("unused.lifecycleEvidenceBoundary")}</Alert>
        </section>
        <section aria-labelledby="unused-access-recommendation" className={styles.stack}>
          <Typography.Title as="h3" id="unused-access-recommendation" level={3}>{t("unused.recommendationTitle")}</Typography.Title>
          <p className={styles.note}>{t(`unused.recommendations.${selectedUnused.findingType}`)}</p>
          <Alert status="info">{t(`unused.lifecycleBoundaries.${selectedUnused.lifecycle}`)}</Alert>
          <Alert status="warning">{t("unused.noAutomaticAction")}</Alert>
        </section>
      </Card.Body>
    </Card>
  </WorkspaceDetail>;
  }
  const content = <>
    <Alert status="info">{t("previewBoundary")}</Alert>
    <Tabs.Root value={section} onValueChange={(value) => setSection(value as "external" | "unused" | "rule")}>
      <Tabs.List aria-label={t("sections")} className={styles.accessAnalysisTabs}><Tabs.Trigger value="external">{t("tabs.external")} ({analysis.trustEntries.length})</Tabs.Trigger><Tabs.Trigger value="unused">{t("tabs.unused")} ({unusedFindings.length})</Tabs.Trigger><Tabs.Trigger value="rule">{t("tabs.rule")}</Tabs.Trigger></Tabs.List>
      <Tabs.Content className={styles.stack} value="external">
        <Card>
          <Card.Header><div><Typography.Title as="h2" level={3}>{t("external.coverageTitle")}</Typography.Title><Typography.Text tone="muted">{t("external.coverageHint")}</Typography.Text></div><Badge status="info">{t("mockConfiguration")}</Badge></Card.Header>
          <Card.Body className={styles.securityReportBody}>
            <dl className={styles.activityEvidence} aria-label={t("external.coverageTitle")}>{analysis.coverage.map((item) => <div key={item.id}><dt>{t(`external.coverage.${item.id}.title`)}</dt><dd><Badge status={item.state === "INSUFFICIENT_COVERAGE" ? "warning" : "neutral"}>{t(`external.coverageStates.${item.state}`)}</Badge><span>{t(`external.coverageReasons.${item.reason}`)}</span><code>{item.reason}</code>{item.observedFrom && item.observedThrough ? <small>{t("external.observedWindow")} <WorkspaceTime value={item.observedFrom} /> – <WorkspaceTime value={item.observedThrough} /></small> : null}<span>{t(`external.coverage.${item.id}.hint`)}</span></dd></div>)}</dl>
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
          <Card.Header><div><Typography.Title as="h2" level={3}>{t("unused.scan.title")}</Typography.Title><Typography.Text tone="muted">{t("unused.scan.hint")}</Typography.Text></div><Badge status="warning">{t("unused.scan.mockFailure")}</Badge></Card.Header>
          <Card.Body className={styles.securityReportBody}>
            <dl className={`${styles.securityReportSummary} ${styles.scanSummary}`} aria-label={t("unused.scan.summary")}>
              <div><dt>{t("unused.scan.lastSucceeded")}</dt><dd><WorkspaceTime value={analysis.scanPreview.lastSucceededAt} /></dd></div>
              <div><dt>{t("unused.scan.lastAttempted")}</dt><dd><WorkspaceTime value={analysis.scanPreview.lastAttemptedAt} /></dd></div>
              <div><dt>{t("unused.scan.currentAttempt")}</dt><dd>{t(`unused.scan.states.${analysis.scanPreview.state}`)}</dd></div>
              <div><dt>{t("unused.scan.displayedEvidence")}</dt><dd>{t(`unused.scan.evidence.${analysis.scanPreview.evidence}`)}</dd></div>
            </dl>
            <Alert status="warning">{t("unused.scan.failureBoundary")}</Alert>
          </Card.Body>
        </Card>
        <Card>
          <Card.Header><div><Typography.Title as="h2" level={3}>{t("unused.sampleAnalyzer")}</Typography.Title><Typography.Text tone="muted">{t("unused.sampleAnalyzerHint")}</Typography.Text></div><Badge status="info">{t("unused.mock")}</Badge></Card.Header>
          <Card.Body className={styles.securityReportBody}>
            <dl className={`${styles.securityReportSummary} ${styles.unusedAccessSummary}`} aria-label={t("unused.sampleSummary")}>
              <div><dt>{t("unused.sampleCount")}</dt><dd>{unusedFindings.length}</dd></div>
              <div><dt>{t("unused.reviewWindow")}</dt><dd>{t("unused.days", { count: 90 })}</dd></div>
              <div><dt>{t("unused.liveCandidate")}</dt><dd>{t("unused.liveEmpty")}</dd></div>
            </dl>
            <p className={styles.note}>{t("unused.sampleWindow", { count: 90 })}</p>
          </Card.Body>
        </Card>
        <Alert status="info">{t("unused.lifecyclePreviewBoundary")}</Alert>
        <Alert status="info">{t("unused.scaleBoundary", { count: unusedFindings.length })}</Alert>
        <WorkspaceCollection embedded title={t("unused.findings")} description={t("unused.directoryHint")} items={unusedFindings}
          columns={[t("unused.principal"), t("unused.findingType"), t("unused.status"), t("unused.lastObserved"), t("unused.reviewWindow")]}
          keywords={(finding) => `${finding.subjectId} ${finding.findingType} ${finding.lifecycle}`}
          filter={{ label: t("unused.status"), defaultValue: "ACTIVE", options: (["ACTIVE", "ARCHIVED", "RESOLVED"] as const).map((value) => ({ value, label: t(`unused.lifecycle.${value}`) })), matches: (finding, value) => finding.lifecycle === value }}
          row={(finding) => <><td><button className={styles.userLink} onClick={() => setSelectedUnusedFinding(finding)}>{finding.name}</button><small>{finding.subjectId}</small></td><td>{t(`unused.types.${finding.findingType}`)}</td><td><Badge status={unusedFindingStatus[finding.lifecycle]} title={finding.lifecycle}>{t(`unused.lifecycle.${finding.lifecycle}`)}</Badge></td><td><WorkspaceTime value={finding.lastObservedAt} /></td><td>{t("unused.days", { count: finding.windowDays })}</td></>}
          footerNote={t("unused.directoryHint")} />
      </Tabs.Content>
      <Tabs.Content className={styles.stack} value="rule">
        {rule ? <AccessAnalysisRulesPanel rule={rule} saved={ruleSaved} onEditAnalyzer={() => { setRuleSaved(null); setEditingRule("analyzer"); }} onEditDisposition={() => { setRuleSaved(null); setEditingRule("disposition"); }} /> : null}
      </Tabs.Content>
    </Tabs.Root>
  </>;
  return onBack
    ? <WorkspaceDetail key="access-analysis" title={t("title")} onBack={onBack}>{content}</WorkspaceDetail>
    : <div className={styles.detailWorkspace}><ContentPage.Heading title={t("title")} scrollKey="access-analysis" />{content}</div>;
}

function CredentialReportPreview({ workspace, scene, onBack }: {
  workspace: AccessWorkspace;
  scene: AccountAccessScene;
  onBack(): void;
}) {
  const t = useTranslations("IamWorkspace.reportPreview");
  const workspaceT = useTranslations("IamWorkspace");
  const [generatedAt] = useState(() => new Date().toISOString());
  const report = buildCredentialReport(workspace, scene, generatedAt);
  const members = report.users.map((user) => ({ ...user, id: user.loginName, name: user.loginName }));
  const accessLabel = (value: boolean | string) => t(value === true ? "enabled" : value === false ? "disabled" : value === "NOT_APPLICABLE" ? "notApplicable" : "unknown");
  const passwordLabel = (value: boolean | string) => t(value === true ? "resetRequired" : value === false ? "current" : value === "NOT_APPLICABLE" ? "notApplicable" : "unknown");
  const coverageLabels: Record<string, string> = {
    COMPLETE: t("coverage.COMPLETE"), PARTIAL: t("coverage.PARTIAL"),
    UNOBSERVED: t("coverage.UNOBSERVED"), UNAVAILABLE: t("coverage.UNAVAILABLE")
  };
  const actions = { secondary: [{ id: "export", label: t("exportCsv"), disabledReason: t("exportUnavailable"), onSelect: () => undefined }] };
  return <WorkspaceDetail key={`report:credentials:${workspace.accountId}`} title={workspaceT("credentialReport")} onBack={onBack} actions={actions}>
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
  </WorkspaceDetail>;
}

function AccountSecurityReportPreview({ workspace, scene, currentSession, initialReport = null, onBack }: {
  workspace: AccessWorkspace;
  scene: AccountAccessScene;
  currentSession: SessionSummary | null;
  initialReport?: AccountSecurityReportPreviewModel | null;
  onBack(): void;
}) {
  const t = useTranslations("IamWorkspace.securityReportPreview");
  const failureTitle = (boundary: typeof accountSecurityReportFailureBoundaries[number]) => boundary === "retainedReportLimit"
    ? t(`failures.${boundary}.title`, { reports: accountSecurityReportLimits.retainedReports })
    : t(`failures.${boundary}.title`);
  const [requestId] = useState(() => initialReport?.requestId ?? `mock-${Date.now().toString(36)}`);
  const [report, setReport] = useState<AccountSecurityReportPreviewModel | null>(initialReport);
  const plannedUsers = scene.users.length + 1;
  const plannedScopes = [
    { id: "account" as const, rows: 1 },
    { id: "users" as const, rows: plannedUsers },
    { id: "accessKeys" as const, rows: workspace.keys.length }
  ];
  const scopes = report ? [
    { id: "account" as const, rows: 1 },
    { id: "users" as const, rows: report.totals.users },
    { id: "accessKeys" as const, rows: report.totals.accessKeys }
  ] : plannedScopes;
  const totalRows = scopes.reduce((total, scope) => total + scope.rows, 0);
  const limitViolation = accountSecurityReportLimitViolation(plannedUsers, workspace.keys.length);
  const generate = () => {
    const result = createAccountSecurityReportPreview(workspace, scene, new Date().toISOString(), requestId, currentSession);
    if (result.outcome === "COMPLETED") setReport(result.report);
  };
  const actions = {
    primary: {
      id: "generate",
      label: t("generate"),
      disabledReason: report ? t("alreadyGenerated") : limitViolation ? t(`limitViolations.${limitViolation}`) : undefined,
      onSelect: generate
    },
    secondary: [{ id: "download", label: t("download"), disabledReason: t("downloadUnavailable"), onSelect: () => undefined }]
  };
  return <WorkspaceDetail key={`report:security:${workspace.accountId}`} title={t(report ? "detailTitle" : "createTitle")} onBack={onBack} actions={actions}>
    <Alert status="info">{t("mockBoundary")}</Alert>
    <Card>
      <Card.Header>
        <div><Typography.Title as="h2" level={3}>{t(report ? "sealedTitle" : "reviewTitle")}</Typography.Title><Typography.Text tone="muted">{t(report ? "sealedHint" : "reviewHint")}</Typography.Text></div>
        <Badge status={report ? "success" : "info"}>{t(report ? "available" : "review")}</Badge>
      </Card.Header>
      <Card.Body className={styles.detail}>
        <dl className={styles.facts}>
          <div><dt>{t("account")}</dt><dd><code>{workspace.accountId}</code></dd></div>
          <div><dt>{t("requestId")}</dt><dd><code>{requestId}</code></dd></div>
          {report ? <>
            <div><dt>{t("reportId")}</dt><dd><code>{report.reportId}</code></dd></div>
            <div><dt>{t("observedAt")}</dt><dd><WorkspaceTime value={report.observedAt} /></dd></div>
            <div><dt>{t("expiresAt")}</dt><dd><WorkspaceTime value={report.expiresAt} /></dd></div>
            <div><dt>{t("settingsVersion")}</dt><dd>v{report.accountSecuritySettingsVersion}</dd></div>
          </> : null}
          <div><dt>{t("format")}</dt><dd>{t("formatV1")}</dd></div>
          <div><dt>{t("retention")}</dt><dd>{t("retentionValue", { days: accountSecurityReportLimits.retainedDays, reports: accountSecurityReportLimits.retainedReports })}</dd></div>
          <div><dt>{t("permissions")}</dt><dd className={styles.reportPermissions}><code>iam.security-report.create</code><code>iam.security-report.read</code><code>iam.security-report.download</code></dd></div>
        </dl>
      </Card.Body>
    </Card>
    {report ? <Tabs.Root defaultValue="overview">
      <Tabs.List aria-label={t("reportSections")}>
        <Tabs.Trigger value="overview">{t("overviewTab")}</Tabs.Trigger>
        <Tabs.Trigger value="users">{t("usersTab", { count: report.users.length })}</Tabs.Trigger>
        <Tabs.Trigger value="accessKeys">{t("accessKeysTab", { count: report.accessKeys.length })}</Tabs.Trigger>
      </Tabs.List>
      <Tabs.Content className={styles.stack} value="overview">
        <Card>
          <Card.Header><div><Typography.Title as="h2" level={3}>{t("scopeTitle")}</Typography.Title><Typography.Text tone="muted">{t("scopeHint")}</Typography.Text></div><Badge status="info">{t("immutable")}</Badge></Card.Header>
          <Card.Body className={styles.securityReportBody}>
            <dl className={styles.securityReportSummary} aria-label={t("limitsTitle")}>
              <div><dt>{t("users")}</dt><dd>{report.totals.users} / {accountSecurityReportLimits.users}</dd></div>
              <div><dt>{t("accessKeys")}</dt><dd>{report.totals.accessKeys} / {accountSecurityReportLimits.accessKeys}</dd></div>
              <div><dt>{t("rows")}</dt><dd>{report.totals.rows} / {accountSecurityReportLimits.rows}</dd></div>
              <div><dt>{t("content")}</dt><dd>≤ 4 MiB</dd></div>
            </dl>
            <ul className={styles.securityChecks}>
              {scopes.map((scope) => <li key={scope.id}><div className={styles.securityCheckCopy}><div className={styles.securityCheckHeading}><strong>{t(`scopes.${scope.id}.title`)}</strong><Badge status="info">{t("rowCount", { count: scope.rows })}</Badge></div><p>{t(`scopes.${scope.id}.fields`)}</p><span className={styles.securityEvidenceState}>{t(`scopes.${scope.id}.csv`)}</span></div></li>)}
            </ul>
            <Alert status="warning">{t("commitmentBoundary")}</Alert>
          </Card.Body>
        </Card>
        <Card>
          <Card.Header><div><Typography.Title as="h2" level={3}>{t("evidenceTitle")}</Typography.Title><Typography.Text tone="muted">{t("evidenceHint")}</Typography.Text></div></Card.Header>
          <Card.Body className={styles.securityReportBody}>
            <ul className={styles.securityChecks}>
              {report.coverage.map((coverage) => <li key={coverage.source}><div className={styles.securityCheckCopy}><div className={styles.securityCheckHeading}><strong>{t(`coverageSources.${coverage.source}.title`)}</strong><Badge status={coverage.state === "COMPLETE" ? "success" : "neutral"}>{t(`coverage.${coverage.state}`)}</Badge></div><p>{t(`coverageSources.${coverage.source}.hint`)}</p></div></li>)}
            </ul>
          </Card.Body>
        </Card>
        <Card>
          <Card.Header><Typography.Title as="h2" level={3}>{t("failureTitle")}</Typography.Title></Card.Header>
          <Card.Body><dl className={styles.activityEvidence} aria-label={t("failureTitle")}>
            {accountSecurityReportFailureBoundaries.map((boundary) => <div key={boundary}><dt>{failureTitle(boundary)}</dt><dd><Badge status="neutral">{t(`failures.${boundary}.status`)}</Badge><span>{t(`failures.${boundary}.hint`)}</span></dd></div>)}
          </dl></Card.Body>
        </Card>
      </Tabs.Content>
      <Tabs.Content value="users">
        <WorkspaceCollection embedded title={t("userEvidenceTitle")} description={t("userEvidenceHint")} items={report.users}
          columns={[t("user"), t("status"), t("rootIdentity"), t("mfa"), t("passwordLogin")]}
          keywords={(user) => `${user.loginName} ${user.displayName} ${user.status} ${user.mfaState} ${user.lastPasswordLogin.state}`}
          row={(user) => <><td><strong>{user.displayName}</strong><small><code>{user.loginName}</code> · {user.id}</small></td><td><Badge status={user.status === "ACTIVE" ? "success" : "neutral"}>{t(`states.${user.status}`)}</Badge>{user.mustChangePassword ? <small>{t("mustChangePassword")}</small> : null}</td><td>{user.root ? <Badge status="info">{t("root")}</Badge> : t("member")}</td><td><span>{t(`mfaStates.${user.mfaState}`)}</span><small>{user.resourceVersion ? t("resourceVersion", { version: user.resourceVersion }) : t("versionUnavailable")}</small></td><td><Badge status={user.lastPasswordLogin.state === "OBSERVED" ? "success" : user.lastPasswordLogin.state === "UNKNOWN" ? "warning" : "neutral"}>{t(`observations.${user.lastPasswordLogin.state}`)}</Badge>{user.lastPasswordLogin.observedAt ? <small><WorkspaceTime value={user.lastPasswordLogin.observedAt} /></small> : null}</td></>}
          footerNote={t("userEvidenceHint")} />
      </Tabs.Content>
      <Tabs.Content value="accessKeys">
        <WorkspaceCollection embedded title={t("keyEvidenceTitle")} description={t("keyEvidenceHint")} items={report.accessKeys}
          columns={[t("accessKey"), t("owner"), t("status"), t("network"), t("authorizationObservation")]}
          keywords={(key) => `${key.id} ${key.userId} ${key.status} ${key.allowedSourceCidrs.join(" ")} ${key.authorization.product ?? ""} ${key.authorization.action ?? ""}`}
          row={(key) => <><td><code>{key.id}</code><small>{t("resourceVersion", { version: key.resourceVersion })} · <WorkspaceTime value={key.createdAt} /></small></td><td><code>{key.userId}</code></td><td><Badge status={key.status === "ENABLED" ? "success" : "neutral"}>{t(`keyStates.${key.status}`)}</Badge></td><td>{key.allowedSourceCidrs.length ? key.allowedSourceCidrs.map((cidr) => <code key={cidr}>{cidr}</code>) : t("allNetworks")}</td><td><Badge status={key.authorization.state === "OBSERVED" ? key.authorization.allowed ? "success" : "warning" : "neutral"}>{key.authorization.state === "OBSERVED" ? t(key.authorization.allowed ? "allowed" : "denied") : t(`observations.${key.authorization.state}`)}</Badge>{key.authorization.action ? <small>{key.authorization.product} · <code>{key.authorization.action}</code></small> : null}{key.authorization.sourceIp ? <small>{t("sourceIp")} · <code>{key.authorization.sourceIp}</code></small> : null}{key.authorization.observedAt ? <small><WorkspaceTime value={key.authorization.observedAt} /></small> : null}</td></>}
          footerNote={t("keyEvidenceHint")} />
      </Tabs.Content>
    </Tabs.Root> : <>
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{t("scopeTitle")}</Typography.Title><Typography.Text tone="muted">{t("scopeHint")}</Typography.Text></div><Badge status="info">{t("immutable")}</Badge></Card.Header>
      <Card.Body className={styles.securityReportBody}>
        <dl className={styles.securityReportSummary} aria-label={t("limitsTitle")}>
          <div><dt>{t("users")}</dt><dd>{plannedUsers} / {accountSecurityReportLimits.users}</dd></div>
          <div><dt>{t("accessKeys")}</dt><dd>{workspace.keys.length} / {accountSecurityReportLimits.accessKeys}</dd></div>
          <div><dt>{t("rows")}</dt><dd>{totalRows} / {accountSecurityReportLimits.rows}</dd></div>
          <div><dt>{t("content")}</dt><dd>≤ 4 MiB</dd></div>
        </dl>
        <ul className={styles.securityChecks}>
          {scopes.map((scope) => <li key={scope.id}><div className={styles.securityCheckCopy}><div className={styles.securityCheckHeading}><strong>{t(`scopes.${scope.id}.title`)}</strong><Badge status="info">{t("rowCount", { count: scope.rows })}</Badge></div><p>{t(`scopes.${scope.id}.fields`)}</p><span className={styles.securityEvidenceState}>{t(`scopes.${scope.id}.csv`)}</span></div></li>)}
        </ul>
        {limitViolation ? <Alert status="danger">{t(`limitViolations.${limitViolation}`)}</Alert> : <Alert status="warning">{t("limitBoundary")}</Alert>}
      </Card.Body>
    </Card>
    <Card>
      <Card.Header><Typography.Title as="h2" level={3}>{t("beforeGenerateTitle")}</Typography.Title></Card.Header>
      <Card.Body className={styles.securityReportBody}><p className={styles.note}>{t("beforeGenerateHint")}</p><Alert status="warning">{t("noRealtimeConclusion")}</Alert></Card.Body>
    </Card>
    <Card>
      <Card.Header><Typography.Title as="h2" level={3}>{t("failureTitle")}</Typography.Title></Card.Header>
      <Card.Body><dl className={styles.activityEvidence} aria-label={t("failureTitle")}>
        {accountSecurityReportFailureBoundaries.map((boundary) => <div key={boundary}><dt>{failureTitle(boundary)}</dt><dd><Badge status="neutral">{t(`failures.${boundary}.status`)}</Badge><span>{t(`failures.${boundary}.hint`)}</span></dd></div>)}
      </dl></Card.Body>
    </Card>
    </>}
  </WorkspaceDetail>;
}

export function AccessReportPreview({ kind, workspace, scene, currentSession = null, onBack }: {
  kind: "credentials" | "security";
  workspace: AccessWorkspace;
  scene: AccountAccessScene;
  currentSession?: SessionSummary | null;
  onBack(): void;
}) {
  return kind === "security"
    ? <AccountSecurityReportPreview workspace={workspace} scene={scene} currentSession={currentSession} onBack={onBack} />
    : <CredentialReportPreview workspace={workspace} scene={scene} onBack={onBack} />;
}

function ExpiredSecurityReportPreview({ entry, onBack }: { entry: AccountSecurityReportDirectoryEntry; onBack(): void }) {
  const t = useTranslations("IamWorkspace.securityReportDirectory");
  const report = entry.report;
  return <WorkspaceDetail title={t("detailTitle")} onBack={onBack}>
    <Alert status="warning">{t("expiredBoundary")}</Alert>
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{report.reportId}</Typography.Title><Typography.Text tone="muted">{t("expiredHint")}</Typography.Text></div><Badge status="neutral">{t("statuses.expired")}</Badge></Card.Header>
      <Card.Body className={styles.detail}>
        <dl className={styles.facts}>
          <div><dt>{t("account")}</dt><dd><code>{report.accountId}</code></dd></div>
          <div><dt>{t("reportId")}</dt><dd><code>{report.reportId}</code></dd></div>
          <div><dt>{t("observedAt")}</dt><dd><WorkspaceTime value={report.observedAt} /></dd></div>
          <div><dt>{t("expiresAt")}</dt><dd><WorkspaceTime value={report.expiresAt} /></dd></div>
          <div><dt>{t("format")}</dt><dd>CSV v{report.formatVersion}</dd></div>
          <div><dt>{t("rows")}</dt><dd>{report.totals.rows}</dd></div>
        </dl>
      </Card.Body>
    </Card>
  </WorkspaceDetail>;
}

export function SecurityReportDirectoryPreview({ workspace, scene, currentSession = null }: {
  workspace?: AccessWorkspace;
  scene: AccountAccessScene;
  currentSession?: SessionSummary | null;
}) {
  const t = useTranslations("IamWorkspace.securityReportDirectory");
  const [referenceAt] = useState(() => new Date().toISOString());
  const [selected, setSelected] = useState<AccountSecurityReportDirectoryEntry | null>(null);
  const [creating, setCreating] = useState(false);
  const reports = useMemo(() => workspace
    ? buildAccountSecurityReportDirectoryPreview(workspace, scene, referenceAt, currentSession)
    : [], [currentSession, referenceAt, scene, workspace]);

  if (!workspace) return <div className={styles.stack}>
    <ContentPage.Heading title={t("title")} scrollKey="security-report-directory-live" />
    <Alert status="info">{t("liveBoundary")}</Alert>
    <EmptyState title={t("liveUnavailableTitle")} description={t("liveUnavailableHint")} />
  </div>;
  if (creating) return <AccountSecurityReportPreview workspace={workspace} scene={scene} currentSession={currentSession} onBack={() => setCreating(false)} />;
  if (selected) return selected.status === "expired"
    ? <ExpiredSecurityReportPreview entry={selected} onBack={() => setSelected(null)} />
    : <AccountSecurityReportPreview workspace={workspace} scene={scene} currentSession={currentSession} initialReport={selected.report} onBack={() => setSelected(null)} />;

  const available = reports.filter((entry) => entry.status !== "expired").length;
  const expiringSoon = reports.filter((entry) => entry.status === "expiringSoon").length;
  const expired = reports.filter((entry) => entry.status === "expired").length;
  return <WorkspaceCollection title={t("title")} description={t("description")} items={reports}
    create={{ label: t("create"), onClick: () => setCreating(true) }}
    columns={[t("report"), t("observedAt"), t("coverage"), t("rows"), t("retentionStatus")]}
    keywords={(entry) => `${entry.status} ${entry.report.accountId} ${entry.report.formatVersion}`}
    filter={{ label: t("retentionStatus"), options: (["available", "expiringSoon", "expired"] as const).map((status) => ({ value: status, label: t(`statuses.${status}`) })), matches: (entry, status) => entry.status === status }}
    intro={<div className={styles.stack}>
      <Alert status="info">{t("mockBoundary")}</Alert>
      <dl className={styles.securityReportSummary} aria-label={t("summary")}>
        <div><dt>{t("readable")}</dt><dd>{available}</dd></div>
        <div><dt>{t("expiringSoon")}</dt><dd>{expiringSoon}</dd></div>
        <div><dt>{t("expired")}</dt><dd>{expired}</dd></div>
        <div><dt>{t("retentionLimit")}</dt><dd>{reports.length} / {accountSecurityReportLimits.retainedReports}</dd></div>
      </dl>
    </div>}
    row={(entry) => <>
      <td><button className={styles.userLink} onClick={() => setSelected(entry)}>{entry.report.reportId}</button><small>{t("formatValue", { version: entry.report.formatVersion })}</small></td>
      <td><WorkspaceTime value={entry.report.observedAt} /></td>
      <td><span>{t("coverageValue", { count: entry.report.coverage.filter((item) => item.state === "COMPLETE").length, total: entry.report.coverage.length })}</span><small>{t("iamOnly")}</small></td>
      <td>{entry.report.totals.rows}</td>
      <td><Badge status={reportDirectoryStatus[entry.status]}>{t(`statuses.${entry.status}`)}</Badge><small><WorkspaceTime value={entry.report.expiresAt} /></small></td>
    </>}
    status={t("fixtureCount", { count: reports.length })}
    footerNote={t("directoryBoundary")} />;
}

export function AccessReports({ workspace, scene, currentSession = null, onNavigate, onOpenReport, reportTriggerRef }: {
  workspace: AccessWorkspace;
  scene: AccountAccessScene;
  currentSession?: SessionSummary | null;
  onNavigate(view: AccountAccessView, id?: string): void;
  onOpenReport?(kind: "credentials" | "security"): void;
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
      <div className={styles.actions}><Badge status="info">{t("mockEvidence")}</Badge><Button size="small" variant="ghost" onClick={() => onNavigate("access-analysis")}>{t("accessAnalysis.open")}<ArrowRight aria-hidden="true" /></Button></div>
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
        { id: "security", label: t("securityReport"), onSelect: () => onNavigate("security-reports") }
      ]} /> : null}
    </Card.Footer>
  </Card>;
}
