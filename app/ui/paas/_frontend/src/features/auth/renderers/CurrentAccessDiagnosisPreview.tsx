"use client";

import { useEffect, useRef, useState, type RefObject } from "react";
import { useTranslations } from "next-intl";
import { FileSearch, ShieldQuestion } from "lucide-react";
import { Alert, Badge, Button, Card, EmptyState, FormField, Select, Table } from "@ui/xiak";
import {
  previewAccessDiagnosisBinding,
  projectPreviewAccessDiagnosis,
  type AccessDiagnosisScenario,
  type AuthorizationDiagnosisBinding,
  type CurrentAccessDiagnosis,
  type PreviewAccessDiagnosis
} from "../domain/accessDiagnosis";
import type { AccountAccessView } from "../domain/accounts";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./CurrentAccessDiagnosisPreview.module.css";

type DiagnosisSnapshot = {
  scenarioId: AccessDiagnosisScenario["id"];
  workspace: AccessWorkspace;
  projection: PreviewAccessDiagnosis;
};

function LiveDiagnosisBoundary() {
  const t = useTranslations("CurrentAccessDiagnosis");
  return <Card>
    <Card.Header><div className={styles.cardHeading}><div><span>{t("liveEyebrow")}</span><h2>{t("unavailableTitle")}</h2></div><Badge status="neutral">LIVE · NOT_CONNECTED</Badge></div></Card.Header>
    <Card.Body className={styles.unavailable}>
      <EmptyState icon={<ShieldQuestion aria-hidden="true" />} title={t("liveEntryTitle")} description={t("unavailableHint")} />
      <dl className={styles.liveBoundary} aria-label={t("liveBoundaryTitle")}>
        <div><dt>{t("liveEntry")}</dt><dd>{t("liveEntryHint")}</dd></div>
        <div><dt>{t("liveMediator")}</dt><dd>{t("liveMediatorHint")}</dd></div>
        <div><dt>{t("liveBrowser")}</dt><dd>{t("liveBrowserHint")}</dd></div>
      </dl>
      <Alert status="info"><strong>{t("liveHandoffTitle")}</strong><p>{t("unavailableBoundary")}</p></Alert>
    </Card.Body>
  </Card>;
}

function DiagnosisRequestPreview({
  workspace,
  scenario,
  binding,
  subjectName,
  onScenarioChange,
  onRun
}: {
  workspace: AccessWorkspace;
  scenario: AccessDiagnosisScenario;
  binding: AuthorizationDiagnosisBinding;
  subjectName?: string;
  onScenarioChange(value: AccessDiagnosisScenario["id"]): void;
  onRun(): void;
}) {
  const t = useTranslations("CurrentAccessDiagnosis");
  const rules = useTranslations("PolicyRules");
  const contextSummary = [
    binding.networkContext ? t("networkContextPresent") : t("networkContextAbsent"),
    t("resourceTagCount", { count: binding.resourceTags?.length ?? 0 }),
    t("requestTagCount", { count: binding.requestTags?.length ?? 0 })
  ].join(" · ");
  return <Card>
    <Card.Header><div className={styles.cardHeading}><div><span>{t("step", { number: 1 })}</span><h2>{t("requestTitle")}</h2></div><Badge status="warning">MOCK</Badge></div></Card.Header>
    <Card.Body className={styles.stack}>
      <FormField id="access-diagnosis-scenario" label={t("scenario")} hint={t("scenarioHint")}>
        <Select
          id="access-diagnosis-scenario"
          value={scenario.id}
          options={workspace.testRequests.map((entry) => ({ value: entry.id, label: t(`scenarios.${entry.id}.label`) }))}
          onValueChange={(value) => onScenarioChange(value as AccessDiagnosisScenario["id"])}
        />
      </FormField>
      <p className={styles.scenarioHint}>{t(`scenarios.${scenario.id}.hint`)}</p>
      <dl className={styles.requestGrid} aria-label={t("bindingTitle")}>
        <div><dt>{t("subject")}</dt><dd><strong>{subjectName ?? binding.subject.id}</strong><code>{binding.subject.type} · {binding.subject.id}</code><Badge status="neutral">{t("syntheticIdentity")}</Badge></dd></div>
        <div><dt>{t("profileBinding")}</dt><dd><strong>{rules(`services.${binding.profile.product}`)}</strong><code>{binding.profile.product} · r{binding.profile.revision}</code><small><code>{binding.profile.contentDigest}</code></small></dd></div>
        <div><dt>{t("actionResourceBinding")}</dt><dd><strong><code>{binding.action}</code></strong><code>{binding.resource.kind}:{binding.resource.id}</code><Badge status="neutral">{binding.resourceMode}</Badge></dd></div>
        <div><dt>{t("requestContext")}</dt><dd><strong>{contextSummary}</strong><small>{t("contextBoundary")}</small><Badge status="neutral">{t("notObserved")}</Badge></dd></div>
      </dl>
      <div className={styles.actions}><Button onClick={onRun}><FileSearch aria-hidden="true" />{t("run")}</Button><span>{t("runHint")}</span></div>
    </Card.Body>
  </Card>;
}

function DiagnosisSourcesTable({ diagnosis }: { diagnosis: CurrentAccessDiagnosis }) {
  const t = useTranslations("CurrentAccessDiagnosis");
  if (!diagnosis.sources.length) return <Card.Body><EmptyState title={t("noSourcesTitle")} description={t("noSourcesHint")} /></Card.Body>;
  return <div className={styles.sourcesTable}><Table aria-label={t("sourcesTitle")} mobileLayout="stack">
    <thead><tr><th scope="col">{t("sourceKind")}</th><th scope="col">{t("effect")}</th><th scope="col">{t("policyVersion")}</th><th scope="col">{t("sourceReference")}</th></tr></thead>
    <tbody>{diagnosis.sources.map((entry) => <tr key={`${entry.kind}:${entry.effect}:${entry.version.policyId}:${entry.version.versionId}:${entry.attachmentId ?? ""}:${entry.membershipId ?? ""}`}>
      <td data-label={t("sourceKind")}><strong>{entry.kind}</strong><small>{t(`sources.${entry.kind}`)}</small></td>
      <td data-label={t("effect")}><Badge status={entry.effect === "ALLOW" ? "success" : "danger"}>{entry.effect}</Badge></td>
      <td data-label={t("policyVersion")}><strong><code>{entry.version.policyId} · {entry.version.versionId}</code></strong><small><code>{entry.version.contentDigest}</code></small><small>{t("syntheticReference")}</small></td>
      <td data-label={t("sourceReference")}><code>{entry.attachmentId ?? "—"}</code>{entry.membershipId ? <small><code>{entry.membershipId}</code></small> : null}</td>
    </tr>)}</tbody>
  </Table></div>;
}

function DiagnosisResult({
  diagnosis,
  subjectName,
  headingRef,
  onInspectSubject
}: {
  diagnosis: CurrentAccessDiagnosis;
  subjectName?: string;
  headingRef: RefObject<HTMLHeadingElement | null>;
  onInspectSubject(): void;
}) {
  const t = useTranslations("CurrentAccessDiagnosis");
  return <Card>
    <Card.Header><div className={styles.cardHeading}><div><span>{t("step", { number: 2 })}</span><h2 ref={headingRef} tabIndex={-1}>{t("resultTitle")}</h2></div><Badge status={diagnosis.outcome === "ALLOWED" ? "success" : "danger"}>{diagnosis.outcome} · MOCK</Badge></div></Card.Header>
    <Card.Body className={styles.stack}>
      <Alert status={diagnosis.outcome === "ALLOWED" ? "warning" : "danger"}><strong>{t(diagnosis.outcome === "ALLOWED" ? "allowedSummary" : "deniedSummary")}</strong><p>{t("resultBoundary")}</p></Alert>
      <dl className={styles.resultFacts} aria-label={t("resultFactsTitle")}>
        <div><dt>{t("contractType")}</dt><dd><strong>{diagnosis.kind}</strong><code>{diagnosis.apiVersion}</code></dd></div>
        <div><dt>{t("scope")}</dt><dd><strong>TENANT</strong><code>{diagnosis.tenantId}</code></dd></div>
        <div><dt>{t("evaluatedAt")}</dt><dd><WorkspaceTime value={diagnosis.evaluatedAt} /></dd></div>
        <div><dt>{t("requestId")}</dt><dd><code>{diagnosis.requestId}</code><small>{t("syntheticReference")}</small></dd></div>
        <div><dt>{t("correlationId")}</dt><dd><code>{diagnosis.correlationId}</code><small>{t("syntheticReference")}</small></dd></div>
        <div><dt>{t("responseBinding")}</dt><dd><code>{diagnosis.subject.type}:{diagnosis.subject.id}</code><small>{diagnosis.profile.product} · r{diagnosis.profile.revision} · {diagnosis.resourceMode}</small></dd></div>
      </dl>
      <section className={styles.contractSection} aria-labelledby="diagnosis-reasons-title"><div className={styles.sectionHeading}><h3 id="diagnosis-reasons-title">{t("reasonsTitle")}</h3><p>{t("reasonsHint")}</p></div>{diagnosis.reasons.length ? <ul className={styles.reasonList}>{diagnosis.reasons.map((reason) => <li key={reason}><Badge status="danger">{reason}</Badge><span>{t(`reasonDescriptions.${reason}`)}</span></li>)}</ul> : <Alert status="info">{t("noReasons")}</Alert>}</section>
      <section className={styles.contractSection} aria-labelledby="diagnosis-restrictions-title"><div className={styles.sectionHeading}><h3 id="diagnosis-restrictions-title">{t("restrictionsTitle")}</h3><p>{t("restrictionsHint")}</p></div><ul className={styles.restrictionList}>{diagnosis.restrictions.map((restriction) => <li key={restriction.kind}><div><strong>{restriction.kind}</strong><span>{t(`restrictionDescriptions.${restriction.kind}`)}</span></div><Badge status={restriction.state === "MATCHED" ? "success" : restriction.state === "BLOCKED" ? "danger" : "neutral"}>{restriction.state}</Badge>{restriction.version ? <div className={styles.restrictionPolicy}><code>{restriction.version.policyId} · {restriction.version.versionId}</code><small><code>{restriction.version.contentDigest}</code></small><small>{t("syntheticReference")}</small></div> : restriction.contentDigest ? <div className={styles.restrictionPolicy}><code>{restriction.contentDigest}</code><small>{t("syntheticReference")}</small></div> : <span className={styles.restrictionEmpty}>—</span>}</li>)}</ul></section>
      <section className={styles.contractSection} aria-labelledby="diagnosis-boundaries-title"><div className={styles.sectionHeading}><h3 id="diagnosis-boundaries-title">{t("notEvaluatedTitle")}</h3><p>{t("notEvaluatedHint")}</p></div><dl className={styles.boundaryGrid}><div><dt>{t("resourceExistence")}</dt><dd><Badge status="neutral">{diagnosis.resourceExistence}</Badge></dd></div><div><dt>{t("businessOutcome")}</dt><dd><Badge status="neutral">{diagnosis.businessOutcome}</Badge></dd></div></dl></section>
      <div className={styles.resultActions}><Button variant="ghost" size="small" onClick={onInspectSubject}>{t("inspectSubject", { name: subjectName ?? diagnosis.subject.id })}</Button><span>{t("resultProvenance")}</span></div>
    </Card.Body>
    <DiagnosisSourcesTable diagnosis={diagnosis} />
  </Card>;
}

function UnavailableDiagnosisResult({ headingRef }: { headingRef: RefObject<HTMLHeadingElement | null> }) {
  const t = useTranslations("CurrentAccessDiagnosis");
  return <Card>
    <Card.Header><div className={styles.cardHeading}><div><span>{t("step", { number: 2 })}</span><h2 ref={headingRef} tabIndex={-1}>{t("resultTitle")}</h2></div><Badge status="warning">{t("unavailableResult")}</Badge></div></Card.Header>
    <Card.Body><Alert status="warning"><strong>{t("unavailableResultTitle")}</strong><p>{t("unavailableResultHint")}</p></Alert></Card.Body>
  </Card>;
}

export function CurrentAccessDiagnosisPreview({ workspace, scene, onOpen }: {
  workspace?: AccessWorkspace;
  scene: AccountAccessScene;
  onOpen(view: AccountAccessView, id?: string): void;
}) {
  const t = useTranslations("CurrentAccessDiagnosis");
  const [scenarioId, setScenarioId] = useState<AccessDiagnosisScenario["id"] | "">(() => workspace?.testRequests[0]?.id ?? "");
  const [snapshot, setSnapshot] = useState<DiagnosisSnapshot | null>(null);
  const resultHeading = useRef<HTMLHeadingElement>(null);
  const scenario = workspace?.testRequests.find((entry) => entry.id === scenarioId) ?? workspace?.testRequests[0];
  const binding = workspace && scenario ? previewAccessDiagnosisBinding(workspace, scenario) : null;
  const subject = scenario ? scene.users.find((entry) => entry.id === scenario.request.principalId) : undefined;
  const current = workspace && scenario && snapshot && snapshot.workspace === workspace && snapshot.scenarioId === scenario.id
    ? snapshot.projection
    : null;

  useEffect(() => {
    if (!current) return;
    resultHeading.current?.focus({ preventScroll: true });
    resultHeading.current?.scrollIntoView?.({ block: "center", inline: "nearest" });
  }, [current]);

  if (!workspace) return <LiveDiagnosisBoundary />;
  if (!scenario) return <EmptyState title={t("emptyTitle")} description={t("emptyHint")} />;
  if (!binding) return <EmptyState title={t("unavailableResultTitle")} description={t("unavailableResultHint")} />;
  return <div className={styles.root}>
    <Alert status="info"><strong>{t("previewTitle")}</strong><p>{t("previewBoundary")}</p></Alert>
    <DiagnosisRequestPreview
      workspace={workspace}
      scenario={scenario}
      binding={binding}
      subjectName={subject?.loginName}
      onScenarioChange={(value) => { setScenarioId(value); setSnapshot(null); }}
      onRun={() => setSnapshot({
        scenarioId: scenario.id,
        workspace,
        projection: projectPreviewAccessDiagnosis(workspace, scene.users.map((entry) => entry.id), scenario, new Date().toISOString())
      })}
    />
    {current?.state === "READY"
      ? <DiagnosisResult diagnosis={current.diagnosis} subjectName={subject?.loginName} headingRef={resultHeading} onInspectSubject={() => onOpen("users", current.diagnosis.subject.id)} />
      : current?.state === "UNAVAILABLE"
        ? <UnavailableDiagnosisResult headingRef={resultHeading} />
        : <p className={styles.beforeRun}>{t("beforeRun")}</p>}
  </div>;
}
