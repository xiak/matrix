"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { FileSearch, ShieldQuestion } from "lucide-react";
import { Alert, Badge, Button, Card, EmptyState, FormField, Select, Table } from "@ui/xiak";
import type { AccountAccessView } from "../domain/accounts";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import { type AccessTestEvidence, type AccessTestResult, evaluateUserAccess } from "../domain/policyEvaluation";
import { parsePolicyResource } from "../domain/policyLanguage";
import { policyActions, previewAuthorizationCatalogVersion } from "../domain/previewAuthorizationCatalog";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./CurrentAccessDiagnosisPreview.module.css";

type Scenario = AccessWorkspace["testRequests"][number];
type DiagnosisReason = "EXPLICIT_DENY" | "NO_MATCHING_ALLOW" | "USER_PERMISSION_BOUNDARY" | "ROLE_PERMISSION_BOUNDARY" | "SESSION_POLICY" | "CREDENTIAL_RESTRICTED" | "SUBJECT_UNSUPPORTED" | "CALLING_SERVICE_UNSUPPORTED" | "RESOURCE_CONTEXT_UNSUPPORTED";
type DiagnosisSource = {
  kind: "DIRECT" | "GROUP" | "ROLE" | "SERVICE_ROLE";
  effect: "ALLOW" | "DENY";
  policyId: string;
  policyName: string;
  version: number | null;
  attachmentId: string;
  membershipId?: string;
};
type DiagnosisRestriction = {
  kind: "USER_BOUNDARY" | "ROLE_BOUNDARY" | "SESSION_POLICY";
  state: "MATCHED" | "BLOCKED" | "NOT_APPLICABLE";
  policyId?: string;
  policyName?: string;
  version?: number | null;
};
type FixedDiagnosisPreview = {
  outcome: "ALLOWED" | "DENIED";
  reasons: DiagnosisReason[];
  sources: DiagnosisSource[];
  restrictions: DiagnosisRestriction[];
  requestId: string;
  correlationId: string;
  evaluatedAt: string;
  resourceExistence: "NOT_EVALUATED";
  businessOutcome: "NOT_EVALUATED";
};
type DiagnosisSnapshot =
  | { scenario: Scenario; workspace: AccessWorkspace; state: "READY"; diagnosis: FixedDiagnosisPreview }
  | { scenario: Scenario; workspace: AccessWorkspace; state: "UNAVAILABLE" };

const reasonOrder: DiagnosisReason[] = ["CALLING_SERVICE_UNSUPPORTED", "CREDENTIAL_RESTRICTED", "EXPLICIT_DENY", "NO_MATCHING_ALLOW", "RESOURCE_CONTEXT_UNSUPPORTED", "ROLE_PERMISSION_BOUNDARY", "SESSION_POLICY", "SUBJECT_UNSUPPORTED", "USER_PERMISSION_BOUNDARY"];

function resultReasons(result: AccessTestResult): DiagnosisReason[] | null {
  if (result.decision === "indeterminate") return null;
  if (result.error) {
    const reason: DiagnosisReason = result.error === "unknownAction" || result.error === "actionResourceMismatch"
      ? "CALLING_SERVICE_UNSUPPORTED"
      : result.error === "unknownResource" || result.error === "crossTenant"
        ? "RESOURCE_CONTEXT_UNSUPPORTED"
        : result.error === "unknownIdentity" || result.error === "requiresRoleTrust"
          ? "SUBJECT_UNSUPPORTED"
          : "CREDENTIAL_RESTRICTED";
    return [reason];
  }
  if (result.decision === "allow") return [];
  const reasons = new Set<DiagnosisReason>();
  if (result.decision === "explicitDeny") reasons.add("EXPLICIT_DENY");
  if (!result.evidence.some((entry) => entry.source !== "boundary" && entry.effect === "allow" && entry.reason === "matched")) reasons.add("NO_MATCHING_ALLOW");
  if (result.boundary && result.boundary.decision !== "allow") reasons.add("USER_PERMISSION_BOUNDARY");
  return reasonOrder.filter((reason) => reasons.has(reason));
}

function sourceKind(source: AccessTestEvidence["source"]): DiagnosisSource["kind"] | null {
  if (source === "direct") return "DIRECT";
  if (source === "group") return "GROUP";
  if (source === "role") return "ROLE";
  return null;
}

function diagnosisSources(scenario: Scenario, result: AccessTestResult): DiagnosisSource[] {
  const seen = new Set<string>();
  const sources: DiagnosisSource[] = [];
  for (const entry of result.evidence) {
    const kind = sourceKind(entry.source);
    if (!kind || entry.reason !== "matched" || !entry.effect) continue;
    const key = [kind, entry.effect, entry.policyId, entry.version ?? "", entry.groupId ?? ""].join(":");
    if (seen.has(key)) continue;
    seen.add(key);
    sources.push({
      kind,
      effect: entry.effect === "allow" ? "ALLOW" : "DENY",
      policyId: entry.policyId,
      policyName: entry.policyName,
      version: entry.version ?? null,
      attachmentId: `mock-attachment:${kind.toLowerCase()}:${entry.policyId}`,
      membershipId: entry.groupId ? `mock-membership:${entry.groupId}:${scenario.request.principalId}` : undefined
    });
  }
  return sources.sort((left, right) => [left.kind, left.effect, left.policyId, left.version ?? 0, left.attachmentId, left.membershipId ?? ""].join(":").localeCompare([right.kind, right.effect, right.policyId, right.version ?? 0, right.attachmentId, right.membershipId ?? ""].join(":")));
}

function diagnosisRestrictions(workspace: AccessWorkspace, result: AccessTestResult): DiagnosisRestriction[] {
  if (!result.boundary) return [{ kind: "USER_BOUNDARY", state: "NOT_APPLICABLE" }];
  const policy = workspace.policies.find((entry) => entry.id === result.boundary?.policyId);
  return [{
    kind: "USER_BOUNDARY",
    state: result.boundary.decision === "allow" ? "MATCHED" : "BLOCKED",
    policyId: result.boundary.policyId,
    policyName: policy?.name ?? result.boundary.policyId,
    version: policy?.versions.find((entry) => entry.id === policy.defaultVersion)?.id ?? null
  }];
}

function projectDiagnosis(workspace: AccessWorkspace, scene: AccountAccessScene, scenario: Scenario): DiagnosisSnapshot {
  const result = evaluateUserAccess(workspace, scene.users.map((entry) => entry.id), scenario.request);
  const reasons = resultReasons(result);
  if (!reasons) return { scenario, workspace, state: "UNAVAILABLE" };
  return {
    scenario,
    workspace,
    state: "READY",
    diagnosis: {
      outcome: result.decision === "allow" ? "ALLOWED" : "DENIED",
      reasons,
      sources: diagnosisSources(scenario, result),
      restrictions: diagnosisRestrictions(workspace, result),
      requestId: `mock-diagnosis:${scenario.id}`,
      correlationId: `mock-current-access:${scenario.id}`,
      evaluatedAt: new Date().toISOString(),
      resourceExistence: "NOT_EVALUATED",
      businessOutcome: "NOT_EVALUATED"
    }
  };
}

export function CurrentAccessDiagnosisPreview({ workspace, scene, onOpen }: {
  workspace?: AccessWorkspace;
  scene: AccountAccessScene;
  onOpen(view: AccountAccessView, id?: string): void;
}) {
  const t = useTranslations("CurrentAccessDiagnosis");
  const rules = useTranslations("PolicyRules");
  const [scenarioId, setScenarioId] = useState<Scenario["id"] | "">(() => workspace?.testRequests[0]?.id ?? "");
  const [snapshot, setSnapshot] = useState<DiagnosisSnapshot | null>(null);
  const resultHeading = useRef<HTMLHeadingElement>(null);
  const scenario = workspace?.testRequests.find((entry) => entry.id === scenarioId);
  const request = scenario?.request;
  const subject = request ? scene.users.find((entry) => entry.id === request.principalId) : undefined;
  const resource = request ? workspace?.testResources.find((entry) => entry.id === request.resourceId) : undefined;
  const parsedResource = useMemo(() => parsePolicyResource(resource?.reference ?? "", false), [resource?.reference]);
  const action = request ? policyActions.find((entry) => entry.id === request.action) : undefined;
  const current = snapshot && snapshot.workspace === workspace && snapshot.scenario.id === scenarioId ? snapshot : null;

  useEffect(() => {
    if (!current) return;
    resultHeading.current?.focus({ preventScroll: true });
    resultHeading.current?.scrollIntoView?.({ block: "center", inline: "nearest" });
  }, [current]);

  if (!workspace) return <Card><Card.Body className={styles.unavailable}>
    <Badge status="neutral">LIVE · NOT_CONNECTED</Badge>
    <EmptyState icon={<ShieldQuestion aria-hidden="true" />} title={t("unavailableTitle")} description={t("unavailableHint")} />
    <p>{t("unavailableBoundary")}</p>
  </Card.Body></Card>;

  if (!workspace.testRequests.length) return <EmptyState title={t("emptyTitle")} description={t("emptyHint")} />;

  const diagnosis = current?.state === "READY" ? current.diagnosis : null;
  return <div className={styles.root}>
    <Alert status="info"><strong>{t("previewTitle")}</strong><p>{t("previewBoundary")}</p></Alert>
    <Card><Card.Header><div className={styles.cardHeading}><div><span>{t("step", { number: 1 })}</span><h2>{t("requestTitle")}</h2></div><Badge status="warning">MOCK</Badge></div></Card.Header><Card.Body className={styles.stack}>
      <FormField id="access-diagnosis-scenario" label={t("scenario")} hint={t("scenarioHint")}>
        <Select id="access-diagnosis-scenario" value={scenarioId} options={workspace.testRequests.map((entry) => ({ value: entry.id, label: t(`scenarios.${entry.id}.label`) }))} onValueChange={(value) => { setScenarioId(value as Scenario["id"]); setSnapshot(null); }} />
      </FormField>
      {scenario ? <p className={styles.scenarioHint}>{t(`scenarios.${scenario.id}.hint`)}</p> : null}
      <dl className={styles.requestGrid}>
        <div><dt>{t("subject")}</dt><dd><strong>{subject?.loginName ?? request?.principalId}</strong><small>{request?.principalId}</small><Badge status="neutral">{t("syntheticIdentity")}</Badge></dd></div>
        <div><dt>{t("serviceAction")}</dt><dd><strong>{action ? rules(`services.${action.service}`) : "—"}</strong><code>{request?.action ?? "—"}</code><Badge status="neutral">{t("staticProfile", { version: previewAuthorizationCatalogVersion })}</Badge></dd></div>
        <div><dt>{t("resource")}</dt><dd><strong>{parsedResource?.id ?? request?.resourceId ?? "—"}</strong><code>{resource?.reference ?? "—"}</code><Badge status="neutral">{t("syntheticResource")}</Badge></dd></div>
        <div><dt>{t("requestContext")}</dt><dd><strong>{request?.sourceIp || request?.at ? t("syntheticContext") : t("contextNotProvided")}</strong><small>{t("contextBoundary")}</small><Badge status="neutral">{t("notObserved")}</Badge></dd></div>
      </dl>
      <div className={styles.actions}><Button disabled={!scenario || !subject || !resource || !action} onClick={() => {
        if (!scenario) return;
        setSnapshot(projectDiagnosis(workspace, scene, scenario));
      }}><FileSearch aria-hidden="true" />{t("run")}</Button><span>{t("runHint")}</span></div>
    </Card.Body></Card>

    {current?.state === "UNAVAILABLE" ? <Card><Card.Header><div className={styles.cardHeading}><div><span>{t("step", { number: 2 })}</span><h2 ref={resultHeading} tabIndex={-1}>{t("resultTitle")}</h2></div><Badge status="warning">{t("unavailableResult")}</Badge></div></Card.Header><Card.Body><Alert status="warning"><strong>{t("unavailableResultTitle")}</strong><p>{t("unavailableResultHint")}</p></Alert></Card.Body></Card> : diagnosis ? <Card><Card.Header><div className={styles.cardHeading}><div><span>{t("step", { number: 2 })}</span><h2 ref={resultHeading} tabIndex={-1}>{t("resultTitle")}</h2></div><Badge status={diagnosis.outcome === "ALLOWED" ? "success" : "danger"}>{diagnosis.outcome} · MOCK</Badge></div></Card.Header><Card.Body className={styles.stack}>
      <Alert status={diagnosis.outcome === "ALLOWED" ? "warning" : "danger"}><strong>{t(diagnosis.outcome === "ALLOWED" ? "allowedSummary" : "deniedSummary")}</strong><p>{t("resultBoundary")}</p></Alert>
      <dl className={styles.resultFacts} aria-label={t("resultFactsTitle")}>
        <div><dt>{t("scope")}</dt><dd><strong>TENANT</strong><code>{workspace.accountId}</code></dd></div>
        <div><dt>{t("evaluatedAt")}</dt><dd><WorkspaceTime value={diagnosis.evaluatedAt} /></dd></div>
        <div><dt>{t("requestId")}</dt><dd><code>{diagnosis.requestId}</code><small>{t("syntheticReference")}</small></dd></div>
        <div><dt>{t("correlationId")}</dt><dd><code>{diagnosis.correlationId}</code><small>{t("syntheticReference")}</small></dd></div>
      </dl>
      <section className={styles.contractSection} aria-labelledby="diagnosis-reasons-title"><div className={styles.sectionHeading}><h3 id="diagnosis-reasons-title">{t("reasonsTitle")}</h3><p>{t("reasonsHint")}</p></div>{diagnosis.reasons.length ? <ul className={styles.reasonList}>{diagnosis.reasons.map((reason) => <li key={reason}><Badge status="danger">{reason}</Badge><span>{t(`reasonDescriptions.${reason}`)}</span></li>)}</ul> : <Alert status="info">{t("noReasons")}</Alert>}</section>
      <section className={styles.contractSection} aria-labelledby="diagnosis-restrictions-title"><div className={styles.sectionHeading}><h3 id="diagnosis-restrictions-title">{t("restrictionsTitle")}</h3><p>{t("restrictionsHint")}</p></div><ul className={styles.restrictionList}>{diagnosis.restrictions.map((restriction) => <li key={restriction.kind}><div><strong>{restriction.kind}</strong><span>{t(`restrictionDescriptions.${restriction.kind}`)}</span></div><Badge status={restriction.state === "MATCHED" ? "success" : restriction.state === "BLOCKED" ? "danger" : "neutral"}>{restriction.state}</Badge>{restriction.policyId ? <div className={styles.restrictionPolicy}><strong>{restriction.policyName}</strong><code>{restriction.policyId} · {restriction.version ? `v${restriction.version}` : "—"}</code></div> : <span className={styles.restrictionEmpty}>—</span>}</li>)}</ul></section>
      <section className={styles.contractSection} aria-labelledby="diagnosis-boundaries-title"><div className={styles.sectionHeading}><h3 id="diagnosis-boundaries-title">{t("notEvaluatedTitle")}</h3><p>{t("notEvaluatedHint")}</p></div><dl className={styles.boundaryGrid}><div><dt>{t("resourceExistence")}</dt><dd><Badge status="neutral">{diagnosis.resourceExistence}</Badge></dd></div><div><dt>{t("businessOutcome")}</dt><dd><Badge status="neutral">{diagnosis.businessOutcome}</Badge></dd></div></dl></section>
      <div className={styles.resultActions}>{subject ? <Button variant="ghost" size="small" onClick={() => onOpen("users", subject.id)}>{t("inspectSubject", { name: subject.loginName })}</Button> : null}<span>{t("resultProvenance")}</span></div>
    </Card.Body>
    {diagnosis.sources.length ? <Table aria-label={t("sourcesTitle")} mobileLayout="stack"><thead><tr><th scope="col">{t("sourceKind")}</th><th scope="col">{t("effect")}</th><th scope="col">{t("policyVersion")}</th><th scope="col">{t("sourceReference")}</th></tr></thead><tbody>{diagnosis.sources.map((entry) => <tr key={`${entry.kind}:${entry.effect}:${entry.policyId}:${entry.version ?? ""}:${entry.attachmentId}:${entry.membershipId ?? ""}`}>
      <td data-label={t("sourceKind")}><strong>{entry.kind}</strong><small>{t(`sources.${entry.kind}`)}</small></td>
      <td data-label={t("effect")}><Badge status={entry.effect === "ALLOW" ? "success" : "danger"}>{entry.effect}</Badge></td>
      <td data-label={t("policyVersion")}><strong>{entry.policyName}</strong><small><code>{entry.policyId}</code> · {entry.version ? `v${entry.version}` : "—"}</small></td>
      <td data-label={t("sourceReference")}><code>{entry.attachmentId}</code>{entry.membershipId ? <small><code>{entry.membershipId}</code></small> : null}<small>{t("syntheticReference")}</small></td>
    </tr>)}</tbody></Table> : <Card.Body><EmptyState title={t("noSourcesTitle")} description={t("noSourcesHint")} /></Card.Body>}
    </Card> : <p className={styles.beforeRun}>{t("beforeRun")}</p>}
  </div>;
}
