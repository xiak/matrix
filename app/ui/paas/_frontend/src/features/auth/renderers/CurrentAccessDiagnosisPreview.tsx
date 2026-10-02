"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { FileSearch, ShieldQuestion } from "lucide-react";
import { Alert, Badge, Button, Card, EmptyState, FormField, Select, Table } from "@ui/xiak";
import type { AccountAccessView } from "../domain/accounts";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import { type AccessPolicyDecision, type AccessTestResult, evaluateUserAccess } from "../domain/policyEvaluation";
import { parsePolicyResource } from "../domain/policyLanguage";
import { policyActions, previewAuthorizationCatalogVersion } from "../domain/previewAuthorizationCatalog";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import styles from "./CurrentAccessDiagnosisPreview.module.css";

type Scenario = AccessWorkspace["testRequests"][number];
type DiagnosisSnapshot = { scenario: Scenario; result: AccessTestResult; workspace: AccessWorkspace };
type DiagnosisMessage =
  | "reasons.explicitDeny" | "reasons.indeterminate" | "reasons.boundaryNotAllowing" | "reasons.noMatchingAllow" | "reasons.matchingAllow"
  | "errors.unknownIdentity" | "errors.unknownResource" | "errors.crossTenant" | "errors.unknownAction" | "errors.actionResourceMismatch"
  | "errors.requiresRoleTrust" | "errors.authorityRequired" | "errors.expiredSession" | "errors.revokedSession" | "errors.unavailableSession";

function stableReason(result: AccessTestResult): DiagnosisMessage {
  if (result.error) return `errors.${result.error}`;
  if (result.decision === "explicitDeny") return "reasons.explicitDeny";
  if (result.decision === "indeterminate") return "reasons.indeterminate";
  if (result.decision === "implicitDeny" && result.boundary?.decision !== "allow") return "reasons.boundaryNotAllowing";
  if (result.decision === "implicitDeny") return "reasons.noMatchingAllow";
  return "reasons.matchingAllow";
}

function decisionStatus(decision: AccessTestResult["decision"]): "success" | "danger" | "warning" | "neutral" {
  if (decision === "allow") return "success";
  if (decision === "explicitDeny") return "danger";
  if (decision === "implicitDeny" || decision === "indeterminate") return "warning";
  return "neutral";
}

function layerDecision(decision?: AccessPolicyDecision) {
  return decision ?? "notEvaluated";
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

  const result = current?.result;
  const evidence = result?.evidence ?? [];
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
        setSnapshot({ scenario, workspace, result: evaluateUserAccess(workspace, scene.users.map((entry) => entry.id), scenario.request) });
      }}><FileSearch aria-hidden="true" />{t("run")}</Button><span>{t("runHint")}</span></div>
    </Card.Body></Card>

    {result ? <Card><Card.Header><div className={styles.cardHeading}><div><span>{t("step", { number: 2 })}</span><h2 ref={resultHeading} tabIndex={-1}>{t("resultTitle")}</h2></div><Badge status={decisionStatus(result.decision)}>{t(`decisions.${result.decision}`)}</Badge></div></Card.Header><Card.Body className={styles.stack}>
      <Alert status={result.decision === "allow" ? "warning" : result.decision === "explicitDeny" ? "danger" : "warning"}><strong>{t(stableReason(result))}</strong><p>{t("resultBoundary")}</p></Alert>
      <section className={styles.layers} aria-labelledby="diagnosis-layers-title"><div className={styles.sectionHeading}><h3 id="diagnosis-layers-title">{t("layersTitle")}</h3><p>{t("layersHint")}</p></div><ol>
        <li><span>1</span><div><strong>{t("layers.identity")}</strong><Badge status={decisionStatus(layerDecision(result.principalPolicyDecision) as AccessTestResult["decision"])}>{t(`layerStates.${layerDecision(result.principalPolicyDecision)}`)}</Badge><p>{t("layerHints.identity")}</p></div></li>
        <li><span>2</span><div><strong>{t("layers.boundary")}</strong><Badge status={result.boundary ? decisionStatus(result.boundary.decision) : "neutral"}>{t(`layerStates.${result.boundary ? result.boundary.decision : "notConfigured"}`)}</Badge><p>{t(result.boundary ? "layerHints.boundary" : "layerHints.boundaryAbsent")}</p></div></li>
        <li><span>3</span><div><strong>{t("layers.session")}</strong><Badge status="neutral">{t("layerStates.notApplicable")}</Badge><p>{t("layerHints.session")}</p></div></li>
        <li><span>4</span><div><strong>{t("layers.execution")}</strong><Badge status="neutral">NOT_EVALUATED</Badge><p>{t("layerHints.execution")}</p></div></li>
      </ol></section>
      <div className={styles.resultActions}>{subject ? <Button variant="ghost" size="small" onClick={() => onOpen("users", subject.id)}>{t("inspectSubject", { name: subject.loginName })}</Button> : null}<span>{t("resultProvenance")}</span></div>
    </Card.Body>
    {evidence.length ? <Table aria-label={t("evidenceTitle")} mobileLayout="stack"><thead><tr><th scope="col">{t("policy")}</th><th scope="col">{t("source")}</th><th scope="col">{t("statement")}</th><th scope="col">{t("evidenceState")}</th></tr></thead><tbody>{evidence.map((entry, index) => <tr key={`${entry.policyId}:${entry.source}:${entry.groupId ?? ""}:${entry.statement ?? index}`}>
      <td data-label={t("policy")}>{entry.policyName}<small>{entry.version ? `v${entry.version}` : "—"}</small></td>
      <td data-label={t("source")}>{t(`sources.${entry.source}`)}{entry.groupId ? <small>{workspace.groups.find((group) => group.id === entry.groupId)?.name ?? entry.groupId}</small> : null}</td>
      <td data-label={t("statement")}>{entry.effect ? <Badge>{entry.effect.toUpperCase()}</Badge> : "—"}<small>{entry.statement ? `#${entry.statement}` : "—"}</small></td>
      <td data-label={t("evidenceState")}><Badge status={entry.reason === "matched" ? "success" : entry.reason === "missingContext" || entry.reason === "invalidPolicy" ? "warning" : "neutral"}>{t(`evidenceReasons.${entry.reason}`)}</Badge>{entry.missing?.length ? <small>{t("missingFacts", { conditions: entry.missing.map((fact) => t(`facts.${fact}`)).join(" · ") })}</small> : null}</td>
    </tr>)}</tbody></Table> : <Card.Body><EmptyState title={t("noEvidenceTitle")} description={t("noEvidenceHint")} /></Card.Body>}
    </Card> : <p className={styles.beforeRun}>{t("beforeRun")}</p>}
  </div>;
}
