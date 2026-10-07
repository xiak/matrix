"use client";

import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react";
import { ArrowRight, Rocket } from "lucide-react";
import { ActionMenu, Alert, Badge, Button, Card, FormField, Select, Steps, Table, Typography } from "@ui/xiak";
import { useTranslations } from "next-intl";
import type { ExperienceApplicationDeploymentSnapshot } from "../domain/experience";
import type { UnifiedResourceScene } from "../scenes/consoleScene";
import { useConsoleFormat } from "./useConsoleFormat";
import styles from "./ApplicationDeploymentManagement.module.css";

type DeploymentAction = "update" | "stop" | "rollback";
type WorkflowStep = "edit" | "review";
type PreviewOutcome = "success" | "noChange" | "idempotencyConflict" | "versionConflict" | "operationInProgress" | "denied" | "unavailable" | "responseLost";
type FailedAttempt = Exclude<PreviewOutcome, "success">;
const previewOutcomes: PreviewOutcome[] = ["success", "noChange", "idempotencyConflict", "versionConflict", "operationInProgress", "denied", "unavailable", "responseLost"];

type MockOperation = {
  id: string;
  action: "UPDATE" | "STOP" | "ROLLBACK";
  state: "ACCEPTED" | "SUCCEEDED";
  responseStatus: 200 | 202;
  target: string;
  requestedBy: { type: "USER"; id: "principal-lin"; accessKeyId: "MOCK-pipeline-key" };
  requestId: string;
  createdAt: string;
};

function phaseStatus(phase: ExperienceApplicationDeploymentSnapshot["deployment"]["phase"]) {
  if (phase === "READY") return "success" as const;
  if (phase === "DEGRADED" || phase === "STOPPING") return "warning" as const;
  if (phase === "FAILED") return "danger" as const;
  return "info" as const;
}

function etag(resourceVersion: number) {
  return `"${resourceVersion}"`;
}

export function ApplicationDeploymentManagement({ resource, initialSnapshot }: {
  resource: UnifiedResourceScene;
  initialSnapshot: ExperienceApplicationDeploymentSnapshot | undefined;
}) {
  const t = useTranslations("ApplicationDeploymentManagement");
  const format = useConsoleFormat();
  const scenarioId = useId();
  const [snapshot, setSnapshot] = useState(initialSnapshot);
  const [action, setAction] = useState<DeploymentAction | null>(null);
  const [step, setStep] = useState<WorkflowStep | null>(null);
  const [revisionId, setRevisionId] = useState("");
  const [replicas, setReplicas] = useState("1");
  const [sourceGeneration, setSourceGeneration] = useState("");
  const [scenario, setScenario] = useState<PreviewOutcome>("success");
  const [attempt, setAttempt] = useState<FailedAttempt | null>(null);
  const [draftError, setDraftError] = useState<string | null>(null);
  const [lastOperation, setLastOperation] = useState<MockOperation | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const updateRef = useRef<HTMLButtonElement>(null);
  const moreRef = useRef<HTMLButtonElement>(null);
  const opener = useRef<"update" | "more">("update");
  const [requestId, setRequestId] = useState("");
  const deployment = snapshot?.deployment;
  const rollbackSources = useMemo(() => snapshot?.acceptedGenerations.filter((item) => item.generation < (deployment?.generation ?? 0) && item.desiredState === "RUNNING") ?? [], [snapshot, deployment?.generation]);
  const blocked = Boolean(deployment?.currentOperationId) || ["PENDING", "PLACING", "APPLYING", "STOPPING"].includes(deployment?.phase ?? "");
  const steps = useMemo(() => ([{ id: "edit", label: t("steps.edit") }, { id: "review", label: t("steps.review") }]), [t]);

  useEffect(() => {
    if (step) headingRef.current?.focus({ preventScroll: true });
  }, [step]);

  function clearWorkflow(restoreFocus = true) {
    setAction(null);
    setStep(null);
    setAttempt(null);
    setDraftError(null);
    setScenario("success");
    setRequestId("");
    if (restoreFocus) requestAnimationFrame(() => (opener.current === "update" ? updateRef.current : moreRef.current)?.focus({ preventScroll: true }));
  }

  function start(next: DeploymentAction, source: "update" | "more") {
    if (!snapshot || blocked) return;
    opener.current = source;
    setRequestId("");
    setAction(next);
    setAttempt(null);
    setDraftError(null);
    setScenario("success");
    setRevisionId(snapshot.revisions.find((item) => item.id !== snapshot.deployment.applicationRevisionId)?.id ?? snapshot.deployment.applicationRevisionId);
    setReplicas(String(snapshot.deployment.components[0]?.replicas ?? 1));
    setSourceGeneration(String(rollbackSources[0]?.generation ?? ""));
    if (next === "stop") {
      setRequestId(`mock-deployment-${crypto.randomUUID()}`);
      setStep("review");
    } else setStep("edit");
  }

  function review(event: FormEvent) {
    event.preventDefault();
    if (!snapshot || !action) return;
    if (action === "update" && revisionId === snapshot.deployment.applicationRevisionId && Number(replicas) === (snapshot.deployment.components[0]?.replicas ?? 0)) {
      setDraftError(t("outcomes.noChange"));
      return;
    }
    if (action === "rollback" && !rollbackSources.some((item) => String(item.generation) === sourceGeneration)) {
      setDraftError(t("rollbackUnavailable"));
      return;
    }
    setRequestId(`mock-deployment-${crypto.randomUUID()}`);
    setAttempt(null);
    setDraftError(null);
    setStep("review");
  }

  function apply(event: FormEvent) {
    event.preventDefault();
    if (!snapshot || !action) return;
    if (scenario !== "success") {
      setAttempt(scenario);
      if (scenario === "versionConflict") {
        setSnapshot({ ...snapshot, deployment: { ...snapshot.deployment, resourceVersion: snapshot.deployment.resourceVersion + 1 } });
        setRequestId("");
        setStep("edit");
      }
      if (["versionConflict", "unavailable", "responseLost"].includes(scenario)) setScenario("success");
      requestAnimationFrame(() => headingRef.current?.focus({ preventScroll: true }));
      return;
    }

    const source = rollbackSources.find((item) => String(item.generation) === sourceGeneration);
    const operationAction = action === "update" ? "UPDATE" : action === "stop" ? "STOP" : "ROLLBACK";
    const nextGeneration = snapshot.deployment.generation + 1;
    const now = new Date().toISOString();
    const recoveredTerminal = attempt === "responseLost";
    const operation: MockOperation = {
      id: `operation-preview-${snapshot.deployment.id}-${nextGeneration}`,
      action: operationAction,
      state: recoveredTerminal ? "SUCCEEDED" : "ACCEPTED",
      responseStatus: recoveredTerminal ? 200 : 202,
      target: snapshot.deployment.id,
      requestedBy: { type: "USER", id: "principal-lin", accessKeyId: "MOCK-pipeline-key" },
      requestId: requestId || `mock-deployment-${crypto.randomUUID()}`,
      createdAt: now
    };
    const currentComponent = snapshot.deployment.components[0];
    const nextRevision = action === "rollback" ? source?.applicationRevisionId ?? snapshot.deployment.applicationRevisionId : action === "update" ? revisionId : snapshot.deployment.applicationRevisionId;
    const nextReplicas = action === "rollback" ? source?.componentReplicas ?? currentComponent?.replicas ?? 1 : action === "update" ? Number(replicas) : currentComponent?.replicas ?? 1;
    setSnapshot({
      ...snapshot,
      deployment: {
        ...snapshot.deployment,
        resourceVersion: snapshot.deployment.resourceVersion + 1,
        generation: nextGeneration,
        desiredState: action === "stop" ? "STOPPED" : "RUNNING",
        phase: recoveredTerminal ? action === "stop" ? "STOPPED" : "READY" : action === "stop" ? "STOPPING" : "PENDING",
        observedGeneration: recoveredTerminal ? nextGeneration : snapshot.deployment.observedGeneration,
        applicationRevisionId: nextRevision,
        observedApplicationRevisionId: recoveredTerminal ? nextRevision : snapshot.deployment.observedApplicationRevisionId,
        currentOperationId: recoveredTerminal ? undefined : operation.id,
        components: snapshot.deployment.components.map((component, index) => index === 0 ? { ...component, replicas: nextReplicas, readyReplicas: recoveredTerminal && action !== "stop" ? nextReplicas : action === "stop" && recoveredTerminal ? 0 : component.readyReplicas } : component)
      }
    });
    setLastOperation(operation);
    clearWorkflow();
  }

  if (!snapshot || !deployment) return <Card><Card.Header><Typography.Title as="h3" level={3}>{t("title")}</Typography.Title></Card.Header><Card.Body><Alert status="info">{t("snapshotUnavailable")}</Alert></Card.Body></Card>;

  const selectedSource = rollbackSources.find((item) => String(item.generation) === sourceGeneration);
  const reviewTarget = action === "update"
    ? `${revisionId} · ${replicas} ${t("replicasUnit")}`
    : action === "stop" ? t("desiredStopped") : `${t("generation", { generation: sourceGeneration })} · ${selectedSource?.applicationRevisionId ?? "—"}`;
  const iamAction = action === "update" ? "paas.deployment.update" : action === "stop" ? "paas.deployment.stop" : "paas.deployment.rollback";
  const method = action === "rollback" ? `POST /v1/deployments/${deployment.id}/rollback` : `PUT /v1/deployments/${deployment.id}`;
  const retryable = attempt === "unavailable" || attempt === "responseLost";

  return <Card aria-labelledby="application-deployment-title">
    <Card.Header>
      <div className={styles.heading}>
        <div className={styles.identity}><span className={styles.icon}><Rocket aria-hidden="true" /></span><div><Typography.Title as="h3" id="application-deployment-title" level={3}>{t("title")}</Typography.Title><Typography.Text tone="muted">{t("hint")}</Typography.Text></div></div>
        <div className={styles.headingActions}>
          <Badge status="neutral">{t("mockCandidate")}</Badge>
          <Button ref={updateRef} size="small" disabled={blocked || Boolean(action)} title={blocked ? t("operationPending") : undefined} onClick={() => start("update", "update")}>{t("update")}</Button>
          <ActionMenu triggerRef={moreRef} iconOnly label={t("moreActions")} disabled={Boolean(action)} actions={[
            { id: "rollback", label: t("rollback"), disabledReason: blocked ? t("operationPending") : rollbackSources.length ? undefined : t("rollbackUnavailable"), onSelect: () => start("rollback", "more") },
            { id: "stop", label: t("stop"), danger: true, disabledReason: blocked ? t("operationPending") : deployment.desiredState === "STOPPED" ? t("alreadyStopped") : undefined, onSelect: () => start("stop", "more") }
          ]} />
        </div>
      </div>
    </Card.Header>
    <Card.Body className={styles.body}>
      {lastOperation ? <Alert status={lastOperation.state === "SUCCEEDED" ? "success" : "info"}>{t(lastOperation.state === "SUCCEEDED" ? "recovered" : "accepted", { operation: lastOperation.id })}</Alert> : null}
      {lastOperation ? <section className={styles.outcome} aria-labelledby="deployment-operation-title">
        <div className={styles.outcomeHeading}><h4 id="deployment-operation-title">{t("outcome.title")}</h4><Badge status={lastOperation.state === "SUCCEEDED" ? "success" : "info"}>{t(`outcome.states.${lastOperation.state}`)}</Badge></div>
        <dl className={styles.outcomeFacts}>
          <div><dt>{t("outcome.operationId")}</dt><dd><code>{lastOperation.id}</code></dd></div>
          <div><dt>{t("outcome.action")}</dt><dd><code>{lastOperation.action}</code></dd></div>
          <div><dt>{t("outcome.response")}</dt><dd><code>{lastOperation.responseStatus}</code></dd></div>
          <div><dt>{t("outcome.requestedBy")}</dt><dd>{t("outcome.userAttribution", { user: lastOperation.requestedBy.id, key: lastOperation.requestedBy.accessKeyId })}</dd></div>
          <div><dt>{t("outcome.requestId")}</dt><dd><code>{lastOperation.requestId}</code></dd></div>
          <div><dt>{t("outcome.createdAt")}</dt><dd>{format.timestamp(lastOperation.createdAt)}</dd></div>
          <div><dt>{t("resourceVersion")}</dt><dd><code>{etag(deployment.resourceVersion)}</code></dd></div>
        </dl>
        <Typography.Text tone="muted">{t(lastOperation.state === "SUCCEEDED" ? "outcome.recoveredBoundary" : "outcome.boundary")}</Typography.Text>
      </section> : null}

      {action === null ? <>
        <dl className={styles.facts}>
          <div><dt>{t("deployment")}</dt><dd><code>{deployment.id}</code></dd></div>
          <div><dt>{t("phase")}</dt><dd><Badge status={phaseStatus(deployment.phase)}>{t(`phases.${deployment.phase}`)}</Badge></dd></div>
          <div><dt>{t("desiredState")}</dt><dd>{t(`desired.${deployment.desiredState}`)}</dd></div>
          <div><dt>{t("generationLabel")}</dt><dd>{t("generationProgress", { current: deployment.generation, observed: deployment.observedGeneration })}</dd></div>
          <div><dt>{t("revision")}</dt><dd><code>{deployment.applicationRevisionId}</code><span>/</span><code>{deployment.observedApplicationRevisionId}</code></dd></div>
          <div><dt>{t("placement")}</dt><dd><code>{deployment.placementPolicyId}</code><span>/</span><code>{deployment.placementDecisionId ?? t("none")}</code></dd></div>
          <div><dt>{t("resourceVersion")}</dt><dd><code>{etag(deployment.resourceVersion)}</code></dd></div>
          <div><dt>{t("currentOperation")}</dt><dd>{deployment.currentOperationId ? <code>{deployment.currentOperationId}</code> : t("none")}</dd></div>
        </dl>
        <Table aria-label={t("componentsTable")} mobileLayout="stack"><thead><tr><th scope="col">{t("component")}</th><th scope="col">{t("desiredReplicas")}</th><th scope="col">{t("readyReplicas")}</th></tr></thead><tbody>{deployment.components.map((component) => <tr key={component.name}><td><strong>{component.name}</strong></td><td data-label={t("desiredReplicas")}>{component.replicas}</td><td data-label={t("readyReplicas")}>{component.readyReplicas} / {component.replicas}</td></tr>)}</tbody></Table>
        <Alert status="info">{t("contractBoundary")}</Alert>
      </> : <div className={styles.workflow}>
        <Steps label={t("workflowLabel")} items={steps} current={step === "edit" ? 0 : 1} onChange={(index) => { if (index === 0 && action !== "stop") { setAttempt(null); setDraftError(null); setStep("edit"); } }} />
        {step === "edit" ? <form noValidate onSubmit={review}>
          <div className={styles.workflowHeading}><div><h4 ref={headingRef} tabIndex={-1}>{t(`editTitles.${action}`)}</h4><Typography.Text tone="muted">{t(`editHints.${action}`)}</Typography.Text></div><Badge status="neutral">{t("mockOnly")}</Badge></div>
          {attempt === "versionConflict" ? <Alert status="warning">{t("outcomes.versionConflict", { etag: etag(deployment.resourceVersion) })}</Alert> : null}
          {draftError ? <Alert status="warning">{draftError}</Alert> : null}
          {action === "update" ? <div className={styles.fieldGrid}>
            <FormField id="deployment-revision" label={t("revision")} hint={t("revisionHint")}><Select id="deployment-revision" value={revisionId} options={snapshot.revisions.map((item) => ({ value: item.id, label: item.label }))} onValueChange={(value) => { setRevisionId(value); setDraftError(null); }} /></FormField>
            <FormField id="deployment-replicas" label={t("desiredReplicas")} hint={t("replicasHint")}><Select id="deployment-replicas" value={replicas} options={[1, 2, 3, 4].map((value) => ({ value: String(value), label: String(value) }))} onValueChange={(value) => { setReplicas(value); setDraftError(null); }} /></FormField>
          </div> : action === "rollback" ? <FormField id="deployment-rollback-generation" label={t("rollbackSource")} hint={t("rollbackHint")}><Select id="deployment-rollback-generation" value={sourceGeneration} options={rollbackSources.map((item) => ({ value: String(item.generation), label: `${t("generation", { generation: item.generation })} · ${item.applicationRevisionId} · ${format.timestamp(item.createdAt)}` }))} onValueChange={(value) => { setSourceGeneration(value); setDraftError(null); }} /></FormField> : <Alert status="warning">{t("stopWarning")}</Alert>}
          <div className={styles.actions}><Button type="button" variant="ghost" onClick={() => clearWorkflow()}>{t("cancel")}</Button><Button type="submit">{t("review")}</Button></div>
        </form> : <form noValidate onSubmit={apply}>
          <div className={styles.workflowHeading}><div><h4 ref={headingRef} tabIndex={-1}>{t(`reviewTitles.${action}`)}</h4><Typography.Text tone="muted">{t("reviewHint")}</Typography.Text></div><Badge status="info">{t("mockOnly")}</Badge></div>
          <dl className={styles.reviewFacts}>
            <div><dt>{t("resource")}</dt><dd>{resource.name}<code>{resource.id}</code></dd></div>
            <div><dt>{t("deployment")}</dt><dd><code>{deployment.id}</code></dd></div>
            <div><dt>{t("action")}</dt><dd><code>{iamAction}</code></dd></div>
            <div><dt>{t("request")}</dt><dd><code>{method}</code></dd></div>
            <div><dt>{t("concurrency")}</dt><dd><code>{`If-Match: ${etag(deployment.resourceVersion)}`}</code></dd></div>
            <div><dt>{t("requestId")}</dt><dd><code>{requestId}</code></dd></div>
            <div><dt>{t("current")}</dt><dd>{deployment.applicationRevisionId} · {deployment.components[0]?.replicas ?? 0} {t("replicasUnit")}</dd></div>
            <div><dt>{t("target")}</dt><dd><ArrowRight aria-hidden="true" />{reviewTarget}</dd></div>
          </dl>
          <div className={styles.reviewAlerts}>
            {attempt ? <Alert status={attempt === "denied" || attempt === "idempotencyConflict" ? "danger" : "warning"}>{t(`outcomes.${attempt}`, { etag: etag(deployment.resourceVersion) })}</Alert> : null}
            {action === "stop" ? <Alert status="warning">{t("stopWarning")}</Alert> : null}
            {action === "rollback" ? <Alert status="warning">{t("rollbackWarning")}</Alert> : null}
            <Alert status="info">{t("submitBoundary")}</Alert>
          </div>
          <details className={styles.scenarioDetails}><summary>{t("tryOtherOutcomes")}{scenario !== "success" ? ` · ${t(`scenarios.${scenario}`)}` : ""}</summary><FormField id={scenarioId} label={t("scenarioLabel")} hint={t("scenarioHint")}><Select id={scenarioId} value={scenario} options={previewOutcomes.map((item) => ({ value: item, label: t(`scenarios.${item}`) }))} onValueChange={(value) => { setScenario(value as PreviewOutcome); setAttempt(null); }} /></FormField></details>
          <div className={styles.actions}><Button type="button" variant="ghost" onClick={() => clearWorkflow()}>{t("cancel")}</Button>{action !== "stop" ? <Button type="button" variant="secondary" onClick={() => { setAttempt(null); setStep("edit"); }}>{t("back")}</Button> : null}{!attempt || retryable ? <Button type="submit">{attempt ? t(`retry.${attempt}`) : t("submit")}</Button> : null}</div>
        </form>}
      </div>}
    </Card.Body>
  </Card>;
}
