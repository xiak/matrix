"use client";

import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react";
import { ArrowRight, Tags } from "lucide-react";
import { Alert, Badge, Button, Card, EmptyState, FormField, Input, RadioGroup, Select, Steps, Table, Typography, useUnsavedChanges } from "@ui/xiak";
import { useTranslations } from "next-intl";
import type { ExperienceApplicationTagSnapshot } from "../domain/experience";
import { applicationLabelLooksSensitive, validApplicationLabelValue, validApplicationName } from "../domain/application";
import type { UnifiedResourceScene } from "../scenes/consoleScene";
import { useConsoleFormat } from "./useConsoleFormat";
import styles from "./ApplicationTagManagement.module.css";

type MutationKind = "set" | "delete";
type WorkflowStep = "edit" | "review";
type DraftError = "key" | "value" | "unchanged" | "missing" | "limit" | "sensitive" | null;
type PreviewOutcome = "success" | "noChange" | "idempotencyConflict" | "versionConflict" | "denied" | "unavailable" | "responseLost";
type FailedAttempt = Exclude<PreviewOutcome, "success">;
type MockCompletedOperation = {
  id: string;
  action: "paas.application-label.set" | "paas.application-label.delete";
  state: "SUCCEEDED";
  target: string;
  requestedBy: "principal-admin";
  createdAt: string;
  updatedAt: string;
  terminalAt: string;
};

function nextMockEtag(current: string) {
  const matched = current.match(/:tags:(\d+)(?="?$)/);
  if (!matched) return current;
  return current.replace(/:tags:(\d+)(?="?$)/, `:tags:${Number(matched[1]) + 1}`);
}

function iamCondition(key: string) {
  return key === "environment" ? `resource.tag/${key}` : null;
}

export function ApplicationTagManagement({ resource, initialSnapshot }: {
  resource: UnifiedResourceScene;
  initialSnapshot: ExperienceApplicationTagSnapshot | undefined;
}) {
  const t = useTranslations("CloudExperience");
  const w = useTranslations("CloudExperience.applicationTagManagement");
  const format = useConsoleFormat();
  const scenarioId = useId();
  const [snapshot, setSnapshot] = useState(initialSnapshot);
  const [step, setStep] = useState<WorkflowStep | null>(null);
  const [kind, setKind] = useState<MutationKind>("set");
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [error, setError] = useState<DraftError>(null);
  const [scenario, setScenario] = useState<PreviewOutcome>("success");
  const [attempt, setAttempt] = useState<FailedAttempt | null>(null);
  const [lastChange, setLastChange] = useState<{ kind: MutationKind; key: string; value?: string; etag: string; operation: MockCompletedOperation } | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const manageRef = useRef<HTMLButtonElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const keyRef = useRef<HTMLInputElement>(null);
  const valueRef = useRef<HTMLInputElement>(null);
  const deleteRef = useRef<HTMLButtonElement>(null);
  const restoreManageFocus = useRef(false);
  const requestIdRef = useRef("");
  const tags = snapshot?.tags ?? [];
  const current = tags.find((tag) => tag.key === key);
  const retryableAttempt = attempt === "versionConflict" || attempt === "unavailable" || attempt === "responseLost";
  const dirty = step !== null && (kind !== "set" || key !== "" || value !== "");
  const steps = useMemo(() => ([
    { id: "edit", label: w("steps.edit") },
    { id: "review", label: w("steps.review") }
  ]), [w]);
  const leaveCopy = useMemo(() => ({
    title: w("leave.title"), description: w("leave.description"), stay: w("leave.stay"), leave: w("leave.discard"), close: w("leave.close"),
    busyTitle: w("leave.busyTitle"), busyDescription: w("leave.busyDescription"), failure: w("leave.failure"), retry: w("leave.retry")
  }), [w]);
  const requestLeave = useUnsavedChanges({ dirty, busy: false, copy: leaveCopy, focusRef: cancelRef });

  useEffect(() => {
    if (step) headingRef.current?.focus({ preventScroll: true });
    else if (restoreManageFocus.current) {
      restoreManageFocus.current = false;
      manageRef.current?.focus({ preventScroll: true });
    }
  }, [step]);

  function clearDraft() {
    requestIdRef.current = "";
    setStep(null);
    setKind("set");
    setKey("");
    setValue("");
    setError(null);
    setScenario("success");
    setAttempt(null);
    restoreManageFocus.current = true;
  }

  function start() {
    requestIdRef.current = "";
    setLastChange(null);
    setScenario("success");
    setAttempt(null);
    setStep("edit");
  }

  function cancel() {
    requestLeave(clearDraft);
  }

  function changeKind(next: MutationKind) {
    requestIdRef.current = "";
    setKind(next);
    setKey("");
    setValue("");
    setError(null);
    setScenario("success");
    setAttempt(null);
  }

  function validate() {
    if (!validApplicationName(key)) return "key" as const;
    if (kind === "delete" && !current) return "missing" as const;
    if (kind === "set" && tags.length >= 64 && !current) return "limit" as const;
    if (kind === "set" && applicationLabelLooksSensitive(value)) return "sensitive" as const;
    if (kind === "set" && (value === "" || !validApplicationLabelValue(value))) return "value" as const;
    if (kind === "set" && current?.value === value) return "unchanged" as const;
    return null;
  }

  function review(event: FormEvent) {
    event.preventDefault();
    const nextError = validate();
    setError(nextError);
    if (nextError) {
      requestAnimationFrame(() => (nextError === "value" || nextError === "sensitive" || nextError === "unchanged" ? valueRef.current : kind === "delete" ? deleteRef.current : keyRef.current)?.focus());
      return;
    }
    requestIdRef.current = `mock-application-tag-${crypto.randomUUID()}`;
    setAttempt(null);
    setStep("review");
  }

  function simulateConcurrentSnapshot(source: ExperienceApplicationTagSnapshot) {
    const externalValue = "external-preview";
    return {
      ...source,
      etag: nextMockEtag(source.etag),
      tags: current
        ? source.tags.map((tag) => tag.key === key ? { ...tag, value: externalValue } : tag)
        : [...source.tags, { key, value: externalValue }]
    };
  }

  function apply(event: FormEvent) {
    event.preventDefault();
    if (!snapshot || validate()) return;
    if (scenario !== "success") {
      setAttempt(scenario);
      if (scenario === "versionConflict") {
        setSnapshot(simulateConcurrentSnapshot(snapshot));
        // The changed ETag creates a new request fingerprint. Reusing the old
        // key would correctly produce IDEMPOTENCY_CONFLICT in the real API.
        requestIdRef.current = "";
      }
      if (scenario === "versionConflict" || scenario === "unavailable" || scenario === "responseLost") setScenario("success");
      requestAnimationFrame(() => headingRef.current?.focus({ preventScroll: true }));
      return;
    }
    // 503/transport uncertainty keeps the original key. A 412 path reaches
    // here only after a fresh user confirmation and therefore gets a new key.
    if (!requestIdRef.current) requestIdRef.current = `mock-application-tag-${crypto.randomUUID()}`;
    const completedAt = new Date().toISOString();
    const nextEtag = nextMockEtag(snapshot.etag);
    const nextTags = kind === "delete"
      ? snapshot.tags.filter((tag) => tag.key !== key)
      : current
        ? snapshot.tags.map((tag) => tag.key === key ? { key, value } : tag)
        : [...snapshot.tags, { key, value }];
    setSnapshot({ ...snapshot, etag: nextEtag, tags: nextTags });
    setLastChange({
      kind,
      key,
      ...(kind === "set" ? { value } : {}),
      etag: nextEtag,
      operation: {
        id: `operation-preview-${resource.id}-tags-${nextEtag.match(/:tags:(\d+)/)?.[1] ?? "next"}`,
        action: kind === "delete" ? "paas.application-label.delete" : "paas.application-label.set",
        state: "SUCCEEDED",
        target: resource.id,
        requestedBy: "principal-admin",
        createdAt: completedAt,
        updatedAt: completedAt,
        terminalAt: completedAt
      }
    });
    clearDraft();
  }

  const errorMessage = error ? w(`errors.${error}`) : undefined;
  const permissionSensitive = key === "environment";

  return <Card aria-labelledby="application-resource-tags-title">
    <Card.Header>
      <div className={styles.heading}>
        <div className={styles.identity}>
          <span className={styles.icon}><Tags aria-hidden="true" /></span>
          <div><Typography.Title as="h3" id="application-resource-tags-title" level={3}>{t("resourceTags")}</Typography.Title><Typography.Text tone="muted">{t("resourceTagsHint")}</Typography.Text></div>
        </div>
        <div className={styles.headingActions}>
          <Badge status="neutral">{t("mockSnapshot")}</Badge>
          {step === null ? <Button ref={manageRef} disabled={!snapshot} size="small" title={!snapshot ? w("snapshotUnavailable") : undefined} variant="secondary" onClick={start}>{w("manage")}</Button> : null}
        </div>
      </div>
    </Card.Header>
    <Card.Body className={styles.body}>
      {lastChange ? <>
        <Alert status="success">{lastChange.kind === "delete" ? w("success.delete", { key: lastChange.key }) : w("success.set", { key: lastChange.key, value: lastChange.value ?? "" })}</Alert>
        <section className={styles.outcome} aria-labelledby="application-tag-operation-title">
          <div className={styles.outcomeHeading}><h4 id="application-tag-operation-title">{w("outcome.title")}</h4><Badge status="success">{w(`outcome.states.${lastChange.operation.state}`)}</Badge></div>
          <dl className={styles.outcomeFacts}>
            <div><dt>{w("outcome.operationId")}</dt><dd><code>{lastChange.operation.id}</code></dd></div>
            <div><dt>{w("outcome.action")}</dt><dd><code>{lastChange.operation.action}</code></dd></div>
            <div><dt>{w("outcome.target")}</dt><dd><code>{lastChange.operation.target}</code></dd></div>
            <div><dt>{w("outcome.requestedBy")}</dt><dd><code>{lastChange.operation.requestedBy}</code></dd></div>
            <div><dt>{w("outcome.completedAt")}</dt><dd>{format.timestamp(lastChange.operation.terminalAt)}</dd></div>
            <div><dt>{t("tagVersion")}</dt><dd><code>{lastChange.etag}</code></dd></div>
          </dl>
          <Typography.Text tone="muted">{w("outcome.reloaded")}</Typography.Text>
        </section>
      </> : null}
      {step === null ? <>
        {tags.length ? <Table aria-label={t("resourceTagsTable")} mobileLayout="stack">
          <thead><tr><th scope="col">{t("tagKey")}</th><th scope="col">{t("tagValue")}</th><th scope="col">{t("iamCondition")}</th></tr></thead>
          <tbody>{tags.map((tag) => <tr key={tag.key}>
            <td><code>{tag.key}</code></td>
            <td data-label={t("tagValue")}>{tag.value}</td>
            <td data-label={t("iamCondition")}>{iamCondition(tag.key) ? <code>{iamCondition(tag.key)}</code> : <span className={styles.notExposed}>{t("notExposedToIam")}</span>}</td>
          </tr>)}</tbody>
        </Table> : <EmptyState title={t("noResourceTags")} description={t("noResourceTagsHint")} />}
        {snapshot ? <div className={styles.version}><span>{t("tagVersion")}</span><code>{snapshot.etag}</code></div> : null}
        <Alert status="info">{t("resourceTagBoundary")}</Alert>
      </> : <div className={styles.workflow}>
        <Steps label={w("workflowLabel")} items={steps} current={step === "edit" ? 0 : 1} onChange={(index) => { if (index === 0) { setError(null); setStep("edit"); } }} />
        {step === "edit" ? <form noValidate onSubmit={review}>
          <div className={styles.workflowHeading}><div><h4 ref={headingRef} tabIndex={-1}>{w("editTitle")}</h4><Typography.Text tone="muted">{w("editHint")}</Typography.Text></div><span>{w("oneKeyOnly")}</span></div>
          <div className={styles.formStack}>
            <RadioGroup label={w("kindLabel")} options={[
              { value: "set", label: w("kinds.set") },
              { value: "delete", label: w("kinds.delete") }
            ]} value={kind} onValueChange={(next) => changeKind(next as MutationKind)} />
            {kind === "set" ? <div className={styles.fieldGrid}>
              <FormField id="application-tag-key" label={w("keyLabel")} hint={w("keyHint")} error={error === "key" || error === "limit" ? errorMessage : undefined}>
                <Input id="application-tag-key" ref={keyRef} autoComplete="off" maxLength={63} value={key} invalid={error === "key" || error === "limit"} aria-describedby={`application-tag-key-hint${error === "key" || error === "limit" ? " application-tag-key-error" : ""}`} onChange={(event) => { setKey(event.target.value); setError(null); }} />
              </FormField>
              <FormField id="application-tag-value" label={w("valueLabel")} hint={current ? w("currentValue", { value: current.value }) : w("valueHint")} error={error === "value" || error === "sensitive" || error === "unchanged" ? errorMessage : undefined}>
                <Input id="application-tag-value" ref={valueRef} autoComplete="off" value={value} invalid={error === "value" || error === "sensitive" || error === "unchanged"} aria-describedby={`application-tag-value-hint${error === "value" || error === "sensitive" || error === "unchanged" ? " application-tag-value-error" : ""}`} onChange={(event) => { setValue(event.target.value); setError(null); }} />
              </FormField>
            </div> : <FormField id="application-tag-delete" label={w("deleteLabel")} hint={w("deleteHint")} error={error === "missing" || error === "key" ? errorMessage : undefined}>
              <Select id="application-tag-delete" ref={deleteRef} value={key} invalid={error === "missing" || error === "key"} aria-describedby={`application-tag-delete-hint${error === "missing" || error === "key" ? " application-tag-delete-error" : ""}`} options={[{ value: "", label: w("deletePlaceholder") }, ...tags.map((tag) => ({ value: tag.key, label: `${tag.key} = ${tag.value}` }))]} onValueChange={(next) => { setKey(next); setError(null); }} />
            </FormField>}
            <Alert status="info">{w("sensitiveHint")}</Alert>
          </div>
          <div className={styles.actions}><Button ref={cancelRef} type="button" variant="ghost" onClick={cancel}>{w("cancel")}</Button><Button type="submit">{w("review")}</Button></div>
        </form> : <form noValidate onSubmit={apply}>
          <div className={styles.workflowHeading}><div><h4 ref={headingRef} tabIndex={-1}>{w("reviewTitle")}</h4><Typography.Text tone="muted">{w("reviewHint")}</Typography.Text></div><Badge status="info">{w("mockOnly")}</Badge></div>
          <dl className={styles.reviewFacts}>
            <div><dt>{w("resource")}</dt><dd>{resource.name}<code>{resource.id}</code></dd></div>
            <div><dt>{t("tagVersion")}</dt><dd><code>{snapshot?.etag}</code></dd></div>
            <div><dt>{w("operation")}</dt><dd>{w(`kinds.${kind}`)}</dd></div>
            <div><dt>{w("action")}</dt><dd><code>{kind === "delete" ? "paas.application-label.delete" : "paas.application-label.set"}</code></dd></div>
            <div><dt>{w("concurrency")}</dt><dd><code>{`If-Match: ${snapshot?.etag}`}</code></dd></div>
            <div><dt>{w("change")}</dt><dd><span>{current?.value ?? w("notSet")}</span><ArrowRight aria-hidden="true" /><strong>{kind === "delete" ? w("deleted") : value}</strong></dd></div>
            <div><dt>{w("keyLabel")}</dt><dd><code>{key}</code></dd></div>
            <div><dt>{t("iamCondition")}</dt><dd>{iamCondition(key) ? <code>{iamCondition(key)}</code> : t("notExposedToIam")}</dd></div>
          </dl>
          <div className={styles.reviewAlerts}>
            {attempt ? <Alert status={attempt === "noChange" ? "info" : attempt === "idempotencyConflict" || attempt === "denied" ? "danger" : "warning"}>{w(`outcomes.${attempt}`)}</Alert> : null}
            {permissionSensitive ? <Alert status="warning">{w("authorizationWarning")}</Alert> : null}
            <Alert status="info">{w("applyBoundary")}</Alert>
          </div>
          <details className={styles.scenarioDetails}>
            <summary>{w("tryOtherOutcomes")}{scenario !== "success" ? ` · ${w(`scenarios.${scenario}`)}` : ""}</summary>
            <FormField id={scenarioId} label={w("scenarioLabel")} hint={w("scenarioHint")}>
              <Select id={scenarioId} value={scenario} options={(["success", "noChange", "idempotencyConflict", "versionConflict", "denied", "unavailable", "responseLost"] as const).map((outcome) => ({ value: outcome, label: w(`scenarios.${outcome}`) }))} onValueChange={(outcome) => { setScenario(outcome as PreviewOutcome); setAttempt(null); }} />
            </FormField>
          </details>
          <div className={styles.actions}><Button ref={cancelRef} type="button" variant="ghost" onClick={cancel}>{w("cancel")}</Button><Button type="button" variant="secondary" onClick={() => { requestIdRef.current = ""; setError(null); setAttempt(null); setStep("edit"); }}>{w("back")}</Button>{!attempt || retryableAttempt ? <Button type="submit">{attempt ? w(`retry.${attempt}`) : w("apply")}</Button> : null}</div>
        </form>}
      </div>}
    </Card.Body>
  </Card>;
}
