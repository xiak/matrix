"use client";

import { useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, FormField, Input, RadioGroup, Typography } from "@ui/xiak";
import type { AccessAnalysisDispositionRulePreview, AccessAnalysisRulePreview } from "../scenes/accessReport";
import { WorkspaceDetail } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

export type AccessAnalysisRuleSavedKind = "analyzer" | "disposition";

export function AccessAnalysisRuleWorkflow({ rule, onBack, onApply }: {
  rule: AccessAnalysisRulePreview;
  onBack(): void;
  onApply(rule: AccessAnalysisRulePreview): void;
}) {
  const t = useTranslations("IamWorkspace.accessAnalysis.rule");
  const id = useId();
  const [step, setStep] = useState<"edit" | "review">("edit");
  const [windowValue, setWindowValue] = useState(String(rule.windowDays));
  const [status, setStatus] = useState(rule.status);
  const windowDays = Number(windowValue);
  const invalidWindow = !/^\d+$/.test(windowValue) || !Number.isInteger(windowDays) || windowDays < 1 || windowDays > 365;
  const next = () => { if (!invalidWindow) setStep("review"); };
  const apply = () => onApply({ ...rule, resourceVersion: rule.resourceVersion + 1, windowDays, status });

  return <WorkspaceDetail title={t(step === "edit" ? "editTitle" : "reviewTitle")} onBack={step === "review" ? () => setStep("edit") : onBack}>
    <Alert status="info">{t("workflowBoundary")}</Alert>
    {step === "edit" ? <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{t("configuration")}</Typography.Title><Typography.Text tone="muted">{t("configurationHint")}</Typography.Text></div><Badge status="warning">{t("mock")}</Badge></Card.Header>
      <Card.Body className={styles.detail}>
        <FormField id={`${id}-window`} label={t("window")} hint={t("windowHint")} error={invalidWindow ? t("windowInvalid") : undefined}><Input id={`${id}-window`} required type="number" min={1} max={365} step={1} invalid={invalidWindow} aria-describedby={`${id}-window-hint${invalidWindow ? ` ${id}-window-error` : ""}`} value={windowValue} onChange={(event) => setWindowValue(event.target.value)} /></FormField>
        <RadioGroup label={t("status")} value={status} onValueChange={(value) => setStatus(value as AccessAnalysisRulePreview["status"])} options={(["ACTIVE", "DISABLED"] as const).map((value) => ({ value, label: t(`statuses.${value}`) }))} />
        <Alert status="warning">{t("sourceGate")}</Alert>
      </Card.Body>
      <Card.Footer><div className={styles.actions}><Button disabled={invalidWindow} onClick={next}>{t("review")}</Button><Button variant="secondary" onClick={onBack}>{t("cancel")}</Button></div></Card.Footer>
    </Card> : <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{t("reviewSummary")}</Typography.Title><Typography.Text tone="muted">{t("reviewHint")}</Typography.Text></div><Badge status="warning">{t("sessionOnly")}</Badge></Card.Header>
      <Card.Body className={styles.detail}>
        <dl className={styles.facts}>
          <div><dt>{t("account")}</dt><dd><code>{rule.accountId}</code></dd></div>
          <div><dt>{t("analyzerId")}</dt><dd><code>{rule.id}</code></dd></div>
          <div><dt>{t("analyzerType")}</dt><dd><code>{rule.type}</code></dd></div>
          <div><dt>{t("nextResourceVersion")}</dt><dd>{rule.resourceVersion + 1}</dd></div>
          <div><dt>{t("window")}</dt><dd>{t("days", { count: windowDays })}</dd></div>
          <div><dt>{t("status")}</dt><dd>{t(`statuses.${status}`)}</dd></div>
        </dl>
        <Alert status="warning">{t("applyBoundary")}</Alert>
      </Card.Body>
      <Card.Footer><div className={styles.actions}><Button onClick={apply}>{t("applyMock")}</Button><Button variant="secondary" onClick={() => setStep("edit")}>{t("backToEdit")}</Button></div></Card.Footer>
    </Card>}
  </WorkspaceDetail>;
}

export function AccessAnalysisDispositionWorkflow({ rule, onBack, onApply }: {
  rule: AccessAnalysisRulePreview;
  onBack(): void;
  onApply(rule: AccessAnalysisRulePreview): void;
}) {
  const t = useTranslations("IamWorkspace.accessAnalysis.disposition");
  const id = useId();
  const [step, setStep] = useState<"edit" | "review">("edit");
  const [mode, setMode] = useState<AccessAnalysisDispositionRulePreview["mode"]>(rule.disposition.mode);
  const [delayValue, setDelayValue] = useState(String(rule.disposition.findingDelayDays || 7));
  const delayDays = Number(delayValue);
  const automatic = mode === "DISABLE_UNUSED_ACCESS_KEYS";
  const invalidDelay = automatic && (!/^\d+$/.test(delayValue) || !Number.isInteger(delayDays) || delayDays < 1 || delayDays > 30);
  const next = () => { if (!invalidDelay) setStep("review"); };
  const disposition: AccessAnalysisDispositionRulePreview = {
    mode,
    findingDelayDays: automatic ? delayDays : 0
  };
  const apply = () => onApply({ ...rule, resourceVersion: rule.resourceVersion + 1, disposition });

  return <WorkspaceDetail title={t(step === "edit" ? "editTitle" : "reviewTitle")} onBack={step === "review" ? () => setStep("edit") : onBack}>
    <Alert status="info">{t("workflowBoundary")}</Alert>
    {step === "edit" ? <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{t("configuration")}</Typography.Title><Typography.Text tone="muted">{t("configurationHint")}</Typography.Text></div><Badge status="warning">{t("mock")}</Badge></Card.Header>
      <Card.Body className={styles.detail}>
        <RadioGroup label={t("mode")} value={mode} onValueChange={(value) => setMode(value as AccessAnalysisDispositionRulePreview["mode"])} options={(["REVIEW_ONLY", "DISABLE_UNUSED_ACCESS_KEYS"] as const).map((value) => ({ value, label: t(`modes.${value}`) }))} />
        {automatic ? <FormField id={`${id}-delay`} label={t("delay")} hint={t("delayHint")} error={invalidDelay ? t("delayInvalid") : undefined}><Input id={`${id}-delay`} required type="number" min={1} max={30} step={1} invalid={invalidDelay} aria-describedby={`${id}-delay-hint${invalidDelay ? ` ${id}-delay-error` : ""}`} value={delayValue} onChange={(event) => setDelayValue(event.target.value)} /></FormField> : <Alert status="info">{t("reviewOnlyMeaning")}</Alert>}
        <Alert status="warning">{t("scopeBoundary")}</Alert>
        <Alert status="info">{t("permissionBoundary")}</Alert>
      </Card.Body>
      <Card.Footer><div className={styles.actions}><Button disabled={invalidDelay} onClick={next}>{t("review")}</Button><Button variant="secondary" onClick={onBack}>{t("cancel")}</Button></div></Card.Footer>
    </Card> : <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{t("reviewSummary")}</Typography.Title><Typography.Text tone="muted">{t("reviewHint")}</Typography.Text></div><Badge status="warning">{t("sessionOnly")}</Badge></Card.Header>
      <Card.Body className={styles.detail}>
        <dl className={styles.facts}>
          <div><dt>{t("account")}</dt><dd><code>{rule.accountId}</code></dd></div>
          <div><dt>{t("analyzerId")}</dt><dd><code>{rule.id}</code></dd></div>
          <div><dt>{t("nextResourceVersion")}</dt><dd>{rule.resourceVersion + 1}</dd></div>
          <div><dt>{t("mode")}</dt><dd className={styles.dispositionFact}><code>{mode}</code><small>{t(`modes.${mode}`)}</small></dd></div>
          <div><dt>{t("eligibleFinding")}</dt><dd><code>UNUSED_ACCESS_KEY</code></dd></div>
          <div><dt>{t("effect")}</dt><dd className={styles.dispositionFact}>{automatic ? <><code>DISABLE_ACCESS_KEY</code><small>{t("disableMeaning")}</small></> : t("noWriteEffect")}</dd></div>
          <div><dt>{t("delay")}</dt><dd>{automatic ? t("days", { count: delayDays }) : t("notApplicable")}</dd></div>
        </dl>
        <Alert status="warning">{t("reviewBoundary")}</Alert>
        <Alert status="info">{t("safeguardsBoundary")}</Alert>
        <Alert status="info">{t("applyBoundary")}</Alert>
      </Card.Body>
      <Card.Footer><div className={styles.actions}><Button onClick={apply}>{t("applyMock")}</Button><Button variant="secondary" onClick={() => setStep("edit")}>{t("backToEdit")}</Button></div></Card.Footer>
    </Card>}
  </WorkspaceDetail>;
}

export function AccessAnalysisRulesPanel({ rule, saved, onEditAnalyzer, onEditDisposition }: {
  rule: AccessAnalysisRulePreview;
  saved: AccessAnalysisRuleSavedKind | null;
  onEditAnalyzer(): void;
  onEditDisposition(): void;
}) {
  const t = useTranslations("IamWorkspace.accessAnalysis");
  return <div className={styles.stack}>
    {saved === "analyzer" ? <Alert status="success">{t("rule.saved", { version: rule.resourceVersion })}</Alert> : null}
    {saved === "disposition" ? <Alert status="success">{t("disposition.saved", { version: rule.resourceVersion })}</Alert> : null}
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{t("rule.title")}</Typography.Title><Typography.Text tone="muted">{t("rule.hint")}</Typography.Text></div><Badge status="warning">{t("rule.mock")}</Badge></Card.Header>
      <Card.Body className={styles.detail}>
        <dl className={styles.facts}>
          <div><dt>{t("rule.account")}</dt><dd><code>{rule.accountId}</code></dd></div>
          <div><dt>{t("rule.analyzerId")}</dt><dd><code>{rule.id}</code></dd></div>
          <div><dt>{t("rule.analyzerType")}</dt><dd><code>{rule.type}</code></dd></div>
          <div><dt>{t("rule.resourceVersion")}</dt><dd>{rule.resourceVersion}</dd></div>
          <div><dt>{t("rule.window")}</dt><dd>{t("rule.days", { count: rule.windowDays })}</dd></div>
          <div><dt>{t("rule.status")}</dt><dd><Badge status={rule.status === "ACTIVE" ? "success" : "neutral"}>{t(`rule.statuses.${rule.status}`)}</Badge></dd></div>
          <div><dt>{t("rule.evidence")}</dt><dd>{t(`rule.evidenceStates.${rule.evidence}`)}</dd></div>
        </dl>
        <Alert status="warning">{t("rule.noBackgroundWorker")}</Alert>
      </Card.Body>
      <Card.Footer><Button variant="secondary" onClick={onEditAnalyzer}>{t("rule.edit")}</Button></Card.Footer>
    </Card>
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{t("disposition.title")}</Typography.Title><Typography.Text tone="muted">{t("disposition.hint")}</Typography.Text></div><Badge status={rule.disposition.mode === "REVIEW_ONLY" ? "neutral" : "warning"}>{t(`disposition.modes.${rule.disposition.mode}`)}</Badge></Card.Header>
      <Card.Body className={styles.detail}>
        <dl className={styles.facts}>
          <div><dt>{t("disposition.mode")}</dt><dd><code>{rule.disposition.mode}</code></dd></div>
          <div><dt>{t("disposition.eligibleFinding")}</dt><dd><code>UNUSED_ACCESS_KEY</code></dd></div>
          <div><dt>{t("disposition.effect")}</dt><dd>{rule.disposition.mode === "DISABLE_UNUSED_ACCESS_KEYS" ? <code>DISABLE_ACCESS_KEY</code> : t("disposition.noWriteEffect")}</dd></div>
          <div><dt>{t("disposition.delay")}</dt><dd>{rule.disposition.mode === "DISABLE_UNUSED_ACCESS_KEYS" ? t("disposition.days", { count: rule.disposition.findingDelayDays }) : t("disposition.notApplicable")}</dd></div>
          <div><dt>{t("disposition.permission")}</dt><dd><code>iam.access-analyzer.set-disposition</code></dd></div>
        </dl>
        <Alert status="warning">{t("disposition.summaryBoundary")}</Alert>
      </Card.Body>
      <Card.Footer><Button variant="secondary" onClick={onEditDisposition}>{t("disposition.edit")}</Button></Card.Footer>
    </Card>
  </div>;
}
