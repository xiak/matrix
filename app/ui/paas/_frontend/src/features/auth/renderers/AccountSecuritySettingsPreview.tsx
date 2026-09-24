"use client";

import { useId, useLayoutEffect, useRef, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, Checkbox, FormField, Select, Typography } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessWorkspace, PendingAccountRuleChange } from "../domain/accessWorkspace";
import { SecurityStepUpPreview } from "./SecurityStepUpPreview";
import styles from "./MfaPreviewExperience.module.css";

type Stage = "summary" | "edit" | "review" | "verify" | "conflict" | "denied" | "unknown";
type SaveScenario = "success" | "denied" | "conflict" | "response-lost";
type InspectionScenario = "found-applied" | "found-rejected" | "not-found" | "unavailable";

export function AccountSecuritySettingsPreview({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("MfaPreview");
  const access = useAccountAccess();
  const scenarioId = useId();
  const inspectionId = useId();
  const [required, setRequired] = useState(workspace.settings.loginProtection);
  const [stage, setStage] = useState<Stage>(() => workspace.pendingAccountRuleChange ? "unknown" : "summary");
  const [feedback, setFeedback] = useState<"enabled" | "disabled" | "rejected" | null>(null);
  const [scenario, setScenario] = useState<SaveScenario>("success");
  const [inspection, setInspection] = useState<InspectionScenario>("found-applied");
  const [requestId, setRequestId] = useState(() => `mock-account-rule-${crypto.randomUUID()}`);
  const [localPending, setLocalPending] = useState<PendingAccountRuleChange | null>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const flowHeading = useRef<HTMLHeadingElement>(null);
  const focus = useRef<"trigger" | "heading" | "flow" | null>(null);
  const changed = required !== workspace.settings.loginProtection;
  const pending = workspace.pendingAccountRuleChange ?? localPending;
  const factorReady = workspace.personalMfa.factorState === "bound" && workspace.personalMfa.recoveryState === "idle";
  const canChangeRule = factorReady && !workspace.personalMfa.reauthenticationRequired;

  const focusPersonalSecurity = () => {
    const personalSecurity = document.getElementById("personal-security");
    personalSecurity?.focus();
    personalSecurity?.scrollIntoView?.({ behavior: "smooth", block: "start" });
  };

  useLayoutEffect(() => {
    if (!focus.current) return;
    const target = focus.current;
    focus.current = null;
    if (target === "trigger") trigger.current?.focus();
    else if (target === "flow") flowHeading.current?.focus();
    else heading.current?.focus();
  }, [stage, workspace.settings.loginProtection]);

  const review = () => {
    setFeedback(null);
    focus.current = "flow";
    setStage("review");
  };
  const backToEdit = () => {
    focus.current = "trigger";
    setStage("edit");
  };
  const save = async () => {
    const intent: PendingAccountRuleChange = { requestId, baselineLoginProtection: workspace.settings.loginProtection, requestedLoginProtection: required, status: "UNKNOWN" };
    if (scenario === "conflict") {
      access.clearWorkspaceError();
      focus.current = "flow";
      setStage("conflict");
      return false;
    }
    if (scenario === "denied") {
      access.clearWorkspaceError();
      focus.current = "flow";
      setStage("denied");
      return false;
    }
    const saved = await access.executeWorkspace(
      { kind: "save-account-rule", requestId, expectedLoginProtection: workspace.settings.loginProtection, loginProtection: required, responseMode: scenario === "response-lost" ? "response-lost" : "success" },
      (error) => {
        focus.current = "flow";
        if (error === "conflict") {
          access.clearWorkspaceError();
          setStage("conflict");
        } else if (error === "forbidden") {
          access.clearWorkspaceError();
          setStage("denied");
        } else {
          setLocalPending(intent);
          setStage("unknown");
        }
      }
    );
    if (!saved) return false;
    if (scenario === "response-lost") {
      setLocalPending(intent);
      access.clearWorkspaceError();
      focus.current = "flow";
      setStage("unknown");
      return true;
    }
    setFeedback(required ? "enabled" : "disabled");
    setLocalPending(null);
    focus.current = "heading";
    setStage("summary");
    return true;
  };
  const inspect = async () => {
    if (!pending) return;
    access.clearWorkspaceError();
    const inspected = await access.executeWorkspace({ kind: "inspect-account-rule-change", requestId: pending.requestId, resultMode: inspection });
    if (!inspected) return;
    setFeedback(inspection === "found-applied" ? (pending.requestedLoginProtection ? "enabled" : "disabled") : "rejected");
    setLocalPending(null);
    setRequired(inspection === "found-applied" ? pending.requestedLoginProtection : pending.baselineLoginProtection);
    setRequestId(`mock-account-rule-${crypto.randomUUID()}`);
    focus.current = "heading";
    setStage("summary");
  };

  return <section aria-labelledby="account-policy" className={styles.section}>
    <div className={styles.sectionHeading}><div><p>{t("accountEyebrow")}</p><h2 id="account-policy" ref={heading} tabIndex={-1}>{t("accountTitle")}</h2><span>{t("accountHint")}</span></div><div className={styles.headingBadges}><Badge status={workspace.settings.loginProtection ? "success" : "neutral"}>{t(workspace.settings.loginProtection ? "required" : "optional")}</Badge><Badge status="warning">MOCK</Badge></div></div>
    {feedback ? <Alert status={feedback === "rejected" ? "warning" : "success"}>{t(feedback === "rejected" ? "feedback.policyRejected" : `feedback.policy${feedback === "enabled" ? "Enabled" : "Disabled"}`)}</Alert> : null}
    {stage === "verify" ? <SecurityStepUpPreview action="securitySettings" onCancel={() => { focus.current = "flow"; setStage("review"); }} onVerified={save} /> : null}
    {stage === "review" ? <Card className={styles.flowCard}>
      <Card.Header><div><h3 className={styles.flowTitle} ref={flowHeading} tabIndex={-1}>{t("accountReviewTitle")}</h3><Typography.Text tone="muted">{t("accountReviewHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header>
      <Card.Body className={styles.flowBody}>
        <dl className={styles.facts}>
          <div><dt>{t("accountChange")}</dt><dd>{t(workspace.settings.loginProtection ? "required" : "optional")} → {t(required ? "required" : "optional")}</dd></div>
          <div><dt>{t("accountTarget")}</dt><dd><code>{workspace.accountId}</code></dd></div>
          <div><dt>{t("accountScope")}</dt><dd>{t("accountScopeValue")}</dd></div>
          <div><dt>{t("protectedIdentities")}</dt><dd>{t("protectedIdentitiesValue")}</dd></div>
          <div><dt>{t("sessionEffect")}</dt><dd>{t(required ? "sessionEffectTighten" : "sessionEffectRelax")}</dd></div>
        </dl>
        <Alert status="warning">{t("accountReviewBoundary")}</Alert>
        <FormField id={scenarioId} label={t("accountSaveScenario")}><Select id={scenarioId} value={scenario} onValueChange={(value) => setScenario(value as SaveScenario)} options={(["success", "denied", "conflict", "response-lost"] as const).map((value) => ({ value, label: t(`accountSaveScenarios.${value}`) }))} /></FormField>
        <p className={styles.boundary}>{t("accountSaveScenarioHint")}</p>
        <div className={styles.flowActions}><Button onClick={backToEdit} variant="ghost">{t("back")}</Button><Button onClick={() => setStage("verify")}>{t("verifyAccountChange")}</Button></div>
      </Card.Body>
    </Card> : null}
    {stage === "conflict" ? <Card className={styles.flowCard}>
      <Card.Header><div><h3 className={styles.flowTitle} ref={flowHeading} tabIndex={-1}>{t("accountConflictTitle")}</h3><Typography.Text tone="muted">{t("accountConflictHint")}</Typography.Text></div><Badge status="warning">{t("staleReview")}</Badge></Card.Header>
      <Card.Body className={styles.flowBody}>
        <dl className={styles.facts}>
          <div><dt>{t("accountTarget")}</dt><dd><code>{workspace.accountId}</code></dd></div>
          <div><dt>{t("attemptedChange")}</dt><dd>{t(workspace.settings.loginProtection ? "required" : "optional")} → {t(required ? "required" : "optional")}</dd></div>
          <div><dt>{t("verificationState")}</dt><dd>{t("verificationDiscarded")}</dd></div>
        </dl>
        <Alert status="warning">{t("accountConflictBoundary")}</Alert>
        <div className={styles.flowActions}><Button disabled={access.loading} onClick={() => { access.clearWorkspaceError(); setFeedback(null); setRequired(workspace.settings.loginProtection); focus.current = "heading"; setStage("summary"); access.reload(); }}>{t(access.loading ? "reloadingRule" : "reloadCurrentRule")}</Button></div>
      </Card.Body>
    </Card> : null}
    {stage === "denied" ? <Card className={styles.flowCard}>
      <Card.Header><div><h3 className={styles.flowTitle} ref={flowHeading} tabIndex={-1}>{t("accountDeniedTitle")}</h3><Typography.Text tone="muted">{t("accountDeniedHint")}</Typography.Text></div><Badge status="danger">{t("updateDenied")}</Badge></Card.Header>
      <Card.Body className={styles.flowBody}>
        <dl className={styles.facts}>
          <div><dt>{t("currentRule")}</dt><dd>{t(workspace.settings.loginProtection ? "required" : "optional")}</dd></div>
          <div><dt>{t("attemptedChange")}</dt><dd>{t(workspace.settings.loginProtection ? "required" : "optional")} → {t(required ? "required" : "optional")}</dd></div>
          <div><dt>{t("verificationState")}</dt><dd>{t("verificationDiscarded")}</dd></div>
        </dl>
        <Alert status="warning">{t("accountDeniedBoundary")}</Alert>
        <div className={styles.flowActions}><Button onClick={() => { setFeedback(null); setRequired(workspace.settings.loginProtection); setRequestId(`mock-account-rule-${crypto.randomUUID()}`); focus.current = "heading"; setStage("summary"); }}>{t("backToCurrentRule")}</Button></div>
      </Card.Body>
    </Card> : null}
    {stage === "unknown" ? <Card className={styles.flowCard}>
      <Card.Header><div><h3 className={styles.flowTitle} ref={flowHeading} tabIndex={-1}>{t("accountUnknownTitle")}</h3><Typography.Text tone="muted">{t("accountUnknownHint")}</Typography.Text></div><Badge status="warning">{t("outcomeUnknown")}</Badge></Card.Header>
      <Card.Body className={styles.flowBody}>
        <dl className={styles.facts}>
          <div><dt>{t("accountTarget")}</dt><dd><code>{workspace.accountId}</code></dd></div>
          <div><dt>{t("attemptedChange")}</dt><dd>{t((pending?.baselineLoginProtection ?? workspace.settings.loginProtection) ? "required" : "optional")} → {t((pending?.requestedLoginProtection ?? required) ? "required" : "optional")}</dd></div>
          <div><dt>{t("originalIntent")}</dt><dd><code>{pending?.requestId ?? requestId}</code></dd></div>
          <div><dt>{t("verificationState")}</dt><dd>{t("verificationDiscarded")}</dd></div>
        </dl>
        <Alert status="warning">{t("accountUnknownBoundary")}</Alert>
        {workspace.pendingAccountRuleChange?.status === "UNKNOWN" ? <><FormField id={inspectionId} label={t("accountInspectionScenario")}><Select id={inspectionId} value={inspection} onValueChange={(value) => setInspection(value as InspectionScenario)} options={(["found-applied", "found-rejected", "not-found", "unavailable"] as const).map((value) => ({ value, label: t(`accountInspectionScenarios.${value}`) }))} /></FormField>
          {access.workspaceError ? <Alert status="danger">{t(`accountInspectionErrors.${access.workspaceError === "accountRuleResultNotFound" ? "notFound" : "unavailable"}`)}</Alert> : null}
          <div className={styles.flowActions}><Button disabled={access.busy} onClick={() => void inspect()}>{t(access.busy ? "inspectingOriginalIntent" : "inspectOriginalIntent")}</Button></div></> : <Alert>{t("accountInspectionUnavailable")}</Alert>}
      </Card.Body>
    </Card> : null}
    {stage === "summary" || stage === "edit" ? <Card><Card.Header><div className={styles.cardTitle}><span><ShieldCheck aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("accountControlTitle")}</Typography.Title><Typography.Text tone="muted">{t("accountControlHint")}</Typography.Text></div></div></Card.Header><Card.Body>
      {stage === "summary" ? <div className={styles.policyForm}>
        <dl className={styles.facts}>
          <div><dt>{t("currentRule")}</dt><dd>{t(workspace.settings.loginProtection ? "required" : "optional")}</dd></div>
          <div><dt>{t("accountScope")}</dt><dd>{t("accountScopeValue")}</dd></div>
          <div><dt>{t("protectedIdentities")}</dt><dd>{t("protectedIdentitiesValue")}</dd></div>
        </dl>
        <Alert>{t("accountMockBoundary")}</Alert>
        {!factorReady ? <Alert status="warning">{t("accountFactorRequired")}</Alert> : workspace.personalMfa.reauthenticationRequired ? <Alert status="warning">{t("accountReauthenticationRequired")}</Alert> : null}
        <div className={styles.flowActions}>{!factorReady ? <Button onClick={focusPersonalSecurity} variant="secondary">{t("goToPersonalSecurity")}</Button> : <Button disabled={!canChangeRule || access.loading || access.busy} ref={trigger} onClick={() => { setFeedback(null); setRequired(workspace.settings.loginProtection); setScenario("success"); setRequestId(`mock-account-rule-${crypto.randomUUID()}`); setStage("edit"); }}>{t("editAccountRule")}</Button>}</div>
      </div> : <form className={styles.policyForm} onSubmit={(event) => { event.preventDefault(); review(); }}>
        <Checkbox checked={required} onChange={(event) => { setRequired(event.target.checked); setFeedback(null); }}>{t("requireForUsers")}</Checkbox>
        <p>{t("requireForUsersHint")}</p>
        {changed && required ? <Alert status="warning">{t("reauthenticationWarning")}</Alert> : null}
        <Alert>{t("accountMockBoundary")}</Alert>
        <div className={styles.flowActions}><Button disabled={!changed || access.busy} ref={trigger} type="submit">{t("reviewAccountChange")}</Button><Button disabled={access.busy} onClick={() => { setRequired(workspace.settings.loginProtection); setFeedback(null); focus.current = "trigger"; setStage("summary"); }} type="button" variant="ghost">{t("cancel")}</Button></div>
      </form>}
    </Card.Body></Card> : null}
  </section>;
}
