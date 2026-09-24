"use client";

import { useEffect, useId, useLayoutEffect, useRef, useState, type FormEvent } from "react";
import { useFormatter, useTranslations } from "next-intl";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  KeyRound,
  Mail,
  RefreshCw,
  ShieldCheck,
  Smartphone
} from "lucide-react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  FormField,
  Input,
  PasswordInput,
  Typography
} from "@ui/xiak";
import { nextPreviewTotpCode, previewTotpCode, type AccessWorkspace, type PersonalMfaPreviewState } from "../domain/accessWorkspace";
import { useAccountAccess } from "../application/AccountAccessProvider";
import { useSession, useSessionCredential } from "../application/SessionProvider";
import styles from "./MfaPreviewExperience.module.css";
import { SecurityNotificationAddressPreview } from "./SecurityNotificationAddressPreview";
import { SecurityStepUpPreview, type SecurityStepUpAction } from "./SecurityStepUpPreview";

const demonstrationCode = "624810";

type EnrollmentReason = "first" | "recovery" | "replace";
type Feedback = "removed" | "replaced" | "bound" | "regenerated";
const enrollmentSteps = ["prepare", "scan", "verify", "recoveryCodes"] as const;
function replacementDeadlineElapsed(expiresAt?: string) {
  const deadline = Date.parse(expiresAt ?? "");
  return !Number.isFinite(deadline) || Date.now() >= deadline;
}

function DemoQr() {
  const pattern = "111111101010111111110100001011100100001011101110101110101110111010101110101010111010101110101110111000101000101110001010111011101011101011101000001010001000001011111110101011111111";
  return <div aria-label="MOCK QR" className={styles.qr} role="img">
    {pattern.slice(0, 13 * 13).split("").map((cell, index) => <span data-filled={cell === "1" ? "true" : undefined} key={index} />)}
  </div>;
}

function FlowSteps({ current }: { current: number }) {
  const t = useTranslations("MfaPreview");
  return <ol aria-label={t("progress")} className={styles.steps}>
    {enrollmentSteps.map((key, index) => <li aria-current={index === current ? "step" : undefined} data-active={index <= current ? "true" : undefined} key={key}>
      <span>{index < current ? <Check aria-hidden="true" /> : index + 1}</span><small>{t(`steps.${key}`)}</small>
    </li>)}
  </ol>;
}

function RecoveryCodes({ onDone, codes }: { onDone(): void; codes: string[] }) {
  const t = useTranslations("MfaPreview");
  const [acknowledged, setAcknowledged] = useState(false);
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      if (!navigator.clipboard) return;
      await navigator.clipboard.writeText(codes.join("\n"));
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }
  return <div className={styles.flowBody}>
    <Alert status="warning">{t("codesOneTime")}</Alert>
    <div className={styles.secretHeader}><div><strong>{t("codesTitle")}</strong><p>{t("codesHint")}</p></div><Button onClick={() => void copy()} size="small" variant="secondary">{t(copied ? "copied" : "copyCodes")}</Button></div>
    <ul aria-label={t("codesTitle")} className={styles.codes}>{codes.map((code) => <li key={code}>{code}</li>)}</ul>
    <Checkbox checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)}>{t("codesSaved")}</Checkbox>
    <div className={styles.flowActions}><Button disabled={!acknowledged} onClick={onDone}>{t("finish")}</Button></div>
  </div>;
}

function EnrollmentWizard({ reason, onCancel, onAbandon, onConfirmed, onUnknown, onFinish, replacement, verificationCode = demonstrationCode }: { reason: EnrollmentReason; onCancel(): void; onAbandon?(): void; onConfirmed(): string[] | false | Promise<string[] | false>; onUnknown?(): Promise<void>; onFinish(): void; replacement?: { active: boolean; expiresAt: string }; verificationCode?: string }) {
  const t = useTranslations("MfaPreview");
  const format = useFormatter();
  const [step, setStep] = useState(0);
  const [code, setCode] = useState("");
  const [error, setError] = useState<"code" | "outcome" | null>(null);
  const [issuedCodes, setIssuedCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [deadlineReached, setDeadlineReached] = useState(() => reason === "replace" && replacementDeadlineElapsed(replacement?.expiresAt));
  const [confirmationUnknown, setConfirmationUnknown] = useState(false);
  const confirming = useRef(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const codeId = useId();
  const replacementExpiresAt = replacement?.expiresAt;
  const stopped = reason === "replace" && step !== 3 && (confirmationUnknown || !replacement?.active || deadlineReached);
  const visibleStage = reason === "replace" && busy ? "checking" : stopped ? "stopped" : `step-${step}`;
  useLayoutEffect(() => { heading.current?.focus({ preventScroll: true }); }, [visibleStage]);
  useEffect(() => {
    if (reason !== "replace" || !replacementExpiresAt) return;
    const remaining = Date.parse(replacementExpiresAt) - Date.now();
    const timer = window.setTimeout(() => setDeadlineReached(true), Number.isFinite(remaining) ? Math.max(0, remaining) : 0);
    return () => window.clearTimeout(timer);
  }, [reason, replacementExpiresAt]);
  async function stopUnknown() {
    setCode("");
    try { await onUnknown?.(); } catch { /* A failed observation must not re-show one-time material. */ }
    setConfirmationUnknown(true);
  }
  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (confirming.current || confirmationUnknown || (reason === "replace" && (!replacement?.active || deadlineReached || replacementDeadlineElapsed(replacement.expiresAt)))) return;
    if (code !== verificationCode) { setError("code"); return; }
    confirming.current = true;
    setBusy(true);
    setError(null);
    try {
      const result = await onConfirmed();
      if (!result || result.length !== 10 || new Set(result).size !== 10) {
        if (reason === "replace") await stopUnknown();
        else setError("outcome");
        return;
      }
      setIssuedCodes(result);
      setStep(3);
    } catch {
      if (reason === "replace") await stopUnknown();
      else setError("outcome");
    } finally {
      confirming.current = false;
      setBusy(false);
    }
  }
  if (reason === "replace" && busy) return <Card className={styles.flowCard}>
    <Card.Header><h2 className={styles.flowTitle} ref={heading} tabIndex={-1}>{t("replacementCheckingTitle")}</h2><Badge status="info">MOCK</Badge></Card.Header>
    <Card.Body><Alert>{t("replacementCheckingHint")}</Alert></Card.Body>
  </Card>;
  if (stopped) return <Card className={styles.flowCard}>
    <Card.Header><h2 className={styles.flowTitle} ref={heading} tabIndex={-1}>{t("replacementStoppedTitle")}</h2><Badge status="warning">MOCK</Badge></Card.Header>
    <Card.Body className={styles.flowBody}>
      <Alert status="warning">{t(confirmationUnknown ? "replacementOutcomeUnknown" : "replacementNoLongerValid")}</Alert>
      <div className={styles.flowActions}><Button onClick={onAbandon} variant="secondary">{t("returnToSecurity")}</Button></div>
    </Card.Body>
  </Card>;
  return <Card className={styles.flowCard}>
    <Card.Header><div><h2 className={styles.flowTitle} ref={heading} tabIndex={-1}>{t(`enrollment.${reason}.title`)}</h2><Typography.Text tone="muted">{t(`enrollment.${reason}.hint`)}</Typography.Text></div><Badge status="info">MOCK</Badge></Card.Header>
    <Card.Body className={styles.flowBody}>
      <FlowSteps current={step} />
      {reason === "replace" && replacement?.active && step < 3 ? <p className={styles.boundary}>{t("replacementDeadline")}: {format.dateTime(new Date(replacement.expiresAt), { hour: "2-digit", minute: "2-digit", second: "2-digit", timeZoneName: "short" })}</p> : null}
      {step === 0 ? <>
        <div className={styles.flowLead}><Smartphone aria-hidden="true" /><div><strong>{t("installTitle")}</strong><p>{t("installHint")}</p></div></div>
        {reason === "first" ? <Alert status="warning"><Mail aria-hidden="true" />{t("firstEnrollmentBoundary")}</Alert> : null}
        {reason === "recovery" ? <Alert status="warning">{t("recoveryBoundary")}</Alert> : null}
        {reason === "replace" ? <Alert>{t("replaceBoundary")}</Alert> : null}
        <div className={styles.flowActions}><Button onClick={onCancel} variant="ghost">{t("cancel")}</Button><Button onClick={() => setStep(1)}>{t("continue")}</Button></div>
      </> : null}
      {step === 1 ? <>
        <div className={styles.enrollmentGrid}><DemoQr /><div className={styles.manualKey}><strong>{t("scanTitle")}</strong><p>{t("scanHint")}</p><small>{t("manualKey")}</small><code>MTRX-DEMO-NOT-A-SECRET</code><em>{t("demoSecret")}</em></div></div>
        <div className={styles.flowActions}><Button onClick={() => setStep(0)} variant="ghost">{t("back")}</Button><Button onClick={() => setStep(2)}>{t("scanned")}</Button></div>
      </> : null}
      {step === 2 ? <form className={styles.form} onSubmit={(event) => void verify(event)}>
        <Alert>{t("demoCode", { code: verificationCode })}</Alert>
        <FormField id={codeId} label={t("verificationCode")} hint={t("waitForNewCode")}><Input autoComplete="one-time-code" id={codeId} inputMode="numeric" maxLength={6} onChange={(event) => { setCode(event.target.value.replace(/\D/g, "")); setError(null); }} pattern="[0-9]{6}" required value={code} /></FormField>
        {error ? <Alert status="danger">{t(error === "code" ? "invalidCode" : "confirmationFailed")}</Alert> : null}
        <div className={styles.flowActions}><Button disabled={busy} onClick={() => setStep(1)} type="button" variant="ghost">{t("back")}</Button><Button disabled={busy || code.length !== 6} type="submit">{t(busy ? "stepUp.verifying" : "confirmBinding")}</Button></div>
      </form> : null}
      {step === 3 && issuedCodes ? <RecoveryCodes codes={issuedCodes} onDone={onFinish} /> : null}
    </Card.Body>
  </Card>;
}

export function MfaLoginPreview({ state, recoveryCodeHint, onBack, onAuthenticated, onBeginRecovery, onCancelRecovery, onConfirmRecovery }: {
  state: PersonalMfaPreviewState;
  onBack(): void;
  onAuthenticated(): boolean | void | Promise<boolean | void>;
  recoveryCodeHint: string | null;
  onBeginRecovery(password: string, recoveryCode: string): Promise<string | null>;
  onCancelRecovery(challenge: string): void;
  onConfirmRecovery(challenge: string): string[] | false | Promise<string[] | false>;
}) {
  const t = useTranslations("MfaPreview");
  const auth = useTranslations("Auth");
  const [mode, setMode] = useState<"challenge" | "recover" | "enroll-recovery" | "recovered">(state.recoveryState === "rebind-required" ? "recover" : "challenge");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [recoveryChallenge, setRecoveryChallenge] = useState<string | null>(null);
  const [error, setError] = useState(false);
  const codeId = useId();
  const requiresFactor = state.factorState !== "removed";
  if (mode === "enroll-recovery") return <EnrollmentWizard reason="recovery" onCancel={() => { if (recoveryChallenge) onCancelRecovery(recoveryChallenge); setRecoveryChallenge(null); onBack(); }} onConfirmed={() => recoveryChallenge ? onConfirmRecovery(recoveryChallenge) : false} onFinish={() => setMode("recovered")} />;
  if (mode === "recovered") return <div className={styles.loginFlow}><div className={styles.completion}><CheckCircle2 aria-hidden="true" /><div><h1>{t("reenrollComplete")}</h1><p>{t("reenrollCompleteHint")}</p></div></div><Button block onClick={onBack}>{t("returnToLogin")}</Button></div>;
  if (mode === "recover") return <form className={styles.loginFlow} onSubmit={(event) => { event.preventDefault(); void (async () => { const challenge = await onBeginRecovery(password, code); if (!challenge) { setError(true); return; } setRecoveryChallenge(challenge); setMode("enroll-recovery"); })(); }}>
    <div className={styles.loginHeading}><KeyRound aria-hidden="true" /><div><h1>{t("recoverTitle")}</h1><p>{t("recoverHint")}</p></div></div>
    <Alert status="warning">{recoveryCodeHint ? t("demoRecoveryCode", { code: recoveryCodeHint }) : t("noRecoveryMaterial")}</Alert>
    <FormField id={`${codeId}-recovery-password`} label={t("currentPassword")}><PasswordInput autoComplete="current-password" capsLockLabel={auth("capsLock")} hideLabel={auth("hidePassword")} id={`${codeId}-recovery-password`} onChange={(event) => { setPassword(event.target.value); setError(false); }} showLabel={auth("showPassword")} value={password} /></FormField>
    <FormField id={codeId} label={t("recoveryCode")} hint={t("recoverRestriction")}><Input autoComplete="off" id={codeId} onChange={(event) => { setCode(event.target.value); setError(false); }} required value={code} /></FormField>
    {error ? <Alert status="danger">{t("invalidRecoveryCode")}</Alert> : null}
    <Button block disabled={!password || !code || !recoveryCodeHint} type="submit">{t("continueRecovery")}</Button>
    <Button block onClick={onBack} type="button" variant="ghost">{t("returnToLogin")}</Button>
    <p className={styles.boundary}><AlertTriangle aria-hidden="true" />{t("noRecoveryMaterial")}</p>
  </form>;
  return <form className={styles.loginFlow} onSubmit={(event) => { event.preventDefault(); void (async () => { if (password !== "demo-password" || (requiresFactor && code !== previewTotpCode(state)) || await onAuthenticated() === false) { setError(true); return; } })(); }}>
    <div className={styles.loginHeading}><ShieldCheck aria-hidden="true" /><div><h1>{t("challengeTitle")}</h1><p>{t("challengeHint")}</p></div></div>
    <div className={styles.identity}><span>{t("signingInAs")}</span><strong>preview-admin</strong><small>org-xiak</small></div>
    <Alert>{t(requiresFactor ? "demoLoginChallenge" : "demoPasswordOnly", { password: "demo-password", code: previewTotpCode(state) })}</Alert>
    <FormField id={`${codeId}-password`} label={t("currentPassword")}><PasswordInput autoComplete="current-password" capsLockLabel={auth("capsLock")} hideLabel={auth("hidePassword")} id={`${codeId}-password`} onChange={(event) => { setPassword(event.target.value); setError(false); }} showLabel={auth("showPassword")} value={password} /></FormField>
    {requiresFactor ? <FormField id={codeId} label={t("verificationCode")} hint={t("waitForNewCode")}><Input autoComplete="one-time-code" id={codeId} inputMode="numeric" maxLength={6} onChange={(event) => { setCode(event.target.value.replace(/\D/g, "")); setError(false); }} pattern="[0-9]{6}" required value={code} /></FormField> : null}
    {error ? <Alert status="danger">{t("invalidCode")}</Alert> : null}
    <Button block disabled={!password || (requiresFactor && code.length !== 6)} type="submit">{t("verifyAndSignIn")}</Button>
    {requiresFactor ? <div className={styles.loginLinks}><Button onClick={() => { setMode("recover"); setCode(""); setError(false); }} type="button" variant="ghost">{t("lostAuthenticator")}</Button></div> : null}
    <Button block onClick={onBack} type="button" variant="ghost">{t("returnToLogin")}</Button>
  </form>;
}

export function MfaSecurityPreview({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("MfaPreview");
  const format = useFormatter();
  const access = useAccountAccess();
  const session = useSession();
  const credential = useSessionCredential();
  const [stepUp, setStepUp] = useState<SecurityStepUpAction | null>(null);
  const [enrollment, setEnrollment] = useState<EnrollmentReason | null>(null);
  const [replacementRequestId, setReplacementRequestId] = useState<string | null>(null);
  const [unresolvedReplacementRequestId, setUnresolvedReplacementRequestId] = useState<string | null>(null);
  const [pendingInspectBusy, setPendingInspectBusy] = useState(false);
  const [pendingInspectError, setPendingInspectError] = useState(false);
  const [regeneratedCodes, setRegeneratedCodes] = useState<string[] | null>(null);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [verifiedNotificationAddress, setVerifiedNotificationAddress] = useState<string | null>(null);
  const personalHeading = useRef<HTMLHeadingElement>(null);
  const bindTrigger = useRef<HTMLButtonElement>(null);
  const replaceTrigger = useRef<HTMLButtonElement>(null);
  const removeTrigger = useRef<HTMLButtonElement>(null);
  const regenerateTrigger = useRef<HTMLButtonElement>(null);
  const lastAction = useRef<SecurityStepUpAction | null>(null);
  const restoreFocus = useRef(false);
  const { factorState, reauthenticationRequired, pendingReplacement } = workspace.personalMfa;
  const replacementOutcomeUnknown = pendingReplacement?.status === "CONFIRMATION_UNKNOWN" || Boolean(pendingReplacement && pendingReplacement.requestId === unresolvedReplacementRequestId);
  const required = workspace.settings.loginProtection;
  const blockedActionHint = t(workspace.pendingAccountRuleChange?.status === "UNKNOWN" ? "accountOutcomeUnknownActionBlocked" : "reauthenticationActionBlocked");

  useLayoutEffect(() => {
    if (stepUp || enrollment || regeneratedCodes || !restoreFocus.current) return;
    restoreFocus.current = false;
    const trigger = lastAction.current === "bind" ? bindTrigger.current : lastAction.current === "replace" ? replaceTrigger.current : lastAction.current === "remove" ? removeTrigger.current : lastAction.current === "regenerate" ? regenerateTrigger.current : null;
    if (trigger && !trigger.disabled) trigger.focus({ preventScroll: true });
    else personalHeading.current?.focus({ preventScroll: true });
  }, [stepUp, enrollment, regeneratedCodes]);

  function begin(action: SecurityStepUpAction) { lastAction.current = action; setFeedback(null); setStepUp(action); setEnrollment(null); setRegeneratedCodes(null); }
  async function verified(proofStartedAt: string) {
    if (stepUp === "bind") { setEnrollment("first"); setStepUp(null); return; }
    if (stepUp === "replace") {
      const requestId = `mock-totp-replace-${crypto.randomUUID()}`;
      if (!await access.executeWorkspace({ kind: "begin-personal-mfa-replacement", requestId, proofStartedAt })) return false;
      setReplacementRequestId(requestId); setEnrollment("replace"); setStepUp(null); return;
    }
    if (stepUp === "regenerate") {
      const result = await access.executeWorkspace({ kind: "regenerate-personal-recovery-codes" });
      if (!result?.recoveryCodes || result.recoveryCodes.length !== 10) return false;
      setRegeneratedCodes(result.recoveryCodes); setStepUp(null); return;
    }
    if (stepUp === "remove") {
      const removed = await access.executeWorkspace({ kind: "remove-personal-mfa" });
      if (!removed) return false;
      setStepUp(null); setFeedback("removed");
      if (credential) session.expire(credential);
    }
  }
  if (enrollment) return <EnrollmentWizard reason={enrollment} replacement={enrollment === "replace" ? { active: Boolean(replacementRequestId && pendingReplacement?.requestId === replacementRequestId && pendingReplacement.status === "PENDING" && pendingReplacement.accountRuleVersion === workspace.settings.accountRuleVersion && Number.isFinite(Date.parse(pendingReplacement.expiresAt)) && !reauthenticationRequired && !workspace.pendingAccountRuleChange), expiresAt: pendingReplacement?.expiresAt ?? "" } : undefined} verificationCode={enrollment === "replace" ? nextPreviewTotpCode(workspace.personalMfa) : demonstrationCode} onAbandon={() => { restoreFocus.current = true; setEnrollment(null); setReplacementRequestId(null); }} onUnknown={enrollment === "replace" && replacementRequestId ? async () => { setUnresolvedReplacementRequestId(replacementRequestId); await access.executeWorkspace({ kind: "mark-personal-mfa-replacement-unknown", requestId: replacementRequestId }); } : undefined} onCancel={() => {
    if (enrollment === "replace" && replacementRequestId) {
      void access.executeWorkspace({ kind: "cancel-personal-mfa-replacement", requestId: replacementRequestId }).then((result) => {
        if (result) { restoreFocus.current = true; setEnrollment(null); setReplacementRequestId(null); }
      });
    } else { restoreFocus.current = true; setEnrollment(null); }
  }} onConfirmed={async () => {
    if (enrollment === "replace") {
      if (!replacementRequestId) return false;
      const result = await access.executeWorkspace({ kind: "confirm-personal-mfa-replacement", requestId: replacementRequestId });
      return result?.recoveryCodes?.length === 10 ? result.recoveryCodes : false;
    }
    const result = await access.executeWorkspace({ kind: "confirm-personal-mfa" });
    return result?.recoveryCodes?.length === 10 ? result.recoveryCodes : false;
  }} onFinish={() => { setEnrollment(null); setReplacementRequestId(null); setFeedback(enrollment === "replace" ? "replaced" : "bound"); if (credential) session.expire(credential); }} />;
  if (regeneratedCodes) return <Card className={styles.flowCard}><Card.Header><Typography.Title as="h2" level={3}>{t("regenerateTitle")}</Typography.Title><Badge status="warning">MOCK</Badge></Card.Header><Card.Body><RecoveryCodes codes={regeneratedCodes} onDone={() => { restoreFocus.current = true; setRegeneratedCodes(null); setFeedback("regenerated"); }} /></Card.Body></Card>;
  if (stepUp) return <SecurityStepUpPreview action={stepUp} demonstrationCode={previewTotpCode(workspace.personalMfa)} onCancel={() => { restoreFocus.current = true; setStepUp(null); }} onVerified={verified} />;

  return <>
    {feedback ? <Alert status="success">{t(`feedback.${feedback}`)}</Alert> : null}
    {reauthenticationRequired ? <Alert status="warning">{t(workspace.pendingAccountRuleChange?.status === "UNKNOWN" ? "accountOutcomeUnknownReauthenticationRequired" : "reauthenticationRequired")}</Alert> : null}
    {pendingReplacement ? <Card className={styles.flowCard}><Card.Header><Typography.Title as="h2" level={3}>{t("replacementPendingTitle")}</Typography.Title><Badge status="warning">MOCK</Badge></Card.Header><Card.Body className={styles.form}><Alert status="warning">{t(replacementOutcomeUnknown ? "replacementPendingUnknown" : "replacementPendingHint")}</Alert>{pendingInspectError ? <Alert status="danger">{t("replacementInspectFailed")}</Alert> : null}<dl className={styles.facts}><div><dt>{t("replacementRequest")}</dt><dd><code>{pendingReplacement.requestId}</code></dd></div><div><dt>{t("replacementDeadline")}</dt><dd>{format.dateTime(new Date(pendingReplacement.expiresAt), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", timeZoneName: "short" })}</dd></div></dl><div className={styles.flowActions}>{replacementOutcomeUnknown ? <Button disabled={pendingInspectBusy} onClick={() => { setPendingInspectBusy(true); setPendingInspectError(false); void access.executeWorkspace({ kind: "inspect-personal-mfa-replacement", requestId: pendingReplacement.requestId }).then((result) => { if (!result) setPendingInspectError(true); else setUnresolvedReplacementRequestId(null); }).catch(() => setPendingInspectError(true)).finally(() => setPendingInspectBusy(false)); }} variant="secondary">{pendingInspectBusy ? t("replacementInspecting") : t("replacementInspectMock")}</Button> : <Button onClick={() => void access.executeWorkspace({ kind: "cancel-personal-mfa-replacement", requestId: pendingReplacement.requestId })} variant="secondary">{t("cancelReplacement")}</Button>}</div></Card.Body></Card> : null}
    <SecurityNotificationAddressPreview onVerified={setVerifiedNotificationAddress} verifiedAddress={verifiedNotificationAddress} />
    <section aria-labelledby="personal-security" className={styles.section}>
      <div className={styles.sectionHeading}><div><p>{t("personalEyebrow")}</p><h2 id="personal-security" ref={personalHeading} tabIndex={-1}>{t("personalTitle")}</h2><span>{t("personalHint")}</span></div><Badge status={reauthenticationRequired ? "warning" : factorState === "bound" ? "success" : required ? "warning" : "neutral"}>{t(reauthenticationRequired ? "reauthenticate" : factorState === "bound" ? "bound" : required ? "bindingRequired" : "notBound")}</Badge></div>
      <div className={styles.securityCards}>
        <Card><Card.Header><div className={styles.cardTitle}><span><Smartphone aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("authenticatorTitle")}</Typography.Title><Typography.Text tone="muted">{t("authenticatorHint")}</Typography.Text></div></div></Card.Header><Card.Body className={styles.cardBody}>
          <dl className={styles.facts}><div><dt>{t("method")}</dt><dd>{t("totp")}</dd></div><div><dt>{t("state")}</dt><dd>{t(factorState === "bound" ? "bound" : "notBound")}</dd></div><div><dt>{t("scope")}</dt><dd>{t("currentUserOnly")}</dd></div></dl>
          <div className={styles.actions}>{factorState === "bound" ? <><Button ref={replaceTrigger} disabled={reauthenticationRequired || Boolean(pendingReplacement)} onClick={() => begin("replace")} title={reauthenticationRequired ? blockedActionHint : undefined} variant="secondary">{t("replace")}</Button><Button ref={removeTrigger} disabled={required || reauthenticationRequired || Boolean(pendingReplacement)} onClick={() => begin("remove")} title={reauthenticationRequired ? blockedActionHint : required ? t("removeBlocked") : undefined} variant="ghost">{t("remove")}</Button></> : <Button ref={bindTrigger} disabled={!verifiedNotificationAddress || reauthenticationRequired} onClick={() => begin("bind")} title={reauthenticationRequired ? blockedActionHint : !verifiedNotificationAddress ? t("bindRequiresVerifiedAddress") : undefined}>{t("bind")}</Button>}</div>
        </Card.Body></Card>
        <Card><Card.Header><div className={styles.cardTitle}><span><KeyRound aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("recoveryTitle")}</Typography.Title><Typography.Text tone="muted">{t("recoverySummary")}</Typography.Text></div></div></Card.Header><Card.Body className={styles.cardBody}>
          <dl className={styles.facts}><div><dt>{t("state")}</dt><dd>{t(factorState === "bound" ? "recoveryBatchReady" : "notAvailable")}</dd></div><div><dt>{t("display")}</dt><dd>{t("oneTimeOnly")}</dd></div><div><dt>{t("use")}</dt><dd>{t("restrictedRebind")}</dd></div></dl>
          <div className={styles.actions}><Button ref={regenerateTrigger} disabled={factorState !== "bound" || reauthenticationRequired || Boolean(pendingReplacement)} onClick={() => begin("regenerate")} title={reauthenticationRequired ? blockedActionHint : undefined} variant="secondary"><RefreshCw aria-hidden="true" />{t("regenerate")}</Button></div>
        </Card.Body></Card>
      </div>
    </section>
  </>;
}
