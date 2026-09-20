"use client";

import { useId, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  KeyRound,
  LockKeyhole,
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
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import styles from "./MfaPreviewExperience.module.css";
import { SecurityNotificationAddressPreview } from "./SecurityNotificationAddressPreview";

const demonstrationCode = "624810";
const demonstrationRecoveryCode = "MTRX-RECOVER-01";
const recoveryCodes = [
  "MTRX-4Q7F-K2PA", "MTRX-9C2M-W6RT", "MTRX-3J8N-H5VX", "MTRX-7P4D-Y9KL",
  "MTRX-5T2B-Q8NC", "MTRX-8R6W-F3JM", "MTRX-2V9K-P7HD", "MTRX-6N3X-C4QA"
];

type EnrollmentReason = "first" | "recovery" | "replace";
type StepUpAction = "bind" | "replace" | "remove" | "regenerate";
type Feedback = "removed" | "replaced" | "bound" | "regenerated" | "policyEnabled" | "policyDisabled";
const enrollmentSteps = ["prepare", "scan", "verify", "recoveryCodes"] as const;

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

function RecoveryCodes({ onDone, onCancel }: { onDone(): void; onCancel?(): void }) {
  const t = useTranslations("MfaPreview");
  const [acknowledged, setAcknowledged] = useState(false);
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      if (!navigator.clipboard) return;
      await navigator.clipboard.writeText(recoveryCodes.join("\n"));
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }
  return <div className={styles.flowBody}>
    <Alert status="warning">{t("codesOneTime")}</Alert>
    <div className={styles.secretHeader}><div><strong>{t("codesTitle")}</strong><p>{t("codesHint")}</p></div><Button onClick={() => void copy()} size="small" variant="secondary">{t(copied ? "copied" : "copyCodes")}</Button></div>
    <ul aria-label={t("codesTitle")} className={styles.codes}>{recoveryCodes.map((code) => <li key={code}>{code}</li>)}</ul>
    <Checkbox checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)}>{t("codesSaved")}</Checkbox>
    <div className={styles.flowActions}>{onCancel ? <Button onClick={onCancel} variant="ghost">{t("cancel")}</Button> : null}<Button disabled={!acknowledged} onClick={onDone}>{t("finish")}</Button></div>
  </div>;
}

function EnrollmentWizard({ reason, sessionless = false, onCancel, onFinish }: { reason: EnrollmentReason; sessionless?: boolean; onCancel(): void; onFinish(): void }) {
  const t = useTranslations("MfaPreview");
  const [step, setStep] = useState(0);
  const [code, setCode] = useState("");
  const [error, setError] = useState(false);
  const codeId = useId();
  function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (code !== demonstrationCode) { setError(true); return; }
    setError(false);
    setStep(3);
  }
  return <Card className={styles.flowCard}>
    <Card.Header><div><Typography.Title as="h2" level={3}>{t(`enrollment.${reason}.title`)}</Typography.Title><Typography.Text tone="muted">{t(`enrollment.${reason}.hint`)}</Typography.Text></div><Badge status="info">MOCK</Badge></Card.Header>
    <Card.Body className={styles.flowBody}>
      <FlowSteps current={step} />
      {step === 0 ? <>
        <div className={styles.flowLead}><Smartphone aria-hidden="true" /><div><strong>{t("installTitle")}</strong><p>{t("installHint")}</p></div></div>
        {reason === "first" && sessionless ? <Alert status="warning"><Mail aria-hidden="true" />{t("notificationAddressGate")}</Alert> : null}
        {reason === "recovery" ? <Alert status="warning">{t("recoveryBoundary")}</Alert> : null}
        {reason === "replace" ? <Alert>{t("replaceBoundary")}</Alert> : null}
        <div className={styles.flowActions}><Button onClick={onCancel} variant="ghost">{t("cancel")}</Button><Button onClick={() => setStep(1)}>{t("continue")}</Button></div>
      </> : null}
      {step === 1 ? <>
        <div className={styles.enrollmentGrid}><DemoQr /><div className={styles.manualKey}><strong>{t("scanTitle")}</strong><p>{t("scanHint")}</p><small>{t("manualKey")}</small><code>MTRX-DEMO-NOT-A-SECRET</code><em>{t("demoSecret")}</em></div></div>
        <div className={styles.flowActions}><Button onClick={() => setStep(0)} variant="ghost">{t("back")}</Button><Button onClick={() => setStep(2)}>{t("scanned")}</Button></div>
      </> : null}
      {step === 2 ? <form className={styles.form} onSubmit={verify}>
        <Alert>{t("demoCode", { code: demonstrationCode })}</Alert>
        <FormField id={codeId} label={t("verificationCode")} hint={t("waitForNewCode")}><Input autoComplete="one-time-code" id={codeId} inputMode="numeric" maxLength={6} onChange={(event) => { setCode(event.target.value.replace(/\D/g, "")); setError(false); }} pattern="[0-9]{6}" required value={code} /></FormField>
        {error ? <Alert status="danger">{t("invalidCode")}</Alert> : null}
        <div className={styles.flowActions}><Button onClick={() => setStep(1)} type="button" variant="ghost">{t("back")}</Button><Button disabled={code.length !== 6} type="submit">{t("confirmBinding")}</Button></div>
      </form> : null}
      {step === 3 ? <RecoveryCodes onCancel={onCancel} onDone={onFinish} /> : null}
    </Card.Body>
  </Card>;
}

export function MfaLoginPreview({ onBack, onAuthenticated }: { onBack(): void; onAuthenticated(): void }) {
  const t = useTranslations("MfaPreview");
  const [mode, setMode] = useState<"challenge" | "recover" | "enroll-first" | "enroll-recovery" | "recovered">("challenge");
  const [code, setCode] = useState("");
  const [error, setError] = useState(false);
  const codeId = useId();
  if (mode === "enroll-first" || mode === "enroll-recovery") return <EnrollmentWizard reason={mode === "enroll-first" ? "first" : "recovery"} sessionless onCancel={() => setMode("challenge")} onFinish={() => setMode("recovered")} />;
  if (mode === "recovered") return <div className={styles.loginFlow}><div className={styles.completion}><CheckCircle2 aria-hidden="true" /><div><h1>{t("reenrollComplete")}</h1><p>{t("reenrollCompleteHint")}</p></div></div><Button block onClick={onBack}>{t("returnToLogin")}</Button></div>;
  if (mode === "recover") return <form className={styles.loginFlow} onSubmit={(event) => { event.preventDefault(); if (code === demonstrationRecoveryCode) setMode("enroll-recovery"); else setError(true); }}>
    <div className={styles.loginHeading}><KeyRound aria-hidden="true" /><div><h1>{t("recoverTitle")}</h1><p>{t("recoverHint")}</p></div></div>
    <Alert status="warning">{t("demoRecoveryCode", { code: demonstrationRecoveryCode })}</Alert>
    <FormField id={codeId} label={t("recoveryCode")} hint={t("recoverRestriction")}><Input autoComplete="off" id={codeId} onChange={(event) => { setCode(event.target.value.trim().toUpperCase()); setError(false); }} required value={code} /></FormField>
    {error ? <Alert status="danger">{t("invalidRecoveryCode")}</Alert> : null}
    <Button block type="submit">{t("continueRecovery")}</Button>
    <Button block onClick={() => { setMode("challenge"); setCode(""); setError(false); }} type="button" variant="ghost">{t("back")}</Button>
    <p className={styles.boundary}><AlertTriangle aria-hidden="true" />{t("noRecoveryMaterial")}</p>
  </form>;
  return <form className={styles.loginFlow} onSubmit={(event) => { event.preventDefault(); if (code === demonstrationCode) onAuthenticated(); else setError(true); }}>
    <div className={styles.loginHeading}><ShieldCheck aria-hidden="true" /><div><h1>{t("challengeTitle")}</h1><p>{t("challengeHint")}</p></div></div>
    <div className={styles.identity}><span>{t("signingInAs")}</span><strong>preview-admin</strong><small>org-xiak</small></div>
    <Alert>{t("demoCode", { code: demonstrationCode })}</Alert>
    <FormField id={codeId} label={t("verificationCode")} hint={t("waitForNewCode")}><Input autoComplete="one-time-code" id={codeId} inputMode="numeric" maxLength={6} onChange={(event) => { setCode(event.target.value.replace(/\D/g, "")); setError(false); }} pattern="[0-9]{6}" required value={code} /></FormField>
    {error ? <Alert status="danger">{t("invalidCode")}</Alert> : null}
    <Button block disabled={code.length !== 6} type="submit">{t("verifyAndSignIn")}</Button>
    <div className={styles.loginLinks}><Button onClick={() => { setMode("recover"); setCode(""); setError(false); }} type="button" variant="ghost">{t("lostAuthenticator")}</Button><Button onClick={() => setMode("enroll-first")} type="button" variant="ghost">{t("previewFirstEnrollment")}</Button></div>
    <Button block onClick={onBack} type="button" variant="ghost">{t("returnToLogin")}</Button>
  </form>;
}

function StepUpPanel({ action, onCancel, onVerified }: { action: StepUpAction; onCancel(): void; onVerified(): void }) {
  const t = useTranslations("MfaPreview");
  const auth = useTranslations("Auth");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState(false);
  const id = useId();
  return <Card className={styles.flowCard}>
    <Card.Header><div><Typography.Title as="h2" level={3}>{t(`stepUp.${action}.title`)}</Typography.Title><Typography.Text tone="muted">{t("stepUp.hint")}</Typography.Text></div><Badge status="warning">{t("stepUp.once")}</Badge></Card.Header>
    <Card.Body><form className={styles.form} onSubmit={(event) => { event.preventDefault(); if (password === "demo-password" && code === demonstrationCode) onVerified(); else setError(true); }}>
      <Alert>{t("demoStepUp", { password: "demo-password", code: demonstrationCode })}</Alert>
      <FormField id={`${id}-password`} label={t("currentPassword")}><PasswordInput autoComplete="current-password" capsLockLabel={auth("capsLock")} hideLabel={auth("hidePassword")} id={`${id}-password`} onChange={(event) => { setPassword(event.target.value); setError(false); }} showLabel={auth("showPassword")} value={password} /></FormField>
      <FormField id={`${id}-code`} label={t("verificationCode")}><Input autoComplete="one-time-code" id={`${id}-code`} inputMode="numeric" maxLength={6} onChange={(event) => { setCode(event.target.value.replace(/\D/g, "")); setError(false); }} value={code} /></FormField>
      {error ? <Alert status="danger">{t("stepUp.invalid")}</Alert> : null}
      <p className={styles.boundary}><LockKeyhole aria-hidden="true" />{t("stepUp.boundary")}</p>
      <div className={styles.flowActions}><Button onClick={onCancel} type="button" variant="ghost">{t("cancel")}</Button><Button disabled={!password || code.length !== 6} type="submit">{t("stepUp.verify")}</Button></div>
    </form></Card.Body>
  </Card>;
}

export function MfaSecurityPreview({ workspace }: { workspace: AccessWorkspace }) {
  const t = useTranslations("MfaPreview");
  const access = useAccountAccess();
  const [required, setRequired] = useState(workspace.settings.loginProtection);
  const [factorState, setFactorState] = useState<"bound" | "removed">("bound");
  const [stepUp, setStepUp] = useState<StepUpAction | null>(null);
  const [enrollment, setEnrollment] = useState<EnrollmentReason | null>(null);
  const [showCodes, setShowCodes] = useState(false);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const changed = required !== workspace.settings.loginProtection;

  function begin(action: StepUpAction) { setFeedback(null); setStepUp(action); setEnrollment(null); setShowCodes(false); }
  function verified() {
    if (stepUp === "bind") { setEnrollment("first"); setStepUp(null); return; }
    if (stepUp === "replace") { setEnrollment("replace"); setStepUp(null); return; }
    if (stepUp === "regenerate") { setShowCodes(true); setStepUp(null); return; }
    if (stepUp === "remove") { setFactorState("removed"); setStepUp(null); setFeedback("removed"); }
  }
  if (enrollment) return <EnrollmentWizard reason={enrollment} onCancel={() => setEnrollment(null)} onFinish={() => { setFactorState("bound"); setEnrollment(null); setFeedback(enrollment === "replace" ? "replaced" : "bound"); }} />;
  if (showCodes) return <Card className={styles.flowCard}><Card.Header><Typography.Title as="h2" level={3}>{t("regenerateTitle")}</Typography.Title><Badge status="warning">MOCK</Badge></Card.Header><Card.Body><RecoveryCodes onCancel={() => setShowCodes(false)} onDone={() => { setShowCodes(false); setFeedback("regenerated"); }} /></Card.Body></Card>;
  if (stepUp) return <StepUpPanel action={stepUp} onCancel={() => setStepUp(null)} onVerified={verified} />;

  return <div className={styles.securityRoot}>
    <Alert>{t("mockBoundary")}</Alert>
    {feedback ? <Alert status="success">{t(`feedback.${feedback}`)}</Alert> : null}
    <SecurityNotificationAddressPreview />
    <section aria-labelledby="personal-security" className={styles.section}>
      <div className={styles.sectionHeading}><div><p>{t("personalEyebrow")}</p><h2 id="personal-security">{t("personalTitle")}</h2><span>{t("personalHint")}</span></div><Badge status={factorState === "bound" ? "success" : required ? "warning" : "neutral"}>{t(factorState === "bound" ? "bound" : required ? "bindingRequired" : "notBound")}</Badge></div>
      <div className={styles.securityCards}>
        <Card><Card.Header><div className={styles.cardTitle}><span><Smartphone aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("authenticatorTitle")}</Typography.Title><Typography.Text tone="muted">{t("authenticatorHint")}</Typography.Text></div></div></Card.Header><Card.Body className={styles.cardBody}>
          <dl className={styles.facts}><div><dt>{t("method")}</dt><dd>{t("totp")}</dd></div><div><dt>{t("state")}</dt><dd>{t(factorState === "bound" ? "bound" : "notBound")}</dd></div><div><dt>{t("scope")}</dt><dd>{t("currentUserOnly")}</dd></div></dl>
          <div className={styles.actions}>{factorState === "bound" ? <><Button onClick={() => begin("replace")} variant="secondary">{t("replace")}</Button><Button disabled={required} onClick={() => begin("remove")} title={required ? t("removeBlocked") : undefined} variant="ghost">{t("remove")}</Button></> : <Button onClick={() => begin("bind")}>{t("bind")}</Button>}</div>
        </Card.Body></Card>
        <Card><Card.Header><div className={styles.cardTitle}><span><KeyRound aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("recoveryTitle")}</Typography.Title><Typography.Text tone="muted">{t("recoverySummary")}</Typography.Text></div></div></Card.Header><Card.Body className={styles.cardBody}>
          <dl className={styles.facts}><div><dt>{t("availableCodes")}</dt><dd>{factorState === "bound" ? "8 / 8" : "—"}</dd></div><div><dt>{t("display")}</dt><dd>{t("oneTimeOnly")}</dd></div><div><dt>{t("use")}</dt><dd>{t("restrictedRebind")}</dd></div></dl>
          <div className={styles.actions}><Button disabled={factorState !== "bound"} onClick={() => begin("regenerate")} variant="secondary"><RefreshCw aria-hidden="true" />{t("regenerate")}</Button></div>
        </Card.Body></Card>
      </div>
    </section>
    <section aria-labelledby="account-policy" className={styles.section}>
      <div className={styles.sectionHeading}><div><p>{t("accountEyebrow")}</p><h2 id="account-policy">{t("accountTitle")}</h2><span>{t("accountHint")}</span></div><Badge status={workspace.settings.loginProtection ? "success" : "neutral"}>{t(workspace.settings.loginProtection ? "required" : "optional")}</Badge></div>
      <Card><Card.Body><form className={styles.policyForm} onSubmit={async (event) => { event.preventDefault(); const saved = await access.executeWorkspace({ kind: "save-settings", settings: { ...workspace.settings, loginProtection: required } }); if (saved) setFeedback(required ? "policyEnabled" : "policyDisabled"); }}>
        <Checkbox checked={required} onChange={(event) => { setRequired(event.target.checked); setFeedback(null); }}>{t("requireForUsers")}</Checkbox>
        <p>{t("requireForUsersHint")}</p>
        {changed && required ? <Alert status="warning">{t("reauthenticationWarning")}</Alert> : null}
        <div className={styles.flowActions}><Button disabled={!changed || access.busy} type="submit">{access.busy ? t("saving") : t("savePolicy")}</Button><Button disabled={!changed || access.busy} onClick={() => setRequired(workspace.settings.loginProtection)} type="button" variant="ghost">{t("cancel")}</Button></div>
      </form></Card.Body></Card>
    </section>
    <section aria-labelledby="planned-security" className={styles.section}>
      <div className={styles.sectionHeading}><div><p>{t("plannedEyebrow")}</p><h2 id="planned-security">{t("plannedTitle")}</h2><span>{t("plannedHint")}</span></div></div>
      <div className={styles.plannedGrid}><div><LockKeyhole aria-hidden="true" /><span><strong>{t("operationProtection")}</strong><small>{t("operationProtectionHint")}</small></span><Badge>{t("designing")}</Badge></div></div>
    </section>
  </div>;
}
