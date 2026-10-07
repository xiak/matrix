"use client";

import { useEffect, useId, useLayoutEffect, useRef, useState, type FormEvent, type RefObject } from "react";
import { Mail } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, FormField, Input, PasswordInput, Select, Typography } from "@ui/xiak";
import { validPreviewNotificationAddress, type PendingNotificationAddressReplacement } from "../domain/accessWorkspace";
import styles from "./MfaPreviewExperience.module.css";

const demonstrationCode = "48392017";
const demonstrationPassword = "demo-password";
const demonstrationReplacementTotp = "630127";
const contactSteps = ["address", "verify", "complete"] as const;
const replacementSteps = ["target", "proof", "verify", "complete"] as const;

type ContactStage = "summary" | "address" | "verify" | "replacement";
type FocusTarget = "trigger" | "summary" | null;

function ContactProgress({ current }: { current: number }) {
  const t = useTranslations("SecurityNotificationPreview");
  return <ol aria-label={t("progress")} className={styles.contactSteps}>
    {contactSteps.map((step, index) => <li aria-current={current === index ? "step" : undefined} data-active={index <= current ? "true" : undefined} key={step}>
      <span>{index + 1}</span><small>{t(`steps.${step}`)}</small>
    </li>)}
  </ol>;
}

function ReplacementProgress({ current }: { current: number }) {
  const t = useTranslations("SecurityNotificationPreview.replacement");
  return <ol aria-label={t("progress")} className={styles.steps}>
    {replacementSteps.map((step, index) => <li aria-current={current === index ? "step" : undefined} data-active={index <= current ? "true" : undefined} key={step}>
      <span>{index + 1}</span><small>{t(`progressSteps.${step}`)}</small>
    </li>)}
  </ol>;
}

export function SecurityNotificationAddressPreview({ verifiedAddress: controlledVerifiedAddress, onOpenReplacement, onVerified,
  replacementAvailable = true, replacementIntent = null, replacementTotpCode = demonstrationReplacementTotp,
  onBeginReplacement, onConfirmReplacement, onInspectReplacement }: {
  verifiedAddress?: string | null;
  onOpenReplacement?(): void;
  onVerified?(address: string): boolean | void | Promise<boolean | void>;
  replacementAvailable?: boolean;
  replacementIntent?: PendingNotificationAddressReplacement | null;
  replacementTotpCode?: string;
  onBeginReplacement?(mockVerificationId: string, targetAddress: string): Promise<boolean>;
  onConfirmReplacement?(mockVerificationId: string, responseMode: "success" | "response-lost"): Promise<boolean>;
  onInspectReplacement?(mockVerificationId: string, resultMode: "found-applied" | "found-rejected" | "not-found" | "unavailable"): Promise<boolean>;
} = {}) {
  const t = useTranslations("SecurityNotificationPreview");
  const auth = useTranslations("Auth");
  const [stage, setStage] = useState<ContactStage>("summary");
  const [address, setAddress] = useState("");
  const [password, setPassword] = useState("");
  const [pendingAddress, setPendingAddress] = useState<string | null>(null);
  const [localVerifiedAddress, setLocalVerifiedAddress] = useState<string | null>(null);
  const verifiedAddress = controlledVerifiedAddress === undefined ? localVerifiedAddress : controlledVerifiedAddress;
  const [code, setCode] = useState("");
  const [error, setError] = useState<"credentials" | "code" | "unavailable" | null>(null);
  const [confirming, setConfirming] = useState(false);
  const confirmingRef = useRef(false);
  const [completed, setCompleted] = useState(false);
  const [replacementCompleted, setReplacementCompleted] = useState(false);
  const addressId = useId();
  const passwordId = useId();
  const codeId = useId();
  const trigger = useRef<HTMLButtonElement>(null);
  const summaryHeading = useRef<HTMLHeadingElement>(null);
  const flowHeading = useRef<HTMLHeadingElement>(null);
  const focusTarget = useRef<FocusTarget>(null);

  useEffect(() => {
    if (stage !== "summary") flowHeading.current?.focus();
  }, [stage]);
  useLayoutEffect(() => {
    if (stage !== "summary" || !focusTarget.current) return;
    const target = focusTarget.current;
    focusTarget.current = null;
    if (target === "summary") summaryHeading.current?.focus();
    else trigger.current?.focus();
  }, [stage]);

  const begin = () => {
    setCompleted(false);
    setError(null);
    setCode("");
    setStage(pendingAddress ? "verify" : "address");
  };
  const previewReplacement = () => {
    onOpenReplacement?.();
    setCompleted(false);
    setReplacementCompleted(false);
    setError(null);
    setStage("replacement");
  };
  const close = () => {
    focusTarget.current = "trigger";
    setError(null);
    setStage("summary");
  };
  const prepare = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const candidate = address.trim();
    if (!validPreviewNotificationAddress(candidate) || password !== demonstrationPassword) {
      setError("credentials");
      return;
    }
    setPendingAddress(candidate);
    setAddress(candidate);
    setPassword("");
    setCode("");
    setError(null);
    setStage("verify");
  };
  const confirm = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (confirmingRef.current) return;
    if (code !== demonstrationCode || !pendingAddress) {
      setError("code");
      return;
    }
    confirmingRef.current = true;
    setConfirming(true);
    try {
      if (await onVerified?.(pendingAddress) === false) throw new Error("MOCK_VERIFICATION_UNAVAILABLE");
      if (controlledVerifiedAddress === undefined) setLocalVerifiedAddress(pendingAddress);
      setPendingAddress(null);
      setCode("");
      setError(null);
      setCompleted(true);
      focusTarget.current = "summary";
      setStage("summary");
    } catch {
      setError("unavailable");
    } finally {
      confirmingRef.current = false;
      setConfirming(false);
    }
  };

  if (stage === "replacement" && verifiedAddress) return <NotificationAddressReplacementPreview address={verifiedAddress} demonstrationTotp={replacementTotpCode} headingRef={flowHeading} intent={replacementIntent}
    onBegin={onBeginReplacement ?? (async () => false)} onConfirm={onConfirmReplacement ?? (async () => false)}
    onInspect={onInspectReplacement ?? (async () => false)} onClose={close} onComplete={() => {
    setReplacementCompleted(true);
    close();
  }} />;

  if (stage === "address") return <Card className={styles.flowCard}>
    <Card.Header><div><h2 className={styles.flowTitle} ref={flowHeading} tabIndex={-1}>{t("flowTitle")}</h2><Typography.Text tone="muted">{t("flowHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header>
    <Card.Body className={styles.flowBody}>
      <ContactProgress current={0} />
      <Alert status="warning">{t("mockBoundary")}</Alert>
      <form className={styles.form} onSubmit={prepare}>
        <FormField id={addressId} label={t("emailLabel")} hint={t("emailHint")}><Input autoComplete="email" id={addressId} onChange={(event) => { setAddress(event.target.value); setError(null); }} required value={address} /></FormField>
        <FormField id={passwordId} label={t("currentPassword")}><PasswordInput autoComplete="current-password" capsLockLabel={auth("capsLock")} hideLabel={auth("hidePassword")} id={passwordId} onChange={(event) => { setPassword(event.target.value); setError(null); }} showLabel={auth("showPassword")} value={password} /></FormField>
        <Alert>{t("demoPassword", { password: demonstrationPassword })}</Alert>
        {error === "credentials" ? <Alert status="danger">{t("invalidCredentials")}</Alert> : null}
        <p className={styles.boundary}><Mail aria-hidden="true" />{t("flowBoundary")}</p>
        <div className={styles.flowActions}><Button onClick={close} type="button" variant="ghost">{t("cancel")}</Button><Button disabled={!address.trim() || !password} type="submit">{t("createIntent")}</Button></div>
      </form>
    </Card.Body>
  </Card>;

  if (stage === "verify" && pendingAddress) return <Card className={styles.flowCard}>
    <Card.Header><div><h2 className={styles.flowTitle} ref={flowHeading} tabIndex={-1}>{t("verifyTitle")}</h2><Typography.Text tone="muted">{t("verifyHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header>
    <Card.Body className={styles.flowBody}>
      <ContactProgress current={1} />
      <dl className={styles.facts}>
        <div><dt>{t("address")}</dt><dd>{pendingAddress}</dd></div>
        <div><dt>{t("verificationState")}</dt><dd><Badge status="warning">{t("verificationPending")}</Badge></dd></div>
        <div><dt>{t("deliveryState")}</dt><dd><Badge status="warning">{t("deliveryPending")}</Badge></dd></div>
        <div><dt>{t("expires")}</dt><dd>{t("expiresValue")}</dd></div>
      </dl>
      <Alert status="warning">{t("pendingBoundary")}</Alert>
      <Alert>{t("demoCode", { code: demonstrationCode })}</Alert>
      <form className={styles.form} onSubmit={(event) => void confirm(event)}>
        <FormField id={codeId} label={t("codeLabel")} hint={t("codeHint")}><Input autoComplete="one-time-code" id={codeId} inputMode="numeric" maxLength={8} onChange={(event) => { setCode(event.target.value.replace(/\D/g, "")); setError(null); }} pattern="[0-9]{8}" required value={code} /></FormField>
        {error === "code" ? <Alert status="danger">{t("invalidCode")}</Alert> : null}
        {error === "unavailable" ? <Alert status="danger">{t("verificationUnavailable")}</Alert> : null}
        <p className={styles.boundary}><Mail aria-hidden="true" />{t("stateVocabulary")}</p>
        <div className={styles.flowActions}><Button disabled={confirming} onClick={close} type="button" variant="ghost">{t("closeForNow")}</Button><Button disabled={confirming || code.length !== 8} type="submit">{t("confirm")}</Button></div>
      </form>
    </Card.Body>
  </Card>;

  const state = verifiedAddress ? "VERIFIED" : "NONE";
  return <section aria-labelledby="security-notification-address" className={styles.section}>
    <div className={styles.sectionHeading}><div><p>{t("eyebrow")}</p><h2 id="security-notification-address" ref={summaryHeading} tabIndex={-1}>{t("title")}</h2><span>{t("hint")}</span></div><Badge status={verifiedAddress ? "success" : pendingAddress ? "warning" : "neutral"}>{t(pendingAddress ? "verificationInProgress" : `states.${state}`)}</Badge></div>
    {completed ? <Alert status="success">{t("completed")}</Alert> : null}
    {replacementCompleted ? <Alert status="success">{t("replacement.completed")}</Alert> : null}
    <Card><Card.Header><div className={styles.cardTitle}><span><Mail aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("cardTitle")}</Typography.Title><Typography.Text tone="muted">{t("cardHint")}</Typography.Text></div></div></Card.Header><Card.Body className={styles.cardBody}>
      <dl className={styles.facts}>
        <div><dt>{t("address")}</dt><dd>{verifiedAddress ?? pendingAddress ?? t("notConfigured")}</dd></div>
        <div><dt>{t("state")}</dt><dd>{t(`states.${state}`)}</dd></div>
        {pendingAddress ? <div><dt>{t("verificationState")}</dt><dd>{t("verificationPending")}</dd></div> : null}
        <div><dt>{t("purpose")}</dt><dd>{t("purposeValue")}</dd></div>
        <div><dt>{t("owner")}</dt><dd>{t("ownerValue")}</dd></div>
        {pendingAddress ? <div><dt>{t("deliveryState")}</dt><dd>{t("deliveryPending")}</dd></div> : null}
      </dl>
      {verifiedAddress ? <><Alert>{t("firstSliceBoundary")}</Alert><div className={styles.actions}><Button ref={trigger} disabled={!replacementAvailable && !replacementIntent} onClick={previewReplacement} title={!replacementAvailable && !replacementIntent ? t("replacement.unavailable") : undefined} variant="secondary">{t(replacementIntent ? "replacement.resume" : "replacement.open")}</Button></div></> : <div className={styles.actions}><Button ref={trigger} onClick={begin}>{t(pendingAddress ? "resume" : "start")}</Button></div>}
    </Card.Body></Card>
  </section>;
}

function NotificationAddressReplacementPreview({ address, demonstrationTotp, headingRef, intent, onBegin, onConfirm, onInspect, onClose, onComplete }: {
  address: string;
  demonstrationTotp: string;
  headingRef: RefObject<HTMLHeadingElement | null>;
  intent: PendingNotificationAddressReplacement | null;
  onBegin(mockVerificationId: string, targetAddress: string): Promise<boolean>;
  onConfirm(mockVerificationId: string, responseMode: "success" | "response-lost"): Promise<boolean>;
  onInspect(mockVerificationId: string, resultMode: "found-applied" | "found-rejected" | "not-found" | "unavailable"): Promise<boolean>;
  onClose(): void;
  onComplete(): void;
}) {
  const t = useTranslations("SecurityNotificationPreview");
  const auth = useTranslations("Auth");
  const [stage, setStage] = useState<"target" | "proof" | "complete">("target");
  const [originalAddress] = useState(intent?.previousAddress ?? address);
  const [targetAddress, setTargetAddress] = useState(intent?.targetAddress ?? "");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [mailCode, setMailCode] = useState("");
  const [error, setError] = useState<"address" | "proof" | "code" | "action" | "rejected" | "lookup" | null>(null);
  const [responseMode, setResponseMode] = useState<"success" | "response-lost">("success");
  const [inspectionMode, setInspectionMode] = useState<"found-applied" | "found-rejected" | "not-found" | "unavailable">("found-applied");
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const targetId = useId();
  const passwordId = useId();
  const totpId = useId();
  const mailCodeId = useId();
  const responseModeId = useId();
  const inspectionModeId = useId();
  const stepIndex = stage === "complete" || intent?.status === "CONFIRM_UNKNOWN" ? 3 : intent ? 2 : stage === "proof" ? 1 : 0;
  useEffect(() => { headingRef.current?.focus(); }, [headingRef, stage]);

  const prepareTarget = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const candidate = targetAddress.trim().toLowerCase();
    if (!validPreviewNotificationAddress(candidate) || candidate === originalAddress.toLowerCase()) { setError("address"); return; }
    setTargetAddress(candidate);
    setError(null);
    setStage("proof");
  };
  const verifyIdentity = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busyRef.current) return;
    const accepted = password === demonstrationPassword && totp === demonstrationTotp;
    setPassword("");
    setTotp("");
    if (!accepted) { setError("proof"); return; }
    busyRef.current = true;
    setBusy(true);
    try {
      const created = await onBegin(`mock-notification-verification-${crypto.randomUUID()}`, targetAddress);
      setError(created ? null : "action");
    } catch { setError("action"); }
    finally { busyRef.current = false; setBusy(false); }
  };
  const verifyTarget = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busyRef.current) return;
    const accepted = mailCode === demonstrationCode;
    setMailCode("");
    if (!accepted) { setError("code"); return; }
    if (!intent) { setError("action"); return; }
    busyRef.current = true; setBusy(true);
    try {
      if (!await onConfirm(intent.mockVerificationId, responseMode)) setError("action");
      else if (responseMode === "success") { setError(null); setStage("complete"); }
    } catch { setError("action"); }
    finally { busyRef.current = false; setBusy(false); }
  };
  const inspect = async () => {
    if (!intent || intent.status !== "CONFIRM_UNKNOWN" || busyRef.current) return;
    busyRef.current = true; setBusy(true);
    try {
      if (!await onInspect(intent.mockVerificationId, inspectionMode)) setError("lookup");
      else if (inspectionMode === "found-applied") { setError(null); setStage("complete"); }
      else if (inspectionMode === "found-rejected") { setError("rejected"); setTargetAddress(""); setStage("target"); }
      else setError("lookup");
    } catch { setError("lookup"); }
    finally { busyRef.current = false; setBusy(false); }
  };

  return <Card className={styles.flowCard}>
    <Card.Header><div><h2 className={styles.flowTitle} ref={headingRef} tabIndex={-1}>{t("replacement.title")}</h2><Typography.Text tone="muted">{t("replacement.hint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header>
    <Card.Body className={styles.flowBody}>
      <ReplacementProgress current={stepIndex} />
      <dl className={styles.facts}>
        <div><dt>{t("replacement.currentAddress")}</dt><dd>{stage === "complete" ? targetAddress : originalAddress}</dd></div>
        <div><dt>{t("replacement.currentState")}</dt><dd>{t("states.VERIFIED")}</dd></div>
        <div><dt>{t("replacement.targetState")}</dt><dd>{stage === "complete" ? t("replacement.switched") : intent?.status === "CONFIRM_UNKNOWN" ? t("replacement.unknown") : targetAddress ? t("replacement.pendingTarget", { address: targetAddress }) : t("replacement.noChange")}</dd></div>
      </dl>
      {!intent && stage === "target" ? <form className={styles.form} onSubmit={prepareTarget}>
        <Alert status="warning">{t("replacement.mockBoundary")}</Alert>
        {error === "rejected" ? <Alert status="warning">{t("replacement.rejected")}</Alert> : null}
        <FormField id={targetId} label={t("replacement.newAddress")} hint={t("replacement.newAddressHint")}><Input autoComplete="email" id={targetId} onChange={(event) => { setTargetAddress(event.target.value); setError(null); }} required value={targetAddress} /></FormField>
        {error === "address" ? <Alert status="danger">{t("replacement.invalidAddress")}</Alert> : null}
        <Alert>{t("replacement.beforeCommit")}</Alert>
        <div className={styles.flowActions}><Button onClick={onClose} type="button" variant="ghost">{t("replacement.cancel")}</Button><Button disabled={!targetAddress.trim()} type="submit">{t("replacement.continue")}</Button></div>
      </form> : null}
      {!intent && stage === "proof" ? <form className={styles.form} onSubmit={(event) => void verifyIdentity(event)}>
        <Alert>{t("replacement.proofBoundary")}</Alert>
        <FormField id={passwordId} label={t("currentPassword")}><PasswordInput autoComplete="current-password" capsLockLabel={auth("capsLock")} hideLabel={auth("hidePassword")} id={passwordId} onChange={(event) => { setPassword(event.target.value); setError(null); }} showLabel={auth("showPassword")} value={password} /></FormField>
        <FormField id={totpId} label={t("replacement.totpLabel")} hint={t("replacement.totpHint")}><Input autoComplete="one-time-code" id={totpId} inputMode="numeric" maxLength={6} onChange={(event) => { setTotp(event.target.value.replace(/\D/g, "")); setError(null); }} pattern="[0-9]{6}" required value={totp} /></FormField>
        <Alert>{t("replacement.demoProof", { password: demonstrationPassword, code: demonstrationTotp })}</Alert>
        {error === "proof" ? <Alert status="danger">{t("replacement.invalidProof")}</Alert> : null}
        {error === "action" ? <Alert status="danger">{t("replacement.actionUnavailable")}</Alert> : null}
        <div className={styles.flowActions}><Button disabled={busy} onClick={() => { setError(null); setStage("target"); }} type="button" variant="ghost">{t("replacement.back")}</Button><Button disabled={busy || !password || totp.length !== 6} type="submit">{busy ? t("replacement.verifying") : t("replacement.verifyIdentity")}</Button></div>
      </form> : null}
      {intent?.status === "PENDING_VERIFICATION" ? <form className={styles.form} onSubmit={(event) => void verifyTarget(event)}>
        <Alert status="warning">{t("replacement.verifyBoundary", { address: targetAddress })}</Alert>
        <Alert>{t("demoCode", { code: demonstrationCode })}</Alert>
        <FormField id={mailCodeId} label={t("codeLabel")} hint={t("codeHint")}><Input autoComplete="one-time-code" id={mailCodeId} inputMode="numeric" maxLength={8} onChange={(event) => { setMailCode(event.target.value.replace(/\D/g, "")); setError(null); }} pattern="[0-9]{8}" required value={mailCode} /></FormField>
        {error === "code" ? <Alert status="danger">{t("invalidCode")}</Alert> : null}
        {error === "action" ? <Alert status="danger">{t("replacement.actionUnavailable")}</Alert> : null}
        <p className={styles.boundary}><Mail aria-hidden="true" />{t("replacement.confirmBoundary")}</p>
        <details className={styles.scenarioDetails}><summary>{t("replacement.previewScenarios")}</summary><FormField id={responseModeId} label={t("replacement.responseScenario")}><Select id={responseModeId} value={responseMode} onValueChange={(value) => setResponseMode(value as typeof responseMode)} options={(["success", "response-lost"] as const).map((value) => ({ value, label: t(`replacement.responseScenarios.${value}`) }))} /></FormField></details>
        <div className={styles.flowActions}><Button disabled={busy} onClick={onClose} type="button" variant="ghost">{t("replacement.closeForNow")}</Button><Button disabled={busy || mailCode.length !== 8} type="submit">{busy ? t("replacement.verifying") : t("replacement.verifyAddress")}</Button></div>
      </form> : null}
      {intent?.status === "CONFIRM_UNKNOWN" ? <div className={styles.form}>
        <Alert status="warning">{t("replacement.applyUnknown")}</Alert>
        <dl className={styles.facts}><div><dt>{t("replacement.mockVerification")}</dt><dd><code>{intent.mockVerificationId}</code></dd></div><div><dt>{t("replacement.previousAddress")}</dt><dd>{intent.previousAddress}</dd></div><div><dt>{t("replacement.verifiedTarget")}</dt><dd>{intent.targetAddress}</dd></div></dl>
        <details className={styles.scenarioDetails}><summary>{t("replacement.previewScenarios")}</summary><FormField id={inspectionModeId} label={t("replacement.inspectionScenario")}><Select id={inspectionModeId} value={inspectionMode} onValueChange={(value) => setInspectionMode(value as typeof inspectionMode)} options={(["found-applied", "found-rejected", "not-found", "unavailable"] as const).map((value) => ({ value, label: t(`replacement.inspectionScenarios.${value}`) }))} /></FormField></details>
        {error === "lookup" ? <Alert status="warning">{t("replacement.lookupPending")}</Alert> : null}
        <div className={styles.flowActions}><Button disabled={busy} onClick={onClose} variant="ghost">{t("replacement.closeForNow")}</Button><Button disabled={busy} onClick={() => void inspect()}>{busy ? t("replacement.inspecting") : t("replacement.inspect")}</Button></div>
      </div> : null}
      {stage === "complete" ? <div className={styles.form}>
        <Alert status="success">{t("replacement.success")}</Alert>
        <dl className={styles.facts}>
          <div><dt>{t("replacement.previousAddress")}</dt><dd>{originalAddress}</dd></div>
          <div><dt>{t("replacement.newTrustedAddress")}</dt><dd>{targetAddress}</dd></div>
          <div><dt>{t("replacement.notificationResult")}</dt><dd>{t("replacement.notificationResultValue")}</dd></div>
        </dl>
        <Alert>{t("replacement.localOnly")}</Alert>
        <div className={styles.flowActions}><Button onClick={onComplete}>{t("replacement.finish")}</Button></div>
      </div> : null}
    </Card.Body>
  </Card>;
}
