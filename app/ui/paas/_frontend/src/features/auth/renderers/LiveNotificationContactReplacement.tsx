"use client";

import { useId, useRef, useState, type FormEvent } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { RefreshCcw } from "lucide-react";
import { Alert, Button, FormField, Input, PasswordInput } from "@ui/xiak";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import {
  NotificationReplacementProofRejected,
  type PersonalSecurityClient
} from "../application/PersonalSecurityProvider";
import type { AuthenticatorState, NotificationContact } from "../domain/personalSecurity";
import styles from "./MfaPreviewExperience.module.css";

type ReplacementError = "start" | "startUnknown" | "inspect" | "proofRejected" | "proofUnknown"
  | "proofBusy" | "proofInvalid" | "verificationBusy" | "verificationUnknown"
  | "confirmRejected" | "confirmBusy" | "confirmUnknown" | null;

function localTime(value: string, format: ReturnType<typeof useFormatter>) {
  return format.dateTime(new Date(value), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export function LiveNotificationContactReplacement({ client, contact, factor, onCommitted }: {
  client: PersonalSecurityClient;
  contact: Extract<NotificationContact, { state: "VERIFIED" }>;
  factor: AuthenticatorState;
  onCommitted(): Promise<boolean>;
}) {
  const t = useTranslations("PersonalSecurity.contact.replacement");
  const auth = useTranslations("Auth");
  const format = useFormatter();
  const emailId = useId();
  const passwordId = useId();
  const totpId = useId();
  const codeId = useId();
  const passwordRef = useRef<HTMLInputElement>(null);
  const codeRef = useRef<HTMLInputElement>(null);
  const [drafting, setDrafting] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [emailCode, setEmailCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ReplacementError>(null);
  const progress = client.notificationReplacementProgress;
  const canStart = client.notificationReplacementAvailable && factor.enrollmentState === "BOUND" && !contact.pendingVerificationId;

  async function finish() {
    if (!await onCommitted()) return false;
    client.clearNotificationReplacementProgress();
    setDrafting(false);
    setEmail("");
    setEmailCode("");
    setError(null);
    return true;
  }

  async function refreshCommitted() {
    setBusy(true); setError(null);
    try {
      if (!await finish()) setError("inspect");
    } finally { setBusy(false); }
  }

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(null);
    try {
      await client.startNotificationReplacement({
        email,
        expectedResourceVersion: contact.resourceVersion,
        expectedFactorRevision: factor.factorRevision
      });
      setEmail("");
    } catch (failure) {
      setError(!(failure instanceof HttpProblem) || failure.status === 409 || failure.status === 429 || failure.status >= 500
        ? null : "start");
    } finally { setBusy(false); }
  }

  async function retryStepUp() {
    setBusy(true); setError(null);
    try { await client.retryNotificationReplacementStepUp(); }
    catch { setError("startUnknown"); }
    finally { setBusy(false); }
  }

  async function inspectStepUp() {
    setBusy(true); setError(null);
    try { await client.inspectNotificationReplacementStepUp(); }
    catch { setError("inspect"); }
    finally { setBusy(false); }
  }

  async function prove(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(null);
    try { await client.proveNotificationReplacement({ password, code: totpCode }); }
    catch (failure) {
      if (failure instanceof NotificationReplacementProofRejected) {
        setError("proofRejected");
        queueMicrotask(() => passwordRef.current?.focus());
      } else if (failure instanceof HttpProblem && failure.status === 429) {
        setError("proofBusy");
      } else if (failure instanceof HttpProblem && [400, 413, 415, 422].includes(failure.status)) {
        setError("proofInvalid");
      } else {
        setError(null);
      }
    } finally {
      setPassword(""); setTotpCode(""); setBusy(false);
    }
  }

  async function startVerification() {
    setBusy(true); setError(null);
    try { await client.startNotificationReplacementVerification(); }
    catch (failure) { setError(failure instanceof HttpProblem && failure.status === 429 ? "verificationBusy" : null); }
    finally { setBusy(false); }
  }

  async function inspectVerification() {
    setBusy(true); setError(null);
    try {
      const verification = await client.inspectNotificationReplacementVerification();
      if (verification.state === "VERIFIED" && !await finish()) setError("inspect");
    } catch { setError("inspect"); }
    finally { setBusy(false); }
  }

  async function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(null);
    try {
      await client.confirmNotificationReplacement(emailCode);
      setEmailCode("");
      await finish();
    } catch (failure) {
      if (failure instanceof HttpProblem && failure.status === 422 && failure.code === "iam.verification.rejected") {
        setError("confirmRejected");
        queueMicrotask(() => codeRef.current?.focus());
      } else if (failure instanceof HttpProblem && failure.status === 429) {
        setError("confirmBusy");
      } else setError(null);
    } finally { setEmailCode(""); setBusy(false); }
  }

  if (!progress && !drafting) return <div className={styles.stateGuide}>
    <div><h4>{t("title")}</h4><p>{t(contact.pendingVerificationId ? "pendingElsewhere" : canStart ? "ready" : client.notificationReplacementAvailable ? "factorRequired" : "unavailable")}</p></div>
    <div className={styles.flowActions}><Button disabled={!canStart} onClick={() => setDrafting(true)} variant="secondary">{t("start")}</Button></div>
  </div>;

  if (!progress) return <form className={styles.form} onSubmit={(event) => void start(event)}>
    <Alert>{t("targetBoundary")}</Alert>
    {error ? <Alert status="danger">{t(`errors.${error}`)}</Alert> : null}
    <dl className={styles.facts}><div><dt>{t("current")}</dt><dd>{contact.email}</dd></div></dl>
    <FormField id={emailId} label={t("target")} hint={t("targetHint")}><Input autoComplete="email" id={emailId} onChange={(event) => setEmail(event.target.value)} required type="email" value={email} /></FormField>
    <div className={styles.flowActions}><Button disabled={busy} onClick={() => { setDrafting(false); setEmail(""); setError(null); }} type="button" variant="ghost">{t("back")}</Button><Button disabled={busy || !email || email.toLowerCase() === contact.email.toLowerCase()} type="submit">{busy ? t("working") : t("continue")}</Button></div>
  </form>;

  const verification = progress.verification;
  return <div className={styles.form}>
    <div><h4 className={styles.flowTitle}>{t("title")}</h4><p className={styles.boundary}>{t("serverIntentBoundary")}</p></div>
    {error ? <Alert status="danger">{t(`errors.${error}`)}</Alert> : null}
    <dl className={styles.facts}>
      <div><dt>{t("current")}</dt><dd>{contact.email}</dd></div>
      <div><dt>{t("target")}</dt><dd>{progress.notificationContact.email}</dd></div>
      <div><dt>{t("stateLabel")}</dt><dd>{t(`states.${progress.state}`)}</dd></div>
    </dl>
    {progress.state === "STEP_UP_UNKNOWN" ? <>
      <Alert status="warning">{t("stepUpUnknown")}</Alert>
      <div className={styles.flowActions}><Button disabled={busy} onClick={() => void inspectStepUp()} variant="secondary"><RefreshCcw aria-hidden="true" />{t("inspectProof")}</Button><Button disabled={busy} onClick={() => void retryStepUp()}>{t("retryExact")}</Button></div>
    </> : null}
    {progress.state === "PENDING_PROOF" ? <form className={styles.form} onSubmit={(event) => void prove(event)}>
      <Alert>{t("proofBoundary")}</Alert>
      <FormField id={passwordId} label={t("password")}><PasswordInput autoComplete="current-password" capsLockLabel={auth("capsLock")} hideLabel={auth("hidePassword")} id={passwordId} onChange={(event) => setPassword(event.target.value)} ref={passwordRef} required showLabel={auth("showPassword")} value={password} /></FormField>
      <FormField id={totpId} label={t("totp")} hint={t("totpHint")}><Input autoComplete="one-time-code" id={totpId} inputMode="numeric" maxLength={6} onChange={(event) => setTotpCode(event.target.value.replace(/\D/g, ""))} pattern="[0-9]{6}" required value={totpCode} /></FormField>
      <div className={styles.flowActions}><Button disabled={busy || !password || totpCode.length !== 6} type="submit">{busy ? t("working") : t("prove")}</Button></div>
    </form> : null}
    {progress.state === "PROOF_UNKNOWN" ? <><Alert status="warning">{t("proofUnknown")}</Alert><div className={styles.flowActions}><Button disabled={busy} onClick={() => void inspectStepUp()} variant="secondary"><RefreshCcw aria-hidden="true" />{t("inspectProof")}</Button></div></> : null}
    {progress.state === "PROVED" || progress.state === "VERIFICATION_UNKNOWN" ? <>
      <Alert status={progress.state === "VERIFICATION_UNKNOWN" ? "warning" : "info"}>{t(progress.state === "VERIFICATION_UNKNOWN" ? "verificationUnknown" : "proofReady")}</Alert>
      <div className={styles.flowActions}><Button disabled={busy} onClick={() => void startVerification()}>{busy ? t("working") : t(progress.state === "VERIFICATION_UNKNOWN" ? "retryExact" : "send")}</Button></div>
    </> : null}
    {progress.state === "PENDING_CONFIRMATION" && verification ? <form className={styles.form} onSubmit={(event) => void confirm(event)}>
      <Alert status={verification.delivery.state === "FAILED" || verification.delivery.state === "EXPIRED" ? "warning" : "info"}>{t(`delivery.${verification.delivery.state}`)} {t("deliveryMeaning")}</Alert>
      <dl className={styles.facts}><div><dt>{t("expiresAt")}</dt><dd>{localTime(verification.expiresAt, format)}</dd></div><div><dt>{t("attempts")}</dt><dd>{verification.delivery.attempts}</dd></div></dl>
      <FormField id={codeId} label={t("emailCode")} hint={t("emailCodeHint")}><Input autoComplete="one-time-code" id={codeId} inputMode="numeric" maxLength={8} onChange={(event) => setEmailCode(event.target.value.replace(/\D/g, ""))} pattern="[0-9]{8}" ref={codeRef} required value={emailCode} /></FormField>
      <div className={styles.flowActions}><Button disabled={busy} onClick={() => void inspectVerification()} type="button" variant="secondary"><RefreshCcw aria-hidden="true" />{t("refresh")}</Button><Button disabled={busy || emailCode.length !== 8} type="submit">{busy ? t("working") : t("confirm")}</Button></div>
    </form> : null}
    {progress.state === "CONFIRM_UNKNOWN" ? <><Alert status="warning">{t("confirmUnknown")}</Alert><div className={styles.flowActions}><Button disabled={busy} onClick={() => void inspectVerification()} variant="secondary"><RefreshCcw aria-hidden="true" />{t("inspectConfirmation")}</Button></div></> : null}
    {progress.state === "COMPLETED" ? <><Alert status="success">{t("completed")}</Alert><div className={styles.flowActions}><Button disabled={busy} onClick={() => void refreshCommitted()} variant="secondary"><RefreshCcw aria-hidden="true" />{busy ? t("working") : t("reloadCurrent")}</Button></div></> : null}
    {progress.state === "EXPIRED" ? <><Alert status="warning">{t("expired")}</Alert><div className={styles.flowActions}><Button disabled={busy} onClick={() => client.clearNotificationReplacementProgress()} variant="secondary">{t("finish")}</Button></div></> : null}
  </div>;
}
