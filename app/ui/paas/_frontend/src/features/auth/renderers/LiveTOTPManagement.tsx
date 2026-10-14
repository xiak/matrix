"use client";

import { useEffect, useId, useLayoutEffect, useRef, useState, type FormEvent } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { Alert, Button, Card, FormField, Input, PasswordInput, Typography } from "@ui/xiak";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { usePersonalSecurity } from "../application/PersonalSecurityProvider";
import type { AuthenticatorState, TOTPChangeIntent, TOTPEnrollmentStart } from "../domain/personalSecurity";
import styles from "./MfaPreviewExperience.module.css";

/** Factor change owns its local secrets and forms; the Provider owns the frozen intent. */
export function LiveTOTPManagement({ factor, onCommitted }: { factor: AuthenticatorState; onCommitted(): Promise<boolean> }) {
  const client = usePersonalSecurity();
  const t = useTranslations("PersonalSecurity.factor.change");
  const auth = useTranslations("Auth");
  const format = useFormatter();
  const activeClient = useRef(client);
  const heading = useRef<HTMLSpanElement>(null);
  const replaceTrigger = useRef<HTMLButtonElement>(null);
  const removeTrigger = useRef<HTMLButtonElement>(null);
  const returnOperation = useRef<TOTPChangeIntent["operation"] | null>(null);
  const submitting = useRef(false);
  const inputId = useId();
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [provisioning, setProvisioning] = useState<Extract<TOTPEnrollmentStart, { outcome: "APPLIED" }> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<"rejected" | "unknown" | "notFound" | null>(null);
  const [expiredDeadline, setExpiredDeadline] = useState<string | null>(null);
  const intent = client?.totpChangeIntent;
  const state = intent?.state;
  const oldSession = Boolean(client?.totpChangePreviousSession);
  const deadline = intent?.enrollment?.expiresAt ?? intent?.stepUp?.expiresAt;
  const expired = Boolean(deadline && expiredDeadline === deadline);

  useEffect(() => {
    if (!deadline) return;
    const timer = window.setTimeout(() => {
      setExpiredDeadline(deadline); setProvisioning(null); setPassword(""); setCode("");
    }, Math.max(0, Date.parse(deadline) - Date.now()));
    return () => window.clearTimeout(timer);
  }, [deadline]);

  useLayoutEffect(() => {
    activeClient.current = client;
    return () => { activeClient.current = null; };
  }, [client]);
  useLayoutEffect(() => {
    if (state) heading.current?.focus({ preventScroll: true });
    else if (returnOperation.current) {
      const trigger = returnOperation.current === "TOTP_REPLACE" ? replaceTrigger.current : removeTrigger.current;
      if (trigger?.isConnected && !trigger.disabled) trigger.focus({ preventScroll: true });
      else heading.current?.focus({ preventScroll: true });
      returnOperation.current = null;
    }
  }, [state]);

  async function perform<T,>(request: () => Promise<T>, receive?: (value: T) => void) {
    if (!client || submitting.current) return;
    const originalRequest = intent?.requestId;
    const sameSession = () => activeClient.current?.accountId === client.accountId && activeClient.current.userId === client.userId &&
      activeClient.current.sessionId === client.sessionId && activeClient.current.sessionRevision === client.sessionRevision;
    const owned = () => sameSession() && (!originalRequest || activeClient.current?.totpChangeIntent?.requestId === originalRequest);
    submitting.current = true; setBusy(true); setError(null);
    try { const value = await request(); if (owned()) receive?.(value); }
    catch (failure) {
      if (failure instanceof Error && failure.message === "STALE_IAM_PHASE") return;
      if (owned()) setError(failure instanceof HttpProblem && failure.status === 404 ? "notFound"
        : failure instanceof HttpProblem && failure.status < 500 ? "rejected" : "unknown");
    } finally { submitting.current = false; if (sameSession()) { setBusy(false); setPassword(""); setCode(""); } }
  }

  function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (client) void perform(() => client.verifyTOTPChange({ password, code }));
  }
  function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client || !provisioning || provisioning.enrollment.id !== intent?.enrollment?.id) return;
    void perform(async () => {
      try { await client.confirmReplacementEnrollment(code); }
      catch (failure) {
        // A definite wrong-code rejection may be corrected using the still-local
        // provisioning. An uncertain outcome must immediately discard it.
        if (!(failure instanceof HttpProblem && failure.status === 422 && failure.code === "iam.verification.rejected")) setProvisioning(null);
        throw failure;
      }
    }, () => setProvisioning(null));
  }

  if (!client || !client.totpReplacementAvailable && !client.totpRemovalAvailable) return null;
  return <Card aria-busy={busy}>
    <Card.Header><Typography.Title as="h3" level={3}><span ref={heading} tabIndex={-1}>{t("title")}</span></Typography.Title></Card.Header>
    <Card.Body className={styles.form}>
      <Alert status="info">{t("boundary")}</Alert>
      {error ? <Alert status="danger">{t(`errors.${error}`)}</Alert> : null}
      {!intent ? <>
        <p>{t("ready")}</p>
        <div className={styles.flowActions}>
          {client.totpReplacementAvailable ? <Button ref={replaceTrigger} disabled={busy || factor.enrollmentState !== "BOUND" || Boolean(client.recoveryCodeRegenerationIntent || client.notificationReplacementProgress)}
            onClick={() => void perform(() => client.startTOTPChange("TOTP_REPLACE", factor))} variant="secondary">{t("replace")}</Button> : null}
          {client.totpRemovalAvailable ? <Button ref={removeTrigger} disabled={busy || factor.enrollmentState !== "BOUND" || Boolean(client.recoveryCodeRegenerationIntent || client.notificationReplacementProgress)}
            onClick={() => void perform(() => client.startTOTPChange("TOTP_REMOVE", factor))} variant="danger">{t("remove")}</Button> : null}
        </div>
      </> : <>
        <strong>{t(intent.operation === "TOTP_REPLACE" ? "replace" : "remove")}</strong>
        <dl className={styles.facts}>
          <div><dt>{t("request")}</dt><dd><code>{intent.requestId}</code></dd></div>
          <div><dt>{t("state")}</dt><dd>{t(`states.${intent.state}`)}</dd></div>
          <div><dt>{t("revision")}</dt><dd>{intent.expectedFactorRevision}</dd></div>
          {deadline ? <div><dt>{t("deadline")}</dt><dd>{format.dateTime(new Date(deadline), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" })}</dd></div> : null}
        </dl>
        {oldSession ? <Alert status="warning">{t("previousSession")}</Alert> : null}
        {expired && state !== "COMPLETED" && state !== "EXPIRED" && state !== "REJECTED" && state !== "CANCELLED" ? <Alert status="warning">{t("deadlineElapsed")}</Alert> : null}
        {state === "PENDING_PROOF" && !oldSession && !expired ? <form className={styles.form} onSubmit={verify}>
          <FormField id={`${inputId}-password`} label={t("password")}><PasswordInput autoComplete="current-password" capsLockLabel={auth("capsLock")} hideLabel={auth("hidePassword")} showLabel={auth("showPassword")} id={`${inputId}-password`} disabled={busy} required value={password} onChange={(event) => setPassword(event.target.value)} /></FormField>
          <FormField id={`${inputId}-code`} label={t("oldCode")}><Input id={`${inputId}-code`} disabled={busy} autoComplete="one-time-code" inputMode="numeric" maxLength={6} pattern="[0-9]{6}" required value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))} /></FormField>
          <Button disabled={busy || !password || code.length !== 6} type="submit">{t("prove")}</Button>
        </form> : null}
        {state === "PROVED" && !oldSession && !expired ? <>
          <Alert status="warning">{t(intent.operation === "TOTP_REPLACE" ? "replaceReview" : "removeReview")}</Alert>
          <Button disabled={busy} variant={intent.operation === "TOTP_REMOVE" ? "danger" : "primary"} onClick={() => {
            if (intent.operation === "TOTP_REMOVE") void perform(() => client.removeTOTP());
            else void perform(() => client.startReplacementEnrollment(), (value) => setProvisioning(value.outcome === "APPLIED" ? value : null));
          }}>{t(intent.operation === "TOTP_REPLACE" ? "startEnrollment" : "confirmRemove")}</Button>
        </> : null}
        {state === "ENROLLING" ? <>
          {provisioning && !oldSession && !expired && provisioning.enrollment.id === intent.enrollment?.id ? <form className={styles.form} onSubmit={confirm}>
            <Alert status="warning">{t("secretOnce")}</Alert>
            <div className={styles.manualKey}><strong>{t("seed")}</strong><code>{provisioning.provisioning.seed}</code><details><summary>{t("uri")}</summary><code>{provisioning.provisioning.uri}</code></details></div>
            <FormField id={`${inputId}-new-code`} label={t("newCode")}><Input disabled={busy} id={`${inputId}-new-code`} autoComplete="one-time-code" inputMode="numeric" maxLength={6} pattern="[0-9]{6}" required value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))} /></FormField>
            <Button disabled={busy || code.length !== 6} type="submit">{t("confirmReplacement")}</Button>
          </form> : <Alert status="warning">{t("materialLost")}</Alert>}
          <Button disabled={busy} variant="secondary" onClick={() => { setProvisioning(null); void perform(() => client.cancelReplacementEnrollment()); }}>{t("cancelPending")}</Button>
        </> : null}
        {state && ["STEP_UP_UNKNOWN", "PROOF_UNKNOWN", "ENROLLMENT_UNKNOWN", "CONFIRM_UNKNOWN", "CANCEL_UNKNOWN", "REMOVAL_UNKNOWN"].includes(state) ? <Alert status="warning">{t("unknownBoundary")}</Alert> : null}
        {state === "COMPLETED" ? <Alert status="success">{t("historyOnly")}</Alert> : null}
        {state === "REJECTED" ? <Alert status="warning">{t("rejected")}</Alert> : null}
        {state === "CANCELLED" ? <Alert status="info">{t("cancelled")}</Alert> : null}
        {state === "EXPIRED" ? <Alert status="warning">{t("ended")}</Alert> : null}
      </>}
    </Card.Body>
    {intent ? <Card.Footer>
      {!["REJECTED", "CANCELLED", "EXPIRED"].includes(intent.state) ? <Button disabled={busy} variant="secondary" onClick={() => void perform(() => client.inspectTOTPChange())}>{t("inspect")}</Button> : null}
      {["PENDING_PROOF", "PROVED", "COMPLETED", "REJECTED", "CANCELLED", "EXPIRED"].includes(intent.state) ? <Button disabled={busy} variant="ghost" onClick={() => void perform(async () => {
        if (!await onCommitted()) throw new Error("CURRENT_SECURITY_STATE_UNAVAILABLE");
        returnOperation.current = intent.operation;
        client.clearTOTPChange(); setProvisioning(null);
      })}>{t(intent.state === "COMPLETED" ? "closeCompleted" : "stop")}</Button> : null}
    </Card.Footer> : null}
  </Card>;
}
