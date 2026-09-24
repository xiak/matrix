"use client";

import { useId, useRef, useState, type FormEvent } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { Copy, KeyRound, RefreshCcw, ShieldCheck } from "lucide-react";
import { Alert, Button, Checkbox, FormField, Input, PasswordInput } from "@ui/xiak";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import { usePersonalSecurity } from "../application/PersonalSecurityProvider";
import type { AuthenticatorState } from "../domain/personalSecurity";
import styles from "./MfaPreviewExperience.module.css";

type BoundFactor = Extract<AuthenticatorState, { enrollmentState: "BOUND" }>;
type FlowError = "startRejected" | "startUnknown" | "inspect" | "notFound" | "verifyRejected" | "verifyUnknown" | "regenerateUnknown" | null;

function knownRejection(value: unknown): value is HttpProblem {
  return value instanceof HttpProblem && [400, 401, 403, 409, 413, 415, 422, 429].includes(value.status);
}

export function LiveRecoveryCodeRegeneration({ factor }: { factor: BoundFactor }) {
  const t = useTranslations("PersonalSecurity.factor.recoveryCodes");
  const auth = useTranslations("Auth");
  const format = useFormatter();
  const client = usePersonalSecurity();
  const passwordId = useId();
  const codeId = useId();
  const verifyRequest = useRef(requestToken("ui-recovery-codes-verify-"));
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<FlowError>(null);
  const intent = client?.recoveryCodeRegenerationIntent ?? null;

  async function start() {
    if (!client) return;
    setBusy(true); setError(null); setCodes(null); setAcknowledged(false);
    try {
      await client.startRecoveryCodeRegeneration({
        requestId: requestToken("ui-recovery-codes-regenerate-"),
        factorId: factor.factorId,
        expectedFactorRevision: factor.factorRevision
      });
    } catch (failure) {
      setError(knownRejection(failure) ? "startRejected" : "startUnknown");
    } finally { setBusy(false); }
  }

  async function retryStart() {
    if (!client) return;
    setBusy(true); setError(null);
    try { await client.retryRecoveryCodeStepUp(); }
    catch (failure) { setError(knownRejection(failure) ? "startRejected" : "startUnknown"); }
    finally { setBusy(false); }
  }

  async function inspectStepUp() {
    if (!client) return;
    setBusy(true); setError(null);
    try { await client.inspectRecoveryCodeStepUp(); }
    catch (failure) { setError(failure instanceof HttpProblem && failure.status === 404 ? "notFound" : "inspect"); }
    finally { setBusy(false); }
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client) return;
    setBusy(true); setError(null);
    const requestId = verifyRequest.current;
    try {
      await client.verifyRecoveryCodeStepUp({ requestId, password, code });
      setPassword(""); setCode("");
    } catch (failure) {
      setPassword(""); setCode(""); verifyRequest.current = requestToken("ui-recovery-codes-verify-");
      setError(failure instanceof HttpProblem && [400, 401, 413, 415, 422, 429].includes(failure.status) ? "verifyRejected" : "verifyUnknown");
    } finally { setBusy(false); }
  }

  async function regenerate() {
    if (!client) return;
    setBusy(true); setError(null);
    try {
      const result = await client.regenerateRecoveryCodes();
      setCodes(result.outcome === "APPLIED" ? [...result.recoveryCodes] : null);
    } catch {
      setCodes(null); setError("regenerateUnknown");
    } finally { setBusy(false); }
  }

  async function inspectRegeneration() {
    if (!client) return;
    setBusy(true); setError(null);
    try { await client.inspectRecoveryCodeRegeneration(); }
    catch (failure) { setError(failure instanceof HttpProblem && failure.status === 404 ? "notFound" : "inspect"); }
    finally { setBusy(false); }
  }

  async function copy() {
    try {
      if (!codes || !navigator.clipboard) return;
      await navigator.clipboard.writeText(codes.join("\n"));
      setCopied(true);
    } catch { setCopied(false); }
  }

  function finish() {
    if (!client || !intent) return;
    setCodes(null); setPassword(""); setCode(""); setAcknowledged(false); setCopied(false); setError(null);
    client.clearRecoveryCodeRegenerationIntent(intent.requestId);
  }

  if (!client?.recoveryCodeRegenerationAvailable) return <Alert status="success">{t("unavailable")}</Alert>;

  if (!intent) return <div className={styles.form}>
    {error ? <Alert status="danger">{t(`errors.${error}`)}</Alert> : null}
    <Alert status="success">{t("ready")}</Alert>
    <p className={styles.boundary}><ShieldCheck aria-hidden="true" />{t("boundary")}</p>
    <div className={styles.flowActions}><Button disabled={busy} onClick={() => void start()} type="button" variant="secondary"><RefreshCcw aria-hidden="true" />{busy ? t("starting") : t("start")}</Button></div>
  </div>;

  const expiresAt = intent.stepUp?.expiresAt;
  return <div aria-live="polite" className={styles.form}>
    {error ? <Alert status="danger">{t(`errors.${error}`)}</Alert> : null}
    <dl className={styles.facts}>
      <div><dt>{t("requestId")}</dt><dd><code>{intent.requestId}</code></dd></div>
      <div><dt>{t("stateLabel")}</dt><dd>{t(`states.${intent.state}`)}</dd></div>
      {expiresAt ? <div><dt>{t("expiresAt")}</dt><dd>{format.dateTime(new Date(expiresAt), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" })}</dd></div> : null}
    </dl>

    {intent.state === "STEP_UP_UNKNOWN" ? <>
      <Alert status="warning">{t("stepUpUnknown")}</Alert>
      <div className={styles.flowActions}><Button disabled={busy} onClick={() => void retryStart()} type="button" variant="ghost">{t("retryExact")}</Button><Button disabled={busy} onClick={() => void inspectStepUp()} type="button" variant="secondary"><RefreshCcw aria-hidden="true" />{t("inspectStepUp")}</Button></div>
    </> : null}

    {intent.state === "PENDING" ? <form className={styles.form} onSubmit={(event) => void verify(event)}>
      <Alert>{t("verifyBoundary")}</Alert>
      <FormField id={passwordId} label={t("password")}><PasswordInput autoComplete="current-password" capsLockLabel={auth("capsLock")} hideLabel={auth("hidePassword")} id={passwordId} onChange={(event) => setPassword(event.target.value)} required showLabel={auth("showPassword")} value={password} /></FormField>
      <FormField id={codeId} label={t("code")} hint={t("codeHint")}><Input autoComplete="one-time-code" id={codeId} inputMode="numeric" maxLength={6} onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))} pattern="[0-9]{6}" required value={code} /></FormField>
      <div className={styles.flowActions}><Button disabled={busy || !password || code.length !== 6} type="submit"><KeyRound aria-hidden="true" />{busy ? t("verifying") : t("verify")}</Button></div>
    </form> : null}

    {intent.state === "VERIFICATION_UNKNOWN" ? <>
      <Alert status="warning">{t("verificationUnknown")}</Alert>
      <div className={styles.flowActions}><Button disabled={busy} onClick={() => void inspectStepUp()} type="button" variant="secondary"><RefreshCcw aria-hidden="true" />{t("inspectStepUp")}</Button></div>
    </> : null}

    {intent.state === "PROVED" ? <>
      <Alert status="warning">{t("proved")}</Alert>
      <div className={styles.flowActions}><Button disabled={busy} onClick={() => void regenerate()} type="button">{busy ? t("regenerating") : t("regenerate")}</Button></div>
    </> : null}

    {intent.state === "REGENERATION_UNKNOWN" ? <>
      <Alert status="warning">{t("regenerationUnknown")}</Alert>
      <div className={styles.flowActions}><Button disabled={busy} onClick={() => void inspectRegeneration()} type="button" variant="secondary"><RefreshCcw aria-hidden="true" />{t("inspectRegeneration")}</Button></div>
    </> : null}

    {intent.state === "COMPLETED" && codes ? <>
      <Alert status="warning"><ShieldCheck aria-hidden="true" />{t("oneTime")}</Alert>
      <div className={styles.secretHeader}><div><strong>{t("codes")}</strong><p>{t("offline")}</p></div><Button onClick={() => void copy()} size="small" variant="secondary"><Copy aria-hidden="true" />{t(copied ? "copied" : "copy")}</Button></div>
      <ul aria-label={t("codes")} className={styles.codes}>{codes.map((value) => <li key={value}>{value}</li>)}</ul>
      <Checkbox checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)}>{t("saved")}</Checkbox>
      <div className={styles.flowActions}><Button disabled={!acknowledged} onClick={finish} type="button">{t("finish")}</Button></div>
    </> : null}

    {intent.state === "COMPLETED" && !codes ? <>
      <Alert status="warning">{t("completedWithoutCodes")}</Alert>
      {intent.regeneration ? <dl className={styles.facts}><div><dt>{t("completedAt")}</dt><dd>{format.dateTime(new Date(intent.regeneration.createdAt), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}</dd></div><div><dt>{t("regenerationId")}</dt><dd><code>{intent.regeneration.id}</code></dd></div></dl> : null}
      <div className={styles.flowActions}><Button onClick={finish} type="button" variant="secondary">{t("newIntent")}</Button></div>
    </> : null}

    {intent.state === "EXPIRED" ? <>
      <Alert status="warning">{t("expired")}</Alert>
      <div className={styles.flowActions}><Button onClick={finish} type="button" variant="secondary">{t("newIntent")}</Button></div>
    </> : null}
  </div>;
}
