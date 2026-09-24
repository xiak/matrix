"use client";

import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { KeyRound, Mail, RefreshCcw, ShieldCheck, Smartphone } from "lucide-react";
import { Alert, Badge, Button, Card, FormField, Input, PasswordInput, Skeleton, Typography } from "@ui/xiak";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import { usePersonalSecurity, type PersonalSecurityClient } from "../application/PersonalSecurityProvider";
import type { AuthenticatorState, NotificationContact, NotificationContactVerification, TOTPEnrollmentStart } from "../domain/personalSecurity";
import { LiveRecoveryCodeRegeneration } from "./LiveRecoveryCodeRegeneration";
import styles from "./MfaPreviewExperience.module.css";

type LoadState = "loading" | "ready" | "error";
type FlowError = "load" | "contactStart" | "contactConfirm" | "enrollmentStart" | "enrollmentOutcomeUnknown"
  | "enrollmentInspect" | "enrollmentNotFound" | "enrollmentConfirm" | "cancel" | null;

function localTime(value: string, format: ReturnType<typeof useFormatter>) {
  return format.dateTime(new Date(value), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export function LivePersonalSecuritySettings() {
  const client = usePersonalSecurity();
  const scope = client ? `${client.accountId}:${client.userId}:${client.sessionId}:${client.sessionRevision}` : "unavailable";
  return <SessionPersonalSecuritySettings key={scope} client={client} />;
}

function SessionPersonalSecuritySettings({ client }: { client: PersonalSecurityClient | null }) {
  const t = useTranslations("PersonalSecurity");
  const auth = useTranslations("Auth");
  const format = useFormatter();
  const clientRef = useRef(client);
  const clientScope = client ? `${client.accountId}:${client.userId}:${client.sessionId}:${client.sessionRevision}` : null;
  const emailId = useId();
  const contactCodeId = useId();
  const passwordId = useId();
  const totpCodeId = useId();
  const requestRevision = useRef(0);
  const contactRequest = useRef(requestToken("ui-security-contact-"));
  const contactConfirmRequest = useRef(requestToken("ui-security-contact-confirm-"));
  const enrollmentRequest = useRef(requestToken("ui-totp-enroll-"));
  const enrollmentConfirmRequest = useRef(requestToken("ui-totp-confirm-"));
  const [loadState, setLoadState] = useState<LoadState>(client ? "loading" : "error");
  const [contact, setContact] = useState<NotificationContact | null>(null);
  const [verification, setVerification] = useState<NotificationContactVerification | null>(null);
  const [factor, setFactor] = useState<AuthenticatorState | null>(null);
  const [enrollment, setEnrollment] = useState<TOTPEnrollmentStart | null>(null);
  const [email, setEmail] = useState("");
  const [contactPassword, setContactPassword] = useState("");
  const [contactCode, setContactCode] = useState("");
  const [factorPassword, setFactorPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<FlowError>(null);

  useEffect(() => {
    clientRef.current = client;
  }, [client]);

  const load = useCallback(async () => {
    if (!clientScope) return;
    const activeClient = clientRef.current;
    if (!activeClient) return;
    const revision = ++requestRevision.current;
    try {
      const [nextContact, nextFactor] = await Promise.all([activeClient.notificationContact(), activeClient.authenticatorState()]);
      if (revision !== requestRevision.current) return;
      let nextVerification: NotificationContactVerification | null = null;
      if (nextContact.state === "NONE" && nextContact.pendingVerificationId) {
        nextVerification = await activeClient.notificationVerification(nextContact.pendingVerificationId);
        if (revision !== requestRevision.current) return;
      }
      setContact(nextContact);
      setVerification(nextVerification?.state === "PENDING" ? nextVerification : null);
      setFactor(nextFactor);
      setError(null);
      setLoadState("ready");
    } catch {
      if (revision === requestRevision.current) { setLoadState("error"); setError("load"); }
    }
  }, [clientScope]);

  useEffect(() => {
    const timer = window.setTimeout(() => { void load(); }, 0);
    return () => { window.clearTimeout(timer); requestRevision.current += 1; };
  }, [load]);

  async function startContact(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client) return;
    setBusy(true); setError(null);
    try {
      const next = await client.startNotificationVerification({ email, password: contactPassword, requestId: contactRequest.current });
      setVerification(next); setContactPassword(""); setContactCode("");
      contactConfirmRequest.current = requestToken("ui-security-contact-confirm-");
    } catch { setError("contactStart"); }
    finally { setBusy(false); }
  }

  async function confirmContact(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client || !verification) return;
    setBusy(true); setError(null);
    try {
      const next = await client.confirmNotificationVerification(verification.id, { code: contactCode, requestId: contactConfirmRequest.current });
      setVerification(next); setContactCode("");
      await load();
    } catch { setError("contactConfirm"); }
    finally { setBusy(false); }
  }

  async function startEnrollment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client || !factor) return;
    setBusy(true); setError(null);
    try {
      const next = await client.startTOTPEnrollment({ requestId: enrollmentRequest.current, password: factorPassword, expectedFactorRevision: factor.factorRevision });
      setEnrollment(next); setFactorPassword(""); setTotpCode("");
      enrollmentConfirmRequest.current = requestToken("ui-totp-confirm-");
    } catch (failure) {
      setError(failure instanceof HttpProblem && [400, 401, 403, 409, 413, 415, 422, 429].includes(failure.status)
        ? "enrollmentStart"
        : "enrollmentOutcomeUnknown");
    }
    finally { setBusy(false); }
  }

  async function inspectEnrollmentIntent() {
    if (!client?.totpEnrollmentIntent) return;
    setBusy(true); setError(null);
    try {
      const next = await client.totpEnrollmentByRequest(client.totpEnrollmentIntent.requestId);
      setEnrollment({ outcome: "EQUAL_REPLAY", enrollment: next });
    } catch (failure) {
      setError(failure instanceof HttpProblem && failure.status === 404 ? "enrollmentNotFound" : "enrollmentInspect");
    } finally { setBusy(false); }
  }

  async function cancelEnrollment() {
    if (!client || !enrollment) return;
    setBusy(true); setError(null);
    try {
      await client.cancelTOTPEnrollment(enrollment.enrollment.id);
      setEnrollment(null); setTotpCode(""); enrollmentRequest.current = requestToken("ui-totp-enroll-");
      await load();
    } catch { setError("cancel"); }
    finally { setBusy(false); }
  }

  function restartEnrollment() {
    if (client?.totpEnrollmentIntent) client.clearTOTPEnrollmentIntent(client.totpEnrollmentIntent.requestId);
    setEnrollment(null); setTotpCode(""); setError(null);
    enrollmentRequest.current = requestToken("ui-totp-enroll-");
    enrollmentConfirmRequest.current = requestToken("ui-totp-confirm-");
  }

  async function confirmEnrollment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client || !enrollment) return;
    setBusy(true); setError(null);
    try {
      await client.confirmTOTPEnrollment(enrollment.enrollment.id, { code: totpCode, requestId: enrollmentConfirmRequest.current });
    } catch { setError("enrollmentConfirm"); setBusy(false); }
  }

  const verified = contact?.state === "VERIFIED";
  const deliveryKey = verification ? `delivery.${verification.delivery.state}` as const : null;

  return <section aria-labelledby="live-personal-security" className={styles.securityRoot}>
    <div className={styles.sectionHeading}>
      <div><p>{t("eyebrow")}</p><h2 id="live-personal-security">{t("title")}</h2><span>{t("hint")}</span></div>
      <Badge status="success">LIVE</Badge>
    </div>
    <Alert status="info"><ShieldCheck aria-hidden="true" />{t("boundary")}</Alert>
    {error ? <Alert status="danger">{t(`errors.${error}`)} {error === "load" ? <Button onClick={() => { setLoadState("loading"); setError(null); void load(); }} size="small" variant="ghost"><RefreshCcw aria-hidden="true" />{t("retry")}</Button> : null}</Alert> : null}
    {!client ? <Alert status="warning">{t("unavailable")}</Alert> : null}
    <div className={styles.securityCards}>
      <Card>
        <Card.Header><div className={styles.cardTitle}><span><Mail aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("contact.title")}</Typography.Title><Typography.Text tone="muted">{t("contact.hint")}</Typography.Text></div></div>{loadState === "ready" ? <Badge status={verified ? "success" : verification ? "warning" : "neutral"}>{t(verified ? "contact.verified" : verification ? "contact.pending" : "contact.none")}</Badge> : null}</Card.Header>
        <Card.Body className={styles.cardBody}>
          {loadState === "loading" ? <><Skeleton /><Skeleton /></> : null}
          {loadState === "ready" && contact?.state === "VERIFIED" ? <dl className={styles.facts}><div><dt>{t("contact.address")}</dt><dd>{contact.email}</dd></div><div><dt>{t("contact.verifiedAt")}</dt><dd>{localTime(contact.verifiedAt, format)}</dd></div><div><dt>{t("revision")}</dt><dd>v{contact.resourceVersion}</dd></div></dl> : null}
          {loadState === "ready" && contact?.state === "NONE" && !verification ? <form className={styles.form} onSubmit={(event) => void startContact(event)}>
            <Alert>{t("contact.firstOnly")}</Alert>
            <FormField id={emailId} label={t("contact.address")}><Input autoComplete="email" id={emailId} inputMode="email" onChange={(event) => { setEmail(event.target.value); contactRequest.current = requestToken("ui-security-contact-"); }} required type="email" value={email} /></FormField>
            <FormField id={`${emailId}-password`} label={t("currentPassword")}><PasswordInput autoComplete="current-password" capsLockLabel={auth("capsLock")} hideLabel={auth("hidePassword")} id={`${emailId}-password`} onChange={(event) => { setContactPassword(event.target.value); contactRequest.current = requestToken("ui-security-contact-"); }} required showLabel={auth("showPassword")} value={contactPassword} /></FormField>
            <div className={styles.flowActions}><Button disabled={busy || !email || !contactPassword} type="submit">{busy ? t("saving") : t("contact.send")}</Button></div>
          </form> : null}
          {loadState === "ready" && verification ? <form className={styles.form} onSubmit={(event) => void confirmContact(event)}>
            <Alert status={verification.delivery.state === "FAILED" || verification.delivery.state === "EXPIRED" ? "warning" : "info"}>{t(deliveryKey!)} {t("contact.deliveryMeaning")}</Alert>
            <dl className={styles.facts}><div><dt>{t("contact.address")}</dt><dd>{verification.email}</dd></div><div><dt>{t("contact.expiresAt")}</dt><dd>{localTime(verification.expiresAt, format)}</dd></div><div><dt>{t("contact.attempts")}</dt><dd>{verification.delivery.attempts}</dd></div></dl>
            <FormField id={contactCodeId} label={t("contact.code")} hint={t("contact.codeHint")}><Input autoComplete="one-time-code" id={contactCodeId} inputMode="numeric" maxLength={8} onChange={(event) => setContactCode(event.target.value.replace(/\D/g, ""))} pattern="[0-9]{8}" required value={contactCode} /></FormField>
            <div className={styles.flowActions}><Button disabled={busy || contactCode.length !== 8} type="submit">{busy ? t("saving") : t("contact.confirm")}</Button></div>
          </form> : null}
        </Card.Body>
      </Card>
      <Card>
        <Card.Header><div className={styles.cardTitle}><span><Smartphone aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("factor.title")}</Typography.Title><Typography.Text tone="muted">{t("factor.hint")}</Typography.Text></div></div>{loadState === "ready" && factor ? <Badge status={factor.enrollmentState === "BOUND" ? "success" : factor.enrollmentState === "RECOVERY_REQUIRED" ? "warning" : "neutral"}>{t(`factor.${factor.enrollmentState}`)}</Badge> : null}</Card.Header>
        <Card.Body className={styles.cardBody}>
          {loadState === "loading" ? <><Skeleton /><Skeleton /></> : null}
          {loadState === "ready" && factor && client && !enrollment ? <>
            <dl className={styles.facts}><div><dt>{t("factor.method")}</dt><dd>TOTP · 6</dd></div><div><dt>{t("factor.state")}</dt><dd>{t(`factor.${factor.enrollmentState}`)}</dd></div><div><dt>{t("revision")}</dt><dd>v{factor.factorRevision}</dd></div>{factor.factorId ? <div><dt>{t("factor.id")}</dt><dd><code>{factor.factorId}</code></dd></div> : null}</dl>
            {factor.enrollmentState === "NEVER_BOUND" && !verified ? <Alert status="warning">{t("factor.verifyContactFirst")}</Alert> : null}
            {factor.enrollmentState === "NEVER_BOUND" && verified && client.totpEnrollmentIntent ? <div className={styles.form}>
              <Alert status="warning">{t("factor.pendingIntent")}</Alert>
              <dl className={styles.facts}><div><dt>{t("factor.requestId")}</dt><dd><code>{client.totpEnrollmentIntent.requestId}</code></dd></div><div><dt>{t("factor.intentState")}</dt><dd>{t(`factor.intent.${client.totpEnrollmentIntent.state}`)}</dd></div></dl>
              <p className={styles.boundary}>{t("factor.pendingIntentBoundary")}</p>
              <div className={styles.flowActions}><Button disabled={busy} onClick={() => void inspectEnrollmentIntent()} type="button" variant="secondary"><RefreshCcw aria-hidden="true" />{busy ? t("factor.inspecting") : t("factor.inspect")}</Button></div>
            </div> : null}
            {factor.enrollmentState === "NEVER_BOUND" && verified && !client.totpEnrollmentIntent ? <form className={styles.form} onSubmit={(event) => void startEnrollment(event)}><Alert>{t("factor.firstOnly")}</Alert><FormField id={passwordId} label={t("currentPassword")}><PasswordInput autoComplete="current-password" capsLockLabel={auth("capsLock")} hideLabel={auth("hidePassword")} id={passwordId} onChange={(event) => { setFactorPassword(event.target.value); enrollmentRequest.current = requestToken("ui-totp-enroll-"); }} required showLabel={auth("showPassword")} value={factorPassword} /></FormField><div className={styles.flowActions}><Button disabled={busy || !factorPassword} type="submit"><KeyRound aria-hidden="true" />{busy ? t("saving") : t("factor.start")}</Button></div></form> : null}
            {factor.enrollmentState === "BOUND" ? <LiveRecoveryCodeRegeneration key={`${client.sessionId}:${client.sessionRevision}`} factor={factor} /> : null}
            {factor.enrollmentState === "RECOVERY_REQUIRED" ? <Alert status="warning">{t("factor.recoveryUnavailable")}</Alert> : null}
          </> : null}
          {loadState === "ready" && enrollment ? <form className={styles.form} onSubmit={(event) => void confirmEnrollment(event)}>
            <Alert status="warning">{t(enrollment.outcome === "APPLIED" ? "factor.secretWarning" : "factor.replay")}</Alert>
            {enrollment.outcome === "APPLIED" ? <div className={styles.manualKey}><strong>{t("factor.manual")}</strong><code>{enrollment.provisioning.seed}</code><em>{t("factor.noExternalQr")}</em><details><summary>{t("factor.uri")}</summary><code>{enrollment.provisioning.uri}</code></details></div> : null}
            <dl className={styles.facts}><div><dt>{t("factor.enrollmentId")}</dt><dd><code>{enrollment.enrollment.id}</code></dd></div><div><dt>{t("contact.expiresAt")}</dt><dd>{localTime(enrollment.enrollment.expiresAt, format)}</dd></div></dl>
            {enrollment.outcome === "APPLIED" ? <FormField id={totpCodeId} label={t("factor.code")} hint={t("factor.codeHint")}><Input autoComplete="one-time-code" id={totpCodeId} inputMode="numeric" maxLength={6} onChange={(event) => setTotpCode(event.target.value.replace(/\D/g, ""))} pattern="[0-9]{6}" required value={totpCode} /></FormField> : null}
            {enrollment.enrollment.state === "CONFIRMED" ? <Alert status="warning">{t("factor.confirmedElsewhere")}</Alert> : null}
            <div className={styles.flowActions}>
              {enrollment.enrollment.state === "PENDING" ? <Button disabled={busy} onClick={() => void cancelEnrollment()} type="button" variant="ghost">{t("cancel")}</Button> : null}
              {enrollment.enrollment.state === "CANCELLED" || enrollment.enrollment.state === "EXPIRED" ? <Button disabled={busy} onClick={restartEnrollment} type="button" variant="ghost">{t("factor.restart")}</Button> : null}
              {enrollment.outcome === "APPLIED" ? <Button disabled={busy || totpCode.length !== 6} type="submit">{busy ? t("saving") : t("factor.confirm")}</Button> : null}
            </div>
          </form> : null}
        </Card.Body>
      </Card>
    </div>
  </section>;
}
