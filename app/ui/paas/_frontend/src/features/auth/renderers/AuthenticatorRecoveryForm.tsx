"use client";

import { useId, useState, type FormEvent } from "react";
import { useLocale, useTranslations } from "next-intl";
import { ArrowLeft, ArrowRight, Copy, KeyRound, LoaderCircle, ShieldAlert, Smartphone } from "lucide-react";
import { Alert, Button, FormField, Input } from "@ui/xiak";
import { uxPreviewEnabled } from "@/infrastructure/runtime/uxPreviewMode";
import { useSession } from "../application/SessionProvider";
import styles from "./LoginRenderer.module.css";

const recoveryPhases = new Set([
  "recovery-code-required",
  "starting-recovery",
  "recovery-enrollment-required",
  "confirming-recovery",
  "recovery-result-required",
  "inspecting-recovery",
  "recovery-start-unknown",
  "recovery-confirm-unknown"
]);

export function isAuthenticatorRecoveryPhase(phase: string): boolean {
  return recoveryPhases.has(phase);
}

export function AuthenticatorRecoveryForm() {
  const session = useSession();
  const t = useTranslations("Auth");
  const locale = useLocale();
  const inputId = useId();
  const [recoveryCode, setRecoveryCode] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [copied, setCopied] = useState(false);
  const challenge = session.challenge;
  const recovery = session.authenticatorRecovery;
  const phase = session.phase;
  const starting = phase === "starting-recovery";
  const confirming = phase === "confirming-recovery";
  const inspecting = phase === "inspecting-recovery";
  const loginName = challenge?.loginName ?? recovery?.loginName ?? "";

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (starting || !recoveryCode.trim()) return;
    if (await session.startAuthenticatorRecovery(recoveryCode.trim())) setRecoveryCode("");
  }

  async function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (confirming || verificationCode.length !== 6) return;
    if (await session.confirmAuthenticatorRecovery(verificationCode)) setVerificationCode("");
  }

  async function copySeed() {
    try {
      if (!navigator.clipboard || !recovery?.provisioning) return;
      await navigator.clipboard.writeText(recovery.provisioning.seed);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  const identity = loginName ? <div className={styles.challengeIdentity}>
    <span>{t("signingInAs")}</span><strong>{loginName}</strong>
  </div> : null;
  const error = session.error ? <Alert status="danger">{t(`errors.${session.error}`)}</Alert> : null;

  if (phase === "recovery-result-required" || inspecting) {
    return <>
      <div className={styles.cardHeading}>
        <span className={styles.challengeIcon}><ShieldAlert aria-hidden="true" /></span>
        <h1>{t("recoveryResultTitle")}</h1>
        <p>{t("recoveryResultHint")}</p>
      </div>
      {identity}
      <Alert status="warning">{t("recoveryResultBoundary")}</Alert>
      {error}
      <div className={styles.recoveryActions}>
        <Button block disabled={inspecting} onClick={() => void session.inspectAuthenticatorRecovery()} size="large">
          {inspecting ? <LoaderCircle aria-hidden="true" className={styles.spinner} /> : null}
          {t(inspecting ? "inspectingRecovery" : "inspectRecovery")}
        </Button>
        <Button block disabled={inspecting} onClick={session.leaveAuthenticatorRecovery} variant="ghost">
          <ArrowLeft aria-hidden="true" />{t("returnToSignIn")}
        </Button>
      </div>
    </>;
  }

  if (phase === "recovery-start-unknown") {
    const canRestart = challenge?.challenge.purpose === "LOGIN" &&
      (challenge.challenge.nextStep === "TOTP" || challenge.challenge.nextStep === "RECOVER");
    return <>
      <div className={styles.cardHeading}>
        <span className={styles.challengeIcon}><ShieldAlert aria-hidden="true" /></span>
        <h1>{t("recoveryUnknownTitle")}</h1>
        <p>{t(canRestart ? "recoveryMaterialLostHint" : "recoveryUnknownHint")}</p>
      </div>
      {identity}
      <Alert status="warning">{t(recovery?.state === "NOT_FOUND" ? "recoveryNotFoundBoundary" : "recoveryUnknownBoundary")}</Alert>
      {error}
      <div className={styles.recoveryActions}>
        {canRestart ? <Button block onClick={session.restartAuthenticatorRecovery} size="large">
          {t("restartRecovery")}<ArrowRight aria-hidden="true" />
        </Button> : null}
        <Button block onClick={session.leaveAuthenticatorRecovery} variant="ghost">
          <ArrowLeft aria-hidden="true" />{t("returnToSignIn")}
        </Button>
      </div>
    </>;
  }

  if (phase === "recovery-confirm-unknown") {
    return <>
      <div className={styles.cardHeading}>
        <span className={styles.challengeIcon}><ShieldAlert aria-hidden="true" /></span>
        <h1>{t("recoveryConfirmUnknownTitle")}</h1>
        <p>{t("recoveryConfirmUnknownHint")}</p>
      </div>
      {identity}
      <Alert status="warning">{t("recoveryConfirmUnknownBoundary")}</Alert>
      {error}
      <Button block onClick={session.leaveAuthenticatorRecovery} size="large">
        {t("signInWithNewAuthenticator")}<ArrowRight aria-hidden="true" />
      </Button>
    </>;
  }

  if (phase === "recovery-enrollment-required" || confirming) {
    if (!recovery?.provisioning || !challenge || challenge.challenge.purpose !== "RECOVERY") return null;
    const expiresAt = new Intl.DateTimeFormat(locale, { hour: "2-digit", minute: "2-digit" }).format(new Date(challenge.challenge.expiresAt));
    return <>
      <div className={styles.cardHeading}>
        <span className={styles.challengeIcon}><Smartphone aria-hidden="true" /></span>
        <h1>{t("recoveryEnrollmentTitle")}</h1>
        <p>{t("recoveryEnrollmentHint", { time: expiresAt })}</p>
      </div>
      {identity}
      <Alert status="warning">{t("recoveryIrreversibleBoundary")}</Alert>
      <div className={styles.recoverySecret}>
        <div><strong>{t("recoverySetupKey")}</strong><span>{t("recoverySetupKeyHint")}</span></div>
        <code>{recovery.provisioning.seed}</code>
        <Button disabled={confirming} onClick={() => void copySeed()} size="small" variant="secondary">
          <Copy aria-hidden="true" />{t(copied ? "recoverySetupKeyCopied" : "recoverySetupKeyCopy")}
        </Button>
      </div>
      <form aria-busy={confirming} className={styles.form} onSubmit={confirm}>
        <FormField id={inputId} label={t("recoveryNewVerificationCode")} hint={t("recoveryNewVerificationHint")}>
          <Input autoComplete="one-time-code" controlSize="large" disabled={confirming} id={inputId} inputMode="numeric"
            maxLength={6} onChange={(event) => { setVerificationCode(event.target.value.replace(/\D/g, "")); session.clearError(); }}
            pattern="[0-9]{6}" required value={verificationCode} />
        </FormField>
        {uxPreviewEnabled ? <p className={styles.previewChallengeHint}>{t("previewRecoveryOtpHint")}</p> : null}
        {error}
        <Button block disabled={confirming || verificationCode.length !== 6} size="large" type="submit">
          {confirming ? <LoaderCircle aria-hidden="true" className={styles.spinner} /> : null}
          {t(confirming ? "confirmingRecovery" : "confirmRecovery")}
        </Button>
      </form>
      <Button block disabled={confirming} onClick={session.leaveAuthenticatorRecovery} variant="ghost">
        <ArrowLeft aria-hidden="true" />{t("leaveRecovery")}
      </Button>
    </>;
  }

  return <>
    <div className={styles.cardHeading}>
      <span className={styles.challengeIcon}><KeyRound aria-hidden="true" /></span>
      <h1>{t("recoveryCodeTitle")}</h1>
      <p>{t("recoveryCodeHint")}</p>
    </div>
    {identity}
    <Alert status="warning">{t("recoveryStartBoundary")}</Alert>
    <form aria-busy={starting} className={styles.form} onSubmit={start}>
      <FormField id={inputId} label={t("recoveryCode")} hint={t("recoveryCodeHelp")}>
        <Input autoCapitalize="characters" autoComplete="off" controlSize="large" disabled={starting} id={inputId}
          maxLength={128} onChange={(event) => { setRecoveryCode(event.target.value); session.clearError(); }} required spellCheck={false} value={recoveryCode} />
      </FormField>
      {uxPreviewEnabled ? <p className={styles.previewChallengeHint}>{t("previewRecoveryCodeHint")}</p> : null}
      {error}
      <Button block disabled={starting || !recoveryCode.trim()} size="large" type="submit">
        {starting ? <LoaderCircle aria-hidden="true" className={styles.spinner} /> : null}
        {t(starting ? "startingRecovery" : "startRecovery")} {!starting ? <ArrowRight aria-hidden="true" /> : null}
      </Button>
    </form>
    <Button block disabled={starting} onClick={session.leaveAuthenticatorRecovery} variant="ghost">
      <ArrowLeft aria-hidden="true" />{t("returnToSignIn")}
    </Button>
  </>;
}
