"use client";

import { useId, useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useLocale, useTranslations } from "next-intl";
import { ArrowLeft, ArrowRight, CheckCircle2, LoaderCircle, ShieldCheck } from "lucide-react";
import { Alert, Button, FormField, Input, PasswordInput } from "@ui/xiak";
import { uxPreviewEnabled } from "@/infrastructure/runtime/uxPreviewMode";
import { useSession } from "../application/SessionProvider";
import styles from "./LoginRenderer.module.css";

export function AuthenticationChallengeForm({ returnTo }: { returnTo: string }) {
  const router = useRouter();
  const session = useSession();
  const t = useTranslations("Auth");
  const locale = useLocale();
  const inputId = useId();
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmedPassword, setConfirmedPassword] = useState("");
  const [mismatch, setMismatch] = useState(false);
  const challenge = session.challenge;

  if (session.phase === "reauthentication-required") {
    return <div className={styles.challengeCompletion}>
      <CheckCircle2 aria-hidden="true" />
      <div className={styles.cardHeading}>
        <h1>{t("challengePasswordChanged")}</h1>
        <p>{t("challengeReauthenticateHint")}</p>
      </div>
      <Button block onClick={session.acknowledgeReauthentication} size="large">
        {t("returnToSignIn")}<ArrowRight aria-hidden="true" />
      </Button>
    </div>;
  }

  if (!challenge) return null;
  const changingPassword = session.phase === "challenge-password-required" || session.phase === "changing-challenge-password";
  const busy = session.phase === "verifying-challenge" || session.phase === "changing-challenge-password";
  const expiresAt = new Intl.DateTimeFormat(locale, { hour: "2-digit", minute: "2-digit" }).format(new Date(challenge.challenge.expiresAt));

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || code.length !== 6) return;
    const outcome = await session.verifyAuthenticationChallenge(code);
    setCode("");
    if (outcome === "authenticated") router.replace(returnTo, { scroll: false });
  }

  async function savePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    if (newPassword !== confirmedPassword) {
      setMismatch(true);
      return;
    }
    if (await session.changeChallengePassword(newPassword)) {
      setNewPassword("");
      setConfirmedPassword("");
    }
  }

  return <>
    <div className={styles.cardHeading}>
      <span className={styles.challengeIcon}><ShieldCheck aria-hidden="true" /></span>
      <h1>{t(changingPassword ? "challengePasswordTitle" : "challengeTitle")}</h1>
      <p>{t(changingPassword ? "challengePasswordHint" : "challengeHint", { time: expiresAt })}</p>
    </div>
    <div className={styles.challengeIdentity}>
      <span>{t("signingInAs")}</span>
      <strong>{challenge.loginName}</strong>
    </div>
    <Alert status="warning">{t(changingPassword ? "challengePasswordBoundary" : "challengeBoundary")}</Alert>
    {changingPassword ? <form aria-busy={busy} className={styles.form} onSubmit={savePassword}>
      <FormField id={`${inputId}-new`} label={t("newPassword")} hint={t("passwordPolicy")}>
        <PasswordInput autoComplete="new-password" capsLockLabel={t("capsLock")} disabled={busy} hideLabel={t("hidePassword")}
          id={`${inputId}-new`} maxLength={128} onChange={(event) => { setNewPassword(event.target.value); setMismatch(false); }}
          required showLabel={t("showPassword")} value={newPassword} />
      </FormField>
      <FormField id={`${inputId}-confirm`} label={t("confirmPassword")}>
        <PasswordInput autoComplete="new-password" capsLockLabel={t("capsLock")} disabled={busy} hideLabel={t("hidePassword")}
          id={`${inputId}-confirm`} maxLength={128} onChange={(event) => { setConfirmedPassword(event.target.value); setMismatch(false); }}
          required showLabel={t("showPassword")} value={confirmedPassword} />
      </FormField>
      {mismatch ? <Alert status="danger">{t("errors.passwordMismatch")}</Alert> : null}
      {session.error ? <Alert status="danger">{t(`errors.${session.error}`)}</Alert> : null}
      <Button block disabled={busy || !newPassword || !confirmedPassword} size="large" type="submit">
        {busy ? <LoaderCircle aria-hidden="true" className={styles.spinner} /> : null}
        {t(busy ? "changingChallengePassword" : "changeChallengePassword")}
      </Button>
    </form> : <form aria-busy={busy} className={styles.form} onSubmit={verify}>
      <FormField id={inputId} label={t("verificationCode")} hint={t("verificationHint")}>
        <Input autoComplete="one-time-code" controlSize="large" disabled={busy} id={inputId} inputMode="numeric" maxLength={6}
          onChange={(event) => { setCode(event.target.value.replace(/\D/g, "")); session.clearError(); }} pattern="[0-9]{6}" required value={code} />
      </FormField>
      {uxPreviewEnabled ? <p className={styles.previewChallengeHint}>{t("previewChallengeHint")}</p> : null}
      {session.error ? <Alert status="danger">{t(`errors.${session.error}`)}</Alert> : null}
      <Button block disabled={busy || code.length !== 6} size="large" type="submit">
        {busy ? <LoaderCircle aria-hidden="true" className={styles.spinner} /> : null}
        {t(busy ? "verifyingCode" : "verifyCode")}{!busy ? <ArrowRight aria-hidden="true" /> : null}
      </Button>
      <Button block disabled={busy} onClick={session.enterAuthenticatorRecovery} type="button" variant="secondary">
        {t("cannotUseAuthenticator")}
      </Button>
    </form>}
    <Button block disabled={busy} onClick={session.cancelAuthenticationChallenge} variant="ghost">
      <ArrowLeft aria-hidden="true" />{t("returnToSignIn")}
    </Button>
  </>;
}
