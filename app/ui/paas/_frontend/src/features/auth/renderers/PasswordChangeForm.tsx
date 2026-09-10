"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { ArrowRight, LoaderCircle } from "lucide-react";
import { Button, FormField, Alert, PasswordInput } from "@ui/xiak";
import { useSession } from "../application/SessionProvider";
import styles from "./LoginRenderer.module.css";

export function PasswordChangeForm({ returnTo }: { returnTo: string }) {
  const router = useRouter();
  const session = useSession();
  const t = useTranslations("Auth");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmedPassword, setConfirmedPassword] = useState("");
  const [mismatch, setMismatch] = useState(false);
  const busy = session.phase === "changing-password" || session.phase === "revoking";
  const error = mismatch ? "passwordMismatch" : session.error;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setMismatch(false);
    if (newPassword !== confirmedPassword) { setMismatch(true); return; }
    const accepted = await session.changePassword(currentPassword, newPassword);
    setCurrentPassword("");
    if (accepted) {
      setNewPassword("");
      setConfirmedPassword("");
      router.replace(returnTo);
    }
  }

  return <>
    <div className={styles.cardHeading}>
      <p className={styles.eyebrow}>{t("firstLogin", { name: session.current?.loginName ?? "" })}</p>
      <h1>{t("changeTitle")}</h1><p>{t("changeHint")}</p>
    </div>
    <form aria-busy={busy} className={styles.form} id="password-change-form" onSubmit={submit}>
      <FormField id="current-password" label={t("currentPassword")}>
        <PasswordInput controlSize="large" autoComplete="current-password" capsLockLabel={t("capsLock")} disabled={busy}
          hideLabel={t("hidePassword")} id="current-password" maxLength={128} name="currentPassword"
          onChange={(event) => setCurrentPassword(event.target.value)} required showLabel={t("showPassword")} value={currentPassword} />
      </FormField>
      <FormField id="new-password" label={t("newPassword")} hint={t("passwordPolicy")}>
        <PasswordInput controlSize="large" aria-describedby="new-password-hint" autoComplete="new-password" capsLockLabel={t("capsLock")}
          disabled={busy} hideLabel={t("hidePassword")} id="new-password" maxLength={128} minLength={14}
          name="newPassword" onChange={(event) => { setNewPassword(event.target.value); setMismatch(false); }}
          required showLabel={t("showPassword")} value={newPassword} />
      </FormField>
      <FormField id="confirm-password" label={t("confirmPassword")}>
        <PasswordInput controlSize="large" autoComplete="new-password" capsLockLabel={t("capsLock")} disabled={busy}
          hideLabel={t("hidePassword")} id="confirm-password" invalid={mismatch} maxLength={128} minLength={14}
          name="confirmedPassword" onChange={(event) => { setConfirmedPassword(event.target.value); setMismatch(false); }}
          required showLabel={t("showPassword")} value={confirmedPassword} />
      </FormField>
      {error ? <Alert status="danger">{t(`errors.${error}`)}</Alert> : null}
      <Button block disabled={busy || !currentPassword || !newPassword || !confirmedPassword} size="large" type="submit">
        {session.phase === "changing-password" ? <LoaderCircle aria-hidden="true" className={styles.spinner} /> : <ArrowRight aria-hidden="true" />}
        {t(session.phase === "changing-password" ? "savingPassword" : "savePassword")}
      </Button>
      <Button block disabled={busy} onClick={() => void session.logout()} variant="ghost">
        {t(session.phase === "revoking" ? "exitingSession" : "exitSession")}
      </Button>
    </form>
  </>;
}
