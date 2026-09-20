"use client";

import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { LockKeyhole } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, FormField, Input, PasswordInput, Typography } from "@ui/xiak";
import styles from "./MfaPreviewExperience.module.css";

const demonstrationCode = "624810";
const demonstrationPassword = "demo-password";

export type SecurityStepUpAction = "bind" | "replace" | "remove" | "regenerate" | "securitySettings";

export function SecurityStepUpPreview({ action, onCancel, onVerified }: {
  action: SecurityStepUpAction;
  onCancel(): void;
  onVerified(): boolean | void | Promise<boolean | void>;
}) {
  const t = useTranslations("MfaPreview");
  const auth = useTranslations("Auth");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState(false);
  const [busy, setBusy] = useState(false);
  const id = useId();
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => { heading.current?.focus(); }, []);

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    if (password !== demonstrationPassword || code !== demonstrationCode) {
      setError(true);
      return;
    }
    setBusy(true);
    try {
      const completed = await onVerified();
      if (completed === false) setBusy(false);
    } catch (failure) {
      setBusy(false);
      throw failure;
    }
  }

  return <Card className={styles.flowCard}>
    <Card.Header><div><h2 className={styles.flowTitle} ref={heading} tabIndex={-1}>{t(`stepUp.${action}.title`)}</h2><Typography.Text tone="muted">{t("stepUp.hint")}</Typography.Text></div><Badge status="warning">{t("stepUp.once")}</Badge></Card.Header>
    <Card.Body><form className={styles.form} onSubmit={(event) => void verify(event)}>
      <Alert>{t("demoStepUp", { password: demonstrationPassword, code: demonstrationCode })}</Alert>
      <FormField id={`${id}-password`} label={t("currentPassword")}><PasswordInput autoComplete="current-password" capsLockLabel={auth("capsLock")} disabled={busy} hideLabel={auth("hidePassword")} id={`${id}-password`} onChange={(event) => { setPassword(event.target.value); setError(false); }} showLabel={auth("showPassword")} value={password} /></FormField>
      <FormField id={`${id}-code`} label={t("verificationCode")}><Input autoComplete="one-time-code" disabled={busy} id={`${id}-code`} inputMode="numeric" maxLength={6} onChange={(event) => { setCode(event.target.value.replace(/\D/g, "")); setError(false); }} value={code} /></FormField>
      {error ? <Alert status="danger">{t("stepUp.invalid")}</Alert> : null}
      <p className={styles.boundary}><LockKeyhole aria-hidden="true" />{t("stepUp.boundary")}</p>
      <div className={styles.flowActions}><Button disabled={busy} onClick={onCancel} type="button" variant="ghost">{t("cancel")}</Button><Button disabled={busy || !password || code.length !== 6} type="submit">{t(busy ? "stepUp.verifying" : "stepUp.verify")}</Button></div>
    </form></Card.Body>
  </Card>;
}
