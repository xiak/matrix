"use client";
import { useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { ApiError } from "@/api/client";
import { Button, Card, ContentPage, FormField, PasswordInput, useUnsavedChanges } from "@ui/xiak";
import { useApi, useSession } from "./SessionProvider";
import { RequestFeedback } from "../platform/RequestFeedback";
import styles from "../platform/Workspace.module.css";

export function AccountPage() {
  const t = useTranslations("Auth");
  const p = useTranslations("Platform");
  const d = useTranslations("Draft");
  const api = useApi();
  const session = useSession()!;
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const form = useRef<HTMLFormElement>(null);
  const copy = { title: d("title"), description: d("description"), stay: d("stay"), leave: d("leave"), close: d("close"), busyTitle: d("busyTitle"), busyDescription: d("busyDescription"), failure: d("failure"), retry: d("retry") };
  const leave = useUnsavedChanges({ dirty: Boolean(current || next || confirm), busy, focusRef: form, copy });
  const passwordLabels = { showLabel: t("showPassword"), hideLabel: t("hidePassword"), capsLockLabel: t("capsLock") };
  return <div className={styles.stack}><ContentPage.Heading title={p("account")} />
    <Card><Card.Body><dl className={styles.facts}>{[[t("loginName"), session.loginName], [t("accountId"), session.organizationId], [t("principalId"), session.principalId], [t("sessionId"), session.id], [t("expires"), session.expiresAt]].map(([label,value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl></Card.Body></Card>
    <Card><Card.Header><strong>{t("passwordChange")}</strong></Card.Header><Card.Body><form className={styles.form} ref={form} onSubmit={async event => { event.preventDefault(); if (busy) return; setError(undefined); if (next !== confirm) { setError(new ApiError("INPUT")); return; } setBusy(true); try { await api.changePassword(current, next); } catch (cause) { setError(cause); } finally { setBusy(false); setCurrent(""); setNext(""); setConfirm(""); } }}>
      <p className={styles.muted}>{t("passwordHint")}</p><fieldset disabled={busy} className={styles.fields}>
        <FormField label={t("currentPassword")}><PasswordInput required autoComplete="current-password" value={current} onChange={event => setCurrent(event.target.value)} {...passwordLabels} /></FormField>
        <FormField label={t("newPassword")}><PasswordInput required autoComplete="new-password" value={next} onChange={event => setNext(event.target.value)} {...passwordLabels} /></FormField>
        <FormField label={t("confirmPassword")} error={confirm && next !== confirm ? t("passwordMismatch") : undefined}><PasswordInput required autoComplete="new-password" value={confirm} onChange={event => setConfirm(event.target.value)} {...passwordLabels} /></FormField>
      </fieldset><RequestFeedback error={error} busy={busy} /><div><Button type="submit" disabled={busy}>{t("save")}</Button></div>
    </form></Card.Body></Card>
    <Card><Card.Body className={styles.stack}><strong>{p("switchAccount")}</strong><p className={styles.muted}>{p("switchHint")}</p><div><Button variant="secondary" onClick={() => leave(() => api.logout())}>{p("switchAccount")}</Button></div></Card.Body></Card>
  </div>;
}
