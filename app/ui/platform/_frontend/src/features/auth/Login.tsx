"use client";
import { useState, useSyncExternalStore } from "react";
import { useTranslations } from "next-intl";
import { ShieldCheck } from "lucide-react";
import { Brand, Button, FormField, Input, PasswordInput } from "@ui/xiak";
import { AppearanceControls } from "@/preferences/AppearanceControls";
import { useApi } from "./SessionProvider";
import { RequestFeedback } from "../platform/RequestFeedback";
import styles from "./Login.module.css";

export function Login() {
  const t = useTranslations("Auth");
  const p = useTranslations("Platform");
  const api = useApi();
  const notice = useSyncExternalStore(api.subscribe, api.notice, () => null);
  const [loginName, setLoginName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  return <main className={styles.login}>
    <header className={styles.header}><Brand responsive /><AppearanceControls /></header>
    <div className={styles.body}>
      <section className={styles.identity}><Brand variant="signature" /><span className={styles.context}>{p("privateCloud")}</span><h1>{t("intro")}</h1><p>{t("description")}</p><div className={styles.assurance}><ShieldCheck aria-hidden="true" />{p("signedInventory")}</div></section>
      <section className={styles.panel} aria-label={t("title")}><h2>{t("title")}</h2>
        {notice ? <p role="status" className={styles.hint}>{t(notice)}</p> : null}
        <form onSubmit={async event => { event.preventDefault(); if (busy) return; setBusy(true); setError(undefined); try { await api.login(loginName.trim(), password); } catch (cause) { setError(cause); } finally { setPassword(""); setBusy(false); } }}>
          <fieldset disabled={busy}>
            <FormField label={t("loginName")}><Input autoComplete="username" required maxLength={128} value={loginName} onChange={event => setLoginName(event.target.value)} /></FormField>
            <FormField label={t("password")}><PasswordInput autoComplete="current-password" required value={password} onChange={event => setPassword(event.target.value)} showLabel={t("showPassword")} hideLabel={t("hidePassword")} capsLockLabel={t("capsLock")} /></FormField>
            <RequestFeedback error={error} />
            <Button type="submit" size="large">{busy ? t("signingIn") : t("signIn")}</Button>
          </fieldset>
        </form><p className={styles.hint}>{t("securityHint")}</p>
      </section>
    </div>
  </main>;
}
