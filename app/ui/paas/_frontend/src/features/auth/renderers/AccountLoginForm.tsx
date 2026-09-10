"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { ArrowRight, LoaderCircle } from "lucide-react";
import { Button, FormField, Alert, Input, PasswordInput, Tabs } from "@ui/xiak";
import { useSession } from "../application/SessionProvider";
import { uxPreviewEnabled } from "@/infrastructure/runtime/uxPreviewMode";
import styles from "./LoginRenderer.module.css";

export function AccountLoginForm({ returnTo }: { returnTo: string }) {
  const router = useRouter();
  const session = useSession();
  const t = useTranslations("Auth");
  const [mode, setMode] = useState<"primary" | "subaccount">("primary");
  const [loginName, setLoginName] = useState("admin");
  const [password, setPassword] = useState("");
  const [formError, setFormError] = useState<"primaryIdentifier" | "childIdentifier" | null>(null);
  const [submission, setSubmission] = useState<"login" | "preview" | null>(null);
  const busy = session.phase === "authenticating";
  const error = formError ?? session.error;

  function changeMode(next: string) {
    if ((next !== "primary" && next !== "subaccount") || busy) return;
    setMode(next);
    setLoginName("");
    setPassword("");
    setFormError(null);
    session.clearError();
  }

  async function submitLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setFormError(null);
    const identifier = loginName.trim();
    if ((mode === "subaccount") !== identifier.includes("@")) {
      setFormError(mode === "subaccount" ? "childIdentifier" : "primaryIdentifier");
      return;
    }
    setSubmission("login");
    const outcome = await session.login(identifier, password);
    setPassword("");
    setSubmission(null);
    if (outcome === "authenticated") router.replace(returnTo);
  }

  async function enterPreview() {
    if (busy) return;
    setFormError(null);
    setPassword("");
    setSubmission("preview");
    const outcome = await session.login("preview-admin", "experience-only");
    setSubmission(null);
    if (outcome === "authenticated") router.replace(returnTo);
  }

  return <>
    <div className={styles.cardHeading}>
      <h1>{t("welcome")}</h1><p>{t("welcomeHint")}</p>
    </div>
    <Tabs.Root value={mode} onValueChange={changeMode}>
      <Tabs.List aria-label={t("mode")}>
        <Tabs.Trigger disabled={busy} value="primary">{t("primary")}</Tabs.Trigger>
        <Tabs.Trigger disabled={busy} value="subaccount">{t("subaccount")}</Tabs.Trigger>
      </Tabs.List>
      <Tabs.Content value={mode}>
        <form aria-busy={busy} className={styles.form} id="login-form" onSubmit={submitLogin}>
          <FormField id="login-name" label={t(mode === "primary" ? "loginName" : "childLoginName")}
            hint={mode === "subaccount" ? t("childHelp") : undefined}>
            <Input controlSize="large" aria-describedby={mode === "subaccount" ? "login-name-hint" : undefined}
              autoCapitalize="none" autoComplete="username" disabled={busy} id="login-name"
              maxLength={mode === "primary" ? 64 : 193} name="loginName"
              onChange={(event) => { setLoginName(event.target.value); setFormError(null); }}
              placeholder={t(mode === "primary" ? "loginPlaceholder" : "childPlaceholder")}
              required spellCheck={false} type="text" value={loginName} />
          </FormField>
          <FormField id="login-password" label={t("password")}>
            <PasswordInput controlSize="large" autoComplete="current-password" capsLockLabel={t("capsLock")}
              disabled={busy} hideLabel={t("hidePassword")} id="login-password" key={mode}
              maxLength={128} name="password" onChange={(event) => setPassword(event.target.value)}
              placeholder={t("passwordPlaceholder")} required showLabel={t("showPassword")} value={password} />
          </FormField>
          {error ? <Alert status="danger">{t(`errors.${error}`)}</Alert> : null}
          <Button block disabled={busy || !loginName.trim() || !password} size="large" type="submit">
            {busy && submission === "login" ? <LoaderCircle aria-hidden="true" className={styles.spinner} /> : null}
            {t(busy && submission === "login" ? "signingIn" : "signIn")}{!busy ? <ArrowRight aria-hidden="true" /> : null}
          </Button>
        </form>
      </Tabs.Content>
    </Tabs.Root>
    {uxPreviewEnabled ? <div className={styles.previewEntry}>
      <div className={styles.previewHeading}><strong>{t("previewTitle")}</strong><span>MOCK</span></div>
      <p>{t("previewDescription")}</p>
      <Button block disabled={busy} onClick={() => void enterPreview()} variant="secondary">
        {busy && submission === "preview" ? <LoaderCircle aria-hidden="true" className={styles.spinner} /> : null}
        {t(busy && submission === "preview" ? "previewPending" : "previewAction")}<ArrowRight aria-hidden="true" />
      </Button>
    </div> : null}
  </>;
}
