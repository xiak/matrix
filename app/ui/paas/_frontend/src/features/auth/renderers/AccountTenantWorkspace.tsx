"use client";

import { type FormEvent, useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, FormField, PasswordInput } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { CapabilityRestriction } from "../domain/accounts";
import type { AccountTenantScene } from "../scenes/accountAccessScene";
import { WorkspaceDetail } from "./AccessWorkspaceUi";
import { AccountIdentifier } from "./AccountOverview";
import styles from "./AccountAccessRenderer.module.css";

export function AccountTenantWorkspace({ account, onBack }: { account: AccountTenantScene; onBack(): void }) {
  const t = useTranslations("AccountAccess");
  const auth = useTranslations("Auth");
  const access = useAccountAccess();
  const passwordId = useId();
  const [confirmation, setConfirmation] = useState<"status" | "recovery" | null>(null);
  const [password, setPassword] = useState("");
  const disabled = access.busy || access.loading;
  const restriction = (reason: CapabilityRestriction | null) => t(`restrictions.${reason ?? "AUTHORITY_REQUIRED"}`);

  function cancel() {
    setConfirmation(null);
    setPassword("");
  }

  async function recover(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const initialPassword = password;
    setPassword("");
    if (await access.execute({
      kind: "recover-root-credentials",
      accountId: account.id,
      initialPassword,
      resourceVersion: account.resourceVersion
    })) cancel();
  }

  return <WorkspaceDetail title={account.name} onBack={onBack}>
    <div className={styles.userSummary}>
      <div><strong>{account.name}</strong><span className={styles.note}>{account.id}</span></div>
      <Badge status={account.enabled ? "success" : "neutral"}>{t(account.enabled ? "tenantActive" : "tenantDisabled")}</Badge>
    </div>

    <section className={styles.identitySection}>
      <h3>{t("tenantIdentity")}</h3>
      <dl className={styles.facts}>
        <div><dt>{t("tenantId")}</dt><dd><AccountIdentifier label={t("tenantId")} value={account.id} /></dd></div>
        <div><dt>{t("primaryLogin")}</dt><dd>{account.rootLoginName}</dd></div>
        <div><dt>{t("rootIdentityId")}</dt><dd><AccountIdentifier label={t("rootIdentityId")} value={account.rootPrincipalId} /></dd></div>
        <div><dt>{t("alias")}</dt><dd>{account.loginAlias ?? t("aliasUnset")}</dd></div>
        <div><dt>{t("status")}</dt><dd>{t(account.enabled ? "tenantActive" : "tenantDisabled")}</dd></div>
      </dl>
      <p className={styles.note}>{t("tenantLifecycleHint")}</p>
    </section>

    <section className={styles.identitySection}>
      <h3>{t("tenantLifecycle")}</h3>
      <div className={styles.actions}>
        <Button disabled={disabled || !account.canSetStatus} title={!account.canSetStatus ? restriction(account.statusRestrictionReason) : undefined}
          onClick={() => { setConfirmation("status"); setPassword(""); }} variant="secondary">
          {t(account.enabled ? "disableTenant" : "enableTenant")}
        </Button>
        <Button disabled={disabled || !account.canRecoverRoot} title={!account.canRecoverRoot ? restriction(account.recoveryRestrictionReason) : undefined}
          onClick={() => { setConfirmation("recovery"); setPassword(""); }} variant="secondary">
          {t("recoverRoot")}
        </Button>
      </div>
      {!account.canSetStatus ? <p className={styles.note}>{t("tenantStatusRestriction")}: {restriction(account.statusRestrictionReason)}</p> : null}
      {!account.canRecoverRoot ? <p className={styles.note}>{t("tenantRecoveryRestriction")}: {restriction(account.recoveryRestrictionReason)}</p> : null}
    </section>

    {confirmation === "status" ? <Alert status={account.enabled ? "warning" : "info"}>
      <div className={styles.confirmation}>
        <p>{t(account.enabled ? "disableTenantHint" : "enableTenantHint")}</p>
        <div className={styles.actions}>
          <Button disabled={disabled || !account.canSetStatus} onClick={async () => {
            if (await access.execute({ kind: "set-account-status", accountId: account.id, status: account.enabled ? "DISABLED" : "ACTIVE", resourceVersion: account.resourceVersion })) cancel();
          }} variant={account.enabled ? "danger" : "primary"}>{t(account.enabled ? "confirmDisableTenant" : "confirmEnableTenant")}</Button>
          <Button disabled={disabled} onClick={cancel} variant="ghost">{t("cancel")}</Button>
        </div>
      </div>
    </Alert> : null}

    {confirmation === "recovery" ? <form aria-label={t("recoverRoot")} className={styles.form} onSubmit={recover}>
      <p className={styles.note}>{t("recoverRootHint")}</p>
      <FormField id={passwordId} label={t("initialPassword")} hint={t("passwordHint")}>
        <PasswordInput id={passwordId} autoComplete="new-password" minLength={14} maxLength={128} required value={password} onChange={(event) => setPassword(event.target.value)} showLabel={auth("showPassword")} hideLabel={auth("hidePassword")} capsLockLabel={auth("capsLock")} />
      </FormField>
      <div className={styles.actions}>
        <Button disabled={disabled || password.length < 14} type="submit" variant="danger">{t("confirmRecoverRoot")}</Button>
        <Button disabled={disabled} onClick={cancel} variant="ghost">{t("cancel")}</Button>
      </div>
    </form> : null}
  </WorkspaceDetail>;
}
