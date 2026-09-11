"use client";

import { useId, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import { KeyRound, ShieldCheck } from "lucide-react";
import { Alert, Dialog, FormField, Badge, Button, Input, PasswordInput, Select, Typography } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccountUserScene } from "../scenes/accountAccessScene";
import styles from "./AccountAccessRenderer.module.css";

const loginPattern = "[a-z][a-z0-9._\\-]{2,63}";

function PasswordField({ value, onChange, autoFocus = false }: { value: string; onChange(value: string): void; autoFocus?: boolean }) {
  const t = useTranslations("AccountAccess");
  const auth = useTranslations("Auth");
  const id = useId();
  return <FormField id={id} label={t("initialPassword")} hint={t("passwordHint")}>
    <PasswordInput autoFocus={autoFocus} aria-describedby={`${id}-hint`} id={id} autoComplete="new-password" maxLength={128} minLength={14} onChange={(event) => onChange(event.target.value)} required value={value} showLabel={auth("showPassword")} hideLabel={auth("hidePassword")} capsLockLabel={auth("capsLock")} />
  </FormField>;
}

export function CreateTenantDialog({ onClose }: { onClose(): void }) {
  const access = useAccountAccess();
  const t = useTranslations("AccountAccess");
  const formId = useId();
  const [password, setPassword] = useState("");
  const [loginName, setLoginName] = useState("");
  const [displayName, setDisplayName] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    const initialPassword = password;
    setPassword("");
    if (await access.execute({
      kind: "create-organization", id: String(fields.get("accountId") ?? "").trim(),
      displayName: String(fields.get("accountName") ?? "").trim(),
      administratorLoginName: loginName.trim(), administratorDisplayName: displayName.trim(), initialPassword
    })) onClose();
  }
  return <Dialog open title={t("createTenantTitle")} closeLabel={t("closeCreate")} onClose={onClose} busy={access.busy} footer={<>
    <Button disabled={access.busy} onClick={onClose} variant="secondary">{t("cancel")}</Button>
    <Button disabled={access.busy || access.loading || !password} form={formId} type="submit">{t(access.busy ? "creating" : "confirmTenant")}</Button>
  </>}>
    <form aria-label={t("createTenantTitle")} className={styles.form} id={formId} onSubmit={submit}>
      <FormField id={formId + "-id"} label={t("accountId")} hint={t("accountIdHint")}><Input aria-describedby={formId + "-id-hint"} id={formId + "-id"} autoComplete="off" maxLength={128} name="accountId" pattern={"[A-Za-z0-9][A-Za-z0-9._:\\-]{0,127}"} placeholder={t("accountIdPlaceholder")} required /></FormField>
      <FormField id={formId + "-tenant"} label={t("accountName")}><Input id={formId + "-tenant"} maxLength={128} name="accountName" required /></FormField>
      <FormField id={formId + "-login"} label={t("primaryLogin")} hint={t("loginHint") + " " + t("primaryLoginHint")}><Input aria-describedby={formId + "-login-hint"} id={formId + "-login"} autoComplete="off" maxLength={64} minLength={3} name="loginName" pattern={loginPattern} placeholder={t("primaryPlaceholder")} required value={loginName} onChange={(event) => setLoginName(event.target.value)} /></FormField>
      <FormField id={formId + "-name"} label={t("displayName")}><Input id={formId + "-name"} maxLength={128} name="displayName" required value={displayName} onChange={(event) => setDisplayName(event.target.value)} /></FormField>
      <PasswordField onChange={setPassword} value={password} />
      <Alert>{t("tenantNotice")}</Alert>
      {access.error ? <Alert status="danger">{t(`errors.${access.error}`)}</Alert> : null}
    </form>
  </Dialog>;
}

export function UserAccessDialog({ user, onClose }: { user: AccountUserScene; onClose(): void }) {
  const t = useTranslations("AccountAccess");
  const access = useAccountAccess();
  const [password, setPassword] = useState("");
  const [confirmStatus, setConfirmStatus] = useState(false);
  const [resettingPassword, setResettingPassword] = useState(false);
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [selectedPolicy, setSelectedPolicy] = useState<{ id: string; resourceVersion: number } | null>(null);
  const policies = access.scene?.policies ?? [];
  const attached = new Set(user.attachments.map((attachment) => attachment.policyId));
  const availablePolicies = policies.filter((policy) => policy.status === "ACTIVE" && !attached.has(policy.id));
  const currentPolicy = selectedPolicy ? policies.find((policy) => policy.id === selectedPolicy.id) : undefined;
  const policyChanged = Boolean(selectedPolicy && (!currentPolicy || currentPolicy.resourceVersion !== selectedPolicy.resourceVersion));
  const disabled = access.busy || access.loading;

  async function resetPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const initialPassword = password;
    setPassword("");
    if (await access.execute({ kind: "reset-password", principalId: user.id, resourceVersion: user.resourceVersion, initialPassword })) setResettingPassword(false);
  }
  return <Dialog open title={t("manageUser", { name: user.name })} closeLabel={t("closeDetails")} onClose={onClose} busy={access.busy} footer={<Button disabled={access.busy} onClick={onClose} variant="secondary">{t("closeDetails")}</Button>}>
    <div className={styles.detail}>
      <div className={styles.userSummary}><div><strong>{user.name}</strong><Typography.Text tone="muted">{user.qualifiedName}</Typography.Text></div><Badge status={user.enabled ? "success" : "neutral"}>{t(`states.${user.state}`)}</Badge></div>
      <dl className={styles.facts}><div><dt>{t("userType")}</dt><dd>{t("child")}</dd></div><div><dt>{t("ownership")}</dt><dd>{access.scene?.accountName}</dd></div><div><dt>{t("userId")}</dt><dd><Typography.Code>{user.id}</Typography.Code></dd></div></dl>
      <p className={styles.note}>{t("subuserOwnershipHint")}</p>
      {access.error ? <Alert status="danger">{t(`errors.${access.error}`)}</Alert> : null}
      {access.success ? <Alert status="success">{t(access.success)}</Alert> : null}
      <div className={styles.sectionHeading}><ShieldCheck aria-hidden="true" /><strong>{t("directPolicyAttachments")}</strong></div>
      <p className={styles.note}>{t("policyAttachmentHint")}</p>
      <ul className={styles.bindingList}>
        {user.attachments.map((attachment) => <li key={attachment.id}>
          <div><strong>{attachment.label}</strong><small>{attachment.policyId} · {t(attachment.scope === "INSTALLATION" ? "installationScope" : "tenantScope")}{attachment.policyStatus === "RETIRED" ? ` · ${t("retiredPolicy")}` : ""}</small></div>
          {revokeId === attachment.id ? <div className={styles.actions}>
            <span>{t("revokePrompt")}</span><Button disabled={disabled} onClick={async () => { if (await access.execute({ kind: "revoke-policy-attachment", attachmentId: attachment.id, resourceVersion: attachment.resourceVersion })) setRevokeId(null); }} size="small" variant="danger">{t("confirmRevoke")}</Button>
            <Button disabled={disabled} onClick={() => setRevokeId(null)} size="small" variant="ghost">{t("cancel")}</Button>
          </div> : <Button aria-label={t("revokePolicy", { name: attachment.label })} disabled={disabled} onClick={() => setRevokeId(attachment.id)} size="small" variant="ghost">{t("revoke")}</Button>}
        </li>)}
      </ul>
      {user.attachments.length === 0 ? <p className={styles.note}>{t("noPolicyAttachmentsHint")}</p> : null}
      {policyChanged ? <Alert status="warning">{t("policyRevisionChanged")} <Button size="small" variant="ghost" onClick={() => setSelectedPolicy(null)}>{t("reselectPolicy")}</Button></Alert> : null}
      {availablePolicies.length > 0 ? <form className={styles.inlineForm} onSubmit={async (event) => {
        event.preventDefault();
        if (selectedPolicy && !policyChanged && await access.execute({ kind: "create-policy-attachment", principalId: user.id, policyId: selectedPolicy.id, policyResourceVersion: selectedPolicy.resourceVersion })) setSelectedPolicy(null);
      }}>
        <FormField label={t("attachPolicy")}><Select disabled={disabled} onValueChange={(policyId) => { const policy = policies.find((item) => item.id === policyId); setSelectedPolicy(policy ? { id: policy.id, resourceVersion: policy.resourceVersion } : null); }} required value={selectedPolicy?.id ?? ""} placeholder={t("choosePolicy")} options={availablePolicies.map((policy) => ({ value: policy.id, label: `${policy.displayName} · ${t(policy.scope === "INSTALLATION" ? "installationScope" : "tenantScope")}` }))} /></FormField>
        <Button disabled={disabled || !selectedPolicy || policyChanged} type="submit" variant="secondary">{t("attachPolicy")}</Button>
      </form> : <p className={styles.note}>{access.scene?.canViewPolicies ? t("allPoliciesAttached") : t("policyDirectoryUnavailable")}</p>}
      <div className={styles.sectionHeading}><KeyRound aria-hidden="true" /><strong>{t("loginSecurity")}</strong></div>
      {user.protected ? <p className={styles.note}>{t("protectedHint")}</p> : <>
        <div className={styles.actions}>
          <Button disabled={disabled} onClick={() => { setConfirmStatus(true); setResettingPassword(false); setPassword(""); }} variant="secondary">{user.enabled ? t("disableUser") : t("enableUser")}</Button>
          <Button disabled={disabled} onClick={() => { setResettingPassword(true); setConfirmStatus(false); }} variant="secondary">{t("resetPassword")}</Button>
        </div>
        {confirmStatus ? <Alert status={user.enabled ? "warning" : "info"}><div className={styles.confirmation}>
          <p>{user.enabled ? t("disableHint") : t("enableHint")}</p>
          <div className={styles.actions}>
            <Button disabled={disabled} onClick={async () => { if (await access.execute({ kind: "set-status", principalId: user.id, status: user.enabled ? "DISABLED" : "ACTIVE", resourceVersion: user.resourceVersion })) setConfirmStatus(false); }} variant={user.enabled ? "danger" : "primary"}>{user.enabled ? t("confirmDisable") : t("confirmEnable")}</Button>
            <Button disabled={disabled} onClick={() => setConfirmStatus(false)} variant="ghost">{t("cancel")}</Button>
          </div>
        </div></Alert> : null}
        {resettingPassword ? <form className={styles.form} onSubmit={resetPassword}>
          <PasswordField autoFocus onChange={setPassword} value={password} />
          <p className={styles.note}>{t("resetHint")}</p>
          <div className={styles.actions}><Button disabled={disabled || !password} type="submit">{t("confirmReset")}</Button><Button disabled={disabled} onClick={() => { setResettingPassword(false); setPassword(""); }} variant="ghost">{t("cancel")}</Button></div>
        </form> : null}
      </>}
    </div>
  </Dialog>;
}
