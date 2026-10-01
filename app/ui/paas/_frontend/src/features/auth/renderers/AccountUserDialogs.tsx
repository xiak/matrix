"use client";

import { useId, useLayoutEffect, useRef, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import { KeyRound, ShieldCheck, UserRound } from "lucide-react";
import { Alert, Dialog, FormField, Badge, Button, Input, PasswordInput, Select, Typography } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import { withinNewPasswordProductBounds } from "../domain/passwordEntry";
import { LiveAccessCredentials } from "./LiveAccessCredentials";
import type { CapabilityRestriction } from "../domain/accounts";
import type { AccountUserScene } from "../scenes/accountAccessScene";
import styles from "./AccountAccessRenderer.module.css";

const loginPattern = "[a-z][a-z0-9._\\-]{2,63}";

function PasswordField({ value, onChange, autoFocus = false }: { value: string; onChange(value: string): void; autoFocus?: boolean }) {
  const t = useTranslations("AccountAccess");
  const auth = useTranslations("Auth");
  const id = useId();
  return <FormField id={id} label={t("initialPassword")} hint={t("passwordHint")}>
    <PasswordInput autoFocus={autoFocus} aria-describedby={`${id}-hint`} id={id} autoComplete="new-password" onChange={(event) => onChange(event.target.value)} required value={value} showLabel={auth("showPassword")} hideLabel={auth("hidePassword")} capsLockLabel={auth("capsLock")} />
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
    if (access.busy || access.loading || !withinNewPasswordProductBounds(password)) return;
    const fields = new FormData(event.currentTarget);
    const initialPassword = password;
    setPassword("");
    if (await access.execute({
      kind: "create-account", id: String(fields.get("accountId") ?? "").trim(),
      displayName: String(fields.get("accountName") ?? "").trim(),
      rootLoginName: loginName.trim(), rootDisplayName: displayName.trim(), initialPassword
    })) onClose();
  }
  return <Dialog open title={t("createTenantTitle")} closeLabel={t("closeCreate")} onClose={onClose} busy={access.busy} footer={<>
    <Button disabled={access.busy} onClick={onClose} variant="secondary">{t("cancel")}</Button>
    <Button disabled={access.busy || access.loading || !withinNewPasswordProductBounds(password)} form={formId} type="submit">{t(access.busy ? "creating" : "confirmTenant")}</Button>
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

export function UserAccessManagement({ user, onDeleted, profileActions = false, deleteAction = false, showLiveEvidenceBoundary = false }: {
  user: AccountUserScene;
  onDeleted?(): void;
  profileActions?: boolean;
  deleteAction?: boolean;
  showLiveEvidenceBoundary?: boolean;
}) {
  const t = useTranslations("AccountAccess");
  const access = useAccountAccess();
  const profileId = useId();
  const deleteId = useId();
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState(user.name);
  const [editingProfile, setEditingProfile] = useState(false);
  const [confirmStatus, setConfirmStatus] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleteConfirmation, setDeleteConfirmation] = useState("");
  const [resettingPassword, setResettingPassword] = useState(false);
  const [reviewingReset, setReviewingReset] = useState(false);
  const [showKeys, setShowKeys] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState<{ id: string; resourceVersion: number } | null>(null);
  const relationIntent = access.userPolicyChangeIntent;
  const reviewingPolicy = relationIntent?.userId === user.id;
  const otherUserIntent = relationIntent && !reviewingPolicy ? relationIntent : null;
  const reviewHeading = useRef<HTMLHeadingElement>(null);
  const resetReviewHeading = useRef<HTMLHeadingElement>(null);
  const reviewTrigger = useRef<HTMLButtonElement>(null);
  const returnToTrigger = useRef(false);
  const lastTrigger = useRef<HTMLButtonElement | null>(null);
  const policies = access.scene?.policies ?? [];
  const attached = new Set(user.attachments.map((attachment) => attachment.policyId));
  const availablePolicies = policies.filter((policy) => policy.status === "ACTIVE" && !attached.has(policy.id));
  const disabled = access.busy || access.loading;
  const relationDisabled = disabled || Boolean(relationIntent);
  const attachablePolicies = availablePolicies.filter((policy) => policy.scope === "INSTALLATION" ? user.canAttachPlatformPolicy : user.canAttachTenantPolicy);
  const platformAttachmentBlocked = !user.canAttachPlatformPolicy && availablePolicies.some((policy) => policy.scope === "INSTALLATION");
  const tenantAttachmentBlocked = !user.canAttachTenantPolicy && availablePolicies.some((policy) => policy.scope === "TENANT");
  const currentPolicy = selectedPolicy ? attachablePolicies.find((policy) => policy.id === selectedPolicy.id) : undefined;
  const policyChanged = Boolean(selectedPolicy && (!currentPolicy || currentPolicy.resourceVersion !== selectedPolicy.resourceVersion));
  const restriction = (reason: CapabilityRestriction | null) => t(`restrictions.${reason ?? "AUTHORITY_REQUIRED"}`);
  useLayoutEffect(() => {
    if (reviewingPolicy) reviewHeading.current?.focus({ preventScroll: true });
    else if (returnToTrigger.current) {
      returnToTrigger.current = false;
      (lastTrigger.current?.isConnected ? lastTrigger.current : reviewTrigger.current)?.focus({ preventScroll: true });
    }
  }, [reviewingPolicy]);
  useLayoutEffect(() => {
    if (resettingPassword && reviewingReset) resetReviewHeading.current?.focus({ preventScroll: true });
  }, [resettingPassword, reviewingReset]);

  async function resetPassword() {
    const initialPassword = password;
    setPassword("");
    setReviewingReset(false);
    setResettingPassword(false);
    await access.resetUserPassword(user, initialPassword);
  }
  return <div className={styles.detail}>
      <div className={styles.userSummary}><div><strong>{user.name}</strong><Typography.Text tone="muted">{user.qualifiedName}</Typography.Text></div><Badge status={user.enabled ? "success" : "neutral"}>{t(`states.${user.state}`)}</Badge></div>
      <dl className={styles.facts}><div><dt>{t("userType")}</dt><dd>{t("child")}</dd></div><div><dt>{t("ownership")}</dt><dd>{access.scene?.accountName}</dd></div><div><dt>{t("userId")}</dt><dd><Typography.Code>{user.id}</Typography.Code></dd></div></dl>
      <p className={styles.note}>{t("subuserOwnershipHint")}</p>
      {access.error ? <Alert status="danger">{t(`errors.${access.error}`)}</Alert> : null}
      {access.success ? <Alert status="success">{t(access.success)}</Alert> : null}
      {profileActions ? <section className={styles.identitySection}>
        <div className={styles.sectionHeading}><UserRound aria-hidden="true" /><strong>{t("userProfile")}</strong></div>
        {editingProfile ? <form className={styles.inlineForm} onSubmit={async (event) => {
          event.preventDefault();
          const next = displayName.trim();
          if (next && await access.execute({ kind: "update-user", userId: user.id, displayName: next, resourceVersion: user.resourceVersion })) setEditingProfile(false);
        }}>
          <FormField id={profileId} label={t("displayName")}><Input autoFocus id={profileId} disabled={disabled} maxLength={128} minLength={1} required value={displayName} onChange={(event) => setDisplayName(event.target.value)} /></FormField>
          <Button disabled={disabled || !displayName.trim() || displayName.trim() === user.name} type="submit">{t("saveDisplayName")}</Button>
          <Button disabled={disabled} onClick={() => { setDisplayName(user.name); setEditingProfile(false); }} type="button" variant="ghost">{t("cancel")}</Button>
        </form> : <div className={styles.actions}><Button disabled={disabled || !user.canUpdate} onClick={() => setEditingProfile(true)} title={!user.canUpdate ? restriction(user.updateRestrictionReason) : undefined} variant="secondary">{t("editDisplayName")}</Button></div>}
        <p className={styles.note}>{t("immutableUserFieldsHint")}</p>
      </section> : null}
      {showLiveEvidenceBoundary ? <section className={styles.identitySection}>
        <div className={styles.sectionHeading}><KeyRound aria-hidden="true" /><strong>{t("accessMethodsAndCredentials")}</strong></div>
        <p className={styles.note}>{t(access.accessKeys ? "liveCredentialManagedHint" : "liveCredentialContractHint")}</p>
        {access.accessKeys && access.scene ? <>
          <div className={styles.actions}><Button onClick={() => setShowKeys((current) => !current)} variant="secondary">{t(showKeys ? "hideAccessKeys" : "manageAccessKeys")}</Button></div>
          {showKeys ? <LiveAccessCredentials client={access.accessKeys} scene={access.scene} createIntent={access.accessKeyCreateIntent} scopedOwner={user}
            userDirectory={{ busy: access.busy, loading: access.loading, readPage: access.usersPage }} /> : null}
        </> : null}
      </section> : null}
      <div className={styles.sectionHeading}><ShieldCheck aria-hidden="true" /><strong>{t("directPolicyAttachments")}</strong></div>
      <p className={styles.note}>{t("policyAttachmentHint")}</p>
      <ul className={styles.bindingList}>
        {user.attachments.map((attachment) => <li key={attachment.id}>
          <div><strong>{attachment.label}</strong><small>{attachment.policyId} · {t(attachment.scope === "INSTALLATION" ? "installationScope" : "tenantScope")}{attachment.policyStatus === "RETIRED" ? ` · ${t("retiredPolicy")}` : ""}</small></div>
          <Button aria-label={t("revokePolicy", { name: attachment.label })} disabled={relationDisabled || !attachment.canRevoke} title={!attachment.canRevoke ? restriction(attachment.revokeRestrictionReason) : undefined} onClick={(event) => {
            if (access.beginUserPolicyRevocation(user, attachment.id)) lastTrigger.current = event.currentTarget;
          }} size="small" variant="ghost">{t("revoke")}</Button>
        </li>)}
      </ul>
      {user.attachments.length === 0 ? <p className={styles.note}>{t("noPolicyAttachmentsHint")}</p> : null}
      {policyChanged ? <Alert status="warning">{t("policyRevisionChanged")} <Button size="small" variant="ghost" onClick={() => setSelectedPolicy(null)}>{t("reselectPolicy")}</Button></Alert> : null}
      {otherUserIntent ? <Alert status="warning">{t(otherUserIntent.phase === "review" ? "attachmentOtherUserReview" : "attachmentOtherUserPending", { user: otherUserIntent.userQualifiedName })}</Alert> : null}
      {reviewingPolicy && relationIntent ? <section aria-label={t(relationIntent.kind === "attach" ? "attachmentReviewTitle" : "revocationReviewTitle")} className={styles.policyAttachmentReview}>
        <h3 ref={reviewHeading} tabIndex={-1} className={styles.stepTitle}>{t(relationIntent.kind === "attach" ? "attachmentReviewTitle" : "revocationReviewTitle")}</h3>
        <dl className={styles.facts}>
          <div><dt>{t("attachmentTarget")}</dt><dd>{relationIntent.userQualifiedName}<small>{relationIntent.userId}</small></dd></div>
          <div><dt>{t("attachmentPolicy")}</dt><dd>{relationIntent.policyDisplayName}<small>{relationIntent.policyId}</small></dd></div>
          <div><dt>{t("attachmentScope")}</dt><dd>{t(relationIntent.policyScope === "INSTALLATION" ? "installationScope" : "tenantScope")}</dd></div>
          {relationIntent.kind === "attach" ? <div><dt>{t("attachmentVersion")}</dt><dd>{relationIntent.defaultVersionId} · {t("attachmentRevision", { revision: relationIntent.policyResourceVersion })}</dd></div>
            : <div><dt>{t("revocationAttachment")}</dt><dd><Typography.Code>{relationIntent.attachmentId}</Typography.Code> · {t("attachmentRevision", { revision: relationIntent.attachmentResourceVersion })}</dd></div>}
        </dl>
        <Alert status="warning">{t(relationIntent.kind === "revoke" ? "revocationReviewHint" : relationIntent.policyScope === "INSTALLATION" ? "platformAttachmentReviewHint" : "tenantAttachmentReviewHint")}</Alert>
        {relationIntent.phase === "unknown" ? <Alert status="warning">{t(relationIntent.kind === "revoke" ? "revocationUnknownResult" : "attachmentUnknownResult", { requestId: relationIntent.requestId })}</Alert> : null}
        {relationIntent.phase === "conflict" || relationIntent.phase === "rejected" ? <Alert status="danger">{t("attachmentRetryNeedsReview", { requestId: relationIntent.requestId })}{relationIntent.error ? ` ${t(`errors.${relationIntent.error}`)}` : ""}</Alert> : null}
        <div className={styles.actions}>
          <Button disabled={disabled || (relationIntent.phase !== "review" && relationIntent.phase !== "unknown")} onClick={async () => {
            if (await access.submitUserPolicyChange(relationIntent.requestId)) {
              setSelectedPolicy(null);
            }
          }} variant={relationIntent.kind === "revoke" ? "danger" : "primary"}>{t(relationIntent.phase === "unknown" ? "retryOriginalAttachment" : relationIntent.kind === "revoke" ? "confirmRevoke" : "confirmAttachPolicy")}</Button>
          <Button disabled={disabled} onClick={() => {
            returnToTrigger.current = relationIntent.phase === "review";
            if (access.endUserPolicyChange(relationIntent.requestId) && relationIntent.phase !== "review") setSelectedPolicy(null);
          }} variant="secondary">{t(relationIntent.phase === "review" ? relationIntent.kind === "attach" ? "changeAttachmentSelection" : "cancel" : "endAttachmentIntent")}</Button>
        </div>
      </section> : attachablePolicies.length > 0 ? <form className={styles.inlineForm} onSubmit={(event) => {
        event.preventDefault();
        if (selectedPolicy && !policyChanged && !relationIntent) {
          lastTrigger.current = reviewTrigger.current;
          access.beginUserPolicyAttachment(user, selectedPolicy.id);
        }
      }}>
        <FormField label={t("attachPolicy")}><Select disabled={relationDisabled} onValueChange={(policyId) => { const policy = attachablePolicies.find((item) => item.id === policyId); setSelectedPolicy(policy ? { id: policy.id, resourceVersion: policy.resourceVersion } : null); }} required value={selectedPolicy?.id ?? ""} placeholder={t("choosePolicy")} options={attachablePolicies.map((policy) => ({ value: policy.id, label: `${policy.displayName} · ${t(policy.scope === "INSTALLATION" ? "installationScope" : "tenantScope")}` }))} /></FormField>
        <Button ref={reviewTrigger} disabled={relationDisabled || !selectedPolicy || policyChanged} type="submit" variant="secondary">{t("reviewAttachPolicy")}</Button>
      </form> : <p className={styles.note}>{availablePolicies.length ? t("noAttachablePolicies") : access.scene?.canViewPolicies ? t("allPoliciesAttached") : t("policyDirectoryUnavailable")}</p>}
      {platformAttachmentBlocked ? <p className={styles.note}>{t("platformAttachmentUnavailable", { reason: restriction(user.platformAttachmentRestrictionReason) })}</p> : null}
      {tenantAttachmentBlocked ? <p className={styles.note}>{t("tenantAttachmentUnavailable", { reason: restriction(user.tenantAttachmentRestrictionReason) })}</p> : null}
      <div className={styles.sectionHeading}><KeyRound aria-hidden="true" /><strong>{t("loginSecurity")}</strong></div>
      <div className={styles.actions}>
          <Button disabled={disabled || !user.canSetStatus} title={!user.canSetStatus ? restriction(user.statusRestrictionReason) : undefined} onClick={() => { setConfirmStatus(true); setConfirmDelete(false); setResettingPassword(false); setPassword(""); }} variant="secondary">{user.enabled ? t("disableUser") : t("enableUser")}</Button>
          <Button disabled={disabled || !user.canResetPassword || Boolean(access.passwordResetUnknown)} title={access.passwordResetUnknown ? t("resetUnknownBlocked") : !user.canResetPassword ? restriction(user.passwordRestrictionReason) : undefined} onClick={() => { setResettingPassword(true); setReviewingReset(false); setConfirmDelete(false); setConfirmStatus(false); }} variant="secondary">{t("resetPassword")}</Button>
          {deleteAction ? <Button disabled={disabled || !user.canDelete} title={!user.canDelete ? restriction(user.deleteRestrictionReason) : undefined} onClick={() => { setConfirmDelete(true); setConfirmStatus(false); setResettingPassword(false); }} variant="danger">{t("deleteUser")}</Button> : null}
      </div>
      {!user.canSetStatus || !user.canResetPassword ? <p className={styles.note}>{restriction(user.statusRestrictionReason ?? user.passwordRestrictionReason)}</p> : null}
      {deleteAction && !user.canDelete ? <p className={styles.note}>{t("deleteUnavailable", { reason: restriction(user.deleteRestrictionReason) })}</p> : null}
        {confirmStatus ? <Alert status={user.enabled ? "warning" : "info"}><div className={styles.confirmation}>
          <p>{user.enabled ? t("disableHint") : t("enableHint")}</p>
          <div className={styles.actions}>
            <Button disabled={disabled || !user.canSetStatus} onClick={async () => { if (await access.execute({ kind: "set-status", userId: user.id, status: user.enabled ? "DISABLED" : "ACTIVE", resourceVersion: user.resourceVersion })) setConfirmStatus(false); }} variant={user.enabled ? "danger" : "primary"}>{user.enabled ? t("confirmDisable") : t("confirmEnable")}</Button>
            <Button disabled={disabled} onClick={() => setConfirmStatus(false)} variant="ghost">{t("cancel")}</Button>
          </div>
        </div></Alert> : null}
        {resettingPassword && !reviewingReset ? <form className={styles.form} onSubmit={(event) => { event.preventDefault(); if (withinNewPasswordProductBounds(password) && !disabled) setReviewingReset(true); }}>
          <PasswordField autoFocus onChange={setPassword} value={password} />
          <p className={styles.note}>{t("resetHint")}</p>
          <div className={styles.actions}><Button disabled={disabled || !withinNewPasswordProductBounds(password)} type="submit">{t("reviewReset")}</Button><Button disabled={disabled} onClick={() => { setResettingPassword(false); setPassword(""); }} variant="ghost">{t("cancel")}</Button></div>
        </form> : null}
        {resettingPassword && reviewingReset ? <section aria-label={t("resetReviewTitle")} className={styles.policyAttachmentReview}>
          <h3 ref={resetReviewHeading} tabIndex={-1} className={styles.stepTitle}>{t("resetReviewTitle")}</h3>
          <dl className={styles.facts}>
            <div><dt>{t("attachmentTarget")}</dt><dd>{user.qualifiedName}<small>{user.id}</small></dd></div>
            <div><dt>{t("ownership")}</dt><dd>{access.scene?.accountName}</dd></div>
          </dl>
          <Alert status="warning">{t("resetHint")}</Alert>
          <p className={styles.note}>{t("resetReviewSecretHint")}</p>
          <div className={styles.actions}>
            <Button disabled={disabled || !user.canResetPassword || Boolean(access.passwordResetUnknown)} onClick={() => void resetPassword()}>{t("confirmReset")}</Button>
            <Button disabled={disabled} onClick={() => setReviewingReset(false)} variant="secondary">{t("changeResetPassword")}</Button>
            <Button disabled={disabled} onClick={() => { setResettingPassword(false); setReviewingReset(false); setPassword(""); }} variant="ghost">{t("cancel")}</Button>
          </div>
        </section> : null}
        {confirmDelete ? <Alert status="warning"><form className={styles.confirmation} onSubmit={async (event) => {
          event.preventDefault();
          if (deleteConfirmation !== user.loginName || !user.canDelete) return;
          if (await access.execute({ kind: "delete-user", userId: user.id, resourceVersion: user.resourceVersion })) onDeleted?.();
        }}>
          <strong>{t("deleteUserTitle", { name: user.loginName })}</strong>
          <p>{t("deleteUserImpact")}</p>
          <FormField id={deleteId} label={t("deleteUserConfirmLabel", { name: user.loginName })}><Input autoComplete="off" id={deleteId} disabled={disabled} required value={deleteConfirmation} onChange={(event) => setDeleteConfirmation(event.target.value)} /></FormField>
          <div className={styles.actions}><Button disabled={disabled || deleteConfirmation !== user.loginName || !user.canDelete} type="submit" variant="danger">{t("confirmDeleteUser")}</Button><Button disabled={disabled} onClick={() => { setConfirmDelete(false); setDeleteConfirmation(""); }} type="button" variant="ghost">{t("cancel")}</Button></div>
        </form></Alert> : null}
    </div>;
}

export function UserAccessDialog({ user, onClose }: { user: AccountUserScene; onClose(): void }) {
  const t = useTranslations("AccountAccess");
  const access = useAccountAccess();
  return <Dialog open title={t("manageUser", { name: user.name })} closeLabel={t("closeDetails")} onClose={onClose} busy={access.busy} footer={<Button disabled={access.busy} onClick={onClose} variant="secondary">{t("closeDetails")}</Button>}>
    <UserAccessManagement key={`${user.id}:${user.resourceVersion}`} user={user} />
  </Dialog>;
}
