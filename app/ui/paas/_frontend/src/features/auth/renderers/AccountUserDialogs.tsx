"use client";

import { useEffect, useId, useLayoutEffect, useRef, useState, type FormEvent, type Ref } from "react";
import { useTranslations } from "next-intl";
import { Plus } from "lucide-react";
import { Alert, HelpDisclosure, FormField, Button, Input, PasswordInput, Select, Typography } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import { withinNewPasswordProductBounds } from "../domain/passwordEntry";
import { useAccessDraft } from "./useAccessDraft";
import { WorkspaceDetail, WorkspaceTime } from "./AccessWorkspaceUi";
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

export function CreateTenantWorkspace({ onClose }: { onClose(): void }) {
  const access = useAccountAccess();
  const t = useTranslations("AccountAccess");
  const formId = useId();
  const form = useRef<HTMLFormElement>(null);
  const [password, setPassword] = useState("");
  const [loginName, setLoginName] = useState("");
  const [displayName, setDisplayName] = useState("");
  useEffect(() => {
    if (!access.error || access.busy) return;
    const alert = form.current?.querySelector<HTMLElement>('[role="alert"]');
    alert?.focus({ preventScroll: true });
    alert?.scrollIntoView?.({ block: "nearest" });
  }, [access.busy, access.error]);
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
  return <WorkspaceDetail title={t("createTenantTitle")} onBack={onClose}>
    <form aria-busy={access.busy || undefined} aria-label={t("createTenantTitle")} className={styles.form} id={formId} onSubmit={submit} ref={form}>
      <FormField id={formId + "-id"} label={t("accountId")} hint={t("accountIdHint")}><Input aria-describedby={formId + "-id-hint"} id={formId + "-id"} autoComplete="off" maxLength={128} name="accountId" pattern={"[A-Za-z0-9][A-Za-z0-9._:\\-]{0,127}"} placeholder={t("accountIdPlaceholder")} required /></FormField>
      <FormField id={formId + "-tenant"} label={t("accountName")}><Input id={formId + "-tenant"} maxLength={128} name="accountName" required /></FormField>
      <FormField id={formId + "-login"} label={t("primaryLogin")} hint={t("loginHint") + " " + t("primaryLoginHint")}><Input aria-describedby={formId + "-login-hint"} id={formId + "-login"} autoComplete="off" maxLength={64} minLength={3} name="loginName" pattern={loginPattern} placeholder={t("primaryPlaceholder")} required value={loginName} onChange={(event) => setLoginName(event.target.value)} /></FormField>
      <FormField id={formId + "-name"} label={t("displayName")}><Input id={formId + "-name"} maxLength={128} name="displayName" required value={displayName} onChange={(event) => setDisplayName(event.target.value)} /></FormField>
      <PasswordField onChange={setPassword} value={password} />
      <HelpDisclosure label={t("tenantHelp")}>{t("tenantNotice")}</HelpDisclosure>
      {access.error ? <Alert status="danger" tabIndex={-1}>{t(`errors.${access.error}`)}</Alert> : null}
      <div className={styles.actions}>
        <Button disabled={access.busy || access.loading || !withinNewPasswordProductBounds(password)} type="submit">{t(access.busy ? "creating" : "confirmTenant")}</Button>
        <Button disabled={access.busy} onClick={onClose} type="button" variant="secondary">{t("cancel")}</Button>
      </div>
    </form>
  </WorkspaceDetail>;
}

export function UserDirectPolicies({ user }: { user: AccountUserScene }) {
  const t = useTranslations("AccountAccess");
  const policyChange = useTranslations("PolicyAttachmentChange");
  const access = useAccountAccess();
  const [choosing, setChoosing] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState<{ id: string; resourceVersion: number } | null>(null);
  const relationIntent = access.userPolicyChangeIntent;
  const reviewingPolicy = relationIntent?.userId === user.id;
  const otherUserIntent = relationIntent && !reviewingPolicy ? relationIntent : null;
  const reviewHeading = useRef<HTMLHeadingElement>(null);
  const attachTrigger = useRef<HTMLButtonElement>(null);
  const reviewTrigger = useRef<HTMLButtonElement>(null);
  const returnToTrigger = useRef(false);
  const lastTrigger = useRef<HTMLButtonElement | null>(null);
  const policies = access.scene?.policies ?? [];
  const attached = new Set(user.attachments.map((attachment) => attachment.policyId));
  const availablePolicies = policies.filter((policy) => policy.status === "ACTIVE" && !attached.has(policy.id));
  const disabled = access.busy || access.loading;
  const policyChangeDisabled = disabled || !access.userPolicyChangeReady;
  const relationDisabled = policyChangeDisabled || Boolean(relationIntent);
  const attachablePolicies = availablePolicies.filter((policy) => policy.scope === "INSTALLATION" ? user.canAttachPlatformPolicy : user.canAttachTenantPolicy);
  const platformAttachmentBlocked = !user.canAttachPlatformPolicy && availablePolicies.some((policy) => policy.scope === "INSTALLATION");
  const tenantAttachmentBlocked = !user.canAttachTenantPolicy && availablePolicies.some((policy) => policy.scope === "TENANT");
  const showRestrictions = !reviewingPolicy && (choosing || attachablePolicies.length === 0);
  const currentPolicy = selectedPolicy ? attachablePolicies.find((policy) => policy.id === selectedPolicy.id) : undefined;
  const policyChanged = Boolean(selectedPolicy && (!currentPolicy || currentPolicy.resourceVersion !== selectedPolicy.resourceVersion));
  const restriction = (reason: CapabilityRestriction | null) => t(`restrictions.${reason ?? "AUTHORITY_REQUIRED"}`);
  useLayoutEffect(() => {
    if (reviewingPolicy) reviewHeading.current?.focus({ preventScroll: true });
    else if (returnToTrigger.current) {
      returnToTrigger.current = false;
      (lastTrigger.current?.isConnected ? lastTrigger.current : reviewTrigger.current ?? attachTrigger.current)?.focus({ preventScroll: true });
    }
  }, [reviewingPolicy]);
  function finishReview(requestId: string) {
    if (access.endUserPolicyChange(requestId)) {
      returnToTrigger.current = true;
      setSelectedPolicy(null);
      setChoosing(false);
    }
  }
  return <section aria-label={t("directPolicyAttachments")} className={styles.userSection}>
    <div className={styles.userSectionHeader}>
      <h3>{t("directPolicyAttachments")}</h3>
      {!reviewingPolicy && attachablePolicies.length > 0 ? <Button ref={attachTrigger} size="small"
        variant={choosing ? "ghost" : "primary"} disabled={relationDisabled} aria-expanded={choosing}
        onClick={() => { setChoosing(!choosing); setSelectedPolicy(null); }}>
        {choosing ? null : <Plus aria-hidden="true" />}{t(choosing ? "cancel" : "attachPolicy")}
      </Button> : null}
    </div>
    {user.attachments.length > 0 ? <>
      <ul className={styles.bindingList}>
        {user.attachments.map((attachment) => <li key={attachment.id}>
          <div><strong>{attachment.label}</strong><small>{attachment.policyId} · {t(attachment.scope === "INSTALLATION" ? "installationScope" : "tenantScope")}{attachment.policyStatus === "RETIRED" ? ` · ${t("retiredPolicy")}` : ""}</small></div>
          <Button aria-label={t("revokePolicy", { name: attachment.label })} disabled={relationDisabled || !attachment.canRevoke} title={!attachment.canRevoke ? restriction(attachment.revokeRestrictionReason) : undefined} onClick={(event) => {
            if (access.beginUserPolicyRevocation(user, attachment.id)) lastTrigger.current = event.currentTarget;
          }} size="small" variant="ghost">{t("revoke")}</Button>
        </li>)}
      </ul>
      <HelpDisclosure label={t("policySources")}>{t("policyAttachmentHint")}</HelpDisclosure>
    </> : <p className={styles.note}>{t("noPolicyAttachmentsHint")}</p>}
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
      {relationIntent.phase === "unknown" || relationIntent.phase === "checking" ? <Alert status="warning"><div className={styles.confirmation}>
        <strong>{t("attachmentUnknownTitle")}</strong>
        <p>{t(relationIntent.kind === "revoke" ? "revocationUnknownResult" : "attachmentUnknownResult", { requestId: relationIntent.requestId })}</p>
        {relationIntent.lookupStatus !== "unchecked" ? <p role="status">{t(`attachmentLookup.${relationIntent.lookupStatus}`)}</p> : null}
        <p>{t("attachmentUnknownLockHint")}</p>
      </div></Alert> : null}
      {relationIntent.phase === "confirmed" && relationIntent.completion ? <Alert status="success" role="status" aria-label={policyChange("completedTitle")}><div className={styles.confirmation}>
        <strong>{policyChange("completedTitle")}</strong>
        <p>{policyChange("completedHint")}</p>
        <dl className={styles.facts}>
          <div><dt>{policyChange("operation")}</dt><dd>{policyChange(relationIntent.completion.operation === "CREATE" ? "attach" : "revoke")}</dd></div>
          <div><dt>{policyChange("requestId")}</dt><dd><Typography.Code>{relationIntent.completion.requestId}</Typography.Code></dd></div>
          <div><dt>{policyChange("completedAt")}</dt><dd><WorkspaceTime value={relationIntent.completion.completedAt} /></dd></div>
          <div><dt>{policyChange("target")}</dt><dd><Typography.Code>{relationIntent.userId}</Typography.Code></dd></div>
          <div><dt>{policyChange("policyId")}</dt><dd><Typography.Code>{relationIntent.policyId}</Typography.Code></dd></div>
          <div><dt>{policyChange("attachmentId")}</dt><dd><Typography.Code>{relationIntent.completion.operation === "CREATE" ? relationIntent.completion.attachment.id : relationIntent.completion.attachmentId}</Typography.Code></dd></div>
          <div><dt>{policyChange("resultingRevision")}</dt><dd>{relationIntent.completion.operation === "CREATE" ? relationIntent.completion.attachment.resourceVersion : relationIntent.completion.revocation.resourceVersion}</dd></div>
        </dl>
      </div></Alert> : null}
      {relationIntent.phase === "conflict" || relationIntent.phase === "rejected" ? <Alert status="danger">{t("attachmentRetryNeedsReview", { requestId: relationIntent.requestId })}{relationIntent.error ? ` ${t(`errors.${relationIntent.error}`)}` : ""}</Alert> : null}
      <div className={styles.actions}>
        {relationIntent.phase === "review" ? <>
          <Button disabled={policyChangeDisabled} onClick={async () => {
            if (await access.submitUserPolicyChange(relationIntent.requestId)) setSelectedPolicy(null);
          }} variant={relationIntent.kind === "revoke" ? "danger" : "primary"}>{t(relationIntent.kind === "revoke" ? "confirmRevoke" : "confirmAttachPolicy")}</Button>
          <Button disabled={disabled} onClick={() => {
            if (relationIntent.kind === "attach") setChoosing(true);
            returnToTrigger.current = true;
            access.endUserPolicyChange(relationIntent.requestId);
          }} variant="secondary">{t(relationIntent.kind === "attach" ? "changeAttachmentSelection" : "cancel")}</Button>
        </> : null}
        {relationIntent.phase === "unknown" || relationIntent.phase === "checking" ? <>
          <Button disabled={policyChangeDisabled || relationIntent.phase === "checking"} onClick={() => void access.inspectUserPolicyChange(relationIntent.requestId)}>{t(relationIntent.phase === "checking" ? "checkingOriginalAttachment" : "checkOriginalAttachment")}</Button>
        </> : null}
        {relationIntent.phase === "confirmed" ? <Button disabled={disabled} onClick={() => finishReview(relationIntent.requestId)}>{t("acknowledgeAttachmentCompletion")}</Button> : null}
        {relationIntent.phase === "conflict" || relationIntent.phase === "rejected" ? <Button disabled={disabled} onClick={() => finishReview(relationIntent.requestId)} variant="secondary">{t("endAttachmentIntent")}</Button> : null}
      </div>
    </section> : choosing && attachablePolicies.length > 0 ? <form className={styles.inlineForm} onSubmit={(event) => {
      event.preventDefault();
      if (selectedPolicy && !policyChanged && !relationIntent) {
        lastTrigger.current = reviewTrigger.current;
        access.beginUserPolicyAttachment(user, selectedPolicy.id);
      }
    }}>
      <FormField label={t("attachPolicy")}><Select autoFocus disabled={relationDisabled} onValueChange={(policyId) => { const policy = attachablePolicies.find((item) => item.id === policyId); setSelectedPolicy(policy ? { id: policy.id, resourceVersion: policy.resourceVersion } : null); }} required value={selectedPolicy?.id ?? ""} placeholder={t("choosePolicy")} options={attachablePolicies.map((policy) => ({ value: policy.id, label: `${policy.displayName} · ${t(policy.scope === "INSTALLATION" ? "installationScope" : "tenantScope")}` }))} /></FormField>
      <Button ref={reviewTrigger} disabled={relationDisabled || !selectedPolicy || policyChanged} type="submit" variant="secondary">{t("reviewAttachPolicy")}</Button>
    </form> : null}
    {showRestrictions && attachablePolicies.length === 0 ? <p className={styles.note}>{availablePolicies.length ? t("noAttachablePolicies") : access.scene?.canViewPolicies ? t("allPoliciesAttached") : t("policyDirectoryUnavailable")}</p> : null}
    {showRestrictions && platformAttachmentBlocked ? <p className={styles.note}>{t("platformAttachmentUnavailable", { reason: restriction(user.platformAttachmentRestrictionReason) })}</p> : null}
    {showRestrictions && tenantAttachmentBlocked ? <p className={styles.note}>{t("tenantAttachmentUnavailable", { reason: restriction(user.tenantAttachmentRestrictionReason) })}</p> : null}
  </section>;
}

export function UserSignInSecurity({ user, onDelete, onStatus, statusDisabled, statusActionRef }: {
  user: AccountUserScene;
  onDelete?(): void;
  onStatus?(): void;
  statusDisabled?: boolean;
  statusActionRef?: Ref<HTMLButtonElement>;
}) {
  const t = useTranslations("AccountAccess");
  const auth = useTranslations("Auth");
  const wizard = useTranslations("UserWizard");
  const access = useAccountAccess();
  const [password, setPassword] = useState("");
  const [confirmStatus, setConfirmStatus] = useState(false);
  const [resettingPassword, setResettingPassword] = useState(false);
  const [reviewingReset, setReviewingReset] = useState(false);
  const resetReviewHeading = useRef<HTMLHeadingElement>(null);
  const passwordRow = useRef<HTMLElement>(null);
  const resetTrigger = useRef<HTMLButtonElement>(null);
  const disabled = access.busy || access.loading;
  const restriction = (reason: CapabilityRestriction | null) => t(`restrictions.${reason ?? "AUTHORITY_REQUIRED"}`);
  const resetReason = access.passwordResetUnknown ? t("resetUnknownBlocked") : !user.canResetPassword ? restriction(user.passwordRestrictionReason) : undefined;
  const requestLeave = useAccessDraft({ dirty: resettingPassword && Boolean(password), busy: false, title: t("resetPassword"), description: t("discardResetDraft"), form: passwordRow });
  useLayoutEffect(() => {
    if (resettingPassword && reviewingReset) resetReviewHeading.current?.focus({ preventScroll: true });
  }, [resettingPassword, reviewingReset]);
  function closeReset() {
    setPassword("");
    setReviewingReset(false);
    setResettingPassword(false);
    resetTrigger.current?.focus({ preventScroll: true });
  }
  async function resetPassword() {
    const initialPassword = password;
    closeReset();
    await access.resetUserPassword(user, initialPassword);
  }
  return <div className={styles.userSections}>
    <section className={styles.userSection} ref={passwordRow}>
      <div className={styles.userSectionHeader}>
        <h3>{auth("password")}</h3>
        <Button ref={resetTrigger} disabled={disabled || Boolean(resetReason)} title={resetReason} aria-expanded={resettingPassword}
          onClick={() => { setResettingPassword(true); setReviewingReset(false); setConfirmStatus(false); }} size="small" variant="secondary">{t("resetPassword")}</Button>
      </div>
      {resetReason ? <p className={styles.note}>{resetReason}</p> : user.state === "passwordChangeRequired" ? <p className={styles.note}>{t("initialPasswordNextSignIn")}</p> : null}
      {resettingPassword && !reviewingReset ? <form className={styles.form} onSubmit={(event) => { event.preventDefault(); if (withinNewPasswordProductBounds(password) && !disabled) setReviewingReset(true); }}>
        <PasswordField autoFocus onChange={setPassword} value={password} />
        <p className={styles.note}>{t("resetHint")}</p>
        <div className={styles.actions}><Button disabled={disabled || !withinNewPasswordProductBounds(password)} type="submit">{t("reviewReset")}</Button><Button disabled={disabled} onClick={closeReset} variant="ghost">{t("cancel")}</Button></div>
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
          <Button disabled={disabled} onClick={closeReset} variant="ghost">{t("cancel")}</Button>
        </div>
      </section> : null}
    </section>
    <section className={styles.userSection}>
      <div className={styles.userSectionHeader}>
        <h3>{t("userStatus")}</h3>
        <Button ref={statusActionRef} disabled={disabled || statusDisabled || !user.canSetStatus}
          title={!user.canSetStatus ? restriction(user.statusRestrictionReason) : undefined} onClick={() => requestLeave(() => {
            if (onStatus) onStatus();
            else { setConfirmStatus(true); setResettingPassword(false); setReviewingReset(false); setPassword(""); }
          })} size="small" variant="secondary">{t(user.enabled ? "disableUser" : "enableUser")}</Button>
      </div>
      <p className={styles.note}>{wizard(user.enabled ? "enabled" : "disabled")}</p>
      {!user.canSetStatus ? <p className={styles.note}>{restriction(user.statusRestrictionReason)}</p> : null}
      {confirmStatus ? <Alert status={user.enabled ? "warning" : "info"}><div className={styles.confirmation}>
        <p>{user.enabled ? t("disableHint") : t("enableHint")}</p>
        <div className={styles.actions}>
          <Button disabled={disabled || !user.canSetStatus} onClick={async () => { if (await access.execute({ kind: "set-status", userId: user.id, status: user.enabled ? "DISABLED" : "ACTIVE", resourceVersion: user.resourceVersion })) setConfirmStatus(false); }} variant={user.enabled ? "danger" : "primary"}>{user.enabled ? t("confirmDisable") : t("confirmEnable")}</Button>
          <Button disabled={disabled} onClick={() => setConfirmStatus(false)} variant="ghost">{t("cancel")}</Button>
        </div>
      </div></Alert> : null}
    </section>
    {onDelete ? <section className={styles.userSection}>
      <div className={styles.userSectionHeader}>
        <h3>{t("accountRemoval")}</h3>
        <Button disabled={disabled || !user.canDelete} onClick={onDelete} size="small" variant="danger">{t("deleteUser")}</Button>
      </div>
      <p className={styles.note}>{user.canDelete ? t("deleteUserShortImpact") : restriction(user.deleteRestrictionReason)}</p>
    </section> : null}
  </div>;
}
