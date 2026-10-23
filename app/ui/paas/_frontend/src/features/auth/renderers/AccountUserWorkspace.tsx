"use client";
import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, EmptyState, FormField, Input, Table, TableSkeleton, Tabs } from "@ui/xiak";
import { requestToken } from "@/infrastructure/http/jsonRequest";
import { UserDeletionRecoveryUnavailable, UserDeletionRejected, useAccountAccess, type UserBoundarySnapshot, type UserDeletionClient } from "../application/AccountAccessProvider";
import { useUserManagementMutation } from "../application/userManagementMutation";
import { UserManagementEditor, UserManagementReceiptNotice } from "./UserManagementCommand";
import type { AccountAccessView, UserDeletion, UserDeletionIntent } from "../domain/accounts";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import { containsDenyStatement } from "../domain/policyDocument";
import type { AccountAccessScene, AccountUserScene } from "../scenes/accountAccessScene";
import { AuthorizationOverview, WorkspaceDelete, WorkspaceDetail, WorkspaceInlineForm, WorkspaceRelationshipDirectory, WorkspaceTime } from "./AccessWorkspaceUi";
import { AccessCredentials } from "./AccessCredentials";
import { UserAccessManagement, UserAccessWorkspace } from "./AccountUserDialogs";
import { LivePermissionBoundary, PermissionBoundary } from "./PermissionBoundary";
import { UserAssociationWorkflow } from "./UserAssociationWorkflow";
import styles from "./AccountAccessRenderer.module.css";

export type AccountUserDetailTab = "identity" | "access" | "policies" | "groups" | "security" | "keys";

export function AccountUserAccessMethods({ user, workspace }: { user: AccountUserScene; workspace: AccessWorkspace | null }) {
  const t = useTranslations("UserWizard");
  const a = useTranslations("AccountAccess");
  const profile = workspace?.userProfiles[user.id];
  return <ul className={styles.accessMethods}>
    <li data-enabled={profile?.consoleAccess}><span>{t("consoleAccess")}</span><span>{profile ? t(profile.consoleAccess ? "enabled" : "disabled") : workspace ? a("accessUnknown") : a("accessSwitchUnreported")}</span></li>
    <li data-enabled={profile?.programmaticAccess}><span>{t("programmaticAccess")}</span><span>{profile ? t(profile.programmaticAccess ? "enabled" : "disabled") : workspace ? a("accessUnknown") : a("accessSwitchUnreported")}</span></li>
  </ul>;
}

function AccountUserSnapshot({ user, busy, children }: { user: AccountUserScene; busy: boolean; children?: ReactNode }) {
  const t = useTranslations("AccountAccess");
  return <div className={styles.detail} aria-busy={busy || undefined}>
    <div className={styles.userSummary}>
      <div><strong>{user.name}</strong><span className={styles.note}>{user.qualifiedName}</span></div>
      <Badge status={user.enabled ? "success" : "neutral"}>{t(`states.${user.state}`)}</Badge>
    </div>
    <dl className={styles.facts}>
      <div><dt>{t("userType")}</dt><dd>{t("child")}</dd></div>
      <div><dt>{t("ownership")}</dt><dd>{user.accountId}</dd></div>
      <div><dt>{t("userId")}</dt><dd>{user.id}</dd></div>
    </dl>
    <p className={styles.note}>{t("subuserOwnershipHint")}</p>
    {children}
  </div>;
}

type LiveUserWorkspaceProps = {
  userId: string;
  summary?: AccountUserScene;
  initialSection?: Extract<AccountUserDetailTab, "policies" | "keys">;
  onBack(): void;
};

type LiveUserDeletionReceipt = {
  client: UserDeletionClient;
  requestId: string;
  result: UserDeletion;
};

function LiveUserDeletionReceiptView({ receipt }: { receipt: LiveUserDeletionReceipt }) {
  const t = useTranslations("AccountAccess");
  return <Alert status="success" role="status" aria-label={t("userDeleteReceiptTitle")}>
    <strong>{t("userDeleteReceiptTitle")}</strong>
    <p>{t("userDeleteReceiptHint")}</p>
    <dl className={styles.facts}>
      <div><dt>{t("userDeleteReceiptLoginName")}</dt><dd>{receipt.result.loginName}</dd></div>
      <div><dt>{t("userDeleteReceiptId")}</dt><dd><code>{receipt.result.id}</code></dd></div>
      <div><dt>{t("userDeleteReceiptRequest")}</dt><dd><code>{receipt.requestId}</code></dd></div>
      <div><dt>{t("userDeleteReceiptRevision")}</dt><dd>{receipt.result.resourceVersion}</dd></div>
      <div><dt>{t("userDeleteReceiptTime")}</dt><dd><WorkspaceTime value={receipt.result.deletedAt} /></dd></div>
    </dl>
  </Alert>;
}

export function LiveUserDeletionUnknownView({ intent }: { intent: UserDeletionIntent }) {
  const t = useTranslations("AccountAccess");
  return <Alert status="warning" role="alert" aria-label={t("userDeleteUnknownTitle")}>
    <strong>{t("userDeleteUnknownTitle")}</strong>
    <p>{t("userDeleteUnknownHint")}</p>
    <dl className={styles.facts}>
      <div><dt>{t("userDeleteReceiptLoginName")}</dt><dd>{intent.loginName}</dd></div>
      <div><dt>{t("userDeleteReceiptId")}</dt><dd><code>{intent.userId}</code></dd></div>
      <div><dt>{t("userDeleteReceiptRequest")}</dt><dd><code>{intent.commandRequestId}</code></dd></div>
      <div><dt>{t("userDeleteSourceRevision")}</dt><dd>{intent.expectedResourceVersion}</dd></div>
    </dl>
  </Alert>;
}

function LiveUserDelete({ user, client, onClose, onDeleted, onUnknown }: {
  user: AccountUserScene;
  client: UserDeletionClient;
  onClose(): void;
  onDeleted(receipt: LiveUserDeletionReceipt): void;
  onUnknown(): void;
}) {
  const t = useTranslations("AccountAccess");
  const intent = useRef<{ resourceVersion: number; requestId: string; expectedLoginName: string } | null>(null);
  const currentClientIdentity = useRef<string | null>(client.identity);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();
  useLayoutEffect(() => { currentClientIdentity.current = client.identity; return () => { currentClientIdentity.current = null; }; }, [client.identity]);
  const confirm = async () => {
    if (busy || intent.current) return false;
    const frozen = { resourceVersion: user.resourceVersion, requestId: requestToken("ui-user-delete-"), expectedLoginName: user.loginName };
    intent.current = frozen;
    setBusy(true);
    setError(undefined);
    try {
      const result = await client.delete(user.id, frozen);
      if (currentClientIdentity.current !== client.identity) return false;
      if (result.accountId !== client.accountId || result.id !== user.id || result.loginName !== user.loginName ||
          result.resourceVersion !== user.resourceVersion + 1 || !Number.isFinite(Date.parse(result.deletedAt))) {
        throw new Error("INVALID_IAM_USER_DELETION");
      }
      onDeleted({ client, requestId: frozen.requestId, result: structuredClone(result) });
      return true;
    } catch (failure) {
      if (currentClientIdentity.current !== client.identity) return false;
      if (failure instanceof UserDeletionRecoveryUnavailable) {
        setError(t("userDeleteRecoveryUnavailable"));
        return false;
      }
      if (failure instanceof UserDeletionRejected) {
        if (failure.reason === "expired") {
          client.expire();
          return false;
        }
        intent.current = null;
        setError(t(`errors.${failure.reason}`));
        return false;
      }
      onUnknown();
      return true;
    } finally {
      setBusy(false);
    }
  };
  return <WorkspaceDelete name={user.loginName} onClose={onClose} onConfirm={confirm}
    hint={t("userDeleteLiveConfirmHint")}
    impact={<Alert status="warning">{t("deleteUserImpact")}</Alert>}
    operation={{ busy, error, clearError: () => setError(undefined) }} />;
}

export function AccountLiveUserWorkspace(props: LiveUserWorkspaceProps) {
  const { userDeletion, userManagement } = useAccountAccess();
  return <LiveUserWorkspace key={`${userManagement?.identity ?? "read"}:${userDeletion?.identity ?? "no-delete"}:${props.userId}`} {...props} />;
}

function LiveUserWorkspace({ userId, summary, initialSection, onBack }: LiveUserWorkspaceProps) {
  const t = useTranslations("AccountAccess");
  const w = useTranslations("IamWorkspace");
  const management = useTranslations("UserManagementCommand");
  const access = useAccountAccess();
  const { loadUser, permissionBoundaries, userDeletion, userManagement } = access;
  const command = useUserManagementMutation(userManagement, userId);
  const [workflow, setWorkflow] = useState<"rename" | "status" | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleted, setDeleted] = useState<LiveUserDeletionReceipt | null>(null);
  const unknown = access.userDeletionUnknowns.find((intent) => intent.userId === userId) ?? null;
  const deletionNavigationStarted = useRef(false);
  const renameRef = useRef<HTMLButtonElement>(null), statusRef = useRef<HTMLButtonElement>(null);
  const returnAction = useRef<"rename" | "status" | null>(null);
  const [loadVersion, setLoadVersion] = useState(0);
  const owner = useMemo(() => ({ loadUser, permissionBoundaries, userId, loadVersion }), [loadUser, loadVersion, permissionBoundaries, userId]);
  type UserRead = { state: "loading" } | { state: "ready"; user: AccountUserScene; boundary?: UserBoundarySnapshot } | { state: "error" };
  const [snapshot, setSnapshot] = useState<{ owner: typeof owner; value: UserRead }>({ owner, value: { state: "loading" } });
  const loaded: UserRead = snapshot.owner === owner ? snapshot.value : { state: "loading" };
  const currentOwner = useRef<typeof owner | null>(owner);
  useLayoutEffect(() => { currentOwner.current = owner; return () => { currentOwner.current = null; }; }, [owner]);
  useLayoutEffect(() => {
    if (workflow || command.pending || loaded.state !== "ready" || !returnAction.current) return;
    (returnAction.current === "rename" ? renameRef : statusRef).current?.focus({ preventScroll: true });
    returnAction.current = null;
  }, [command.pending, loaded.state, workflow]);
  const boundaryChanged = useCallback((boundary: UserBoundarySnapshot) => {
    if (currentOwner.current === owner) setSnapshot({ owner, value: { state: "ready", user: boundary.user, boundary } });
  }, [owner]);
  useEffect(() => {
    let current = true;
    const read = permissionBoundaries ? permissionBoundaries.load(userId).then((boundary) => ({ state: "ready" as const, user: boundary.user, boundary })) : loadUser(userId).then((user) => ({ state: "ready" as const, user }));
    void read.then(
      (result) => { if (current) setSnapshot({ owner, value: result }); },
      () => { if (current) setSnapshot({ owner, value: { state: "error" } }); }
    );
    return () => { current = false; };
  }, [loadUser, owner, permissionBoundaries, userId]);
  const title = summary?.loginName ?? userId;
  const finishDeletion = useCallback(() => {
    if (deletionNavigationStarted.current) return;
    deletionNavigationStarted.current = true;
    access.reload();
    onBack();
  }, [access, onBack]);
  if (deleted) return <WorkspaceDetail title={`${t("userDeleteReceiptTitle")} · ${deleted.result.loginName}`} onBack={finishDeletion} backLabel={t("userDeleteFinish")}>
    <LiveUserDeletionReceiptView receipt={deleted} />
  </WorkspaceDetail>;
  if (unknown) return <WorkspaceDetail title={`${t("userDeleteUnknownTitle")} · ${unknown.loginName}`} onBack={finishDeletion} backLabel={t("userDeleteUnknownFinish")}>
    <LiveUserDeletionUnknownView intent={unknown} />
  </WorkspaceDetail>;
  const completed = () => { setWorkflow(null); setLoadVersion((current) => current + 1); };
  const commandFeedback = <>{loaded.state === "ready" && !userManagement ? <Alert>{management("readOnlyUnavailable")}</Alert> : null}
    {command.recoveryError ? <Alert status="danger">{management("storageUnavailable")}</Alert> : null}
    {command.receipt ? <UserManagementReceiptNotice receipt={command.receipt} /> : null}
    {command.error === "conflict" || command.error === "forbidden" ? <Alert status="warning">{management("staleReview")}</Alert> : null}</>;
  if (command.pending || workflow && loaded.state === "ready") return <WorkspaceDetail title={title} onBack={onBack}>
    <UserManagementEditor userId={userId} user={loaded.state === "ready" ? loaded.user : undefined} mode={workflow ?? (command.pending?.operation === "USER_UPDATE" ? "rename" : "status")} command={command}
      onClose={command.pending ? onBack : () => setWorkflow(null)} onCompleted={completed} onStale={completed} />
  </WorkspaceDetail>;
  if (loaded.state === "loading") return <WorkspaceDetail title={title} onBack={onBack}>{commandFeedback}{summary && !command.receipt ? <AccountUserSnapshot user={summary} busy>
    <TableSkeleton label={t("loadingUser")} rows={3} header={false} />
  </AccountUserSnapshot> : <TableSkeleton label={t("loadingUser")} rows={3} header={false} />}</WorkspaceDetail>;
  if (loaded.state === "error") return <WorkspaceDetail title={title} onBack={onBack}>
    {commandFeedback}
    {summary && !command.receipt ? <AccountUserSnapshot user={summary} busy={false} /> : null}
    <EmptyState title={w("entityUnavailable")} description={w("entityUnavailableHint")} action={<div className={styles.actions}>
      <Button onClick={() => setLoadVersion((current) => current + 1)}>{t("retryUser")}</Button>
      <Button variant="secondary" onClick={onBack}>{w("back")}</Button>
    </div>} />
  </WorkspaceDetail>;
  return <WorkspaceDetail title={loaded.user.loginName} onBack={onBack}>
    {commandFeedback}
    <UserAccessManagement key={`${loaded.user.id}:${loaded.user.resourceVersion}`} showLiveEvidenceBoundary initialSection={initialSection} user={loaded.user}
      onDelete={userDeletion && !access.userDeletionRecoveryError && !unknown ? () => setDeleting(true) : undefined} renameActionRef={renameRef} statusActionRef={statusRef}
      managementCommands={{ disabled: !command.ready || !userManagement,
        onRename() { returnAction.current = "rename"; setWorkflow("rename"); }, onStatus() { returnAction.current = "status"; setWorkflow("status"); } }} />
    {permissionBoundaries && loaded.boundary ? <LivePermissionBoundary key={`${permissionBoundaries.accountId}:${loaded.user.id}`} client={permissionBoundaries} snapshot={loaded.boundary} onChanged={boundaryChanged} /> : null}
    {deleting && userDeletion ? <LiveUserDelete key={`${userDeletion.identity}:${loaded.user.id}`} user={loaded.user} client={userDeletion}
      onClose={() => setDeleting(false)} onDeleted={setDeleted} onUnknown={() => setDeleting(false)} /> : null}
  </WorkspaceDetail>;
}

export function AccountPrimaryWorkspace({ scene, onBack, onOpen }: { scene: AccountAccessScene; onBack(): void; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("AccountAccess");
  const w = useTranslations("IamWorkspace");
  const primary = scene.accountOwner;
  return <WorkspaceDetail title={primary.loginName} onBack={onBack} actions={{ primary: { id: "settings", label: t("settings"), variant: "secondary", onSelect: () => onOpen("settings") } }}>
    <div className={styles.userSummary}><div><strong>{primary.name ?? t("resourceOwner")}</strong><span className={styles.note}>{scene.accountName}</span></div><Badge>{t("primary")}</Badge></div>

    <Tabs.Root defaultValue="identity"><Tabs.List aria-label={primary.loginName}><Tabs.Trigger value="identity">{t("identityInfo")}</Tabs.Trigger><Tabs.Trigger value="access">{t("accessMethods")}</Tabs.Trigger><Tabs.Trigger value="permissions">{w("permissions")}</Tabs.Trigger></Tabs.List>
      <Tabs.Content className={styles.stack} value="identity"><dl className={styles.facts}>
        <div><dt>{t("userType")}</dt><dd>{t("primary")}{primary.isCurrent ? ` · ${t("signedIn")}` : ""}</dd></div>
        <div><dt>{t("ownership")}</dt><dd>{scene.accountName}</dd></div>
        <div><dt>{t("tenantId")}</dt><dd>{scene.accountId}</dd></div>
        <div><dt>{t("userId")}</dt><dd>{primary.id}</dd></div>
        <div><dt>{t("currentLoginName")}</dt><dd>{primary.loginName}</dd></div>
        <div><dt>{t("status")}</dt><dd>{primary.state ? t(`states.${primary.state}`) : t("unknown")}</dd></div>
      </dl></Tabs.Content>
      <Tabs.Content className={styles.stack} value="access"><dl className={styles.facts}><div><dt>{t("accessMethods")}</dt><dd>{t("primaryConsoleAccess")}</dd></div></dl><p className={styles.note}>{t("primaryCredentialsHint")}</p></Tabs.Content>
      <Tabs.Content className={styles.stack} value="permissions"><section className={styles.identitySection}><h3>{t("resourceOwner")}</h3><p className={styles.note}>{t("ownerPermissionsHint")}</p><p className={styles.note}>{t("rootIdentityBoundaryHint")}</p></section></Tabs.Content>
    </Tabs.Root>
  </WorkspaceDetail>;
}

function UserEditor({ user, onClose }: { user: AccountUserScene; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const [name, setName] = useState(user.name);
  return <WorkspaceInlineForm title={t("edit") + " · " + user.loginName} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "update-user", principalId: user.id, displayName: name }))}><FormField id={id} label={t("name")}><Input id={id} required maxLength={128} value={name} onChange={(event) => setName(event.target.value)} /></FormField></WorkspaceInlineForm>;
}

export function AccountUserWorkspace({ user, scene, workspace, initialTab = "identity", onBack, onOpen, onDelete }: { user: AccountUserScene; scene: AccountAccessScene; workspace: AccessWorkspace; initialTab?: AccountUserDetailTab; onBack(): void; onOpen(view: AccountAccessView, id?: string): void; onDelete(): void }) {
  const t = useTranslations("IamWorkspace");
  const a = useTranslations("AccountAccess");
  const wizard = useTranslations("UserWizard");
  const relationship = useTranslations("RelationshipDirectory");
  const access = useAccountAccess();
  const [workflow, setWorkflow] = useState<"security" | "edit" | null>(null);
  const [activeTab, setActiveTab] = useState<AccountUserDetailTab>(initialTab);
  const [focusDetailHeading, setFocusDetailHeading] = useState(true);
  const editActionFocus = useRef<{ focus(): void }>(null);
  const previousEditing = useRef(false);
  const securityActionFocus = useRef<HTMLButtonElement>(null);
  const previousSecurity = useRef(false);
  const [association, setAssociation] = useState<"groups" | "policies" | null>(null);
  const groups = workspace.groups.filter((group) => group.memberIds.includes(user.id));
  const direct = workspace.userPolicies[user.id] ?? [];
  const inherited = [...new Set(groups.flatMap((group) => group.policyIds))];
  const attachedPolicies = workspace.policies.filter((policy) => direct.includes(policy.id) || inherited.includes(policy.id));
  const policiesWithDeny = new Set(attachedPolicies.filter((policy) => {
    const document = policy.versions.find((version) => version.id === policy.defaultVersion)?.document;
    return document ? containsDenyStatement(document) : false;
  }).map((policy) => policy.id));
  const boundary = workspace.userBoundaries[user.id];
  const profile = workspace.userProfiles[user.id];
  useLayoutEffect(() => {
    const wasEditing = previousEditing.current;
    previousEditing.current = workflow === "edit";
    if (wasEditing && workflow !== "edit") editActionFocus.current?.focus();
  }, [workflow]);
  useEffect(() => {
    const wasSecurity = previousSecurity.current;
    previousSecurity.current = workflow === "security";
    if (wasSecurity && workflow !== "security") securityActionFocus.current?.focus({ preventScroll: true });
  }, [workflow]);
  if (association) return <UserAssociationWorkflow user={user} workspace={workspace} kind={association} onBack={() => setAssociation(null)} />;
  if (workflow === "security") return <UserAccessWorkspace user={user} onClose={() => setWorkflow(null)} />;
  return <WorkspaceDetail title={user.loginName} onBack={onBack} focus={focusDetailHeading} actionFocusRef={editActionFocus} actions={workflow === "edit" ? undefined : { primary: { id: "edit", label: t("edit"), variant: "secondary", onSelect: () => setWorkflow("edit") }, secondary: [{ id: "delete", label: t("delete"), danger: true, disabled: !user.canDelete, disabledReason: !user.canDelete ? a(`restrictions.${user.deleteRestrictionReason ?? "AUTHORITY_REQUIRED"}`) : undefined, onSelect: onDelete }] }}>
    {workflow === "edit" ? <UserEditor user={user} onClose={() => setWorkflow(null)} /> : <>
    <div className={styles.userSummary}><div><strong>{user.name}</strong><span className={styles.note}>{user.qualifiedName}</span></div><div className={styles.roleTags}><Badge>{a("child")}</Badge><Badge status={user.enabled ? "success" : "neutral"}>{a(`states.${user.state}`)}</Badge></div></div>
    <Tabs.Root value={activeTab} onValueChange={(value) => setActiveTab(value as AccountUserDetailTab)}><Tabs.List aria-label={user.loginName}><Tabs.Trigger value="identity">{a("identityInfo")}</Tabs.Trigger><Tabs.Trigger value="access">{a("accessMethods")}</Tabs.Trigger><Tabs.Trigger value="policies">{t("permissions")}</Tabs.Trigger><Tabs.Trigger value="groups">{t("userGroups")}</Tabs.Trigger><Tabs.Trigger value="security">{t("securitySettings")}</Tabs.Trigger><Tabs.Trigger value="keys">{t("keys")}</Tabs.Trigger></Tabs.List>
      <Tabs.Content className={styles.stack} value="identity"><dl className={styles.facts}>
        <div><dt>{a("userType")}</dt><dd>{a("child")}</dd></div><div><dt>{a("ownership")}</dt><dd>{scene.accountName}</dd></div><div><dt>{a("tenantId")}</dt><dd>{scene.accountId}</dd></div><div><dt>{a("userId")}</dt><dd>{user.id}</dd></div><div><dt>{a("currentLoginName")}</dt><dd>{user.loginName}</dd></div><div><dt>{a("qualifiedLogin")}</dt><dd>{user.qualifiedName}</dd></div>
        {profile ? <div><dt>{wizard("steps.tags")}</dt><dd>{profile.tags.map((tag) => <Badge key={tag.key}>{tag.key} : {tag.value || "—"}</Badge>)}{!profile.tags.length ? wizard("none") : null}</dd></div> : null}
      </dl><p className={styles.note}>{a("subuserOwnershipHint")}</p></Tabs.Content>
      <Tabs.Content className={styles.stack} value="access"><AccountUserAccessMethods user={user} workspace={workspace} /><p className={styles.note}>{a("accessPermissionHint")}</p><p className={styles.note}>{wizard("keyHint")}</p><p className={styles.note}>{wizard("mockSecurity")}</p></Tabs.Content>
      <Tabs.Content className={styles.stack} value="policies"><div className={styles.actions}><Button variant="secondary" onClick={() => setAssociation("policies")}>{t("associate")}</Button><Button variant="secondary" onClick={() => onOpen("policy-configuration", user.id)}>{t("policyConfigurationReview")}</Button></div><p className={styles.note}>{a("permissionSourceHint")}</p>
        <AuthorizationOverview title={t("grantOverview")} hint={t("grantOverviewHint")} items={[
          { label: t("directPolicies"), value: <><strong>{direct.length}</strong> {t(direct.length === 1 ? "item" : "items")}</> },
          { label: t("inheritedPolicies"), value: <><strong>{inherited.length}</strong> {t(inherited.length === 1 ? "item" : "items")}</> },
          { label: t("policiesWithDeny"), value: <><strong>{policiesWithDeny.size}</strong> {t(policiesWithDeny.size === 1 ? "item" : "items")}</> },
          { label: t("permissionBoundary"), value: t(boundary ? "configured" : "notConfigured") }
        ]} />
        <WorkspaceRelationshipDirectory title={t("userPolicies")} searchLabel={t("searchUserPolicies")} items={attachedPolicies}
          columns={[t("name"), t("type"), t("documentEffect"), t("grantSource")]} emptyTitle={t("noSelection")}
          status={(shown) => relationship("completeResults", { shown, total: attachedPolicies.length })} footerNote={relationship("completeScope")}
          keywords={(policy) => [policy.description, t(policy.kind), ...groups.filter((group) => group.policyIds.includes(policy.id)).map((group) => group.name)].join(" ")}
          row={(policy, blocked) => <><td><Table.PrimaryAction disabled={blocked} onClick={() => onOpen("policies", policy.id)}>{policy.name}</Table.PrimaryAction><small>{policy.description}</small></td><td>{t(policy.kind)}</td><td><Badge status={policiesWithDeny.has(policy.id) ? "danger" : "neutral"}>{t(policiesWithDeny.has(policy.id) ? "containsDeny" : "allowStatementsOnly")}</Badge></td><td><div className={styles.stack}>{direct.includes(policy.id) ? <span>{t("directPolicies")}</span> : null}{groups.filter((group) => group.policyIds.includes(policy.id)).map((group) => <button key={group.id} className={styles.userLink} disabled={blocked} onClick={() => onOpen("groups", group.id)}>{t("inheritedFrom", { name: group.name })}</button>)}</div></td></>} />
        <PermissionBoundary owner="user" workspace={workspace} value={boundary} onSave={(policyId) => access.executeWorkspace({ kind: "set-user-boundary", principalId: user.id, policyId })} onOpen={(id) => onOpen("policies", id)} />
      </Tabs.Content>
      <Tabs.Content className={styles.stack} value="groups"><div><Button variant="secondary" onClick={() => setAssociation("groups")}>{t("edit")}</Button></div><WorkspaceRelationshipDirectory title={t("userGroups")} searchLabel={t("searchUserGroups")} items={groups}
        columns={[t("name"), t("permissions")]} emptyTitle={t("empty")}
        status={(shown) => relationship("completeResults", { shown, total: groups.length })} footerNote={relationship("completeScope")}
        keywords={(group) => [group.description, ...group.policyIds].join(" ")}
        row={(group, blocked) => <><td><Table.PrimaryAction disabled={blocked} onClick={() => onOpen("groups", group.id)}>{group.name}</Table.PrimaryAction><small>{group.description}</small></td><td>{group.policyIds.length}</td></>} /></Tabs.Content>
      <Tabs.Content className={styles.stack} value="security"><dl className={styles.facts}><div><dt>{a("status")}</dt><dd>{a(`states.${user.state}`)}</dd></div>{profile ? <><div><dt>{wizard("forceReset")}</dt><dd>{wizard(profile.passwordResetRequired ? "enabled" : "disabled")}</dd></div><div><dt>{wizard("loginProtection")}</dt><dd>{wizard(profile.loginProtection ? "enabled" : "disabled")}</dd></div></> : null}<div><dt>{a("directPolicyAttachments")}</dt><dd>{user.attachments.map((attachment) => attachment.label).join(" · ") || a("noGrantLabel")}</dd></div></dl><p className={styles.note}>{wizard("mockSecurity")}</p>{user.protected ? <p className={styles.note}>{a("protectedHint")}</p> : null}<div><Button ref={securityActionFocus} variant="secondary" onClick={() => { setFocusDetailHeading(false); setWorkflow("security"); }}>{a("manage")}</Button></div></Tabs.Content>
      <Tabs.Content value="keys"><AccessCredentials embedded scene={{ ...scene, users: [user] }} workspace={{ ...workspace, keys: workspace.keys.filter((key) => key.ownerId === user.id) }} /></Tabs.Content>
    </Tabs.Root>
    </>}
  </WorkspaceDetail>;
}
