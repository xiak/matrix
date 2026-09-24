"use client";
import { useCallback, useEffect, useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Badge, Button, EmptyState, FormField, Input, PageSkeleton, Table, Tabs } from "@ui/xiak";
import { useAccountAccess, type UserBoundarySnapshot } from "../application/AccountAccessProvider";
import type { AccountAccessView } from "../domain/accounts";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessScene, AccountUserScene } from "../scenes/accountAccessScene";
import { WorkspaceDelete, WorkspaceDetail, WorkspaceDialog } from "./AccessWorkspaceUi";
import { AccessCredentials } from "./AccessCredentials";
import { UserAccessDialog, UserAccessManagement } from "./AccountUserDialogs";
import { LivePermissionBoundary, PermissionBoundary } from "./PermissionBoundary";
import { UserAssociationWorkflow } from "./UserAssociationWorkflow";
import styles from "./AccountAccessRenderer.module.css";

export function AccountUserAccessMethods({ user, workspace }: { user: AccountUserScene; workspace: AccessWorkspace | null }) {
  const t = useTranslations("UserWizard");
  const a = useTranslations("AccountAccess");
  const profile = workspace?.userProfiles[user.id];
  return <ul className={styles.accessMethods}>
    <li data-enabled={profile?.consoleAccess}><span>{t("consoleAccess")}</span><span>{profile ? t(profile.consoleAccess ? "enabled" : "disabled") : workspace ? a("accessUnknown") : a("accessUnsupported")}</span></li>
    <li data-enabled={profile?.programmaticAccess}><span>{t("programmaticAccess")}</span><span>{profile ? t(profile.programmaticAccess ? "enabled" : "disabled") : workspace ? a("accessUnknown") : a("accessUnsupported")}</span></li>
  </ul>;
}

export function AccountLiveUserWorkspace({ summary, onBack }: { summary: AccountUserScene; onBack(): void }) {
  const t = useTranslations("AccountAccess");
  const w = useTranslations("IamWorkspace");
  const { loadUser, permissionBoundaries } = useAccountAccess();
  const [loaded, setLoaded] = useState<{ state: "loading" } | { state: "ready"; user: AccountUserScene; boundary?: UserBoundarySnapshot } | { state: "error" }>({ state: "loading" });
  const boundaryChanged = useCallback((boundary: UserBoundarySnapshot) => setLoaded({ state: "ready", user: boundary.user, boundary }), []);
  useEffect(() => {
    let current = true;
    const read = permissionBoundaries ? permissionBoundaries.load(summary.id).then((boundary) => ({ state: "ready" as const, user: boundary.user, boundary })) : loadUser(summary.id).then((user) => ({ state: "ready" as const, user }));
    void read.then(
      (result) => { if (current) setLoaded(result); },
      () => { if (current) setLoaded({ state: "error" }); }
    );
    return () => { current = false; };
  }, [loadUser, permissionBoundaries, summary.id, summary.resourceVersion]);
  if (loaded.state === "loading") return <WorkspaceDetail title={summary.loginName} onBack={onBack}><PageSkeleton label={t("loadingUser")} layout="access" /></WorkspaceDetail>;
  if (loaded.state === "error") return <WorkspaceDetail title={summary.loginName} onBack={onBack}><EmptyState title={w("entityUnavailable")} description={w("entityUnavailableHint")} action={<Button variant="secondary" onClick={onBack}>{w("back")}</Button>} /></WorkspaceDetail>;
  return <WorkspaceDetail title={loaded.user.loginName} onBack={onBack}>
    <UserAccessManagement key={`${loaded.user.id}:${loaded.user.resourceVersion}`} deleteAction profileActions showLiveEvidenceBoundary user={loaded.user} onDeleted={onBack} />
    {permissionBoundaries && loaded.boundary ? <LivePermissionBoundary key={`${permissionBoundaries.accountId}:${loaded.user.id}`} client={permissionBoundaries} snapshot={loaded.boundary} onChanged={boundaryChanged} /> : null}
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
  return <WorkspaceDialog title={t("edit") + " · " + user.loginName} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "update-user", principalId: user.id, displayName: name }))}><FormField id={id} label={t("name")}><Input id={id} required maxLength={128} value={name} onChange={(event) => setName(event.target.value)} /></FormField></WorkspaceDialog>;
}

export function AccountUserWorkspace({ user, scene, workspace, onBack, onOpen }: { user: AccountUserScene; scene: AccountAccessScene; workspace: AccessWorkspace; onBack(): void; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("IamWorkspace");
  const a = useTranslations("AccountAccess");
  const wizard = useTranslations("UserWizard");
  const access = useAccountAccess();
  const [dialog, setDialog] = useState<"security" | "edit" | "delete" | null>(null);
  const [association, setAssociation] = useState<"groups" | "policies" | null>(null);
  const groups = workspace.groups.filter((group) => group.memberIds.includes(user.id));
  const direct = workspace.userPolicies[user.id] ?? [];
  const inherited = [...new Set(groups.flatMap((group) => group.policyIds))];
  const profile = workspace.userProfiles[user.id];
  if (association) return <UserAssociationWorkflow user={user} workspace={workspace} kind={association} onBack={() => setAssociation(null)} />;
  return <><WorkspaceDetail title={user.loginName} onBack={onBack} actions={{ primary: { id: "edit", label: t("edit"), variant: "secondary", onSelect: () => setDialog("edit") }, secondary: [{ id: "delete", label: t("delete"), danger: true, disabled: user.protected, disabledReason: user.protected ? a("protectedHint") : undefined, onSelect: () => setDialog("delete") }] }}>
    <div className={styles.userSummary}><div><strong>{user.name}</strong><span className={styles.note}>{user.qualifiedName}</span></div><div className={styles.roleTags}><Badge>{a("child")}</Badge><Badge status={user.enabled ? "success" : "neutral"}>{a(`states.${user.state}`)}</Badge></div></div>
    <Tabs.Root defaultValue="identity"><Tabs.List aria-label={user.loginName}><Tabs.Trigger value="identity">{a("identityInfo")}</Tabs.Trigger><Tabs.Trigger value="access">{a("accessMethods")}</Tabs.Trigger><Tabs.Trigger value="policies">{t("permissions")}</Tabs.Trigger><Tabs.Trigger value="groups">{t("userGroups")}</Tabs.Trigger><Tabs.Trigger value="security">{t("securitySettings")}</Tabs.Trigger><Tabs.Trigger value="keys">{t("keys")}</Tabs.Trigger></Tabs.List>
      <Tabs.Content className={styles.stack} value="identity"><dl className={styles.facts}>
        <div><dt>{a("userType")}</dt><dd>{a("child")}</dd></div><div><dt>{a("ownership")}</dt><dd>{scene.accountName}</dd></div><div><dt>{a("tenantId")}</dt><dd>{scene.accountId}</dd></div><div><dt>{a("userId")}</dt><dd>{user.id}</dd></div><div><dt>{a("currentLoginName")}</dt><dd>{user.loginName}</dd></div><div><dt>{a("qualifiedLogin")}</dt><dd>{user.qualifiedName}</dd></div>
        {profile ? <div><dt>{wizard("steps.tags")}</dt><dd>{profile.tags.map((tag) => <Badge key={tag.key}>{tag.key} : {tag.value || "—"}</Badge>)}{!profile.tags.length ? wizard("none") : null}</dd></div> : null}
      </dl><p className={styles.note}>{a("subuserOwnershipHint")}</p></Tabs.Content>
      <Tabs.Content className={styles.stack} value="access"><AccountUserAccessMethods user={user} workspace={workspace} /><p className={styles.note}>{a("accessPermissionHint")}</p><p className={styles.note}>{wizard("keyHint")}</p><p className={styles.note}>{wizard("mockSecurity")}</p></Tabs.Content>
      <Tabs.Content className={styles.stack} value="policies"><div className={styles.actions}><Button variant="secondary" onClick={() => setAssociation("policies")}>{t("associate")}</Button><Button variant="secondary" onClick={() => onOpen("simulator", user.id)}>{t("simulateAccess")}</Button></div><p className={styles.note}>{a("permissionSourceHint")}</p>
        <Table aria-label={t("userPolicies")} mobileLayout="stack"><thead><tr><th scope="col">{t("name")}</th><th scope="col">{t("type")}</th><th scope="col">{t("grantSource")}</th></tr></thead><tbody>{workspace.policies.filter((policy) => direct.includes(policy.id) || inherited.includes(policy.id)).map((policy) => <tr key={policy.id}><td data-label={t("name")}><button className={styles.userLink} onClick={() => onOpen("policies", policy.id)}>{policy.name}</button><small>{policy.description}</small></td><td data-label={t("type")}>{t(policy.kind)}</td><td data-label={t("grantSource")}><div className={styles.stack}>{direct.includes(policy.id) ? <span>{t("directPolicies")}</span> : null}{groups.filter((group) => group.policyIds.includes(policy.id)).map((group) => <button key={group.id} className={styles.userLink} onClick={() => onOpen("groups", group.id)}>{t("inheritedFrom", { name: group.name })}</button>)}</div></td></tr>)}</tbody></Table>{!direct.length && !inherited.length ? <p className={styles.note}>{t("noSelection")}</p> : null}
        <PermissionBoundary owner="user" workspace={workspace} value={workspace.userBoundaries[user.id]} onSave={(policyId) => access.executeWorkspace({ kind: "set-user-boundary", principalId: user.id, policyId })} onOpen={(id) => onOpen("policies", id)} />
      </Tabs.Content>
      <Tabs.Content className={styles.stack} value="groups"><div><Button variant="secondary" onClick={() => setAssociation("groups")}>{t("edit")}</Button></div><Table aria-label={t("userGroups")} mobileLayout="stack"><thead><tr><th scope="col">{t("name")}</th><th scope="col">{t("permissions")}</th></tr></thead><tbody>{groups.map((group) => <tr key={group.id}><td data-label={t("name")}><button className={styles.userLink} onClick={() => onOpen("groups", group.id)}>{group.name}</button><small>{group.description}</small></td><td data-label={t("permissions")}>{group.policyIds.length}</td></tr>)}</tbody></Table>{!groups.length ? <p className={styles.note}>{t("empty")}</p> : null}</Tabs.Content>
      <Tabs.Content className={styles.stack} value="security"><dl className={styles.facts}><div><dt>{a("status")}</dt><dd>{a(`states.${user.state}`)}</dd></div>{profile ? <><div><dt>{wizard("forceReset")}</dt><dd>{wizard(profile.passwordResetRequired ? "enabled" : "disabled")}</dd></div><div><dt>{wizard("loginProtection")}</dt><dd>{wizard(profile.loginProtection ? "enabled" : "disabled")}</dd></div></> : null}<div><dt>{a("directPolicyAttachments")}</dt><dd>{user.attachments.map((attachment) => attachment.label).join(" · ") || a("noGrantLabel")}</dd></div></dl><p className={styles.note}>{wizard("mockSecurity")}</p>{user.protected ? <p className={styles.note}>{a("protectedHint")}</p> : null}<div><Button variant="secondary" onClick={() => setDialog("security")}>{a("manage")}</Button></div></Tabs.Content>
      <Tabs.Content value="keys"><AccessCredentials embedded scene={{ ...scene, users: [user] }} workspace={{ ...workspace, keys: workspace.keys.filter((key) => key.ownerId === user.id) }} /></Tabs.Content>
    </Tabs.Root>
  </WorkspaceDetail>
  {dialog === "security" ? <UserAccessDialog user={user} onClose={() => setDialog(null)} /> : null}
  {dialog === "edit" ? <UserEditor user={user} onClose={() => setDialog(null)} /> : null}
  {dialog === "delete" ? <WorkspaceDelete name={user.loginName} onClose={() => setDialog(null)} onConfirm={async () => { const result = await access.executeWorkspace({ kind: "delete-user", principalId: user.id }); if (result) onBack(); return result; }} /> : null}
  </>;
}
