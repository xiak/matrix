"use client";
import { useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Badge, Button, FormField, Input, Table, Tabs } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccountAccessView } from "../domain/accounts";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessScene, AccountUserScene } from "../scenes/accountAccessScene";
import { WorkspaceDelete, WorkspaceDetail, WorkspaceDialog, WorkspaceSelection } from "./AccessWorkspaceUi";
import { AccessCredentials } from "./AccessCredentials";
import { UserAccessDialog } from "./AccountUserDialogs";
import { PermissionBoundary } from "./PermissionBoundary";
import styles from "./AccountAccessRenderer.module.css";

export function AccountUserAccessMethods({ user, workspace }: { user: AccountUserScene; workspace: AccessWorkspace | null }) {
  const t = useTranslations("UserWizard");
  const a = useTranslations("AccountAccess");
  const profile = workspace?.userProfiles[user.id];
  return <ul className={styles.accessMethods}>
    <li data-enabled={profile ? profile.consoleAccess : !workspace}><span>{t("consoleAccess")}</span><span>{profile ? t(profile.consoleAccess ? "enabled" : "disabled") : workspace ? a("accessUnknown") : t("enabled")}</span></li>
    <li data-enabled={profile?.programmaticAccess}><span>{t("programmaticAccess")}</span><span>{profile ? t(profile.programmaticAccess ? "enabled" : "disabled") : workspace ? a("accessUnknown") : a("accessUnsupported")}</span></li>
  </ul>;
}

export function AccountPrimaryWorkspace({ scene, onBack, onOpen }: { scene: AccountAccessScene; onBack(): void; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("AccountAccess");
  const w = useTranslations("IamWorkspace");
  const primary = scene.accountOwner;
  return <WorkspaceDetail title={primary.loginName} onBack={onBack} actions={<Button variant="secondary" onClick={() => onOpen("settings")}>{t("settings")}</Button>}>
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

export function UserAssociations({ user, workspace, kind, onClose }: { user: Pick<AccountUserScene, "id" | "loginName">; workspace: AccessWorkspace; kind: "groups" | "policies"; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const [selection, setSelection] = useState(kind === "groups" ? workspace.groups.filter((group) => group.memberIds.includes(user.id)).map((group) => group.id) : workspace.userPolicies[user.id] ?? []);
  return <WorkspaceDialog title={t(kind === "groups" ? "userGroups" : "userPolicies") + " · " + user.loginName} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace(kind === "groups" ? { kind: "set-user-groups", principalId: user.id, groupIds: selection } : { kind: "set-user-policies", principalId: user.id, policyIds: selection }))}>
    <WorkspaceSelection label={t(kind)} options={workspace[kind]} value={selection} onChange={setSelection} />
  </WorkspaceDialog>;
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
  const [dialog, setDialog] = useState<"security" | "groups" | "policies" | "edit" | "delete" | null>(null);
  const groups = workspace.groups.filter((group) => group.memberIds.includes(user.id));
  const direct = workspace.userPolicies[user.id] ?? [];
  const inherited = [...new Set(groups.flatMap((group) => group.policyIds))];
  const profile = workspace.userProfiles[user.id];
  return <><WorkspaceDetail title={user.loginName} onBack={onBack} actions={<><Button variant="secondary" onClick={() => setDialog("edit")}>{t("edit")}</Button><Button disabled={user.protected} variant="ghost" onClick={() => setDialog("delete")}>{t("delete")}</Button></>}>
    <div className={styles.userSummary}><div><strong>{user.name}</strong><span className={styles.note}>{user.qualifiedName}</span></div><div className={styles.roleTags}><Badge>{a("child")}</Badge><Badge status={user.enabled ? "success" : "neutral"}>{a(`states.${user.state}`)}</Badge></div></div>
    <Tabs.Root defaultValue="identity"><Tabs.List aria-label={user.loginName}><Tabs.Trigger value="identity">{a("identityInfo")}</Tabs.Trigger><Tabs.Trigger value="access">{a("accessMethods")}</Tabs.Trigger><Tabs.Trigger value="policies">{t("permissions")}</Tabs.Trigger><Tabs.Trigger value="groups">{t("userGroups")}</Tabs.Trigger><Tabs.Trigger value="security">{t("securitySettings")}</Tabs.Trigger><Tabs.Trigger value="keys">{t("keys")}</Tabs.Trigger></Tabs.List>
      <Tabs.Content className={styles.stack} value="identity"><dl className={styles.facts}>
        <div><dt>{a("userType")}</dt><dd>{a("child")}</dd></div><div><dt>{a("ownership")}</dt><dd>{scene.accountName}</dd></div><div><dt>{a("tenantId")}</dt><dd>{scene.accountId}</dd></div><div><dt>{a("userId")}</dt><dd>{user.id}</dd></div><div><dt>{a("currentLoginName")}</dt><dd>{user.loginName}</dd></div><div><dt>{a("qualifiedLogin")}</dt><dd>{user.qualifiedName}</dd></div>
        {profile ? <div><dt>{wizard("steps.tags")}</dt><dd>{profile.tags.map((tag) => <Badge key={tag.key}>{tag.key} : {tag.value || "—"}</Badge>)}{!profile.tags.length ? wizard("none") : null}</dd></div> : null}
      </dl><p className={styles.note}>{a("subuserOwnershipHint")}</p></Tabs.Content>
      <Tabs.Content className={styles.stack} value="access"><AccountUserAccessMethods user={user} workspace={workspace} /><p className={styles.note}>{a("accessPermissionHint")}</p><p className={styles.note}>{wizard("keyHint")}</p><p className={styles.note}>{wizard("mockSecurity")}</p></Tabs.Content>
      <Tabs.Content className={styles.stack} value="policies"><div className={styles.actions}><Button variant="secondary" onClick={() => setDialog("policies")}>{t("associate")}</Button><Button variant="secondary" onClick={() => onOpen("simulator", user.id)}>{t("simulateAccess")}</Button><Button variant="ghost" onClick={() => setDialog("security")}>{t("realRoles")}</Button></div><p className={styles.note}>{a("permissionSourceHint")}</p>
        <Table aria-label={t("userPolicies")}><thead><tr><th>{t("name")}</th><th>{t("type")}</th><th>{t("grantSource")}</th></tr></thead><tbody>{workspace.policies.filter((policy) => direct.includes(policy.id) || inherited.includes(policy.id)).map((policy) => <tr key={policy.id}><td><button className={styles.userLink} onClick={() => onOpen("policies", policy.id)}>{policy.name}</button><small>{policy.description}</small></td><td>{t(policy.kind)}</td><td><div className={styles.stack}>{direct.includes(policy.id) ? <span>{t("directPolicies")}</span> : null}{groups.filter((group) => group.policyIds.includes(policy.id)).map((group) => <button key={group.id} className={styles.userLink} onClick={() => onOpen("groups", group.id)}>{t("inheritedFrom", { name: group.name })}</button>)}</div></td></tr>)}</tbody></Table>{!direct.length && !inherited.length ? <p className={styles.note}>{t("noSelection")}</p> : null}
        <PermissionBoundary workspace={workspace} value={workspace.userBoundaries[user.id]} onSave={(policyId) => access.executeWorkspace({ kind: "set-user-boundary", principalId: user.id, policyId })} onOpen={(id) => onOpen("policies", id)} />
      </Tabs.Content>
      <Tabs.Content className={styles.stack} value="groups"><div><Button variant="secondary" onClick={() => setDialog("groups")}>{t("edit")}</Button></div><Table aria-label={t("userGroups")}><thead><tr><th>{t("name")}</th><th>{t("permissions")}</th></tr></thead><tbody>{groups.map((group) => <tr key={group.id}><td><button className={styles.userLink} onClick={() => onOpen("groups", group.id)}>{group.name}</button><small>{group.description}</small></td><td>{group.policyIds.length}</td></tr>)}</tbody></Table>{!groups.length ? <p className={styles.note}>{t("empty")}</p> : null}</Tabs.Content>
      <Tabs.Content className={styles.stack} value="security"><dl className={styles.facts}><div><dt>{a("status")}</dt><dd>{a(`states.${user.state}`)}</dd></div>{profile ? <><div><dt>{wizard("forceReset")}</dt><dd>{wizard(profile.passwordResetRequired ? "enabled" : "disabled")}</dd></div><div><dt>{wizard("loginProtection")}</dt><dd>{wizard(profile.loginProtection ? "enabled" : "disabled")}</dd></div></> : null}<div><dt>{a("directPolicyAttachments")}</dt><dd>{user.attachments.map((attachment) => attachment.label).join(" · ") || a("noGrantLabel")}</dd></div></dl><p className={styles.note}>{wizard("mockSecurity")}</p>{user.protected ? <p className={styles.note}>{a("protectedHint")}</p> : null}<div><Button variant="secondary" onClick={() => setDialog("security")}>{a("manage")}</Button></div></Tabs.Content>
      <Tabs.Content value="keys"><AccessCredentials embedded scene={{ ...scene, users: [user] }} workspace={{ ...workspace, keys: workspace.keys.filter((key) => key.ownerId === user.id) }} /></Tabs.Content>
    </Tabs.Root>
  </WorkspaceDetail>
  {dialog === "security" ? <UserAccessDialog user={user} onClose={() => setDialog(null)} /> : null}
  {dialog === "edit" ? <UserEditor user={user} onClose={() => setDialog(null)} /> : null}
  {dialog === "groups" || dialog === "policies" ? <UserAssociations user={user} workspace={workspace} kind={dialog} onClose={() => setDialog(null)} /> : null}
  {dialog === "delete" ? <WorkspaceDelete name={user.loginName} onClose={() => setDialog(null)} onConfirm={async () => { const result = await access.executeWorkspace({ kind: "delete-user", principalId: user.id }); if (result) onBack(); return result; }} /> : null}
  </>;
}
