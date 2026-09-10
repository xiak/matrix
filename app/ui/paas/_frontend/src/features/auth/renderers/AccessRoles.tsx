"use client";
import { useEffect, useId, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, EmptyState, FormField, Table, Tabs, TextArea } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccountAccessView } from "../domain/accounts";
import type { AccessRole, AccessWorkspace } from "../domain/accessWorkspace";
import { roleTrustDocument, validateRoleTrust, type RoleTrust } from "../domain/roleTrust";
import { formatPolicyResource } from "../domain/policyLanguage";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceCollection, WorkspaceDelete, WorkspaceDetail, WorkspaceDialog, WorkspaceSelection, WorkspaceTime } from "./AccessWorkspaceUi";
import { RoleSessionSettings, RoleTags, RoleTrustFields } from "./RoleConfiguration";
import { PermissionBoundary } from "./PermissionBoundary";
import { RoleSessions } from "./RoleSessions";
import styles from "./AccountAccessRenderer.module.css";

function RoleMetadataEditor({ role, onClose }: { role: AccessRole; onClose(): void }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), access = useAccountAccess(), id = useId();
  const [description, setDescription] = useState(role.description), [tags, setTags] = useState(role.tags);
  return <WorkspaceDialog title={t("editMetadata")} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "update-role-metadata", id: role.id, description, tags }))}><p>{role.name}</p><FormField id={id} label={w("description")}><TextArea id={id} maxLength={256} rows={3} value={description} onChange={(event) => setDescription(event.target.value)} /></FormField><RoleTags value={tags} onChange={setTags} /></WorkspaceDialog>;
}
function RoleTrustReview({ role, proposed, workspace, scene }: { role: AccessRole; proposed: RoleTrust; workspace: AccessWorkspace; scene: AccountAccessScene }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace");
  const subjects = (trust: RoleTrust) => trust.principalType === "account" ? trust.trustedUserIds : [trust.principal];
  const previous = subjects(role), next = subjects(proposed);
  const name = (id: string) => role.principalType === "account" ? scene.users.find((user) => user.id === id)?.loginName ?? id : workspace.providers.find((provider) => provider.id === id)?.name ?? id;
  return <div className={styles.stack}>
    <h3 className={styles.stepTitle} tabIndex={-1}>{t("reviewTrust")}</h3>
    <div><strong>{role.name}</strong><p className={styles.note}>{role.id}</p></div>
    <Alert status="warning">{t("trustChangeHint")}</Alert>
    <div className={styles.policyComparison}>{(["before", "after"] as const).map((side) => <Card key={side} aria-label={t(side)}>
      <Card.Header><h4 className={styles.stepTitle}>{t(side)}</h4></Card.Header>
      <Card.Body><p className={styles.note}>{w(role.principalType === "service" ? "servicePrincipal" : role.principalType)}</p>
        <ul className={styles.bindingList}>{(side === "before" ? previous : next).map((id) => <li key={id}>
          <div><strong>{name(id)}</strong>{name(id) !== id ? <p className={styles.note}>{id}</p> : null}</div>
          {side === "before" && !next.includes(id) ? <Badge status="warning">{t("removedTrust")}</Badge> : side === "after" && !previous.includes(id) ? <Badge status="success">{t("addedTrust")}</Badge> : null}
        </li>)}</ul>
      </Card.Body>
    </Card>)}</div>
    <details className={styles.trustDocuments}><summary>{t("compareTrustDocuments")}</summary><div className={styles.policyComparison}>{(["before", "after"] as const).map((side) => <section key={side} className={styles.stack}>
      <h4 className={styles.stepTitle}>{t(side)}</h4><pre className={styles.code} role="region" aria-label={t("trustDocumentSide", { side: t(side) })} tabIndex={0}>{JSON.stringify(roleTrustDocument(side === "before" ? role : proposed), null, 2)}</pre>
    </section>)}</div></details>
    <p className={styles.note}>{t("reviewHint")}</p>
  </div>;
}
function RoleTrustEditor({ role, workspace, scene, onClose }: { role: AccessRole; workspace: AccessWorkspace; scene: AccountAccessScene; onClose(): void }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), access = useAccountAccess();
  const [trust, setTrust] = useState<RoleTrust>(role), [review, setReview] = useState(false), [invalid, setInvalid] = useState(false);
  const stage = useRef<HTMLDivElement>(null), previousReview = useRef(review);
  const changed = role.principal !== trust.principal || role.trustedUserIds.length !== trust.trustedUserIds.length || role.trustedUserIds.some((id) => !trust.trustedUserIds.includes(id));
  useEffect(() => {
    if (previousReview.current === review) return;
    previousReview.current = review;
    stage.current?.querySelector<HTMLElement>(review ? 'h3[tabindex]' : 'input[type="search"], [role="combobox"]:not([disabled])')?.focus();
  }, [review]);
  return <WorkspaceDialog size="wide" title={t("editTrust")} onClose={onClose} submitDisabled={!changed} validationError={invalid ? t("invalidTrust") : undefined} submitLabel={review ? w("save") : t("reviewChange")} onSubmit={async () => {
    try { validateRoleTrust(workspace, trust, scene.users.map((user) => user.id)); } catch { setInvalid(true); return false; }
    setInvalid(false);
    if (!review) { setReview(true); return false; }
    return Boolean(await access.executeWorkspace({ kind: "update-role-trust", id: role.id, principal: trust.principal, trustedUserIds: trust.trustedUserIds }));
  }}>
    <div ref={stage} className={styles.stack}>{review ? <><RoleTrustReview role={role} proposed={trust} workspace={workspace} scene={scene} /><Button variant="ghost" onClick={() => { access.clearWorkspaceError(); setReview(false); }}>{t("backToSelection")}</Button></> : <><RoleTrustFields locked workspace={workspace} users={scene.users.map((user) => ({ id: user.id, name: user.loginName }))} value={trust} onChange={(value) => { setTrust(value); setInvalid(false); access.clearWorkspaceError(); }} />{!changed ? <p className={styles.note}>{t("noTrustChanges")}</p> : null}</>}</div>
  </WorkspaceDialog>;
}
function RoleSettingsEditor({ role, onClose }: { role: AccessRole; onClose(): void }) {
  const t = useTranslations("RoleWorkspace"), access = useAccountAccess();
  const [settings, setSettings] = useState({ sessionMinutes: role.sessionMinutes, consoleAccess: role.consoleAccess });
  return <WorkspaceDialog title={t("editSettings")} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "update-role-settings", id: role.id, ...settings }))}><Alert>{t("settingsChangeHint")}</Alert><RoleSessionSettings value={settings} onChange={setSettings} service={role.principalType === "service"} /></WorkspaceDialog>;
}
function RolePolicyEditor({ role, workspace, mode, onClose }: { role: AccessRole; workspace: AccessWorkspace; mode: "add" | "remove"; onClose(): void }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), access = useAccountAccess();
  const [selected, setSelected] = useState<string[]>([]), [review, setReview] = useState(false);
  const options = mode === "add" ? workspace.policies.filter((policy) => !role.policyIds.includes(policy.id)) : role.policyIds.map((id) => workspace.policies.find((policy) => policy.id === id) ?? { id, name: id });
  return <WorkspaceDialog size="wide" title={t(mode === "add" ? "addPolicies" : "removePolicies")} onClose={onClose} submitDisabled={!selected.length} submitLabel={review ? w("save") : t("reviewChange")} onSubmit={async () => { if (!review) { setReview(true); return false; } return Boolean(await access.executeWorkspace({ kind: "change-role-policies", id: role.id, added: mode === "add" ? selected : [], removed: mode === "remove" ? selected : [] })); }}>
    {review ? <><Alert status="warning">{t("policyChangeHint")}</Alert><p>{t(mode === "add" ? "adding" : "removing")}</p><ul>{selected.map((id) => <li key={id}>{options.find((policy) => policy.id === id)?.name ?? id}</li>)}</ul><Button variant="ghost" onClick={() => setReview(false)}>{t("backToSelection")}</Button></> : <WorkspaceSelection label={w("selectPolicies")} options={options} value={selected} onChange={setSelected} />}
  </WorkspaceDialog>;
}

export function AccessRoles({ workspace, scene, entityId, onCreate, onOpen }: { workspace: AccessWorkspace; scene: AccountAccessScene; entityId?: string; onCreate(): void; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("IamWorkspace"), r = useTranslations("RoleWorkspace"), access = useAccountAccess();
  const [dialog, setDialog] = useState<"metadata" | "trust" | "settings" | "add" | "remove" | null>(null);
  const [deleting, setDeleting] = useState<AccessRole | null>(null);
  const selected = workspace.roles.find((role) => role.id === entityId);
  if (entityId && !selected) return <EmptyState title={t("entityUnavailable")} description={t("entityUnavailableHint")} action={<Button variant="secondary" onClick={() => onOpen("roles")}>{t("back")}</Button>} />;
  const principalLabel = (role: AccessRole) => role.principalType === "provider" ? workspace.providers.find((provider) => provider.id === role.principal)?.name ?? role.principal : role.principal;
  return <>
    {selected ? <WorkspaceDetail title={selected.name} onBack={() => onOpen("roles")} actions={<><Button variant="secondary" onClick={() => setDialog("metadata")}>{r("editMetadata")}</Button><Button variant="ghost" onClick={() => setDeleting(selected)}>{t("delete")}</Button></>}>
      <p className={styles.note}>{selected.description || "—"}</p><dl className={styles.facts}><div><dt>ID</dt><dd>{selected.id}</dd></div><div><dt>{t("principalType")}</dt><dd>{t(selected.principalType === "service" ? "servicePrincipal" : selected.principalType)}</dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div></dl>
      {selected.tags.length ? <div className={styles.actions} aria-label={r("tags")}>{selected.tags.map((tag) => <Badge key={tag.key}>{tag.key} : {tag.value || "—"}</Badge>)}</div> : null}
      <Tabs.Root defaultValue="policies"><Tabs.List aria-label={selected.name}><Tabs.Trigger value="policies">{t("permissions")}</Tabs.Trigger><Tabs.Trigger value="trust">{t("trust")}</Tabs.Trigger><Tabs.Trigger value="sessions">{r("sessions")}</Tabs.Trigger><Tabs.Trigger value="settings">{r("sessionSettings")}</Tabs.Trigger></Tabs.List>
        <Tabs.Content className={styles.stack} value="policies"><div className={styles.actions}><Button variant="secondary" onClick={() => setDialog("add")}>{r("addPolicies")}</Button><Button variant="ghost" disabled={!selected.policyIds.length} onClick={() => setDialog("remove")}>{r("removePolicies")}</Button></div><p className={styles.note}>{r("permissionsHint")}</p><Table aria-label={t("permissions")}><thead><tr><th>{t("name")}</th><th>{t("type")}</th><th>{r("effectiveVersion")}</th></tr></thead><tbody>{selected.policyIds.map((id) => { const policy = workspace.policies.find((policy) => policy.id === id); return <tr key={id}><td><button className={styles.userLink} onClick={() => onOpen("policies", id)}>{policy?.name ?? id}</button><small>{policy?.description}</small></td><td>{policy ? t(policy.kind) : "—"}</td><td>{policy ? "v" + policy.defaultVersion : "—"}</td></tr>; })}</tbody></Table>{!selected.policyIds.length ? <p className={styles.note}>{r("noPermissions")}</p> : null}
          <PermissionBoundary workspace={workspace} value={selected.boundaryPolicyId} onOpen={(id) => onOpen("policies", id)} onSave={(policyId) => access.executeWorkspace({ kind: "set-role-boundary", id: selected.id, policyId })} />
        </Tabs.Content>
        <Tabs.Content className={styles.stack} value="trust"><div><Button variant="secondary" onClick={() => setDialog("trust")}>{r("editTrust")}</Button></div><Alert>{r(`trustHints.${selected.principalType}`)}</Alert><dl className={styles.facts}><div><dt>{t("principal")}</dt><dd>{principalLabel(selected)}</dd></div>{selected.principalType === "account" ? <div><dt>{r("trustedUsers")}</dt><dd><div className={styles.actions}>{selected.trustedUserIds.map((id) => <button key={id} className={styles.userLink} onClick={() => onOpen("users", id)}>{scene.users.find((user) => user.id === id)?.loginName ?? id}</button>)}</div></dd></div> : null}</dl><pre className={styles.code} role="region" aria-label={r("trustDocument")} tabIndex={0}>{JSON.stringify(roleTrustDocument(selected), null, 2)}</pre>{selected.principalType === "account" ? <><p className={styles.note}>{r("requiredAction")}</p><pre className={styles.code}>{JSON.stringify({ action: ["iam:assumeRole"], resource: [formatPolicyResource({ service: "iam", tenant: workspace.accountId, region: "global", type: "role", id: selected.id })] }, null, 2)}</pre></> : null}</Tabs.Content>
        <Tabs.Content value="sessions"><RoleSessions role={selected} workspace={workspace} scene={scene} onOpen={onOpen} /></Tabs.Content>
        <Tabs.Content className={styles.stack} value="settings"><div><Button variant="secondary" onClick={() => setDialog("settings")}>{r("editSettings")}</Button></div><dl className={styles.facts}><div><dt>{t("sessionMinutes")}</dt><dd>{selected.sessionMinutes}</dd></div><div><dt>{t("consoleAccess")}</dt><dd>{t(selected.consoleAccess ? "enabled" : "disabled")}</dd></div></dl><Alert>{r("settingsChangeHint")}</Alert></Tabs.Content>
      </Tabs.Root>
    </WorkspaceDetail> : <WorkspaceCollection title={t("roles")} description={t("roleHint")} items={workspace.roles} keywords={(role) => [role.description, principalLabel(role)].join(" ")} filter={{ label: t("principalType"), options: ["account", "service", "provider"].map((value) => ({ value, label: t(value === "service" ? "servicePrincipal" : value as "account" | "provider") })), matches: (role, value) => role.principalType === value }} create={{ label: t("createRole"), onClick: onCreate }} columns={[t("name"), t("principalType"), t("principal"), t("created"), t("actions")]} row={(role) => <><td><button className={styles.userLink} onClick={() => onOpen("roles", role.id)}>{role.name}</button><small>{role.description}</small></td><td>{t(role.principalType === "service" ? "servicePrincipal" : role.principalType)}</td><td>{principalLabel(role)}</td><td><WorkspaceTime value={role.createdAt} /></td><td><Button size="small" variant="ghost" onClick={() => setDeleting(role)}>{t("delete")}</Button></td></>} />}
    {selected && dialog === "metadata" ? <RoleMetadataEditor role={selected} onClose={() => setDialog(null)} /> : null}
    {selected && dialog === "trust" ? <RoleTrustEditor role={selected} workspace={workspace} scene={scene} onClose={() => setDialog(null)} /> : null}
    {selected && dialog === "settings" ? <RoleSettingsEditor role={selected} onClose={() => setDialog(null)} /> : null}
    {selected && (dialog === "add" || dialog === "remove") ? <RolePolicyEditor role={selected} workspace={workspace} mode={dialog} onClose={() => setDialog(null)} /> : null}
    {deleting ? <WorkspaceDelete name={deleting.name} impact={<Alert status="warning">{r("deleteImpact")}</Alert>} onClose={() => setDeleting(null)} onConfirm={async () => { const result = await access.executeWorkspace({ kind: "delete-role", id: deleting.id }); if (result && entityId === deleting.id) onOpen("roles"); return result; }} /> : null}
  </>;
}
