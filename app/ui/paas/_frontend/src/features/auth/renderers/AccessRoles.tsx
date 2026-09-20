"use client";
import { useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, EmptyState, FormField, Table, Tabs, TextArea } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccountAccessView } from "../domain/accounts";
import type { AccessRole, AccessWorkspace } from "../domain/accessWorkspace";
import { roleTrustDocument, validateRoleTrust, type RoleTrust } from "../domain/roleTrust";
import { formatPolicyResource } from "../domain/policyLanguage";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceCollection, WorkspaceDelete, WorkspaceDetail, WorkspaceInlineForm, WorkspaceSelection, WorkspaceTime } from "./AccessWorkspaceUi";
import { RoleSessionSettings, RoleTags, RoleTrustFields } from "./RoleConfiguration";
import { PermissionBoundary } from "./PermissionBoundary";
import { RoleSessions } from "./RoleSessions";
import { ServiceAuthorizationPreview } from "./ServiceAuthorizationPreview";
import styles from "./AccountAccessRenderer.module.css";

function RoleMetadataEditor({ role, onClose }: { role: AccessRole; onClose(): void }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), access = useAccountAccess(), id = useId();
  const [description, setDescription] = useState(role.description), [tags, setTags] = useState(role.tags);
  return <WorkspaceInlineForm title={t("editMetadata")} backLabel={t("backToRoleDetails")} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "update-role-metadata", id: role.id, description, tags }))}><div><strong>{role.name}</strong><p className={styles.note}>{role.id}</p></div><FormField id={id} label={w("description")}><TextArea id={id} maxLength={256} rows={3} value={description} onChange={(event) => setDescription(event.target.value)} /></FormField><RoleTags value={tags} onChange={setTags} /></WorkspaceInlineForm>;
}
function RoleTrustReview({ role, proposed, workspace, scene }: { role: AccessRole; proposed: RoleTrust; workspace: AccessWorkspace; scene: AccountAccessScene }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace");
  const subjects = (trust: RoleTrust) => trust.principalType === "account" ? trust.trustedUserIds : [trust.principal];
  const previous = subjects(role), next = subjects(proposed);
  const name = (id: string) => role.principalType === "account" ? scene.users.find((user) => user.id === id)?.loginName ?? id : workspace.providers.find((provider) => provider.id === id)?.name ?? id;
  return <div className={styles.stack}>
    <h3 className={styles.stepTitle} data-trust-review-heading tabIndex={-1}>{t("reviewTrust")}</h3>
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
  const stage = useRef<HTMLElement>(null), heading = useRef<HTMLHeadingElement>(null), invalidAlert = useRef<HTMLDivElement>(null), errorAlert = useRef<HTMLDivElement>(null), previousReview = useRef(review);
  const changed = role.principal !== trust.principal || role.trustedUserIds.length !== trust.trustedUserIds.length || role.trustedUserIds.some((id) => !trust.trustedUserIds.includes(id));
  useLayoutEffect(() => { heading.current?.focus({ preventScroll: true }); }, []);
  useLayoutEffect(() => {
    if (previousReview.current === review) return;
    previousReview.current = review;
    stage.current?.querySelector<HTMLElement>(review ? '[data-trust-review-heading]' : 'input[type="search"], [role="combobox"]:not([disabled])')?.focus();
  }, [review]);
  useLayoutEffect(() => { if (invalid) invalidAlert.current?.querySelector<HTMLElement>('[role="alert"]')?.focus({ preventScroll: true }); }, [invalid]);
  useLayoutEffect(() => { if (access.workspaceError) errorAlert.current?.querySelector<HTMLElement>('[role="alert"]')?.focus({ preventScroll: true }); }, [access.workspaceError]);
  const submit = async () => {
    try { validateRoleTrust(workspace, trust, scene.users.map((user) => user.id)); } catch { setInvalid(true); return false; }
    setInvalid(false);
    if (!review) { setReview(true); return false; }
    if (await access.executeWorkspace({ kind: "update-role-trust", id: role.id, principal: trust.principal, trustedUserIds: trust.trustedUserIds })) onClose();
    return false;
  };
  return <section ref={stage} className={styles.stack} role="group" aria-label={t("editTrust")}>
    <div className={styles.sectionHeading}><Button variant="ghost" disabled={access.busy} onClick={onClose}>{t("backToTrust")}</Button><h3 className={styles.detailTitle} ref={heading} tabIndex={-1}>{t("editTrust")}</h3></div>
    {access.workspaceError ? <div ref={errorAlert}><Alert status="danger" tabIndex={-1}>{w(`errors.${access.workspaceError}`)}</Alert></div> : null}
    <form className={styles.stack} aria-busy={access.busy || undefined} onSubmit={(event) => { event.preventDefault(); if (!access.busy && changed) void submit(); }}>
      <fieldset className={styles.editorFields} disabled={access.busy}>{review ? <><RoleTrustReview role={role} proposed={trust} workspace={workspace} scene={scene} /><Button variant="ghost" onClick={() => { access.clearWorkspaceError(); setReview(false); }}>{t("backToSelection")}</Button></> : <><RoleTrustFields locked workspace={workspace} users={scene.users.map((user) => ({ id: user.id, name: user.loginName }))} value={trust} onChange={(value) => { setTrust(value); setInvalid(false); access.clearWorkspaceError(); }} />{invalid ? <div ref={invalidAlert}><Alert status="danger" tabIndex={-1}>{t("invalidTrust")}</Alert></div> : null}{!changed ? <p className={styles.note}>{t("noTrustChanges")}</p> : null}</>}</fieldset>
      <div className={styles.actions}><Button type="submit" disabled={access.busy || !changed}>{review ? w("save") : t("reviewChange")}</Button><Button type="button" variant="secondary" disabled={access.busy} onClick={onClose}>{w("cancel")}</Button></div>
    </form>
  </section>;
}
function RoleSettingsEditor({ role, onClose }: { role: AccessRole; onClose(): void }) {
  const t = useTranslations("RoleWorkspace"), access = useAccountAccess();
  const [settings, setSettings] = useState({ sessionMinutes: role.sessionMinutes, consoleAccess: role.consoleAccess });
  return <WorkspaceInlineForm title={t("editSettings")} backLabel={t("backToRoleDetails")} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "update-role-settings", id: role.id, ...settings }))}><Alert>{t("settingsChangeHint")}</Alert><RoleSessionSettings value={settings} onChange={setSettings} service={role.principalType === "service"} /></WorkspaceInlineForm>;
}
function RolePolicyEditor({ role, workspace, mode, onClose }: { role: AccessRole; workspace: AccessWorkspace; mode: "add" | "remove"; onClose(): void }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), access = useAccountAccess();
  const [selected, setSelected] = useState<string[]>([]), [review, setReview] = useState(false);
  const options = mode === "add" ? workspace.policies.filter((policy) => !role.policyIds.includes(policy.id)) : role.policyIds.map((id) => workspace.policies.find((policy) => policy.id === id) ?? { id, name: id });
  return <WorkspaceInlineForm title={t(mode === "add" ? "addPolicies" : "removePolicies")} backLabel={t("backToRoleDetails")} onClose={onClose} submitDisabled={!selected.length} submitLabel={review ? w("save") : t("reviewChange")} onSubmit={async () => { if (!review) { setReview(true); return false; } return Boolean(await access.executeWorkspace({ kind: "change-role-policies", id: role.id, added: mode === "add" ? selected : [], removed: mode === "remove" ? selected : [] })); }}>
    {review ? <><Alert status="warning">{t("policyChangeHint")}</Alert><p>{t(mode === "add" ? "adding" : "removing")}</p><ul>{selected.map((id) => <li key={id}>{options.find((policy) => policy.id === id)?.name ?? id}</li>)}</ul><Button variant="ghost" onClick={() => setReview(false)}>{t("backToSelection")}</Button></> : <WorkspaceSelection label={w("selectPolicies")} options={options} value={selected} onChange={setSelected} />}
  </WorkspaceInlineForm>;
}

export function AccessRoles({ workspace, scene, entityId, onCreate, onOpen }: { workspace: AccessWorkspace; scene: AccountAccessScene; entityId?: string; onCreate(): void; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("IamWorkspace"), r = useTranslations("RoleWorkspace"), access = useAccountAccess();
  const [workflow, setWorkflow] = useState<"metadata" | "trust" | "settings" | "add" | "remove" | null>(null);
  const [serviceAuthorizationOpen, setServiceAuthorizationOpen] = useState(false);
  const [tab, setTab] = useState("policies");
  const [deleting, setDeleting] = useState<AccessRole | null>(null);
  const metadataTrigger = useRef<HTMLButtonElement>(null), trustTrigger = useRef<HTMLButtonElement>(null), settingsTrigger = useRef<HTMLButtonElement>(null), addTrigger = useRef<HTMLButtonElement>(null), removeTrigger = useRef<HTMLButtonElement>(null);
  const collectionActionFocus = useRef<{ focus(): void }>(null);
  const previousServiceAuthorizationOpen = useRef(false);
  const previousWorkflow = useRef<typeof workflow>(null);
  const selected = workspace.roles.find((role) => role.id === entityId);
  useLayoutEffect(() => {
    const closed = previousWorkflow.current;
    previousWorkflow.current = workflow;
    if (workflow || !closed) return;
    const target = ({ metadata: metadataTrigger, trust: trustTrigger, settings: settingsTrigger, add: addTrigger, remove: removeTrigger }[closed]).current;
    const fallback = closed === "remove" && target?.disabled ? addTrigger.current : null;
    (fallback ?? target)?.focus({ preventScroll: true });
  }, [workflow]);
  useLayoutEffect(() => {
    const wasOpen = previousServiceAuthorizationOpen.current;
    previousServiceAuthorizationOpen.current = serviceAuthorizationOpen;
    if (wasOpen && !serviceAuthorizationOpen) collectionActionFocus.current?.focus();
  }, [serviceAuthorizationOpen]);
  if (entityId && !selected) return <EmptyState title={t("entityUnavailable")} description={t("entityUnavailableHint")} action={<Button variant="secondary" onClick={() => onOpen("roles")}>{t("back")}</Button>} />;
  const principalLabel = (role: AccessRole) => role.principalType === "provider" ? workspace.providers.find((provider) => provider.id === role.principal)?.name ?? role.principal : role.principal;
  const openWorkflow = (next: NonNullable<typeof workflow>) => { access.clearWorkspaceError(); setWorkflow(next); };
  return <>
    {selected ? <WorkspaceDetail title={selected.name} onBack={() => onOpen("roles")} primaryActionRef={metadataTrigger} actions={workflow ? undefined : { primary: { id: "edit", label: r("editMetadata"), variant: "secondary", onSelect: () => openWorkflow("metadata") }, secondary: [{ id: "delete", label: t("delete"), danger: true, onSelect: () => setDeleting(selected) }] }}>
      {workflow === "metadata" ? <RoleMetadataEditor role={selected} onClose={() => setWorkflow(null)} />
        : workflow === "trust" ? <RoleTrustEditor role={selected} workspace={workspace} scene={scene} onClose={() => setWorkflow(null)} />
        : workflow === "settings" ? <RoleSettingsEditor role={selected} onClose={() => setWorkflow(null)} />
        : workflow === "add" || workflow === "remove" ? <RolePolicyEditor role={selected} workspace={workspace} mode={workflow} onClose={() => setWorkflow(null)} />
        : <><p className={styles.note}>{selected.description || "—"}</p><dl className={styles.facts}><div><dt>ID</dt><dd>{selected.id}</dd></div><div><dt>{t("principalType")}</dt><dd>{t(selected.principalType === "service" ? "servicePrincipal" : selected.principalType)}</dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div></dl>
      {selected.tags.length ? <div className={styles.actions} aria-label={r("tags")}>{selected.tags.map((tag) => <Badge key={tag.key}>{tag.key} : {tag.value || "—"}</Badge>)}</div> : null}
      <Tabs.Root value={tab} onValueChange={setTab}><Tabs.List aria-label={selected.name}><Tabs.Trigger value="policies">{t("permissions")}</Tabs.Trigger><Tabs.Trigger value="trust">{t("trust")}</Tabs.Trigger><Tabs.Trigger value="sessions">{r("sessions")}</Tabs.Trigger><Tabs.Trigger value="settings">{r("sessionSettings")}</Tabs.Trigger></Tabs.List>
        <Tabs.Content className={styles.stack} value="policies"><div className={styles.actions}><Button ref={addTrigger} variant="secondary" onClick={() => openWorkflow("add")}>{r("addPolicies")}</Button><Button ref={removeTrigger} variant="ghost" disabled={!selected.policyIds.length} onClick={() => openWorkflow("remove")}>{r("removePolicies")}</Button></div><p className={styles.note}>{r("permissionsHint")}</p><Table aria-label={t("permissions")} mobileLayout="stack"><thead><tr><th scope="col">{t("name")}</th><th scope="col">{t("type")}</th><th scope="col">{r("effectiveVersion")}</th></tr></thead><tbody>{selected.policyIds.map((id) => { const policy = workspace.policies.find((policy) => policy.id === id); return <tr key={id}><td data-label={t("name")}><button className={styles.userLink} onClick={() => onOpen("policies", id)}>{policy?.name ?? id}</button><small>{policy?.description}</small></td><td data-label={t("type")}>{policy ? t(policy.kind) : "—"}</td><td data-label={r("effectiveVersion")}>{policy ? "v" + policy.defaultVersion : "—"}</td></tr>; })}</tbody></Table>{!selected.policyIds.length ? <p className={styles.note}>{r("noPermissions")}</p> : null}
          <PermissionBoundary workspace={workspace} value={selected.boundaryPolicyId} onOpen={(id) => onOpen("policies", id)} onSave={(policyId) => access.executeWorkspace({ kind: "set-role-boundary", id: selected.id, policyId })} />
        </Tabs.Content>
        <Tabs.Content className={styles.stack} value="trust"><div><Button ref={trustTrigger} variant="secondary" onClick={() => openWorkflow("trust")}>{r("editTrust")}</Button></div><Alert>{r(`trustHints.${selected.principalType}`)}</Alert><dl className={styles.facts}><div><dt>{t("principal")}</dt><dd>{principalLabel(selected)}</dd></div>{selected.principalType === "account" ? <div><dt>{r("trustedUsers")}</dt><dd><div className={styles.actions}>{selected.trustedUserIds.map((id) => <button key={id} className={styles.userLink} onClick={() => onOpen("users", id)}>{scene.users.find((user) => user.id === id)?.loginName ?? id}</button>)}</div></dd></div> : null}</dl><pre className={styles.code} role="region" aria-label={r("trustDocument")} tabIndex={0}>{JSON.stringify(roleTrustDocument(selected), null, 2)}</pre>{selected.principalType === "account" ? <><p className={styles.note}>{r("requiredAction")}</p><pre className={styles.code}>{JSON.stringify({ action: ["iam:assumeRole"], resource: [formatPolicyResource({ service: "iam", tenant: workspace.accountId, region: "global", type: "role", id: selected.id })] }, null, 2)}</pre></> : null}</Tabs.Content>
        <Tabs.Content value="sessions"><RoleSessions role={selected} workspace={workspace} scene={scene} onOpen={onOpen} /></Tabs.Content>
        <Tabs.Content className={styles.stack} value="settings"><div><Button ref={settingsTrigger} variant="secondary" onClick={() => openWorkflow("settings")}>{r("editSettings")}</Button></div><dl className={styles.facts}><div><dt>{t("sessionMinutes")}</dt><dd>{selected.sessionMinutes}</dd></div><div><dt>{t("consoleAccess")}</dt><dd>{t(selected.consoleAccess ? "enabled" : "disabled")}</dd></div></dl><Alert>{r("settingsChangeHint")}</Alert></Tabs.Content>
      </Tabs.Root>
      </>}
    </WorkspaceDetail> : <WorkspaceCollection title={t("roles")} description={t("roleHint")} items={workspace.roles} keywords={(role) => [role.description, principalLabel(role)].join(" ")} filter={{ label: t("principalType"), options: ["account", "service", "provider"].map((value) => ({ value, label: t(value === "service" ? "servicePrincipal" : value as "account" | "provider") })), matches: (role, value) => role.principalType === value }} create={{ label: t("createRole"), onClick: onCreate }} secondaryActions={[{ id: "service-authorization", label: r("serviceAuthorization"), variant: "secondary", onSelect: () => setServiceAuthorizationOpen(true) }]} createFocusRef={collectionActionFocus} workflow={serviceAuthorizationOpen ? <ServiceAuthorizationPreview workspace={workspace} onClose={() => setServiceAuthorizationOpen(false)} onOpenPolicy={(id) => onOpen("policies", id)} /> : undefined} columns={[t("name"), t("principalType"), t("principal"), t("created")]} row={(role) => <><td><button className={styles.userLink} onClick={() => onOpen("roles", role.id)}>{role.name}</button><small>{role.description}</small></td><td>{t(role.principalType === "service" ? "servicePrincipal" : role.principalType)}</td><td>{principalLabel(role)}</td><td><WorkspaceTime value={role.createdAt} /></td></>} />}
    {deleting ? <WorkspaceDelete name={deleting.name} impact={<Alert status="warning">{r("deleteImpact")}</Alert>} onClose={() => setDeleting(null)} onConfirm={async () => { const result = await access.executeWorkspace({ kind: "delete-role", id: deleting.id }); if (result && entityId === deleting.id) onOpen("roles"); return result; }} /> : null}
  </>;
}
