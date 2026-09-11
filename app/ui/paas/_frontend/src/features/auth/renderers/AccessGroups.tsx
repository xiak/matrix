"use client";

import { useEffect, useId, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, EmptyState, FormField, Input, Table, Tabs, TextArea } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccountAccessView } from "../domain/accounts";
import type { AccessGroup, AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceCollection, WorkspaceDelete, WorkspaceDetail, WorkspaceDialog, WorkspaceSelection, WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

function GroupMetadataEditor({ group, onClose }: { group: AccessGroup; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const [name, setName] = useState(group.name);
  const [description, setDescription] = useState(group.description);
  return <WorkspaceDialog title={t("edit") + " · " + group.name} onClose={onClose} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "update-group", id: group.id, name, description }))}>
    <FormField id={id + "-name"} label={t("name")}><Input id={id + "-name"} required maxLength={64} value={name} onChange={(event) => setName(event.target.value)} /></FormField>
    <FormField id={id + "-description"} label={t("description")}><TextArea id={id + "-description"} maxLength={256} rows={3} value={description} onChange={(event) => setDescription(event.target.value)} /></FormField>
  </WorkspaceDialog>;
}

type GroupChange = { groupId: string; kind: "members" | "policies"; mode: "add" | "remove"; initial?: string };

function GroupAssociationEditor({ group, workspace, scene, change, onClose }: { group: AccessGroup; workspace: AccessWorkspace; scene: AccountAccessScene; change: GroupChange; onClose(): void }) {
  const t = useTranslations("GroupWorkspace");
  const w = useTranslations("IamWorkspace");
  const a = useTranslations("AccountAccess");
  const access = useAccountAccess();
  const [selection, setSelection] = useState<string[]>(change.initial ? [change.initial] : []);
  const [review, setReview] = useState(false);
  const reviewHeading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (!review) return;
    reviewHeading.current?.focus({ preventScroll: true });
    reviewHeading.current?.scrollIntoView?.({ block: "center" });
  }, [review]);
  const attached = change.kind === "members" ? group.memberIds : group.policyIds;
  const memberDirectory = scene.users;
  const source = change.kind === "members" ? memberDirectory.map((user) => ({ id: user.id, name: user.loginName, description: [a("child"), user.name].filter(Boolean).join(" · ") })) : workspace.policies;
  const options = change.mode === "add" ? source.filter((item) => !attached.includes(item.id)) : attached.map((id) => source.find((item) => item.id === id) ?? { id, name: id });
  const label = t(`${change.mode}${change.kind === "members" ? "Members" : "Policies"}`);
  const affected = change.kind === "members" ? selection : group.memberIds;
  return <WorkspaceDialog size="wide" title={label + " · " + group.name} onClose={onClose} submitLabel={t(review ? "confirmChange" : "reviewChange")} submitDisabled={!selection.length} onSubmit={async () => {
    if (!selection.length) return false;
    if (!review) { setReview(true); return false; }
    return Boolean(await access.executeWorkspace({ kind: change.kind === "members" ? "change-group-members" : "change-group-policies", id: group.id, added: change.mode === "add" ? selection : [], removed: change.mode === "remove" ? selection : [] }));
  }}>
    {review ? <>
      <Alert status={change.mode === "remove" ? "warning" : "info"}>{t("impact", { count: affected.length })} {change.mode === "remove" ? t("remainingSources") : null}</Alert>
      <section className={styles.stack}><h3 ref={reviewHeading} tabIndex={-1} className={styles.detailTitle}>{label} ({selection.length})</h3><div className={styles.roleTags}>{selection.map((id) => <Badge key={id}>{options.find((entry) => entry.id === id)?.name ?? id}</Badge>)}</div></section>
      {change.kind === "policies" ? <section className={styles.stack}><h3 className={styles.stepTitle}>{w("members")}</h3><div className={styles.roleTags}>{affected.slice(0, 20).map((id) => <Badge key={id}>{memberDirectory.find((user) => user.id === id)?.loginName ?? id}</Badge>)}</div>{affected.length > 20 ? <p className={styles.note}>{t("moreMembers", { count: affected.length - 20 })}</p> : null}{!affected.length ? <p className={styles.note}>{t("noMembers")}</p> : null}</section> : null}
      <div><Button variant="secondary" onClick={() => { setReview(false); access.clearWorkspaceError(); }}>{t("backToSelection")}</Button></div>
    </> : <>
      <Alert>{t(change.kind === "members" ? "membershipHint" : "policyChangeHint")}</Alert>
      <WorkspaceSelection label={label} options={options} value={selection} onChange={setSelection} />
    </>}
  </WorkspaceDialog>;
}

export function AccessGroups({ workspace, scene, entityId, onCreate, onOpen }: { workspace: AccessWorkspace; scene: AccountAccessScene; entityId?: string; onCreate(): void; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("IamWorkspace");
  const g = useTranslations("GroupWorkspace");
  const a = useTranslations("AccountAccess");
  const access = useAccountAccess();
  const [editing, setEditing] = useState<AccessGroup | null>(null);
  const [deleting, setDeleting] = useState<AccessGroup | null>(null);
  const [change, setChange] = useState<GroupChange | null>(null);
  const selected = workspace.groups.find((group) => group.id === entityId);
  const changing = workspace.groups.find((group) => group.id === change?.groupId);
  const memberDirectory = scene.users;
  if (entityId && !selected) return <EmptyState title={t("entityUnavailable")} description={t("entityUnavailableHint")} action={<Button variant="secondary" onClick={() => onOpen("groups")}>{t("back")}</Button>} />;
  return <>
    {selected ? <WorkspaceDetail title={selected.name} onBack={() => onOpen("groups")} actions={<><Button onClick={() => setEditing(selected)} variant="secondary">{t("edit")}</Button><Button onClick={() => setDeleting(selected)} variant="ghost">{t("delete")}</Button></>}>
      <p className={styles.note}>{selected.description || t("none")}</p><Alert>{g("groupIdentityHint")}</Alert>
      <dl className={styles.facts}><div><dt>ID</dt><dd>{selected.id}</dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div></dl>
      <Tabs.Root defaultValue="members"><Tabs.List aria-label={selected.name}><Tabs.Trigger value="members">{t("members")} ({selected.memberIds.length})</Tabs.Trigger><Tabs.Trigger value="policies">{t("permissions")} ({selected.policyIds.length})</Tabs.Trigger></Tabs.List>
        <Tabs.Content className={styles.stack} value="members">
          <div className={styles.actions}><Button onClick={() => setChange({ groupId: selected.id, kind: "members", mode: "add" })}>{g("addMembers")}</Button><Button variant="secondary" disabled={!selected.memberIds.length} onClick={() => setChange({ groupId: selected.id, kind: "members", mode: "remove" })}>{g("removeMembers")}</Button></div>
          {selected.memberIds.length ? <Table aria-label={t("members")}><thead><tr><th>{t("name")}</th><th>{a("userType")}</th><th>{t("state")}</th><th>{t("actions")}</th></tr></thead><tbody>{selected.memberIds.map((id) => { const user = memberDirectory.find((entry) => entry.id === id); return <tr key={id}><td><button className={styles.userLink} onClick={() => onOpen("users", id)}>{user?.loginName ?? id}</button><small>{user?.name}</small></td><td>{user ? a("child") : a("unknown")}</td><td>{user?.state ? <Badge status={user.state === "disabled" ? "neutral" : "success"}>{a(`states.${user.state}`)}</Badge> : "—"}</td><td><Button size="small" variant="ghost" aria-label={g("removeMember", { name: user?.loginName ?? id })} onClick={() => setChange({ groupId: selected.id, kind: "members", mode: "remove", initial: id })}>{g("remove")}</Button></td></tr>; })}</tbody></Table> : <EmptyState title={g("noMembers")} description={g("noMembersHint")} />}
        </Tabs.Content>
        <Tabs.Content className={styles.stack} value="policies">
          <div className={styles.actions}><Button onClick={() => setChange({ groupId: selected.id, kind: "policies", mode: "add" })}>{g("addPolicies")}</Button><Button variant="secondary" disabled={!selected.policyIds.length} onClick={() => setChange({ groupId: selected.id, kind: "policies", mode: "remove" })}>{g("removePolicies")}</Button></div><Alert>{g("policyChangeHint")}</Alert>
          {selected.policyIds.length ? <Table aria-label={t("permissions")}><thead><tr><th>{t("name")}</th><th>{t("type")}</th><th>{t("version")}</th></tr></thead><tbody>{workspace.policies.filter((policy) => selected.policyIds.includes(policy.id)).map((policy) => <tr key={policy.id}><td><button className={styles.userLink} onClick={() => onOpen("policies", policy.id)}>{policy.name}</button><small>{policy.description}</small></td><td>{t(policy.kind)}</td><td>v{policy.defaultVersion}</td></tr>)}</tbody></Table> : <EmptyState title={g("noPolicies")} />}
        </Tabs.Content>
      </Tabs.Root>
    </WorkspaceDetail> : <WorkspaceCollection title={t("groups")} description={t("groupHint")} items={workspace.groups} keywords={(group) => group.description} create={{ label: t("createGroup"), onClick: onCreate }} columns={[t("name"), t("members"), t("permissions"), t("created"), t("actions")]} row={(group) => <><td><button className={styles.userLink} onClick={() => onOpen("groups", group.id)}>{group.name}</button><small>{group.description}</small></td><td>{t("memberCount", { count: group.memberIds.length })}</td><td>{group.policyIds.length}</td><td><WorkspaceTime value={group.createdAt} /></td><td><div className={styles.actions}><Button size="small" variant="ghost" onClick={() => setEditing(group)}>{t("edit")}</Button><Button size="small" variant="ghost" onClick={() => setDeleting(group)}>{t("delete")}</Button></div></td></>} />}
    {editing ? <GroupMetadataEditor group={editing} onClose={() => setEditing(null)} /> : null}
    {changing && change ? <GroupAssociationEditor group={changing} workspace={workspace} scene={scene} change={change} onClose={() => setChange(null)} /> : null}
    {deleting ? <WorkspaceDelete name={deleting.name} impact={<Alert status="warning">{g("deleteImpact", { count: deleting.memberIds.length })} {g("remainingSources")}</Alert>} onClose={() => setDeleting(null)} onConfirm={async () => { const result = await access.executeWorkspace({ kind: "delete-group", id: deleting.id }); if (result && entityId === deleting.id) onOpen("groups"); return result; }} /> : null}
  </>;
}
