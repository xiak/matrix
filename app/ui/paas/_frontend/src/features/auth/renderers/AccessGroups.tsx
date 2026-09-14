"use client";

import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, EmptyState, FormField, Input, Table, Tabs, TextArea } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccountAccessView } from "../domain/accounts";
import type { AccessGroup, AccessPolicy, AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import {
  WorkspaceCollection,
  WorkspaceDelete,
  WorkspaceDetail,
  WorkspaceDialog,
  WorkspaceSelection,
  WorkspaceTime
} from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

type OpenGroupEntity = (view: AccountAccessView, id?: string) => void;
type GroupChange = { groupId: string; kind: "members" | "policies"; mode: "add" | "remove" };
type GroupUser = AccountAccessScene["users"][number];

export type GroupActionControl = { disabled?: boolean; reason?: string; onInvoke(): void };
export type GroupDirectoryRecord = {
  id: string;
  name: string;
  description: string;
  createdAt: string;
  directPolicyCount: number;
  /** Omitted when the repository has not supplied an authoritative total. */
  memberCount?: number;
};
export type GroupMemberRecord = {
  id: string;
  userId: string;
  name: string;
  description?: string;
  identityType: "child" | "unknown";
  state?: "active" | "disabled" | "passwordChangeRequired";
};
export type GroupPolicyRecord = {
  id: string;
  policyId: string;
  name: string;
  description?: string;
  kind?: AccessPolicy["kind"];
  version?: number;
};
export type GroupDetailRecord = GroupDirectoryRecord & {
  members: GroupMemberRecord[];
  policies: GroupPolicyRecord[];
};
export type GroupDetailControls = {
  edit?: GroupActionControl;
  delete?: GroupActionControl;
  addMember?: GroupActionControl;
  removeMember?: GroupActionControl;
  addPolicy?: GroupActionControl;
  removePolicy?: GroupActionControl;
};

function GroupMetadataEditor({ group, onClose }: { group: AccessGroup; onClose(): void }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const id = useId();
  const [name, setName] = useState(group.name);
  const [description, setDescription] = useState(group.description);

  return <WorkspaceDialog
    title={`${t("edit")} · ${group.name}`}
    onClose={onClose}
    onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "update-group", id: group.id, name, description }))}
  >
    <FormField id={`${id}-name`} label={t("name")}>
      <Input id={`${id}-name`} required maxLength={64} value={name} onChange={(event) => setName(event.target.value)} />
    </FormField>
    <FormField id={`${id}-description`} label={t("description")}>
      <TextArea id={`${id}-description`} maxLength={256} rows={3} value={description} onChange={(event) => setDescription(event.target.value)} />
    </FormField>
  </WorkspaceDialog>;
}

function GroupAssociationEditor({ group, workspace, scene, change, onClose }: {
  group: AccessGroup;
  workspace: AccessWorkspace;
  scene: AccountAccessScene;
  change: GroupChange;
  onClose(): void;
}) {
  const t = useTranslations("GroupWorkspace");
  const w = useTranslations("IamWorkspace");
  const a = useTranslations("AccountAccess");
  const access = useAccountAccess();
  const [selection, setSelection] = useState<string[]>([]);
  const [review, setReview] = useState(false);
  const reviewHeading = useRef<HTMLHeadingElement>(null);
  const attached = change.kind === "members" ? group.memberIds : group.policyIds;
  const memberDirectory = scene.users;
  const memberById = useMemo(() => new Map(memberDirectory.map((user) => [user.id, user])), [memberDirectory]);
  const source = useMemo(() => change.kind === "members"
    ? memberDirectory.map((user) => ({
        id: user.id,
        name: user.loginName,
        description: [a("child"), user.name].filter(Boolean).join(" · ")
      }))
    : workspace.policies,
  [a, change.kind, memberDirectory, workspace.policies]);
  const sourceById = useMemo(() => new Map(source.map((item) => [item.id, item])), [source]);
  const options = useMemo(() => change.mode === "add"
    ? source.filter((item) => !attached.includes(item.id))
    : attached.map((id) => sourceById.get(id) ?? { id, name: id }),
  [attached, change.mode, source, sourceById]);
  const label = t(`${change.mode}${change.kind === "members" ? "Members" : "Policies"}`);
  const affected = change.kind === "members" ? selection : group.memberIds;

  useEffect(() => {
    if (!review) return;
    reviewHeading.current?.focus({ preventScroll: true });
    reviewHeading.current?.scrollIntoView?.({ block: "center" });
  }, [review]);

  return <WorkspaceDialog
    size="wide"
    title={`${label} · ${group.name}`}
    onClose={onClose}
    submitLabel={t(review ? "confirmChange" : "reviewChange")}
    submitDisabled={!selection.length}
    onSubmit={async () => {
      if (!selection.length) return false;
      if (!review) {
        setReview(true);
        return false;
      }
      return Boolean(await access.executeWorkspace({
        kind: change.kind === "members" ? "change-group-members" : "change-group-policies",
        id: group.id,
        added: change.mode === "add" ? selection : [],
        removed: change.mode === "remove" ? selection : []
      }));
    }}
  >
    {review ? <>
      <Alert status={change.mode === "remove" ? "warning" : "info"}>
        {t("impact", { count: affected.length })} {change.mode === "remove" ? t("remainingSources") : null}
      </Alert>
      <section className={styles.stack}>
        <h3 ref={reviewHeading} tabIndex={-1} className={styles.detailTitle}>{label} ({selection.length})</h3>
        <div className={styles.roleTags}>
          {selection.map((id) => <Badge key={id}>{options.find((entry) => entry.id === id)?.name ?? id}</Badge>)}
        </div>
      </section>
      {change.kind === "policies" ? <section className={styles.stack}>
        <h3 className={styles.stepTitle}>{w("members")}</h3>
        <div className={styles.roleTags}>
          {affected.slice(0, 20).map((id) => <Badge key={id}>{memberById.get(id)?.loginName ?? id}</Badge>)}
        </div>
        {affected.length > 20 ? <p className={styles.note}>{t("moreMembers", { count: affected.length - 20 })}</p> : null}
        {!affected.length ? <p className={styles.note}>{t("noMembers")}</p> : null}
      </section> : null}
      <div>
        <Button variant="secondary" onClick={() => { setReview(false); access.clearWorkspaceError(); }}>
          {t("backToSelection")}
        </Button>
      </div>
    </> : <>
      <Alert>{t(change.kind === "members" ? "membershipHint" : "policyChangeHint")}</Alert>
      <WorkspaceSelection label={label} options={options} value={selection} onChange={setSelection} limit={1} />
    </>}
  </WorkspaceDialog>;
}

export function GroupDirectory({ groups, create, onOpen }: {
  groups: GroupDirectoryRecord[];
  create?: GroupActionControl;
  onOpen: OpenGroupEntity;
}) {
  const t = useTranslations("IamWorkspace");
  const g = useTranslations("GroupWorkspace");
  const showMemberCount = groups.every((group) => group.memberCount !== undefined);

  return <WorkspaceCollection
    title={t("groups")}
    description={t("groupHint")}
    items={groups}
    keywords={(group) => group.description}
    create={create ? { label: t("createGroup"), disabled: create.disabled, reason: create.reason, onClick: create.onInvoke } : undefined}
    columns={[t("name"), ...(showMemberCount ? [t("members")] : []), g("directPolicies"), t("created")]}
    row={(group) => <>
      <td>
        <button className={styles.userLink} onClick={() => onOpen("groups", group.id)}>{group.name}</button>
        <small>{group.description}</small>
      </td>
      {showMemberCount ? <td>{t("memberCount", { count: group.memberCount! })}</td> : null}
      <td>{g("directPolicyCount", { count: group.directPolicyCount })}</td>
      <td><WorkspaceTime value={group.createdAt} /></td>
    </>}
  />;
}

function GroupMemberTable({ members, onOpen }: {
  members: GroupMemberRecord[];
  onOpen: OpenGroupEntity;
}) {
  const t = useTranslations("IamWorkspace");
  const a = useTranslations("AccountAccess");

  return <Table aria-label={t("members")}>
    <thead><tr><th>{t("name")}</th><th>{a("userType")}</th><th>{t("state")}</th></tr></thead>
    <tbody>{members.map((member) => <tr key={member.id}>
        <td>
          <button className={styles.userLink} onClick={() => onOpen("users", member.userId)}>{member.name}</button>
          <small>{member.description}</small>
        </td>
        <td>{a(member.identityType)}</td>
        <td>{member.state ? <Badge status={member.state === "disabled" ? "neutral" : "success"}>{a(`states.${member.state}`)}</Badge> : "—"}</td>
      </tr>)}</tbody>
  </Table>;
}

function GroupPolicyTable({ policies, onOpen }: {
  policies: GroupPolicyRecord[];
  onOpen: OpenGroupEntity;
}) {
  const t = useTranslations("IamWorkspace");

  return <Table aria-label={t("permissions")}>
    <thead><tr><th>{t("name")}</th><th>{t("type")}</th><th>{t("version")}</th></tr></thead>
    <tbody>{policies.map((policy) => <tr key={policy.id}>
      <td>
        <button className={styles.userLink} onClick={() => onOpen("policies", policy.policyId)}>{policy.name}</button>
        <small>{policy.description}</small>
      </td>
      <td>{policy.kind ? t(policy.kind) : "—"}</td>
      <td>{policy.version === undefined ? "—" : `v${policy.version}`}</td>
    </tr>)}</tbody>
  </Table>;
}

function GroupActionButton({ control, children, variant }: {
  control?: GroupActionControl;
  children: string;
  variant?: "secondary" | "ghost";
}) {
  if (!control) return null;
  return <Button
    disabled={control.disabled}
    onClick={control.onInvoke}
    title={control.disabled ? control.reason : undefined}
    variant={variant}
  >{children}</Button>;
}

export function GroupDetail({ group, controls, onBack, onOpen }: {
  group: GroupDetailRecord;
  controls: GroupDetailControls;
  onBack(): void;
  onOpen: OpenGroupEntity;
}) {
  const t = useTranslations("IamWorkspace");
  const g = useTranslations("GroupWorkspace");

  return <WorkspaceDetail
    title={group.name}
    onBack={onBack}
    actions={<>
      <GroupActionButton control={controls.edit} variant="secondary">{t("edit")}</GroupActionButton>
      <GroupActionButton control={controls.delete} variant="ghost">{t("delete")}</GroupActionButton>
    </>}
  >
    <p className={styles.note}>{group.description || t("none")}</p>
    <Alert>{g("groupIdentityHint")}</Alert>
    <dl className={styles.facts}>
      <div><dt>ID</dt><dd>{group.id}</dd></div>
      <div><dt>{t("created")}</dt><dd><WorkspaceTime value={group.createdAt} /></dd></div>
    </dl>
    <Tabs.Root defaultValue="members">
      <Tabs.List aria-label={group.name}>
        <Tabs.Trigger value="members">{t("members")}{group.memberCount === undefined ? null : ` (${group.memberCount})`}</Tabs.Trigger>
        <Tabs.Trigger value="policies">{g("directPolicies")} ({group.directPolicyCount})</Tabs.Trigger>
      </Tabs.List>
      <Tabs.Content className={styles.stack} value="members">
        <div className={styles.actions}>
          <GroupActionButton control={controls.addMember}>{g("addMembers")}</GroupActionButton>
          <GroupActionButton control={controls.removeMember} variant="secondary">{g("removeMembers")}</GroupActionButton>
        </div>
        {group.members.length
          ? <GroupMemberTable members={group.members} onOpen={onOpen} />
          : <EmptyState title={g("noMembers")} description={g("noMembersHint")} />}
      </Tabs.Content>
      <Tabs.Content className={styles.stack} value="policies">
        <div className={styles.actions}>
          <GroupActionButton control={controls.addPolicy}>{g("addPolicies")}</GroupActionButton>
          <GroupActionButton control={controls.removePolicy} variant="secondary">{g("removePolicies")}</GroupActionButton>
        </div>
        <Alert>{g("policyChangeHint")}</Alert>
        {group.policies.length
          ? <GroupPolicyTable policies={group.policies} onOpen={onOpen} />
          : <EmptyState title={g("noPolicies")} />}
      </Tabs.Content>
    </Tabs.Root>
  </WorkspaceDetail>;
}

export function AccessGroups({ workspace, scene, entityId, onCreate, onOpen }: {
  workspace: AccessWorkspace;
  scene: AccountAccessScene;
  entityId?: string;
  onCreate(): void;
  onOpen: OpenGroupEntity;
}) {
  const t = useTranslations("IamWorkspace");
  const g = useTranslations("GroupWorkspace");
  const access = useAccountAccess();
  const [editing, setEditing] = useState<AccessGroup | null>(null);
  const [deleting, setDeleting] = useState<AccessGroup | null>(null);
  const [change, setChange] = useState<GroupChange | null>(null);
  const selected = workspace.groups.find((group) => group.id === entityId);
  const changing = workspace.groups.find((group) => group.id === change?.groupId);
  const busy = access.busy || access.loading;
  const directory = useMemo<GroupDirectoryRecord[]>(() => workspace.groups.map((group) => ({
    id: group.id,
    name: group.name,
    description: group.description,
    createdAt: group.createdAt,
    memberCount: group.memberIds.length,
    directPolicyCount: group.policyIds.length
  })), [workspace.groups]);
  const userById = useMemo(() => new Map<string, GroupUser>(scene.users.map((user) => [user.id, user])), [scene.users]);
  const policyById = useMemo(() => new Map(workspace.policies.map((policy) => [policy.id, policy])), [workspace.policies]);
  const selectedRecord = useMemo<GroupDetailRecord | undefined>(() => {
    if (!selected) return undefined;
    return {
      id: selected.id,
      name: selected.name,
      description: selected.description,
      createdAt: selected.createdAt,
      memberCount: selected.memberIds.length,
      directPolicyCount: selected.policyIds.length,
      members: selected.memberIds.map((userId) => {
        const user = userById.get(userId);
        return {
          id: `preview-membership:${selected.id}:${userId}`,
          userId,
          name: user?.loginName ?? userId,
          description: user?.name,
          identityType: user ? "child" : "unknown",
          state: user?.state
        };
      }),
      policies: selected.policyIds.map((policyId) => {
        const policy = policyById.get(policyId);
        return {
          id: `preview-attachment:${selected.id}:${policyId}`,
          policyId,
          name: policy?.name ?? policyId,
          description: policy?.description,
          kind: policy?.kind,
          version: policy?.defaultVersion
        };
      })
    };
  }, [policyById, selected, userById]);

  if (entityId && !selected) {
    return <EmptyState
      title={t("entityUnavailable")}
      description={t("entityUnavailableHint")}
      action={<Button variant="secondary" onClick={() => onOpen("groups")}>{t("back")}</Button>}
    />;
  }

  return <>
    {selected && selectedRecord ? <GroupDetail
      group={selectedRecord}
      controls={{
        edit: { disabled: busy, onInvoke: () => setEditing(selected) },
        delete: { disabled: busy, onInvoke: () => setDeleting(selected) },
        addMember: { disabled: busy, onInvoke: () => setChange({ groupId: selected.id, kind: "members", mode: "add" }) },
        removeMember: { disabled: busy || !selected.memberIds.length, onInvoke: () => setChange({ groupId: selected.id, kind: "members", mode: "remove" }) },
        addPolicy: { disabled: busy, onInvoke: () => setChange({ groupId: selected.id, kind: "policies", mode: "add" }) },
        removePolicy: { disabled: busy || !selected.policyIds.length, onInvoke: () => setChange({ groupId: selected.id, kind: "policies", mode: "remove" }) }
      }}
      onBack={() => onOpen("groups")}
      onOpen={onOpen}
    /> : <GroupDirectory groups={directory} create={{ disabled: busy, onInvoke: onCreate }} onOpen={onOpen} />}
    {editing ? <GroupMetadataEditor group={editing} onClose={() => setEditing(null)} /> : null}
    {changing && change ? <GroupAssociationEditor group={changing} workspace={workspace} scene={scene} change={change} onClose={() => setChange(null)} /> : null}
    {deleting ? <WorkspaceDelete
      name={deleting.name}
      impact={<Alert status="warning">
        {g("deleteImpact", { members: deleting.memberIds.length, policies: deleting.policyIds.length })} {g("remainingSources")}
      </Alert>}
      onClose={() => setDeleting(null)}
      onConfirm={async () => {
        const result = await access.executeWorkspace({ kind: "delete-group", id: deleting.id });
        if (result && entityId === deleting.id) onOpen("groups");
        return result;
      }}
    /> : null}
  </>;
}
