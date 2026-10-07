"use client";

import { useState, type ReactNode, type RefObject } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, EmptyState, Table, TableSkeleton, Tabs } from "@ui/xiak";
import { AuthorizationOverview, WorkspaceCollection, WorkspaceDetail, WorkspaceRelationshipDirectory, WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

export type GroupActionControl = {
  disabled?: boolean;
  reason?: string;
  onInvoke(): void;
};

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
  kind?: "system" | "custom";
  version?: number | string;
  documentEffect?: "allowStatementsOnly" | "containsDeny";
};

export type GroupDetailRecord = GroupDirectoryRecord & {
  members: GroupMemberRecord[];
  policies: GroupPolicyRecord[];
  /** False while an opaque continuation proves that only a loaded prefix is present. */
  membersDirectoryComplete?: boolean;
  /** Present only when every attached policy's current default document is available to this view. */
  policyDocumentEffects?: "complete";
  membersAvailability?: "ready" | "loading" | "refreshing" | "forbidden" | "error";
  membersError?: string;
};

export type GroupDetailControls = {
  edit?: GroupActionControl;
  delete?: GroupActionControl;
  addMember?: GroupActionControl;
  removeMember?: GroupActionControl;
  addPolicy?: GroupActionControl;
  removePolicy?: GroupActionControl;
  loadMoreMembers?: GroupActionControl;
  retryMembers?: GroupActionControl;
};

export function GroupDirectory({ groups, create, loadMore, status, footerNote, loading, unavailable, onOpen }: {
  groups: GroupDirectoryRecord[];
  create?: GroupActionControl;
  loadMore?: GroupActionControl;
  status?: string;
  footerNote?: string;
  loading?: boolean;
  unavailable?: { description?: string; retry: GroupActionControl };
  onOpen(groupId: string): void;
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
    loadMore={loadMore ? { label: g("loadMore"), disabled: loadMore.disabled, onClick: loadMore.onInvoke } : undefined}
    status={status}
    footerNote={footerNote}
    loading={loading ? { label: g("loadingGroups"), rows: 6 } : undefined}
    unavailable={unavailable ? {
      title: g("directoryUnavailable"),
      description: unavailable.description,
      action: <Button variant="secondary" disabled={unavailable.retry.disabled} title={unavailable.retry.reason} onClick={unavailable.retry.onInvoke}>{g("retry")}</Button>
    } : undefined}
    columns={[t("name"), ...(showMemberCount ? [t("members")] : []), g("directPolicies"), t("created")]}
    row={(group) => <>
      <td>
        <Table.PrimaryAction onClick={() => onOpen(group.id)}>{group.name}</Table.PrimaryAction>
        <small>{group.description}</small>
      </td>
      {showMemberCount ? <td>{t("memberCount", { count: group.memberCount! })}</td> : null}
      <td>{g("directPolicyCount", { count: group.directPolicyCount })}</td>
      <td><WorkspaceTime value={group.createdAt} /></td>
    </>}
  />;
}

function GroupMemberTable({ members, authoritativeTotal, directoryComplete = true, loadMore, onOpen }: {
  members: GroupMemberRecord[];
  authoritativeTotal?: number;
  directoryComplete?: boolean;
  loadMore?: GroupActionControl;
  onOpen(userId: string): void;
}) {
  const t = useTranslations("IamWorkspace");
  const a = useTranslations("AccountAccess");
  const g = useTranslations("GroupWorkspace");
  const relationship = useTranslations("RelationshipDirectory");
  return <WorkspaceRelationshipDirectory title={t("members")} searchLabel={g("searchMembers")} items={members}
    status={(shown, loaded) => !directoryComplete && authoritativeTotal !== undefined
      ? relationship("partialResults", { shown, loaded, total: authoritativeTotal })
      : authoritativeTotal === undefined ? relationship("loadedResults", { shown, loaded }) : relationship("completeResults", { shown, total: authoritativeTotal })}
    footerNote={relationship(directoryComplete ? "completeScope" : "loadedScope")}
    busy={Boolean(loadMore?.disabled)} loadMore={loadMore ? { label: g("loadMoreMembers"), disabled: loadMore.disabled, reason: loadMore.reason, onClick: loadMore.onInvoke } : undefined}
    emptyTitle={g(directoryComplete ? "noMembers" : "noLoadedMembers")} emptyDescription={g(directoryComplete ? "noMembersHint" : "noLoadedMembersHint")}
    keywords={(member) => [member.userId, member.description ?? "", a(member.identityType), member.state ? a(`states.${member.state}`) : ""].join(" ")}
    columns={[t("name"), a("userType"), t("state")]} row={(member, blocked) => <>
      <td data-label={t("name")}>
        <button className={styles.userLink} disabled={blocked} onClick={() => onOpen(member.userId)}>{member.name}</button>
        <small>{member.description}</small>
      </td>
      <td data-label={a("userType")}>{a(member.identityType)}</td>
      <td data-label={t("state")}>{member.state
        ? <Badge status={member.state === "disabled" ? "neutral" : "success"}>{a(`states.${member.state}`)}</Badge>
        : "—"}</td>
    </>} />;
}

function GroupPolicyTable({ policies, onOpen }: {
  policies: GroupPolicyRecord[];
  onOpen(policyId: string): void;
}) {
  const t = useTranslations("IamWorkspace");
  const g = useTranslations("GroupWorkspace");
  const relationship = useTranslations("RelationshipDirectory");
  const showDocumentEffect = policies.some((policy) => policy.documentEffect !== undefined);
  const columns = [t("name"), t("type"), t("version"), ...(showDocumentEffect ? [t("documentEffect")] : [])];
  return <WorkspaceRelationshipDirectory title={t("permissions")} searchLabel={g("searchPolicies")} items={policies}
    status={(shown) => relationship("completeResults", { shown, total: policies.length })} footerNote={relationship("completeScope")}
    emptyTitle={g("noPolicies")} keywords={(policy) => [policy.policyId, policy.description ?? "", policy.kind ? t(policy.kind) : ""].join(" ")} columns={columns} row={(policy, blocked) => <>
      <td data-label={t("name")}>
        <button className={styles.userLink} disabled={blocked} onClick={() => onOpen(policy.policyId)}>{policy.name}</button>
        <small>{policy.description}</small>
      </td>
      <td data-label={t("type")}>{policy.kind ? t(policy.kind) : "—"}</td>
      <td data-label={t("version")}>{policy.version === undefined ? "—" : typeof policy.version === "number" ? `v${policy.version}` : policy.version}</td>
      {showDocumentEffect ? <td data-label={t("documentEffect")}>{policy.documentEffect
        ? <Badge status={policy.documentEffect === "containsDeny" ? "danger" : "neutral"}>{t(policy.documentEffect)}</Badge>
        : "—"}</td> : null}
    </>} />;
}

function GroupActionButton({ control, triggerRef, children, variant }: {
  control?: GroupActionControl;
  triggerRef?: RefObject<HTMLButtonElement | null>;
  children: string;
  variant?: "secondary" | "ghost";
}) {
  if (!control) return null;
  return <Button
    ref={triggerRef}
    disabled={control.disabled}
    onClick={control.onInvoke}
    title={control.disabled ? control.reason : undefined}
    variant={variant}
  >{children}</Button>;
}

export function GroupDetail({ group, controls, workflow, editTriggerRef, actionFocusRef, addMemberTriggerRef, removeMemberTriggerRef, addPolicyTriggerRef, removePolicyTriggerRef, onBack, onOpenMember, onOpenPolicy }: {
  group: GroupDetailRecord;
  controls: GroupDetailControls;
  workflow?: ReactNode;
  editTriggerRef?: RefObject<HTMLButtonElement | null>;
  actionFocusRef?: RefObject<{ focus(): void } | null>;
  addMemberTriggerRef?: RefObject<HTMLButtonElement | null>;
  removeMemberTriggerRef?: RefObject<HTMLButtonElement | null>;
  addPolicyTriggerRef?: RefObject<HTMLButtonElement | null>;
  removePolicyTriggerRef?: RefObject<HTMLButtonElement | null>;
  onBack(): void;
  onOpenMember(userId: string): void;
  onOpenPolicy(policyId: string): void;
}) {
  const t = useTranslations("IamWorkspace");
  const g = useTranslations("GroupWorkspace");
  const [activeTab, setActiveTab] = useState<"members" | "policies">("members");
  const policiesWithDeny = group.policies.filter((policy) => policy.documentEffect === "containsDeny").length;
  const showAuthorizationOverview = group.policyDocumentEffects === "complete" && group.memberCount !== undefined;

  return <WorkspaceDetail
    title={group.name}
    onBack={onBack}
    primaryActionRef={editTriggerRef}
    actionFocusRef={actionFocusRef}
    actions={workflow ? undefined : {
      primary: controls.edit ? { id: "edit", label: t("edit"), variant: "secondary", disabled: controls.edit.disabled, disabledReason: controls.edit.disabled ? controls.edit.reason : undefined, onSelect: controls.edit.onInvoke } : undefined,
      secondary: controls.delete ? [{ id: "delete", label: t("delete"), danger: true, disabled: controls.delete.disabled, disabledReason: controls.delete.disabled ? controls.delete.reason : undefined, onSelect: controls.delete.onInvoke }] : undefined
    }}
  >
    {workflow ?? <>
    <p className={styles.note}>{group.description || t("none")}</p>
    <Alert>{g("groupIdentityHint")}</Alert>
    <dl className={styles.facts}>
      <div><dt>ID</dt><dd>{group.id}</dd></div>
      <div><dt>{t("created")}</dt><dd><WorkspaceTime value={group.createdAt} /></dd></div>
    </dl>
    {showAuthorizationOverview ? <AuthorizationOverview
      title={g("authorizationOverview")}
      hint={g("authorizationOverviewHint")}
      items={[
        { label: t("members"), value: t("memberCount", { count: group.memberCount! }) },
        { label: g("directPolicies"), value: g("directPolicyCount", { count: group.directPolicyCount }) },
        { label: t("policiesWithDeny"), value: <><strong>{policiesWithDeny}</strong> {t(policiesWithDeny === 1 ? "item" : "items")}</> },
        { label: t("permissionBoundary"), value: g("noPermissionBoundary") }
      ]}
    /> : null}
    <Tabs.Root value={activeTab} onValueChange={(value) => setActiveTab(value as "members" | "policies")}>
      <Tabs.List aria-label={group.name}>
        <Tabs.Trigger value="members">{t("members")}{group.memberCount === undefined ? null : ` (${group.memberCount})`}</Tabs.Trigger>
        <Tabs.Trigger value="policies">{g("directPolicies")} ({group.directPolicyCount})</Tabs.Trigger>
      </Tabs.List>
      <Tabs.Content className={styles.stack} value="members">
        <div className={styles.actions}>
          <GroupActionButton control={controls.addMember} triggerRef={addMemberTriggerRef}>{g("addMembers")}</GroupActionButton>
          <GroupActionButton control={controls.removeMember} triggerRef={removeMemberTriggerRef} variant="secondary">{g("removeMembers")}</GroupActionButton>
        </div>
        {group.membersAvailability === "loading" ? <TableSkeleton label={g("loadingMembers")} rows={3} header={false} />
          : group.membersAvailability === "forbidden" ? <EmptyState title={g("membersUnavailable")} description={g("membersUnavailableHint")} />
          : group.membersAvailability === "error" ? <EmptyState title={g("membersLoadFailed")} description={group.membersError ?? g("membersLoadFailedHint")} action={<GroupActionButton control={controls.retryMembers} variant="secondary">{g("retry")}</GroupActionButton>} />
          : <>{group.membersAvailability === "refreshing" ? <Alert status="info">{g("refreshingMembers")}</Alert> : null}
            {group.members.length || group.membersDirectoryComplete === false
              ? <GroupMemberTable members={group.members} authoritativeTotal={group.memberCount} directoryComplete={group.membersDirectoryComplete} loadMore={controls.loadMoreMembers} onOpen={onOpenMember} />
              : <EmptyState title={g("noMembers")} description={g("noMembersHint")} />}</>}
      </Tabs.Content>
      <Tabs.Content className={styles.stack} value="policies">
        <div className={styles.actions}>
          <GroupActionButton control={controls.addPolicy} triggerRef={addPolicyTriggerRef}>{g("addPolicies")}</GroupActionButton>
          <GroupActionButton control={controls.removePolicy} triggerRef={removePolicyTriggerRef} variant="secondary">{g("removePolicies")}</GroupActionButton>
        </div>
        <Alert>{g("policyChangeHint")}</Alert>
        {group.policies.length
          ? <GroupPolicyTable policies={group.policies} onOpen={onOpenPolicy} />
          : <EmptyState title={g("noPolicies")} />}
      </Tabs.Content>
    </Tabs.Root>
    </>}
  </WorkspaceDetail>;
}
