"use client";

import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, EmptyState, FormField, Input, PageSkeleton, TextArea } from "@ui/xiak";
import { accountError, type GroupAccessClient } from "../application/AccountAccessProvider";
import type {
  AccountAccessView,
  GroupAccess,
  GroupMembershipAccess,
  IamAction
} from "../domain/accounts";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { findActionCapability } from "../scenes/accountAccessScene";
import { WorkspaceDelete, WorkspaceDialog, WorkspaceSelection } from "./AccessWorkspaceUi";
import {
  GroupDetail,
  GroupDirectory,
  type GroupDetailRecord,
  type GroupDirectoryRecord
} from "./GroupAccessWorkspace";
import styles from "./AccountAccessRenderer.module.css";

type OpenGroupEntity = (view: AccountAccessView, id?: string) => void;
type GroupChange = { kind: "members" | "policies"; mode: "add" | "remove" };
type OperationState = { busy: boolean; error: string | null };

function commandId(): string {
  return crypto.randomUUID();
}

function groupCapability(access: GroupAccess, action: IamAction) {
  return findActionCapability(access.capabilities, action, "GROUP", access.group.id);
}

function operationProps(state: OperationState, clearError: () => void) {
  return { busy: state.busy, error: state.error ?? undefined, clearError };
}

async function readGroupSnapshot(client: GroupAccessClient, groupId: string) {
  const access = await client.get(groupId);
  if (groupCapability(access, "iam.group-membership.list")?.available !== true) {
    return { access, memberships: [] as GroupMembershipAccess[], nextAfter: null as string | null, membersPhase: "forbidden" as const };
  }
  const page = await client.listMemberships(groupId);
  return { access, memberships: page.items, nextAfter: page.nextAfter, membersPhase: "ready" as const };
}

function LiveGroupMetadataEditor({ client, access, onClose, onChanged, onStale }: {
  client: GroupAccessClient;
  access: GroupAccess;
  onClose(): void;
  onChanged(): Promise<void>;
  onStale(): void;
}) {
  const t = useTranslations("IamWorkspace");
  const g = useTranslations("GroupWorkspace");
  const id = useId();
  const [name, setName] = useState(access.group.name);
  const [description, setDescription] = useState(access.group.description);
  const [operation, setOperation] = useState<OperationState>({ busy: false, error: null });
  const requestId = useRef(commandId());
  const clearError = useCallback(() => setOperation((current) => current.error ? { ...current, error: null } : current), []);
  const changeIntent = (update: () => void) => {
    update();
    requestId.current = commandId();
    clearError();
  };

  return <WorkspaceDialog
    title={`${t("edit")} · ${access.group.name}`}
    onClose={onClose}
    operation={operationProps(operation, clearError)}
    onSubmit={async () => {
      if (!name.trim() || /[<>\u0000-\u001f]/.test(name)) {
        setOperation({ busy: false, error: g("invalidName") });
        return false;
      }
      setOperation({ busy: true, error: null });
      try {
        await client.update(access.group.id, {
          name: name.trim(),
          description,
          resourceVersion: access.group.resourceVersion,
          requestId: requestId.current
        });
        await onChanged();
        return true;
      } catch (failure) {
        const code = accountError(failure);
        if (code === "conflict") onStale();
        else setOperation({ busy: false, error: t(`errors.${code}`) });
        return false;
      } finally {
        setOperation((current) => current.busy ? { ...current, busy: false } : current);
      }
    }}
  >
    <FormField id={`${id}-name`} label={t("name")}>
      <Input id={`${id}-name`} required maxLength={64} value={name} onChange={(event) => changeIntent(() => setName(event.target.value))} />
    </FormField>
    <FormField id={`${id}-description`} label={t("description")}>
      <TextArea id={`${id}-description`} maxLength={512} rows={3} value={description} onChange={(event) => changeIntent(() => setDescription(event.target.value))} />
    </FormField>
  </WorkspaceDialog>;
}

function LiveGroupAssociationEditor({ client, access, memberships, scene, change, onClose, onChanged, onStale }: {
  client: GroupAccessClient;
  access: GroupAccess;
  memberships: GroupMembershipAccess[];
  scene: AccountAccessScene;
  change: GroupChange;
  onClose(): void;
  onChanged(): Promise<void>;
  onStale(): void;
}) {
  const t = useTranslations("GroupWorkspace");
  const w = useTranslations("IamWorkspace");
  const a = useTranslations("AccountAccess");
  const [selection, setSelection] = useState<string[]>([]);
  const [review, setReview] = useState(false);
  const [operation, setOperation] = useState<OperationState>({ busy: false, error: null });
  const requestId = useRef(commandId());
  const clearError = useCallback(() => setOperation((current) => current.error ? { ...current, error: null } : current), []);
  const memberById = useMemo(() => new Map(scene.users.map((user) => [user.id, user])), [scene.users]);
  const policyById = useMemo(() => new Map(scene.policies.map((policy) => [policy.id, policy])), [scene.policies]);
  const activeUserIds = useMemo(() => new Set(memberships.map((entry) => entry.membership.userId)), [memberships]);
  const attachedPolicyIds = useMemo(() => new Set(access.policyAttachments.map((entry) => entry.policyId)), [access.policyAttachments]);
  const options = useMemo(() => {
    if (change.kind === "members" && change.mode === "add") return scene.users
      .filter((user) => !activeUserIds.has(user.id))
      .map((user) => ({ id: user.id, name: user.loginName, description: `${a("child")} · ${user.name}` }));
    if (change.kind === "members") return memberships
      .filter((entry) => findActionCapability(entry.capabilities, "iam.group-membership.remove", "GROUP_MEMBERSHIP", entry.membership.id)?.available === true)
      .map((entry) => {
        const user = memberById.get(entry.membership.userId);
        return { id: entry.membership.id, name: user?.loginName ?? entry.membership.userId, description: user?.name ?? t("unresolvedUser") };
      });
    if (change.mode === "add") return scene.policies
      .filter((policy) => policy.scopeKind === "tenant" && policy.available && !attachedPolicyIds.has(policy.id))
      .map((policy) => ({ id: policy.id, name: policy.displayName, description: `${w(policy.owner === "system" ? "system" : "custom")} · ${policy.id}` }));
    return access.policyAttachments
      .filter((attachment) => findActionCapability(access.capabilities, "iam.group-policy-attachment.revoke", "POLICY_ATTACHMENT", attachment.id)?.available === true)
      .map((attachment) => {
        const policy = policyById.get(attachment.policyId);
        return { id: attachment.id, name: policy?.displayName ?? attachment.policyId, description: policy?.id ?? attachment.policyId };
      });
  }, [a, access.capabilities, access.policyAttachments, activeUserIds, attachedPolicyIds, change.kind, change.mode, memberById, memberships, policyById, scene.policies, scene.users, t, w]);
  const label = t(`${change.mode}${change.kind === "members" ? "Members" : "Policies"}`);
  const selected = options.find((option) => option.id === selection[0]);

  const select = (ids: string[]) => {
    setSelection(ids);
    setReview(false);
    requestId.current = commandId();
    clearError();
  };

  return <WorkspaceDialog
    size="wide"
    title={`${label} · ${access.group.name}`}
    onClose={onClose}
    submitLabel={t(review ? "confirmChange" : "reviewChange")}
    submitDisabled={!selection.length}
    operation={operationProps(operation, clearError)}
    onSubmit={async () => {
      if (!selected) return false;
      if (!review) { setReview(true); return false; }
      setOperation({ busy: true, error: null });
      try {
        if (change.kind === "members" && change.mode === "add") {
          await client.createMembership(access.group.id, { userId: selected.id, requestId: requestId.current });
        } else if (change.kind === "members") {
          const membership = memberships.find((entry) => entry.membership.id === selected.id)?.membership;
          if (!membership) throw new Error("STALE_GROUP_MEMBERSHIP");
          await client.removeMembership(access.group.id, membership.id, { resourceVersion: membership.resourceVersion, requestId: requestId.current });
        } else if (change.mode === "add") {
          const policy = scene.policies.find((entry) => entry.id === selected.id);
          if (!policy) throw new Error("STALE_GROUP_POLICY");
          await client.createPolicyAttachment(access.group.id, { policyId: policy.id, policyResourceVersion: policy.resourceVersion, requestId: requestId.current });
        } else {
          const attachment = access.policyAttachments.find((entry) => entry.id === selected.id);
          if (!attachment) throw new Error("STALE_GROUP_ATTACHMENT");
          await client.revokePolicyAttachment(attachment.id, { resourceVersion: attachment.resourceVersion, requestId: requestId.current });
        }
        await onChanged();
        return true;
      } catch (failure) {
        const code = accountError(failure);
        if (code === "conflict") onStale();
        else setOperation({ busy: false, error: w(`errors.${code}`) });
        return false;
      } finally {
        setOperation((current) => current.busy ? { ...current, busy: false } : current);
      }
    }}
  >
    {review ? <>
      <Alert status={change.mode === "remove" ? "warning" : "info"}>{t("singleRelationImpact")}</Alert>
      <div className={styles.roleTags}><Badge>{selected?.name}</Badge></div>
      {change.mode === "remove" ? <Alert status="warning">{t("remainingSources")}</Alert> : null}
      <div><Button variant="secondary" onClick={() => { setReview(false); clearError(); }}>{t("backToSelection")}</Button></div>
    </> : <>
      <Alert>{t(change.kind === "members" ? "membershipHint" : "policyChangeHint")}</Alert>
      <WorkspaceSelection label={label} options={options} value={selection} onChange={select} limit={1} />
      {change.kind === "members" && change.mode === "add" && !scene.directoryComplete ? <p className={styles.note}>{t("loadedUsersOnly")}</p> : null}
    </>}
  </WorkspaceDialog>;
}

function LiveGroupDelete({ client, access, onClose, onDeleted, onStale }: {
  client: GroupAccessClient;
  access: GroupAccess;
  onClose(): void;
  onDeleted(): void;
  onStale(): void;
}) {
  const t = useTranslations("GroupWorkspace");
  const w = useTranslations("IamWorkspace");
  const [operation, setOperation] = useState<OperationState>({ busy: false, error: null });
  const requestId = useRef(commandId());
  const clearError = useCallback(() => setOperation((current) => current.error ? { ...current, error: null } : current), []);

  return <WorkspaceDelete
    name={access.group.name}
    onClose={onClose}
    operation={operationProps(operation, clearError)}
    impact={<Alert status="warning">{t("liveDeleteImpact")}</Alert>}
    onConfirm={async () => {
      setOperation({ busy: true, error: null });
      try {
        await client.delete(access.group.id, { resourceVersion: access.group.resourceVersion, requestId: requestId.current });
        onDeleted();
        return true;
      } catch (failure) {
        const code = accountError(failure);
        if (code === "conflict") onStale();
        else setOperation({ busy: false, error: w(`errors.${code}`) });
        return false;
      } finally {
        setOperation((current) => current.busy ? { ...current, busy: false } : current);
      }
    }}
  />;
}

function LiveGroupWorkspace({ client, entityId, scene, onOpen }: {
  client: GroupAccessClient;
  entityId: string;
  scene: AccountAccessScene;
  onOpen: OpenGroupEntity;
}) {
  const t = useTranslations("GroupWorkspace");
  const a = useTranslations("AccountAccess");
  const w = useTranslations("IamWorkspace");
  const requestVersion = useRef(0);
  const [access, setAccess] = useState<GroupAccess | null>(null);
  const [memberships, setMemberships] = useState<GroupMembershipAccess[]>([]);
  const [nextAfter, setNextAfter] = useState<string | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "error">("loading");
  const [membersPhase, setMembersPhase] = useState<"loading" | "ready" | "forbidden">("loading");
  const [pageError, setPageError] = useState<string | null>(null);
  const [change, setChange] = useState<GroupChange | null>(null);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);

  const applySnapshot = useCallback((snapshot: Awaited<ReturnType<typeof readGroupSnapshot>>) => {
    setPageError(null);
    setAccess(snapshot.access);
    setMemberships(snapshot.memberships);
    setNextAfter(snapshot.nextAfter);
    setMembersPhase(snapshot.membersPhase);
    setPhase("ready");
  }, []);

  const applyFailure = useCallback((failure: unknown, initial: boolean) => {
    setPageError(a(`errors.${accountError(failure)}`));
    if (initial) setPhase("error");
  }, [a]);

  const load = useCallback(async (initial = false) => {
    const version = ++requestVersion.current;
    try {
      const snapshot = await readGroupSnapshot(client, entityId);
      if (version !== requestVersion.current) return;
      applySnapshot(snapshot);
    } catch (failure) {
      if (version !== requestVersion.current) return;
      applyFailure(failure, initial);
    }
  }, [applyFailure, applySnapshot, client, entityId]);

  useEffect(() => {
    const version = ++requestVersion.current;
    readGroupSnapshot(client, entityId).then((snapshot) => {
      if (version === requestVersion.current) applySnapshot(snapshot);
    }, (failure: unknown) => {
      if (version === requestVersion.current) applyFailure(failure, true);
    });
    return () => { requestVersion.current += 1; };
  }, [applyFailure, applySnapshot, client, entityId]);

  const userById = useMemo(() => new Map(scene.users.map((user) => [user.id, user])), [scene.users]);
  const policyById = useMemo(() => new Map(scene.policies.map((policy) => [policy.id, policy])), [scene.policies]);
  const record = useMemo<GroupDetailRecord | null>(() => {
    if (!access) return null;
    return {
      id: access.group.id,
      name: access.group.name,
      description: access.group.description,
      createdAt: access.group.createdAt,
      directPolicyCount: access.policyAttachments.length,
      membersAvailability: membersPhase === "forbidden" ? "forbidden" : membersPhase === "ready" ? "ready" : "loading",
      members: memberships.map((entry) => {
        const user = userById.get(entry.membership.userId);
        return {
          id: entry.membership.id,
          userId: entry.membership.userId,
          name: user?.loginName ?? entry.membership.userId,
          description: user?.name ?? t("unresolvedUser"),
          identityType: user ? "child" : "unknown",
          state: user?.state
        };
      }),
      policies: access.policyAttachments.map((attachment) => {
        const policy = policyById.get(attachment.policyId);
        return {
          id: attachment.id,
          policyId: attachment.policyId,
          name: policy?.displayName ?? attachment.policyId,
          kind: policy ? policy.owner === "system" ? "system" : "custom" : undefined,
          version: policy?.defaultVersionId
        };
      })
    };
  }, [access, memberships, membersPhase, policyById, t, userById]);

  if (phase === "loading") return <PageSkeleton label={t("loadingGroup")} layout="access" />;
  if (phase === "error" || !access || !record) return <EmptyState title={w("entityUnavailable")} description={pageError ?? w("entityUnavailableHint")} action={<Button variant="secondary" onClick={() => void load(true)}>{t("retry")}</Button>} />;

  const edit = groupCapability(access, "iam.group.update");
  const remove = groupCapability(access, "iam.group.delete");
  const addMember = groupCapability(access, "iam.group-membership.create");
  const addPolicy = groupCapability(access, "iam.group-policy-attachment.create");
  const removableMembers = memberships.some((entry) => findActionCapability(entry.capabilities, "iam.group-membership.remove", "GROUP_MEMBERSHIP", entry.membership.id)?.available === true);
  const removablePolicies = access.policyAttachments.some((attachment) => findActionCapability(access.capabilities, "iam.group-policy-attachment.revoke", "POLICY_ATTACHMENT", attachment.id)?.available === true);
  const stale = () => { setEditing(false); setDeleting(false); setChange(null); setPageError(a("errors.conflict")); void load(); };

  return <>
    {pageError ? <Alert status="warning">{pageError}</Alert> : null}
    <GroupDetail
      group={record}
      controls={{
        edit: { disabled: edit?.available !== true, reason: edit?.restrictionReason ?? undefined, onInvoke: () => setEditing(true) },
        delete: { disabled: remove?.available !== true, reason: remove?.restrictionReason ?? undefined, onInvoke: () => setDeleting(true) },
        addMember: { disabled: addMember?.available !== true || !scene.users.some((user) => !memberships.some((entry) => entry.membership.userId === user.id)), reason: addMember?.restrictionReason ?? undefined, onInvoke: () => setChange({ kind: "members", mode: "add" }) },
        removeMember: { disabled: !removableMembers, onInvoke: () => setChange({ kind: "members", mode: "remove" }) },
        addPolicy: { disabled: addPolicy?.available !== true || !scene.policies.some((policy) => policy.scopeKind === "tenant" && policy.available && !access.policyAttachments.some((attachment) => attachment.policyId === policy.id)), reason: addPolicy?.restrictionReason ?? undefined, onInvoke: () => setChange({ kind: "policies", mode: "add" }) },
        removePolicy: { disabled: !removablePolicies, onInvoke: () => setChange({ kind: "policies", mode: "remove" }) },
        loadMoreMembers: nextAfter ? { disabled: loadingMore, onInvoke: async () => {
          if (!nextAfter || loadingMore) return;
          setLoadingMore(true);
          try {
            const page = await client.listMemberships(entityId, nextAfter);
            setMemberships((current) => [...current, ...page.items]);
            setNextAfter(page.nextAfter);
          } catch (failure) { setPageError(a(`errors.${accountError(failure)}`)); }
          finally { setLoadingMore(false); }
        } } : undefined
      }}
      onBack={() => onOpen("groups")}
      onOpenMember={(userId) => onOpen("users", userId)}
      onOpenPolicy={(policyId) => onOpen("policies", policyId)}
    />
    {editing ? <LiveGroupMetadataEditor client={client} access={access} onClose={() => setEditing(false)} onChanged={() => load()} onStale={stale} /> : null}
    {change ? <LiveGroupAssociationEditor client={client} access={access} memberships={memberships} scene={scene} change={change} onClose={() => setChange(null)} onChanged={() => load()} onStale={stale} /> : null}
    {deleting ? <LiveGroupDelete client={client} access={access} onClose={() => setDeleting(false)} onDeleted={() => onOpen("groups")} onStale={stale} /> : null}
  </>;
}

export function AccountLiveGroups({ client, entityId, scene, onCreate, onOpen }: {
  client: GroupAccessClient;
  entityId?: string;
  scene: AccountAccessScene;
  onCreate(): void;
  onOpen: OpenGroupEntity;
}) {
  const t = useTranslations("GroupWorkspace");
  const a = useTranslations("AccountAccess");
  const [groups, setGroups] = useState<GroupAccess[]>([]);
  const [nextAfter, setNextAfter] = useState<string | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);

  useEffect(() => {
    if (entityId) return;
    let current = true;
    client.list().then((page) => {
      if (!current) return;
      setGroups(page.items);
      setNextAfter(page.nextAfter);
      setPhase("ready");
    }, (failure: unknown) => {
      if (!current) return;
      setError(a(`errors.${accountError(failure)}`));
      setPhase("error");
    });
    return () => { current = false; };
  }, [a, client, entityId]);

  if (entityId) return <LiveGroupWorkspace client={client} entityId={entityId} scene={scene} onOpen={onOpen} />;
  if (phase === "loading") return <PageSkeleton label={t("loadingGroups")} layout="access" />;
  if (phase === "error") return <EmptyState title={t("directoryUnavailable")} description={error ?? undefined} action={<Button variant="secondary" onClick={() => { setPhase("loading"); client.list().then((page) => { setGroups(page.items); setNextAfter(page.nextAfter); setPhase("ready"); setError(null); }, (failure: unknown) => { setError(a(`errors.${accountError(failure)}`)); setPhase("error"); }); }}>{t("retry")}</Button>} />;

  const directory: GroupDirectoryRecord[] = groups.map((entry) => ({
    id: entry.group.id,
    name: entry.group.name,
    description: entry.group.description,
    createdAt: entry.group.createdAt,
    directPolicyCount: entry.policyAttachments.length
  }));
  return <>
    {error ? <Alert status="warning">{error}</Alert> : null}
    <GroupDirectory
      groups={directory}
      status={t("loadedGroups", { count: groups.length })}
      footerNote={t("loadedSearchScope")}
      create={{ disabled: !client.canCreate, reason: client.createRestrictionReason ?? undefined, onInvoke: onCreate }}
      loadMore={nextAfter ? { disabled: loadingMore, onInvoke: async () => {
        if (!nextAfter || loadingMore) return;
        setLoadingMore(true);
        setError(null);
        try {
          const page = await client.list(nextAfter);
          const known = new Set(groups.map((entry) => entry.group.id));
          if (page.items.some((entry) => known.has(entry.group.id))) throw new Error("DUPLICATE_GROUP_PAGE");
          setGroups((current) => [...current, ...page.items]);
          setNextAfter(page.nextAfter);
        } catch (failure) { setError(a(`errors.${accountError(failure)}`)); }
        finally { setLoadingMore(false); }
      } } : undefined}
      onOpen={(groupId) => onOpen("groups", groupId)}
    />
  </>;
}
