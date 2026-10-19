"use client";

import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, EmptyState, FormField, Input, TableSkeleton, TextArea } from "@ui/xiak";
import { accountError, type GroupAccessClient } from "../application/AccountAccessProvider";
import { useGroupMembershipMutation, type GroupMembershipMutationClient } from "../application/groupMembershipMutation";
import type {
  AccountAccessView,
  GroupAccess,
  Group,
  GroupDeletion,
  GroupMembership,
  GroupMembershipAccess,
  IamAction,
  PolicyAttachmentChangeOperationExpectation
} from "../domain/accounts";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { findActionCapability } from "../scenes/accountAccessScene";
import { WorkspaceDelete, WorkspaceDetail, WorkspaceInlineForm, WorkspaceSelection, WorkspaceTime } from "./AccessWorkspaceUi";
import {
  GroupDetail,
  GroupDirectory,
  type GroupDetailRecord,
  type GroupDirectoryRecord
} from "./GroupAccessWorkspace";
import styles from "./AccountAccessRenderer.module.css";
import { PolicyAttachmentChangeFeedback, PolicyAttachmentReview, readPendingPolicyAttachmentChange, usePolicyAttachmentCommand } from "./PolicyAttachmentChangeFlow";

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

  return <WorkspaceInlineForm
    title={`${t("edit")} · ${access.group.name}`}
    backLabel={g("backToGroupDetails")}
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
  </WorkspaceInlineForm>;
}

function LiveGroupPolicyEditor({ client, access, scene, mode, onClose, onChanged }: {
  client: GroupAccessClient;
  access: GroupAccess;
  scene: AccountAccessScene;
  mode: "add" | "remove";
  onClose(): void;
  onChanged(): Promise<void>;
}) {
  const t = useTranslations("GroupWorkspace");
  const w = useTranslations("IamWorkspace");
  const p = useTranslations("PolicyAttachmentChange");
  const policyScope = useMemo(() => ({ accountId: client.accountId, actorPrincipalId: client.actorPrincipalId,
    target: { kind: "GROUP" as const, id: access.group.id } }), [access.group.id, client.accountId, client.actorPrincipalId]);
  const [restoredPolicyIntent] = useState(() => readPendingPolicyAttachmentChange(policyScope));
  const [selection, setSelection] = useState<string[]>(() => restoredPolicyIntent
    ? [restoredPolicyIntent.operation === "CREATE" ? restoredPolicyIntent.policyId : restoredPolicyIntent.attachmentId]
    : []);
  const [review, setReview] = useState(Boolean(restoredPolicyIntent));
  const [requestId, setRequestId] = useState(restoredPolicyIntent?.requestId ?? commandId());
  const policyById = useMemo(() => new Map(scene.policies.map((policy) => [policy.id, policy])), [scene.policies]);
  const attachedPolicyIds = useMemo(() => new Set(access.policyAttachments.map((entry) => entry.policyId)), [access.policyAttachments]);
  const options = useMemo(() => {
    if (mode === "add") return scene.policies
      .filter((policy) => policy.scopeKind === "tenant" && policy.available && !attachedPolicyIds.has(policy.id))
      .map((policy) => ({ id: policy.id, name: policy.displayName, description: `${w(policy.owner === "system" ? "system" : "custom")} · ${policy.id}` }));
    return access.policyAttachments
      .filter((attachment) => findActionCapability(access.capabilities, "iam.group-policy-attachment.revoke", "POLICY_ATTACHMENT", attachment.id)?.available === true)
      .map((attachment) => {
        const policy = policyById.get(attachment.policyId);
        return { id: attachment.id, name: policy?.displayName ?? attachment.policyId, description: policy?.id ?? attachment.policyId };
      });
  }, [access.capabilities, access.policyAttachments, attachedPolicyIds, mode, policyById, scene.policies, w]);
  const label = t(`${mode}Policies`);
  const selected = options.find((option) => option.id === selection[0]);
  const policyCommand = usePolicyAttachmentCommand<PolicyAttachmentChangeOperationExpectation>({
    scope: policyScope,
    execute: async (intent) => {
      if (intent.operation === "CREATE") {
        if (intent.target.kind !== "GROUP" || intent.target.id !== access.group.id) throw new Error("INVALID_GROUP_POLICY_TARGET");
        return client.createPolicyAttachment(access.group.id, {
          policyId: intent.policyId,
          policyResourceVersion: intent.policyResourceVersion,
          requestId: intent.requestId
        });
      }
      return client.revokePolicyAttachment(intent.attachmentId, {
        resourceVersion: intent.expectedResourceVersion,
        requestId: intent.requestId
      });
    },
    inspect: (intent) => client.inspectPolicyAttachmentChange(intent),
    refresh: onChanged
  });
  const policyBusy = policyCommand.state.phase === "pending" || policyCommand.state.phase === "checking";
  const policyLocked = policyCommand.locked;
  const recoveringPolicy = policyCommand.state.phase === "unknown" || policyCommand.state.phase === "checking" || policyCommand.state.phase === "refreshFailed";
  const selectedName = selected?.name ?? (policyCommand.intent?.operation === "CREATE"
    ? policyCommand.intent.policyId
    : policyCommand.intent?.attachmentId);
  const selectedPolicy = mode === "add" && selection[0] ? policyById.get(selection[0]) : undefined;
  const selectedAttachment = mode === "remove" ? access.policyAttachments.find((entry) => entry.id === selection[0]) : undefined;
  const reviewExpectation = policyCommand.intent ?? (mode === "add" && selectedPolicy
    ? { operation: "CREATE" as const, target: policyScope.target, policyId: selectedPolicy.id, policyResourceVersion: selectedPolicy.resourceVersion, requestId }
    : mode === "remove" && selectedAttachment
      ? { operation: "REVOKE" as const, attachmentId: selectedAttachment.id, expectedResourceVersion: selectedAttachment.resourceVersion, requestId }
      : null);
  const reviewPolicyId = reviewExpectation?.operation === "CREATE" ? reviewExpectation.policyId : selectedAttachment?.policyId;
  const reviewPolicyName = reviewPolicyId ? policyById.get(reviewPolicyId)?.displayName : undefined;

  const select = (ids: string[]) => {
    if (policyLocked) return;
    setSelection(ids);
    setReview(false);
    setRequestId(commandId());
    policyCommand.reset();
  };

  return <WorkspaceInlineForm
    title={`${label} · ${access.group.name}`}
    backLabel={t("backToGroupDetails")}
    onClose={onClose}
    cancelLabel={recoveringPolicy ? p("later") : policyCommand.state.phase === "completed" ? p("backToDetail") : undefined}
    submitLabel={policyCommand.state.phase === "completed" ? p("finish") : policyCommand.state.phase === "unknown" ? p("checkOriginalRequest") : policyCommand.state.phase === "checking" ? p("checking") : t(review ? "confirmChange" : "reviewChange")}
    submitDisabled={policyCommand.state.phase !== "completed" && (policyCommand.state.phase === "refreshFailed" || !recoveringPolicy && !selection.length)}
    operation={{ busy: policyBusy, clearError: () => undefined }}
    draft={{ dirty: policyCommand.state.phase === "idle" && (Boolean(selection.length) || review), title: label, description: p("unknownHint") }}
    onSubmit={async () => {
      if (policyCommand.state.phase === "completed") { policyCommand.reset(); return true; }
      if (policyCommand.state.phase === "unknown") return policyCommand.inspectOriginal();
      if (!selected) return false;
      if (!review) { setReview(true); return false; }
      if (mode === "add") {
          const policy = scene.policies.find((entry) => entry.id === selected.id);
          if (!policy) throw new Error("STALE_GROUP_POLICY");
          return policyCommand.run({ operation: "CREATE", target: { kind: "GROUP", id: access.group.id }, policyId: policy.id, policyResourceVersion: policy.resourceVersion, requestId });
      } else {
          const attachment = access.policyAttachments.find((entry) => entry.id === selected.id);
          if (!attachment) throw new Error("STALE_GROUP_ATTACHMENT");
          return policyCommand.run({ operation: "REVOKE", attachmentId: attachment.id, expectedResourceVersion: attachment.resourceVersion, requestId });
      }
    }}
  >
    <PolicyAttachmentChangeFeedback state={policyCommand.state} onRetryRead={policyCommand.retryRead} />
    {review ? <>
      <Alert status={mode === "remove" ? "warning" : "info"}>{t("singleRelationImpact")}</Alert>
      {reviewExpectation ? <PolicyAttachmentReview scope={policyScope} expectation={reviewExpectation} policyName={reviewPolicyName ?? selectedName} policyId={reviewPolicyId} /> : null}
      {mode === "remove" ? <Alert status="warning">{t("remainingSources")}</Alert> : null}
      <div><Button type="button" variant="secondary" disabled={policyLocked} onClick={() => { policyCommand.reset(); setReview(false); }}>{t("backToSelection")}</Button></div>
    </> : <>
      <Alert>{t("policyChangeHint")}</Alert>
      <WorkspaceSelection label={label} options={options} value={selection} onChange={select} limit={1}
        footnote={p(mode === "remove" ? "singleRevokeSelection" : "singleAttachSelection")} />
    </>}
  </WorkspaceInlineForm>;
}

function MembershipReceipt({ receipt }: { receipt: GroupMembership }) {
  const t = useTranslations("GroupMembershipCommand");
  return <Alert status="success" role="status" aria-label={t("receiptTitle")}>
    <strong>{t("receiptTitle")}</strong><p>{t("receiptBoundary")}</p>
    <dl className={styles.facts}>
      <div><dt>{t("membership")}</dt><dd><code>{receipt.id}</code></dd></div>
      <div><dt>{t("group")}</dt><dd><code>{receipt.groupId}</code></dd></div>
      <div><dt>{t("user")}</dt><dd><code>{receipt.userId}</code></dd></div>
      <div><dt>{t("revision")}</dt><dd>{receipt.resourceVersion}</dd></div>
      <div><dt>{t("result")}</dt><dd>{t(receipt.removedAt ? "removed" : "created")} · <WorkspaceTime value={receipt.removedAt ?? receipt.createdAt} /></dd></div>
    </dl>
  </Alert>;
}

function LiveGroupMembershipEditor({ group, mode, memberships, scene, command, canBegin = false, onClose, onCompleted, onStale }: {
  group: Pick<Group, "id" | "name">; mode: "add" | "remove"; memberships: GroupMembershipAccess[]; scene: AccountAccessScene;
  command: GroupMembershipMutationClient; canBegin?: boolean; onClose(): void; onCompleted(): void; onStale?(): void;
}) {
  const t = useTranslations("GroupWorkspace");
  const m = useTranslations("GroupMembershipCommand");
  const a = useTranslations("AccountAccess");
  const [selection, setSelection] = useState<string[]>([]);
  const [review, setReview] = useState<{ name: string; input: Parameters<GroupMembershipMutationClient["begin"]>[0] } | null>(null);
  const users = new Map(scene.users.map((user) => [user.id, user]));
  const options = mode === "add" ? scene.users.filter((user) => !user.protected && user.id !== scene.currentUserId && !memberships.some((item) => item.membership.userId === user.id))
    .map((user) => ({ id: user.id, name: user.loginName, description: `${a("child")} · ${user.name}` }))
    : memberships.filter((item) => findActionCapability(item.capabilities, "iam.group-membership.remove", "GROUP_MEMBERSHIP", item.membership.id)?.available === true)
      .map((item) => ({ id: item.membership.id, name: users.get(item.membership.userId)?.loginName ?? item.membership.userId, description: users.get(item.membership.userId)?.name ?? t("unresolvedUser") }));
  const selected = options.find((option) => option.id === selection[0]);
  const selectedMembership = mode === "remove" ? memberships.find((item) => item.membership.id === selected?.id)?.membership : null;
  const staleReview = Boolean(review && (!selected || review.input.operation === "REMOVE" &&
    (selectedMembership?.id !== review.input.membership.id || selectedMembership?.resourceVersion !== review.input.membership.resourceVersion || selectedMembership?.userId !== review.input.membership.userId)));
  const pending = command.pending;
  const title = `${t(`${pending ? pending.operation === "CREATE" ? "add" : "remove" : mode}Members`)} · ${group.name}`;
  return <WorkspaceInlineForm title={title} onClose={onClose} backLabel={t("backToGroupDetails")}
    operation={{ busy: command.busy, clearError: () => undefined }}
    cancelLabel={pending && !command.receipt ? m("later") : undefined}
    submitLabel={command.receipt && pending ? m("finish") : pending ? m("retryExact") : t(review ? "confirmChange" : "reviewChange")}
    submitDisabled={command.receipt && pending ? false : !command.ready || !pending && (!canBegin || !selected || staleReview)}
    draft={{ dirty: !pending && (Boolean(review) || selection.length > 0), title, description: m("leaveHint") }}
    onSubmit={async () => {
      if (pending && command.receipt) {
        if (command.acknowledge()) onCompleted();
        return false;
      }
      if (pending) {
        const result = await command.retry();
        if (result.status === "applied" && command.acknowledge()) onCompleted();
        return false;
      }
      if (!selected || !canBegin || staleReview) return false;
      if (!review) {
        if (mode === "remove" && !selectedMembership) return false;
        setReview({ name: selected.name, input: mode === "add" ? { operation: "CREATE", userId: selected.id } : { operation: "REMOVE", membership: structuredClone(selectedMembership!) } });
        return false;
      }
      const result = await command.begin(review.input);
      if (result.status === "applied" && command.acknowledge()) onCompleted();
      else if (result.status === "rejected" && result.reason === "conflict") onStale?.();
      return false;
    }}>
    {command.recoveryError ? <Alert status="danger">{m("storageUnavailable")}</Alert> : null}
    {command.busy ? <p role="status">{m("working")}</p> : command.error && !pending ? <Alert status="danger">{a(`errors.${command.error}`)}</Alert> : null}
    {pending ? <>
      {!command.receipt && !command.busy && !command.recoveryError ? <Alert status="warning"><strong>{m("unknown")}</strong>{command.error ? <p>{m("lastAttempt", { reason: a(`errors.${command.error}`) })}</p> : null}</Alert> : null}
      <dl className={styles.facts}>
        <div><dt>{m("account")}</dt><dd><code>{pending.accountId}</code></dd></div>
        <div><dt>{m("actor")}</dt><dd><code>{pending.actorPrincipalId}</code></dd></div>
        <div><dt>{m("group")}</dt><dd><code>{pending.groupId}</code></dd></div>
        <div><dt>{m("user")}</dt><dd><code>{pending.userId}</code></dd></div>
        <div><dt>{m("request")}</dt><dd><code>{pending.requestId}</code></dd></div>
        {pending.operation === "REMOVE" ? <><div><dt>{m("membership")}</dt><dd><code>{pending.membershipId}</code></dd></div><div><dt>{m("revision")}</dt><dd>{pending.resourceVersion}</dd></div></> : null}
      </dl>
      {command.receipt ? <MembershipReceipt receipt={command.receipt} /> : <Alert>{m("retryBoundary")}</Alert>}
    </> : review ? <>
      <Alert status={mode === "remove" ? "warning" : "info"}>{t("singleRelationImpact")}</Alert>
      <Badge>{review.name}</Badge>
      <p>{m("group")} <code>{group.id}</code> · {m("user")} <code>{review.input.operation === "CREATE" ? review.input.userId : review.input.membership.userId}</code></p>
      {review.input.operation === "REMOVE" ? <p>{m("membership")} <code>{review.input.membership.id}</code> · {m("revision")} {review.input.membership.resourceVersion}</p> : null}
      {staleReview || !canBegin ? <Alert status="warning">{m("staleReview")}</Alert> : null}
      {mode === "remove" ? <Alert status="warning">{t("remainingSources")}</Alert> : null}
      <Button variant="secondary" type="button" onClick={() => setReview(null)}>{t("backToSelection")}</Button>
    </> : <>
      <Alert>{t("membershipHint")}</Alert>
      <WorkspaceSelection label={t(`${mode}Members`)} options={options} value={selection} onChange={(value) => { setSelection(value); setReview(null); }} limit={1}
        footnote={m(mode === "remove" ? "singleRemoveSelection" : "singleAddSelection")} />
      {mode === "add" && !scene.directoryComplete ? <p className={styles.note}>{t("loadedUsersOnly")}</p> : null}
    </>}
  </WorkspaceInlineForm>;
}

function LiveGroupDelete({ client, access, onClose, onDeleted }: {
  client: GroupAccessClient;
  access: GroupAccess;
  onClose(): void;
  onDeleted(result: GroupDeletion): void;
}) {
  const t = useTranslations("GroupWorkspace");
  const w = useTranslations("IamWorkspace");
  const [operation, setOperation] = useState<OperationState>({ busy: false, error: null });
  const requestId = useRef(commandId());
  const currentClient = useRef<GroupAccessClient | null>(client);
  useLayoutEffect(() => { currentClient.current = client; return () => { currentClient.current = null; }; }, [client]);
  const clearError = useCallback(() => setOperation((current) => current.error ? { ...current, error: null } : current), []);

  return <WorkspaceDelete
    name={access.group.name}
    onClose={onClose}
    hint={t("liveDeleteConfirmHint")}
    operation={operationProps(operation, clearError)}
    impact={<Alert status="warning">{t("liveDeleteImpact")}</Alert>}
    onConfirm={async () => {
      setOperation({ busy: true, error: null });
      try {
        const result = await client.delete(access.group.id, { resourceVersion: access.group.resourceVersion, requestId: requestId.current });
        if (currentClient.current !== client) return false;
        if (result.id !== access.group.id || result.accountId !== client.accountId || result.name !== access.group.name ||
            result.resourceVersion !== access.group.resourceVersion + 1 || !Number.isSafeInteger(result.removedMemberships) || result.removedMemberships < 0 ||
            !Number.isSafeInteger(result.revokedPolicyAttachments) || result.revokedPolicyAttachments < 0 || !Number.isFinite(Date.parse(result.deletedAt))) throw new Error("INVALID_IAM_GROUP_DELETION");
        onDeleted(structuredClone(result));
        return true;
      } catch (failure) {
        if (currentClient.current !== client) return false;
        const code = accountError(failure);
        setOperation({ busy: false, error: code === "unavailable" ? t("liveDeleteUnconfirmed") : w(`errors.${code}`) });
        return false;
      } finally {
        setOperation((current) => current.busy ? { ...current, busy: false } : current);
      }
    }}
  />;
}

function LiveGroupWorkspace({ client, entityId, scene, onOpen, onDeleted }: {
  client: GroupAccessClient;
  entityId: string;
  scene: AccountAccessScene;
  onOpen: OpenGroupEntity;
  onDeleted(result: GroupDeletion): void;
}) {
  const t = useTranslations("GroupWorkspace");
  const a = useTranslations("AccountAccess");
  const w = useTranslations("IamWorkspace");
  const membershipCommand = useGroupMembershipMutation(client, entityId);
  const requestVersion = useRef(0);
  const membershipRequestVersion = useRef(0);
  const [access, setAccess] = useState<GroupAccess | null>(null);
  const [memberships, setMemberships] = useState<GroupMembershipAccess[]>([]);
  const [nextAfter, setNextAfter] = useState<string | null>(null);
  const [phase, setPhase] = useState<"loading" | "refreshing" | "ready" | "error">("loading");
  const [membersPhase, setMembersPhase] = useState<"loading" | "refreshing" | "ready" | "forbidden" | "error">("loading");
  const [membersError, setMembersError] = useState<string | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [change, setChange] = useState<GroupChange | null>(null);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleted, setDeleted] = useState<{ client: GroupAccessClient; result: GroupDeletion } | null>(null);
  const deletionNavigationStarted = useRef(false);
  useEffect(() => {
    if (!deleted || deleted.client !== client || deleting || deletionNavigationStarted.current) return;
    deletionNavigationStarted.current = true;
    // The dialog has unmounted and its busy/draft registration has cleaned up.
    // Only the actual command receipt triggers this ordinary guarded navigation.
    onDeleted(deleted.result);
    onOpen("groups");
  }, [client, deleted, deleting, onDeleted, onOpen]);
  const [loadingMore, setLoadingMore] = useState(false);
  const editTrigger = useRef<HTMLButtonElement>(null);
  const pageActionFocus = useRef<{ focus(): void }>(null);
  const previousEditing = useRef(false);
  const addMemberTrigger = useRef<HTMLButtonElement>(null);
  const removeMemberTrigger = useRef<HTMLButtonElement>(null);
  const addPolicyTrigger = useRef<HTMLButtonElement>(null);
  const removePolicyTrigger = useRef<HTMLButtonElement>(null);
  const previousChange = useRef<GroupChange | null>(null);

  const restorePendingPolicyChange = useCallback(() => {
    const pending = readPendingPolicyAttachmentChange({ accountId: client.accountId, actorPrincipalId: client.actorPrincipalId,
      target: { kind: "GROUP", id: entityId } });
    if (pending) setChange((current) => current ?? { kind: "policies", mode: pending.operation === "CREATE" ? "add" : "remove" });
  }, [client.accountId, client.actorPrincipalId, entityId]);

  const applyFailure = useCallback((failure: unknown) => {
    setPageError(a(`errors.${accountError(failure)}`));
    setPhase("error");
  }, [a]);

  const loadMemberships = useCallback(async (currentAccess: GroupAccess, refresh = false) => {
    const version = ++membershipRequestVersion.current;
    if (!refresh) {
      setMemberships([]);
      setNextAfter(null);
    }
    setMembersError(null);
    if (groupCapability(currentAccess, "iam.group-membership.list")?.available !== true) {
      setMemberships([]);
      setNextAfter(null);
      setMembersPhase("forbidden");
      return;
    }
    setMembersPhase(refresh ? "refreshing" : "loading");
    try {
      const page = await client.listMemberships(entityId);
      if (version !== membershipRequestVersion.current) return;
      setMemberships(page.items);
      setNextAfter(page.nextAfter);
      setMembersPhase("ready");
    } catch (failure) {
      if (version !== membershipRequestVersion.current) return;
      setMembersError(a(`errors.${accountError(failure)}`));
      setMembersPhase("error");
    }
  }, [a, client, entityId]);

  const load = useCallback(async (initial = false) => {
    const version = ++requestVersion.current;
    membershipRequestVersion.current += 1;
    setPhase(initial ? "loading" : "refreshing");
    try {
      const nextAccess = await client.get(entityId);
      if (version !== requestVersion.current) return;
      setPageError(null);
      setAccess(nextAccess);
      restorePendingPolicyChange();
      setPhase("ready");
      void loadMemberships(nextAccess, !initial);
    } catch (failure) {
      if (version !== requestVersion.current) return;
      applyFailure(failure);
    }
  }, [applyFailure, client, entityId, loadMemberships, restorePendingPolicyChange]);

  useEffect(() => {
    const version = ++requestVersion.current;
    membershipRequestVersion.current += 1;
    client.get(entityId).then((nextAccess) => {
      if (version !== requestVersion.current) return;
      setPageError(null);
      setAccess(nextAccess);
      restorePendingPolicyChange();
      setPhase("ready");
      void loadMemberships(nextAccess);
    }, (failure: unknown) => {
      if (version === requestVersion.current) applyFailure(failure);
    });
    return () => {
      requestVersion.current += 1;
      membershipRequestVersion.current += 1;
    };
  }, [applyFailure, client, entityId, loadMemberships, restorePendingPolicyChange]);

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
      membersAvailability: membersPhase,
      membersError: membersError ?? undefined,
      membersDirectoryComplete: nextAfter === null,
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
  }, [access, membersError, memberships, membersPhase, nextAfter, policyById, t, userById]);

  useLayoutEffect(() => {
    const closed = previousChange.current;
    previousChange.current = change;
    if (change || !closed) return;
    const target = (closed.kind === "members"
      ? closed.mode === "add" ? addMemberTrigger : removeMemberTrigger
      : closed.mode === "add" ? addPolicyTrigger : removePolicyTrigger).current;
    (target?.disabled ? editTrigger.current : target)?.focus({ preventScroll: true });
  }, [change, membersPhase, phase]);

  useLayoutEffect(() => {
    const wasEditing = previousEditing.current;
    previousEditing.current = editing;
    if (wasEditing && !editing) pageActionFocus.current?.focus();
  }, [editing]);

  const stableTitle = access?.group.name ?? entityId;
  // Original-command recovery does not depend on a current Group or member read.
  if (membershipCommand.pending) return <WorkspaceDetail title={access?.group.name ?? entityId} onBack={() => onOpen("groups")}>
    <LiveGroupMembershipEditor group={{ id: entityId, name: access?.group.name ?? entityId }} mode={membershipCommand.pending.operation === "CREATE" ? "add" : "remove"}
      scene={scene} memberships={memberships} command={membershipCommand} onClose={() => onOpen("groups")}
      onCompleted={() => { setChange(null); void load(); }} />
  </WorkspaceDetail>;
  if (phase === "loading") return <WorkspaceDetail title={stableTitle} onBack={() => onOpen("groups")}>
    <TableSkeleton label={t("loadingGroup")} rows={4} header={false} />
  </WorkspaceDetail>;
  if (phase === "error" || !access || !record) return <WorkspaceDetail title={stableTitle} onBack={() => onOpen("groups")}>
    {membershipCommand.receipt ? <MembershipReceipt receipt={membershipCommand.receipt} /> : null}
    <EmptyState title={w("entityUnavailable")} description={pageError ?? w("entityUnavailableHint")} action={<Button variant="secondary" onClick={() => { setPhase("loading"); void load(true); }}>{t("retry")}</Button>} />
  </WorkspaceDetail>;

  const edit = groupCapability(access, "iam.group.update");
  const remove = groupCapability(access, "iam.group.delete");
  const listMembers = groupCapability(access, "iam.group-membership.list");
  const addMember = groupCapability(access, "iam.group-membership.create");
  const addPolicy = groupCapability(access, "iam.group-policy-attachment.create");
  const removableMembers = membersPhase === "ready" && memberships.some((entry) => findActionCapability(entry.capabilities, "iam.group-membership.remove", "GROUP_MEMBERSHIP", entry.membership.id)?.available === true);
  const removablePolicies = access.policyAttachments.some((attachment) => findActionCapability(access.capabilities, "iam.group-policy-attachment.revoke", "POLICY_ATTACHMENT", attachment.id)?.available === true);
  const refreshingGroup = phase === "refreshing";
  const stale = () => { setEditing(false); setDeleting(false); setChange(null); setPageError(a("errors.conflict")); void load(); };

  return <>
    {membershipCommand.receipt ? <MembershipReceipt receipt={membershipCommand.receipt} /> : null}
    {pageError ? <Alert status="warning">{pageError}</Alert> : null}
    <GroupDetail
      group={record}
      workflow={editing ? <LiveGroupMetadataEditor client={client} access={access} onClose={() => setEditing(false)} onChanged={() => load()} onStale={stale} /> : change?.kind === "members" ?
        <LiveGroupMembershipEditor group={access.group} memberships={memberships} scene={scene} mode={change.mode} command={membershipCommand} canBegin={!refreshingGroup && membersPhase === "ready"} onClose={() => setChange(null)} onCompleted={() => { setChange(null); void load(); }} onStale={stale} /> : change ?
        <LiveGroupPolicyEditor client={client} access={access} scene={scene} mode={change.mode} onClose={() => setChange(null)} onChanged={() => load()} /> : undefined}
      controls={{
        edit: { disabled: refreshingGroup || edit?.available !== true, reason: refreshingGroup ? t("loadingGroup") : edit?.restrictionReason ?? undefined, onInvoke: () => setEditing(true) },
        delete: { disabled: refreshingGroup || remove?.available !== true, reason: refreshingGroup ? t("loadingGroup") : remove?.restrictionReason ?? undefined, onInvoke: () => setDeleting(true) },
        addMember: { disabled: refreshingGroup || membersPhase !== "ready" || addMember?.available !== true || !scene.users.some((user) => !memberships.some((entry) => entry.membership.userId === user.id)), reason: refreshingGroup ? t("loadingGroup") : membersPhase === "loading" || membersPhase === "refreshing" ? t("loadingMembers") : membersPhase === "error" ? t("membersLoadFailed") : listMembers?.restrictionReason ?? addMember?.restrictionReason ?? undefined, onInvoke: () => setChange({ kind: "members", mode: "add" }) },
        removeMember: { disabled: refreshingGroup || !removableMembers, reason: refreshingGroup ? t("loadingGroup") : membersPhase === "loading" || membersPhase === "refreshing" ? t("loadingMembers") : membersPhase === "error" ? t("membersLoadFailed") : listMembers?.restrictionReason ?? undefined, onInvoke: () => setChange({ kind: "members", mode: "remove" }) },
        addPolicy: { disabled: refreshingGroup || addPolicy?.available !== true || !scene.policies.some((policy) => policy.scopeKind === "tenant" && policy.available && !access.policyAttachments.some((attachment) => attachment.policyId === policy.id)), reason: refreshingGroup ? t("loadingGroup") : addPolicy?.restrictionReason ?? undefined, onInvoke: () => setChange({ kind: "policies", mode: "add" }) },
        removePolicy: { disabled: refreshingGroup || !removablePolicies, reason: refreshingGroup ? t("loadingGroup") : undefined, onInvoke: () => setChange({ kind: "policies", mode: "remove" }) },
        retryMembers: !refreshingGroup && membersPhase === "error" ? { onInvoke: () => { void loadMemberships(access); } } : undefined,
        loadMoreMembers: !refreshingGroup && membersPhase === "ready" && nextAfter ? { disabled: loadingMore, onInvoke: async () => {
          if (!nextAfter || loadingMore) return;
          const version = membershipRequestVersion.current;
          setLoadingMore(true);
          try {
            const page = await client.listMemberships(entityId, nextAfter);
            if (version !== membershipRequestVersion.current) return;
            setMemberships((current) => [...current, ...page.items]);
            setNextAfter(page.nextAfter);
          } catch (failure) { setPageError(a(`errors.${accountError(failure)}`)); }
          finally { setLoadingMore(false); }
        } } : undefined
      }}
      editTriggerRef={editTrigger}
      actionFocusRef={pageActionFocus}
      addMemberTriggerRef={addMemberTrigger}
      removeMemberTriggerRef={removeMemberTrigger}
      addPolicyTriggerRef={addPolicyTrigger}
      removePolicyTriggerRef={removePolicyTrigger}
      onBack={() => onOpen("groups")}
      onOpenMember={(userId) => onOpen("users", userId)}
      onOpenPolicy={(policyId) => onOpen("policies", policyId)}
    />
    {deleting ? <LiveGroupDelete client={client} access={access} onClose={() => setDeleting(false)} onDeleted={(result) => setDeleted({ client, result })} /> : null}
  </>;
}

type AccountLiveGroupsProps = {
  client: GroupAccessClient;
  entityId?: string;
  scene: AccountAccessScene;
  onCreate(): void;
  onOpen: OpenGroupEntity;
};

export function AccountLiveGroups(props: AccountLiveGroupsProps) {
  return <AccountLiveGroupsWorkspace key={props.client.identity} {...props} />;
}

function AccountLiveGroupsWorkspace({ client, entityId, scene, onCreate, onOpen }: AccountLiveGroupsProps) {
  const t = useTranslations("GroupWorkspace");
  const [receipt, setReceipt] = useState<{ client: GroupAccessClient; result: GroupDeletion } | null>(null);
  if (entityId) return <LiveGroupWorkspace key={entityId} client={client} entityId={entityId} scene={scene} onOpen={onOpen}
    onDeleted={(result) => setReceipt({ client, result })} />;
  return <>
    {receipt?.client === client ? <Alert status="success" role="status" aria-label={t("liveDeleteReceiptTitle")}>
      {t("liveDeleteReceipt", { name: receipt.result.name, id: receipt.result.id, revision: receipt.result.resourceVersion,
        members: receipt.result.removedMemberships, policies: receipt.result.revokedPolicyAttachments })} <WorkspaceTime value={receipt.result.deletedAt} />
    </Alert> : null}
    <LiveGroupDirectory client={client} onCreate={onCreate} onOpen={onOpen} />
  </>;
}

function LiveGroupDirectory({ client, onCreate, onOpen }: { client: GroupAccessClient; onCreate(): void; onOpen: OpenGroupEntity }) {
  const t = useTranslations("GroupWorkspace");
  const a = useTranslations("AccountAccess");
  const [groups, setGroups] = useState<GroupAccess[]>([]);
  const [nextAfter, setNextAfter] = useState<string | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const directoryRequestVersion = useRef(0);

  useEffect(() => {
    const version = ++directoryRequestVersion.current;
    client.list().then((page) => {
      if (version !== directoryRequestVersion.current) return;
      setGroups(page.items);
      setNextAfter(page.nextAfter);
      setPhase("ready");
    }, (failure: unknown) => {
      if (version !== directoryRequestVersion.current) return;
      setError(a(`errors.${accountError(failure)}`));
      setPhase("error");
    });
    return () => { directoryRequestVersion.current += 1; };
  }, [a, client]);

  const directory: GroupDirectoryRecord[] = groups.map((entry) => ({
    id: entry.group.id,
    name: entry.group.name,
    description: entry.group.description,
    createdAt: entry.group.createdAt,
    directPolicyCount: entry.policyAttachments.length
  }));
  return <>
    {phase === "ready" && error ? <Alert status="warning">{error}</Alert> : null}
    <GroupDirectory
      groups={directory}
      loading={phase === "loading"}
      unavailable={phase === "error" ? { description: error ?? undefined, retry: { onInvoke: () => {
        const version = ++directoryRequestVersion.current;
        setPhase("loading");
        setError(null);
        client.list().then((page) => {
          if (version !== directoryRequestVersion.current) return;
          setGroups(page.items);
          setNextAfter(page.nextAfter);
          setPhase("ready");
        }, (failure: unknown) => {
          if (version !== directoryRequestVersion.current) return;
          setError(a(`errors.${accountError(failure)}`));
          setPhase("error");
        });
      } } } : undefined}
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
