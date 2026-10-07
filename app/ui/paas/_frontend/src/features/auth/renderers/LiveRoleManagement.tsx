"use client";

import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, FormField, Input, Select, TextArea } from "@ui/xiak";
import { requestToken } from "@/infrastructure/http/jsonRequest";
import { accountError, type RoleAccessClient } from "../application/AccountAccessProvider";
import type { AccountPolicy, PolicyAttachmentChangeOperationExpectation } from "../domain/accounts";
import {
  roleTrustDocumentFromUnknown,
  validateRoleMetadataInput,
  type DeleteRoleCommand,
  type RoleAccess,
  type RoleTrustDocument,
  type SetRoleStatusCommand,
  type SetRoleTrustPolicyCommand,
  type UpdateRoleCommand
} from "../domain/roles";
import { WorkspaceDelete, WorkspaceInlineForm } from "./AccessWorkspaceUi";
import { PolicyAttachmentChangeFeedback, usePolicyAttachmentCommand } from "./PolicyAttachmentChangeFlow";
import { RoleTags } from "./RoleConfiguration";
import styles from "./AccountAccessRenderer.module.css";

type RoleCommandPhase = "idle" | "pending" | "uncertain" | "conflict" | "refreshFailed" | "rejected" | "completed";
type RoleCommandState = { phase: RoleCommandPhase; error?: ReturnType<typeof accountError>; requestId?: string };
const noop = () => {};

function needsLeaveGuard(state: RoleCommandState) {
  return state.phase === "uncertain" || state.phase === "conflict" || state.phase === "refreshFailed";
}

function canonicalTrust(document: RoleTrustDocument): string {
  const compare = (left: string, right: string) => left < right ? -1 : left > right ? 1 : 0;
  return JSON.stringify({
    languageVersion: document.languageVersion,
    statements: [...document.statements].sort((left, right) => compare(left.sid, right.sid)).map((statement) => ({
      sid: statement.sid,
      effect: statement.effect,
      principals: [...statement.principals].sort((left, right) => compare(left.id, right.id))
    }))
  });
}

function useRoleCommand<I extends { requestId: string }, R>({ client, roleId, execute, onAccessChanged }: {
  client: RoleAccessClient;
  roleId: string;
  execute(intent: I): Promise<R>;
  onAccessChanged(access: RoleAccess): void;
}) {
  const mounted = useRef(true), intent = useRef<I | null>(null);
  const [state, setState] = useState<RoleCommandState>({ phase: "idle" });
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  const readLatest = async (phase: "idle" | "completed") => {
    setState((current) => ({ phase: "pending", requestId: current.requestId }));
    try {
      const access = await client.read(roleId);
      if (!mounted.current) return null;
      onAccessChanged(access);
      if (phase === "idle") intent.current = null;
      setState({ phase, requestId: intent.current?.requestId });
      return access;
    } catch (failure) {
      if (!mounted.current) return null;
      setState({ phase: phase === "completed" ? "refreshFailed" : "conflict", error: accountError(failure), requestId: intent.current?.requestId });
      return null;
    }
  };

  const run = async (next?: I): Promise<boolean> => {
    if (state.phase === "pending") return false;
    if (next) {
      intent.current = next;
    }
    const frozen = intent.current;
    if (!frozen) return false;
    setState({ phase: "pending", requestId: frozen.requestId });
    try {
      await execute(frozen);
      if (!mounted.current) return false;
      intent.current = null;
    } catch (failure) {
      if (!mounted.current) return false;
      const error = accountError(failure);
      if (error !== "unavailable" && error !== "conflict") intent.current = null;
      setState({ phase: error === "unavailable" ? "uncertain" : error === "conflict" ? "conflict" : "rejected", error, requestId: frozen.requestId });
      return false;
    }
    return Boolean(await readLatest("completed"));
  };

  return {
    state,
    locked: state.phase === "pending" || state.phase === "uncertain" || state.phase === "conflict" || state.phase === "refreshFailed",
    submitBlocked: state.phase === "pending" || state.phase === "conflict" || state.phase === "refreshFailed",
    run,
    refreshConflict: () => readLatest("idle"),
    retryRead: () => readLatest("completed"),
    reset: () => { intent.current = null; setState({ phase: "idle" }); }
  };
}

function RoleCommandFeedback({ state, onRefreshConflict, onRetryRead }: {
  state: RoleCommandState;
  onRefreshConflict(): Promise<unknown>;
  onRetryRead(): Promise<unknown>;
}) {
  const t = useTranslations("RoleWorkspace"), a = useTranslations("AccountAccess");
  if (state.phase === "uncertain") return <Alert status="warning">{t("mutationOutcomeUnknown")} <code>{state.requestId}</code></Alert>;
  if (state.phase === "conflict") return <Alert status="warning"><div className={styles.confirmation}><span>{t("mutationConflict")}</span><Button variant="secondary" onClick={() => void onRefreshConflict()}>{t("refreshAndReview")}</Button></div></Alert>;
  if (state.phase === "refreshFailed") return <Alert status="warning"><div className={styles.confirmation}><span>{t("mutationReadbackFailed")}</span><Button variant="secondary" onClick={() => void onRetryRead()}>{t("retryAuthoritativeRead")}</Button></div></Alert>;
  if (state.phase === "rejected" && state.error) return <Alert status="danger">{a(`errors.${state.error}`)}</Alert>;
  return null;
}

export function LiveRoleMetadataEditor({ access, client, onAccessChanged, onClose }: {
  access: RoleAccess;
  client: RoleAccessClient;
  onAccessChanged(access: RoleAccess): void;
  onClose(): void;
}) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace");
  const id = useId();
  const [name, setName] = useState(access.role.name), [description, setDescription] = useState(access.role.description);
  const [minutes, setMinutes] = useState(access.role.maxSessionDurationSeconds / 60), [tags, setTags] = useState(access.role.tags);
  const [review, setReview] = useState(false), [validation, setValidation] = useState<string | undefined>();
  const command = useRoleCommand<UpdateRoleCommand, unknown>({ client, roleId: access.role.id, execute: (intent) => client.update(access.role.id, intent), onAccessChanged });
  const normalized = () => ({ name: name.trim(), description: description.trim(), tags: tags.map((tag) => ({ ...tag })), maxSessionDurationSeconds: minutes * 60 });
  const resetFrom = (latest: RoleAccess) => {
    setName(latest.role.name); setDescription(latest.role.description); setMinutes(latest.role.maxSessionDurationSeconds / 60);
    setTags(latest.role.tags); setReview(false); setValidation(undefined);
  };
  const submit = async () => {
    if (command.state.phase === "uncertain") return command.run();
    if (!review) {
      const value = normalized(), issue = validateRoleMetadataInput(value.name, value.description, value.tags, minutes);
      if (issue) { setValidation(t(`liveErrors.${issue}`)); return false; }
      setValidation(undefined); setReview(true); return false;
    }
    const value = normalized();
    return command.run({ ...value, resourceVersion: access.role.resourceVersion, requestId: requestToken("role-update-") });
  };
  const dirty = name.trim() !== access.role.name || description.trim() !== access.role.description || minutes * 60 !== access.role.maxSessionDurationSeconds || JSON.stringify(tags) !== JSON.stringify(access.role.tags) || review || needsLeaveGuard(command.state);
  return <WorkspaceInlineForm title={t("editMetadata")} backLabel={t("backToRoleDetails")} onClose={onClose} onSubmit={submit}
    submitDisabled={command.submitBlocked || (!review && name.trim() === access.role.name && description.trim() === access.role.description && minutes * 60 === access.role.maxSessionDurationSeconds && JSON.stringify(tags) === JSON.stringify(access.role.tags))}
    submitLabel={command.state.phase === "uncertain" ? t("retryOriginalRequest") : review ? t("confirmRoleUpdate") : t("reviewChange")} validationError={validation}
    operation={{ busy: command.state.phase === "pending", clearError: noop }} draft={{ dirty, title: t("editMetadata"), description: t("roleMutationLeaveHint") }}>
    <RoleCommandFeedback state={command.state} onRefreshConflict={async () => { const latest = await command.refreshConflict(); if (latest) resetFrom(latest); }} onRetryRead={async () => { const latest = await command.retryRead(); if (latest) onClose(); }} />
    {review ? <><Alert status="warning">{t("metadataReviewHint")}</Alert><dl className={styles.facts}>
      <div><dt>{w("name")}</dt><dd>{access.role.name} → {name.trim()}</dd></div>
      <div><dt>{w("description")}</dt><dd>{description.trim() || "—"}</dd></div>
      <div><dt>{t("maximumSession")}</dt><dd>{minutes} min</dd></div>
      <div><dt>{t("tags")}</dt><dd>{tags.length ? tags.map((tag) => <Badge key={tag.key}>{tag.key}: {tag.value || "—"}</Badge>) : "—"}</dd></div>
    </dl><Button variant="ghost" disabled={command.locked} onClick={() => { command.reset(); setReview(false); }}>{t("backToSelection")}</Button></> : <>
      <FormField id={`${id}-name`} label={w("name")} hint={t("liveNameHint")}><Input id={`${id}-name`} maxLength={64} required disabled={command.locked} value={name} onChange={(event) => setName(event.target.value)} /></FormField>
      <FormField id={`${id}-description`} label={w("description")}><TextArea id={`${id}-description`} maxLength={512} rows={3} disabled={command.locked} value={description} onChange={(event) => setDescription(event.target.value)} /></FormField>
      <FormField id={`${id}-duration`} label={w("sessionMinutes")} hint={t("liveDurationHint")}><Input id={`${id}-duration`} type="number" min={1} max={720} required disabled={command.locked} value={minutes} onChange={(event) => setMinutes(Number(event.target.value))} /></FormField>
      <section className={styles.identitySection}><h3>{t("tags")}</h3><RoleTags value={tags} disabled={command.locked} onChange={setTags} /></section>
    </>}
  </WorkspaceInlineForm>;
}

export function LiveRoleStatusEditor({ access, client, onAccessChanged, onClose }: {
  access: RoleAccess;
  client: RoleAccessClient;
  onAccessChanged(access: RoleAccess): void;
  onClose(): void;
}) {
  const t = useTranslations("RoleWorkspace");
  const target = access.role.status === "ACTIVE" ? "DISABLED" : "ACTIVE";
  const command = useRoleCommand<SetRoleStatusCommand, unknown>({ client, roleId: access.role.id, execute: (intent) => client.setStatus(access.role.id, intent), onAccessChanged });
  return <WorkspaceInlineForm title={t(target === "DISABLED" ? "disableRole" : "enableRole")} onClose={onClose} onSubmit={() => command.state.phase === "uncertain" ? command.run() : command.run({ status: target, resourceVersion: access.role.resourceVersion, requestId: requestToken("role-status-") })} submitDisabled={command.submitBlocked}
    submitLabel={command.state.phase === "uncertain" ? t("retryOriginalRequest") : t(target === "DISABLED" ? "confirmDisableRole" : "confirmEnableRole")}
    operation={{ busy: command.state.phase === "pending", clearError: noop }} draft={{ dirty: needsLeaveGuard(command.state), title: t(target === "DISABLED" ? "disableRole" : "enableRole"), description: t("roleMutationLeaveHint") }}>
    <RoleCommandFeedback state={command.state} onRefreshConflict={async () => { if (await command.refreshConflict()) onClose(); }} onRetryRead={async () => { if (await command.retryRead()) onClose(); }} />
    <Alert status={target === "DISABLED" ? "warning" : "info"}>{t(target === "DISABLED" ? "disableRoleImpact" : "enableRoleImpact")}</Alert>
    <dl className={styles.facts}><div><dt>{t("before")}</dt><dd>{t(access.role.status === "ACTIVE" ? "active" : "disabled")}</dd></div><div><dt>{t("after")}</dt><dd>{t(target === "ACTIVE" ? "active" : "disabled")}</dd></div></dl>
  </WorkspaceInlineForm>;
}

export function LiveRoleTrustEditor({ access, client, onAccessChanged, onClose }: {
  access: RoleAccess;
  client: RoleAccessClient;
  onAccessChanged(access: RoleAccess): void;
  onClose(): void;
}) {
  const t = useTranslations("RoleWorkspace");
  const id = useId();
  const [text, setText] = useState(JSON.stringify(access.trustVersion.document, null, 2));
  const [review, setReview] = useState(false), [document, setDocument] = useState<RoleTrustDocument | null>(null), [validation, setValidation] = useState<string | undefined>();
  const command = useRoleCommand<SetRoleTrustPolicyCommand, unknown>({ client, roleId: access.role.id, execute: (intent) => client.setTrustPolicy(access.role.id, intent), onAccessChanged });
  const resetFrom = (latest: RoleAccess) => { setText(JSON.stringify(latest.trustVersion.document, null, 2)); setReview(false); setDocument(null); setValidation(undefined); };
  const submit = async () => {
    if (command.state.phase === "uncertain") return command.run();
    if (!review) {
      let parsed: unknown;
      try { parsed = JSON.parse(text); } catch { setValidation(t("invalidTrustDocument")); return false; }
      const next = roleTrustDocumentFromUnknown(parsed);
      if (!next) { setValidation(t("invalidTrustDocument")); return false; }
      if (canonicalTrust(next) === canonicalTrust(access.trustVersion.document)) { setValidation(t("noTrustChanges")); return false; }
      setDocument(next); setValidation(undefined); setReview(true); return false;
    }
    if (!document) return false;
    return command.run({ document, resourceVersion: access.role.resourceVersion, requestId: requestToken("role-trust-") });
  };
  const initialText = JSON.stringify(access.trustVersion.document, null, 2);
  return <WorkspaceInlineForm title={t("editTrust")} backLabel={t("backToTrust")} onClose={onClose} onSubmit={submit} submitDisabled={command.submitBlocked}
    submitLabel={command.state.phase === "uncertain" ? t("retryOriginalRequest") : review ? t("confirmTrustChange") : t("reviewTrust")} validationError={validation}
    operation={{ busy: command.state.phase === "pending", clearError: noop }} draft={{ dirty: text !== initialText || review || needsLeaveGuard(command.state), title: t("editTrust"), description: t("roleMutationLeaveHint") }}>
    <RoleCommandFeedback state={command.state} onRefreshConflict={async () => { const latest = await command.refreshConflict(); if (latest) resetFrom(latest); }} onRetryRead={async () => { if (await command.retryRead()) onClose(); }} />
    {review && document ? <><Alert status="warning">{t("liveTrustChangeImpact")}</Alert><div className={styles.stack}>
      <div><strong>{t("before")}</strong><pre className={styles.code}>{JSON.stringify(access.trustVersion.document, null, 2)}</pre></div>
      <div><strong>{t("after")}</strong><pre className={styles.code}>{JSON.stringify(document, null, 2)}</pre></div>
    </div><Button variant="ghost" disabled={command.locked} onClick={() => { command.reset(); setReview(false); setDocument(null); }}>{t("backToSelection")}</Button></> : <>
      <Alert>{t("liveTrustEditorHint")}</Alert>
      <FormField id={`${id}-document`} label={t("trustDocument")} hint={t("trustDocumentContract")}><TextArea id={`${id}-document`} className={styles.policyVersionEditor} rows={18} maxLength={16384} spellCheck={false} disabled={command.locked} value={text} onChange={(event) => { setText(event.target.value); setValidation(undefined); }} /></FormField>
    </>}
  </WorkspaceInlineForm>;
}

export function LiveRolePolicyEditor({ access, client, mode, onAccessChanged, onClose }: {
  access: RoleAccess;
  client: RoleAccessClient;
  mode: "add" | "remove";
  onAccessChanged(access: RoleAccess): void;
  onClose(): void;
}) {
  const t = useTranslations("RoleWorkspace");
  const p = useTranslations("PolicyAttachmentChange");
  const id = useId();
  const policyScope = useMemo(() => ({ accountId: client.accountId, actorPrincipalId: client.actorPrincipalId,
    target: { kind: "ROLE" as const, id: access.role.id } }), [access.role.id, client.accountId, client.actorPrincipalId]);
  const [policies, setPolicies] = useState<AccountPolicy[]>([]), [available, setAvailable] = useState(true), [loading, setLoading] = useState(mode === "add");
  const operation = usePolicyAttachmentCommand<PolicyAttachmentChangeOperationExpectation>({
    scope: policyScope,
    execute: async (intent) => {
      if (intent.operation === "CREATE") {
        if (intent.target.kind !== "ROLE" || intent.target.id !== access.role.id) throw new Error("INVALID_ROLE_POLICY_TARGET");
        return client.createPolicyAttachment(access.role.id, {
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
    refresh: async () => onAccessChanged(await client.read(access.role.id))
  });
  const [selectedId, setSelectedId] = useState(() => operation.intent
    ? operation.intent.operation === "CREATE" ? operation.intent.policyId : operation.intent.attachmentId
    : "");
  const [review, setReview] = useState(Boolean(operation.intent)), [validation, setValidation] = useState<string | undefined>();
  useEffect(() => {
    if (mode !== "add") return;
    let current = true;
    client.listTenantPolicies().then((result) => {
      if (!current) return;
      setPolicies(result.items); setAvailable(result.available); setLoading(false);
    }, () => { if (current) { setAvailable(false); setLoading(false); } });
    return () => { current = false; };
  }, [client, mode]);
  const attached = new Set(access.policyAttachments.map((attachment) => attachment.policyId));
  const choices = mode === "add"
    ? policies.filter((policy) => policy.status === "ACTIVE" && policy.scope === "TENANT" && !attached.has(policy.id)).map((policy) => ({ value: policy.id, label: `${policy.displayName} · ${policy.id}` }))
    : access.policyAttachments.filter((attachment) => access.capabilities.some((capability) => capability.action === "iam.role-policy-attachment.revoke" && capability.resource.kind === "POLICY_ATTACHMENT" && capability.resource.id === attachment.id && capability.available)).map((attachment) => ({ value: attachment.id, label: attachment.policyId }));
  const selectedPolicy = policies.find((policy) => policy.id === selectedId), selectedAttachment = access.policyAttachments.find((attachment) => attachment.id === selectedId);
  const recovering = operation.state.phase === "unknown" || operation.state.phase === "checking" || operation.state.phase === "refreshFailed";
  const selectedPolicyId = mode === "add" ? selectedPolicy?.id ?? (operation.intent?.operation === "CREATE" ? operation.intent.policyId : undefined) : selectedAttachment?.policyId;
  const selectedLabel = mode === "add" ? selectedPolicy?.displayName ?? selectedPolicyId : selectedAttachment?.policyId ?? (operation.intent?.operation === "REVOKE" ? operation.intent.attachmentId : undefined);
  const submit = async () => {
    if (operation.state.phase === "unknown") return operation.inspectOriginal();
    if (!review) {
      if (!selectedId || (mode === "add" ? !selectedPolicy : !selectedAttachment)) { setValidation(t("selectOnePolicy")); return false; }
      setValidation(undefined); setReview(true); return false;
    }
    if (mode === "add" && selectedPolicy) return operation.run({ operation: "CREATE", target: { kind: "ROLE", id: access.role.id }, policyId: selectedPolicy.id, policyResourceVersion: selectedPolicy.resourceVersion, requestId: requestToken("role-attachment-") });
    if (mode === "remove" && selectedAttachment) return operation.run({ operation: "REVOKE", attachmentId: selectedAttachment.id, expectedResourceVersion: selectedAttachment.resourceVersion, requestId: requestToken("role-revocation-") });
    return false;
  };
  return <WorkspaceInlineForm title={t(mode === "add" ? "addPolicies" : "removePolicies")} onClose={onClose} onSubmit={submit}
    submitDisabled={operation.state.phase === "refreshFailed" || !recovering && (loading || !available || !choices.length)} submitLabel={operation.state.phase === "unknown" ? p("checkOriginalRequest") : operation.state.phase === "checking" ? p("checking") : review ? t(mode === "add" ? "confirmAttachPolicy" : "confirmRevokePolicy") : t("reviewChange")} validationError={validation}
    operation={{ busy: operation.state.phase === "pending" || operation.state.phase === "checking", clearError: noop }} draft={{ dirty: Boolean(selectedId) || review || operation.locked, title: t(mode === "add" ? "addPolicies" : "removePolicies"), description: p("unknownHint") }}>
    <PolicyAttachmentChangeFeedback state={operation.state} onRetryRead={operation.retryRead} />
    <Alert>{t(mode === "add" ? "liveAttachPolicyHint" : "liveRevokePolicyHint")}</Alert>
    {review ? <><dl className={styles.facts}><div><dt>{t(mode === "add" ? "adding" : "removing")}</dt><dd>{selectedLabel}</dd></div><div><dt>{t("policyId")}</dt><dd><code>{selectedPolicyId ?? selectedLabel}</code></dd></div></dl><Button variant="ghost" disabled={operation.locked} onClick={() => { operation.reset(); setReview(false); }}>{t("backToSelection")}</Button></> : loading ? <p className={styles.note} role="status">{t("policyDirectoryLoading")}</p> : !available ? <Alert status="warning">{t("policyDirectoryUnavailable")}</Alert> : choices.length ? <FormField id={`${id}-policy`} label={t(mode === "add" ? "policyToAttach" : "policyToRevoke")} hint={t("singlePolicyCommandHint")}><Select id={`${id}-policy`} disabled={operation.locked} value={selectedId} options={[{ value: "", label: t("choosePolicy") }, ...choices]} onValueChange={(value) => { operation.reset(); setSelectedId(value); }} /></FormField> : <Alert>{t(mode === "add" ? "noEligiblePolicies" : "noRevocablePolicies")}</Alert>}
  </WorkspaceInlineForm>;
}

export function LiveRoleDelete({ access, client, onAccessChanged, onClose, onDeleted }: {
  access: RoleAccess;
  client: RoleAccessClient;
  onAccessChanged(access: RoleAccess): void;
  onClose(): void;
  onDeleted(): void;
}) {
  const t = useTranslations("RoleWorkspace"), a = useTranslations("AccountAccess");
  const intent = useRef<DeleteRoleCommand | null>(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | undefined>(), [uncertain, setUncertain] = useState(false);
  const clearError = useCallback(() => setError(undefined), []);
  const confirm = async () => {
    if (busy) return false;
    const frozen = intent.current ?? { resourceVersion: access.role.resourceVersion, requestId: requestToken("role-delete-"), expectedName: access.role.name };
    intent.current = frozen; setBusy(true); setError(undefined);
    try {
      await client.delete(access.role.id, frozen);
      intent.current = null; onDeleted(); return true;
    } catch (failure) {
      const reason = accountError(failure);
      if (reason === "unavailable") { setUncertain(true); setError(`${t("deleteOutcomeUnknown")} ${frozen.requestId}`); }
      else if (reason === "conflict") {
        intent.current = null; setUncertain(false); setError(t("deleteConflict"));
        try { onAccessChanged(await client.read(access.role.id)); } catch { /* the conflict remains explicit */ }
      } else { intent.current = null; setUncertain(false); setError(a(`errors.${reason}`)); }
      return false;
    } finally { setBusy(false); }
  };
  return <WorkspaceDelete name={access.role.name} onClose={onClose} onConfirm={confirm} hint={t("liveDeleteConfirmHint")} operation={{ busy, error, clearError }}
    draft={{ dirty: uncertain, title: t("deleteRole"), description: t("roleMutationLeaveHint") }}
    impact={<div className={styles.stack}><Alert status="warning">{t("liveDeleteImpact")}</Alert>{uncertain ? <Alert status="warning">{t("retryDeleteOriginal")}</Alert> : null}</div>} />;
}
