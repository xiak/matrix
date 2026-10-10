"use client";

import { useCallback, useEffect, useId, useRef, useState, type ComponentProps } from "react";
import { useTranslations } from "next-intl";
import { KeyRound } from "lucide-react";
import { Alert, Badge, Button, Card, Checkbox, ContentPage, Table, TableSkeleton, Typography } from "@ui/xiak";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import type { AccessKeyAccess, AccessKeyDirectory, AccessKeyStatus } from "../domain/accessKeys";
import type { IamAction } from "../domain/accounts";
import type { AccessKeyClient, AccessKeyCreateIntent, AccountSecuritySettingsClient, AuthorizationProfileClient } from "../application/AccountAccessProvider";
import type { AccountAccessScene, AccountUserScene } from "../scenes/accountAccessScene";
import { AccountIdentifier } from "./AccountOverview";
import { AccessKeyOwnerDirectory } from "./AccessKeyOwnerDirectory";
import { accessKeyNetworkRestrictionsEqual, parseAccessKeyNetworkDraft, type AccessKeyNetworkDraftIssue } from "../domain/accessKeyNetwork";
import { AccessKeyNetworkDetail, AccessKeyNetworkDraftField, AccessKeySecuritySignals, AccessKeyUsagePreview, type AccessKeyAccountNetworkState } from "./AccessKeyNetworkPreview";
import { AccessKeyCredentialStateBadge, ProgrammaticAccessGuide, RotationGuide } from "./AccessCredentials";
import { WorkspaceDetail, WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccessCredentials.module.css";

type LiveKeyError = "forbidden" | "routeUnavailable" | "conflict" | "unavailable";
type LiveKeyFlow =
  | { kind: "create"; requestId: string; userResourceVersion: number; networkRestrictions: { allowedSourceCidrs: string[] } }
  | { kind: "issued"; keyId: string; secret: string; requestId: string }
  | { kind: "replayed"; keyId: string }
  | { kind: "status"; access: AccessKeyAccess; status: AccessKeyStatus; requestId: string }
  | { kind: "network"; access: AccessKeyAccess; requestId: string }
  | { kind: "delete"; access: AccessKeyAccess; requestId: string };
type AccessKeyDirectoryState =
  | { status: "loading" }
  | { status: "ready"; directory: AccessKeyDirectory }
  | { status: "error"; error: LiveKeyError };
type OwnedAccessKeyDirectory = { client: AccessKeyClient; userId: string; state: AccessKeyDirectoryState };
type OwnedAccessKeySelection = { client: AccessKeyClient; userId: string; access: AccessKeyAccess };
type OwnedLiveKeyFlow = { client: AccessKeyClient; userId: string; flow: LiveKeyFlow };
type OwnedLiveKeyError = { client: AccessKeyClient; userId: string; error: LiveKeyError };
type AccessKeyIntentBinding = { client: AccessKeyClient; observed: AccessKeyCreateIntent | null; requestId: string | null };

const loadingAccessKeyDirectory: AccessKeyDirectoryState = { status: "loading" };

function keyError(error: unknown): LiveKeyError {
  if (error instanceof HttpProblem) {
    if (error.status === 403) return "forbidden";
    if (error.status === 404) return "routeUnavailable";
    if (error.status === 409) return "conflict";
  }
  return "unavailable";
}

function capability(access: AccessKeyAccess | AccessKeyDirectory, action: IamAction) {
  return access.capabilities.find((item) => item.action === action) ?? null;
}

function LiveKeyWorkflow({ flow, owner, directory, client, retryingOriginal, onChanged, onClose, onInspectRecovered }: {
  flow: LiveKeyFlow;
  owner: AccountUserScene;
  directory: AccessKeyDirectory;
  client: AccessKeyClient;
  retryingOriginal: boolean;
  onChanged(): Promise<void>;
  onClose(): void;
  onInspectRecovered(keyId: string): void;
}) {
  const t = useTranslations("IamWorkspace");
  const network = useTranslations("AccessKeyNetworkPreview");
  const restrictions = useTranslations("AccountAccess.restrictions");
  const networkFieldId = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const mounted = useRef(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<LiveKeyError | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [deleteConfirmed, setDeleteConfirmed] = useState(false);
  const initialNetwork = flow.kind === "create" ? flow.networkRestrictions : flow.kind === "network" ? flow.access.key.networkRestrictions : { allowedSourceCidrs: [] };
  const [networkDraft, setNetworkDraft] = useState(() => initialNetwork.allowedSourceCidrs.join("\n"));
  const [networkIssue, setNetworkIssue] = useState<AccessKeyNetworkDraftIssue | null>(null);
  useEffect(() => { heading.current?.focus({ preventScroll: true }); }, [flow.kind]);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  const createCapability = capability(directory, "iam.access-key.create");
  const actionCapability = flow.kind === "status" ? capability(flow.access, "iam.access-key.set-status")
    : flow.kind === "network" ? capability(flow.access, "iam.access-key.set-network-restrictions")
    : flow.kind === "delete" ? capability(flow.access, "iam.access-key.delete") : null;
  const title = flow.kind === "create" ? t("keyCreateReview")
    : flow.kind === "issued" ? t("keyLiveCreated")
      : flow.kind === "replayed" ? t("keyLiveReplayTitle")
        : flow.kind === "status" ? t("changeStateTitle", { action: t(flow.status === "ENABLED" ? "enable" : "disable"), name: flow.access.key.id })
          : flow.kind === "network" ? network("editKeyTitle")
          : t("keyDeleteReview", { name: flow.access.key.id });

  const run = async () => {
    const parsedNetwork = flow.kind === "create" || flow.kind === "network" ? parseAccessKeyNetworkDraft(networkDraft) : null;
    if (parsedNetwork && !parsedNetwork.ok) { setNetworkIssue(parsedNetwork.issue); return; }
    setBusy(true); setError(null);
    try {
      if (flow.kind === "create") {
        const result = await client.create(owner.id, { userResourceVersion: flow.userResourceVersion, networkRestrictions: parsedNetwork && parsedNetwork.ok ? parsedNetwork.restrictions : flow.networkRestrictions, requestId: flow.requestId });
        if (!mounted.current) return;
        if (result.outcome === "APPLIED") onCloseWith({ kind: "issued", keyId: result.key.id, secret: result.secret, requestId: flow.requestId });
        else onCloseWith({ kind: "replayed", keyId: result.key.id });
        void onChanged();
        return;
      }
      if (flow.kind === "status") {
        await client.setStatus(owner.id, flow.access.key.id, { accessKeyResourceVersion: flow.access.key.resourceVersion, requestId: flow.requestId, status: flow.status });
      } else if (flow.kind === "network" && parsedNetwork?.ok) {
        await client.setNetworkRestrictions(owner.id, flow.access.key.id, { accessKeyResourceVersion: flow.access.key.resourceVersion, networkRestrictions: parsedNetwork.restrictions, requestId: flow.requestId });
      } else if (flow.kind === "delete") {
        await client.delete(owner.id, flow.access.key.id, { accessKeyResourceVersion: flow.access.key.resourceVersion, requestId: flow.requestId });
      }
      if (!mounted.current) return;
      await onChanged();
      if (mounted.current) onClose();
    } catch (failure) { if (mounted.current) setError(keyError(failure)); }
    finally { if (mounted.current) setBusy(false); }
  };
  const [replacement, setReplacement] = useState<LiveKeyFlow | null>(null);
  const onCloseWith = (next: LiveKeyFlow) => setReplacement(next);
  const active = replacement ?? flow;
  const activeTitle = replacement ? replacement.kind === "issued" ? t("keyLiveCreated") : t("keyLiveReplayTitle") : title;
  const networkDraftResult = flow.kind === "create" || flow.kind === "network" ? parseAccessKeyNetworkDraft(networkDraft) : null;
  const networkUnchanged = flow.kind === "network" && networkDraftResult?.ok &&
    accessKeyNetworkRestrictionsEqual(flow.access.key.networkRestrictions, networkDraftResult.restrictions);

  return <Card>
    <Card.Header className={styles.flowHeader}><div><h2 className={styles.focusHeading} ref={heading} tabIndex={-1}>{activeTitle}</h2><Typography.Text tone="muted">{t("keyInlineWorkflow")}</Typography.Text></div><Badge status="success">LIVE</Badge></Card.Header>
    <Card.Body className={styles.flowBody}>
      {error ? <Alert status="danger"><span>{t(`keyLiveErrors.${error}`)}</span>{error === "unavailable" && flow.kind === "create" ? <span className={styles.operationReference}><strong>{t("keyOperationReference")}</strong><code>{flow.requestId}</code></span> : null}</Alert> : null}
      {active.kind === "create" ? <>
        <dl className={styles.reviewFacts}>
          <div><dt>{t("owner")}</dt><dd><strong>{owner.name}</strong><span>{owner.loginName} · {owner.id}</span></dd></div>
          <div><dt>{t("state")}</dt><dd>{t(owner.enabled ? "enabled" : "disabled")}</dd></div>
        </dl>
        {retryingOriginal ? <div className={styles.operationReference}><strong>{t("keyOperationReference")}</strong><code>{active.requestId}</code></div> : null}
        <AccessKeyNetworkDraftField id={networkFieldId} issue={networkIssue} value={networkDraft} onChange={(value) => { setNetworkDraft(value); setNetworkIssue(null); }} />
        <Alert>{network("emptyLayerMeaning")}</Alert>
        <Alert status="warning">{t("keyCreateWarning")}</Alert>
        {!createCapability?.available && createCapability?.restrictionReason ? <Alert status="warning">{restrictions(createCapability.restrictionReason)}</Alert> : null}
        <div className={styles.actions}><Button disabled={busy || !createCapability?.available} onClick={() => void run()}>{busy ? t("keyLiveSaving") : t(retryingOriginal ? "keyLiveRetryOriginal" : "keyConfirmCreate")}</Button><Button disabled={busy} onClick={onClose} variant="ghost">{t("cancel")}</Button></div>
      </> : null}
      {active.kind === "issued" ? <>
        <Alert status="warning">{t("keyLiveSecretWarning")}</Alert>
        <div className={styles.secretGrid}><div><span>{t("keyId")}</span><AccountIdentifier label={t("keyId")} value={active.keyId} /></div><div><span>{t("keySecret")}</span><AccountIdentifier label={t("keySecret")} value={active.secret} /></div></div>
        <Checkbox checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)}>{t("keyLiveAcknowledge")}</Checkbox>
        <div className={styles.actions}><Button disabled={!acknowledged} onClick={() => { if (client.acknowledgeIssued(active.requestId, active.keyId)) onClose(); }}>{t("done")}</Button></div>
      </> : null}
      {active.kind === "replayed" ? <>
        <Alert status="warning">{t("keyLiveReplay", { id: active.keyId })}</Alert>
        <p className={styles.note}>{t("keyRecoveredNext")}</p>
        <div className={styles.actions}><Button onClick={() => onInspectRecovered(active.keyId)}>{t("keyInspectAndReplace")}</Button><Button onClick={onClose} variant="ghost">{t("done")}</Button></div>
      </> : null}
      {active.kind === "status" ? <>
        <Alert status={active.status === "DISABLED" ? "warning" : "info"}>{t(active.status === "DISABLED" ? "keyDisableImpact" : "keyEnableImpact")}</Alert>
        <dl className={styles.reviewFacts}><div><dt>{t("keyId")}</dt><dd><code>{active.access.key.id}</code></dd></div><div><dt>{t("owner")}</dt><dd><strong>{owner.name}</strong><span>{owner.loginName} · {owner.id}</span></dd></div><div><dt>{t("state")}</dt><dd>{t(active.access.key.status === "ENABLED" ? "enabled" : "disabled")} → {t(active.status === "ENABLED" ? "enabled" : "disabled")}</dd></div></dl>
        {!actionCapability?.available && actionCapability?.restrictionReason ? <Alert status="warning">{restrictions(actionCapability.restrictionReason)}</Alert> : null}
        <div className={styles.actions}><Button disabled={busy || !actionCapability?.available} onClick={() => void run()}>{busy ? t("keyLiveSaving") : t(active.status === "ENABLED" ? "enable" : "disable")}</Button><Button disabled={busy} onClick={onClose} variant="ghost">{t("cancel")}</Button></div>
      </> : null}
      {active.kind === "network" ? <>
        <dl className={styles.reviewFacts}><div><dt>{t("keyId")}</dt><dd><code>{active.access.key.id}</code></dd></div><div><dt>{t("owner")}</dt><dd><strong>{owner.name}</strong><span>{owner.loginName} · {owner.id}</span></dd></div></dl>
        <AccessKeyNetworkDraftField id={networkFieldId} issue={networkIssue} value={networkDraft} onChange={(value) => { setNetworkDraft(value); setNetworkIssue(null); }} />
        <Alert status="info">{network("liveKeyReviewBoundary")}</Alert>
        {!actionCapability?.available && actionCapability?.restrictionReason ? <Alert status="warning">{restrictions(actionCapability.restrictionReason)}</Alert> : null}
        <div className={styles.actions}><Button disabled={busy || !actionCapability?.available || !networkDraftResult?.ok || networkUnchanged} onClick={() => void run()}>{busy ? t("keyLiveSaving") : network("applyLive")}</Button><Button disabled={busy} onClick={onClose} variant="ghost">{t("cancel")}</Button></div>
      </> : null}
      {active.kind === "delete" ? <>
        <Alert status="danger">{t("keyDeleteImpact")}</Alert>
        <dl className={styles.reviewFacts}><div><dt>{t("keyId")}</dt><dd><code>{active.access.key.id}</code></dd></div><div><dt>{t("owner")}</dt><dd><strong>{owner.name}</strong><span>{owner.loginName} · {owner.id}</span></dd></div><div><dt>{t("state")}</dt><dd>{t("disabled")}</dd></div></dl>
        {!actionCapability?.available && actionCapability?.restrictionReason ? <Alert status="warning">{restrictions(actionCapability.restrictionReason)}</Alert> : null}
        <Checkbox checked={deleteConfirmed} onChange={(event) => setDeleteConfirmed(event.target.checked)}>{t("keyDeleteAcknowledge")}</Checkbox>
        <div className={styles.actions}><Button disabled={busy || !deleteConfirmed || active.access.key.status !== "DISABLED" || !actionCapability?.available} onClick={() => void run()} variant="danger">{busy ? t("keyLiveSaving") : t("deleteConfirm")}</Button><Button disabled={busy} onClick={onClose} variant="ghost">{t("cancel")}</Button></div>
      </> : null}
    </Card.Body>
  </Card>;
}

export function LiveAccessCredentials({ client, scene, createIntent = null, scopedOwner, userDirectory, accountSecuritySettings = null, authorizationProfiles = null, onInspectPermissions }: {
  client: AccessKeyClient;
  scene: AccountAccessScene;
  createIntent?: AccessKeyCreateIntent | null;
  scopedOwner?: AccountUserScene;
  userDirectory?: { busy: boolean; loading: boolean; readPage(after: string): void };
  accountSecuritySettings?: AccountSecuritySettingsClient | null;
  authorizationProfiles?: AuthorizationProfileClient | null;
  onInspectPermissions?(ownerId: string): void;
}) {
  const t = useTranslations("IamWorkspace");
  const network = useTranslations("AccessKeyNetworkPreview");
  const restrictions = useTranslations("AccountAccess.restrictions");
  const [ownerId, setOwnerId] = useState<string | null>(scopedOwner?.id ?? null);
  const owner = scopedOwner ?? scene.users.find((user) => user.id === ownerId) ?? null;
  const activeOwnerId = owner?.id ?? null;
  const [directoryView, setDirectoryView] = useState<OwnedAccessKeyDirectory | null>(() => scopedOwner
    ? { client, userId: scopedOwner.id, state: loadingAccessKeyDirectory } : null);
  const directoryState = activeOwnerId && directoryView?.client === client && directoryView.userId === activeOwnerId
    ? directoryView.state : activeOwnerId ? loadingAccessKeyDirectory : null;
  const directory = directoryState?.status === "ready" ? directoryState.directory : null;
  const loading = directoryState?.status === "loading";
  const directoryError = directoryState?.status === "error" ? directoryState.error : null;
  const [selection, setSelection] = useState<OwnedAccessKeySelection | null>(null);
  const selected = activeOwnerId && selection?.client === client && selection.userId === activeOwnerId ? selection.access : null;
  const [flowView, setFlowView] = useState<OwnedLiveKeyFlow | null>(null);
  const flow = activeOwnerId && flowView?.client === client && flowView.userId === activeOwnerId ? flowView.flow : null;
  const [interactionErrorView, setInteractionErrorView] = useState<OwnedLiveKeyError | null>(null);
  const interactionError = activeOwnerId && interactionErrorView?.client === client && interactionErrorView.userId === activeOwnerId
    ? interactionErrorView.error : null;
  const error = interactionError ?? directoryError;
  const setFlow = (next: LiveKeyFlow | null) => {
    if (next && activeOwnerId) {
      setFlowView({ client, userId: activeOwnerId, flow: next });
      return;
    }
    setFlowView((current) => current?.client === client && current.userId === activeOwnerId ? null : current);
  };
  const [storedIntentBinding, setStoredIntentBinding] = useState<AccessKeyIntentBinding>(() => ({ client, observed: createIntent, requestId: createIntent?.requestId ?? null }));
  let intentBinding = storedIntentBinding;
  if (storedIntentBinding.observed !== createIntent) {
    intentBinding = {
      client: createIntent && storedIntentBinding.requestId === createIntent.requestId ? storedIntentBinding.client : client,
      observed: createIntent,
      requestId: createIntent?.requestId ?? null
    };
    setStoredIntentBinding(intentBinding);
  }
  const currentCreateIntent = createIntent && intentBinding.client === client && intentBinding.requestId === createIntent.requestId ? createIntent : null;
  const [accountNetworkView, setAccountNetworkView] = useState<{
    client: AccountSecuritySettingsClient | null;
    state: AccessKeyAccountNetworkState;
  }>({ client: accountSecuritySettings, state: accountSecuritySettings ? { status: "loading" } : { status: "unavailable" } });
  const requestRevisions = useRef(new WeakMap<AccessKeyClient, Map<string, number>>());
  const detailRequestRevisions = useRef(new WeakMap<AccessKeyClient, Map<string, number>>());
  const accountNetwork = accountNetworkView.client === accountSecuritySettings
    ? accountNetworkView.state : accountSecuritySettings ? { status: "loading" as const } : { status: "unavailable" as const };

  useEffect(() => {
    if (!accountSecuritySettings) return;
    let current = true;
    void accountSecuritySettings.load().then((result) => {
      if (!current) return;
      setAccountNetworkView({ client: accountSecuritySettings, state: result.status === "ready" ? { status: "ready", value: result.settings.accessKeyNetwork } : { status: "unavailable" } });
    }, () => { if (current) setAccountNetworkView({ client: accountSecuritySettings, state: { status: "unavailable" } }); });
    return () => { current = false; };
  }, [accountSecuritySettings]);

  const load = useCallback(async (userId: string, foreground = true) => {
    const revisions = requestRevisions.current;
    const clientRevisions = revisions.get(client) ?? new Map<string, number>();
    revisions.set(client, clientRevisions);
    const request = (clientRevisions.get(userId) ?? 0) + 1;
    clientRevisions.set(userId, request);
    if (foreground) {
      setDirectoryView({ client, userId, state: loadingAccessKeyDirectory });
      setSelection((current) => current?.client === client && current.userId === userId ? current : null);
      setFlowView((current) => current?.client === client && current.userId === userId ? current : null);
    }
    setInteractionErrorView((current) => current?.client === client && current.userId === userId ? null : current);
    try {
      const next = await client.list(userId);
      if (clientRevisions.get(userId) !== request) return;
      setDirectoryView((current) => current?.client === client && current.userId === userId
        ? { client, userId, state: { status: "ready", directory: next } } : current);
      setSelection((current) => {
        if (current?.client !== client || current.userId !== userId) return current;
        const access = next.items.find((item) => item.key.id === current.access.key.id);
        return access ? { client, userId, access } : null;
      });
    } catch (failure) {
      if (clientRevisions.get(userId) === request) {
        setDirectoryView((current) => current?.client === client && current.userId === userId
          ? { client, userId, state: { status: "error", error: keyError(failure) } } : current);
        setSelection((current) => current?.client === client && current.userId === userId ? null : current);
      }
    }
  }, [client]);

  useEffect(() => {
    if (!activeOwnerId) return;
    void Promise.resolve().then(() => load(activeOwnerId));
  }, [activeOwnerId, load]);

  const chooseOwner = (userId: string) => {
    setDirectoryView(null); setSelection(null); setFlowView(null); setInteractionErrorView(null); setOwnerId(userId);
  };
  const closeOwner = () => {
    setOwnerId(null); setDirectoryView(null); setSelection(null); setFlowView(null); setInteractionErrorView(null);
  };

  if (!owner) return <section className={styles.root}>
    <ContentPage.Heading title={t("keys")} scrollKey="live-access-key-user-directory" />
    <Alert status="info"><KeyRound aria-hidden="true" />{t("keyBoundary")}</Alert>
    {createIntent ? <Alert status="warning">{currentCreateIntent
      ? t("keyLivePendingOwner", { id: currentCreateIntent.userId })
      : t("keyClientChangedIntent", { id: createIntent.requestId })} {currentCreateIntent && scene.users.some((user) => user.id === currentCreateIntent.userId)
        ? <Button onClick={() => chooseOwner(currentCreateIntent.userId)} size="small" variant="ghost">{t("keyLiveResume")}</Button> : null}</Alert> : null}
    <AccessKeyOwnerDirectory scene={scene} busy={userDirectory?.busy} loading={userDirectory?.loading} onOpen={chooseOwner} onReadPage={userDirectory?.readPage} />
    <RotationGuide />
  </section>;

  const startCreate = () => {
    if (createIntent) return;
    if (directory) setFlow({ kind: "create", requestId: requestToken("ui-access-key-create-"), userResourceVersion: directory.userResourceVersion, networkRestrictions: { allowedSourceCidrs: [] } });
  };
  const resumeCreate = () => {
    if (!currentCreateIntent || currentCreateIntent.userId !== owner.id) return;
    setFlow(currentCreateIntent.phase === "unknown"
      ? { kind: "create", requestId: currentCreateIntent.requestId, userResourceVersion: currentCreateIntent.userResourceVersion, networkRestrictions: currentCreateIntent.networkRestrictions }
      : { kind: "replayed", keyId: currentCreateIntent.keyId });
  };
  const openKey = async (access: AccessKeyAccess) => {
    const userId = owner.id;
    const revisions = detailRequestRevisions.current;
    const clientRevisions = revisions.get(client) ?? new Map<string, number>();
    revisions.set(client, clientRevisions);
    const request = (clientRevisions.get(userId) ?? 0) + 1;
    clientRevisions.set(userId, request);
    setSelection({ client, userId, access }); setFlow(null); setInteractionErrorView(null);
    try {
      const next = await client.read(userId, access.key.id);
      if (clientRevisions.get(userId) === request) setSelection((current) => current?.client === client && current.userId === userId
        ? { client, userId, access: next } : current);
    } catch (failure) {
      if (clientRevisions.get(userId) === request) setInteractionErrorView((current) => current && (current.client !== client || current.userId !== userId)
        ? current : { client, userId, error: keyError(failure) });
    }
  };
  const createCapability = directory ? capability(directory, "iam.access-key.create") : null;

  if (!flow && selected && directory) {
    const statusCapability = capability(selected, "iam.access-key.set-status");
    const networkCapability = capability(selected, "iam.access-key.set-network-restrictions");
    const deleteCapability = capability(selected, "iam.access-key.delete");
    const restrictionReason = (value: typeof statusCapability) => value?.restrictionReason
      ? restrictions(value.restrictionReason) : undefined;
    const createDisabled = Boolean(createIntent) || directory.items.length >= 2 || !createCapability?.available;
    const createDisabledReason = createIntent ? t("keyCreatePendingReason")
      : directory.items.length >= 2 ? t("keyQuotaReached")
        : !createCapability?.available ? restrictionReason(createCapability) : undefined;
    const remove = {
      id: "delete", label: t("delete"), danger: true,
      disabled: selected.key.status !== "DISABLED" || !deleteCapability?.available,
      disabledReason: selected.key.status !== "DISABLED" ? t("errors.disableFirst")
        : !deleteCapability?.available ? restrictionReason(deleteCapability) : undefined,
      onSelect: () => setFlow({ kind: "delete", access: selected, requestId: requestToken("ui-access-key-delete-") })
    };
    const replace = { id: "replace", label: t("keyCreateReplacement"), disabled: createDisabled, disabledReason: createDisabledReason, onSelect: startCreate };
    const actions: ComponentProps<typeof WorkspaceDetail>["actions"] = selected.key.credentialState === "RECOVERY_FENCED"
      ? selected.key.status === "ENABLED"
        ? { primary: { id: "status", label: t("disable"), variant: "secondary", disabled: !statusCapability?.available, disabledReason: !statusCapability?.available ? restrictionReason(statusCapability) : undefined, onSelect: () => setFlow({ kind: "status", access: selected, status: "DISABLED", requestId: requestToken("ui-access-key-status-") }) }, secondary: [replace, remove] }
        : { primary: replace, secondary: [remove] }
      : {
          primary: {
            id: "status", label: t(selected.key.status === "ENABLED" ? "disable" : "enable"), variant: "secondary",
            disabled: !statusCapability?.available, disabledReason: !statusCapability?.available ? restrictionReason(statusCapability) : undefined,
            onSelect: () => setFlow({ kind: "status", access: selected, status: selected.key.status === "ENABLED" ? "DISABLED" : "ENABLED", requestId: requestToken("ui-access-key-status-") })
          },
          secondary: [{
            id: "network", label: network("configureKey"), disabled: !networkCapability?.available,
            disabledReason: !networkCapability?.available ? restrictionReason(networkCapability) : undefined,
            onSelect: () => setFlow({ kind: "network", access: selected, requestId: requestToken("ui-access-key-network-") })
          }, remove]
        };
    return <section className={styles.root}>
      <WorkspaceDetail embedded={Boolean(scopedOwner)} title={selected.key.id} onBack={() => setSelection(null)} actions={actions}>
        {!scopedOwner ? <Alert status="info">{t("keyLiveProductBoundary")}</Alert> : null}
        {error ? <Alert status="danger">{t(`keyLiveErrors.${error}`)} <Button onClick={() => void load(owner.id)} size="small" variant="ghost">{t("keyLiveRetry")}</Button></Alert> : null}
        {selected.key.credentialState === "RECOVERY_FENCED" ? <Alert status="danger">{t("keyCredentialFencedAlert")}</Alert> : null}
        <Card><Card.Body className={styles.detailBody}>
          <dl className={styles.keyFacts}><div><dt>{t("keyId")}</dt><dd><AccountIdentifier label={t("keyId")} value={selected.key.id} /></dd></div><div><dt>{t("owner")}</dt><dd><strong>{owner.name}</strong><span>{owner.loginName} · {owner.id}</span></dd></div><div><dt>{t("keyCredentialState")}</dt><dd><AccessKeyCredentialStateBadge value={selected.key.credentialState} /><span>{t(selected.key.credentialState === "RECOVERY_FENCED" ? "keyCredentialFencedHint" : "keyCredentialCurrentHint")}</span></dd></div><div><dt>{t("keyManagementState")}</dt><dd><Badge status={selected.key.credentialState === "CURRENT" && selected.key.status === "ENABLED" ? "success" : "neutral"}>{t(selected.key.status === "ENABLED" ? "enabled" : "disabled")}</Badge></dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.key.createdAt} /></dd></div></dl>
        </Card.Body></Card>
        <AccessKeyNetworkDetail account={accountNetwork} keyValue={selected.key} source="LIVE" />
        <AccessKeyUsagePreview source="LIVE" usage={selected.usage} />
        <ProgrammaticAccessGuide client={authorizationProfiles} owner={owner} onInspectPermissions={onInspectPermissions} />
        <RotationGuide />
      </WorkspaceDetail>
    </section>;
  }

  return <section className={styles.root}>
    {scopedOwner ? <div className={styles.embeddedHeading}><h3>{t("keys")}</h3><Button disabled={Boolean(flow || createIntent) || !createCapability?.available} onClick={startCreate} size="small">{t("createKey")}</Button></div>
      : <ContentPage.Heading title={`${owner.loginName} · ${t("keys")}`} scrollKey={`live-access-keys:${owner.id}`} back={{ label: t("back"), onClick: closeOwner }} actions={!flow && directory ? <ContentPage.Commands label={t("keys")} primary={{ id: "create-key", label: t("createKey"), disabled: Boolean(createIntent) || !createCapability?.available, disabledReason: createCapability?.restrictionReason ? restrictions(createCapability.restrictionReason) : undefined, onSelect: startCreate }} /> : undefined} focus />}
    {!scopedOwner ? <Alert status="info">{t("keyLiveProductBoundary")}</Alert> : null}
    {createIntent && !flow ? <Alert status="warning">{currentCreateIntent
      ? currentCreateIntent.userId === owner.id
        ? currentCreateIntent.phase === "unknown" ? t("keyCreateUncertain", { id: currentCreateIntent.requestId }) : t("keyRecovered", { id: currentCreateIntent.keyId })
        : t("keyLivePendingOwner", { id: currentCreateIntent.userId })
      : t("keyClientChangedIntent", { id: createIntent.requestId })} {currentCreateIntent
        ? currentCreateIntent.userId === owner.id
          ? <Button disabled={Boolean(flow) || currentCreateIntent.phase === "unknown" && !createCapability?.available} onClick={resumeCreate} size="small" variant="ghost">{t("keyLiveResume")}</Button>
          : !scopedOwner && scene.users.some((user) => user.id === currentCreateIntent.userId) ? <Button onClick={() => chooseOwner(currentCreateIntent.userId)} size="small" variant="ghost">{t("keyLiveResume")}</Button> : null
        : null}</Alert> : null}
    {error ? <Alert status="danger">{t(`keyLiveErrors.${error}`)} <Button onClick={() => void load(owner.id)} size="small" variant="ghost">{t("keyLiveRetry")}</Button></Alert> : null}
    {loading && !directory ? <Card>
      <Card.Header className={styles.directoryHeader}><div><Typography.Title as="h2" level={3}>{t("keyDirectory")}</Typography.Title><Typography.Text tone="muted">{t("keyDirectoryHint", { name: owner.loginName })}</Typography.Text></div></Card.Header>
      <TableSkeleton header={false} label={t("keyLiveLoading")} labelVisible={false} rows={2} />
    </Card> : null}
    {flow && directory ? <LiveKeyWorkflow flow={flow} owner={owner} directory={directory} client={client}
      retryingOriginal={flow.kind === "create" && currentCreateIntent?.phase === "unknown" && currentCreateIntent.requestId === flow.requestId}
      onChanged={() => load(owner.id, false)} onClose={() => setFlow(null)}
      onInspectRecovered={(keyId) => { setFlow(null); const found = directory.items.find((item) => item.key.id === keyId); if (found) void openKey(found); else void load(owner.id); }} /> : null}
    {!flow && !selected && directory ? <>
      <Card><Card.Header className={styles.directoryHeader}><div><Typography.Title as="h2" level={3}>{t("keyDirectory")}</Typography.Title><Typography.Text tone="muted">{t("keyDirectoryHint", { name: owner.loginName })}</Typography.Text></div><Badge status={directory.items.length >= 2 ? "warning" : "neutral"}>{t("keyQuota", { count: directory.items.length })}</Badge></Card.Header><Card.Body className={styles.tableBody}>{directory.items.length ? <Table aria-label={t("keys")} mobileLayout="stack"><thead><tr><th scope="col">{t("keyId")}</th><th scope="col">{t("keyCredentialState")}</th><th scope="col">{t("keyManagementState")}</th><th scope="col">{t("created")}</th><th scope="col">{t("keySecuritySignals")}</th></tr></thead><tbody>{directory.items.map((item) => <tr key={item.key.id}><td data-label={t("keyId")}><Table.PrimaryAction onClick={() => void openKey(item)}>{item.key.id}</Table.PrimaryAction></td><td data-label={t("keyCredentialState")}><AccessKeyCredentialStateBadge value={item.key.credentialState} /></td><td data-label={t("keyManagementState")}><Badge status={item.key.credentialState === "CURRENT" && item.key.status === "ENABLED" ? "success" : "neutral"}>{t(item.key.status === "ENABLED" ? "enabled" : "disabled")}</Badge></td><td data-label={t("created")}><WorkspaceTime value={item.key.createdAt} /></td><td data-label={t("keySecuritySignals")}><AccessKeySecuritySignals account={accountNetwork} keyValue={item.key} usage={item.usage} /></td></tr>)}</tbody></Table> : <div className={styles.emptyKeys}><KeyRound aria-hidden="true" /><strong>{t("keyEmpty")}</strong><span>{t("keyEmptyHint")}</span></div>}</Card.Body></Card>
      <ProgrammaticAccessGuide client={authorizationProfiles} owner={owner} onInspectPermissions={onInspectPermissions} />
      <RotationGuide />
    </> : null}
  </section>;
}
