"use client";

import { useCallback, useEffect, useId, useRef, useState } from "react";
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
import { ProgrammaticAccessGuide, RotationGuide } from "./AccessCredentials";
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
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<LiveKeyError | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [deleteConfirmed, setDeleteConfirmed] = useState(false);
  const initialNetwork = flow.kind === "create" ? flow.networkRestrictions : flow.kind === "network" ? flow.access.key.networkRestrictions : { allowedSourceCidrs: [] };
  const [networkDraft, setNetworkDraft] = useState(() => initialNetwork.allowedSourceCidrs.join("\n"));
  const [networkIssue, setNetworkIssue] = useState<AccessKeyNetworkDraftIssue | null>(null);
  useEffect(() => { heading.current?.focus({ preventScroll: true }); }, [flow.kind]);

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
      await onChanged();
      onClose();
    } catch (failure) { setError(keyError(failure)); }
    finally { setBusy(false); }
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
        <div className={styles.actions}><Button disabled={!acknowledged} onClick={() => { client.acknowledgeIssued(active.requestId, active.keyId); onClose(); }}>{t("done")}</Button></div>
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
  const [directory, setDirectory] = useState<AccessKeyDirectory | null>(null);
  const [selected, setSelected] = useState<AccessKeyAccess | null>(null);
  const [flow, setFlow] = useState<LiveKeyFlow | null>(null);
  const [loading, setLoading] = useState(Boolean(scopedOwner));
  const [error, setError] = useState<LiveKeyError | null>(null);
  const [accountNetworkView, setAccountNetworkView] = useState<{
    client: AccountSecuritySettingsClient | null;
    state: AccessKeyAccountNetworkState;
  }>({ client: accountSecuritySettings, state: accountSecuritySettings ? { status: "loading" } : { status: "unavailable" } });
  const requestRevision = useRef(0);
  const scopedOwnerId = scopedOwner?.id ?? null;
  const owner = scopedOwner ?? scene.users.find((user) => user.id === ownerId) ?? null;
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
    const request = ++requestRevision.current;
    if (foreground) setLoading(true);
    setError(null);
    try {
      const next = await client.list(userId);
      if (request !== requestRevision.current) return;
      setDirectory(next);
      setSelected((current) => current ? next.items.find((item) => item.key.id === current.key.id) ?? null : null);
    } catch (failure) {
      if (request === requestRevision.current) { setDirectory(null); setSelected(null); setError(keyError(failure)); }
    } finally { if (request === requestRevision.current) setLoading(false); }
  }, [client]);

  useEffect(() => {
    if (!scopedOwnerId) return;
    const request = ++requestRevision.current;
    void client.list(scopedOwnerId).then(
      (next) => { if (request === requestRevision.current) { setDirectory(next); setLoading(false); } },
      (failure) => { if (request === requestRevision.current) { setError(keyError(failure)); setLoading(false); } }
    );
    return () => { requestRevision.current += 1; };
  }, [client, scopedOwnerId]);

  const chooseOwner = (userId: string) => {
    requestRevision.current += 1;
    setDirectory(null); setSelected(null); setFlow(null); setError(null); setLoading(true); setOwnerId(userId);
    void load(userId);
  };
  const closeOwner = () => {
    requestRevision.current += 1;
    setOwnerId(null); setDirectory(null); setSelected(null); setFlow(null); setError(null); setLoading(false);
  };

  if (!owner) return <section className={styles.root}>
    <ContentPage.Heading title={t("keys")} scrollKey="live-access-key-user-directory" />
    <Alert status="info"><KeyRound aria-hidden="true" />{t("keyBoundary")}</Alert>
    {createIntent ? <Alert status="warning">{t("keyLivePendingOwner", { id: createIntent.userId })} {scene.users.some((user) => user.id === createIntent.userId) ? <Button onClick={() => chooseOwner(createIntent.userId)} size="small" variant="ghost">{t("keyLiveResume")}</Button> : null}</Alert> : null}
    <AccessKeyOwnerDirectory scene={scene} busy={userDirectory?.busy} loading={userDirectory?.loading} onOpen={chooseOwner} onReadPage={userDirectory?.readPage} />
    <RotationGuide />
  </section>;

  const startCreate = () => {
    if (createIntent) return;
    if (directory) setFlow({ kind: "create", requestId: requestToken("ui-access-key-create-"), userResourceVersion: directory.userResourceVersion, networkRestrictions: { allowedSourceCidrs: [] } });
  };
  const resumeCreate = () => {
    if (!createIntent || createIntent.userId !== owner.id) return;
    setFlow(createIntent.phase === "unknown"
      ? { kind: "create", requestId: createIntent.requestId, userResourceVersion: createIntent.userResourceVersion, networkRestrictions: createIntent.networkRestrictions }
      : { kind: "replayed", keyId: createIntent.keyId });
  };
  const openKey = async (access: AccessKeyAccess) => {
    setSelected(access); setFlow(null); setError(null);
    try { setSelected(await client.read(owner.id, access.key.id)); }
    catch (failure) { setError(keyError(failure)); }
  };
  const createCapability = directory ? capability(directory, "iam.access-key.create") : null;

  if (!flow && selected) {
    const statusCapability = capability(selected, "iam.access-key.set-status");
    const networkCapability = capability(selected, "iam.access-key.set-network-restrictions");
    const deleteCapability = capability(selected, "iam.access-key.delete");
    const restrictionReason = (value: typeof statusCapability) => value?.restrictionReason
      ? restrictions(value.restrictionReason) : undefined;
    return <section className={styles.root}>
      <WorkspaceDetail embedded={Boolean(scopedOwner)} title={selected.key.id} onBack={() => setSelected(null)} actions={{
        primary: {
          id: "status",
          label: t(selected.key.status === "ENABLED" ? "disable" : "enable"),
          variant: "secondary",
          disabled: !statusCapability?.available,
          disabledReason: !statusCapability?.available ? restrictionReason(statusCapability) : undefined,
          onSelect: () => setFlow({ kind: "status", access: selected, status: selected.key.status === "ENABLED" ? "DISABLED" : "ENABLED", requestId: requestToken("ui-access-key-status-") })
        },
        secondary: [{
          id: "network",
          label: network("configureKey"),
          disabled: !networkCapability?.available,
          disabledReason: !networkCapability?.available ? restrictionReason(networkCapability) : undefined,
          onSelect: () => setFlow({ kind: "network", access: selected, requestId: requestToken("ui-access-key-network-") })
        }, {
          id: "delete",
          label: t("delete"),
          danger: true,
          disabled: selected.key.status !== "DISABLED" || !deleteCapability?.available,
          disabledReason: selected.key.status !== "DISABLED" ? t("errors.disableFirst")
            : !deleteCapability?.available ? restrictionReason(deleteCapability) : undefined,
          onSelect: () => setFlow({ kind: "delete", access: selected, requestId: requestToken("ui-access-key-delete-") })
        }]
      }}>
        {!scopedOwner ? <Alert status="info">{t("keyLiveProductBoundary")}</Alert> : null}
        {error ? <Alert status="danger">{t(`keyLiveErrors.${error}`)} <Button onClick={() => void load(owner.id)} size="small" variant="ghost">{t("keyLiveRetry")}</Button></Alert> : null}
        <Card><Card.Body className={styles.detailBody}>
          <dl className={styles.keyFacts}><div><dt>{t("keyId")}</dt><dd><AccountIdentifier label={t("keyId")} value={selected.key.id} /></dd></div><div><dt>{t("owner")}</dt><dd><strong>{owner.name}</strong><span>{owner.loginName} · {owner.id}</span></dd></div><div><dt>{t("state")}</dt><dd><Badge status={selected.key.status === "ENABLED" ? "success" : "neutral"}>{t(selected.key.status === "ENABLED" ? "enabled" : "disabled")}</Badge></dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.key.createdAt} /></dd></div></dl>
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
    {createIntent && !flow ? <Alert status="warning">{createIntent.userId === owner.id
      ? createIntent.phase === "unknown" ? t("keyCreateUncertain", { id: createIntent.requestId }) : t("keyRecovered", { id: createIntent.keyId })
      : t("keyLivePendingOwner", { id: createIntent.userId })} {createIntent.userId === owner.id
        ? <Button disabled={Boolean(flow) || createIntent.phase === "unknown" && !createCapability?.available} onClick={resumeCreate} size="small" variant="ghost">{t("keyLiveResume")}</Button>
        : !scopedOwner && scene.users.some((user) => user.id === createIntent.userId) ? <Button onClick={() => chooseOwner(createIntent.userId)} size="small" variant="ghost">{t("keyLiveResume")}</Button> : null}</Alert> : null}
    {error ? <Alert status="danger">{t(`keyLiveErrors.${error}`)} <Button onClick={() => void load(owner.id)} size="small" variant="ghost">{t("keyLiveRetry")}</Button></Alert> : null}
    {loading && !directory ? <Card>
      <Card.Header className={styles.directoryHeader}><div><Typography.Title as="h2" level={3}>{t("keyDirectory")}</Typography.Title><Typography.Text tone="muted">{t("keyDirectoryHint", { name: owner.loginName })}</Typography.Text></div></Card.Header>
      <TableSkeleton header={false} label={t("keyLiveLoading")} labelVisible={false} rows={2} />
    </Card> : null}
    {flow && directory ? <LiveKeyWorkflow flow={flow} owner={owner} directory={directory} client={client}
      retryingOriginal={flow.kind === "create" && createIntent?.phase === "unknown" && createIntent.requestId === flow.requestId}
      onChanged={() => load(owner.id, false)} onClose={() => setFlow(null)}
      onInspectRecovered={(keyId) => { setFlow(null); const found = directory.items.find((item) => item.key.id === keyId); if (found) void openKey(found); else void load(owner.id); }} /> : null}
    {!flow && !selected && directory ? <>
      <Card><Card.Header className={styles.directoryHeader}><div><Typography.Title as="h2" level={3}>{t("keyDirectory")}</Typography.Title><Typography.Text tone="muted">{t("keyDirectoryHint", { name: owner.loginName })}</Typography.Text></div><Badge status={directory.items.length >= 2 ? "warning" : "neutral"}>{t("keyQuota", { count: directory.items.length })}</Badge></Card.Header><Card.Body className={styles.tableBody}>{directory.items.length ? <Table aria-label={t("keys")} mobileLayout="stack"><thead><tr><th scope="col">{t("keyId")}</th><th scope="col">{t("state")}</th><th scope="col">{t("created")}</th><th scope="col">{t("keySecuritySignals")}</th></tr></thead><tbody>{directory.items.map((item) => <tr key={item.key.id}><td data-label={t("keyId")}><Table.PrimaryAction onClick={() => void openKey(item)}>{item.key.id}</Table.PrimaryAction></td><td data-label={t("state")}><Badge status={item.key.status === "ENABLED" ? "success" : "neutral"}>{t(item.key.status === "ENABLED" ? "enabled" : "disabled")}</Badge></td><td data-label={t("created")}><WorkspaceTime value={item.key.createdAt} /></td><td data-label={t("keySecuritySignals")}><AccessKeySecuritySignals account={accountNetwork} keyValue={item.key} usage={item.usage} /></td></tr>)}</tbody></Table> : <div className={styles.emptyKeys}><KeyRound aria-hidden="true" /><strong>{t("keyEmpty")}</strong><span>{t("keyEmptyHint")}</span></div>}</Card.Body></Card>
      <ProgrammaticAccessGuide client={authorizationProfiles} owner={owner} onInspectPermissions={onInspectPermissions} />
      <RotationGuide />
    </> : null}
  </section>;
}
