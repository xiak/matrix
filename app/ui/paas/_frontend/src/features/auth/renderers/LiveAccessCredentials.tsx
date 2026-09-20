"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { KeyRound, RotateCw, UserRound } from "lucide-react";
import { Alert, Badge, Button, Card, Checkbox, ContentPage, Table, Typography } from "@ui/xiak";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import type { AccessKeyAccess, AccessKeyDirectory, AccessKeyStatus } from "../domain/accessKeys";
import type { IamAction } from "../domain/accounts";
import type { AccessKeyClient } from "../application/AccountAccessProvider";
import type { AccountAccessScene, AccountUserScene } from "../scenes/accountAccessScene";
import { AccountIdentifier } from "./AccountOverview";
import { WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccessCredentials.module.css";

type LiveKeyError = "forbidden" | "routeUnavailable" | "conflict" | "unavailable";
type LiveKeyFlow =
  | { kind: "create"; requestId: string }
  | { kind: "issued"; keyId: string; secret: string }
  | { kind: "replayed"; keyId: string }
  | { kind: "status"; access: AccessKeyAccess; status: AccessKeyStatus; requestId: string }
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

function RotationGuide() {
  const t = useTranslations("IamWorkspace");
  return <Card>
    <Card.Header><div className={styles.cardHeading}><RotateCw aria-hidden="true" /><div><Typography.Title as="h2" level={3}>{t("keyRotationTitle")}</Typography.Title><Typography.Text tone="muted">{t("keyRotationHint")}</Typography.Text></div></div></Card.Header>
    <Card.Body><ol className={styles.rotationSteps}>{(["create", "migrate", "verify", "retire"] as const).map((step, index) => <li key={step}><span>{index + 1}</span><div><strong>{t(`keyRotation.${step}.title`)}</strong><small>{t(`keyRotation.${step}.hint`)}</small></div></li>)}</ol></Card.Body>
  </Card>;
}

function LiveKeyWorkflow({ flow, owner, directory, client, onChanged, onClose }: {
  flow: LiveKeyFlow;
  owner: AccountUserScene;
  directory: AccessKeyDirectory;
  client: AccessKeyClient;
  onChanged(): Promise<void>;
  onClose(): void;
}) {
  const t = useTranslations("IamWorkspace");
  const restrictions = useTranslations("AccountAccess.restrictions");
  const heading = useRef<HTMLHeadingElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<LiveKeyError | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [deleteConfirmed, setDeleteConfirmed] = useState(false);
  useEffect(() => { heading.current?.focus({ preventScroll: true }); }, [flow.kind]);

  const createCapability = capability(directory, "iam.access-key.create");
  const actionCapability = flow.kind === "status" ? capability(flow.access, "iam.access-key.set-status")
    : flow.kind === "delete" ? capability(flow.access, "iam.access-key.delete") : null;
  const title = flow.kind === "create" ? t("keyCreateReview")
    : flow.kind === "issued" ? t("keyLiveCreated")
      : flow.kind === "replayed" ? t("keyLiveReplayTitle")
        : flow.kind === "status" ? t("changeStateTitle", { action: t(flow.status === "ENABLED" ? "enable" : "disable"), name: flow.access.key.id })
          : t("keyDeleteReview", { name: flow.access.key.id });

  const run = async () => {
    setBusy(true); setError(null);
    try {
      if (flow.kind === "create") {
        const result = await client.create(owner.id, { userResourceVersion: directory.userResourceVersion, requestId: flow.requestId });
        await onChanged();
        if (result.outcome === "APPLIED") onCloseWith({ kind: "issued", keyId: result.key.id, secret: result.secret });
        else onCloseWith({ kind: "replayed", keyId: result.key.id });
        return;
      }
      if (flow.kind === "status") {
        await client.setStatus(owner.id, flow.access.key.id, { accessKeyResourceVersion: flow.access.key.resourceVersion, requestId: flow.requestId, status: flow.status });
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

  return <Card>
    <Card.Header className={styles.flowHeader}><div><h2 className={styles.focusHeading} ref={heading} tabIndex={-1}>{activeTitle}</h2><Typography.Text tone="muted">{t("keyInlineWorkflow")}</Typography.Text></div><Badge status="success">LIVE</Badge></Card.Header>
    <Card.Body className={styles.flowBody}>
      {error ? <Alert status="danger">{t(`keyLiveErrors.${error}`)}</Alert> : null}
      {active.kind === "create" ? <>
        <dl className={styles.reviewFacts}>
          <div><dt>{t("owner")}</dt><dd><strong>{owner.name}</strong><span>{owner.loginName} · {owner.id}</span></dd></div>
          <div><dt>{t("keyUserRevision")}</dt><dd>v{directory.userResourceVersion}</dd></div>
          <div><dt>requestId</dt><dd><code>{active.requestId}</code></dd></div>
        </dl>
        <Alert status="warning">{t("keyCreateWarning")}</Alert>
        {!createCapability?.available && createCapability?.restrictionReason ? <Alert status="warning">{restrictions(createCapability.restrictionReason)}</Alert> : null}
        <div className={styles.actions}><Button disabled={busy || !createCapability?.available} onClick={() => void run()}>{busy ? t("keyLiveSaving") : t("keyConfirmCreate")}</Button><Button disabled={busy} onClick={onClose} variant="ghost">{t("cancel")}</Button></div>
      </> : null}
      {active.kind === "issued" ? <>
        <Alert status="warning">{t("keyLiveSecretWarning")}</Alert>
        <div className={styles.secretGrid}><div><span>{t("keyId")}</span><AccountIdentifier label={t("keyId")} value={active.keyId} /></div><div><span>{t("keySecret")}</span><AccountIdentifier label={t("keySecret")} value={active.secret} /></div></div>
        <Checkbox checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)}>{t("keyLiveAcknowledge")}</Checkbox>
        <div className={styles.actions}><Button disabled={!acknowledged} onClick={onClose}>{t("done")}</Button></div>
      </> : null}
      {active.kind === "replayed" ? <>
        <Alert status="warning">{t("keyLiveReplay", { id: active.keyId })}</Alert>
        <p className={styles.note}>{t("keyRecoveredNext")}</p>
        <div className={styles.actions}><Button onClick={onClose}>{t("done")}</Button></div>
      </> : null}
      {active.kind === "status" ? <>
        <Alert status={active.status === "DISABLED" ? "warning" : "info"}>{t(active.status === "DISABLED" ? "keyDisableImpact" : "keyEnableImpact")}</Alert>
        <dl className={styles.reviewFacts}><div><dt>{t("keyId")}</dt><dd><code>{active.access.key.id}</code></dd></div><div><dt>{t("state")}</dt><dd>{t(active.access.key.status === "ENABLED" ? "enabled" : "disabled")} → {t(active.status === "ENABLED" ? "enabled" : "disabled")}</dd></div><div><dt>{t("keyRevision")}</dt><dd>v{active.access.key.resourceVersion}</dd></div><div><dt>requestId</dt><dd><code>{active.requestId}</code></dd></div></dl>
        {!actionCapability?.available && actionCapability?.restrictionReason ? <Alert status="warning">{restrictions(actionCapability.restrictionReason)}</Alert> : null}
        <div className={styles.actions}><Button disabled={busy || !actionCapability?.available} onClick={() => void run()}>{busy ? t("keyLiveSaving") : t(active.status === "ENABLED" ? "enable" : "disable")}</Button><Button disabled={busy} onClick={onClose} variant="ghost">{t("cancel")}</Button></div>
      </> : null}
      {active.kind === "delete" ? <>
        <Alert status="danger">{t("keyDeleteImpact")}</Alert>
        <dl className={styles.reviewFacts}><div><dt>{t("keyId")}</dt><dd><code>{active.access.key.id}</code></dd></div><div><dt>{t("keyRevision")}</dt><dd>v{active.access.key.resourceVersion}</dd></div><div><dt>requestId</dt><dd><code>{active.requestId}</code></dd></div></dl>
        {!actionCapability?.available && actionCapability?.restrictionReason ? <Alert status="warning">{restrictions(actionCapability.restrictionReason)}</Alert> : null}
        <Checkbox checked={deleteConfirmed} onChange={(event) => setDeleteConfirmed(event.target.checked)}>{t("keyDeleteAcknowledge")}</Checkbox>
        <div className={styles.actions}><Button disabled={busy || !deleteConfirmed || active.access.key.status !== "DISABLED" || !actionCapability?.available} onClick={() => void run()} variant="danger">{busy ? t("keyLiveSaving") : t("deleteConfirm")}</Button><Button disabled={busy} onClick={onClose} variant="ghost">{t("cancel")}</Button></div>
      </> : null}
    </Card.Body>
  </Card>;
}

export function LiveAccessCredentials({ client, scene }: { client: AccessKeyClient; scene: AccountAccessScene }) {
  const t = useTranslations("IamWorkspace");
  const restrictions = useTranslations("AccountAccess.restrictions");
  const [ownerId, setOwnerId] = useState<string | null>(null);
  const [directory, setDirectory] = useState<AccessKeyDirectory | null>(null);
  const [selected, setSelected] = useState<AccessKeyAccess | null>(null);
  const [flow, setFlow] = useState<LiveKeyFlow | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<LiveKeyError | null>(null);
  const requestRevision = useRef(0);
  const owner = scene.users.find((user) => user.id === ownerId) ?? null;

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
    <Card>
      <Card.Header className={styles.directoryHeader}><div><Typography.Title as="h2" level={3}>{t("keyUserDirectory")}</Typography.Title><Typography.Text tone="muted">{t("keyUserDirectoryHint")}</Typography.Text></div><Badge status="neutral">{t("userCount", { count: scene.users.length })}</Badge></Card.Header>
      <Card.Body className={styles.tableBody}>{scene.users.length ? <Table aria-label={t("keyUserDirectory")} mobileLayout="stack"><thead><tr><th scope="col">{t("owner")}</th><th scope="col">{t("state")}</th><th scope="col">{t("keyLoadingModel")}</th></tr></thead><tbody>{scene.users.map((user) => <tr key={user.id}><td data-label={t("owner")}><span className={styles.identity}><UserRound aria-hidden="true" /><span><strong>{user.name}</strong><small>{user.loginName} · {user.id}</small></span></span></td><td data-label={t("state")}><Badge status={user.enabled ? "success" : "neutral"}>{t(user.enabled ? "enabled" : "disabled")}</Badge></td><td data-label={t("keyLoadingModel")}><Button aria-label={t("keyManageNamed", { name: user.loginName })} onClick={() => chooseOwner(user.id)} size="small" variant="secondary">{t("keyManage")}</Button></td></tr>)}</tbody></Table> : <p className={styles.note}>{t("keyPrimary")}</p>}</Card.Body>
    </Card>
    <RotationGuide />
  </section>;

  const startCreate = () => setFlow({ kind: "create", requestId: requestToken("ui-access-key-create-") });
  const openKey = async (access: AccessKeyAccess) => {
    setSelected(access); setFlow(null); setError(null);
    try { setSelected(await client.read(owner.id, access.key.id)); }
    catch (failure) { setError(keyError(failure)); }
  };
  const createCapability = directory ? capability(directory, "iam.access-key.create") : null;

  return <section className={styles.root}>
    <ContentPage.Heading title={`${owner.loginName} · ${t("keys")}`} scrollKey={`live-access-keys:${owner.id}`} back={{ label: t("back"), onClick: closeOwner }} actions={!flow && directory ? <ContentPage.Commands label={t("keys")} primary={{ id: "create-key", label: t("createKey"), disabled: !createCapability?.available, disabledReason: createCapability?.restrictionReason ? restrictions(createCapability.restrictionReason) : undefined, onSelect: startCreate }} /> : undefined} focus />
    <Alert status="warning">{t("keyLiveProductBoundary")}</Alert>
    {error ? <Alert status="danger">{t(`keyLiveErrors.${error}`)} <Button onClick={() => void load(owner.id)} size="small" variant="ghost">{t("keyLiveRetry")}</Button></Alert> : null}
    {loading && !directory ? <Card><Card.Body><p className={styles.note} role="status">{t("keyLiveLoading")}</p></Card.Body></Card> : null}
    {flow && directory ? <LiveKeyWorkflow flow={flow} owner={owner} directory={directory} client={client} onChanged={() => load(owner.id, false)} onClose={() => setFlow(null)} /> : null}
    {!flow && selected ? <>
      <Card><Card.Header><div><Typography.Title as="h2" level={3}>{selected.key.id}</Typography.Title><Typography.Text tone="muted">{t("keyDirectoryHint", { name: owner.loginName })}</Typography.Text></div><Badge status={selected.key.status === "ENABLED" ? "success" : "neutral"}>{t(selected.key.status === "ENABLED" ? "enabled" : "disabled")}</Badge></Card.Header><Card.Body className={styles.detailBody}>
        <dl className={styles.keyFacts}><div><dt>{t("keyId")}</dt><dd><AccountIdentifier label={t("keyId")} value={selected.key.id} /></dd></div><div><dt>{t("owner")}</dt><dd><strong>{owner.name}</strong><span>{owner.loginName} · {owner.id}</span></dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.key.createdAt} /></dd></div><div><dt>{t("keyRevision")}</dt><dd>v{selected.key.resourceVersion}</dd></div></dl>
        <Alert status="info">{t("keyNoUsageEvidence")}</Alert>
        <div className={styles.actions}><Button onClick={() => setSelected(null)} variant="ghost">{t("back")}</Button><Button disabled={!capability(selected, "iam.access-key.set-status")?.available} onClick={() => setFlow({ kind: "status", access: selected, status: selected.key.status === "ENABLED" ? "DISABLED" : "ENABLED", requestId: requestToken("ui-access-key-status-") })} variant="secondary">{t(selected.key.status === "ENABLED" ? "disable" : "enable")}</Button><Button disabled={selected.key.status !== "DISABLED" || !capability(selected, "iam.access-key.delete")?.available} onClick={() => setFlow({ kind: "delete", access: selected, requestId: requestToken("ui-access-key-delete-") })} variant="danger">{t("delete")}</Button></div>
      </Card.Body></Card>
      <RotationGuide />
    </> : null}
    {!flow && !selected && directory ? <>
      <Card><Card.Header className={styles.directoryHeader}><div><Typography.Title as="h2" level={3}>{t("keyDirectory")}</Typography.Title><Typography.Text tone="muted">{t("keyDirectoryHint", { name: owner.loginName })}</Typography.Text></div><Badge status={directory.items.length >= 2 ? "warning" : "neutral"}>{t("keyQuota", { count: directory.items.length })}</Badge></Card.Header><Card.Body className={styles.tableBody}>{directory.items.length ? <Table aria-label={t("keys")} mobileLayout="stack"><thead><tr><th scope="col">{t("keyId")}</th><th scope="col">{t("state")}</th><th scope="col">{t("created")}</th><th scope="col">{t("keyRevision")}</th></tr></thead><tbody>{directory.items.map((item) => <tr key={item.key.id}><td data-label={t("keyId")}><button className={styles.keyLink} onClick={() => void openKey(item)}>{item.key.id}</button></td><td data-label={t("state")}><Badge status={item.key.status === "ENABLED" ? "success" : "neutral"}>{t(item.key.status === "ENABLED" ? "enabled" : "disabled")}</Badge></td><td data-label={t("created")}><WorkspaceTime value={item.key.createdAt} /></td><td data-label={t("keyRevision")}>v{item.key.resourceVersion}</td></tr>)}</tbody></Table> : <div className={styles.emptyKeys}><KeyRound aria-hidden="true" /><strong>{t("keyEmpty")}</strong><span>{t("keyEmptyHint")}</span></div>}</Card.Body></Card>
      <RotationGuide />
    </> : null}
  </section>;
}
