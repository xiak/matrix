"use client";

import { useEffect, useId, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { KeyRound, RotateCw, UserRound } from "lucide-react";
import { Alert, Badge, Button, Card, Checkbox, ContentPage, FormField, Select, Table, Typography } from "@ui/xiak";
import { requestToken } from "@/infrastructure/http/jsonRequest";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessKey, AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessScene, AccountUserScene } from "../scenes/accountAccessScene";
import { AccountIdentifier } from "./AccountOverview";
import { WorkspaceDetail, WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccessCredentials.module.css";

type KeyFlow =
  | { kind: "create"; ownerId: string; requestId: string; scenario: "success" | "response-lost" }
  | { kind: "issued"; ownerId: string; requestId: string; key: { id: string; secret: string } }
  | { kind: "uncertain"; ownerId: string; requestId: string; keyId: string }
  | { kind: "recovered"; ownerId: string; requestId: string; keyId: string }
  | { kind: "status"; keyId: string; requestId: string; status: AccessKey["status"] }
  | { kind: "delete"; keyId: string; requestId: string };

function InlineFlow({ flow, owner, keyValue, onChange, onClose, onOpenKey }: {
  flow: KeyFlow;
  owner: AccountUserScene;
  keyValue: AccessKey | null;
  onChange(flow: KeyFlow): void;
  onClose(): void;
  onOpenKey(id: string): void;
}) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const scenarioId = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [deleteConfirmed, setDeleteConfirmed] = useState(false);
  useEffect(() => { heading.current?.focus({ preventScroll: true }); }, [flow.kind]);

  const title = flow.kind === "create" ? t("keyCreateReview")
    : flow.kind === "issued" ? t("keyCreated")
      : flow.kind === "uncertain" ? t("keyCreateUncertainTitle")
        : flow.kind === "recovered" ? t("keyRecoveredTitle")
          : flow.kind === "status" ? t("changeStateTitle", { action: t(flow.status === "ENABLED" ? "enable" : "disable"), name: flow.keyId })
            : t("keyDeleteReview", { name: flow.keyId });

  const create = async () => {
    if (flow.kind !== "create") return;
    const result = await access.executeWorkspace({
      kind: "create-key",
      ownerId: owner.id,
      userResourceVersion: owner.resourceVersion,
      requestId: flow.requestId
    });
    if (!result?.issuedKey) return;
    onChange(flow.scenario === "response-lost"
      ? { kind: "uncertain", ownerId: owner.id, requestId: flow.requestId, keyId: result.issuedKey.id }
      : { kind: "issued", ownerId: owner.id, requestId: flow.requestId, key: result.issuedKey });
  };

  const applyStatus = async () => {
    if (flow.kind !== "status" || !keyValue) return;
    if (await access.executeWorkspace({ kind: "set-key-status", id: keyValue.id, status: flow.status, resourceVersion: keyValue.resourceVersion, requestId: flow.requestId })) onClose();
  };

  const remove = async () => {
    if (flow.kind !== "delete" || !keyValue || !deleteConfirmed) return;
    if (await access.executeWorkspace({ kind: "delete-key", id: keyValue.id, resourceVersion: keyValue.resourceVersion, requestId: flow.requestId })) onClose();
  };

  return <Card>
    <Card.Header className={styles.flowHeader}><div><h2 className={styles.focusHeading} ref={heading} tabIndex={-1}>{title}</h2><Typography.Text tone="muted">{t("keyInlineWorkflow")}</Typography.Text></div><Badge status="neutral">MOCK</Badge></Card.Header>
    <Card.Body className={styles.flowBody}>
      {flow.kind === "create" ? <>
        <dl className={styles.reviewFacts}>
          <div><dt>{t("owner")}</dt><dd><strong>{owner.name}</strong><span>{owner.loginName} · {owner.id}</span></dd></div>
          <div><dt>{t("state")}</dt><dd>{t(owner.enabled ? "enabled" : "disabled")}</dd></div>
          <div><dt>{t("keyUserRevision")}</dt><dd>v{owner.resourceVersion}</dd></div>
          <div><dt>requestId</dt><dd><code>{flow.requestId}</code></dd></div>
        </dl>
        <Alert status="warning">{t("keyCreateWarning")}</Alert>
        <FormField id={scenarioId} label={t("keyScenario")} hint={t("keyScenarioHint")}>
          <Select id={scenarioId} disabled={access.busy} value={flow.scenario} options={[
            { value: "success", label: t("keyScenarioSuccess") },
            { value: "response-lost", label: t("keyScenarioLost") }
          ]} onValueChange={(scenario) => onChange({ ...flow, scenario: scenario as "success" | "response-lost" })} />
        </FormField>
        <div className={styles.actions}><Button disabled={access.busy || !owner.enabled} onClick={() => void create()}>{t("createKey")}</Button><Button disabled={access.busy} onClick={onClose} variant="ghost">{t("cancel")}</Button></div>
      </> : null}

      {flow.kind === "issued" ? <>
        <Alert status="warning">{t("keyWarning")}</Alert>
        <div className={styles.secretGrid}><div><span>{t("keyId")}</span><AccountIdentifier label={t("keyId")} value={flow.key.id} /></div><div><span>{t("keySecret")}</span><AccountIdentifier label={t("keySecret")} value={flow.key.secret} /></div></div>
        <Checkbox checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)}>{t("keyAcknowledge")}</Checkbox>
        <div className={styles.actions}><Button disabled={!acknowledged} onClick={onClose}>{t("done")}</Button></div>
      </> : null}

      {flow.kind === "uncertain" ? <>
        <Alert status="warning">{t("keyCreateUncertain", { id: flow.requestId })}</Alert>
        <dl className={styles.reviewFacts}><div><dt>requestId</dt><dd><code>{flow.requestId}</code></dd></div><div><dt>{t("keyIntentState")}</dt><dd><Badge status="warning">UNKNOWN</Badge></dd></div></dl>
        <p className={styles.note}>{t("keyIntentLocked")}</p>
        <div className={styles.actions}><Button onClick={() => onChange({ ...flow, kind: "recovered" })} variant="secondary">{t("keyQueryOriginal")}</Button></div>
      </> : null}

      {flow.kind === "recovered" ? <>
        <Alert status="warning">{t("keyRecovered", { id: flow.keyId })}</Alert>
        <dl className={styles.reviewFacts}><div><dt>{t("keyId")}</dt><dd><code>{flow.keyId}</code></dd></div><div><dt>{t("keySecret")}</dt><dd>{t("keySecretUnavailable")}</dd></div><div><dt>requestId</dt><dd><code>{flow.requestId}</code></dd></div></dl>
        <p className={styles.note}>{t("keyRecoveredNext")}</p>
        <div className={styles.actions}><Button onClick={() => onOpenKey(flow.keyId)}>{t("keyInspectAndReplace")}</Button></div>
      </> : null}

      {flow.kind === "status" && keyValue ? <>
        <Alert status={flow.status === "DISABLED" ? "warning" : "info"}>{t(flow.status === "DISABLED" ? "keyDisableImpact" : "keyEnableImpact")}</Alert>
        <dl className={styles.reviewFacts}><div><dt>{t("keyId")}</dt><dd><code>{keyValue.id}</code></dd></div><div><dt>{t("state")}</dt><dd>{t(keyValue.status === "ENABLED" ? "enabled" : "disabled")} → {t(flow.status === "ENABLED" ? "enabled" : "disabled")}</dd></div><div><dt>{t("keyRevision")}</dt><dd>v{keyValue.resourceVersion}</dd></div><div><dt>requestId</dt><dd><code>{flow.requestId}</code></dd></div></dl>
        <div className={styles.actions}><Button disabled={access.busy} onClick={() => void applyStatus()}>{t(flow.status === "ENABLED" ? "enable" : "disable")}</Button><Button disabled={access.busy} onClick={onClose} variant="ghost">{t("cancel")}</Button></div>
      </> : null}

      {flow.kind === "delete" && keyValue ? <>
        <Alert status="danger">{t("keyDeleteImpact")}</Alert>
        <dl className={styles.reviewFacts}><div><dt>{t("keyId")}</dt><dd><code>{keyValue.id}</code></dd></div><div><dt>{t("state")}</dt><dd>{t("disabled")}</dd></div><div><dt>{t("keyRevision")}</dt><dd>v{keyValue.resourceVersion}</dd></div></dl>
        <Checkbox checked={deleteConfirmed} onChange={(event) => setDeleteConfirmed(event.target.checked)}>{t("keyDeleteAcknowledge")}</Checkbox>
        <div className={styles.actions}><Button disabled={access.busy || !deleteConfirmed} onClick={() => void remove()} variant="danger">{t("deleteConfirm")}</Button><Button disabled={access.busy} onClick={onClose} variant="ghost">{t("cancel")}</Button></div>
      </> : null}
    </Card.Body>
  </Card>;
}

function RotationGuide() {
  const t = useTranslations("IamWorkspace");
  return <Card>
    <Card.Header><div className={styles.cardHeading}><RotateCw aria-hidden="true" /><div><Typography.Title as="h2" level={3}>{t("keyRotationTitle")}</Typography.Title><Typography.Text tone="muted">{t("keyRotationHint")}</Typography.Text></div></div></Card.Header>
    <Card.Body><ol className={styles.rotationSteps}>{(["create", "migrate", "verify", "retire"] as const).map((step, index) => <li key={step}><span>{index + 1}</span><div><strong>{t(`keyRotation.${step}.title`)}</strong><small>{t(`keyRotation.${step}.hint`)}</small></div></li>)}</ol></Card.Body>
  </Card>;
}

export function AccessCredentials({ workspace, scene, embedded = false }: { workspace: AccessWorkspace; scene: AccountAccessScene; embedded?: boolean }) {
  const t = useTranslations("IamWorkspace");
  const collection = useTranslations("Collection");
  const access = useAccountAccess();
  const initialOwner = embedded && scene.users.length === 1 ? scene.users[0]!.id : null;
  const [ownerId, setOwnerId] = useState<string | null>(initialOwner);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [flow, setFlow] = useState<KeyFlow | null>(null);
  const owner = scene.users.find((user) => user.id === ownerId) ?? null;
  const ownerKeys = owner ? workspace.keys.filter((key) => key.ownerId === owner.id) : [];
  const selected = ownerKeys.find((key) => key.id === selectedId) ?? null;
  const flowKey = flow && (flow.kind === "status" || flow.kind === "delete") ? ownerKeys.find((key) => key.id === flow.keyId) ?? null : null;

  const returnToDirectory = () => { setFlow(null); setSelectedId(null); };
  const openOwner = (id: string) => { setOwnerId(id); setSelectedId(null); setFlow(null); };
  const openKey = (id: string) => { setFlow(null); setSelectedId(id); };
  const startCreate = () => {
    if (!owner) return;
    access.clearWorkspaceError();
    setSelectedId(null);
    setFlow({ kind: "create", ownerId: owner.id, requestId: requestToken("ui-access-key-create-"), scenario: "success" });
  };

  if (!owner) return <section className={styles.root}>
    <ContentPage.Heading title={t("keys")} scrollKey="access-key-user-directory" />
    <Alert status="info"><KeyRound aria-hidden="true" />{t("keyBoundary")}</Alert>
    <Card>
      <Card.Header className={styles.directoryHeader}><div><Typography.Title as="h2" level={3}>{t("keyUserDirectory")}</Typography.Title><Typography.Text tone="muted">{t("keyUserDirectoryHint")}</Typography.Text></div><Badge status="neutral">{t("userCount", { count: scene.users.length })}</Badge></Card.Header>
      <Card.Body className={styles.tableBody}>{scene.users.length ? <Table aria-label={t("keyUserDirectory")} mobileLayout="stack"><thead><tr><th scope="col">{t("owner")}</th><th scope="col">{t("state")}</th><th scope="col">{t("keyLoadingModel")}</th></tr></thead><tbody>{scene.users.map((user) => <tr key={user.id}><td data-label={t("owner")}><span className={styles.identity}><UserRound aria-hidden="true" /><span><strong>{user.name}</strong><small>{user.loginName} · {user.id}</small></span></span></td><td data-label={t("state")}><Badge status={user.enabled ? "success" : "neutral"}>{t(user.enabled ? "enabled" : "disabled")}</Badge></td><td data-label={t("keyLoadingModel")}><Button aria-label={t("keyManageNamed", { name: user.loginName })} onClick={() => openOwner(user.id)} size="small" variant="secondary">{t("keyManage")}</Button></td></tr>)}</tbody></Table> : <p className={styles.note}>{t("keyPrimary")}</p>}</Card.Body>
    </Card>
    <RotationGuide />
  </section>;

  const createDisabled = !owner.enabled || ownerKeys.length >= 2;
  const commands = !flow && !selected ? <ContentPage.Commands label={collection("pageActions")} primary={{ id: "create-key", label: t("createKey"), disabled: createDisabled, disabledReason: !owner.enabled ? t("keyOwnerDisabled") : ownerKeys.length >= 2 ? t("keyQuotaReached") : undefined, onSelect: startCreate }} /> : undefined;

  if (selected && !flow) return <WorkspaceDetail embedded={embedded} title={selected.id} onBack={() => setSelectedId(null)} actions={{
    primary: { id: "status", label: t(selected.status === "ENABLED" ? "disable" : "enable"), variant: "secondary", onSelect: () => setFlow({ kind: "status", keyId: selected.id, status: selected.status === "ENABLED" ? "DISABLED" : "ENABLED", requestId: requestToken("ui-access-key-status-") }) },
    secondary: [{ id: "delete", label: t("delete"), danger: true, disabled: selected.status === "ENABLED", disabledReason: selected.status === "ENABLED" ? t("errors.disableFirst") : undefined, onSelect: () => setFlow({ kind: "delete", keyId: selected.id, requestId: requestToken("ui-access-key-delete-") }) }]
  }}>
    <Card><Card.Body className={styles.detailBody}>
      <dl className={styles.keyFacts}><div><dt>{t("keyId")}</dt><dd><AccountIdentifier label={t("keyId")} value={selected.id} /></dd></div><div><dt>{t("owner")}</dt><dd><strong>{owner.name}</strong><span>{owner.loginName} · {owner.id}</span></dd></div><div><dt>{t("state")}</dt><dd><Badge status={selected.status === "ENABLED" ? "success" : "neutral"}>{t(selected.status === "ENABLED" ? "enabled" : "disabled")}</Badge></dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div><div><dt>{t("keyRevision")}</dt><dd>v{selected.resourceVersion}</dd></div></dl>
      <Alert status="info">{t("keyNoUsageEvidence")}</Alert>
    </Card.Body></Card>
    <RotationGuide />
  </WorkspaceDetail>;

  const body = <div className={styles.ownerBody}>
    <Alert status="info">{t("keyProductBoundary")}</Alert>
    {flow ? <InlineFlow flow={flow} owner={owner} keyValue={flowKey} onChange={setFlow} onClose={returnToDirectory} onOpenKey={openKey} /> : <>
      <Card>
        <Card.Header className={styles.directoryHeader}><div><Typography.Title as="h2" level={3}>{t("keyDirectory")}</Typography.Title><Typography.Text tone="muted">{t("keyDirectoryHint", { name: owner.loginName })}</Typography.Text></div><Badge status={ownerKeys.length >= 2 ? "warning" : "neutral"}>{t("keyQuota", { count: ownerKeys.length })}</Badge></Card.Header>
        <Card.Body className={styles.tableBody}>{ownerKeys.length ? <Table aria-label={t("keys")} mobileLayout="stack"><thead><tr><th scope="col">{t("keyId")}</th><th scope="col">{t("state")}</th><th scope="col">{t("created")}</th><th scope="col">{t("keyRevision")}</th></tr></thead><tbody>{ownerKeys.map((key) => <tr key={key.id}><td data-label={t("keyId")}><button className={styles.keyLink} onClick={() => setSelectedId(key.id)}>{key.id}</button></td><td data-label={t("state")}><Badge status={key.status === "ENABLED" ? "success" : "neutral"}>{t(key.status === "ENABLED" ? "enabled" : "disabled")}</Badge></td><td data-label={t("created")}><WorkspaceTime value={key.createdAt} /></td><td data-label={t("keyRevision")}>v{key.resourceVersion}</td></tr>)}</tbody></Table> : <div className={styles.emptyKeys}><KeyRound aria-hidden="true" /><strong>{t("keyEmpty")}</strong><span>{t("keyEmptyHint")}</span></div>}</Card.Body>
      </Card>
      <RotationGuide />
    </>}
  </div>;

  if (embedded) return <section className={styles.root}><div className={styles.embeddedHeading}><div><h2>{t("keys")}</h2><p>{t("keyOwnerSummary", { name: owner.loginName, id: owner.id })}</p></div>{!flow ? <Button disabled={createDisabled} onClick={startCreate} size="small">{t("createKey")}</Button> : null}</div>{body}</section>;
  return <section className={styles.root}><ContentPage.Heading title={`${owner.loginName} · ${t("keys")}`} scrollKey={`access-keys:${owner.id}`} back={{ label: t("back"), onClick: () => { setOwnerId(null); returnToDirectory(); } }} actions={commands} focus />{body}</section>;
}
