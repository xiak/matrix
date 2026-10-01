"use client";

import { useEffect, useId, useMemo, useRef, useState, type SyntheticEvent } from "react";
import { useTranslations } from "next-intl";
import { KeyRound, RotateCw } from "lucide-react";
import { Alert, Badge, Button, Card, Checkbox, ContentPage, FormField, Select, Table, TablePagination, Typography } from "@ui/xiak";
import { requestToken } from "@/infrastructure/http/jsonRequest";
import { useAccountAccess, type AuthorizationProfileClient } from "../application/AccountAccessProvider";
import { admittedAuthorizationUserAuthenticationMethods, type AuthorizationProfileDirectory } from "../domain/accounts";
import type { AccessKey, AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessScene, AccountUserScene } from "../scenes/accountAccessScene";
import { AccountIdentifier } from "./AccountOverview";
import { AccessKeyOwnerDirectory } from "./AccessKeyOwnerDirectory";
import { WorkspaceDetail, WorkspaceTime } from "./AccessWorkspaceUi";
import { AccessKeyNetworkDetail, AccessKeyNetworkEditor, AccessKeyUsagePreview } from "./AccessKeyNetworkPreview";
import styles from "./AccessCredentials.module.css";

type KeyFlow =
  | { kind: "create"; ownerId: string; requestId: string; scenario: "success" | "response-lost" }
  | { kind: "issued"; ownerId: string; requestId: string; key: { id: string; secret: string } }
  | { kind: "uncertain"; ownerId: string; requestId: string }
  | { kind: "recovered"; ownerId: string; requestId: string; keyId: string }
  | { kind: "status"; keyId: string; requestId: string; status: AccessKey["status"] }
  | { kind: "delete"; keyId: string; requestId: string };

const previewProgrammaticBoundaries = [{
  kind: "create",
  actions: [
    "paas.application.create",
    "paas.configuration.create",
    "paas.configuration-revision.create",
    "paas.application-revision.create",
    "paas.deployment.create"
  ],
  product: "paas",
  profileRevision: 9,
  fixedSource: "b6d15c89",
  outcomes: [
    { http: 202, code: "Operation", meaning: "accepted", nonce: "consumed" },
    { http: 400, code: "INVALID_ARGUMENT", meaning: "invalidArgument", nonce: "notConsumed" },
    { http: 401, code: "UNAUTHENTICATED", meaning: "unauthenticated", nonce: "unknown" },
    { http: 403, code: "PERMISSION_DENIED", meaning: "permissionDenied", nonce: "consumed" },
    { http: 409, code: "CONFLICT", meaning: "conflict", nonce: "consumed" },
    { http: 503, code: "IDENTITY_UNAVAILABLE", meaning: "identityUnavailable", nonce: "unknown" }
  ]
}, {
  kind: "read",
  actions: ["paas.application.read"],
  product: "paas",
  profileRevision: 9,
  fixedSource: "b6d15c89",
  outcomes: [
    { http: 200, code: "Application", meaning: "resourceReturned", nonce: "consumed" },
    { http: 400, code: "INVALID_ARGUMENT", meaning: "readInvalidArgument", nonce: "notConsumed" },
    { http: 401, code: "UNAUTHENTICATED", meaning: "unauthenticated", nonce: "unknown" },
    { http: 403, code: "PERMISSION_DENIED", meaning: "permissionDenied", nonce: "consumed" },
    { http: 404, code: "NOT_FOUND", meaning: "notFound", nonce: "consumed" },
    { http: 409, code: "CONFLICT", meaning: "conflict", nonce: "consumed" },
    { http: 503, code: "IDENTITY_UNAVAILABLE", meaning: "identityUnavailable", nonce: "unknown" }
  ]
}, {
  kind: "auditQuery",
  actions: ["audit.record.read"],
  product: "audit",
  profileRevision: 3,
  fixedSource: "620960989",
  outcomes: [
    { http: 200, code: "AuditRecordPage", meaning: "auditRecordsReturned", nonce: "unknown" },
    { http: 401, code: "audit.authentication.failed", meaning: "auditUnauthenticated", nonce: "unknown" },
    { http: 403, code: "audit.authorization.denied", meaning: "auditPermissionDenied", nonce: "unknown" },
    { http: 409, code: "audit.state.conflict", meaning: "auditConflict", nonce: "unknown" },
    { http: 422, code: "audit.argument.invalid", meaning: "auditArgumentInvalid", nonce: "unknown" },
    { http: 503, code: "audit.unavailable", meaning: "auditUnavailable", nonce: "unknown" }
  ]
}, {
  kind: "auditIntegrity",
  actions: ["audit.integrity.verify"],
  product: "audit",
  profileRevision: 3,
  fixedSource: "620960989",
  outcomes: [
    { http: 200, code: "ChainVerification", meaning: "auditChainVerified", nonce: "unknown" },
    { http: 401, code: "audit.authentication.failed", meaning: "auditUnauthenticated", nonce: "unknown" },
    { http: 403, code: "audit.authorization.denied", meaning: "auditPermissionDenied", nonce: "unknown" },
    { http: 409, code: "audit.state.conflict", meaning: "auditConflict", nonce: "unknown" },
    { http: 422, code: "audit.argument.invalid", meaning: "auditArgumentInvalid", nonce: "unknown" },
    { http: 503, code: "audit.unavailable", meaning: "auditUnavailable", nonce: "unknown" }
  ]
}] as const;

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
  const inspectionId = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [deleteConfirmed, setDeleteConfirmed] = useState(false);
  const [inspectionMode, setInspectionMode] = useState<"found" | "not-found" | "unavailable">("found");
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
      ownerState: owner.state,
      userResourceVersion: owner.resourceVersion,
      requestId: flow.requestId,
      responseMode: flow.scenario
    });
    if (!result) return;
    if (flow.scenario === "response-lost") { onClose(); return; }
    if (result.issuedKey) onChange({ kind: "issued", ownerId: owner.id, requestId: flow.requestId, key: result.issuedKey });
  };

  const applyStatus = async () => {
    if (flow.kind !== "status" || !keyValue) return;
    if (await access.executeWorkspace({ kind: "set-key-status", id: keyValue.id, ownerState: owner.state, status: flow.status, resourceVersion: keyValue.resourceVersion, requestId: flow.requestId })) onClose();
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
        {owner.state !== "active" ? <Alert status="warning">{t(owner.state === "passwordChangeRequired" ? "keyOwnerPasswordChangeRequired" : "keyOwnerDisabled")}</Alert> : null}
        <div className={styles.actions}><Button disabled={access.busy || owner.state !== "active"} onClick={() => void create()}>{t("createKey")}</Button><Button disabled={access.busy} onClick={onClose} variant="ghost">{t("cancel")}</Button></div>
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
        <FormField id={inspectionId} label={t("keyInspectionScenario")} hint={t("keyInspectionScenarioHint")}>
          <Select id={inspectionId} disabled={access.busy} value={inspectionMode} options={[
            { value: "found", label: t("keyInspectionFound") },
            { value: "not-found", label: t("keyInspectionNotFound") },
            { value: "unavailable", label: t("keyInspectionUnavailable") }
          ]} onValueChange={(mode) => { access.clearWorkspaceError(); setInspectionMode(mode as "found" | "not-found" | "unavailable"); }} />
        </FormField>
        <div className={styles.actions}><Button disabled={access.busy} onClick={() => void access.executeWorkspace({ kind: "inspect-key-creation", ownerId: flow.ownerId, requestId: flow.requestId, resultMode: inspectionMode })} variant="secondary">{t("keyQueryOriginal")}</Button></div>
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
        {flow.status === "ENABLED" && owner.state !== "active" ? <Alert status="warning">{t(owner.state === "passwordChangeRequired" ? "keyOwnerPasswordChangeRequired" : "keyOwnerDisabled")}</Alert> : null}
        <div className={styles.actions}><Button disabled={access.busy || (flow.status === "ENABLED" && owner.state !== "active")} onClick={() => void applyStatus()}>{t(flow.status === "ENABLED" ? "enable" : "disable")}</Button><Button disabled={access.busy} onClick={onClose} variant="ghost">{t("cancel")}</Button></div>
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

export function RotationGuide() {
  const t = useTranslations("IamWorkspace");
  return <Card>
    <Card.Header><div className={styles.cardHeading}><RotateCw aria-hidden="true" /><div><Typography.Title as="h2" level={3}>{t("keyRotationTitle")}</Typography.Title><Typography.Text tone="muted">{t("keyRotationHint")}</Typography.Text></div></div></Card.Header>
    <Card.Body><ol className={styles.rotationSteps}>{(["create", "migrate", "verify", "retire"] as const).map((step, index) => <li key={step}><span>{index + 1}</span><div><strong>{t(`keyRotation.${step}.title`)}</strong><small>{t(`keyRotation.${step}.hint`)}</small></div></li>)}</ol></Card.Body>
  </Card>;
}

function ProgrammaticRequestBoundaryPreview({ actions }: { actions: readonly string[] }) {
  const t = useTranslations("IamWorkspace");
  const operationId = useId();
  const [selectedBoundary, setSelectedBoundary] = useState("");
  const boundaries = previewProgrammaticBoundaries.map((entry) => ({
    ...entry,
    actions: entry.actions.filter((action) => actions.includes(action)),
    key: `${entry.product}:${entry.profileRevision}:${entry.kind}`
  })).filter((entry) => entry.actions.length > 0);
  if (!boundaries.length) return null;
  const entry = boundaries.find((candidate) => candidate.key === selectedBoundary) ?? boundaries[0]!;
  return <details className={styles.requestPreview}>
    <summary><span><strong>{t("keyRequestPreviewTitle")}</strong><small>{t("keyRequestPreviewHint")}</small></span><Badge status="warning">MOCK</Badge></summary>
    <div className={styles.requestPreviewBody}>
      <Alert status="warning">{t("keyRequestPreviewNotLive")}</Alert>
      <div className={styles.requestBoundaryPicker}>
        <FormField id={operationId} label={t("keyRequestPreviewOperation")} hint={t("keyRequestPreviewOperationHint")}>
          <Select id={operationId} value={entry.key} options={boundaries.map((candidate) => ({
            value: candidate.key,
            label: t(`keyRequestPreviewKinds.${candidate.kind}.scope`, { count: candidate.actions.length })
          }))} onValueChange={setSelectedBoundary} />
        </FormField>
      </div>
      <section className={styles.requestBoundary} key={entry.key}>
        <header><div><strong>{t(`keyRequestPreviewKinds.${entry.kind}.scope`, { count: entry.actions.length })}</strong><small>{t("keyRequestPreviewSource", { source: entry.fixedSource })}</small></div><Badge status="neutral">{entry.product} · r{entry.profileRevision}</Badge></header>
        <div className={styles.requestActions}>{entry.actions.map((action) => <code key={action}>{action}</code>)}</div>
        <Table aria-label={t("keyRequestPreviewTable")} className={styles.requestOutcomeTable} mobileLayout="stack">
          <thead><tr><th scope="col">HTTP</th><th scope="col">{t("keyRequestPreviewCode")}</th><th scope="col">{t("keyRequestPreviewMeaning")}</th><th scope="col">Nonce</th></tr></thead>
          <tbody>{entry.outcomes.map((outcome) => <tr key={`${entry.product}:${entry.profileRevision}:${outcome.http}`}>
            <td data-label="HTTP"><code>{outcome.http}</code></td>
            <td data-label={t("keyRequestPreviewCode")}><code>{outcome.code}</code></td>
            <td data-label={t("keyRequestPreviewMeaning")}>{t(`keyRequestPreviewOutcomes.${outcome.meaning}`)}</td>
            <td data-label="Nonce">{t(`keyRequestPreviewNonce.${outcome.nonce}`)}</td>
          </tr>)}</tbody>
        </Table>
        <p className={styles.note}>{t(`keyRequestPreviewKinds.${entry.kind}.successBoundary`)}</p>
      </section>
    </div>
  </details>;
}

export function ProgrammaticAccessGuide({ owner, client, onInspectPermissions }: {
  owner: AccountUserScene;
  client: AuthorizationProfileClient | null;
  onInspectPermissions?(ownerId: string): void;
}) {
  const t = useTranslations("IamWorkspace");
  const [loading, setLoading] = useState(false);
  const [directory, setDirectory] = useState<AuthorizationProfileDirectory | null>(null);
  const [status, setStatus] = useState<"idle" | "ready" | "forbidden" | "routeUnavailable" | "unavailable" | "expired">("idle");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const accepted = useMemo(() => directory?.items.flatMap((entry) => entry.profile.actions
    .filter((action) => admittedAuthorizationUserAuthenticationMethods(action).includes("ACCESS_KEY"))
    .map((action) => ({ product: entry.profile.product, revision: entry.profile.revision, action: action.action }))) ?? [], [directory]);
  const pages = Math.max(1, Math.ceil(accepted.length / pageSize));
  const currentPage = Math.min(page, pages);
  const visible = accepted.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const load = async () => {
    if (!client || loading) {
      if (!client) setStatus("routeUnavailable");
      return;
    }
    setLoading(true);
    const result = await client.load();
    if (result.status === "ready") {
      setDirectory(result.directory);
      setStatus("ready");
    } else {
      setDirectory(null);
      setStatus(result.status);
    }
    setLoading(false);
  };
  const onToggle = (event: SyntheticEvent<HTMLDetailsElement>) => {
    if (event.currentTarget.open && status === "idle") void load();
  };

  return <details className={styles.programmaticGuide} onToggle={onToggle}>
    <summary>
      <span className={styles.programmaticHeading}><KeyRound aria-hidden="true" /><span><strong>{t("keyProgrammaticTitle")}</strong><small>{t("keyProgrammaticHint", { name: owner.loginName })}</small></span></span>
      <span className={styles.programmaticSummary}>{t("keyProgrammaticInspect")}</span>
    </summary>
    <div className={styles.programmaticBody} aria-busy={loading || undefined}>
      <Alert status="info">{t("keyProgrammaticIdentity", { name: owner.loginName })}</Alert>
      {loading ? <p className={styles.note}>{t("keyProgrammaticLoading")}</p> : null}
      {status === "ready" && accepted.length === 0 ? <Alert status="warning">{t("keyProgrammaticNone")}</Alert> : null}
      {status === "ready" && accepted.length > 0 ? <>
        <Alert status="warning">{t("keyProgrammaticNotGrant")}</Alert>
        <Table aria-label={t("keyProgrammaticTitle")} mobileLayout="stack" className={styles.programmaticTable}>
          <thead><tr><th scope="col">{t("keyProgrammaticProduct")}</th><th scope="col">Action</th></tr></thead>
          <tbody>{visible.map((entry) => <tr key={`${entry.product}:${entry.revision}:${entry.action}`}>
            <td data-label={t("keyProgrammaticProduct")}><strong>{entry.product}</strong><small>{t("keyProgrammaticRevision", { revision: entry.revision })}</small></td>
            <td data-label="Action"><code>{entry.action}</code></td>
          </tr>)}</tbody>
        </Table>
        <Table.Footer note={t("keyProgrammaticCount", { count: accepted.length })}><TablePagination page={currentPage} pages={pages} pageSize={pageSize}
          onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }}
          labels={{ summary: t("page", { page: currentPage, pages }), pageSize: t("pageSize"), previous: t("previous"), next: t("next") }} /></Table.Footer>
        {onInspectPermissions ? <div className={styles.programmaticActions}>
          <Button onClick={() => onInspectPermissions(owner.id)} size="small" variant="secondary">{t("keyProgrammaticInspectPermissions")}</Button>
          <Typography.Text tone="muted">{t("keyProgrammaticInspectPermissionsHint")}</Typography.Text>
        </div> : null}
        {client?.preview ? <ProgrammaticRequestBoundaryPreview actions={accepted.map((entry) => entry.action)} /> : null}
      </> : null}
      {status !== "idle" && status !== "ready" && !loading ? <Alert status="warning">{t(`keyProgrammaticStatus.${status}`)}</Alert> : null}
      {status !== "idle" && status !== "ready" && status !== "expired" && !loading ? <div className={styles.actions}><Button onClick={() => void load()} size="small" variant="secondary">{t("keyProgrammaticRetry")}</Button></div> : null}
      <p className={styles.note}>{t("keyProgrammaticSecretBoundary")}</p>
    </div>
  </details>;
}

export function AccessCredentials({ workspace, scene, embedded = false, onInspectPermissions }: {
  workspace: AccessWorkspace;
  scene: AccountAccessScene;
  embedded?: boolean;
  onInspectPermissions?(ownerId: string): void;
}) {
  const t = useTranslations("IamWorkspace");
  const network = useTranslations("AccessKeyNetworkPreview");
  const collection = useTranslations("Collection");
  const access = useAccountAccess();
  const initialOwner = embedded && scene.users.length === 1 ? scene.users[0]!.id : null;
  const [ownerId, setOwnerId] = useState<string | null>(initialOwner);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [flow, setFlow] = useState<KeyFlow | null>(null);
  const [editingNetwork, setEditingNetwork] = useState(false);
  const pending = workspace.pendingKeyCreation;
  const owner = scene.users.find((user) => user.id === (pending?.ownerId ?? ownerId)) ?? null;
  const ownerKeys = owner ? workspace.keys.filter((key) => key.ownerId === owner.id) : [];
  const selected = ownerKeys.find((key) => key.id === selectedId) ?? null;
  const pendingFlow: KeyFlow | null = !selected && pending ? pending.status === "UNKNOWN"
    ? { kind: "uncertain", ownerId: pending.ownerId, requestId: pending.requestId }
    : { kind: "recovered", ownerId: pending.ownerId, requestId: pending.requestId, keyId: pending.keyId }
    : null;
  const activeFlow = flow ?? pendingFlow;
  const flowKey = activeFlow && (activeFlow.kind === "status" || activeFlow.kind === "delete") ? ownerKeys.find((key) => key.id === activeFlow.keyId) ?? null : null;

  const closeFlow = () => {
    if (!flow || flow.kind !== "status") setSelectedId(null);
    setFlow(null);
  };
  const returnToDirectory = () => { setFlow(null); setSelectedId(null); setEditingNetwork(false); };
  const openOwner = (id: string) => { if (pending) return; setOwnerId(id); setSelectedId(null); setFlow(null); setEditingNetwork(false); };
  const openKey = (id: string) => { setFlow(null); setSelectedId(id); setEditingNetwork(false); };
  const startCreate = () => {
    if (!owner || pending || owner.state !== "active") return;
    access.clearWorkspaceError();
    setSelectedId(null);
    setFlow({ kind: "create", ownerId: owner.id, requestId: requestToken("ui-access-key-create-"), scenario: "success" });
  };

  if (!owner) return <section className={styles.root}>
    <ContentPage.Heading title={t("keys")} scrollKey="access-key-user-directory" />
    <Alert status="info"><KeyRound aria-hidden="true" />{t("keyBoundary")}</Alert>
    <AccessKeyOwnerDirectory scene={scene} busy={access.busy} loading={access.loading} onOpen={openOwner} onReadPage={access.usersPage} />
    <RotationGuide />
  </section>;

  const createDisabled = owner.state !== "active" || ownerKeys.length >= 2 || Boolean(pending);
  const ownerDisabledReason = owner.state === "passwordChangeRequired" ? t("keyOwnerPasswordChangeRequired") : owner.state === "disabled" ? t("keyOwnerDisabled") : undefined;
  const commands = !activeFlow && !selected ? <ContentPage.Commands label={collection("pageActions")} primary={{ id: "create-key", label: t("createKey"), disabled: createDisabled, disabledReason: pending ? t("keyIntentLocked") : ownerDisabledReason ?? (ownerKeys.length >= 2 ? t("keyQuotaReached") : undefined), onSelect: startCreate }} /> : undefined;

  if (selected && editingNetwork && !activeFlow) return <WorkspaceDetail embedded={embedded} title={selected.id} onBack={() => setEditingNetwork(false)}>
    <AccessKeyNetworkEditor keyValue={selected} onClose={() => setEditingNetwork(false)} />
  </WorkspaceDetail>;

  if (selected && !activeFlow) return <WorkspaceDetail embedded={embedded} title={selected.id} onBack={() => setSelectedId(null)} actions={{
    primary: { id: "status", label: t(selected.status === "ENABLED" ? "disable" : "enable"), variant: "secondary", disabled: selected.status === "DISABLED" && owner.state !== "active", disabledReason: selected.status === "DISABLED" ? ownerDisabledReason : undefined, onSelect: () => setFlow({ kind: "status", keyId: selected.id, status: selected.status === "ENABLED" ? "DISABLED" : "ENABLED", requestId: requestToken("ui-access-key-status-") }) },
    secondary: [{ id: "network", label: network("configureKey"), onSelect: () => setEditingNetwork(true) }, { id: "delete", label: t("delete"), danger: true, disabled: selected.status === "ENABLED", disabledReason: selected.status === "ENABLED" ? t("errors.disableFirst") : undefined, onSelect: () => setFlow({ kind: "delete", keyId: selected.id, requestId: requestToken("ui-access-key-delete-") }) }]
  }}>
    <Card><Card.Body className={styles.detailBody}>
      <dl className={styles.keyFacts}><div><dt>{t("keyId")}</dt><dd><AccountIdentifier label={t("keyId")} value={selected.id} /></dd></div><div><dt>{t("owner")}</dt><dd><strong>{owner.name}</strong><span>{owner.loginName} · {owner.id}</span></dd></div><div><dt>{t("state")}</dt><dd><Badge status={selected.status === "ENABLED" ? "success" : "neutral"}>{t(selected.status === "ENABLED" ? "enabled" : "disabled")}</Badge></dd></div><div><dt>{t("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div><div><dt>{t("keyRevision")}</dt><dd>v{selected.resourceVersion}</dd></div></dl>
    </Card.Body></Card>
    <AccessKeyNetworkDetail account={workspace.settings.accessKeyNetwork} keyValue={selected} />
    <AccessKeyUsagePreview usage={selected.usage} />
    <ProgrammaticAccessGuide client={access.authorizationProfiles} owner={owner} onInspectPermissions={onInspectPermissions} />
    <RotationGuide />
  </WorkspaceDetail>;

  const body = <div className={styles.ownerBody}>
    <Alert status="info">{t("keyProductBoundary")}</Alert>
    {ownerDisabledReason && !activeFlow ? <Alert status="warning">{ownerDisabledReason}</Alert> : null}
    {activeFlow ? <InlineFlow flow={activeFlow} owner={owner} keyValue={flowKey} onChange={setFlow} onClose={closeFlow} onOpenKey={openKey} /> : <>
      <Card>
        <Card.Header className={styles.directoryHeader}><div><Typography.Title as="h2" level={3}>{t("keyDirectory")}</Typography.Title><Typography.Text tone="muted">{t("keyDirectoryHint", { name: owner.loginName })}</Typography.Text></div><Badge status={ownerKeys.length >= 2 ? "warning" : "neutral"}>{t("keyQuota", { count: ownerKeys.length })}</Badge></Card.Header>
        <Card.Body className={styles.tableBody}>{ownerKeys.length ? <Table aria-label={t("keys")} mobileLayout="stack"><thead><tr><th scope="col">{t("keyId")}</th><th scope="col">{t("state")}</th><th scope="col">{t("created")}</th><th scope="col">{t("keyRevision")}</th></tr></thead><tbody>{ownerKeys.map((key) => <tr key={key.id}><td data-label={t("keyId")}><button className={styles.keyLink} onClick={() => setSelectedId(key.id)}>{key.id}</button></td><td data-label={t("state")}><Badge status={key.status === "ENABLED" ? "success" : "neutral"}>{t(key.status === "ENABLED" ? "enabled" : "disabled")}</Badge></td><td data-label={t("created")}><WorkspaceTime value={key.createdAt} /></td><td data-label={t("keyRevision")}>v{key.resourceVersion}</td></tr>)}</tbody></Table> : <div className={styles.emptyKeys}><KeyRound aria-hidden="true" /><strong>{t("keyEmpty")}</strong><span>{t("keyEmptyHint")}</span></div>}</Card.Body>
      </Card>
      <ProgrammaticAccessGuide client={access.authorizationProfiles} owner={owner} onInspectPermissions={onInspectPermissions} />
      <RotationGuide />
    </>}
  </div>;

  if (embedded) return <section className={styles.root}><div className={styles.embeddedHeading}><div><h2>{t("keys")}</h2><p>{t("keyOwnerSummary", { name: owner.loginName, id: owner.id })}</p></div>{!activeFlow ? <Button disabled={createDisabled} onClick={startCreate} size="small">{t("createKey")}</Button> : null}</div>{body}</section>;
  return <section className={styles.root}><ContentPage.Heading title={`${owner.loginName} · ${t("keys")}`} scrollKey={`access-keys:${owner.id}`} back={pending ? undefined : { label: t("back"), onClick: () => { setOwnerId(null); returnToDirectory(); } }} actions={commands} focus />{body}</section>;
}
