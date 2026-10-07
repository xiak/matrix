"use client";

import { useId, useLayoutEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from "react";
import { ArrowLeft, Boxes, KeyRound, ShieldCheck, Unlink } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, ContentPage, EmptyState, Select, Steps, Table, TablePagination, TableToolbar, Tabs } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountPolicyDocument } from "../domain/accounts";
import type { RoleCapability, RoleSessionFilterLifecycle, RoleSessionLifecycle } from "../domain/roles";
import type { ServicePrincipalReference } from "../domain/serviceAuthorization";
import {
  previewManagedServiceRoleTemplate,
  previewManagedServiceWorkload
} from "../repositories/previewServiceAuthorizationContract";
import { WorkspaceTime } from "./AccessWorkspaceUi";
import { ServiceAuthorizationChain } from "./ServiceAuthorizationChain";
import { ServiceAuthorizationResponsibility } from "./AuthorizationOwnershipFlow";
import styles from "./ServiceAuthorizationPreview.module.css";

type PreviewView = "directory" | "detail" | "review" | "account-access";
type DirectorySection = "authorizations" | "templates";

// Compact renderer projection of the shared release-shaped MOCK contract. It
// never adds a concrete account, service principal or workload to the template.
const previewTemplate = {
  id: previewManagedServiceRoleTemplate.id,
  product: previewManagedServiceRoleTemplate.spec.product,
  version: previewManagedServiceRoleTemplate.version,
  contentDigest: previewManagedServiceRoleTemplate.contentDigest,
  servicePurpose: previewManagedServiceRoleTemplate.spec.servicePurpose,
  roleName: previewManagedServiceRoleTemplate.spec.roleName,
  revision: previewManagedServiceRoleTemplate.version,
  policyId: previewManagedServiceRoleTemplate.spec.policyVersion.policyId,
  policyVersionId: previewManagedServiceRoleTemplate.spec.policyVersion.versionId,
  policyContentDigest: previewManagedServiceRoleTemplate.spec.policyVersion.contentDigest,
  maxSessionDurationSeconds: previewManagedServiceRoleTemplate.spec.maxSessionDurationSeconds,
  workload: previewManagedServiceWorkload,
  snapshotName: previewManagedServiceRoleTemplate.spec.roleName
} as const;

const previewWorkload = {
  kind: "SERVICE_INSTALLATION",
  id: "service-installation-example"
} as const;

const previewAccountAccess = {
  roleId: "preview.service-linked-role.managed-service-installation-read",
  roleStatus: "ACTIVE",
  roleManagement: "SERVICE_LINKED",
  roleResourceVersion: 3,
  principalInstallationId: "preview.service-installation.paas",
  principalId: "preview.paas.service",
  bindingId: "preview.workload-role-binding.service-installation-example",
  bindingStatus: "ACTIVE",
  bindingCount: 1,
  activeBindingCount: 1,
  bindingResourceVersion: 2,
  createdAt: "2026-09-29T08:30:00Z",
  updatedAt: "2026-09-29T08:35:00Z",
} as const;

type PreviewServiceRoleSessionSource = ServicePrincipalReference & { type: "SERVICE_ACCOUNT" };

type PreviewServiceRoleSession = {
  id: string;
  accountId: string;
  source: PreviewServiceRoleSessionSource;
  roleId: string;
  roleName: string;
  lifecycle: RoleSessionLifecycle;
  revokeCapability: RoleCapability;
  issuedAt: string;
  expiresAt: string;
  revokedAt: string | null;
};

function previewServiceSessions(accountId: string): readonly PreviewServiceRoleSession[] {
  return [{
    id: "preview.service-role-session.current",
    accountId,
    source: { type: "SERVICE_ACCOUNT", principalId: "preview.paas.service", installationId: "preview.service-installation.paas", purpose: "PAAS" },
    roleId: previewAccountAccess.roleId,
    roleName: previewTemplate.roleName,
    lifecycle: "UNREVOKED",
    revokeCapability: { action: "iam.role-session.revoke", resource: { kind: "ROLE_SESSION", id: "preview.service-role-session.current" }, available: true, restrictionReason: null },
    issuedAt: "2026-10-01T01:20:00Z",
    expiresAt: "2026-10-01T01:21:00Z",
    revokedAt: null
  },
  {
    id: "preview.service-role-session.expired",
    accountId,
    source: { type: "SERVICE_ACCOUNT", principalId: "preview.paas.service", installationId: "preview.service-installation.paas", purpose: "PAAS" },
    roleId: previewAccountAccess.roleId,
    roleName: previewTemplate.roleName,
    lifecycle: "EXPIRED",
    revokeCapability: { action: "iam.role-session.revoke", resource: { kind: "ROLE_SESSION", id: "preview.service-role-session.expired" }, available: false, restrictionReason: "SESSION_NOT_REVOCABLE" },
    issuedAt: "2026-09-30T23:45:00Z",
    expiresAt: "2026-09-30T23:46:00Z",
    revokedAt: null
  },
  {
    id: "preview.service-role-session.revoked",
    accountId,
    source: { type: "SERVICE_ACCOUNT", principalId: "preview.paas.service", installationId: "preview.service-installation.paas", purpose: "PAAS" },
    roleId: previewAccountAccess.roleId,
    roleName: previewTemplate.roleName,
    lifecycle: "REVOKED",
    revokeCapability: { action: "iam.role-session.revoke", resource: { kind: "ROLE_SESSION", id: "preview.service-role-session.revoked" }, available: false, restrictionReason: "SESSION_NOT_REVOCABLE" },
    issuedAt: "2026-09-30T21:00:00Z",
    expiresAt: "2026-09-30T21:01:00Z",
    revokedAt: "2026-09-30T21:00:15Z"
  }];
}

const stageIds = ["identity", "permissions", "consent"] as const;
const runtimeStageIds = ["authenticate", "issue", "enforce", "execute"] as const;
const authorizationValidityStageIds = ["template", "account", "binding", "runtime"] as const;
type PreviewOperationKind = "bind" | "unbind";
type PreviewOperationScenario = "success" | "unknown" | "stateChanged" | "requestMismatch" | "unauthenticated" | "forbidden" | "invalidRequest";
type PreviewOperationResult = Exclude<PreviewOperationScenario, "success">;

// The template policy is an account-scoped permission ceiling. The exact
// workload is narrowed by a separate WorkloadRoleBinding and the product PEP;
// putting the sample workload ID in this document would merge those boundaries.
function previewPermissionCeiling(): AccountPolicyDocument {
  return {
    languageVersion: "1", scope: "TENANT", statements: [
      { sid: "read-service-installation", effect: "ALLOW", actions: ["managedservice.service-installation.read"],
        resources: [{ kind: "SERVICE_INSTALLATION", match: "ANY_IN_AUTHORITY" }] }
    ]
  };
}

function TemplateDirectory({ triggerRef, onOpen }: {
  triggerRef: RefObject<HTMLButtonElement | null>;
  onOpen(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  return <div className={styles.stack}>
    <div className={styles.sectionHeading}><div><h3>{t("directory.title")}</h3><p>{t("directory.hint")}</p></div><Badge status="warning">{t("states.contractSample")}</Badge></div>
    <Table aria-label={t("directory.tableLabel")} mobileLayout="stack">
      <thead><tr><th scope="col">{t("fields.product")}</th><th scope="col">{t("fields.servicePurpose")}</th><th scope="col">{t("fields.permissionCeiling")}</th><th scope="col">{t("fields.supportedWorkload")}</th><th scope="col">{t("fields.templateState")}</th></tr></thead>
      <tbody><tr>
        <td data-label={t("fields.product")}><Table.PrimaryAction ref={triggerRef} onClick={onOpen}>{t("template.name")}</Table.PrimaryAction><small><code>{previewTemplate.id}</code></small></td>
        <td data-label={t("fields.servicePurpose")}><code>{previewTemplate.servicePurpose}</code><small>{t("template.purpose")}</small></td>
        <td data-label={t("fields.permissionCeiling")}><code>{previewTemplate.policyId}</code><small>{previewTemplate.policyVersionId}</small></td>
        <td data-label={t("fields.supportedWorkload")}><code>{previewTemplate.workload.resourceKind}</code><small>{previewTemplate.workload.bindAction}</small></td>
        <td data-label={t("fields.templateState")}><Badge status="warning">{t("states.contractSample")}</Badge></td>
      </tr></tbody>
    </Table>
    <p className={styles.note}>{t("directory.separation")}</p>
  </div>;
}

function AccountAuthorizationDirectory({ accountId, triggerRef, onOpen }: {
  accountId: string;
  triggerRef: RefObject<HTMLButtonElement | null>;
  onOpen(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  return <div className={styles.stack}>
    <div className={styles.sectionHeading}>
      <div><h3>{t("accountDirectory.title")}</h3><p>{t("accountDirectory.hint")}</p></div>
      <div className={styles.stateBadges}><Badge status="success">{t("states.authorized")}</Badge><Badge status="warning">MOCK</Badge></div>
    </div>
    <Alert status="info">{t("accountDirectory.boundary")}</Alert>
    <Table aria-label={t("accountDirectory.tableLabel")} mobileLayout="stack">
      <thead><tr><th scope="col">{t("accountDirectory.columns.authorization")}</th><th scope="col">{t("accountDirectory.columns.role")}</th><th scope="col">{t("accountDirectory.columns.resource")}</th><th scope="col">{t("accountDirectory.columns.state")}</th></tr></thead>
      <tbody><tr>
        <td data-label={t("accountDirectory.columns.authorization")}><Table.PrimaryAction aria-label={t("accountDirectory.open", { name: t("template.name") })} ref={triggerRef} onClick={onOpen}>{t("template.name")}</Table.PrimaryAction><small>{t("template.purpose")}</small><small><code>{previewTemplate.product} · {previewTemplate.servicePurpose}</code></small></td>
        <td data-label={t("accountDirectory.columns.role")}><code>{previewTemplate.roleName}</code><small>{t("fields.targetAccount")} · <code>{accountId}</code></small></td>
        <td data-label={t("accountDirectory.columns.resource")}><strong>{t("accountDirectory.bindingCount", { active: previewAccountAccess.activeBindingCount, total: previewAccountAccess.bindingCount })}</strong><small><code>{previewWorkload.kind}: {previewWorkload.id}</code></small></td>
        <td data-label={t("accountDirectory.columns.state")}><Badge status="success">{previewAccountAccess.roleStatus}</Badge><small><WorkspaceTime value={previewAccountAccess.updatedAt} /></small></td>
      </tr></tbody>
    </Table>
    <p className={styles.note}>{t("accountDirectory.readOnly")}</p>
  </div>;
}

function TemplateDetail({ reviewRef, observationRef, onReview, onObserve }: {
  reviewRef: RefObject<HTMLButtonElement | null>;
  observationRef: RefObject<HTMLButtonElement | null>;
  onReview(): void;
  onObserve(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  const previewSnapshot = previewPermissionCeiling();
  return <div className={styles.stack}>
    <div className={styles.sectionHeading}><div><span>{t("detail.eyebrow")}</span><h3>{t("template.name")}</h3><p>{t("detail.hint")}</p></div><div className={styles.stateBadges}><Badge status="warning">{t("states.contractSample")}</Badge><Badge status="neutral">{t("states.notAuthorized")}</Badge></div></div>
    <dl className={styles.facts}>
      <div><dt>{t("fields.product")}</dt><dd><code>{previewTemplate.product}</code></dd></div>
      <div><dt>{t("fields.templateId")}</dt><dd><code>{previewTemplate.id}</code></dd></div>
      <div><dt>{t("fields.templateRevision")}</dt><dd>v{previewTemplate.revision}</dd></div>
      <div><dt>{t("fields.servicePurpose")}</dt><dd><code>{previewTemplate.servicePurpose}</code></dd></div>
      <div><dt>{t("fields.roleName")}</dt><dd><code>{previewTemplate.roleName}</code></dd></div>
      <div><dt>{t("fields.roleDescription")}</dt><dd>{t("template.roleDescription")}</dd></div>
      <div><dt>{t("fields.maxSession")}</dt><dd>{t("observation.durationMinutes", { count: previewTemplate.maxSessionDurationSeconds / 60 })}</dd></div>
      <div><dt>{t("fields.supportedWorkload")}</dt><dd><code>{previewTemplate.workload.resourceKind}</code></dd></div>
      <div><dt>{t("fields.bindAction")}</dt><dd><code>{previewTemplate.workload.bindAction}</code></dd></div>
      <div><dt>{t("fields.unbindAction")}</dt><dd><code>{previewTemplate.workload.unbindAction}</code></dd></div>
    </dl>
    <ServiceAuthorizationChain
      template={{ label: t("states.contractSample"), tone: "warning" }}
      account={{ label: t("states.notAuthorized") }}
      binding={{ label: t("states.notConfigured") }}
      runtime={{ label: t("observation.validity.runtimeState") }}
    />
    <div className={styles.detailGrid}>
      <Card><Card.Header className={styles.cardHeading}><KeyRound aria-hidden="true" /><div><span>{t("detail.trustLabel")}</span><h4>{t("detail.trustTitle")}</h4></div></Card.Header><Card.Body className={styles.cardBody}><p>{t("detail.trustHint")}</p><code>{previewTemplate.product} · {previewTemplate.servicePurpose}</code></Card.Body></Card>
      <Card><Card.Header className={styles.cardHeading}><ShieldCheck aria-hidden="true" /><div><span>{t("detail.permissionLabel")}</span><h4>{previewTemplate.snapshotName} · v{previewTemplate.revision}</h4></div></Card.Header><Card.Body className={styles.cardBody}><p>{t("detail.permissionHint")}</p><Alert status="info">{t("detail.snapshotBoundary")}</Alert></Card.Body></Card>
    </div>
    <div className={styles.snapshot}><div><strong>{t("detail.snapshotTitle")}</strong><span>{t("detail.snapshotCount", { count: previewSnapshot.statements.length })}</span></div><ul>{previewSnapshot.statements.flatMap((statement) => statement.actions).map((action) => <li key={action}><code>{action}</code></li>)}</ul></div>
    <Alert status="info">{t("detail.modelBoundary")}</Alert>
    <div className={styles.actions}><Button ref={reviewRef} onClick={onReview}>{t("detail.review")}</Button><Button ref={observationRef} variant="secondary" onClick={onObserve}>{t("detail.observeAuthorized")}</Button></div>
  </div>;
}

function ServiceRoleRuntimeTrace() {
  const t = useTranslations("ServiceAuthorizationPreview");
  const titleId = useId();

  return <section aria-labelledby={titleId} className={styles.runtimeTrace}>
    <div className={styles.runtimeTraceHeading}>
      <div><h4 id={titleId}>{t("observation.runtime.title")}</h4><p>{t("observation.runtime.hint")}</p></div>
      <Badge status="warning">MOCK</Badge>
    </div>
    <ol className={styles.runtimeStages}>
      {runtimeStageIds.map((stage, index) => <li key={stage}>
        <span className={styles.runtimeIndex} aria-hidden="true">{index + 1}</span>
        <div><strong>{t(`observation.runtime.stages.${stage}.title`)}</strong><small>{t(`observation.runtime.stages.${stage}.hint`)}</small></div>
        <Badge status="neutral">{t(`observation.runtime.stages.${stage}.state`)}</Badge>
      </li>)}
    </ol>
    <Alert status="warning">{t("observation.runtime.boundary")}</Alert>
  </section>;
}

function ServiceRoleSessionDirectoryPreview({ accountId }: { accountId: string }) {
  const t = useTranslations("ServiceAuthorizationPreview");
  const toolbarLabels = useTableToolbarLabels();
  const sessions = useMemo(() => previewServiceSessions(accountId), [accountId]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [reviewing, setReviewing] = useState(false);
  const [query, setQuery] = useState("");
  const [lifecycle, setLifecycle] = useState<RoleSessionFilterLifecycle>("ALL");
  const detailHeading = useRef<HTMLHeadingElement>(null);
  const reviewHeading = useRef<HTMLHeadingElement>(null);
  const returnToSession = useRef<string | null>(null);
  const sessionTriggers = useRef(new Map<string, HTMLButtonElement>());
  const selected = sessions.find((session) => session.id === selectedId) ?? null;
  const visibleSessions = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return sessions.filter((session) => {
      if (lifecycle !== "ALL" && session.lifecycle !== lifecycle) return false;
      if (!needle) return true;
      const sourceValues = [session.source.type, session.source.principalId, session.source.installationId, session.source.purpose];
      return [session.id, session.accountId, ...sourceValues, session.roleId, session.roleName]
        .some((value) => value.toLocaleLowerCase().includes(needle));
    });
  }, [lifecycle, query, sessions]);

  useLayoutEffect(() => {
    if (reviewing) reviewHeading.current?.focus({ preventScroll: true });
    else if (selected) detailHeading.current?.focus({ preventScroll: true });
    else if (returnToSession.current) {
      const id = returnToSession.current;
      returnToSession.current = null;
      sessionTriggers.current.get(id)?.focus({ preventScroll: true });
    }
  }, [reviewing, selected]);

  if (selected) {
    const back = () => {
      if (reviewing) {
        setReviewing(false);
        return;
      }
      returnToSession.current = selected.id;
      setSelectedId(null);
    };
    return <section aria-labelledby="service-role-session-detail-title" className={styles.bindingSection}>
      <div className={styles.observationHeading}>
        <div>
          <Button onClick={back} size="small" variant="ghost"><ArrowLeft aria-hidden="true" />{t(reviewing ? "observation.session.backToDetail" : "observation.session.backToDirectory")}</Button>
          <span>{t(reviewing ? "observation.session.revokeEyebrow" : "observation.session.detailEyebrow")}</span>
          <h4 id="service-role-session-detail-title" ref={reviewing ? reviewHeading : detailHeading} tabIndex={-1}>{t(reviewing ? "observation.session.revokeTitle" : "observation.session.detailTitle")}</h4>
        </div>
        <div className={styles.stateBadges}><Badge status="warning">MOCK</Badge><Badge status={selected.lifecycle === "EXPIRED" ? "neutral" : "info"}>{t(`observation.session.states.${selected.lifecycle}`)}</Badge></div>
      </div>
      <Alert status="warning">{t(reviewing ? "observation.session.revokeBoundary" : `observation.session.detailBoundaries.${selected.lifecycle}`)}</Alert>
      <dl className={styles.compactFacts}>
        <div><dt>{t("observation.session.fields.id")}</dt><dd><code>{selected.id}</code></dd></div>
        <div><dt>{t("observation.session.fields.account")}</dt><dd><code>{selected.accountId}</code></dd></div>
        <div><dt>{t("observation.session.fields.sourceIdentity")}</dt><dd><Badge status="info">{selected.source.type}</Badge><code>{selected.source.principalId}</code><small><code>{selected.source.installationId}</code> · {selected.source.purpose}</small></dd></div>
        <div><dt>{t("observation.session.fields.role")}</dt><dd><code>{selected.roleName}</code><small><code>{selected.roleId}</code></small></dd></div>
        <div><dt>{t("observation.session.fields.issuedAt")}</dt><dd><WorkspaceTime value={selected.issuedAt} /></dd></div>
        <div><dt>{t("observation.session.fields.expiresAt")}</dt><dd><WorkspaceTime value={selected.expiresAt} /></dd></div>
        {selected.revokedAt ? <div><dt>{t("observation.session.fields.revokedAt")}</dt><dd><WorkspaceTime value={selected.revokedAt} /></dd></div> : null}
        <div><dt>{t("observation.session.fields.state")}</dt><dd>{t(`observation.session.states.${selected.lifecycle}`)}</dd></div>
        <div><dt>{t("observation.session.fields.revokeCapability")}</dt><dd><Badge status={selected.revokeCapability.available ? "info" : "neutral"}>{t(selected.revokeCapability.available ? "observation.session.capabilities.available" : "observation.session.capabilities.unavailable")}</Badge><small><code>{selected.revokeCapability.action}</code></small></dd></div>
      </dl>
      {reviewing ? <>
        <div className={styles.snapshot}><div><strong>{t("observation.session.revokeEffectTitle")}</strong><span>{t("observation.session.revokeEffectHint")}</span></div><ul><li>{t("observation.session.revokeEffectSession")}</li><li>{t("observation.session.revokeEffectNoGrant")}</li><li>{t("observation.session.revokeEffectNoProof")}</li></ul></div>
        <div className={styles.actions}><Button disabled title={t("observation.session.revokeUnavailable")} variant="danger">{t("observation.session.revokeUnavailable")}</Button></div>
      </> : selected.revokeCapability.available ? <div className={styles.actions}><Button onClick={() => setReviewing(true)} variant="secondary">{t("observation.session.reviewRevoke")}</Button></div>
        : <Alert status="info">{t(selected.lifecycle === "EXPIRED" ? "observation.session.expiredHint" : "observation.session.revokedHint")}</Alert>}
    </section>;
  }

  return <section aria-labelledby="service-role-session-directory-title" className={styles.bindingSection}>
    <div className={styles.sectionHeading}><div><h3 id="service-role-session-directory-title">{t("observation.session.directoryTitle")}</h3><p>{t("observation.session.directoryHint")}</p></div><div className={styles.stateBadges}><Badge status="warning">MOCK</Badge><Badge status="neutral">{sessions.length}</Badge></div></div>
    <Alert status="warning">{t("observation.session.directoryBoundary", { count: sessions.length })}</Alert>
    <TableToolbar
      search={{ label: t("observation.session.search"), value: query, onChange: setQuery }}
      filters={[{
        id: "lifecycle", label: t("observation.session.stateFilter"), value: lifecycle, defaultValue: "ALL",
        onChange: (value) => setLifecycle(value as RoleSessionFilterLifecycle),
        options: [
          { value: "ALL", label: t("observation.session.allStates") },
          { value: "UNREVOKED", label: t("observation.session.states.UNREVOKED") },
          { value: "EXPIRED", label: t("observation.session.states.EXPIRED") },
          { value: "REVOKED", label: t("observation.session.states.REVOKED") }
        ]
      }]}
      labels={toolbarLabels}
      status={t("observation.session.filteredCount", { count: visibleSessions.length, total: sessions.length })}
    />
    {visibleSessions.length ? <><Table aria-label={t("observation.session.tableLabel")} className={styles.sessionDirectoryTable} mobileLayout="stack">
      <thead><tr><th scope="col">{t("observation.session.fields.id")}</th><th scope="col">{t("observation.session.fields.sourceIdentity")}</th><th scope="col">{t("observation.session.fields.role")}</th><th scope="col">{t("observation.session.fields.lifecycle")}</th></tr></thead>
      <tbody>{visibleSessions.map((session) => <tr key={session.id}>
        <td data-label={t("observation.session.fields.id")}><Table.PrimaryAction className={styles.directoryIdentifier} title={session.id} ref={(node) => { if (node) sessionTriggers.current.set(session.id, node); else sessionTriggers.current.delete(session.id); }} onClick={() => { setReviewing(false); setSelectedId(session.id); }}>{session.id}</Table.PrimaryAction></td>
        <td data-label={t("observation.session.fields.sourceIdentity")}><Badge status="info">{session.source.type}</Badge><code>{session.source.principalId}</code><small><code>{session.source.installationId}</code> · {session.source.purpose}</small></td>
        <td data-label={t("observation.session.fields.role")}><strong>{t("template.name")}</strong><small className={styles.directoryIdentifier} title={session.roleName}><code>{session.roleName}</code></small></td>
        <td data-label={t("observation.session.fields.lifecycle")}><WorkspaceTime value={session.expiresAt} /><small><Badge status={session.lifecycle === "EXPIRED" ? "neutral" : "info"}>{t(`observation.session.states.${session.lifecycle}`)}</Badge></small></td>
      </tr>)}</tbody>
    </Table>
    <Table.Footer note={t("observation.session.footer")}><TablePagination mode="cursor" summary={t("observation.session.cursorPage", { page: 1 })}
      previous={{ label: t("observation.session.previous"), disabled: true, onClick: () => undefined }}
      next={{ label: t("observation.session.next"), disabled: true, onClick: () => undefined }} /></Table.Footer></>
      : <EmptyState title={t("observation.session.emptyTitle")} description={t("observation.session.emptyHint")} action={<Button variant="secondary" onClick={() => { setQuery(""); setLifecycle("ALL"); }}>{toolbarLabels.resetQuery}</Button>} />}
  </section>;
}

function ServiceAuthorizationValiditySummary() {
  const t = useTranslations("ServiceAuthorizationPreview");
  const titleId = useId();

  return <section aria-labelledby={titleId} className={styles.validitySummary}>
    <div className={styles.runtimeTraceHeading}>
      <div><h4 id={titleId}>{t("observation.validity.title")}</h4><p>{t("observation.validity.hint")}</p></div>
      <div className={styles.stateBadges}>
        <Badge status="success">{t("observation.validity.configurationState")}</Badge>
        <Badge status="neutral">{t("observation.validity.runtimeState")}</Badge>
      </div>
    </div>
    <ol className={styles.runtimeStages}>
      {authorizationValidityStageIds.map((stage, index) => <li key={stage}>
        <span className={styles.runtimeIndex} aria-hidden="true">{index + 1}</span>
        <div><strong>{t(`observation.validity.stages.${stage}.title`)}</strong><small>{t(`observation.validity.stages.${stage}.hint`)}</small></div>
        <Badge status={stage === "runtime" ? "neutral" : "success"}>{t(`observation.validity.stages.${stage}.state`)}</Badge>
      </li>)}
    </ol>
    <Alert status="info">{t("observation.validity.conclusion")}</Alert>
    <Alert status="warning">{t("observation.validity.revocationBoundary")}</Alert>
  </section>;
}

function ServiceLinkedRoleObservation({ accountId }: { accountId: string }) {
  const t = useTranslations("ServiceAuthorizationPreview");
  const previewSnapshot = previewPermissionCeiling();
  const [detailSection, setDetailSection] = useState("configuration");
  return <div className={styles.stack}>
    <div className={styles.sectionHeading}>
      <div><span>{t("observation.eyebrow")}</span><h3>{t("observation.title")}</h3><p>{t("observation.hint")}</p></div>
      <div className={styles.stateBadges}><Badge status="success">{t("states.authorized")}</Badge><Badge status="warning">MOCK</Badge></div>
    </div>
    <Alert status="info">{t("observation.contractBoundary")}</Alert>
    <ServiceAuthorizationValiditySummary />
    <Tabs.Root value={detailSection} onValueChange={setDetailSection}>
      <Tabs.List aria-label={t("observation.details.sectionsLabel")}>
        <Tabs.Trigger value="configuration">{t("observation.details.configuration")}</Tabs.Trigger>
        <Tabs.Trigger value="bindings">{t("observation.details.bindings", { count: 1 })}</Tabs.Trigger>
        <Tabs.Trigger value="runtime">{t("observation.details.runtime")}</Tabs.Trigger>
      </Tabs.List>
      <Tabs.Content className={styles.stack} value="configuration">
        <div className={styles.observationGrid}>
          <Card>
            <Card.Header className={styles.observationHeading}><div><span>{t("observation.template.eyebrow")}</span><h4>{t("observation.template.title")}</h4></div><Badge status="success">{t("states.active")}</Badge></Card.Header>
            <Card.Body className={styles.cardBody}><dl className={styles.compactFacts}>
              <div><dt>{t("fields.templateId")}</dt><dd><code>{previewTemplate.id}</code></dd></div>
              <div><dt>{t("fields.templateRevision")}</dt><dd>v{previewTemplate.version}</dd></div>
              <div><dt>{t("fields.contentDigest")}</dt><dd><code>{previewTemplate.contentDigest}</code></dd></div>
              <div><dt>{t("fields.permissionCeiling")}</dt><dd><code>{previewTemplate.policyId}@{previewTemplate.policyVersionId}</code></dd></div>
              <div><dt>{t("fields.workloadKinds")}</dt><dd><code>{previewTemplate.workload.resourceKind}</code></dd></div>
              <div><dt>{t("fields.bindAction")}</dt><dd><code>{previewTemplate.workload.bindAction}</code></dd></div>
              <div><dt>{t("fields.unbindAction")}</dt><dd><code>{previewTemplate.workload.unbindAction}</code></dd></div>
              <div><dt>{t("fields.maxSession")}</dt><dd>{t("observation.durationMinutes", { count: previewTemplate.maxSessionDurationSeconds / 60 })}</dd></div>
            </dl></Card.Body>
          </Card>
          <Card>
            <Card.Header className={styles.observationHeading}><div><span>{t("observation.relation.eyebrow")}</span><h4>{t("observation.relation.title")}</h4></div><Badge status="success">{previewAccountAccess.roleStatus}</Badge></Card.Header>
            <Card.Body className={styles.cardBody}><dl className={styles.compactFacts}>
              <div><dt>{t("fields.targetAccount")}</dt><dd><code>{accountId}</code></dd></div>
              <div><dt>{t("fields.roleId")}</dt><dd><code>{previewAccountAccess.roleId}</code></dd></div>
              <div><dt>{t("fields.roleManagement")}</dt><dd><code>{previewAccountAccess.roleManagement}</code></dd></div>
              <div><dt>{t("fields.resourceVersion")}</dt><dd>{previewAccountAccess.roleResourceVersion}</dd></div>
              <div><dt>{t("fields.serviceInstallation")}</dt><dd><code>{previewAccountAccess.principalInstallationId}</code></dd></div>
              <div><dt>{t("fields.servicePrincipal")}</dt><dd><code>{previewAccountAccess.principalId}</code></dd></div>
              <div><dt>{t("fields.purpose")}</dt><dd><code>{previewTemplate.servicePurpose}</code></dd></div>
              <div><dt>{t("fields.roleName")}</dt><dd><code>{previewTemplate.roleName}</code></dd></div>
              <div><dt>{t("fields.roleDescription")}</dt><dd>{t("template.roleDescription")}</dd></div>
              <div><dt>{t("fields.templateReference")}</dt><dd><code>{previewTemplate.id}@v{previewTemplate.version}</code></dd></div>
              <div><dt>{t("fields.contentDigest")}</dt><dd><code>{previewTemplate.contentDigest}</code></dd></div>
              <div><dt>{t("fields.permissionCeiling")}</dt><dd><code>{previewTemplate.policyId}@{previewTemplate.policyVersionId}</code></dd></div>
              <div><dt>{t("fields.permissionCeilingDigest")}</dt><dd><code>{previewTemplate.policyContentDigest}</code></dd></div>
            </dl></Card.Body>
          </Card>
        </div>
        <Alert status="warning">{t("observation.roleIsNotBinding")}</Alert>
      </Tabs.Content>
      <Tabs.Content className={styles.stack} value="bindings">
        <section className={styles.bindingSection} aria-labelledby="service-authorization-binding-title">
          <div className={styles.sectionHeading}><div><h3 id="service-authorization-binding-title">{t("observation.binding.title")}</h3><p>{t("observation.binding.hint")}</p></div><Badge status="neutral">1</Badge></div>
          <Table aria-label={t("observation.binding.tableLabel")} mobileLayout="stack">
            <thead><tr><th scope="col">{t("fields.workload")}</th><th scope="col">{t("fields.bindingState")}</th><th scope="col">{t("fields.bindingId")}</th><th scope="col">{t("fields.resourceVersion")}</th><th scope="col">{t("fields.updatedAt")}</th></tr></thead>
            <tbody><tr>
              <td data-label={t("fields.workload")}><strong>{previewWorkload.kind}</strong><small><code>{previewWorkload.id}</code></small></td>
              <td data-label={t("fields.bindingState")}><Badge status="success">{previewAccountAccess.bindingStatus}</Badge></td>
              <td data-label={t("fields.bindingId")}><code>{previewAccountAccess.bindingId}</code>
                <small>{t("fields.targetAccount")} · <code>{accountId}</code></small>
                <small>{t("fields.roleId")} · <code>{previewAccountAccess.roleId}</code></small>
                <small>{t("fields.templateReference")} · <code>{previewTemplate.id}@v{previewTemplate.version}</code></small>
                <small>{t("fields.contentDigest")} · <code>{previewTemplate.contentDigest}</code></small>
              </td>
              <td data-label={t("fields.resourceVersion")}>{previewAccountAccess.bindingResourceVersion}</td>
              <td data-label={t("fields.updatedAt")}><WorkspaceTime value={previewAccountAccess.updatedAt} /><small>{t("observation.binding.createdAt")} <WorkspaceTime value={previewAccountAccess.createdAt} /></small></td>
            </tr></tbody>
          </Table>
          <Table.Footer note={t("observation.binding.snapshotNote")}><TablePagination mode="cursor" summary={t("observation.binding.cursorPage", { page: 1 })}
            previous={{ label: t("observation.binding.previous"), disabled: true, onClick: () => undefined }}
            next={{ label: t("observation.binding.next"), disabled: true, onClick: () => undefined }} /></Table.Footer>
        </section>
      </Tabs.Content>
      <Tabs.Content className={styles.stack} value="runtime">
        <Card>
          <Card.Header className={styles.observationHeading}>
            <div><span>{t("observation.session.eyebrow")}</span><h4>{t("observation.session.title")}</h4></div>
            <Badge status="neutral">{t("observation.session.notIssued")}</Badge>
          </Card.Header>
          <Card.Body className={styles.cardBody}>
            <dl className={styles.compactFacts}>
              <div><dt>{t("observation.session.identityType")}</dt><dd><code>ServiceRoleSession</code></dd></div>
              <div><dt>{t("observation.session.source")}</dt><dd><code>SERVICE_ACCOUNT</code></dd></div>
              <div><dt>{t("fields.maxSession")}</dt><dd>{t("observation.durationMinutes", { count: previewTemplate.maxSessionDurationSeconds / 60 })}</dd></div>
            </dl>
            <Alert status="info">{t("observation.session.boundary")}</Alert>
            <ServiceRoleRuntimeTrace />
          </Card.Body>
        </Card>
        <ServiceRoleSessionDirectoryPreview accountId={accountId} />
        <div className={styles.snapshot}><div><strong>{t("observation.permissionTitle")}</strong><span>{t("observation.permissionHint")}</span></div><ul>{previewSnapshot.statements.flatMap((statement) => statement.actions).map((action) => <li key={action}><code>{action}</code></li>)}</ul></div>
      </Tabs.Content>
    </Tabs.Root>
    <Alert status="info">{t("observation.readOnly")}</Alert>
  </div>;
}

function PreviewOperationControls({ kind, targetResourceId, primaryLabel, closeLabel, danger = false, leadingAction, onApplied, onClose }: {
  kind: PreviewOperationKind;
  targetResourceId: string;
  primaryLabel: string;
  closeLabel: string;
  danger?: boolean;
  leadingAction?: ReactNode;
  onApplied(): void;
  onClose(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  const headingId = useId();
  const [scenario, setScenario] = useState<PreviewOperationScenario>("success");
  const [result, setResult] = useState<PreviewOperationResult | null>(null);
  const requestId = `preview-service-role-${kind}-${targetResourceId}`;
  const options = useMemo(() => (["success", "unknown", "stateChanged", "requestMismatch", "unauthenticated", "forbidden", "invalidRequest"] as const)
    .map((value) => ({ value, label: t(`operationPreview.scenarios.${value}`) })), [t]);
  const submit = () => {
    if (scenario === "success") onApplied();
    else setResult(scenario);
  };
  const alertStatus = result === "forbidden" || result === "invalidRequest" || result === "requestMismatch" ? "danger" : "warning";
  const recoveryLabel = result === "stateChanged" ? t("operationPreview.reread")
    : result === "unauthenticated" ? t("operationPreview.returnPreservingRequest")
      : t("operationPreview.returnWithoutConfirmation");

  return <>
    <section aria-labelledby={headingId} className={styles.operationPreview}>
      <div className={styles.operationPreviewHeading}>
        <div><Badge status="warning">MOCK</Badge><strong id={headingId}>{t("operationPreview.title")}</strong><p>{t("operationPreview.hint")}</p></div>
        {!result ? <label className={styles.operationScenario}><span>{t("operationPreview.scenarioLabel")}</span><Select aria-label={t("operationPreview.scenarioLabel")} options={options} value={scenario} onValueChange={(value) => setScenario(value as PreviewOperationScenario)} /></label> : null}
      </div>
      {result ? <div className={styles.operationResult}>
        <Alert status={alertStatus}><div className={styles.operationResultCopy}><strong>{t(`operationPreview.results.${result}.title`)}</strong><p>{t(`operationPreview.results.${result}.description`)}</p></div></Alert>
        <dl className={styles.operationRequest}><div><dt>{t("operationPreview.requestId")}</dt><dd><code>{requestId}</code></dd></div></dl>
      </div> : null}
    </section>
    <div className={styles.reviewActions}>
      {!result ? leadingAction ?? <span /> : <span />}
      <div>{result === "unknown" ? <><Button onClick={onApplied}>{t("operationPreview.retrySame")}</Button><Button variant="secondary" onClick={onClose}>{t("operationPreview.returnWithoutConfirmation")}</Button></>
        : result ? <Button variant="secondary" onClick={onClose}>{recoveryLabel}</Button>
          : <>{danger ? <Button variant="danger" onClick={submit}>{primaryLabel}</Button> : <Button onClick={submit}>{primaryLabel}</Button>}<Button variant="secondary" onClick={onClose}>{closeLabel}</Button></>}</div>
    </div>
  </>;
}

export function ServiceAuthorizationConsentReview({ accountId, targetResourceId, stage, onStageChange, onClose, onPreviewAuthorize }: {
  accountId: string;
  targetResourceId: string;
  stage: number;
  onStageChange(stage: number): void;
  onClose(): void;
  onPreviewAuthorize?(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  const steps = useMemo(() => stageIds.map((id) => ({ id, label: t(`steps.${id}`) })), [t]);
  const currentStage = stageIds[stage] ?? "identity";
  const statements = previewPermissionCeiling().statements;
  const stageHeading = useRef<HTMLHeadingElement>(null);
  const previousStage = useRef(stage);

  useLayoutEffect(() => {
    if (previousStage.current !== stage) stageHeading.current?.focus({ preventScroll: true });
    previousStage.current = stage;
  }, [stage]);

  return <div className={styles.stack}>
    <div className={styles.steps}><Steps label={t("progress")} items={steps} current={stage} onChange={onStageChange} /></div>
    <Card className={styles.reviewCard}>
      <Card.Header className={styles.cardHeading}>{stage === 0 ? <KeyRound aria-hidden="true" /> : stage === 1 ? <ShieldCheck aria-hidden="true" /> : <Boxes aria-hidden="true" />}<div><span>{t("stageLabel", { current: stage + 1, total: stageIds.length })}</span><h3 ref={stageHeading} tabIndex={-1}>{t(`review.${currentStage}.title`)}</h3></div></Card.Header>
      <Card.Body className={styles.cardBody}>
        <p className={styles.lead}>{t(stage === 2 && onPreviewAuthorize ? "review.consent.previewLead" : `review.${currentStage}.lead`)}</p>
        {stage === 0 ? <><dl className={styles.facts}><div><dt>{t("fields.product")}</dt><dd><code>{previewTemplate.product}</code></dd></div><div><dt>{t("fields.targetAccount")}</dt><dd><code>{accountId}</code></dd></div><div><dt>{t("fields.targetResource")}</dt><dd><code>{previewWorkload.kind}:{targetResourceId}</code></dd></div><div><dt>{t("fields.serviceInstallation")}</dt><dd><code>{previewAccountAccess.principalInstallationId}</code></dd></div><div><dt>{t("fields.servicePrincipal")}</dt><dd><code>{previewAccountAccess.principalId}</code></dd></div><div><dt>{t("fields.purpose")}</dt><dd><code>{previewTemplate.servicePurpose}</code></dd></div><div><dt>{t("fields.roleName")}</dt><dd><code>{previewTemplate.roleName}</code></dd></div><div><dt>{t("fields.roleDescription")}</dt><dd>{t("template.roleDescription")}</dd></div><div><dt>{t("fields.maxSession")}</dt><dd>{t("observation.durationMinutes", { count: previewTemplate.maxSessionDurationSeconds / 60 })}</dd></div></dl><div className={styles.snapshot}><div><strong>{t("review.identity.requiredChecks")}</strong><span>{t("review.identity.requiredChecksHint")}</span></div><ul><li><code>{previewTemplate.workload.bindAction}</code></li><li><code>iam.service-linked-role.create</code></li><li><code>iam.role.pass</code></li></ul></div><Alert status="info">{t("review.identity.passRoleBoundary")}</Alert></> : null}
        {stage === 1 ? <><div className={styles.permissionReference}><div><span>{t("fields.policySnapshot")}</span><strong>{previewTemplate.snapshotName} · v{previewTemplate.revision}</strong></div><Badge>{t("review.permissions.illustrative")}</Badge></div>
          <dl className={styles.facts}><div><dt>{t("fields.policyId")}</dt><dd><code>{previewTemplate.policyId}</code></dd></div><div><dt>{t("fields.policyVersion")}</dt><dd><code>{previewTemplate.policyVersionId}</code></dd></div><div><dt>{t("fields.permissionCeilingDigest")}</dt><dd><code>{previewTemplate.policyContentDigest}</code></dd></div></dl>
          <div className={styles.permissionStatements}>{statements.map((statement, index) => <section aria-label={t("review.permissions.statement", { number: index + 1 })} className={styles.permissionStatement} key={index}>
            <div className={styles.permissionStatementHeading}><strong>{t("review.permissions.statement", { number: index + 1 })}</strong><Badge status={statement.effect === "DENY" ? "danger" : "success"}>{t(`review.permissions.${statement.effect === "DENY" ? "deny" : "allow"}`)}</Badge></div>
            <dl><div><dt>{t("review.permissions.actionPatterns")}</dt><dd><ul className={styles.permissionList}>{statement.actions.map((action) => <li key={action}><code>{action}</code></li>)}</ul></dd></div>
              <div><dt>{t("review.permissions.resources")}</dt><dd><ul className={styles.resourceList}>{statement.resources.map((resource) => <li key={`${resource.kind}:${resource.id ?? ""}`}><code>{resource.kind}</code> · {t(`review.permissions.match.${resource.match}`)}{resource.id ? <> · <code>{resource.id}</code></> : null}</li>)}</ul></dd></div>
              <div><dt>{t("review.permissions.conditions")}</dt><dd>{statement.conditions?.length ? statement.conditions.map((condition) => <code key={condition.key}>{condition.key} · {condition.operator} · {condition.values.join(", ")}</code>) : t("review.permissions.noConditions")}</dd></div></dl>
          </section>)}</div>
          <Alert status="info">{t("review.permissions.snapshotBoundary")}</Alert></> : null}
        {stage === 2 ? <><dl className={styles.facts}><div><dt>{t("fields.templateState")}</dt><dd>{t("states.contractSample")}</dd></div><div><dt>{t("fields.accountState")}</dt><dd>{t("states.notAuthorized")}</dd></div></dl><ul className={styles.boundaries}>{(["explicit", "shortTerm", "noExpansion", "cleanup"] as const).map((item) => <li key={item}><strong>{t(`review.consent.items.${item}.title`)}</strong><p>{t(`review.consent.items.${item}.hint`)}</p></li>)}</ul><Alert status={onPreviewAuthorize ? "info" : "warning"}>{t(onPreviewAuthorize ? "review.consent.previewAvailable" : "review.consent.unavailable")}</Alert></> : null}
      </Card.Body>
    </Card>
    {stage === stageIds.length - 1 && onPreviewAuthorize ? <PreviewOperationControls kind="bind" targetResourceId={targetResourceId} primaryLabel={t("authorizePreview")} closeLabel={t("finish")} leadingAction={<Button variant="secondary" onClick={() => onStageChange(stage - 1)}>{t("previous")}</Button>} onApplied={onPreviewAuthorize} onClose={onClose} />
      : <div className={styles.reviewActions}>
        {stage > 0 ? <Button variant="secondary" onClick={() => onStageChange(stage - 1)}>{t("previous")}</Button> : <span />}
        <div>{stage < stageIds.length - 1 ? <Button onClick={() => onStageChange(stage + 1)}>{t("next")}</Button> : <><Button disabled title={t("review.consent.unavailable")}>{t("authorizeDisabled")}</Button><Button variant="secondary" onClick={onClose}>{t("finish")}</Button></>}</div>
      </div>}
  </div>;
}

export function ServiceAuthorizationUnbindReview({ accountId, targetResourceId, bindingId, otherBoundResourceCount, onClose, onPreviewUnbind }: {
  accountId: string;
  targetResourceId: string;
  bindingId: string;
  otherBoundResourceCount: number;
  onClose(): void;
  onPreviewUnbind(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");

  return <div className={styles.stack}>
    <Card className={styles.reviewCard}>
      <Card.Header className={styles.cardHeading}><Unlink aria-hidden="true" /><div><span>{t("unbind.eyebrow")}</span><h3>{t("unbind.title")}</h3></div></Card.Header>
      <Card.Body className={styles.cardBody}>
        <p className={styles.lead}>{t("unbind.lead")}</p>
        <dl className={styles.facts}>
          <div><dt>{t("fields.targetAccount")}</dt><dd><code>{accountId}</code></dd></div>
          <div><dt>{t("fields.targetResource")}</dt><dd><code>SERVICE_INSTALLATION:{targetResourceId}</code></dd></div>
          <div><dt>{t("fields.bindingId")}</dt><dd><code>{bindingId}</code></dd></div>
          <div><dt>{t("fields.templateReference")}</dt><dd><code>{previewTemplate.id}@v{previewTemplate.version}</code></dd></div>
          <div><dt>{t("unbind.otherBindings")}</dt><dd>{t("unbind.otherBindingsCount", { count: otherBoundResourceCount })}</dd></div>
        </dl>
        <ul className={styles.boundaries}>{(["resourceOnly", "accountRelation", "sessions"] as const).map((item) => <li key={item}><strong>{t(`unbind.items.${item}.title`)}</strong><p>{t(`unbind.items.${item}.hint`)}</p></li>)}</ul>
        <Alert status="warning">{t("unbind.previewBoundary")}</Alert>
      </Card.Body>
    </Card>
    <PreviewOperationControls kind="unbind" targetResourceId={targetResourceId} primaryLabel={t("unbind.confirmPreview")} closeLabel={t("unbind.cancel")} danger onApplied={onPreviewUnbind} onClose={onClose} />
  </div>;
}

export function ServiceAuthorizationPreview({ workspace, onClose }: {
  workspace: AccessWorkspace;
  onClose(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  const [view, setView] = useState<PreviewView>("directory");
  const [directorySection, setDirectorySection] = useState<DirectorySection>("authorizations");
  const [accountAccessOrigin, setAccountAccessOrigin] = useState<"directory" | "detail">("directory");
  const [stage, setStage] = useState(0);
  const accountAccessTrigger = useRef<HTMLButtonElement>(null);
  const templateTrigger = useRef<HTMLButtonElement>(null);
  const reviewTrigger = useRef<HTMLButtonElement>(null);
  const observationTrigger = useRef<HTMLButtonElement>(null);
  const previousView = useRef<PreviewView>(view);

  useLayoutEffect(() => {
    const previous = previousView.current;
    previousView.current = view;
    if (previous === "review" && view === "detail") reviewTrigger.current?.focus({ preventScroll: true });
    else if (previous === "account-access" && view === "detail") observationTrigger.current?.focus({ preventScroll: true });
    else if (previous === "account-access" && view === "directory") accountAccessTrigger.current?.focus({ preventScroll: true });
    else if (previous === "detail" && view === "directory") templateTrigger.current?.focus({ preventScroll: true });
    // Forward navigation is a page-level state change. The shared H1 owns
    // focus through ContentPage.Heading; reverse navigation restores the
    // control that opened the nested view.
  }, [view]);

  const back = () => {
    if (view === "directory") onClose();
    else if (view === "detail") setView("directory");
    else if (view === "account-access") setView(accountAccessOrigin);
    else setView("detail");
  };
  const backLabel = view === "directory" ? t("backToRoles") : view === "detail" ? t("backToDirectory") : view === "account-access" && accountAccessOrigin === "directory" ? t("backToDirectory") : t("backToTemplate");
  const title = view === "directory" ? t("title") : view === "detail" ? t("detail.title") : view === "account-access" ? t("observation.pageTitle") : t("review.title");

  return <>
    <ContentPage.Heading key={view} title={title} scrollKey={`service-authorization:${view}`} back={{ label: backLabel, onClick: back }} focus />
    <Card aria-label={title}>
      <Card.Body className={styles.root}>
        <div className={styles.summary}><p>{t("subtitle")}</p><div className={styles.badges}><Badge status="warning">MOCK</Badge><Badge>{t("previewOnly")}</Badge></div></div>
        <Alert status="warning">{t("boundary")}</Alert>
        <ServiceAuthorizationResponsibility />
        {view === "directory" ? <Tabs.Root value={directorySection} onValueChange={(value) => setDirectorySection(value as DirectorySection)}>
          <Tabs.List aria-label={t("directory.sectionsLabel")}><Tabs.Trigger value="authorizations">{t("directory.authorizations")}</Tabs.Trigger><Tabs.Trigger value="templates">{t("directory.templates")}</Tabs.Trigger></Tabs.List>
          <Tabs.Content className={styles.stack} value="authorizations"><AccountAuthorizationDirectory accountId={workspace.accountId} triggerRef={accountAccessTrigger} onOpen={() => { setAccountAccessOrigin("directory"); setView("account-access"); }} /></Tabs.Content>
          <Tabs.Content className={styles.stack} value="templates"><TemplateDirectory triggerRef={templateTrigger} onOpen={() => setView("detail")} /></Tabs.Content>
        </Tabs.Root> : null}
        {view === "detail" ? <TemplateDetail reviewRef={reviewTrigger} observationRef={observationTrigger} onReview={() => { setStage(0); setView("review"); }} onObserve={() => { setAccountAccessOrigin("detail"); setView("account-access"); }} /> : null}
        {view === "review" ? <ServiceAuthorizationConsentReview accountId={workspace.accountId} targetResourceId={previewWorkload.id} stage={stage} onStageChange={setStage} onClose={() => setView("detail")} /> : null}
        {view === "account-access" ? <ServiceLinkedRoleObservation accountId={workspace.accountId} /> : null}
      </Card.Body>
    </Card>
  </>;
}
