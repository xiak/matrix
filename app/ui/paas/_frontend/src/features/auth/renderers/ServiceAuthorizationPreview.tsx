"use client";

import { useId, useLayoutEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from "react";
import { ArrowLeft, Boxes, KeyRound, ShieldCheck, Unlink } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, ContentPage, EmptyState, Select, Steps, Table, TablePagination, TableToolbar, Tabs } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountPolicyDocument } from "../domain/accounts";
import { WorkspaceTime } from "./AccessWorkspaceUi";
import { ServiceAuthorizationChain } from "./ServiceAuthorizationChain";
import styles from "./ServiceAuthorizationPreview.module.css";

type PreviewView = "directory" | "detail" | "review" | "account-access";
type DirectorySection = "authorizations" | "templates";

// UX-only projection of the FEAT-IAM-008 service-delegation boundary. The
// sample permission content is separate from tenant-editable MOCK policies.
// Neither these identities nor the snapshot revision are a published contract.
const previewTemplate = {
  id: "preview.service-role-template.managed-service-installation-read.v1",
  product: "managedservice",
  version: 1,
  contentDigest: `sha256:${"8".repeat(64)}`,
  servicePrincipal: "preview.paas.service",
  roleName: "PreviewServiceRoleForManagedServiceInstallationRead",
  purpose: "managed-service-installation-read",
  revision: 1,
  policyId: "preview.policy.managed-service-installation-read",
  policyVersionId: "v1",
  policyContentDigest: `sha256:${"9".repeat(64)}`,
  maxSessionDurationSeconds: 3600,
  workloadResourceKind: "SERVICE_INSTALLATION",
  snapshotName: "PreviewManagedServiceInstallationRead",
  targetResourceId: "service-installation-example",
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

type PreviewServiceRoleSessionSource =
  | { kind: "USER"; userId: string }
  | { kind: "SERVICE"; principalId: string; installationId: string };

type PreviewServiceRoleSession = {
  id: string;
  accountId: string;
  source: PreviewServiceRoleSessionSource;
  roleId: string;
  roleName: string;
  observation: "unrevoked" | "expired" | "revoked";
  issuedAt: string;
  expiresAt: string;
  revokedAt: string | null;
};

function previewServiceSessions(accountId: string): readonly PreviewServiceRoleSession[] {
  return [{
    id: "preview.service-role-session.current",
    accountId,
    source: { kind: "SERVICE", principalId: "preview.paas.service", installationId: "preview.service-installation.paas" },
    roleId: previewAccountAccess.roleId,
    roleName: previewTemplate.roleName,
    observation: "unrevoked",
    issuedAt: "2026-10-01T01:20:00Z",
    expiresAt: "2026-10-01T02:20:00Z",
    revokedAt: null
  },
  {
    id: "preview.service-role-session.expired",
    accountId,
    source: { kind: "SERVICE", principalId: "preview.paas.service", installationId: "preview.service-installation.paas" },
    roleId: previewAccountAccess.roleId,
    roleName: previewTemplate.roleName,
    observation: "expired",
    issuedAt: "2026-09-30T23:45:00Z",
    expiresAt: "2026-10-01T00:45:00Z",
    revokedAt: null
  },
  {
    id: "preview.service-role-session.revoked",
    accountId,
    source: { kind: "SERVICE", principalId: "preview.paas.service", installationId: "preview.service-installation.paas" },
    roleId: previewAccountAccess.roleId,
    roleName: previewTemplate.roleName,
    observation: "revoked",
    issuedAt: "2026-09-30T21:00:00Z",
    expiresAt: "2026-09-30T22:00:00Z",
    revokedAt: "2026-09-30T21:15:00Z"
  }];
}

const stageIds = ["identity", "permissions", "consent"] as const;
const runtimeStageIds = ["authenticate", "issue", "enforce", "execute"] as const;
const authorizationValidityStageIds = ["template", "account", "binding", "runtime"] as const;
type PreviewOperationKind = "bind" | "unbind";
type PreviewOperationScenario = "success" | "unknown" | "stateChanged" | "requestMismatch" | "unauthenticated" | "forbidden" | "invalidRequest";
type PreviewOperationResult = Exclude<PreviewOperationScenario, "success">;

// Only an already-declared managed-service read Action is used here. The exact
// sample ID illustrates the resource boundary; it grants no access to that ID.
function previewSnapshotFor(targetResourceId: string): AccountPolicyDocument {
  return {
    languageVersion: "1", scope: "TENANT", statements: [
      { sid: "read-service-installation", effect: "ALLOW", actions: ["managedservice.service-installation.read"],
        resources: [{ kind: "SERVICE_INSTALLATION", match: "EXACT", id: targetResourceId }] }
    ]
  };
}

function TemplateDirectory({ triggerRef, onOpen }: {
  triggerRef: RefObject<HTMLButtonElement | null>;
  onOpen(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  const responsibilityTitleId = useId();
  return <div className={styles.stack}>
    <div className={styles.sectionHeading}><div><h3>{t("directory.title")}</h3><p>{t("directory.hint")}</p></div><Badge status="warning">{t("states.illustrative")}</Badge></div>
    <section aria-labelledby={responsibilityTitleId} className={styles.responsibility}>
      <div className={styles.responsibilityHeading}>
        <h4 id={responsibilityTitleId}>{t("directory.responsibility.title")}</h4>
        <p>{t("directory.responsibility.hint")}</p>
      </div>
      <ol className={styles.responsibilityStages}>
        {(["product", "iam", "tenant"] as const).map((owner, index) => <li key={owner}>
          <span className={styles.runtimeIndex} aria-hidden="true">{index + 1}</span>
          <div><strong>{t(`directory.responsibility.${owner}.title`)}</strong><small>{t(`directory.responsibility.${owner}.hint`)}</small></div>
          <Badge status="neutral">{t(`directory.responsibility.${owner}.state`)}</Badge>
        </li>)}
      </ol>
    </section>
    <Table aria-label={t("directory.tableLabel")} mobileLayout="stack">
      <thead><tr><th scope="col">{t("fields.product")}</th><th scope="col">{t("fields.purpose")}</th><th scope="col">{t("fields.policySnapshot")}</th><th scope="col">{t("fields.templateState")}</th><th scope="col">{t("fields.accountState")}</th></tr></thead>
      <tbody><tr>
        <td data-label={t("fields.product")}><button className={styles.link} ref={triggerRef} onClick={onOpen}>{t("template.name")}</button><small><code>{previewTemplate.id}</code></small></td>
        <td data-label={t("fields.purpose")}>{t("template.purpose")}<small><code>{previewTemplate.servicePrincipal}</code></small></td>
        <td data-label={t("fields.policySnapshot")}>{previewTemplate.snapshotName}<small>v{previewTemplate.revision} · {t("previewOnly")}</small></td>
        <td data-label={t("fields.templateState")}><Badge status="warning">{t("states.illustrative")}</Badge></td>
        <td data-label={t("fields.accountState")}><Badge status="neutral">{t("states.notAuthorized")}</Badge></td>
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
        <td data-label={t("accountDirectory.columns.authorization")}><button aria-label={t("accountDirectory.open", { name: t("template.name") })} className={styles.link} ref={triggerRef} onClick={onOpen}>{t("template.name")}</button><small>{t("template.purpose")}</small><small><code>{previewTemplate.product} · {previewTemplate.purpose}</code></small></td>
        <td data-label={t("accountDirectory.columns.role")}><code>{previewTemplate.roleName}</code><small>{t("fields.targetAccount")} · <code>{accountId}</code></small></td>
        <td data-label={t("accountDirectory.columns.resource")}><strong>{t("accountDirectory.bindingCount", { active: previewAccountAccess.activeBindingCount, total: previewAccountAccess.bindingCount })}</strong><small><code>{previewTemplate.workloadResourceKind}: {previewTemplate.targetResourceId}</code></small></td>
        <td data-label={t("accountDirectory.columns.state")}><Badge status="success">{previewAccountAccess.roleStatus}</Badge><small><WorkspaceTime value={previewAccountAccess.updatedAt} /></small></td>
      </tr></tbody>
    </Table>
    <p className={styles.note}>{t("accountDirectory.readOnly")}</p>
  </div>;
}

function TemplateDetail({ accountId, reviewRef, observationRef, onReview, onObserve }: {
  accountId: string;
  reviewRef: RefObject<HTMLButtonElement | null>;
  observationRef: RefObject<HTMLButtonElement | null>;
  onReview(): void;
  onObserve(): void;
}) {
  const t = useTranslations("ServiceAuthorizationPreview");
  const previewSnapshot = previewSnapshotFor(previewTemplate.targetResourceId);
  return <div className={styles.stack}>
    <div className={styles.sectionHeading}><div><span>{t("detail.eyebrow")}</span><h3>{t("template.name")}</h3><p>{t("detail.hint")}</p></div><div className={styles.stateBadges}><Badge status="warning">{t("states.illustrative")}</Badge><Badge status="neutral">{t("states.notAuthorized")}</Badge></div></div>
    <dl className={styles.facts}>
      <div><dt>{t("fields.targetAccount")}</dt><dd><code>{accountId}</code></dd></div>
      <div><dt>{t("fields.templateRevision")}</dt><dd>v{previewTemplate.revision}</dd></div>
      <div><dt>{t("fields.servicePrincipal")}</dt><dd><code>{previewTemplate.servicePrincipal}</code></dd></div>
      <div><dt>{t("fields.roleName")}</dt><dd><code>{previewTemplate.roleName}</code></dd></div>
      <div><dt>{t("fields.roleDescription")}</dt><dd>{t("template.roleDescription")}</dd></div>
      <div><dt>{t("fields.purpose")}</dt><dd><code>{previewTemplate.purpose}</code></dd></div>
      <div><dt>{t("fields.targetResource")}</dt><dd><code>SERVICE_INSTALLATION:{previewTemplate.targetResourceId}</code></dd></div>
    </dl>
    <ServiceAuthorizationChain
      template={{ label: t("states.illustrative"), tone: "warning" }}
      account={{ label: t("states.notAuthorized") }}
      binding={{ label: t("states.notConfigured") }}
    />
    <div className={styles.detailGrid}>
      <Card><Card.Header className={styles.cardHeading}><KeyRound aria-hidden="true" /><div><span>{t("detail.trustLabel")}</span><h4>{t("detail.trustTitle")}</h4></div></Card.Header><Card.Body className={styles.cardBody}><p>{t("detail.trustHint")}</p><code>{previewTemplate.servicePrincipal}</code></Card.Body></Card>
      <Card><Card.Header className={styles.cardHeading}><ShieldCheck aria-hidden="true" /><div><span>{t("detail.permissionLabel")}</span><h4>{previewTemplate.snapshotName} · v{previewTemplate.revision}</h4></div></Card.Header><Card.Body className={styles.cardBody}><p>{t("detail.permissionHint")}</p><Alert status="info">{t("detail.snapshotBoundary")}</Alert></Card.Body></Card>
    </div>
    <div className={styles.snapshot}><div><strong>{t("detail.snapshotTitle")}</strong><span>{t("detail.snapshotCount", { count: previewSnapshot.statements.length })}</span></div><ul>{previewSnapshot.statements.flatMap((statement) => statement.actions).map((action) => <li key={action}><code>{action}</code></li>)}</ul></div>
    <Alert status="info">{t("detail.ordinaryRole")}</Alert>
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
  const [lifecycle, setLifecycle] = useState<"all" | "unrevoked" | "expired" | "revoked">("all");
  const detailHeading = useRef<HTMLHeadingElement>(null);
  const reviewHeading = useRef<HTMLHeadingElement>(null);
  const returnToSession = useRef<string | null>(null);
  const sessionTriggers = useRef(new Map<string, HTMLButtonElement>());
  const selected = sessions.find((session) => session.id === selectedId) ?? null;
  const visibleSessions = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return sessions.filter((session) => {
      if (lifecycle !== "all" && session.observation !== lifecycle) return false;
      if (!needle) return true;
      const sourceValues = session.source.kind === "SERVICE"
        ? [session.source.kind, session.source.principalId, session.source.installationId]
        : [session.source.kind, session.source.userId];
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
        <div className={styles.stateBadges}><Badge status="warning">MOCK</Badge><Badge status={selected.observation === "expired" ? "neutral" : "info"}>{t(`observation.session.states.${selected.observation}`)}</Badge></div>
      </div>
      <Alert status="warning">{t(reviewing ? "observation.session.revokeBoundary" : `observation.session.detailBoundaries.${selected.observation}`)}</Alert>
      <dl className={styles.compactFacts}>
        <div><dt>{t("observation.session.fields.id")}</dt><dd><code>{selected.id}</code></dd></div>
        <div><dt>{t("observation.session.fields.account")}</dt><dd><code>{selected.accountId}</code></dd></div>
        <div><dt>{t("observation.session.fields.sourceIdentity")}</dt><dd><Badge status="info">{selected.source.kind}</Badge>{selected.source.kind === "SERVICE"
          ? <><code>{selected.source.principalId}</code><small><code>{selected.source.installationId}</code></small></>
          : <code>{selected.source.userId}</code>}</dd></div>
        <div><dt>{t("observation.session.fields.role")}</dt><dd><code>{selected.roleName}</code><small><code>{selected.roleId}</code></small></dd></div>
        <div><dt>{t("observation.session.fields.issuedAt")}</dt><dd><WorkspaceTime value={selected.issuedAt} /></dd></div>
        <div><dt>{t("observation.session.fields.expiresAt")}</dt><dd><WorkspaceTime value={selected.expiresAt} /></dd></div>
        {selected.revokedAt ? <div><dt>{t("observation.session.fields.revokedAt")}</dt><dd><WorkspaceTime value={selected.revokedAt} /></dd></div> : null}
        <div><dt>{t("observation.session.fields.state")}</dt><dd>{t(`observation.session.states.${selected.observation}`)}</dd></div>
      </dl>
      {reviewing ? <>
        <div className={styles.snapshot}><div><strong>{t("observation.session.revokeEffectTitle")}</strong><span>{t("observation.session.revokeEffectHint")}</span></div><ul><li>{t("observation.session.revokeEffectSession")}</li><li>{t("observation.session.revokeEffectNoGrant")}</li><li>{t("observation.session.revokeEffectNoProof")}</li></ul></div>
        <div className={styles.actions}><Button disabled title={t("observation.session.revokeUnavailable")} variant="danger">{t("observation.session.revokeUnavailable")}</Button></div>
      </> : selected.observation === "unrevoked" ? <div className={styles.actions}><Button onClick={() => setReviewing(true)} variant="secondary">{t("observation.session.reviewRevoke")}</Button></div>
        : <Alert status="info">{t(selected.observation === "expired" ? "observation.session.expiredHint" : "observation.session.revokedHint")}</Alert>}
    </section>;
  }

  return <section aria-labelledby="service-role-session-directory-title" className={styles.bindingSection}>
    <div className={styles.sectionHeading}><div><h3 id="service-role-session-directory-title">{t("observation.session.directoryTitle")}</h3><p>{t("observation.session.directoryHint")}</p></div><div className={styles.stateBadges}><Badge status="warning">MOCK</Badge><Badge status="neutral">{sessions.length}</Badge></div></div>
    <Alert status="warning">{t("observation.session.directoryBoundary", { count: sessions.length })}</Alert>
    <TableToolbar
      search={{ label: t("observation.session.search"), value: query, onChange: setQuery }}
      filters={[{
        id: "lifecycle", label: t("observation.session.stateFilter"), value: lifecycle, defaultValue: "all",
        onChange: (value) => setLifecycle(value as "all" | "unrevoked" | "expired" | "revoked"),
        options: [
          { value: "all", label: t("observation.session.allStates") },
          { value: "unrevoked", label: t("observation.session.states.unrevoked") },
          { value: "expired", label: t("observation.session.states.expired") },
          { value: "revoked", label: t("observation.session.states.revoked") }
        ]
      }]}
      labels={toolbarLabels}
      status={t("observation.session.filteredCount", { count: visibleSessions.length, total: sessions.length })}
    />
    {visibleSessions.length ? <><Table aria-label={t("observation.session.tableLabel")} className={styles.sessionDirectoryTable} mobileLayout="stack">
      <thead><tr><th scope="col">{t("observation.session.fields.id")}</th><th scope="col">{t("observation.session.fields.sourceIdentity")}</th><th scope="col">{t("observation.session.fields.role")}</th><th scope="col">{t("observation.session.fields.lifecycle")}</th></tr></thead>
      <tbody>{visibleSessions.map((session) => <tr key={session.id}>
        <td data-label={t("observation.session.fields.id")}><button className={`${styles.link} ${styles.directoryIdentifier}`} title={session.id} ref={(node) => { if (node) sessionTriggers.current.set(session.id, node); else sessionTriggers.current.delete(session.id); }} onClick={() => { setReviewing(false); setSelectedId(session.id); }}>{session.id}</button></td>
        <td data-label={t("observation.session.fields.sourceIdentity")}><Badge status="info">{session.source.kind}</Badge>{session.source.kind === "SERVICE"
          ? <><code>{session.source.principalId}</code><small><code>{session.source.installationId}</code></small></>
          : <code>{session.source.userId}</code>}</td>
        <td data-label={t("observation.session.fields.role")}><strong>{t("template.name")}</strong><small className={styles.directoryIdentifier} title={session.roleName}><code>{session.roleName}</code></small></td>
        <td data-label={t("observation.session.fields.lifecycle")}><WorkspaceTime value={session.expiresAt} /><small><Badge status={session.observation === "expired" ? "neutral" : "info"}>{t(`observation.session.states.${session.observation}`)}</Badge></small></td>
      </tr>)}</tbody>
    </Table>
    <Table.Footer note={t("observation.session.footer")}><TablePagination mode="cursor" summary={t("observation.session.cursorPage", { page: 1 })}
      previous={{ label: t("observation.session.previous"), disabled: true, onClick: () => undefined }}
      next={{ label: t("observation.session.next"), disabled: true, onClick: () => undefined }} /></Table.Footer></>
      : <EmptyState title={t("observation.session.emptyTitle")} description={t("observation.session.emptyHint")} action={<Button variant="secondary" onClick={() => { setQuery(""); setLifecycle("all"); }}>{toolbarLabels.resetQuery}</Button>} />}
  </section>;
}

function ServiceAuthorizationValiditySummary() {
  const t = useTranslations("ServiceAuthorizationPreview");
  const titleId = useId();

  return <section aria-labelledby={titleId} className={styles.responsibility}>
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
  const previewSnapshot = previewSnapshotFor(previewTemplate.targetResourceId);
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
              <div><dt>{t("fields.workloadKinds")}</dt><dd><code>{previewTemplate.workloadResourceKind}</code></dd></div>
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
              <div><dt>{t("fields.purpose")}</dt><dd><code>{previewTemplate.purpose}</code></dd></div>
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
              <td data-label={t("fields.workload")}><strong>{previewTemplate.workloadResourceKind}</strong><small><code>{previewTemplate.targetResourceId}</code></small></td>
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
              <div><dt>{t("observation.session.source")}</dt><dd><code>SERVICE</code></dd></div>
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
  const statements = previewSnapshotFor(targetResourceId).statements;
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
        {stage === 0 ? <><dl className={styles.facts}><div><dt>{t("fields.product")}</dt><dd><code>{previewTemplate.product}</code></dd></div><div><dt>{t("fields.targetAccount")}</dt><dd><code>{accountId}</code></dd></div><div><dt>{t("fields.targetResource")}</dt><dd><code>SERVICE_INSTALLATION:{targetResourceId}</code></dd></div><div><dt>{t("fields.servicePrincipal")}</dt><dd><code>{previewTemplate.servicePrincipal}</code></dd></div><div><dt>{t("fields.purpose")}</dt><dd><code>{previewTemplate.purpose}</code></dd></div><div><dt>{t("fields.roleName")}</dt><dd><code>{previewTemplate.roleName}</code></dd></div><div><dt>{t("fields.roleDescription")}</dt><dd>{t("template.roleDescription")}</dd></div><div><dt>{t("fields.maxSession")}</dt><dd>{t("observation.durationMinutes", { count: previewTemplate.maxSessionDurationSeconds / 60 })}</dd></div></dl><Alert status="info">{t("review.identity.passRoleBoundary")}</Alert></> : null}
        {stage === 1 ? <><div className={styles.permissionReference}><div><span>{t("fields.policySnapshot")}</span><strong>{previewTemplate.snapshotName} · v{previewTemplate.revision}</strong></div><Badge>{t("review.permissions.illustrative")}</Badge></div>
          <dl className={styles.facts}><div><dt>{t("fields.policyId")}</dt><dd><code>{previewTemplate.policyId}</code></dd></div><div><dt>{t("fields.policyVersion")}</dt><dd><code>{previewTemplate.policyVersionId}</code></dd></div><div><dt>{t("fields.permissionCeilingDigest")}</dt><dd><code>{previewTemplate.policyContentDigest}</code></dd></div></dl>
          <div className={styles.permissionStatements}>{statements.map((statement, index) => <section aria-label={t("review.permissions.statement", { number: index + 1 })} className={styles.permissionStatement} key={index}>
            <div className={styles.permissionStatementHeading}><strong>{t("review.permissions.statement", { number: index + 1 })}</strong><Badge status={statement.effect === "DENY" ? "danger" : "success"}>{t(`review.permissions.${statement.effect === "DENY" ? "deny" : "allow"}`)}</Badge></div>
            <dl><div><dt>{t("review.permissions.actionPatterns")}</dt><dd><ul className={styles.permissionList}>{statement.actions.map((action) => <li key={action}><code>{action}</code></li>)}</ul></dd></div>
              <div><dt>{t("review.permissions.resources")}</dt><dd><ul className={styles.resourceList}>{statement.resources.map((resource) => <li key={`${resource.kind}:${resource.id ?? ""}`}><code>{resource.kind}</code> · {t(`review.permissions.match.${resource.match}`)}{resource.id ? <> · <code>{resource.id}</code></> : null}</li>)}</ul></dd></div>
              <div><dt>{t("review.permissions.conditions")}</dt><dd>{statement.conditions?.length ? statement.conditions.map((condition) => <code key={condition.key}>{condition.key} · {condition.operator} · {condition.values.join(", ")}</code>) : t("review.permissions.noConditions")}</dd></div></dl>
          </section>)}</div>
          <Alert status="info">{t("review.permissions.snapshotBoundary")}</Alert></> : null}
        {stage === 2 ? <><dl className={styles.facts}><div><dt>{t("fields.templateState")}</dt><dd>{t("states.illustrative")}</dd></div><div><dt>{t("fields.accountState")}</dt><dd>{t("states.notAuthorized")}</dd></div></dl><ul className={styles.boundaries}>{(["explicit", "shortTerm", "noExpansion", "cleanup"] as const).map((item) => <li key={item}><strong>{t(`review.consent.items.${item}.title`)}</strong><p>{t(`review.consent.items.${item}.hint`)}</p></li>)}</ul><Alert status={onPreviewAuthorize ? "info" : "warning"}>{t(onPreviewAuthorize ? "review.consent.previewAvailable" : "review.consent.unavailable")}</Alert></> : null}
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
        {view === "directory" ? <Tabs.Root value={directorySection} onValueChange={(value) => setDirectorySection(value as DirectorySection)}>
          <Tabs.List aria-label={t("directory.sectionsLabel")}><Tabs.Trigger value="authorizations">{t("directory.authorizations")}</Tabs.Trigger><Tabs.Trigger value="templates">{t("directory.templates")}</Tabs.Trigger></Tabs.List>
          <Tabs.Content className={styles.stack} value="authorizations"><AccountAuthorizationDirectory accountId={workspace.accountId} triggerRef={accountAccessTrigger} onOpen={() => { setAccountAccessOrigin("directory"); setView("account-access"); }} /></Tabs.Content>
          <Tabs.Content className={styles.stack} value="templates"><TemplateDirectory triggerRef={templateTrigger} onOpen={() => setView("detail")} /></Tabs.Content>
        </Tabs.Root> : null}
        {view === "detail" ? <TemplateDetail accountId={workspace.accountId} reviewRef={reviewTrigger} observationRef={observationTrigger} onReview={() => { setStage(0); setView("review"); }} onObserve={() => { setAccountAccessOrigin("detail"); setView("account-access"); }} /> : null}
        {view === "review" ? <ServiceAuthorizationConsentReview accountId={workspace.accountId} targetResourceId={previewTemplate.targetResourceId} stage={stage} onStageChange={setStage} onClose={() => setView("detail")} /> : null}
        {view === "account-access" ? <ServiceLinkedRoleObservation accountId={workspace.accountId} /> : null}
      </Card.Body>
    </Card>
  </>;
}
