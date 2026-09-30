"use client";

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, ContentPage, EmptyState, Table, TablePagination, TableSkeleton, Tabs } from "@ui/xiak";
import type {
  ServiceLinkedRoleAccessLoad,
  ServiceLinkedRoleClient,
  ServiceLinkedRoleDirectoryLoad,
  ServiceRoleTemplateClient,
  ServiceRoleTemplateLoad
} from "../application/AccountAccessProvider";
import type { ServiceLinkedRoleAccess, ServiceLinkedRoleDirectory, ServiceLinkedRoleListing, ServiceLinkedRoleRelation, ServiceRoleTemplate } from "../domain/serviceAuthorization";
import { WorkspaceDetail, WorkspaceTime } from "./AccessWorkspaceUi";
import { ServiceAuthorizationChain } from "./ServiceAuthorizationChain";
import styles from "./AccountAccessRenderer.module.css";

type FailureStatus = "forbidden" | "routeUnavailable" | "unavailable" | "expired";
type RelationState = { status: "loading" } | ServiceLinkedRoleDirectoryLoad;
type TemplateState = { status: "loading" } | ServiceRoleTemplateLoad;
type Selection =
  | { kind: "relation"; roleId: string; roleName: string }
  | { kind: "template"; template: ServiceRoleTemplate };

function durationLabel(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  return `${seconds / 60} min`;
}

function sameRelation(left: ServiceLinkedRoleRelation, right: ServiceLinkedRoleRelation): boolean {
  return left.role.id === right.role.id && left.role.resourceVersion === right.role.resourceVersion && left.role.updatedAt === right.role.updatedAt &&
    left.template.id === right.template.id && left.template.version === right.template.version && left.template.contentDigest === right.template.contentDigest &&
    left.servicePrincipal.installationId === right.servicePrincipal.installationId && left.servicePrincipal.principalId === right.servicePrincipal.principalId &&
    left.servicePrincipal.purpose === right.servicePrincipal.purpose && left.permissionCeiling.policyId === right.permissionCeiling.policyId &&
    left.permissionCeiling.versionId === right.permissionCeiling.versionId && left.permissionCeiling.contentDigest === right.permissionCeiling.contentDigest;
}

function CursorFooter({ page, previous, next, hasNext, busy, note }: {
  page: number;
  previous(): void;
  next(): void;
  hasNext: boolean;
  busy: boolean;
  note: string;
}) {
  const t = useTranslations("ServiceAuthorizationDirectory");
  return <Table.Footer note={note}><TablePagination mode="cursor" disabled={busy} summary={t("page", { page })}
    previous={{ label: t("previous"), disabled: page === 1, onClick: previous }}
    next={{ label: t("next"), disabled: !hasNext, onClick: next }} /></Table.Footer>;
}

function LoadFailure({ status, retry, scope }: { status: FailureStatus; retry(): void; scope: "relations" | "templates" }) {
  const t = useTranslations("ServiceAuthorizationDirectory");
  return <EmptyState title={t(`errors.${scope}.${status}.title`)} description={t(`errors.${scope}.${status}.description`)}
    action={status === "expired" ? undefined : <Button variant="secondary" onClick={retry}>{t("retry")}</Button>} />;
}

function RelationDirectory({ client, onOpen }: {
  client: ServiceLinkedRoleClient;
  onOpen(listing: ServiceLinkedRoleListing, trigger: HTMLButtonElement): void;
}) {
  const t = useTranslations("ServiceAuthorizationDirectory");
  const [state, setState] = useState<RelationState>({ status: "loading" });
  const [pages, setPages] = useState<ServiceLinkedRoleDirectory[]>([]);
  const [pageIndex, setPageIndex] = useState(0);
  const [paging, setPaging] = useState(false);
  const [pageFailure, setPageFailure] = useState<FailureStatus | null>(null);
  const request = useRef(0);
  const pagingRequest = useRef(false);

  const load = useCallback(() => {
    const revision = ++request.current;
    setState({ status: "loading" });
    setPages([]);
    setPageIndex(0);
    setPageFailure(null);
    client.list().then((result) => {
      if (request.current !== revision) return;
      setState(result);
      if (result.status === "ready") setPages([result.directory]);
    });
  }, [client]);

  useEffect(() => {
    const revision = ++request.current;
    client.list().then((result) => {
      if (request.current !== revision) return;
      setState(result);
      if (result.status === "ready") setPages([result.directory]);
    });
    return () => { request.current += 1; };
  }, [client]);

  const current = pages[pageIndex] ?? (state.status === "ready" ? state.directory : null);
  const nextPage = async () => {
    if (!current || pagingRequest.current || !current.nextAfter) return;
    if (pages[pageIndex + 1]) { setPageIndex((value) => value + 1); setPageFailure(null); return; }
    pagingRequest.current = true;
    setPaging(true); setPageFailure(null);
    const revision = request.current;
    const result = await client.list(current.nextAfter);
    if (request.current !== revision) return;
    if (result.status === "ready") {
      const known = new Set(pages.flatMap((page) => page.items.map((item) => item.relation.role.id)));
      if (result.directory.items.some((item) => known.has(item.relation.role.id))) setPageFailure("unavailable");
      else { setPages((value) => [...value, result.directory]); setPageIndex((value) => value + 1); }
    } else setPageFailure(result.status);
    pagingRequest.current = false;
    setPaging(false);
  };

  return <section className={styles.stack} aria-labelledby="service-linked-role-directory-title">
    <div className={styles.sectionHeading}>
      <div><h3 className={styles.detailTitle} id="service-linked-role-directory-title">{t("relations.title")}</h3><p className={styles.note}>{t("relations.hint")}</p></div>
      <Badge>{t("readOnly")}</Badge>
    </div>
    <Alert>{t("relations.boundary")}</Alert>
    {state.status === "loading" ? <TableSkeleton label={t("relations.loading")} rows={4} /> : null}
    {state.status !== "loading" && state.status !== "ready" ? <LoadFailure status={state.status} retry={load} scope="relations" /> : null}
    {current ? <>
      {current.items.length ? <Table aria-label={t("relations.tableLabel")} mobileLayout="stack">
        <thead><tr><th scope="col">{t("fields.service")}</th><th scope="col">{t("fields.role")}</th><th scope="col">{t("fields.bindings")}</th><th scope="col">{t("fields.stateAndTime")}</th></tr></thead>
        <tbody>{current.items.map((item) => <tr key={item.relation.role.id}>
          <td data-label={t("fields.service")}><strong>{t(`purposes.${item.relation.servicePrincipal.purpose}`)}</strong><small><code>{item.relation.servicePrincipal.installationId}</code></small><small><code>{item.relation.servicePrincipal.principalId}</code></small></td>
          <td data-label={t("fields.role")}><button className={styles.userLink} onClick={(event) => onOpen(item, event.currentTarget)}>{item.relation.role.name}</button><small><code>{item.relation.role.id}</code></small><small>{item.relation.role.description}</small></td>
          <td data-label={t("fields.bindings")}><strong>{t("relations.bindingCount", { active: item.activeBindingCount, total: item.bindingCount })}</strong><small><code>{item.relation.template.id} @v{item.relation.template.version}</code></small></td>
          <td data-label={t("fields.stateAndTime")}><Badge status={item.relation.role.status === "ACTIVE" ? "success" : "neutral"}>{t(`states.${item.relation.role.status}`)}</Badge><small><WorkspaceTime value={item.relation.role.updatedAt} /></small></td>
        </tr>)}</tbody>
      </Table> : <EmptyState title={t("relations.emptyTitle")} description={t("relations.emptyDescription")} />}
      <CursorFooter page={pageIndex + 1} hasNext={Boolean(current.nextAfter || pages[pageIndex + 1])} busy={paging} previous={() => { setPageIndex((value) => Math.max(0, value - 1)); setPageFailure(null); }} next={nextPage}
        note={current.nextAfter ? t("relations.more") : t("relations.complete", { count: current.items.length })} />
      {pageFailure ? <Alert status="warning">{t(`errors.relations.${pageFailure}.description`)}</Alert> : null}
    </> : null}
  </section>;
}

function TemplateDetail({ template, onBack }: { template: ServiceRoleTemplate; onBack(): void }) {
  const t = useTranslations("ServiceRoleTemplateDirectory");
  return <WorkspaceDetail title={`${t("detailTitle")} · ${template.id}`} onBack={onBack}>
    <Card>
      <div className={styles.sectionHeading}>
        <div><Badge status={template.status === "ACTIVE" ? "success" : "neutral"}>{t(`states.${template.status}`)}</Badge> <Badge>{t(`purposes.${template.spec.servicePurpose}`)}</Badge></div>
      </div>
      <Alert>{t("activeIsNotConsent")}</Alert>
      <dl className={styles.facts}>
        <div><dt>{t("fields.templateId")}</dt><dd><code>{template.id}</code></dd></div>
        <div><dt>{t("fields.templateVersion")}</dt><dd>v{template.version}</dd></div>
        <div><dt>{t("fields.product")}</dt><dd><code>{template.spec.product}</code></dd></div>
        <div><dt>{t("fields.servicePurpose")}</dt><dd>{t(`purposes.${template.spec.servicePurpose}`)} <small><code>{template.spec.servicePurpose}</code></small></dd></div>
        <div><dt>{t("fields.roleName")}</dt><dd><code>{template.spec.roleName}</code></dd></div>
        <div><dt>{t("fields.roleDescription")}</dt><dd>{template.spec.roleDescription || "—"}</dd></div>
        <div><dt>{t("fields.maxSession")}</dt><dd>{durationLabel(template.spec.maxSessionDurationSeconds)}</dd></div>
      </dl>
      <ServiceAuthorizationChain
        template={{ label: t(`states.${template.status}`), tone: template.status === "ACTIVE" ? "success" : "neutral" }}
        account={{ label: t("accountReadSeparately") }}
        binding={{ label: t("accountReadSeparately") }}
      />
      <section className={styles.stack} aria-labelledby="service-role-workloads">
        <div><h3 className={styles.detailTitle} id="service-role-workloads">{t("workloadTitle")}</h3><p className={styles.note}>{t("workloadHint")}</p></div>
        <Table aria-label={t("workloadTable")} mobileLayout="stack">
          <thead><tr><th scope="col">{t("fields.workloadKinds")}</th><th scope="col">{t("fields.bindAction")}</th><th scope="col">{t("fields.unbindAction")}</th></tr></thead>
          <tbody>{template.spec.workloads.map((workload) => <tr key={workload.resourceKind}>
            <td data-label={t("fields.workloadKinds")}><Badge>{workload.resourceKind}</Badge></td>
            <td data-label={t("fields.bindAction")}><code>{workload.bindAction}</code></td>
            <td data-label={t("fields.unbindAction")}><code>{workload.unbindAction}</code></td>
          </tr>)}</tbody>
        </Table>
      </section>
      <section className={styles.stack} aria-labelledby="service-role-policy-version">
        <div><h3 className={styles.detailTitle} id="service-role-policy-version">{t("policySnapshotTitle")}</h3><p className={styles.note}>{t("policySnapshotHint")}</p></div>
        <dl className={styles.facts}>
          <div><dt>{t("fields.policyId")}</dt><dd><code>{template.spec.policyVersion.policyId}</code></dd></div>
          <div><dt>{t("fields.policyVersionId")}</dt><dd><code>{template.spec.policyVersion.versionId}</code></dd></div>
          <div><dt>{t("fields.policyDigest")}</dt><dd><code>{template.spec.policyVersion.contentDigest}</code></dd></div>
          <div><dt>{t("fields.templateDigest")}</dt><dd><code>{template.contentDigest}</code></dd></div>
        </dl>
      </section>
      <Alert status="warning">{t("accountReadHint")}</Alert>
    </Card>
  </WorkspaceDetail>;
}

function TemplateDirectory({ client, onOpen }: { client: ServiceRoleTemplateClient; onOpen(template: ServiceRoleTemplate, trigger: HTMLButtonElement): void }) {
  const t = useTranslations("ServiceRoleTemplateDirectory");
  const [state, setState] = useState<TemplateState>({ status: "loading" });
  const request = useRef(0);
  const retry = useCallback(() => {
    const revision = ++request.current;
    setState({ status: "loading" });
    client.load().then((result) => { if (request.current === revision) setState(result); });
  }, [client]);
  useEffect(() => {
    const revision = ++request.current;
    client.load().then((result) => { if (request.current === revision) setState(result); });
    return () => { request.current += 1; };
  }, [client]);

  return <section className={styles.stack} aria-labelledby="service-role-template-directory-title">
    <div><h3 className={styles.detailTitle} id="service-role-template-directory-title">{t("title")}</h3><p className={styles.note}>{t("directoryHint")}</p></div>
    <Alert>{t("boundary")}</Alert>
    {state.status === "loading" ? <TableSkeleton label={t("loading")} rows={4} /> : null}
    {state.status !== "loading" && state.status !== "ready" ? <LoadFailure status={state.status} retry={retry} scope="templates" /> : null}
    {state.status === "ready" ? <>
      {state.directory.items.length ? <Table aria-label={t("tableLabel")} mobileLayout="stack">
        <thead><tr><th scope="col">{t("fields.template")}</th><th scope="col">{t("fields.roleName")}</th><th scope="col">{t("fields.workloadKinds")}</th><th scope="col">{t("fields.policySnapshot")}</th><th scope="col">{t("fields.templateState")}</th></tr></thead>
        <tbody>{state.directory.items.map((template) => <tr key={template.id}>
          <td data-label={t("fields.template")}><button className={styles.userLink} onClick={(event) => onOpen(template, event.currentTarget)}>{template.id}</button><small>v{template.version} · <code>{template.spec.product}</code></small></td>
          <td data-label={t("fields.roleName")}><code>{template.spec.roleName}</code><small>{template.spec.roleDescription}</small></td>
          <td data-label={t("fields.workloadKinds")}><div className={styles.roleTags}>{template.spec.workloads.map((workload) => <Badge key={workload.resourceKind}>{workload.resourceKind}</Badge>)}</div></td>
          <td data-label={t("fields.policySnapshot")}><code>{template.spec.policyVersion.policyId}</code><small>{template.spec.policyVersion.versionId}</small></td>
          <td data-label={t("fields.templateState")}><Badge status={template.status === "ACTIVE" ? "success" : "neutral"}>{t(`states.${template.status}`)}</Badge><small>{t("notAccountState")}</small></td>
        </tr>)}</tbody>
      </Table> : <EmptyState title={t("emptyTitle")} description={t("emptyDescription")} />}
      <Table.Footer note={t("footerNote")} />
    </> : null}
  </section>;
}

function RelationDetail({ client, roleId, initialName, onBack }: { client: ServiceLinkedRoleClient; roleId: string; initialName: string; onBack(): void }) {
  const t = useTranslations("ServiceAuthorizationDirectory");
  const [state, setState] = useState<{ status: "loading" } | ServiceLinkedRoleAccessLoad>({ status: "loading" });
  const [pages, setPages] = useState<Array<{ status: "ready"; access: ServiceLinkedRoleAccess }>>([]);
  const [pageIndex, setPageIndex] = useState(0);
  const [paging, setPaging] = useState(false);
  const [pageFailure, setPageFailure] = useState<FailureStatus | null>(null);
  const request = useRef(0);
  const pagingRequest = useRef(false);
  const load = useCallback(() => {
    const revision = ++request.current;
    setState({ status: "loading" }); setPages([]); setPageIndex(0); setPageFailure(null);
    client.read(roleId).then((result) => {
      if (request.current !== revision) return;
      setState(result);
      if (result.status === "ready") setPages([result]);
    });
  }, [client, roleId]);
  useEffect(() => {
    const revision = ++request.current;
    client.read(roleId).then((result) => {
      if (request.current !== revision) return;
      setState(result);
      if (result.status === "ready") setPages([result]);
    });
    return () => { request.current += 1; };
  }, [client, roleId]);
  const current = pages[pageIndex]?.access ?? (state.status === "ready" ? state.access : null);
  const nextPage = async () => {
    if (!current || pagingRequest.current || !current.nextAfter) return;
    if (pages[pageIndex + 1]) { setPageIndex((value) => value + 1); setPageFailure(null); return; }
    pagingRequest.current = true;
    setPaging(true); setPageFailure(null);
    const revision = request.current;
    const result = await client.read(roleId, current.nextAfter);
    if (request.current !== revision) return;
    if (result.status === "ready") {
      const relation = pages[0]?.access.relation;
      const known = new Set(pages.flatMap((page) => page.access.bindings.map((binding) => binding.id)));
      if (!relation || !sameRelation(result.access.relation, relation) || result.access.bindings.some((binding) => known.has(binding.id))) setPageFailure("unavailable");
      else { setPages((value) => [...value, result]); setPageIndex((value) => value + 1); }
    } else setPageFailure(result.status);
    pagingRequest.current = false;
    setPaging(false);
  };

  const relation = current?.relation;
  return <WorkspaceDetail title={relation?.role.name ?? initialName} onBack={onBack}>
    <Card>
      {state.status === "loading" ? <TableSkeleton label={t("detail.loading")} rows={5} header={false} /> : null}
      {state.status !== "loading" && state.status !== "ready" ? <LoadFailure status={state.status} retry={load} scope="relations" /> : null}
      {current && relation ? <div className={styles.stack}>
        <div className={styles.sectionHeading}><div><Badge status={relation.role.status === "ACTIVE" ? "success" : "neutral"}>{t(`states.${relation.role.status}`)}</Badge> <Badge>SERVICE_LINKED</Badge></div></div>
        <Alert>{t("detail.boundary")}</Alert>
        <dl className={styles.facts}>
          <div><dt>{t("fields.role")}</dt><dd><code>{relation.role.name}</code><small>{relation.role.description}</small></dd></div>
          <div><dt>{t("fields.roleId")}</dt><dd><code>{relation.role.id}</code></dd></div>
          <div><dt>{t("fields.targetAccount")}</dt><dd><code>{relation.role.accountId}</code></dd></div>
          <div><dt>{t("fields.servicePrincipal")}</dt><dd><code>{relation.servicePrincipal.principalId}</code><small>{relation.servicePrincipal.installationId} · {t(`purposes.${relation.servicePrincipal.purpose}`)}</small></dd></div>
          <div><dt>{t("fields.maxSession")}</dt><dd>{durationLabel(relation.role.maxSessionDurationSeconds)}</dd></div>
          <div><dt>{t("fields.resourceVersion")}</dt><dd>v{relation.role.resourceVersion}</dd></div>
        </dl>
        <ServiceAuthorizationChain
          template={{ label: t("detail.exactTemplate"), tone: "neutral" }}
          account={{ label: t(`states.${relation.role.status}`), tone: relation.role.status === "ACTIVE" ? "success" : "neutral" }}
          binding={{ label: t("detail.bindingHistory"), tone: current.bindings.some((binding) => binding.status === "ACTIVE") ? "success" : "neutral" }}
        />
        <section className={styles.stack} aria-labelledby="service-linked-role-authority">
          <div><h3 className={styles.detailTitle} id="service-linked-role-authority">{t("detail.authorityTitle")}</h3><p className={styles.note}>{t("detail.authorityHint")}</p></div>
          <dl className={styles.facts}>
            <div><dt>{t("fields.template")}</dt><dd><code>{relation.template.id} @v{relation.template.version}</code></dd></div>
            <div><dt>{t("fields.templateDigest")}</dt><dd><code>{relation.template.contentDigest}</code></dd></div>
            <div><dt>{t("fields.permissionCeiling")}</dt><dd><code>{relation.permissionCeiling.policyId} @ {relation.permissionCeiling.versionId}</code></dd></div>
            <div><dt>{t("fields.policyDigest")}</dt><dd><code>{relation.permissionCeiling.contentDigest}</code></dd></div>
          </dl>
        </section>
        <section className={styles.stack} aria-labelledby="service-linked-role-bindings">
          <div><h3 className={styles.detailTitle} id="service-linked-role-bindings">{t("detail.bindingsTitle")}</h3><p className={styles.note}>{t("detail.bindingsHint")}</p></div>
          {current.bindings.length ? <Table aria-label={t("detail.bindingsTable")} mobileLayout="stack">
            <thead><tr><th scope="col">{t("fields.workload")}</th><th scope="col">{t("fields.bindingState")}</th><th scope="col">{t("fields.binding")}</th><th scope="col">{t("fields.lifecycle")}</th></tr></thead>
            <tbody>{current.bindings.map((binding) => <tr key={binding.id}>
              <td data-label={t("fields.workload")}><strong>{binding.workload.kind}</strong><small><code>{binding.workload.id}</code></small></td>
              <td data-label={t("fields.bindingState")}><Badge status={binding.status === "ACTIVE" ? "success" : "neutral"}>{t(`bindingStates.${binding.status}`)}</Badge></td>
              <td data-label={t("fields.binding")}><code>{binding.id}</code><small>v{binding.resourceVersion} · {binding.template.id} @v{binding.template.version}</small></td>
              <td data-label={t("fields.lifecycle")}><small>{t("detail.created")} <WorkspaceTime value={binding.createdAt} /></small><small>{binding.revokedAt ? <>{t("detail.revoked")} <WorkspaceTime value={binding.revokedAt} /></> : <>{t("detail.updated")} <WorkspaceTime value={binding.updatedAt} /></>}</small></td>
            </tr>)}</tbody>
          </Table> : <EmptyState title={t("detail.emptyBindingsTitle")} description={t("detail.emptyBindingsDescription")} />}
          <CursorFooter page={pageIndex + 1} hasNext={Boolean(current.nextAfter || pages[pageIndex + 1])} busy={paging} previous={() => { setPageIndex((value) => Math.max(0, value - 1)); setPageFailure(null); }} next={nextPage}
            note={current.nextAfter ? t("detail.moreBindings") : t("detail.completeBindings", { count: current.bindings.length })} />
          {pageFailure ? <Alert status="warning">{t(`errors.relations.${pageFailure}.description`)}</Alert> : null}
        </section>
        <Alert>{t("detail.activeBindingIsNotSession")}</Alert>
        <Alert status="warning">{t("detail.noCommands")}</Alert>
      </div> : null}
    </Card>
  </WorkspaceDetail>;
}

export function AccountServiceAuthorizations({ relations, templates, onBack }: {
  relations: ServiceLinkedRoleClient | null;
  templates: ServiceRoleTemplateClient | null;
  onBack(): void;
}) {
  const t = useTranslations("ServiceAuthorizationDirectory");
  const [section, setSection] = useState(relations ? "authorizations" : "templates");
  const [selection, setSelection] = useState<Selection | null>(null);
  const returnFocus = useRef<HTMLButtonElement | null>(null);
  const previousSelection = useRef<Selection | null>(selection);
  useLayoutEffect(() => {
    if (previousSelection.current && !selection) returnFocus.current?.focus({ preventScroll: true });
    previousSelection.current = selection;
  }, [selection]);

  if (selection?.kind === "relation" && relations) return <RelationDetail client={relations} roleId={selection.roleId} initialName={selection.roleName} onBack={() => setSelection(null)} />;
  if (selection?.kind === "template") return <TemplateDetail template={selection.template} onBack={() => setSelection(null)} />;

  return <Card aria-description={t("hint")}>
    <ContentPage.Heading title={t("title")} scrollKey="service-authorization-directory" back={{ label: t("backToRoles"), onClick: onBack }} focus />
    <div className={styles.policyDirectoryIntro}><p>{t("hint")}</p><p>{t("boundary")}</p></div>
    <Tabs.Root value={section} onValueChange={setSection}>
      <Tabs.List aria-label={t("sectionsLabel")}>
        {relations ? <Tabs.Trigger value="authorizations">{t("sections.authorizations")}</Tabs.Trigger> : null}
        {templates ? <Tabs.Trigger value="templates">{t("sections.templates")}</Tabs.Trigger> : null}
      </Tabs.List>
      {relations ? <Tabs.Content className={styles.stack} value="authorizations">{section === "authorizations" ? <RelationDirectory client={relations} onOpen={(listing, trigger) => { returnFocus.current = trigger; setSelection({ kind: "relation", roleId: listing.relation.role.id, roleName: listing.relation.role.name }); }} /> : null}</Tabs.Content> : null}
      {templates ? <Tabs.Content className={styles.stack} value="templates">{section === "templates" ? <TemplateDirectory client={templates} onOpen={(template, trigger) => { returnFocus.current = trigger; setSelection({ kind: "template", template }); }} /> : null}</Tabs.Content> : null}
    </Tabs.Root>
  </Card>;
}
