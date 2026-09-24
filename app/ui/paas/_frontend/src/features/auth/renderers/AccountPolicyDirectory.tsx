"use client";

import { useEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, ContentPage, EmptyState, Table, TablePagination, TableSkeleton, TableToolbar, Tabs } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { useAccountAccess, type AccountPolicyReadClient, type AccountPolicyReadLoad, type AccountPolicyVersionDirectoryLoad } from "../application/AccountAccessProvider";
import type { AccountPolicy, AccountPolicyVersion } from "../domain/accounts";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceDetail, WorkspaceTime } from "./AccessWorkspaceUi";
import { AccountAuthorizationProfileCatalog } from "./AccountAuthorizationProfileCatalog";
import styles from "./AccountAccessRenderer.module.css";

type PolicyDetailState = { status: "loading" } | AccountPolicyReadLoad;
type PolicyVersionDirectoryState = { status: "loading" } | AccountPolicyVersionDirectoryLoad;

function PolicyStatementTable({ version }: { version: AccountPolicyVersion }) {
  const t = useTranslations("AccountPolicyDirectory");
  return <section className={styles.catalogNotice}>
    <h3 className={styles.stepTitle}>{t("statementTitle", { count: version.document.statements.length })}</h3>
    <Table aria-label={t("statementTable")} mobileLayout="stack" className={styles.policyStatementTable}>
      <thead><tr><th scope="col">{t("statement")}</th><th scope="col">{t("effect")}</th><th scope="col">{t("declaredActions")}</th><th scope="col">{t("resources")}</th><th scope="col">{t("conditions")}</th></tr></thead>
      <tbody>{version.document.statements.map((statement) => {
        const resolved = version.compilation?.resolvedStatements.find((entry) => entry.sid === statement.sid);
        return <tr key={statement.sid}>
          <td data-label={t("statement")}><code>{statement.sid}</code></td>
          <td data-label={t("effect")}><Badge status={statement.effect === "DENY" ? "danger" : "success"}>{t(statement.effect === "DENY" ? "deny" : "allow")}</Badge></td>
          <td data-label={t("declaredActions")}><div className={styles.policyStackedValues}>{statement.actions.map((action) => <code key={action}>{action}</code>)}
            {resolved ? <div className={styles.policyResolved}><strong>{t("frozenActions")}</strong>{resolved.actions.map((action) => <code key={action}>{action}</code>)}</div> : null}</div></td>
          <td data-label={t("resources")}><div className={styles.policyStackedValues}>{statement.resources.map((resource) => <code key={`${resource.kind}:${resource.match}:${resource.id ?? ""}`}>{resource.kind} · {t(`matches.${resource.match}`)}{resource.id ? ` · ${resource.id}` : ""}</code>)}</div></td>
          <td data-label={t("conditions")}><div className={styles.policyStackedValues}>{statement.conditions?.map((condition) => <code key={`${condition.key}:${condition.operator}`}>{condition.key} · {condition.operator} · {condition.values.join(", ")}</code>) ?? t("none")}</div></td>
        </tr>;
      })}</tbody>
    </Table>
  </section>;
}

function PolicyVersionDocument({ version, title }: { version: AccountPolicyVersion; title: string }) {
  const t = useTranslations("AccountPolicyDirectory");
  return <section className={styles.catalogNotice} aria-label={title}>
    <div className={styles.catalogDetailHeading}><h2>{title}</h2><Badge>{t("contractVersion", { version: version.contractVersion })}</Badge></div>
    <p className={styles.note}>{t("documentNotice")}</p>
    <dl className={styles.catalogFacts}>
      <div><dt>{t("digest")}</dt><dd><code>{version.contentDigest}</code></dd></div>
      <div><dt>{t("frozenProfiles")}</dt><dd>{version.compilation ? version.compilation.profiles.map((item) => `${item.product} @ ${item.revision}`).join(" · ") : t("legacyVersion")}</dd></div>
    </dl>
    <PolicyStatementTable version={version} />
    <details className={styles.policyRawDocument}><summary>{t("rawDocument")}</summary><pre tabIndex={0}>{JSON.stringify(version.document, null, 2)}</pre></details>
  </section>;
}

function AccountPolicyVersions({ policy, listVersions, readVersion }: {
  policy: AccountPolicy;
  listVersions: NonNullable<AccountPolicyReadClient["listVersions"]>;
  readVersion: NonNullable<AccountPolicyReadClient["readVersion"]>;
}) {
  const t = useTranslations("AccountPolicyDirectory");
  const [state, setState] = useState<PolicyVersionDirectoryState>({ status: "loading" });
  const [revision, setRevision] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<PolicyDetailState>({ status: "loading" });
  const [selectedRevision, setSelectedRevision] = useState(0);
  const title = useRef<HTMLHeadingElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const opener = useRef<string | null>(null);
  useEffect(() => {
    let current = true;
    void listVersions(policy.id).then((result) => { if (current) setState(result); });
    return () => { current = false; };
  }, [listVersions, policy.id, revision]);
  useEffect(() => {
    if (!selectedId) return;
    let current = true;
    void readVersion(policy.id, selectedId).then((result) => { if (current) setSelected(result); });
    return () => { current = false; };
  }, [readVersion, policy.id, selectedId, selectedRevision]);
  useEffect(() => {
    if (selectedId) title.current?.focus();
    else if (opener.current) {
      const target = Array.from(list.current?.querySelectorAll<HTMLButtonElement>("button[data-version-id]") ?? [])
        .find((item) => item.dataset.versionId === opener.current);
      target?.focus(); opener.current = null;
    }
  }, [selectedId]);
  if (selectedId) return <div className={styles.catalogNotice}>
    <div><Button variant="secondary" onClick={() => setSelectedId(null)}>{t("backToVersions")}</Button></div>
    <h2 ref={title} tabIndex={-1} className={styles.stepTitle}>{t("versionInspection", { version: selectedId })}</h2>
    {selected.status === "loading" ? <TableSkeleton label={t("loadingVersion")} rows={3} header={false} /> :
      selected.status !== "ready" ? <div className={styles.catalogNotice}><Alert status={selected.status === "forbidden" ? "warning" : "danger"}>{t(`versionErrors.${selected.status}`)}</Alert>
        {selected.status !== "expired" ? <div><Button variant="secondary" onClick={() => { setSelected({ status: "loading" }); setSelectedRevision((value) => value + 1); }}>{t("retry")}</Button></div> : null}</div> :
      <PolicyVersionDocument version={selected.detail.version} title={t("versionDocument", { version: selectedId })} />}
  </div>;
  return <div ref={list} className={styles.catalogNotice}>
    <p className={styles.note}>{t("versionDirectoryNotice")}</p>
    {state.status === "loading" ? <TableSkeleton label={t("loadingVersions")} rows={3} header={false} /> :
      state.status !== "ready" ? <div className={styles.catalogNotice}><Alert status={state.status === "forbidden" ? "warning" : "danger"}>{t(`versionErrors.${state.status}`)}</Alert>
        {state.status !== "expired" ? <div><Button variant="secondary" onClick={() => { setState({ status: "loading" }); setRevision((value) => value + 1); }}>{t("retry")}</Button></div> : null}</div> : <>
        <p>{t("versionCount", { count: state.directory.items.length })}</p>
        <Table aria-label={t("versionTable")} mobileLayout="stack" className={styles.policyVersionTable}>
          <thead><tr><th scope="col">{t("versionId")}</th><th scope="col">{t("defaultVersion")}</th><th scope="col">{t("versionContract")}</th><th scope="col">{t("digest")}</th></tr></thead>
          <tbody>{state.directory.items.map((item) => <tr key={item.versionId}>
            <td data-label={t("versionId")}><button className={styles.userLink} data-version-id={item.versionId} onClick={() => { opener.current = item.versionId; setSelected({ status: "loading" }); setSelectedId(item.versionId); }}>{item.versionId}</button></td>
            <td data-label={t("defaultVersion")}>{item.versionId === state.directory.policy.defaultVersionId ? <Badge status="success">{t("currentDefault")}</Badge> : "—"}</td>
            <td data-label={t("versionContract")}>{t("contractVersion", { version: item.contractVersion })}</td>
            <td data-label={t("digest")}><code>{item.contentDigest}</code></td>
          </tr>)}</tbody>
        </Table>
      </>}
  </div>;
}

function AccountPolicyDetailView({ policy, client, onBack }: { policy: AccountPolicy; client: AccountPolicyReadClient | null; onBack(): void }) {
  const t = useTranslations("AccountPolicyDirectory");
  const [state, setState] = useState<PolicyDetailState>({ status: "loading" });
  const [revision, setRevision] = useState(0);
  const [section, setSection] = useState("document");
  const [versionsMounted, setVersionsMounted] = useState(false);
  useEffect(() => {
    if (policy.scope !== "TENANT" || !client) return;
    let current = true;
    void client.read(policy.id).then((result) => { if (current) setState(result); });
    return () => { current = false; };
  }, [client, policy.id, policy.scope, revision]);
  const detail = state.status === "ready" ? state.detail : null;
  const documentRegion = policy.scope === "INSTALLATION" ? <Alert status="info">{t("platformDetailUnavailable")}</Alert> :
    !client ? <Alert status="danger">{t("errors.unavailable")}</Alert> :
    state.status === "loading" ? <TableSkeleton label={t("loadingDetail")} rows={3} header={false} /> :
    state.status !== "ready" ? <div className={styles.catalogNotice}><Alert status={state.status === "forbidden" ? "warning" : "danger"}>{t(`errors.${state.status}`)}</Alert>
      {state.status !== "expired" ? <div><Button variant="secondary" onClick={() => { setState({ status: "loading" }); setRevision((value) => value + 1); }}>{t("retry")}</Button></div> : null}</div> :
    detail ? <PolicyVersionDocument version={detail.version} title={t("defaultDocument")} /> : null;
  return <WorkspaceDetail title={policy.displayName} onBack={onBack}>
    <p className={styles.note}>{t("detailNotice")}</p>
    <dl className={styles.catalogFacts}>
      <div><dt>{t("policyId")}</dt><dd><code>{policy.id}</code></dd></div>
      <div><dt>{t("management")}</dt><dd>{t(policy.management === "SYSTEM" ? "system" : "customer")}</dd></div>
      <div><dt>{t("scope")}</dt><dd>{t(policy.scope === "TENANT" ? "tenant" : "installation")}</dd></div>
      <div><dt>{t("defaultVersion")}</dt><dd><code>{detail?.version.versionId ?? policy.defaultVersionId}</code></dd></div>
      <div><dt>{t("updated")}</dt><dd><WorkspaceTime value={detail?.policy.updatedAt ?? policy.updatedAt} /></dd></div>
    </dl>
    {policy.management === "CUSTOMER" && policy.scope === "TENANT" && client?.listVersions && client.readVersion ?
      <Tabs.Root value={section} onValueChange={(next) => { setSection(next); if (next === "versions") setVersionsMounted(true); }}>
        <Tabs.List aria-label={t("detailSections")}><Tabs.Trigger value="document">{t("defaultDocument")}</Tabs.Trigger><Tabs.Trigger value="versions">{t("versionsTab")}</Tabs.Trigger></Tabs.List>
        <Tabs.Content value="document">{documentRegion}</Tabs.Content>
        <Tabs.Content value="versions" forceMount={versionsMounted || undefined}>{versionsMounted ? <AccountPolicyVersions policy={policy} listVersions={client.listVersions} readVersion={client.readVersion} /> : null}</Tabs.Content>
      </Tabs.Root> : documentRegion}
  </WorkspaceDetail>;
}

export function AccountPolicyDirectory({ scene, entityId, onOpen }: { scene: AccountAccessScene; entityId?: string; onOpen(id?: string): void }) {
  const t = useTranslations("AccountPolicyDirectory");
  const toolbarLabels = useTableToolbarLabels();
  const client = useAccountAccess().policyRead;
  const selected = entityId ? scene.policies.find((policy) => policy.id === entityId) : null;
  const [query, setQuery] = useState("");
  const [management, setManagement] = useState("all");
  const [scope, setScope] = useState("all");
  const [status, setStatus] = useState("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [section, setSection] = useState("policies");
  const [catalogMounted, setCatalogMounted] = useState(false);
  const words = query.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean);
  const filtered = scene.policies.filter((policy) => {
    const text = `${policy.displayName} ${policy.id}`.normalize("NFKC").toLowerCase();
    return words.every((word) => text.includes(word)) &&
      (management === "all" || policy.management === management) &&
      (scope === "all" || policy.scope === scope) &&
      (status === "all" || policy.status === status);
  });
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pages);
  const rows = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const change = (update: () => void) => { update(); setPage(1); };
  const reset = () => { setQuery(""); setManagement("all"); setScope("all"); setStatus("all"); setPage(1); };
  const partial = !scene.tenantPoliciesAvailable || !scene.platformPoliciesAvailable;

  if (entityId) return selected
    ? <AccountPolicyDetailView key={`${client?.accountId ?? scene.accountId}:${client?.sessionRevision ?? "none"}:${entityId}`} policy={selected} client={client} onBack={() => onOpen()} />
    : <EmptyState title={t("notFound")} description={t("notFoundHint")} action={<Button variant="secondary" onClick={() => onOpen()}>{t("back")}</Button>} />;

  return <Card>
    <ContentPage.Heading title={t("title")} scrollKey="policy-directory" />
    <Tabs.Root value={section} onValueChange={(next) => { setSection(next); if (next === "profiles") setCatalogMounted(true); }}>
      <Tabs.List aria-label={t("sections")} className={styles.policyDirectoryTabs}><Tabs.Trigger value="policies">{t("policiesTab")}</Tabs.Trigger><Tabs.Trigger value="profiles">{t("profilesTab")}</Tabs.Trigger></Tabs.List>
      <Tabs.Content value="policies">
        <div className={styles.policyDirectoryIntro}>
          <p>{t("description")}</p>
          <p>{t("managementSnapshot")}</p>
        </div>
        {partial ? <Alert status="warning">{t(scene.tenantPoliciesAvailable ? "platformUnavailable" : "tenantUnavailable")}</Alert> : null}
        <TableToolbar labels={toolbarLabels}
          search={{ label: t("search"), placeholder: t("searchPlaceholder"), value: query, onChange: (value) => change(() => setQuery(value)) }}
          status={t("resultCount", { count: filtered.length })}
          filters={[
            { id: "management", label: t("management"), value: management, onChange: (value) => change(() => setManagement(value)), options: [{ value: "all", label: t("all") }, { value: "SYSTEM", label: t("system") }, { value: "CUSTOMER", label: t("customer") }] },
            { id: "scope", label: t("scope"), value: scope, onChange: (value) => change(() => setScope(value)), options: [{ value: "all", label: t("all") }, { value: "TENANT", label: t("tenant") }, { value: "INSTALLATION", label: t("installation") }] },
            { id: "status", label: t("status"), value: status, onChange: (value) => change(() => setStatus(value)), options: [{ value: "all", label: t("all") }, { value: "ACTIVE", label: t("active") }, { value: "RETIRED", label: t("retired") }] }
          ]} />
        {rows.length ? <Table aria-label={t("table")} className={styles.policyMetadataTable}>
          <thead><tr><th scope="col">{t("policy")}</th><th scope="col">{t("management")}</th><th scope="col">{t("scope")}</th><th scope="col">{t("status")}</th><th scope="col">{t("defaultVersion")}</th><th scope="col">{t("updated")}</th></tr></thead>
          <tbody>{rows.map((policy) => <tr key={policy.id}>
            <td><button className={styles.userLink} onClick={() => onOpen(policy.id)}>{policy.displayName}</button><small className={styles.userIdentifier}>{policy.id}</small></td>
            <td><Badge>{t(policy.management === "SYSTEM" ? "system" : "customer")}</Badge></td>
            <td>{t(policy.scope === "TENANT" ? "tenant" : "installation")}</td>
            <td><Badge status={policy.status === "ACTIVE" ? "success" : "neutral"}>{t(policy.status === "ACTIVE" ? "active" : "retired")}</Badge></td>
            <td>{policy.defaultVersionId}</td>
            <td><WorkspaceTime value={policy.updatedAt} /></td>
          </tr>)}</tbody>
        </Table> : <EmptyState title={t(scene.policies.length ? "noResults" : "empty")} description={t(scene.policies.length ? "noResultsHint" : "emptyHint")} action={scene.policies.length ? <Button variant="secondary" onClick={reset}>{toolbarLabels.resetQuery}</Button> : undefined} />}
        <Table.Footer note={t("completeSnapshot", { count: scene.policies.length })}><TablePagination page={currentPage} pages={pages} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} labels={{ summary: t("page", { page: currentPage, pages }), pageSize: t("pageSize"), previous: t("previous"), next: t("next") }} /></Table.Footer>
      </Tabs.Content>
      <Tabs.Content forceMount={catalogMounted || undefined} value="profiles">{catalogMounted ? <AccountAuthorizationProfileCatalog /> : null}</Tabs.Content>
    </Tabs.Root>
  </Card>;
}
