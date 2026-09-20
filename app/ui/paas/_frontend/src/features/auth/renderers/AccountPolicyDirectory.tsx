"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, ContentPage, EmptyState, Table, TablePagination, TableToolbar, Tabs } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceTime } from "./AccessWorkspaceUi";
import { AccountAuthorizationProfileCatalog } from "./AccountAuthorizationProfileCatalog";
import styles from "./AccountAccessRenderer.module.css";

export function AccountPolicyDirectory({ scene }: { scene: AccountAccessScene }) {
  const t = useTranslations("AccountPolicyDirectory");
  const toolbarLabels = useTableToolbarLabels();
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
            <td><strong>{policy.displayName}</strong><small className={styles.userIdentifier}>{policy.id}</small></td>
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
