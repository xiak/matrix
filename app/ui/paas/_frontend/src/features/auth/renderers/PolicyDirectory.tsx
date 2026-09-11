"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useLocale, useTranslations } from "next-intl";
import { Plus } from "lucide-react";
import { Badge, Button, Card, ContentPage, EmptyState, TableActions, TableSelectionCell, TablePagination, TableToolbar, Select, Table, Tabs } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { defaultPolicyDirectoryView, useAccountAccess, type PolicyDirectoryView } from "../application/AccountAccessProvider";
import { type AccessPolicy, type AccessWorkspace } from "../domain/accessWorkspace";
import { expandPolicyActions, policyServices } from "../domain/policyLanguage";
import { WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./PolicyWorkspace.module.css";

const localizedPresets = ["policy-admin", "policy-read", "policy-delivery", "policy-audit"] as const;
export function usePolicyDescription() {
  const t = useTranslations("PolicyWorkspace");
  return useCallback((policy: AccessPolicy) => {
    const id = localizedPresets.find((id) => id === policy.id);
    return policy.kind === "system" && id ? t(`presetDescriptions.${id}`) : policy.description;
  }, [t]);
}

// Policy-specific directory complexity lives here, not in the generic collection
// used by small identity directories. All controls still use the public UI owner.
export function PolicyDirectory({ workspace, onCreate, onOpen, onAssociate }: {
  workspace: AccessWorkspace; onCreate(): void; onOpen(id: string): void; onAssociate(policies: AccessPolicy[], additive?: boolean): void;
}) {
  const t = useTranslations("PolicyWorkspace"), w = useTranslations("IamWorkspace"), r = useTranslations("PolicyRules");
  const locale = useLocale();
  const toolbarLabels = useTableToolbarLabels();
  const describe = usePolicyDescription();
  const { policyDirectoryView, busy } = useAccountAccess();
  const collection = useTranslations("Collection");
  const [view, setView] = useState(policyDirectoryView.read);
  const [selection, setSelection] = useState<string[]>([]);
  useEffect(() => { policyDirectoryView.remember(view); }, [view, policyDirectoryView]);
  const directory = useMemo(() => workspace.policies.map((policy) => {
    const document = policy.versions.find((version) => version.id === policy.defaultVersion)!.document;
    const actions = expandPolicyActions(document.statement.flatMap((statement) => statement.action));
    const services = [...new Set(actions.map((action) => action.service))];
    const description = describe(policy);
    const keywords = [policy.id, policy.name, description, ...policy.tags.flatMap((tag) => [tag.key, tag.value]),
      ...services.map((service) => r(`services.${service}`))].join(" ").normalize("NFKC").toLowerCase();
    return { policy, description, services, keywords };
  }), [workspace.policies, describe, r]);
  const matches = useMemo(() => {
    const words = view.query.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean);
    return directory.filter((row) => (view.kind === "all" || row.policy.kind === view.kind) &&
      (view.service === "all" || row.services.some((service) => service === view.service)) &&
      (view.category === "all" || row.policy.systemCategory === view.category) && words.every((word) => row.keywords.includes(word)))
      .sort((a, b) => view.sort === "name" ? a.policy.name.localeCompare(b.policy.name, locale) :
        (view.sort === "newest" ? -1 : 1) * a.policy.updatedAt.localeCompare(b.policy.updatedAt) || a.policy.name.localeCompare(b.policy.name, locale));
  }, [directory, view, locale]);
  const pages = Math.max(1, Math.ceil(matches.length / view.pageSize));
  const page = Math.min(view.page, pages);
  const visible = matches.slice((page - 1) * view.pageSize, page * view.pageSize);
  const selected = workspace.policies.filter((policy) => selection.includes(policy.id));
  const allSelected = visible.length > 0 && visible.every((row) => selection.includes(row.policy.id));
  const someSelected = visible.some((row) => selection.includes(row.policy.id));
  const change = (next: Partial<PolicyDirectoryView>) => setView((current) => ({ ...current, page: 1, ...next }));
  const reset = () => setView({ ...defaultPolicyDirectoryView, pageSize: view.pageSize, sort: view.sort });
  const customOnly = view.kind === "custom";
  return <Tabs.Root className={styles.directory} value={view.kind} onValueChange={(kind) => change({ kind, service: "all", category: "all" })}>
    <ContentPage.Heading title={w("policies")} actions={<>
      <Button size="small" disabled={busy} onClick={onCreate}><Plus aria-hidden="true" />{t("createCustomPolicy")}</Button>
      <TableActions label={collection("moreActions")} disabled={busy || !selected.length} hint={collection("selectFirst")}
        selectionLabel={selected.length ? t("selected", { count: selected.length }) : undefined} clearLabel={t("clearSelected")} onClear={() => setSelection([])}
        actions={[{ id: "associate", label: selected.length > 1 ? t("batchAttach") : w("associateTargets"), onSelect: () => onAssociate(selected, selected.length > 1) }]} />
    </>} />
    <Card>
      <div className={styles.directoryHeading}>
        <Tabs.List aria-label={w("type")}>
          <Tabs.Trigger value="all">{t("allPolicies")}</Tabs.Trigger><Tabs.Trigger value="system">{w("system")}</Tabs.Trigger><Tabs.Trigger value="custom">{w("custom")}</Tabs.Trigger>
        </Tabs.List>
      </div>
      <Tabs.Content className={styles.directoryContent} value={view.kind}>
      <TableToolbar labels={toolbarLabels} search={{ label: t("searchPolicies"), value: view.query, onChange: (query) => change({ query }) }}
        status={t("resultCount", { count: matches.length })} filters={customOnly ? [] : [
          { id: "service", label: t("product"), value: view.service, onChange: (service) => change({ service }), options: [{ value: "all", label: t("allServices") }, ...policyServices.map((value) => ({ value, label: r(`services.${value}`) }))] },
          { id: "category", label: t("permissionCategory"), value: view.category, onChange: (category) => change({ category }), options: [{ value: "all", label: t("allCategories") }, ...(["global", "product"] as const).map((value) => ({ value, label: t(`categories.${value}`) }))] }
        ]} tools={<Select controlSize="small" aria-label={t("sort")} value={view.sort} onValueChange={(sort) => change({ sort })} options={[{ value: "name", label: t("nameSort") }, { value: "newest", label: t("newest") }, { value: "oldest", label: t("oldest") }]} />} />
      <Table aria-label={w("policies")} className={styles.policyTable} data-custom-only={customOnly || undefined}>
        <thead><tr><TableSelectionCell header label={t("selectPage")} checked={allSelected ? true : someSelected ? "mixed" : false} disabled={busy || !visible.length || (!allSelected && new Set([...selection, ...visible.map((row) => row.policy.id)]).size > 30)} onChange={(checked) => setSelection(!checked ? selection.filter((id) => !visible.some((row) => row.policy.id === id)) : [...new Set([...selection, ...visible.map((row) => row.policy.id)])])} />
          <th scope="col" className={styles.nameCell}>{t("policyName")}</th>{!customOnly ? <><th scope="col" className={styles.productCell}>{t("product")}</th><th scope="col" className={styles.categoryCell}>{t("permissionCategory")}</th></> : null}<th scope="col">{w("description")}</th><th scope="col" className={styles.timeCell}>{t("updatedAt")}</th><th scope="col" className={styles.operationCell}>{w("actions")}</th></tr></thead>
        <tbody>{visible.map(({ policy, description, services }) => <tr key={policy.id} data-selected={selection.includes(policy.id) || undefined}>
          <TableSelectionCell label={t("selectPolicy", { name: policy.name })} checked={selection.includes(policy.id)} disabled={busy || !selection.includes(policy.id) && selection.length >= 30} onChange={(checked) => setSelection(checked ? [...selection, policy.id] : selection.filter((id) => id !== policy.id))} />
          <td><div className={styles.policyIdentity}><button className={styles.nameLink} title={policy.name} onClick={() => onOpen(policy.id)}>{policy.name}</button>{view.kind === "all" && policy.kind === "custom" ? <Badge>{w("custom")}</Badge> : null}</div></td>
          {!customOnly ? <><td>{policy.systemCategory === "product" ? <span title={services.map((service) => r(`services.${service}`)).join(" · ")}>{services.map((service) => r(`services.${service}`)).join(" · ")}</span> : "—"}</td><td>{policy.systemCategory ? t(`categories.${policy.systemCategory}`) : "—"}</td></> : null}
          <td><span className={styles.description} title={description}>{description || "—"}</span></td>
          <td><WorkspaceTime value={policy.updatedAt} /></td>
          <td><button className={styles.serviceLink} disabled={busy} onClick={() => onAssociate([policy])}>{t("authorize")}</button></td>
        </tr>)}</tbody>
      </Table>
      {!matches.length ? <EmptyState title={w("noResults")} description={w("noResultsHint")} action={<Button variant="secondary" onClick={reset}>{toolbarLabels.resetQuery}</Button>} /> : null}
      <Card.Footer><TablePagination page={page} pages={pages} pageSize={view.pageSize} disabled={busy} onPageChange={(page) => change({ page })} onPageSizeChange={(pageSize) => change({ pageSize })}
        labels={{ summary: w("page", { page, pages }), pageSize: w("pageSize"), previous: w("previous"), next: w("next") }} /></Card.Footer>
      </Tabs.Content>
    </Card>
    <p className={styles.note}>{t("batchLimit")} {t("categoryHint")}</p>
  </Tabs.Root>;
}
