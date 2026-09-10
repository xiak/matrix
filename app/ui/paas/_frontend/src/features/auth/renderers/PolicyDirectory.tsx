"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useLocale, useTranslations } from "next-intl";
import { ChevronLeft, ChevronRight, Plus } from "lucide-react";
import { Badge, Button, Card, Checkbox, ContentPage, EmptyState, TableToolbar, Select, Table, Tabs } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { defaultPolicyDirectoryView, useAccountAccess, type PolicyDirectoryView } from "../application/AccountAccessProvider";
import { policyAssociationCount, type AccessPolicy, type AccessWorkspace } from "../domain/accessWorkspace";
import { expandPolicyActions, policyServices } from "../domain/policyLanguage";
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
  const { policyDirectoryView } = useAccountAccess();
  const [view, setView] = useState(policyDirectoryView.read);
  const [selection, setSelection] = useState<string[]>([]);
  useEffect(() => { policyDirectoryView.remember(view); }, [view, policyDirectoryView]);
  const directory = useMemo(() => workspace.policies.map((policy) => {
    const document = policy.versions.find((version) => version.id === policy.defaultVersion)!.document;
    const actions = expandPolicyActions(document.statement.flatMap((statement) => statement.action));
    const services = [...new Set(actions.map((action) => action.service))];
    const levels = [...new Set(actions.map((action) => action.level))];
    const scopes = [...new Set(document.statement.map((statement) => statement.condition?.resourceTag ? "tag" : statement.resource.includes("*") ? "tenant" : "specific"))];
    const description = describe(policy);
    const keywords = [policy.id, policy.name, description, ...policy.tags.flatMap((tag) => [tag.key, tag.value]),
      ...services.map((service) => r(`services.${service}`)), ...levels.map((level) => r(`levels.${level}`)), ...actions.map((action) => action.id)].join(" ").normalize("NFKC").toLowerCase();
    return { policy, description, services, levels, scopes, keywords, conditional: document.statement.some((statement) => statement.condition) };
  }), [workspace.policies, describe, r]);
  const matches = useMemo(() => {
    const words = view.query.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean);
    return directory.filter((row) => (view.kind === "all" || row.policy.kind === view.kind) &&
      (view.service === "all" || row.services.some((service) => service === view.service)) &&
      (view.level === "all" || row.levels.some((level) => level === view.level)) &&
      (view.scope === "all" || row.scopes.some((scope) => scope === view.scope)) && words.every((word) => row.keywords.includes(word)))
      .sort((a, b) => view.sort === "name" ? a.policy.name.localeCompare(b.policy.name, locale) :
        (view.sort === "newest" ? -1 : 1) * a.policy.createdAt.localeCompare(b.policy.createdAt) || a.policy.name.localeCompare(b.policy.name, locale));
  }, [directory, view, locale]);
  const pages = Math.max(1, Math.ceil(matches.length / view.pageSize));
  const page = Math.min(view.page, pages);
  const visible = matches.slice((page - 1) * view.pageSize, page * view.pageSize);
  const selected = workspace.policies.filter((policy) => selection.includes(policy.id));
  const allSelected = visible.length > 0 && visible.every((row) => selection.includes(row.policy.id));
  const someSelected = visible.some((row) => selection.includes(row.policy.id));
  const change = (next: Partial<PolicyDirectoryView>) => setView((current) => ({ ...current, page: 1, ...next }));
  const reset = () => setView({ ...defaultPolicyDirectoryView, pageSize: view.pageSize, sort: view.sort });
  return <Tabs.Root className={styles.directory} value={view.kind} onValueChange={(kind) => change({ kind })}>
    <ContentPage.Heading title={w("policies")} actions={<Button size="small" onClick={onCreate}><Plus aria-hidden="true" />{w("createPolicy")}</Button>} />
    <Card>
      <div className={styles.directoryHeading}>
        <Tabs.List aria-label={w("type")}>
          <Tabs.Trigger value="all">{t("allPolicies")}</Tabs.Trigger><Tabs.Trigger value="system">{w("system")}</Tabs.Trigger><Tabs.Trigger value="custom">{w("custom")}</Tabs.Trigger>
        </Tabs.List>
      </div>
      <Tabs.Content className={styles.directoryContent} value={view.kind}>
      <TableToolbar labels={toolbarLabels} search={{ label: w("search"), value: view.query, onChange: (query) => change({ query }) }}
        status={t("resultCount", { count: matches.length })} filters={[
          { id: "service", label: r("service"), value: view.service, onChange: (service) => change({ service }), options: [{ value: "all", label: t("allServices") }, ...policyServices.map((value) => ({ value, label: r(`services.${value}`) }))] },
          { id: "level", label: t("operationLevel"), value: view.level, onChange: (level) => change({ level }), options: [{ value: "all", label: t("allLevels") }, ...(["read", "list", "write", "permissions"] as const).map((value) => ({ value, label: r(`levels.${value}`) }))] },
          { id: "scope", label: t("scope"), value: view.scope, onChange: (scope) => change({ scope }), options: [{ value: "all", label: t("allScopes") }, { value: "tenant", label: t("scopeAll") }, { value: "specific", label: t("scopeSpecific") }, { value: "tag", label: t("scopeTag") }] }
        ]} tools={<Select controlSize="small" aria-label={t("sort")} value={view.sort} onValueChange={(sort) => change({ sort })} options={[{ value: "name", label: t("nameSort") }, { value: "newest", label: t("newest") }, { value: "oldest", label: t("oldest") }]} />} />
      {selected.length ? <div className={styles.selectionBar}>
        <span>{t("selected", { count: selected.length })}</span><span className={styles.note}>{t("batchLimit")}</span><Button size="small" onClick={() => onAssociate(selected, true)}>{t("batchAttach")}</Button><Button variant="ghost" size="small" onClick={() => setSelection([])}>{t("clearSelected")}</Button>
      </div> : null}
      <Table aria-label={w("policies")} className={styles.policyTable}>
        <thead><tr><th className={styles.checkCell}><Checkbox aria-label={t("selectPage")} ref={(input) => { if (input) input.indeterminate = someSelected && !allSelected; }} checked={allSelected} disabled={!visible.length || (!allSelected && new Set([...selection, ...visible.map((row) => row.policy.id)]).size > 30)} onChange={() => setSelection(allSelected ? selection.filter((id) => !visible.some((row) => row.policy.id === id)) : [...new Set([...selection, ...visible.map((row) => row.policy.id)])])}>{null}</Checkbox></th>
          <th scope="col" className={styles.nameCell}>{w("name")}</th><th scope="col" className={styles.kindCell}>{w("type")}</th><th scope="col">{r("service")}</th><th scope="col">{t("operationLevel")}</th><th scope="col">{t("scope")}</th><th scope="col" className={styles.countCell}>{w("associations")}</th><th scope="col" className={styles.actionCell}>{w("actions")}</th></tr></thead>
        <tbody>{visible.map(({ policy, description, services, levels, scopes, conditional }) => <tr key={policy.id} data-selected={selection.includes(policy.id) || undefined}>
          <td className={styles.checkCell}><Checkbox aria-label={t("selectPolicy", { name: policy.name })} checked={selection.includes(policy.id)} disabled={!selection.includes(policy.id) && selection.length >= 30} onChange={(event) => setSelection(event.target.checked ? [...selection, policy.id] : selection.filter((id) => id !== policy.id))}>{null}</Checkbox></td>
          <td><button className={styles.nameLink} title={policy.name} onClick={() => onOpen(policy.id)}>{policy.name}</button><small className={styles.ellipsis} title={description}>{description || "—"}</small></td>
          <td><Badge status={policy.kind === "custom" ? "info" : "neutral"}>{w(policy.kind)}</Badge></td>
          <td><span title={services.map((service) => r(`services.${service}`)).join(" · ")}>{services.length === policyServices.length ? t("allRegisteredServices") : r(`services.${services[0]!}`)}{services.length > 1 && services.length < policyServices.length ? ` +${services.length - 1}` : ""}</span></td>
          <td><span className={styles.levels}>{levels.map((level) => r(`levels.${level}`)).join(" · ")}</span></td>
          <td>{scopes.length > 1 ? t("scopeMixed") : t(scopes[0] === "tag" ? "scopeTag" : scopes[0] === "specific" ? "scopeSpecific" : "scopeAll")}{conditional ? <small>{t("conditional")}</small> : null}</td>
          <td>{policyAssociationCount(workspace, policy.id)}</td>
          <td><Button variant="ghost" size="small" aria-label={w("associateTargets") + " · " + policy.name} onClick={() => onAssociate([policy])}>{t("attach")}</Button></td>
        </tr>)}</tbody>
      </Table>
      {!matches.length ? <EmptyState title={w("noResults")} description={w("noResultsHint")} action={<Button variant="secondary" onClick={reset}>{toolbarLabels.resetQuery}</Button>} /> : null}
      <Card.Footer><span className={styles.note}>{w("page", { page, pages })}</span><div className={styles.pagination}>
        <Select controlSize="small" aria-label={w("pageSize")} value={String(view.pageSize)} onValueChange={(value) => change({ pageSize: Number(value) })} options={[10, 20, 50].map((value) => ({ value: String(value), label: String(value) }))} />
        <Button variant="secondary" size="small" iconOnly disabled={page <= 1} aria-label={w("previous")} onClick={() => change({ page: page - 1 })}><ChevronLeft aria-hidden="true" /></Button>
        <Button variant="secondary" size="small" iconOnly disabled={page >= pages} aria-label={w("next")} onClick={() => change({ page: page + 1 })}><ChevronRight aria-hidden="true" /></Button>
      </div></Card.Footer>
      </Tabs.Content>
    </Card>
    <p className={styles.note}>{t("scopeHint")} {w("previewNote")}</p>
  </Tabs.Root>;
}
