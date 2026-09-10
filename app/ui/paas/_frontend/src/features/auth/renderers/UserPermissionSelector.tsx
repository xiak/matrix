"use client";

import { useMemo, useState } from "react";
import { useTranslations } from "next-intl";
import { FileCheck2, Users } from "lucide-react";
import { Alert, Button, Select, Tabs, Transfer } from "@ui/xiak";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { usePolicyDescription } from "./PolicyDirectory";
import styles from "./CreateUserWizard.module.css";

export type UserPermissions = { policyIds: string[]; groupIds: string[] };

export function UserPermissionSelector({ workspace, scene, value, onChange }: {
  workspace: AccessWorkspace; scene: AccountAccessScene; value: UserPermissions; onChange(value: UserPermissions): void;
}) {
  const t = useTranslations("UserWizard");
  const w = useTranslations("IamWorkspace");
  const describe = usePolicyDescription();
  const [mode, setMode] = useState("policies");
  const [kind, setKind] = useState("all");
  const [sourceId, setSourceId] = useState("");
  const [copied, setCopied] = useState(false);
  const selectedPolicies = workspace.policies.filter((policy) => value.policyIds.includes(policy.id));
  const selectedGroups = workspace.groups.filter((group) => value.groupIds.includes(group.id));
  const sourcePolicies = workspace.userPolicies[sourceId] ?? [];
  const sourceGroups = workspace.groups.filter((group) => group.memberIds.includes(sourceId));
  const source = scene.users.find((user) => user.id === sourceId);
  const options = useMemo(() => mode === "copy" ? [] : mode === "groups"
    ? workspace.groups.map((group) => ({ id: group.id, label: group.name, description: group.description + " · " + t("groupSize", { users: group.memberIds.length, policies: group.policyIds.length }) }))
    : workspace.policies.filter((policy) => kind === "all" || policy.kind === kind).map((policy) => ({ id: policy.id, label: policy.name, description: describe(policy), keywords: policy.tags.flatMap((tag) => [tag.key, tag.value]).join(" "), annotation: w(policy.kind) })), [mode, kind, workspace.groups, workspace.policies, describe, t, w]);
  const grantIds = new Set([...value.policyIds, ...selectedGroups.flatMap((group) => group.policyIds)]);
  const elevated = workspace.policies.some((policy) => grantIds.has(policy.id) && policy.versions.find((version) => version.id === policy.defaultVersion)?.document.statement.some((statement) => statement.effect === "allow" && statement.action.includes("*")));
  function toggle(ids: readonly string[], checked: boolean) {
    const key = mode === "groups" ? "groupIds" : "policyIds";
    const next = checked ? [...new Set([...value[key], ...ids])] : value[key].filter((item) => !ids.includes(item));
    if (next.length <= 30) onChange({ ...value, [key]: next });
  }
  return <div className={styles.stack}>
    <Alert>{t("leastPrivilege")}</Alert>
    <Tabs.Root value={mode} onValueChange={(next) => { setMode(next); setCopied(false); }}>
      <Tabs.List aria-label={t("permissionMethod")}><Tabs.Trigger value="policies">{t("choosePolicies")}</Tabs.Trigger><Tabs.Trigger value="groups">{t("joinGroups")}</Tabs.Trigger><Tabs.Trigger value="copy">{t("copyUser")}</Tabs.Trigger></Tabs.List>
      <Tabs.Content value={mode} className={styles.stack}>
        <Transfer key={mode} options={options}
          remaining={30 - (mode === "groups" ? value.groupIds.length : value.policyIds.length)} filterKey={kind}
          selected={[...selectedPolicies.map((item) => ({ id: item.id, label: item.name, description: t("direct"), icon: <FileCheck2 aria-hidden="true" /> })), ...selectedGroups.map((item) => ({ id: item.id, label: item.name, description: t("inherited"), icon: <Users aria-hidden="true" /> }))]}
          onSelect={toggle} onClear={() => onChange({ policyIds: [], groupIds: [] })}
          onRemove={(id) => onChange({ policyIds: value.policyIds.filter((item) => item !== id), groupIds: value.groupIds.filter((item) => item !== id) })}
          labels={{ available: t(mode === "groups" ? "availableGroups" : "availablePolicies"), selected: t("selectedCount", { count: selectedPolicies.length + selectedGroups.length }), search: t("searchPermissions"), clearSearch: w("clear"), clearSelected: t("clearSelection"), empty: t("nothingSelected"), emptyHint: t("emptySelectionHint"), noResults: w("noResults"), remove: (name) => t("removePermission", { name }), previous: w("previous"), next: w("next"), page: (page, pages) => w("page", { page, pages }), selectPage: w("selectPage"), clearPage: w("clearPage"), pageSelection: (selected, total) => w("pageSelection", { selected, total }), limit: (remaining, needed) => w("pageSelectionLimit", { remaining, needed }), option: t(mode === "groups" ? "groupColumn" : "policyColumn"), annotation: mode === "policies" ? t("policyType") : undefined }}
          footnote={<>{t("selectionCounts", { policies: value.policyIds.length, groups: value.groupIds.length })}<br />{t("selectionHint")}</>}
          filter={mode === "policies" ? <Select aria-label={t("policyType")} value={kind} onValueChange={setKind} options={[{ value: "all", label: w("all") }, { value: "system", label: w("system") }, { value: "custom", label: w("custom") }]} /> : undefined}
          source={mode === "copy" ? <div className={styles.copyPane}>
            <h3>{t("copyUser")}</h3><p className={styles.muted}>{t("copyHint")}</p>
            <Select aria-label={t("sourceUser")} placeholder={t("sourceUser")} options={scene.users.map((user) => ({ value: user.id, label: user.loginName + " · " + user.name }))} value={sourceId} onValueChange={(id) => { setSourceId(id); setCopied(false); }} />
            {source ? <><p>{t("copySummary", { policies: sourcePolicies.length, groups: sourceGroups.length })}</p><Button variant="secondary" onClick={() => { onChange({ policyIds: [...sourcePolicies], groupIds: sourceGroups.map((group) => group.id) }); setCopied(true); }}>{t("applyCopy")}</Button></> : null}
            {copied ? <p role="status" className={styles.muted}>{t("copied")}</p> : null}
          </div> : undefined}
        />
        {elevated ? <Alert status="warning">{t("widePermissionWarning")}</Alert> : null}
      </Tabs.Content>
    </Tabs.Root>
  </div>;
}
