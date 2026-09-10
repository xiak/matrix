"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { Badge, Tabs, Transfer } from "@ui/xiak";
import type { AccessWorkspace, PolicyTargets } from "../domain/accessWorkspace";
import type { AccountAccessScene } from "../scenes/accountAccessScene";

export function PolicyTargetSelector({ workspace, scene, value, onChange }: {
  workspace: AccessWorkspace; scene: AccountAccessScene; value: PolicyTargets; onChange(value: PolicyTargets): void;
}) {
  const t = useTranslations("PolicyWizard");
  const w = useTranslations("IamWorkspace");
  const [kind, setKind] = useState<keyof PolicyTargets>("userIds");
  const sources = {
    userIds: scene.users.map((user) => ({ id: user.id, name: user.loginName, description: user.name })),
    groupIds: workspace.groups,
    roleIds: workspace.roles
  };
  const selected = (Object.keys(sources) as (keyof PolicyTargets)[]).flatMap((key) => sources[key].filter((entry) => value[key].includes(entry.id)).map((entry) => ({ id: key + ":" + entry.id, label: entry.name, description: t(`targets.${key}`) })));
  function remove(encoded: string) {
    const key = encoded.slice(0, encoded.indexOf(":")) as keyof PolicyTargets;
    const id = encoded.slice(encoded.indexOf(":") + 1);
    onChange({ ...value, [key]: value[key].filter((entry) => entry !== id) });
  }
  return <Tabs.Root value={kind} onValueChange={(next) => setKind(next as keyof PolicyTargets)}>
    <Tabs.List aria-label={w("associations")}>{(Object.keys(sources) as (keyof PolicyTargets)[]).map((key) => <Tabs.Trigger key={key} value={key}>{t(`targets.${key}`)} <Badge>{value[key].length}</Badge></Tabs.Trigger>)}</Tabs.List>
    <Tabs.Content value={kind}>
      <Transfer key={kind} options={sources[kind].map((entry) => ({ id: kind + ":" + entry.id, label: entry.name, description: entry.description }))} selected={selected} remaining={30 - value[kind].length}
        onSelect={(encoded, checked) => { const ids = encoded.map((id) => id.slice(id.indexOf(":") + 1)); const next = checked ? [...new Set([...value[kind], ...ids])] : value[kind].filter((id) => !ids.includes(id)); if (next.length <= 30) onChange({ ...value, [kind]: next }); }} onRemove={remove} onClear={() => onChange({ userIds: [], groupIds: [], roleIds: [] })}
        labels={{ available: t(`targets.${kind}`), selected: t("selectedTargets", { count: selected.length }), search: w("search"), clearSearch: w("clear"), clearSelected: t("clearTargets"), empty: t("noTargets"), emptyHint: t("noTargetsHint"), noResults: w("noResults"), remove: (name) => t("removeTarget", { name }), previous: w("previous"), next: w("next"), page: (page, pages) => w("page", { page, pages }), selectPage: w("selectPage"), clearPage: w("clearPage"), pageSelection: (selected, total) => w("pageSelection", { selected, total }), limit: (remaining, needed) => w("pageSelectionLimit", { remaining, needed }) }} footnote={t("targetLimit")} />
    </Tabs.Content>
  </Tabs.Root>;
}
