"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { Badge, Tabs, Transfer } from "@ui/xiak";
import type { AccessWorkspace, PolicyTargets } from "../domain/accessWorkspace";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { workspaceSelectionLabels } from "./AccessWorkspaceUi";

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
  const selected = (Object.keys(sources) as (keyof PolicyTargets)[]).flatMap((key) => value[key].map((id) => ({
    id: key + ":" + id, label: sources[key].find((entry) => entry.id === id)?.name ?? id, description: t(`targets.${key}`)
  })));
  function toggle(encoded: readonly string[], checked: boolean) {
    if (!checked) {
      const removed = new Set(encoded);
      onChange({
        userIds: value.userIds.filter((id) => !removed.has("userIds:" + id)),
        groupIds: value.groupIds.filter((id) => !removed.has("groupIds:" + id)),
        roleIds: value.roleIds.filter((id) => !removed.has("roleIds:" + id))
      });
      return;
    }
    const ids = encoded.map((id) => id.slice(id.indexOf(":") + 1));
    const next = [...new Set([...value[kind], ...ids])];
    if (next.length <= 30) onChange({ ...value, [kind]: next });
  }
  return <Tabs.Root value={kind} onValueChange={(next) => setKind(next as keyof PolicyTargets)}>
    <Tabs.List aria-label={w("associations")}>{(Object.keys(sources) as (keyof PolicyTargets)[]).map((key) => <Tabs.Trigger key={key} value={key}>{t(`targets.${key}`)} <Badge>{value[key].length}</Badge></Tabs.Trigger>)}</Tabs.List>
    <Tabs.Content value={kind}>
      <Transfer key={kind} options={sources[kind].map((entry) => ({ id: kind + ":" + entry.id, label: entry.name, description: entry.description }))} selected={selected} remaining={30 - value[kind].length}
        onSelect={toggle} onClear={() => onChange({ userIds: [], groupIds: [], roleIds: [] })}
        labels={{
          ...workspaceSelectionLabels(w), available: t(`targets.${kind}`), selected: t("selectedTargets", { count: selected.length }),
          search: w("search"), empty: t("noTargets")
        }} footnote={t("targetLimit")} />
    </Tabs.Content>
  </Tabs.Root>;
}
