"use client";

import { useEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import { policyGrantTargets, type AccessPolicy, type AccessWorkspace, type PolicyTargets } from "../domain/accessWorkspace";
import { includesPermissionManagement } from "../domain/policyDocument";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceDialog } from "./AccessWorkspaceUi";
import { PolicyTargetSelector } from "./PolicyTargetSelector";
import styles from "./PolicyWorkspace.module.css";

const emptyTargets = (): PolicyTargets => ({ userIds: [], groupIds: [], roleIds: [] });
const kinds = ["userIds", "groupIds", "roleIds"] as const;
function subjectName(kind: keyof PolicyTargets, id: string, workspace: AccessWorkspace, scene: AccountAccessScene): string {
  return kind === "userIds" ? scene.users.find((user) => user.id === id)?.loginName ?? id :
    (kind === "groupIds" ? workspace.groups : workspace.roles).find((entry) => entry.id === id)?.name ?? id;
}

export function PolicyAssociationChanges({ before, after, workspace, scene }: {
  before: PolicyTargets; after: PolicyTargets; workspace: AccessWorkspace; scene: AccountAccessScene;
}) {
  const t = useTranslations("PolicyWorkspace"), p = useTranslations("PolicyWizard");
  const entries = kinds.flatMap((kind) => [...new Set([...before[kind], ...after[kind]])].map((id) => ({ kind, id,
    change: !before[kind].includes(id) ? "added" : !after[kind].includes(id) ? "removed" : "unchanged" } as const)));
  // Include group members affected by removal, not only directly detached users.
  const removedUsers = new Set([...before.userIds.filter((id) => !after.userIds.includes(id)),
    ...workspace.groups.filter((group) => before.groupIds.includes(group.id) && !after.groupIds.includes(group.id)).flatMap((group) => group.memberIds)]);
  const remaining = [...removedUsers].flatMap((id) => {
    const groups = workspace.groups.filter((group) => after.groupIds.includes(group.id) && group.memberIds.includes(id));
    const direct = after.userIds.includes(id);
    return groups.length || direct ? [{ id, direct, groups: groups.map((group) => group.name).join("、") }] : [];
  });
  return <div className={styles.stack}>
    <p className={styles.note}>{t("associationReviewHint")}</p>
    {(["added", "removed", "unchanged"] as const).map((change) => {
      const selected = entries.filter((entry) => entry.change === change);
      return selected.length ? <section key={change} className={styles.reviewSection} aria-label={t(change)}><h3>{t(change)} · {selected.length}</h3>
        <ul className={styles.subjectList}>{selected.map(({ kind, id }) => <li key={kind + id}><Badge status={change === "removed" ? "warning" : change === "added" ? "success" : "neutral"}>{p(`targets.${kind}`)}</Badge><span>{subjectName(kind, id, workspace, scene)}</span>{kind === "groupIds" ? <span className={styles.note}>({workspace.groups.find((group) => group.id === id)?.memberIds.length ?? 0})</span> : null}</li>)}</ul>
      </section> : null;
    })}
    {!entries.length ? <p className={styles.note}>{t("noChanges")}</p> : null}
    {remaining.length ? <Alert status="warning"><p>{t("remainingHint")}</p>{remaining.map(({ id, groups, direct }) => <div key={id}>{groups ? <p>{t("keptGroup", { user: subjectName("userIds", id, workspace, scene), groups })}</p> : null}{direct ? <p>{t("keptDirect", { user: subjectName("userIds", id, workspace, scene) })}</p> : null}</div>)}</Alert> : null}
  </div>;
}

/** One impact view serves edits and rollback; boundaries are never called grants. */
export function PolicyAffectedIdentities({ policyId, targets, workspace, scene }: {
  policyId: string; targets?: PolicyTargets; workspace: AccessWorkspace; scene: AccountAccessScene;
}) {
  const t = useTranslations("PolicyWorkspace"), p = useTranslations("PolicyWizard");
  const grants = targets ?? policyGrantTargets(workspace, policyId);
  const rows = [
    ...grants.userIds.map((id) => ({ id: "direct:" + id, name: subjectName("userIds", id, workspace, scene), source: t("direct") })),
    ...workspace.groups.filter((group) => grants.groupIds.includes(group.id)).flatMap((group) => [
      { id: "group:" + group.id, name: t("groupMembers", { name: group.name, count: group.memberIds.length }), source: p("targets.groupIds") },
      ...group.memberIds.map((id) => ({ id: group.id + ":" + id, name: subjectName("userIds", id, workspace, scene), source: t("inherited") + " · " + group.name }))
    ]),
    ...grants.roleIds.map((id) => ({ id: "role:" + id, name: subjectName("roleIds", id, workspace, scene), source: t("role") })),
    ...Object.entries(workspace.userBoundaries).filter(([, id]) => id === policyId).map(([id]) => ({ id: "userBoundary:" + id, name: subjectName("userIds", id, workspace, scene), source: t("boundary") })),
    ...workspace.roles.filter((role) => role.boundaryPolicyId === policyId).map((role) => ({ id: "roleBoundary:" + role.id, name: role.name, source: t("boundary") }))
  ];
  return <section className={styles.reviewSection} aria-label={t("impact")}><h3>{t("impact")}</h3><p className={styles.note}>{t("impactHint")}</p>
    {rows.length ? <ul className={styles.subjectList}>{rows.map((row) => <li key={row.id}><span>{row.name}</span><span className={styles.note}>{row.source}</span></li>)}</ul> : <p className={styles.note}>{t("noImpact")}</p>}
  </section>;
}

export function PolicyAssociationEditor({ policies, additive = false, workspace, scene, onClose }: {
  policies: AccessPolicy[]; additive?: boolean; workspace: AccessWorkspace; scene: AccountAccessScene; onClose(): void;
}) {
  const t = useTranslations("PolicyWorkspace"), w = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const [initial] = useState(() => additive ? emptyTargets() : policyGrantTargets(workspace, policies[0]!.id));
  const [targets, setTargets] = useState(initial);
  const [reviewing, setReviewing] = useState(false);
  const review = useRef<HTMLElement>(null);
  useEffect(() => { if (reviewing) { review.current?.focus({ preventScroll: true }); review.current?.scrollIntoView?.({ block: "start" }); } }, [reviewing]);
  const changed = kinds.some((kind) => initial[kind].some((id) => !targets[kind].includes(id)) || targets[kind].some((id) => !initial[kind].includes(id)));
  const high = policies.some((policy) => includesPermissionManagement(policy.versions.find((version) => version.id === policy.defaultVersion)!.document));
  return <WorkspaceDialog size="wide" title={additive ? t(reviewing ? "batchReview" : "batchAttach") : w("associateTargets") + " · " + policies[0]!.name}
    onClose={onClose} submitLabel={t(reviewing ? "confirmAssociations" : "review")} submitDisabled={!changed} onSubmit={async () => {
      if (!reviewing) { setReviewing(true); return false; }
      return Boolean(await access.executeWorkspace(additive ? { kind: "attach-policies", policyIds: policies.map((policy) => policy.id), targets } : { kind: "associate-policy", id: policies[0]!.id, ...targets }));
    }}>
    {additive ? <><p className={styles.note}>{t("batchHint")}</p><section aria-label={t("policySet")} className={styles.actions}>{policies.map((policy) => <Badge key={policy.id}>{policy.name}</Badge>)}</section></> : null}
    {reviewing ? <><div><Button variant="ghost" onClick={() => setReviewing(false)}>{t("backSelection")}</Button></div><section ref={review} tabIndex={-1} aria-label={t("reviewAssociations")}><PolicyAssociationChanges before={initial} after={targets} workspace={workspace} scene={scene} /></section></> : <PolicyTargetSelector workspace={workspace} scene={scene} value={targets} onChange={setTargets} />}
    {high ? <Alert status="warning">{w("highPrivilege")}</Alert> : null}
  </WorkspaceDialog>;
}
