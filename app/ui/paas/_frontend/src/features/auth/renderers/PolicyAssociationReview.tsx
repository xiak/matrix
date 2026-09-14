"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import { ArrowRight, ShieldCheck } from "lucide-react";
import { Alert, Badge, Button, ContentPage, Wizard } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import { policyGrantTargets, type AccessPolicy, type AccessWorkspace, type PolicyTargets } from "../domain/accessWorkspace";
import { includesPermissionManagement } from "../domain/policyDocument";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { PolicyTargetSelector } from "./PolicyTargetSelector";
import { useAccessDraft } from "./useAccessDraft";
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

export function PolicyAssociationWizard({ policies, additive = false, workspace, scene, onBack }: {
  policies: AccessPolicy[]; additive?: boolean; workspace: AccessWorkspace; scene: AccountAccessScene; onBack(): void;
}) {
  const t = useTranslations("PolicyWorkspace"), w = useTranslations("IamWorkspace"), p = useTranslations("PolicyWizard"), a = useTranslations("AccountAccess"), u = useTranslations("UserWizard");
  const access = useAccountAccess();
  const [initial] = useState(() => additive ? emptyTargets() : policyGrantTargets(workspace, policies[0]!.id));
  const [targets, setTargets] = useState(initial);
  const [step, setStep] = useState(0);
  const [complete, setComplete] = useState(false);
  const form = useRef<HTMLFormElement>(null);
  const submitting = useRef(false);
  const changed = kinds.some((kind) => initial[kind].some((id) => !targets[kind].includes(id)) || targets[kind].some((id) => !initial[kind].includes(id)));
  const high = policies.some((policy) => includesPermissionManagement(policy.versions.find((version) => version.id === policy.defaultVersion)!.document));
  const busy = access.busy || access.loading;
  const clearError = access.clearWorkspaceError;
  const pageTitle = additive ? t("batchAttach") : w("associateTargets");
  const workflowLabel = additive ? t("batchAttach") : `${w("associateTargets")} · ${policies[0]!.name}`;
  const requestLeave = useAccessDraft({ dirty: changed && !complete, busy: access.busy, title: t("associationCancelTitle"), description: t("associationCancelHint"), form });
  useEffect(() => { clearError(); }, [clearError]);
  useEffect(() => {
    if (!access.workspaceError || busy) return;
    const alert = form.current?.querySelector<HTMLElement>('[data-workspace-error]');
    alert?.focus({ preventScroll: true });
    alert?.scrollIntoView?.({ block: "nearest" });
  }, [access.workspaceError, busy]);
  function changeStep(next: number) { clearError(); setStep(next); }
  function cancel() { requestLeave(onBack); }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || submitting.current || complete || !changed) return;
    if (step === 0) { changeStep(1); return; }
    submitting.current = true;
    const saved = await access.executeWorkspace(additive ? { kind: "attach-policies", policyIds: policies.map((policy) => policy.id), targets } : { kind: "associate-policy", id: policies[0]!.id, ...targets });
    submitting.current = false;
    if (saved) setComplete(true);
  }
  return <div className={styles.associationWorkflow}>
    <ContentPage.Heading title={pageTitle} scrollKey={`associate-policy:${additive ? "batch:" + policies.map((policy) => policy.id).join(",") : policies[0]!.id}`} back={{ label: p("back"), parentLabel: additive ? w("policies") : policies[0]!.name, disabled: busy, onClick: cancel }} />
    <Wizard label={workflowLabel} steps={[{ id: "select", label: t("selectAssociations") }, { id: "review", label: t("reviewAssociations") }]} currentStep={step} onStepChange={changeStep} busy={busy} completed={complete} formRef={form} onSubmit={submit}
      title={complete ? t("associationSaved") : step === 0 ? t("selectAssociations") : t("reviewAssociations")}
      description={complete ? t("associationSavedHint") : step === 0 ? additive ? t("batchHint") : p("targetsHint") : t("associationReviewHint")}
      progressLabel={complete ? undefined : u("stepCount", { current: step + 1, total: 2 })}
      hint={<><ShieldCheck aria-hidden="true" />{p("mockHint")}</>}
      actions={complete ? <Button type="button" onClick={onBack}>{t("finishAssociations")}<ArrowRight aria-hidden="true" /></Button> : <><Button type="button" variant="ghost" disabled={busy} onClick={cancel}>{w("cancel")}</Button>{step > 0 ? <Button type="button" variant="secondary" disabled={busy} onClick={() => changeStep(step - 1)}>{a("previousStep")}</Button> : null}<Button type="submit" disabled={busy || !changed}>{busy ? a("saving") : step === 0 ? t("review") : t("confirmAssociations")}</Button></>}>
      {complete ? <Alert status="success">{t("associationSavedScope")}</Alert> : <div className={styles.stack}>
        <section aria-label={t("policySet")} className={styles.policySet}><span className={styles.note}>{t("policySet")}</span><div className={styles.actions}>{policies.map((policy) => <Badge key={policy.id}>{policy.name}</Badge>)}</div></section>
        {step === 0 ? <PolicyTargetSelector workspace={workspace} scene={scene} value={targets} onChange={setTargets} /> : <section aria-label={t("reviewAssociations")}><PolicyAssociationChanges before={initial} after={targets} workspace={workspace} scene={scene} /></section>}
        {high ? <Alert status="warning">{w("highPrivilege")}</Alert> : null}
        {access.workspaceError ? <Alert data-workspace-error status="danger" tabIndex={-1}>{w(`errors.${access.workspaceError}`)}</Alert> : null}
      </div>}
    </Wizard>
  </div>;
}
