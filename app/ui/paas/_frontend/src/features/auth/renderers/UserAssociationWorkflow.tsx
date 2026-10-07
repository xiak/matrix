"use client";

import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import { ArrowRight, ShieldCheck } from "lucide-react";
import { Alert, Button, ContentPage, Wizard } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountUserScene } from "../scenes/accountAccessScene";
import { WorkspaceSelection } from "./AccessWorkspaceUi";
import { PolicySecurityReview } from "./PolicySecurityReview";
import { useAccessDraft } from "./useAccessDraft";
import styles from "./AccountAccessRenderer.module.css";

type AssociationKind = "groups" | "policies";

function AssociationChangeList({ label, ids, items }: {
  label: string;
  ids: readonly string[];
  items: ReadonlyMap<string, { name: string; metadata: string }>;
}) {
  if (!ids.length) return null;
  return <section className={styles.identitySection} aria-label={`${label} · ${ids.length}`}>
    <h3>{label} · {ids.length}</h3>
    <ul className={styles.bindingList}>{ids.map((id) => <li key={id} className={styles.associationChangeItem}>
      <strong>{items.get(id)?.name ?? id}</strong>
      <small>{items.get(id)?.metadata ?? id}</small>
    </li>)}</ul>
  </section>;
}

/** User-owned relationship editing stays in the content area; persistence remains the preview repository's concern. */
export function UserAssociationWorkflow({ user, workspace, kind, onBack }: {
  user: Pick<AccountUserScene, "id" | "loginName">;
  workspace: AccessWorkspace;
  kind: AssociationKind;
  onBack(): void;
}) {
  const t = useTranslations("IamWorkspace");
  const p = useTranslations("PolicyWorkspace");
  const a = useTranslations("AccountAccess");
  const u = useTranslations("UserWizard");
  const access = useAccountAccess();
  const clearWorkspaceError = access.clearWorkspaceError;
  const options = kind === "groups" ? workspace.groups : workspace.policies;
  const reviewItems = useMemo(() => new Map<string, { name: string; metadata: string }>(kind === "groups"
    ? workspace.groups.map((group) => [group.id, { name: group.name, metadata: group.id }])
    : workspace.policies.map((policy) => [policy.id, { name: policy.name,
      metadata: `${policy.id} · ${t(policy.kind === "system" ? "system" : "custom")} · ${t("defaultVersion")} v${policy.defaultVersion}` }])),
  [kind, t, workspace.groups, workspace.policies]);
  const [initial] = useState(() => kind === "groups"
    ? workspace.groups.filter((group) => group.memberIds.includes(user.id)).map((group) => group.id)
    : workspace.userPolicies[user.id] ?? []);
  const [selection, setSelection] = useState(initial);
  const [step, setStep] = useState(0);
  const [complete, setComplete] = useState(false);
  const form = useRef<HTMLFormElement>(null);
  const submitting = useRef(false);
  const added = selection.filter((id) => !initial.includes(id));
  const removed = initial.filter((id) => !selection.includes(id));
  const unchanged = initial.filter((id) => selection.includes(id));
  const changed = added.length > 0 || removed.length > 0;
  const busy = access.busy || access.loading;
  const title = t(kind === "groups" ? "manageUserGroups" : "manageUserPolicies");
  const selectionHint = t(kind === "groups" ? "userGroupAssociationHint" : "userPolicyAssociationHint");
  const savedHint = t(kind === "groups" ? "userGroupAssociationsSavedHint" : "userPolicyAssociationsSavedHint");
  const selectedPolicyIds = kind === "policies" ? selection : workspace.groups.filter((group) => selection.includes(group.id)).flatMap((group) => group.policyIds);
  const selectedPolicies = workspace.policies.filter((policy) => selectedPolicyIds.includes(policy.id));
  const requestLeave = useAccessDraft({
    dirty: changed && !complete,
    busy,
    title: t("userAssociationCancelTitle"),
    description: t("userAssociationCancelHint"),
    form
  });

  useEffect(() => { clearWorkspaceError(); }, [clearWorkspaceError]);
  useEffect(() => {
    if (!access.workspaceError || busy) return;
    const alert = form.current?.querySelector<HTMLElement>("[data-workspace-error]");
    alert?.focus({ preventScroll: true });
    alert?.scrollIntoView?.({ block: "nearest" });
  }, [access.workspaceError, busy]);

  function changeStep(next: number) {
    clearWorkspaceError();
    setStep(next);
  }

  function leave() {
    requestLeave(onBack);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || complete || submitting.current || !changed) return;
    if (step === 0) {
      changeStep(1);
      return;
    }
    submitting.current = true;
    const saved = await access.executeWorkspace(kind === "groups"
      ? { kind: "set-user-groups", principalId: user.id, groupIds: selection }
      : { kind: "set-user-policies", principalId: user.id, policyIds: selection });
    submitting.current = false;
    if (saved) setComplete(true);
  }

  return <div className={styles.associationWorkflow}>
    <ContentPage.Heading title={title} scrollKey={`user-associations:${user.id}:${kind}`} back={{ label: t("back"), parentLabel: user.loginName, disabled: busy, onClick: leave }} />
    <Wizard
      label={`${title} · ${user.loginName}`}
      steps={[{ id: "select", label: p("selectAssociations") }, { id: "review", label: p("reviewAssociations") }]}
      currentStep={step}
      onStepChange={changeStep}
      busy={busy}
      completed={complete}
      formRef={form}
      onSubmit={submit}
      title={complete ? p("associationSaved") : step === 0 ? p("selectAssociations") : p("reviewAssociations")}
      description={complete ? savedHint : step === 0 ? selectionHint : t("userAssociationReviewHint")}
      progressLabel={complete ? undefined : u("stepCount", { current: step + 1, total: 2 })}
      hint={<><ShieldCheck aria-hidden="true" />{t("userAssociationMockHint")}</>}
      actions={complete
        ? <Button type="button" onClick={onBack}>{p("finishAssociations")}<ArrowRight aria-hidden="true" /></Button>
        : <><Button type="button" variant="ghost" disabled={busy} onClick={leave}>{t("cancel")}</Button>{step > 0 ? <Button type="button" variant="secondary" disabled={busy} onClick={() => changeStep(0)}>{a("previousStep")}</Button> : null}<Button type="submit" disabled={busy || !changed}>{busy ? a("saving") : step === 0 ? p("review") : p("confirmAssociations")}</Button></>}
    >
      {complete ? <Alert status="success">{savedHint}</Alert> : <div className={styles.stack}>
        <dl className={styles.facts}>
          <div><dt>{t("userAssociationTarget")}</dt><dd>{user.loginName}<small className={styles.associationTargetId}>{user.id}</small></dd></div>
          <div><dt>{t("userAssociationAccount")}</dt><dd>{workspace.accountId}</dd></div>
          <div><dt>{t("type")}</dt><dd>{t(kind === "groups" ? "userGroups" : "directPolicies")}</dd></div>
        </dl>
        {step === 0
          ? <><Alert status="info">{selectionHint}</Alert><WorkspaceSelection label={t(kind)} options={options} value={selection} onChange={setSelection} /></>
          : <section className={styles.stack} aria-label={p("reviewAssociations")}>
            <AssociationChangeList label={p("added")} ids={added} items={reviewItems} />
            <AssociationChangeList label={p("removed")} ids={removed} items={reviewItems} />
            <AssociationChangeList label={p("unchanged")} ids={unchanged} items={reviewItems} />
            {!changed ? <p className={styles.note}>{p("noChanges")}</p> : null}
          </section>}
        <PolicySecurityReview policies={selectedPolicies} />
        {access.workspaceError ? <Alert data-workspace-error status="danger" tabIndex={-1}>{t(`errors.${access.workspaceError}`)}</Alert> : null}
      </div>}
    </Wizard>
  </div>;
}
