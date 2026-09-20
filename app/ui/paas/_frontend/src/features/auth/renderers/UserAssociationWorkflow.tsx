"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import { ArrowRight, ShieldCheck } from "lucide-react";
import { Alert, Badge, Button, ContentPage, Wizard } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import { includesPermissionManagement } from "../domain/policyDocument";
import type { AccountUserScene } from "../scenes/accountAccessScene";
import { WorkspaceSelection } from "./AccessWorkspaceUi";
import { useAccessDraft } from "./useAccessDraft";
import styles from "./AccountAccessRenderer.module.css";

type AssociationKind = "groups" | "policies";

function AssociationChangeList({ label, status, ids, names }: {
  label: string;
  status: "success" | "warning" | "neutral";
  ids: readonly string[];
  names: ReadonlyMap<string, string>;
}) {
  if (!ids.length) return null;
  return <section className={styles.identitySection} aria-label={`${label} · ${ids.length}`}>
    <h3>{label} · {ids.length}</h3>
    <ul className={styles.bindingList}>{ids.map((id) => <li key={id}><span>{names.get(id) ?? id}</span><Badge status={status}>{label}</Badge></li>)}</ul>
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
  const names = new Map(options.map((option) => [option.id, option.name]));
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
  const includesHighPrivilege = workspace.policies.some((policy) => selectedPolicyIds.includes(policy.id)
    && includesPermissionManagement(policy.versions.find((version) => version.id === policy.defaultVersion)!.document));
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
          <div><dt>{t("userAssociationTarget")}</dt><dd>{user.loginName}</dd></div>
          <div><dt>{t("type")}</dt><dd>{t(kind === "groups" ? "userGroups" : "directPolicies")}</dd></div>
        </dl>
        {step === 0
          ? <><Alert status="info">{selectionHint}</Alert><WorkspaceSelection label={t(kind)} options={options} value={selection} onChange={setSelection} /></>
          : <section className={styles.stack} aria-label={p("reviewAssociations")}>
            <p className={styles.note}>{t("userAssociationReviewHint")}</p>
            <AssociationChangeList label={p("added")} status="success" ids={added} names={names} />
            <AssociationChangeList label={p("removed")} status="warning" ids={removed} names={names} />
            <AssociationChangeList label={p("unchanged")} status="neutral" ids={unchanged} names={names} />
            {!changed ? <p className={styles.note}>{p("noChanges")}</p> : null}
          </section>}
        {includesHighPrivilege ? <Alert status="warning">{t("highPrivilege")}</Alert> : null}
        {access.workspaceError ? <Alert data-workspace-error status="danger" tabIndex={-1}>{t(`errors.${access.workspaceError}`)}</Alert> : null}
      </div>}
    </Wizard>
  </div>;
}
