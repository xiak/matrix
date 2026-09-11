"use client";

import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import { ShieldCheck } from "lucide-react";
import { ContentPage, Alert, Badge, Button, FormField, Input, TextArea, Wizard } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import { WorkspaceSelection } from "./AccessWorkspaceUi";
import { useAccessDraft } from "./useAccessDraft";
import styles from "./PolicyAuthoringWizard.module.css";

/** Creation grants policies to a group, never silently adds users to it. */
export function GroupCreationWizard({ workspace, onBack, onDone }: { workspace: AccessWorkspace; onBack(): void; onDone(id: string): void }) {
  const t = useTranslations("GroupWorkspace");
  const w = useTranslations("IamWorkspace");
  const u = useTranslations("UserWizard");
  const a = useTranslations("AccountAccess");
  const access = useAccountAccess();
  const id = useId();
  const form = useRef<HTMLFormElement>(null);
  const submitting = useRef(false);
  const [step, setStep] = useState(0);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [policyIds, setPolicyIds] = useState<string[]>([]);
  const [error, setError] = useState<"invalidName" | "duplicate" | null>(null);
  const [created, setCreated] = useState(false);
  const dirty = Boolean(name || description || policyIds.length);
  const busy = access.busy || access.loading;
  const requestLeave = useAccessDraft({ dirty: dirty && !created, busy: access.busy, title: t("cancelTitle"), description: t("cancelHint"), form });
  const clear = access.clearWorkspaceError;
  useEffect(() => { clear(); }, [clear]);
  useEffect(() => {
    const target = form.current?.querySelector<HTMLElement>('[aria-invalid="true"]');
    if (error) { target?.focus({ preventScroll: true }); target?.scrollIntoView?.({ block: "center" }); }
  }, [error]);
  function cancel() { requestLeave(onBack); }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || submitting.current) return;
    const invalid = !name.trim() || name.length > 64 || /[<>\u0000-\u001f]/.test(name) ? "invalidName" : workspace.groups.some((group) => group.name.toLowerCase() === name.trim().toLowerCase()) ? "duplicate" : null;
    if (invalid) { setError(invalid); setStep(0); return; }
    if (step < 2) { setStep(step + 1); return; }
    submitting.current = true;
    const saved = await access.executeWorkspace({ kind: "create-group", name: name.trim(), description, policyIds });
    submitting.current = false;
    if (saved) setCreated(true);
  }
  const steps = ["details", "policies", "review"] as const;
  const currentStep = steps[step] ?? "details";
  return <div className={styles.root}><ContentPage.Heading title={w("createGroup")} back={{ label: t("back"), parentLabel: w("groups"), disabled: busy, onClick: cancel }} />
    <Wizard label={w("createGroup")} steps={steps.map((key) => ({ id: key, label: t(`steps.${key}`) }))} currentStep={step} onStepChange={(next) => { setError(null); clear(); setStep(next); }} completed={created} busy={busy} formRef={form} onSubmit={submit}
      title={created ? t("created") : t(`steps.${currentStep}`)} description={created ? t("createdHint") : t(`hints.${currentStep}`)} progressLabel={u("stepCount", { current: step + 1, total: 3 })} hint={<><ShieldCheck aria-hidden="true" />{t("mockHint")}</>}
      actions={created ? <Button onClick={() => { const group = workspace.groups.find((entry) => entry.name === name.trim()); if (group) onDone(group.id); else onBack(); }}>{t("viewGroup")}</Button> : <><Button variant="ghost" disabled={busy} onClick={cancel}>{w("cancel")}</Button>{step ? <Button variant="secondary" disabled={busy} onClick={() => setStep(step - 1)}>{a("previousStep")}</Button> : null}<Button type="submit" disabled={busy}>{busy ? t("saving") : step < 2 ? t("next") : w("createGroup")}</Button></>}>
      {created ? <Alert status="success">{t("createdScope")}</Alert> : <>
        {step === 0 ? <div className={styles.metadata}><FormField id={id + "-name"} label={w("name")} hint={t("nameHint")} error={error ? t(error) : undefined}><Input id={id + "-name"} aria-required="true" value={name} maxLength={64} invalid={Boolean(error)} aria-describedby={[id + "-name-hint", error ? id + "-name-error" : ""].filter(Boolean).join(" ")} onChange={(event) => { setName(event.target.value); setError(null); }} /></FormField><FormField id={id + "-description"} label={w("description")}><TextArea id={id + "-description"} rows={3} maxLength={256} value={description} onChange={(event) => setDescription(event.target.value)} /></FormField></div> : null}
        {step === 1 ? <div className={styles.stack}><Alert>{t("policyHint")}</Alert><WorkspaceSelection label={w("selectPolicies")} options={workspace.policies} value={policyIds} onChange={setPolicyIds} /></div> : null}
        {step === 2 ? <div className={styles.stack}><Alert>{t("reviewHint")}</Alert><dl className={styles.facts}><div><dt>{w("name")}</dt><dd>{name.trim()}</dd></div><div><dt>{w("description")}</dt><dd>{description || "—"}</dd></div><div><dt>{w("members")}</dt><dd>0</dd></div><div><dt>{w("permissions")}</dt><dd>{policyIds.length ? workspace.policies.filter((policy) => policyIds.includes(policy.id)).map((policy) => <Badge key={policy.id}>{policy.name}</Badge>) : t("noPolicies")}</dd></div></dl></div> : null}
        {access.workspaceError ? <Alert status="danger">{w(`errors.${access.workspaceError}`)}</Alert> : null}
      </>}
    </Wizard>
  </div>;
}
