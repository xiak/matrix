"use client";

import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import { ShieldCheck } from "lucide-react";
import { ContentPage, Alert, Button, FormField, Input, TextArea, Wizard } from "@ui/xiak";
import { accountError, useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import { useAccessDraft } from "./useAccessDraft";
import styles from "./PolicyAuthoringWizard.module.css";

/** Creation owns only the group. Memberships and policy attachments are separate commands in group detail. */
export function GroupCreationWizard({ workspace, onBack, onDone }: { workspace?: AccessWorkspace; onBack(): void; onDone(id: string): void }) {
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
  const [error, setError] = useState<"invalidName" | "duplicate" | null>(null);
  const [liveError, setLiveError] = useState<string | null>(null);
  const [liveBusy, setLiveBusy] = useState(false);
  const [created, setCreated] = useState(false);
  const [createdId, setCreatedId] = useState<string | null>(null);
  const requestId = useRef(crypto.randomUUID());
  const dirty = Boolean(name || description);
  const busy = workspace ? access.busy || access.loading : liveBusy;
  const requestLeave = useAccessDraft({ dirty: dirty && !created, busy, title: t("cancelTitle"), description: t("cancelHint"), form });
  const clearWorkspaceError = access.clearWorkspaceError;
  const clear = useCallback(() => { clearWorkspaceError(); setLiveError(null); }, [clearWorkspaceError]);
  useEffect(() => { clearWorkspaceError(); }, [clearWorkspaceError]);
  useEffect(() => {
    const target = form.current?.querySelector<HTMLElement>('[aria-invalid="true"]');
    if (error) { target?.focus({ preventScroll: true }); target?.scrollIntoView?.({ block: "center" }); }
  }, [error]);
  function cancel() { requestLeave(onBack); }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || submitting.current) return;
    const invalid = !name.trim() || name.length > 64 || /[<>\u0000-\u001f]/.test(name) ? "invalidName" : workspace?.groups.some((group) => group.name.toLowerCase() === name.trim().toLowerCase()) ? "duplicate" : null;
    if (invalid) { setError(invalid); setStep(0); return; }
    if (step < 1) { setStep(step + 1); return; }
    submitting.current = true;
    if (workspace) {
      const saved = await access.executeWorkspace({ kind: "create-group", name: name.trim(), description });
      submitting.current = false;
      if (saved) setCreated(true);
      return;
    }
    const client = access.groups;
    if (!client?.canCreate) { setLiveError(a("errors.forbidden")); submitting.current = false; return; }
    setLiveBusy(true); setLiveError(null);
    try {
      const group = await client.create({ name: name.trim(), description, requestId: requestId.current });
      setCreatedId(group.id);
      setCreated(true);
    } catch (failure) { setLiveError(a(`errors.${accountError(failure)}`)); }
    finally { submitting.current = false; setLiveBusy(false); }
  }
  const steps = ["details", "review"] as const;
  const currentStep = steps[step] ?? "details";
  return <div className={styles.root}><ContentPage.Heading title={w("createGroup")} back={{ label: t("back"), parentLabel: w("groups"), disabled: busy, onClick: cancel }} />
    <Wizard label={w("createGroup")} steps={steps.map((key) => ({ id: key, label: t(`steps.${key}`) }))} currentStep={step} onStepChange={(next) => { setError(null); clear(); setStep(next); }} completed={created} busy={busy} formRef={form} onSubmit={submit}
      title={created ? t("created") : t(`steps.${currentStep}`)} description={created ? t("createdHint") : t(`hints.${currentStep}`)} progressLabel={u("stepCount", { current: step + 1, total: 2 })} hint={<><ShieldCheck aria-hidden="true" />{t(workspace ? "mockHint" : "liveHint")}</>}
      actions={created ? <Button onClick={() => { const groupId = createdId ?? workspace?.groups.find((entry) => entry.name === name.trim())?.id; if (groupId) onDone(groupId); else onBack(); }}>{t("viewGroup")}</Button> : <><Button variant="ghost" disabled={busy} onClick={cancel}>{w("cancel")}</Button>{step ? <Button variant="secondary" disabled={busy} onClick={() => setStep(step - 1)}>{a("previousStep")}</Button> : null}<Button type="submit" disabled={busy}>{busy ? t("saving") : step < 1 ? t("next") : w("createGroup")}</Button></>}>
      {created ? <Alert status="success">{t(workspace ? "createdScope" : "liveCreatedScope")}</Alert> : <>
        {step === 0 ? <div className={styles.metadata}><FormField id={id + "-name"} label={w("name")} hint={t("nameHint")} error={error ? t(error) : undefined}><Input id={id + "-name"} aria-required="true" value={name} maxLength={64} invalid={Boolean(error)} aria-describedby={[id + "-name-hint", error ? id + "-name-error" : ""].filter(Boolean).join(" ")} onChange={(event) => { setName(event.target.value); setError(null); setLiveError(null); requestId.current = crypto.randomUUID(); }} /></FormField><FormField id={id + "-description"} label={w("description")}><TextArea id={id + "-description"} rows={3} maxLength={workspace ? 256 : 512} value={description} onChange={(event) => { setDescription(event.target.value); setLiveError(null); requestId.current = crypto.randomUUID(); }} /></FormField></div> : null}
        {step === 1 ? <div className={styles.stack}><Alert>{t("reviewHint")}</Alert><dl className={styles.facts}><div><dt>{w("name")}</dt><dd>{name.trim()}</dd></div><div><dt>{w("description")}</dt><dd>{description || "—"}</dd></div><div><dt>{w("members")}</dt><dd>0</dd></div><div><dt>{t("directPolicies")}</dt><dd>{t("directPolicyCount", { count: 0 })}</dd></div></dl></div> : null}
        {workspace && access.workspaceError ? <Alert status="danger">{w(`errors.${access.workspaceError}`)}</Alert> : null}
        {liveError ? <Alert status="danger">{liveError}</Alert> : null}
      </>}
    </Wizard>
  </div>;
}
