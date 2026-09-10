"use client";

import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import { ArrowRight, ShieldCheck } from "lucide-react";
import { ContentPage, Alert, Badge, Button, FormField, Input, Select, TagEditor, TextArea, Wizard } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import { policyGrantTargets, policyVersionLimit, type AccessPolicy, type AccessWorkspace, type PolicyTargets } from "../domain/accessWorkspace";
import { parsePolicyDocument } from "../domain/policyDocument";
import { AccessWorkspaceError } from "../domain/accessWorkspaceError";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { PolicyDocumentEditor } from "./PolicyDocumentEditor";
import { PolicyDocumentViewer } from "./PolicyDocumentViewer";
import { PolicyTargetSelector } from "./PolicyTargetSelector";
import { PolicyDocumentChanges } from "./PolicyDocumentChanges";
import { PolicyAffectedIdentities, PolicyAssociationChanges } from "./PolicyAssociationReview";
import { useAccessDraft } from "./useAccessDraft";
import styles from "./PolicyAuthoringWizard.module.css";

const steps = ["document", "details", "review"] as const;
const emptyTargets = (): PolicyTargets => ({ userIds: [], groupIds: [], roleIds: [] });
const policyDocument = (policy: AccessPolicy) => policy.versions.find((entry) => entry.id === policy.defaultVersion)!.document;
type DraftErrors = { document?: AccessWorkspaceError["code"]; name?: "invalidName" | "duplicate"; tags?: boolean; replacement?: boolean };

export function PolicyAuthoringWizard({ policy, copy = false, workspace, scene, onBack, onDone, doneLabel }: {
  policy?: AccessPolicy; copy?: boolean; workspace: AccessWorkspace; scene: AccountAccessScene; onBack(): void; onDone(policyId: string): void; doneLabel?: string;
}) {
  const access = useAccountAccess();
  const t = useTranslations("PolicyWizard");
  const w = useTranslations("IamWorkspace");
  const a = useTranslations("AccountAccess");
  const u = useTranslations("UserWizard");
  const id = useId();
  const form = useRef<HTMLFormElement>(null);
  const submitting = useRef(false);
  const editing = Boolean(policy && !copy);
  const [name, setName] = useState(policy ? policy.name + (copy ? "-copy" : "") : "");
  const [description, setDescription] = useState(policy?.description ?? "");
  const [tags, setTags] = useState<AccessPolicy["tags"]>(() => policy?.tags.map((entry) => ({ ...entry })) ?? []);
  const [initialDocument] = useState(() => JSON.stringify(policy ? policyDocument(policy) : { version: "1", statement: [{ effect: "allow", action: [], resource: ["*"] }] }, null, 2));
  const [text, setText] = useState(initialDocument);
  const [targets, setTargets] = useState<PolicyTargets>(() => editing && policy ? {
    userIds: Object.entries(workspace.userPolicies).filter(([, ids]) => ids.includes(policy.id)).map(([user]) => user),
    groupIds: workspace.groups.filter((group) => group.policyIds.includes(policy.id)).map((group) => group.id),
    roleIds: workspace.roles.filter((role) => role.policyIds.includes(policy.id)).map((role) => role.id)
  } : emptyTargets());
  const [step, setStep] = useState(0);
  const [complete, setComplete] = useState(false);
  const [replaceVersion, setReplaceVersion] = useState("");
  const [errors, setErrors] = useState<DraftErrors>({});
  const [initial] = useState(() => JSON.stringify({ name, description, tags, text, targets }));
  const dirty = initial !== JSON.stringify({ name, description, tags, text, targets });
  const busy = access.busy || access.loading;
  const requestLeave = useAccessDraft({ dirty: dirty && !complete, busy: access.busy, title: t("cancelTitle"), description: t("cancelHint"), form });
  const validation = useMemo(() => {
    try { return { document: parsePolicyDocument(text, workspace.accountId), error: null }; }
    catch (error) { return { document: null, error: error instanceof AccessWorkspaceError ? error.code : "invalid" as const }; }
  }, [text, workspace.accountId]);
  const currentPolicy = editing ? workspace.policies.find((entry) => entry.id === policy?.id) : undefined;
  const changedContent = Boolean(currentPolicy && validation.document && JSON.stringify(policyDocument(currentPolicy)) !== JSON.stringify(validation.document));
  const needsReplacement = changedContent && currentPolicy!.versions.length >= policyVersionLimit;
  const replacement = needsReplacement ? currentPolicy?.versions.find((entry) => entry.id === Number(replaceVersion) && entry.id !== currentPolicy.defaultVersion) : undefined;
  const selected = [
    ...scene.users.filter((user) => targets.userIds.includes(user.id)).map((user) => ({ id: user.id, name: user.loginName, type: "userIds" as const })),
    ...workspace.groups.filter((group) => targets.groupIds.includes(group.id)).map((group) => ({ id: group.id, name: group.name, type: "groupIds" as const })),
    ...workspace.roles.filter((role) => targets.roleIds.includes(role.id)).map((role) => ({ id: role.id, name: role.name, type: "roleIds" as const }))
  ];
  const clearError = access.clearWorkspaceError;
  useEffect(() => { clearError(); }, [clearError]);
  useEffect(() => {
    if (!Object.keys(errors).length) return;
    const target = form.current?.querySelector<HTMLElement>('[aria-invalid="true"], [data-policy-validation]');
    target?.focus({ preventScroll: true });
    target?.scrollIntoView?.({ block: "center", inline: "nearest" });
  }, [errors]);
  function changeStep(next: number) { setErrors({}); clearError(); setStep(next); }
  function cancel() { requestLeave(onBack); }
  function metadataErrors() {
    const result: typeof errors = {};
    if (!name.trim() || name.length > 64 || /[<>\u0000-\u001f]/.test(name)) result.name = "invalidName";
    else if (workspace.policies.some((entry) => entry.id !== (editing ? policy?.id : undefined) && entry.name.toLowerCase() === name.trim().toLowerCase())) result.name = "duplicate";
    if (tags.length > 10 || tags.some((tag) => !tag.key.trim() || tag.key.length > 64 || tag.value.length > 128 || /[<>\u0000-\u001f]/.test(tag.key + tag.value)) || new Set(tags.map((tag) => tag.key.trim())).size !== tags.length) result.tags = true;
    return result;
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || submitting.current) return;
    if (!validation.document) { setStep(0); setErrors({ document: validation.error ?? "invalid" }); return; }
    if (step > 0) {
      const invalid = metadataErrors();
      if (Object.keys(invalid).length) { setStep(1); setErrors(invalid); return; }
    }
    if (step < 2) { changeStep(step + 1); return; }
    if (needsReplacement && !replacement) { setErrors({ replacement: true }); return; }
    submitting.current = true;
    const saved = await access.executeWorkspace({ kind: "save-policy", id: editing ? policy?.id : undefined, name: name.trim(), description, tags, document: validation.document, targets, replaceVersion: replacement?.id });
    submitting.current = false;
    if (saved) setComplete(true);
  }
  return <div className={styles.root}>
    <ContentPage.Heading title={editing ? `${w("edit")} · ${policy?.name}` : w("createPolicy")} back={{ label: t("back"), parentLabel: w("policies"), disabled: busy, onClick: cancel }} />
    <Wizard label={editing ? w("editPolicyContent") : w("createPolicy")} steps={steps.map((key) => ({ id: key, label: t(`steps.${key}`) }))} currentStep={step} onStepChange={changeStep} completed={complete} busy={busy} formRef={form} onSubmit={submit}
      title={complete ? t("saved") : t(`steps.${steps[step]!}`)} description={complete ? t("savedHint", { name: name.trim() }) : t(`hints.${steps[step]!}`)} progressLabel={complete ? undefined : u("stepCount", { current: step + 1, total: steps.length })} hint={<><ShieldCheck aria-hidden="true" />{t("mockHint")}</>}
      actions={complete ? <Button onClick={() => { const saved = workspace.policies.find((entry) => entry.name === name.trim()); if (saved) onDone(saved.id); else onBack(); }}>{doneLabel ?? t("viewPolicy")}<ArrowRight aria-hidden="true" /></Button> : <><Button variant="ghost" disabled={busy} onClick={cancel}>{w("cancel")}</Button>{step > 0 ? <Button variant="secondary" disabled={busy} onClick={() => changeStep(step - 1)}>{a("previousStep")}</Button> : null}<Button type="submit" disabled={busy}>{busy ? a("saving") : step < 2 ? a("nextStep") : editing ? t("confirmSave") : t("confirmCreate")}</Button></>}>
      {complete ? <Alert status="success">{t("savedScope")}</Alert> : <>
        {step === 0 ? <PolicyDocumentEditor accountId={workspace.accountId} resources={workspace.testResources} text={text} hasDocumentChanges={text !== initialDocument} onChange={(next) => { setText(next); setErrors({}); }} policies={workspace.policies} error={errors.document ? w(`errors.${errors.document}`) : undefined} /> : null}
        {step === 1 ? <div className={styles.stack}>
          <div className={styles.metadata}><div className={styles.fields}>
            <FormField id={id + "-name"} label={w("name")} hint={editing ? w("policyNameImmutable") : t("nameHint")} error={errors.name ? errors.name === "duplicate" ? w("errors.duplicate") : t("invalidName") : undefined}><Input id={id + "-name"} readOnly={editing} maxLength={64} value={name} invalid={Boolean(errors.name)} aria-describedby={[id + "-name-hint", errors.name ? id + "-name-error" : ""].filter(Boolean).join(" ")} onChange={(event) => { setName(event.target.value); setErrors({}); }} /></FormField>
            <FormField id={id + "-description"} label={w("description")}><TextArea id={id + "-description"} maxLength={256} rows={2} value={description} onChange={(event) => setDescription(event.target.value)} /></FormField>
          </div><section className={styles.section}><h3>{t("metadataTags")}</h3><p className={styles.note}>{t("tagsHint")}</p><TagEditor value={tags} onChange={(next) => { setTags(next); setErrors({}); }} error={errors.tags ? u("invalidTags") : undefined} labels={{ key: (index) => u("tagKey", { index }), value: (index) => u("tagValue", { index }), remove: (index) => u("removeTag", { index }), add: u("addTag"), empty: u("noTagsHint"), count: u("tagCount", { count: tags.length }) }} /></section></div>
          <section className={styles.section}><h3>{t("optionalTargets")}</h3><p className={styles.note}>{t("targetsHint")}</p><PolicyTargetSelector workspace={workspace} scene={scene} value={targets} onChange={setTargets} /></section>
        </div> : null}
        {step === 2 && validation.document ? <div className={styles.stack}>
          <Alert status={selected.length ? "warning" : "info"}>{selected.length ? t("grantImpact", { count: selected.length }) : t("noTargetsHint")}</Alert>
          <div className={styles.row}><h3>{t("steps.details")}</h3><Button variant="ghost" size="small" onClick={() => changeStep(1)}>{w("edit")}</Button></div>
          <dl className={styles.facts}><div><dt>{w("name")}</dt><dd>{name.trim()}</dd></div><div><dt>{w("description")}</dt><dd>{description || "—"}</dd></div><div><dt>{t("metadataTags")}</dt><dd>{tags.length ? tags.map((tag) => <Badge key={tag.key}>{tag.key} : {tag.value || "—"}</Badge>) : "—"}</dd></div><div><dt>{w("associations")}</dt><dd>{selected.length ? selected.map((target) => <Badge key={target.type + target.id}>{t(`targets.${target.type}`)} · {target.name}</Badge>) : t("noTargets")}</dd></div></dl>
          <section className={styles.section}><div className={styles.row}><h3>{w("document")}</h3><Button variant="ghost" size="small" onClick={() => changeStep(0)}>{w("editPolicyContent")}</Button></div><PolicyDocumentViewer document={validation.document} /></section>
          {editing && currentPolicy ? <><Alert>{changedContent ? t("newRevision", { version: currentPolicy.lastVersion + 1 }) : t("metadataOnly")}</Alert><details><summary>{t("inspectCurrent", { version: currentPolicy.defaultVersion })}</summary><PolicyDocumentViewer document={policyDocument(currentPolicy)} /></details></> : null}
          {editing && currentPolicy ? <><PolicyDocumentChanges before={policyDocument(currentPolicy)} after={validation.document} /><PolicyAffectedIdentities policyId={currentPolicy.id} targets={targets} workspace={workspace} scene={scene} /><PolicyAssociationChanges before={policyGrantTargets(workspace, currentPolicy.id)} after={targets} workspace={workspace} scene={scene} /></> : null}
          {needsReplacement ? <section className={styles.section}><Alert status="warning">{t("historyFull")}</Alert><FormField id={id + "-replacement"} label={t("replacement")} error={errors.replacement ? t("chooseReplacement") : undefined}><Select id={id + "-replacement"} aria-invalid={Boolean(errors.replacement)} value={replaceVersion} onValueChange={(value) => { setReplaceVersion(value); setErrors({}); }} placeholder={t("chooseReplacement")} options={currentPolicy!.versions.filter((entry) => entry.id !== currentPolicy!.defaultVersion).map((entry) => ({ value: String(entry.id), label: `v${entry.id}` }))} /></FormField>{replacement ? <><p className={styles.note}>{t("replacementHint", { version: replacement.id })}</p><PolicyDocumentViewer document={replacement.document} /></> : null}</section> : null}
        </div> : null}
        {access.workspaceError ? <Alert status="danger">{w(`errors.${access.workspaceError}`)}</Alert> : null}
      </>}
    </Wizard>
  </div>;
}
