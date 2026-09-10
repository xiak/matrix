"use client";
import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import { ShieldCheck } from "lucide-react";
import { ContentPage, Alert, Badge, Button, FormField, Input, TextArea, Wizard } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessRole, AccessWorkspace } from "../domain/accessWorkspace";
import { validateRoleTrust, type RoleTrust } from "../domain/roleTrust";
import { includesPermissionManagement } from "../domain/policyDocument";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceSelection } from "./AccessWorkspaceUi";
import { BoundarySelector } from "./PermissionBoundary";
import { RoleSessionSettings, RoleTags, RoleTrustFields } from "./RoleConfiguration";
import { useAccessDraft } from "./useAccessDraft";
import styles from "./PolicyAuthoringWizard.module.css";

export function RoleCreationWizard({ workspace, scene, onBack, onDone }: { workspace: AccessWorkspace; scene: AccountAccessScene; onBack(): void; onDone(id: string): void }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), u = useTranslations("UserWizard"), a = useTranslations("AccountAccess");
  const access = useAccountAccess(), id = useId(), form = useRef<HTMLFormElement>(null), submitting = useRef(false);
  const [step, setStep] = useState(0), [name, setName] = useState(""), [description, setDescription] = useState("");
  const [trust, setTrust] = useState<RoleTrust>({ principalType: "account", principal: workspace.accountId, trustedUserIds: [] });
  const [policyIds, setPolicyIds] = useState<string[]>([]), [boundaryPolicyId, setBoundary] = useState<string>();
  const [tags, setTags] = useState<AccessRole["tags"]>([]), [settings, setSettings] = useState({ sessionMinutes: 60, consoleAccess: false });
  const [error, setError] = useState<"invalidTrust" | "invalidName" | "duplicate" | "invalidMetadata" | null>(null), [created, setCreated] = useState(false);
  const busy = access.busy || access.loading;
  const dirty = Boolean(name || description || trust.principalType !== "account" || trust.trustedUserIds.length || policyIds.length || boundaryPolicyId || tags.length || settings.sessionMinutes !== 60 || settings.consoleAccess);
  const requestLeave = useAccessDraft({ dirty: dirty && !created, busy: access.busy, title: t("cancelTitle"), description: t("cancelHint"), form });
  const clear = access.clearWorkspaceError;
  useEffect(() => { clear(); }, [clear]);
  useEffect(() => { if (!error) return; const target = form.current?.querySelector<HTMLElement>('[role="alert"]'); target?.focus({ preventScroll: true }); target?.scrollIntoView?.({ block: "center" }); }, [error]);
  function cancel() { requestLeave(onBack); }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (busy || submitting.current) return;
    try { validateRoleTrust(workspace, trust, scene.users.map((user) => user.id)); } catch { setError("invalidTrust"); setStep(0); return; }
    if (step >= 2) {
      const invalid = !name.trim() || name.length > 64 || /[<>\u0000-\u001f]/.test(name);
      if (invalid || workspace.roles.some((role) => role.name.toLowerCase() === name.trim().toLowerCase())) { setError(invalid ? "invalidName" : "duplicate"); setStep(2); return; }
      if (!Number.isInteger(settings.sessionMinutes) || settings.sessionMinutes < 15 || settings.sessionMinutes > 720 || tags.length > 10 || tags.some((tag) => !tag.key.trim() || tag.key.length > 64 || tag.value.length > 128 || /[<>\u0000-\u001f]/.test(tag.key + tag.value)) || new Set(tags.map((tag) => tag.key.trim())).size !== tags.length) { setError("invalidMetadata"); setStep(2); return; }
    }
    setError(null); if (step < 3) { setStep(step + 1); return; }
    submitting.current = true;
    const saved = await access.executeWorkspace({ kind: "create-role", name, description, ...trust, ...settings, policyIds, boundaryPolicyId, tags });
    submitting.current = false; if (saved) setCreated(true);
  }
  const steps = ["trust", "permissions", "details", "review"] as const;
  const highPrivilege = workspace.policies.some((policy) => {
    const document = policy.versions.find((version) => version.id === policy.defaultVersion)?.document;
    return policyIds.includes(policy.id) && document && includesPermissionManagement(document);
  });
  const selectedNames = (ids: string[]) => ids.map((id) => workspace.policies.find((entry) => entry.id === id)?.name ?? id).join(" · ");
  return <div className={styles.root}><ContentPage.Heading title={w("createRole")} back={{ label: t("back"), parentLabel: w("roles"), disabled: busy, onClick: cancel }} />
    <Wizard label={w("createRole")} steps={steps.map((key) => ({ id: key, label: t(`steps.${key}`) }))} currentStep={step} onStepChange={(step) => { setError(null); clear(); setStep(step); }} completed={created} busy={busy} formRef={form} onSubmit={submit} title={created ? t("created") : t(`steps.${steps[step] ?? "trust"}`)} description={created ? t("createdHint") : t(`hints.${steps[step] ?? "trust"}`)} progressLabel={u("stepCount", { current: step + 1, total: 4 })} hint={<><ShieldCheck aria-hidden="true" />{w("roleSecurity")}</>}
      actions={created ? <Button onClick={() => { const role = workspace.roles.find((role) => role.name === name.trim()); if (role) onDone(role.id); else onBack(); }}>{t("viewRole")}</Button> : <><Button variant="ghost" disabled={busy} onClick={cancel}>{w("cancel")}</Button>{step ? <Button variant="secondary" disabled={busy} onClick={() => { setStep(step - 1); setError(null); }}>{a("previousStep")}</Button> : null}<Button type="submit" disabled={busy}>{busy ? t("saving") : step < 3 ? t("next") : w("createRole")}</Button></>}>
      {created ? <Alert status="success">{t("createdHint")}</Alert> : <>
        {error ? <Alert status="danger" tabIndex={-1}>{t(error)}</Alert> : null}
        {(step === 1 || step === 3) && highPrivilege ? <Alert status="warning">{w("highPrivilege")}</Alert> : null}
        {step === 0 ? <RoleTrustFields workspace={workspace} users={scene.users.map((user) => ({ id: user.id, name: user.loginName }))} value={trust} onChange={(next) => { if (next.principalType === "service") setSettings((value) => ({ ...value, consoleAccess: false })); setTrust(next); setError(null); }} /> : null}
        {step === 1 ? <div className={styles.stack}><Alert>{t("permissionsHint")}</Alert><WorkspaceSelection label={w("selectPolicies")} options={workspace.policies} value={policyIds} onChange={setPolicyIds} /><section className={styles.section}><BoundarySelector workspace={workspace} value={boundaryPolicyId} onChange={setBoundary} /></section></div> : null}
        {step === 2 ? <div className={styles.metadata}><FormField id={id + "-name"} label={w("name")} hint={t("nameHint")}><Input id={id + "-name"} required maxLength={64} value={name} aria-describedby={id + "-name-hint"} onChange={(event) => { setName(event.target.value); setError(null); }} /></FormField><FormField id={id + "-description"} label={w("description")}><TextArea id={id + "-description"} maxLength={256} rows={3} value={description} onChange={(event) => setDescription(event.target.value)} /></FormField><section className={styles.section}><h3>{t("tags")}</h3><RoleTags value={tags} onChange={setTags} /></section><RoleSessionSettings value={settings} onChange={setSettings} service={trust.principalType === "service"} /></div> : null}
        {step === 3 ? <div className={styles.stack}><Alert>{t("reviewHint")}</Alert><dl className={styles.facts}><div><dt>{w("name")}</dt><dd>{name.trim()}</dd></div><div><dt>{w("description")}</dt><dd>{description || "—"}</dd></div><div><dt>{w("principalType")}</dt><dd>{w(trust.principalType === "service" ? "servicePrincipal" : trust.principalType)}</dd></div><div><dt>{w("principal")}</dt><dd>{trust.principalType === "account" ? trust.trustedUserIds.map((id) => scene.users.find((user) => user.id === id)?.loginName ?? id).join(" · ") : workspace.providers.find((entry) => entry.id === trust.principal)?.name ?? trust.principal}</dd></div><div><dt>{w("permissions")}</dt><dd>{selectedNames(policyIds) || t("noPermissions")}</dd></div><div><dt>{t("boundary")}</dt><dd>{boundaryPolicyId ? selectedNames([boundaryPolicyId]) : t("noBoundary")}</dd></div><div><dt>{w("sessionMinutes")}</dt><dd>{settings.sessionMinutes}</dd></div><div><dt>{w("consoleAccess")}</dt><dd>{w(settings.consoleAccess ? "enabled" : "disabled")}</dd></div><div><dt>{t("tags")}</dt><dd>{tags.length ? tags.map((tag) => <Badge key={tag.key}>{tag.key} : {tag.value || "—"}</Badge>) : "—"}</dd></div></dl></div> : null}
        {access.workspaceError ? <Alert status="danger">{w(`errors.${access.workspaceError}`)}</Alert> : null}
      </>}
    </Wizard>
  </div>;
}
