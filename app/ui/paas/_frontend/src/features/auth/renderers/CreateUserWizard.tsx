"use client";

import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import { ArrowRight, Check, CheckCircle2, Code2, ShieldCheck, UserRound } from "lucide-react";
import { ContentPage, Alert, Badge, Button, Checkbox, FormField, Input, PasswordInput, Radio, RadioGroup, TagEditor, Wizard } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { PreviewUserProfile } from "../domain/accessWorkspace";
import { UserPermissionSelector, type UserPermissions } from "./UserPermissionSelector";
import { useAccessDraft } from "./useAccessDraft";
import styles from "./CreateUserWizard.module.css";

type Step = "type" | "identity" | "permissions" | "tags" | "review";
type ErrorKey = "invalidLogin" | "duplicateLogin" | "requiredName" | "requiredAccess" | "invalidTags" | "passwordHint" | "reenterPassword";
type Errors = Partial<Record<"login" | "name" | "access" | "password" | "tags", ErrorKey>>;

export function CreateUserWizard({ onBack }: { onBack(): void }) {
  const access = useAccountAccess();
  const t = useTranslations("UserWizard");
  const a = useTranslations("AccountAccess");
  const auth = useTranslations("Auth");
  const w = useTranslations("IamWorkspace");
  const id = useId();
  const form = useRef<HTMLFormElement>(null);
  const submitting = useRef(false);
  const [step, setStep] = useState(0);
  const [persona, setPersona] = useState("person");
  const [login, setLogin] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [passwordMode, setPasswordMode] = useState("auto");
  const [profile, setProfile] = useState<PreviewUserProfile>({ consoleAccess: true, programmaticAccess: false, passwordResetRequired: true, loginProtection: true, tags: [] });
  const [permissions, setPermissions] = useState<UserPermissions>({ policyIds: [], groupIds: [] });
  const [errors, setErrors] = useState<Errors>({});
  const [complete, setComplete] = useState(false);
  const workspace = access.workspace;
  const scene = access.scene;
  const preview = Boolean(workspace);
  const steps: Step[] = preview ? ["type", "identity", "permissions", "tags", "review"] : ["identity", "permissions", "review"];
  const current = steps[step] ?? "review";
  const busy = access.busy || access.loading;
  const dirty = Boolean(login || name || password || permissions.policyIds.length || permissions.groupIds.length || profile.tags.length || persona !== "person"
    || passwordMode !== "auto" || !profile.consoleAccess || profile.programmaticAccess || !profile.passwordResetRequired || !profile.loginProtection);
  const requestLeave = useAccessDraft({ dirty: dirty && !complete, busy: access.busy, title: t("cancelTitle"), description: t("cancelHint"), form });
  useEffect(() => { if (Object.keys(errors).length) form.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus(); }, [errors]);
  if (!scene) return null;
  function changeStep(next: number) { setErrors({}); setStep(next); }
  function cancel() { requestLeave(() => { setPassword(""); onBack(); }); }
  function validateIdentity(): Errors {
    const result: Errors = {};
    if (!/^[a-z][a-z0-9._-]{2,63}$/.test(login.trim())) result.login = "invalidLogin";
    else if (login.trim() === scene!.primaryLoginName || scene!.users.some((user) => user.loginName === login.trim())) result.login = "duplicateLogin";
    if (!name.trim()) result.name = "requiredName";
    if (preview && !profile.consoleAccess && !profile.programmaticAccess) result.access = "requiredAccess";
    if ((!preview || (profile.consoleAccess && passwordMode === "custom")) && (password.length < 14 || password.length > 128)) result.password = "passwordHint";
    return result;
  }
  function validateTags(): Errors {
    return profile.tags.some((tag) => !tag.key.trim() || /[<>\u0000-\u001f]/.test(tag.key + tag.value)) || new Set(profile.tags.map((tag) => tag.key.trim())).size !== profile.tags.length ? { tags: "invalidTags" } : {};
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || submitting.current) return;
    const invalid = current === "identity" ? validateIdentity() : current === "tags" ? validateTags() : {};
    if (Object.keys(invalid).length) { setErrors(invalid); return; }
    if (current !== "review") { changeStep(step + 1); return; }
    const identityErrors = validateIdentity();
    if (Object.keys(identityErrors).length) { setStep(steps.indexOf("identity")); setErrors(identityErrors); return; }
    const tagErrors = validateTags();
    if (preview && Object.keys(tagErrors).length) { setStep(steps.indexOf("tags")); setErrors(tagErrors); return; }
    submitting.current = true;
    const initialPassword = password;
    setPassword("");
    const accepted = preview ? Boolean(await access.executeWorkspace({ kind: "create-subuser", loginName: login.trim(), displayName: name.trim(), profile, ...permissions })) : await access.execute({ kind: "create-user", loginName: login.trim(), displayName: name.trim(), initialPassword });
    submitting.current = false;
    if (accepted) setComplete(true);
    else { setStep(steps.indexOf("identity")); if (!preview || passwordMode === "custom") setErrors({ password: "reenterPassword" }); }
  }
  const policyIds = new Set([...permissions.policyIds, ...workspace?.groups.filter((group) => permissions.groupIds.includes(group.id)).flatMap((group) => group.policyIds) ?? []]);
  const elevated = Boolean(workspace?.policies.some((policy) => policyIds.has(policy.id) && policy.versions.find((version) => version.id === policy.defaultVersion)?.document.statement.some((statement) => statement.effect === "allow" && statement.action.includes("*"))));
  const errorText = (field: keyof Errors) => errors[field] === "passwordHint" ? a("passwordHint") : errors[field] ? t(errors[field]) : undefined;
  const errorFor = (field: keyof Errors) => errors[field] ? `${id}-${field}-error` : undefined;
  const updateProfile = (next: Partial<PreviewUserProfile>) => setProfile((previous) => ({ ...previous, ...next }));
  return <div className={styles.wizard}>
    <ContentPage.Heading title={a("createUserTitle")} back={{ label: t("backUsers"), parentLabel: a("usersTitle"), disabled: busy, onClick: cancel }} />
    <Wizard label={a("createUserTitle")} steps={steps.map((item) => ({ id: item, label: t(`steps.${item}`) }))} currentStep={step} onStepChange={changeStep} busy={busy} completed={complete}
      title={complete ? t("created") : t(`steps.${current}`)} description={complete ? t("createdHint", { name: login.trim() }) : t(`hints.${current}`)} progressLabel={complete ? undefined : t("stepCount", { current: step + 1, total: steps.length })}
      formRef={form} onSubmit={submit} hint={<><ShieldCheck aria-hidden="true" />{t(preview ? "previewFooter" : "secureFooter")}</>}
      actions={complete ? <Button disabled={busy} onClick={onBack}>{t("done")}<ArrowRight aria-hidden="true" /></Button> : <><Button variant="ghost" disabled={busy} onClick={cancel}>{a("cancel")}</Button>{step > 0 ? <Button variant="secondary" disabled={busy} onClick={() => changeStep(step - 1)}>{a("previousStep")}</Button> : null}<Button type="submit" disabled={busy}>{busy ? a("creating") : current === "review" ? t(preview ? "createMockUser" : "confirmCreate") : a("nextStep")}{!busy && current !== "review" ? <ArrowRight aria-hidden="true" /> : null}</Button></>}
    >
          {complete ? <div className={styles.success}><CheckCircle2 aria-hidden="true" /><div className={styles.successFacts}><span><Check aria-hidden="true" />{t("identityCreated")}</span><span><Check aria-hidden="true" />{t("permissionsSaved")}</span>{profile.tags.length ? <span><Check aria-hidden="true" />{t("tagsSaved")}</span> : null}</div>{preview ? <Alert>{t("mockSecurity")}</Alert> : <Alert>{a("firstLoginHint")}</Alert>}</div> : <>
            {current === "type" ? <div className={styles.typeOptions}>{(["person", "service"] as const).map((type) => <div key={type} data-selected={persona === type || undefined}><Radio aria-label={t(type)} checked={persona === type} name={`${id}-type`} onChange={() => { setPersona(type); updateProfile({ consoleAccess: type === "person", programmaticAccess: type === "service" }); if (type === "service") setPassword(""); }}><span className={styles.typeIcon}>{type === "person" ? <UserRound aria-hidden="true" /> : <Code2 aria-hidden="true" />}</span><strong>{t(type)}</strong><span>{t(`${type}Hint`)}</span></Radio></div>)}</div> : null}
            {current === "identity" ? <div className={styles.identity}>
              <p className={styles.muted}>{a("userType")}：{a("child")} · {a("subuserOwnershipHint")}</p>
              <div className={styles.formSection}><h3>{t("basicInfo")}</h3><div className={styles.formGrid}>
                <FormField id={`${id}-login`} label={a("childLogin")} hint={a("loginHint")} error={errorText("login")}><Input id={`${id}-login`} aria-required="true" aria-describedby={[`${id}-login-hint`, errorFor("login")].filter(Boolean).join(" ")} invalid={Boolean(errors.login)} maxLength={64} autoComplete="off" placeholder={a("childPlaceholder")} value={login} onChange={(event) => setLogin(event.target.value)} /></FormField>
                <FormField id={`${id}-name`} label={a("displayName")} hint={t("nameHint")} error={errorText("name")}><Input id={`${id}-name`} aria-required="true" aria-describedby={[`${id}-name-hint`, errorFor("name")].filter(Boolean).join(" ")} invalid={Boolean(errors.name)} maxLength={128} autoComplete="off" placeholder={t("namePlaceholder")} value={name} onChange={(event) => setName(event.target.value)} /></FormField>
              </div></div>
              {preview ? <div className={styles.formSection}><h3>{t("accessMethods")}</h3><p className={styles.muted}>{t("accessHint")}</p><div className={styles.accessOptions}>
                <Checkbox aria-label={t("consoleAccess")} aria-invalid={Boolean(errors.access)} aria-describedby={errorFor("access")} checked={profile.consoleAccess} onChange={(event) => { updateProfile({ consoleAccess: event.target.checked }); setPassword(""); }}>{t("consoleAccess")}</Checkbox>
                <Checkbox aria-label={t("programmaticAccess")} checked={profile.programmaticAccess} onChange={(event) => updateProfile({ programmaticAccess: event.target.checked })}>{t("programmaticAccess")}</Checkbox>
              </div>{errors.access ? <p className={styles.error} id={`${id}-access-error`} role="alert">{errorText("access")}</p> : null}{profile.programmaticAccess ? <p className={styles.muted}>{t("keyHint")}</p> : null}</div> : null}
              {!preview || profile.consoleAccess ? <div className={styles.formSection}><h3>{a("loginSecurity")}</h3>{preview ? <RadioGroup label={a("initialPassword")} options={[{ value: "auto", label: t("autoPassword") }, { value: "custom", label: t("customPassword") }]} value={passwordMode} onValueChange={(mode) => { setPasswordMode(mode); setPassword(""); }} /> : null}
                {!preview || passwordMode === "custom" ? <div className={styles.passwordField}><FormField id={`${id}-password`} label={a("initialPassword")} hint={a("passwordHint")} error={errorText("password")}><PasswordInput id={`${id}-password`} aria-required="true" aria-invalid={Boolean(errors.password)} aria-describedby={[`${id}-password-hint`, errorFor("password")].filter(Boolean).join(" ")} value={password} onChange={(event) => setPassword(event.target.value)} maxLength={128} autoComplete="new-password" showLabel={auth("showPassword")} hideLabel={auth("hidePassword")} capsLockLabel={auth("capsLock")} /></FormField></div> : null}
                {preview ? <div className={styles.securityOptions}><Checkbox checked={profile.passwordResetRequired} onChange={(event) => updateProfile({ passwordResetRequired: event.target.checked })}>{t("forceReset")}</Checkbox><Checkbox checked={profile.loginProtection} onChange={(event) => updateProfile({ loginProtection: event.target.checked })}>{t("loginProtection")}</Checkbox><p className={styles.muted}>{t("mockSecurity")}</p></div> : <p className={styles.muted}>{a("firstLoginHint")}</p>}
              </div> : null}
            </div> : null}
            {current === "permissions" ? workspace ? <UserPermissionSelector workspace={workspace} scene={scene} value={permissions} onChange={setPermissions} /> : <div className={styles.livePermissions}><Alert status="info">{a("liveUserDefaultNoGrant")}</Alert><p className={styles.muted}>{a("livePolicyAfterCreateHint")}</p></div> : null}
            {current === "tags" ? <div className={styles.tags}><p className={styles.muted}>{t("tagHint")}</p><TagEditor value={profile.tags} onChange={(tags) => updateProfile({ tags })} error={errorText("tags")} labels={{ key: (index) => t("tagKey", { index }), value: (index) => t("tagValue", { index }), remove: (index) => t("removeTag", { index }), add: t("addTag"), empty: t("noTagsHint"), count: t("tagCount", { count: profile.tags.length }) }} /></div> : null}
            {current === "review" ? <div className={styles.review}><Alert status={elevated ? "warning" : "info"}>{elevated ? preview ? t("widePermissionWarning") : a("adminGrantWarning") : t("reviewHint")}</Alert>
              <section><div className={styles.reviewHeading}><h3>{t("basicInfo")}</h3><Button size="small" variant="ghost" onClick={() => changeStep(steps.indexOf("identity"))}>{t("editIdentity")}</Button></div><dl><div><dt>{a("userType")}</dt><dd>{a("child")}</dd></div><div><dt>{a("ownership")}</dt><dd>{scene.accountName} · {scene.accountId}</dd></div><div><dt>{a("childLogin")}</dt><dd>{login.trim()}</dd></div><div><dt>{a("displayName")}</dt><dd>{name.trim()}</dd></div><div><dt>{a("qualifiedLogin")}</dt><dd>{login.trim()}@{scene.loginAlias ?? scene.accountId}</dd></div><div><dt>{t("accessMethods")}</dt><dd>{[!preview || profile.consoleAccess ? t("consoleAccess") : "", preview && profile.programmaticAccess ? t("programmaticAccess") : ""].filter(Boolean).join(" · ")}</dd></div>{!preview || profile.consoleAccess ? <div><dt>{a("initialPassword")}</dt><dd>{preview && passwordMode === "auto" ? t("autoPassword") : a("passwordReady")}</dd></div> : null}{preview && profile.consoleAccess ? <><div><dt>{t("forceReset")}</dt><dd>{t(profile.passwordResetRequired ? "enabled" : "disabled")}</dd></div><div><dt>{t("loginProtection")}</dt><dd>{t(profile.loginProtection ? "enabled" : "disabled")}</dd></div></> : null}</dl></section>
              <section><div className={styles.reviewHeading}><h3>{t("steps.permissions")}</h3><Button size="small" variant="ghost" onClick={() => changeStep(steps.indexOf("permissions"))}>{t("editPermissions")}</Button></div>{workspace ? <dl><div><dt>{t("direct")}</dt><dd>{workspace.policies.filter((policy) => permissions.policyIds.includes(policy.id)).map((policy) => <Badge key={policy.id}>{policy.name}</Badge>)}{!permissions.policyIds.length ? a("noGrantLabel") : null}</dd></div><div><dt>{t("joinGroups")}</dt><dd>{workspace.groups.filter((group) => permissions.groupIds.includes(group.id)).map((group) => <Badge key={group.id}>{group.name}</Badge>)}{!permissions.groupIds.length ? t("none") : null}</dd></div></dl> : <p>{a("noGrantLabel")} · {a("livePolicyAfterCreateShort")}</p>}</section>
              {preview ? <section><div className={styles.reviewHeading}><h3>{t("steps.tags")}</h3><Button size="small" variant="ghost" onClick={() => changeStep(steps.indexOf("tags"))}>{t("editTags")}</Button></div><div className={styles.tagActions}>{profile.tags.map((tag) => <Badge key={tag.key}>{tag.key} : {tag.value || "—"}</Badge>)}{!profile.tags.length ? <span className={styles.muted}>{t("none")}</span> : null}</div></section> : null}
            </div> : null}
            {access.workspaceError ? <Alert status="danger">{w(`errors.${access.workspaceError}`)}</Alert> : null}{access.error ? <Alert status="danger">{a(`errors.${access.error}`)}</Alert> : null}
          </>}
    </Wizard>
  </div>;
}
