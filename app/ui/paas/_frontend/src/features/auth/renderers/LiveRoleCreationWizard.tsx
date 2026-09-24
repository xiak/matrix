"use client";

import { useEffect, useId, useLayoutEffect, useRef, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import { ShieldCheck } from "lucide-react";
import { Alert, Badge, Button, ContentPage, FormField, Input, TextArea, Wizard } from "@ui/xiak";
import { accountError, type RoleAccessClient } from "../application/AccountAccessProvider";
import type { CreateRoleCommand, RoleTag } from "../domain/roles";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceSelection } from "./AccessWorkspaceUi";
import { RoleTags } from "./RoleConfiguration";
import { useAccessDraft } from "./useAccessDraft";
import styles from "./PolicyAuthoringWizard.module.css";

type ValidationError = "invalidTrust" | "invalidName" | "invalidMetadata";

function validMetadata(name: string, description: string, tags: RoleTag[], minutes: number): ValidationError | null {
  if (!name || Array.from(name).length > 64 || /[<>\p{Cc}]/u.test(name)) return "invalidName";
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 720 || Array.from(description).length > 512 || /\p{Cc}/u.test(description)) return "invalidMetadata";
  if (tags.length > 50 || new Set(tags.map((tag) => tag.key.trim())).size !== tags.length ||
      tags.some((tag) => !tag.key.trim() || tag.key !== tag.key.trim() || tag.value !== tag.value.trim() ||
        Array.from(tag.key).length > 64 || Array.from(tag.value).length > 256 || /[<>\p{Cc}]/u.test(tag.key + tag.value)) ||
      tags.reduce((size, tag) => size + tag.key.length + tag.value.length, name.length + description.length) > 4096) return "invalidMetadata";
  return null;
}

/** Live role creation owns metadata and the initial USER trust document only. Grants and the mandatory boundary remain separate commands. */
export function LiveRoleCreationWizard({ client, scene, onBack, onDone }: {
  client: RoleAccessClient;
  scene: AccountAccessScene;
  onBack(): void;
  onDone(id: string): void;
}) {
  const t = useTranslations("RoleWorkspace");
  const w = useTranslations("IamWorkspace");
  const u = useTranslations("UserWizard");
  const a = useTranslations("AccountAccess");
  const id = useId();
  const form = useRef<HTMLFormElement>(null);
  const submitting = useRef(false);
  const requestId = useRef(crypto.randomUUID());
  const latestClient = useRef(client);
  const mountedClient = useRef(client);
  const [step, setStep] = useState(0);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [trustedUserIds, setTrustedUserIds] = useState<string[]>([]);
  const [tags, setTags] = useState<RoleTag[]>([]);
  const [sessionMinutes, setSessionMinutes] = useState(60);
  const [validationError, setValidationError] = useState<ValidationError | null>(null);
  const [liveError, setLiveError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [createdId, setCreatedId] = useState<string | null>(null);
  const [uncertain, setUncertain] = useState<CreateRoleCommand | null>(null);
  const created = createdId !== null;
  const dirty = Boolean(name || description || trustedUserIds.length || tags.length || sessionMinutes !== 60 || uncertain);
  const requestLeave = useAccessDraft({
    dirty: dirty && !created,
    busy,
    title: t(uncertain ? "unknownLeaveTitle" : "cancelTitle"),
    description: t(uncertain ? "unknownLeaveHint" : "liveCancelHint"),
    form
  });
  const trustedUsers = scene.users.map((user) => ({ id: user.id, name: user.loginName, description: user.name }));
  const trustedDirectory = new Set(trustedUsers.map((user) => user.id));

  useLayoutEffect(() => {
    latestClient.current = client;
    if (mountedClient.current === client) return;
    // A role creation intent belongs to the login Session that created the
    // client. Never carry local draft, unknown outcome, or one-time success
    // state into another Session, even when the Account and USER are equal.
    mountedClient.current = client;
    submitting.current = false;
    requestId.current = crypto.randomUUID();
    setStep(0);
    setName("");
    setDescription("");
    setTrustedUserIds([]);
    setTags([]);
    setSessionMinutes(60);
    setValidationError(null);
    setLiveError(null);
    setBusy(false);
    setCreatedId(null);
    setUncertain(null);
  }, [client]);

  useEffect(() => {
    if (!validationError) return;
    const target = form.current?.querySelector<HTMLElement>('[aria-invalid="true"], [role="alert"]');
    target?.focus({ preventScroll: true });
    target?.scrollIntoView?.({ block: "center" });
  }, [validationError]);

  function changeIntent(change: () => void) {
    if (uncertain) return;
    change();
    setValidationError(null);
    setLiveError(null);
    requestId.current = crypto.randomUUID();
  }

  function cancel() { requestLeave(onBack); }

  function command(): CreateRoleCommand {
    const normalizedName = name.trim();
    const normalizedDescription = description.trim();
    return {
      name: normalizedName,
      description: normalizedDescription,
      tags: tags.map((tag) => ({ ...tag })),
      maxSessionDurationSeconds: sessionMinutes * 60,
      trustPolicy: {
        languageVersion: "1",
        statements: [{ sid: "trusted-users", effect: "ALLOW", principals: trustedUserIds.map((userId) => ({ type: "USER", id: userId })) }]
      },
      requestId: requestId.current
    };
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || submitting.current || created) return;
    const normalizedName = name.trim(), normalizedDescription = description.trim();
    if (!trustedUserIds.length || trustedUserIds.length > 256 || new Set(trustedUserIds).size !== trustedUserIds.length || trustedUserIds.some((userId) => !trustedDirectory.has(userId))) {
      setValidationError("invalidTrust");
      setStep(0);
      return;
    }
    const invalid = validMetadata(normalizedName, normalizedDescription, tags, sessionMinutes);
    if (invalid) {
      setValidationError(invalid);
      setStep(1);
      return;
    }
    if (step < 2 && !uncertain) {
      setValidationError(null);
      setStep(step + 1);
      return;
    }
    if (!client.canCreate) {
      setLiveError(a("errors.forbidden"));
      return;
    }
    const intent = uncertain ?? command();
    const sourceClient = client;
    submitting.current = true;
    setBusy(true);
    setLiveError(null);
    try {
      const role = await sourceClient.create(intent);
      if (latestClient.current !== sourceClient) return;
      setUncertain(null);
      setCreatedId(role.id);
    } catch (failure) {
      if (latestClient.current !== sourceClient) return;
      const code = accountError(failure);
      if (code === "unavailable") setUncertain(intent);
      setLiveError(a(`errors.${code}`));
    } finally {
      if (latestClient.current === sourceClient) {
        submitting.current = false;
        setBusy(false);
      }
    }
  }

  const steps = ["trust", "details", "review"] as const;
  const currentStep = steps[step] ?? "trust";
  return <div className={styles.root}>
    <ContentPage.Heading title={w("createRole")} scrollKey="create-live-role" back={{ label: t("back"), parentLabel: w("roles"), disabled: busy, onClick: cancel }} />
    <Wizard label={w("createRole")} steps={steps.map((key) => ({ id: key, label: t(`liveSteps.${key}`) }))} currentStep={step}
      onStepChange={(next) => { if (!uncertain) { setValidationError(null); setLiveError(null); setStep(next); } }} completed={created} busy={busy}
      formRef={form} onSubmit={submit} title={created ? t("created") : t(`liveSteps.${currentStep}`)}
      description={created ? t("liveCreatedHint") : t(`liveHints.${currentStep}`)} progressLabel={u("stepCount", { current: step + 1, total: 3 })}
      hint={<><ShieldCheck aria-hidden="true" />{t("liveCreateHint")}</>}
      actions={created ? <Button onClick={() => onDone(createdId!)}>{t("viewRole")}</Button> : <>
        <Button variant="ghost" disabled={busy} onClick={cancel}>{w("cancel")}</Button>
        {step && !uncertain ? <Button variant="secondary" disabled={busy} onClick={() => { setStep(step - 1); setValidationError(null); }}>{a("previousStep")}</Button> : null}
        <Button type="submit" disabled={busy || !client.canCreate}>{busy ? t("saving") : uncertain ? t("retryOriginalRequest") : step < 2 ? t("next") : w("createRole")}</Button>
      </>}>
      {created ? <Alert status="success">{t("liveCreatedHint")}</Alert> : <fieldset className={styles.stack} disabled={Boolean(uncertain)}>
        {validationError ? <Alert status="danger" tabIndex={-1}>{t(`liveErrors.${validationError}`)}</Alert> : null}
        {uncertain ? <Alert status="warning" tabIndex={-1}>{t("createOutcomeUnknown")} <code>{uncertain.requestId}</code></Alert> : null}
        {!client.canCreate ? <Alert status="warning">{client.createRestrictionReason ?? a("errors.forbidden")}</Alert> : null}
        {step === 0 ? <div className={styles.stack}>
          <Alert>{t("liveTrustCreateHint")}</Alert>
          {!scene.directoryComplete ? <Alert status="warning">{t("loadedUsersOnly")}</Alert> : null}
          <WorkspaceSelection label={t("trustedUsers")} options={trustedUsers} value={trustedUserIds} limit={256}
            onChange={(ids) => changeIntent(() => setTrustedUserIds(ids))} />
        </div> : null}
        {step === 1 ? <div className={styles.metadata}>
          <FormField id={`${id}-name`} label={w("name")} hint={t("nameHint")} error={validationError === "invalidName" ? t("liveErrors.invalidName") : undefined}>
            <Input id={`${id}-name`} required maxLength={64} value={name} invalid={validationError === "invalidName"}
              onChange={(event) => changeIntent(() => setName(event.target.value))} />
          </FormField>
          <FormField id={`${id}-description`} label={w("description")}>
            <TextArea id={`${id}-description`} maxLength={512} rows={3} value={description} onChange={(event) => changeIntent(() => setDescription(event.target.value))} />
          </FormField>
          <FormField id={`${id}-duration`} label={w("sessionMinutes")} hint={t("liveDurationHint")}>
            <Input id={`${id}-duration`} type="number" min={1} max={720} required value={sessionMinutes}
              onChange={(event) => changeIntent(() => setSessionMinutes(Number(event.target.value)))} />
          </FormField>
          <section className={styles.section}><h3>{t("tags")}</h3><RoleTags value={tags} onChange={(value) => changeIntent(() => setTags(value))} /></section>
        </div> : null}
        {step === 2 ? <div className={styles.stack}>
          <Alert>{t("liveCreationScope")}</Alert>
          <dl className={styles.facts}>
            <div><dt>{w("name")}</dt><dd>{name.trim()}</dd></div>
            <div><dt>{w("description")}</dt><dd>{description.trim() || "—"}</dd></div>
            <div><dt>{t("trustedUsers")}</dt><dd>{trustedUserIds.map((userId) => scene.users.find((user) => user.id === userId)?.loginName ?? userId).join(" · ")}</dd></div>
            <div><dt>{w("sessionMinutes")}</dt><dd>{sessionMinutes}</dd></div>
            <div><dt>{t("tags")}</dt><dd>{tags.length ? tags.map((tag) => <Badge key={tag.key}>{tag.key}: {tag.value || "—"}</Badge>) : "—"}</dd></div>
          </dl>
        </div> : null}
        {liveError ? <Alert status="danger">{liveError}</Alert> : null}
      </fieldset>}
    </Wizard>
  </div>;
}
