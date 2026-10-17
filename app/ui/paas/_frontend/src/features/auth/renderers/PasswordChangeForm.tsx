"use client";

import { useId, useLayoutEffect, useRef, useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { ArrowRight, KeyRound, LoaderCircle } from "lucide-react";
import { Button, Card, Checkbox, FormField, Alert, PasswordInput, Typography, UnsavedChangesProvider } from "@ui/xiak";
import { useSession } from "../application/SessionProvider";
import { useRoleSession } from "../application/RoleSessionProvider";
import { withinNewPasswordProductBounds } from "../domain/passwordEntry";
import { useAccessDraft } from "./useAccessDraft";
import styles from "./LoginRenderer.module.css";
import securityStyles from "./MfaPreviewExperience.module.css";

export function PasswordChangeForm({ returnTo }: { returnTo: string }) {
  const session = useSession();
  return <UnsavedChangesProvider><PasswordChangeFields key={session.passwordChange.identity} mode="required" returnTo={returnTo} /></UnsavedChangesProvider>;
}

export function SelfPasswordSettings() {
  const session = useSession();
  const role = useRoleSession();
  if (!session.current || (session.phase !== "authenticated" && session.phase !== "revoking") || role.mode !== "USER") return null;
  return <SessionPasswordSettings key={session.passwordChange.identity} />;
}

function SessionPasswordSettings() {
  const t = useTranslations("SelfPassword");
  const session = useSession();
  const [editing, setEditing] = useState(false);
  const wasEditing = useRef(false);
  const trigger = useRef<HTMLButtonElement>(null);
  useLayoutEffect(() => { if (wasEditing.current && !editing) trigger.current?.focus(); wasEditing.current = editing; }, [editing]);
  return <Card>
    <Card.Header><div className={securityStyles.cardTitle}><span><KeyRound aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("title")}</Typography.Title><Typography.Text tone="muted">{t("identity", { name: session.current?.loginName ?? "" })}</Typography.Text></div></div></Card.Header>
    {editing ? <PasswordChangeFields mode="self-service" onClose={() => setEditing(false)} /> : <><Card.Body className={securityStyles.cardBody}>
      <Typography.Text tone="muted">{t("hint")}</Typography.Text>
      {session.passwordChange.state === "outcome-unknown" ? <Alert role="alert" status="warning">{t("unknown")}</Alert> : null}
    </Card.Body><Card.Footer><Button ref={trigger} onClick={() => { session.clearError(); setEditing(true); }} type="button" variant="secondary">{t(session.passwordChange.state === "outcome-unknown" ? "viewUnconfirmed" : "edit")}</Button></Card.Footer></>}
  </Card>;
}

function PasswordChangeFields(props: { mode: "required"; returnTo: string } | { mode: "self-service"; onClose(): void }) {
  const router = useRouter();
  const session = useSession();
  const t = useTranslations("Auth");
  const self = useTranslations("SelfPassword");
  const id = useId();
  const form = useRef<HTMLFormElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const currentInput = useRef<HTMLInputElement>(null);
  const newInput = useRef<HTMLInputElement>(null);
  const confirmInput = useRef<HTMLInputElement>(null);
  const finishAction = useRef<HTMLButtonElement>(null);
  const alive = useRef(true);
  const focusRejected = useRef(false);
  useLayoutEffect(() => { alive.current = true; heading.current?.focus({ preventScroll: true }); return () => { alive.current = false; }; }, []);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmedPassword, setConfirmedPassword] = useState("");
  const [revokeOtherSessions, setRevokeOtherSessions] = useState(true);
  const [completed, setCompleted] = useState(false);
  useLayoutEffect(() => { if (completed) finishAction.current?.focus(); }, [completed]);
  const [mismatch, setMismatch] = useState(false);
  const [invalidProductBounds, setInvalidProductBounds] = useState(false);
  const busy = session.passwordChange.state === "pending" || session.phase === "revoking";
  const unknown = session.passwordChange.state === "outcome-unknown";
  const required = props.mode === "required";
  const error = invalidProductBounds ? "passwordPolicy" : mismatch ? "passwordMismatch" : session.error;
  const leave = useAccessDraft({ dirty: !completed && Boolean(currentPassword || newPassword || confirmedPassword), busy, title: self("leaveTitle"), description: self("leaveHint"), form });
  useLayoutEffect(() => { if (focusRejected.current && !busy && !unknown) { focusRejected.current = false; currentInput.current?.focus(); } }, [busy, unknown]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || unknown || completed) return;
    setMismatch(false);
    if (!withinNewPasswordProductBounds(newPassword)) { setInvalidProductBounds(true); newInput.current?.focus(); return; }
    if (newPassword !== confirmedPassword) { setMismatch(true); confirmInput.current?.focus(); return; }
    const accepted = await session.changePassword(currentPassword, newPassword, required || revokeOtherSessions);
    if (!alive.current) return;
    setCurrentPassword(""); setNewPassword(""); setConfirmedPassword("");
    if (accepted && props.mode === "required") router.replace(props.returnTo, { scroll: false });
    else if (accepted) setCompleted(true);
    else focusRejected.current = true;
  }

  if (completed && props.mode === "self-service") return <><Card.Body><Alert role="status" aria-label={self("result")} status="success">{self("success")}</Alert></Card.Body><Card.Footer><Button type="button" ref={finishAction} onClick={props.onClose}>{self("done")}</Button></Card.Footer></>;
  const title = required ? <div className={styles.cardHeading}>
      <p className={styles.eyebrow}>{t("firstLogin", { name: session.current?.loginName ?? "" })}</p>
      <h1 ref={heading} tabIndex={-1}>{t("changeTitle")}</h1><p>{t("changeHint")}</p>
    </div> : <h4 className={securityStyles.flowTitle} ref={heading} tabIndex={-1}>{self("edit")}</h4>;
  const fields = <>
      {unknown ? <Alert role="alert" status="warning">{self("unknown")}</Alert> : null}
      <FormField id={`${id}-current`} label={required ? t("currentPassword") : self("currentPassword")}>
        <PasswordInput controlSize={required ? "large" : undefined} autoComplete="current-password" capsLockLabel={t("capsLock")} disabled={busy || unknown}
          hideLabel={t("hidePassword")} id={`${id}-current`} name="currentPassword" ref={currentInput}
          onChange={(event) => setCurrentPassword(event.target.value)} required showLabel={t("showPassword")} value={currentPassword} />
      </FormField>
      <FormField id={`${id}-new`} label={t("newPassword")} hint={t("passwordPolicy")}>
        <PasswordInput controlSize={required ? "large" : undefined} aria-describedby={`${id}-new-hint`} autoComplete="new-password" capsLockLabel={t("capsLock")}
          disabled={busy || unknown} hideLabel={t("hidePassword")} id={`${id}-new`} ref={newInput} invalid={invalidProductBounds}
          name="newPassword" onChange={(event) => { setNewPassword(event.target.value); setMismatch(false); setInvalidProductBounds(false); }}
          required showLabel={t("showPassword")} value={newPassword} />
      </FormField>
      <FormField id={`${id}-confirm`} label={t("confirmPassword")}>
        <PasswordInput controlSize={required ? "large" : undefined} autoComplete="new-password" capsLockLabel={t("capsLock")} disabled={busy || unknown}
          hideLabel={t("hidePassword")} id={`${id}-confirm`} invalid={mismatch} ref={confirmInput}
          name="confirmedPassword" onChange={(event) => { setConfirmedPassword(event.target.value); setMismatch(false); }}
          required showLabel={t("showPassword")} value={confirmedPassword} />
      </FormField>
      {required ? <Alert>{self("requiredPolicy")}</Alert> : <fieldset className={securityStyles.ruleFields}><legend>{self("sessionPolicy")}</legend><Checkbox checked={revokeOtherSessions} disabled={busy || unknown} onChange={(event) => setRevokeOtherSessions(event.target.checked)}>{self("revokeOthers")}</Checkbox><Typography.Text tone="muted">{self("retainHint")}</Typography.Text></fieldset>}
      {error && (!unknown || error === "logoutUnavailable") ? <Alert status="danger">{t(`errors.${error}`)}</Alert> : null}
  </>;
  const actions = <>
      <Button block={required} disabled={busy || unknown || !currentPassword || !newPassword || !confirmedPassword} size={required ? "large" : undefined} type="submit">
        {busy ? <LoaderCircle aria-hidden="true" className={styles.spinner} /> : <ArrowRight aria-hidden="true" />}
        {busy ? t("savingPassword") : required ? t("savePassword") : self("save")}
      </Button>
      {props.mode === "self-service" ? <Button disabled={busy} onClick={() => leave(props.onClose)} type="button" variant="ghost">{self("cancel")}</Button> : null}
      {required || unknown ? <Button block={required} disabled={busy} onClick={() => void session.logout()} type="button" variant="ghost">{session.phase === "revoking" ? t("exitingSession") : unknown ? self("signInAgain") : t("exitSession")}</Button> : null}
  </>;
  return <>
    {required ? title : null}
    <form ref={form} aria-label={required ? t("changeTitle") : self("edit")} aria-busy={busy} className={required ? styles.form : undefined} id="password-change-form" onSubmit={submit}>
      {required ? <>{fields}{actions}</> : <><Card.Body className={securityStyles.cardBody}>{title}{fields}</Card.Body><Card.Footer className={securityStyles.actions}>{actions}</Card.Footer></>}
    </form>
  </>;
}
