"use client";
import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { ActionMenu, Alert, Badge, Button, EmptyState, FormField, Input, Select, Table, TablePagination } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessRole, AccessRoleSession, AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessView } from "../domain/accounts";
import { evaluateRoleAssumption, type RoleAssumptionResult } from "../domain/policyEvaluation";
import { roleServicePrincipals, roleSessionStatus, type RoleSessionCaller } from "../domain/roleTrust";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

function SessionCreation({ role, workspace, scene, onClose }: { role: AccessRole; workspace: AccessWorkspace; scene: AccountAccessScene; onClose(): void }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), d = useTranslations("AccessSimulator"), access = useAccountAccess(), id = useId();
  const type: RoleSessionCaller["type"] = role.principalType === "account" ? "user" : role.principalType === "service" ? "service" : "federation";
  const options = type === "user" ? scene.users.map((user) => ({ value: user.id, label: user.loginName })) : type === "service" ? roleServicePrincipals.map((value) => ({ value, label: value })) : workspace.federations.map((entry) => ({ value: entry.id, label: entry.name }));
  const [callerId, setCaller] = useState(""), [minutes, setMinutes] = useState(Math.min(60, role.sessionMinutes)), [sourceIp, setSourceIp] = useState("192.0.2.42");
  const [checked, setChecked] = useState<{ workspace: AccessWorkspace; result: RoleAssumptionResult } | null>(null);
  const result = checked?.workspace === workspace ? checked.result : null;
  const heading = useRef<HTMLHeadingElement>(null), errorFeedback = useRef<HTMLDivElement>(null), resultFeedback = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => { heading.current?.focus({ preventScroll: true }); }, []);
  useLayoutEffect(() => { if (access.workspaceError) errorFeedback.current?.querySelector<HTMLElement>('[role="alert"]')?.focus({ preventScroll: true }); }, [access.workspaceError]);
  useLayoutEffect(() => { if (result && !access.workspaceError) resultFeedback.current?.querySelector<HTMLElement>('[role="alert"], [role="status"]')?.focus({ preventScroll: true }); }, [access.workspaceError, result]);
  const submit = async () => {
    if (!result?.allowed) { setChecked({ workspace, result: evaluateRoleAssumption(workspace, scene.users.map((user) => user.id), { roleId: role.id, caller: { type, id: callerId }, sourceIp, at: new Date().toISOString() }) }); return false; }
    if (await access.executeWorkspace({ kind: "create-role-session", roleId: role.id, caller: { type, id: callerId }, sessionMinutes: minutes, sourceIp })) onClose();
    return false;
  };
  return <section className={styles.stack} role="group" aria-label={t("createSession")}>
    <div className={styles.sectionHeading}><Button variant="ghost" disabled={access.busy} onClick={onClose}>{t("backToSessions")}</Button><h3 className={styles.detailTitle} ref={heading} tabIndex={-1}>{t("createSession")}</h3></div>
    <Alert>{t("sessionHint")}</Alert>
    {access.workspaceError ? <div ref={errorFeedback}><Alert status="danger" tabIndex={-1}>{w(`errors.${access.workspaceError}`)}</Alert></div> : null}
    <form className={styles.stack} aria-busy={access.busy || undefined} onSubmit={(event) => { event.preventDefault(); if (!access.busy && callerId) void submit(); }}>
      <fieldset className={styles.editorFields} disabled={access.busy}><FormField id={id + "-caller"} label={t("caller")}><Select id={id + "-caller"} value={callerId} placeholder={t("choosePrincipal")} options={options} onValueChange={(id) => { setCaller(id); setChecked(null); access.clearWorkspaceError(); }} /></FormField><FormField id={id + "-duration"} label={w("sessionMinutes")} hint={t("sessionLimitHint", { max: role.sessionMinutes })}><Input id={id + "-duration"} required type="number" min={15} max={role.sessionMinutes} value={minutes} aria-describedby={id + "-duration-hint"} onChange={(event) => { setMinutes(Number(event.target.value)); setChecked(null); access.clearWorkspaceError(); }} /></FormField><FormField id={id + "-ip"} label={d("sourceIp")}><Input id={id + "-ip"} value={sourceIp} maxLength={64} onChange={(event) => { setSourceIp(event.target.value); setChecked(null); access.clearWorkspaceError(); }} /></FormField>
        {result ? <div ref={resultFeedback}><Alert status={result.allowed ? "success" : "danger"} tabIndex={-1}><strong>{t(`assumption.${result.reason}`)}</strong>{result.callerDecision ? <p>{t("callerDecision", { decision: d(`decisions.${result.callerDecision.decision}`) })}</p> : null}<p>{t(result.allowed ? "readyToCreate" : "assumptionDeniedHint")}</p></Alert></div> : null}</fieldset>
      <div className={styles.actions}><Button type="submit" disabled={access.busy || !callerId}>{result?.allowed ? t("createSession") : t("checkAssumption")}</Button><Button variant="secondary" disabled={access.busy} onClick={onClose}>{w("cancel")}</Button></div>
    </form>
  </section>;
}

function SessionRevocation({ session, caller, onClose }: { session: AccessRoleSession; caller: string; onClose(): void }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), access = useAccountAccess();
  const heading = useRef<HTMLHeadingElement>(null), feedback = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => { heading.current?.focus({ preventScroll: true }); }, []);
  useLayoutEffect(() => { if (access.workspaceError) feedback.current?.querySelector<HTMLElement>('[role="alert"]')?.focus({ preventScroll: true }); }, [access.workspaceError]);
  return <section className={styles.stack} role="group" aria-label={t("revoke")}>
    <div className={styles.sectionHeading}><Button variant="ghost" disabled={access.busy} onClick={onClose}>{t("backToSessions")}</Button><h3 className={styles.detailTitle} ref={heading} tabIndex={-1}>{t("revoke")}</h3></div>
    {access.workspaceError ? <div ref={feedback}><Alert status="danger" tabIndex={-1}>{w(`errors.${access.workspaceError}`)}</Alert></div> : null}
    <Alert status="warning">{t("revokeHint")}</Alert><dl className={styles.facts}><div><dt>{t("caller")}</dt><dd>{caller}</dd></div><div><dt>{t("sessionId")}</dt><dd><code>{session.id}</code></dd></div><div><dt>{t("expires")}</dt><dd><WorkspaceTime value={session.expiresAt} /></dd></div></dl>
    <div className={styles.actions}><Button variant="danger" disabled={access.busy} onClick={async () => { if (await access.executeWorkspace({ kind: "revoke-role-session", id: session.id })) onClose(); }}>{t("revoke")}</Button><Button variant="secondary" disabled={access.busy} onClick={onClose}>{w("cancel")}</Button></div>
  </section>;
}

export function RoleSessions({ role, workspace, scene, onOpen }: { role: AccessRole; workspace: AccessWorkspace; scene: AccountAccessScene; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), access = useAccountAccess();
  const [intent, setIntent] = useState<{ action: "create" } | { action: "revoke"; session: AccessRoleSession } | null>(null), [page, setPage] = useState(1), [pageSize, setPageSize] = useState(10), [now, setNow] = useState(() => new Date().toISOString());
  const directory = useRef<HTMLDivElement>(null), returnFocus = useRef<{ action: "create" } | { action: "session"; id: string } | null>(null), previousIntent = useRef(intent);
  useEffect(() => { const timer = window.setInterval(() => setNow(new Date().toISOString()), 15000); return () => window.clearInterval(timer); }, []);
  useLayoutEffect(() => {
    if (previousIntent.current && !intent && returnFocus.current) {
      const target = returnFocus.current.action === "create" ? directory.current?.querySelector<HTMLElement>("[data-create-session]") : directory.current?.querySelector<HTMLElement>(`[data-session-actions="${returnFocus.current.id}"] button`);
      target?.focus({ preventScroll: true }); returnFocus.current = null;
    }
    previousIntent.current = intent;
  }, [intent]);
  const sessions = workspace.roleSessions.filter((session) => session.roleId === role.id).reverse();
  const pages = Math.max(1, Math.ceil(sessions.length / pageSize)), current = Math.min(page, pages);
  const userIds = scene.users.map((user) => user.id);
  const callerLabel = (session: AccessRoleSession) => session.caller.type === "user" ? scene.users.find((user) => user.id === session.caller.id)?.loginName ?? session.caller.id : session.caller.type === "federation" ? workspace.federations.find((entry) => entry.id === session.caller.id)?.name ?? session.caller.id : session.caller.id;
  const close = () => { access.clearWorkspaceError(); setIntent(null); setPage(1); setNow(new Date().toISOString()); };
  if (intent?.action === "create") return <SessionCreation workspace={workspace} role={role} scene={scene} onClose={close} />;
  if (intent?.action === "revoke") return <SessionRevocation session={intent.session} caller={callerLabel(intent.session)} onClose={close} />;
  return <div className={styles.stack} ref={directory}><div className={styles.actionHeader}><h3>{t("sessions")}</h3><Button data-create-session onClick={() => { returnFocus.current = { action: "create" }; access.clearWorkspaceError(); setIntent({ action: "create" }); }}>{t("createSession")}</Button></div><p className={styles.note}>{t("sessionDirectoryHint")}</p>
    {sessions.length ? <><Table aria-label={t("sessions")} mobileLayout="stack"><thead><tr><th scope="col">{t("caller")}</th><th scope="col">{t("sessionStatus")}</th><th scope="col">{t("expires")}</th><th scope="col">{w("actions")}</th></tr></thead><tbody>{sessions.slice((current - 1) * pageSize, current * pageSize).map((session) => { const status = roleSessionStatus(workspace, session, userIds, now); return <tr key={session.id}><td data-label={t("caller")}><strong>{callerLabel(session)}</strong><small>{session.id}</small></td><td data-label={t("sessionStatus")}><Badge status={status === "active" ? "success" : "neutral"}>{t(`statuses.${status}`)}</Badge></td><td data-label={t("expires")}><WorkspaceTime value={session.expiresAt} /></td><td data-label={w("actions")}><span data-session-actions={session.id}><ActionMenu iconOnly label={t("sessionActions", { id: session.id })} actions={[{ id: "simulate", label: w("simulateAccess"), onSelect: () => onOpen("simulator", session.id) }, { id: "revoke", label: t("revoke"), danger: true, disabled: status !== "active", onSelect: () => { returnFocus.current = { action: "session", id: session.id }; access.clearWorkspaceError(); setIntent({ action: "revoke", session }); } }]} /></span></td></tr>; })}</tbody></Table><Table.Footer><TablePagination page={current} pages={pages} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} labels={{ summary: w("page", { page: current, pages }), pageSize: w("pageSize"), previous: w("previous"), next: w("next") }} /></Table.Footer></> : <EmptyState title={t("noSessions")} description={t("noSessionsHint")} />}
  </div>;
}
