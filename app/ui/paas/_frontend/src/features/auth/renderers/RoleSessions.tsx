"use client";
import { useEffect, useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, EmptyState, FormField, Input, Select, Table } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessRole, AccessRoleSession, AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessView } from "../domain/accounts";
import { evaluateRoleAssumption, type RoleAssumptionResult } from "../domain/policyEvaluation";
import { roleServicePrincipals, roleSessionStatus, type RoleSessionCaller } from "../domain/roleTrust";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceDialog, WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

function SessionCreation({ role, workspace, scene, onClose }: { role: AccessRole; workspace: AccessWorkspace; scene: AccountAccessScene; onClose(): void }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), d = useTranslations("AccessSimulator"), access = useAccountAccess(), id = useId();
  const type: RoleSessionCaller["type"] = role.principalType === "account" ? "user" : role.principalType === "service" ? "service" : "federation";
  const options = type === "user" ? scene.users.map((user) => ({ value: user.id, label: user.loginName })) : type === "service" ? roleServicePrincipals.map((value) => ({ value, label: value })) : workspace.federations.map((entry) => ({ value: entry.id, label: entry.name }));
  const [callerId, setCaller] = useState(""), [minutes, setMinutes] = useState(Math.min(60, role.sessionMinutes)), [sourceIp, setSourceIp] = useState("192.0.2.42");
  const [checked, setChecked] = useState<{ workspace: AccessWorkspace; result: RoleAssumptionResult } | null>(null);
  const result = checked?.workspace === workspace ? checked.result : null;
  return <WorkspaceDialog title={t("createSession")} onClose={onClose} submitLabel={result?.allowed ? t("createSession") : t("checkAssumption")} submitDisabled={!callerId} onSubmit={async () => {
    if (!result?.allowed) { setChecked({ workspace, result: evaluateRoleAssumption(workspace, scene.users.map((user) => user.id), { roleId: role.id, caller: { type, id: callerId }, sourceIp, at: new Date().toISOString() }) }); return false; }
    return Boolean(await access.executeWorkspace({ kind: "create-role-session", roleId: role.id, caller: { type, id: callerId }, sessionMinutes: minutes, sourceIp }));
  }}><Alert>{t("sessionHint")}</Alert><FormField id={id + "-caller"} label={t("caller")}><Select id={id + "-caller"} value={callerId} placeholder={t("choosePrincipal")} options={options} onValueChange={(id) => { setCaller(id); setChecked(null); }} /></FormField><FormField id={id + "-duration"} label={w("sessionMinutes")} hint={t("sessionLimitHint", { max: role.sessionMinutes })}><Input id={id + "-duration"} required type="number" min={15} max={role.sessionMinutes} value={minutes} aria-describedby={id + "-duration-hint"} onChange={(event) => { setMinutes(Number(event.target.value)); setChecked(null); }} /></FormField><FormField id={id + "-ip"} label={d("sourceIp")}><Input id={id + "-ip"} value={sourceIp} maxLength={64} onChange={(event) => { setSourceIp(event.target.value); setChecked(null); }} /></FormField>
    {result ? <Alert status={result.allowed ? "success" : "danger"}><strong>{t(`assumption.${result.reason}`)}</strong>{result.callerDecision ? <p>{t("callerDecision", { decision: d(`decisions.${result.callerDecision.decision}`) })}</p> : null}<p>{t(result.allowed ? "readyToCreate" : "assumptionDeniedHint")}</p></Alert> : null}
  </WorkspaceDialog>;
}
export function RoleSessions({ role, workspace, scene, onOpen }: { role: AccessRole; workspace: AccessWorkspace; scene: AccountAccessScene; onOpen(view: AccountAccessView, id?: string): void }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), access = useAccountAccess();
  const [creating, setCreating] = useState(false), [revoking, setRevoking] = useState<AccessRoleSession | null>(null), [page, setPage] = useState(1), [now, setNow] = useState(() => new Date().toISOString());
  useEffect(() => { const timer = window.setInterval(() => setNow(new Date().toISOString()), 15000); return () => window.clearInterval(timer); }, []);
  const sessions = workspace.roleSessions.filter((session) => session.roleId === role.id).reverse();
  const pages = Math.max(1, Math.ceil(sessions.length / 10)), current = Math.min(page, pages);
  const userIds = scene.users.map((user) => user.id);
  const callerLabel = (session: AccessRoleSession) => session.caller.type === "user" ? scene.users.find((user) => user.id === session.caller.id)?.loginName ?? session.caller.id : session.caller.type === "federation" ? workspace.federations.find((entry) => entry.id === session.caller.id)?.name ?? session.caller.id : session.caller.id;
  return <div className={styles.stack}><div className={styles.actionHeader}><h3>{t("sessions")}</h3><Button onClick={() => setCreating(true)}>{t("createSession")}</Button></div><p className={styles.note}>{t("sessionHint")}</p>
    {sessions.length ? <Table aria-label={t("sessions")}><thead><tr><th>{t("caller")}</th><th>{t("sessionStatus")}</th><th>{t("expires")}</th><th>{w("actions")}</th></tr></thead><tbody>{sessions.slice((current - 1) * 10, current * 10).map((session) => { const status = roleSessionStatus(workspace, session, userIds, now); return <tr key={session.id}><td><strong>{callerLabel(session)}</strong><small>{session.id}</small></td><td><Badge status={status === "active" ? "success" : "neutral"}>{t(`statuses.${status}`)}</Badge></td><td><WorkspaceTime value={session.expiresAt} /></td><td><div className={styles.actions}><Button variant="ghost" size="small" onClick={() => onOpen("simulator", session.id)}>{w("simulateAccess")}</Button><Button variant="ghost" size="small" disabled={status !== "active"} onClick={() => setRevoking(session)}>{t("revoke")}</Button></div></td></tr>; })}</tbody></Table> : <EmptyState title={t("noSessions")} description={t("noSessionsHint")} />}
    {pages > 1 ? <div className={styles.actions}><span>{w("page", { page: current, pages })}</span><Button variant="secondary" disabled={current <= 1} onClick={() => setPage(current - 1)}>{w("previous")}</Button><Button variant="secondary" disabled={current >= pages} onClick={() => setPage(current + 1)}>{w("next")}</Button></div> : null}
    {creating ? <SessionCreation workspace={workspace} role={role} scene={scene} onClose={() => { setCreating(false); setPage(1); setNow(new Date().toISOString()); }} /> : null}
    {revoking ? <WorkspaceDialog title={t("revoke")} submitLabel={t("revoke")} onClose={() => setRevoking(null)} onSubmit={async () => Boolean(await access.executeWorkspace({ kind: "revoke-role-session", id: revoking.id }))}><Alert status="warning">{t("revokeHint")}</Alert><p>{callerLabel(revoking)}</p><code>{revoking.id}</code></WorkspaceDialog> : null}
  </div>;
}
