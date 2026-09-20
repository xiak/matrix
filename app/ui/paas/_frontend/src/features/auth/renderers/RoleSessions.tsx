"use client";

import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { ActionMenu, Alert, Badge, Button, EmptyState, Table, TablePagination, TableToolbar } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccessRole, AccessRoleSession, AccessWorkspace } from "../domain/accessWorkspace";
import { roleSessionStatus } from "../domain/roleTrust";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

type LifecycleFilter = "unrevoked" | "expired" | "revoked" | "all";

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

export function RoleSessions({ role, workspace, scene }: { role: AccessRole; workspace: AccessWorkspace; scene: AccountAccessScene }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), access = useAccountAccess(), toolbarLabels = useTableToolbarLabels();
  const [intent, setIntent] = useState<{ session: AccessRoleSession } | null>(null);
  const [sessionId, setSessionId] = useState(""), [sourceUserId, setSourceUserId] = useState("all"), [lifecycle, setLifecycle] = useState<LifecycleFilter>("unrevoked");
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(10), [now, setNow] = useState(() => new Date().toISOString());
  const directory = useRef<HTMLDivElement>(null), returnFocus = useRef<string | null>(null), previousIntent = useRef(intent);
  const userIds = useMemo(() => scene.users.map((user) => user.id), [scene.users]);
  const allSessions = useMemo(() => workspace.roleSessions.filter((session) => session.roleId === role.id).reverse(), [role.id, workspace.roleSessions]);

  // Lifecycle changes are event boundaries, not a polling concern. Wake once at
  // the next expiry rather than rerendering the whole directory every 15s.
  useEffect(() => {
    const observedAt = Date.parse(now);
    const nextExpiry = allSessions.reduce<number | null>((next, session) => {
      if (session.revokedAt) return next;
      const expiry = Date.parse(session.expiresAt);
      return Number.isFinite(expiry) && expiry > observedAt && (next === null || expiry < next) ? expiry : next;
    }, null);
    if (nextExpiry === null) return;
    const timer = window.setTimeout(() => setNow(new Date().toISOString()), Math.min(Math.max(nextExpiry - Date.now() + 20, 20), 2_147_483_647));
    return () => window.clearTimeout(timer);
  }, [allSessions, now]);

  useLayoutEffect(() => {
    if (previousIntent.current && !intent && returnFocus.current) {
      directory.current?.querySelector<HTMLElement>(`[data-session-actions="${returnFocus.current}"] button`)?.focus({ preventScroll: true });
      returnFocus.current = null;
    }
    previousIntent.current = intent;
  }, [intent]);

  const callerLabel = (session: AccessRoleSession) => session.caller.type === "user" ? scene.users.find((user) => user.id === session.caller.id)?.loginName ?? session.caller.id : session.caller.type === "federation" ? workspace.federations.find((entry) => entry.id === session.caller.id)?.name ?? session.caller.id : session.caller.id;
  const normalizedSessionId = sessionId.trim();
  const sessions = allSessions.filter((session) => {
    const status = roleSessionStatus(workspace, session, userIds, now);
    const lifecycleMatches = lifecycle === "all" || (lifecycle === "unrevoked" && status === "active") || lifecycle === status;
    return (!normalizedSessionId || session.id === normalizedSessionId) && (sourceUserId === "all" || (session.caller.type === "user" && session.caller.id === sourceUserId)) && lifecycleMatches;
  });
  const pages = Math.max(1, Math.ceil(sessions.length / pageSize)), current = Math.min(page, pages);
  const showHistory = () => { setSessionId(""); setSourceUserId("all"); setLifecycle("all"); setPage(1); };
  const close = () => { access.clearWorkspaceError(); setIntent(null); setNow(new Date().toISOString()); };

  if (intent) return <SessionRevocation session={intent.session} caller={callerLabel(intent.session)} onClose={close} />;
  return <div className={styles.stack} ref={directory}>
    <div className={styles.actionHeader}><h3>{t("sessions")}</h3><Badge status="neutral">MOCK</Badge></div>
    <Alert status="info">{t("sessionDirectoryHint")}</Alert>
    <TableToolbar labels={toolbarLabels} search={{ label: t("exactSessionSearch"), value: sessionId, onChange: (value) => { setSessionId(value); setPage(1); } }} filters={[
      { id: "source-user", label: t("sourceUserFilter"), value: sourceUserId, onChange: (value) => { setSourceUserId(value); setPage(1); }, options: [{ value: "all", label: w("all") }, ...scene.users.map((user) => ({ value: user.id, label: `${user.loginName} · ${user.id}` }))] },
      { id: "lifecycle", label: t("lifecycleFilter"), value: lifecycle, defaultValue: "unrevoked", onChange: (value) => { setLifecycle(value as LifecycleFilter); setPage(1); }, options: (["unrevoked", "expired", "revoked", "all"] as const).map((value) => ({ value, label: t(`lifecycle.${value}`) })) }
    ]} status={t("sessionCount", { count: sessions.length })} />
    {sessions.length ? <><Table aria-label={t("sessions")} mobileLayout="stack"><thead><tr><th scope="col">{t("caller")}</th><th scope="col">{t("sessionStatus")}</th><th scope="col">{t("expires")}</th><th scope="col">{w("actions")}</th></tr></thead><tbody>{sessions.slice((current - 1) * pageSize, current * pageSize).map((session) => { const status = roleSessionStatus(workspace, session, userIds, now); return <tr key={session.id}><td data-label={t("caller")}><strong>{callerLabel(session)}</strong><small>{session.caller.type.toUpperCase()} · {session.id}</small></td><td data-label={t("sessionStatus")}><Badge status={status === "active" ? "success" : "neutral"}>{t(`statuses.${status}`)}</Badge></td><td data-label={t("expires")}><WorkspaceTime value={session.expiresAt} /></td><td data-label={w("actions")}><span data-session-actions={session.id}><ActionMenu iconOnly label={t("sessionActions", { id: session.id })} actions={[{ id: "revoke", label: t("revoke"), danger: true, disabledReason: status !== "active" ? t("revokeUnavailable") : undefined, onSelect: () => { returnFocus.current = session.id; access.clearWorkspaceError(); setIntent({ session }); } }]} /></span></td></tr>; })}</tbody></Table><Table.Footer><TablePagination page={current} pages={pages} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} labels={{ summary: w("page", { page: current, pages }), pageSize: w("pageSize"), previous: w("previous"), next: w("next") }} /></Table.Footer></> : <EmptyState title={allSessions.length ? t("noMatchingSessions") : t("noSessions")} description={allSessions.length ? t("noMatchingSessionsHint") : t("noSessionsHint")} action={allSessions.length ? <Button variant="secondary" onClick={showHistory}>{t("showAllSessions")}</Button> : undefined} />}
  </div>;
}
