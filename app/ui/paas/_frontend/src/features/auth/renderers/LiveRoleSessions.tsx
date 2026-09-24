"use client";

import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { ActionMenu, Alert, Badge, Button, EmptyState, Table, TablePagination, TableSkeleton, TableToolbar } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { accountError, type RoleAccessClient, type RoleSessionRevokeIntent } from "../application/AccountAccessProvider";
import type { RoleCapability, RoleSessionDirectory, RoleSessionFilter, RoleSessionFilterLifecycle, RoleSessionListing } from "../domain/roles";
import { WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

const exactIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
function replaceSession(directory: RoleSessionDirectory | null, item: RoleSessionListing, filter: RoleSessionFilter): RoleSessionDirectory | null {
  if (!directory) return directory;
  const matchesLifecycle = filter.lifecycle === "ALL" || filter.lifecycle === item.lifecycle;
  const matchesExact = !filter.exactId || (filter.exactKind === "session" ? item.session.id === filter.exactId : item.sourceUser.id === filter.exactId);
  return { ...directory, items: directory.items.flatMap((candidate) => candidate.session.id === item.session.id ? matchesLifecycle && matchesExact ? [item] : [] : [candidate]) };
}

export function LiveRoleSessions({ client, roleId, listCapability, revokeIntent, onRevokeIntentChange }: {
  client: RoleAccessClient;
  roleId: string;
  listCapability: RoleCapability;
  revokeIntent: RoleSessionRevokeIntent | null;
  onRevokeIntentChange(expectedRequestId: string | null, intent: RoleSessionRevokeIntent | null): void;
}) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), a = useTranslations("AccountAccess"), toolbarLabels = useTableToolbarLabels();
  const [queryKind, setQueryKind] = useState<RoleSessionFilter["exactKind"]>("session"), [query, setQuery] = useState(""), [appliedQuery, setAppliedQuery] = useState("");
  const [lifecycle, setLifecycle] = useState<RoleSessionFilterLifecycle>("UNREVOKED"), [directory, setDirectory] = useState<RoleSessionDirectory | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "error">("loading"), [completedRequest, setCompletedRequest] = useState(""), [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null), [page, setPage] = useState(1), [pageSize, setPageSize] = useState(10), [refresh, setRefresh] = useState(0);
  const ownedRevokeIntent = revokeIntent?.accountId === client.accountId && revokeIntent.roleId === roleId && revokeIntent.item.session.roleId === roleId ? revokeIntent : null;
  const directoryRegion = useRef<HTMLDivElement>(null), heading = useRef<HTMLHeadingElement>(null), returnFocus = useRef<string | null>(null);
  const previousIntentOpen = useRef(ownedRevokeIntent?.open ?? false), requests = useRef(0), pageRequests = useRef(0);
  const normalized = query.trim(), queryValid = !normalized || exactIdPattern.test(normalized);
  const filter = useMemo<RoleSessionFilter>(() => ({ exactKind: queryKind, exactId: appliedQuery, lifecycle }), [appliedQuery, lifecycle, queryKind]);
  const requestKey = `${roleId}\u0000${queryKind}\u0000${appliedQuery}\u0000${lifecycle}\u0000${refresh}`;
  const pending = listCapability.available && (!appliedQuery || exactIdPattern.test(appliedQuery)) && completedRequest !== requestKey;

  useEffect(() => { const timer = window.setTimeout(() => { pageRequests.current += 1; setLoadingMore(false); setAppliedQuery(normalized); }, 250); return () => window.clearTimeout(timer); }, [normalized]);
  useEffect(() => {
    const request = ++requests.current;
    pageRequests.current += 1;
    if (!listCapability.available || (appliedQuery && !exactIdPattern.test(appliedQuery))) return;
    client.listSessions(roleId, filter).then((result) => {
      if (request !== requests.current) return;
      setDirectory(result); setPhase("ready"); setPage(1); setError(null); setCompletedRequest(requestKey);
    }, (failure: unknown) => {
      if (request !== requests.current) return;
      setError(a(`errors.${accountError(failure)}`)); setPhase((current) => current === "ready" ? current : "error"); setCompletedRequest(requestKey);
    });
  }, [a, appliedQuery, client, filter, listCapability.available, requestKey, roleId]);
  useLayoutEffect(() => {
    if (previousIntentOpen.current && !ownedRevokeIntent?.open && returnFocus.current) {
      const trigger = directoryRegion.current?.querySelector<HTMLElement>(`[data-live-session-actions="${returnFocus.current}"] button`);
      if (trigger) trigger.focus({ preventScroll: true }); else heading.current?.focus({ preventScroll: true });
      returnFocus.current = null;
    }
    previousIntentOpen.current = ownedRevokeIntent?.open ?? false;
  }, [ownedRevokeIntent?.open]);

  if (!listCapability.available) return <EmptyState title={t("liveSessionsUnavailable")} description={t("liveSessionsUnavailableHint")} />;
  if (ownedRevokeIntent?.open) {
    const observed = ownedRevokeIntent.observation;
    const terminalObservation = observed?.lifecycle === "REVOKED" || observed?.lifecycle === "EXPIRED";
    const close = () => onRevokeIntentChange(ownedRevokeIntent.requestId, ownedRevokeIntent.phase === "unknown" && !terminalObservation ? { ...ownedRevokeIntent, open: false } : null);
    const confirm = async () => {
      onRevokeIntentChange(ownedRevokeIntent.requestId, { ...ownedRevokeIntent, phase: "submitting" });
      try {
        const result = await client.revokeSession(roleId, ownedRevokeIntent.item.session.id, ownedRevokeIntent.requestId);
        const revoked: RoleSessionListing = { ...ownedRevokeIntent.item, session: result.session, lifecycle: "REVOKED", revokeCapability: { ...ownedRevokeIntent.item.revokeCapability, available: false, restrictionReason: "SESSION_NOT_REVOCABLE" } };
        setDirectory((current) => replaceSession(current, revoked, filter)); onRevokeIntentChange(ownedRevokeIntent.requestId, null);
      } catch {
        onRevokeIntentChange(ownedRevokeIntent.requestId, { ...ownedRevokeIntent, phase: "unknown" });
      }
    };
    const inspect = async () => {
      onRevokeIntentChange(ownedRevokeIntent.requestId, { ...ownedRevokeIntent, phase: "checking" });
      try {
        const result = await client.readSession(roleId, ownedRevokeIntent.item.session.id);
        setDirectory((current) => replaceSession(current, result.item, filter));
        onRevokeIntentChange(ownedRevokeIntent.requestId, { ...ownedRevokeIntent, phase: "unknown", observation: result.item });
      } catch { onRevokeIntentChange(ownedRevokeIntent.requestId, { ...ownedRevokeIntent, phase: "unknown" }); }
    };
    const busy = ownedRevokeIntent.phase === "submitting" || ownedRevokeIntent.phase === "checking";
    return <section className={styles.stack} role="group" aria-label={t("revoke")}>
      <div className={styles.sectionHeading}><Button variant="ghost" disabled={busy} onClick={close}>{t("backToSessions")}</Button><h3 className={styles.detailTitle} tabIndex={-1}>{t("revoke")}</h3></div>
      <Alert status="warning">{t("liveRevokeHint")}</Alert>
      {ownedRevokeIntent.phase === "unknown" ? <Alert status={terminalObservation ? "info" : "danger"}>{observed ? t(observed.lifecycle === "REVOKED" ? "authoritativeRevoked" : observed.lifecycle === "EXPIRED" ? "authoritativeExpired" : "authoritativeUnrevoked") : t("revokeOutcomeUnknown")}</Alert> : null}
      <dl className={styles.facts}><div><dt>{t("caller")}</dt><dd>{ownedRevokeIntent.item.sourceUser.loginName}<small>{ownedRevokeIntent.item.sourceUser.id}</small></dd></div><div><dt>{t("sessionId")}</dt><dd><code>{ownedRevokeIntent.item.session.id}</code></dd></div><div><dt>{t("requestId")}</dt><dd><code>{ownedRevokeIntent.requestId}</code></dd></div><div><dt>{t("expires")}</dt><dd><WorkspaceTime value={ownedRevokeIntent.item.session.expiresAt} /></dd></div></dl>
      <div className={styles.actions}>
        {terminalObservation ? <Button variant="secondary" onClick={close}>{t("backToSessions")}</Button> : <Button variant="danger" disabled={busy} onClick={() => void confirm()}>{ownedRevokeIntent.phase === "unknown" ? t("retryOriginalRequest") : t("revoke")}</Button>}
        {ownedRevokeIntent.phase === "unknown" && !terminalObservation ? <Button variant="secondary" disabled={busy} onClick={() => void inspect()}>{t("readAuthoritativeState")}</Button> : null}
        <Button variant="ghost" disabled={busy} onClick={close}>{w("cancel")}</Button>
      </div>
    </section>;
  }

  const items = directory?.items ?? [], pages = Math.max(1, Math.ceil(items.length / pageSize)), current = Math.min(page, pages);
  const loadMore = async () => {
    if (!directory?.nextAfter || loadingMore) return;
    const pageRequest = ++pageRequests.current, listRequest = requests.current;
    setLoadingMore(true); setError(null);
    try {
      const next = await client.listSessions(roleId, filter, directory.nextAfter), previous = directory.items.at(-1)?.session.id;
      if (pageRequest !== pageRequests.current || listRequest !== requests.current) return;
      if (next.items.some((item) => directory.items.some((known) => known.session.id === item.session.id)) || (previous && next.items[0] && next.items[0].session.id <= previous)) throw new Error("INVALID_IAM_RESPONSE");
      setDirectory({ ...next, items: [...directory.items, ...next.items] });
    } catch (failure) {
      if (pageRequest === pageRequests.current && listRequest === requests.current) setError(a(`errors.${accountError(failure)}`));
    } finally {
      if (pageRequest === pageRequests.current) setLoadingMore(false);
    }
  };

  const resetDirectoryQuery = () => { pageRequests.current += 1; setLoadingMore(false); setError(null); setPage(1); };

  return <div className={styles.stack} ref={directoryRegion} aria-busy={pending || loadingMore}>
    <div className={styles.actionHeader}><h3 ref={heading} tabIndex={-1}>{t("liveSessions")}</h3><Badge status="success">LIVE</Badge></div>
    <Alert>{t("liveSessionDirectoryHint")}</Alert>
    {ownedRevokeIntent?.phase === "unknown" ? <div className={styles.stack}><Alert status="warning">{t("pendingUnknownRevoke", { id: ownedRevokeIntent.item.session.id })}</Alert><div className={styles.actions}><Button size="small" variant="secondary" onClick={() => { returnFocus.current = ownedRevokeIntent.item.session.id; onRevokeIntentChange(ownedRevokeIntent.requestId, { ...ownedRevokeIntent, open: true }); }}>{t("resumeUnknownRevoke")}</Button></div></div> : null}
    <TableToolbar labels={toolbarLabels} search={{ label: t(queryKind === "session" ? "exactSessionSearch" : "exactSourceUserSearch"), value: query, onChange: (value) => { setQuery(value); resetDirectoryQuery(); } }}
      filters={[
        { id: "exact-kind", label: t("exactQueryKind"), value: queryKind, defaultValue: "session", onChange: (value) => { setQueryKind(value as RoleSessionFilter["exactKind"]); resetDirectoryQuery(); }, options: [{ value: "session", label: t("sessionId") }, { value: "sourceUser", label: t("sourceUserId") }] },
        { id: "lifecycle", label: t("lifecycleFilter"), value: lifecycle, defaultValue: "UNREVOKED", onChange: (value) => { setLifecycle(value as RoleSessionFilterLifecycle); resetDirectoryQuery(); }, options: (["UNREVOKED", "EXPIRED", "REVOKED", "ALL"] as const).map((value) => ({ value, label: t(`liveLifecycle.${value}`) })) }
      ]}
      status={pending ? t("refreshingSessions") : directory ? t("sessionCount", { count: items.length }) : undefined}
      tools={<Button size="small" variant="ghost" disabled={pending} onClick={() => { resetDirectoryQuery(); setRefresh((value) => value + 1); }}>{a("refresh")}</Button>} />
    {!queryValid ? <Alert status="warning">{t("exactIdInvalid")}</Alert> : null}
    {phase === "loading" ? <TableSkeleton label={t("loadingSessions")} rows={4} /> : null}
    {phase === "error" ? <EmptyState title={t("sessionDirectoryUnavailable")} description={error ?? undefined} action={<Button variant="secondary" onClick={() => { setError(null); setRefresh((value) => value + 1); }}>{t("retry")}</Button>} /> : null}
      {phase === "ready" && items.length ? <><Table aria-label={t("liveSessions")} mobileLayout="stack"><thead><tr><th scope="col">{t("caller")}</th><th scope="col">{t("sessionStatus")}</th><th scope="col">{t("issued")}</th><th scope="col">{t("expires")}</th><th scope="col">{w("actions")}</th></tr></thead><tbody>{items.slice((current - 1) * pageSize, current * pageSize).map((item) => { const resumesPending = ownedRevokeIntent?.phase === "unknown" && ownedRevokeIntent.item.session.id === item.session.id; const blockedByPending = Boolean(revokeIntent) && !resumesPending; return <tr key={item.session.id}><td data-label={t("caller")}><strong>{item.sourceUser.loginName}</strong><small>{item.sourceUser.displayName} · {item.sourceUser.id}</small><small>{item.session.id}</small></td><td data-label={t("sessionStatus")}><Badge status={item.lifecycle === "UNREVOKED" ? "success" : "neutral"}>{t(`liveLifecycle.${item.lifecycle}`)}</Badge></td><td data-label={t("issued")}><WorkspaceTime value={item.session.issuedAt} /></td><td data-label={t("expires")}><WorkspaceTime value={item.session.expiresAt} /></td><td data-label={w("actions")}><span data-live-session-actions={item.session.id}><ActionMenu iconOnly label={t("sessionActions", { id: item.session.id })} actions={[{ id: "revoke", label: t(resumesPending ? "resumeUnknownRevoke" : "revoke"), danger: true, disabledReason: blockedByPending ? t("pendingRevokeAnother") : item.revokeCapability.available ? undefined : t("revokeUnavailable"), onSelect: () => { returnFocus.current = item.session.id; if (resumesPending && ownedRevokeIntent) onRevokeIntentChange(ownedRevokeIntent.requestId, { ...ownedRevokeIntent, open: true }); else onRevokeIntentChange(null, { accountId: client.accountId, roleId, item, requestId: `ui-role-session-revoke-${crypto.randomUUID()}`, phase: "confirm", open: true }); } }]} /></span></td></tr>; })}</tbody></Table><Table.Footer note={t("liveSessionPageHint")}><TablePagination page={current} pages={pages} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} trailing={directory?.nextAfter ? <Button size="small" variant="secondary" disabled={pending || loadingMore} onClick={() => void loadMore()}>{t("loadMore")}</Button> : null} labels={{ summary: w("page", { page: current, pages }), pageSize: w("pageSize"), previous: w("previous"), next: w("next") }} /></Table.Footer></> : null}
    {phase === "ready" && !items.length ? <EmptyState title={directory?.nextAfter ? t("emptySessionWindow") : t("noMatchingSessions")} description={directory?.nextAfter ? t("emptySessionWindowHint") : t("noMatchingSessionsHint")} action={directory?.nextAfter ? <Button variant="secondary" disabled={pending || loadingMore} onClick={() => void loadMore()}>{t("continueSessionScan")}</Button> : undefined} /> : null}
    {error && phase === "ready" ? <Alert status="warning">{error}</Alert> : null}
  </div>;
}
