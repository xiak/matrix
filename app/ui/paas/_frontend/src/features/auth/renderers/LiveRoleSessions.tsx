"use client";

import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { ActionMenu, Alert, Badge, Button, EmptyState, Table, TablePagination, TableSkeleton, TableToolbar } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { accountError, type RoleAccessClient } from "../application/AccountAccessProvider";
import type { RoleCapability, RoleSessionDirectory, RoleSessionFilter, RoleSessionFilterLifecycle, RoleSessionListing } from "../domain/roles";
import { WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

const exactIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
type RevokeIntent = { item: RoleSessionListing; requestId: string; phase: "confirm" | "submitting" | "unknown" | "checking"; observation?: RoleSessionListing };

function replaceSession(directory: RoleSessionDirectory | null, item: RoleSessionListing, filter: RoleSessionFilter): RoleSessionDirectory | null {
  if (!directory) return directory;
  const matchesLifecycle = filter.lifecycle === "ALL" || filter.lifecycle === item.lifecycle;
  const matchesExact = !filter.exactId || (filter.exactKind === "session" ? item.session.id === filter.exactId : item.sourceUser.id === filter.exactId);
  return { ...directory, items: directory.items.flatMap((candidate) => candidate.session.id === item.session.id ? matchesLifecycle && matchesExact ? [item] : [] : [candidate]) };
}

export function LiveRoleSessions({ client, roleId, listCapability }: { client: RoleAccessClient; roleId: string; listCapability: RoleCapability }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), a = useTranslations("AccountAccess"), toolbarLabels = useTableToolbarLabels();
  const [queryKind, setQueryKind] = useState<RoleSessionFilter["exactKind"]>("session"), [query, setQuery] = useState(""), [appliedQuery, setAppliedQuery] = useState("");
  const [lifecycle, setLifecycle] = useState<RoleSessionFilterLifecycle>("UNREVOKED"), [directory, setDirectory] = useState<RoleSessionDirectory | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "error">("loading"), [completedRequest, setCompletedRequest] = useState(""), [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null), [page, setPage] = useState(1), [pageSize, setPageSize] = useState(10), [refresh, setRefresh] = useState(0);
  const [intent, setIntent] = useState<RevokeIntent | null>(null);
  const directoryRegion = useRef<HTMLDivElement>(null), heading = useRef<HTMLHeadingElement>(null), returnFocus = useRef<string | null>(null), previousIntent = useRef(intent), requests = useRef(0);
  const normalized = query.trim(), queryValid = !normalized || exactIdPattern.test(normalized);
  const filter = useMemo<RoleSessionFilter>(() => ({ exactKind: queryKind, exactId: appliedQuery, lifecycle }), [appliedQuery, lifecycle, queryKind]);
  const requestKey = `${roleId}\u0000${queryKind}\u0000${appliedQuery}\u0000${lifecycle}\u0000${refresh}`;
  const pending = listCapability.available && (!appliedQuery || exactIdPattern.test(appliedQuery)) && completedRequest !== requestKey;

  useEffect(() => { const timer = window.setTimeout(() => setAppliedQuery(normalized), 250); return () => window.clearTimeout(timer); }, [normalized]);
  useEffect(() => {
    const request = ++requests.current;
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
    if (previousIntent.current && !intent && returnFocus.current) {
      const trigger = directoryRegion.current?.querySelector<HTMLElement>(`[data-live-session-actions="${returnFocus.current}"] button`);
      if (trigger) trigger.focus({ preventScroll: true }); else heading.current?.focus({ preventScroll: true });
      returnFocus.current = null;
    }
    previousIntent.current = intent;
  }, [intent]);

  if (!listCapability.available) return <EmptyState title={t("liveSessionsUnavailable")} description={t("liveSessionsUnavailableHint")} />;
  if (intent) {
    const observed = intent.observation;
    const confirm = async () => {
      setIntent((current) => current ? { ...current, phase: "submitting" } : current);
      try {
        const result = await client.revokeSession(roleId, intent.item.session.id, intent.requestId);
        const revoked: RoleSessionListing = { ...intent.item, session: result.session, lifecycle: "REVOKED", revokeCapability: { ...intent.item.revokeCapability, available: false, restrictionReason: "SESSION_NOT_REVOCABLE" } };
        setDirectory((current) => replaceSession(current, revoked, filter)); setIntent(null);
      } catch {
        setIntent((current) => current ? { ...current, phase: "unknown" } : current);
      }
    };
    const inspect = async () => {
      setIntent((current) => current ? { ...current, phase: "checking" } : current);
      try {
        const result = await client.readSession(roleId, intent.item.session.id);
        setDirectory((current) => replaceSession(current, result.item, filter));
        setIntent((current) => current ? { ...current, phase: "unknown", observation: result.item } : current);
      } catch { setIntent((current) => current ? { ...current, phase: "unknown" } : current); }
    };
    const busy = intent.phase === "submitting" || intent.phase === "checking";
    return <section className={styles.stack} role="group" aria-label={t("revoke")}>
      <div className={styles.sectionHeading}><Button variant="ghost" disabled={busy} onClick={() => setIntent(null)}>{t("backToSessions")}</Button><h3 className={styles.detailTitle} tabIndex={-1}>{t("revoke")}</h3></div>
      <Alert status="warning">{t("liveRevokeHint")}</Alert>
      {intent.phase === "unknown" ? <Alert status={observed?.lifecycle === "REVOKED" ? "info" : "danger"}>{observed ? t(observed.lifecycle === "REVOKED" ? "authoritativeRevoked" : "authoritativeUnrevoked") : t("revokeOutcomeUnknown")}</Alert> : null}
      <dl className={styles.facts}><div><dt>{t("caller")}</dt><dd>{intent.item.sourceUser.loginName}<small>{intent.item.sourceUser.id}</small></dd></div><div><dt>{t("sessionId")}</dt><dd><code>{intent.item.session.id}</code></dd></div><div><dt>{t("requestId")}</dt><dd><code>{intent.requestId}</code></dd></div><div><dt>{t("expires")}</dt><dd><WorkspaceTime value={intent.item.session.expiresAt} /></dd></div></dl>
      <div className={styles.actions}>
        {observed?.lifecycle === "REVOKED" ? <Button variant="secondary" onClick={() => setIntent(null)}>{t("backToSessions")}</Button> : <Button variant="danger" disabled={busy} onClick={() => void confirm()}>{intent.phase === "unknown" ? t("retryOriginalRequest") : t("revoke")}</Button>}
        {intent.phase === "unknown" ? <Button variant="secondary" disabled={busy} onClick={() => void inspect()}>{t("readAuthoritativeState")}</Button> : null}
        <Button variant="ghost" disabled={busy} onClick={() => setIntent(null)}>{w("cancel")}</Button>
      </div>
    </section>;
  }

  const items = directory?.items ?? [], pages = Math.max(1, Math.ceil(items.length / pageSize)), current = Math.min(page, pages);
  const loadMore = async () => {
    if (!directory?.nextAfter || loadingMore) return;
    setLoadingMore(true); setError(null);
    try {
      const next = await client.listSessions(roleId, filter, directory.nextAfter), previous = directory.items.at(-1)?.session.id;
      if (next.items.some((item) => directory.items.some((known) => known.session.id === item.session.id)) || (previous && next.items[0] && next.items[0].session.id <= previous)) throw new Error("INVALID_IAM_RESPONSE");
      setDirectory({ ...next, items: [...directory.items, ...next.items] });
    } catch (failure) { setError(a(`errors.${accountError(failure)}`)); }
    finally { setLoadingMore(false); }
  };

  return <div className={styles.stack} ref={directoryRegion} aria-busy={pending || loadingMore}>
    <div className={styles.actionHeader}><h3 ref={heading} tabIndex={-1}>{t("liveSessions")}</h3><Badge status="success">LIVE</Badge></div>
    <Alert>{t("liveSessionDirectoryHint")}</Alert>
    <TableToolbar labels={toolbarLabels} search={{ label: t(queryKind === "session" ? "exactSessionSearch" : "exactSourceUserSearch"), value: query, onChange: (value) => { setQuery(value); setError(null); setPage(1); } }}
      filters={[
        { id: "exact-kind", label: t("exactQueryKind"), value: queryKind, defaultValue: "session", onChange: (value) => { setQueryKind(value as RoleSessionFilter["exactKind"]); setError(null); setPage(1); }, options: [{ value: "session", label: t("sessionId") }, { value: "sourceUser", label: t("sourceUserId") }] },
        { id: "lifecycle", label: t("lifecycleFilter"), value: lifecycle, defaultValue: "UNREVOKED", onChange: (value) => { setLifecycle(value as RoleSessionFilterLifecycle); setError(null); setPage(1); }, options: (["UNREVOKED", "EXPIRED", "REVOKED", "ALL"] as const).map((value) => ({ value, label: t(`liveLifecycle.${value}`) })) }
      ]}
      status={pending ? t("refreshingSessions") : directory ? t("sessionCount", { count: items.length }) : undefined}
      tools={<Button size="small" variant="ghost" disabled={pending} onClick={() => { setError(null); setRefresh((value) => value + 1); }}>{a("refresh")}</Button>} />
    {!queryValid ? <Alert status="warning">{t("exactIdInvalid")}</Alert> : null}
    {phase === "loading" ? <TableSkeleton label={t("loadingSessions")} rows={4} /> : null}
    {phase === "error" ? <EmptyState title={t("sessionDirectoryUnavailable")} description={error ?? undefined} action={<Button variant="secondary" onClick={() => { setError(null); setRefresh((value) => value + 1); }}>{t("retry")}</Button>} /> : null}
      {phase === "ready" && items.length ? <><Table aria-label={t("liveSessions")} mobileLayout="stack"><thead><tr><th scope="col">{t("caller")}</th><th scope="col">{t("sessionStatus")}</th><th scope="col">{t("issued")}</th><th scope="col">{t("expires")}</th><th scope="col">{w("actions")}</th></tr></thead><tbody>{items.slice((current - 1) * pageSize, current * pageSize).map((item) => <tr key={item.session.id}><td data-label={t("caller")}><strong>{item.sourceUser.loginName}</strong><small>{item.sourceUser.displayName} · {item.sourceUser.id}</small><small>{item.session.id}</small></td><td data-label={t("sessionStatus")}><Badge status={item.lifecycle === "UNREVOKED" ? "success" : "neutral"}>{t(`liveLifecycle.${item.lifecycle}`)}</Badge></td><td data-label={t("issued")}><WorkspaceTime value={item.session.issuedAt} /></td><td data-label={t("expires")}><WorkspaceTime value={item.session.expiresAt} /></td><td data-label={w("actions")}><span data-live-session-actions={item.session.id}><ActionMenu iconOnly label={t("sessionActions", { id: item.session.id })} actions={[{ id: "revoke", label: t("revoke"), danger: true, disabledReason: item.revokeCapability.available ? undefined : t("revokeUnavailable"), onSelect: () => { returnFocus.current = item.session.id; setIntent({ item, requestId: `ui-role-session-revoke-${crypto.randomUUID()}`, phase: "confirm" }); } }]} /></span></td></tr>)}</tbody></Table><Table.Footer note={t("liveSessionPageHint")}><TablePagination page={current} pages={pages} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} trailing={directory?.nextAfter ? <Button size="small" variant="secondary" disabled={pending || loadingMore} onClick={() => void loadMore()}>{t("loadMore")}</Button> : null} labels={{ summary: w("page", { page: current, pages }), pageSize: w("pageSize"), previous: w("previous"), next: w("next") }} /></Table.Footer></> : null}
    {phase === "ready" && !items.length ? <EmptyState title={directory?.nextAfter ? t("emptySessionWindow") : t("noMatchingSessions")} description={directory?.nextAfter ? t("emptySessionWindowHint") : t("noMatchingSessionsHint")} action={directory?.nextAfter ? <Button variant="secondary" disabled={pending || loadingMore} onClick={() => void loadMore()}>{t("continueSessionScan")}</Button> : undefined} /> : null}
    {error && phase === "ready" ? <Alert status="warning">{error}</Alert> : null}
  </div>;
}
