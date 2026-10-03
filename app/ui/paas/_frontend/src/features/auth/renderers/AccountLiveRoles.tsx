"use client";

import { useCallback, useDeferredValue, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Plus } from "lucide-react";
import { Alert, Badge, Button, Card, ContentPage, EmptyState, FormField, Select, Skeleton, Table, TablePagination, TableSkeleton, TableToolbar, Tabs } from "@ui/xiak";
import { requestToken } from "@/infrastructure/http/jsonRequest";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { accountError, type RoleAccessClient, type RoleSessionRevokeIntent, type ServiceLinkedRoleClient, type ServiceRoleTemplateClient } from "../application/AccountAccessProvider";
import type { AccountAccessView, AccountPolicy } from "../domain/accounts";
import type { RoleAccess, RoleCapability, RoleCapabilityAction, RoleListing, RolePermissionBoundary, RoleTrustVersion, RoleTrustVersionDirectory } from "../domain/roles";
import { AuthorizationOverview, WorkspaceDetail, WorkspaceTime } from "./AccessWorkspaceUi";
import { LiveRoleSessions } from "./LiveRoleSessions";
import { AccountServiceAuthorizations } from "./AccountServiceAuthorizations";
import { useAccessDraft } from "./useAccessDraft";
import styles from "./AccountAccessRenderer.module.css";

type OpenRoleEntity = (view: AccountAccessView, id?: string) => void;

function durationLabel(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  return `${Math.round(seconds / 60)} min`;
}

function capabilityState(capability: RoleCapability) {
  return capability.available ? "available" : "restricted";
}

function trustPrincipalCount(version: RoleTrustVersion): number {
  return version.document.statements.reduce((count, statement) => count + statement.principals.length, 0);
}

type RoleBoundaryIntent =
  | { kind: "set"; policyId: string; policyResourceVersion: number; resourceVersion: number; requestId: string; versionId: string }
  | { kind: "remove"; resourceVersion: number; requestId: string };
type RoleBoundaryOperation = { state: "idle" | "pending" | "uncertain" | "conflict" | "refreshFailed" | "completed"; error?: ReturnType<typeof accountError> };

function roleCapability(access: RoleAccess, action: RoleCapabilityAction): RoleCapability | null {
  return access.capabilities.find((candidate) => candidate.action === action && candidate.resource.kind === "ROLE" && candidate.resource.id === access.role.id) ?? null;
}

function LiveRoleAuthorizationOverview({ access, client, onAccessChanged, onOpen }: {
  access: RoleAccess;
  client: RoleAccessClient;
  onAccessChanged(access: RoleAccess): void;
  onOpen: OpenRoleEntity;
}) {
  const t = useTranslations("RoleWorkspace"), a = useTranslations("AccountAccess"), w = useTranslations("IamWorkspace");
  const selectId = useId();
  const form = useRef<HTMLFormElement>(null), editTrigger = useRef<HTMLButtonElement>(null), restoreEditFocus = useRef(false);
  const mounted = useRef(true), requests = useRef(0), policyRequests = useRef(0), intent = useRef<RoleBoundaryIntent | null>(null);
  const [boundary, setBoundary] = useState<RolePermissionBoundary | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null), [refresh, setRefresh] = useState(0), [editing, setEditing] = useState(false);
  const [policies, setPolicies] = useState<AccountPolicy[]>([]), [policiesAvailable, setPoliciesAvailable] = useState(true);
  const [policyPhase, setPolicyPhase] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [value, setValue] = useState(""), [review, setReview] = useState(false), [reviewedVersion, setReviewedVersion] = useState<string | null>(null);
  const [operation, setOperation] = useState<RoleBoundaryOperation>({ state: "idle" });

  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  useEffect(() => {
    const request = ++requests.current;
    client.readPermissionBoundary(access.role.id).then((value) => {
      if (request !== requests.current) return;
      setBoundary(value); setValue(value.policy?.policyId ?? ""); setPhase("ready");
    }, (failure: unknown) => {
      if (request !== requests.current) return;
      setError(a(`errors.${accountError(failure)}`)); setPhase("error");
    });
    return () => { requests.current += 1; };
  }, [a, access.role.id, client, refresh]);

  const retry = () => {
    setBoundary(null); setError(null); setPhase("loading");
    setRefresh((value) => value + 1);
  };
  const setCapability = roleCapability(access, "iam.role.permission-boundary.set");
  const removeCapability = roleCapability(access, "iam.role.permission-boundary.remove");
  const canSet = setCapability?.available === true, canRemove = removeCapability?.available === true;
  const canChange = phase === "ready" && (canSet || (boundary?.policy !== null && canRemove));
  const activePolicies = policies.filter((policy) => policy.status === "ACTIVE" && policy.scope === "TENANT" && (policy.accountId === null || policy.accountId === client.accountId));
  const selected = activePolicies.find((policy) => policy.id === value);
  const currentPolicyId = boundary?.policy?.policyId ?? "";
  const eligible = phase === "ready" && value !== currentPolicyId && (value ? Boolean(selected && canSet) : Boolean(boundary?.policy && canRemove));
  const locked = operation.state === "pending" || operation.state === "conflict" || operation.state === "refreshFailed";
  const restrictionReason = setCapability?.restrictionReason ?? removeCapability?.restrictionReason ?? "AUTHORITY_REQUIRED";
  useAccessDraft({ dirty: editing && (value !== currentPolicyId || review || operation.state === "uncertain"), busy: operation.state === "pending", title: t("editBoundary"), description: t("boundaryChangeHint"), form });
  useLayoutEffect(() => {
    if (!editing && restoreEditFocus.current) {
      restoreEditFocus.current = false;
      editTrigger.current?.focus({ preventScroll: true });
    }
  }, [editing, operation.state]);

  const loadPolicies = useCallback(async () => {
    const request = ++policyRequests.current;
    setPolicyPhase("loading"); setPoliciesAvailable(true);
    try {
      const directory = await client.listBoundaryPolicies();
      if (!mounted.current || request !== policyRequests.current) return;
      setPolicies(directory.items); setPoliciesAvailable(directory.available); setPolicyPhase("ready");
    } catch {
      if (!mounted.current || request !== policyRequests.current) return;
      setPolicies([]); setPoliciesAvailable(false); setPolicyPhase("error");
    }
  }, [client]);

  const openEditor = () => {
    if (!boundary || !canChange) return;
    setValue(boundary.policy?.policyId ?? ""); setReview(false); setReviewedVersion(null); intent.current = null;
    setOperation({ state: "idle" }); setEditing(true);
    if (canSet && (policyPhase === "idle" || policyPhase === "error")) void loadPolicies();
  };

  const refreshAuthoritative = async (purpose: "conflict" | "confirmed") => {
    setOperation({ state: "pending" });
    try {
      const [latestAccess, latestBoundary] = await Promise.all([client.read(access.role.id), client.readPermissionBoundary(access.role.id)]);
      if (!mounted.current) return;
      onAccessChanged(latestAccess); setBoundary(latestBoundary); setValue(latestBoundary.policy?.policyId ?? "");
      intent.current = null; setReview(false); setReviewedVersion(null);
      if (purpose === "confirmed") { restoreEditFocus.current = true; setEditing(false); setOperation({ state: "completed" }); }
      else {
        const latestCanSet = roleCapability(latestAccess, "iam.role.permission-boundary.set")?.available === true;
        if (latestCanSet) await loadPolicies();
        if (mounted.current) setOperation({ state: "idle" });
      }
    } catch (failure) {
      if (!mounted.current) return;
      setOperation({ state: purpose === "confirmed" ? "refreshFailed" : "conflict", error: accountError(failure) });
    }
  };

  const submit = async () => {
    if (!boundary || locked) return;
    if (!review) {
      if (!eligible) return;
      intent.current = selected && value
        ? { kind: "set", policyId: selected.id, policyResourceVersion: selected.resourceVersion, resourceVersion: boundary.resourceVersion, requestId: requestToken("role-boundary-"), versionId: selected.defaultVersionId }
        : { kind: "remove", resourceVersion: boundary.resourceVersion, requestId: requestToken("role-boundary-") };
      setReviewedVersion(selected?.defaultVersionId ?? null); setReview(true); setOperation({ state: "idle" });
      return;
    }
    const original = intent.current;
    if (!original) return;
    setOperation({ state: "pending" });
    try {
      const result = original.kind === "set"
        ? await client.setPermissionBoundary(access.role.id, { policyId: original.policyId, policyResourceVersion: original.policyResourceVersion, resourceVersion: original.resourceVersion, requestId: original.requestId })
        : await client.removePermissionBoundary(access.role.id, { resourceVersion: original.resourceVersion, requestId: original.requestId });
      if (!mounted.current) return;
      if (original.kind === "set" && result.policy?.versionId !== original.versionId) throw new Error("INVALID_IAM_RESPONSE");
      setBoundary(result); setValue(result.policy?.policyId ?? ""); intent.current = null; setReview(false); setReviewedVersion(null);
    } catch (failure) {
      if (!mounted.current) return;
      const next = accountError(failure);
      if (next === "expired") { intent.current = null; setEditing(false); setReview(false); }
      else if (next !== "unavailable" && next !== "conflict") { intent.current = null; setReview(false); }
      setOperation({ state: next === "unavailable" ? "uncertain" : next === "conflict" ? "conflict" : "idle", error: next });
      return;
    }
    await refreshAuthoritative("confirmed");
  };

  const boundaryValue = phase === "loading" ? <span aria-label={t("boundaryLoading")} role="status"><Skeleton /></span>
    : phase === "error" ? <Badge status="neutral">{t("boundaryUnknown")}</Badge>
      : boundary?.policy ? <span><button className={styles.userLink} onClick={() => onOpen("policies", currentPolicyId)} type="button">{boundary.policy.policyId}</button><small>{t("boundaryPolicyVersion", { version: boundary.policy.versionId, revision: boundary.resourceVersion })}</small></span>
        : <span><Badge status="warning">{t("boundaryClosed")}</Badge><small>{t("boundaryClosedHint")}</small></span>;
  return <>
    <AuthorizationOverview title={t("authorizationOverview")} hint={t("liveAuthorizationOverviewHint")} items={[
      { label: t("trustAdmission"), value: t("trustedUserCount", { count: trustPrincipalCount(access.trustVersion) }) },
      { label: t("livePermissions"), value: t("attachedPolicyCount", { count: access.policyAttachments.length }) },
      { label: t("boundary"), value: boundaryValue },
      { label: t("maximumSession"), value: durationLabel(access.role.maxSessionDurationSeconds) }
    ]} />
    {phase === "error" ? <Alert status="warning"><div className={styles.confirmation}><span>{t("boundaryUnavailable")}{error ? ` ${error}` : ""}</span><Button size="small" variant="secondary" onClick={retry}>{t("retry")}</Button></div></Alert> : null}
    {phase === "ready" && boundary ? <section className={styles.identitySection} aria-label={t("boundaryManagement")}>
      <div className={styles.actionHeader}><div><h3>{t("boundaryManagement")}</h3><p className={styles.note}>{t("boundaryManagementHint")}</p></div>{!editing && canChange ? <Button ref={editTrigger} variant="secondary" disabled={locked} onClick={openEditor}>{t("editBoundary")}</Button> : null}</div>
      {!canChange ? <Alert>{t("boundaryReadOnly")} {a(`restrictions.${restrictionReason}`)}</Alert> : null}
      {operation.state === "completed" ? <Alert status="success">{t("boundaryUpdated")}</Alert> : null}
      {operation.state === "uncertain" || operation.state === "conflict" || operation.state === "refreshFailed" || operation.error ? <Alert status="warning">
        {operation.state === "uncertain" ? t("boundaryOutcomeUnknown") : operation.state === "conflict" ? t("boundaryConflict") : operation.state === "refreshFailed" ? t("boundaryRefreshFailed") : a(`errors.${operation.error!}`)}
        {operation.state === "conflict" || operation.state === "refreshFailed" ? <div className={styles.actions}><Button variant="secondary" onClick={() => void refreshAuthoritative(operation.state === "conflict" ? "conflict" : "confirmed")}>{t(operation.state === "conflict" ? "boundaryRefreshReview" : "boundaryRetryRead")}</Button></div> : null}
      </Alert> : null}
      {editing ? <form ref={form} className={styles.stack} aria-label={t("editBoundary")} onSubmit={(event) => { event.preventDefault(); void submit(); }}>
        {review ? <><Alert status="warning">{value ? t("boundarySetReviewHint") : t("boundaryRemoveReviewHint")}</Alert><dl className={styles.facts}>
          <div><dt>{t("before")}</dt><dd>{boundary.policy?.policyId ?? t("boundaryClosed")}</dd></div>
          <div><dt>{t("after")}</dt><dd>{value || t("boundaryClosed")}</dd></div>
          {reviewedVersion ? <div><dt>{t("effectiveVersion")}</dt><dd>{reviewedVersion}</dd></div> : null}
        </dl></> : <FormField id={selectId} label={t("boundary")} hint={t("boundarySelectorHint")}>
          <Select autoFocus id={selectId} disabled={locked} value={value} aria-describedby={`${selectId}-hint`} options={[
            { value: "", label: t("noBoundaryClosed"), disabled: boundary.policy !== null && !canRemove },
            ...activePolicies.map((policy) => ({ value: policy.id, label: `${policy.displayName} · ${policy.id}`, disabled: !canSet })),
            ...(!selected && value ? [{ value, label: value, disabled: true }] : [])
          ]} onValueChange={(next) => { setValue(next); intent.current = null; setOperation({ state: "idle" }); }} />
        </FormField>}
        {policyPhase === "loading" ? <p className={styles.note} role="status">{t("boundaryDirectoryLoading")}</p> : null}
        {policyPhase === "error" || !policiesAvailable ? <p className={styles.note}>{t("boundaryDirectoryUnavailable")}</p> : null}
        <div className={styles.actions}>
          <Button type="submit" disabled={locked || (!review && !eligible)}>{operation.state === "pending" ? t("boundarySaving") : operation.state === "uncertain" ? t("boundaryRetryOriginal") : review ? t("boundaryConfirm") : t("reviewChange")}</Button>
          {review ? <Button variant="secondary" disabled={locked} onClick={() => { intent.current = null; setReview(false); setOperation({ state: "idle" }); }}>{t("backToSelection")}</Button> : null}
          <Button variant="ghost" disabled={locked} onClick={() => { intent.current = null; restoreEditFocus.current = true; setEditing(false); setReview(false); setOperation({ state: "idle" }); }}>{w("cancel")}</Button>
        </div>
      </form> : null}
    </section> : null}
  </>;
}

function LiveRoleTrustHistory({ client, roleId, currentVersionId }: { client: RoleAccessClient; roleId: string; currentVersionId: string }) {
  const t = useTranslations("RoleWorkspace"), w = useTranslations("IamWorkspace"), a = useTranslations("AccountAccess");
  const [directory, setDirectory] = useState<RoleTrustVersionDirectory | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null), [loadingMore, setLoadingMore] = useState(false);
  const [selected, setSelected] = useState<RoleTrustVersion | null>(null), [page, setPage] = useState(1), [pageSize, setPageSize] = useState(10);
  const requests = useRef(0), pageRequests = useRef(0);
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    const request = ++requests.current;
    pageRequests.current += 1;
    client.listTrustVersions(roleId).then((result) => {
      if (request !== requests.current) return;
      setDirectory(result); setPhase("ready");
    }, (failure: unknown) => {
      if (request !== requests.current) return;
      setError(a(`errors.${accountError(failure)}`)); setPhase("error");
    });
    return () => { requests.current += 1; pageRequests.current += 1; };
  }, [a, client, refresh, roleId]);

  const retry = () => {
    setPhase("loading"); setDirectory(null); setSelected(null); setError(null); setPage(1);
    setRefresh((value) => value + 1);
  };

  const loadMore = async () => {
    if (!directory?.nextAfter || loadingMore) return;
    const request = ++pageRequests.current, listRequest = requests.current;
    setLoadingMore(true); setError(null);
    try {
      const next = await client.listTrustVersions(roleId, directory.nextAfter);
      if (request !== pageRequests.current || listRequest !== requests.current) return;
      if (next.items.some((item) => directory.items.some((known) => known.id === item.id))) throw new Error("INVALID_IAM_RESPONSE");
      setDirectory({ ...next, items: [...directory.items, ...next.items] });
    } catch (failure) {
      if (request === pageRequests.current && listRequest === requests.current) setError(a(`errors.${accountError(failure)}`));
    } finally {
      if (request === pageRequests.current) setLoadingMore(false);
    }
  };

  if (selected) return <section aria-label={t("trustVersionDetail")} className={styles.stack} role="group">
    <div className={styles.sectionHeading}><Button variant="ghost" onClick={() => setSelected(null)}>{t("backToTrustHistory")}</Button><h3 className={styles.detailTitle}>{t("trustVersionDetail")}</h3></div>
    <div className={styles.sectionHeading}><Badge status={selected.id === currentVersionId ? "success" : "neutral"}>{t(selected.id === currentVersionId ? "currentTrust" : "historicalTrust")}</Badge><code>{selected.id}</code></div>
    <dl className={styles.facts}><div><dt>{w("created")}</dt><dd><WorkspaceTime value={selected.createdAt} /></dd></div><div><dt>{t("statementCount")}</dt><dd>{selected.document.statements.length}</dd></div><div><dt>{t("principalCount")}</dt><dd>{trustPrincipalCount(selected)}</dd></div><div><dt>{t("verifiedDigest")}</dt><dd><code>{selected.contentDigest}</code></dd></div></dl>
    <pre className={styles.code}>{JSON.stringify(selected.document, null, 2)}</pre>
  </section>;

  if (phase === "loading") return <TableSkeleton label={t("loadingTrustHistory")} rows={4} />;
  if (phase === "error") return <EmptyState title={t("trustHistoryUnavailable")} description={error ?? undefined} action={<Button variant="secondary" onClick={retry}>{t("retry")}</Button>} />;
  const items = directory?.items ?? [], pages = Math.max(1, Math.ceil(items.length / pageSize)), current = Math.min(page, pages);
  return <div className={styles.stack} aria-busy={loadingMore}>
    <Alert>{t("trustHistoryHint")}</Alert>
    {items.length ? <><Table aria-label={t("trustHistory")} mobileLayout="stack"><thead><tr><th scope="col">{t("trustVersion")}</th><th scope="col">{w("created")}</th><th scope="col">{t("trustedUsers")}</th><th scope="col">{w("state")}</th></tr></thead><tbody>{items.slice((current - 1) * pageSize, current * pageSize).map((version) => <tr key={version.id}>
      <td data-label={t("trustVersion")}><button className={styles.userLink} onClick={() => setSelected(version)}>{version.id}</button><small>{version.contentDigest}</small></td>
      <td data-label={w("created")}><WorkspaceTime value={version.createdAt} /></td><td data-label={t("trustedUsers")}>{trustPrincipalCount(version)}</td>
      <td data-label={w("state")}><Badge status={version.id === currentVersionId ? "success" : "neutral"}>{t(version.id === currentVersionId ? "currentTrust" : "historicalTrust")}</Badge></td>
    </tr>)}</tbody></Table><Table.Footer note={t("trustHistoryPageHint")}><TablePagination page={current} pages={pages} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} trailing={directory?.nextAfter ? <Button size="small" variant="secondary" disabled={loadingMore} onClick={() => void loadMore()}>{t("loadMore")}</Button> : null} labels={{ summary: w("page", { page: current, pages }), pageSize: w("pageSize"), previous: w("previous"), next: w("next") }} /></Table.Footer></> : <EmptyState title={t("noTrustHistory")} description={t("noTrustHistoryHint")} />}
    {error ? <Alert status="warning">{error}</Alert> : null}
  </div>;
}

function RoleDetail({ client, roleId, onOpen, revokeIntent, onRevokeIntentChange }: {
  client: RoleAccessClient;
  roleId: string;
  onOpen: OpenRoleEntity;
  revokeIntent: RoleSessionRevokeIntent | null;
  onRevokeIntentChange(expectedRequestId: string | null, intent: RoleSessionRevokeIntent | null): void;
}) {
  const t = useTranslations("RoleWorkspace");
  const w = useTranslations("IamWorkspace");
  const a = useTranslations("AccountAccess");
  const [access, setAccess] = useState<RoleAccess | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [section, setSection] = useState("permissions");

  const retry = useCallback(() => {
    setPhase("loading");
    setError(null);
    client.read(roleId).then((value) => {
      setAccess(value);
      setPhase("ready");
    }, (failure: unknown) => {
      setError(a(`errors.${accountError(failure)}`));
      setPhase("error");
    });
  }, [a, client, roleId]);

  useEffect(() => {
    let current = true;
    client.read(roleId).then((value) => {
      if (!current) return;
      setAccess(value);
      setPhase("ready");
    }, (failure: unknown) => {
      if (!current) return;
      setError(a(`errors.${accountError(failure)}`));
      setPhase("error");
    });
    return () => { current = false; };
  }, [a, client, roleId]);

  return <WorkspaceDetail title={access?.role.name ?? roleId} onBack={() => onOpen("roles")}>
    {phase === "loading" ? <TableSkeleton label={t("loadingRole")} rows={4} header={false} /> : null}
    {phase === "error" ? <EmptyState title={t("roleUnavailable")} description={error ?? undefined} action={<Button variant="secondary" onClick={retry}>{t("retry")}</Button>} /> : null}
    {phase === "ready" && access ? <>
      <div className={styles.sectionHeading}>
        <Badge status={access.role.status === "ACTIVE" ? "success" : "neutral"}>{t(access.role.status === "ACTIVE" ? "active" : "disabled")}</Badge>
        <Badge>{t("customerManaged")}</Badge>
      </div>
      <p className={styles.note}>{access.role.description || w("none")}</p>
      <Alert>{t("liveTrustExplanation")}</Alert>
      <LiveRoleAuthorizationOverview key={`${client.sessionRevision}:${access.role.id}`} access={access} client={client} onAccessChanged={setAccess} onOpen={onOpen} />
      <dl className={styles.facts}>
        <div><dt>{t("roleId")}</dt><dd><code>{access.role.id}</code></dd></div>
        <div><dt>{t("resourceVersion")}</dt><dd>v{access.role.resourceVersion}</dd></div>
        <div><dt>{t("maximumSession")}</dt><dd>{durationLabel(access.role.maxSessionDurationSeconds)}</dd></div>
        <div><dt>{t("trustVersion")}</dt><dd><code>{access.trustVersion.id}</code></dd></div>
        <div><dt>{w("created")}</dt><dd><WorkspaceTime value={access.role.createdAt} /></dd></div>
        <div><dt>{t("updated")}</dt><dd><WorkspaceTime value={access.role.updatedAt} /></dd></div>
      </dl>
      {access.role.tags.length ? <div className={styles.roleTags}>{access.role.tags.map((tag) => <Badge key={tag.key}>{tag.key}: {tag.value}</Badge>)}</div> : null}
      <Tabs.Root value={section} onValueChange={setSection}>
        <Tabs.List aria-label={access.role.name}>
          <Tabs.Trigger value="permissions">{t("livePermissions")} ({access.policyAttachments.length})</Tabs.Trigger>
          <Tabs.Trigger value="trust">{t("liveTrust")} ({access.trustVersion.document.statements.length})</Tabs.Trigger>
          <Tabs.Trigger value="trustHistory">{t("trustHistory")}</Tabs.Trigger>
          <Tabs.Trigger value="sessions">{t("liveSessions")}</Tabs.Trigger>
          <Tabs.Trigger value="capabilities">{t("availableOperations")}</Tabs.Trigger>
        </Tabs.List>
        <Tabs.Content className={styles.stack} value="permissions">
          <Alert>{t("permissionsAreRoleGrants")}</Alert>
          {access.policyAttachments.length ? <Table aria-label={t("livePermissions")} mobileLayout="stack">
            <thead><tr><th scope="col">{t("policyId")}</th><th scope="col">{t("scope")}</th><th scope="col">{t("attachmentVersion")}</th><th scope="col">{t("updated")}</th></tr></thead>
            <tbody>{access.policyAttachments.map((attachment) => <tr key={attachment.id}>
              <td data-label={t("policyId")}><button className={styles.userLink} onClick={() => onOpen("policies", attachment.policyId)} type="button">{attachment.policyId}</button><small>{attachment.id}</small></td>
              <td data-label={t("scope")}>{t("tenantScope")}</td>
              <td data-label={t("attachmentVersion")}>v{attachment.resourceVersion}</td>
              <td data-label={t("updated")}><WorkspaceTime value={attachment.updatedAt} /></td>
            </tr>)}</tbody>
          </Table> : <EmptyState title={t("noLivePermissions")} description={t("noLivePermissionsHint")} />}
        </Tabs.Content>
        <Tabs.Content className={styles.stack} value="trust">
          <Alert>{t("trustIsAdmissionOnly")}</Alert>
          {access.trustVersion.document.statements.length ? <Table aria-label={t("liveTrust")} mobileLayout="stack">
            <thead><tr><th scope="col">SID</th><th scope="col">{t("effect")}</th><th scope="col">{t("trustedUsers")}</th></tr></thead>
            <tbody>{access.trustVersion.document.statements.map((statement) => <tr key={statement.sid}>
              <td data-label="SID"><code>{statement.sid}</code></td>
              <td data-label={t("effect")}><Badge status={statement.effect === "ALLOW" ? "success" : "warning"}>{statement.effect}</Badge></td>
              <td data-label={t("trustedUsers")}><div className={styles.roleTags}>{statement.principals.map((principal) => <button className={styles.userLink} key={principal.id} onClick={() => onOpen("users", principal.id)} type="button"><Badge>USER · {principal.id}</Badge></button>)}</div></td>
            </tr>)}</tbody>
          </Table> : <EmptyState title={t("trustClosed")} description={t("trustClosedHint")} />}
          <details className={styles.trustDocuments}>
            <summary>{t("completeTrustDocument")}</summary>
            <pre className={styles.code}>{JSON.stringify(access.trustVersion.document, null, 2)}</pre>
          </details>
          <p className={styles.note}>{t("verifiedDigest")}: <code>{access.trustVersion.contentDigest}</code></p>
        </Tabs.Content>
        <Tabs.Content className={styles.stack} value="trustHistory">
          {section === "trustHistory" ? <LiveRoleTrustHistory client={client} roleId={roleId} currentVersionId={access.role.currentTrustVersionId} /> : null}
        </Tabs.Content>
        <Tabs.Content className={styles.stack} value="sessions">
          {section === "sessions" ? <LiveRoleSessions client={client} roleId={roleId} listCapability={access.capabilities.find((capability) => capability.action === "iam.role-session.list")!} revokeIntent={revokeIntent} onRevokeIntentChange={onRevokeIntentChange} /> : null}
        </Tabs.Content>
        <Tabs.Content className={styles.stack} value="capabilities">
          <Alert>{t("capabilitySnapshotHint")}</Alert>
          <Table aria-label={t("availableOperations")} mobileLayout="stack">
            <thead><tr><th scope="col">Action</th><th scope="col">{t("resource")}</th><th scope="col">{w("state")}</th></tr></thead>
            <tbody>{access.capabilities.map((capability) => <tr key={`${capability.action}:${capability.resource.kind}:${capability.resource.id}`}>
              <td data-label="Action"><code>{capability.action}</code></td>
              <td data-label={t("resource")}><code>{capability.resource.kind}:{capability.resource.id}</code></td>
              <td data-label={w("state")}><Badge status={capability.available ? "success" : "neutral"}>{t(capabilityState(capability))}</Badge>{capability.restrictionReason ? <small>{capability.restrictionReason}</small> : null}</td>
            </tr>)}</tbody>
          </Table>
        </Tabs.Content>
      </Tabs.Root>
    </> : null}
  </WorkspaceDetail>;
}

export function AccountLiveRoles({ client, serviceRoleTemplates, serviceLinkedRoles, entityId, onCreate, onOpen, revokeIntent, onRevokeIntentChange }: {
  client: RoleAccessClient;
  serviceRoleTemplates?: ServiceRoleTemplateClient | null;
  serviceLinkedRoles?: ServiceLinkedRoleClient | null;
  entityId?: string;
  onCreate(): void;
  onOpen: OpenRoleEntity;
  revokeIntent: RoleSessionRevokeIntent | null;
  onRevokeIntentChange(expectedRequestId: string | null, intent: RoleSessionRevokeIntent | null): void;
}) {
  const t = useTranslations("RoleWorkspace");
  const w = useTranslations("IamWorkspace");
  const a = useTranslations("AccountAccess");
  const collection = useTranslations("Collection");
  const toolbarLabels = useTableToolbarLabels();
  const [roles, setRoles] = useState<RoleListing[]>([]);
  const [nextAfter, setNextAfter] = useState<string | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [query, setQuery] = useState("");
  const [state, setState] = useState("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [serviceAuthorizationOpen, setServiceAuthorizationOpen] = useState(false);
  const deferredQuery = useDeferredValue(query);

  const retry = useCallback(() => {
    setPhase("loading");
    setError(null);
    client.list().then((directory) => {
      setRoles(directory.items);
      setNextAfter(directory.nextAfter);
      setPhase("ready");
    }, (failure: unknown) => {
      setError(a(`errors.${accountError(failure)}`));
      setPhase("error");
    });
  }, [a, client]);

  useEffect(() => {
    if (entityId) return;
    let current = true;
    client.list().then((directory) => {
      if (!current) return;
      setRoles(directory.items);
      setNextAfter(directory.nextAfter);
      setPhase("ready");
    }, (failure: unknown) => {
      if (!current) return;
      setError(a(`errors.${accountError(failure)}`));
      setPhase("error");
    });
    return () => { current = false; };
  }, [a, client, entityId]);
  const words = useMemo(() => deferredQuery.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean), [deferredQuery]);
  const matches = useMemo(() => roles.filter(({ role }) => {
    const haystack = [role.name, role.id, role.description, ...role.tags.flatMap((tag) => [tag.key, tag.value])].join(" ").normalize("NFKC").toLowerCase();
    return words.every((word) => haystack.includes(word)) && (state === "all" || role.status === state);
  }), [roles, state, words]);
  const pages = Math.max(1, Math.ceil(matches.length / pageSize));
  const currentPage = Math.min(page, pages);

  if (serviceAuthorizationOpen && (serviceLinkedRoles || serviceRoleTemplates)) return <AccountServiceAuthorizations key={serviceLinkedRoles?.sessionRevision ?? serviceRoleTemplates?.sessionRevision} relations={serviceLinkedRoles ?? null} templates={serviceRoleTemplates ?? null} onBack={() => setServiceAuthorizationOpen(false)} />;
  if (entityId) return <RoleDetail client={client} roleId={entityId} onOpen={onOpen} revokeIntent={revokeIntent} onRevokeIntentChange={onRevokeIntentChange} />;

  return <Card aria-description={t("liveDirectoryHint")}>
    <ContentPage.Heading title={w("roles")} scrollKey="live-role-directory" actions={<ContentPage.Commands label={collection("pageActions")} moreLabel={collection("moreActions")}
      primary={{ id: "create", label: w("createRole"), icon: <Plus aria-hidden="true" />, disabled: !client.canCreate, disabledReason: client.createRestrictionReason ?? undefined, onSelect: onCreate }}
      secondary={serviceLinkedRoles || serviceRoleTemplates ? [{ id: "service-authorization", label: t("serviceAuthorization"), variant: "secondary", onSelect: () => setServiceAuthorizationOpen(true) }] : []} />} />
    <div className={styles.policyDirectoryIntro}><p>{t("liveDirectoryHint")}</p></div>
    <TableToolbar
      labels={toolbarLabels}
      search={{ label: t("searchRoles"), value: query, onChange: (value) => { setQuery(value); setPage(1); } }}
      filters={[{ id: "state", label: w("state"), options: [
        { value: "all", label: w("all") }, { value: "ACTIVE", label: t("active") }, { value: "DISABLED", label: t("disabled") }
      ], value: state, onChange: (value) => { setState(value); setPage(1); } }]}
      status={phase === "ready" ? t("loadedRoles", { count: roles.length }) : undefined}
    />
    {phase === "loading" ? <TableSkeleton label={t("loadingRoles")} rows={6} /> : null}
    {phase === "error" ? <EmptyState title={t("directoryUnavailable")} description={error ?? undefined} action={<Button variant="secondary" onClick={retry}>{t("retry")}</Button>} /> : null}
    {phase === "ready" ? <>
      <Table aria-label={w("roles")} aria-busy={query !== deferredQuery} mobileLayout="stack">
        <thead><tr><th scope="col">{w("name")}</th><th scope="col">{w("state")}</th><th scope="col">{t("maximumSession")}</th><th scope="col">{t("updated")}</th></tr></thead>
        <tbody>{matches.slice((currentPage - 1) * pageSize, currentPage * pageSize).map(({ role }) => <tr key={role.id}>
          <td data-label={w("name")}><button className={styles.userLink} onClick={() => onOpen("roles", role.id)}>{role.name}</button><small>{role.description || role.id}</small></td>
          <td data-label={w("state")}><Badge status={role.status === "ACTIVE" ? "success" : "neutral"}>{t(role.status === "ACTIVE" ? "active" : "disabled")}</Badge></td>
          <td data-label={t("maximumSession")}>{durationLabel(role.maxSessionDurationSeconds)}</td>
          <td data-label={t("updated")}><WorkspaceTime value={role.updatedAt} /></td>
        </tr>)}</tbody>
      </Table>
      {!matches.length ? <EmptyState title={roles.length ? w("noResults") : t("noRoles")} description={roles.length ? w("noResultsHint") : t("noRolesHint")} action={roles.length ? <Button variant="secondary" onClick={() => { setQuery(""); setState("all"); setPage(1); }}>{toolbarLabels.resetQuery}</Button> : undefined} /> : null}
      <Table.Footer note={t("loadedSearchScope")}>
        <TablePagination page={currentPage} pages={pages} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }}
          trailing={nextAfter ? <Button size="small" variant="secondary" disabled={loadingMore} onClick={async () => {
            if (!nextAfter || loadingMore) return;
            setLoadingMore(true);
            setError(null);
            try {
              const directory = await client.list(nextAfter);
              const known = new Set(roles.map((entry) => entry.role.id));
              if (directory.items.some((entry) => known.has(entry.role.id))) throw new Error("DUPLICATE_ROLE_PAGE");
              setRoles((current) => [...current, ...directory.items]);
              setNextAfter(directory.nextAfter);
            } catch (failure) { setError(a(`errors.${accountError(failure)}`)); }
            finally { setLoadingMore(false); }
          }}>{t("loadMore")}</Button> : null}
          labels={{ summary: w("page", { page: currentPage, pages }), pageSize: w("pageSize"), previous: w("previous"), next: w("next") }} />
      </Table.Footer>
      {error ? <Alert status="warning">{error}</Alert> : null}
    </> : null}
  </Card>;
}
