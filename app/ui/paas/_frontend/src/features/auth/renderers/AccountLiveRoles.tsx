"use client";

import { useCallback, useDeferredValue, useEffect, useMemo, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, ContentPage, EmptyState, Table, TablePagination, TableSkeleton, TableToolbar, Tabs } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { accountError, type RoleAccessClient } from "../application/AccountAccessProvider";
import type { AccountAccessView } from "../domain/accounts";
import type { RoleAccess, RoleCapability, RoleListing } from "../domain/roles";
import { WorkspaceDetail, WorkspaceTime } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

type OpenRoleEntity = (view: AccountAccessView, id?: string) => void;

function durationLabel(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  return `${Math.round(seconds / 60)} min`;
}

function capabilityState(capability: RoleCapability) {
  return capability.available ? "available" : "restricted";
}

function RoleDetail({ client, roleId, onOpen }: { client: RoleAccessClient; roleId: string; onOpen: OpenRoleEntity }) {
  const t = useTranslations("RoleWorkspace");
  const w = useTranslations("IamWorkspace");
  const a = useTranslations("AccountAccess");
  const [access, setAccess] = useState<RoleAccess | null>(null);
  const [phase, setPhase] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);

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
      <dl className={styles.facts}>
        <div><dt>{t("roleId")}</dt><dd><code>{access.role.id}</code></dd></div>
        <div><dt>{t("resourceVersion")}</dt><dd>v{access.role.resourceVersion}</dd></div>
        <div><dt>{t("maximumSession")}</dt><dd>{durationLabel(access.role.maxSessionDurationSeconds)}</dd></div>
        <div><dt>{t("trustVersion")}</dt><dd><code>{access.trustVersion.id}</code></dd></div>
        <div><dt>{w("created")}</dt><dd><WorkspaceTime value={access.role.createdAt} /></dd></div>
        <div><dt>{t("updated")}</dt><dd><WorkspaceTime value={access.role.updatedAt} /></dd></div>
      </dl>
      {access.role.tags.length ? <div className={styles.roleTags}>{access.role.tags.map((tag) => <Badge key={tag.key}>{tag.key}: {tag.value}</Badge>)}</div> : null}
      <Tabs.Root defaultValue="permissions">
        <Tabs.List aria-label={access.role.name}>
          <Tabs.Trigger value="permissions">{t("livePermissions")} ({access.policyAttachments.length})</Tabs.Trigger>
          <Tabs.Trigger value="trust">{t("liveTrust")} ({access.trustVersion.document.statements.length})</Tabs.Trigger>
          <Tabs.Trigger value="capabilities">{t("availableOperations")}</Tabs.Trigger>
        </Tabs.List>
        <Tabs.Content className={styles.stack} value="permissions">
          <Alert>{t("permissionsAreRoleGrants")}</Alert>
          {access.policyAttachments.length ? <Table aria-label={t("livePermissions")} mobileLayout="stack">
            <thead><tr><th scope="col">{t("policyId")}</th><th scope="col">{t("scope")}</th><th scope="col">{t("attachmentVersion")}</th><th scope="col">{t("updated")}</th></tr></thead>
            <tbody>{access.policyAttachments.map((attachment) => <tr key={attachment.id}>
              <td data-label={t("policyId")}><code>{attachment.policyId}</code><small>{attachment.id}</small></td>
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
              <td data-label={t("trustedUsers")}><div className={styles.roleTags}>{statement.principals.map((principal) => <Badge key={principal.id}>USER · {principal.id}</Badge>)}</div></td>
            </tr>)}</tbody>
          </Table> : <EmptyState title={t("trustClosed")} description={t("trustClosedHint")} />}
          <details className={styles.trustDocuments}>
            <summary>{t("completeTrustDocument")}</summary>
            <pre className={styles.code}>{JSON.stringify(access.trustVersion.document, null, 2)}</pre>
          </details>
          <p className={styles.note}>{t("verifiedDigest")}: <code>{access.trustVersion.contentDigest}</code></p>
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

export function AccountLiveRoles({ client, entityId, onOpen }: { client: RoleAccessClient; entityId?: string; onOpen: OpenRoleEntity }) {
  const t = useTranslations("RoleWorkspace");
  const w = useTranslations("IamWorkspace");
  const a = useTranslations("AccountAccess");
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

  if (entityId) return <RoleDetail client={client} roleId={entityId} onOpen={onOpen} />;

  return <Card aria-description={t("liveDirectoryHint")}>
    <ContentPage.Heading title={w("roles")} scrollKey="live-role-directory" />
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
