"use client";

import { useEffect, useId, useLayoutEffect, useRef, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import { Plus } from "lucide-react";
import {
  Alert,
  Badge,
  Button,
  Card,
  ContentPage,
  EmptyState,
  FormField,
  Input,
  LoadingNotice,
  PasswordInput,
  Table,
  TablePagination,
  Tabs,
  type PageCommandsHandle
} from "@ui/xiak";
import { requestToken } from "@/infrastructure/http/jsonRequest";
import {
  accountError,
  type AccountLifecycleClient,
  type AccountLifecycleMutationResult
} from "../application/AccountAccessProvider";
import type { Account, AccountAccess } from "../domain/accounts";
import { withinNewPasswordProductBounds } from "../domain/passwordEntry";
import { buildAccountTenantScene, type AccountAccessScene, type AccountTenantScene } from "../scenes/accountAccessScene";
import { AccountIdentifier } from "./AccountOverview";
import { OrganizationGovernancePreview } from "./OrganizationGovernancePreview";
import { WorkspaceDetail } from "./AccessWorkspaceUi";
import styles from "./AccountAccessRenderer.module.css";

const loginPattern = "[A-Za-z0-9][A-Za-z0-9._-]{2,63}";

type MutationNotice = "status" | "recovered" | null;
type MutationFailure = "conflict" | "unknown" | "blocked" | "refresh" | ReturnType<typeof accountError> | null;

function rejectedFailure(value: MutationFailure): ReturnType<typeof accountError> | null {
  if (value === "expired" || value === "forbidden" || value === "conflict" || value === "invalid" || value === "unavailable") return value;
  return null;
}

function accountSummary(account: Account, previous?: AccountTenantScene | null): AccountTenantScene {
  return {
    id: account.id,
    name: account.displayName,
    loginAlias: account.loginAlias,
    rootLoginName: account.rootIdentity.loginName,
    rootPrincipalId: account.rootIdentity.principalId,
    enabled: account.status === "ACTIVE",
    resourceVersion: account.resourceVersion,
    canSetStatus: false,
    statusRestrictionReason: previous?.statusRestrictionReason ?? "AUTHORITY_REQUIRED",
    canRecoverRoot: false,
    recoveryRestrictionReason: previous?.recoveryRestrictionReason ?? "AUTHORITY_REQUIRED"
  };
}

function PendingBoundary({ client, onOpen }: { client: AccountLifecycleClient; onOpen(accountId: string, create: boolean): void }) {
  const t = useTranslations("AccountAccess");
  const pending = client.pending;
  if (!pending) return null;
  return <Alert status="warning">
    <div className={styles.confirmation}>
      <strong>{t(pending.ownerCurrent ? "tenantMutationUnknownTitle" : "tenantMutationPreviousSessionTitle")}</strong>
      <p>{t(pending.ownerCurrent ? "tenantMutationUnknownHint" : "tenantMutationPreviousSessionHint", { account: pending.accountId })}</p>
      <p>{t("tenantMutationRequestId")} <code className={styles.resetRequestId}>{pending.requestId}</code></p>
      {pending.ownerCurrent ? <div className={styles.actions}>
        <Button onClick={() => onOpen(pending.accountId, pending.kind === "create")} size="small" variant="secondary">
          {t("reviewTenantMutation")}
        </Button>
      </div> : null}
    </div>
  </Alert>;
}

function CreateLiveAccount({ client, onBack, onCreated }: {
  client: AccountLifecycleClient;
  onBack(): void;
  onCreated(account: Account): Promise<void>;
}) {
  const t = useTranslations("AccountAccess");
  const auth = useTranslations("Auth");
  const formId = useId();
  const form = useRef<HTMLFormElement>(null);
  const [accountId, setAccountId] = useState("");
  const [accountName, setAccountName] = useState("");
  const [loginName, setLoginName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<MutationFailure>(null);
  const [observed, setObserved] = useState<AccountAccess | null>(null);
  const pending = client.pending;
  const pendingCreate = pending?.kind === "create" ? pending : null;
  const frozen = Boolean(pending);
  const rejected = failure === "conflict" ? null : rejectedFailure(failure);

  async function observeConflict(target: string) {
    try { setObserved(await client.read(target)); }
    catch { setObserved(null); }
  }

  async function finish(result: AccountLifecycleMutationResult, target: string) {
    if (result.status === "applied") {
      setPassword("");
      setFailure(null);
      await onCreated(result.account);
      return;
    }
    if (result.status === "conflict") {
      setFailure("conflict");
      await observeConflict(target);
      return;
    }
    if (result.status === "unknown" || result.status === "blocked") {
      setFailure(result.status);
      return;
    }
    setFailure(result.reason);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || frozen || !withinNewPasswordProductBounds(password)) return;
    const target = accountId.trim();
    setBusy(true); setFailure(null); setObserved(null);
    try {
      await finish(await client.create({
        id: target,
        displayName: accountName.trim(),
        rootLoginName: loginName.trim(),
        rootDisplayName: displayName.trim(),
        initialPassword: password,
        requestId: requestToken("ui-account-create-")
      }), target);
    } finally { setBusy(false); }
  }

  async function retry() {
    if (busy || !pendingCreate?.ownerCurrent) return;
    setBusy(true); setFailure(null);
    try { await finish(await client.retry(), pendingCreate.accountId); }
    finally { setBusy(false); }
  }

  useEffect(() => {
    if (!failure || busy) return;
    form.current?.querySelector<HTMLElement>('[role="alert"]')?.focus({ preventScroll: true });
  }, [busy, failure]);

  return <WorkspaceDetail title={t("createTenantTitle")} onBack={onBack}>
    <form aria-busy={busy || undefined} aria-label={t("createTenantTitle")} className={styles.form} id={formId} onSubmit={submit} ref={form}>
      <Alert>{t("tenantNotice")}</Alert>
      {pendingCreate ? <Alert status="warning" tabIndex={-1}>
        <div className={styles.confirmation}>
          <strong>{t(pendingCreate.ownerCurrent ? "tenantMutationUnknownTitle" : "tenantMutationPreviousSessionTitle")}</strong>
          <p>{t(pendingCreate.ownerCurrent ? "tenantCreateUnknownHint" : "tenantMutationPreviousSessionHint", { account: pendingCreate.accountId })}</p>
          <p>{t("tenantMutationRequestId")} <code className={styles.resetRequestId}>{pendingCreate.requestId}</code></p>
          {pendingCreate.ownerCurrent ? <Button disabled={busy} onClick={() => void retry()} type="button" variant="secondary">{t("retryExactTenantMutation")}</Button> : null}
        </div>
      </Alert> : null}
      {pending && !pendingCreate ? <Alert status="warning" tabIndex={-1}>{t("tenantMutationOtherTarget", { account: pending.accountId })}</Alert> : null}
      {failure === "conflict" ? <Alert status="warning" tabIndex={-1}>
        <div className={styles.confirmation}>
          <strong>{t("tenantMutationConflictTitle")}</strong>
          <p>{t(observed ? "tenantCreateConflictObserved" : "tenantMutationConflictHint", { account: accountId.trim() })}</p>
          {observed ? <p>{t("tenantObservedState", { status: t(observed.account.status === "ACTIVE" ? "tenantActive" : "tenantDisabled"), version: observed.account.resourceVersion })}</p> : null}
        </div>
      </Alert> : null}
      {rejected ? <Alert status="danger" tabIndex={-1}>{t(`errors.${rejected}`)}</Alert> : null}
      <FormField id={`${formId}-id`} label={t("accountId")} hint={t("accountIdHint")}>
        <Input aria-describedby={`${formId}-id-hint`} disabled={frozen || busy} id={`${formId}-id`} autoComplete="off" maxLength={128} pattern={"[A-Za-z0-9][A-Za-z0-9._:\\-]{0,127}"} placeholder={t("accountIdPlaceholder")} required value={accountId} onChange={(event) => setAccountId(event.target.value)} />
      </FormField>
      <FormField id={`${formId}-tenant`} label={t("accountName")}><Input disabled={frozen || busy} id={`${formId}-tenant`} maxLength={128} required value={accountName} onChange={(event) => setAccountName(event.target.value)} /></FormField>
      <FormField id={`${formId}-login`} label={t("primaryLogin")} hint={`${t("loginHint")} ${t("primaryLoginHint")}`}>
        <Input aria-describedby={`${formId}-login-hint`} disabled={frozen || busy} id={`${formId}-login`} autoComplete="off" maxLength={64} minLength={3} pattern={loginPattern} placeholder={t("primaryPlaceholder")} required value={loginName} onChange={(event) => setLoginName(event.target.value)} />
      </FormField>
      <FormField id={`${formId}-name`} label={t("displayName")}><Input disabled={frozen || busy} id={`${formId}-name`} maxLength={128} required value={displayName} onChange={(event) => setDisplayName(event.target.value)} /></FormField>
      <FormField id={`${formId}-password`} label={t("initialPassword")} hint={t("passwordHint")}>
        <PasswordInput disabled={frozen || busy} id={`${formId}-password`} autoComplete="new-password" required value={password} onChange={(event) => setPassword(event.target.value)} showLabel={auth("showPassword")} hideLabel={auth("hidePassword")} capsLockLabel={auth("capsLock")} />
      </FormField>
      <div className={styles.actions}>
        <Button disabled={frozen || busy || !withinNewPasswordProductBounds(password)} type="submit">{t(busy ? "creating" : "confirmTenant")}</Button>
        <Button disabled={busy} onClick={onBack} type="button" variant="secondary">{t("cancel")}</Button>
      </div>
    </form>
  </WorkspaceDetail>;
}

function LiveAccountDetail({ access, client, error, loading, onBack, onRefresh, onUpdated, summary }: {
  access: AccountAccess | null;
  client: AccountLifecycleClient;
  error: ReturnType<typeof accountError> | null;
  loading: boolean;
  onBack(): void;
  onRefresh(): Promise<void>;
  onUpdated(account: Account): Promise<boolean>;
  summary: AccountTenantScene | null;
}) {
  const t = useTranslations("AccountAccess");
  const auth = useTranslations("Auth");
  const passwordId = useId();
  const exact = access ? buildAccountTenantScene(access) : null;
  const account = exact ?? summary;
  const [confirmation, setConfirmation] = useState<"status" | "recovery" | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<MutationFailure>(null);
  const [notice, setNotice] = useState<MutationNotice>(null);
  const pending = client.pending;
  const targetPending = pending && account && pending.accountId === account.id ? pending : null;
  const blocked = Boolean(pending && !targetPending) || Boolean(targetPending && !targetPending.ownerCurrent);
  const rejected = failure === "conflict" ? null : rejectedFailure(failure);
  const restriction = (reason: AccountTenantScene["statusRestrictionReason"]) => t(`restrictions.${reason ?? "AUTHORITY_REQUIRED"}`);

  async function finish(result: AccountLifecycleMutationResult, kind: "status" | "recovered") {
    if (result.status === "applied") {
      setFailure(null); setNotice(null); setConfirmation(null); setPassword("");
      const refreshed = await onUpdated(result.account);
      if (refreshed) setNotice(kind);
      else setFailure("refresh");
      return;
    }
    if (result.status === "conflict") {
      setFailure("conflict"); setNotice(null);
      await onRefresh();
      return;
    }
    if (result.status === "unknown" || result.status === "blocked") {
      setFailure(result.status); setNotice(null);
      return;
    }
    setFailure(result.reason); setNotice(null);
  }

  async function retry() {
    if (busy || !targetPending?.ownerCurrent) return;
    setBusy(true); setFailure(null);
    try { await finish(await client.retry(), targetPending.kind === "recover-root-credentials" ? "recovered" : "status"); }
    finally { setBusy(false); }
  }

  async function submitStatus() {
    if (!exact || busy || pending) return;
    setBusy(true); setFailure(null); setNotice(null);
    try {
      await finish(await client.setStatus(exact.id, {
        status: exact.enabled ? "DISABLED" : "ACTIVE",
        resourceVersion: exact.resourceVersion,
        requestId: requestToken("ui-account-status-")
      }), "status");
    } finally { setBusy(false); }
  }

  async function recover(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!exact || busy || pending || !withinNewPasswordProductBounds(password)) return;
    setBusy(true); setFailure(null); setNotice(null);
    try {
      await finish(await client.recoverRootCredentials(exact.id, {
        initialPassword: password,
        resourceVersion: exact.resourceVersion,
        requestId: requestToken("ui-account-recovery-")
      }), "recovered");
    } finally { setBusy(false); }
  }

  return <WorkspaceDetail title={account?.name ?? t("tenantAccounts")} onBack={onBack}>
    <div className={styles.userSummary}>
      <div><strong>{account?.name ?? account?.id}</strong>{account ? <span className={styles.note}>{account.id}</span> : null}</div>
      {account ? <Badge status={account.enabled ? "success" : "neutral"}>{t(account.enabled ? "tenantActive" : "tenantDisabled")}</Badge> : null}
    </div>
    {loading ? <LoadingNotice className={styles.note} label={t("tenantDetailLoading")} /> : null}
    {error ? <Alert status="danger"><div className={styles.confirmation}><span>{t(`errors.${error}`)}</span><Button onClick={() => void onRefresh()} size="small" variant="secondary">{t("retryTenantRead")}</Button></div></Alert> : null}
    {targetPending ? <Alert status="warning">
      <div className={styles.confirmation}>
        <strong>{t(targetPending.ownerCurrent ? "tenantMutationUnknownTitle" : "tenantMutationPreviousSessionTitle")}</strong>
        <p>{t(targetPending.ownerCurrent ? targetPending.kind === "recover-root-credentials" ? "tenantRecoveryUnknownHint" : "tenantStatusUnknownHint" : "tenantMutationPreviousSessionHint", { account: targetPending.accountId })}</p>
        <p>{t("tenantMutationRequestId")} <code className={styles.resetRequestId}>{targetPending.requestId}</code></p>
        {targetPending.ownerCurrent ? <Button disabled={busy} onClick={() => void retry()} variant="secondary">{t("retryExactTenantMutation")}</Button> : null}
      </div>
    </Alert> : pending ? <Alert status="warning">{t("tenantMutationOtherTarget", { account: pending.accountId })}</Alert> : null}
    {failure === "conflict" ? <Alert status="warning"><div className={styles.confirmation}><strong>{t("tenantMutationConflictTitle")}</strong><p>{t("tenantMutationConflictHint", { account: account?.id ?? "—" })}</p>{exact ? <p>{t("tenantObservedState", { status: t(exact.enabled ? "tenantActive" : "tenantDisabled"), version: exact.resourceVersion })}</p> : null}</div></Alert> : null}
    {failure === "refresh" ? <Alert status="warning">{t("tenantMutationRefreshFailed")}</Alert> : null}
    {rejected ? <Alert status="danger">{t(`errors.${rejected}`)}</Alert> : null}
    {notice ? <Alert status="success">{t(notice === "status" ? "tenantStatusUpdated" : "tenantRootRecovered")}</Alert> : null}
    {account ? <section className={styles.identitySection}>
      <h3>{t("tenantIdentity")}</h3>
      <dl className={styles.facts}>
        <div><dt>{t("tenantId")}</dt><dd><AccountIdentifier label={t("tenantId")} value={account.id} /></dd></div>
        <div><dt>{t("primaryLogin")}</dt><dd>{account.rootLoginName}</dd></div>
        <div><dt>{t("rootIdentityId")}</dt><dd><AccountIdentifier label={t("rootIdentityId")} value={account.rootPrincipalId} /></dd></div>
        <div><dt>{t("alias")}</dt><dd>{account.loginAlias ?? t("aliasUnset")}</dd></div>
        <div><dt>{t("status")}</dt><dd>{t(account.enabled ? "tenantActive" : "tenantDisabled")}</dd></div>
      </dl>
      <p className={styles.note}>{t("tenantLifecycleHint")}</p>
    </section> : null}
    {exact ? <section className={styles.identitySection}>
      <h3>{t("tenantLifecycle")}</h3>
      <div className={styles.actions}>
        <Button disabled={busy || blocked || Boolean(pending) || !exact.canSetStatus} title={!exact.canSetStatus ? restriction(exact.statusRestrictionReason) : undefined} onClick={() => { setConfirmation("status"); setFailure(null); }} variant="secondary">{t(exact.enabled ? "disableTenant" : "enableTenant")}</Button>
        <Button disabled={busy || blocked || Boolean(pending) || !exact.canRecoverRoot} title={!exact.canRecoverRoot ? restriction(exact.recoveryRestrictionReason) : undefined} onClick={() => { setConfirmation("recovery"); setFailure(null); }} variant="secondary">{t("recoverRoot")}</Button>
      </div>
      {!exact.canSetStatus ? <p className={styles.note}>{t("tenantStatusRestriction")}: {restriction(exact.statusRestrictionReason)}</p> : null}
      {!exact.canRecoverRoot ? <p className={styles.note}>{t("tenantRecoveryRestriction")}: {restriction(exact.recoveryRestrictionReason)}</p> : null}
    </section> : null}
    {confirmation === "status" && exact ? <Alert status={exact.enabled ? "warning" : "info"}>
      <div className={styles.confirmation}>
        <p>{t(exact.enabled ? "disableTenantHint" : "enableTenantHint")}</p>
        <div className={styles.actions}>
          <Button disabled={busy || Boolean(pending) || !exact.canSetStatus} onClick={() => void submitStatus()} variant={exact.enabled ? "danger" : "primary"}>{t(exact.enabled ? "confirmDisableTenant" : "confirmEnableTenant")}</Button>
          <Button disabled={busy} onClick={() => setConfirmation(null)} variant="ghost">{t("cancel")}</Button>
        </div>
      </div>
    </Alert> : null}
    {confirmation === "recovery" && exact ? <form aria-label={t("recoverRoot")} className={styles.form} onSubmit={recover}>
      <p className={styles.note}>{t("recoverRootHint")}</p>
      <FormField id={passwordId} label={t("initialPassword")} hint={t("passwordHint")}>
        <PasswordInput id={passwordId} autoComplete="new-password" disabled={busy || Boolean(pending)} required value={password} onChange={(event) => setPassword(event.target.value)} showLabel={auth("showPassword")} hideLabel={auth("hidePassword")} capsLockLabel={auth("capsLock")} />
      </FormField>
      <div className={styles.actions}>
        <Button disabled={busy || Boolean(pending) || !withinNewPasswordProductBounds(password)} type="submit" variant="danger">{t("confirmRecoverRoot")}</Button>
        <Button disabled={busy} onClick={() => setConfirmation(null)} type="button" variant="ghost">{t("cancel")}</Button>
      </div>
    </form> : null}
  </WorkspaceDetail>;
}

function LiveAccountDirectoryGeneration({ client, initialAccounts, initialNextAfter }: {
  client: AccountLifecycleClient;
  initialAccounts: AccountTenantScene[];
  initialNextAfter: string | null;
}) {
  const t = useTranslations("AccountAccess");
  const w = useTranslations("IamWorkspace");
  const collection = useTranslations("Collection");
  const [accounts, setAccounts] = useState(initialAccounts);
  const [nextAfter, setNextAfter] = useState(initialNextAfter);
  const [cursorStack, setCursorStack] = useState<Array<string | undefined>>([undefined]);
  const [pageIndex, setPageIndex] = useState(0);
  const [listLoading, setListLoading] = useState(false);
  const [listError, setListError] = useState<ReturnType<typeof accountError> | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedSummary, setSelectedSummary] = useState<AccountTenantScene | null>(null);
  const [selectedAccess, setSelectedAccess] = useState<AccountAccess | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<ReturnType<typeof accountError> | null>(null);
  const [creating, setCreating] = useState(false);
  const createActionFocus = useRef<PageCommandsHandle>(null);
  const previousCreating = useRef(false);
  const detailRequest = useRef(0);
  const lifecycleClient = useRef(client);

  useLayoutEffect(() => {
    lifecycleClient.current = client;
  }, [client]);

  useLayoutEffect(() => {
    const wasCreating = previousCreating.current;
    previousCreating.current = creating;
    if (wasCreating && !creating) createActionFocus.current?.focus("create");
  }, [creating]);

  async function readSelected(accountId = selectedId): Promise<boolean> {
    if (!accountId) return false;
    const request = ++detailRequest.current;
    setDetailLoading(true); setDetailError(null); setSelectedAccess(null);
    try {
      const value = await client.read(accountId);
      if (request !== detailRequest.current) return false;
      const summary = buildAccountTenantScene(value);
      setSelectedAccess(value); setSelectedSummary(summary);
      setAccounts((current) => current.map((item) => item.id === summary.id ? summary : item));
      return true;
    } catch (failure) {
      if (request !== detailRequest.current) return false;
      setDetailError(accountError(failure));
      return false;
    } finally { if (request === detailRequest.current) setDetailLoading(false); }
  }

  useEffect(() => {
    if (!selectedId) return;
    const request = ++detailRequest.current;
    void lifecycleClient.current.read(selectedId).then((value) => {
      if (request !== detailRequest.current) return;
      const summary = buildAccountTenantScene(value);
      setSelectedAccess(value);
      setSelectedSummary(summary);
      setAccounts((current) => current.map((item) => item.id === summary.id ? summary : item));
    }).catch((failure) => {
      if (request !== detailRequest.current) return;
      setDetailError(accountError(failure));
    }).finally(() => {
      if (request === detailRequest.current) setDetailLoading(false);
    });
    return () => { detailRequest.current += 1; };
  }, [client.identity, selectedId]);

  async function loadPage(after: string | undefined, nextPage: number) {
    if (listLoading) return;
    setListLoading(true); setListError(null);
    try {
      const page = await client.list(after);
      setAccounts(page.items.map(buildAccountTenantScene));
      setNextAfter(page.nextAfter);
      setPageIndex(nextPage);
    } catch (failure) { setListError(accountError(failure)); }
    finally { setListLoading(false); }
  }

  async function updateAfterMutation(account: Account): Promise<boolean> {
    const summary = accountSummary(account, selectedSummary);
    setSelectedSummary(summary); setSelectedAccess(null);
    setAccounts((current) => current.map((item) => item.id === account.id ? summary : item));
    return readSelected(account.id);
  }

  async function refreshAfterCreate() {
    setCreating(false);
    setListError(null);
    try {
      const page = await client.list(cursorStack[pageIndex]);
      setAccounts(page.items.map(buildAccountTenantScene)); setNextAfter(page.nextAfter);
    } catch (failure) {
      // Creation is already confirmed. A failed directory refresh is a separate read failure.
      setListError(accountError(failure));
    }
  }

  function openPending(accountId: string, create: boolean) {
    if (create) { setCreating(true); setSelectedId(null); return; }
    const summary = accounts.find((item) => item.id === accountId) ?? null;
    setSelectedSummary(summary); setSelectedAccess(null); setDetailError(null); setDetailLoading(true); setCreating(false); setSelectedId(accountId);
  }

  if (creating) return <CreateLiveAccount client={client} onBack={() => setCreating(false)} onCreated={refreshAfterCreate} />;
  if (selectedId) return <LiveAccountDetail access={selectedAccess} client={client} error={detailError} loading={detailLoading}
    onBack={() => { detailRequest.current += 1; setSelectedId(null); setSelectedAccess(null); setDetailError(null); }}
    onRefresh={async () => { await readSelected(selectedId); }} onUpdated={updateAfterMutation} summary={selectedSummary} />;

  return <div className={styles.stack}>
    <PendingBoundary client={client} onOpen={openPending} />
    <Card>
      <ContentPage.Heading title={t("tenantAccounts")} scrollKey="live-tenant-directory" actions={client.canCreate ? <ContentPage.Commands label={collection("pageActions")} focusRef={createActionFocus} primary={{ id: "create", label: t("openTenant"), icon: <Plus aria-hidden="true" />, disabled: listLoading || Boolean(client.pending), onSelect: () => { setCreating(true); setSelectedId(null); } }} /> : undefined} />
      <Alert>{t("tenantLiveBoundary")}</Alert>
      {listError ? <Alert status="danger"><div className={styles.confirmation}><span>{t(`errors.${listError}`)}</span><Button onClick={() => void loadPage(cursorStack[pageIndex], pageIndex)} size="small" variant="secondary">{t("retryTenantRead")}</Button></div></Alert> : null}
      {listLoading ? <LoadingNotice className={styles.note} label={t("loadingTenants")} /> : null}
      <Table aria-label={t("tenantTable")} mobileLayout="stack"><thead><tr><th scope="col">{t("tenant")}</th><th scope="col">{t("primaryLogin")}</th><th scope="col">{t("alias")}</th><th scope="col">{t("status")}</th></tr></thead>
        <tbody>{accounts.map((account) => <tr key={account.id}><td data-label={t("tenant")}><Table.PrimaryAction onClick={() => { setSelectedSummary(account); setSelectedAccess(null); setDetailError(null); setDetailLoading(true); setSelectedId(account.id); }}>{account.name}</Table.PrimaryAction><small>{account.id}</small></td><td data-label={t("primaryLogin")}>{account.rootLoginName}</td><td data-label={t("alias")}>{account.loginAlias ?? t("aliasUnset")}</td><td data-label={t("status")}><Badge status={account.enabled ? "success" : "neutral"}>{t(account.enabled ? "tenantActive" : "tenantDisabled")}</Badge></td></tr>)}</tbody>
      </Table>
      {!accounts.length && !listLoading ? <EmptyState title={t("noTenants")} /> : null}
      <Table.Footer note={t("tenantScopeHint")}><TablePagination mode="cursor" disabled={listLoading} summary={w("cursorPage", { page: pageIndex + 1 })}
        previous={{ label: t("firstPage"), disabled: pageIndex === 0, onClick: () => { const next = Math.max(0, pageIndex - 1); void loadPage(cursorStack[next], next); } }}
        next={{ label: t("nextPage"), disabled: !nextAfter, onClick: () => { if (!nextAfter) return; const next = pageIndex + 1; setCursorStack((current) => { const updated = current.slice(0, next); updated[next] = nextAfter; return updated; }); void loadPage(nextAfter, next); } }} /></Table.Footer>
    </Card>
  </div>;
}

export function LiveAccountTenants({ client, scene }: { client: AccountLifecycleClient; scene: AccountAccessScene }) {
  const t = useTranslations("AccountAccess");
  const [section, setSection] = useState<"accounts" | "governance">("accounts");
  const [binding, setBinding] = useState(() => ({ identity: client.identity, generation: 0 }));
  let current = binding;
  if (binding.identity !== client.identity) {
    current = { identity: client.identity, generation: binding.generation + 1 };
    setBinding(current);
  }
  return <Tabs.Root value={section} onValueChange={(value) => setSection(value as typeof section)}>
    <Tabs.List aria-label={t("tenantManagementSections")}>
      <Tabs.Trigger value="accounts">{t("tenantAccounts")}</Tabs.Trigger>
      <Tabs.Trigger value="governance">{t("organizationGovernance.tab")}</Tabs.Trigger>
    </Tabs.List>
    <Tabs.Content value="accounts"><LiveAccountDirectoryGeneration client={client} initialAccounts={scene.accounts} initialNextAfter={scene.nextAccountPage} key={current.generation} /></Tabs.Content>
    <Tabs.Content value="governance"><OrganizationGovernancePreview /></Tabs.Content>
  </Tabs.Root>;
}
