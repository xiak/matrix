import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { Profiler, useState } from "react";
import userEvent from "@testing-library/user-event";
import { LocaleProvider, useLocalePreference } from "@/i18n/LocaleProvider";
import { UnsavedChangesProvider, useLeaveConfirmation } from "@ui/xiak";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { SessionProvider, useSession } from "../application/SessionProvider";
import { AccountAccessProvider, useAccountAccess, useAccountCapabilities, type RoleAccessClient, type RoleSessionRevokeIntent } from "../application/AccountAccessProvider";
import type { Account, AccountAccess, AccountAccessView, AccountIdentity, AccountPolicy, AccountPolicyDetail, AccountPolicyDocument, AccountPolicyVersion, ActionCapability, AuthorizationProfileDirectory, CapabilityRestriction, IamAction, PolicyDirectory, User, UserAccess, UserPolicyAttachment, UserPermissionBoundary } from "../domain/accounts";
import type { AuthenticatorState, NotificationContact } from "../domain/personalSecurity";
import type { AccountRepository, IamRepository } from "../repositories/iamRepository";
import type { RoleAccess, RoleCapabilityAction, RoleDirectory } from "../domain/roles";
import { AccountAccessRenderer } from "./AccountAccessRenderer";
import { LiveRoleCreationWizard } from "./LiveRoleCreationWizard";
import { LoginRenderer } from "./LoginRenderer";
import { buildAccountAccessScene } from "../scenes/accountAccessScene";

const navigation = vi.hoisted(() => ({ replace: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => navigation }));
const credential = "account-test-only-memory-credential";
const timestamp = "2026-09-11T08:00:00Z";
const account: Account = { id: "tenant-a", displayName: "Team A", status: "ACTIVE", rootIdentity: { principalId: "primary-a", loginName: "admin" }, loginAlias: null, resourceVersion: 1 };
const rootUser: User = { id: "primary-a", accountId: "tenant-a", loginName: "admin", displayName: "Account owner", status: "ACTIVE", resourceVersion: 2, mustChangePassword: false };
const tenantPolicy: AccountPolicy = { id: "system.paas-viewer", management: "SYSTEM", accountId: null, displayName: "ReadOnlyAccess", scope: "TENANT", status: "ACTIVE", defaultVersionId: "version-1", resourceVersion: 3, createdAt: timestamp, updatedAt: timestamp };
const platformPolicy: AccountPolicy = { ...tenantPolicy, id: "system.platform-admin", displayName: "PlatformAdministrator", scope: "INSTALLATION", resourceVersion: 2 };
const attachment = (principalId: string, policy: AccountPolicy): UserPolicyAttachment => ({ id: `attachment-${principalId}-${policy.id}`, accountId: "tenant-a", target: { kind: "USER", id: principalId }, policyId: policy.id, scope: policy.scope, installationId: policy.scope === "INSTALLATION" ? "installation-a" : null, resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp });
const directory = (platform: boolean): PolicyDirectory => ({ accountId: "tenant-a", scope: platform ? "INSTALLATION" : "TENANT", installationId: platform ? "installation-a" : null, items: [platform ? platformPolicy : tenantPolicy] });
const profileDirectory = (): AuthorizationProfileDirectory => ({ accountId: account.id, items: [{
  profile: { product: "paas", revision: 1, callingService: "PAAS", actions: [{ action: "paas.application.read", resourceKind: "APPLICATION", scope: "TENANT", resourceShapes: [{ mode: "INSTANCE", prefixAllowed: true }], conditions: [{ key: "iam.account-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" }] }] },
  contentDigest: `sha256:${"a".repeat(64)}`
}] });
const tenantPolicyDetail: AccountPolicyDetail = { policy: tenantPolicy, version: {
  policyId: tenantPolicy.id, versionId: tenantPolicy.defaultVersionId, contentDigest: `sha256:${"a".repeat(64)}`, contractVersion: 1,
  document: { languageVersion: "1", scope: "TENANT", statements: [{ sid: "read-applications", effect: "ALLOW",
    actions: ["paas.application.read"], resources: [{ kind: "APPLICATION", match: "ANY_IN_AUTHORITY" }] }] }
} };
const capability = (action: IamAction, kind: ActionCapability["resource"]["kind"], id: string, reason: CapabilityRestriction | null = null): ActionCapability => ({ action, resource: { kind, id }, available: reason === null, restrictionReason: reason });
const currentCapabilities = (available = true): ActionCapability[] => [
  capability("iam.account.create", "ACCOUNT", "collection", available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.account.read", "ACCOUNT", "collection", available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.account.alias-set", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.user.list", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.user.create", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.policy.list", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.group.list", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED"),
  capability("iam.group.create", "ACCOUNT", account.id, available ? null : "AUTHORITY_REQUIRED")
];
const userCapabilities = (user: User, attachments: UserPolicyAttachment[] = [], reason: CapabilityRestriction | null = null): ActionCapability[] => [
  capability("iam.user.read", "USER", user.id, reason),
  capability("iam.user.update", "USER", user.id, reason),
  capability("iam.user.permission-boundary.set", "USER", user.id, reason),
  capability("iam.user.permission-boundary.remove", "USER", user.id, reason),
  capability("iam.user.delete", "USER", user.id, reason ?? (user.status === "ACTIVE" ? "TARGET_MUST_BE_DISABLED" : null)),
  capability("iam.user.set-status", "USER", user.id, reason),
  capability("iam.user.reset-password", "USER", user.id, reason),
  capability("iam.policy-attachment.create", "USER", user.id),
  capability("iam.platform-policy-attachment.create", "USER", user.id),
  ...attachments.map((item) => capability(item.scope === "INSTALLATION" ? "iam.platform-policy-attachment.revoke" : "iam.policy-attachment.revoke", "POLICY_ATTACHMENT", item.id))
];
const accountAccess = (value: Account): AccountAccess => ({ account: value, capabilities: [
  capability("iam.account.set-status", "ACCOUNT", value.id),
  capability("iam.account.recover-root-credentials", "ACCOUNT", value.id)
] });
const identity: AccountIdentity = {
  account, user: rootUser, identityKind: "ROOT_IDENTITY", policySources: [], permissionBoundary: { accountId: account.id, userId: rootUser.id, resourceVersion: rootUser.resourceVersion, policy: null }, capabilities: currentCapabilities()
};
const childUser: User = { ...rootUser, id: "child-a", loginName: "developer", displayName: "Developer A" };
const child: UserAccess = { user: childUser, policyAttachments: [attachment("child-a", tenantPolicy)], capabilities: userCapabilities(childUser, [attachment("child-a", tenantPolicy)]) };
const managedRole = {
  id: "role-reviewer", accountId: account.id, name: "ProductionLogReviewer", description: "Review production logs during an incident",
  tags: [{ key: "team", value: "operations" }], management: "CUSTOMER" as const, status: "ACTIVE" as const,
  maxSessionDurationSeconds: 3600, resourceVersion: 3, currentTrustVersionId: "trust-reviewer-v2", createdAt: timestamp, updatedAt: timestamp
};
const managedRoleActions: RoleCapabilityAction[] = [
  "iam.role.read", "iam.role.update", "iam.role.set-status", "iam.role.delete", "iam.role-trust.set",
  "iam.role-policy-attachment.create", "iam.role.permission-boundary.set", "iam.role.permission-boundary.remove", "iam.role-session.list"
];
const managedRoleCapabilities = managedRoleActions.map((action) => ({
  action, resource: { kind: "ROLE" as const, id: managedRole.id }, available: action !== "iam.role.delete",
  restrictionReason: action === "iam.role.delete" ? "AUTHORITY_REQUIRED" as const : null
}));
const managedRoleDirectory: RoleDirectory = { accountId: account.id, items: [{ role: managedRole, capabilities: managedRoleCapabilities }], nextAfter: null };
const managedRoleAccess: RoleAccess = {
  role: managedRole,
  trustVersion: {
    id: managedRole.currentTrustVersionId, accountId: account.id, roleId: managedRole.id, createdAt: timestamp,
    contentDigest: `sha256:${"a".repeat(64)}`,
    document: { languageVersion: "1", statements: [{ sid: "incident-review", effect: "ALLOW", principals: [{ type: "USER", id: childUser.id }] }] }
  },
  policyAttachments: [],
  capabilities: [...managedRoleCapabilities, {
    action: "iam.role.assume", resource: { kind: "ROLE", id: managedRole.id }, available: false, restrictionReason: "AUTHORITY_REQUIRED"
  }]
};
const managedRoleSession = {
  id: "rs1.incident-review", accountId: account.id, roleId: managedRole.id, sourceUserId: childUser.id, status: "ACTIVE" as const,
  issuedAt: timestamp, expiresAt: "2026-09-21T09:00:00Z", revokedAt: null
};
const managedRoleSessionItem = {
  session: managedRoleSession,
  sourceUser: { id: childUser.id, loginName: childUser.loginName, displayName: childUser.displayName },
  lifecycle: "UNREVOKED" as const,
  revokeCapability: { action: "iam.role-session.revoke" as const, resource: { kind: "ROLE_SESSION" as const, id: managedRoleSession.id }, available: true, restrictionReason: null }
};

function iam(overrides: Partial<IamRepository> = {}, id = "primary-a"): IamRepository {
  return {
    login: vi.fn().mockResolvedValue({ credential, mustChangePassword: false, session: { id: "session-test", organizationId: "tenant-a", principalId: id, status: "ACTIVE", issuedAt: "2026-08-27T00:00:00Z", expiresAt: "2099-08-27T00:00:00Z" } }),
    changePassword: vi.fn(), logout: vi.fn(), ...overrides
  };
}

function accounts(overrides: Partial<AccountRepository> = {}): AccountRepository {
  return {
    currentIdentity: vi.fn().mockResolvedValue(structuredClone(identity)),
    listUsers: vi.fn().mockResolvedValue({ items: [child], nextAfter: null }),
    getUser: vi.fn().mockResolvedValue(structuredClone(child)),
    listPolicies: vi.fn().mockImplementation(async (_credential: string, platform: boolean) => directory(platform)),
    listAuthorizationProfiles: vi.fn().mockResolvedValue(profileDirectory()),
    listAccounts: vi.fn().mockResolvedValue({ items: [accountAccess(identity.account)], nextAfter: null }),
    execute: vi.fn().mockResolvedValue(undefined), ...overrides
  } as AccountRepository;
}

function livePolicyVersions() {
  let policy: AccountPolicy = { ...tenantPolicy, id: "customer.logs", management: "CUSTOMER", accountId: account.id,
    displayName: "LogBoundary", defaultVersionId: "version-logs", resourceVersion: 4 };
  const current: AccountPolicyVersion = { ...tenantPolicyDetail.version, policyId: policy.id, versionId: policy.defaultVersionId };
  const earlier: AccountPolicyVersion = { ...current, versionId: "version-a", contentDigest: `sha256:${"b".repeat(64)}`,
    document: { ...current.document, statements: [{ ...current.document.statements[0]!, actions: ["paas.application.delete"] }] } };
  let versions = [earlier, current];
  const readPolicy = vi.fn(async () => ({ policy: structuredClone(policy), version: structuredClone(versions.find((item) => item.versionId === policy.defaultVersionId)!) }));
  const listPolicyVersions = vi.fn(async () => ({ policy: structuredClone(policy), items: structuredClone(versions) }));
  const createPolicyVersion = vi.fn(async (_credential: string, _accountId: string, _policyId: string,
    command: { document: AccountPolicyDocument; resourceVersion: number; expectedDefaultVersionId: string; requestId: string }) => {
    if (command.resourceVersion !== policy.resourceVersion || command.expectedDefaultVersionId !== policy.defaultVersionId) throw new HttpProblem(409, "IAM_CONFLICT");
    const version: AccountPolicyVersion = { ...current, versionId: "version-new", document: structuredClone(command.document),
      contentDigest: `sha256:${"c".repeat(64)}` };
    versions = [...versions, version].sort((left, right) => left.versionId.localeCompare(right.versionId));
    policy = { ...policy, resourceVersion: policy.resourceVersion + 1 };
    return { policy: structuredClone(policy), version: structuredClone(version) };
  });
  const setDefaultPolicyVersion = vi.fn(async (_credential: string, _accountId: string, _policyId: string,
    command: { versionId: string; resourceVersion: number; requestId: string }) => {
    if (command.resourceVersion !== policy.resourceVersion) throw new HttpProblem(409, "IAM_CONFLICT");
    policy = { ...policy, defaultVersionId: command.versionId, resourceVersion: policy.resourceVersion + 1 };
    return { policy: structuredClone(policy), version: structuredClone(versions.find((item) => item.versionId === policy.defaultVersionId)!) };
  });
  const retirePolicyVersion = vi.fn(async (_credential: string, _accountId: string, _policyId: string, versionId: string,
    command: { resourceVersion: number; expectedDefaultVersionId: string; requestId: string }) => {
    if (command.resourceVersion !== policy.resourceVersion || versionId === policy.defaultVersionId) throw new HttpProblem(409, "IAM_CONFLICT");
    versions = versions.filter((item) => item.versionId !== versionId);
    policy = { ...policy, resourceVersion: policy.resourceVersion + 1 };
    return { policy: structuredClone(policy), version: structuredClone(versions.find((item) => item.versionId === policy.defaultVersionId)!) };
  });
  const repository = accounts({ readPolicy, listPolicyVersions, readPolicyVersion: vi.fn(async (_credential, _accountId, _policyId, versionId) =>
    ({ policy: structuredClone(policy), version: structuredClone(versions.find((item) => item.versionId === versionId)!) })),
  createPolicyVersion, setDefaultPolicyVersion, retirePolicyVersion,
  listPolicies: vi.fn(async (_credential: string, platform: boolean) => platform ? directory(true) : { ...directory(false), items: [structuredClone(policy)] }) });
  return { repository, readPolicy, listPolicyVersions, createPolicyVersion, setDefaultPolicyVersion, retirePolicyVersion };
}

function boundaryFixture() {
  const target = structuredClone(child);
  let boundary: UserPermissionBoundary = { accountId: account.id, userId: target.user.id, resourceVersion: target.user.resourceVersion, policy: null };
  let policies = [structuredClone(tenantPolicy), { ...tenantPolicy, id: "customer.logs", management: "CUSTOMER" as const, accountId: account.id, displayName: "LogBoundary", resourceVersion: 4, defaultVersionId: "version-logs" }];
  const reference = (policyId: string) => {
    const policy = policies.find((item) => item.id === policyId)!;
    return { policyId, versionId: policy.defaultVersionId, contentDigest: `sha256:${"a".repeat(64)}` };
  };
  const boundaries = {
    read: vi.fn(async () => structuredClone(boundary)),
    set: vi.fn(async (_credential: string, _accountId: string, _userId: string, command: { policyId: string; policyResourceVersion: number; resourceVersion: number; requestId: string }) => {
      if (command.resourceVersion !== target.user.resourceVersion) throw new HttpProblem(409, "IAM_CONFLICT");
      target.user.resourceVersion += 1;
      boundary = { ...boundary, resourceVersion: target.user.resourceVersion, policy: reference(command.policyId) };
      return structuredClone(boundary);
    }),
    remove: vi.fn(async (_credential: string, _accountId: string, _userId: string, command: { resourceVersion: number; requestId: string }) => {
      if (command.resourceVersion !== target.user.resourceVersion) throw new HttpProblem(409, "IAM_CONFLICT");
      target.user.resourceVersion += 1;
      boundary = { ...boundary, resourceVersion: target.user.resourceVersion, policy: null };
      return structuredClone(boundary);
    })
  };
  const repository = accounts({
    permissionBoundaries: boundaries,
    getUser: vi.fn(async () => structuredClone(target)),
    listPolicies: vi.fn(async (_credential: string, platform: boolean) => platform ? directory(true) : { ...directory(false), items: structuredClone(policies) })
  });
  return { repository, boundaries,
    advance() { target.user.resourceVersion += 1; boundary.resourceVersion = target.user.resourceVersion; policies = policies.map((policy) => ({ ...policy, resourceVersion: policy.resourceVersion + 1 })); },
    readOnly() { target.capabilities = target.capabilities.map((capability) => capability.action.includes("permission-boundary") ? { ...capability, available: false, restrictionReason: "AUTHORITY_REQUIRED" } : capability); }
  };
}

async function openBoundary(fixture: ReturnType<typeof boundaryFixture>) {
  const result = await openAccess(fixture.repository);
  await screen.findByText("Developer A");
  await result.user.click(screen.getByRole("button", { name: "查看用户 developer" }));
  await screen.findByRole("region", { name: "权限边界" });
  return result;
}

async function chooseBoundary(user: ReturnType<typeof userEvent.setup>, label: string) {
  await user.click(screen.getByRole("button", { name: "修改权限边界" }));
  await user.click(screen.getByRole("combobox", { name: "权限边界" }));
  await user.click(screen.getByRole("option", { name: label }));
  await user.click(screen.getByRole("button", { name: "审阅变更" }));
}

function LanguageSwitch() {
  const { locale, setLocale } = useLocalePreference();
  return <button onClick={() => setLocale(locale === "en" ? "zh-CN" : "en")}>Switch language</button>;
}

const capabilityCommit = vi.fn();
function CapabilityProbe() {
  const capabilities = useAccountCapabilities();
  return <Profiler id="navigation-capabilities" onRender={capabilityCommit}>
    <output data-testid="can-manage">{String(capabilities.canListUsers)}</output>
    <output data-testid="can-read-accounts">{String(capabilities.canReadAccounts)}</output>
  </Profiler>;
}

const accountSwitchIntent: RoleSessionRevokeIntent = {
  accountId: account.id,
  roleId: managedRole.id,
  item: managedRoleSessionItem,
  requestId: "ui-role-session-revoke-account-switch",
  phase: "unknown",
  open: false
};

function AccountIntentProbe() {
  const session = useSession();
  const access = useAccountAccess();
  return <>
    <button onClick={() => void session.login("admin-a", "password-a")}>login-a</button>
    <button onClick={() => void session.logout()}>logout</button>
    <button onClick={() => void session.login("admin-b", "password-b")}>login-b</button>
    <button onClick={() => access.changeRoleSessionRevokeIntent(null, accountSwitchIntent)}>remember-revoke</button>
    <button onClick={() => access.changeRoleSessionRevokeIntent(accountSwitchIntent.requestId, { ...accountSwitchIntent, phase: "checking" })}>late-old-update</button>
    <output aria-label="active-account">{access.scene?.accountId ?? "none"}</output>
    <output aria-label="pending-revoke">{access.roleSessionRevokeIntent?.requestId ?? "none"}</output>
  </>;
}

function AuthenticatedAccess({ repository, initialView }: { repository: AccountRepository; initialView: AccountAccessView }) {
  const requestLeave = useLeaveConfirmation();
  const session = useSession();
  const [view, setView] = useState(initialView);
  const [entityId, setEntityId] = useState<string>();
  return session.phase === "authenticated" ? <AccountAccessProvider repository={repository}><CapabilityProbe /><nav>{(["overview", "users", "settings", "policies", "roles", "tenants"] as const).map((target) => <button data-testid={"nav-" + target} aria-current={view === target ? "page" : undefined} key={target} onClick={() => requestLeave(() => { setView(target); setEntityId(undefined); })}>{target}</button>)}</nav><AccountAccessRenderer view={view} entityId={entityId} onNavigate={(next, id) => requestLeave(() => { setView(next); setEntityId(id); })} /></AccountAccessProvider> : <LoginRenderer />;
}

async function openAccess(repository = accounts(), iamRepository = iam(), initialView: AccountAccessView = "users") {
  const user = userEvent.setup();
  const view = render(<LocaleProvider><LanguageSwitch /><SessionProvider repository={iamRepository}><UnsavedChangesProvider><AuthenticatedAccess repository={repository} initialView={initialView} /></UnsavedChangesProvider></SessionProvider></LocaleProvider>);
  await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
  await user.click(screen.getByRole("button", { name: "登录控制台" }));
  await waitFor(() => expect(repository.currentIdentity).toHaveBeenCalledWith(credential));
  return { user, view, repository };
}

afterEach(() => { cleanup(); vi.clearAllMocks(); localStorage.clear(); sessionStorage.clear(); });

describe("qualified login", () => {
  it("returns a primary user to the originally requested console page", async () => {
    const repository = iam();
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={repository}><LoginRenderer returnTo="/console/resources/" /></SessionProvider></LocaleProvider>);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await waitFor(() => expect(navigation.replace).toHaveBeenCalledWith("/console/resources/", { scroll: false }));
  });

  it("uses one text identifier, clears secrets on mode change, and preserves IAM's account namespace", async () => {
    const repository = iam();
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={repository}><LoginRenderer /></SessionProvider></LocaleProvider>);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Previous-mode-secret-49!");
    await user.click(screen.getByRole("tab", { name: "IAM 子账号" }));
    expect((screen.getByLabelText("密码", { exact: true }) as HTMLInputElement).value).toBe("");
    const field = screen.getByLabelText("子账号登录名") as HTMLInputElement;
    expect(field.type).toBe("text");
    await user.type(field, "developer@tenant-a");
    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await waitFor(() => expect(repository.login).toHaveBeenCalledWith({ loginName: "developer@tenant-a", password: "Only-Test-Password-49!" }));
    expect(navigation.replace).toHaveBeenCalledWith("/console/", { scroll: false });
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("does not submit an unqualified child or leak prior authentication errors between modes", async () => {
    const repository = iam({ login: vi.fn().mockRejectedValue(new HttpProblem(401, "private upstream")) });
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={repository}><LoginRenderer /></SessionProvider></LocaleProvider>);
    await user.type(screen.getByLabelText("密码", { exact: true }), "Wrong-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    await screen.findByRole("alert");
    await user.click(screen.getByRole("tab", { name: "IAM 子账号" }));
    expect(screen.queryByRole("alert")).toBeNull();
    await user.type(screen.getByLabelText("子账号登录名"), "developer");
    await user.type(screen.getByLabelText("密码", { exact: true }), "Only-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "登录控制台" }));
    expect(screen.getByRole("alert").textContent).toContain("主账号ID或别名");
    expect(repository.login).toHaveBeenCalledTimes(1);
  });
});

describe("account access", () => {
  it("changes a live user boundary through selection, review and confirmation without changing grants", async () => {
    const f = boundaryFixture();
    const { user } = await openBoundary(f);
    expect(screen.queryByRole("dialog")).toBeNull();
    await chooseBoundary(user, "ReadOnlyAccess · system.paas-viewer");
    expect(f.boundaries.set).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText("权限边界变更已确认，用户状态已重新读取。");
    expect(f.boundaries.set).toHaveBeenLastCalledWith(credential, account.id, childUser.id, { policyId: tenantPolicy.id, policyResourceVersion: tenantPolicy.resourceVersion, resourceVersion: childUser.resourceVersion, requestId: expect.any(String) });
    await chooseBoundary(user, "LogBoundary · customer.logs");
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText("customer.logs", { exact: true });
    await chooseBoundary(user, "未设置租户权限边界");
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText("未设置租户权限边界");
    expect(f.boundaries.remove).toHaveBeenCalledWith(credential, account.id, childUser.id, { resourceVersion: childUser.resourceVersion + 2, requestId: expect.any(String) });
    expect(f.repository.execute).not.toHaveBeenCalled();
    expect(f.repository.currentIdentity).toHaveBeenCalledTimes(1);
  });

  it("owns keyboard focus while entering and leaving the inline boundary editor", async () => {
    const f = boundaryFixture();
    const { user } = await openBoundary(f);
    const edit = screen.getByRole("button", { name: "修改权限边界" });
    edit.focus();
    await user.keyboard("{Enter}");
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("combobox", { name: "权限边界" })));
    await user.click(screen.getByRole("combobox", { name: "权限边界" }));
    await user.click(screen.getByRole("option", { name: "ReadOnlyAccess · system.paas-viewer" }));
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "返回选择" }));
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("combobox", { name: "权限边界" })));
    const cancel = screen.getByRole("button", { name: "取消" });
    cancel.focus();
    await user.keyboard("{Enter}");
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: "修改权限边界" })));
    expect(f.boundaries.set).not.toHaveBeenCalled();
    expect(f.boundaries.remove).not.toHaveBeenCalled();
  });

  it("keeps the exact live boundary request and review after an uncertain outcome", async () => {
    const f = boundaryFixture();
    f.boundaries.set.mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const { user } = await openBoundary(f);
    await chooseBoundary(user, "LogBoundary · customer.logs");
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText(/请求结果尚未确认/);
    expect((screen.getByRole("button", { name: "返回选择" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("button", { name: "重试原请求" }));
    await screen.findByText("权限边界变更已确认，用户状态已重新读取。");
    expect(f.boundaries.set.mock.calls[0]).toEqual(f.boundaries.set.mock.calls[1]);
  });

  it("does not resubmit an acknowledged boundary change when the follow-up read fails", async () => {
    const f = boundaryFixture();
    const { user } = await openBoundary(f);
    await chooseBoundary(user, "LogBoundary · customer.logs");
    f.boundaries.read.mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"));
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText(/边界变更已确认，但暂无法重新读取/);
    expect(screen.getByText("customer.logs", { exact: true })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "重试读取" }));
    await screen.findByText("权限边界变更已确认，用户状态已重新读取。");
    expect(f.boundaries.set).toHaveBeenCalledTimes(1);
  });

  it("retains a stale boundary selection but requires fresh revisions and a new explicit review", async () => {
    const f = boundaryFixture();
    const { user } = await openBoundary(f);
    await chooseBoundary(user, "LogBoundary · customer.logs");
    f.advance();
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText(/用户或策略版本已变化/);
    await user.click(screen.getByRole("button", { name: "重新读取并审阅" }));
    const selection = await screen.findByRole("combobox", { name: "权限边界" });
    expect(selection.textContent).toContain("LogBoundary");
    expect(f.boundaries.set).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByText("权限边界变更已确认，用户状态已重新读取。");
    const first = f.boundaries.set.mock.calls[0]![3], second = f.boundaries.set.mock.calls[1]![3];
    expect(second.resourceVersion).toBe(first.resourceVersion + 1);
    expect(second.policyResourceVersion).toBe(first.policyResourceVersion + 1);
    expect(second.requestId).not.toBe(first.requestId);
  });

  it("expires sensitive live boundary state on 401 rather than leaving an editable private page", async () => {
    const f = boundaryFixture();
    f.boundaries.set.mockRejectedValueOnce(new HttpProblem(401, "IAM_EXPIRED"));
    const { user, view } = await openBoundary(f);
    await chooseBoundary(user, "LogBoundary · customer.logs");
    await user.click(screen.getByRole("button", { name: "确认变更" }));
    await screen.findByRole("button", { name: "登录控制台" });
    expect(screen.queryByRole("region", { name: "权限边界" })).toBeNull();
    expect(view.container.textContent).not.toContain(credential);
    expect(JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)])).not.toContain(credential);
    expect(JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)])).not.toContain("customer.logs");
  });

  it("does not offer boundary mutations when both authoritative capabilities are unavailable", async () => {
    const f = boundaryFixture(); f.readOnly();
    await openBoundary(f);
    expect(screen.queryByRole("button", { name: "修改权限边界" })).toBeNull();
    expect(screen.getByText(/当前身份没有此用户的边界变更权限/)).toBeTruthy();
    expect(f.boundaries.set).not.toHaveBeenCalled();
    expect(f.boundaries.remove).not.toHaveBeenCalled();
  });
  it("keeps owner identity separate from child targets and never infers identity type from policy names", () => {
    const namedAdministrator = { ...tenantPolicy, id: "customer.administrator", management: "CUSTOMER" as const, accountId: "tenant-a", displayName: "TenantAdministrator" };
    const adminAttachment = attachment("child-a", namedAdministrator);
    const adminChild: UserAccess = { ...child, policyAttachments: [adminAttachment], capabilities: userCapabilities(child.user, [adminAttachment]) };
    const tenantDirectory = { ...directory(false), items: [namedAdministrator, tenantPolicy].sort((left, right) => left.id.localeCompare(right.id)) };
    const scene = buildAccountAccessScene(identity, { items: [adminChild], nextAfter: null }, null, tenantDirectory, directory(true));
    expect(scene.accountOwner).toMatchObject({ id: "primary-a", accountType: "primary", name: "Account owner", state: "active" });
    expect(scene.users).toHaveLength(1);
    expect(scene.users[0]).toMatchObject({ id: "child-a", accountType: "subuser", attachments: [{ policyId: "customer.administrator" }] });
    const actingChild: AccountIdentity = { ...identity, user: child.user, identityKind: "USER", permissionBoundary: { accountId: account.id, userId: child.user.id, resourceVersion: child.user.resourceVersion, policy: null }, policySources: child.policyAttachments.map((attachment) => ({ kind: "DIRECT" as const, attachment })), capabilities: currentCapabilities(false) };
    const selfProtected: UserAccess = { ...child, capabilities: userCapabilities(child.user, child.policyAttachments, "SELF_PROTECTED") };
    const pageWithoutOwner = buildAccountAccessScene(actingChild, { items: [selfProtected], nextAfter: "later" }, null, directory(false), null);
    expect(pageWithoutOwner.accountOwner).toMatchObject({ id: "primary-a", loginName: "admin", name: null, state: null, isCurrent: false });
    expect(pageWithoutOwner.accountOwner.name).not.toBe(actingChild.user.displayName);
    expect(pageWithoutOwner.users[0]?.protected).toBe(true);
  });

  it("shows a read-only resource owner with separate identity, access and permission details", async () => {
    const { user, repository } = await openAccess();
    const owner = within(await screen.findByRole("region", { name: "账号所有者" }));
    expect(owner.getByText("主账号")).toBeTruthy();
    expect(owner.getByText("账号所有者")).toBeTruthy();
    expect(owner.getByText("账号管理与恢复权能")).toBeTruthy();
    expect(owner.queryByText("未授权")).toBeNull();
    expect(owner.queryByRole("button", { name: "管理 admin" })).toBeNull();
    await user.click(owner.getByRole("button", { name: "查看用户 admin" }));
    expect(await screen.findByRole("heading", { name: "admin" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "身份信息" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByText("primary-a")).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "权限策略" }));
    expect(screen.getByText(/具体业务资源操作取决于产品能力和当前安全条件/)).toBeTruthy();
    for (const name of ["禁用用户", "授予角色", "删除", "重置密码", "关联策略"]) expect(screen.queryByRole("button", { name })).toBeNull();
    await user.click(screen.getByRole("tab", { name: "访问方式" }));
    expect(screen.getByText(/当前页面不提供主账号密钥创建或密码重置/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Switch language" }));
    expect(screen.getByRole("tab", { name: "Access methods" }).getAttribute("aria-selected")).toBe("true");
    expect(repository.execute).not.toHaveBeenCalled();
  });

  it("filters subusers without hiding the separately projected account owner", async () => {
    const adminChild: UserAccess = child;
    const ungrantedUser: User = { ...child.user, id: "ungranted", loginName: "new.user" };
    const ungranted: UserAccess = { user: ungrantedUser, policyAttachments: [], capabilities: userCapabilities(ungrantedUser) };
    const { user } = await openAccess(accounts({ listUsers: vi.fn().mockResolvedValue({ items: [adminChild, ungranted], nextAfter: null }) }));
    const admin = within((await screen.findByRole("button", { name: "查看用户 developer" })).closest("tr")!);
    expect(admin.getByText("IAM 子用户")).toBeTruthy();
    expect(admin.getByText("ReadOnlyAccess")).toBeTruthy();
    expect(admin.queryByText("主账号")).toBeNull();
    const userTable = screen.getByRole("table", { name: "租户用户列表" });
    expect(userTable.getAttribute("data-mobile-layout")).toBe("stack");
    expect(admin.getByText("ReadOnlyAccess").closest("td")?.getAttribute("data-label")).toBe("策略关联");
    expect(admin.getByText("控制台访问").closest("td")?.getAttribute("data-label")).toBe("访问方式");
    await user.click(screen.getByRole("button", { name: "筛选" }));
    await user.click(screen.getByRole("combobox", { name: "筛选策略来源" }));
    await user.click(screen.getByRole("option", { name: "未关联授权策略" }));
    expect(screen.getByRole("button", { name: "查看用户 new.user" })).toBeTruthy();
    expect(within(screen.getByRole("region", { name: "账号所有者" })).getByRole("button", { name: "查看用户 admin" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "清除筛选" }));
    expect(within(screen.getByRole("table", { name: "租户用户列表" })).getAllByRole("row")).toHaveLength(3);
  });

  it("keeps navigation out of mutation renders and preserves unrelated exact capabilities", async () => {
    let finish!: () => void;
    const repository = accounts({ execute: vi.fn(() => new Promise<void>((resolve) => { finish = resolve; })) });
    const { user } = await openAccess(repository, iam(), "settings");
    await screen.findByRole("button", { name: "保存别名" });
    await user.type(screen.getByLabelText(/^主账号别名/), "acme");
    expect(screen.getByTestId("can-manage").textContent).toBe("true");
    capabilityCommit.mockClear();
    await user.click(screen.getByRole("button", { name: "保存别名" }));
    expect(screen.getByRole("button", { name: "正在保存…" })).toBeTruthy();
    expect(capabilityCommit).not.toHaveBeenCalled();
    vi.mocked(repository.listUsers).mockRejectedValue(new HttpProblem(403, "FORBIDDEN"));
    await act(async () => { finish(); });
    await waitFor(() => expect(screen.getByTestId("can-manage").textContent).toBe("false"));
    expect(screen.getByTestId("can-read-accounts").textContent).toBe("true");
    expect(capabilityCommit).toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "保存别名" })).toBeTruthy();
  });

  it("loads the real current-account MFA rule only in settings and keeps read denial local", async () => {
    const read = vi.fn().mockRejectedValue(new HttpProblem(403, "IAM_AUTHORIZATION_DENIED"));
    const repository = accounts({ accountSecuritySettings: { read } });
    const { user } = await openAccess(repository, iam(), "users");
    await screen.findByRole("table", { name: "租户用户列表" });
    expect(read).not.toHaveBeenCalled();
    await user.click(screen.getByTestId("nav-settings"));
    expect(await screen.findByText(/没有查看账号安全规则的权限/)).toBeTruthy();
    expect(read).toHaveBeenCalledWith(credential, account.id);
    expect(screen.getByTestId("nav-settings").getAttribute("aria-current")).toBe("page");
    expect(screen.queryByText("用户可选")).toBeNull();
  });

  it("expires the credential on a real account-rule 401 instead of treating it as read denial", async () => {
    const read = vi.fn().mockRejectedValue(new HttpProblem(401, "IAM_SESSION_EXPIRED"));
    await openAccess(accounts({ accountSecuritySettings: { read } }), iam(), "settings");
    expect(await screen.findByRole("button", { name: "登录控制台" })).toBeTruthy();
    expect(screen.queryByText(/没有查看账号安全规则的权限/)).toBeNull();
  });

  it("switches a settings draft and an existing safe error without reloading IAM", async () => {
    const repository = accounts({ execute: vi.fn().mockRejectedValue(new HttpProblem(409, "PRIVATE UPSTREAM DETAIL")) });
    const { user } = await openAccess(repository);
    await screen.findByText("Developer A");
    await user.click(screen.getByTestId("nav-settings"));
    await user.type(screen.getByLabelText("主账号别名", { exact: true }), "team-new");
    await user.click(screen.getByRole("button", { name: "Switch language" }));
    expect(screen.getByTestId("nav-settings").getAttribute("aria-current")).toBe("page");
    expect((screen.getByLabelText("Primary account alias", { exact: true }) as HTMLInputElement).value).toBe("team-new");
    await user.click(screen.getByRole("button", { name: "Save alias" }));
    expect((await screen.findByRole("alert")).textContent).toContain("The name is taken or reserved");
    await user.click(screen.getByRole("button", { name: "Switch language" }));
    expect(screen.getByRole("alert").textContent).toContain("名称已被占用或保留");
    expect(screen.getByRole("alert").textContent).not.toContain("PRIVATE UPSTREAM");
    expect((screen.getByLabelText("主账号别名", { exact: true }) as HTMLInputElement).value).toBe("team-new");
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
  });

  it("localizes content-area user management and focuses the new destination", async () => {
    const { user } = await openAccess();
    await screen.findByText("Developer A");
    await user.click(screen.getByRole("button", { name: "Switch language" }));
    const trigger = screen.getByRole("button", { name: "View user developer" });
    await user.click(trigger);
    const heading = await screen.findByRole("heading", { name: "developer" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(heading);
    const region = screen.getByRole("region", { name: "Identity and access" });
    expect(region.textContent).not.toMatch(/\p{Script=Han}/u);
    expect(within(region).getByRole("button", { name: "Revoke policy ReadOnlyAccess" })).toBeTruthy();
    expect((within(region).getByRole("button", { name: "Attach policy" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(within(region).getByRole("button", { name: "Reset password" }));
    expect(document.activeElement).toBe(within(region).getByLabelText("Initial password"));
    expect(region.textContent).not.toMatch(/\p{Script=Han}/u);
    await user.click(screen.getByRole("button", { name: "Back to list" }));
    expect(await screen.findByRole("table", { name: "Tenant users" })).toBeTruthy();
    await user.click(screen.getByTestId("nav-roles"));
    expect(screen.getByText("This capability is not connected")).toBeTruthy();
    await user.click(screen.getByTestId("nav-policies"));
    expect(screen.getByRole("table", { name: "Policy metadata directory" })).toBeTruthy();
    await user.click(screen.getByTestId("nav-tenants"));
    expect(screen.getByRole("table", { name: "Tenant accounts" })).toBeTruthy();
  });

  it("opens account lifecycle management from the object name without adding an operation column", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository, iam(), "tenants");
    const table = await screen.findByRole("table", { name: "租户账号列表" });
    expect(within(table).queryByRole("columnheader", { name: "操作" })).toBeNull();
    await user.click(within(table).getByRole("button", { name: "Team A" }));
    expect(screen.getByRole("heading", { name: "Team A" })).toBeTruthy();
    expect(screen.queryByRole("table", { name: "租户账号列表" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "停用账户" }));
    await user.click(screen.getByRole("button", { name: "确认停用账户" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, {
      kind: "set-account-status",
      accountId: "tenant-a",
      status: "DISABLED",
      resourceVersion: 1
    }));
  });

  it("starts on a dedicated overview and opens the user workspace without an extra fetch", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository, iam(), "overview");
    await screen.findByText("Account owner");
    expect(screen.getByText("所属账号 · 资源归属")).toBeTruthy();
    expect(screen.queryByRole("table", { name: "子用户列表" })).toBeNull();
    await user.click(screen.getByTestId("nav-users"));
    await screen.findByText("Developer A");
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
  });

  it("pages each live directory without reloading identity or unrelated IAM collections", async () => {
    const userCursor = "ic1.dXNlcnM";
    const accountCursor = "ic1.YWNjb3VudHM";
    const nextUser: UserAccess = {
      user: { ...childUser, id: "child-b", loginName: "auditor", displayName: "Auditor B" },
      policyAttachments: [],
      capabilities: userCapabilities({ ...childUser, id: "child-b", loginName: "auditor", displayName: "Auditor B" })
    };
    const nextAccount: Account = {
      ...account,
      id: "tenant-b",
      displayName: "Team B",
      rootIdentity: { principalId: "primary-b", loginName: "owner-b" }
    };
    const listUsers = vi.fn(async (_credential: string, after?: string) => after
      ? { items: [nextUser], nextAfter: null }
      : { items: [child], nextAfter: userCursor });
    const listAccounts = vi.fn(async (_credential: string, after?: string) => after
      ? { items: [accountAccess(nextAccount)], nextAfter: null }
      : { items: [accountAccess(account)], nextAfter: accountCursor });
    const listPolicies = vi.fn(async (_credential: string, platform: boolean) => directory(platform));
    const repository = accounts({ listUsers, listAccounts, listPolicies });
    const { user } = await openAccess(repository);

    await screen.findByText("Developer A");
    await user.click(screen.getByRole("button", { name: "下一页" }));
    expect(await screen.findByText("Auditor B")).toBeTruthy();
    expect(listUsers).toHaveBeenNthCalledWith(2, credential, userCursor);
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
    expect(listPolicies).toHaveBeenCalledTimes(2);
    expect(listAccounts).toHaveBeenCalledTimes(1);

    await user.click(screen.getByTestId("nav-tenants"));
    await user.click(screen.getByRole("button", { name: "下一页" }));
    expect(await screen.findByRole("button", { name: "Team B" })).toBeTruthy();
    expect(listAccounts).toHaveBeenNthCalledWith(2, credential, accountCursor);
    expect(repository.currentIdentity).toHaveBeenCalledTimes(1);
    expect(listUsers).toHaveBeenCalledTimes(2);
    expect(listPolicies).toHaveBeenCalledTimes(2);
  });

  it("replaces the directory immediately with a local skeleton before loading live user details", async () => {
    let resolveUser!: (value: UserAccess) => void;
    const getUser = vi.fn(() => new Promise<UserAccess>((resolve) => { resolveUser = resolve; }));
    const repository = accounts({ getUser });
    const { user } = await openAccess(repository);
    await screen.findByText("Developer A");
    await user.click(screen.getByRole("button", { name: "查看用户 developer" }));
    expect(screen.queryByRole("table", { name: "租户用户列表" })).toBeNull();
    expect(screen.getByText("正在读取用户详情…")).toBeTruthy();
    expect(screen.queryByText("用户资料")).toBeNull();
    await act(async () => { resolveUser(structuredClone(child)); });
    expect(await screen.findByText("用户资料")).toBeTruthy();
    expect(getUser).toHaveBeenCalledWith(credential, "child-a");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByText(/不根据用户状态推断访问方式/)).toBeTruthy();
  });

  it("updates only the display name through the live user revision", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(await screen.findByRole("button", { name: "修改显示名称" }));
    const field = screen.getByLabelText("用户显示名称");
    await user.clear(field);
    await user.type(field, "Developer Renamed");
    await user.click(screen.getByRole("button", { name: "保存显示名称" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "update-user", userId: "child-a", displayName: "Developer Renamed", resourceVersion: 2 }));
  });

  it("requires disablement and typed confirmation before irreversible live deletion", async () => {
    const disabledUser: User = { ...childUser, status: "DISABLED", resourceVersion: 5 };
    const disabledAttachment = attachment(disabledUser.id, tenantPolicy);
    const disabled: UserAccess = { user: disabledUser, policyAttachments: [disabledAttachment], capabilities: userCapabilities(disabledUser, [disabledAttachment]) };
    const repository = accounts({
      listUsers: vi.fn().mockResolvedValue({ items: [disabled], nextAfter: null }),
      getUser: vi.fn().mockResolvedValue(structuredClone(disabled))
    });
    const { user } = await openAccess(repository);
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    const deleteButton = await screen.findByRole("button", { name: "删除用户" });
    expect((deleteButton as HTMLButtonElement).disabled).toBe(false);
    await user.click(deleteButton);
    expect(repository.execute).not.toHaveBeenCalled();
    const confirmation = screen.getByLabelText("输入 developer 确认删除");
    await user.type(confirmation, "developer");
    await user.click(screen.getByRole("button", { name: "永久删除用户" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "delete-user", userId: "child-a", resourceVersion: 5 }));
    expect(await screen.findByRole("table", { name: "租户用户列表" })).toBeTruthy();
  });

  it("separates the resource owner from subusers and defaults creation to no business grant", async () => {
    const { user, repository, view } = await openAccess();
    await screen.findByText("Developer A");
    expect(screen.queryByRole("button", { name: "管理 admin" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "创建用户" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("form", { name: "创建子用户" })).toBeTruthy();
    await user.type(screen.getByLabelText(/^子用户名/), "new.developer");
    await user.type(screen.getByLabelText("用户显示名称"), "New Developer");
    await user.type(screen.getByLabelText(/^初始密码/), "New-Child-Test-Password-49!");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByText("新用户将按默认拒绝创建，不在创建请求中捆绑权限。")).toBeTruthy();
    expect(screen.queryByRole("combobox", { name: /^初始权限/ })).toBeNull();
    expect(repository.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.queryByDisplayValue("New-Child-Test-Password-49!")).toBeNull();
    await user.click(screen.getByRole("button", { name: "确认创建用户" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "create-user", loginName: "new.developer", displayName: "New Developer", initialPassword: "New-Child-Test-Password-49!" }));
    expect(view.container.textContent).not.toContain(credential);
    expect(view.container.innerHTML).not.toContain("New-Child-Test-Password-49!");
  });

  it("sets an independent account alias with an optimistic version and shows both login forms", async () => {
    const repository = accounts();
    const { user } = await openAccess(repository);
    await screen.findByText("Developer A");
    await user.click(screen.getByTestId("nav-settings"));
    await user.type(screen.getByLabelText(/^主账号别名/), "acme");
    await user.click(screen.getByRole("button", { name: "保存别名" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "set-alias", alias: "acme", resourceVersion: 1 }));
    expect(screen.getByText("username@tenant-a")).toBeTruthy();
    expect(screen.getByText("admin", { exact: true })).toBeTruthy();
  });

  it("keeps the personal-security shell stable while only live security cards load", async () => {
    let finishContact!: (value: NotificationContact) => void;
    let finishFactor!: (value: AuthenticatorState) => void;
    const security = {
      notificationContact: vi.fn(() => new Promise<NotificationContact>((resolve) => { finishContact = resolve; })),
      authenticatorState: vi.fn(() => new Promise<AuthenticatorState>((resolve) => { finishFactor = resolve; })),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    expect(within(securityRegion).getByRole("heading", { name: "安全通知地址" })).toBeTruthy();
    expect(within(securityRegion).getByRole("heading", { name: "身份验证器应用" })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    await act(async () => {
      finishContact({ accountId: account.id, userId: rootUser.id, state: "NONE", resourceVersion: 0, pendingVerificationId: null });
      finishFactor({ enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null });
    });
    expect(await within(securityRegion).findByText("未设置")).toBeTruthy();
  });

  it("verifies the first notification address inline before enabling first authenticator enrollment", async () => {
    const none = { accountId: account.id, userId: rootUser.id, state: "NONE" as const, resourceVersion: 0 as const, pendingVerificationId: null };
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    const verification = { id: "verification-one", accountId: account.id, userId: rootUser.id, requestId: "request-one", email: "admin@example.com", state: "PENDING" as const, issuedAt: timestamp, expiresAt: "2026-09-11T08:10:00Z", completedAt: null, delivery: { state: "ACCEPTED" as const, attempts: 1, lastOutcome: "ACCEPTED" as const, lastSmtpCode: 250, updatedAt: timestamp } };
    const security = {
      notificationContact: vi.fn().mockResolvedValueOnce(none).mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn().mockResolvedValue(verification),
      notificationVerification: vi.fn(),
      confirmNotificationVerification: vi.fn().mockResolvedValue({ ...verification, state: "VERIFIED", completedAt: "2026-09-11T08:02:00Z" }),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByText("未设置");
    await user.type(screen.getByLabelText("邮箱地址"), "admin@example.com");
    await user.type(screen.getAllByLabelText("当前密码")[0]!, "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "发送验证码" }));
    expect(await screen.findByText(/邮件服务器已接受/)).toBeTruthy();
    expect(screen.getByText(/不代表收件人已收到或阅读/)).toBeTruthy();
    await user.type(screen.getByLabelText("8 位邮箱验证码"), "12345678");
    await user.click(screen.getByRole("button", { name: "验证通知地址" }));
    expect(await screen.findByText("admin@example.com")).toBeTruthy();
    expect(screen.getByRole("button", { name: /开始绑定/ })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(security.startNotificationVerification).toHaveBeenCalledWith(credential, expect.objectContaining({ email: "admin@example.com", password: "Private-Password-49!" }));
    expect(security.confirmNotificationVerification).toHaveBeenCalledWith(credential, "verification-one", expect.objectContaining({ code: "12345678" }));
  });

  it("never renders TOTP provisioning or confirmation controls for an equal replay", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    const enrollment = { id: "enrollment-one", requestId: "request-one", factorRevision: 1, state: "PENDING" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:05:00Z", completedAt: null };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND" as const, factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn().mockResolvedValue({ outcome: "EQUAL_REPLAY" as const, enrollment }),
      totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn().mockResolvedValue({ ...enrollment, state: "CANCELLED", completedAt: "2026-09-11T08:01:00Z" }), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    const securityRegion = (await screen.findByRole("heading", { name: "安全通知与身份验证器" })).closest("section")!;
    await within(securityRegion).findByText("admin@example.com");
    await user.type(screen.getByLabelText("当前密码"), "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "开始绑定" }));
    expect(await screen.findByText(/等值重放/)).toBeTruthy();
    expect(screen.queryByLabelText("6 位动态验证码")).toBeNull();
    expect(screen.queryByText(/手动密钥/)).toBeNull();
    expect(screen.getByRole("button", { name: "取消绑定" })).toBeTruthy();
    expect(security.confirmTOTPEnrollment).not.toHaveBeenCalled();
  });

  it("keeps an unknown first-enrollment request across content remounts and resolves only that intent", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    let originalRequestId = "";
    const enrollment = { id: "enrollment-unknown", requestId: "", factorRevision: 1, state: "PENDING" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:05:00Z", completedAt: null };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND" as const, factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn().mockImplementation(async (_credential: string, command: { requestId: string }) => {
        originalRequestId = command.requestId;
        enrollment.requestId = command.requestId;
        throw new Error("connection lost after submit");
      }),
      totpEnrollment: vi.fn(),
      totpEnrollmentByRequest: vi.fn().mockImplementation(async (_credential: string, requestId: string) => ({ ...enrollment, requestId })),
      cancelTOTPEnrollment: vi.fn().mockImplementation(async (_credential: string, enrollmentId: string) => ({ ...enrollment, id: enrollmentId, state: "CANCELLED" as const, completedAt: "2026-09-11T08:02:00Z" })),
      confirmTOTPEnrollment: vi.fn()
    };
    const { user, view } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    await screen.findByText("admin@example.com");
    await user.type(screen.getByLabelText("当前密码"), "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "开始绑定" }));

    expect(await screen.findByText(/上一次绑定请求的结果尚未确认/)).toBeTruthy();
    expect(screen.getByText(originalRequestId)).toBeTruthy();
    expect(screen.queryByLabelText("当前密码")).toBeNull();
    expect(view.container.innerHTML).not.toContain("Private-Password-49!");

    await user.click(screen.getByTestId("nav-users"));
    await screen.findByRole("table", { name: "租户用户列表" });
    await user.click(screen.getByTestId("nav-settings"));
    expect(await screen.findByText(originalRequestId)).toBeTruthy();
    expect(screen.queryByLabelText("当前密码")).toBeNull();

    await user.click(screen.getByRole("button", { name: "查询原绑定意图" }));
    expect(await screen.findByText(/等值重放/)).toBeTruthy();
    expect(security.totpEnrollmentByRequest).toHaveBeenCalledWith(credential, originalRequestId);
    expect(screen.queryByLabelText("6 位动态验证码")).toBeNull();
    expect(screen.queryByText(/手动设置密钥/)).toBeNull();

    await user.click(screen.getByRole("button", { name: "取消绑定" }));
    await waitFor(() => expect(security.cancelTOTPEnrollment).toHaveBeenCalledWith(credential, "enrollment-unknown"));
    expect(await screen.findByRole("button", { name: "开始绑定" })).toBeTruthy();
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("does not treat a missing by-request lookup as proof that an unknown enrollment never committed", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "NEVER_BOUND" as const, factorRevision: 1, factorId: null }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn().mockRejectedValue(new Error("connection lost after submit")),
      totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn().mockRejectedValue(new HttpProblem(404, "IAM_NOT_FOUND")), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn()
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    await screen.findByText("admin@example.com");
    await user.type(screen.getByLabelText("当前密码"), "Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "开始绑定" }));
    await user.click(await screen.findByRole("button", { name: "查询原绑定意图" }));

    expect(await screen.findByText(/不能证明请求从未提交/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "开始绑定" })).toBeNull();
    expect(screen.getByRole("button", { name: "查询原绑定意图" })).toBeTruthy();
  });

  it("regenerates recovery codes through a purpose-limited live step-up and clears one-time material", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    let operationRequestId = "";
    const recoveryCodes = Array.from({ length: 10 }, (_, index) => `ROTATED-RECOVERY-${index}`);
    const recovery = {
      startStepUp: vi.fn().mockImplementation(async (_credential: string, command: { requestId: string; expectedFactorRevision: number }) => {
        operationRequestId = command.requestId;
        return { id: "step-up-one", requestId: command.requestId, operation: "RECOVERY_CODES_REGENERATE" as const, expectedFactorRevision: 2, state: "PENDING" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: null, consumedAt: null };
      }),
      stepUpByRequest: vi.fn(),
      verifyStepUp: vi.fn().mockImplementation(async () => ({ id: "step-up-one", requestId: operationRequestId, operation: "RECOVERY_CODES_REGENERATE" as const, expectedFactorRevision: 2, state: "PROVED" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: "2026-09-11T08:00:30Z", consumedAt: null })),
      regenerate: vi.fn().mockImplementation(async () => ({ outcome: "APPLIED" as const, regeneration: { id: "regeneration-one", requestId: operationRequestId, factorId: "factor-one", factorRevision: 2, createdAt: "2026-09-11T08:00:40Z" }, recoveryCodes })),
      regenerationByRequest: vi.fn()
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 2, factorId: "factor-one" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn(),
      recoveryCodes: recovery
    };
    const { user, view } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    await screen.findByText("admin@example.com");
    await user.click(screen.getByRole("button", { name: "重新生成恢复码" }));
    await user.type(screen.getByLabelText("当前密码"), "Private-Password-49!");
    await user.type(screen.getByLabelText("6 位动态验证码"), "123456");
    await user.click(screen.getByRole("button", { name: "验证本次操作" }));
    expect(await screen.findByRole("button", { name: "生成新的 10 条恢复码" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "生成新的 10 条恢复码" }));
    const list = await screen.findByRole("list", { name: "新恢复码" });
    expect(within(list).getByText("ROTATED-RECOVERY-9")).toBeTruthy();
    expect(screen.queryByLabelText("当前密码")).toBeNull();
    expect(screen.queryByLabelText("6 位动态验证码")).toBeNull();
    expect(view.container.innerHTML).not.toContain("Private-Password-49!");
    expect(view.container.innerHTML).not.toContain(credential);
    expect(recovery.startStepUp).toHaveBeenCalledWith(credential, { requestId: operationRequestId, expectedFactorRevision: 2 });
    expect(recovery.regenerate).toHaveBeenCalledWith(credential, { requestId: operationRequestId, stepUpId: "step-up-one", expectedFactorRevision: 2 });
    await user.click(screen.getByRole("checkbox", { name: "我已安全保存全部新恢复码" }));
    await user.click(screen.getByRole("button", { name: "完成并清除页面材料" }));
    expect(screen.queryByText("ROTATED-RECOVERY-9")).toBeNull();
    expect(screen.getByRole("button", { name: "重新生成恢复码" })).toBeTruthy();
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });

  it("retries an unknown step-up creation only with the frozen request", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    const requestIds: string[] = [];
    const recovery = {
      startStepUp: vi.fn().mockImplementation(async (_credential: string, command: { requestId: string }) => {
        requestIds.push(command.requestId);
        if (requestIds.length === 1) throw new Error("connection lost after step-up creation");
        return { id: "step-up-retried", requestId: command.requestId, operation: "RECOVERY_CODES_REGENERATE" as const, expectedFactorRevision: 2, state: "PENDING" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: null, consumedAt: null };
      }),
      stepUpByRequest: vi.fn(), verifyStepUp: vi.fn(), regenerate: vi.fn(), regenerationByRequest: vi.fn()
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 2, factorId: "factor-one" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn(),
      recoveryCodes: recovery
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    await screen.findByText("admin@example.com");
    await user.click(screen.getByRole("button", { name: "重新生成恢复码" }));
    expect(await screen.findByText("用途限定验证的创建结果未知。不要创建第二个意图；请查询原 requestId，或用完全相同的请求重试。")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "重新生成恢复码" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "按原请求重试" }));
    expect(await screen.findByLabelText("当前密码")).toBeTruthy();
    expect(requestIds).toHaveLength(2);
    expect(requestIds[1]).toBe(requestIds[0]);
  });

  it("does not interpret a rejected step-up password or OTP as proof that the login bearer expired", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    let operationRequestId = "";
    const recovery = {
      startStepUp: vi.fn().mockImplementation(async (_credential: string, command: { requestId: string }) => {
        operationRequestId = command.requestId;
        return { id: "step-up-rejected", requestId: command.requestId, operation: "RECOVERY_CODES_REGENERATE" as const, expectedFactorRevision: 2, state: "PENDING" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: null, consumedAt: null };
      }),
      stepUpByRequest: vi.fn(),
      verifyStepUp: vi.fn().mockRejectedValue(new HttpProblem(401, "iam.authentication.failed")),
      regenerate: vi.fn(), regenerationByRequest: vi.fn()
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 2, factorId: "factor-one" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn(), recoveryCodes: recovery
    };
    const { user } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    await screen.findByText("admin@example.com");
    await user.click(screen.getByRole("button", { name: "重新生成恢复码" }));
    await user.type(screen.getByLabelText("当前密码"), "Wrong-Password-49!");
    await user.type(screen.getByLabelText("6 位动态验证码"), "123456");
    await user.click(screen.getByRole("button", { name: "验证本次操作" }));
    expect(await screen.findByText(/密码或动态验证码未通过/)).toBeTruthy();
    expect(screen.getByRole("heading", { name: "安全通知与身份验证器" })).toBeTruthy();
    expect(screen.getByTestId("nav-settings").getAttribute("aria-current")).toBe("page");
    expect(screen.queryByRole("button", { name: "登录控制台" })).toBeNull();
    expect(screen.getByText(operationRequestId)).toBeTruthy();
  });

  it("never replays proof secrets or a regeneration after an unknown outcome", async () => {
    const verified = { accountId: account.id, userId: rootUser.id, state: "VERIFIED" as const, resourceVersion: 1, email: "admin@example.com", verifiedAt: timestamp, pendingVerificationId: null };
    let operationRequestId = "";
    const pending = () => ({ id: "step-up-unknown", requestId: operationRequestId, operation: "RECOVERY_CODES_REGENERATE" as const, expectedFactorRevision: 2, state: "PENDING" as const, createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z", provedAt: null, consumedAt: null });
    const proved = () => ({ ...pending(), state: "PROVED" as const, provedAt: "2026-09-11T08:00:30Z" });
    const recovery = {
      startStepUp: vi.fn().mockImplementation(async (_credential: string, command: { requestId: string }) => { operationRequestId = command.requestId; return pending(); }),
      stepUpByRequest: vi.fn().mockImplementation(async () => proved()),
      verifyStepUp: vi.fn().mockRejectedValue(new Error("connection lost after proof submission")),
      regenerate: vi.fn().mockRejectedValue(new Error("connection lost after regeneration submission")),
      regenerationByRequest: vi.fn().mockImplementation(async () => ({ id: "regeneration-unknown", requestId: operationRequestId, factorId: "factor-one", factorRevision: 2, createdAt: "2026-09-11T08:00:40Z" }))
    };
    const security = {
      notificationContact: vi.fn().mockResolvedValue(verified),
      authenticatorState: vi.fn().mockResolvedValue({ enrollmentState: "BOUND" as const, factorRevision: 2, factorId: "factor-one" }),
      startNotificationVerification: vi.fn(), notificationVerification: vi.fn(), confirmNotificationVerification: vi.fn(),
      startTOTPEnrollment: vi.fn(), totpEnrollment: vi.fn(), totpEnrollmentByRequest: vi.fn(), cancelTOTPEnrollment: vi.fn(), confirmTOTPEnrollment: vi.fn(),
      recoveryCodes: recovery
    };
    const { user, view } = await openAccess(accounts(), iam({ personalSecurity: security }), "settings");
    await screen.findByText("admin@example.com");
    await user.click(screen.getByRole("button", { name: "重新生成恢复码" }));
    await user.type(screen.getByLabelText("当前密码"), "Private-Password-49!");
    await user.type(screen.getByLabelText("6 位动态验证码"), "123456");
    await user.click(screen.getByRole("button", { name: "验证本次操作" }));
    expect(await screen.findByText(/结果未知时只能读取原安全验证状态/)).toBeTruthy();
    expect(screen.queryByLabelText("当前密码")).toBeNull();
    expect(screen.queryByLabelText("6 位动态验证码")).toBeNull();
    expect(view.container.innerHTML).not.toContain("Private-Password-49!");
    await user.click(screen.getByRole("button", { name: "查询原安全验证" }));
    expect(await screen.findByRole("button", { name: "生成新的 10 条恢复码" })).toBeTruthy();
    expect(recovery.verifyStepUp).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "生成新的 10 条恢复码" }));
    expect(await screen.findByText("重新生成结果未知。不要再次提交或创建第二个意图；请只查询原 requestId。")).toBeTruthy();
    await user.click(screen.getByTestId("nav-users"));
    await screen.findByRole("table", { name: "租户用户列表" });
    await user.click(screen.getByTestId("nav-settings"));
    expect(await screen.findByText(operationRequestId)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "查询原重新生成结果" }));
    expect(await screen.findByText(/一次性恢复码材料已不在当前页面/)).toBeTruthy();
    expect(screen.queryByRole("list", { name: "新恢复码" })).toBeNull();
    expect(recovery.regenerate).toHaveBeenCalledTimes(1);
    expect(recovery.regenerationByRequest).toHaveBeenCalledWith(credential, operationRequestId);
  });

  it("allows an unprivileged user to inspect its own settings without querying admin directories", async () => {
    const reader: AccountIdentity = { ...identity, user: child.user, identityKind: "USER", permissionBoundary: { accountId: account.id, userId: child.user.id, resourceVersion: child.user.resourceVersion, policy: null }, policySources: [], capabilities: currentCapabilities(false) };
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(reader), listUsers: vi.fn().mockRejectedValue(new HttpProblem(403, "FORBIDDEN")) });
    await openAccess(repository, iam({}, "child-a"), "overview");
    await screen.findByText("未授权");
    expect(repository.listUsers).not.toHaveBeenCalled();
    expect(repository.listAccounts).not.toHaveBeenCalled();
    expect(screen.queryByRole("tab", { name: "租户管理" })).toBeNull();
    expect(screen.queryByRole("button", { name: "保存别名" })).toBeNull();
    expect(screen.getByText("username@tenant-a")).toBeTruthy();
  });

  it("keeps the tenant policy directory usable when only the platform directory is forbidden", async () => {
    const listPolicies = vi.fn(async (_credential: string, platform: boolean) => {
      if (platform) throw new HttpProblem(403, "FORBIDDEN");
      return directory(false);
    });
    const repository = accounts({ listPolicies });
    await openAccess(repository, iam(), "policies");
    const table = await screen.findByRole("table", { name: "策略元数据目录" });
    expect(table.getAttribute("data-mobile-layout")).toBe("stack");
    const policyRow = within(table).getByRole("button", { name: "ReadOnlyAccess" }).closest("tr")!;
    expect(policyRow.cells[0]?.getAttribute("data-label")).toBe("策略");
    expect(policyRow.cells[5]?.getAttribute("data-label")).toBe("更新时间");
    expect(screen.getByText("ReadOnlyAccess")).toBeTruthy();
    expect(screen.getByText(/租户策略仍可查看/)).toBeTruthy();
    expect(listPolicies).toHaveBeenCalledTimes(2);
  });

  it("reads a tenant policy's default document only after opening its detail and keeps platform metadata separate", async () => {
    const readPolicy = vi.fn().mockResolvedValue(tenantPolicyDetail);
    const { user } = await openAccess(accounts({ readPolicy }), iam(), "policies");
    await screen.findByRole("table", { name: "策略元数据目录" });
    expect(readPolicy).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: tenantPolicy.displayName }));
    expect(await screen.findByRole("table", { name: "策略声明" })).toBeTruthy();
    expect(readPolicy).toHaveBeenCalledWith(credential, account.id, tenantPolicy.id);
    expect(screen.getByText("paas.application.read")).toBeTruthy();
    expect(screen.getByText(/不代表当前身份或任何主体的有效权限/)).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByRole("button", { name: "保存" })).toBeNull();

    await user.click(screen.getByRole("button", { name: "返回列表" }));
    await user.click(screen.getByRole("button", { name: platformPolicy.displayName }));
    expect(screen.getByText(/平台安装策略当前只提供目录元数据/)).toBeTruthy();
    expect(readPolicy).toHaveBeenCalledTimes(1);
  });

  it("separates authored family syntax from the frozen v2 action expansion", async () => {
    const readPolicy = vi.fn().mockResolvedValue({ ...tenantPolicyDetail, version: {
      ...tenantPolicyDetail.version, contractVersion: 2,
      document: { ...tenantPolicyDetail.version.document, statements: [{ ...tenantPolicyDetail.version.document.statements[0],
        actions: ["paas.application.*"] }] },
      compilation: { compilationVersion: "1", profiles: [{ product: "paas", revision: 2,
        contentDigest: `sha256:${"b".repeat(64)}` }], resolvedStatements: [{ sid: "read-applications", actions: ["paas.application.read"] }] }
    } });
    const { user } = await openAccess(accounts({ readPolicy }), iam(), "policies");
    await user.click(await screen.findByRole("button", { name: tenantPolicy.displayName }));
    const table = await screen.findByRole("table", { name: "策略声明" });
    expect(within(table).getByText("paas.application.*")).toBeTruthy();
    expect(within(table).getByText("发布时冻结的 Action")).toBeTruthy();
    expect(within(table).getByText("paas.application.read")).toBeTruthy();
    expect(screen.getByText("paas @ 2")).toBeTruthy();
  });

  it("loads customer versions only when selected and inspects a non-default version inline", async () => {
    const customer = { ...tenantPolicy, id: "customer.logs", management: "CUSTOMER" as const, accountId: account.id,
      displayName: "LogBoundary", defaultVersionId: "version-logs" };
    const current = { ...tenantPolicyDetail.version, policyId: customer.id, versionId: customer.defaultVersionId };
    const earlier = { ...current, versionId: "version-a", contentDigest: `sha256:${"b".repeat(64)}` };
    const readPolicy = vi.fn().mockResolvedValue({ policy: customer, version: current });
    const listPolicyVersions = vi.fn().mockResolvedValue({ policy: customer, items: [earlier, current] });
    const readPolicyVersion = vi.fn().mockResolvedValue({ policy: customer, version: earlier });
    const repository = accounts({ readPolicy, listPolicyVersions, readPolicyVersion,
      listPolicies: vi.fn(async (_credential: string, platform: boolean) => platform ? directory(true) : { ...directory(false), items: [customer, tenantPolicy] }) });
    const { user } = await openAccess(repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: customer.displayName }));
    expect(await screen.findByRole("tab", { name: "策略版本" })).toBeTruthy();
    expect(listPolicyVersions).not.toHaveBeenCalled();
    expect(readPolicyVersion).not.toHaveBeenCalled();

    await user.click(screen.getByRole("tab", { name: "策略版本" }));
    const table = await screen.findByRole("table", { name: "策略版本目录" });
    expect(within(table).getByText("当前默认")).toBeTruthy();
    expect(screen.getByText("当前可管理版本：2 / 5")).toBeTruthy();
    expect(listPolicyVersions).toHaveBeenCalledWith(credential, account.id, customer.id);
    expect(readPolicyVersion).not.toHaveBeenCalled();

    await user.click(within(table).getByRole("button", { name: "version-a" }));
    expect(await screen.findByRole("heading", { name: "查看版本 version-a" })).toBe(document.activeElement);
    expect(await screen.findByRole("table", { name: "策略声明" })).toBeTruthy();
    expect(readPolicyVersion).toHaveBeenCalledWith(credential, account.id, customer.id, "version-a");
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "返回版本目录" }));
    expect(within(screen.getByRole("table", { name: "策略版本目录" })).getByRole("button", { name: "version-a" })).toBe(document.activeElement);
  });

  it("reviews a live default switch and retirement inline against the exact resource revision", async () => {
    const fixture = livePolicyVersions();
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "版本 version-a 的操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "切换默认版本" }));
    expect(screen.getByRole("heading", { name: "将 version-a 设为默认版本" })).toBe(document.activeElement);
    expect(screen.getByText(/包括用户、组及角色/)).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "确认切换" }));
    await waitFor(() => expect(fixture.setDefaultPolicyVersion).toHaveBeenCalledTimes(1));
    expect(fixture.setDefaultPolicyVersion.mock.calls[0]).toEqual([credential, account.id, "customer.logs", {
      versionId: "version-a", resourceVersion: 4, requestId: expect.stringMatching(/^ui-policy-version-/)
    }]);
    await waitFor(() => expect(within(screen.getByRole("table", { name: "策略版本目录" })).getByText("当前默认")).toBeTruthy());
    await user.click(screen.getByRole("button", { name: "版本 version-logs 的操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "退休版本" }));
    expect(screen.getByText(/历史记录仍保留/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认退休" }));
    await waitFor(() => expect(fixture.retirePolicyVersion).toHaveBeenCalledTimes(1));
    expect(fixture.retirePolicyVersion.mock.calls[0]).toEqual([credential, account.id, "customer.logs", "version-logs", {
      resourceVersion: 5, expectedDefaultVersionId: "version-a", requestId: expect.stringMatching(/^ui-policy-version-/)
    }]);
    expect(await screen.findByText("当前可管理版本：1 / 5")).toBeTruthy();
  });

  it("reviews and publishes a live policy version without switching the default or leaving the content area", async () => {
    const fixture = livePolicyVersions();
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    expect(screen.getByRole("heading", { name: "编写新版本" })).toBe(document.activeElement);
    expect(screen.queryByRole("dialog")).toBeNull();
    const proposed = structuredClone(tenantPolicyDetail.version.document);
    proposed.statements[0]!.actions = ["paas.application.list"];
    fireEvent.change(screen.getByRole("textbox", { name: "待发布声明 JSON" }), { target: { value: JSON.stringify(proposed, null, 2) } });
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByRole("heading", { name: "审阅待发布版本" })).toBe(document.activeElement);
    expect(screen.getByText(/发布只创建不可变版本/)).toBeTruthy();
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "确认发布新版本" }));
    await waitFor(() => expect(fixture.createPolicyVersion).toHaveBeenCalledTimes(1));
    expect(fixture.createPolicyVersion.mock.calls[0]).toEqual([credential, account.id, "customer.logs", {
      document: proposed, resourceVersion: 4, expectedDefaultVersionId: "version-logs", requestId: expect.stringMatching(/^ui-policy-version-/)
    }]);
    expect(await screen.findByRole("heading", { name: "版本 version-new 已发布" })).toBeTruthy();
    expect(screen.getByText(/当前默认版本仍是 version-logs/)).toBeTruthy();
    expect(fixture.setDefaultPolicyVersion).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("loads the live permission catalog only for visual authoring and publishes the reviewed exact declaration", async () => {
    const fixture = livePolicyVersions();
    const catalog = profileDirectory();
    catalog.items[0]!.profile.actions.push({ action: "paas.application.list", resourceKind: "APPLICATION", scope: "TENANT",
      resourceShapes: [{ mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_LIST" }] });
    const listAuthorizationProfiles = vi.fn().mockResolvedValue(catalog);
    const { user } = await openAccess(accounts({ ...fixture.repository, listAuthorizationProfiles }), iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    expect(listAuthorizationProfiles).not.toHaveBeenCalled();
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    expect(await screen.findByRole("checkbox", { name: /paas.application.read/ })).toBeTruthy();
    expect(listAuthorizationProfiles).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("combobox", { name: "授权效果" }));
    await user.click(screen.getByRole("option", { name: "拒绝" }));
    await user.click(screen.getByRole("combobox", { name: "资源选择器 1" }));
    await user.click(screen.getByRole("option", { name: "精确 ID" }));
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByText(/可视化草稿还有未完成/)).toBeTruthy();
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
    await user.type(screen.getByRole("textbox", { name: "资源 ID 或前缀" }), "app-prod");
    expect(screen.getByRole("checkbox", { name: /paas.application.list/ })).toHaveProperty("disabled", true);
    await user.click(screen.getByRole("button", { name: "仅看已选" }));
    expect(screen.queryByRole("checkbox", { name: /paas.application.list/ })).toBeNull();
    await user.click(screen.getByRole("button", { name: "显示全部操作" }));
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByRole("heading", { name: "审阅待发布版本" })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "返回编辑" }));
    expect(screen.getByRole("checkbox", { name: /paas.application.read/ })).toHaveProperty("checked", true);
    expect((screen.getByRole("textbox", { name: "资源 ID 或前缀" }) as HTMLInputElement).value).toBe("app-prod");
    expect(listAuthorizationProfiles).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认发布新版本" }));
    await waitFor(() => expect(fixture.createPolicyVersion).toHaveBeenCalledTimes(1));
    const submitted = fixture.createPolicyVersion.mock.calls[0]![3].document;
    expect(submitted).toEqual({ languageVersion: "1", scope: "TENANT", statements: [{ sid: "read-applications", effect: "DENY",
      actions: ["paas.application.read"], resources: [{ kind: "APPLICATION", match: "EXACT", id: "app-prod" }] }] });
    expect(fixture.setDefaultPolicyVersion).not.toHaveBeenCalled();
  });

  it("selects compatible Actions together while keeping resource and condition limits shared", async () => {
    const fixture = livePolicyVersions();
    const catalog = profileDirectory();
    catalog.items[0]!.profile.actions.push({ action: "paas.application.inspect", resourceKind: "APPLICATION", scope: "TENANT",
      resourceShapes: [{ mode: "INSTANCE", prefixAllowed: true }] });
    catalog.items[0]!.profile.actions.push({ action: "paas.application.upsert", resourceKind: "APPLICATION", scope: "TENANT",
      resourceShapes: [{ mode: "INSTANCE", prefixAllowed: true }, { mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_CREATE" }] });
    const { user } = await openAccess(accounts({ ...fixture.repository, listAuthorizationProfiles: vi.fn().mockResolvedValue(catalog) }), iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    const read = await screen.findByRole("checkbox", { name: /paas.application.read/ });
    expect(read).toHaveProperty("disabled", true);
    expect(screen.getByRole("checkbox", { name: /paas.application.upsert/ })).toHaveProperty("disabled", true);
    await user.click(screen.getByRole("checkbox", { name: /paas.application.inspect/ }));
    expect(read).toHaveProperty("disabled", false);
    expect(screen.getByText(/已选 2 \/ 128 个操作/)).toBeTruthy();
    expect(screen.getByText("所选操作没有共同支持的策略条件。")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByRole("heading", { name: "审阅待发布版本" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认发布新版本" }));
    await waitFor(() => expect(fixture.createPolicyVersion).toHaveBeenCalledTimes(1));
    expect(fixture.createPolicyVersion.mock.calls[0]![3].document.statements[0]!.actions)
      .toEqual(["paas.application.inspect", "paas.application.read"]);
  });

  it("creates a live custom policy from an explicitly selected catalog Action without attaching it", async () => {
    const createPolicy = vi.fn(async (_credential: string, _accountId: string,
      command: { displayName: string; document: AccountPolicyDocument; requestId: string }): Promise<AccountPolicyDetail> => {
      const policy: AccountPolicy = { ...tenantPolicy, id: "customer.new", management: "CUSTOMER", accountId: account.id,
        displayName: command.displayName, defaultVersionId: "version-new", resourceVersion: 1 };
      return { policy, version: { ...tenantPolicyDetail.version, policyId: policy.id, versionId: policy.defaultVersionId,
        document: structuredClone(command.document) } };
    });
    const listAuthorizationProfiles = vi.fn().mockResolvedValue(profileDirectory());
    const readPolicy = vi.fn(async (_credential: string, _accountId: string, policyId: string) => {
      const call = createPolicy.mock.calls[0];
      if (policyId !== "customer.new" || !call) throw new Error("INVALID_TEST_TARGET");
      return createPolicy.mock.results[0]!.value;
    });
    const { user } = await openAccess(accounts({ createPolicy, readPolicy, listAuthorizationProfiles }), iam(), "policies");
    await user.click(screen.getByRole("button", { name: "新建自定义策略" }));
    expect(listAuthorizationProfiles).not.toHaveBeenCalled();
    fireEvent.change(screen.getByRole("textbox", { name: "策略名称" }), { target: { value: "Application reader" } });
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    const action = await screen.findByRole("radio", { name: /paas.application.read/ });
    await user.click(action);
    expect(screen.getAllByText("paas.application.read", { selector: "code" }).length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    expect(screen.getByText(/可视化声明还有未完成/)).toBeTruthy();
    await user.type(screen.getByRole("textbox", { name: "资源 ID 或前缀" }), "app-prod");
    await user.click(screen.getByRole("button", { name: "添加条件" }));
    await user.type(screen.getByRole("textbox", { name: "条件值" }), "tenant-a");
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    expect(screen.getByRole("heading", { name: "审阅新策略" })).toBeTruthy();
    const summary = screen.getByRole("region", { name: "声明摘要" });
    expect(within(summary).getByText("paas.application.read", { selector: "code" })).toBeTruthy();
    expect(within(summary).getByText("app-prod", { selector: "code" })).toBeTruthy();
    expect(within(summary).getByText("当前账号 ID", { exact: false })).toBeTruthy();
    expect(within(summary).getByText("tenant-a", { selector: "code" })).toBeTruthy();
    expect(screen.getByText("查看完整 JSON").closest("details")?.open).toBe(false);
    await user.click(screen.getByRole("button", { name: "返回编辑" }));
    expect((screen.getByRole("textbox", { name: "策略名称" }) as HTMLInputElement).value).toBe("Application reader");
    expect(document.activeElement).toBe(screen.getByRole("textbox", { name: "策略名称" }));
    expect(screen.getByRole("checkbox", { name: /paas.application.read/ })).toHaveProperty("checked", true);
    expect((screen.getByRole("textbox", { name: "资源 ID 或前缀" }) as HTMLInputElement).value).toBe("app-prod");
    expect(listAuthorizationProfiles).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    await user.click(screen.getByRole("button", { name: "确认创建" }));
    await waitFor(() => expect(createPolicy).toHaveBeenCalledTimes(1));
    const submitted = createPolicy.mock.calls[0]![2];
    expect(submitted.displayName).toBe("Application reader");
    expect(submitted.document).toEqual({ languageVersion: "1", scope: "TENANT", statements: [{ sid: "statement-1", effect: "ALLOW",
      actions: ["paas.application.read"], resources: [{ kind: "APPLICATION", match: "EXACT", id: "app-prod" }],
      conditions: [{ key: "iam.account-id", operator: "STRING_EQUALS", values: ["tenant-a"] }] }] });
    expect(submitted.requestId).toMatch(/^ui-policy-create-/);
    expect(await screen.findByText(/策略 customer.new 已创建/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "查看策略" }));
    expect(await screen.findByText("customer.new")).toBeTruthy();
  });

  it("keeps an unknown policy creation frozen across navigation and retries byte-equivalently", async () => {
    const createPolicy = vi.fn().mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"))
      .mockRejectedValueOnce(new HttpProblem(409, "IAM_CONFLICT"));
    const { user } = await openAccess(accounts({ createPolicy }), iam(), "policies");
    await user.click(screen.getByRole("button", { name: "新建自定义策略" }));
    fireEvent.change(screen.getByRole("textbox", { name: "策略名称" }), { target: { value: "Uncertain policy" } });
    fireEvent.change(screen.getByRole("textbox", { name: "策略声明 JSON" }), { target: { value: JSON.stringify(tenantPolicyDetail.version.document) } });
    await user.click(screen.getByRole("button", { name: "审阅策略" }));
    expect(screen.queryByRole("region", { name: "声明摘要" })).toBeNull();
    expect(screen.getByRole("heading", { name: "策略声明 JSON" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "确认创建" }));
    expect(await screen.findByRole("heading", { name: "策略创建结果未确认" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "查看策略目录" }));
    expect(screen.getByRole("button", { name: "新建自定义策略" })).toHaveProperty("disabled", true);
    await user.click(screen.getByRole("button", { name: "按原请求重试" }));
    await waitFor(() => expect(createPolicy).toHaveBeenCalledTimes(2));
    expect(createPolicy.mock.calls[1]).toEqual(createPolicy.mock.calls[0]);
    expect(screen.getByRole("heading", { name: "策略创建结果未确认" })).toBeTruthy();
    await user.click(screen.getByRole("checkbox", { name: /我理解结果仍未知/ }));
    await user.click(screen.getByRole("button", { name: "结束旧意图" }));
    expect(screen.getByRole("button", { name: "新建自定义策略" })).toHaveProperty("disabled", false);
  });

  it("keeps JSON available when the live catalog is forbidden", async () => {
    const fixture = livePolicyVersions();
    const listAuthorizationProfiles = vi.fn().mockRejectedValue(new HttpProblem(403, "IAM_FORBIDDEN"));
    const { user } = await openAccess(accounts({ ...fixture.repository, listAuthorizationProfiles }), iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    expect(await screen.findByText(/无权读取权限能力目录/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByText(/可视化草稿还有未完成/)).toBeTruthy();
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
    await user.click(screen.getByRole("tab", { name: "JSON 编辑" }));
    expect((screen.getByRole("textbox", { name: "待发布声明 JSON" }) as HTMLTextAreaElement).value).toContain("read-applications");
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
  });

  it("renders only the current action page when the product catalog grows past a thousand actions", async () => {
    const fixture = livePolicyVersions();
    const catalog = profileDirectory();
    const base = catalog.items[0]!.profile.actions[0]!;
    catalog.items[0]!.profile.actions.push(...Array.from({ length: 1200 }, (_, index) => ({ ...base, action: `paas.application.read-${String(index).padStart(4, "0")}` })));
    const { user } = await openAccess(accounts({ ...fixture.repository, listAuthorizationProfiles: vi.fn().mockResolvedValue(catalog) }), iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    const actionRegion = await screen.findByRole("region", { name: "产品操作" });
    expect(within(actionRegion).getAllByRole("checkbox")).toHaveLength(10);
    await user.type(within(actionRegion).getByRole("searchbox", { name: "搜索当前产品操作" }), "read-1199");
    expect(within(actionRegion).getAllByRole("checkbox")).toHaveLength(1);
    expect(within(actionRegion).getByRole("checkbox", { name: /paas.application.read-1199/ })).toBeTruthy();
  });

  it("never drops unknown JSON fields while attempting to switch to the visual editor", async () => {
    const fixture = livePolicyVersions();
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    const original = JSON.stringify({ ...tenantPolicyDetail.version.document, futureField: "keep-me" }, null, 2);
    fireEvent.change(screen.getByRole("textbox", { name: "待发布声明 JSON" }), { target: { value: original } });
    await user.click(screen.getByRole("tab", { name: "可视化编辑" }));
    expect(await screen.findByText(/无法无损呈现的字段或结构/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "返回 JSON 编辑" }));
    expect((screen.getByRole("textbox", { name: "待发布声明 JSON" }) as HTMLTextAreaElement).value).toBe(original);
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
  });

  it("replays the exact unpublished document after an unknown publish response", async () => {
    const fixture = livePolicyVersions();
    fixture.createPolicyVersion.mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    const proposed = structuredClone(tenantPolicyDetail.version.document);
    proposed.statements[0]!.actions = ["paas.application.list"];
    fireEvent.change(screen.getByRole("textbox", { name: "待发布声明 JSON" }), { target: { value: JSON.stringify(proposed) } });
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认发布新版本" }));
    expect(await screen.findByRole("heading", { name: "版本变更结果未确认" })).toBeTruthy();
    expect(screen.getByText(/原请求：发布新版本/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "发布新版本" }).hasAttribute("disabled")).toBe(true);
    await user.click(screen.getByRole("button", { name: "按原请求重试" }));
    await waitFor(() => expect(fixture.createPolicyVersion).toHaveBeenCalledTimes(2));
    expect(fixture.createPolicyVersion.mock.calls[1]).toEqual(fixture.createPolicyVersion.mock.calls[0]);
    expect(fixture.setDefaultPolicyVersion).not.toHaveBeenCalled();
  });

  it("keeps invalid publish input local and a definite IAM validation rejection in review", async () => {
    const fixture = livePolicyVersions();
    fixture.createPolicyVersion.mockRejectedValueOnce(new HttpProblem(422, "iam.argument.invalid"));
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    const editor = screen.getByRole("textbox", { name: "待发布声明 JSON" });
    fireEvent.change(editor, { target: { value: "{" } });
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    expect(screen.getByText("JSON 语法无效，请修正后再审阅。")).toBeTruthy();
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
    fireEvent.change(editor, { target: { value: JSON.stringify(tenantPolicyDetail.version.document) } });
    await user.click(screen.getByRole("button", { name: "审阅变更" }));
    await user.click(screen.getByRole("button", { name: "确认发布新版本" }));
    expect(await screen.findByText("提交未通过校验；请核对当前版本与声明。")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "审阅待发布版本" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "版本变更结果未确认" })).toBeNull();
  });

  it("keeps an edited live version draft until the operator explicitly discards it", async () => {
    const fixture = livePolicyVersions();
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "发布新版本" }));
    const editor = screen.getByRole("textbox", { name: "待发布声明 JSON" });
    fireEvent.change(editor, { target: { value: "{\n  \"languageVersion\": \"1\"\n}" } });
    await user.click(screen.getByTestId("nav-users"));
    expect(await screen.findByRole("dialog", { name: "离开未发布的策略草稿？" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "继续编辑" }));
    expect((screen.getByRole("textbox", { name: "待发布声明 JSON" }) as HTMLTextAreaElement).value).toContain("languageVersion");
    expect(fixture.createPolicyVersion).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "取消" }));
    await user.click(await screen.findByRole("button", { name: "放弃并离开" }));
    expect(await screen.findByRole("table", { name: "策略版本目录" })).toBeTruthy();
  });

  it("keeps an uncertain live version intent across IAM navigation and retries with identical input", async () => {
    const fixture = livePolicyVersions();
    fixture.setDefaultPolicyVersion.mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"));
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "版本 version-a 的操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "切换默认版本" }));
    await user.click(screen.getByRole("button", { name: "确认切换" }));
    const recoveryHeading = await screen.findByRole("heading", { name: "版本变更结果未确认" });
    await waitFor(() => expect(recoveryHeading).toBe(document.activeElement));
    await user.click(screen.getByTestId("nav-users"));
    await user.click(screen.getByTestId("nav-policies"));
    expect(await screen.findByRole("heading", { name: "版本变更结果未确认" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "按原请求重试" }));
    await waitFor(() => expect(fixture.setDefaultPolicyVersion).toHaveBeenCalledTimes(2));
    expect(fixture.setDefaultPolicyVersion.mock.calls[1]).toEqual(fixture.setDefaultPolicyVersion.mock.calls[0]);
    await waitFor(() => expect(screen.queryByRole("heading", { name: "版本变更结果未确认" })).toBeNull());
  });

  it("does not treat a retry conflict or current-state read as proof of the original version mutation", async () => {
    const fixture = livePolicyVersions();
    fixture.setDefaultPolicyVersion.mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE"))
      .mockRejectedValueOnce(new HttpProblem(409, "IAM_CONFLICT"));
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "版本 version-a 的操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "切换默认版本" }));
    await user.click(screen.getByRole("button", { name: "确认切换" }));
    await screen.findByRole("heading", { name: "版本变更结果未确认" });
    await user.click(screen.getByRole("button", { name: "按原请求重试" }));
    await waitFor(() => expect(fixture.setDefaultPolicyVersion).toHaveBeenCalledTimes(2));
    expect(screen.getByText(/即使重试返回冲突/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "读取当前状态" }));
    expect(await screen.findByText(/当前读取：默认版本 version-logs/)).toBeTruthy();
    expect(screen.getByText(/不能证明原请求是否执行/)).toBeTruthy();
    const end = screen.getByRole("button", { name: "结束旧意图" });
    expect(end.hasAttribute("disabled")).toBe(true);
    await user.click(screen.getByRole("checkbox", { name: /我理解原请求结果仍未知/ }));
    await user.click(end);
    await waitFor(() => expect(screen.queryByRole("heading", { name: "版本变更结果未确认" })).toBeNull());
    expect(fixture.setDefaultPolicyVersion.mock.calls[1]).toEqual(fixture.setDefaultPolicyVersion.mock.calls[0]);
  });

  it("keeps a first-submit authorization rejection in review without claiming version-write permission", async () => {
    const fixture = livePolicyVersions();
    fixture.setDefaultPolicyVersion.mockRejectedValueOnce(new HttpProblem(403, "IAM_FORBIDDEN"));
    const { user } = await openAccess(fixture.repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: "LogBoundary" }));
    await user.click(await screen.findByRole("tab", { name: "策略版本" }));
    await screen.findByRole("table", { name: "策略版本目录" });
    await user.click(screen.getByRole("button", { name: "版本 version-a 的操作" }));
    await user.click(await screen.findByRole("menuitem", { name: "切换默认版本" }));
    await user.click(screen.getByRole("button", { name: "确认切换" }));
    expect(await screen.findByText("当前身份无权执行此操作。")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "将 version-a 设为默认版本" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "版本变更结果未确认" })).toBeNull();
    expect(fixture.setDefaultPolicyVersion).toHaveBeenCalledTimes(1);
  });

  it("keeps a forbidden version directory local while the independently readable default remains visible", async () => {
    const customer = { ...tenantPolicy, id: "customer.logs", management: "CUSTOMER" as const, accountId: account.id,
      displayName: "LogBoundary", defaultVersionId: "version-logs" };
    const readPolicy = vi.fn().mockResolvedValue({ policy: customer, version: { ...tenantPolicyDetail.version,
      policyId: customer.id, versionId: customer.defaultVersionId } });
    const listPolicyVersions = vi.fn().mockRejectedValue(new HttpProblem(403, "FORBIDDEN"));
    const repository = accounts({ readPolicy, listPolicyVersions, readPolicyVersion: vi.fn(),
      listPolicies: vi.fn(async (_credential: string, platform: boolean) => platform ? directory(true) : { ...directory(false), items: [customer] }) });
    const { user } = await openAccess(repository, iam(), "policies");
    await user.click(await screen.findByRole("button", { name: customer.displayName }));
    expect(await screen.findByRole("table", { name: "策略声明" })).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "策略版本" }));
    expect(await screen.findByText(/无权读取这些版本/)).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "当前默认版本" }));
    expect(screen.getByRole("table", { name: "策略声明" })).toBeTruthy();
    expect(readPolicy).toHaveBeenCalledTimes(1);
  });

  it("keeps a forbidden policy detail local and never substitutes MOCK content", async () => {
    const readPolicy = vi.fn().mockRejectedValue(new HttpProblem(403, "FORBIDDEN"));
    const { user } = await openAccess(accounts({ readPolicy }), iam(), "policies");
    await user.click(await screen.findByRole("button", { name: tenantPolicy.displayName }));
    expect(await screen.findByText(/无权读取该策略的详情/)).toBeTruthy();
    expect(screen.queryByRole("table", { name: "策略声明" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "返回列表" }));
    expect(screen.getByRole("table", { name: "策略元数据目录" })).toBeTruthy();
    expect(screen.queryByText(/隔离 MOCK 的权限能力目录/)).toBeNull();
  });

  it("loads the permission catalog only after its tab opens and keeps product detail in the content area", async () => {
    const listAuthorizationProfiles = vi.fn().mockResolvedValue(profileDirectory());
    const { user } = await openAccess(accounts({ listAuthorizationProfiles }), iam(), "policies");
    expect(await screen.findByRole("table", { name: "策略元数据目录" })).toBeTruthy();
    expect(listAuthorizationProfiles).not.toHaveBeenCalled();

    await user.click(screen.getByRole("tab", { name: "权限能力目录" }));
    expect(await screen.findByRole("table", { name: "产品权限能力目录" })).toBeTruthy();
    expect(listAuthorizationProfiles).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/不是当前用户权限/)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "paas" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("heading", { level: 2, name: "paas" })).toBe(document.activeElement);
    expect(screen.queryByRole("button", { name: "体验产品接入审阅" })).toBeNull();
    expect(screen.getByRole("table", { name: "产品 paas 的 Action 声明" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "返回能力目录" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "paas" })).toBe(document.activeElement));
  });

  it("keeps the catalog notice and search in place while its data region waits", async () => {
    let resolve!: (value: AuthorizationProfileDirectory) => void;
    const pending = new Promise<AuthorizationProfileDirectory>((done) => { resolve = done; });
    const listAuthorizationProfiles = vi.fn().mockReturnValue(pending);
    const { user } = await openAccess(accounts({ listAuthorizationProfiles }), iam(), "policies");
    await screen.findByRole("table", { name: "策略元数据目录" });
    await user.click(screen.getByRole("tab", { name: "权限能力目录" }));
    expect(listAuthorizationProfiles).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/不是当前用户权限/)).toBeTruthy();
    const search = screen.getByRole("searchbox", { name: "搜索产品能力" });
    await user.type(search, "paas");
    expect((search as HTMLInputElement).value).toBe("paas");
    expect(screen.queryByRole("table", { name: "产品权限能力目录" })).toBeNull();
    await act(async () => resolve(profileDirectory()));
    expect(screen.getByRole("searchbox", { name: "搜索产品能力" })).toBe(search);
    expect(await screen.findByRole("table", { name: "产品权限能力目录" })).toBeTruthy();
  });

  it("retains the same catalog search control and query through a local retry", async () => {
    let resolve!: (value: AuthorizationProfileDirectory) => void;
    const pending = new Promise<AuthorizationProfileDirectory>((done) => { resolve = done; });
    const listAuthorizationProfiles = vi.fn().mockRejectedValueOnce(new HttpProblem(503, "IAM_UNAVAILABLE")).mockReturnValueOnce(pending);
    const { user } = await openAccess(accounts({ listAuthorizationProfiles }), iam(), "policies");
    await user.click(await screen.findByRole("tab", { name: "权限能力目录" }));
    expect(await screen.findByText(/权限能力目录暂时不可用/)).toBeTruthy();
    const search = screen.getByRole("searchbox", { name: "搜索产品能力" });
    await user.type(search, "paas");
    await user.click(screen.getByRole("button", { name: "重新读取" }));
    expect(screen.getByRole("searchbox", { name: "搜索产品能力" })).toBe(search);
    expect((search as HTMLInputElement).value).toBe("paas");
    await act(async () => resolve(profileDirectory()));
    expect(within(await screen.findByRole("table", { name: "产品权限能力目录" })).getByRole("button", { name: "paas" })).toBeTruthy();
  });

  it("pages a complete product snapshot locally and preserves the page when returning from detail", async () => {
    const sample = profileDirectory().items[0]!;
    const items = Array.from({ length: 12 }, (_, index) => ({
      ...sample,
      profile: { ...sample.profile, product: `product-${String(index).padStart(2, "0")}` }
    }));
    const { user } = await openAccess(accounts({ listAuthorizationProfiles: vi.fn().mockResolvedValue({ accountId: account.id, items }) }), iam(), "policies");
    await user.click(await screen.findByRole("tab", { name: "权限能力目录" }));
    const table = await screen.findByRole("table", { name: "产品权限能力目录" });
    expect(within(table).getAllByRole("row")).toHaveLength(11);
    expect(within(table).queryByRole("button", { name: "product-10" })).toBeNull();
    expect(screen.getByText("第 1 / 2 页")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "下一页" }));
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    await user.click(within(table).getByRole("button", { name: "product-11" }));
    expect(screen.getByRole("heading", { level: 2, name: "product-11" })).toBe(document.activeElement);
    await user.click(screen.getByRole("button", { name: "返回能力目录" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "product-11" })).toBe(document.activeElement));
    expect(screen.getByText("第 2 / 2 页")).toBeTruthy();

    await user.type(screen.getByRole("searchbox", { name: "搜索产品能力" }), "product-03");
    expect(screen.getByText("第 1 / 1 页")).toBeTruthy();
    const filteredTable = screen.getByRole("table", { name: "产品权限能力目录" });
    expect(within(filteredTable).getAllByRole("row")).toHaveLength(2);
    expect(within(filteredTable).getByRole("button", { name: "product-03" })).toBeTruthy();
  });

  it.each([
    [403, "当前身份无权读取权限能力目录"],
    [404, "后端版本或路由可能未匹配"],
    [503, "权限能力目录暂时不可用"]
  ])("localizes catalog HTTP %s without replacing the policy directory or falling back to MOCK", async (status, message) => {
    const { user } = await openAccess(accounts({ listAuthorizationProfiles: vi.fn().mockRejectedValue(new HttpProblem(status, "PRIVATE")) }), iam(), "policies");
    await screen.findByRole("table", { name: "策略元数据目录" });
    await user.click(screen.getByRole("tab", { name: "权限能力目录" }));
    expect(await screen.findByText(new RegExp(message))).toBeTruthy();
    expect(screen.queryByText(/隔离 MOCK 的权限能力目录/)).toBeNull();
    await user.click(screen.getByRole("tab", { name: "策略目录" }));
    expect(screen.getByRole("table", { name: "策略元数据目录" })).toBeTruthy();
  });

  it("rejects a catalog bound to another account without clearing the policy scene", async () => {
    const { user } = await openAccess(accounts({ listAuthorizationProfiles: vi.fn().mockResolvedValue({ ...profileDirectory(), accountId: "tenant-b" }) }), iam(), "policies");
    await user.click(await screen.findByRole("tab", { name: "权限能力目录" }));
    expect(await screen.findByText(/权限能力目录暂时不可用/)).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "策略目录" }));
    expect(screen.getByRole("table", { name: "策略元数据目录" })).toBeTruthy();
  });

  it("creates a live role in the content area and retains the exact request after an unknown result", async () => {
    const roleIdentity: AccountIdentity = { ...identity, capabilities: [
      ...identity.capabilities,
      capability("iam.role.list", "ACCOUNT", account.id),
      capability("iam.role.create", "ACCOUNT", account.id)
    ] };
    const create = vi.fn()
      .mockRejectedValueOnce(new Error("connection lost after submit"))
      .mockResolvedValue({ ...managedRole, name: "IncidentResponder", description: "Temporary incident response" });
    const repository = accounts({
      currentIdentity: vi.fn().mockResolvedValue(roleIdentity),
      roles: {
        list: vi.fn().mockResolvedValue(managedRoleDirectory),
        read: vi.fn().mockResolvedValue(managedRoleAccess),
        create,
        listSessions: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, observedAt: timestamp, items: [], nextAfter: null }),
        readSession: vi.fn().mockRejectedValue(new Error("unused session read")),
        revokeSession: vi.fn().mockRejectedValue(new Error("unused session revoke"))
      }
    });
    const { user } = await openAccess(repository, iam(), "roles");

    await user.click(await screen.findByRole("button", { name: "新建角色" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(screen.getByRole("alert").textContent).toContain("至少选择一名");
    await user.click(screen.getByRole("checkbox", { name: "developer" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.type(screen.getByLabelText("名称", { exact: true }), "IncidentResponder");
    await user.type(screen.getByLabelText("描述", { exact: true }), "Temporary incident response");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    expect(create).not.toHaveBeenCalled();
    expect(screen.getByText("本次命令只创建角色元数据", { exact: false })).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "新建角色" }));
    expect(await screen.findByText("创建结果尚未确认", { exact: false })).toBeTruthy();
    const original = create.mock.calls[0]?.[2];
    expect(original).toMatchObject({
      name: "IncidentResponder",
      description: "Temporary incident response",
      maxSessionDurationSeconds: 3600,
      trustPolicy: { statements: [{ principals: [{ type: "USER", id: childUser.id }] }] }
    });
    await user.click(screen.getByRole("button", { name: "重试原请求" }));
    expect(await screen.findByRole("heading", { name: "角色已创建" })).toBeTruthy();
    expect(create).toHaveBeenCalledTimes(2);
    expect(create.mock.calls[1]?.[2]).toEqual(original);
  });

  it("discards a late role creation result when the Session-scoped client changes", async () => {
    const roleIdentity: AccountIdentity = { ...identity, capabilities: [
      ...identity.capabilities,
      capability("iam.role.list", "ACCOUNT", account.id),
      capability("iam.role.create", "ACCOUNT", account.id)
    ] };
    const scene = buildAccountAccessScene(roleIdentity, { items: [child], nextAfter: null }, null, directory(false), directory(true));
    let resolveCreate!: (value: typeof managedRole) => void;
    const create = vi.fn(() => new Promise<typeof managedRole>((resolve) => { resolveCreate = resolve; }));
    const roleClient = (operation: RoleAccessClient["create"]): RoleAccessClient => ({
      accountId: account.id,
      canCreate: true,
      createRestrictionReason: null,
      list: vi.fn().mockResolvedValue(managedRoleDirectory),
      read: vi.fn().mockResolvedValue(managedRoleAccess),
      create: operation,
      listSessions: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, observedAt: timestamp, items: [], nextAfter: null }),
      readSession: vi.fn().mockRejectedValue(new Error("unused session read")),
      revokeSession: vi.fn().mockRejectedValue(new Error("unused session revoke"))
    });
    const firstClient = roleClient(create);
    const secondClient = roleClient(vi.fn().mockResolvedValue(managedRole));
    const user = userEvent.setup();
    const onDone = vi.fn();
    const wizard = (client: RoleAccessClient) => <LocaleProvider><UnsavedChangesProvider>
      <LiveRoleCreationWizard client={client} scene={scene} onBack={vi.fn()} onDone={onDone} />
    </UnsavedChangesProvider></LocaleProvider>;
    const view = render(wizard(firstClient));

    await user.click(screen.getByRole("checkbox", { name: "developer" }));
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.type(screen.getByLabelText("名称", { exact: true }), "OldSessionRole");
    await user.click(screen.getByRole("button", { name: "下一步" }));
    await user.click(screen.getByRole("button", { name: "新建角色" }));
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));

    view.rerender(wizard(secondClient));
    await waitFor(() => expect((screen.getByRole("checkbox", { name: "developer" }) as HTMLInputElement).checked).toBe(false));
    await act(async () => { resolveCreate({ ...managedRole, id: "late-old-session-role", name: "OldSessionRole" }); });

    expect(screen.queryByRole("heading", { name: "角色已创建" })).toBeNull();
    expect(screen.queryByText("late-old-session-role")).toBeNull();
    expect(onDone).not.toHaveBeenCalled();
  });

  it("retains one uncertain role-session revoke across the real keyed directory navigation boundary", async () => {
    const roleIdentity: AccountIdentity = { ...identity, capabilities: [
      ...identity.capabilities,
      capability("iam.role.list", "ACCOUNT", account.id),
      capability("iam.role.create", "ACCOUNT", "collection")
    ] };
    const revoked = { ...managedRoleSession, status: "REVOKED" as const, revokedAt: "2026-09-21T08:31:00Z" };
    const revokeSession = vi.fn().mockRejectedValueOnce(new Error("connection lost after submit")).mockResolvedValue({ outcome: "EQUAL_REPLAY" as const, session: revoked });
    const repository = accounts({
      currentIdentity: vi.fn().mockResolvedValue(roleIdentity),
      roles: {
        list: vi.fn().mockResolvedValue(managedRoleDirectory),
        read: vi.fn().mockResolvedValue(managedRoleAccess),
        create: vi.fn().mockResolvedValue(managedRole),
        listSessions: vi.fn().mockResolvedValue({ accountId: account.id, roleId: managedRole.id, observedAt: timestamp, items: [managedRoleSessionItem], nextAfter: null }),
        readSession: vi.fn().mockResolvedValue({ observedAt: timestamp, item: managedRoleSessionItem }),
        revokeSession
      }
    });
    const { user } = await openAccess(repository, iam(), "roles");

    await user.click(await screen.findByRole("button", { name: managedRole.name }));
    await user.click(await screen.findByRole("tab", { name: "角色会话" }));
    await user.click(await screen.findByRole("button", { name: `会话 ${managedRoleSession.id} 的操作` }));
    await user.click(screen.getByRole("menuitem", { name: "撤销会话" }));
    let workflow = screen.getByRole("group", { name: "撤销会话" });
    await user.click(within(workflow).getByRole("button", { name: "撤销会话" }));
    expect(await within(workflow).findByText("撤销结果尚未确认", { exact: false })).toBeTruthy();
    const originalRequestId = revokeSession.mock.calls[0]?.[4];
    await user.click(within(workflow).getByRole("button", { name: "取消" }));
    await user.click(screen.getByRole("button", { name: "返回列表" }));
    await user.click(await screen.findByRole("button", { name: managedRole.name }));
    await user.click(await screen.findByRole("tab", { name: "角色会话" }));
    await user.click(await screen.findByRole("button", { name: "继续处理未知结果" }));
    workflow = screen.getByRole("group", { name: "撤销会话" });
    expect(within(workflow).getByText(originalRequestId ?? "missing")).toBeTruthy();
    await user.click(within(workflow).getByRole("button", { name: "重试原请求" }));
    await waitFor(() => expect(revokeSession).toHaveBeenCalledTimes(2));
    expect(revokeSession.mock.calls[1]?.[4]).toBe(originalRequestId);
  });

  it("clears a pending role-session revoke across accounts and rejects a late callback from the old account", async () => {
    const identityFor = (suffix: "a" | "b"): AccountIdentity => {
      const tenant = `tenant-${suffix}`;
      const principal = `primary-${suffix}`;
      return {
        account: { id: tenant, displayName: `Team ${suffix.toUpperCase()}`, status: "ACTIVE", rootIdentity: { principalId: principal, loginName: `admin-${suffix}` }, loginAlias: null, resourceVersion: 1 },
        user: { id: principal, accountId: tenant, loginName: `admin-${suffix}`, displayName: `Admin ${suffix.toUpperCase()}`, status: "ACTIVE", resourceVersion: 1, mustChangePassword: false },
        identityKind: "ROOT_IDENTITY",
        policySources: [],
        permissionBoundary: { accountId: tenant, userId: principal, resourceVersion: 1, policy: null },
        capabilities: []
      };
    };
    const auth = iam({
      login: vi.fn(async ({ loginName }) => {
        const suffix = loginName.endsWith("-b") ? "b" : "a";
        return { outcome: "AUTHENTICATED" as const, credential: `credential-tenant-${suffix}`, mustChangePassword: false, session: { id: `session-${suffix}`, organizationId: `tenant-${suffix}`, principalId: `primary-${suffix}`, status: "ACTIVE" as const, issuedAt: timestamp, expiresAt: "2099-08-27T00:00:00Z" } };
      })
    });
    const repository = accounts({
      currentIdentity: vi.fn(async (activeCredential: string) => identityFor(activeCredential.endsWith("-b") ? "b" : "a")),
      listPolicies: vi.fn(async (activeCredential: string, platform: boolean) => ({
        accountId: activeCredential.endsWith("-b") ? "tenant-b" : "tenant-a",
        scope: platform ? "INSTALLATION" as const : "TENANT" as const,
        installationId: platform ? "installation-test" : null,
        items: []
      }))
    });
    const user = userEvent.setup();
    render(<LocaleProvider><SessionProvider repository={auth}><AccountAccessProvider repository={repository}><AccountIntentProbe /></AccountAccessProvider></SessionProvider></LocaleProvider>);

    await user.click(screen.getByRole("button", { name: "login-a" }));
    await waitFor(() => expect(screen.getByLabelText("active-account").textContent).toBe("tenant-a"));
    await user.click(screen.getByRole("button", { name: "remember-revoke" }));
    expect(screen.getByLabelText("pending-revoke").textContent).toBe(accountSwitchIntent.requestId);
    await user.click(screen.getByRole("button", { name: "logout" }));
    await waitFor(() => expect(screen.getByLabelText("pending-revoke").textContent).toBe("none"));
    await user.click(screen.getByRole("button", { name: "login-b" }));
    await waitFor(() => expect(screen.getByLabelText("active-account").textContent).toBe("tenant-b"));
    await user.click(screen.getByRole("button", { name: "late-old-update" }));
    expect(screen.getByLabelText("pending-revoke").textContent).toBe("none");
  });

  it("fails the live scene without substituting MOCK data when a policy directory has a non-authorization error", async () => {
    const repository = accounts({ listPolicies: vi.fn(async (_credential: string, platform: boolean) => {
      if (platform) throw new HttpProblem(503, "UPSTREAM_UNAVAILABLE");
      return directory(false);
    }) });
    await openAccess(repository, iam(), "policies");
    expect((await screen.findByRole("alert")).textContent).toContain("访问管理暂时不可用");
    expect(screen.queryByRole("table", { name: "策略元数据目录" })).toBeNull();
    expect(screen.queryByText("ReadOnlyAccess")).toBeNull();
  });

  it("requires an explicit current policy revision for every direct attachment", async () => {
    const { user, repository } = await openAccess();
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    expect((screen.getByRole("button", { name: "关联策略" }) as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByRole("combobox", { name: "关联策略" }));
    await user.click(screen.getByRole("option", { name: /PlatformAdministrator/ }));
    await user.click(screen.getByRole("button", { name: "关联策略" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "create-policy-attachment", userId: "child-a", policyId: "system.platform-admin", policyResourceVersion: 2 }));
    await waitFor(() => expect(screen.getByRole("combobox", { name: "关联策略" }).textContent).toBe("选择可关联策略"));
    expect((screen.getByRole("button", { name: "关联策略" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("requires confirmation for revocation and disabling and clears a submitted reset password", async () => {
    const { user, repository } = await openAccess();
    await user.click(await screen.findByRole("button", { name: "查看用户 developer" }));
    await user.click(screen.getByRole("button", { name: "撤销策略 ReadOnlyAccess" }));
    expect(repository.execute).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "确认撤销" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "revoke-policy-attachment", attachmentId: "attachment-child-a-system.paas-viewer", resourceVersion: 1 }));
    await waitFor(() => expect((screen.getByRole("button", { name: "禁用用户" }) as HTMLButtonElement).disabled).toBe(false));
    await user.click(screen.getByRole("button", { name: "禁用用户" }));
    expect(repository.execute).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "确认禁用" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "set-status", userId: "child-a", status: "DISABLED", resourceVersion: 2 }));
    await waitFor(() => expect((screen.getByRole("button", { name: "重置密码" }) as HTMLButtonElement).disabled).toBe(false));
    await user.click(screen.getByRole("button", { name: "重置密码" }));
    await user.type(screen.getByLabelText(/^初始密码/), "Reset-Only-Test-Password-74!");
    await user.click(screen.getByRole("button", { name: "确认重置密码" }));
    await waitFor(() => expect(repository.execute).toHaveBeenCalledWith(credential, { kind: "reset-password", userId: "child-a", initialPassword: "Reset-Only-Test-Password-74!", resourceVersion: 2 }));
    expect(screen.queryByDisplayValue("Reset-Only-Test-Password-74!")).toBeNull();
  });

  it.each(["identity", "directory", "principal", "root-directory"])("fails closed on a mismatched %s instead of showing another subject", async (mismatch) => {
    const other = structuredClone(identity);
    if (mismatch === "identity") other.account.id = "tenant-b";
    if (mismatch === "principal") other.user.id = "other-principal";
    const foreignUser: User = { ...child.user, accountId: "tenant-b", displayName: "PRIVATE OTHER USER" };
    const directoryUser = mismatch === "root-directory"
      ? { user: rootUser, policyAttachments: [], capabilities: userCapabilities(rootUser, [], "ROOT_IDENTITY_PROTECTED") }
      : { user: foreignUser, policyAttachments: [], capabilities: userCapabilities(foreignUser) };
    const repository = accounts({ currentIdentity: vi.fn().mockResolvedValue(other), ...(["directory", "root-directory"].includes(mismatch) ? { listUsers: vi.fn().mockResolvedValue({ items: [directoryUser], nextAfter: null }) } : {}) });
    await openAccess(repository);
    expect((await screen.findByRole("alert")).textContent).toContain("暂时不可用");
    expect(screen.queryByText("PRIVATE OTHER USER")).toBeNull();
    expect(screen.queryByRole("button", { name: "创建用户" })).toBeNull();
  });
});
