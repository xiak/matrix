"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import { useSession, useSessionCredential } from "./SessionProvider";
import type {
  AccountCommand,
  AccountPolicy,
  AuthorizationProfileDirectory,
  CapabilityRestriction,
  DirectoryPage,
  Group,
  GroupAccess,
  GroupDeletion,
  GroupMembership,
  GroupMembershipPage,
  GroupPolicyAttachment,
  PolicyAttachmentRevocation,
  UserPermissionBoundary
} from "../domain/accounts";
import { type AccessWorkspace, type AccessWorkspaceCommand } from "../domain/accessWorkspace";
import { AccessWorkspaceError } from "../domain/accessWorkspaceError";
import type { AccountRepository } from "../repositories/iamRepository";
import { httpAccountRepository } from "../repositories/httpIamRepository";
import { buildAccountAccessScene, buildAccountTenantScene, buildAccountUserScene, findActionCapability, type AccountAccessScene, type AccountUserScene } from "../scenes/accountAccessScene";
import { userBatchDisabledReason, type UserBatchCommand } from "../domain/userBatch";

type AccountError = "expired" | "forbidden" | "conflict" | "invalid" | "unavailable";
type WorkspaceExecutionError = AccessWorkspaceError["code"] | AccountError;

export type UserBoundarySnapshot = {
  user: AccountUserScene;
  boundary: UserPermissionBoundary;
  policies: AccountPolicy[];
  policiesAvailable: boolean;
};
export type UserBoundaryClient = {
  accountId: string;
  load(userId: string): Promise<UserBoundarySnapshot>;
  set(userId: string, command: { policyId: string; policyResourceVersion: number; resourceVersion: number; requestId: string }): Promise<UserPermissionBoundary>;
  remove(userId: string, command: { resourceVersion: number; requestId: string }): Promise<UserPermissionBoundary>;
};

export type GroupAccessClient = {
  accountId: string;
  canList: boolean;
  listRestrictionReason: CapabilityRestriction | null;
  canCreate: boolean;
  createRestrictionReason: CapabilityRestriction | null;
  list(after?: string): Promise<DirectoryPage<GroupAccess>>;
  get(groupId: string): Promise<GroupAccess>;
  create(command: { name: string; description?: string; requestId: string }): Promise<Group>;
  update(groupId: string, command: { name: string; description?: string; resourceVersion: number; requestId: string }): Promise<Group>;
  delete(groupId: string, command: { resourceVersion: number; requestId: string }): Promise<GroupDeletion>;
  listMemberships(groupId: string, after?: string): Promise<GroupMembershipPage>;
  createMembership(groupId: string, command: { userId: string; requestId: string }): Promise<GroupMembership>;
  removeMembership(groupId: string, membershipId: string, command: { resourceVersion: number; requestId: string }): Promise<GroupMembership>;
  createPolicyAttachment(groupId: string, command: { policyId: string; policyResourceVersion: number; requestId: string }): Promise<GroupPolicyAttachment>;
  revokePolicyAttachment(attachmentId: string, command: { resourceVersion: number; requestId: string }): Promise<PolicyAttachmentRevocation>;
};

export type AuthorizationProfileLoad =
  | { status: "ready"; directory: AuthorizationProfileDirectory }
  | { status: "forbidden" | "routeUnavailable" | "unavailable" | "expired" };

export type AuthorizationProfileClient = {
  accountId: string;
  preview: boolean;
  load(): Promise<AuthorizationProfileLoad>;
};

export type PolicyDirectoryView = { query: string; kind: string; service: string; category: string; sort: string; page: number; pageSize: number };
export const defaultPolicyDirectoryView: PolicyDirectoryView = { query: "", kind: "all", service: "all", category: "all", sort: "name", page: 1, pageSize: 10 };
export type UserDirectoryView = { query: string; state: string; role: string };
const defaultUserDirectoryView: UserDirectoryView = { query: "", state: "all", role: "all" };

type AccountAccess = {
  supportsUserBatch: boolean;
  executeUserBatch(command: UserBatchCommand): Promise<boolean>;
  policyDirectoryView: { read(): PolicyDirectoryView; remember(value: PolicyDirectoryView): void };
  userDirectoryView: { read(): UserDirectoryView; remember(value: UserDirectoryView): void };
  workspace: AccessWorkspace | null;
  workspaceError: WorkspaceExecutionError | null;
  executeWorkspace(command: AccessWorkspaceCommand, onError?: (error: WorkspaceExecutionError) => void): Promise<{ issuedKey?: { id: string; secret: string } } | null>;
  clearWorkspaceError(): void;
  clearFeedback(): void;
  groups: GroupAccessClient | null;
  permissionBoundaries: UserBoundaryClient | null;
  authorizationProfiles: AuthorizationProfileClient | null;
  scene: AccountAccessScene | null;
  loading: boolean;
  busy: boolean;
  error: AccountError | null;
  success: "completed" | null;
  reload(): void;
  usersPage(after: string): void;
  accountsPage(after: string): void;
  loadUser(userId: string): Promise<AccountUserScene>;
  execute(command: AccountCommand): Promise<boolean>;
};

const AccountAccessContext = createContext<AccountAccess | null>(null);
type AccountCapabilities = Pick<AccountAccessScene, "canListUsers" | "canListGroups" | "canReadAccounts" | "canCreateAccounts" | "canViewPolicies"> & { hasPreviewWorkspace: boolean };
const AccountCapabilitiesContext = createContext<AccountCapabilities | null>(null);

export function accountError(error: unknown): AccountError {
  if (error instanceof HttpProblem) {
    if (error.status === 401) return "expired";
    if (error.status === 403) return "forbidden";
    if (error.status === 409) return "conflict";
    if (error.status === 422 || error.status === 400) return "invalid";
  }
  return "unavailable";
}

async function readWhenAuthorized<T>(read: () => Promise<T>): Promise<T | null> {
  try {
    return await read();
  } catch (error) {
    if (error instanceof HttpProblem && error.status === 403) return null;
    throw error;
  }
}

function accountCommandAvailable(scene: AccountAccessScene, command: AccountCommand): boolean {
  if (command.kind === "create-user") return scene.canCreateUsers;
  if (command.kind === "create-account") return scene.canCreateAccounts;
  if (command.kind === "set-alias") return scene.canSetAlias;
  if (command.kind === "set-account-status" || command.kind === "recover-root-credentials") {
    const account = scene.accounts.find((item) => item.id === command.accountId);
    return command.kind === "set-account-status" ? account?.canSetStatus === true : account?.canRecoverRoot === true;
  }
  if (command.kind === "revoke-policy-attachment") {
    return scene.users.some((user) => user.attachments.some((attachment) => attachment.id === command.attachmentId && attachment.canRevoke));
  }
  const user = scene.users.find((item) => item.id === command.userId);
  if (!user) return false;
  if (command.kind === "update-user") return user.canUpdate;
  if (command.kind === "delete-user") return user.canDelete;
  if (command.kind === "set-status") return user.canSetStatus;
  if (command.kind === "reset-password") return user.canResetPassword;
  const policy = scene.policies.find((item) => item.id === command.policyId);
  return policy?.scope === "INSTALLATION" ? user.canAttachPlatformPolicy : user.canAttachTenantPolicy;
}

export function AccountAccessProvider({ children, repository = httpAccountRepository, active = true }: { children: ReactNode; repository?: AccountRepository; active?: boolean }) {
  const credential = useSessionCredential();
  const session = useSession();
  const expireSession = session.expire;
  const tenantId = session.current?.session.organizationId;
  const principalId = session.current?.session.principalId;
  const [scene, setScene] = useState<AccountAccessScene | null>(null);
  const [workspace, setWorkspace] = useState<AccessWorkspace | null>(null);
  const [workspaceError, setWorkspaceError] = useState<AccountAccess["workspaceError"]>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<AccountError | null>(null);
  const [success, setSuccess] = useState<"completed" | null>(null);
  const [revision, setRevision] = useState(0);
  const mutationPending = useRef(false);
  const directoryRequest = useRef({ users: 0, accounts: 0 });
  // View context survives list/detail navigation, not account/session changes.
  // Keeping it outside React state avoids rerendering the shell on each keystroke.
  const viewSession = useMemo(() => ({ credential, tenantId, principalId }), [credential, tenantId, principalId]);
  const storedPolicyView = useRef<{ session: typeof viewSession; view: PolicyDirectoryView } | null>(null);
  const policyDirectoryView = useMemo(() => ({
    read() { const stored = storedPolicyView.current; return stored?.session === viewSession ? stored.view : { ...defaultPolicyDirectoryView }; },
    remember(view: PolicyDirectoryView) { storedPolicyView.current = { session: viewSession, view: { ...view } }; }
  }), [viewSession]);
  const clearWorkspaceError = useCallback(() => setWorkspaceError(null), []);
  const protectedMutation = useCallback(<T,>(request: () => Promise<T>): Promise<T> => {
    if (workspace?.personalMfa.reauthenticationRequired) {
      setWorkspaceError("reauthenticationRequired");
      return Promise.reject(new AccessWorkspaceError("reauthenticationRequired"));
    }
    return request();
  }, [workspace?.personalMfa.reauthenticationRequired]);
  const storedUserView = useRef<{ session: typeof viewSession; view: UserDirectoryView } | null>(null);
  const userDirectoryView = useMemo(() => ({
    read() { const stored = storedUserView.current; return stored?.session === viewSession ? stored.view : { ...defaultUserDirectoryView }; },
    remember(view: UserDirectoryView) { storedUserView.current = { session: viewSession, view: { ...view } }; }
  }), [viewSession]);
  const clearFeedback = useCallback(() => { setWorkspaceError(null); setSuccess(null); }, []);
  const canListUsers = Boolean(scene?.canListUsers);
  const canListGroups = Boolean(scene?.canListGroups);
  const canReadAccounts = Boolean(scene?.canReadAccounts);
  const canCreateAccounts = Boolean(scene?.canCreateAccounts);
  const canViewPolicies = Boolean(scene?.canViewPolicies);
  const hasPreviewWorkspace = Boolean(repository.workspace);
  // Navigation observes permission changes, not every form's pending/error state.
  const capabilities = useMemo(() => ({ canListUsers, canListGroups, canReadAccounts, canCreateAccounts, canViewPolicies, hasPreviewWorkspace }), [canCreateAccounts, canListGroups, canListUsers, canReadAccounts, canViewPolicies, hasPreviewWorkspace]);

  useEffect(() => {
    if (!active || !credential || !tenantId) return;
    let mounted = true;
    directoryRequest.current.users += 1;
    directoryRequest.current.accounts += 1;
    async function read() {
      const identity = await repository.currentIdentity(credential!);
      if (identity.account.id !== tenantId || identity.user.id !== principalId) throw new Error("INVALID_IAM_IDENTITY");
      const currentCapability = (action: Parameters<typeof findActionCapability>[1], id = identity.account.id) =>
        findActionCapability(identity.capabilities, action, "ACCOUNT", id)?.available === true;
      const [users, accounts, tenantPolicies, platformPolicies] = await Promise.all([
        currentCapability("iam.user.list") ? readWhenAuthorized(() => repository.listUsers(credential!)) : null,
        currentCapability("iam.account.read", "collection") ? readWhenAuthorized(() => repository.listAccounts(credential!)) : null,
        currentCapability("iam.policy.list") ? readWhenAuthorized(() => repository.listPolicies(credential!, false)) : null,
        readWhenAuthorized(() => repository.listPolicies(credential!, true))
      ]);
      // The advanced workspace is an explicit preview capability. Do not fetch its
      // larger graph unless the live directory boundary has authorized management.
      const extension = users !== null && repository.workspace ? await repository.workspace.read(credential!) : null;
      if (users?.items.some((entry) => entry.user.accountId !== tenantId || entry.user.id === identity.account.rootIdentity.principalId)) throw new Error("INVALID_IAM_TENANT");
      if (tenantPolicies && tenantPolicies.accountId !== tenantId) throw new Error("INVALID_IAM_TENANT");
      if (platformPolicies && platformPolicies.accountId !== tenantId) throw new Error("INVALID_IAM_TENANT");
      if (extension && (extension.accountId !== tenantId || extension.mode !== "preview")) throw new Error("INVALID_IAM_TENANT");
      return { scene: buildAccountAccessScene(identity, users, accounts, tenantPolicies, platformPolicies), extension };
    }
    read().then((loaded) => { if (mounted) { setScene(loaded.scene); setWorkspace(loaded.extension); setError(null); } },
      (failure: unknown) => { if (mounted) { setScene(null); setWorkspace(null); setError(accountError(failure)); } })
      .finally(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, [active, credential, principalId, repository, revision, tenantId]);

  const loadUser = useCallback(async (userId: string): Promise<AccountUserScene> => {
    if (!active || !credential || !scene || !userId || userId === scene.accountOwner.id) throw new Error("INVALID_IAM_USER_TARGET");
    const access = await repository.getUser(credential, userId);
    if (access.user.id !== userId || access.user.accountId !== tenantId) throw new Error("INVALID_IAM_TENANT");
    return buildAccountUserScene({ id: scene.accountId, loginAlias: scene.loginAlias }, scene.policies, access);
  }, [active, credential, repository, scene, tenantId]);

  const groups = useMemo<GroupAccessClient | null>(() => {
    if (!active || !credential || !scene || scene.accountId !== tenantId) return null;
    const accountId = scene.accountId;
    return {
      accountId,
      canList: scene.canListGroups,
      listRestrictionReason: scene.listGroupsRestrictionReason,
      canCreate: scene.canCreateGroups,
      createRestrictionReason: scene.createGroupsRestrictionReason,
      list: (after) => repository.listGroups(credential, accountId, after),
      get: (groupId) => repository.getGroup(credential, accountId, groupId),
      create: (command) => protectedMutation(() => repository.createGroup(credential, accountId, command)),
      update: (groupId, command) => protectedMutation(() => repository.updateGroup(credential, accountId, groupId, command)),
      delete: (groupId, command) => protectedMutation(() => repository.deleteGroup(credential, accountId, groupId, command)),
      listMemberships: (groupId, after) => repository.listGroupMemberships(credential, accountId, groupId, after),
      createMembership: (groupId, command) => protectedMutation(() => repository.createGroupMembership(credential, accountId, groupId, command)),
      removeMembership: (groupId, membershipId, command) => protectedMutation(() => repository.removeGroupMembership(credential, accountId, groupId, membershipId, command)),
      createPolicyAttachment: (groupId, command) => protectedMutation(() => repository.createGroupPolicyAttachment(credential, accountId, groupId, command)),
      revokePolicyAttachment: (attachmentId, command) => protectedMutation(() => repository.revokePolicyAttachment(credential, attachmentId, command))
    };
  }, [active, credential, protectedMutation, repository, scene, tenantId]);

  const permissionBoundaries = useMemo<UserBoundaryClient | null>(() => {
    const boundaryRepository = repository.permissionBoundaries;
    if (!active || !credential || !scene || scene.accountId !== tenantId || !boundaryRepository) return null;
    const accountId = scene.accountId;
    const target = (userId: string) => {
      if (!userId || userId === scene.accountOwner.id) throw new Error("INVALID_IAM_USER_TARGET");
      return userId;
    };
    const scoped = async <T,>(request: Promise<T>): Promise<T> => {
      try { return await request; }
      catch (failure) {
        if (failure instanceof HttpProblem && failure.status === 401 && expireSession(credential)) {
          setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
        }
        throw failure;
      }
    };
    return {
      accountId,
      load: (userId) => scoped((async () => {
        const access = await repository.getUser(credential, target(userId));
        if (access.user.id !== userId || access.user.accountId !== accountId) throw new Error("INVALID_IAM_TENANT");
        const boundary = await boundaryRepository.read(credential, accountId, userId);
        if (boundary.accountId !== accountId || boundary.userId !== userId) throw new Error("INVALID_IAM_TENANT");
        if (boundary.resourceVersion !== access.user.resourceVersion) throw new HttpProblem(409, "IAM_USER_REVISION_CHANGED");
        const directory = scene.tenantPoliciesAvailable ? await readWhenAuthorized(() => repository.listPolicies(credential, false)) : null;
        if (directory && (directory.accountId !== accountId || directory.scope !== "TENANT")) throw new Error("INVALID_IAM_TENANT");
        const policies = directory?.items ?? [];
        return { user: buildAccountUserScene({ id: accountId, loginAlias: scene.loginAlias }, policies, access), boundary, policies, policiesAvailable: directory !== null };
      })()),
      set: (userId, command) => protectedMutation(() => scoped(boundaryRepository.set(credential, accountId, target(userId), command))),
      remove: (userId, command) => protectedMutation(() => scoped(boundaryRepository.remove(credential, accountId, target(userId), command)))
    };
  }, [active, credential, expireSession, protectedMutation, repository, scene, tenantId]);

  const authorizationProfiles = useMemo<AuthorizationProfileClient | null>(() => {
    if (!active || !credential || !scene || scene.accountId !== tenantId || !scene.canViewPolicies) return null;
    const accountId = scene.accountId;
    return {
      accountId,
      preview: Boolean(repository.workspace),
      async load() {
        try {
          const directory = await repository.listAuthorizationProfiles(credential);
          if (directory.accountId !== accountId) throw new Error("INVALID_IAM_TENANT");
          return { status: "ready", directory };
        } catch (failure) {
          if (failure instanceof HttpProblem) {
            if (failure.status === 401) {
              if (expireSession(credential)) {
                setScene(null); setWorkspace(null); setWorkspaceError(null); setSuccess(null); setError("expired");
              }
              return { status: "expired" };
            }
            if (failure.status === 403) return { status: "forbidden" };
            if (failure.status === 404) return { status: "routeUnavailable" };
          }
          return { status: "unavailable" };
        }
      }
    };
  }, [active, credential, expireSession, repository, scene, tenantId]);

  const loadUsersPage = useCallback(async (after: string) => {
    if (!active || !credential || !scene || loading || mutationPending.current) return;
    const source = scene;
    const request = ++directoryRequest.current.users;
    setLoading(true); setError(null); setSuccess(null);
    try {
      const users = await repository.listUsers(credential, after || undefined);
      if (request !== directoryRequest.current.users) return;
      if (users.items.some((entry) => entry.user.accountId !== tenantId || entry.user.id === source.accountOwner.id)) throw new Error("INVALID_IAM_TENANT");
      const items = users.items.map((entry) => buildAccountUserScene({ id: source.accountId, loginAlias: source.loginAlias }, source.policies, entry));
      setScene((current) => current?.accountId === source.accountId ? {
        ...current,
        users: items,
        nextUserPage: users.nextAfter,
        directoryComplete: !after && !users.nextAfter
      } : current);
    } catch (failure) {
      if (request === directoryRequest.current.users) setError(accountError(failure));
    } finally {
      if (request === directoryRequest.current.users) setLoading(false);
    }
  }, [active, credential, loading, repository, scene, tenantId]);

  const loadAccountsPage = useCallback(async (after: string) => {
    if (!active || !credential || !scene || loading || mutationPending.current) return;
    const source = scene;
    const request = ++directoryRequest.current.accounts;
    setLoading(true); setError(null); setSuccess(null);
    try {
      const accounts = await repository.listAccounts(credential, after || undefined);
      if (request !== directoryRequest.current.accounts) return;
      setScene((current) => current?.accountId === source.accountId ? {
        ...current,
        accounts: accounts.items.map(buildAccountTenantScene),
        nextAccountPage: accounts.nextAfter
      } : current);
    } catch (failure) {
      if (request === directoryRequest.current.accounts) setError(accountError(failure));
    } finally {
      if (request === directoryRequest.current.accounts) setLoading(false);
    }
  }, [active, credential, loading, repository, scene]);

  const value = useMemo<AccountAccess>(() => ({
    supportsUserBatch: Boolean(repository.executeUserBatch),
    async executeUserBatch(command) {
      if (!active || !credential || !scene || !workspace || !repository.executeUserBatch || loading || mutationPending.current) return false;
      if (workspace.personalMfa.reauthenticationRequired) { setWorkspaceError("reauthenticationRequired"); return false; }
      const targets = command.targets.map((target) => {
        const user = scene.users.find((entry) => entry.id === target.id);
        return {
          id: target.id,
          enabled: target.id === scene.accountOwner.id ? null : user?.enabled ?? null,
          canSetStatus: user?.canSetStatus ?? false,
          canAttachPolicy: user?.canAttachTenantPolicy ?? false,
          protected: user?.protected ?? true
        };
      });
      const unavailable = command.targets.some((target) => target.id !== scene.accountOwner.id && !scene.users.some((user) => user.id === target.id && user.resourceVersion === target.resourceVersion));
      if (unavailable || userBatchDisabledReason(command.action, { targets, rootId: scene.accountOwner.id, actorId: scene.currentUserId, canListUsers: scene.canListUsers, supported: true })) { setWorkspaceError("ineligibleUsers"); return false; }
      mutationPending.current = true;
      setBusy(true); setWorkspaceError(null); setSuccess(null);
      try {
        const result = await repository.executeUserBatch(credential, command);
        if (result.workspace.accountId !== tenantId || result.workspace.mode !== "preview") throw new Error("INVALID_IAM_TENANT");
        setWorkspace(result.workspace); setSuccess("completed");
        setLoading(true); setRevision((current) => current + 1);
        return true;
      } catch (failure) { setWorkspaceError(failure instanceof AccessWorkspaceError ? failure.code : accountError(failure)); return false; }
      finally { mutationPending.current = false; setBusy(false); }
    },
    policyDirectoryView,
    userDirectoryView,
    groups,
    permissionBoundaries,
    authorizationProfiles,
    workspace, workspaceError,
    clearWorkspaceError, clearFeedback,
    async executeWorkspace(command, onError) {
      if (!active || !credential || !scene?.canListUsers || !repository.workspace || loading || mutationPending.current) return null;
      if (workspace?.personalMfa.reauthenticationRequired) { setWorkspaceError("reauthenticationRequired"); return null; }
      if ("principalId" in command && command.principalId === scene.accountOwner.id) { setWorkspaceError("forbidden"); return null; }
      mutationPending.current = true;
      setBusy(true); setWorkspaceError(null); setSuccess(null);
      try {
        const result = await repository.workspace.execute(credential, command);
        if (result.workspace.accountId !== tenantId || result.workspace.mode !== "preview") throw new Error("INVALID_IAM_TENANT");
        setWorkspace(result.workspace);
        if (command.kind === "create-subuser" || command.kind === "delete-user" || command.kind === "update-user" || command.kind === "import-enterprise-members") { setLoading(true); setRevision((current) => current + 1); }
        if (!(command.kind === "save-account-rule" && command.responseMode === "response-lost")) {
          setSuccess("completed");
        }
        return { issuedKey: result.issuedKey };
      } catch (failure) {
        const code = failure instanceof AccessWorkspaceError ? failure.code : accountError(failure);
        setWorkspaceError(code);
        onError?.(code);
        return null;
      } finally { mutationPending.current = false; setBusy(false); }
    },
    scene, loading, busy, error, success,
    reload() { directoryRequest.current.users += 1; directoryRequest.current.accounts += 1; setLoading(true); setRevision((current) => current + 1); },
    usersPage(after) { void loadUsersPage(after); },
    accountsPage(after) { void loadAccountsPage(after); },
    loadUser,
    async execute(command) {
      if (!active || !credential || loading || mutationPending.current) return false;
      if (workspace?.personalMfa.reauthenticationRequired) { setWorkspaceError("reauthenticationRequired"); return false; }
      if (!scene || !accountCommandAvailable(scene, command)) { setError("forbidden"); return false; }
      mutationPending.current = true;
      setBusy(true); setError(null); setSuccess(null);
      try {
        await repository.execute(credential, command);
        setSuccess("completed");
        setLoading(true); setRevision((current) => current + 1);
        return true;
      } catch (failure) { setError(accountError(failure)); return false; }
      finally { mutationPending.current = false; setBusy(false); }
    }
  }), [active, busy, credential, error, loading, repository, scene, success, tenantId, workspace, workspaceError, clearWorkspaceError, clearFeedback, groups, permissionBoundaries, authorizationProfiles, loadUser, loadUsersPage, loadAccountsPage, policyDirectoryView, userDirectoryView]);

  return <AccountCapabilitiesContext.Provider value={capabilities}>
    <AccountAccessContext.Provider value={value}>{children}</AccountAccessContext.Provider>
  </AccountCapabilitiesContext.Provider>;
}

export function useAccountCapabilities(): AccountCapabilities {
  const value = useContext(AccountCapabilitiesContext);
  if (!value) throw new Error("useAccountCapabilities must be used inside AccountAccessProvider");
  return value;
}

export function useAccountAccess(): AccountAccess {
  const value = useContext(AccountAccessContext);
  if (!value) throw new Error("useAccountAccess must be used inside AccountAccessProvider");
  return value;
}
