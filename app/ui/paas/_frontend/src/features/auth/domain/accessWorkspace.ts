import { parsePolicyDocument, type PolicyDocument } from "./policyDocument";
import { AccessWorkspaceError } from "./accessWorkspaceError";
import { validateRoleTrust, type RoleSessionCaller } from "./roleTrust";
import { evaluateRoleAssumption, type AccessTestRequest } from "./policyEvaluation";

// Preview-only configuration. The diagnostic evaluator never replaces live IAM.
export type AccessPolicy = {
  id: string; name: string; description: string; kind: "system" | "custom";
  tags: { key: string; value: string }[];
  // Directory metadata only; never an input to authorization evaluation.
  systemCategory?: "global" | "product";
  versions: { id: number; document: PolicyDocument; createdAt: string }[];
  defaultVersion: number; lastVersion: number; createdAt: string; updatedAt: string;
};
export type PolicyTargets = { userIds: string[]; groupIds: string[]; roleIds: string[] };
export type AccessGroup = { id: string; name: string; description: string; memberIds: string[]; policyIds: string[]; createdAt: string };
export type AccessRole = {
  id: string; name: string; description: string; principalType: "account" | "service" | "provider";
  principal: string; trustedUserIds: string[]; policyIds: string[]; boundaryPolicyId?: string;
  tags: { key: string; value: string }[]; sessionMinutes: number; consoleAccess: boolean; createdAt: string;
};
export type AccessRoleSession = { id: string; roleId: string; caller: RoleSessionCaller; createdAt: string; expiresAt: string; revokedAt?: string };
export type IdentityProvider = {
  id: string; name: string; protocol: "SAML" | "OIDC"; issuer: string; audience: string;
  metadata: string; enabled: boolean; createdAt: string;
};
export type FederatedAccount = { id: string; name: string; subject: string; providerId: string; roleId: string; enabled: boolean; createdAt: string };
export type AccessKey = { id: string; ownerId: string; description: string; enabled: boolean; createdAt: string; lastUsedAt: string | null };
export type EnterpriseMember = { id: string; name: string; department: string };
export type EnterpriseAccount = { id: string; name: string; corporationId: string; visibleMemberIds: string[]; importedMemberIds: string[]; createdAt: string };
export function enterprisePrincipalId(accountId: string, memberId: string): string { return "principal-wecom-" + accountId + "-" + memberId; }
export type AccessSettings = {
  passwordMinLength: number; passwordExpiryDays: number; preventPasswordReuse: number;
  requireComplexity: boolean; sessionMinutes: number; loginProtection: boolean; sensitiveProtection: boolean;
  userSsoEnabled: boolean; userSsoProviderId: string;
};
export type AccessEvent = { id: string; action: AccessWorkspaceCommand["kind"] | "sign-in" | "batch-users"; target: string; at: string };
export type PreviewUserProfile = {
  consoleAccess: boolean; programmaticAccess: boolean; passwordResetRequired: boolean;
  loginProtection: boolean; tags: { key: string; value: string }[];
};
export function previewUserPrincipalId(loginName: string): string { return `principal-${loginName}`; }
export type AccessWorkspace = {
  mode: "preview"; accountId: string; groups: AccessGroup[]; policies: AccessPolicy[];
  roles: AccessRole[]; providers: IdentityProvider[]; federations: FederatedAccount[]; keys: AccessKey[];
  userPolicies: Record<string, string[]>; settings: AccessSettings; events: AccessEvent[];
  enterprises: EnterpriseAccount[]; enterpriseMembers: EnterpriseMember[];
  userProfiles: Record<string, PreviewUserProfile>;
  userBoundaries: Record<string, string>; roleSessions: AccessRoleSession[];
  testResources: { id: string; reference: string; tags?: Record<string, string> }[];
  // Synthetic diagnostic inputs, not canned decisions or authorization rules.
  testRequests: { id: "path" | "duplicate" | "tags" | "deny" | "boundary" | "ungranted"; request: AccessTestRequest }[];
};
export type AccessWorkspaceCommand =
  | { kind: "create-subuser"; loginName: string; displayName: string; profile: PreviewUserProfile; policyIds: string[]; groupIds: string[] }
  | { kind: "create-group"; name: string; description: string; policyIds: string[] }
  | { kind: "update-group"; id: string; name: string; description: string }
  | { kind: "change-group-members"; id: string; added: string[]; removed: string[] }
  | { kind: "change-group-policies"; id: string; added: string[]; removed: string[] }
  | { kind: "delete-group"; id: string }
  | { kind: "save-policy"; id?: string; name: string; description: string; document: PolicyDocument; tags?: AccessPolicy["tags"]; targets?: PolicyTargets; replaceVersion?: number }
  | { kind: "update-policy-description"; id: string; description: string }
  | { kind: "set-policy-version"; id: string; version: number }
  | { kind: "delete-policy-version"; id: string; version: number }
  | { kind: "delete-policy"; id: string }
  | { kind: "associate-policy"; id: string; userIds: string[]; groupIds: string[]; roleIds: string[] }
  | { kind: "attach-policies"; policyIds: string[]; targets: PolicyTargets }
  | { kind: "create-role"; name: string; description: string; principalType: AccessRole["principalType"]; principal: string; trustedUserIds: string[]; policyIds: string[]; boundaryPolicyId?: string; tags: AccessRole["tags"]; sessionMinutes: number; consoleAccess: boolean }
  | { kind: "update-role-metadata"; id: string; description: string; tags: AccessRole["tags"] }
  | { kind: "update-role-trust"; id: string; principal: string; trustedUserIds: string[] }
  | { kind: "update-role-settings"; id: string; sessionMinutes: number; consoleAccess: boolean }
  | { kind: "change-role-policies"; id: string; added: string[]; removed: string[] }
  | { kind: "set-role-boundary"; id: string; policyId?: string }
  | { kind: "set-user-boundary"; principalId: string; policyId?: string }
  | { kind: "create-role-session"; roleId: string; caller: RoleSessionCaller; sessionMinutes: number; sourceIp?: string }
  | { kind: "revoke-role-session"; id: string }
  | { kind: "delete-role"; id: string }
  | { kind: "save-provider"; id?: string; name: string; protocol: IdentityProvider["protocol"]; issuer: string; audience: string; metadata: string; enabled: boolean }
  | { kind: "delete-provider"; id: string }
  | { kind: "save-federation"; id?: string; name: string; subject: string; providerId: string; roleId: string; enabled: boolean }
  | { kind: "delete-federation"; id: string }
  | { kind: "create-key"; ownerId: string; description: string }
  | { kind: "set-key-status"; id: string; enabled: boolean }
  | { kind: "delete-key"; id: string }
  | { kind: "set-user-policies"; principalId: string; policyIds: string[] }
  | { kind: "set-user-groups"; principalId: string; groupIds: string[] }
  | { kind: "update-user"; principalId: string; displayName: string }
  | { kind: "delete-user"; principalId: string }
  | { kind: "save-enterprise"; id?: string; name: string; corporationId: string; visibleMemberIds: string[] }
  | { kind: "delete-enterprise"; id: string }
  | { kind: "import-enterprise-members"; id: string; memberIds: string[] }
  | { kind: "save-settings"; settings: AccessSettings };

export const policyVersionLimit = 5;

export function policyGrantTargets(state: AccessWorkspace, policyId: string): PolicyTargets {
  return {
    userIds: Object.entries(state.userPolicies).filter(([, ids]) => ids.includes(policyId)).map(([id]) => id),
    groupIds: state.groups.filter((group) => group.policyIds.includes(policyId)).map((group) => group.id),
    roleIds: state.roles.filter((role) => role.policyIds.includes(policyId)).map((role) => role.id)
  };
}

export function policyBoundaryTargets(state: AccessWorkspace, policyId: string) {
  return {
    userIds: Object.entries(state.userBoundaries).filter(([, id]) => id === policyId).map(([id]) => id),
    roleIds: state.roles.filter((role) => role.boundaryPolicyId === policyId).map((role) => role.id)
  };
}

export function policyUsageCounts(state: AccessWorkspace, policyId: string) {
  const grants = policyGrantTargets(state, policyId);
  const boundaries = policyBoundaryTargets(state, policyId);
  const permissionAttachments = grants.userIds.length + grants.groupIds.length + grants.roleIds.length;
  const permissionBoundaries = boundaries.userIds.length + boundaries.roleIds.length;
  return { permissionAttachments, permissionBoundaries, total: permissionAttachments + permissionBoundaries };
}

// Shared single/bulk cleanup, after the caller validates identity and authority.
// One clone and one pass per collection, regardless of selected user count.
export function withoutUserAccess(source: AccessWorkspace, principalIds: readonly string[], at: string): AccessWorkspace {
  const state = structuredClone(source);
  const ids = new Set(principalIds);
  for (const group of state.groups) group.memberIds = group.memberIds.filter((id) => !ids.has(id));
  for (const id of ids) { delete state.userPolicies[id]; delete state.userProfiles[id]; delete state.userBoundaries[id]; }
  for (const role of state.roles) role.trustedUserIds = role.trustedUserIds.filter((id) => !ids.has(id));
  for (const session of state.roleSessions) if (session.caller.type === "user" && ids.has(session.caller.id) && !session.revokedAt) session.revokedAt = at;
  state.keys = state.keys.filter((key) => !ids.has(key.ownerId));
  for (const enterprise of state.enterprises) enterprise.importedMemberIds = enterprise.importedMemberIds.filter((member) => !ids.has(enterprisePrincipalId(enterprise.id, member)));
  return state;
}

// Pure, deterministic preview transitions. Adapters supply identity, IDs and time.
export function applyAccessWorkspaceCommand(source: AccessWorkspace, command: AccessWorkspaceCommand, context: { id: string; at: string; userIds: string[]; primaryPrincipalId: string }): AccessWorkspace {
  const state = command.kind === "delete-user" ? withoutUserAccess(source, [command.principalId], context.at) : structuredClone(source);
  const invalid = () => { throw new AccessWorkspaceError("invalid"); };
  // Only membership accepts the owner. Child grants, keys and lifecycle stay
  // constrained to child identities, even if an adapter supplies a bad list.
  if (!context.primaryPrincipalId || context.userIds.includes(context.primaryPrincipalId)) invalid();
  const canJoinGroup = (principalId: string) => principalId === context.primaryPrincipalId || context.userIds.includes(principalId);
  const exists = <T extends { id: string }>(items: T[], id: string): T => {
    const item = items.find((entry) => entry.id === id);
    if (!item) throw new AccessWorkspaceError("notFound");
    return item;
  };
  const validateName = (items: { id: string; name: string }[], name: string, id?: string) => {
    if (!name.trim() || name.length > 64 || /[<>\u0000-\u001f]/.test(name)) invalid();
    if (items.some((entry) => entry.id !== id && entry.name.toLowerCase() === name.trim().toLowerCase())) throw new AccessWorkspaceError("duplicate");
    if (id) exists(items, id);
  };
  const policies = (ids: string[]) => { ids.forEach((id) => exists(state.policies, id)); return [...new Set(ids)]; };
  const roleSettings = (minutes: number, consoleAccess: boolean, type: AccessRole["principalType"]) => {
    if (!Number.isInteger(minutes) || minutes < 15 || minutes > 720 || (type === "service" && consoleAccess)) invalid();
  };
  const roleMetadata = (description: string, tags: AccessRole["tags"]) => {
    if (description.length > 256 || tags.length > 10 || tags.some((tag) => !tag.key.trim() || tag.key.length > 64 || tag.value.length > 128 || /[<>\u0000-\u001f]/.test(tag.key + tag.value)) || new Set(tags.map((tag) => tag.key.trim())).size !== tags.length) invalid();
    return tags.map((tag) => ({ key: tag.key.trim(), value: tag.value }));
  };
  const associatePolicy = (policyId: string, targets: PolicyTargets) => {
    if ([targets.userIds, targets.groupIds, targets.roleIds].some((ids) => ids.length > 30)) invalid();
    if (targets.userIds.some((user) => !context.userIds.includes(user))) invalid();
    targets.groupIds.forEach((group) => exists(state.groups, group));
    targets.roleIds.forEach((role) => exists(state.roles, role));
    const update = (ids: string[], selected: boolean) => selected ? [...new Set([...ids, policyId])] : ids.filter((policy) => policy !== policyId);
    for (const user of context.userIds) if (state.userPolicies[user] || targets.userIds.includes(user)) state.userPolicies[user] = update(state.userPolicies[user] ?? [], targets.userIds.includes(user));
    for (const group of state.groups) group.policyIds = update(group.policyIds, targets.groupIds.includes(group.id));
    for (const role of state.roles) role.policyIds = update(role.policyIds, targets.roleIds.includes(role.id));
  };
  const put = <T extends { id: string }>(items: T[], value: T) => [...items.filter((entry) => entry.id !== value.id), value];
  const id = "id" in command && command.id ? command.id : context.id;
  const createdAt = context.at;
  let target = id;
  switch (command.kind) {
    case "create-subuser": {
      const principalId = previewUserPrincipalId(command.loginName);
      const profile = command.profile;
      if (!/^[a-z][a-z0-9._-]{2,63}$/.test(command.loginName) || !command.displayName.trim() || command.displayName.length > 128 ||
        (!profile.consoleAccess && !profile.programmaticAccess) || profile.tags.length > 10 ||
        profile.tags.some((tag) => !tag.key.trim() || tag.key.length > 64 || tag.value.length > 128 || /[<>\u0000-\u001f]/.test(tag.key + tag.value)) ||
        new Set(profile.tags.map((tag) => tag.key.trim())).size !== profile.tags.length || command.policyIds.length > 30 || command.groupIds.length > 30) invalid();
      if (principalId === context.primaryPrincipalId || context.userIds.includes(principalId) || state.userProfiles[principalId]) throw new AccessWorkspaceError("duplicate");
      const selectedPolicies = policies(command.policyIds);
      command.groupIds.forEach((group) => exists(state.groups, group));
      state.userProfiles[principalId] = { consoleAccess: profile.consoleAccess, programmaticAccess: profile.programmaticAccess, passwordResetRequired: profile.consoleAccess && profile.passwordResetRequired, loginProtection: profile.consoleAccess && profile.loginProtection, tags: profile.tags.map((tag) => ({ key: tag.key.trim(), value: tag.value.trim() })) };
      state.userPolicies[principalId] = selectedPolicies;
      for (const group of state.groups) if (command.groupIds.includes(group.id)) group.memberIds.push(principalId);
      target = principalId; break;
    }
    case "create-group": {
      validateName(state.groups, command.name);
      if (command.description.length > 256 || command.policyIds.length > 30) invalid();
      state.groups.push({ id, name: command.name.trim(), description: command.description, memberIds: [], policyIds: policies(command.policyIds), createdAt });
      target = command.name; break;
    }
    case "update-group": {
      validateName(state.groups, command.name, id);
      if (command.description.length > 256) invalid();
      const group = exists(state.groups, id);
      group.name = command.name.trim(); group.description = command.description;
      target = group.name; break;
    }
    case "change-group-members": {
      const group = exists(state.groups, id);
      if (command.added.length + command.removed.length > 30 || command.added.some((member) => !canJoinGroup(member) || command.removed.includes(member)) || command.removed.some((member) => !group.memberIds.includes(member))) invalid();
      group.memberIds = [...new Set([...group.memberIds.filter((member) => !command.removed.includes(member)), ...command.added])]; target = group.name; break;
    }
    case "change-group-policies": {
      const group = exists(state.groups, id);
      if (command.added.length + command.removed.length > 30 || command.added.some((policy) => command.removed.includes(policy)) || command.removed.some((policy) => !group.policyIds.includes(policy))) invalid();
      group.policyIds = [...new Set([...group.policyIds.filter((policy) => !command.removed.includes(policy)), ...policies(command.added)])]; target = group.name; break;
    }
    case "delete-group":
      exists(state.groups, id); state.groups = state.groups.filter((entry) => entry.id !== id); break;
    case "save-policy": {
      validateName(state.policies, command.name, command.id);
      const previous = state.policies.find((entry) => entry.id === id);
      if (previous?.kind === "system") throw new AccessWorkspaceError("systemPolicy");
      if (previous && command.name.trim() !== previous.name) throw new AccessWorkspaceError("immutablePolicyName");
      if (command.description.length > 256) invalid();
      const document = parsePolicyDocument(JSON.stringify(command.document), state.accountId);
      const tags = command.tags ?? previous?.tags ?? [];
      if (tags.length > 10 || tags.some((tag) => !tag.key.trim() || tag.key.length > 64 || tag.value.length > 128 || /[<>\u0000-\u001f]/.test(tag.key + tag.value)) || new Set(tags.map((tag) => tag.key.trim())).size !== tags.length) invalid();
      const normalizedTags = tags.map((tag) => ({ key: tag.key.trim(), value: tag.value.trim() }));
      const current = previous?.versions.find((entry) => entry.id === previous.defaultVersion);
      if (previous && current && JSON.stringify(current.document) === JSON.stringify(document)) {
        if (command.replaceVersion !== undefined) invalid();
        if (previous.description !== command.description || JSON.stringify(previous.tags) !== JSON.stringify(normalizedTags)) previous.updatedAt = context.at;
        previous.description = command.description;
        previous.tags = normalizedTags;
      } else {
        let history = previous?.versions ?? [];
        if (command.replaceVersion !== undefined) {
          if (!previous || history.length !== policyVersionLimit) invalid();
          if (command.replaceVersion === previous!.defaultVersion) throw new AccessWorkspaceError("defaultVersion");
          if (!history.some((entry) => entry.id === command.replaceVersion)) throw new AccessWorkspaceError("notFound");
          history = history.filter((entry) => entry.id !== command.replaceVersion);
        }
        if (history.length >= policyVersionLimit) throw new AccessWorkspaceError("versionLimit");
        // The high-water mark survives removal, so identifiers are never reused.
        const version = (previous?.lastVersion ?? 0) + 1;
        state.policies = put(state.policies, { id, name: command.name.trim(), description: command.description, tags: normalizedTags, kind: "custom", versions: [...history, { id: version, document, createdAt }], defaultVersion: version, lastVersion: version, createdAt: previous?.createdAt ?? createdAt, updatedAt: context.at });
      }
      if (command.targets) associatePolicy(id, command.targets);
      target = command.name; break;
    }
    case "update-policy-description": {
      const policy = exists(state.policies, id);
      if (policy.kind === "system") throw new AccessWorkspaceError("systemPolicy");
      if (command.description.length > 256) invalid();
      if (policy.description !== command.description) policy.updatedAt = context.at;
      policy.description = command.description;
      target = policy.name; break;
    }
    case "set-policy-version": {
      const policy = exists(state.policies, id);
      if (policy.kind === "system") throw new AccessWorkspaceError("systemPolicy");
      if (!policy.versions.some((entry) => entry.id === command.version)) invalid();
      if (policy.defaultVersion !== command.version) policy.updatedAt = context.at;
      policy.defaultVersion = command.version; break;
    }
    case "delete-policy-version": {
      const policy = exists(state.policies, id);
      if (policy.kind === "system") throw new AccessWorkspaceError("systemPolicy");
      if (!policy.versions.some((entry) => entry.id === command.version)) throw new AccessWorkspaceError("notFound");
      if (policy.defaultVersion === command.version) throw new AccessWorkspaceError("defaultVersion");
      policy.versions = policy.versions.filter((entry) => entry.id !== command.version);
      policy.updatedAt = context.at;
      target = policy.name; break;
    }
    case "delete-policy":
      if (exists(state.policies, id).kind === "system") throw new AccessWorkspaceError("systemPolicy");
      if (policyUsageCounts(state, id).total) throw new AccessWorkspaceError("referenced");
      state.policies = state.policies.filter((entry) => entry.id !== id); break;
    case "associate-policy": {
      exists(state.policies, id);
      associatePolicy(id, command);
      break;
    }
    case "attach-policies": {
      const selected = command.targets;
      if (!command.policyIds.length || command.policyIds.length > 30 || ![...selected.userIds, ...selected.groupIds, ...selected.roleIds].length ||
        [selected.userIds, selected.groupIds, selected.roleIds].some((ids) => ids.length > 30) || selected.userIds.some((user) => !context.userIds.includes(user))) invalid();
      const grants = policies(command.policyIds);
      selected.groupIds.forEach((group) => exists(state.groups, group));
      selected.roleIds.forEach((role) => exists(state.roles, role));
      // Additive batch, validated before mutation; clone is committed atomically
      // by the repository. Existing grants and boundaries are never replaced.
      for (const user of selected.userIds) state.userPolicies[user] = [...new Set([...(state.userPolicies[user] ?? []), ...grants])];
      for (const group of state.groups) if (selected.groupIds.includes(group.id)) group.policyIds = [...new Set([...group.policyIds, ...grants])];
      for (const role of state.roles) if (selected.roleIds.includes(role.id)) role.policyIds = [...new Set([...role.policyIds, ...grants])];
      target = grants.map((id) => exists(state.policies, id).name).join(", "); break;
    }
    case "create-role": {
      validateName(state.roles, command.name);
      validateRoleTrust(state, command, context.userIds);
      roleSettings(command.sessionMinutes, command.consoleAccess, command.principalType);
      if (command.policyIds.length > 30) invalid();
      if (command.boundaryPolicyId) exists(state.policies, command.boundaryPolicyId);
      state.roles.push({ id, name: command.name.trim(), description: command.description, principalType: command.principalType, principal: command.principal, trustedUserIds: [...new Set(command.trustedUserIds)], policyIds: policies(command.policyIds), boundaryPolicyId: command.boundaryPolicyId, tags: roleMetadata(command.description, command.tags), sessionMinutes: command.sessionMinutes, consoleAccess: command.consoleAccess, createdAt });
      target = command.name; break;
    }
    case "update-role-metadata": {
      const role = exists(state.roles, id);
      role.tags = roleMetadata(command.description, command.tags); role.description = command.description; break;
    }
    case "update-role-trust": {
      const role = exists(state.roles, id);
      validateRoleTrust(state, { ...role, ...command }, context.userIds);
      if (state.federations.some((entry) => entry.roleId === id && entry.providerId !== command.principal)) throw new AccessWorkspaceError("referenced");
      role.principal = command.principal; role.trustedUserIds = [...new Set(command.trustedUserIds)]; break;
    }
    case "update-role-settings": {
      const role = exists(state.roles, id);
      roleSettings(command.sessionMinutes, command.consoleAccess, role.principalType);
      role.sessionMinutes = command.sessionMinutes; role.consoleAccess = command.consoleAccess; break;
    }
    case "change-role-policies": {
      const role = exists(state.roles, id);
      if (!command.added.length && !command.removed.length || command.added.length + command.removed.length > 30 || command.added.some((id) => command.removed.includes(id)) || command.removed.some((id) => !role.policyIds.includes(id))) invalid();
      role.policyIds = [...new Set([...role.policyIds.filter((id) => !command.removed.includes(id)), ...policies(command.added)])]; break;
    }
    case "set-role-boundary": {
      const role = exists(state.roles, id);
      if (command.policyId) exists(state.policies, command.policyId);
      role.boundaryPolicyId = command.policyId; break;
    }
    case "set-user-boundary":
      if (!context.userIds.includes(command.principalId)) invalid();
      if (command.policyId) { exists(state.policies, command.policyId); state.userBoundaries[command.principalId] = command.policyId; }
      else delete state.userBoundaries[command.principalId];
      target = command.principalId; break;
    case "create-role-session": {
      const role = exists(state.roles, command.roleId);
      if (!Number.isFinite(Date.parse(context.at)) || !Number.isInteger(command.sessionMinutes) || command.sessionMinutes < 15 || command.sessionMinutes > role.sessionMinutes) invalid();
      const result = evaluateRoleAssumption(state, context.userIds, { roleId: role.id, caller: command.caller, sourceIp: command.sourceIp, at: context.at });
      if (!result.allowed) throw new AccessWorkspaceError(result.reason === "callerDenied" ? "callerDenied" : "trustDenied");
      if (state.roleSessions.filter((session) => !session.revokedAt && Date.parse(session.expiresAt) > Date.parse(context.at)).length >= 100) throw new AccessWorkspaceError("sessionLimit");
      state.roleSessions.push({ id, roleId: role.id, caller: structuredClone(command.caller), createdAt, expiresAt: new Date(Date.parse(context.at) + command.sessionMinutes * 60000).toISOString() });
      target = role.name; break;
    }
    case "revoke-role-session": {
      const session = exists(state.roleSessions, id);
      if (!session.revokedAt) session.revokedAt = context.at;
      break;
    }
    case "delete-role":
      exists(state.roles, id);
      if (state.federations.some((entry) => entry.roleId === id)) throw new AccessWorkspaceError("referenced");
      state.roles = state.roles.filter((entry) => entry.id !== id); break;
    case "save-provider": {
      validateName(state.providers, command.name, command.id);
      if (!command.audience.trim() || !command.metadata.trim() || command.metadata.length > 65536) invalid();
      try { if (new URL(command.issuer).protocol !== "https:") invalid(); } catch { invalid(); }
      if (command.protocol === "OIDC") {
        try { const jwks = JSON.parse(command.metadata); if (!Array.isArray(jwks.keys) || !jwks.keys.length) invalid(); } catch { invalid(); }
      } else if (!/<(?:[\w-]+:)?EntityDescriptor[\s>]/.test(command.metadata)) invalid();
      const previous = state.providers.find((entry) => entry.id === id);
      state.providers = put(state.providers, { ...command, id, name: command.name.trim(), createdAt: previous?.createdAt ?? createdAt });
      target = command.name; break;
    }
    case "delete-provider":
      exists(state.providers, id);
      if (state.roles.some((entry) => entry.principalType === "provider" && entry.principal === id) || state.federations.some((entry) => entry.providerId === id) || (state.settings.userSsoEnabled && state.settings.userSsoProviderId === id)) throw new AccessWorkspaceError("referenced");
      state.providers = state.providers.filter((entry) => entry.id !== id);
      if (state.settings.userSsoProviderId === id) state.settings.userSsoProviderId = "";
      break;
    case "save-federation": {
      validateName(state.federations, command.name, command.id);
      if (!command.subject.trim()) invalid();
      exists(state.providers, command.providerId);
      const role = exists(state.roles, command.roleId);
      if (role.principalType !== "provider" || role.principal !== command.providerId) invalid();
      const previous = state.federations.find((entry) => entry.id === id);
      state.federations = put(state.federations, { ...command, id, name: command.name.trim(), createdAt: previous?.createdAt ?? createdAt });
      target = command.name; break;
    }
    case "delete-federation":
      exists(state.federations, id); state.federations = state.federations.filter((entry) => entry.id !== id); break;
    case "create-key":
      if (!context.userIds.includes(command.ownerId) || state.keys.filter((key) => key.ownerId === command.ownerId).length >= 2) invalid();
      state.keys.push({ id: "MOCK-" + id, ownerId: command.ownerId, description: command.description, enabled: true, createdAt, lastUsedAt: null });
      target = "MOCK-" + id; break;
    case "set-key-status":
      exists(state.keys, id).enabled = command.enabled; break;
    case "delete-key":
      if (exists(state.keys, id).enabled) throw new AccessWorkspaceError("disableFirst");
      state.keys = state.keys.filter((entry) => entry.id !== id); break;
    case "set-user-policies":
      if (!context.userIds.includes(command.principalId)) invalid();
      state.userPolicies[command.principalId] = policies(command.policyIds); target = command.principalId; break;
    case "set-user-groups":
      if (!canJoinGroup(command.principalId) || command.groupIds.length > 30) invalid();
      command.groupIds.forEach((group) => exists(state.groups, group));
      for (const group of state.groups) group.memberIds = command.groupIds.includes(group.id) ? [...new Set([...group.memberIds, command.principalId])] : group.memberIds.filter((user) => user !== command.principalId);
      target = command.principalId; break;
    case "update-user":
      if (!context.userIds.includes(command.principalId) || !command.displayName.trim() || command.displayName.length > 128) invalid();
      target = command.principalId; break;
    case "delete-user":
      if (!context.userIds.includes(command.principalId)) invalid();
      target = command.principalId; break;
    case "save-enterprise": {
      validateName(state.enterprises, command.name, command.id);
      if (!command.corporationId.trim() || command.corporationId.length > 128 || command.visibleMemberIds.some((member) => !state.enterpriseMembers.some((entry) => entry.id === member))) invalid();
      if (state.enterprises.some((entry) => entry.id !== id && entry.corporationId === command.corporationId.trim())) throw new AccessWorkspaceError("duplicate");
      const previous = state.enterprises.find((entry) => entry.id === id);
      state.enterprises = put(state.enterprises, { id, name: command.name.trim(), corporationId: command.corporationId.trim(), visibleMemberIds: [...new Set(command.visibleMemberIds)], importedMemberIds: previous?.importedMemberIds ?? [], createdAt: previous?.createdAt ?? createdAt });
      target = command.name; break;
    }
    case "delete-enterprise":
      if (exists(state.enterprises, id).importedMemberIds.length) throw new AccessWorkspaceError("referenced");
      state.enterprises = state.enterprises.filter((entry) => entry.id !== id); break;
    case "import-enterprise-members": {
      const enterprise = exists(state.enterprises, id);
      if (!command.memberIds.length || command.memberIds.some((member) => !enterprise.visibleMemberIds.includes(member))) invalid();
      enterprise.importedMemberIds = [...new Set([...enterprise.importedMemberIds, ...command.memberIds])];
      target = enterprise.name; break;
    }
    case "save-settings": {
      const s = command.settings;
      if (![s.passwordMinLength, s.passwordExpiryDays, s.preventPasswordReuse, s.sessionMinutes].every(Number.isInteger) || s.passwordMinLength < 12 || s.passwordMinLength > 64 || s.passwordExpiryDays < 0 || s.passwordExpiryDays > 365 || s.preventPasswordReuse < 0 || s.preventPasswordReuse > 24 || s.sessionMinutes < 15 || s.sessionMinutes > 720) invalid();
      if (s.userSsoEnabled && !exists(state.providers, s.userSsoProviderId).enabled) invalid();
      state.settings = { ...s }; target = source.accountId; break;
    }
  }
  state.events = [{ id: context.id, action: command.kind, target, at: context.at }, ...state.events].slice(0, 100);
  return state;
}
