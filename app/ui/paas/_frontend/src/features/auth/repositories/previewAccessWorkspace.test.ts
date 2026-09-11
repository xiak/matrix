import { describe, expect, it } from "vitest";
import { applyAccessWorkspaceCommand, policyUsageCounts } from "../domain/accessWorkspace";
import { analyzePolicyDocument, includesPermissionManagement, parsePolicyDocument, policyStatementKey, resourcesForPolicyActions, summarizePolicyServices, type PolicyDocument } from "../domain/policyDocument";
import { expandPolicyActions, policyActions, policyServices } from "../domain/policyLanguage";
import { createPreviewAccessWorkspace, initialAccessWorkspace } from "./previewAccessWorkspace";
import { previewAccountRepository, previewCredential, previewIamRepository } from "./previewIamRepository";
import type { AccountCommand } from "../domain/accounts";
import type { AccessWorkspaceCommand } from "../domain/accessWorkspace";
import { applyUserBatch, userBatchDisabledReason, userBatchLimit, type UserBatchCommand } from "../domain/userBatch";

const context = { id: "new-id", at: "2026-09-09T02:00:00Z", userIds: ["principal-lin", "principal-chen"], primaryPrincipalId: "principal-admin", canManage: true, canListUsers: true };
const document = parsePolicyDocument('{"version":"1","statement":[{"effect":"allow","action":["logs:read"],"resource":["matrix:logs:org-xiak:*:topic/production/*"]}]}');

describe("atomic user directory batches", () => {
  async function fixture() {
    await previewIamRepository.logout(previewCredential);
    const identity = await previewAccountRepository.currentIdentity(previewCredential);
    const users = (await previewAccountRepository.listUsers(previewCredential)).items;
    const workspace = await previewAccountRepository.workspace!.read(previewCredential);
    return { identity, users, workspace, targets: users.map(({ user }) => ({ id: user.id, resourceVersion: user.resourceVersion })) };
  }
  it("appends user memberships without replacing existing memberships or grants", async () => {
    const f = await fixture();
    const targets = f.targets;
    await previewAccountRepository.executeUserBatch!(previewCredential, { action: "add-groups", targets, groupIds: ["group-delivery"] });
    const after = await previewAccountRepository.workspace!.read(previewCredential);
    expect(after.groups[0]?.memberIds).toEqual(expect.arrayContaining(targets.map((target) => target.id)));
    expect(after.groups[0]?.memberIds).not.toContain(f.identity.account.rootIdentity.principalId);
    expect(after.groups[1]?.memberIds).toEqual(f.workspace.groups[1]?.memberIds);
    expect(after.userPolicies).toEqual(f.workspace.userPolicies);
    expect((await previewAccountRepository.listUsers(previewCredential)).items).toEqual(f.users);
    expect(await previewAccountRepository.currentIdentity(previewCredential)).toEqual(f.identity);
    await previewAccountRepository.executeUserBatch!(previewCredential, { action: "add-groups", targets, groupIds: ["group-delivery"] });
    expect((await previewAccountRepository.workspace!.read(previewCredential)).groups[0]?.memberIds).toHaveLength(targets.length);
  });
  it("appends direct policies without replacing group inheritance or permission boundaries", async () => {
    const f = await fixture();
    f.workspace.userBoundaries["principal-lin"] = "policy-read";
    const result = applyUserBatch(f.workspace, f.users, f.identity, { action: "authorize", targets: f.targets, policyIds: ["policy-read"] }, context);
    expect(result.workspace.userPolicies["principal-lin"]).toEqual(["policy-prod-logs", "policy-read"]);
    expect(result.workspace.userPolicies["principal-chen"]).toEqual(["policy-read"]);
    expect(result.workspace.groups).toEqual(f.workspace.groups);
    expect(result.workspace.userBoundaries).toEqual(f.workspace.userBoundaries);
    expect(f.workspace.userPolicies["principal-chen"]).toBeUndefined();
  });
  it.each(["add-groups", "authorize", "enable", "disable", "delete"] as const)("blocks the entire %s batch when the primary account is selected", async (action) => {
    const f = await fixture();
    const command = { action, targets: [...f.targets, { id: f.identity.account.rootIdentity.principalId, resourceVersion: null }], policyIds: ["policy-read"], groupIds: ["group-delivery"] } as UserBatchCommand;
    await expect(previewAccountRepository.executeUserBatch!(previewCredential, command)).rejects.toThrow("ineligibleUsers");
    expect((await previewAccountRepository.listUsers(previewCredential)).items).toEqual(f.users);
    expect(await previewAccountRepository.workspace!.read(previewCredential)).toEqual(f.workspace);
  });
  it("rejects stale, missing, duplicate and oversized selections before publishing any change", async () => {
    const f = await fixture();
    const selections = [[], [f.targets[0]!, f.targets[0]!], [f.targets[0]!, { id: "foreign-user", resourceVersion: 1 }],
      [f.targets[0]!, { ...f.targets[1]!, resourceVersion: 0 }]];
    for (const targets of selections) await expect(previewAccountRepository.executeUserBatch!(previewCredential, { action: "disable", targets })).rejects.toThrow();
    expect((await previewAccountRepository.listUsers(previewCredential)).items).toEqual(f.users);
    expect(await previewAccountRepository.workspace!.read(previewCredential)).toEqual(f.workspace);
    expect(userBatchDisabledReason("delete", { canListUsers: true, supported: true, rootId: "owner", actorId: "actor", targets: Array.from({ length: userBatchLimit + 1 }, (_, index) => ({ id: String(index), enabled: true, canSetStatus: true, canAttachPolicy: true, protected: false })) })).toBe("limit");
    await expect(previewAccountRepository.executeUserBatch!("wrong-credential", { action: "delete", targets: f.targets })).rejects.toThrow();
  });
  it("guards the current actor, actor authority and mixed states for the whole selection", async () => {
    const f = await fixture();
    const asChild = { ...f.identity, user: f.users[0]!.user, identityKind: "USER" as const };
    for (const action of ["enable", "disable", "delete"] as const) expect(() => applyUserBatch(f.workspace, f.users, asChild, { action, targets: f.targets }, context)).toThrow("ineligibleUsers");
    expect(() => applyUserBatch(f.workspace, f.users, f.identity, { action: "authorize", targets: f.targets, policyIds: ["policy-read"] }, { ...context, canListUsers: false })).toThrow("ineligibleUsers");
    await previewAccountRepository.executeUserBatch!(previewCredential, { action: "disable", targets: [f.targets[0]!] });
    const mixed = (await previewAccountRepository.listUsers(previewCredential)).items;
    const targets = mixed.map(({ user }) => ({ id: user.id, resourceVersion: user.resourceVersion }));
    await expect(previewAccountRepository.executeUserBatch!(previewCredential, { action: "enable", targets })).rejects.toThrow("ineligibleUsers");
    expect((await previewAccountRepository.listUsers(previewCredential)).items).toEqual(mixed);
    await previewAccountRepository.executeUserBatch!(previewCredential, { action: "enable", targets: [targets[0]!] });
    expect((await previewAccountRepository.listUsers(previewCredential)).items.every((entry) => entry.user.status === "ACTIVE")).toBe(true);
  });
  it("honors per-user capabilities before a preview batch changes protected identities", async () => {
    const f = await fixture();
    const protectedUsers = f.users.map((entry, index) => index ? entry : {
      ...entry,
      capabilities: entry.capabilities.map((item) => item.action === "iam.user.set-status" || item.action === "iam.policy-attachment.create" ?
        { ...item, available: false, restrictionReason: "INSTALLATION_AUTHORITY_PROTECTED" as const } : item)
    });
    const target = [f.targets[0]!];
    expect(() => applyUserBatch(f.workspace, protectedUsers, f.identity, { action: "disable", targets: target }, context)).toThrow("ineligibleUsers");
    expect(() => applyUserBatch(f.workspace, protectedUsers, f.identity, { action: "authorize", targets: target, policyIds: ["policy-read"] }, context)).toThrow("ineligibleUsers");
    expect(() => applyUserBatch(f.workspace, protectedUsers, f.identity, { action: "delete", targets: target }, context)).toThrow("ineligibleUsers");
  });
  it("deletes selected identity access and sessions while preserving other identities and cloud inventory", async () => {
    const f = await fixture();
    f.workspace.roles[0]!.trustedUserIds = ["principal-lin", "principal-chen"];
    f.workspace.roleSessions = [{ id: "session-lin", roleId: f.workspace.roles[0]!.id, caller: { type: "user", id: "principal-lin" }, createdAt: context.at, expiresAt: "2099-01-01T00:00:00Z" }];
    const result = applyUserBatch(f.workspace, f.users, f.identity, { action: "delete", targets: [f.targets[0]!] }, context);
    expect(result.users).toEqual(f.users.filter((entry) => entry.user.id !== "principal-lin"));
    expect(result.workspace.groups.flatMap((group) => group.memberIds)).not.toContain("principal-lin");
    expect(result.workspace.keys.some((key) => key.ownerId === "principal-lin")).toBe(false);
    expect(result.workspace.roles[0]!.trustedUserIds).toEqual(["principal-chen"]);
    expect(result.workspace.roleSessions[0]!.revokedAt).toBe(context.at);
    expect(result.workspace.testResources).toEqual(f.workspace.testResources);
    expect(f.workspace.roleSessions[0]!.revokedAt).toBeUndefined();
  });
  it("does not partially append associations when any target would exceed the limit", async () => {
    const f = await fixture();
    const base = f.workspace.groups[0]!;
    f.workspace.groups = Array.from({ length: 30 }, (_, index) => ({ ...base, id: `group-${index}`, memberIds: ["principal-chen"] }));
    f.workspace.groups.push({ ...base, id: "new-group", memberIds: [] });
    const before = structuredClone(f.workspace);
    expect(() => applyUserBatch(f.workspace, f.users, f.identity, { action: "add-groups", targets: f.targets, groupIds: ["new-group"] }, context)).toThrow("associationLimit");
    expect(f.workspace).toEqual(before);
  });
});

describe("policy modification time", () => {
  it("tracks content, metadata and version changes but not grants, no-ops or failed writes", () => {
    let state = initialAccessWorkspace("org-xiak");
    const id = "policy-prod-logs", original = state.policies.find((policy) => policy.id === id)!;
    const policy = () => state.policies.find((policy) => policy.id === id)!;
    state = applyAccessWorkspaceCommand(state, { kind: "update-policy-description", id, description: "Updated" }, context);
    expect(policy().updatedAt).toBe(context.at);
    expect(policy().createdAt).toBe(original.createdAt);
    const later = { ...context, at: "2026-09-10T03:00:00Z" };
    state = applyAccessWorkspaceCommand(state, { kind: "associate-policy", id, userIds: [], groupIds: [], roleIds: [] }, later);
    state = applyAccessWorkspaceCommand(state, { kind: "update-policy-description", id, description: "Updated" }, later);
    expect(policy().updatedAt).toBe(context.at);
    state = applyAccessWorkspaceCommand(state, { kind: "save-policy", id, name: original.name, description: "Updated", document, tags: [{ key: "team", value: "delivery" }] }, later);
    expect(policy().updatedAt).toBe(later.at);
    const rollback = { ...context, at: "2026-09-11T04:00:00Z" };
    state = applyAccessWorkspaceCommand(state, { kind: "set-policy-version", id, version: 1 }, rollback);
    expect(policy().updatedAt).toBe(rollback.at);
    const before = structuredClone(state);
    expect(() => applyAccessWorkspaceCommand(state, { kind: "update-policy-description", id, description: "x".repeat(257) }, context)).toThrow();
    expect(state).toEqual(before);
    expect(state.policies.filter((entry) => entry.kind === "system")).toEqual(initialAccessWorkspace("org-xiak").policies.filter((entry) => entry.kind === "system"));
  });
});

describe("access workspace preview invariants", () => {
  it("rejects primary authorization and lifecycle mutations without altering preview state", async () => {
    await previewIamRepository.logout(previewCredential);
    const principalId = (await previewAccountRepository.currentIdentity(previewCredential)).account.rootIdentity.principalId;
    const beforeIdentity = await previewAccountRepository.currentIdentity(previewCredential);
    const beforeUsers = await previewAccountRepository.listUsers(previewCredential);
    const extension = previewAccountRepository.workspace!;
    const beforeWorkspace = await extension.read(previewCredential);
    const accountCommands: AccountCommand[] = [
      { kind: "set-status", userId: principalId, status: "DISABLED", resourceVersion: 5 },
      { kind: "reset-password", userId: principalId, initialPassword: "Mock-password-only-49!", resourceVersion: 5 },
      { kind: "create-policy-attachment", userId: principalId, policyId: "policy-read", policyResourceVersion: 1 }
    ];
    for (const command of accountCommands) await expect(previewAccountRepository.execute(previewCredential, command)).rejects.toMatchObject({ status: 403 });
    const workspaceCommands: AccessWorkspaceCommand[] = [
      { kind: "delete-user", principalId },
      { kind: "update-user", principalId, displayName: "Changed owner" },
      { kind: "set-user-policies", principalId, policyIds: ["policy-read"] },
      { kind: "set-user-groups", principalId: "foreign-primary", groupIds: ["group-delivery"] },
      { kind: "set-user-boundary", principalId, policyId: "policy-read" },
      { kind: "create-key", ownerId: principalId, description: "Unsupported primary key" },
      { kind: "associate-policy", id: "policy-read", userIds: [principalId], groupIds: [], roleIds: [] },
      { kind: "change-group-members", id: "group-delivery", added: ["foreign-primary"], removed: [] }
    ];
    for (const command of workspaceCommands) await expect(extension.execute(previewCredential, command)).rejects.toThrow();
    expect(await previewAccountRepository.currentIdentity(previewCredential)).toEqual(beforeIdentity);
    expect(await previewAccountRepository.listUsers(previewCredential)).toEqual(beforeUsers);
    expect(await extension.read(previewCredential)).toEqual(beforeWorkspace);
    const policy = (await previewAccountRepository.listPolicies(previewCredential, false)).items.find((entry) => entry.id === "policy-read")!;
    await previewAccountRepository.execute(previewCredential, { kind: "create-policy-attachment", userId: "principal-lin", policyId: policy.id, policyResourceVersion: policy.resourceVersion });
    const promoted = (await previewAccountRepository.listUsers(previewCredential)).items.find((entry) => entry.user.id === "principal-lin")!;
    const attachment = promoted.policyAttachments.find((entry) => entry.policyId === policy.id)!;
    expect(attachment).toBeDefined();
    expect((await previewAccountRepository.currentIdentity(previewCredential)).account.rootIdentity.principalId).toBe(principalId);
    await previewAccountRepository.execute(previewCredential, { kind: "revoke-policy-attachment", attachmentId: attachment.id, resourceVersion: attachment.resourceVersion });
    expect((await previewAccountRepository.listUsers(previewCredential)).items.find((entry) => entry.user.id === "principal-lin")?.policyAttachments.some((entry) => entry.policyId === policy.id)).toBe(false);
    await previewIamRepository.logout(previewCredential);
  });
  it("keeps the primary identity outside user groups and other user relations", () => {
    const original = initialAccessWorkspace("org-xiak");
    const principalId = context.primaryPrincipalId;
    expect(() => applyAccessWorkspaceCommand(original, { kind: "set-user-groups", principalId, groupIds: ["group-delivery"] }, context)).toThrow("invalid");
    expect(() => applyAccessWorkspaceCommand(original, { kind: "change-group-members", id: "group-delivery", added: [principalId], removed: [] }, context)).toThrow("invalid");
    expect(original.groups[0]?.memberIds).not.toContain(principalId);
    expect(() => applyAccessWorkspaceCommand(original, { kind: "set-user-groups", principalId: "foreign-primary", groupIds: ["group-delivery"] }, context)).toThrow("invalid");
    expect(() => applyAccessWorkspaceCommand(original, { kind: "set-user-policies", principalId, policyIds: ["policy-admin"] }, { ...context, userIds: [...context.userIds, principalId] })).toThrow("invalid");
  });
  it("projects wildcard policies into registered services without rewriting their documents", () => {
    const broad: PolicyDocument = { version: "1", statement: [{ effect: "allow", action: ["*"], resource: ["*"] }] };
    const before = JSON.stringify(broad);
    const summary = summarizePolicyServices(broad);
    expect(summary.map((entry) => entry.service)).toEqual([...policyServices]);
    expect(summary.flatMap((entry) => entry.actions)).toEqual([...policyActions]);
    for (const entry of summary) {
      expect(entry.rules).toHaveLength(1);
      expect(entry.rules[0]).toMatchObject({ statement: 1, patterns: ["*"], resources: ["*"] });
    }
    expect(JSON.stringify(broad)).toBe(before);
  });
  it("keeps allow/deny, overlapping actions, resource scopes and condition branches separate", () => {
    const first = "matrix:logs:org-xiak:cn-shanghai-a:topic/production/*";
    const second = "matrix:logs:org-xiak:cn-shanghai-b:topic/test/*";
    const database = "matrix:database:org-xiak:*:instance/db-a";
    const source: PolicyDocument = { version: "1", statement: [
      { effect: "allow", action: ["logs:search", "database:read"], resource: [first, database], condition: { sourceIp: ["192.0.2.0/24"] } },
      { effect: "allow", action: ["logs:search"], resource: [second], condition: { sourceIp: ["198.51.100.0/24"], resourceTag: [{ key: "env", value: "test" }] } },
      { effect: "deny", action: ["logs:search"], resource: [first], condition: { notAfter: "2026-09-10T00:00:00Z" } }
    ] };
    expect(parsePolicyDocument(JSON.stringify(source), "org-xiak")).toEqual(source);
    const result = summarizePolicyServices(source);
    expect(result).toHaveLength(3);
    const logs = result.find((entry) => entry.key === "allow:logs")!;
    expect(logs.actions.map((action) => action.id)).toEqual(["logs:search"]);
    expect(logs.rules.map((rule) => ({ statement: rule.statement, resources: rule.resources, condition: rule.condition }))).toEqual([
      { statement: 1, resources: [first], condition: source.statement[0]!.condition },
      { statement: 2, resources: [second], condition: source.statement[1]!.condition }
    ]);
    expect(result.find((entry) => entry.key === "allow:database")!.rules[0]?.resources).toEqual([database]);
    expect(result.find((entry) => entry.key === "deny:logs")!.rules[0]).toMatchObject({ statement: 3, resources: [first], condition: source.statement[2]!.condition });
  });
  it("projects resources to the matching operation type within one service", () => {
    const region = "matrix:regions:org-xiak:*:region/shanghai";
    const node = "matrix:regions:org-xiak:*:node/node-a";
    expect(resourcesForPolicyActions([region, node], expandPolicyActions(["regions:readNode"]))).toEqual([node]);
    expect(resourcesForPolicyActions(["*"], expandPolicyActions(["regions:read"]))).toEqual(["*"]);
  });

  it("reports bounded statement errors without repairing unsupported or foreign resource drafts", () => {
    const text = JSON.stringify({ version: "1", statement: [
      { effect: "allow", action: ["logs:unknown"], resource: ["*"] },
      { effect: "allow", action: ["logs:search"], resource: ["matrix:logs:foreign:shanghai:topic/private"] },
      { effect: "allow", action: ["logs:search"], resource: ["*"], condition: { unknown: true } }
    ] });
    expect(analyzePolicyDocument(text, "org-xiak")).toEqual({ document: null, diagnostics: [
      { severity: "error", code: "unknownAction", path: "$.statement[0]" },
      { severity: "error", code: "tenantResource", path: "$.statement[1]" },
      { severity: "error", code: "unsupportedPolicy", path: "$.statement[2]" }
    ] });
    for (const raw of ["{", " ".repeat(65537), JSON.stringify({ version: "1", principal: "*", statement: document.statement })]) {
      const analysis = analyzePolicyDocument(raw, "org-xiak");
      expect(analysis.document).toBeNull();
      expect(analysis.diagnostics).toHaveLength(1);
      expect(analysis.diagnostics[0]).toMatchObject({ severity: "error", path: "$" });
    }
  });
  it("separates non-blocking risk diagnostics from structural duplicate suggestions", () => {
    const statement = { effect: "allow" as const, action: ["iam:*"], resource: ["*"] };
    const text = JSON.stringify({ version: "1", statement: [statement, statement] });
    const analysis = analyzePolicyDocument(text, "org-xiak");
    expect(analysis.document).toEqual(parsePolicyDocument(text, "org-xiak"));
    expect(analysis.diagnostics.some((item) => item.severity === "error")).toBe(false);
    expect(analysis.diagnostics).toContainEqual({ severity: "warning", code: "permissionManagement", path: "$.statement[0].action" });
    expect(analysis.diagnostics).toContainEqual({ severity: "warning", code: "unrestrictedWrite", path: "$.statement[0].resource" });
    expect(analysis.diagnostics).toContainEqual({ severity: "suggestion", code: "duplicateStatement", path: "$.statement[1]" });
    const read = { effect: "allow" as const, action: ["logs:read", "logs:search"], resource: ["*"], condition: { resourceTag: [{ key: "team", value: "platform" }, { key: "env", value: "production" }] } };
    expect(policyStatementKey(read)).toBe(policyStatementKey({ ...read, action: ["logs:search", "logs:read", "logs:read"], condition: { resourceTag: [...read.condition.resourceTag].reverse() } }));
    expect(policyStatementKey(read)).not.toBe(policyStatementKey({ ...read, action: ["logs:*"] }));
    expect(policyStatementKey(read)).not.toBe(policyStatementKey({ ...read, condition: { resourceTag: [{ key: "env", value: "test" }] } }));
  });
  it("attaches a batch additively and atomically without changing members, boundaries or unrelated grants", async () => {
    const extension = createPreviewAccessWorkspace("org-xiak", () => context.userIds, context.primaryPrincipalId);
    const before = await extension.read("preview");
    const command = { kind: "attach-policies" as const, policyIds: ["policy-read", "policy-prod-logs", "policy-read"], targets: { userIds: ["principal-lin"], groupIds: ["group-delivery"], roleIds: ["role-pipeline"] } };
    for (const invalid of [
      { ...command, policyIds: ["policy-read", "foreign-policy"] },
      { ...command, targets: { ...command.targets, groupIds: ["foreign-group"] } },
      { ...command, targets: { ...command.targets, roleIds: ["foreign-role"] } },
      { ...command, targets: { ...command.targets, userIds: ["foreign-user"] } },
      { ...command, policyIds: Array.from({ length: 31 }, () => "policy-read") },
      { ...command, targets: { userIds: [], groupIds: [], roleIds: [] } }
    ]) {
      await expect(extension.execute("preview", invalid)).rejects.toThrow();
      expect(await extension.read("preview")).toEqual(before);
    }
    const { workspace: next } = await extension.execute("preview", command);
    expect(next.userPolicies["principal-lin"]).toEqual(["policy-prod-logs", "policy-read"]);
    expect(next.groups[0]?.policyIds).toEqual(["policy-delivery", "policy-read", "policy-prod-logs"]);
    expect(next.roles[0]?.policyIds).toEqual(["policy-delivery", "policy-read", "policy-prod-logs"]);
    expect(next.groups.map((group) => group.memberIds)).toEqual(before.groups.map((group) => group.memberIds));
    expect(next.userBoundaries).toEqual(before.userBoundaries);
    expect(next.roles.map((role) => role.boundaryPolicyId)).toEqual(before.roles.map((role) => role.boundaryPolicyId));
    expect(next.policies).toEqual(before.policies);
    expect(next.groups[1]).toEqual(before.groups[1]);
  });
  it.each([
    ["allow", "*", true], ["allow", "iam:*", true], ["allow", "iam:grantUser", true],
    ["allow", "iam:assumeRole", true], ["allow", "iam:readAudit", false], ["deny", "*", false]
  ] as const)("classifies %s %s for review without treating it as an effective-access decision", (effect, action, expected) => {
    expect(includesPermissionManagement({ version: "1", statement: [{ effect, action: [action], resource: ["*"] }] })).toBe(expected);
  });
  it("creates a preview user with atomic groups, policies and tags, without live grants or credentials", async () => {
    await previewIamRepository.logout(previewCredential);
    const extension = previewAccountRepository.workspace!;
    const before = await extension.read(previewCredential);
    const command = { kind: "create-subuser" as const, loginName: "wizard.test", displayName: "Wizard Test", profile: { consoleAccess: true, programmaticAccess: true, passwordResetRequired: true, loginProtection: true, tags: [{ key: "team", value: "platform" }], password: "MUST_NOT_BE_RETAINED" }, policyIds: ["policy-read"], groupIds: ["group-delivery"] };
    await expect(extension.execute(previewCredential, { ...command, groupIds: ["foreign-group"] })).rejects.toThrow("notFound");
    expect(await extension.read(previewCredential)).toEqual(before);
    expect((await previewAccountRepository.listUsers(previewCredential)).items.some((entry) => entry.user.loginName === command.loginName)).toBe(false);
    const result = await extension.execute(previewCredential, command);
    const principalId = "principal-wizard.test";
    expect(result.workspace.userPolicies[principalId]).toEqual(["policy-read"]);
    expect(result.workspace.groups.find((group) => group.id === "group-delivery")?.memberIds).toContain(principalId);
    expect(result.workspace.userProfiles[principalId]?.tags).toEqual([{ key: "team", value: "platform" }]);
    expect(JSON.stringify(result.workspace)).not.toContain("MUST_NOT_BE_RETAINED");
    const created = (await previewAccountRepository.listUsers(previewCredential)).items.find((entry) => entry.user.id === principalId)!;
    expect(created.policyAttachments.map((attachment) => attachment.policyId)).toEqual(["policy-read"]);
    expect(created.user.mustChangePassword).toBe(true);
    await expect(extension.execute(previewCredential, command)).rejects.toThrow("duplicate");
    const removed = await extension.execute(previewCredential, { kind: "delete-user", principalId });
    expect(removed.workspace.userProfiles[principalId]).toBeUndefined();
    expect(removed.workspace.userPolicies[principalId]).toBeUndefined();
    expect(removed.workspace.groups.some((group) => group.memberIds.includes(principalId))).toBe(false);
    await previewIamRepository.logout(previewCredential);
  });
  it("rejects preview creation without an access method or with duplicate tag keys", () => {
    const state = initialAccessWorkspace("org-xiak");
    const command = { kind: "create-subuser" as const, loginName: "new.user", displayName: "New", profile: { consoleAccess: false, programmaticAccess: false, passwordResetRequired: true, loginProtection: true, tags: [] }, policyIds: [], groupIds: [] };
    expect(() => applyAccessWorkspaceCommand(state, command, context)).toThrow("invalid");
    expect(() => applyAccessWorkspaceCommand(state, { ...command, profile: { ...command.profile, programmaticAccess: true, tags: [{ key: "team", value: "one" }, { key: " team ", value: "two" }] } }, context)).toThrow("invalid");
    const next = applyAccessWorkspaceCommand(state, { ...command, profile: { ...command.profile, programmaticAccess: true } }, context);
    expect(next.userProfiles["principal-new.user"]).toMatchObject({ consoleAccess: false, passwordResetRequired: false, loginProtection: false });
  });
  it("creates empty groups atomically, validates policy references and rejects duplicate names", () => {
    const source = initialAccessWorkspace("org-xiak");
    const next = applyAccessWorkspaceCommand(source, { kind: "create-group", name: "New Team", description: "", policyIds: [] }, context);
    expect(next.groups).toHaveLength(source.groups.length + 1);
    expect(source.groups.some((group) => group.name === "New Team")).toBe(false);
    expect(next.groups.at(-1)?.memberIds).toEqual([]);
    expect(next.groups.at(-1)?.policyIds).toEqual([]);
    expect(() => applyAccessWorkspaceCommand(source, { kind: "create-group", name: "Outside", description: "", policyIds: ["other-account-policy"] }, context)).toThrow("notFound");
    expect(() => applyAccessWorkspaceCommand(source, { kind: "create-group", name: "deliveryteam", description: "", policyIds: [] }, context)).toThrow("duplicate");
    const attached = applyAccessWorkspaceCommand(source, { kind: "create-group", name: "Readers", description: "", policyIds: ["policy-read", "policy-read"] }, context);
    expect(attached.groups.at(-1)?.policyIds).toEqual(["policy-read"]);
    expect(attached.groups.at(-1)?.memberIds).toEqual([]);
  });
  it("separates metadata, membership and policy commands without replacing unseen members", () => {
    const source = initialAccessWorkspace("org-xiak");
    const group = source.groups[0]!;
    group.memberIds = ["principal-lin", "unloaded-same-tenant-user"];
    const changed = applyAccessWorkspaceCommand(source, { kind: "update-group", id: group.id, name: "Renamed", description: "Team metadata" }, context);
    expect(changed.groups[0]).toEqual({ ...group, name: "Renamed", description: "Team metadata" });
    const members = applyAccessWorkspaceCommand(changed, { kind: "change-group-members", id: group.id, added: ["principal-chen", "principal-chen"], removed: ["principal-lin"] }, context);
    expect(members.groups[0]?.memberIds).toEqual(["unloaded-same-tenant-user", "principal-chen"]);
    expect(members.groups[0]?.policyIds).toEqual(group.policyIds);
    const policies = applyAccessWorkspaceCommand(members, { kind: "change-group-policies", id: group.id, added: ["policy-read"], removed: group.policyIds }, context);
    expect(policies.groups[0]?.policyIds).toEqual(["policy-read"]);
    expect(policies.groups[0]?.memberIds).toEqual(members.groups[0]?.memberIds);
    expect(source.groups[0]).toEqual(group);
  });
  it("rejects foreign, contradictory and oversized group deltas without partial changes", () => {
    const source = initialAccessWorkspace("org-xiak");
    const before = structuredClone(source);
    const id = source.groups[0]!.id;
    expect(() => applyAccessWorkspaceCommand(source, { kind: "change-group-members", id, added: ["foreign"], removed: ["principal-lin"] }, context)).toThrow("invalid");
    expect(() => applyAccessWorkspaceCommand(source, { kind: "change-group-members", id, added: ["principal-lin"], removed: ["principal-lin"] }, context)).toThrow("invalid");
    expect(() => applyAccessWorkspaceCommand(source, { kind: "change-group-members", id, added: [], removed: ["not-a-member"] }, context)).toThrow("invalid");
    expect(() => applyAccessWorkspaceCommand(source, { kind: "change-group-members", id, added: Array(31).fill("principal-chen"), removed: [] }, context)).toThrow("invalid");
    expect(() => applyAccessWorkspaceCommand(source, { kind: "change-group-policies", id, added: ["foreign"], removed: source.groups[0]!.policyIds }, context)).toThrow("notFound");
    expect(() => applyAccessWorkspaceCommand(source, { kind: "change-group-policies", id, added: ["policy-read"], removed: ["policy-read"] }, context)).toThrow("invalid");
    expect(() => applyAccessWorkspaceCommand(source, { kind: "change-group-policies", id, added: Array(31).fill("policy-read"), removed: [] }, context)).toThrow("invalid");
    expect(source).toEqual(before);
  });
  it("creates policy versions and changes the default without losing history", () => {
    let state = initialAccessWorkspace("org-xiak");
    const previous = structuredClone(state.policies.find((policy) => policy.id === "policy-prod-logs"));
    state = applyAccessWorkspaceCommand(state, { kind: "save-policy", id: "policy-prod-logs", name: "ProductionLogReader", description: "Updated", document }, context);
    const policy = state.policies.find((entry) => entry.id === "policy-prod-logs")!;
    expect(policy.versions).toHaveLength(2);
    expect(policy.defaultVersion).toBe(2);
    expect(policy.versions[0]).toEqual(previous?.versions[0]);
    state = applyAccessWorkspaceCommand(state, { kind: "set-policy-version", id: policy.id, version: 1 }, context);
    expect(state.policies.find((entry) => entry.id === policy.id)?.defaultVersion).toBe(1);
  });
  it("separates policy metadata from revisions and keeps policy names immutable", () => {
    const source = initialAccessWorkspace("org-xiak");
    const policy = source.policies.find((entry) => entry.id === "policy-prod-logs")!;
    const described = applyAccessWorkspaceCommand(source, { kind: "update-policy-description", id: policy.id, description: "New description" }, context);
    expect(described.policies.find((entry) => entry.id === policy.id)).toEqual({ ...policy, description: "New description", updatedAt: context.at });
    const unchanged = applyAccessWorkspaceCommand(source, { kind: "save-policy", id: policy.id, name: policy.name, description: "Metadata only", document: policy.versions[0]!.document }, context);
    expect(unchanged.policies.find((entry) => entry.id === policy.id)?.versions).toEqual(policy.versions);
    expect(unchanged.policies.find((entry) => entry.id === policy.id)?.lastVersion).toBe(1);
    expect(() => applyAccessWorkspaceCommand(source, { kind: "save-policy", id: policy.id, name: "Renamed", description: "", document }, context)).toThrow("immutablePolicyName");
    expect(() => applyAccessWorkspaceCommand(source, { kind: "update-policy-description", id: "policy-admin", description: "Changed" }, context)).toThrow("systemPolicy");
  });
  it("bounds history, protects the default and never reuses a deleted revision number", () => {
    let state = initialAccessWorkspace("org-xiak");
    const save = (version: number) => ({ kind: "save-policy" as const, id: "policy-prod-logs", name: "ProductionLogReader", description: "", document: { ...document, statement: [{ ...document.statement[0]!, resource: [`matrix:logs:org-xiak:*:topic/production/${version}`] }] } });
    for (let version = 2; version <= 5; version++) state = applyAccessWorkspaceCommand(state, save(version), context);
    const before = structuredClone(state);
    expect(() => applyAccessWorkspaceCommand(state, save(6), context)).toThrow("versionLimit");
    expect(() => applyAccessWorkspaceCommand(state, { kind: "delete-policy-version", id: "policy-prod-logs", version: 5 }, context)).toThrow("defaultVersion");
    expect(state).toEqual(before);
    const described = applyAccessWorkspaceCommand(state, { kind: "update-policy-description", id: "policy-prod-logs", description: "Still editable at capacity" }, context);
    expect(described.policies.find((entry) => entry.id === "policy-prod-logs")?.versions).toHaveLength(5);
    state = applyAccessWorkspaceCommand(state, { kind: "set-policy-version", id: "policy-prod-logs", version: 1 }, context);
    state = applyAccessWorkspaceCommand(state, { kind: "delete-policy-version", id: "policy-prod-logs", version: 5 }, context);
    expect(state.userPolicies).toEqual(before.userPolicies);
    expect(state.policies.find((entry) => entry.id === "policy-prod-logs")?.defaultVersion).toBe(1);
    state = applyAccessWorkspaceCommand(state, save(6), context);
    const policy = state.policies.find((entry) => entry.id === "policy-prod-logs")!;
    expect(policy.versions.map((version) => version.id)).toEqual([1, 2, 3, 4, 6]);
    expect(policy.lastVersion).toBe(6);
    expect(policy.defaultVersion).toBe(6);
    expect(() => applyAccessWorkspaceCommand(state, { kind: "delete-policy-version", id: "policy-prod-logs", version: 5 }, context)).toThrow("notFound");
    expect(() => applyAccessWorkspaceCommand(state, { kind: "delete-policy-version", id: "policy-admin", version: 1 }, context)).toThrow("systemPolicy");
  });
  it("rejects unsupported restrictions rather than silently removing them", () => {
    const statement = document.statement[0]!;
    for (const field of [{ condition: { ip: "192.0.2.0/24" } }, { principal: { user: "example" } }, { notAction: ["logs:delete"] }]) {
      expect(() => parsePolicyDocument(JSON.stringify({ ...document, statement: [{ ...statement, ...field }] }))).toThrow("unsupportedPolicy");
    }
    expect(() => parsePolicyDocument(JSON.stringify({ ...document, condition: {} }))).toThrow("unsupportedPolicy");
    expect(() => parsePolicyDocument(JSON.stringify({ ...document, statement: [{ ...statement, action: ["a".repeat(65537)] }] }))).toThrow("invalid");
    const multiple = { version: "1", statement: [statement, { effect: "deny", action: ["logs:delete"], resource: ["*"] }] };
    expect(parsePolicyDocument(JSON.stringify(multiple))).toEqual(multiple);
  });
  it("creates metadata and selected associations as one atomic transition", () => {
    const source = initialAccessWorkspace("org-xiak");
    const targets = { userIds: ["principal-lin"], groupIds: ["group-delivery"], roleIds: ["role-pipeline"] };
    const command = { kind: "save-policy" as const, name: "ScopedLogs", description: "", document, tags: [{ key: "team", value: "platform" }], targets };
    const created = applyAccessWorkspaceCommand(source, command, context);
    expect(created.policies.at(-1)?.tags).toEqual(command.tags);
    expect(created.userPolicies["principal-lin"]).toContain(context.id);
    expect(created.groups.find((group) => group.id === "group-delivery")?.policyIds).toContain(context.id);
    expect(created.roles.find((role) => role.id === "role-pipeline")?.policyIds).toContain(context.id);
    expect(() => applyAccessWorkspaceCommand(source, { ...command, targets: { ...targets, roleIds: ["missing-role"] } }, context)).toThrow("notFound");
    expect(() => applyAccessWorkspaceCommand(source, { ...command, tags: [{ key: " team", value: "" }, { key: "team", value: "" }] }, context)).toThrow("invalid");
    expect(() => applyAccessWorkspaceCommand(source, { ...command, targets: { ...targets, userIds: Array(31).fill("principal-lin") } }, context)).toThrow("invalid");
    expect(created.policies).toHaveLength(source.policies.length + 1);
    expect(source.policies.some((policy) => policy.id === context.id)).toBe(false);
    expect(source.userPolicies["principal-lin"]).not.toContain(context.id);
  });
  it("replaces nominated nondefault history only when the entire save succeeds", () => {
    let source = initialAccessWorkspace("org-xiak");
    const command = { kind: "save-policy" as const, id: "policy-prod-logs", name: "ProductionLogReader", description: "", document };
    for (let version = 2; version <= 5; version++) source = applyAccessWorkspaceCommand(source, { ...command, document: { ...document, statement: [{ ...document.statement[0]!, resource: [`matrix:logs:org-xiak:*:topic/production/${version}`] }] } }, context);
    const before = structuredClone(source);
    const replacement = { ...command, replaceVersion: 2, targets: { userIds: ["principal-chen"], groupIds: [], roleIds: [] } };
    expect(() => applyAccessWorkspaceCommand(source, { ...replacement, targets: { ...replacement.targets, groupIds: ["missing"] } }, context)).toThrow("notFound");
    expect(() => applyAccessWorkspaceCommand(source, { ...replacement, replaceVersion: 5 }, context)).toThrow("defaultVersion");
    expect(source).toEqual(before);
    const saved = applyAccessWorkspaceCommand(source, replacement, context);
    const policy = saved.policies.find((entry) => entry.id === command.id)!;
    expect(policy.versions.map((entry) => entry.id)).toEqual([1, 3, 4, 5, 6]);
    expect(policy.defaultVersion).toBe(6);
    expect(policy.lastVersion).toBe(6);
    expect(policy.versions.find((entry) => entry.id === 5)).toEqual(before.policies.find((entry) => entry.id === command.id)!.versions.find((entry) => entry.id === 5));
    expect(saved.userPolicies["principal-chen"]).toContain(policy.id);
    expect(saved.userPolicies["principal-lin"]).not.toContain(policy.id);
  });
  it.each(["null", "{}", '{"version":"1","statement":[]}', '{"version":"1","statement":[{"effect":"allow","action":[],"resource":["*"]}]}', '{"version":"1","statement":[{"effect":"maybe","action":["*"],"resource":["*"]}]}'])("rejects malformed policy documents %s", (text) => {
    expect(() => parsePolicyDocument(text)).toThrow("invalid");
  });
  it("protects predefined and referenced policies, and updates associations atomically", () => {
    let state = initialAccessWorkspace("org-xiak");
    expect(() => applyAccessWorkspaceCommand(state, { kind: "delete-policy", id: "policy-admin" }, context)).toThrow("systemPolicy");
    expect(() => applyAccessWorkspaceCommand(state, { kind: "delete-policy", id: "policy-prod-logs" }, context)).toThrow("referenced");
    state = applyAccessWorkspaceCommand(state, { kind: "associate-policy", id: "policy-prod-logs", userIds: [], groupIds: ["group-delivery"], roleIds: ["role-pipeline"] }, context);
    expect(policyUsageCounts(state, "policy-prod-logs")).toEqual({ permissionAttachments: 2, permissionBoundaries: 0, total: 2 });
    expect(state.userPolicies["principal-lin"]).not.toContain("policy-prod-logs");
    state = applyAccessWorkspaceCommand(state, { kind: "associate-policy", id: "policy-prod-logs", userIds: [], groupIds: [], roleIds: [] }, context);
    expect(applyAccessWorkspaceCommand(state, { kind: "delete-policy", id: "policy-prod-logs" }, context).policies.some((policy) => policy.id === "policy-prod-logs")).toBe(false);
  });
  it("keeps role trust aligned with federation and protects referenced providers", () => {
    const state = initialAccessWorkspace("org-xiak");
    expect(() => applyAccessWorkspaceCommand(state, { kind: "delete-provider", id: "idp-example" }, context)).toThrow("referenced");
    expect(() => applyAccessWorkspaceCommand(state, { kind: "delete-role", id: "role-audit" }, context)).toThrow("referenced");
    expect(() => applyAccessWorkspaceCommand(state, { kind: "save-federation", name: "Wrong Trust", subject: "external", providerId: "idp-example", roleId: "role-pipeline", enabled: true }, context)).toThrow("invalid");
    const role = state.roles.find((entry) => entry.id === "role-pipeline")!;
    expect(() => applyAccessWorkspaceCommand(state, { kind: "update-role-settings", id: role.id, sessionMinutes: 60, consoleAccess: true }, context)).toThrow("invalid");
  });
  it("validates HTTPS and metadata shape without claiming external validation", () => {
    const command = { kind: "save-provider" as const, name: "OIDC", protocol: "OIDC" as const, issuer: "https://id.example.invalid", audience: "matrix", metadata: '{"keys":[{"kty":"RSA","kid":"MOCK"}]}', enabled: true };
    const state = initialAccessWorkspace("org-xiak");
    expect(applyAccessWorkspaceCommand(state, command, context).providers.at(-1)?.protocol).toBe("OIDC");
    expect(() => applyAccessWorkspaceCommand(state, { ...command, issuer: "javascript:alert(1)" }, context)).toThrow("invalid");
    expect(() => applyAccessWorkspaceCommand(state, { ...command, metadata: "{}" }, context)).toThrow("invalid");
  });
  it("limits keys per subuser and requires disabling before deletion", () => {
    let state = initialAccessWorkspace("org-xiak");
    state = applyAccessWorkspaceCommand(state, { kind: "create-key", ownerId: "principal-lin", description: "" }, context);
    expect(() => applyAccessWorkspaceCommand(state, { kind: "create-key", ownerId: "principal-lin", description: "" }, context)).toThrow("invalid");
    expect(() => applyAccessWorkspaceCommand(state, { kind: "delete-key", id: "MOCK-new-id" }, context)).toThrow("disableFirst");
    state = applyAccessWorkspaceCommand(state, { kind: "set-key-status", id: "MOCK-new-id", enabled: false }, context);
    expect(applyAccessWorkspaceCommand(state, { kind: "delete-key", id: "MOCK-new-id" }, context).keys).toHaveLength(1);
    expect(() => applyAccessWorkspaceCommand(state, { kind: "create-key", ownerId: "primary-admin", description: "" }, context)).toThrow("invalid");
  });
  it("returns a mock secret once without storing it in snapshots or reports", async () => {
    const repository = createPreviewAccessWorkspace("org-xiak", () => context.userIds, context.primaryPrincipalId);
    const result = await repository.execute("mock", { kind: "create-key", ownerId: "principal-chen", description: "Test" });
    expect(result.issuedKey?.secret).toMatch(/^MOCK_NOT_A_CREDENTIAL_/);
    expect(JSON.stringify(result.workspace)).not.toContain(result.issuedKey?.secret);
    expect(JSON.stringify(await repository.read("mock"))).not.toContain("MOCK_NOT_A_CREDENTIAL_");
    repository.reset();
    expect((await repository.read("mock")).keys).toHaveLength(1);
  });
  it("removes a deleted user's memberships, direct permissions and keys together", () => {
    const state = applyAccessWorkspaceCommand(initialAccessWorkspace("org-xiak"), { kind: "delete-user", principalId: "principal-lin" }, context);
    expect(state.groups.some((group) => group.memberIds.includes("principal-lin"))).toBe(false);
    expect(state.userPolicies["principal-lin"]).toBeUndefined();
    expect(state.keys).toHaveLength(0);
  });
  it("bounds security settings and requires an available SSO provider", () => {
    const state = initialAccessWorkspace("org-xiak");
    expect(() => applyAccessWorkspaceCommand(state, { kind: "save-settings", settings: { ...state.settings, passwordMinLength: 5 } }, context)).toThrow("invalid");
    expect(() => applyAccessWorkspaceCommand(state, { kind: "save-settings", settings: { ...state.settings, userSsoEnabled: true, userSsoProviderId: "missing" } }, context)).toThrow("notFound");
    const updated = applyAccessWorkspaceCommand(state, { kind: "save-settings", settings: { ...state.settings, userSsoEnabled: true, userSsoProviderId: "idp-example" } }, context);
    expect(updated.settings.userSsoEnabled).toBe(true);
  });
  it("imports visible enterprise members as ungranted preview users and resets them on logout", async () => {
    await previewIamRepository.logout(previewCredential);
    const originalUsers = (await previewAccountRepository.listUsers(previewCredential)).items;
    const extension = previewAccountRepository.workspace!;
    const connected = await extension.execute(previewCredential, { kind: "save-enterprise", name: "MOCK Enterprise", corporationId: "MOCK_CORP", visibleMemberIds: ["dev01"] });
    const id = connected.workspace.enterprises[0]!.id;
    await expect(extension.execute(previewCredential, { kind: "import-enterprise-members", id, memberIds: ["ops01"] })).rejects.toThrow("invalid");
    await extension.execute(previewCredential, { kind: "import-enterprise-members", id, memberIds: ["dev01"] });
    const imported = (await previewAccountRepository.listUsers(previewCredential)).items.find((entry) => entry.user.loginName.startsWith("wecom."))!;
    expect(imported.user.displayName).toBe("Dev Member");
    expect(imported.policyAttachments).toEqual([]);
    await expect(extension.execute(previewCredential, { kind: "delete-enterprise", id })).rejects.toThrow("referenced");
    await extension.execute(previewCredential, { kind: "delete-user", principalId: imported.user.id });
    await extension.execute(previewCredential, { kind: "delete-enterprise", id });
    await previewIamRepository.logout(previewCredential);
    expect((await previewAccountRepository.listUsers(previewCredential)).items).toEqual(originalUsers);
    expect((await extension.read(previewCredential)).enterprises).toHaveLength(0);
  });
});
