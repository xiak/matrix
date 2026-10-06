import { afterEach, describe, expect, it, vi } from "vitest";
import { httpAccountRepository, httpIamRepository } from "./httpIamRepository";

const apiVersion = "iam.matrix.xiak.com/v1";
const timestamp = "2026-09-11T08:00:00Z";
const user = {
  apiVersion, kind: "User", id: "user-alex", accountId: "account-acme",
  loginName: "alex", displayName: "Alex", status: "ACTIVE", mustChangePassword: false, resourceVersion: 2,
  createdAt: timestamp, updatedAt: timestamp
};
const permissionBoundary = { apiVersion, kind: "UserPermissionBoundary", accountId: user.accountId, userId: user.id, resourceVersion: user.resourceVersion, policy: null };
const account = {
  apiVersion, kind: "Account", id: "account-acme", displayName: "Acme", status: "ACTIVE",
  rootIdentity: { principalId: "root-acme", loginName: "acme.owner" }, loginAlias: "acme", resourceVersion: 2,
  createdAt: timestamp, updatedAt: timestamp
};
const tenantAttachment = {
  apiVersion, kind: "PolicyAttachment", id: "attachment-viewer", accountId: "account-acme",
  target: { kind: "USER", id: "user-alex" }, policyId: "system.paas-viewer", scope: "TENANT",
  resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp
};
const platformAttachment = {
  ...tenantAttachment, id: "attachment-platform", policyId: "system.platform-operator", scope: "INSTALLATION",
  installationId: "installation-acme"
};
const tenantPolicy = {
  apiVersion, kind: "Policy", id: "system.paas-viewer", management: "SYSTEM", displayName: "只读策略",
  scope: "TENANT", status: "ACTIVE", defaultVersionId: "version-viewer", resourceVersion: 3,
  createdAt: timestamp, updatedAt: timestamp
};
const customerPolicy = {
  ...tenantPolicy, id: "customer.build", management: "CUSTOMER", accountId: "account-acme",
  displayName: "构建策略", defaultVersionId: "version-build"
};
const platformPolicy = {
  ...tenantPolicy, id: "system.platform-operator", displayName: "平台运营策略", scope: "INSTALLATION",
  defaultVersionId: "version-platform"
};
const profileConditions = [
  { key: "iam.account-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" },
  { key: "iam.current-time", valueType: "TIME", source: "IAM_TRANSACTION_TIME" },
  { key: "iam.principal-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" }
];
function profileEntry(product = "paas") {
  return {
    profile: { apiVersion, kind: "AuthorizationProfile", product, revision: 1, callingService: "PAAS", actions: [{
      action: `${product}.application.create`, resourceKind: "APPLICATION", scope: "TENANT",
      resourceShapes: [{ mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_CREATE" }],
      conditions: profileConditions, resultResourceKind: "APPLICATION"
    }, {
      action: `${product}.application.read`, resourceKind: "APPLICATION", scope: "TENANT",
      resourceShapes: [{ mode: "INSTANCE", prefixAllowed: true }], conditions: profileConditions
    }] },
    contentDigest: `sha256:${"a".repeat(64)}`
  };
}

function serviceRoleTemplate(id = "managedservice.installation-reader") {
  return {
    apiVersion, kind: "ServiceRoleTemplate", id, version: 1,
    spec: {
      product: "managedservice", servicePurpose: "PAAS",
      roleName: "ManagedServiceInstallationReader",
      roleDescription: "Allows inspection of one consented installation.",
      policyVersion: {
        policyId: "system.managedservice-installation-reader",
        versionId: "version-managedservice-installation-reader-v1",
        contentDigest: `sha256:${"b".repeat(64)}`
      },
      workloads: [{
        resourceKind: "SERVICE_INSTALLATION",
        bindAction: "managedservice.installation.bind-service-role",
        unbindAction: "managedservice.installation.unbind-service-role"
      }],
      maxSessionDurationSeconds: 900
    },
    contentDigest: `sha256:${"c".repeat(64)}`,
    status: "ACTIVE"
  };
}

function capability(action: string, kind: "ACCOUNT" | "USER" | "GROUP" | "ROLE" | "ROLE_SESSION" | "GROUP_MEMBERSHIP" | "POLICY_ATTACHMENT" | "ACCESS_KEY", id: string, available = true, restrictionReason = "AUTHORITY_REQUIRED") {
  return { action, resource: { kind, id }, available, ...(available ? {} : { restrictionReason }) };
}

function currentCapabilities(available = true) {
  return [
    capability("iam.account.create", "ACCOUNT", "collection", available),
    capability("iam.account.read", "ACCOUNT", "collection", available),
    capability("iam.account.alias-set", "ACCOUNT", account.id, available),
    capability("iam.user.list", "ACCOUNT", account.id, available),
    capability("iam.user.create", "ACCOUNT", account.id, available),
    capability("iam.policy.list", "ACCOUNT", account.id, available),
    capability("iam.group.list", "ACCOUNT", account.id, available),
    capability("iam.group.create", "ACCOUNT", account.id, available),
    capability("iam.role.list", "ACCOUNT", account.id, available),
    capability("iam.role.create", "ACCOUNT", account.id, available)
  ];
}

function userCapabilities(attachments = [tenantAttachment]) {
  return [
    capability("iam.user.read", "USER", user.id),
    capability("iam.user.update", "USER", user.id),
    capability("iam.user.delete", "USER", user.id, false, "TARGET_MUST_BE_DISABLED"),
    capability("iam.user.permission-boundary.set", "USER", user.id),
    capability("iam.user.permission-boundary.remove", "USER", user.id),
    capability("iam.user.set-status", "USER", user.id),
    capability("iam.user.reset-password", "USER", user.id),
    capability("iam.policy-attachment.create", "USER", user.id),
    capability("iam.platform-policy-attachment.create", "USER", user.id),
    ...attachments.map((item) => capability(item.scope === "INSTALLATION" ? "iam.platform-policy-attachment.revoke" : "iam.policy-attachment.revoke", "POLICY_ATTACHMENT", item.id))
  ];
}

function accountAccess(value = account) {
  return { account: value, capabilities: [
    capability("iam.account.set-status", "ACCOUNT", value.id),
    capability("iam.account.recover-root-credentials", "ACCOUNT", value.id)
  ] };
}

function reply(body: unknown) {
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } }));
  vi.stubGlobal("fetch", fetcher);
  return fetcher;
}

function directSources(...attachments: Array<typeof tenantAttachment>) {
  return attachments.map((attachment) => ({ kind: "DIRECT", attachment })).sort((left, right) => left.attachment.id.localeCompare(right.attachment.id));
}

function requestBody(fetcher: ReturnType<typeof reply>) {
  return JSON.parse(firstRequest(fetcher)[1].body) as Record<string, unknown>;
}

function firstRequest(fetcher: ReturnType<typeof reply>) {
  const call = fetcher.mock.calls[0];
  if (!call) throw new Error("Expected an IAM request");
  return call;
}

afterEach(() => { vi.unstubAllGlobals(); });

const group = { apiVersion, kind: "Group", id: "group-build", accountId: account.id, name: "Build operators", resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp };
const groupAttachment = { ...tenantAttachment, id: "attachment-group", target: { kind: "GROUP", id: group.id } };
const membership = { apiVersion, kind: "GroupMembership", id: "membership-alex", accountId: account.id, groupId: group.id,
  userId: user.id, createdBy: account.rootIdentity.principalId, resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp };
function groupAccess(value = group) {
  return { group: value, policyAttachments: [{ ...groupAttachment, target: { kind: "GROUP", id: value.id } }], capabilities: [
    ...["iam.group.read", "iam.group.update", "iam.group.delete", "iam.group-membership.list", "iam.group-membership.create", "iam.group-policy-attachment.create"].map((action) => capability(action, "GROUP", value.id)),
    capability("iam.group-policy-attachment.revoke", "POLICY_ATTACHMENT", groupAttachment.id, false)
  ] };
}
function membershipPage() {
  return { apiVersion, kind: "GroupMembershipList", accountId: account.id, groupId: group.id, items: [{ membership,
    capabilities: [capability("iam.group-membership.remove", "GROUP_MEMBERSHIP", membership.id)] }] };
}

const role = {
  apiVersion, kind: "Role", id: "role-reviewer", accountId: account.id, name: "ProductionLogReviewer",
  description: "Review production logs during an incident", tags: [{ key: "team", value: "operations" }],
  management: "CUSTOMER", status: "ACTIVE", maxSessionDurationSeconds: 3600, resourceVersion: 3,
  currentTrustVersionId: "trust-reviewer-v2", createdAt: timestamp, updatedAt: timestamp
};
const roleAttachment = {
  ...tenantAttachment, id: "attachment-role-reviewer", target: { kind: "ROLE", id: role.id }, policyId: "system.paas-viewer"
};
const roleCapabilityActions = [
  "iam.role.read", "iam.role.update", "iam.role.set-status", "iam.role.delete", "iam.role-trust.set",
  "iam.role-policy-attachment.create", "iam.role.permission-boundary.set", "iam.role.permission-boundary.remove", "iam.role-session.list"
];
function roleCapabilities(value = role, attachments = [roleAttachment]) {
  return [
    ...roleCapabilityActions.map((action) => capability(action, "ROLE", value.id)),
    capability("iam.role.assume", "ROLE", value.id, false),
    ...attachments.map((attachment) => capability("iam.role-policy-attachment.revoke", "POLICY_ATTACHMENT", attachment.id))
  ];
}
async function trustDigest(document: object) {
  const bytes = new TextEncoder().encode(`matrix.iam.role-trust.v1\u0000${JSON.stringify(document)}`);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return `sha256:${Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join("")}`;
}
async function roleAccess() {
  const document = { languageVersion: "1", statements: [{ sid: "incident-review", effect: "ALLOW", principals: [{ type: "USER", id: user.id }] }] };
  return {
    role,
    trustVersion: { apiVersion, kind: "RoleTrustVersion", id: role.currentTrustVersionId, accountId: account.id, roleId: role.id, document, contentDigest: await trustDigest(document), createdAt: timestamp },
    policyAttachments: [roleAttachment],
    capabilities: roleCapabilities()
  };
}

describe("IAM HTTP role boundary", () => {
  it("loads the account-confined role directory without caller selectors", async () => {
    const fetcher = reply({ apiVersion, kind: "RoleList", accountId: account.id, items: [{ role, capabilities: roleCapabilities(role, []).slice(0, 9) }] });
    const directory = await httpAccountRepository.roles!.list("bearer", account.id);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/roles");
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer bearer" } });
    expect(directory).toMatchObject({ accountId: account.id, nextAfter: null, items: [{ role: { id: role.id, name: role.name } }] });
  });

  it("reads an exact role, current trust document and policy attachment set", async () => {
    const response = await roleAccess();
    const fetcher = reply(response);
    const result = await httpAccountRepository.roles!.read("bearer", account.id, role.id);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}`);
    expect(result.role.id).toBe(role.id);
    expect(result.trustVersion.document.statements[0]?.principals).toEqual([{ type: "USER", id: user.id }]);
    expect(result.policyAttachments[0]?.target).toEqual({ kind: "ROLE", id: role.id });
  });

  it("lists only digest-verified immutable trust versions for the exact role", async () => {
    const current = (await roleAccess()).trustVersion;
    const previousDocument = { languageVersion: "1", statements: [{ sid: "initial-review", effect: "ALLOW", principals: [{ type: "USER", id: user.id }] }] };
    const previous = { ...current, id: "trust-reviewer-v1", document: previousDocument, contentDigest: await trustDigest(previousDocument), createdAt: "2026-09-20T08:00:00Z" };
    const fetcher = reply({ apiVersion, kind: "RoleTrustVersionList", accountId: account.id, roleId: role.id, items: [previous, current] });

    const result = await httpAccountRepository.roles!.listTrustVersions("bearer", account.id, role.id);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}/trust-versions`);
    expect(result).toMatchObject({ accountId: account.id, roleId: role.id, nextAfter: null, items: [{ id: previous.id }, { id: current.id }] });

    reply({ apiVersion, kind: "RoleTrustVersionList", accountId: account.id, roleId: role.id, items: [{ ...previous, contentDigest: `sha256:${"0".repeat(64)}` }] });
    await expect(httpAccountRepository.roles!.listTrustVersions("bearer", account.id, role.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("reads the exact mandatory role permission boundary without treating null as unlimited", async () => {
    const digest = `sha256:${"c".repeat(64)}`;
    const fetcher = reply({ apiVersion, kind: "RolePermissionBoundary", accountId: account.id, roleId: role.id, resourceVersion: 4,
      policy: { policyId: "policy-role-ceiling", versionId: "v3", contentDigest: digest } });
    const result = await httpAccountRepository.roles!.readPermissionBoundary("bearer", account.id, role.id);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}/permission-boundary`);
    expect(result).toEqual({ accountId: account.id, roleId: role.id, resourceVersion: 4,
      policy: { policyId: "policy-role-ceiling", versionId: "v3", contentDigest: digest } });

    reply({ apiVersion, kind: "RolePermissionBoundary", accountId: account.id, roleId: role.id, resourceVersion: 5, policy: null });
    await expect(httpAccountRepository.roles!.readPermissionBoundary("bearer", account.id, role.id)).resolves.toEqual({ accountId: account.id, roleId: role.id, resourceVersion: 5, policy: null });
    reply({ apiVersion, kind: "RolePermissionBoundary", accountId: account.id, roleId: role.id, resourceVersion: 5,
      policy: { policyId: "policy-role-ceiling", versionId: "v3", contentDigest: `sha256:${"C".repeat(64)}` } });
    await expect(httpAccountRepository.roles!.readPermissionBoundary("bearer", account.id, role.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("sets and removes the exact role boundary with explicit concurrency and request identity", async () => {
    const client = httpAccountRepository.roles!;
    const reference = { policyId: "policy-role-ceiling", versionId: "v3", contentDigest: `sha256:${"d".repeat(64)}` };
    const set = { policyId: reference.policyId, policyResourceVersion: 7, resourceVersion: 4, requestId: "request-role-boundary-set" };
    let fetcher = reply({ apiVersion, kind: "RolePermissionBoundary", accountId: account.id, roleId: role.id, resourceVersion: 5, policy: reference });
    expect((await client.setPermissionBoundary("bearer", account.id, role.id, { ...set, accountId: "forged" } as typeof set)).policy).toEqual(reference);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}/permission-boundary`);
    expect(firstRequest(fetcher)[1].method).toBe("PUT");
    expect(requestBody(fetcher)).toEqual(set);

    const remove = { resourceVersion: 5, requestId: "request-role-boundary-remove" };
    fetcher = reply({ apiVersion, kind: "RolePermissionBoundary", accountId: account.id, roleId: role.id, resourceVersion: 6, policy: null });
    expect((await client.removePermissionBoundary("bearer", account.id, role.id, remove)).policy).toBeNull();
    expect(firstRequest(fetcher)[1].method).toBe("DELETE");
    expect(requestBody(fetcher)).toEqual(remove);
  });

  it("rejects foreign or non-concurrent role boundary write outcomes", async () => {
    const client = httpAccountRepository.roles!;
    const reference = { policyId: "policy-role-ceiling", versionId: "v3", contentDigest: `sha256:${"e".repeat(64)}` };
    const command = { policyId: reference.policyId, policyResourceVersion: 7, resourceVersion: 4, requestId: "request-role-boundary-invalid" };
    for (const result of [
      { apiVersion, kind: "RolePermissionBoundary", accountId: account.id, roleId: role.id, resourceVersion: 4, policy: reference },
      { apiVersion, kind: "RolePermissionBoundary", accountId: account.id, roleId: role.id, resourceVersion: 6, policy: reference },
      { apiVersion, kind: "RolePermissionBoundary", accountId: account.id, roleId: role.id, resourceVersion: 5, policy: null },
      { apiVersion, kind: "RolePermissionBoundary", accountId: account.id, roleId: "role-other", resourceVersion: 5, policy: reference },
      { apiVersion, kind: "RolePermissionBoundary", accountId: "account-other", roleId: role.id, resourceVersion: 5, policy: reference },
      { apiVersion, kind: "RolePermissionBoundary", accountId: account.id, roleId: role.id, resourceVersion: 5, policy: { ...reference, policyId: "policy-other" } }
    ]) {
      reply(result);
      await expect(client.setPermissionBoundary("bearer", account.id, role.id, command)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    reply({ apiVersion, kind: "RolePermissionBoundary", accountId: account.id, roleId: role.id, resourceVersion: 5, policy: reference });
    await expect(client.removePermissionBoundary("bearer", account.id, role.id, { resourceVersion: 4, requestId: "request-role-boundary-remove-invalid" })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("retries an uncertain role boundary request byte-for-byte", async () => {
    const reference = { policyId: "policy-role-ceiling", versionId: "v3", contentDigest: `sha256:${"f".repeat(64)}` };
    const response = { apiVersion, kind: "RolePermissionBoundary", accountId: account.id, roleId: role.id, resourceVersion: 5, policy: reference };
    const fetcher = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ code: "IAM_UNAVAILABLE" }), { status: 503 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(response), { status: 200 }));
    vi.stubGlobal("fetch", fetcher);
    const command = { policyId: reference.policyId, policyResourceVersion: 7, resourceVersion: 4, requestId: "request-role-boundary-uncertain" };
    await expect(httpAccountRepository.roles!.setPermissionBoundary("bearer", account.id, role.id, command)).rejects.toMatchObject({ status: 503 });
    await httpAccountRepository.roles!.setPermissionBoundary("bearer", account.id, role.id, command);
    expect(fetcher.mock.calls[0]).toEqual(fetcher.mock.calls[1]);
  });

  it("creates a role with only metadata, USER trust and one retained request ID", async () => {
    const trustPolicy = { languageVersion: "1" as const, statements: [{ sid: "trusted-users", effect: "ALLOW" as const, principals: [{ type: "USER" as const, id: user.id }] }] };
    const fetcher = reply(role);
    const created = await httpAccountRepository.roles!.create("bearer", account.id, {
      name: role.name,
      description: role.description,
      tags: role.tags,
      maxSessionDurationSeconds: role.maxSessionDurationSeconds,
      trustPolicy,
      requestId: "ui-create-role-one"
    });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/roles");
    expect(requestBody(fetcher)).toEqual({
      name: role.name,
      description: role.description,
      tags: role.tags,
      maxSessionDurationSeconds: role.maxSessionDurationSeconds,
      trustPolicy,
      requestId: "ui-create-role-one"
    });
    expect(created).toMatchObject({ id: role.id, accountId: account.id, status: "ACTIVE" });
  });

  it("rejects a create response that changes the submitted owner or metadata", async () => {
    const command = {
      name: role.name,
      description: role.description,
      tags: role.tags,
      maxSessionDurationSeconds: role.maxSessionDurationSeconds,
      trustPolicy: { languageVersion: "1" as const, statements: [{ sid: "trusted-users", effect: "ALLOW" as const, principals: [{ type: "USER" as const, id: user.id }] }] },
      requestId: "ui-create-role-one"
    };
    for (const response of [{ ...role, accountId: "account-foreign" }, { ...role, name: "DifferentRole" }, { ...role, status: "DISABLED" }]) {
      reply(response);
      await expect(httpAccountRepository.roles!.create("bearer", account.id, command)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("updates complete role metadata with one CAS-bound request", async () => {
    const command = {
      name: "ProductionLogAuditor", description: "Review retained production logs", tags: [{ key: "team", value: "security" }],
      maxSessionDurationSeconds: 1800, resourceVersion: role.resourceVersion, requestId: "ui-role-update-one"
    };
    const response = { ...role, ...command, requestId: undefined, resourceVersion: role.resourceVersion + 1 };
    delete response.requestId;
    const fetcher = reply(response);

    const updated = await httpAccountRepository.roles!.update("bearer", account.id, role.id, command);

    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}`);
    expect(firstRequest(fetcher)[1].method).toBe("PATCH");
    expect(requestBody(fetcher)).toEqual(command);
    expect(updated).toMatchObject({ id: role.id, name: command.name, resourceVersion: role.resourceVersion + 1 });
  });

  it("keeps status and trust replacement as separate role commands", async () => {
    const status = { status: "DISABLED" as const, resourceVersion: role.resourceVersion, requestId: "ui-role-disable-one" };
    let fetcher = reply({ ...role, status: status.status, resourceVersion: role.resourceVersion + 1 });
    await httpAccountRepository.roles!.setStatus("bearer", account.id, role.id, status);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}:set-status`);
    expect(requestBody(fetcher)).toEqual(status);

    const document = { languageVersion: "1" as const, statements: [{ sid: "security-review", effect: "ALLOW" as const, principals: [{ type: "USER" as const, id: user.id }] }] };
    const trust = { document, resourceVersion: role.resourceVersion, requestId: "ui-role-trust-one" };
    fetcher = reply({ ...role, currentTrustVersionId: "trust-reviewer-v3", resourceVersion: role.resourceVersion + 1 });
    await httpAccountRepository.roles!.setTrustPolicy("bearer", account.id, role.id, trust);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}/trust-policy`);
    expect(firstRequest(fetcher)[1].method).toBe("PUT");
    expect(requestBody(fetcher)).toEqual(trust);
  });

  it("binds role deletion to the reviewed name and revision", async () => {
    const command = { resourceVersion: role.resourceVersion, requestId: "ui-role-delete-one", expectedName: role.name };
    const response = { apiVersion, kind: "RoleDeletion", id: role.id, accountId: account.id, name: role.name,
      resourceVersion: role.resourceVersion + 1, revokedPolicyAttachments: 2, deletedAt: timestamp };
    const fetcher = reply(response);

    const deleted = await httpAccountRepository.roles!.delete("bearer", account.id, role.id, command);

    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}`);
    expect(firstRequest(fetcher)[1].method).toBe("DELETE");
    expect(requestBody(fetcher)).toEqual({ resourceVersion: command.resourceVersion, requestId: command.requestId });
    expect(deleted.revokedPolicyAttachments).toBe(2);

    reply({ ...response, name: "DifferentRole" });
    await expect(httpAccountRepository.roles!.delete("bearer", account.id, role.id, command)).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("creates an exact ROLE policy attachment without authority selectors", async () => {
    const command = { policyId: customerPolicy.id, policyResourceVersion: customerPolicy.resourceVersion, requestId: "ui-role-attachment-one" };
    const response = { ...roleAttachment, policyId: customerPolicy.id };
    const fetcher = reply(response);

    const attached = await httpAccountRepository.roles!.createPolicyAttachment("bearer", account.id, role.id, command);

    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policy-attachments");
    expect(requestBody(fetcher)).toEqual({ target: { kind: "ROLE", id: role.id }, ...command });
    expect(attached).toMatchObject({ accountId: account.id, target: { kind: "ROLE", id: role.id }, policyId: customerPolicy.id });
  });

  it("rejects foreign ownership, invented trust carriers, mismatched revisions and bad digests", async () => {
    const base = await roleAccess();
    const invalid = [
      { ...base, role: { ...base.role, accountId: "account-foreign" } },
      { ...base, trustVersion: { ...base.trustVersion, roleId: "role-other" } },
      { ...base, trustVersion: { ...base.trustVersion, id: "trust-old" } },
      { ...base, trustVersion: { ...base.trustVersion, contentDigest: `sha256:${"0".repeat(64)}` } },
      { ...base, trustVersion: { ...base.trustVersion, document: { languageVersion: "1", statements: [{ sid: "service", effect: "ALLOW", principals: [{ type: "SERVICE", id: "paas" }] }] } } },
      { ...base, policyAttachments: [{ ...base.policyAttachments[0], target: { kind: "USER", id: user.id } }] },
      { ...base, capabilities: base.capabilities.map((item, index) => index ? item : { ...item, resource: { kind: "ROLE", id: "role-other" } }) },
      { ...base, sourceSessionId: "private-lineage" }
    ];
    for (const response of invalid) {
      reply(response);
      await expect(httpAccountRepository.roles!.read("bearer", account.id, role.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("keeps role cursors opaque, bounded and tied to complete pages", async () => {
    await expect(httpAccountRepository.roles!.list("bearer", account.id, "ir1.discovery-cursor")).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ apiVersion, kind: "RoleList", accountId: account.id, items: [{ role, capabilities: roleCapabilities(role, []).slice(0, 9) }], nextAfter: "ic1.next-page" });
    await expect(httpAccountRepository.roles!.list("bearer", account.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ apiVersion, kind: "RoleList", accountId: "account-foreign", items: [] });
    await expect(httpAccountRepository.roles!.list("bearer", account.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
  });
});

const roleSessionObservedAt = "2026-09-11T08:30:00Z";
const roleSession = {
  apiVersion, kind: "RoleSession", id: "rs1.incident-review", accountId: account.id, roleId: role.id,
  sourceUserId: user.id, status: "ACTIVE", issuedAt: timestamp, expiresAt: "2026-09-11T09:00:00Z"
};
const servicePrincipal = { installationId: "installation-paas-primary", principalId: "service-paas-runtime", purpose: "PAAS" };
const serviceRoleSession = {
  apiVersion, kind: "RoleSession", id: "rs1.service-read", accountId: account.id, roleId: role.id,
  sourceServicePrincipalId: servicePrincipal.principalId, status: "ACTIVE", issuedAt: timestamp, expiresAt: "2026-09-11T09:00:00Z"
};
function roleSessionListing(session: typeof roleSession & Record<string, unknown> = roleSession, lifecycle = "UNREVOKED", available = true) {
  return {
    session,
    source: { type: "USER", user: { id: user.id, loginName: user.loginName, displayName: user.displayName } },
    lifecycle,
    revokeCapability: capability("iam.role-session.revoke", "ROLE_SESSION", session.id, available, available ? "AUTHORITY_REQUIRED" : "SESSION_NOT_REVOCABLE")
  };
}
function serviceRoleSessionListing(lifecycle = "UNREVOKED", available = true) {
  return {
    session: serviceRoleSession,
    source: { type: "SERVICE_ACCOUNT", servicePrincipal },
    lifecycle,
    revokeCapability: capability("iam.role-session.revoke", "ROLE_SESSION", serviceRoleSession.id, available, available ? "AUTHORITY_REQUIRED" : "SESSION_NOT_REVOCABLE")
  };
}
function roleSessionDirectory(items: Record<string, unknown>[] = [roleSessionListing()], nextAfter?: string) {
  return { apiVersion, kind: "RoleSessionList", accountId: account.id, roleId: role.id, observedAt: roleSessionObservedAt, items, ...(nextAfter ? { nextAfter } : {}) };
}

describe("IAM HTTP role-session boundary", () => {
  it("uses exact server filters and preserves opaque empty-window cursors", async () => {
    let fetcher = reply(roleSessionDirectory());
    const result = await httpAccountRepository.roles!.listSessions("bearer", account.id, role.id, { exactKind: "sourceUser", exactId: user.id, sourceType: "USER", lifecycle: "ALL" });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}/sessions?sourceType=USER&sourceUserId=${user.id}&lifecycle=ALL`);
    expect(result.items[0]).toMatchObject({ lifecycle: "UNREVOKED", session: { id: roleSession.id }, source: { type: "USER", user: { id: user.id } } });

    fetcher = reply(roleSessionDirectory([serviceRoleSessionListing()]));
    const service = await httpAccountRepository.roles!.listSessions("bearer", account.id, role.id, { exactKind: "sourceServicePrincipal", exactId: servicePrincipal.principalId, sourceType: "SERVICE_ACCOUNT", lifecycle: "ALL" });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}/sessions?sourceType=SERVICE_ACCOUNT&sourceServicePrincipalId=${servicePrincipal.principalId}&lifecycle=ALL`);
    expect(service.items[0]).toMatchObject({ session: { sourceServicePrincipalId: servicePrincipal.principalId }, source: { type: "SERVICE_ACCOUNT", servicePrincipal } });

    fetcher = reply(roleSessionDirectory([], "ic1.next-window"));
    const empty = await httpAccountRepository.roles!.listSessions("bearer", account.id, role.id, { exactKind: "session", exactId: "", sourceType: "ALL", lifecycle: "UNREVOKED" });
    expect(empty).toMatchObject({ items: [], nextAfter: "ic1.next-window" });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}/sessions`);

    fetcher = reply(roleSessionDirectory([], "ic1.next-window"));
    await httpAccountRepository.roles!.listSessions("bearer", account.id, role.id, { exactKind: "session", exactId: "", sourceType: "ALL", lifecycle: "UNREVOKED" }, "ic1.previous-window");
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}/sessions?after=ic1.previous-window`);
  });

  it("rejects invented lifecycle, source, capability and private response fields", async () => {
    const invalid = [
      roleSessionDirectory([{ ...roleSessionListing(), lifecycle: "EXPIRED" }]),
      roleSessionDirectory([{ ...roleSessionListing(), source: { type: "USER", user: { id: "user-other", loginName: "other", displayName: "Other" } } }]),
      roleSessionDirectory([{ ...serviceRoleSessionListing(), source: { type: "USER", user: { id: user.id, loginName: user.loginName, displayName: user.displayName } } }]),
      roleSessionDirectory([{ ...serviceRoleSessionListing(), source: { type: "SERVICE_ACCOUNT", servicePrincipal, user: { id: user.id } } }]),
      roleSessionDirectory([{ ...roleSessionListing(), revokeCapability: capability("iam.role-session.revoke", "ROLE_SESSION", "rs1.other") }]),
      roleSessionDirectory([{ ...roleSessionListing(), session: { ...roleSession, sourceSessionId: "private-login-session" } }]),
      roleSessionDirectory([{ ...roleSessionListing(), session: { ...roleSession, sourceServicePrincipalId: servicePrincipal.principalId } }])
    ];
    for (const response of invalid) {
      reply(response);
      await expect(httpAccountRepository.roles!.listSessions("bearer", account.id, role.id, { exactKind: "session", exactId: "", sourceType: "ALL", lifecycle: "ALL" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("reads one exact observation and revokes with only the retained request ID", async () => {
    let fetcher = reply({ apiVersion, kind: "RoleSessionAccess", observedAt: roleSessionObservedAt, item: roleSessionListing() });
    const exact = await httpAccountRepository.roles!.readSession("bearer", account.id, role.id, roleSession.id);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}/sessions/${roleSession.id}`);
    expect(exact.item.session.id).toBe(roleSession.id);

    const revoked = { ...roleSession, status: "REVOKED", revokedAt: "2026-09-11T08:31:00Z" };
    fetcher = reply({ outcome: "APPLIED", session: revoked });
    const result = await httpAccountRepository.roles!.revokeSession("bearer", account.id, role.id, roleSession.id, "ui-role-session-revoke-one");
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}/sessions/${roleSession.id}:revoke`);
    expect(requestBody(fetcher)).toEqual({ requestId: "ui-role-session-revoke-one" });
    expect(result).toMatchObject({ outcome: "APPLIED", session: { status: "REVOKED" } });
  });

  it("does not accept a successful revoke shape with an active session or leaked credential", async () => {
    for (const response of [{ outcome: "APPLIED", session: roleSession }, { outcome: "APPLIED", session: { ...roleSession, status: "REVOKED", revokedAt: "2026-09-11T08:31:00Z" }, credential: "secret" }]) {
      reply(response);
      await expect(httpAccountRepository.roles!.revokeSession("bearer", account.id, role.id, roleSession.id, "ui-role-session-revoke-one")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });
});

describe("IAM HTTP member role self-service boundary", () => {
  const assumable = {
    roleId: role.id,
    accountId: account.id,
    name: role.name,
    status: "ACTIVE",
    maxSessionDurationSeconds: role.maxSessionDurationSeconds,
    resourceVersion: role.resourceVersion,
    capability: capability("iam.role.assume", "ROLE", role.id)
  };

  it("discovers only the current USER scope and preserves sparse discovery cursors", async () => {
    let fetcher = reply({ apiVersion, kind: "AssumableRoleList", accountId: account.id, sourceUserId: user.id, items: [], nextAfter: "ir1.next-window" });
    const first = await httpIamRepository.roleSelfService!.listAssumable("user-bearer");
    expect(first).toMatchObject({ accountId: account.id, sourceUserId: user.id, items: [], nextAfter: "ir1.next-window" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/assumable-roles");
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer user-bearer" } });

    fetcher = reply({ apiVersion, kind: "AssumableRoleList", accountId: account.id, sourceUserId: user.id, items: [assumable] });
    const second = await httpIamRepository.roleSelfService!.listAssumable("user-bearer", "ir1.next-window");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/assumable-roles?after=ir1.next-window");
    expect(second.items[0]).toMatchObject({ roleId: role.id, capability: { action: "iam.role.assume", available: true } });
  });

  it("sends only the frozen role intent and accepts a secret only on first application", async () => {
    const command = { resourceVersion: role.resourceVersion, durationSeconds: 3600, requestId: "ui-role-assume-one" };
    let fetcher = reply({ outcome: "APPLIED", session: roleSession, credential: "role-secret" });
    const applied = await httpIamRepository.roleSelfService!.assume("user-bearer", role.id, command);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}:assume`);
    expect(requestBody(fetcher)).toEqual(command);
    expect(applied).toMatchObject({ outcome: "APPLIED", credential: "role-secret", session: { sourceUserId: user.id } });

    fetcher = reply({ outcome: "EQUAL_REPLAY", session: roleSession });
    expect(await httpIamRepository.roleSelfService!.assume("user-bearer", role.id, command)).toMatchObject({ outcome: "EQUAL_REPLAY", credential: null });
    reply({ outcome: "EQUAL_REPLAY", session: roleSession, credential: "leaked-secret" });
    await expect(httpIamRepository.roleSelfService!.assume("user-bearer", role.id, command)).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("separates non-secret recovery, role-bearer identity, logout, and source revalidation", async () => {
    let fetcher = reply(roleSession);
    expect((await httpIamRepository.roleSelfService!.readByRequest("user-bearer", "ui-role-assume-one")).id).toBe(roleSession.id);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/role-sessions/by-request/ui-role-assume-one");

    const revoked = { ...roleSession, status: "REVOKED", revokedAt: "2026-09-11T08:31:00Z" };
    fetcher = reply(revoked);
    await httpIamRepository.roleSelfService!.revokeByRequest("user-bearer", "ui-role-assume-one", "ui-role-revoke-one");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/role-sessions/by-request/ui-role-assume-one:revoke");
    expect(requestBody(fetcher)).toEqual({ requestId: "ui-role-revoke-one" });

    fetcher = reply({
      apiVersion, kind: "CurrentRoleIdentity", session: roleSession,
      account: { id: account.id, displayName: account.displayName },
      role: { id: role.id, name: role.name },
      sourceUser: { id: user.id, loginName: user.loginName, displayName: user.displayName }
    });
    expect((await httpIamRepository.roleSelfService!.currentIdentity("role-bearer")).role.id).toBe(role.id);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/role-session");
    expect(firstRequest(fetcher)[1]).toMatchObject({ headers: { Authorization: "Bearer role-bearer" } });

    fetcher = reply(revoked);
    await httpIamRepository.roleSelfService!.logout("role-bearer", "ui-role-logout-one");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/role-session:logout");
    expect(requestBody(fetcher)).toEqual({ requestId: "ui-role-logout-one" });

    fetcher = reply({ apiVersion, kind: "CurrentIdentity", account, user, identityKind: "USER", policySources: [], permissionBoundary, capabilities: currentCapabilities() });
    await httpIamRepository.roleSelfService!.revalidateSource("user-bearer", account.id, user.id);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/me");
    expect(firstRequest(fetcher)[1]).toMatchObject({ headers: { Authorization: "Bearer user-bearer" } });
  });
});

const accessKey = { apiVersion, kind: "AccessKey", id: "mak1.alex-primary", accountId: account.id, userId: user.id,
  status: "ENABLED", networkRestrictions: { allowedSourceCidrs: ["198.51.100.0/24"] }, resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp };
function accessKeyAccess(value = accessKey) {
  return { key: value, usage: { observedAt: timestamp, lastAuthorization: {
    evaluatedAt: timestamp, allowed: false, product: "audit", action: "audit.record.read", sourceIp: "198.51.100.42"
  } }, capabilities: [
    capability("iam.access-key.read", "ACCESS_KEY", value.id),
    capability("iam.access-key.set-status", "ACCESS_KEY", value.id),
    capability("iam.access-key.set-network-restrictions", "ACCESS_KEY", value.id),
    capability("iam.access-key.delete", "ACCESS_KEY", value.id, value.status === "DISABLED", "TARGET_MUST_BE_DISABLED")
  ] };
}
function accessKeyList() {
  return { apiVersion, kind: "AccessKeyList", accountId: account.id, userId: user.id, userResourceVersion: user.resourceVersion,
    capabilities: [capability("iam.access-key.create", "USER", user.id)], items: [accessKeyAccess()] };
}

describe("IAM HTTP access-key boundary", () => {
  it("loads one exact per-user directory without an account selector", async () => {
    const fetcher = reply(accessKeyList());
    const result = await httpAccountRepository.accessKeys!.list("bearer", account.id, user.id);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/users/${user.id}/access-keys`);
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer bearer" } });
    expect(result).toMatchObject({ accountId: account.id, userId: user.id, userResourceVersion: 2 });
    expect(result.items[0]?.key).toMatchObject({ id: accessKey.id, status: "ENABLED", resourceVersion: 1 });
  });

  it("accepts the one-time secret only on a first applied creation", async () => {
    const fetcher = reply({ outcome: "APPLIED", key: accessKey, secret: "mak1.secret-material" });
    const result = await httpAccountRepository.accessKeys!.create("bearer", account.id, user.id, { userResourceVersion: 2, networkRestrictions: { allowedSourceCidrs: [] }, requestId: "create-key-1" });
    expect(result).toEqual(expect.objectContaining({ outcome: "APPLIED", secret: "mak1.secret-material" }));
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/users/${user.id}/access-keys`);
    expect(requestBody(fetcher)).toEqual({ userResourceVersion: 2, networkRestrictions: { allowedSourceCidrs: [] }, requestId: "create-key-1" });

    reply({ outcome: "EQUAL_REPLAY", key: accessKey, secret: "must-not-repeat" });
    await expect(httpAccountRepository.accessKeys!.create("bearer", account.id, user.id, { userResourceVersion: 2, networkRestrictions: { allowedSourceCidrs: [] }, requestId: "create-key-1" })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("keeps exact capability resource bindings and ordered key identities", async () => {
    reply({ ...accessKeyList(), items: [{ ...accessKeyAccess(), capabilities: [
      capability("iam.access-key.read", "ACCESS_KEY", "another-key"),
      capability("iam.access-key.set-status", "ACCESS_KEY", accessKey.id),
      capability("iam.access-key.set-network-restrictions", "ACCESS_KEY", accessKey.id),
      capability("iam.access-key.delete", "ACCESS_KEY", accessKey.id)
    ] }] });
    await expect(httpAccountRepository.accessKeys!.list("bearer", account.id, user.id)).rejects.toThrow("INVALID_IAM_RESPONSE");

    reply({ ...accessKeyList(), items: [accessKeyAccess({ ...accessKey, id: "mak1.z" }), accessKeyAccess({ ...accessKey, id: "mak1.a" })] });
    await expect(httpAccountRepository.accessKeys!.list("bearer", account.id, user.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("fails closed on malformed network and retained authorization observations", async () => {
    const base = accessKeyAccess();
    for (const invalid of [
      { ...base, key: { ...accessKey, networkRestrictions: undefined } },
      { ...base, key: { ...accessKey, networkRestrictions: { allowedSourceCidrs: ["198.51.100.1/24"] } } },
      { ...base, key: { ...accessKey, networkRestrictions: { allowedSourceCidrs: ["203.0.113.0/24", "198.51.100.0/24"] } } },
      { ...base, usage: {} },
      { ...base, usage: { ...base.usage, observedAt: "not-a-time" } },
      { ...base, usage: { ...base.usage, lastAuthorization: { ...base.usage.lastAuthorization, evaluatedAt: "2026-09-11T08:01:00Z" } } },
      { ...base, usage: { ...base.usage, lastAuthorization: { ...base.usage.lastAuthorization, product: "iam" } } },
      { ...base, usage: { ...base.usage, lastAuthorization: { ...base.usage.lastAuthorization, sourceIp: "0.0.0.0" } } },
      { ...base, usage: { ...base.usage, lastAuthorization: { ...base.usage.lastAuthorization, sourceIp: "2001:0db8::1" } } },
      { ...base, usage: { ...base.usage, extra: true } },
      { ...base, capabilities: base.capabilities.slice(0, 3) }
    ]) {
      reply({ ...accessKeyList(), items: [invalid] });
      await expect(httpAccountRepository.accessKeys!.list("bearer", account.id, user.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }

    reply({ ...accessKeyList(), items: [{ ...base, usage: { observedAt: timestamp } }] });
    await expect(httpAccountRepository.accessKeys!.list("bearer", account.id, user.id)).resolves.toMatchObject({
      items: [{ usage: { observedAt: timestamp } }]
    });
  });

  it("updates and deletes one key at its exact resource version", async () => {
    const disabled = { ...accessKey, status: "DISABLED", resourceVersion: 2, updatedAt: "2026-09-11T08:01:00Z" };
    let fetcher = reply({ outcome: "APPLIED", key: disabled });
    const status = await httpAccountRepository.accessKeys!.setStatus("bearer", account.id, user.id, accessKey.id, { accessKeyResourceVersion: 1, requestId: "disable-key-1", status: "DISABLED" });
    expect(status.key).toMatchObject({ status: "DISABLED", resourceVersion: 2 });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/users/${user.id}/access-keys/${accessKey.id}:set-status`);
    expect(requestBody(fetcher)).toEqual({ accessKeyResourceVersion: 1, requestId: "disable-key-1", status: "DISABLED" });

    const restricted = { ...accessKey, networkRestrictions: { allowedSourceCidrs: ["2001:db8::/32"] }, resourceVersion: 2, updatedAt: "2026-09-11T08:01:00Z" };
    fetcher = reply({ outcome: "APPLIED", key: restricted });
    const network = await httpAccountRepository.accessKeys!.setNetworkRestrictions("bearer", account.id, user.id, accessKey.id, {
      accessKeyResourceVersion: 1, networkRestrictions: restricted.networkRestrictions, requestId: "network-key-1"
    });
    expect(network.key.networkRestrictions).toEqual(restricted.networkRestrictions);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/users/${user.id}/access-keys/${accessKey.id}/network-restrictions`);
    expect(requestBody(fetcher)).toEqual({ accessKeyResourceVersion: 1, networkRestrictions: restricted.networkRestrictions, requestId: "network-key-1" });

    fetcher = reply({ outcome: "APPLIED", deletion: { apiVersion, kind: "AccessKeyDeletion", id: accessKey.id, accountId: account.id, userId: user.id, resourceVersion: 3, deletedAt: "2026-09-11T08:02:00Z" } });
    const deletion = await httpAccountRepository.accessKeys!.delete("bearer", account.id, user.id, accessKey.id, { accessKeyResourceVersion: 2, requestId: "delete-key-1" });
    expect(deletion.deletion).toMatchObject({ id: accessKey.id, resourceVersion: 3 });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/users/${user.id}/access-keys/${accessKey.id}:delete`);
  });
});

const securityReportCoverage = [
  { source: "IAM_ACCOUNT", state: "COMPLETE" },
  { source: "IAM_USERS", state: "COMPLETE" },
  { source: "IAM_LOGIN_SESSIONS", state: "COMPLETE" },
  { source: "IAM_ACCESS_KEYS", state: "COMPLETE" },
  { source: "IAM_ROLE_ACTIVITY", state: "NOT_INCLUDED" },
  { source: "PAAS_RESULTS", state: "NOT_INCLUDED" },
  { source: "AUDIT_STATISTICS", state: "NOT_INCLUDED" },
  { source: "NOTIFICATION_DELIVERY", state: "NOT_INCLUDED" },
  { source: "EXTERNAL_RISK", state: "NOT_INCLUDED" }
];

async function securityReportFixture(csv = new TextEncoder().encode("resource_type,resource_id\nACCOUNT,account-acme\n")) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", csv));
  const csvContentDigest = `sha256:${Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join("")}`;
  const metadata = {
    apiVersion, kind: "AccountSecurityReportMetadata", id: "report-one", accountId: account.id, formatVersion: 1,
    observedAt: "2026-09-11T08:00:00Z", expiresAt: "2026-09-18T08:00:00Z",
    documentDigest: `sha256:${"a".repeat(64)}`, csvContentDigest,
    userCount: 2, accessKeyCount: 1, rowCount: 4, csvBytes: csv.length
  };
  return { csv, report: {
    metadata, accountSecuritySettingsVersion: 4, coverage: securityReportCoverage,
    users: [{
      id: "root-acme", loginName: "admin", displayName: "Account owner", status: "ACTIVE", root: true,
      resourceVersion: 4, createdAt: "2026-01-01T00:00:00Z", mfa: { enrollmentState: "NEVER_BOUND", factorRevision: 1 },
      lastPasswordLogin: { state: "OBSERVED", observedAt: "2026-09-11T07:00:00Z" }
    }, {
      id: user.id, loginName: user.loginName, displayName: user.displayName, status: "ACTIVE", root: false,
      resourceVersion: user.resourceVersion, createdAt: "2026-02-01T00:00:00Z", mfa: { enrollmentState: "UNKNOWN" },
      lastPasswordLogin: { state: "UNKNOWN" }
    }],
    accessKeys: [{
      id: "key-alex", userId: user.id, status: "ENABLED", networkRestrictions: { allowedSourceCidrs: ["10.0.0.0/24"] },
      resourceVersion: 2, createdAt: "2026-03-01T00:00:00Z",
      lastAuthorization: { evaluatedAt: "2026-09-11T06:00:00Z", allowed: true, product: "paas", action: "paas.application.read", sourceIp: "10.0.0.8" }
    }]
  } };
}

describe("IAM HTTP account-security-report boundary", () => {
  it("creates and reads only the current-account report with the exact fixed request", async () => {
    const fixture = await securityReportFixture();
    let fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ outcome: "APPLIED", metadata: fixture.report.metadata }), {
      status: 201, headers: { "Content-Type": "application/json" }
    }));
    vi.stubGlobal("fetch", fetcher);
    const creation = await httpAccountRepository.securityReports!.create("bearer", account.id, { formatVersion: 1, requestId: "report-request-one" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/account/security-reports");
    expect(requestBody(fetcher as ReturnType<typeof reply>)).toEqual({ formatVersion: 1, requestId: "report-request-one" });
    expect(creation).toMatchObject({ outcome: "APPLIED", metadata: { id: "report-one", accountId: account.id } });

    fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(fixture.report), {
      status: 200, headers: { "Cache-Control": "no-store", "Content-Type": "application/json" }
    }));
    vi.stubGlobal("fetch", fetcher);
    const report = await httpAccountRepository.securityReports!.read("bearer", account.id, "report-one");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/account/security-reports/report-one");
    expect(report).toMatchObject({ metadata: { id: "report-one", rowCount: 4 }, users: [{ root: true }, { id: user.id }], accessKeys: [{ id: "key-alex" }] });
  });

  it("requires the protocol status that corresponds to APPLIED or EQUAL_REPLAY", async () => {
    const fixture = await securityReportFixture();
    for (const [status, outcome] of [[200, "APPLIED"], [201, "EQUAL_REPLAY"]] as const) {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ outcome, metadata: fixture.report.metadata }), {
        status, headers: { "Content-Type": "application/json" }
      })));
      await expect(httpAccountRepository.securityReports!.create("bearer", account.id, { formatVersion: 1, requestId: "report-request-one" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("re-reads current metadata and verifies exact CSV bytes before returning a download", async () => {
    const fixture = await securityReportFixture();
    const fetcher = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(fixture.report), { status: 200, headers: { "Cache-Control": "no-store", "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(fixture.csv, { status: 200, headers: {
        "Cache-Control": "no-store", "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="matrix-iam-security-report-report-one.csv"'
      } }));
    vi.stubGlobal("fetch", fetcher);
    const result = await httpAccountRepository.securityReports!.download("bearer", account.id, "report-one");
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls.map((call) => call[0])).toEqual([
      "/api/iam/v1/account/security-reports/report-one",
      "/api/iam/v1/account/security-reports/report-one/content"
    ]);
    expect(result.filename).toBe("matrix-iam-security-report-report-one.csv");
    expect(Array.from(result.bytes)).toEqual(Array.from(fixture.csv));
  });

  it("fails closed for foreign reports, expanded documents, reordered coverage, and corrupted CSV", async () => {
    const fixture = await securityReportFixture();
    for (const response of [
      { ...fixture.report, metadata: { ...fixture.report.metadata, accountId: "account-foreign" } },
      { ...fixture.report, leakedAuthority: true },
      { ...fixture.report, coverage: [securityReportCoverage[1], securityReportCoverage[0], ...securityReportCoverage.slice(2)] }
    ]) {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(response), {
        status: 200, headers: { "Cache-Control": "no-store", "Content-Type": "application/json" }
      })));
      await expect(httpAccountRepository.securityReports!.read("bearer", account.id, "report-one")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(fixture.report), {
      status: 200, headers: { "Content-Type": "application/json" }
    })));
    await expect(httpAccountRepository.securityReports!.read("bearer", account.id, "report-one")).rejects.toThrow("INVALID_IAM_RESPONSE");

    const corrupted = Uint8Array.from(fixture.csv);
    corrupted[corrupted.length - 2] = corrupted[corrupted.length - 2]! ^ 1;
    vi.stubGlobal("fetch", vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(fixture.report), { status: 200, headers: { "Cache-Control": "no-store", "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(corrupted, { status: 200, headers: {
        "Cache-Control": "no-store", "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="matrix-iam-security-report-report-one.csv"'
      } })));
    await expect(httpAccountRepository.securityReports!.download("bearer", account.id, "report-one")).rejects.toThrow("INVALID_IAM_RESPONSE");
  });
});

const accessAnalyzer = {
  apiVersion, kind: "AccessAnalyzer", id: "analyzer-unused", accountId: account.id,
  type: "UNUSED_ACCESS", status: "ACTIVE", unusedAccessAgeDays: 90,
  disposition: { mode: "REVIEW_ONLY", findingDelayDays: 0 }, resourceVersion: 1,
  createdAt: "2026-06-11T08:00:00Z", updatedAt: "2026-06-11T08:00:00Z"
};
const accessFinding = {
  apiVersion, kind: "AccessFinding", id: "finding-password-alex", accountId: account.id,
  analyzerId: accessAnalyzer.id, analyzerRevision: accessAnalyzer.resourceVersion,
  type: "UNUSED_PASSWORD", status: "ACTIVE", target: { kind: "USER", id: user.id },
  targetResourceVersion: user.resourceVersion, conditionGeneration: 1, activityRevision: 1, recoveryEpoch: 0,
  windowStartedAt: "2026-06-11T08:00:00Z", observedAt: "2026-09-11T08:00:00Z",
  lastActivityAt: "2026-06-01T08:00:00Z", resourceVersion: 1,
  createdAt: "2026-09-11T07:00:00Z", updatedAt: "2026-09-11T07:00:00Z"
};
const accessCoverage = [
  { source: "IAM_PASSWORD_SESSIONS", state: "COMPLETE", observedFrom: "2026-06-11T08:00:00Z", observedThrough: "2026-09-11T08:00:00Z" },
  { source: "IAM_ACCESS_KEY_AUTHORIZATIONS", state: "INSUFFICIENT_COVERAGE", observedFrom: "2026-08-11T08:00:00Z", observedThrough: "2026-09-11T08:00:00Z", reason: "SOURCE_NOT_READY" },
  { source: "IAM_ROLE_SESSIONS", state: "COMPLETE", observedFrom: "2026-06-11T08:00:00Z", observedThrough: "2026-09-11T08:00:00Z" },
  { source: "IAM_ROLE_AUTHORIZATIONS", state: "COMPLETE", observedFrom: "2026-06-11T08:00:00Z", observedThrough: "2026-09-11T08:00:00Z" },
  { source: "PAAS_RESULTS", state: "NOT_INCLUDED", reason: "SOURCE_NOT_IMPLEMENTED" },
  { source: "EXTERNAL_FEDERATION", state: "NOT_INCLUDED", reason: "SOURCE_NOT_IMPLEMENTED" }
];
function accessFindingList(items: unknown[] = [accessFinding], coverage = accessCoverage) {
  return {
    apiVersion, kind: "AccessFindingList", accountId: account.id, analyzerId: accessAnalyzer.id,
    observedAt: "2026-09-11T08:00:00Z", coverage, items
  };
}

describe("IAM HTTP access-analysis boundary", () => {
  it("loads and mutates one current-account analyzer without an account selector", async () => {
    let fetcher = reply({ apiVersion, kind: "AccessAnalyzerList", accountId: account.id, items: [accessAnalyzer] });
    const directory = await httpAccountRepository.accessAnalysis!.listAnalyzers("bearer", account.id);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/account/access-analyzers");
    expect(directory).toMatchObject({ accountId: account.id, nextAfter: null, items: [{ id: accessAnalyzer.id, unusedAccessAgeDays: 90 }] });

    fetcher = reply(accessAnalyzer);
    expect((await httpAccountRepository.accessAnalysis!.readAnalyzer("bearer", account.id, accessAnalyzer.id)).id).toBe(accessAnalyzer.id);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/account/access-analyzers/${accessAnalyzer.id}`);

    fetcher = reply(accessAnalyzer);
    await httpAccountRepository.accessAnalysis!.createAnalyzer("bearer", account.id, { type: "UNUSED_ACCESS", requestId: "create-analyzer-one" });
    expect(requestBody(fetcher)).toEqual({ type: "UNUSED_ACCESS", requestId: "create-analyzer-one" });

    const updated = { ...accessAnalyzer, status: "DISABLED", unusedAccessAgeDays: 120, resourceVersion: 2, updatedAt: "2026-06-11T08:01:00Z" };
    fetcher = reply(updated);
    const result = await httpAccountRepository.accessAnalysis!.updateAnalyzer("bearer", account.id, accessAnalyzer.id, {
      status: "DISABLED", unusedAccessAgeDays: 120, resourceVersion: 1, requestId: "update-analyzer-one"
    });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/account/access-analyzers/${accessAnalyzer.id}:update`);
    expect(requestBody(fetcher)).toEqual({ status: "DISABLED", unusedAccessAgeDays: 120, resourceVersion: 1, requestId: "update-analyzer-one" });
    expect(result).toMatchObject({ status: "DISABLED", resourceVersion: 2 });

    const optedIn = { ...updated, disposition: { mode: "DISABLE_UNUSED_ACCESS_KEYS", findingDelayDays: 7 }, resourceVersion: 3, updatedAt: "2026-06-11T08:02:00Z" };
    fetcher = reply(optedIn);
    const disposition = await httpAccountRepository.accessAnalysis!.setDisposition("bearer", account.id, accessAnalyzer.id, {
      disposition: { mode: "DISABLE_UNUSED_ACCESS_KEYS", findingDelayDays: 7 }, resourceVersion: 2, requestId: "set-disposition-one"
    });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/account/access-analyzers/${accessAnalyzer.id}:set-disposition`);
    expect(requestBody(fetcher)).toEqual({ disposition: { mode: "DISABLE_UNUSED_ACCESS_KEYS", findingDelayDays: 7 }, resourceVersion: 2, requestId: "set-disposition-one" });
    expect(disposition).toMatchObject({ disposition: { mode: "DISABLE_UNUSED_ACCESS_KEYS", findingDelayDays: 7 }, resourceVersion: 3 });
  });

  it("binds the finding lifecycle filter and opaque cursor into the exact list request", async () => {
    const fetcher = reply(accessFindingList());
    const result = await httpAccountRepository.accessAnalysis!.listFindings("bearer", account.id, accessAnalyzer.id, "ACTIVE", "ic1.next-page");
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/account/access-analyzers/${accessAnalyzer.id}/findings?status=ACTIVE&after=ic1.next-page`);
    expect(result).toMatchObject({ accountId: account.id, analyzerId: accessAnalyzer.id, nextAfter: null });
    expect(result.coverage[0]).toMatchObject({ source: "IAM_PASSWORD_SESSIONS", state: "COMPLETE", reason: null });
    expect(result.items[0]).toMatchObject({ id: accessFinding.id, type: "UNUSED_PASSWORD", status: "ACTIVE", target: { kind: "USER", id: user.id } });
  });

  it("archives and unarchives only the selected finding at its exact resource version", async () => {
    const archived = { ...accessFinding, status: "ARCHIVED", resourceVersion: 2, updatedAt: "2026-09-11T08:01:00Z" };
    let fetcher = reply(archived);
    const archivedResult = await httpAccountRepository.accessAnalysis!.archiveFinding("bearer", account.id, accessAnalyzer.id, accessFinding.id, {
      resourceVersion: 1, requestId: "archive-finding-one"
    });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/account/access-analyzers/${accessAnalyzer.id}/findings/${accessFinding.id}:archive`);
    expect(requestBody(fetcher)).toEqual({ resourceVersion: 1, requestId: "archive-finding-one" });
    expect(archivedResult).toMatchObject({ status: "ARCHIVED", resourceVersion: 2 });

    const active = { ...accessFinding, resourceVersion: 3, updatedAt: "2026-09-11T08:02:00Z" };
    fetcher = reply(active);
    const activeResult = await httpAccountRepository.accessAnalysis!.unarchiveFinding("bearer", account.id, accessAnalyzer.id, accessFinding.id, {
      resourceVersion: 2, requestId: "unarchive-finding-one"
    });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/account/access-analyzers/${accessAnalyzer.id}/findings/${accessFinding.id}:unarchive`);
    expect(activeResult).toMatchObject({ status: "ACTIVE", resourceVersion: 3 });
  });

  it("rejects foreign ownership, reordered coverage, mismatched targets, and invented resolutions", async () => {
    const invalidResponses = [
      { ...accessFindingList(), accountId: "account-foreign" },
      accessFindingList([accessFinding], [accessCoverage[1]!, accessCoverage[0]!, ...accessCoverage.slice(2)]),
      accessFindingList([{ ...accessFinding, target: { kind: "ROLE", id: "role-foreign" } }]),
      accessFindingList([{ ...accessFinding, status: "RESOLVED" }])
    ];
    for (const response of invalidResponses) {
      reply(response);
      await expect(httpAccountRepository.accessAnalysis!.listFindings("bearer", account.id, accessAnalyzer.id, "ALL")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("rejects response expansion and invalid analyzer command values before they become UI state", async () => {
    reply({ ...accessAnalyzer, leakedAuthority: true });
    await expect(httpAccountRepository.accessAnalysis!.readAnalyzer("bearer", account.id, accessAnalyzer.id)).rejects.toThrow("INVALID_IAM_RESPONSE");

    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    await expect(httpAccountRepository.accessAnalysis!.createAnalyzer("bearer", account.id, {
      type: "UNUSED_ACCESS", unusedAccessAgeDays: 0, requestId: "create-analyzer-invalid"
    })).rejects.toThrow();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("requires the fixed disposition shape and resolved Finding reason", async () => {
    const invalidAnalyzers = [
      Object.fromEntries(Object.entries(accessAnalyzer).filter(([key]) => key !== "disposition")),
      { ...accessAnalyzer, disposition: { mode: "REVIEW_ONLY", findingDelayDays: 1 } },
      { ...accessAnalyzer, disposition: { mode: "DISABLE_UNUSED_ACCESS_KEYS", findingDelayDays: 31 } },
      { ...accessAnalyzer, disposition: { mode: "REVIEW_ONLY", findingDelayDays: 0, extra: true } }
    ];
    for (const response of invalidAnalyzers) {
      reply(response);
      await expect(httpAccountRepository.accessAnalysis!.readAnalyzer("bearer", account.id, accessAnalyzer.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }

    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    await expect(httpAccountRepository.accessAnalysis!.setDisposition("bearer", account.id, accessAnalyzer.id, {
      disposition: { mode: "DISABLE_UNUSED_ACCESS_KEYS", findingDelayDays: 31 }, resourceVersion: 1, requestId: "invalid-disposition"
    } as never)).rejects.toThrow("INVALID_IAM_REQUEST");
    expect(fetcher).not.toHaveBeenCalled();

    const resolved = {
      ...accessFinding,
      status: "RESOLVED",
      observedAt: "2026-09-11T08:00:00Z",
      updatedAt: "2026-09-11T08:00:00Z",
      resolvedAt: "2026-09-11T08:00:00Z",
      resolutionReason: "AUTOMATIC_DISPOSITION"
    };
    reply(accessFindingList([resolved]));
    const directory = await httpAccountRepository.accessAnalysis!.listFindings("bearer", account.id, accessAnalyzer.id, "RESOLVED");
    expect(directory.items[0]).toMatchObject({ status: "RESOLVED", resolutionReason: "AUTOMATIC_DISPOSITION" });

    for (const response of [
      accessFindingList([{ ...resolved, resolutionReason: undefined }]),
      accessFindingList([{ ...accessFinding, resolutionReason: "CONDITION_CLEARED" }])
    ]) {
      reply(response);
      await expect(httpAccountRepository.accessAnalysis!.listFindings("bearer", account.id, accessAnalyzer.id, "ALL")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });
});

const notificationContact = {
  apiVersion, kind: "NotificationContact", accountId: account.id, userId: user.id,
  state: "NONE", resourceVersion: 0
};
const notificationVerification = {
  apiVersion, kind: "NotificationContactVerification", id: "verification-primary", accountId: account.id,
  userId: user.id, requestId: "verify-contact-1", email: "Admin@example.com", state: "PENDING",
  issuedAt: timestamp, expiresAt: "2026-09-11T08:10:00Z",
  delivery: { state: "PENDING", attempts: 0, updatedAt: timestamp }
};
const pendingEnrollment = {
  apiVersion, kind: "TOTPEnrollment", id: "enrollment-primary", requestId: "enroll-factor-1",
  factorRevision: 1, state: "PENDING", createdAt: timestamp, expiresAt: "2026-09-11T08:05:00Z"
};

describe("IAM HTTP personal-security boundary", () => {
  it("uses current-session resources without account or user selectors", async () => {
    let fetcher = reply(notificationContact);
    const contact = await httpIamRepository.personalSecurity!.notificationContact("bearer");
    expect(contact).toEqual({ accountId: account.id, userId: user.id, state: "NONE", resourceVersion: 0, pendingVerificationId: null });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/notification-contact");
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer bearer" } });

    fetcher = reply({
      apiVersion, kind: "NotificationContact", accountId: account.id, userId: user.id,
      state: "VERIFIED", resourceVersion: 7, email: "old@example.com", verifiedAt: timestamp,
      pendingVerificationId: "verification-replacement-1"
    });
    await expect(httpIamRepository.personalSecurity!.notificationContact("bearer")).resolves.toMatchObject({
      state: "VERIFIED", email: "old@example.com", resourceVersion: 7, pendingVerificationId: "verification-replacement-1"
    });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/notification-contact");

    fetcher = reply(notificationVerification);
    await httpIamRepository.personalSecurity!.startNotificationVerification("bearer", {
      email: "Admin@example.com", password: "private-password", requestId: "verify-contact-1"
    });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/notification-contact/verifications");
    expect(requestBody(fetcher)).toEqual({ email: "Admin@example.com", password: "private-password", requestId: "verify-contact-1" });

    fetcher = reply({ apiVersion, kind: "AuthenticatorState", enrollmentState: "NEVER_BOUND", factorRevision: 1 });
    expect(await httpIamRepository.personalSecurity!.authenticatorState("bearer")).toEqual({ enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/authenticators");
  });

  it("binds notification-address replacement to one exact proof, version, and candidate address", async () => {
    const requestId = "replace-notification-contact-1";
    const notificationContact = { expectedResourceVersion: 7, email: "Security@example.com" };
    const stepUp = {
      apiVersion, kind: "StepUp", id: "step-up-notification-1", requestId,
      operation: "NOTIFICATION_CONTACT_REPLACE", expectedFactorRevision: 3, notificationContact,
      state: "PENDING", createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z"
    };
    let fetcher = reply(stepUp);
    await expect(httpIamRepository.personalSecurity!.notificationReplacement!.startStepUp("bearer", {
      requestId, expectedFactorRevision: 3, notificationContact
    })).resolves.toMatchObject({ operation: "NOTIFICATION_CONTACT_REPLACE", notificationContact, state: "PENDING" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/step-up");
    expect(requestBody(fetcher)).toEqual({
      requestId, operation: "NOTIFICATION_CONTACT_REPLACE", expectedFactorRevision: 3, notificationContact
    });

    fetcher = reply(stepUp);
    await httpIamRepository.personalSecurity!.notificationReplacement!.stepUpByRequest(
      "bearer", requestId, 3, notificationContact
    );
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/step-up/by-request/${requestId}`);

    fetcher = reply({ ...stepUp, state: "PROVED", provedAt: "2026-09-11T08:00:30Z" });
    await httpIamRepository.personalSecurity!.notificationReplacement!.verifyStepUp(
      "bearer", stepUp.id, requestId, 3, notificationContact,
      { requestId: "prove-notification-contact-1", password: "private-password", code: "123456" }
    );
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/step-up/${stepUp.id}:verify`);
    expect(requestBody(fetcher)).toEqual({
      requestId: "prove-notification-contact-1", password: "private-password", code: "123456"
    });

    const verification = {
      apiVersion, kind: "NotificationContactVerification", id: "verification-replacement-1",
      accountId: account.id, userId: user.id, requestId, purpose: "REPLACEMENT",
      expectedResourceVersion: 7, email: "Security@example.com", state: "PENDING",
      issuedAt: timestamp, expiresAt: "2026-09-11T08:10:00Z",
      delivery: { state: "PENDING", attempts: 0, updatedAt: timestamp }
    };
    fetcher = reply(verification);
    await expect(httpIamRepository.personalSecurity!.notificationReplacement!.startVerification("bearer", {
      stepUpId: stepUp.id, requestId, ...notificationContact
    })).resolves.toMatchObject({ purpose: "REPLACEMENT", expectedResourceVersion: 7, state: "PENDING" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/notification-contact/replacements");
    expect(requestBody(fetcher)).toEqual({ stepUpId: stepUp.id, requestId, ...notificationContact });

    fetcher = reply(verification);
    await httpIamRepository.personalSecurity!.notificationReplacement!.verification(
      "bearer", verification.id, { requestId, ...notificationContact }
    );
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/notification-contact/verifications/${verification.id}`);

    fetcher = reply({ ...verification, state: "VERIFIED", completedAt: "2026-09-11T08:01:00Z" });
    await httpIamRepository.personalSecurity!.notificationReplacement!.confirmVerification(
      "bearer", verification.id, { requestId, ...notificationContact },
      { requestId: "confirm-notification-contact-1", code: "12345678" }
    );
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/notification-contact/verifications/${verification.id}:confirm`);
    expect(requestBody(fetcher)).toEqual({ requestId: "confirm-notification-contact-1", code: "12345678" });
  });

  it("fails closed when notification replacement drifts from its original intent", async () => {
    const requestId = "replace-notification-contact-1";
    const notificationContact = { expectedResourceVersion: 7, email: "Security@example.com" };
    const stepUp = {
      apiVersion, kind: "StepUp", id: "step-up-notification-1", requestId,
      operation: "NOTIFICATION_CONTACT_REPLACE", expectedFactorRevision: 3, notificationContact,
      state: "PENDING", createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z"
    };
    for (const body of [
      { ...stepUp, notificationContact: { ...notificationContact, expectedResourceVersion: 8 } },
      { ...stepUp, notificationContact: { ...notificationContact, email: "Other@example.com" } },
      { ...stepUp, notificationContact: undefined },
      { ...stepUp, operation: "TOTP_REPLACE" }
    ]) {
      reply(body);
      await expect(httpIamRepository.personalSecurity!.notificationReplacement!.stepUpByRequest(
        "bearer", requestId, 3, notificationContact
      )).rejects.toThrow("INVALID_IAM_RESPONSE");
    }

    const verification = {
      apiVersion, kind: "NotificationContactVerification", id: "verification-replacement-1",
      accountId: account.id, userId: user.id, requestId, purpose: "REPLACEMENT",
      expectedResourceVersion: 7, email: "Security@example.com", state: "PENDING",
      issuedAt: timestamp, expiresAt: "2026-09-11T08:10:00Z",
      delivery: { state: "PENDING", attempts: 0, updatedAt: timestamp }
    };
    for (const body of [
      { ...verification, purpose: "FIRST_ADDRESS" },
      { ...verification, expectedResourceVersion: 8 },
      { ...verification, requestId: "another-request" },
      { ...verification, email: "Other@example.com" },
      { ...verification, purpose: undefined }
    ]) {
      reply(body);
      await expect(httpIamRepository.personalSecurity!.notificationReplacement!.verification(
        "bearer", verification.id, { requestId, ...notificationContact }
      )).rejects.toThrow("INVALID_IAM_RESPONSE");
    }

    for (const action of [
      () => httpIamRepository.personalSecurity!.notificationReplacement!.startStepUp("bearer", {
        requestId, expectedFactorRevision: 1, notificationContact
      }),
      () => httpIamRepository.personalSecurity!.notificationReplacement!.startVerification("bearer", {
        stepUpId: stepUp.id, requestId, expectedResourceVersion: 0, email: notificationContact.email
      }),
      () => httpIamRepository.personalSecurity!.notificationReplacement!.confirmVerification(
        "bearer", verification.id, { requestId, ...notificationContact }, { requestId: "confirm-one", code: "123" }
      )
    ]) {
      const fetcher = reply({});
      await expect(action()).rejects.toThrow("INVALID_IAM_RESPONSE");
      expect(fetcher).not.toHaveBeenCalled();
    }
  });

  it("binds recovery-code regeneration to one purpose-limited proof and original request", async () => {
    const requestId = "regenerate-codes-1";
    const stepUp = {
      apiVersion, kind: "StepUp", id: "step-up-1", requestId,
      operation: "RECOVERY_CODES_REGENERATE", expectedFactorRevision: 2, state: "PENDING",
      createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z"
    };
    let fetcher = reply(stepUp);
    await expect(httpIamRepository.personalSecurity!.recoveryCodes!.startStepUp("bearer", {
      requestId, expectedFactorRevision: 2
    })).resolves.toMatchObject({ id: "step-up-1", state: "PENDING" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/step-up");
    expect(requestBody(fetcher)).toEqual({ requestId, operation: "RECOVERY_CODES_REGENERATE", expectedFactorRevision: 2 });

    fetcher = reply(stepUp);
    await httpIamRepository.personalSecurity!.recoveryCodes!.stepUpByRequest("bearer", requestId);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/step-up/by-request/${requestId}`);

    const proved = { ...stepUp, state: "PROVED", provedAt: "2026-09-11T08:00:30Z" };
    fetcher = reply(proved);
    await httpIamRepository.personalSecurity!.recoveryCodes!.verifyStepUp("bearer", "step-up-1", {
      requestId: "verify-step-up-1", password: "private-password", code: "123456"
    });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/step-up/step-up-1:verify");
    expect(requestBody(fetcher)).toEqual({ requestId: "verify-step-up-1", password: "private-password", code: "123456" });

    const regeneration = {
      apiVersion, kind: "RecoveryCodeRegeneration", id: "regeneration-1", requestId,
      factorId: "factor-1", factorRevision: 2, createdAt: "2026-09-11T08:00:40Z"
    };
    const recoveryCodes = Array.from({ length: 10 }, (_, index) => `NEW-RECOVERY-${index}`);
    fetcher = reply({ outcome: "APPLIED", regeneration, recoveryCodes });
    await expect(httpIamRepository.personalSecurity!.recoveryCodes!.regenerate("bearer", {
      requestId, stepUpId: "step-up-1", expectedFactorRevision: 2
    })).resolves.toMatchObject({ outcome: "APPLIED", recoveryCodes });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/recovery-codes:regenerate");
    expect(requestBody(fetcher)).toEqual({ requestId, stepUpId: "step-up-1", expectedFactorRevision: 2 });

    fetcher = reply(regeneration);
    await httpIamRepository.personalSecurity!.recoveryCodes!.regenerationByRequest("bearer", requestId);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/recovery-codes/regenerations/by-request/${requestId}`);
  });

  it("rejects malformed step-up states and any replayed recovery-code secret", async () => {
    const requestId = "regenerate-codes-1";
    const stepUp = {
      apiVersion, kind: "StepUp", id: "step-up-1", requestId,
      operation: "RECOVERY_CODES_REGENERATE", expectedFactorRevision: 2, state: "PENDING",
      createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z"
    };
    for (const body of [
      { ...stepUp, expiresAt: "2026-09-11T08:01:59Z" },
      { ...stepUp, state: "PROVED" },
      { ...stepUp, operation: "LOGIN" },
      { ...stepUp, expectedFactorRevision: 1 },
      { ...stepUp, state: "CONSUMED", provedAt: "2026-09-11T08:00:30Z" }
    ]) {
      reply(body);
      await expect(httpIamRepository.personalSecurity!.recoveryCodes!.stepUpByRequest("bearer", requestId)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }

    const regeneration = {
      apiVersion, kind: "RecoveryCodeRegeneration", id: "regeneration-1", requestId,
      factorId: "factor-1", factorRevision: 2, createdAt: "2026-09-11T08:00:40Z"
    };
    reply({ outcome: "EQUAL_REPLAY", regeneration, recoveryCodes: [] });
    await expect(httpIamRepository.personalSecurity!.recoveryCodes!.regenerate("bearer", {
      requestId, stepUpId: "step-up-1", expectedFactorRevision: 2
    })).rejects.toThrow("INVALID_IAM_RESPONSE");

    reply({ outcome: "APPLIED", regeneration, recoveryCodes: Array(10).fill("DUPLICATE") });
    await expect(httpIamRepository.personalSecurity!.recoveryCodes!.regenerate("bearer", {
      requestId, stepUpId: "step-up-1", expectedFactorRevision: 2
    })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("accepts provisioning only on the first applied enrollment response", async () => {
    const fetcher = reply({ outcome: "APPLIED", enrollment: pendingEnrollment, provisioning: { seed: "SECRETBASE32", uri: "otpauth://totp/Matrix:alex?secret=SECRETBASE32" } });
    const applied = await httpIamRepository.personalSecurity!.startTOTPEnrollment("bearer", {
      requestId: "enroll-factor-1", password: "private-password", expectedFactorRevision: 1
    });
    expect(applied).toMatchObject({ outcome: "APPLIED", provisioning: { seed: "SECRETBASE32" } });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/totp/enrollments");
    expect(requestBody(fetcher)).toEqual({ requestId: "enroll-factor-1", password: "private-password", expectedFactorRevision: 1 });

    reply({ outcome: "EQUAL_REPLAY", enrollment: pendingEnrollment, provisioning: { seed: "leaked", uri: "leaked" } });
    await expect(httpIamRepository.personalSecurity!.startTOTPEnrollment("bearer", {
      requestId: "enroll-factor-1", password: "private-password", expectedFactorRevision: 1
    })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("binds replacement to a TOTP_REPLACE proof and accepts only the original two-minute window", async () => {
    const requestId = "replace-factor-1";
    const stepUp = {
      apiVersion, kind: "StepUp", id: "step-up-replace-1", requestId,
      operation: "TOTP_REPLACE", expectedFactorRevision: 2, state: "PENDING",
      createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z"
    };
    let fetcher = reply(stepUp);
    await expect(httpIamRepository.personalSecurity!.replacement!.startStepUp("bearer", { requestId, expectedFactorRevision: 2 })).resolves.toMatchObject({ operation: "TOTP_REPLACE", state: "PENDING" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/step-up");
    expect(requestBody(fetcher)).toEqual({ requestId, operation: "TOTP_REPLACE", expectedFactorRevision: 2 });

    fetcher = reply({ ...stepUp, state: "PROVED", provedAt: "2026-09-11T08:00:30Z" });
    await httpIamRepository.personalSecurity!.replacement!.verifyStepUp("bearer", stepUp.id, { requestId: "verify-replace-1", password: "private-password", code: "123456" });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/step-up/${stepUp.id}:verify`);
    expect(requestBody(fetcher)).toEqual({ requestId: "verify-replace-1", password: "private-password", code: "123456" });

    const replacementEnrollment = { ...pendingEnrollment, requestId, purpose: "REPLACEMENT", factorRevision: 2, expiresAt: "2026-09-11T08:01:58Z" };
    fetcher = reply({ outcome: "APPLIED", enrollment: replacementEnrollment, provisioning: { seed: "NEWSECRET", uri: "otpauth://totp/Matrix:new?secret=NEWSECRET" } });
    await expect(httpIamRepository.personalSecurity!.replacement!.startEnrollment("bearer", { requestId, stepUpId: stepUp.id, expectedFactorRevision: 2 })).resolves.toMatchObject({ outcome: "APPLIED", enrollment: { purpose: "REPLACEMENT" } });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/totp/enrollments:replace");
    expect(requestBody(fetcher)).toEqual({ requestId, stepUpId: stepUp.id, expectedFactorRevision: 2 });

    fetcher = reply(replacementEnrollment);
    await expect(httpIamRepository.personalSecurity!.replacement!.enrollmentByRequest("bearer", requestId)).resolves.toMatchObject({ purpose: "REPLACEMENT" });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/totp/enrollments/by-request/${requestId}`);

    for (const invalid of [
      { ...replacementEnrollment, purpose: undefined },
      { ...replacementEnrollment, purpose: "INITIAL" },
      { ...replacementEnrollment, factorRevision: 1 },
      { ...replacementEnrollment, expiresAt: "2026-09-11T08:02:01Z" }
    ]) {
      reply({ outcome: "APPLIED", enrollment: invalid, provisioning: { seed: "NEWSECRET", uri: "otpauth://totp/Matrix:new?secret=NEWSECRET" } });
      await expect(httpIamRepository.personalSecurity!.replacement!.startEnrollment("bearer", { requestId, stepUpId: stepUp.id, expectedFactorRevision: 2 })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    reply({ ...stepUp, operation: "RECOVERY_CODES_REGENERATE" });
    await expect(httpIamRepository.personalSecurity!.replacement!.stepUpByRequest("bearer", requestId)).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ ...stepUp, operation: "TOTP_REPLACE" });
    await expect(httpIamRepository.personalSecurity!.recoveryCodes!.stepUpByRequest("bearer", requestId)).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("requires a confirmed enrollment and exactly ten unique recovery codes", async () => {
    const confirmed = { ...pendingEnrollment, state: "CONFIRMED", completedAt: "2026-09-11T08:04:00Z" };
    const recoveryCodes = Array.from({ length: 10 }, (_, index) => `RECOVERY-${index}`);
    const fetcher = reply({ enrollment: confirmed, nextStep: "REAUTHENTICATE", recoveryCodes });
    const result = await httpIamRepository.personalSecurity!.confirmTOTPEnrollment("bearer", pendingEnrollment.id, { requestId: "confirm-factor-1", code: "123456" });
    expect(result.recoveryCodes).toEqual(recoveryCodes);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/totp/enrollments/${pendingEnrollment.id}:confirm`);
    expect(requestBody(fetcher)).toEqual({ requestId: "confirm-factor-1", code: "123456" });

    for (const invalidCodes of [recoveryCodes.slice(0, 9), [...recoveryCodes.slice(0, 9), recoveryCodes[0]]]) {
      reply({ enrollment: confirmed, nextStep: "REAUTHENTICATE", recoveryCodes: invalidCodes });
      await expect(httpIamRepository.personalSecurity!.confirmTOTPEnrollment("bearer", pendingEnrollment.id, { requestId: "confirm-factor-1", code: "123456" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("fails closed on malformed state unions, lifetimes, delivery evidence, and replay secrets", async () => {
    const invalidBodies = [
      { action: () => httpIamRepository.personalSecurity!.notificationContact("bearer"), body: { ...notificationContact, resourceVersion: 1 } },
      { action: () => httpIamRepository.personalSecurity!.notificationContact("bearer"), body: { ...notificationContact, state: "VERIFIED", resourceVersion: 1 } },
      { action: () => httpIamRepository.personalSecurity!.notificationVerification("bearer", notificationVerification.id), body: { ...notificationVerification, expiresAt: "2026-09-11T08:09:59Z" } },
      { action: () => httpIamRepository.personalSecurity!.notificationVerification("bearer", notificationVerification.id), body: { ...notificationVerification, issuedAt: "2026-09-11T08:00:00.000001Z", expiresAt: "2026-09-11T08:10:00.000999Z", delivery: { ...notificationVerification.delivery, updatedAt: "2026-09-11T08:00:00.000001Z" } } },
      { action: () => httpIamRepository.personalSecurity!.notificationVerification("bearer", notificationVerification.id), body: { ...notificationVerification, delivery: { state: "ACCEPTED", attempts: 1, updatedAt: timestamp } } },
      { action: () => httpIamRepository.personalSecurity!.notificationVerification("bearer", notificationVerification.id), body: { ...notificationVerification, delivery: { state: "EXPIRED", attempts: 1, updatedAt: timestamp } } },
      { action: () => httpIamRepository.personalSecurity!.authenticatorState("bearer"), body: { apiVersion, kind: "AuthenticatorState", enrollmentState: "BOUND", factorRevision: 1, factorId: "factor-one" } },
      { action: () => httpIamRepository.personalSecurity!.totpEnrollment("bearer", pendingEnrollment.id), body: { ...pendingEnrollment, expiresAt: "2026-09-11T08:04:59Z" } },
      { action: () => httpIamRepository.personalSecurity!.totpEnrollment("bearer", pendingEnrollment.id), body: { ...pendingEnrollment, purpose: "REPLACEMENT" } },
      { action: () => httpIamRepository.personalSecurity!.startTOTPEnrollment("bearer", { requestId: "enroll-factor-1", password: "private-password", expectedFactorRevision: 1 }), body: { outcome: "EQUAL_REPLAY", enrollment: pendingEnrollment, provisioning: { seed: "leaked", uri: "leaked" } } }
    ];
    for (const item of invalidBodies) {
      reply(item.body);
      await expect(item.action()).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("rejects malformed security commands before sending secrets", async () => {
    for (const action of [
      () => httpIamRepository.personalSecurity!.startNotificationVerification("bearer", { email: "admin@Example.com", password: "private", requestId: "contact-one" }),
      () => httpIamRepository.personalSecurity!.startNotificationVerification("bearer", { email: "admin@example.com", password: "", requestId: "contact-one" }),
      () => httpIamRepository.personalSecurity!.confirmNotificationVerification("bearer", "verification-one", { code: "123", requestId: "confirm-one" }),
      () => httpIamRepository.personalSecurity!.startTOTPEnrollment("bearer", { requestId: "enroll-one", password: "private", expectedFactorRevision: Number.MAX_SAFE_INTEGER }),
      () => httpIamRepository.personalSecurity!.confirmTOTPEnrollment("bearer", "enrollment-one", { requestId: "confirm-one", code: "" }),
      () => httpIamRepository.personalSecurity!.recoveryCodes!.startStepUp("bearer", { requestId: "regenerate-one", expectedFactorRevision: 1 }),
      () => httpIamRepository.personalSecurity!.recoveryCodes!.verifyStepUp("bearer", "step-up-one", { requestId: "verify-one", password: "", code: "123456" }),
      () => httpIamRepository.personalSecurity!.recoveryCodes!.verifyStepUp("bearer", "step-up-one", { requestId: "verify-one", password: "private", code: "" }),
      () => httpIamRepository.personalSecurity!.recoveryCodes!.regenerate("bearer", { requestId: "regenerate-one", stepUpId: "step-up-one", expectedFactorRevision: 1 })
    ]) {
      const fetcher = reply({});
      await expect(action()).rejects.toThrow("INVALID_IAM_RESPONSE");
      expect(fetcher).not.toHaveBeenCalled();
    }
  });
});

describe("IAM HTTP group boundary", () => {
  it("reads group detail and direct attachments without caller account selectors", async () => {
    const fetcher = reply(groupAccess());
    const access = await httpAccountRepository.getGroup("bearer", account.id, group.id);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/groups/${group.id}`);
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer bearer" } });
    expect(access.group).toMatchObject({ id: group.id, accountId: account.id, description: "" });
    expect(access.policyAttachments[0]).toMatchObject({ id: groupAttachment.id, target: { kind: "GROUP", id: group.id }, scope: "TENANT", installationId: null });
    expect(access.capabilities.at(-1)).toMatchObject({ available: false, restrictionReason: "AUTHORITY_REQUIRED" });
  });

  it("fails closed on incomplete capabilities and foreign or malformed group relations", async () => {
    const access = groupAccess();
    for (const invalid of [
      { ...access, group: { ...group, accountId: "other-account" } },
      { ...access, group: { ...group, id: "other-group" } },
      { ...access, group: { ...group, updatedAt: "2026-02-30T08:00:00Z" } },
      { ...access, group: { ...group, createdAt: "2026-09-11T08:00:00.000002Z", updatedAt: "2026-09-11T08:00:00.000001Z" } },
      { ...access, capabilities: access.capabilities.slice(1) },
      { ...access, capabilities: [...access.capabilities.slice(1), access.capabilities[1]] },
      { ...access, capabilities: [...access.capabilities, capability("iam.user.delete", "USER", user.id)] },
      { ...access, policyAttachments: [{ ...groupAttachment, accountId: "other-account" }] },
      { ...access, policyAttachments: [{ ...groupAttachment, target: { kind: "GROUP", id: "other-group" } }] },
      { ...access, policyAttachments: [tenantAttachment] },
      { ...access, policyAttachments: [{ ...groupAttachment, revokedAt: timestamp, resourceVersion: 2 }] },
      { ...access, policyAttachments: [{ ...groupAttachment, scope: "INSTALLATION", installationId: "installation-a" }] },
      { ...access, inheritedPolicies: [] }
    ]) {
      reply(invalid);
      await expect(httpAccountRepository.getGroup("bearer", account.id, group.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("checks group page order and account while passing signed continuation unchanged", async () => {
    const items = Array.from({ length: 100 }, (_, index) => groupAccess({ ...group, id: `group-${index.toString().padStart(3, "0")}` }));
    const fetcher = reply({ apiVersion, kind: "GroupList", items, nextAfter: "ic1.Opaque_signed-continuation" });
    const page = await httpAccountRepository.listGroups("bearer", account.id);
    expect(page.items).toHaveLength(100);
    expect(page.nextAfter).toBe("ic1.Opaque_signed-continuation");
    expect(fetcher).toHaveBeenCalledTimes(1);
    for (const invalid of [
      { apiVersion, kind: "GroupList", items, nextAfter: "group-999" },
      { apiVersion, kind: "GroupList", items: [...items, items[0]] },
      { apiVersion, kind: "GroupList", items: [items[1], items[0]] },
      { apiVersion, kind: "GroupList", items: [items[0], items[0]] },
      { apiVersion, kind: "GroupList", items: [groupAccess({ ...group, accountId: "other" })] },
      { apiVersion, kind: "GroupList", items: [], accountId: "injected" }
    ]) {
      reply(invalid);
      await expect(httpAccountRepository.listGroups("bearer", account.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    reply({ apiVersion, kind: "GroupList", items: [groupAccess()] });
    await expect(httpAccountRepository.listGroups("bearer", account.id, group.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("rejects noncanonical cursors and never compares opaque text with resource IDs", async () => {
    for (const after of ["", group.id, "ic2.future", "ic1.trailing\n", "ic1.space ", "ic1.bad=", `ic1.${"a".repeat(381)}`]) {
      const fetcher = reply({ apiVersion, kind: "GroupList", items: [groupAccess()] });
      await expect(httpAccountRepository.listGroups("bearer", account.id, after)).rejects.toThrow("INVALID_IAM_RESPONSE");
      expect(fetcher).not.toHaveBeenCalled();
    }
    const fetcher = reply({ apiVersion, kind: "GroupList", items: [groupAccess()] });
    const page = await httpAccountRepository.listGroups("bearer", account.id, "ic1.zzzz_OPAQUE");
    expect(page.items[0]?.group.id).toBe(group.id);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/groups?after=ic1.zzzz_OPAQUE");
    const items = Array.from({ length: 100 }, (_, index) => groupAccess({ ...group, id: `group-${index.toString().padStart(3, "0")}` }));
    for (const nextAfter of ["ic1.trailing\n", "ic1.again", `ic1.${"a".repeat(381)}`]) {
      reply({ apiVersion, kind: "GroupList", items, nextAfter });
      await expect(httpAccountRepository.listGroups("bearer", account.id, "ic1.again")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("reads membership relations and keys removal capabilities by membership ID", async () => {
    const fetcher = reply(membershipPage());
    const page = await httpAccountRepository.listGroupMemberships("bearer", account.id, group.id, "ic1.Opaque_signed-continuation");
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/groups/${group.id}/memberships?after=ic1.Opaque_signed-continuation`);
    expect(page.items[0]?.membership).toMatchObject({ id: membership.id, userId: user.id, groupId: group.id });
    expect(page.items[0]?.capabilities[0]?.resource).toEqual({ kind: "GROUP_MEMBERSHIP", id: membership.id });
    const valid = membershipPage();
    for (const invalid of [
      { ...valid, accountId: "other-account" }, { ...valid, groupId: "other-group" },
      { ...valid, items: [{ ...valid.items[0], membership: { ...membership, accountId: "other-account" } }] },
      { ...valid, items: [{ ...valid.items[0], membership: { ...membership, groupId: "other-group" } }] },
      { ...valid, items: [{ ...valid.items[0], membership: { ...membership, removedAt: timestamp, resourceVersion: 2 } }] },
      { ...valid, items: [{ ...valid.items[0], capabilities: [capability("iam.group-membership.remove", "USER", user.id)] }] },
      { ...valid, nextAfter: "membership-other" }, { ...valid, items: [valid.items[0], valid.items[0]] }
    ]) {
      reply(invalid);
      await expect(httpAccountRepository.listGroupMemberships("bearer", account.id, group.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("creates only an empty group and retains caller-owned idempotency input", async () => {
    const fetcher = reply(group);
    fetcher.mockImplementation(() => Promise.resolve(new Response(JSON.stringify(group), { status: 201 })));
    const command = { name: group.name, requestId: "retained-group-intent", accountId: "forged", policyIds: [tenantPolicy.id], members: [user.id] };
    const before = structuredClone(command);
    const first = await httpAccountRepository.createGroup("bearer", account.id, command);
    const second = await httpAccountRepository.createGroup("bearer", account.id, command);
    expect(first).toEqual(second);
    expect(command).toEqual(before);
    expect(fetcher).toHaveBeenCalledTimes(2);
    for (const [, options] of fetcher.mock.calls) expect(JSON.parse(options.body)).toEqual({ name: group.name, requestId: command.requestId });
  });

  it("does not retry unknown outcomes or replace an intent after 409", async () => {
    const fetcher = vi.fn().mockRejectedValue(new Error("Disconnected"));
    vi.stubGlobal("fetch", fetcher);
    const command = { name: group.name, requestId: "one-group-intent" };
    await expect(httpAccountRepository.createGroup("bearer", account.id, command)).rejects.toThrow();
    expect(fetcher).toHaveBeenCalledTimes(1);
    fetcher.mockResolvedValue(new Response(JSON.stringify({ code: "iam.conflict", title: "Conflict" }), { status: 409 }));
    await expect(httpAccountRepository.createGroup("bearer", account.id, command)).rejects.toThrow();
    expect(fetcher).toHaveBeenCalledTimes(2);
    for (const [, options] of fetcher.mock.calls) expect(JSON.parse(options.body).requestId).toBe(command.requestId);
  });

  it("checks exact profile and deletion revisions and returns the cascade receipt", async () => {
    let fetcher = reply({ ...group, name: "Renamed", description: "", resourceVersion: 2 });
    const updated = await httpAccountRepository.updateGroup("bearer", account.id, group.id, { name: "Renamed", description: "", resourceVersion: 1, requestId: "rename-group" });
    expect(updated.resourceVersion).toBe(2);
    expect(requestBody(fetcher)).toEqual({ name: "Renamed", description: "", resourceVersion: 1, requestId: "rename-group" });
    fetcher = reply({ apiVersion, kind: "GroupDeletion", accountId: account.id, id: group.id, name: "Renamed", resourceVersion: 3, removedMemberships: 4, revokedPolicyAttachments: 2, deletedAt: timestamp });
    const deleted = await httpAccountRepository.deleteGroup("bearer", account.id, group.id, { resourceVersion: 2, requestId: "delete-group" });
    expect(deleted).toMatchObject({ id: group.id, removedMemberships: 4, revokedPolicyAttachments: 2 });
    expect(requestBody(fetcher)).toEqual({ resourceVersion: 2, requestId: "delete-group" });
    reply({ ...group, name: "Renamed", resourceVersion: 4 });
    await expect(httpAccountRepository.updateGroup("bearer", account.id, group.id, { name: "Renamed", resourceVersion: 1, requestId: "rename-group" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    for (const override of [{ resourceVersion: 4 }, { id: "other-group" }, { accountId: "other-account" }, { removedMemberships: -1 }]) {
      reply({ apiVersion, kind: "GroupDeletion", accountId: account.id, id: group.id, name: group.name, resourceVersion: 2, removedMemberships: 1, revokedPolicyAttachments: 0, deletedAt: timestamp, ...override });
      await expect(httpAccountRepository.deleteGroup("bearer", account.id, group.id, { resourceVersion: 1, requestId: "delete-group" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("uses one membership command and returns a terminal removal without reviving it", async () => {
    let fetcher = reply(membership);
    await httpAccountRepository.createGroupMembership("bearer", account.id, group.id, { userId: user.id, requestId: "add-member" });
    expect(requestBody(fetcher)).toEqual({ userId: user.id, requestId: "add-member" });
    fetcher = reply({ ...membership, resourceVersion: 2, removedAt: timestamp, removedBy: account.rootIdentity.principalId });
    const removed = await httpAccountRepository.removeGroupMembership("bearer", account.id, group.id, membership.id, { resourceVersion: 1, requestId: "remove-member" });
    expect(removed.removedAt).toBe(timestamp);
    expect(removed.removedBy).toBe(account.rootIdentity.principalId);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/groups/${group.id}/memberships/${membership.id}:remove`);
    expect(requestBody(fetcher)).toEqual({ resourceVersion: 1, requestId: "remove-member" });
    for (const override of [{ groupId: "other-group" }, { accountId: "other-account" }, { userId: "other-user" }, { removedAt: timestamp, resourceVersion: 2 }]) {
      reply({ ...membership, ...override });
      await expect(httpAccountRepository.createGroupMembership("bearer", account.id, group.id, { userId: user.id, requestId: "add-member" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    for (const invalid of [membership,
      { ...membership, removedBy: account.rootIdentity.principalId },
      { ...membership, resourceVersion: 2, removedAt: timestamp },
      { ...membership, resourceVersion: 2, removedAt: timestamp, removedBy: "" }]) {
      reply(invalid);
      await expect(httpAccountRepository.removeGroupMembership("bearer", account.id, group.id, membership.id, { resourceVersion: 1, requestId: "remove-member" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("uses generic attachment routes while checking the exact GROUP target", async () => {
    let fetcher = reply(groupAttachment);
    const attachment = await httpAccountRepository.createGroupPolicyAttachment("bearer", account.id, group.id, { policyId: groupAttachment.policyId, policyResourceVersion: 3, requestId: "attach-group" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policy-attachments");
    expect(requestBody(fetcher)).toEqual({ target: { kind: "GROUP", id: group.id }, policyId: groupAttachment.policyId, policyResourceVersion: 3, requestId: "attach-group" });
    expect(attachment.target.kind).toBe("GROUP");
    fetcher = reply({ apiVersion, kind: "Revocation", id: groupAttachment.id, resourceVersion: 2, revokedAt: timestamp });
    await httpAccountRepository.revokePolicyAttachment("bearer", groupAttachment.id, { resourceVersion: 1, requestId: "revoke-group-policy" });
    expect(requestBody(fetcher)).toEqual({ resourceVersion: 1, requestId: "revoke-group-policy" });
    for (const invalid of [tenantAttachment, { ...groupAttachment, accountId: "other" }, { ...groupAttachment, policyId: "other-policy" }, { ...groupAttachment, scope: "INSTALLATION", installationId: "installation-a" }]) {
      reply(invalid);
      await expect(httpAccountRepository.createGroupPolicyAttachment("bearer", account.id, group.id, { policyId: groupAttachment.policyId, policyResourceVersion: 1, requestId: "attach-group" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });
});

describe("IAM HTTP account boundary", () => {
  it("requires an explicit boundary bound to the current account, user and user revision", async () => {
    const reference = { policyId: customerPolicy.id, versionId: customerPolicy.defaultVersionId, contentDigest: `sha256:${"a".repeat(64)}` };
    const current = { apiVersion, kind: "CurrentIdentity", account, user, identityKind: "USER", policySources: [], permissionBoundary, capabilities: currentCapabilities() };
    reply({ ...current, permissionBoundary: { ...permissionBoundary, policy: reference } });
    const identity = await httpAccountRepository.currentIdentity("bearer");
    expect(identity.permissionBoundary.policy).toEqual(reference);
    expect(identity.policySources).toEqual([]);
    for (const boundary of [
      undefined, null, {},
      { ...permissionBoundary, policy: undefined },
      { ...permissionBoundary, accountId: "other-account" },
      { ...permissionBoundary, userId: "other-user" },
      { ...permissionBoundary, resourceVersion: user.resourceVersion + 1 },
      { ...permissionBoundary, policy: {} },
      { ...permissionBoundary, policy: { ...reference, contentDigest: "a".repeat(64) } },
      { ...permissionBoundary, policy: { ...reference, contentDigest: `sha256:${"A".repeat(64)}` } },
      { ...permissionBoundary, policy: { ...reference, allowed: true } },
      { ...permissionBoundary, available: true }
    ]) {
      reply({ ...current, permissionBoundary: boundary });
      await expect(httpAccountRepository.currentIdentity("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    const root = { ...user, id: account.rootIdentity.principalId };
    const rootBoundary = { ...permissionBoundary, userId: root.id };
    reply({ ...current, user: root, identityKind: "ROOT_IDENTITY", permissionBoundary: rootBoundary });
    expect((await httpAccountRepository.currentIdentity("bearer")).permissionBoundary.policy).toBeNull();
    reply({ ...current, user: root, identityKind: "ROOT_IDENTITY", permissionBoundary: { ...rootBoundary, policy: reference } });
    await expect(httpAccountRepository.currentIdentity("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ ...current, capabilities: currentCapabilities().map((item) => item.resource.id === "collection" ? { ...item, resource: { ...item.resource, id: "accounts" } } : item) });
    await expect(httpAccountRepository.currentIdentity("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("reads and changes only the exact user's boundary with explicit concurrency and request identity", async () => {
    const client = httpAccountRepository.permissionBoundaries!;
    let fetcher = reply(permissionBoundary);
    expect(await client.read("bearer", account.id, user.id)).toMatchObject({ userId: user.id, resourceVersion: user.resourceVersion, policy: null });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/users/${user.id}/permission-boundary`);
    expect(firstRequest(fetcher)[1].body).toBeUndefined();
    const reference = { policyId: customerPolicy.id, versionId: customerPolicy.defaultVersionId, contentDigest: `sha256:${"b".repeat(64)}` };
    const set = { policyId: customerPolicy.id, policyResourceVersion: customerPolicy.resourceVersion, resourceVersion: user.resourceVersion, requestId: "request-boundary-set" };
    fetcher = reply({ ...permissionBoundary, resourceVersion: user.resourceVersion + 1, policy: reference });
    expect((await client.set("bearer", account.id, user.id, { ...set, accountId: "forged", compiled: {} } as typeof set)).policy).toEqual(reference);
    expect(firstRequest(fetcher)[1].method).toBe("PUT");
    expect(requestBody(fetcher)).toEqual(set);
    fetcher = reply({ ...permissionBoundary, resourceVersion: user.resourceVersion + 2 });
    const remove = { resourceVersion: user.resourceVersion + 1, requestId: "request-boundary-remove" };
    expect((await client.remove("bearer", account.id, user.id, remove)).policy).toBeNull();
    expect(firstRequest(fetcher)[1].method).toBe("DELETE");
    expect(requestBody(fetcher)).toEqual(remove);
  });

  it("rejects incomplete, foreign and unexpected boundary write outcomes", async () => {
    const client = httpAccountRepository.permissionBoundaries!;
    const reference = { policyId: customerPolicy.id, versionId: customerPolicy.defaultVersionId, contentDigest: `sha256:${"c".repeat(64)}` };
    const set = { policyId: customerPolicy.id, policyResourceVersion: customerPolicy.resourceVersion, resourceVersion: user.resourceVersion, requestId: "request-set" };
    for (const result of [
      permissionBoundary,
      { ...permissionBoundary, resourceVersion: user.resourceVersion + 1 },
      { ...permissionBoundary, resourceVersion: user.resourceVersion + 2, policy: reference },
      { ...permissionBoundary, resourceVersion: user.resourceVersion + 1, policy: { ...reference, policyId: "other-policy" } },
      { ...permissionBoundary, resourceVersion: user.resourceVersion + 1, userId: "other-user", policy: reference },
      { ...permissionBoundary, resourceVersion: user.resourceVersion + 1, accountId: "other-account", policy: reference }
    ]) {
      reply(result);
      await expect(client.set("bearer", account.id, user.id, set)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    reply({ ...permissionBoundary, resourceVersion: user.resourceVersion + 1, policy: reference });
    await expect(client.remove("bearer", account.id, user.id, { resourceVersion: user.resourceVersion, requestId: "request-remove" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ ...permissionBoundary, policy: null, accountId: "other-account" });
    await expect(client.read("bearer", account.id, user.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("retries an uncertain boundary request byte-for-byte without replacing its request identity", async () => {
    const reference = { policyId: customerPolicy.id, versionId: customerPolicy.defaultVersionId, contentDigest: `sha256:${"d".repeat(64)}` };
    const fetcher = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ code: "IAM_UNAVAILABLE" }), { status: 503 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ...permissionBoundary, resourceVersion: user.resourceVersion + 1, policy: reference }), { status: 200 }));
    vi.stubGlobal("fetch", fetcher);
    const command = { policyId: customerPolicy.id, policyResourceVersion: customerPolicy.resourceVersion, resourceVersion: user.resourceVersion, requestId: "request-uncertain" };
    await expect(httpAccountRepository.permissionBoundaries!.set("bearer", account.id, user.id, command)).rejects.toMatchObject({ status: 503 });
    await httpAccountRepository.permissionBoundaries!.set("bearer", account.id, user.id, command);
    expect(fetcher.mock.calls[0]).toEqual(fetcher.mock.calls[1]);
  });

  it("requires both exact USER boundary capabilities without treating them as grants", async () => {
    const current = { user, policyAttachments: [], capabilities: userCapabilities([]) };
    reply(current);
    expect((await httpAccountRepository.getUser("bearer", user.id)).capabilities).toHaveLength(9);
    for (const capabilities of [
      current.capabilities.filter((item) => !item.action.includes("permission-boundary")),
      current.capabilities.map((item) => item.action === "iam.user.permission-boundary.set" ? { ...item, resource: { kind: "ACCOUNT", id: account.id } } : item),
      current.capabilities.map((item) => item.action === "iam.user.permission-boundary.remove" ? { ...item, resource: { kind: "USER", id: "other-user" } } : item)
    ]) {
      reply({ ...current, capabilities });
      await expect(httpAccountRepository.getUser("bearer", user.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });
  it.each([undefined, true, false])("sends only the password session policy %s, never a retained-session selector", async (revokeOtherSessions) => {
    const fetcher = reply({ changedAt: timestamp, bootstrapFileRetirable: false });
    const command = { currentPassword: "Current-Only-Test-Password-49!", newPassword: "New-Only-Test-Password-73!", revokeOtherSessions, sessionId: "forged-session", tenantId: "forged-tenant" };
    await httpIamRepository.changePassword("transient-bearer", command);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/password");
    expect(requestBody(fetcher)).toEqual({
      currentPassword: command.currentPassword, newPassword: command.newPassword, requestId: expect.any(String),
      ...(revokeOtherSessions === undefined ? {} : { revokeOtherSessions })
    });
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer transient-bearer" } });
  });

  it("sends the qualified username as one login identifier", async () => {
    const fetcher = reply({ outcome: "AUTHENTICATED", credential: "transient-bearer", mustChangePassword: false,
      session: { apiVersion, kind: "Session", id: "session", organizationId: "account-acme", principalId: "principal-alex", status: "ACTIVE", issuedAt: timestamp, expiresAt: "2099-08-27T00:00:00Z" } });
    await expect(httpIamRepository.login({ loginName: "alex@acme", password: "synthetic-test-password" })).resolves.toMatchObject({ outcome: "AUTHENTICATED", credential: "transient-bearer" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/login");
    expect(requestBody(fetcher)).toEqual({ loginName: "alex@acme", password: "synthetic-test-password", requestId: expect.any(String) });
  });

  it("keeps a login challenge separate from a session and verifies it without a bearer", async () => {
    const challenge = { apiVersion, kind: "AuthenticationChallenge", id: "challenge-one", purpose: "LOGIN", nextStep: "TOTP", expiresAt: "2099-09-20T01:07:03Z" };
    const loginFetch = reply({ outcome: "CHALLENGE_REQUIRED", challenge, challengeCredential: "challenge-secret" });
    await expect(httpIamRepository.login({ loginName: "alex@acme", password: "synthetic-test-password" })).resolves.toEqual({
      outcome: "CHALLENGE_REQUIRED",
      challenge: { id: "challenge-one", purpose: "LOGIN", nextStep: "TOTP", expiresAt: "2099-09-20T01:07:03Z" },
      challengeCredential: "challenge-secret"
    });
    expect(firstRequest(loginFetch)[1].headers).not.toMatchObject({ Authorization: expect.any(String) });

    const verifyFetch = reply({ outcome: "AUTHENTICATED", credential: "transient-bearer", mustChangePassword: false,
      session: { apiVersion, kind: "Session", id: "session", organizationId: "account-acme", principalId: "principal-alex", status: "ACTIVE", issuedAt: timestamp, expiresAt: "2099-08-27T00:00:00Z" } });
    await expect(httpIamRepository.authenticationChallenges!.verify({ challengeId: "challenge-one", challengeCredential: "challenge-secret", code: "123456" })).resolves.toMatchObject({ outcome: "AUTHENTICATED" });
    expect(firstRequest(verifyFetch)[0]).toBe("/api/iam/v1/auth/challenges/challenge-one:verify");
    expect(requestBody(verifyFetch)).toEqual({ requestId: expect.any(String), challengeCredential: "challenge-secret", code: "123456" });
    expect(firstRequest(verifyFetch)[1].headers).not.toMatchObject({ Authorization: expect.any(String) });
  });

  it("uses the separately credentialed challenge password endpoint and only accepts reauthentication", async () => {
    const fetcher = reply({ nextStep: "REAUTHENTICATE", changedAt: timestamp });
    await expect(httpIamRepository.authenticationChallenges!.changePassword({ challengeId: "challenge-password", challengeCredential: "challenge-secret", newPassword: "New-Only-Test-Password-73!" })).resolves.toEqual({ nextStep: "REAUTHENTICATE", changedAt: timestamp });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/challenges/challenge-password:password");
    expect(requestBody(fetcher)).toEqual({ requestId: expect.any(String), challengeCredential: "challenge-secret", newPassword: "New-Only-Test-Password-73!" });
    expect(firstRequest(fetcher)[1].headers).not.toMatchObject({ Authorization: expect.any(String) });
  });

  it("keeps first enrollment on restricted challenge routes without a Session or bearer", async () => {
    const expiresAt = "2026-09-11T08:05:00Z";
    const challenge = { apiVersion, kind: "AuthenticationChallenge", id: "first-one", purpose: "ENROLLMENT", nextStep: "ENROLLMENT", expiresAt };
    const challengeCredential = "first-enrollment-secret";
    let fetcher = reply({ outcome: "CHALLENGE_REQUIRED", challenge, challengeCredential });
    await expect(httpIamRepository.login({ loginName: "alex@acme", password: "initial-password" })).resolves.toMatchObject({
      outcome: "CHALLENGE_REQUIRED", challenge: { purpose: "ENROLLMENT", nextStep: "ENROLLMENT" }
    });
    expect(firstRequest(fetcher)[1].headers).not.toMatchObject({ Authorization: expect.any(String) });

    fetcher = reply({ challenge, notificationContact });
    await expect(httpIamRepository.authenticationChallenges!.inspectFirstEnrollment!({ challengeId: challenge.id, challengeCredential }))
      .resolves.toMatchObject({ challenge: { purpose: "ENROLLMENT" }, notificationContact: { state: "NONE" } });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/challenges/${challenge.id}:enrollment-state`);
    expect(requestBody(fetcher)).toEqual({ challengeCredential });
    expect(firstRequest(fetcher)[1].headers).not.toMatchObject({ Authorization: expect.any(String) });

    fetcher = reply({ ...notificationVerification, requestId: "first-contact-1", email: "alex@example.com" });
    await httpIamRepository.authenticationChallenges!.startFirstContact!({ challengeId: challenge.id, challengeCredential,
      email: "alex@example.com", requestId: "first-contact-1" });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/challenges/${challenge.id}/notification-contact/verifications`);
    expect(requestBody(fetcher)).toEqual({ challengeCredential, email: "alex@example.com", requestId: "first-contact-1" });
    expect(firstRequest(fetcher)[1].headers).not.toMatchObject({ Authorization: expect.any(String) });

    const enrollment = { ...pendingEnrollment, requestId: "first-factor-1", purpose: "INITIAL", createdAt: "2026-09-11T08:01:00Z",
      expiresAt: "2026-09-11T08:04:00Z" };
    fetcher = reply({ outcome: "APPLIED", enrollment, provisioning: { seed: "ONLY-ONCE", uri: "otpauth://totp/Matrix:alex?secret=ONLY-ONCE" } });
    await expect(httpIamRepository.authenticationChallenges!.startFirstTOTP!({ challengeId: challenge.id, challengeCredential,
      requestId: "first-factor-1" })).resolves.toMatchObject({ outcome: "APPLIED", provisioning: { seed: "ONLY-ONCE" } });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/challenges/${challenge.id}:enroll`);
    expect(requestBody(fetcher)).toEqual({ challengeCredential, requestId: "first-factor-1" });
    expect(firstRequest(fetcher)[1].headers).not.toMatchObject({ Authorization: expect.any(String) });

    fetcher = reply({ challenge, notificationContact: { ...notificationContact, state: "VERIFIED", resourceVersion: 1,
      email: "alex@example.com", verifiedAt: timestamp }, enrollment });
    await expect(httpIamRepository.authenticationChallenges!.inspectFirstEnrollment!({ challengeId: challenge.id, challengeCredential }))
      .resolves.toMatchObject({ enrollment: { id: enrollment.id, expiresAt: enrollment.expiresAt } });

    fetcher = reply({ outcome: "EQUAL_REPLAY", enrollment });
    const replay = await httpIamRepository.authenticationChallenges!.startFirstTOTP!({ challengeId: challenge.id, challengeCredential,
      requestId: "first-factor-1" });
    expect(replay).toEqual({ outcome: "EQUAL_REPLAY", enrollment: expect.any(Object) });
    expect(firstRequest(fetcher)[1].headers).not.toMatchObject({ Authorization: expect.any(String) });
    expect(JSON.stringify(replay)).not.toContain("ONLY-ONCE");

    const recoveryCodes = Array.from({ length: 10 }, (_, index) => `FIRST-RECOVERY-${index}`);
    fetcher = reply({ enrollment: { ...enrollment, state: "CONFIRMED", completedAt: "2026-09-11T08:03:00Z" },
      nextStep: "REAUTHENTICATE", recoveryCodes });
    await expect(httpIamRepository.authenticationChallenges!.confirmFirstTOTP!({ challengeId: challenge.id, challengeCredential,
      enrollmentId: enrollment.id, code: "123456", requestId: "first-confirm-1" })).resolves.toMatchObject({ recoveryCodes });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/challenges/${challenge.id}:confirm-enrollment`);
    expect(requestBody(fetcher)).toEqual({ challengeCredential, requestId: "first-confirm-1", code: "123456" });
    expect(firstRequest(fetcher)[1].headers).not.toMatchObject({ Authorization: expect.any(String) });
  });

  it("rejects crossed first-enrollment phase, target or extra session data", async () => {
    const challenge = { apiVersion, kind: "AuthenticationChallenge", id: "first-one", purpose: "ENROLLMENT", nextStep: "ENROLLMENT",
      expiresAt: "2026-09-11T08:05:00Z" };
    for (const response of [
      { challenge: { ...challenge, id: "other" }, notificationContact },
      { challenge: { ...challenge, purpose: "LOGIN" }, notificationContact },
      { challenge, notificationContact: null },
      { challenge, notificationContact, session: { id: "forbidden" } },
      { challenge: { ...challenge, nextStep: "PASSWORD_CHANGE" }, notificationContact }
    ]) {
      reply(response);
      await expect(httpIamRepository.authenticationChallenges!.inspectFirstEnrollment!({ challengeId: "first-one",
        challengeCredential: "secret" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("uses sealed recovery routes without a bearer and validates the complete one-time ceremony", async () => {
    const requestId = "recovery-request-one";
    const createdAt = "2026-09-21T01:00:00Z";
    const expiresAt = "2026-09-21T01:05:00Z";
    const recovery = { apiVersion, kind: "AuthenticatorRecovery", id: "recovery-one", requestId, state: "STARTED", createdAt, expiresAt };
    const recoveryChallenge = { apiVersion, kind: "AuthenticationChallenge", id: "recovery-challenge", purpose: "RECOVERY", nextStep: "ENROLLMENT", expiresAt };
    const startFetch = reply({ recovery, challenge: recoveryChallenge, challengeCredential: "recovery-secret", provisioning: { seed: "SECRETBASE32", uri: "otpauth://totp/Matrix:test?secret=SECRETBASE32" } });
    await expect(httpIamRepository.authenticationChallenges!.startRecovery!({
      challengeId: "login-challenge", challengeCredential: "login-secret", recoveryCode: "RECOVERY-ONE", requestId
    })).resolves.toMatchObject({ recovery: { requestId, state: "STARTED" }, challenge: { purpose: "RECOVERY", nextStep: "ENROLLMENT" } });
    expect(firstRequest(startFetch)[0]).toBe("/api/iam/v1/auth/challenges/login-challenge:recover");
    expect(requestBody(startFetch)).toEqual({ requestId, challengeCredential: "login-secret", recoveryCode: "RECOVERY-ONE" });
    expect(firstRequest(startFetch)[1].headers).not.toMatchObject({ Authorization: expect.any(String) });

    const recoveryCodes = Array.from({ length: 10 }, (_, index) => `NEW-RECOVERY-${index}`);
    const completed = { ...recovery, state: "COMPLETED", completedAt: "2026-09-21T01:02:00Z" };
    const confirmFetch = reply({ recovery: completed, nextStep: "REAUTHENTICATE", recoveryCodes });
    await expect(httpIamRepository.authenticationChallenges!.confirmRecovery!({
      challengeId: "recovery-challenge", challengeCredential: "recovery-secret", code: "123456",
      requestId: "confirm-request-one", recoveryRequestId: requestId
    })).resolves.toMatchObject({ recovery: { requestId, state: "COMPLETED" }, recoveryCodes });
    expect(firstRequest(confirmFetch)[0]).toBe("/api/iam/v1/auth/challenges/recovery-challenge:confirm-recovery");
    expect(requestBody(confirmFetch)).toEqual({ requestId: "confirm-request-one", challengeCredential: "recovery-secret", code: "123456" });
    expect(firstRequest(confirmFetch)[1].headers).not.toMatchObject({ Authorization: expect.any(String) });

    const inspectFetch = reply(completed);
    await expect(httpIamRepository.authenticationChallenges!.inspectRecovery!({
      challengeId: "fresh-login-challenge", challengeCredential: "fresh-login-secret", requestId
    })).resolves.toMatchObject({ requestId, state: "COMPLETED" });
    expect(firstRequest(inspectFetch)[0]).toBe("/api/iam/v1/auth/challenges/fresh-login-challenge:recovery-result");
    expect(requestBody(inspectFetch)).toEqual({ requestId, challengeCredential: "fresh-login-secret" });
    expect(firstRequest(inspectFetch)[1].headers).not.toMatchObject({ Authorization: expect.any(String) });

    reply({ ...recovery, state: "EXPIRED", completedAt: expiresAt });
    await expect(httpIamRepository.authenticationChallenges!.inspectRecovery!({
      challengeId: "fresh-login-challenge", challengeCredential: "fresh-login-secret", requestId
    })).resolves.toMatchObject({ requestId, state: "EXPIRED", completedAt: expiresAt });
  });

  it("fails closed on malformed recovery metadata, crossed expiry, secret replay, or mixed login purpose", async () => {
    const requestId = "recovery-request-one";
    const createdAt = "2026-09-21T01:00:00Z";
    const expiresAt = "2026-09-21T01:05:00Z";
    const recovery = { apiVersion, kind: "AuthenticatorRecovery", id: "recovery-one", requestId, state: "STARTED", createdAt, expiresAt };
    const challenge = { apiVersion, kind: "AuthenticationChallenge", id: "recovery-challenge", purpose: "RECOVERY", nextStep: "ENROLLMENT", expiresAt };
    const command = { challengeId: "login-challenge", challengeCredential: "login-secret", recoveryCode: "RECOVERY-ONE", requestId };
    for (const response of [
      { recovery: { ...recovery, requestId: "another-request" }, challenge, challengeCredential: "secret", provisioning: { seed: "seed", uri: "uri" } },
      { recovery: { ...recovery, expiresAt: "2026-09-21T01:05:01Z" }, challenge: { ...challenge, expiresAt: "2026-09-21T01:05:01Z" }, challengeCredential: "secret", provisioning: { seed: "seed", uri: "uri" } },
      { recovery, challenge: { ...challenge, purpose: "LOGIN", nextStep: "TOTP" }, challengeCredential: "secret", provisioning: { seed: "seed", uri: "uri" } },
      { recovery, challenge, challengeCredential: "secret", provisioning: { seed: "seed", uri: "uri" }, session: { id: "forbidden" } }
    ]) {
      reply(response);
      await expect(httpIamRepository.authenticationChallenges!.startRecovery!(command)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }

    const completed = { ...recovery, state: "COMPLETED", completedAt: "2026-09-21T01:02:00Z" };
    for (const response of [
      { recovery: completed, nextStep: "REAUTHENTICATE", recoveryCodes: Array.from({ length: 9 }, (_, index) => `CODE-${index}`) },
      { recovery: completed, nextStep: "REAUTHENTICATE", recoveryCodes: Array(10).fill("DUPLICATE") },
      { recovery: { ...completed, completedAt: expiresAt }, nextStep: "REAUTHENTICATE", recoveryCodes: Array.from({ length: 10 }, (_, index) => `CODE-${index}`) }
    ]) {
      reply(response);
      await expect(httpIamRepository.authenticationChallenges!.confirmRecovery!({
        challengeId: "recovery-challenge", challengeCredential: "secret", code: "123456",
        requestId: "confirm-request", recoveryRequestId: requestId
      })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }

    reply({ outcome: "CHALLENGE_REQUIRED", challenge, challengeCredential: "secret" });
    await expect(httpIamRepository.login({ loginName: "alex@acme", password: "synthetic-test-password" })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it.each([
    { outcome: "AUTHENTICATED", credential: "bearer", mustChangePassword: false, challenge: { apiVersion, kind: "AuthenticationChallenge", id: "challenge", purpose: "LOGIN", nextStep: "TOTP", expiresAt: "2099-09-20T01:07:03Z" }, session: { apiVersion, kind: "Session", id: "session", organizationId: "account-acme", principalId: "principal-alex", status: "ACTIVE", issuedAt: timestamp, expiresAt: "2099-08-27T00:00:00Z" } },
    { outcome: "CHALLENGE_REQUIRED", challenge: { apiVersion, kind: "AuthenticationChallenge", id: "challenge", purpose: "LOGIN", nextStep: "RECOVERY", expiresAt: "2099-09-20T01:07:03Z" }, challengeCredential: "secret" },
    { outcome: "CHALLENGE_REQUIRED", challenge: { apiVersion, kind: "AuthenticationChallenge", id: "challenge", purpose: "LOGIN", nextStep: "TOTP", expiresAt: "2099-09-20T01:07:03Z" }, challengeCredential: "secret", credential: "forbidden" }
  ])("rejects mixed or unsupported login response branches", async (response) => {
    reply(response);
    await expect(httpIamRepository.login({ loginName: "alex@acme", password: "synthetic-test-password" })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("rejects challenge steps that are valid in another phase but not at this endpoint", async () => {
    const passwordChallenge = { apiVersion, kind: "AuthenticationChallenge", id: "challenge-password", purpose: "LOGIN", nextStep: "PASSWORD_CHANGE", expiresAt: "2099-09-20T01:07:03Z" };
    reply({ outcome: "CHALLENGE_REQUIRED", challenge: passwordChallenge, challengeCredential: "secret" });
    await expect(httpIamRepository.login({ loginName: "alex@acme", password: "synthetic-test-password" })).rejects.toThrow("INVALID_IAM_RESPONSE");

    const totpChallenge = { ...passwordChallenge, id: "challenge-totp", nextStep: "TOTP" };
    reply({ outcome: "CHALLENGE_REQUIRED", challenge: totpChallenge, challengeCredential: "secret" });
    await expect(httpIamRepository.authenticationChallenges!.verify({ challengeId: "challenge-totp", challengeCredential: "secret", code: "123456" })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("creates a user with no implicit policy or caller-supplied account", async () => {
    const fetcher = reply({ ...user, mustChangePassword: true });
    const command = { kind: "create-user" as const, loginName: "alex", displayName: "Alex", initialPassword: "synthetic-test-password", initialRole: "PAAS_VIEWER", tenantId: "forged" };
    await httpAccountRepository.execute("transient-bearer", command);
    expect(requestBody(fetcher)).toEqual({ loginName: "alex", displayName: "Alex", initialPassword: "synthetic-test-password", requestId: expect.any(String) });
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer transient-bearer" } });
  });

  it("parses current attachments without interpreting policy names", async () => {
    reply({ apiVersion, kind: "CurrentIdentity", account, user, identityKind: "USER", policySources: directSources(tenantAttachment, platformAttachment), permissionBoundary, capabilities: currentCapabilities() });
    const identity = await httpAccountRepository.currentIdentity("bearer");
    expect(identity.policySources.map((item) => item.attachment.policyId)).toEqual(["system.platform-operator", "system.paas-viewer"]);
    for (const patch of [
      { capabilities: currentCapabilities().slice(1) },
      { capabilities: [...currentCapabilities(), capability("iam.user.list", "ACCOUNT", account.id)] },
      { capabilities: currentCapabilities().map((item) => item.action === "iam.user.list" ? { ...item, action: "iam.principal.list" } : item) },
      { user: { ...user, accountId: "another-account" } },
      { policySources: directSources({ ...tenantAttachment, accountId: "another-account" }) },
      { policySources: directSources(tenantAttachment, tenantAttachment) },
      { policyAttachments: [] },
      { roles: ["PLATFORM_OPERATOR"] },
      { apiVersion: "future/v2" }
    ]) {
      reply({ apiVersion, kind: "CurrentIdentity", account, user, identityKind: "USER", policySources: [], permissionBoundary, capabilities: currentCapabilities(false), ...patch });
      await expect(httpAccountRepository.currentIdentity("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("binds every inherited source to its live membership and permits the same policy through distinct sources", async () => {
    const membership = { apiVersion, kind: "GroupMembership", id: "membership-a", accountId: account.id,
      groupId: "group-a", userId: user.id, createdBy: account.rootIdentity.principalId, resourceVersion: 1,
      createdAt: timestamp, updatedAt: timestamp };
    const inherited = { kind: "GROUP", attachment: { ...tenantAttachment, id: "attachment-group", target: { kind: "GROUP", id: membership.groupId } }, membership };
    const base = { apiVersion, kind: "CurrentIdentity", account, user, identityKind: "USER", permissionBoundary, capabilities: currentCapabilities(false) };
    reply({ ...base, policySources: [inherited, ...directSources(tenantAttachment)] });
    const identity = await httpAccountRepository.currentIdentity("bearer");
    expect(identity.policySources.map((source) => source.kind)).toEqual(["GROUP", "DIRECT"]);
    for (const source of [
      { ...inherited, membership: undefined },
      { ...inherited, membership: { ...membership, userId: "another-user" } },
      { ...inherited, membership: { ...membership, groupId: "another-group" } },
      { ...inherited, membership: { ...membership, accountId: "another-account" } },
      { ...inherited, membership: { ...membership, resourceVersion: 2 } },
      { ...inherited, membership: { ...membership, removedAt: timestamp, removedBy: user.id } },
      { ...inherited, attachment: { ...inherited.attachment, scope: "INSTALLATION", installationId: "installation-a" } },
      { ...inherited, kind: "DIRECT" },
      { ...inherited, kind: "ROLE" },
      { ...inherited, permit: true }
    ]) {
      reply({ ...base, policySources: [source] });
      await expect(httpAccountRepository.currentIdentity("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("bounds member pages and rejects foreign, duplicate, revoked, or old role projections", async () => {
    const fetcher = reply({ apiVersion, kind: "UserList", items: [{ user, policyAttachments: [tenantAttachment], capabilities: userCapabilities() }] });
    const page = await httpAccountRepository.listUsers("bearer", "ic1.Opaque_signed-continuation");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/users?after=ic1.Opaque_signed-continuation");
    expect(page.items[0]?.policyAttachments[0]?.policyId).toBe("system.paas-viewer");
    for (const item of [
      { user, policyAttachments: [{ ...tenantAttachment, accountId: "another-account" }], capabilities: userCapabilities() },
      { user, policyAttachments: [tenantAttachment, tenantAttachment], capabilities: userCapabilities() },
      { user, policyAttachments: [{ ...tenantAttachment, revokedAt: timestamp }], capabilities: userCapabilities() },
      { user, policyAttachments: [tenantAttachment], capabilities: userCapabilities().slice(1) },
      { user, roleBindings: [] }
    ]) {
      reply({ apiVersion, kind: "UserList", items: [item] });
      await expect(httpAccountRepository.listUsers("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    reply({ apiVersion, kind: "UserList", items: Array.from({ length: 101 }, () => ({ user, policyAttachments: [], capabilities: userCapabilities([]) })) });
    await expect(httpAccountRepository.listUsers("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("reads one exact user projection from the path target", async () => {
    let fetcher = reply({ user, policyAttachments: [tenantAttachment], capabilities: userCapabilities() });
    const access = await httpAccountRepository.getUser("bearer", user.id);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/users/user-alex");
    expect(access.user.id).toBe(user.id);

    fetcher = reply({ user: { ...user, id: "another-user" }, policyAttachments: [], capabilities: userCapabilities([]).map((entry) => ({ ...entry, resource: entry.resource.kind === "USER" ? { kind: "USER", id: "another-user" } : entry.resource })) });
    await expect(httpAccountRepository.getUser("bearer", user.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/users/user-alex");
  });

  it("parses account management as per-resource capabilities", async () => {
    const fetcher = reply({ apiVersion, kind: "AccountList", items: [accountAccess()] });
    const page = await httpAccountRepository.listAccounts("bearer", "ic1.Opaque_signed-continuation");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/accounts?after=ic1.Opaque_signed-continuation");
    expect(page.items[0]?.capabilities.map((item) => item.action)).toEqual([
      "iam.account.set-status", "iam.account.recover-root-credentials"
    ]);
    for (const item of [
      { account, capabilities: accountAccess().capabilities.slice(1) },
      { account, capabilities: [...accountAccess().capabilities, capability("iam.account.create", "ACCOUNT", "collection")] },
      { account: { ...account, id: "another-account" }, capabilities: accountAccess().capabilities }
    ]) {
      reply({ apiVersion, kind: "AccountList", items: [item] });
      await expect(httpAccountRepository.listAccounts("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("reads separate complete policy directories with no caller selector", async () => {
    let fetcher = reply({ apiVersion, kind: "PolicyList", accountId: "account-acme", scope: "TENANT", items: [customerPolicy, tenantPolicy].sort((a, b) => a.id.localeCompare(b.id)) });
    const tenant = await httpAccountRepository.listPolicies("bearer", false);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policies");
    expect(tenant.items.map((item) => item.id)).toEqual(["customer.build", "system.paas-viewer"]);
    fetcher = reply({ apiVersion, kind: "PolicyList", accountId: "account-acme", scope: "INSTALLATION", installationId: "installation-acme", items: [platformPolicy] });
    const platform = await httpAccountRepository.listPolicies("bearer", true);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/platform-policies");
    expect(platform.installationId).toBe("installation-acme");
    for (const body of [
      { apiVersion, kind: "PolicyList", accountId: "account-acme", scope: "TENANT", items: [{ ...customerPolicy, accountId: "other" }] },
      { apiVersion, kind: "PolicyList", accountId: "account-acme", scope: "TENANT", items: [tenantPolicy, customerPolicy] },
      { apiVersion, kind: "PolicyList", accountId: "account-acme", scope: "TENANT", items: [{ ...tenantPolicy, document: {} }] },
      { apiVersion, kind: "PolicyList", accountId: "account-acme", scope: "TENANT", items: [{ ...tenantPolicy, status: "DELETED" }] },
      { apiVersion, kind: "PolicyList", accountId: "account-acme", scope: "TENANT", items: Array.from({ length: 257 }, (_, index) => ({ ...customerPolicy, id: `customer.${index.toString().padStart(3, "0")}` })) },
      { apiVersion, kind: "PolicyList", accountId: "account-acme", scope: "TENANT", installationId: "forged", items: [] }
    ]) {
      reply(body);
      await expect(httpAccountRepository.listPolicies("bearer", false)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("reads only the exact tenant policy's current default document without an account selector", async () => {
    const document = { languageVersion: "1", scope: "TENANT", statements: [{
      sid: "read-applications", effect: "ALLOW", actions: ["paas.application.read"],
      resources: [{ kind: "APPLICATION", match: "ANY_IN_AUTHORITY" }],
      conditions: [
        { key: "request.source-ip", operator: "IP_ADDRESS", values: ["192.0.2.0/24"] },
        { key: "request.tag/environment", operator: "STRING_EQUALS", values: ["production", "预发布"] },
        { key: "resource.tag/environment", operator: "STRING_NOT_EQUALS", values: ["retired"] }
      ]
    }] };
    const version = { policyId: customerPolicy.id, versionId: customerPolicy.defaultVersionId, document,
      contentDigest: `sha256:${"a".repeat(64)}`, contractVersion: 1 };
    const body = { apiVersion, kind: "PolicyDetail", policy: customerPolicy, version };
    const fetcher = reply(body);
    const detail = await httpAccountRepository.readPolicy!("bearer", account.id, customerPolicy.id);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policies/customer.build");
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer bearer" } });
    expect(firstRequest(fetcher)[1].body).toBeUndefined();
    expect(detail.version.document.statements[0]?.actions).toEqual(["paas.application.read"]);
    expect(detail.version.document.statements[0]?.conditions).toEqual(document.statements[0]!.conditions);

    for (const invalid of [
      { ...body, policy: { ...customerPolicy, accountId: "another-account" } },
      { ...body, policy: { ...customerPolicy, id: "customer.other" } },
      { ...body, policy: { ...customerPolicy, scope: "INSTALLATION" } },
      { ...body, version: { ...version, versionId: "version-other" } },
      { ...body, version: { ...version, document: { ...document, statements: [{ ...document.statements[0], actions: ["paas.application.*"] }] } } },
      { ...body, version: { ...version, contractVersion: 2 } },
      { ...body, version: { ...version, document: { ...document, statements: [{ ...document.statements[0], resources: [{ kind: "OTHER", match: "ANY_IN_AUTHORITY" }] }] } } },
      { ...body, version: { ...version, document: { ...document, statements: [{ ...document.statements[0], conditions: [{ key: "request.source-ip", operator: "IP_ADDRESS", values: ["192.0.2.42/24"] }] }] } } },
      { ...body, version: { ...version, document: { ...document, statements: [{ ...document.statements[0], conditions: [{ key: "request.tag/environment", operator: "STRING_EQUALS", values: [" production"] }] }] } } },
      { ...body, version: { ...version, document: { ...document, statements: [{ ...document.statements[0], conditions: [{ key: "resource.tag/environment", operator: "STRING_EQUALS", values: [" production"] }] }] } } },
      { ...body, version: { ...version, document: { ...document, statements: [{ ...document.statements[0], conditions: [{ key: "resource.tag/team", operator: "STRING_EQUALS", values: ["platform"] }] }] } } },
      { ...body, version: { ...version, extra: true } }
    ]) {
      reply(invalid);
      await expect(httpAccountRepository.readPolicy!("bearer", account.id, customerPolicy.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("shows the author action family and its immutable v2 expansion as separate policy facts", async () => {
    const document = { languageVersion: "1", scope: "TENANT", statements: [{
      sid: "read-applications", effect: "ALLOW", actions: ["paas.application.*"],
      resources: [{ kind: "APPLICATION", match: "ANY_IN_AUTHORITY" }]
    }] };
    const compilation = { compilationVersion: "1", profiles: [{ product: "paas", revision: 2,
      contentDigest: `sha256:${"b".repeat(64)}` }], resolvedStatements: [{ sid: "read-applications",
      actions: ["paas.application.list", "paas.application.read"] }] };
    const version = { policyId: customerPolicy.id, versionId: customerPolicy.defaultVersionId, document,
      contentDigest: `sha256:${"a".repeat(64)}`, contractVersion: 2, compilation };
    const body = { apiVersion, kind: "PolicyDetail", policy: customerPolicy, version };
    reply(body);
    const detail = await httpAccountRepository.readPolicy!("bearer", account.id, customerPolicy.id);
    expect(detail.version.document.statements[0]?.actions).toEqual(["paas.application.*"]);
    expect(detail.version.compilation?.resolvedStatements[0]?.actions).toEqual(["paas.application.list", "paas.application.read"]);
    expect(detail.version.compilation?.profiles[0]?.revision).toBe(2);

    for (const invalid of [
      { ...compilation, profiles: [] },
      { ...compilation, profiles: [{ ...compilation.profiles[0], product: "iam" }] },
      { ...compilation, resolvedStatements: [{ sid: "read-applications", actions: ["paas.application.read", "paas.application.read"] }] },
      { ...compilation, resolvedStatements: [{ sid: "read-applications", actions: ["paas.application.read", "paas.deployment.read"] }] },
      { ...compilation, resolvedStatements: [{ sid: "other", actions: ["paas.application.read"] }] }
    ]) {
      reply({ ...body, version: { ...version, compilation: invalid } });
      await expect(httpAccountRepository.readPolicy!("bearer", account.id, customerPolicy.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    reply({ ...body, version: { ...version, document: { ...document, statements: [{ ...document.statements[0],
      actions: ["paas.application.*", "paas.application.read"] }] }, compilation: { ...compilation,
      resolvedStatements: [{ sid: "read-applications", actions: ["paas.application.list"] }] } } });
    await expect(httpAccountRepository.readPolicy!("bearer", account.id, customerPolicy.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("lists only manageable customer versions and reads an exact non-default version", async () => {
    const document = { languageVersion: "1", scope: "TENANT", statements: [{
      sid: "read-applications", effect: "ALLOW", actions: ["paas.application.read"],
      resources: [{ kind: "APPLICATION", match: "ANY_IN_AUTHORITY" }]
    }] };
    const current = { policyId: customerPolicy.id, versionId: customerPolicy.defaultVersionId, document,
      contentDigest: `sha256:${"a".repeat(64)}`, contractVersion: 1 };
    const earlier = { ...current, versionId: "version-a", contentDigest: `sha256:${"b".repeat(64)}` };
    const list = { apiVersion, kind: "PolicyVersionList", policy: customerPolicy, items: [earlier, current] };
    let fetcher = reply(list);
    const directory = await httpAccountRepository.listPolicyVersions!("bearer", account.id, customerPolicy.id);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policies/customer.build/versions");
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer bearer" } });
    expect(firstRequest(fetcher)[1].body).toBeUndefined();
    expect(directory.items.map((item) => item.versionId)).toEqual(["version-a", "version-build"]);

    fetcher = reply({ apiVersion, kind: "PolicyVersionDetail", policy: customerPolicy, version: earlier });
    const detail = await httpAccountRepository.readPolicyVersion!("bearer", account.id, customerPolicy.id, earlier.versionId);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policies/customer.build/versions/version-a");
    expect(firstRequest(fetcher)[1].body).toBeUndefined();
    expect(detail.version.versionId).toBe("version-a");
    expect(detail.policy.defaultVersionId).toBe("version-build");

    for (const invalid of [
      { ...list, policy: tenantPolicy },
      { ...list, policy: { ...customerPolicy, accountId: "foreign-account" } },
      { ...list, policy: { ...customerPolicy, status: "RETIRED" } },
      { ...list, items: [current, earlier] },
      { ...list, items: [earlier] },
      { ...list, items: [earlier, current, current] },
      { ...list, items: Array.from({ length: 6 }, (_, index) => ({ ...current, versionId: `version-${index}` })) },
      { ...list, nextAfter: "unsupported" }
    ]) {
      reply(invalid);
      await expect(httpAccountRepository.listPolicyVersions!("bearer", account.id, customerPolicy.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    for (const invalid of [
      { apiVersion, kind: "PolicyVersionDetail", policy: customerPolicy, version: current },
      { apiVersion, kind: "PolicyVersionDetail", policy: { ...customerPolicy, accountId: "foreign-account" }, version: earlier },
      { apiVersion, kind: "PolicyDetail", policy: customerPolicy, version: earlier },
      { apiVersion, kind: "PolicyVersionDetail", policy: customerPolicy, version: { ...earlier, policyId: "customer.other" } }
    ]) {
      reply(invalid);
      await expect(httpAccountRepository.readPolicyVersion!("bearer", account.id, customerPolicy.id, earlier.versionId)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("creates an account-owned policy with an initial default version but no attachment", async () => {
    const document = { languageVersion: "1", scope: "TENANT", statements: [{ sid: "application-read", effect: "ALLOW",
      actions: ["paas.application.read"], resources: [{ kind: "APPLICATION", match: "EXACT", id: "app-prod" }] }] };
    const policy = { ...customerPolicy, id: "customer.new", displayName: "New policy", defaultVersionId: "version-new", resourceVersion: 1 };
    const version = { policyId: policy.id, versionId: policy.defaultVersionId, document,
      contentDigest: `sha256:${"c".repeat(64)}`, contractVersion: 1 };
    const created = { apiVersion, kind: "PolicyDetail", policy, version };
    const command = { displayName: policy.displayName, document: document as import("../domain/accounts").AccountPolicyDocument,
      requestId: "ui-policy-create-fixed" };
    let fetcher = reply(created);
    const detail = await httpAccountRepository.createPolicy!("bearer", account.id, command);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policies");
    expect(firstRequest(fetcher)[1].method).toBe("POST");
    expect(requestBody(fetcher)).toEqual(command);
    expect(detail.policy.id).toBe(policy.id);
    expect(detail.version.versionId).toBe(policy.defaultVersionId);
    for (const invalid of [
      { ...created, kind: "PolicyVersionDetail" },
      { ...created, policy: { ...policy, management: "SYSTEM" } },
      { ...created, policy: { ...policy, accountId: "foreign-account" } },
      { ...created, policy: { ...policy, displayName: "Different" } },
      { ...created, version: { ...version, versionId: "other" } },
      { ...created, version: { ...version, document: { ...document, statements: [{ ...document.statements[0], actions: ["paas.application.delete"] }] } } }
    ]) {
      fetcher = reply(invalid);
      await expect(httpAccountRepository.createPolicy!("bearer", account.id, command)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("publishes a customer version against the exact policy revision without changing its default", async () => {
    const document = { languageVersion: "1", scope: "TENANT", statements: [{
      sid: "read-applications", effect: "ALLOW", actions: ["paas.application.read"],
      resources: [{ kind: "APPLICATION", match: "ANY_IN_AUTHORITY" }]
    }] };
    const version = { policyId: customerPolicy.id, versionId: "version-new", document,
      contentDigest: `sha256:${"c".repeat(64)}`, contractVersion: 1 };
    const published = { apiVersion, kind: "PolicyVersionDetail", policy: {
      ...customerPolicy, resourceVersion: customerPolicy.resourceVersion + 1
    }, version };
    const command = { document: document as import("../domain/accounts").AccountPolicyDocument,
      resourceVersion: customerPolicy.resourceVersion, expectedDefaultVersionId: customerPolicy.defaultVersionId,
      requestId: "ui-publish-version-fixed" };
    let fetcher = reply(published);
    const detail = await httpAccountRepository.createPolicyVersion!("bearer", account.id, customerPolicy.id, command);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policies/customer.build/versions");
    expect(firstRequest(fetcher)[1].method).toBe("POST");
    expect(requestBody(fetcher)).toEqual({ document, resourceVersion: command.resourceVersion, requestId: command.requestId });
    expect(detail.version.versionId).toBe("version-new");
    expect(detail.policy.defaultVersionId).toBe(customerPolicy.defaultVersionId);
    for (const invalid of [
      { ...published, kind: "PolicyDetail" },
      { ...published, policy: { ...published.policy, management: "SYSTEM" } },
      { ...published, policy: { ...published.policy, accountId: "foreign-account" } },
      { ...published, policy: { ...published.policy, resourceVersion: customerPolicy.resourceVersion + 2 } },
      { ...published, policy: { ...published.policy, defaultVersionId: "version-new" } },
      { ...published, version: { ...version, policyId: "customer.other" } },
      { ...published, version: { ...version, document: { ...document, statements: [{ ...document.statements[0], actions: ["paas.application.list"] }] } } }
    ]) {
      fetcher = reply(invalid);
      await expect(httpAccountRepository.createPolicyVersion!("bearer", account.id, customerPolicy.id, command)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("binds default selection and non-default retirement to the exact customer policy revision", async () => {
    const document = { languageVersion: "1", scope: "TENANT", statements: [{
      sid: "read-applications", effect: "ALLOW", actions: ["paas.application.read"],
      resources: [{ kind: "APPLICATION", match: "ANY_IN_AUTHORITY" }]
    }] };
    const current = { policyId: customerPolicy.id, versionId: customerPolicy.defaultVersionId, document,
      contentDigest: `sha256:${"a".repeat(64)}`, contractVersion: 1 };
    const earlier = { ...current, versionId: "version-a", contentDigest: `sha256:${"b".repeat(64)}` };
    const selected = { apiVersion, kind: "PolicyDetail", policy: { ...customerPolicy,
      defaultVersionId: earlier.versionId, resourceVersion: customerPolicy.resourceVersion + 1 }, version: earlier };
    let fetcher = reply(selected);
    const command = { versionId: earlier.versionId, resourceVersion: customerPolicy.resourceVersion, requestId: "ui-select-version-fixed" };
    const result = await httpAccountRepository.setDefaultPolicyVersion!("bearer", account.id, customerPolicy.id, command);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policies/customer.build:set-default-version");
    expect(firstRequest(fetcher)[1].method).toBe("POST");
    expect(requestBody(fetcher)).toEqual(command);
    expect(result.policy.defaultVersionId).toBe(earlier.versionId);

    const retired = { apiVersion, kind: "PolicyDetail", policy: { ...customerPolicy,
      resourceVersion: customerPolicy.resourceVersion + 1 }, version: current };
    fetcher = reply(retired);
    const retirement = { resourceVersion: customerPolicy.resourceVersion,
      expectedDefaultVersionId: customerPolicy.defaultVersionId, requestId: "ui-retire-version-fixed" };
    await httpAccountRepository.retirePolicyVersion!("bearer", account.id, customerPolicy.id, earlier.versionId, retirement);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policies/customer.build/versions/version-a");
    expect(firstRequest(fetcher)[1].method).toBe("DELETE");
    expect(requestBody(fetcher)).toEqual({ resourceVersion: retirement.resourceVersion, requestId: retirement.requestId });

    for (const invalid of [
      { ...selected, policy: { ...selected.policy, accountId: "foreign-account" } },
      { ...selected, policy: { ...selected.policy, resourceVersion: customerPolicy.resourceVersion + 2 } },
      { ...selected, policy: { ...selected.policy, defaultVersionId: customerPolicy.defaultVersionId }, version: current },
      { ...selected, policy: { ...selected.policy, management: "SYSTEM" } }
    ]) {
      reply(invalid);
      await expect(httpAccountRepository.setDefaultPolicyVersion!("bearer", account.id, customerPolicy.id, command)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    for (const invalid of [
      { ...retired, policy: { ...retired.policy, resourceVersion: customerPolicy.resourceVersion + 2 } },
      { ...retired, policy: { ...retired.policy, defaultVersionId: earlier.versionId }, version: earlier },
      { ...retired, policy: { ...retired.policy, management: "SYSTEM" } }
    ]) {
      reply(invalid);
      await expect(httpAccountRepository.retirePolicyVersion!("bearer", account.id, customerPolicy.id, earlier.versionId, retirement)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    const noRequest = vi.fn(); vi.stubGlobal("fetch", noRequest);
    await expect(httpAccountRepository.retirePolicyVersion!("bearer", account.id, customerPolicy.id, current.versionId, retirement)).rejects.toThrow("INVALID_IAM_REQUEST");
    expect(noRequest).not.toHaveBeenCalled();
  });

  it("reads the complete current authorization profiles without an account or version selector", async () => {
    const fetcher = reply({ apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [profileEntry("iam"), profileEntry("paas")] });
    const result = await httpAccountRepository.listAuthorizationProfiles("bearer");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/authorization-profiles");
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer bearer" } });
    expect(firstRequest(fetcher)[1].method).toBeUndefined();
    expect(firstRequest(fetcher)[1].body).toBeUndefined();
    expect(result).toEqual({ accountId: account.id, items: [
      { ...profileEntry("iam"), profile: { ...profileEntry("iam").profile, apiVersion: undefined, kind: undefined } },
      { ...profileEntry("paas"), profile: { ...profileEntry("paas").profile, apiVersion: undefined, kind: undefined } }
    ].map((entry) => ({ contentDigest: entry.contentDigest, profile: {
      product: entry.profile.product, revision: entry.profile.revision, callingService: entry.profile.callingService, actions: entry.profile.actions
    } })) });
  });

  it("accepts only the fixed network, trusted request-tag, and trusted resource-tag Profile declarations", async () => {
    const entry = profileEntry("paas");
    entry.profile.revision = 5;
    entry.profile.actions[0]!.conditions = [
      ...entry.profile.actions[0]!.conditions,
      { key: "request.source-ip", valueType: "IP", source: "CALLING_SERVICE_NETWORK" },
      { key: "request.tag/environment", valueType: "STRING", source: "CALLING_SERVICE_REQUEST_TAG" },
      { key: "resource.tag/environment", valueType: "STRING", source: "CALLING_SERVICE_RESOURCE_TAG" }
    ];
    reply({ apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [entry] });
    const result = await httpAccountRepository.listAuthorizationProfiles("bearer");
    expect(result.items[0]!.profile.revision).toBe(5);
    expect(result.items[0]!.profile.actions[0]!.conditions?.slice(-3)).toEqual([
      { key: "request.source-ip", valueType: "IP", source: "CALLING_SERVICE_NETWORK" },
      { key: "request.tag/environment", valueType: "STRING", source: "CALLING_SERVICE_REQUEST_TAG" },
      { key: "resource.tag/environment", valueType: "STRING", source: "CALLING_SERVICE_RESOURCE_TAG" }
    ]);
    for (const condition of [
      { key: "resource.tag/environment", valueType: "STRING", source: "CALLING_SERVICE_REQUEST_TAG" },
      { key: "resource.tag/environment", valueType: "IP", source: "CALLING_SERVICE_RESOURCE_TAG" },
      { key: "resource.tag/team", valueType: "STRING", source: "CALLING_SERVICE_RESOURCE_TAG" }
    ]) {
      reply({ apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [{ ...entry,
        profile: { ...entry.profile, actions: [{ ...entry.profile.actions[0]!, conditions: [condition] }] } }] });
      await expect(httpAccountRepository.listAuthorizationProfiles("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("reads the platform service-role template directory without an account selector or request body", async () => {
    const template = serviceRoleTemplate();
    const fetcher = reply({ apiVersion, kind: "ServiceRoleTemplateList", items: [template] });
    const result = await httpAccountRepository.listServiceRoleTemplates!("bearer");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/service-role-templates");
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer bearer" } });
    expect(firstRequest(fetcher)[1].method).toBeUndefined();
    expect(firstRequest(fetcher)[1].body).toBeUndefined();
    expect(result).toEqual({ items: [{
      id: template.id, version: template.version, spec: template.spec,
      contentDigest: template.contentDigest, status: template.status
    }] });
  });

  it("fails closed on malformed, ambiguous, or unordered service-role template directories", async () => {
    const template = serviceRoleTemplate("managedservice.a-reader");
    const second = serviceRoleTemplate("managedservice.b-reader");
    const invalid = [
      { apiVersion, kind: "ServiceRoleTemplateList", items: [template], accountId: account.id },
      { apiVersion: "legacy", kind: "ServiceRoleTemplateList", items: [template] },
      { apiVersion, kind: "ServiceRoleTemplates", items: [template] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: null },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [second, template] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [template, template] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [{ ...template, consented: true }] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [{ ...template, kind: "ServiceLinkedRole" }] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [{ ...template, version: 0 }] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [{ ...template, status: "AUTHORIZED" }] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [{ ...template, contentDigest: "sha256:ABC" }] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [{ ...template, spec: { ...template.spec, product: "ManagedService" } }] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [{ ...template, spec: { ...template.spec, servicePurpose: "UNKNOWN" } }] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [{ ...template, spec: { ...template.spec, maxSessionDurationSeconds: 30 } }] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [{ ...template, spec: { ...template.spec, workloads: [] } }] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [{ ...template, spec: { ...template.spec, workloads: [template.spec.workloads[0], template.spec.workloads[0]] } }] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [{ ...template, spec: { ...template.spec, roleName: "" } }] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [{ ...template, spec: { ...template.spec, workloads: [{ ...template.spec.workloads[0], bindAction: "ManagedService.bind" }] } }] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [{ ...template, spec: { ...template.spec, policyVersion: { ...template.spec.policyVersion, contentDigest: "digest" } } }] },
      { apiVersion, kind: "ServiceRoleTemplateList", items: [{ ...template, spec: { ...template.spec, policyVersion: { ...template.spec.policyVersion, latest: true } } }] }
    ];
    for (const directory of invalid) {
      reply(directory);
      await expect(httpAccountRepository.listServiceRoleTemplates!("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("reads current-account service-linked roles without sending an account selector", async () => {
    const template = serviceRoleTemplate();
    const serviceRole = {
      ...role,
      id: "role-managedservice-reader",
      name: "ManagedServiceInstallationReader",
      management: "SERVICE_LINKED",
      resourceVersion: 1,
      currentTrustVersionId: "trust-managedservice-v1"
    };
    const relation = {
      apiVersion, kind: "ServiceLinkedRole", role: serviceRole,
      template: { id: template.id, version: template.version, contentDigest: template.contentDigest },
      servicePrincipal: { installationId: "installation-managedservice", principalId: "service-managedservice", purpose: "PAAS" },
      permissionCeiling: template.spec.policyVersion
    };
    const fetcher = reply({ apiVersion, kind: "ServiceLinkedRoleList", accountId: account.id,
      items: [{ relation, bindingCount: 2, activeBindingCount: 1 }] });
    const result = await httpAccountRepository.listServiceLinkedRoles!("bearer", account.id);

    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/service-linked-roles");
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer bearer" } });
    expect(firstRequest(fetcher)[1].body).toBeUndefined();
    expect(result).toMatchObject({ accountId: account.id, nextAfter: null, items: [{
      bindingCount: 2, activeBindingCount: 1, relation: { role: { id: serviceRole.id, management: "SERVICE_LINKED" },
        template: { id: template.id, version: 1 }, permissionCeiling: { versionId: template.spec.policyVersion.versionId } }
    }] });

    const cursorFetcher = reply({ apiVersion, kind: "ServiceLinkedRoleList", accountId: account.id, items: [] });
    await httpAccountRepository.listServiceLinkedRoles!("bearer", account.id, "ic1.next-service-role");
    expect(firstRequest(cursorFetcher)[0]).toBe("/api/iam/v1/service-linked-roles?after=ic1.next-service-role");
  });

  it("reads exact active and revoked workload bindings as immutable history", async () => {
    const template = serviceRoleTemplate();
    const serviceRole = {
      ...role,
      id: "role-managedservice-reader",
      name: "ManagedServiceInstallationReader",
      management: "SERVICE_LINKED",
      resourceVersion: 1,
      currentTrustVersionId: "trust-managedservice-v1"
    };
    const templateReference = { id: template.id, version: template.version, contentDigest: template.contentDigest };
    const relation = {
      apiVersion, kind: "ServiceLinkedRole", role: serviceRole, template: templateReference,
      servicePrincipal: { installationId: "installation-managedservice", principalId: "service-managedservice", purpose: "PAAS" },
      permissionCeiling: template.spec.policyVersion
    };
    const active = {
      apiVersion, kind: "WorkloadRoleBinding", id: "binding-active", accountId: account.id, roleId: serviceRole.id,
      template: templateReference, workload: { kind: "SERVICE_INSTALLATION", id: "installation-current" },
      status: "ACTIVE", resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp
    };
    const revokedAt = "2026-09-12T08:00:00Z";
    const revoked = {
      ...active, id: "binding-revoked", workload: { kind: "SERVICE_INSTALLATION", id: "installation-former" },
      status: "REVOKED", resourceVersion: 2, updatedAt: revokedAt, revokedAt
    };
    const fetcher = reply({ apiVersion, kind: "ServiceLinkedRoleAccess", relation, bindings: [active, revoked] });
    const result = await httpAccountRepository.getServiceLinkedRole!("bearer", account.id, serviceRole.id);

    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/service-linked-roles/${serviceRole.id}`);
    expect(result.bindings).toEqual([
      expect.objectContaining({ id: active.id, status: "ACTIVE", revokedAt: null, resourceVersion: 1 }),
      expect.objectContaining({ id: revoked.id, status: "REVOKED", revokedAt, resourceVersion: 2 })
    ]);
  });

  it("fails closed on cross-account service relations, ambiguous counts, or invalid binding lifecycle", async () => {
    const template = serviceRoleTemplate();
    const serviceRole = {
      ...role,
      id: "role-managedservice-reader",
      name: "ManagedServiceInstallationReader",
      management: "SERVICE_LINKED",
      resourceVersion: 1,
      currentTrustVersionId: "trust-managedservice-v1"
    };
    const templateReference = { id: template.id, version: template.version, contentDigest: template.contentDigest };
    const relation = {
      apiVersion, kind: "ServiceLinkedRole", role: serviceRole, template: templateReference,
      servicePrincipal: { installationId: "installation-managedservice", principalId: "service-managedservice", purpose: "PAAS" },
      permissionCeiling: template.spec.policyVersion
    };
    for (const body of [
      { apiVersion, kind: "ServiceLinkedRoleList", accountId: "foreign-account", items: [] },
      { apiVersion, kind: "ServiceLinkedRoleList", accountId: account.id, items: [{ relation, bindingCount: 0, activeBindingCount: 0 }] },
      { apiVersion, kind: "ServiceLinkedRoleList", accountId: account.id, items: [{ relation, bindingCount: 1, activeBindingCount: 2 }] },
      { apiVersion, kind: "ServiceLinkedRoleList", accountId: account.id, items: [{ relation: { ...relation, role: { ...serviceRole, management: "CUSTOMER" } }, bindingCount: 1, activeBindingCount: 1 }] }
    ]) {
      reply(body);
      await expect(httpAccountRepository.listServiceLinkedRoles!("bearer", account.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }

    const invalidActive = {
      apiVersion, kind: "WorkloadRoleBinding", id: "binding-active", accountId: account.id, roleId: serviceRole.id,
      template: templateReference, workload: { kind: "SERVICE_INSTALLATION", id: "installation-current" },
      status: "ACTIVE", resourceVersion: 1, createdAt: timestamp, updatedAt: "2026-09-12T08:00:00Z"
    };
    const invalidRevoked = { ...invalidActive, status: "REVOKED", resourceVersion: 2, revokedAt: "2026-09-12T08:01:00Z" };
    for (const binding of [invalidActive, invalidRevoked, { ...invalidActive, accountId: "foreign-account", updatedAt: timestamp }]) {
      reply({ apiVersion, kind: "ServiceLinkedRoleAccess", relation, bindings: [binding] });
      await expect(httpAccountRepository.getServiceLinkedRole!("bearer", account.id, serviceRole.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("preserves explicit subject and USER credential admission independently of legacy omission", async () => {
    const entry = profileEntry();
    const action = entry.profile.actions[0]!;
    const actions = [
      { ...action, subjectTypes: ["USER", "ROLE", "SERVICE_ACCOUNT"], userAuthenticationMethods: ["LOGIN_SESSION", "ACCESS_KEY"] },
      { ...action, action: "paas.application.probe", scope: "INSTALLATION_PROBE", conditions: [],
        subjectTypes: ["SERVICE_ACCOUNT"] },
      { ...action, action: "paas.application.legacy" },
      { ...action, action: "paas.application.key", userAuthenticationMethods: ["ACCESS_KEY"] }
    ];
    reply({ apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [{ ...entry, profile: { ...entry.profile, actions } }] });
    const result = await httpAccountRepository.listAuthorizationProfiles("bearer");
    expect(result.items[0]!.profile.actions[0]).toMatchObject({ subjectTypes: ["USER", "ROLE", "SERVICE_ACCOUNT"], userAuthenticationMethods: ["LOGIN_SESSION", "ACCESS_KEY"] });
    expect(result.items[0]!.profile.actions[1]).toMatchObject({ subjectTypes: ["SERVICE_ACCOUNT"] });
    expect(result.items[0]!.profile.actions[1]).not.toHaveProperty("userAuthenticationMethods");
    expect(result.items[0]!.profile.actions[2]).not.toHaveProperty("subjectTypes");
    expect(result.items[0]!.profile.actions[2]).not.toHaveProperty("userAuthenticationMethods");
    expect(result.items[0]!.profile.actions[3]).toMatchObject({ userAuthenticationMethods: ["ACCESS_KEY"] });
  });

  it("preserves only a bounded tenant instance-list batch declaration", async () => {
    const entry = profileEntry("managedservice");
    const listAction = {
      ...entry.profile.actions[1]!, action: "managedservice.offering.read", resourceKind: "SERVICE_OFFERING",
      resourceShapes: [
        { mode: "INSTANCE", prefixAllowed: false },
        { mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_LIST" }
      ], instanceListBatch: true
    };
    reply({ apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [{ ...entry,
      profile: { ...entry.profile, actions: [listAction] } }] });
    const result = await httpAccountRepository.listAuthorizationProfiles("bearer");
    expect(result.items[0]!.profile.actions[0]).toMatchObject({ instanceListBatch: true });

    for (const invalid of [
      { ...listAction, instanceListBatch: "true" },
      { ...listAction, scope: "INSTALLATION", conditions: [] },
      { ...listAction, resourceShapes: [{ mode: "INSTANCE", prefixAllowed: false }] },
      { ...listAction, resourceShapes: [{ mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_LIST" }] },
      { ...listAction, resultResourceKind: "SERVICE_OFFERING" }
    ]) {
      reply({ apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [{ ...entry,
        profile: { ...entry.profile, actions: [invalid] } }] });
      await expect(httpAccountRepository.listAuthorizationProfiles("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("rejects malformed or incompatible subject and credential admission without ignoring fields", async () => {
    const entry = profileEntry();
    for (const fields of [
      { subjectTypes: null }, { subjectTypes: [] }, { subjectTypes: "USER" },
      { subjectTypes: ["USER", "USER"] }, { subjectTypes: ["ACCOUNT"] },
      { userAuthenticationMethods: null }, { userAuthenticationMethods: [] }, { userAuthenticationMethods: "ACCESS_KEY" },
      { userAuthenticationMethods: ["LOGIN_SESSION", "LOGIN_SESSION"] }, { userAuthenticationMethods: ["PASSWORD"] },
      { subjectTypes: ["ROLE"], userAuthenticationMethods: ["LOGIN_SESSION"] },
      { subjectTypes: ["SERVICE_ACCOUNT"], userAuthenticationMethods: ["ACCESS_KEY"] },
      { scope: "INSTALLATION_PROBE", conditions: [], userAuthenticationMethods: ["LOGIN_SESSION"] },
      { subjectTypes: ["USER"], unknownAdmission: true }
    ]) {
      reply({ apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [{ ...entry,
        profile: { ...entry.profile, actions: [{ ...entry.profile.actions[0], ...fields }] } }] });
      await expect(httpAccountRepository.listAuthorizationProfiles("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("reads only the authenticated account's security rule and rejects partial or cross-account data", async () => {
    const password = { minimumLength: 15, requireLowercase: false, requireUppercase: false,
      requireDigit: false, requireSymbol: false, historyCount: 1, maxAgeDays: 0, expiryMode: "CHANGE_PASSWORD" };
    const session = { idleTimeoutMinutes: 30 };
    const accessKeyNetwork = { allowedSourceCidrs: [] };
    const settings = { apiVersion, kind: "AccountSecuritySettings", accountId: account.id,
      resourceVersion: 4, mfa: { requiredForUsers: false }, password, session, accessKeyNetwork, updatedAt: timestamp };
    const fetcher = reply(settings);
    await expect(httpAccountRepository.accountSecuritySettings!.read("bearer", account.id)).resolves.toEqual({
      accountId: account.id, resourceVersion: 4, mfa: { requiredForUsers: false }, password, session, accessKeyNetwork, updatedAt: timestamp
    });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/account/security-settings");
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer bearer" } });
    expect(firstRequest(fetcher)[1].method).toBeUndefined();
    expect(firstRequest(fetcher)[1].body).toBeUndefined();
    for (const invalid of [
      { ...settings, accountId: "other-account" },
      { ...settings, apiVersion: "legacy" },
      { ...settings, kind: "Account" },
      { ...settings, mfa: {} },
      { ...settings, mfa: { requiredForUsers: null } },
      { ...settings, mfa: { requiredForUsers: false, factorBound: true } },
      { ...settings, resourceVersion: 0 },
      { ...settings, password: undefined },
      { ...settings, session: undefined },
      { ...settings, accessKeyNetwork: undefined },
      { ...settings, session: { idleTimeoutMinutes: 4 } },
      { ...settings, accessKeyNetwork: { allowedSourceCidrs: ["198.51.100.1/24"] } },
      { ...settings, updatedAt: "not-a-timestamp" },
      { ...settings, editAllowed: true }
    ]) {
      reply(invalid);
      await expect(httpAccountRepository.accountSecuritySettings!.read("bearer", account.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("reads complete account password rules without inventing defaults or trusting malformed rules", async () => {
    const password = { minimumLength: 21, requireLowercase: true, requireUppercase: false,
      requireDigit: true, requireSymbol: false, historyCount: 3, maxAgeDays: 90, expiryMode: "ADMIN_RESET" };
    const settings = { apiVersion, kind: "AccountSecuritySettings", accountId: account.id,
      resourceVersion: 7, mfa: { requiredForUsers: true }, password, session: { idleTimeoutMinutes: 30 },
      accessKeyNetwork: { allowedSourceCidrs: ["198.51.100.0/24"] }, updatedAt: timestamp };
    reply(settings);
    await expect(httpAccountRepository.accountSecuritySettings!.read("bearer", account.id)).resolves.toEqual({
      accountId: account.id, resourceVersion: 7, mfa: { requiredForUsers: true }, password,
      session: settings.session, accessKeyNetwork: settings.accessKeyNetwork, updatedAt: timestamp
    });
    for (const invalid of [
      { ...password, minimumLength: 14 }, { ...password, minimumLength: 129 },
      { ...password, minimumLength: "21" }, { ...password, historyCount: -1 },
      { ...password, historyCount: 25 }, { ...password, requireDigit: undefined },
      { ...password, requireSymbol: "false" }, { ...password, maxAgeDays: 366 },
      { ...password, expiryMode: "UNKNOWN" }, { ...password, unrecognized: true }
    ]) {
      reply({ ...settings, password: invalid });
      await expect(httpAccountRepository.accountSecuritySettings!.read("bearer", account.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    reply({ ...settings, password: null });
    await expect(httpAccountRepository.accountSecuritySettings!.read("bearer", account.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("binds account MFA updates to one exact operation proof and original request", async () => {
    const update = httpAccountRepository.accountSecuritySettings!.update!;
    const intent = { expectedResourceVersion: 4, mfa: { requiredForUsers: true },
      password: { minimumLength: 18, requireLowercase: true, requireUppercase: true, requireDigit: true, requireSymbol: false, historyCount: 4, maxAgeDays: 90, expiryMode: "CHANGE_PASSWORD" as const },
      session: { idleTimeoutMinutes: 20 }, accessKeyNetwork: { allowedSourceCidrs: ["198.51.100.0/24"] } };
    const stepUp = { apiVersion, kind: "StepUp", id: "settings-proof-1", requestId: "settings-change-1",
      operation: "SECURITY_SETTINGS_UPDATE", expectedFactorRevision: 2, securitySettings: intent,
      state: "PENDING", createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z" };
    const settings = { apiVersion, kind: "AccountSecuritySettings", accountId: account.id,
      resourceVersion: 5, mfa: { requiredForUsers: true }, password: intent.password, session: intent.session,
      accessKeyNetwork: intent.accessKeyNetwork, updatedAt: timestamp };
    const change = { apiVersion, kind: "AccountSecuritySettingsChange", requestId: stepUp.requestId,
      expectedResourceVersion: 4, settings, callerSessionEnded: true };

    let fetcher = reply(stepUp);
    await expect(update.startStepUp("bearer", { requestId: stepUp.requestId, expectedFactorRevision: 2, intent })).resolves.toMatchObject({ operation: "SECURITY_SETTINGS_UPDATE", securitySettings: intent });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/step-up");
    expect(requestBody(fetcher)).toEqual({ requestId: stepUp.requestId, operation: "SECURITY_SETTINGS_UPDATE", expectedFactorRevision: 2, securitySettings: intent });

    fetcher = reply(stepUp);
    await update.stepUpByRequest("bearer", stepUp.requestId, 2, intent);
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/step-up/by-request/${stepUp.requestId}`);

    fetcher = reply({ ...stepUp, state: "PROVED", provedAt: "2026-09-11T08:00:30Z" });
    await update.verifyStepUp("bearer", stepUp.id, stepUp.requestId, 2, intent,
      { requestId: "verify-settings-1", password: "private-password", code: "123456" });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/step-up/${stepUp.id}:verify`);
    expect(requestBody(fetcher)).toEqual({ requestId: "verify-settings-1", password: "private-password", code: "123456" });

    fetcher = reply({ outcome: "APPLIED", change });
    await expect(update.apply("bearer", account.id, { requestId: stepUp.requestId, stepUpId: stepUp.id, intent })).resolves.toMatchObject({ outcome: "APPLIED", change: { callerSessionEnded: true, settings: { resourceVersion: 5 } } });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/account/security-settings");
    expect(firstRequest(fetcher)[1].method).toBe("PUT");
    expect(requestBody(fetcher)).toEqual({ requestId: stepUp.requestId, stepUpId: stepUp.id, ...intent });

    fetcher = reply(change);
    await expect(update.changeByRequest("new-bearer", account.id, stepUp.requestId, intent)).resolves.toMatchObject({ requestId: stepUp.requestId, callerSessionEnded: true });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/account/security-settings/changes/${stepUp.requestId}`);
    expect(firstRequest(fetcher)[1].method).toBeUndefined();
  });

  it("rejects drifted security proofs and account-rule completions without treating them as success", async () => {
    const update = httpAccountRepository.accountSecuritySettings!.update!;
    const intent = { expectedResourceVersion: 4, mfa: { requiredForUsers: true },
      password: { minimumLength: 18, requireLowercase: true, requireUppercase: true, requireDigit: true, requireSymbol: false, historyCount: 4, maxAgeDays: 90, expiryMode: "CHANGE_PASSWORD" as const },
      session: { idleTimeoutMinutes: 20 }, accessKeyNetwork: { allowedSourceCidrs: ["198.51.100.0/24"] } };
    const stepUp = { apiVersion, kind: "StepUp", id: "settings-proof-1", requestId: "settings-change-1",
      operation: "SECURITY_SETTINGS_UPDATE", expectedFactorRevision: 2, securitySettings: intent,
      state: "PENDING", createdAt: timestamp, expiresAt: "2026-09-11T08:02:00Z" };
    const settings = { apiVersion, kind: "AccountSecuritySettings", accountId: account.id,
      resourceVersion: 5, mfa: { requiredForUsers: true }, password: intent.password, session: intent.session,
      accessKeyNetwork: intent.accessKeyNetwork, updatedAt: timestamp };
    const change = { apiVersion, kind: "AccountSecuritySettingsChange", requestId: stepUp.requestId,
      expectedResourceVersion: 4, settings, callerSessionEnded: true };
    for (const invalid of [
      { ...stepUp, operation: "TOTP_REPLACE" },
      { ...stepUp, securitySettings: undefined },
      { ...stepUp, securitySettings: { ...intent, mfa: { requiredForUsers: false } } },
      { ...stepUp, securitySettings: { ...intent, session: { idleTimeoutMinutes: 30 } } },
      { ...stepUp, securitySettings: { ...intent, accessKeyNetwork: { allowedSourceCidrs: [] } } },
      { ...stepUp, expectedFactorRevision: 3 },
      { ...stepUp, securitySettings: { ...intent, unrelated: true } }
    ]) {
      reply(invalid);
      await expect(update.startStepUp("bearer", { requestId: stepUp.requestId, expectedFactorRevision: 2, intent })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    for (const invalid of [
      { ...change, requestId: "other-change" },
      { ...change, expectedResourceVersion: 3 },
      { ...change, callerSessionEnded: false },
      { ...change, settings: { ...settings, accountId: "other-account" } },
      { ...change, settings: { ...settings, resourceVersion: 6 } },
      { ...change, settings: { ...settings, mfa: { requiredForUsers: false } } },
      { ...change, settings: { ...settings, password: { ...intent.password, historyCount: 1 } } },
      { ...change, settings: { ...settings, session: { idleTimeoutMinutes: 30 } } },
      { ...change, settings: { ...settings, accessKeyNetwork: { allowedSourceCidrs: [] } } },
      { ...change, extra: true }
    ]) {
      reply({ outcome: "APPLIED", change: invalid });
      await expect(update.apply("bearer", account.id, { requestId: stepUp.requestId, stepUpId: stepUp.id, intent })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    reply({ outcome: "UNKNOWN", change });
    await expect(update.apply("bearer", account.id, { requestId: stepUp.requestId, stepUpId: stepUp.id, intent })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("fails closed on partial, reordered or semantically invalid authorization profile declarations", async () => {
    const valid = profileEntry("paas");
    const action = valid.profile.actions[0]!;
    for (const body of [
      { apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [] },
      { apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [profileEntry("paas"), profileEntry("iam")] },
      { apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [valid, valid] },
      { apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [{ ...valid, allowed: true }] },
      { apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [{ ...valid, contentDigest: `sha256:${"A".repeat(64)}` }] },
      { apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [{ ...valid, profile: { ...valid.profile, actions: [{ ...action, action: "other.application.create" }] } }] },
      { apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [{ ...valid, profile: { ...valid.profile, actions: [{ ...action, resourceShapes: [{ mode: "COLLECTION", prefixAllowed: false }] }] } }] },
      { apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [{ ...valid, profile: { ...valid.profile, actions: [{ ...action, scope: "INSTALLATION", conditions: [], resourceShapes: [{ mode: "INSTANCE", prefixAllowed: true }] }] } }] },
      { apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [{ ...valid, profile: { ...valid.profile, actions: [{ ...action, conditions: [{ key: "iam.current-time", valueType: "STRING", source: "CALLER" }] }] } }] },
      { apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [{ ...valid, profile: { ...valid.profile, actions: [{ ...action, resourceShapes: [{ mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_LIST" }] }] } }] },
      { apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: [{ ...valid, profile: { ...valid.profile, actions: [{ ...action, resultResourceKind: undefined }] } }] },
      { apiVersion, kind: "AuthorizationProfileList", accountId: account.id, items: Array.from({ length: 17 }, (_, index) => profileEntry(`p${index.toString().padStart(2, "0")}`)) }
    ]) {
      reply(body);
      await expect(httpAccountRepository.listAuthorizationProfiles("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("binds lifecycle requests to the exact account root and resource version", async () => {
    const disabled = { ...account, status: "DISABLED" };
    let fetcher = reply(disabled);
    await httpAccountRepository.execute("bearer", { kind: "set-account-status", accountId: account.id,
      status: "DISABLED", resourceVersion: 1 });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/accounts/account-acme:set-status");
    expect(requestBody(fetcher)).toEqual({ status: "DISABLED", resourceVersion: 1, requestId: expect.any(String) });

    fetcher = reply(disabled);
    await httpAccountRepository.execute("bearer", { kind: "recover-root-credentials", accountId: account.id,
      initialPassword: "Recovery-Test-Password-49!", resourceVersion: 1 });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/accounts/account-acme:recover-root-credentials");
    expect(requestBody(fetcher)).toEqual({ initialPassword: "Recovery-Test-Password-49!", resourceVersion: 1, requestId: expect.any(String) });
  });

  it("binds profile updates and irreversible deletion to one user revision", async () => {
    let fetcher = reply({ ...user, displayName: "Renamed Alex", resourceVersion: 3 });
    await httpAccountRepository.execute("bearer", { kind: "update-user", userId: user.id, displayName: "Renamed Alex", resourceVersion: 2 });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/users/user-alex:update");
    expect(requestBody(fetcher)).toEqual({ displayName: "Renamed Alex", resourceVersion: 2, requestId: expect.any(String) });

    fetcher = reply({ apiVersion, kind: "UserDeletion", accountId: account.id, id: user.id, loginName: user.loginName, resourceVersion: 3, deletedAt: timestamp });
    await httpAccountRepository.execute("bearer", { kind: "delete-user", userId: user.id, resourceVersion: 2 });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/users/user-alex:delete");
    expect(requestBody(fetcher)).toEqual({ resourceVersion: 2, requestId: expect.any(String) });

    for (const body of [
      { ...user, id: "another-user", displayName: "Renamed Alex", resourceVersion: 3 },
      { ...user, displayName: "Wrong name", resourceVersion: 3 }
    ]) {
      reply(body);
      await expect(httpAccountRepository.execute("bearer", { kind: "update-user", userId: user.id, displayName: "Renamed Alex", resourceVersion: 2 })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    for (const body of [
      { apiVersion, kind: "UserDeletion", accountId: account.id, id: "another-user", loginName: user.loginName, resourceVersion: 3, deletedAt: timestamp },
      { apiVersion, kind: "UserDeletion", accountId: account.id, id: user.id, loginName: user.loginName, resourceVersion: 4, deletedAt: timestamp },
      { apiVersion, kind: "UserDeletion", accountId: account.id, id: user.id, loginName: user.loginName, resourceVersion: 3, deletedAt: timestamp, password: "PRIVATE" }
    ]) {
      reply(body);
      await expect(httpAccountRepository.execute("bearer", { kind: "delete-user", userId: user.id, resourceVersion: 2 })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("sends the reviewed reset request identity unchanged without creating a second token", async () => {
    const fetcher = reply({ ...user, mustChangePassword: true, resourceVersion: 3 });
    await httpAccountRepository.execute("bearer", { kind: "reset-password", userId: user.id,
      initialPassword: "Reset-Only-Test-Password-74!", resourceVersion: 2, requestId: "ui-user-reset-original" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/users/user-alex:reset-password");
    expect(requestBody(fetcher)).toEqual({ initialPassword: "Reset-Only-Test-Password-74!", resourceVersion: 2,
      requestId: "ui-user-reset-original" });
  });

  it("looks up only the original reset tuple and rejects unbound or secret-bearing confirmations", async () => {
    const request = { accountId: account.id, actorId: "root-acme", userId: user.id, requestId: "ui-user-reset-original", resourceVersion: 2 };
    const completion = { apiVersion, kind: "UserPasswordResetCompletion", accountId: account.id,
      actorPrincipalId: request.actorId, userId: user.id, requestId: request.requestId,
      expectedResourceVersion: 2, resultingResourceVersion: 3, eventId: "event-reset-original", occurredAt: timestamp };
    const fetcher = reply(completion);
    expect(await httpAccountRepository.readPasswordResetCompletion("bearer", request)).toEqual({
      accountId: account.id, actorPrincipalId: request.actorId, userId: user.id, requestId: request.requestId,
      expectedResourceVersion: 2, resultingResourceVersion: 3, eventId: "event-reset-original", occurredAt: timestamp
    });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/users/user-alex/password-resets/ui-user-reset-original?resourceVersion=2");
    expect(firstRequest(fetcher)[1]).not.toHaveProperty("body");
    for (const wrong of [
      { actorPrincipalId: "different-actor" }, { accountId: "other-account" }, { userId: "other-user" },
      { requestId: "other-request" }, { expectedResourceVersion: 3 }, { resultingResourceVersion: 4 },
      { password: "MUST_NOT_BE_ACCEPTED" }
    ]) {
      reply({ ...completion, ...wrong });
      await expect(httpAccountRepository.readPasswordResetCompletion("bearer", request)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("uses exact policy identity and revisions for attach and revoke", async () => {
    let fetcher = reply(tenantAttachment);
    await httpAccountRepository.execute("bearer", { kind: "create-policy-attachment", userId: user.id,
      policyId: tenantAttachment.policyId, policyResourceVersion: 3, requestId: "attachment-intent-one" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policy-attachments");
    expect(requestBody(fetcher)).toEqual({ target: { kind: "USER", id: user.id }, policyId: tenantAttachment.policyId,
      policyResourceVersion: 3, requestId: "attachment-intent-one" });

    fetcher = reply({ apiVersion, kind: "Revocation", id: tenantAttachment.id, resourceVersion: 2, revokedAt: timestamp });
    await httpAccountRepository.revokePolicyAttachment("bearer", tenantAttachment.id, { resourceVersion: 1, requestId: "revocation-intent-one" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policy-attachments/attachment-viewer:revoke");
    expect(requestBody(fetcher)).toEqual({ resourceVersion: 1, requestId: "revocation-intent-one" });
  });

  it("reads one immutable policy attachment completion by request without sending authority selectors", async () => {
    const createExpectation = {
      operation: "CREATE" as const,
      accountId: account.id,
      actorPrincipalId: account.rootIdentity.principalId,
      requestId: `ui-user-attachment-${"a".repeat(32)}`,
      userId: user.id,
      policyId: tenantAttachment.policyId,
      policyResourceVersion: 3
    };
    const createCompletion = {
      apiVersion, kind: "PolicyAttachmentChange", operation: "CREATE",
      accountId: createExpectation.accountId, actorPrincipalId: createExpectation.actorPrincipalId,
      requestId: createExpectation.requestId, completedAt: timestamp,
      target: { kind: "USER", id: user.id }, policyId: tenantAttachment.policyId,
      policyResourceVersion: 3, attachment: tenantAttachment
    };
    const parsedAttachment = {
        id: tenantAttachment.id, accountId: account.id, target: tenantAttachment.target,
        policyId: tenantAttachment.policyId, scope: "TENANT", installationId: null,
        resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp
    };
    let fetcher = reply(createCompletion);
    await expect(httpAccountRepository.readUserPolicyAttachmentChange!("bearer", createExpectation)).resolves.toEqual({
      operation: "CREATE", accountId: account.id, actorPrincipalId: account.rootIdentity.principalId,
      requestId: createExpectation.requestId, completedAt: timestamp,
      target: { kind: "USER", id: user.id }, policyId: tenantAttachment.policyId,
      policyResourceVersion: 3, attachment: parsedAttachment
    });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/policy-attachment-changes/by-request/${createExpectation.requestId}`);
    expect(firstRequest(fetcher)[1]).not.toHaveProperty("body");

    const revokeExpectation = {
      operation: "REVOKE" as const,
      accountId: account.id,
      actorPrincipalId: account.rootIdentity.principalId,
      requestId: `ui-user-revocation-${"b".repeat(32)}`,
      attachmentId: tenantAttachment.id,
      expectedResourceVersion: 1
    };
    const revocation = { apiVersion, kind: "Revocation", id: tenantAttachment.id, resourceVersion: 2, revokedAt: timestamp };
    fetcher = reply({
      apiVersion, kind: "PolicyAttachmentChange", operation: "REVOKE",
      accountId: revokeExpectation.accountId, actorPrincipalId: revokeExpectation.actorPrincipalId,
      requestId: revokeExpectation.requestId, completedAt: timestamp,
      attachmentId: tenantAttachment.id, expectedResourceVersion: 1, revocation
    });
    await expect(httpAccountRepository.readUserPolicyAttachmentChange!("bearer", revokeExpectation)).resolves.toEqual({
      operation: "REVOKE", accountId: account.id, actorPrincipalId: account.rootIdentity.principalId,
      requestId: revokeExpectation.requestId, completedAt: timestamp,
      attachmentId: tenantAttachment.id, expectedResourceVersion: 1,
      revocation: { id: tenantAttachment.id, resourceVersion: 2, revokedAt: timestamp }
    });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/policy-attachment-changes/by-request/${revokeExpectation.requestId}`);
    expect(firstRequest(fetcher)[1]).not.toHaveProperty("body");
  });

  it("rejects policy attachment completions that are not byte-bound to the original actor and input", async () => {
    const expectation = {
      operation: "CREATE" as const,
      accountId: account.id,
      actorPrincipalId: account.rootIdentity.principalId,
      requestId: `ui-user-attachment-${"c".repeat(32)}`,
      userId: user.id,
      policyId: tenantAttachment.policyId,
      policyResourceVersion: 3
    };
    const valid = {
      apiVersion, kind: "PolicyAttachmentChange", operation: "CREATE",
      accountId: expectation.accountId, actorPrincipalId: expectation.actorPrincipalId,
      requestId: expectation.requestId, completedAt: timestamp,
      target: { kind: "USER", id: user.id }, policyId: tenantAttachment.policyId,
      policyResourceVersion: 3, attachment: tenantAttachment
    };
    for (const body of [
      { ...valid, accountId: "other-account" },
      { ...valid, actorPrincipalId: "other-actor" },
      { ...valid, requestId: "different-request" },
      { ...valid, operation: "REVOKE" },
      { ...valid, target: { kind: "USER", id: "other-user" } },
      { ...valid, policyId: "system.other-policy" },
      { ...valid, policyResourceVersion: 4 },
      { ...valid, attachment: { ...tenantAttachment, resourceVersion: 2 } },
      { ...valid, attachment: { ...tenantAttachment, updatedAt: "2026-09-11T08:00:01Z" } },
      { ...valid, credential: "MUST_NOT_BE_ACCEPTED" }
    ]) {
      reply(body);
      await expect(httpAccountRepository.readUserPolicyAttachmentChange!("bearer", expectation)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }

    const revokeExpectation = {
      operation: "REVOKE" as const,
      accountId: account.id,
      actorPrincipalId: account.rootIdentity.principalId,
      requestId: `ui-user-revocation-${"d".repeat(32)}`,
      attachmentId: tenantAttachment.id,
      expectedResourceVersion: 1
    };
    const validRevoke = {
      apiVersion, kind: "PolicyAttachmentChange", operation: "REVOKE",
      accountId: revokeExpectation.accountId, actorPrincipalId: revokeExpectation.actorPrincipalId,
      requestId: revokeExpectation.requestId, completedAt: timestamp,
      attachmentId: tenantAttachment.id, expectedResourceVersion: 1,
      revocation: { apiVersion, kind: "Revocation", id: tenantAttachment.id, resourceVersion: 2, revokedAt: timestamp }
    };
    for (const body of [
      { ...validRevoke, attachmentId: "other-attachment" },
      { ...validRevoke, expectedResourceVersion: 2 },
      { ...validRevoke, revocation: { ...validRevoke.revocation, resourceVersion: 3 } },
      { ...validRevoke, revocation: { ...validRevoke.revocation, revokedAt: "2026-09-11T08:00:01Z" } },
      { ...validRevoke, target: { kind: "USER", id: user.id } }
    ]) {
      reply(body);
      await expect(httpAccountRepository.readUserPolicyAttachmentChange!("bearer", revokeExpectation)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("rejects successful-looking responses for a different mutation target", async () => {
    reply({ ...tenantAttachment, target: { kind: "USER", id: "another-user" } });
    await expect(httpAccountRepository.execute("bearer", { kind: "create-policy-attachment", userId: user.id,
      policyId: tenantAttachment.policyId, policyResourceVersion: 3, requestId: "attachment-intent-two" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ apiVersion, kind: "Revocation", id: "another-attachment", resourceVersion: 2, revokedAt: timestamp });
    await expect(httpAccountRepository.revokePolicyAttachment("bearer", tenantAttachment.id,
      { resourceVersion: 1, requestId: "revocation-intent-two" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ ...account, loginAlias: "wrong-alias" });
    await expect(httpAccountRepository.execute("bearer", { kind: "set-alias", alias: "acme", resourceVersion: 1 })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });
});

describe("IAM HTTP own-session boundary", () => {
  const session = {
    apiVersion,
    kind: "Session",
    id: "session-001",
    organizationId: account.id,
    principalId: user.id,
    status: "ACTIVE",
    issuedAt: "2026-09-11T07:00:00.000001Z",
    expiresAt: "2026-09-11T09:00:00.000001Z"
  };
  const observation = {
    apiVersion,
    kind: "SessionList",
    accountId: account.id,
    userId: user.id,
    currentSessionId: session.id,
    observedAt: timestamp,
    items: [session]
  };

  it("lists only the authenticated user's canonical live session projection", async () => {
    const fetcher = reply(observation);
    const page = await httpIamRepository.sessions!.list("transient-bearer");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/sessions");
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer transient-bearer" } });
    expect(page).toMatchObject({ accountId: account.id, userId: user.id, currentSessionId: session.id, nextCursor: null });
    expect(page.items).toEqual([expect.objectContaining({ id: session.id, status: "ACTIVE" })]);
  });

  it("passes an opaque continuation unchanged and accepts a full-page next cursor", async () => {
    const items = Array.from({ length: 100 }, (_, index) => ({
      ...session,
      id: `session-${index.toString().padStart(3, "0")}`
    }));
    const fetcher = reply({ ...observation, items, nextCursor: "ic1.Opaque_signed-continuation" });
    const page = await httpIamRepository.sessions!.list("transient-bearer", "ic1.Current_signed-continuation");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/sessions?after=ic1.Current_signed-continuation");
    expect(page.nextCursor).toBe("ic1.Opaque_signed-continuation");
  });

  it("fails closed on foreign, expired, unordered, revoked or extended session projections", async () => {
    for (const invalid of [
      { ...observation, accountId: "other-account" },
      { ...observation, items: [{ ...session, organizationId: "other-account" }] },
      { ...observation, items: [{ ...session, principalId: "other-user" }] },
      { ...observation, items: [{ ...session, status: "REVOKED" }] },
      { ...observation, items: [{ ...session, revokedAt: timestamp }] },
      { ...observation, items: [{ ...session, issuedAt: "2026-09-11T08:00:00.000001Z" }] },
      { ...observation, items: [{ ...session, expiresAt: timestamp }] },
      { ...observation, items: [{ ...session, id: "session-002" }, session] },
      { ...observation, items: null },
      { ...observation, items: [session], nextCursor: "ic1.not-allowed-on-short-page" },
      { ...observation, items: [session], device: "invented" }
    ]) {
      reply(invalid);
      await expect(httpIamRepository.sessions!.list("transient-bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("sends only the retained request identity and verifies the exact revoked target", async () => {
    const response = { outcome: "APPLIED", revocation: { apiVersion, kind: "Revocation", id: session.id, resourceVersion: 2, revokedAt: timestamp } };
    const fetcher = reply(response);
    expect(await httpIamRepository.sessions!.revoke("transient-bearer", session.id, "ui-session-revoke-fixed")).toEqual({
      outcome: "APPLIED",
      revocation: { id: session.id, resourceVersion: 2, revokedAt: timestamp }
    });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/auth/sessions/${session.id}:revoke`);
    expect(firstRequest(fetcher)[1].method).toBe("POST");
    expect(requestBody(fetcher)).toEqual({ requestId: "ui-session-revoke-fixed" });
    for (const invalid of [
      { ...response, outcome: "UNKNOWN" },
      { ...response, revocation: { ...response.revocation, id: "session-other" } },
      { ...response, revocation: { ...response.revocation, resourceVersion: 0 } },
      { ...response, revocation: { ...response.revocation, target: session.id } },
      { ...response, receipt: {} }
    ]) {
      reply(invalid);
      await expect(httpIamRepository.sessions!.revoke("transient-bearer", session.id, "ui-session-revoke-fixed")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("ends other sessions without caller selectors and verifies the complete receipt", async () => {
    const requestId = "ui-session-revoke-others-fixed";
    const response = {
      apiVersion,
      kind: "OtherSessionsRevocation",
      outcome: "APPLIED",
      accountId: account.id,
      userId: user.id,
      currentSessionId: session.id,
      requestId,
      revokedCount: 2,
      completedAt: timestamp
    };
    const fetcher = reply(response);
    expect(await httpIamRepository.sessions!.revokeOthers("transient-bearer", requestId)).toEqual({
      outcome: "APPLIED",
      accountId: account.id,
      userId: user.id,
      currentSessionId: session.id,
      requestId,
      revokedCount: 2,
      completedAt: timestamp
    });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/sessions:revoke-others");
    expect(firstRequest(fetcher)[1].method).toBe("POST");
    expect(requestBody(fetcher)).toEqual({ requestId });
    for (const invalid of [
      { ...response, outcome: "UNKNOWN" },
      { ...response, kind: "Revocation" },
      { ...response, requestId: "other-request" },
      { ...response, revokedCount: -1 },
      { ...response, revokedCount: Number.MAX_SAFE_INTEGER + 1 },
      { ...response, targets: [] }
    ]) {
      reply(invalid);
      await expect(httpIamRepository.sessions!.revokeOthers("transient-bearer", requestId)).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });
});
