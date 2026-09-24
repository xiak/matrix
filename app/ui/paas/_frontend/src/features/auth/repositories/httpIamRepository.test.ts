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
function roleSessionListing(session: typeof roleSession & Record<string, unknown> = roleSession, lifecycle = "UNREVOKED", available = true) {
  return {
    session,
    sourceUser: { id: user.id, loginName: user.loginName, displayName: user.displayName },
    lifecycle,
    revokeCapability: capability("iam.role-session.revoke", "ROLE_SESSION", session.id, available, available ? "AUTHORITY_REQUIRED" : "SESSION_NOT_REVOCABLE")
  };
}
function roleSessionDirectory(items = [roleSessionListing()], nextAfter?: string) {
  return { apiVersion, kind: "RoleSessionList", accountId: account.id, roleId: role.id, observedAt: roleSessionObservedAt, items, ...(nextAfter ? { nextAfter } : {}) };
}

describe("IAM HTTP role-session boundary", () => {
  it("uses exact server filters and preserves opaque empty-window cursors", async () => {
    let fetcher = reply(roleSessionDirectory());
    const result = await httpAccountRepository.roles!.listSessions("bearer", account.id, role.id, { exactKind: "sourceUser", exactId: user.id, lifecycle: "ALL" });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}/sessions?sourceUserId=${user.id}&lifecycle=ALL`);
    expect(result.items[0]).toMatchObject({ lifecycle: "UNREVOKED", session: { id: roleSession.id }, sourceUser: { id: user.id } });

    fetcher = reply(roleSessionDirectory([], "ic1.next-window"));
    const empty = await httpAccountRepository.roles!.listSessions("bearer", account.id, role.id, { exactKind: "session", exactId: "", lifecycle: "UNREVOKED" });
    expect(empty).toMatchObject({ items: [], nextAfter: "ic1.next-window" });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}/sessions`);

    fetcher = reply(roleSessionDirectory([], "ic1.next-window"));
    await httpAccountRepository.roles!.listSessions("bearer", account.id, role.id, { exactKind: "session", exactId: "", lifecycle: "UNREVOKED" }, "ic1.previous-window");
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/roles/${role.id}/sessions?after=ic1.previous-window`);
  });

  it("rejects invented lifecycle, source, capability and private response fields", async () => {
    const invalid = [
      roleSessionDirectory([{ ...roleSessionListing(), lifecycle: "EXPIRED" }]),
      roleSessionDirectory([{ ...roleSessionListing(), sourceUser: { id: "user-other", loginName: "other", displayName: "Other" } }]),
      roleSessionDirectory([{ ...roleSessionListing(), revokeCapability: capability("iam.role-session.revoke", "ROLE_SESSION", "rs1.other") }]),
      roleSessionDirectory([{ ...roleSessionListing(), session: { ...roleSession, sourceSessionId: "private-login-session" } }])
    ];
    for (const response of invalid) {
      reply(response);
      await expect(httpAccountRepository.roles!.listSessions("bearer", account.id, role.id, { exactKind: "session", exactId: "", lifecycle: "ALL" })).rejects.toThrow("INVALID_IAM_RESPONSE");
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

const accessKey = { apiVersion, kind: "AccessKey", id: "mak1.alex-primary", accountId: account.id, userId: user.id,
  status: "ENABLED", resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp };
function accessKeyAccess(value = accessKey) {
  return { key: value, capabilities: [
    capability("iam.access-key.read", "ACCESS_KEY", value.id),
    capability("iam.access-key.set-status", "ACCESS_KEY", value.id),
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
    const result = await httpAccountRepository.accessKeys!.create("bearer", account.id, user.id, { userResourceVersion: 2, requestId: "create-key-1" });
    expect(result).toEqual(expect.objectContaining({ outcome: "APPLIED", secret: "mak1.secret-material" }));
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/users/${user.id}/access-keys`);
    expect(requestBody(fetcher)).toEqual({ userResourceVersion: 2, requestId: "create-key-1" });

    reply({ outcome: "EQUAL_REPLAY", key: accessKey, secret: "must-not-repeat" });
    await expect(httpAccountRepository.accessKeys!.create("bearer", account.id, user.id, { userResourceVersion: 2, requestId: "create-key-1" })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("keeps exact capability resource bindings and ordered key identities", async () => {
    reply({ ...accessKeyList(), items: [{ ...accessKeyAccess(), capabilities: [
      capability("iam.access-key.read", "ACCESS_KEY", "another-key"),
      capability("iam.access-key.set-status", "ACCESS_KEY", accessKey.id),
      capability("iam.access-key.delete", "ACCESS_KEY", accessKey.id)
    ] }] });
    await expect(httpAccountRepository.accessKeys!.list("bearer", account.id, user.id)).rejects.toThrow("INVALID_IAM_RESPONSE");

    reply({ ...accessKeyList(), items: [accessKeyAccess({ ...accessKey, id: "mak1.z" }), accessKeyAccess({ ...accessKey, id: "mak1.a" })] });
    await expect(httpAccountRepository.accessKeys!.list("bearer", account.id, user.id)).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("updates and deletes one key at its exact resource version", async () => {
    const disabled = { ...accessKey, status: "DISABLED", resourceVersion: 2, updatedAt: "2026-09-11T08:01:00Z" };
    let fetcher = reply({ outcome: "APPLIED", key: disabled });
    const status = await httpAccountRepository.accessKeys!.setStatus("bearer", account.id, user.id, accessKey.id, { accessKeyResourceVersion: 1, requestId: "disable-key-1", status: "DISABLED" });
    expect(status.key).toMatchObject({ status: "DISABLED", resourceVersion: 2 });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/users/${user.id}/access-keys/${accessKey.id}:set-status`);
    expect(requestBody(fetcher)).toEqual({ accessKeyResourceVersion: 1, requestId: "disable-key-1", status: "DISABLED" });

    fetcher = reply({ outcome: "APPLIED", deletion: { apiVersion, kind: "AccessKeyDeletion", id: accessKey.id, accountId: account.id, userId: user.id, resourceVersion: 3, deletedAt: "2026-09-11T08:02:00Z" } });
    const deletion = await httpAccountRepository.accessKeys!.delete("bearer", account.id, user.id, accessKey.id, { accessKeyResourceVersion: 2, requestId: "delete-key-1" });
    expect(deletion.deletion).toMatchObject({ id: accessKey.id, resourceVersion: 3 });
    expect(firstRequest(fetcher)[0]).toBe(`/api/iam/v1/users/${user.id}/access-keys/${accessKey.id}:delete`);
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
      () => httpIamRepository.personalSecurity!.confirmTOTPEnrollment("bearer", "enrollment-one", { requestId: "confirm-one", code: "" })
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

  it("uses exact policy identity and revisions for attach and revoke", async () => {
    let fetcher = reply(tenantAttachment);
    await httpAccountRepository.execute("bearer", { kind: "create-policy-attachment", userId: user.id,
      policyId: tenantAttachment.policyId, policyResourceVersion: 3 });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policy-attachments");
    expect(requestBody(fetcher)).toEqual({ target: { kind: "USER", id: user.id }, policyId: tenantAttachment.policyId,
      policyResourceVersion: 3, requestId: expect.any(String) });

    fetcher = reply({ apiVersion, kind: "Revocation", id: tenantAttachment.id, resourceVersion: 2, revokedAt: timestamp });
    await httpAccountRepository.execute("bearer", { kind: "revoke-policy-attachment", attachmentId: tenantAttachment.id, resourceVersion: 1 });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policy-attachments/attachment-viewer:revoke");
    expect(requestBody(fetcher)).toEqual({ resourceVersion: 1, requestId: expect.any(String) });
  });

  it("rejects successful-looking responses for a different mutation target", async () => {
    reply({ ...tenantAttachment, target: { kind: "USER", id: "another-user" } });
    await expect(httpAccountRepository.execute("bearer", { kind: "create-policy-attachment", userId: user.id,
      policyId: tenantAttachment.policyId, policyResourceVersion: 3 })).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ apiVersion, kind: "Revocation", id: "another-attachment", resourceVersion: 2, revokedAt: timestamp });
    await expect(httpAccountRepository.execute("bearer", { kind: "revoke-policy-attachment", attachmentId: tenantAttachment.id,
      resourceVersion: 1 })).rejects.toThrow("INVALID_IAM_RESPONSE");
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
