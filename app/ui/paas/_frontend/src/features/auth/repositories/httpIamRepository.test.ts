import { afterEach, describe, expect, it, vi } from "vitest";
import { httpAccountRepository, httpIamRepository } from "./httpIamRepository";

const apiVersion = "iam.matrix.xiak.com/v1";
const timestamp = "2026-09-11T08:00:00Z";
const principal = {
  apiVersion, kind: "Principal", type: "USER", id: "principal-alex", organizationId: "account-acme",
  loginName: "alex", displayName: "Alex", status: "ACTIVE", mustChangePassword: false, resourceVersion: 2
};
const account = {
  organization: { apiVersion, kind: "Organization", id: "account-acme", displayName: "Acme", status: "ACTIVE", resourceVersion: 2 },
  primaryPrincipalId: "primary-acme", primaryLoginName: "acme.owner", loginAlias: "acme"
};
const tenantAttachment = {
  apiVersion, kind: "PolicyAttachment", id: "attachment-viewer", accountId: "account-acme",
  target: { kind: "USER", id: "principal-alex" }, policyId: "system.paas-viewer", scope: "TENANT",
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

function reply(body: unknown) {
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } }));
  vi.stubGlobal("fetch", fetcher);
  return fetcher;
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

describe("IAM HTTP account boundary", () => {
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
    const fetcher = reply({ credential: "transient-bearer", mustChangePassword: false,
      session: { id: "session", organizationId: "account-acme", principalId: "principal-alex", status: "ACTIVE", issuedAt: timestamp, expiresAt: "2099-08-27T00:00:00Z" } });
    await httpIamRepository.login({ loginName: "alex@acme", password: "synthetic-test-password" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/login");
    expect(requestBody(fetcher)).toEqual({ loginName: "alex@acme", password: "synthetic-test-password", requestId: expect.any(String) });
  });

  it("creates a user with no implicit policy or caller-supplied account", async () => {
    const fetcher = reply({ ...principal, mustChangePassword: true });
    const command = { kind: "create-user" as const, loginName: "alex", displayName: "Alex", initialPassword: "synthetic-test-password", initialRole: "PAAS_VIEWER", tenantId: "forged" };
    await httpAccountRepository.execute("transient-bearer", command);
    expect(requestBody(fetcher)).toEqual({ loginName: "alex", displayName: "Alex", initialPassword: "synthetic-test-password", requestId: expect.any(String) });
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer transient-bearer" } });
  });

  it("parses current attachments without interpreting policy names", async () => {
    reply({ apiVersion, kind: "CurrentIdentity", account, principal, policyAttachments: [tenantAttachment, platformAttachment], canCreateOrganizations: true });
    const identity = await httpAccountRepository.currentIdentity("bearer");
    expect(identity.policyAttachments.map((item) => item.policyId)).toEqual(["system.paas-viewer", "system.platform-operator"]);
    for (const patch of [
      { canCreateOrganizations: true, policyAttachments: [tenantAttachment] },
      { principal: { ...principal, organizationId: "another-account" } },
      { policyAttachments: [{ ...tenantAttachment, accountId: "another-account" }] },
      { policyAttachments: [tenantAttachment, tenantAttachment] },
      { roles: ["PLATFORM_OPERATOR"] },
      { apiVersion: "future/v2" }
    ]) {
      reply({ apiVersion, kind: "CurrentIdentity", account, principal, policyAttachments: [], canCreateOrganizations: false, ...patch });
      await expect(httpAccountRepository.currentIdentity("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("bounds member pages and rejects foreign, duplicate, revoked, or old role projections", async () => {
    const fetcher = reply({ apiVersion, kind: "PrincipalList", items: [{ principal, policyAttachments: [tenantAttachment] }], nextAfter: principal.id });
    const page = await httpAccountRepository.listUsers("bearer", "principal:first");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/principals?after=principal%3Afirst");
    expect(page.items[0]?.policyAttachments[0]?.policyId).toBe("system.paas-viewer");
    for (const item of [
      { principal, policyAttachments: [{ ...tenantAttachment, accountId: "another-account" }] },
      { principal, policyAttachments: [tenantAttachment, tenantAttachment] },
      { principal, policyAttachments: [{ ...tenantAttachment, revokedAt: timestamp }] },
      { principal, roleBindings: [] }
    ]) {
      reply({ apiVersion, kind: "PrincipalList", items: [item] });
      await expect(httpAccountRepository.listUsers("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    reply({ apiVersion, kind: "PrincipalList", items: Array.from({ length: 101 }, () => ({ principal, policyAttachments: [] })) });
    await expect(httpAccountRepository.listUsers("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
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

  it("binds lifecycle requests to the exact account, original primary, and resource version", async () => {
    const disabled = { ...account, organization: { ...account.organization, status: "DISABLED" } };
    let fetcher = reply(disabled);
    await httpAccountRepository.execute("bearer", { kind: "set-organization-status", organizationId: account.organization.id,
      status: "DISABLED", resourceVersion: 1 });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/organizations/account-acme:set-status");
    expect(requestBody(fetcher)).toEqual({ status: "DISABLED", resourceVersion: 1, requestId: expect.any(String) });

    fetcher = reply(disabled);
    await httpAccountRepository.execute("bearer", { kind: "recover-primary", organizationId: account.organization.id,
      principalId: account.primaryPrincipalId, initialPassword: "Recovery-Test-Password-49!", resourceVersion: 1 });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/organizations/account-acme:recover-administrator");
    expect(requestBody(fetcher)).toEqual({ principalId: account.primaryPrincipalId,
      initialPassword: "Recovery-Test-Password-49!", resourceVersion: 1, requestId: expect.any(String) });
  });

  it("uses exact policy identity and revisions for attach and revoke", async () => {
    let fetcher = reply(tenantAttachment);
    await httpAccountRepository.execute("bearer", { kind: "create-policy-attachment", principalId: principal.id,
      policyId: tenantAttachment.policyId, policyResourceVersion: 3 });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policy-attachments");
    expect(requestBody(fetcher)).toEqual({ target: { kind: "USER", id: principal.id }, policyId: tenantAttachment.policyId,
      policyResourceVersion: 3, requestId: expect.any(String) });

    fetcher = reply({ apiVersion, kind: "Revocation", id: tenantAttachment.id, resourceVersion: 2, revokedAt: timestamp });
    await httpAccountRepository.execute("bearer", { kind: "revoke-policy-attachment", attachmentId: tenantAttachment.id, resourceVersion: 1 });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/policy-attachments/attachment-viewer:revoke");
    expect(requestBody(fetcher)).toEqual({ resourceVersion: 1, requestId: expect.any(String) });
  });

  it("rejects successful-looking responses for a different mutation target", async () => {
    reply({ ...tenantAttachment, target: { kind: "USER", id: "another-user" } });
    await expect(httpAccountRepository.execute("bearer", { kind: "create-policy-attachment", principalId: principal.id,
      policyId: tenantAttachment.policyId, policyResourceVersion: 3 })).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ apiVersion, kind: "Revocation", id: "another-attachment", resourceVersion: 2, revokedAt: timestamp });
    await expect(httpAccountRepository.execute("bearer", { kind: "revoke-policy-attachment", attachmentId: tenantAttachment.id,
      resourceVersion: 1 })).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ ...account, loginAlias: "wrong-alias" });
    await expect(httpAccountRepository.execute("bearer", { kind: "set-alias", alias: "acme", resourceVersion: 1 })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });
});
