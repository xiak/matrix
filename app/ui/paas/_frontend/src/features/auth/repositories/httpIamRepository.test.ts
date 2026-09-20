import { afterEach, describe, expect, it, vi } from "vitest";
import { httpAccountRepository, httpIamRepository } from "./httpIamRepository";

const apiVersion = "iam.matrix.xiak.com/v1";
const principal = {
  apiVersion, kind: "Principal", type: "USER", id: "principal-alex", organizationId: "account-acme",
  loginName: "alex", displayName: "Alex", status: "ACTIVE", mustChangePassword: true, resourceVersion: 2
};
const account = {
  organization: { apiVersion, kind: "Organization", id: "account-acme", displayName: "Acme", status: "ACTIVE", resourceVersion: 2 },
  primaryPrincipalId: "primary-acme", primaryLoginName: "acme.owner", loginAlias: "acme"
};
const binding = { apiVersion, kind: "RoleBinding", id: "binding-viewer", organizationId: "account-acme", principalId: "principal-alex", role: "PAAS_VIEWER" };
const session = {
  apiVersion, kind: "Session", id: "session", organizationId: "account-acme", principalId: "principal-alex",
  status: "ACTIVE", issuedAt: "2026-08-27T00:00:00Z", expiresAt: "2099-08-27T00:00:00Z"
};
const authenticated = { outcome: "AUTHENTICATED", credential: "transient-bearer", mustChangePassword: false, session };

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
    const fetcher = reply({ changedAt: "2026-08-28T01:02:03Z", bootstrapFileRetirable: false });
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
    const fetcher = reply(authenticated);
    await httpIamRepository.login({ loginName: "alex@acme", password: "synthetic-test-password" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/login");
    expect(requestBody(fetcher)).toEqual({ loginName: "alex@acme", password: "synthetic-test-password", requestId: expect.any(String) });
  });

  it("keeps login challenges sessionless and binds follow-up secrets to the path challenge", async () => {
    const challenge = { apiVersion, kind: "AuthenticationChallenge", id: "challenge-a", purpose: "LOGIN",
      nextStep: "TOTP", expiresAt: "2099-08-27T00:01:00Z" };
    let fetcher = reply({ outcome: "CHALLENGE_REQUIRED", challenge, challengeCredential: "challenge-only-secret" });
    const challenged = await httpIamRepository.login({ loginName: "alex@acme", password: "synthetic-test-password" });
    expect(challenged).toEqual({ outcome: "CHALLENGE_REQUIRED", challenge: {
      id: challenge.id, purpose: "LOGIN", nextStep: "TOTP", expiresAt: challenge.expiresAt
    }, challengeCredential: "challenge-only-secret" });
    expect(JSON.stringify(challenged)).not.toContain("session");

    fetcher = reply(authenticated);
    const verified = await httpIamRepository.authenticationChallenges!.verify({
      challengeId: challenge.id, challengeCredential: "challenge-only-secret", code: "123456"
    });
    expect(verified.outcome).toBe("AUTHENTICATED");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/challenges/challenge-a:verify");
    expect(requestBody(fetcher)).toEqual({ requestId: expect.any(String), challengeCredential: "challenge-only-secret", code: "123456" });

    fetcher = reply({ nextStep: "REAUTHENTICATE", changedAt: "2026-08-27T00:02:00Z" });
    await httpIamRepository.authenticationChallenges!.changePassword({
      challengeId: challenge.id, challengeCredential: "rotated-challenge-secret", newPassword: "Changed-Password-73!"
    });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/challenges/challenge-a:password");
    expect(requestBody(fetcher)).toEqual({ requestId: expect.any(String), challengeCredential: "rotated-challenge-secret", newPassword: "Changed-Password-73!" });
  });

  it("rejects mixed, recovery-purpose or otherwise ambiguous login results", async () => {
    const challenge = { apiVersion, kind: "AuthenticationChallenge", id: "challenge-a", purpose: "LOGIN",
      nextStep: "TOTP", expiresAt: "2099-08-27T00:01:00Z" };
    for (const wire of [
      { ...authenticated, challenge },
      { outcome: "CHALLENGE_REQUIRED", challenge: { ...challenge, purpose: "RECOVERY", nextStep: "ENROLLMENT" }, challengeCredential: "secret" },
      { outcome: "CHALLENGE_REQUIRED", challenge, challengeCredential: "secret", session },
      { ...authenticated, session: { ...session, kind: "Principal" } }
    ]) {
      reply(wire);
      await expect(httpIamRepository.login({ loginName: "alex@acme", password: "synthetic-test-password" }))
        .rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("creates a user without an implicit role or caller-supplied tenant", async () => {
    const fetcher = reply(principal);
    const command = { kind: "create-user" as const, loginName: "alex", displayName: "Alex", initialPassword: "synthetic-test-password", tenantId: "forged" };
    await httpAccountRepository.execute("transient-bearer", command);
    expect(requestBody(fetcher)).toEqual({ loginName: "alex", displayName: "Alex", initialPassword: "synthetic-test-password", requestId: expect.any(String) });
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer transient-bearer" } });
  });

  it("preserves explicit initial roles and optimistic alias versions", async () => {
    let fetcher = reply(principal);
    await httpAccountRepository.execute("bearer", { kind: "create-user", loginName: "alex", displayName: "Alex", initialPassword: "synthetic-test-password", initialRole: "PAAS_VIEWER" });
    expect(requestBody(fetcher).initialRole).toBe("PAAS_VIEWER");
    fetcher = reply(account);
    await httpAccountRepository.execute("bearer", { kind: "set-alias", alias: "acme", resourceVersion: 1 });
    expect(requestBody(fetcher)).toEqual({ alias: "acme", resourceVersion: 1, requestId: expect.any(String) });
  });

  it("parses account ownership without treating a child as a platform administrator", async () => {
    reply({ apiVersion, kind: "CurrentIdentity", account, principal, roles: [], canCreateOrganizations: false });
    const identity = await httpAccountRepository.currentIdentity("bearer");
    expect(identity.account.primaryLoginName).toBe("acme.owner");
    expect(identity.principal.loginName).toBe("alex");
    expect(identity.roles).toEqual([]);
    for (const patch of [
      { canCreateOrganizations: true },
      { principal: { ...principal, organizationId: "another-account" } },
      { roles: ["INSTALLATION_VERIFIER"] },
      { apiVersion: "future/v2" }
    ]) {
      reply({ apiVersion, kind: "CurrentIdentity", account, principal, roles: [], canCreateOrganizations: false, ...patch });
      await expect(httpAccountRepository.currentIdentity("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("bounds directory pages and rejects foreign or duplicate grants", async () => {
    const fetcher = reply({ apiVersion, kind: "PrincipalList", items: [{ principal, roleBindings: [binding] }], nextAfter: principal.id });
    const page = await httpAccountRepository.listUsers("bearer", "principal:first");
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/principals?after=principal%3Afirst");
    expect(page.items[0]?.roleBindings[0]?.role).toBe("PAAS_VIEWER");
    for (const roles of [[{ ...binding, organizationId: "another-account" }], [binding, binding]]) {
      reply({ apiVersion, kind: "PrincipalList", items: [{ principal, roleBindings: roles }] });
      await expect(httpAccountRepository.listUsers("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    reply({ apiVersion, kind: "PrincipalList", items: Array.from({ length: 101 }, () => ({ principal, roleBindings: [] })) });
    await expect(httpAccountRepository.listUsers("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
  });

  it("reads a platform binding without turning it into a tenant role", async () => {
    reply({ apiVersion, kind: "CurrentIdentity", account, principal,
      roles: ["PLATFORM_OPERATOR"], canCreateOrganizations: false });
    expect((await httpAccountRepository.currentIdentity("bearer")).roles).toEqual(["PLATFORM_OPERATOR"]);
    reply({ apiVersion, kind: "PrincipalList", items: [{ principal,
      roleBindings: [{ ...binding, role: "PLATFORM_OPERATOR" }] }] });
    expect((await httpAccountRepository.listUsers("bearer")).items[0]?.roleBindings[0]?.role).toBe("PLATFORM_OPERATOR");
  });

  it("accepts a changed-password platform-only child, not a primary tenant administrator, for tenant management", async () => {
    const operator = { ...principal, mustChangePassword: false };
    reply({ apiVersion, kind: "CurrentIdentity", account, principal: operator,
      roles: ["PLATFORM_OPERATOR"], canCreateOrganizations: true });
    expect((await httpAccountRepository.currentIdentity("bearer")).canCreateOrganizations).toBe(true);
    for (const [actor, roles] of [
      [{ ...operator, id: account.primaryPrincipalId }, ["ORGANIZATION_ADMIN"]],
      [principal, ["PLATFORM_OPERATOR"]]
    ]) {
      reply({ apiVersion, kind: "CurrentIdentity", account, principal: actor, roles, canCreateOrganizations: true });
      await expect(httpAccountRepository.currentIdentity("bearer")).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("binds lifecycle requests to an explicit platform target, original primary and organization version", async () => {
    const disabled = { ...account, organization: { ...account.organization, status: "DISABLED" } };
    let fetcher = reply(disabled);
    const status = { kind: "set-organization-status" as const, organizationId: account.organization.id,
      status: "DISABLED" as const, resourceVersion: 1, tenantId: "forged", principalId: "unrelated" };
    await httpAccountRepository.execute("bearer", status);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/organizations/account-acme:set-status");
    expect(requestBody(fetcher)).toEqual({ status: "DISABLED", resourceVersion: 1, requestId: expect.any(String) });

    fetcher = reply(disabled);
    const recovery = { kind: "recover-primary" as const, organizationId: account.organization.id,
      principalId: account.primaryPrincipalId, initialPassword: "Recovery-Test-Password-49!", resourceVersion: 1,
      tenantId: "forged", role: "PLATFORM_OPERATOR", status: "ACTIVE" };
    await httpAccountRepository.execute("bearer", recovery);
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/organizations/account-acme:recover-administrator");
    expect(requestBody(fetcher)).toEqual({ principalId: account.primaryPrincipalId,
      initialPassword: "Recovery-Test-Password-49!", resourceVersion: 1, requestId: expect.any(String) });
    expect(firstRequest(fetcher)[1]).toMatchObject({ cache: "no-store", headers: { Authorization: "Bearer bearer" } });
  });

  it("rejects lifecycle responses with a foreign tenant, unchanged version, wrong status or changed primary", async () => {
    for (const changed of [
      { ...account, organization: { ...account.organization, id: "other-tenant", status: "DISABLED" } },
      { ...account, organization: { ...account.organization, resourceVersion: 1, status: "DISABLED" } },
      account
    ]) {
      reply(changed);
      await expect(httpAccountRepository.execute("bearer", { kind: "set-organization-status",
        organizationId: account.organization.id, status: "DISABLED", resourceVersion: 1 })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
    for (const changed of [
      { ...account, primaryPrincipalId: "promoted-child" },
      { ...account, organization: { ...account.organization, id: "other-tenant" } },
      { ...account, organization: { ...account.organization, resourceVersion: 1 } }
    ]) {
      reply(changed);
      await expect(httpAccountRepository.execute("bearer", { kind: "recover-primary",
        organizationId: account.organization.id, principalId: account.primaryPrincipalId,
        initialPassword: "Recovery-Test-Password-49!", resourceVersion: 1 })).rejects.toThrow("INVALID_IAM_RESPONSE");
    }
  });

  it("rejects successful-looking responses for a different command target", async () => {
    reply({ ...principal, id: "another-user", status: "DISABLED" });
    await expect(httpAccountRepository.execute("bearer", { kind: "set-status", principalId: principal.id, status: "DISABLED", resourceVersion: 1 })).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ ...binding, role: "ORGANIZATION_ADMIN" });
    await expect(httpAccountRepository.execute("bearer", { kind: "grant-role", principalId: principal.id, role: "PAAS_VIEWER" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ ...account, loginAlias: "wrong-alias" });
    await expect(httpAccountRepository.execute("bearer", { kind: "set-alias", alias: "acme", resourceVersion: 1 })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });
});
