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
  it("sends the qualified username as one login identifier", async () => {
    const fetcher = reply({ credential: "transient-bearer", mustChangePassword: false,
      session: { id: "session", organizationId: "account-acme", principalId: "principal-alex", status: "ACTIVE", issuedAt: "2026-08-27T00:00:00Z", expiresAt: "2099-08-27T00:00:00Z" } });
    await httpIamRepository.login({ loginName: "alex@acme", password: "synthetic-test-password" });
    expect(firstRequest(fetcher)[0]).toBe("/api/iam/v1/auth/login");
    expect(requestBody(fetcher)).toEqual({ loginName: "alex@acme", password: "synthetic-test-password", requestId: expect.any(String) });
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

  it("rejects successful-looking responses for a different command target", async () => {
    reply({ ...principal, id: "another-user", status: "DISABLED" });
    await expect(httpAccountRepository.execute("bearer", { kind: "set-status", principalId: principal.id, status: "DISABLED", resourceVersion: 1 })).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ ...binding, role: "ORGANIZATION_ADMIN" });
    await expect(httpAccountRepository.execute("bearer", { kind: "grant-role", principalId: principal.id, role: "PAAS_VIEWER" })).rejects.toThrow("INVALID_IAM_RESPONSE");
    reply({ ...account, loginAlias: "wrong-alias" });
    await expect(httpAccountRepository.execute("bearer", { kind: "set-alias", alias: "acme", resourceVersion: 1 })).rejects.toThrow("INVALID_IAM_RESPONSE");
  });
});
