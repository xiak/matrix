import { afterEach, describe, expect, it, vi } from "vitest";
import { httpControlPlaneRepository } from "./httpControlPlaneRepository";

const managedServiceTemplateReference = {
  id: "managedservice.installation-reader",
  version: 1,
  contentDigest: `sha256:${"c".repeat(64)}`
};

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" }
  });
}

function applicationBody() {
  return {
    apiVersion: "paas.matrix.xiak.com/v1",
    kind: "Application",
    metadata: {
      id: "app-checkout-api",
      name: "checkout-api",
      scope: { kind: "TENANT", tenantId: "org-xiak" },
      labels: { environment: "production", team: "commerce" },
      resourceVersion: 7,
      createdAt: "2026-09-08T08:00:00.123456Z",
      updatedAt: "2026-09-08T09:00:00.654321Z"
    }
  };
}

function applicationResponse(body: unknown, etag: string | null = '"7"'): Response {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (etag !== null) headers.set("ETag", etag);
  return new Response(JSON.stringify(body), { status: 200, headers });
}

function applicationDirectoryBody(items: unknown[] = [applicationBody()], nextAfter?: string) {
  return {
    apiVersion: "paas.matrix.xiak.com/v1",
    kind: "ApplicationList",
    items,
    ...(nextAfter ? { nextAfter } : {})
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("httpControlPlaneRepository", () => {
  it("reads only the resource slice requested by the destination page", async () => {
    const fetchMock = vi.fn(async (path: string) => {
      if (path !== "/api/managed-services/v1/offerings") {
        return new Response(JSON.stringify({ code: "FORBIDDEN" }), { status: 403 });
      }
      return jsonResponse({
        kind: "ServiceOfferingList",
        items: [{
          id: "postgresql-18",
          kind: "POSTGRESQL",
          displayName: "PostgreSQL 18",
          description: "Managed PostgreSQL",
          engineFamily: "PostgreSQL",
          engineVersion: "18",
          state: "AVAILABLE",
          quotaShapes: []
        }]
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await httpControlPlaneRepository.load("memory-only-session", ["offerings"]);

    expect(result.offerings).toHaveLength(1);
    expect(result).not.toHaveProperty("regions");
    expect(result).not.toHaveProperty("entitlements");
    expect(result).not.toHaveProperty("installations");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/managed-services/v1/offerings",
      expect.objectContaining({ headers: expect.objectContaining({ Authorization: "Bearer memory-only-session" }) })
    );
  });

  it("performs no HTTP request for a page without server-owned resource regions", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.load("memory-only-session", [])).resolves.toEqual({});
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reads one installation through its encoded resource route", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      id: "postgres-primary",
      name: "Postgres primary",
      offeringId: "postgresql-18",
      engineVersion: "18",
      quotaEntitlementId: "quota-primary",
      regionId: "local-primary",
      phase: "PROVISIONING",
      endpoint: null,
      credentialReference: null,
      createdAt: "2026-08-26T12:00:00Z",
      operation: {
        id: "operation-primary",
        phase: "PROVISIONING",
        safeFailureCode: null,
        observedAt: "2026-08-26T12:00:04Z"
      }
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    }));
    vi.stubGlobal("fetch", fetchMock);

    const installation = await httpControlPlaneRepository.getInstallation(
      "memory-only-session",
      "postgres-primary"
    );

    expect(installation.phase).toBe("PROVISIONING");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/managed-services/v1/service-installations/postgres-primary",
      expect.objectContaining({
        cache: "no-store",
        headers: expect.objectContaining({ Authorization: "Bearer memory-only-session" })
      })
    );
  });

  it("rejects a resource response whose identity differs from the route", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      id: "postgres-other",
      name: "Postgres other",
      offeringId: "postgresql-18",
      engineVersion: "18",
      quotaEntitlementId: "quota-primary",
      regionId: "local-primary",
      phase: "PENDING",
      endpoint: null,
      credentialReference: null,
      createdAt: "2026-08-26T12:00:00Z",
      operation: {
        id: "operation-other",
        phase: "PENDING",
        safeFailureCode: null,
        observedAt: "2026-08-26T12:00:00Z"
      }
    }), { status: 200, headers: { "Content-Type": "application/json" } })));

    await expect(httpControlPlaneRepository.getInstallation(
      "memory-only-session",
      "postgres-primary"
    )).rejects.toThrow("INVALID_INSTALLATION_ID_RESPONSE");
  });

  it("reads one Application through the exact product route and retains its strong ETag", async () => {
    const fetchMock = vi.fn().mockResolvedValue(applicationResponse(applicationBody()));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.readApplication!("memory-only-session", "app-checkout-api"))
      .resolves.toEqual({ etag: '"7"', application: applicationBody() });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [path, rawInit] = fetchMock.mock.calls[0]!;
    const init = rawInit as RequestInit;
    expect(path).toBe("/api/paas/v1/applications/app-checkout-api");
    expect(init.cache).toBe("no-store");
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer memory-only-session");
    expect(new Headers(init.headers).get("Accept")).toBe("application/json");
  });

  it("fails closed on malformed Application bodies, unsafe labels and non-canonical ETags", async () => {
    const invalid = [
      { body: { ...applicationBody(), unexpected: true }, etag: '"7"' },
      { body: { ...applicationBody(), metadata: { ...applicationBody().metadata, unexpected: true } }, etag: '"7"' },
      { body: { ...applicationBody(), metadata: { ...applicationBody().metadata, id: "app-other" } }, etag: '"7"' },
      { body: { ...applicationBody(), metadata: { ...applicationBody().metadata, scope: { kind: "PLATFORM" } } }, etag: '"7"' },
      { body: { ...applicationBody(), metadata: { ...applicationBody().metadata, resourceVersion: 0 } }, etag: '"0"' },
      { body: { ...applicationBody(), metadata: { ...applicationBody().metadata, updatedAt: "2026-09-08T07:00:00Z" } }, etag: '"7"' },
      { body: { ...applicationBody(), metadata: { ...applicationBody().metadata, labels: { environment: "secret=raw-value" } } }, etag: '"7"' },
      { body: applicationBody(), etag: null },
      { body: applicationBody(), etag: 'W/"7"' },
      { body: applicationBody(), etag: '"8"' }
    ];
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    for (const candidate of invalid) {
      fetchMock.mockResolvedValueOnce(applicationResponse(candidate.body, candidate.etag));
      await expect(httpControlPlaneRepository.readApplication!("memory-only-session", "app-checkout-api"))
        .rejects.toThrow("INVALID_APPLICATION_RESPONSE");
    }
    expect(fetchMock).toHaveBeenCalledTimes(invalid.length);
  });

  it("preserves product authorization and absence responses for the UI state machine", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ code: "APPLICATION_READ_FORBIDDEN" }), { status: 403 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ code: "APPLICATION_NOT_FOUND" }), { status: 404 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.readApplication!("memory-only-session", "app-checkout-api"))
      .rejects.toMatchObject({ status: 403, code: "APPLICATION_READ_FORBIDDEN" });
    await expect(httpControlPlaneRepository.readApplication!("memory-only-session", "app-checkout-api"))
      .rejects.toMatchObject({ status: 404, code: "APPLICATION_NOT_FOUND" });
  });

  it("rejects an invalid Application locator before making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.readApplication!("memory-only-session", "app/checkout"))
      .rejects.toThrow("INVALID_APPLICATION_REQUEST");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reads authorization-filtered Application windows and passes opaque continuations unchanged", async () => {
    const firstCursor = "pc1.First_window-123";
    const secondCursor = "pc1.Second_window-456";
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(applicationDirectoryBody([applicationBody()], firstCursor)))
      .mockResolvedValueOnce(jsonResponse(applicationDirectoryBody([], secondCursor)));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.listApplications!("memory-only-session"))
      .resolves.toEqual({ items: [applicationBody()], nextAfter: firstCursor });
    await expect(httpControlPlaneRepository.listApplications!("memory-only-session", firstCursor))
      .resolves.toEqual({ items: [], nextAfter: secondCursor });

    expect(fetchMock).toHaveBeenNthCalledWith(1, "/api/paas/v1/applications", expect.objectContaining({
      cache: "no-store",
      headers: expect.objectContaining({ Authorization: "Bearer memory-only-session" })
    }));
    expect(fetchMock).toHaveBeenNthCalledWith(2, `/api/paas/v1/applications?after=${firstCursor}`, expect.any(Object));
  });

  it("fails closed on malformed, cross-tenant, unordered or looping Application windows", async () => {
    const first = applicationBody();
    const second = {
      ...applicationBody(),
      metadata: { ...applicationBody().metadata, id: "app-inventory-api", name: "inventory-api" }
    };
    const fiftyOne = Array.from({ length: 51 }, (_, index) => ({
      ...applicationBody(),
      metadata: { ...applicationBody().metadata, id: `app-${String(index).padStart(3, "0")}`, name: `app-${String(index).padStart(3, "0")}` }
    }));
    const currentCursor = "pc1.Current_window";
    const invalid = [
      { ...applicationDirectoryBody(), unexpected: true },
      { ...applicationDirectoryBody(), items: null },
      applicationDirectoryBody(fiftyOne),
      applicationDirectoryBody([first, { ...second, metadata: { ...second.metadata, scope: { kind: "TENANT", tenantId: "org-other" } } }]),
      applicationDirectoryBody([second, first]),
      applicationDirectoryBody([first, first]),
      { ...applicationDirectoryBody(), nextAfter: "application-id" },
      applicationDirectoryBody([], currentCursor)
    ];
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    for (const candidate of invalid) {
      fetchMock.mockResolvedValueOnce(jsonResponse(candidate));
      const after = candidate === invalid.at(-1) ? currentCursor : undefined;
      await expect(httpControlPlaneRepository.listApplications!("memory-only-session", after))
        .rejects.toThrow("INVALID_APPLICATION_RESPONSE");
    }
    expect(fetchMock).toHaveBeenCalledTimes(invalid.length);
  });

  it("rejects a non-canonical Application continuation before making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.listApplications!("memory-only-session", "app-checkout-api"))
      .rejects.toThrow("INVALID_APPLICATION_CURSOR");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("observes the exact published template and active binding without sending an account selector", async () => {
    const apiVersion = "iam.matrix.xiak.com/v1";
    const timestamp = "2026-09-30T08:00:00Z";
    const templateReference = {
      id: "managedservice.installation-reader",
      version: 1,
      contentDigest: `sha256:${"c".repeat(64)}`
    };
    const policyVersion = {
      policyId: "system.managedservice-installation-reader",
      versionId: "version-managedservice-installation-reader-v1",
      contentDigest: `sha256:${"b".repeat(64)}`
    };
    const template = {
      apiVersion, kind: "ServiceRoleTemplate", ...templateReference, status: "ACTIVE",
      spec: {
        product: "managedservice", servicePurpose: "PAAS",
        roleName: "ManagedServiceInstallationReader",
        roleDescription: "Read one explicitly bound installation.",
        policyVersion,
        workloads: [{
          resourceKind: "SERVICE_INSTALLATION",
          bindAction: "managedservice.service-installation.service-role.bind",
          unbindAction: "managedservice.service-installation.service-role.unbind"
        }],
        maxSessionDurationSeconds: 900
      }
    };
    const role = {
      apiVersion, kind: "Role", id: "role-managedservice-reader", accountId: "account-acme",
      name: "ManagedServiceInstallationReader", description: "Read one installation.", tags: [],
      management: "SERVICE_LINKED", status: "ACTIVE", maxSessionDurationSeconds: 900,
      resourceVersion: 1, currentTrustVersionId: "trust-managedservice-reader-v1",
      createdAt: timestamp, updatedAt: timestamp
    };
    const relation = {
      apiVersion, kind: "ServiceLinkedRole", role, template: templateReference,
      servicePrincipal: { installationId: "installation-paas", principalId: "service-paas", purpose: "PAAS" },
      permissionCeiling: policyVersion
    };
    const binding = {
      apiVersion, kind: "WorkloadRoleBinding", id: "binding-pg-test", accountId: "account-acme",
      roleId: role.id, template: templateReference,
      workload: { kind: "SERVICE_INSTALLATION", id: "pg-test" },
      status: "ACTIVE", resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp
    };
    const responses = [
      { apiVersion, kind: "ServiceRoleTemplateList", items: [template] },
      { apiVersion, kind: "ServiceLinkedRoleList", accountId: "account-acme", items: [{ relation, bindingCount: 1, activeBindingCount: 1 }] },
      { apiVersion, kind: "ServiceLinkedRoleAccess", relation, bindings: [binding] }
    ];
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(new Response(JSON.stringify(responses.shift()), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    })));
    vi.stubGlobal("fetch", fetchMock);

    const result = await httpControlPlaneRepository.inspectServiceAuthorization!("session-secret", "account-acme", "pg-test");

    expect(result).toMatchObject({ template: { id: template.id, version: 1 }, relation: { role: { id: role.id } }, binding: { id: binding.id, status: "ACTIVE" } });
    expect(fetchMock.mock.calls.map(([path]) => path)).toEqual([
      "/api/iam/v1/service-role-templates",
      "/api/iam/v1/service-linked-roles",
      `/api/iam/v1/service-linked-roles/${role.id}`
    ]);
    expect(fetchMock.mock.calls.every(([, init]) => init.headers.Authorization === "Bearer session-secret")).toBe(true);
  });

  it("does not infer account consent when no matching account relation exists", async () => {
    const apiVersion = "iam.matrix.xiak.com/v1";
    const template = {
      apiVersion, kind: "ServiceRoleTemplate", id: "managedservice.installation-reader", version: 1,
      spec: {
        product: "managedservice", servicePurpose: "PAAS", roleName: "ManagedServiceInstallationReader",
        roleDescription: "Read one explicitly bound installation.",
        policyVersion: { policyId: "system.managedservice-installation-reader", versionId: "version-v1", contentDigest: `sha256:${"b".repeat(64)}` },
        workloads: [{ resourceKind: "SERVICE_INSTALLATION", bindAction: "managedservice.service-installation.service-role.bind", unbindAction: "managedservice.service-installation.service-role.unbind" }],
        maxSessionDurationSeconds: 900
      },
      contentDigest: `sha256:${"c".repeat(64)}`, status: "ACTIVE"
    };
    const responses = [
      { apiVersion, kind: "ServiceRoleTemplateList", items: [template] },
      { apiVersion, kind: "ServiceLinkedRoleList", accountId: "account-acme", items: [] }
    ];
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => Promise.resolve(new Response(JSON.stringify(responses.shift()), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    }))));

    await expect(httpControlPlaneRepository.inspectServiceAuthorization!("session-secret", "account-acme", "pg-test"))
      .resolves.toMatchObject({ template: { id: template.id }, relation: null, binding: null });
  });

  it("keeps account consent distinct when the relation exists but the exact resource is not bound", async () => {
    const apiVersion = "iam.matrix.xiak.com/v1";
    const timestamp = "2026-09-30T08:00:00Z";
    const templateReference = {
      id: "managedservice.installation-reader", version: 1, contentDigest: `sha256:${"c".repeat(64)}`
    };
    const policyVersion = {
      policyId: "system.managedservice-installation-reader", versionId: "version-v1", contentDigest: `sha256:${"b".repeat(64)}`
    };
    const template = {
      apiVersion, kind: "ServiceRoleTemplate", ...templateReference, status: "ACTIVE",
      spec: {
        product: "managedservice", servicePurpose: "PAAS", roleName: "ManagedServiceInstallationReader",
        roleDescription: "Read one explicitly bound installation.", policyVersion,
        workloads: [{ resourceKind: "SERVICE_INSTALLATION", bindAction: "managedservice.service-installation.service-role.bind", unbindAction: "managedservice.service-installation.service-role.unbind" }],
        maxSessionDurationSeconds: 900
      }
    };
    const role = {
      apiVersion, kind: "Role", id: "role-managedservice-reader", accountId: "account-acme",
      name: "ManagedServiceInstallationReader", description: "Read one installation.", tags: [],
      management: "SERVICE_LINKED", status: "ACTIVE", maxSessionDurationSeconds: 900,
      resourceVersion: 1, currentTrustVersionId: "trust-managedservice-reader-v1",
      createdAt: timestamp, updatedAt: timestamp
    };
    const relation = {
      apiVersion, kind: "ServiceLinkedRole", role, template: templateReference,
      servicePrincipal: { installationId: "installation-paas", principalId: "service-paas", purpose: "PAAS" },
      permissionCeiling: policyVersion
    };
    const otherBinding = {
      apiVersion, kind: "WorkloadRoleBinding", id: "binding-pg-other", accountId: "account-acme",
      roleId: role.id, template: templateReference,
      workload: { kind: "SERVICE_INSTALLATION", id: "pg-other" },
      status: "ACTIVE", resourceVersion: 1, createdAt: timestamp, updatedAt: timestamp
    };
    const responses = [
      { apiVersion, kind: "ServiceRoleTemplateList", items: [template] },
      { apiVersion, kind: "ServiceLinkedRoleList", accountId: "account-acme", items: [{ relation, bindingCount: 1, activeBindingCount: 1 }] },
      { apiVersion, kind: "ServiceLinkedRoleAccess", relation, bindings: [otherBinding] }
    ];
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(new Response(JSON.stringify(responses.shift()), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    })));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.inspectServiceAuthorization!("session-secret", "account-acme", "pg-unbound"))
      .resolves.toMatchObject({ template: { id: template.id }, relation: { role: { id: role.id } }, binding: null });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("binds only the exact published template and binds the receipt to the requested installation", async () => {
    const receipt = {
      kind: "ServiceRoleBindingReceipt",
      serviceInstallationId: "postgres-primary",
      bindingId: "binding-primary",
      roleId: "role-managedservice-reader",
      template: managedServiceTemplateReference,
      status: "ACTIVE",
      resourceVersion: 1,
      createdAt: "2026-09-30T08:00:00.123456Z"
    };
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(receipt));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.bindServiceRole!("session-secret", "postgres-primary", {
      template: managedServiceTemplateReference,
      requestId: "bind-postgres-primary"
    })).resolves.toEqual(receipt);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [path, rawInit] = fetchMock.mock.calls[0]!;
    const init = rawInit as RequestInit;
    const headers = new Headers(init.headers);
    expect(path).toBe("/api/managed-services/v1/service-installations/postgres-primary/service-role-bindings");
    expect(init.method).toBe("POST");
    expect(headers.get("Authorization")).toBe("Bearer session-secret");
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(headers.get("Idempotency-Key")).toBe("bind-postgres-primary");
    expect(JSON.parse(String(init.body))).toEqual({ template: managedServiceTemplateReference });
  });

  it("replays an unbind with the caller's frozen idempotency key and no authority selectors", async () => {
    const receipt = {
      kind: "ServiceRoleUnbindingReceipt",
      serviceInstallationId: "postgres-primary",
      bindingId: "binding-primary",
      roleId: "role-managedservice-reader",
      template: managedServiceTemplateReference,
      status: "REVOKED",
      resourceVersion: 2,
      createdAt: "2026-09-30T08:00:00Z",
      revokedAt: "2026-09-30T08:00:01Z"
    };
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(jsonResponse(receipt)));
    vi.stubGlobal("fetch", fetchMock);
    const command = {
      bindingId: "binding-primary",
      resourceVersion: 1,
      expectedTemplate: managedServiceTemplateReference,
      requestId: "unbind-postgres-primary"
    };

    await expect(httpControlPlaneRepository.unbindServiceRole!("session-secret", "postgres-primary", command))
      .resolves.toEqual(receipt);
    await expect(httpControlPlaneRepository.unbindServiceRole!("session-secret", "postgres-primary", command))
      .resolves.toEqual(receipt);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    for (const [path, rawInit] of fetchMock.mock.calls) {
      const init = rawInit as RequestInit;
      const headers = new Headers(init.headers);
      expect(path).toBe("/api/managed-services/v1/service-installations/postgres-primary/service-role-bindings/binding-primary");
      expect(init.method).toBe("DELETE");
      expect(headers.get("Idempotency-Key")).toBe("unbind-postgres-primary");
      expect(JSON.parse(String(init.body))).toEqual({ resourceVersion: 1 });
      expect(String(init.body)).not.toContain("accountId");
      expect(String(init.body)).not.toContain("roleId");
      expect(String(init.body)).not.toContain("purpose");
    }
  });

  it("fails closed on successful-looking bind receipts that are not the exact requested result", async () => {
    const receipt = {
      kind: "ServiceRoleBindingReceipt",
      serviceInstallationId: "postgres-primary",
      bindingId: "binding-primary",
      roleId: "role-managedservice-reader",
      template: managedServiceTemplateReference,
      status: "ACTIVE",
      resourceVersion: 1,
      createdAt: "2026-09-30T08:00:00Z"
    };
    const invalid = [
      { ...receipt, unexpected: true },
      { ...receipt, serviceInstallationId: "postgres-other" },
      { ...receipt, status: "REVOKED" },
      { ...receipt, resourceVersion: 2 },
      { ...receipt, template: { ...managedServiceTemplateReference, contentDigest: `sha256:${"d".repeat(64)}` } },
      { ...receipt, createdAt: "2026-09-30T08:00:00.1234567Z" }
    ];
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    for (const body of invalid) {
      fetchMock.mockResolvedValueOnce(jsonResponse(body));
      await expect(httpControlPlaneRepository.bindServiceRole!("session-secret", "postgres-primary", {
        template: managedServiceTemplateReference,
        requestId: "bind-postgres-primary"
      })).rejects.toThrow("INVALID_SERVICE_AUTHORIZATION_RESPONSE");
    }
  });

  it("fails closed on an unbind receipt for another binding or an impossible lifecycle", async () => {
    const receipt = {
      kind: "ServiceRoleUnbindingReceipt",
      serviceInstallationId: "postgres-primary",
      bindingId: "binding-primary",
      roleId: "role-managedservice-reader",
      template: managedServiceTemplateReference,
      status: "REVOKED",
      resourceVersion: 2,
      createdAt: "2026-09-30T08:00:01Z",
      revokedAt: "2026-09-30T08:00:00Z"
    };
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const command = {
      bindingId: "binding-primary",
      resourceVersion: 1,
      expectedTemplate: managedServiceTemplateReference,
      requestId: "unbind-postgres-primary"
    };

    fetchMock.mockResolvedValueOnce(jsonResponse(receipt));
    await expect(httpControlPlaneRepository.unbindServiceRole!("session-secret", "postgres-primary", command))
      .rejects.toThrow("INVALID_SERVICE_AUTHORIZATION_RESPONSE");
    fetchMock.mockResolvedValueOnce(jsonResponse({ ...receipt, createdAt: receipt.revokedAt, bindingId: "binding-other" }));
    await expect(httpControlPlaneRepository.unbindServiceRole!("session-secret", "postgres-primary", command))
      .rejects.toThrow("INVALID_SERVICE_AUTHORIZATION_RESPONSE");
  });

  it("rejects malformed bind and unbind commands before making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.bindServiceRole!("session-secret", "postgres/primary", {
      template: managedServiceTemplateReference,
      requestId: "bind-postgres-primary"
    })).rejects.toThrow("INVALID_SERVICE_AUTHORIZATION_REQUEST");
    await expect(httpControlPlaneRepository.unbindServiceRole!("session-secret", "postgres-primary", {
      bindingId: "binding-primary",
      resourceVersion: 2,
      expectedTemplate: managedServiceTemplateReference,
      requestId: "unbind-postgres-primary"
    })).rejects.toThrow("INVALID_SERVICE_AUTHORIZATION_REQUEST");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
