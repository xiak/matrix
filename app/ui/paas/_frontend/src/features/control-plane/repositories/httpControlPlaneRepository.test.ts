import { afterEach, describe, expect, it, vi } from "vitest";
import { httpControlPlaneRepository } from "./httpControlPlaneRepository";
import { managedServiceCommandTypes, type ManagedServiceCommandType } from "../domain/managedServiceCommand";

function recoveredCommand(commandType: ManagedServiceCommandType = "INSTALLATION_CREATE", state = "SUCCEEDED") {
  return {
    kind: "ManagedServiceCommandResult", idempotencyKey: "ui-install-original", commandType,
    inputDigest: `sha256:${"8".repeat(64)}`, state,
    target: { kind: commandType === "QUOTA_ACTIVATE" ? "QUOTA_ENTITLEMENT" : "SERVICE_INSTALLATION", id: "original-resource" },
    ...(commandType === "INSTALLATION_CREATE" || commandType === "INSTALLATION_TERMINATE" ? {
      operation: { id: "original-operation", kind: commandType === "INSTALLATION_CREATE" ? "PROVISION" : "TERMINATE",
        phase: state === "IN_PROGRESS" ? "PROVISIONING" : state === "FAILED" ? "FAILED" : "READY", safeFailureCode: state === "FAILED" ? "PROVISION_FAILED" : null, observedAt: "2026-10-13T10:00:00.123456Z" }
    } : commandType === "QUOTA_ACTIVATE" ? {} : { bindingId: "original-binding" }),
    ...(state === "IN_PROGRESS" ? {} : { completedAt: "2026-10-13T10:00:00.123456Z" })
  };
}

function commandResponse(items: unknown[], headers: Record<string, string> = {}) {
  return new Response(JSON.stringify({ kind: "ManagedServiceCommandResultList", items }), {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers }
  });
}

describe("bounded managed-service command recovery", () => {
  it.each(managedServiceCommandTypes)("reads %s by current bearer only and treats the input commitment as opaque", async (commandType) => {
    const fetch = vi.fn().mockResolvedValue(commandResponse([recoveredCommand(commandType)]));
    vi.stubGlobal("fetch", fetch);
    const results = await httpControlPlaneRepository.listCommandResults!("current-credential", commandType);
    expect(results[0]).toMatchObject({ idempotencyKey: "ui-install-original", commandType, inputDigest: `sha256:${"8".repeat(64)}`, state: "SUCCEEDED" });
    expect(fetch).toHaveBeenCalledWith(`/api/managed-services/v1/command-results/${commandType}`, {
      cache: "no-store", headers: { Accept: "application/json", Authorization: "Bearer current-credential" }
    });
  });

  it.each(["IN_PROGRESS", "FAILED"])("accepts the installation %s result without inventing resource state", async (state) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(commandResponse([recoveredCommand("INSTALLATION_TERMINATE", state)])));
    expect((await httpControlPlaneRepository.listCommandResults!("credential", "INSTALLATION_TERMINATE"))[0]?.state).toBe(state);
  });

  it.each([
    { requestId: "private-iam-key" }, { credential: "never-render" }, { accountId: "foreign-account" },
    { actorId: "foreign-actor" }, { commandType: "UNKNOWN" }, { commandType: "INSTALLATION_TERMINATE" },
    { state: "UNKNOWN" }, { inputDigest: "not-a-sha256-commitment" }, { idempotencyKey: "bad/key" },
    { completedAt: null }, { completedAt: "2026-02-30T10:00:00Z" }, { target: { kind: "ROLE", id: "role-one" } },
    { target: { kind: "SERVICE_INSTALLATION", id: "resource-one", accountId: "foreign-account" } },
    { operation: null }, { bindingId: "unexpected-binding" }
  ])("rejects foreign or unsupported result fields: %j", async (change) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(commandResponse([{ ...recoveredCommand(), ...change }])));
    await expect(httpControlPlaneRepository.listCommandResults!("credential", "INSTALLATION_CREATE")).rejects.toThrow();
  });

  it.each([
    { kind: "TERMINATE" }, { phase: "TERMINATED" }, { phase: "PENDING" }, { observedAt: "yesterday" },
    { observedAt: "2026-02-30T10:00:00Z" }, { actorId: "unexpected" }, { id: "bad/path" }, { safeFailureCode: {} },
    { safeFailureCode: "unexpected" }, { safeFailureCode: "PROVISION_FAILED" }, { observedAt: "2026-10-13T10:00:00.123456789Z" }
  ])("rejects an inconsistent installation operation: %j", async (change) => {
    const result = recoveredCommand();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(commandResponse([{ ...result, operation: { ...("operation" in result ? result.operation : {}), ...change } }])));
    await expect(httpControlPlaneRepository.listCommandResults!("credential", "INSTALLATION_CREATE")).rejects.toThrow();
  });

  it("rejects the replaced requestId-only response rather than accepting a compatibility alias", async () => {
    const result: Record<string, unknown> = { ...recoveredCommand() };
    delete result.idempotencyKey;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(commandResponse([{ ...result, requestId: "old-wire" }])));
    await expect(httpControlPlaneRepository.listCommandResults!("credential", "INSTALLATION_CREATE")).rejects.toThrow();
  });

  it.each(["QUOTA_ACTIVATE", "SERVICE_ROLE_BIND", "SERVICE_ROLE_UNBIND"] as const)("does not accept non-terminal %s", async (commandType) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(commandResponse([recoveredCommand(commandType, "IN_PROGRESS")])));
    await expect(httpControlPlaneRepository.listCommandResults!("credential", commandType)).rejects.toThrow();
  });

  it.each(["", "public", "no-cache"])("requires the no-store response boundary (%s)", async (cacheControl) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(commandResponse([], { "Cache-Control": cacheControl })));
    await expect(httpControlPlaneRepository.listCommandResults!("credential", "INSTALLATION_CREATE")).rejects.toThrow();
  });

  it.each(["items", "duplicate", "oversized", "selector"])("rejects an invalid list: %s", async (kind) => {
    const items = kind === "duplicate" ? [recoveredCommand(), recoveredCommand()] : kind === "oversized"
      ? Array.from({ length: 101 }, (_, index) => ({ ...recoveredCommand(), idempotencyKey: `key-${index}` })) : [];
    const body = { kind: "ManagedServiceCommandResultList", items: kind === "items" ? null : items, ...(kind === "selector" ? { accountId: "foreign" } : {}) };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } })));
    await expect(httpControlPlaneRepository.listCommandResults!("credential", "INSTALLATION_CREATE")).rejects.toThrow();
  });

  it("preserves an authoritative empty list and refuses caller-defined command names", async () => {
    const fetch = vi.fn().mockResolvedValue(commandResponse([]));
    vi.stubGlobal("fetch", fetch);
    expect(await httpControlPlaneRepository.listCommandResults!("credential", "INSTALLATION_CREATE")).toEqual([]);
    fetch.mockClear();
    await expect(httpControlPlaneRepository.listCommandResults!("credential", "ALL?account=foreign" as ManagedServiceCommandType)).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
});

const managedServiceTemplateReference = {
  id: "managedservice.installation-reader",
  version: 1,
  contentDigest: `sha256:${"c".repeat(64)}`
};

function serviceReference(id = "postgresql", digit = "1") {
  return { id, revision: 1, contentDigest: `sha256:${digit.repeat(64)}` };
}

function serviceDefinition(id = "postgresql", digit = "1") {
  return {
    ...serviceReference(id, digit),
    displayName: id === "postgresql" ? "PostgreSQL" : id,
    description: `Managed ${id}`,
    activationPrerequisite: "PERMISSION_ONLY",
    state: "AVAILABLE"
  };
}

function serviceActivation(id = "postgresql", digit = "1") {
  return {
    service: serviceReference(id, digit),
    resourceVersion: 1,
    activatedAt: "2026-10-12T11:00:00.123456Z"
  };
}

const quotaShape = { id: "small", displayName: "Small", cpuMillicores: 500, memoryMiB: 1024, storageGiB: 10 };

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
          service: serviceReference("postgresql", "1"),
          displayName: "PostgreSQL 18",
          description: "Managed PostgreSQL",
          engineFamily: "postgresql",
          engineVersion: "18",
          state: "AVAILABLE",
          quotaShapes: [quotaShape]
        }, {
          id: "mysql-8.4",
          service: serviceReference("mysql", "2"),
          displayName: "MySQL 8.4 LTS",
          description: "Managed MySQL",
          engineFamily: "mysql",
          engineVersion: "8.4",
          state: "AVAILABLE",
          quotaShapes: [quotaShape]
        }, {
          id: "elasticsearch-8.19",
          service: serviceReference("elasticsearch", "3"),
          displayName: "Elasticsearch 8.19",
          description: "Managed Elasticsearch",
          engineFamily: "elasticsearch",
          engineVersion: "8.19.23",
          state: "AVAILABLE",
          quotaShapes: [quotaShape]
        }, {
          id: "rabbitmq-4.1",
          service: serviceReference("rabbitmq", "4"),
          displayName: "RabbitMQ 4.1",
          description: "Managed RabbitMQ",
          engineFamily: "rabbitmq",
          engineVersion: "4.1.8",
          state: "AVAILABLE",
          quotaShapes: [quotaShape]
        }]
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await httpControlPlaneRepository.load("memory-only-session", ["offerings"]);

    expect(result.offerings?.map(({ id, service }) => ({ id, service: service.id }))).toEqual([
      { id: "postgresql-18", service: "postgresql" },
      { id: "mysql-8.4", service: "mysql" },
      { id: "elasticsearch-8.19", service: "elasticsearch" },
      { id: "rabbitmq-4.1", service: "rabbitmq" }
    ]);
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

  it.each([
    ["the superseded kind discriminator", {
      id: "postgresql-18", kind: "POSTGRESQL", displayName: "PostgreSQL 18", description: "Managed PostgreSQL",
      engineFamily: "postgresql", engineVersion: "18", state: "AVAILABLE", quotaShapes: [quotaShape]
    }],
    ["an extra compatibility discriminator", {
      id: "postgresql-18", service: serviceReference(), kind: "POSTGRESQL", displayName: "PostgreSQL 18",
      description: "Managed PostgreSQL", engineFamily: "postgresql", engineVersion: "18", state: "AVAILABLE", quotaShapes: [quotaShape]
    }],
    ["a one-character service name rejected by the backend contract", {
      id: "postgresql-18", service: serviceReference("p"), displayName: "PostgreSQL 18", description: "Managed PostgreSQL",
      engineFamily: "postgresql", engineVersion: "18", state: "AVAILABLE", quotaShapes: [quotaShape]
    }]
  ])("rejects an offering with %s", async (_name, offering) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ kind: "ServiceOfferingList", items: [offering] })));

    await expect(httpControlPlaneRepository.load("memory-only-session", ["offerings"]))
      .rejects.toThrow("INVALID_MANAGED_SERVICE_RESPONSE");
  });

  it.each([
    [true, undefined],
    [false, "AUTHORITY_REQUIRED"]
  ] as const)("reads the exact service directory and activation capability (available=%s)", async (available, restrictionReason) => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      kind: "ServiceDefinitionList",
      items: [serviceDefinition()],
      activationCapability: {
        action: "managedservice.service-activation.activate",
        resource: { kind: "SERVICE_ACTIVATION", id: "collection" },
        available,
        ...(restrictionReason ? { restrictionReason } : {})
      }
    }));
    vi.stubGlobal("fetch", fetchMock);

    const directory = await httpControlPlaneRepository.listServiceDefinitions!("memory-only-session");

    expect(directory.services).toEqual([serviceDefinition()]);
    expect(directory.activationCapability.available).toBe(available);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/managed-services/v1/services",
      expect.objectContaining({ headers: expect.objectContaining({ Authorization: "Bearer memory-only-session" }) })
    );
  });

  it.each([
    ["extra list field", { kind: "ServiceDefinitionList", items: [serviceDefinition()], activationCapability: { action: "managedservice.service-activation.activate", resource: { kind: "SERVICE_ACTIVATION", id: "collection" }, available: true }, extra: true }],
    ["unknown prerequisite", { kind: "ServiceDefinitionList", items: [{ ...serviceDefinition(), activationPrerequisite: "BILLING" }], activationCapability: { action: "managedservice.service-activation.activate", resource: { kind: "SERVICE_ACTIVATION", id: "collection" }, available: true } }],
    ["unsafe revision", { kind: "ServiceDefinitionList", items: [{ ...serviceDefinition(), revision: Number.MAX_SAFE_INTEGER + 1 }], activationCapability: { action: "managedservice.service-activation.activate", resource: { kind: "SERVICE_ACTIVATION", id: "collection" }, available: true } }],
    ["invalid allow restriction", { kind: "ServiceDefinitionList", items: [serviceDefinition()], activationCapability: { action: "managedservice.service-activation.activate", resource: { kind: "SERVICE_ACTIVATION", id: "collection" }, available: true, restrictionReason: "AUTHORITY_REQUIRED" } }],
    ["missing deny restriction", { kind: "ServiceDefinitionList", items: [serviceDefinition()], activationCapability: { action: "managedservice.service-activation.activate", resource: { kind: "SERVICE_ACTIVATION", id: "collection" }, available: false } }],
    ["unsorted services", { kind: "ServiceDefinitionList", items: [serviceDefinition("postgresql", "1"), serviceDefinition("mysql", "2")], activationCapability: { action: "managedservice.service-activation.activate", resource: { kind: "SERVICE_ACTIVATION", id: "collection" }, available: true } }]
  ])("rejects a malformed service directory: %s", async (_name, body) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(body)));
    await expect(httpControlPlaneRepository.listServiceDefinitions!("memory-only-session")).rejects.toThrow("INVALID_MANAGED_SERVICE_RESPONSE");
  });

  it("reads one activation through its service-scoped route", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(serviceActivation()));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.getServiceActivation!("memory-only-session", "postgresql"))
      .resolves.toEqual(serviceActivation());
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/managed-services/v1/service-activations/postgresql",
      expect.objectContaining({ headers: expect.objectContaining({ Authorization: "Bearer memory-only-session" }) })
    );
  });

  it.each([201, 200])("submits only the exact service reference and preserves the idempotency key (%s)", async (status) => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(serviceActivation()), {
      status,
      headers: { "Content-Type": "application/json", Location: "/managed-services/v1/service-activations/postgresql" }
    }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.activateService!(
      "memory-only-session",
      serviceReference(),
      "activation-request-1"
    )).resolves.toEqual(serviceActivation());
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/managed-services/v1/service-activations",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          Authorization: "Bearer memory-only-session",
          "Content-Type": "application/json",
          "Idempotency-Key": "activation-request-1"
        }),
        body: JSON.stringify({ service: serviceReference() })
      })
    );
  });

  it("rejects route-mismatched activation evidence and an invalid creation location", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse(serviceActivation("mysql", "2"))));
    await expect(httpControlPlaneRepository.getServiceActivation!("memory-only-session", "postgresql"))
      .rejects.toThrow("INVALID_MANAGED_SERVICE_RESPONSE");

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(serviceActivation()), {
      status: 201,
      headers: { "Content-Type": "application/json", Location: "/managed-services/v1/service-activations/mysql" }
    })));
    await expect(httpControlPlaneRepository.activateService!("memory-only-session", serviceReference(), "activation-request-1"))
      .rejects.toThrow("INVALID_MANAGED_SERVICE_RESPONSE");
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
      resourceVersion: 2,
      createdAt: "2026-08-26T12:00:00Z",
      operation: {
        id: "operation-primary",
        kind: "PROVISION",
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
      resourceVersion: 1,
      createdAt: "2026-08-26T12:00:00Z",
      operation: {
        id: "operation-other",
        kind: "PROVISION",
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

  it.each([
    ["PROVISION", "PENDING", "PENDING"],
    ["PROVISION", "PROVISIONING", "PROVISIONING"],
    ["PROVISION", "READY", "READY"],
    ["PROVISION", "FAILED", "FAILED"],
    ["PROVISION", "ROLLBACK_FAILED", "FAILED"],
    ["TERMINATE", "TERMINATION_PENDING", "PENDING"],
    ["TERMINATE", "TERMINATING", "PROVISIONING"],
    ["TERMINATE", "TERMINATION_FAILED", "FAILED"],
    ["TERMINATE", "TERMINATED", "READY"]
  ])("accepts the %s operation mapping %s resource state to %s operation state", async (
    operationKind,
    resourcePhase,
    operationPhase
  ) => {
    const retainsReadyResult = ["READY", "TERMINATION_PENDING", "TERMINATING", "TERMINATION_FAILED"]
      .includes(resourcePhase);
    const failed = ["FAILED", "ROLLBACK_FAILED", "TERMINATION_FAILED"].includes(resourcePhase);
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      id: "postgres-primary",
      name: "Postgres primary",
      offeringId: "postgresql-18",
      engineVersion: "18",
      quotaEntitlementId: "quota-primary",
      regionId: "local-primary",
      phase: resourcePhase,
      endpoint: retainsReadyResult ? "postgres-primary.service.local:5432" : null,
      credentialReference: retainsReadyResult ? "credential-postgres-primary" : null,
      resourceVersion: 4,
      createdAt: "2026-08-26T12:00:00Z",
      operation: {
        id: `operation-${operationKind.toLowerCase()}-primary`,
        kind: operationKind,
        phase: operationPhase,
        safeFailureCode: failed ? "SAFE_FAILURE" : null,
        observedAt: "2026-08-26T12:05:00Z"
      }
    }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.getInstallation(
      "memory-only-session",
      "postgres-primary"
    )).resolves.toMatchObject({
      phase: resourcePhase,
      operation: { kind: operationKind, phase: operationPhase }
    });
  });

  it.each([
    ["PROVISION", "ROLLBACK_FAILED", "ROLLBACK_FAILED"],
    ["PROVISION", "TERMINATION_PENDING", "PENDING"],
    ["TERMINATE", "TERMINATING", "PENDING"],
    ["TERMINATE", "TERMINATED", "TERMINATED"]
  ])("rejects the illegal %s operation mapping %s resource state to %s operation state", async (
    operationKind,
    resourcePhase,
    operationPhase
  ) => {
    const retainsReadyResult = ["READY", "TERMINATION_PENDING", "TERMINATING", "TERMINATION_FAILED"]
      .includes(resourcePhase);
    const failed = ["FAILED", "ROLLBACK_FAILED", "TERMINATION_FAILED"].includes(resourcePhase);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({
      id: "postgres-primary",
      name: "Postgres primary",
      offeringId: "postgresql-18",
      engineVersion: "18",
      quotaEntitlementId: "quota-primary",
      regionId: "local-primary",
      phase: resourcePhase,
      endpoint: retainsReadyResult ? "postgres-primary.service.local:5432" : null,
      credentialReference: retainsReadyResult ? "credential-postgres-primary" : null,
      resourceVersion: 4,
      createdAt: "2026-08-26T12:00:00Z",
      operation: {
        id: `operation-${operationKind.toLowerCase()}-primary`,
        kind: operationKind,
        phase: operationPhase,
        safeFailureCode: failed ? "SAFE_FAILURE" : null,
        observedAt: "2026-08-26T12:05:00Z"
      }
    })));

    await expect(httpControlPlaneRepository.getInstallation(
      "memory-only-session",
      "postgres-primary"
    )).rejects.toThrow("INVALID_INSTALLATION_RESPONSE");
  });

  it("forwards the caller's frozen quota request and idempotency key unchanged", async () => {
    const response = {
      id: "quota-primary",
      offeringId: "postgresql-18",
      quotaShapeId: "pg-small",
      purchasedCount: 2,
      reservedCount: 2,
      consumedCount: 0,
      resourceVersion: 1,
      activatedAt: "2026-10-12T00:00:00Z"
    };
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(response));
    vi.stubGlobal("fetch", fetchMock);
    const command = { offeringId: "postgresql-18", quotaShapeId: "pg-small", instanceCount: 2 };

    await expect(httpControlPlaneRepository.activateQuota(
      "session-secret", command, "ui-quota-frozen-request"
    )).resolves.toEqual(response);

    const [path, rawInit] = fetchMock.mock.calls[0]!;
    const init = rawInit as RequestInit;
    const headers = new Headers(init.headers);
    expect(path).toBe("/api/managed-services/v1/quota-entitlements");
    expect(headers.get("Idempotency-Key")).toBe("ui-quota-frozen-request");
    expect(init.body).toBe(JSON.stringify(command));
  });

  it("forwards the caller's frozen installation request and idempotency key unchanged", async () => {
    const command = {
      id: "postgres-primary",
      name: "Postgres primary",
      offeringId: "postgresql-18",
      quotaEntitlementId: "quota-primary",
      regionId: "local-primary"
    };
    const response = {
      ...command,
      engineVersion: "18",
      phase: "PENDING",
      endpoint: null,
      credentialReference: null,
      resourceVersion: 1,
      createdAt: "2026-10-12T00:00:00Z",
      operation: {
        id: "operation-provision-primary",
        kind: "PROVISION",
        phase: "PENDING",
        safeFailureCode: null,
        observedAt: "2026-10-12T00:00:00Z"
      }
    };
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(response));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.createInstallation(
      "session-secret", command, "ui-install-frozen-request"
    )).resolves.toEqual(response);

    const [path, rawInit] = fetchMock.mock.calls[0]!;
    const init = rawInit as RequestInit;
    const headers = new Headers(init.headers);
    expect(path).toBe("/api/managed-services/v1/service-installations");
    expect(headers.get("Idempotency-Key")).toBe("ui-install-frozen-request");
    expect(init.body).toBe(JSON.stringify(command));
  });

  it("rejects malformed caller request IDs before quota or installation writes", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.activateQuota(
      "session-secret",
      { offeringId: "postgresql-18", quotaShapeId: "pg-small", instanceCount: 1 },
      "invalid request"
    )).rejects.toThrow("INVALID_QUOTA_ACTIVATION_REQUEST");
    await expect(httpControlPlaneRepository.createInstallation(
      "session-secret",
      { id: "postgres-primary", name: "Postgres primary", offeringId: "postgresql-18", quotaEntitlementId: "quota-primary", regionId: "local-primary" },
      "invalid request"
    )).rejects.toThrow("INVALID_INSTALLATION_CREATION_REQUEST");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("submits and replays an installation termination with no request body and the caller's frozen idempotency key", async () => {
    const pendingTermination = {
      id: "postgres-primary",
      name: "Postgres primary",
      offeringId: "postgresql-18",
      engineVersion: "18",
      quotaEntitlementId: "quota-primary",
      regionId: "local-primary",
      phase: "TERMINATION_PENDING",
      endpoint: "postgres-primary.service.local:5432",
      credentialReference: "credential-postgres-primary",
      resourceVersion: 3,
      createdAt: "2026-08-26T12:00:00Z",
      operation: {
        id: "operation-terminate-primary",
        kind: "TERMINATE",
        phase: "PENDING",
        safeFailureCode: null,
        observedAt: "2026-08-26T12:04:00Z"
      }
    };
    const completedTermination = {
      ...pendingTermination,
      phase: "TERMINATED",
      endpoint: null,
      credentialReference: null,
      resourceVersion: 4,
      operation: {
        ...pendingTermination.operation,
        phase: "READY",
        observedAt: "2026-08-26T12:05:00Z"
      }
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(pendingTermination))
      .mockResolvedValueOnce(jsonResponse(completedTermination));
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.terminateInstallation!(
      "session-secret", "postgres-primary", "terminate-postgres-primary"
    )).resolves.toEqual(pendingTermination);
    await expect(httpControlPlaneRepository.terminateInstallation!(
      "session-secret", "postgres-primary", "terminate-postgres-primary"
    )).resolves.toEqual(completedTermination);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    for (const [path, rawInit] of fetchMock.mock.calls) {
      const init = rawInit as RequestInit;
      const headers = new Headers(init.headers);
      expect(path).toBe("/api/managed-services/v1/service-installations/postgres-primary/termination");
      expect(init.method).toBe("POST");
      expect(init.body).toBeUndefined();
      expect(headers.get("Authorization")).toBe("Bearer session-secret");
      expect(headers.get("Idempotency-Key")).toBe("terminate-postgres-primary");
      expect(headers.get("Content-Type")).toBeNull();
    }
  });

  it("fails closed on a termination result for another resource, operation kind or phase", async () => {
    const termination = {
      id: "postgres-primary",
      name: "Postgres primary",
      offeringId: "postgresql-18",
      engineVersion: "18",
      quotaEntitlementId: "quota-primary",
      regionId: "local-primary",
      phase: "TERMINATION_PENDING",
      endpoint: null,
      credentialReference: null,
      resourceVersion: 3,
      createdAt: "2026-08-26T12:00:00Z",
      operation: {
        id: "operation-terminate-primary",
        kind: "TERMINATE",
        phase: "PENDING",
        safeFailureCode: null,
        observedAt: "2026-08-26T12:04:00Z"
      }
    };
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockResolvedValueOnce(jsonResponse({ ...termination, id: "postgres-other" }));
    await expect(httpControlPlaneRepository.terminateInstallation!(
      "session-secret", "postgres-primary", "terminate-postgres-primary"
    )).rejects.toThrow("INVALID_INSTALLATION_TERMINATION_RESPONSE");
    fetchMock.mockResolvedValueOnce(jsonResponse({
      ...termination,
      operation: { ...termination.operation, kind: "PROVISION" }
    }));
    await expect(httpControlPlaneRepository.terminateInstallation!(
      "session-secret", "postgres-primary", "terminate-postgres-primary"
    )).rejects.toThrow("INVALID_INSTALLATION_RESPONSE");
    fetchMock.mockResolvedValueOnce(jsonResponse({
      ...termination,
      operation: { ...termination.operation, phase: "TERMINATING" }
    }));
    await expect(httpControlPlaneRepository.terminateInstallation!(
      "session-secret", "postgres-primary", "terminate-postgres-primary"
    )).rejects.toThrow("INVALID_INSTALLATION_RESPONSE");
  });

  it("rejects malformed termination locators before making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(httpControlPlaneRepository.terminateInstallation!(
      "session-secret", "postgres/primary", "terminate-postgres-primary"
    )).rejects.toThrow("INVALID_INSTALLATION_TERMINATION_REQUEST");
    await expect(httpControlPlaneRepository.terminateInstallation!(
      "session-secret", "postgres-primary", "terminate postgres primary"
    )).rejects.toThrow("INVALID_INSTALLATION_TERMINATION_REQUEST");
    expect(fetchMock).not.toHaveBeenCalled();
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
