import { afterEach, describe, expect, it, vi } from "vitest";
import { httpControlPlaneRepository } from "./httpControlPlaneRepository";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("httpControlPlaneRepository", () => {
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
});
