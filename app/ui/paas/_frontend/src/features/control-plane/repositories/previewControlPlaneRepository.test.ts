import { managedServiceProducts } from "../domain/managedServiceProduct";
import { describe, expect, it } from "vitest";
import { previewCredential } from "@/features/auth/repositories/previewIamRepository";
import { previewControlPlaneRepository } from "./previewControlPlaneRepository";

describe("previewControlPlaneRepository", () => {
  it("provides a mutable but isolated end-to-end installation journey", async () => {
    const initial = await previewControlPlaneRepository.load(previewCredential, ["offerings"]);
    expect(initial.offerings?.map(({ id }) => id)).toEqual(managedServiceProducts.map(({ offeringId }) => offeringId));
    expect(initial.offerings![0]?.quotaShapes).toHaveLength(2);
    initial.offerings!.length = 0;
    expect((await previewControlPlaneRepository.load(previewCredential, ["offerings"])).offerings).toHaveLength(managedServiceProducts.length);

    const id = "pg-ux-journey";
    const pending = await previewControlPlaneRepository.createInstallation(previewCredential, {
      id,
      name: "UX 验收数据库",
      offeringId: "postgresql-18",
      quotaEntitlementId: "quota-postgres-development",
      regionId: "shanghai-b"
    }, "ui-preview-create-installation");
    expect(pending.phase).toBe("PENDING");

    const ready = await previewControlPlaneRepository.getInstallation(previewCredential, id);
    expect(ready).toMatchObject({ phase: "READY", endpoint: `${id}.service.local:5432` });

    const terminating = await previewControlPlaneRepository.terminateInstallation!(
      previewCredential, id, "terminate-pg-ux-journey"
    );
    expect(terminating).toMatchObject({
      id,
      phase: "TERMINATION_PENDING",
      operation: { kind: "TERMINATE", phase: "PENDING" }
    });
    await expect(previewControlPlaneRepository.getInstallation(previewCredential, id))
      .resolves.toMatchObject({
        id,
        phase: "TERMINATED",
        endpoint: null,
        credentialReference: null,
        operation: { kind: "TERMINATE", phase: "READY" }
      });
    expect((await previewControlPlaneRepository.load(previewCredential, ["installations"]))
      .installations?.find((installation) => installation.id === id)?.phase).toBe("TERMINATED");
  });

  it("requires an exact READY Elasticsearch and holds deletion protection through Kibana cleanup", async () => {
    const repository = previewControlPlaneRepository;
    const create = { id: "es-preview-dependency", name: "Elasticsearch", offeringId: "elasticsearch-8.19",
      quotaEntitlementId: "quota-preview-es", regionId: "shanghai-a" };
    const es = await repository.createInstallation(previewCredential, create, "create-es");
    const kibana = { ...create, id: "kibana-preview-dependency", name: "Kibana", offeringId: "kibana-8.19",
      elasticsearch: { installationId: es.id, resourceVersion: es.resourceVersion } };
    await expect(repository.createInstallation(previewCredential, kibana, "create-k")).rejects.toThrow("DEPENDENCY_UNAVAILABLE");
    const ready = await repository.getInstallation(previewCredential, es.id);
    await expect(repository.createInstallation(previewCredential, kibana, "create-k")).rejects.toThrow("DEPENDENCY_UNAVAILABLE");
    kibana.elasticsearch.resourceVersion = ready.resourceVersion;
    const pending = await repository.createInstallation(previewCredential, kibana, "create-k");
    expect(pending.elasticsearch).toEqual(kibana.elasticsearch);
    for (const phase of ["PENDING", "READY", "TERMINATION_PENDING"]) {
      await expect(repository.terminateInstallation!(previewCredential, es.id, "terminate-es")).rejects.toThrow("DEPENDENCY_IN_USE");
      if (phase === "PENDING") expect((await repository.getInstallation(previewCredential, kibana.id)).endpoint).toContain(":5601");
      if (phase === "READY") await repository.terminateInstallation!(previewCredential, kibana.id, "terminate-k");
    }
    const terminated = await repository.getInstallation(previewCredential, kibana.id);
    expect(terminated).toMatchObject({ phase: "TERMINATED", elasticsearch: kibana.elasticsearch });
    await expect(repository.terminateInstallation!(previewCredential, es.id, "terminate-es")).resolves.toMatchObject({ phase: "TERMINATION_PENDING" });
    await repository.getInstallation(previewCredential, es.id);
  });

  it("rejects non-preview credentials", async () => {
    await expect(previewControlPlaneRepository.load("production-credential", ["offerings"]))
      .rejects.toThrow("INVALID_PREVIEW_CREDENTIAL");
  });

  it("returns only the resource slices requested by the current page", async () => {
    const regions = await previewControlPlaneRepository.load(previewCredential, ["regions"]);
    expect(regions.regions).toHaveLength(2);
    expect(regions).not.toHaveProperty("offerings");
    expect(regions).not.toHaveProperty("entitlements");
    expect(regions).not.toHaveProperty("installations");
  });
});
