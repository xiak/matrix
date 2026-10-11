import { describe, expect, it } from "vitest";
import { previewCredential } from "@/features/auth/repositories/previewIamRepository";
import { previewControlPlaneRepository } from "./previewControlPlaneRepository";

describe("previewControlPlaneRepository", () => {
  it("provides a mutable but isolated end-to-end installation journey", async () => {
    const initial = await previewControlPlaneRepository.load(previewCredential, ["offerings"]);
    expect(initial.offerings?.map(({ id }) => id)).toEqual([
      "postgresql-18", "mysql-8.4", "elasticsearch-8.19", "rabbitmq-4.1"
    ]);
    expect(initial.offerings![0]?.quotaShapes).toHaveLength(2);
    initial.offerings!.length = 0;
    expect((await previewControlPlaneRepository.load(previewCredential, ["offerings"])).offerings).toHaveLength(4);

    const id = "pg-ux-journey";
    const pending = await previewControlPlaneRepository.createInstallation(previewCredential, {
      id,
      name: "UX 验收数据库",
      offeringId: "postgresql-18",
      quotaEntitlementId: "quota-postgres-development",
      regionId: "shanghai-b"
    });
    expect(pending.phase).toBe("PENDING");

    const ready = await previewControlPlaneRepository.getInstallation(previewCredential, id);
    expect(ready).toMatchObject({ phase: "READY", endpoint: `${id}.service.local:5432` });

    const terminating = await previewControlPlaneRepository.terminateInstallation!(
      previewCredential, id, "terminate-pg-ux-journey"
    );
    expect(terminating).toMatchObject({
      id,
      phase: "TERMINATION_PENDING",
      operation: { kind: "TERMINATE", phase: "TERMINATION_PENDING" }
    });
    await expect(previewControlPlaneRepository.getInstallation(previewCredential, id))
      .resolves.toMatchObject({ id, phase: "TERMINATED", endpoint: null, credentialReference: null });
    expect((await previewControlPlaneRepository.load(previewCredential, ["installations"]))
      .installations?.some((installation) => installation.id === id)).toBe(false);
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
