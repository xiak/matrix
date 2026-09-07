import { describe, expect, it } from "vitest";
import { previewCredential } from "@/features/auth/repositories/previewIamRepository";
import { previewControlPlaneRepository } from "./previewControlPlaneRepository";

describe("previewControlPlaneRepository", () => {
  it("provides a mutable but isolated end-to-end installation journey", async () => {
    const initial = await previewControlPlaneRepository.load(previewCredential);
    expect(initial.offerings[0]?.quotaShapes).toHaveLength(3);
    initial.offerings.length = 0;
    expect((await previewControlPlaneRepository.load(previewCredential)).offerings).toHaveLength(1);

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
  });

  it("rejects non-preview credentials", async () => {
    await expect(previewControlPlaneRepository.load("production-credential"))
      .rejects.toThrow("INVALID_PREVIEW_CREDENTIAL");
  });
});
