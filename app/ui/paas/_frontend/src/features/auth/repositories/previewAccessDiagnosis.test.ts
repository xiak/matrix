import { describe, expect, it } from "vitest";
import { projectPreviewAccessDiagnosis } from "../domain/accessDiagnosis";
import { initialAccessWorkspace } from "./previewAccessWorkspace";

const userIds = ["principal-lin", "principal-chen", "principal-qiao", "principal-wu"];
const evaluatedAt = "2026-10-03T12:00:00Z";

function project(id: "path" | "duplicate" | "tags" | "deny" | "boundary" | "ungranted") {
  const workspace = initialAccessWorkspace("org-xiak");
  const scenario = workspace.testRequests.find((entry) => entry.id === id)!;
  return projectPreviewAccessDiagnosis(workspace, userIds, scenario, evaluatedAt);
}

describe("current access diagnosis preview projection", () => {
  it("projects the fixed credential-bound response shape without creating authorization evidence", () => {
    const result = project("path");
    expect(result.state).toBe("READY");
    if (result.state !== "READY") return;
    expect(result.diagnosis).toMatchObject({
      apiVersion: "iam.matrix.xiak.com/v1",
      kind: "CurrentAccessDiagnosis",
      outcome: "ALLOWED",
      reasons: [],
      tenantId: "org-xiak",
      subject: { type: "USER", id: "principal-lin" },
      action: "logs:search",
      resource: { kind: "topic", id: "production/payment" },
      profile: { product: "logs", revision: 1 },
      resourceMode: "INSTANCE",
      evaluatedAt,
      resourceExistence: "NOT_EVALUATED",
      businessOutcome: "NOT_EVALUATED"
    });
    expect(result.diagnosis.profile.contentDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(result.diagnosis.resourceTags?.map((entry) => entry.key)).toEqual(["environment", "team"]);
    expect(result.diagnosis.sources).toHaveLength(1);
    expect(result.diagnosis.sources.every((entry) => /^sha256:[0-9a-f]{64}$/.test(entry.version.contentDigest))).toBe(true);
    expect(result.diagnosis.restrictions).toEqual([{ kind: "USER_BOUNDARY", state: "NOT_APPLICABLE" }]);
  });

  it("keeps denial reasons, sources and boundary versions stable and contract-shaped", () => {
    const denied = project("deny");
    expect(denied.state).toBe("READY");
    if (denied.state !== "READY") return;
    expect(denied.diagnosis.outcome).toBe("DENIED");
    expect(denied.diagnosis.reasons).toEqual(["EXPLICIT_DENY", "USER_PERMISSION_BOUNDARY"]);
    expect(denied.diagnosis.sources.map((entry) => [entry.kind, entry.effect])).toEqual([
      ["DIRECT", "DENY"],
      ["GROUP", "ALLOW"]
    ]);
    expect(denied.diagnosis.restrictions[0]).toMatchObject({
      kind: "USER_BOUNDARY",
      state: "BLOCKED",
      version: { policyId: "policy-delivery-boundary", versionId: "v1" }
    });
    expect(denied.diagnosis.restrictions[0]?.version?.contentDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("does not fabricate a matching source for default denial", () => {
    const denied = project("ungranted");
    expect(denied.state).toBe("READY");
    if (denied.state !== "READY") return;
    expect(denied.diagnosis).toMatchObject({ outcome: "DENIED", reasons: ["NO_MATCHING_ALLOW"], sources: [] });
  });
});
