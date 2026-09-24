import { describe, expect, it } from "vitest";
import type { AuthorizationProfileDirectory } from "./accounts";
import { visualActionGroups, visualDraftFromJSON, visualDraftHasIncompleteFields } from "./accountPolicyVisualAuthoring";

const catalog: AuthorizationProfileDirectory = { accountId: "tenant-a", items: [
  { profile: { product: "paas", revision: 1, callingService: "PAAS", actions: [
    { action: "paas.application.read", resourceKind: "APPLICATION", scope: "TENANT", resourceShapes: [{ mode: "INSTANCE", prefixAllowed: true }],
      conditions: [{ key: "iam.account-id", valueType: "STRING", source: "IAM_AUTHENTICATED_IDENTITY" }] },
    { action: "paas.application.delete", resourceKind: "APPLICATION", scope: "TENANT", resourceShapes: [{ mode: "INSTANCE", prefixAllowed: false }] },
    { action: "paas.application.list", resourceKind: "APPLICATION", scope: "TENANT", resourceShapes: [{ mode: "COLLECTION", prefixAllowed: false, collectionUsage: "COLLECTION_LIST" }] },
    { action: "paas.node.inspect", resourceKind: "NODE", scope: "INSTALLATION", resourceShapes: [{ mode: "INSTANCE", prefixAllowed: false }] }
  ] }, contentDigest: `sha256:${"a".repeat(64)}` }
] };
const document = { languageVersion: "1", scope: "TENANT", statements: [{ sid: "read-apps", effect: "ALLOW", actions: ["paas.application.read"],
  resources: [{ kind: "APPLICATION", match: "PREFIX_IN_AUTHORITY", id: "app-" }],
  conditions: [{ key: "iam.account-id", operator: "STRING_EQUALS", values: ["tenant-a"] }] }] };

describe("lossless catalog-backed policy visual authoring", () => {
  it("groups only current tenant actions and preserves every supported field", () => {
    expect(visualActionGroups(catalog).map((group) => [group.product, group.resourceKind, group.actions.length])).toEqual([["paas", "APPLICATION", 3]]);
    expect(visualDraftFromJSON(JSON.stringify(document), catalog)).toEqual({ status: "ready", document });
  });
  it("never converts unknown fields or frozen action families into a partial visual form", () => {
    expect(visualDraftFromJSON(JSON.stringify({ ...document, comment: "must not disappear" }), catalog).status).toBe("shapeInvalid");
    expect(visualDraftFromJSON(JSON.stringify({ ...document, statements: [{ ...document.statements[0], actions: ["paas.application.*"] }] }), catalog).status).toBe("catalogMismatch");
    expect(visualDraftFromJSON(JSON.stringify({ ...document, statements: [{ ...document.statements[0], actions: ["paas.application.read", "paas.application.read"] }] }), catalog).status).toBe("catalogMismatch");
    expect(visualDraftFromJSON(JSON.stringify({ ...document, statements: [{ ...document.statements[0], actions: ["paas.application.read", "paas.application.list"], resources: [{ kind: "APPLICATION", match: "ANY_IN_AUTHORITY" }] }] }), catalog).status).toBe("catalogMismatch");
    expect(visualDraftFromJSON(JSON.stringify({ ...document, statements: Array.from({ length: 65 }, (_, index) => ({ ...document.statements[0], sid: `statement-${index}` })) }), catalog).status).toBe("shapeInvalid");
    expect(visualDraftFromJSON("{", catalog).status).toBe("jsonInvalid");
  });
  it("does not assume one action can supply another action's prefix or condition ability", () => {
    const statement = document.statements[0];
    expect(visualDraftFromJSON(JSON.stringify({ ...document, statements: [{ ...statement, actions: ["paas.application.read", "paas.application.delete"] }] }), catalog).status).toBe("catalogMismatch");
    expect(visualDraftFromJSON(JSON.stringify({ ...document, statements: [{ ...statement, actions: ["paas.application.list"], resources: [{ kind: "NODE", match: "ANY_IN_AUTHORITY" }] }] }), catalog).status).toBe("catalogMismatch");
    expect(visualDraftFromJSON(JSON.stringify({ ...document, statements: [{ ...statement, actions: ["paas.application.list"], resources: [{ kind: "APPLICATION", match: "EXACT", id: "app-prod" }] }] }), catalog).status).toBe("catalogMismatch");
    expect(visualDraftFromJSON(JSON.stringify({ ...document, statements: [{ ...statement, actions: ["paas.application.list"], resources: [{ kind: "APPLICATION", match: "EXACT", id: "collection" }], conditions: undefined }] }), catalog).status).toBe("ready");
    expect(visualDraftFromJSON(JSON.stringify({ ...document, statements: [{ ...statement, conditions: [{ key: "unknown", operator: "STRING_EQUALS", values: ["tenant-a"] }] }] }), catalog).status).toBe("catalogMismatch");
  });
  it("blocks incomplete visible fields before review while leaving IAM as final validator", () => {
    const supported = visualDraftFromJSON(JSON.stringify(document), catalog);
    expect(supported.status).toBe("ready");
    if (supported.status !== "ready") return;
    expect(visualDraftHasIncompleteFields(supported.document)).toBe(false);
    const statement = supported.document.statements[0]!;
    expect(visualDraftHasIncompleteFields({ ...supported.document, statements: [{ ...statement, sid: "" }] })).toBe(true);
    expect(visualDraftHasIncompleteFields({ ...supported.document, statements: [{ ...statement, resources: [{ kind: "APPLICATION", match: "EXACT", id: "" }] }] })).toBe(true);
    expect(visualDraftHasIncompleteFields({ ...supported.document, statements: [{ ...statement, conditions: [{ key: "iam.account-id", operator: "STRING_EQUALS", values: [""] }] }] })).toBe(true);
  });
});
