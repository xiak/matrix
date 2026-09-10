import { describe, expect, it } from "vitest";
import { validators as installation } from "./installationContract";
import { validators as iam } from "./iamContract";
import { validators as paas } from "./paasContract";
import { validators as devops } from "./devopsContract";
import { matchesContract } from "./validation";
import { productCanMutate, validateInventory } from "../features/platform/products";

const time = "2026-09-10T10:00:00Z";
const product = { id: "DEVOPS", version: "v0.3.0", routeKey: "devops", state: "READY", observedAt: time };
const inventory = { apiVersion: "installation.matrix.xiak.com/v1", kind: "InstalledProductList", observedAt: time, releaseId: "matrix-v0.3.0-0123456789ab", releaseVersion: "v0.3.0", products: [product] };
describe("current public contracts and product authority", () => {
  it("validates a closed installed inventory and rejects unknown products, fields and conditions", () => {
    expect(matchesContract(installation, "InstalledProductList", inventory)).toBe(true);
    for (const variant of [{ ...product, id: "IAM" }, { ...product, routeKey: "script" }, { ...product, state: "UNKNOWN" }, { ...product, state: "READY", reason: "DEPENDENCY_UNAVAILABLE" }, { ...product, url: "https://example.com" }]) {
      expect(matchesContract(installation, "InstalledProductList", { ...inventory, products: [variant] })).toBe(false);
    }
    expect(matchesContract(installation, "constructor", inventory)).toBe(false);
  });
  it("separately enforces uniqueness, compiled routes and readiness observation age", () => {
    const typed = inventory as Parameters<typeof validateInventory>[0];
    expect(() => validateInventory({ ...typed, products: [...typed.products, ...typed.products] })).toThrow();
    expect(() => validateInventory({ ...typed, products: [{ ...typed.products[0]!, routeKey: "paas" }] })).toThrow();
    expect(productCanMutate(typed.products[0], time, 100, 100)).toBe(true);
    expect(productCanMutate(typed.products[0], time, 100, 120100)).toBe(false);
    expect(productCanMutate({ ...typed.products[0]!, state: "DEGRADED" }, time, 100, 100)).toBe(false);
    expect(productCanMutate(undefined, time, 100, 100)).toBe(false);
  });
  it("honors boolean and conditional JSON Schema branches without browser compilation", () => {
    const scope = { kind: "TENANT", tenantId: "organization-a" };
    expect(matchesContract(paas, "ResourceScope", scope)).toBe(true);
    expect(matchesContract(paas, "ResourceScope", { kind: "OTHER", tenantId: "organization-a" })).toBe(false);
    expect(matchesContract(paas, "ResourceScope", { kind: "TENANT", unsafe: true })).toBe(false);
    const health = { health: "READY", reason: "OBSERVED", observedAt: time };
    expect(matchesContract(devops, "SourceConnectionStatus", health)).toBe(true);
    expect(matchesContract(devops, "SourceConnectionStatus", { ...health, reason: "SECRET_UNAVAILABLE" })).toBe(false);
    expect(matchesContract(iam, "Timestamp", "2026-02-30T10:00:00Z")).toBe(false);
    expect(matchesContract(devops, "VerificationLimits", { cpuMillis: 9999 })).toBe(false);
  });
});
