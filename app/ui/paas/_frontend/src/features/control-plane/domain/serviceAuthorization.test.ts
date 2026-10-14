import { describe, expect, it } from "vitest";
import type { ServiceRoleTemplate } from "@/features/auth/domain/serviceAuthorization";
import {
  isManagedServiceInstallationReader,
  managedServiceInstallationReader,
  sameTemplateReference
} from "./serviceAuthorization";

const template: ServiceRoleTemplate = {
  id: managedServiceInstallationReader.id,
  version: 2,
  contentDigest: `sha256:${"c".repeat(64)}`,
  status: "ACTIVE",
  spec: {
    product: managedServiceInstallationReader.product,
    servicePurpose: managedServiceInstallationReader.purpose,
    roleName: "ManagedServiceInstallationReader",
    roleDescription: "Read one explicitly bound installation.",
    policyVersion: {
      policyId: "system.managedservice-installation-reader",
      versionId: "version-managedservice-installation-reader-v1",
      contentDigest: `sha256:${"b".repeat(64)}`
    },
    workloads: [{
      resourceKind: managedServiceInstallationReader.workloadKind,
      bindAction: managedServiceInstallationReader.bindAction,
      unbindAction: managedServiceInstallationReader.unbindAction
    }],
    maxSessionDurationSeconds: 900
  }
};

describe("managed-service authorization contract", () => {
  it.each([2, 3])("selects the trusted active head by stable semantics, not fixed version %s", (version) => {
    expect(isManagedServiceInstallationReader({ ...template, version })).toBe(true);
  });

  it("rejects another template, retired heads, invalid digests or changed workload semantics", () => {
    expect(isManagedServiceInstallationReader(template)).toBe(true);
    expect(isManagedServiceInstallationReader({ ...template, id: "managedservice.other-reader" })).toBe(false);
    expect(isManagedServiceInstallationReader({ ...template, status: "RETIRED" })).toBe(false);
    expect(isManagedServiceInstallationReader({ ...template, contentDigest: "sha256:invalid" })).toBe(false);
    expect(isManagedServiceInstallationReader({ ...template, spec: { ...template.spec, product: "other-product" } })).toBe(false);
    expect(isManagedServiceInstallationReader({ ...template, spec: { ...template.spec, servicePurpose: "IAM" } })).toBe(false);
    expect(isManagedServiceInstallationReader({
      ...template,
      spec: { ...template.spec, workloads: [{ ...template.spec.workloads[0]!, resourceKind: "OTHER_INSTALLATION" }] }
    })).toBe(false);
    expect(isManagedServiceInstallationReader({
      ...template,
      spec: { ...template.spec, workloads: [{ ...template.spec.workloads[0]!, bindAction: "managedservice.other.bind" }] }
    })).toBe(false);
    expect(isManagedServiceInstallationReader({
      ...template,
      spec: { ...template.spec, workloads: [{ ...template.spec.workloads[0]!, unbindAction: "managedservice.other.unbind" }] }
    })).toBe(false);
  });

  it.each([0, -1, 2.5, Number.MAX_SAFE_INTEGER + 1])("rejects non-positive or unsafe template version %s", (version) => {
    expect(isManagedServiceInstallationReader({ ...template, version })).toBe(false);
  });

  it("compares the complete immutable reference instead of following an ID", () => {
    expect(sameTemplateReference(template, { id: template.id, version: template.version, contentDigest: template.contentDigest })).toBe(true);
    expect(sameTemplateReference(template, { id: template.id, version: template.version, contentDigest: `sha256:${"d".repeat(64)}` })).toBe(false);
    expect(sameTemplateReference(template, { id: template.id, version: template.version + 1, contentDigest: template.contentDigest })).toBe(false);
  });
});
