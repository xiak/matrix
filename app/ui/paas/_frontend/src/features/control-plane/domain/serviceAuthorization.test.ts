import { describe, expect, it } from "vitest";
import type { ServiceRoleTemplate } from "@/features/auth/domain/serviceAuthorization";
import {
  isManagedServiceInstallationReader,
  managedServiceInstallationReader,
  sameTemplateReference
} from "./serviceAuthorization";

const template: ServiceRoleTemplate = {
  id: managedServiceInstallationReader.id,
  version: managedServiceInstallationReader.version,
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
  it("selects only the exact release-owned template version and workload actions", () => {
    expect(isManagedServiceInstallationReader(template)).toBe(true);
    expect(isManagedServiceInstallationReader({ ...template, version: 2 })).toBe(false);
    expect(isManagedServiceInstallationReader({ ...template, status: "RETIRED" })).toBe(false);
    expect(isManagedServiceInstallationReader({
      ...template,
      spec: { ...template.spec, workloads: [{ ...template.spec.workloads[0]!, bindAction: "managedservice.other.bind" }] }
    })).toBe(false);
  });

  it("compares the complete immutable reference instead of following an ID", () => {
    expect(sameTemplateReference(template, { id: template.id, version: template.version, contentDigest: template.contentDigest })).toBe(true);
    expect(sameTemplateReference(template, { id: template.id, version: template.version, contentDigest: `sha256:${"d".repeat(64)}` })).toBe(false);
  });
});
