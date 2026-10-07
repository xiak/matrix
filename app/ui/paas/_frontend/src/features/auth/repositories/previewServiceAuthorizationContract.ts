import type { ServiceRoleTemplate } from "../domain/serviceAuthorization";

// One isolated, release-shaped service template used across the MOCK product
// onboarding and service-authorization views. The vocabulary follows the
// fixed IAM contract; the digests and version IDs remain explicit samples and
// must never be treated as registry evidence.
export const previewManagedServiceRoleTemplate: ServiceRoleTemplate = {
  id: "managedservice.installation-reader",
  version: 1,
  contentDigest: `sha256:${"8".repeat(64)}`,
  spec: {
    product: "managedservice",
    servicePurpose: "PAAS",
    roleName: "ManagedServiceInstallationReader",
    roleDescription: "Allows the managed service controller to read one explicitly bound service installation.",
    policyVersion: {
      policyId: "system.managedservice-installation-reader",
      versionId: "version-preview-managedservice-installation-reader-v1",
      contentDigest: `sha256:${"9".repeat(64)}`
    },
    workloads: [{
      resourceKind: "SERVICE_INSTALLATION",
      bindAction: "managedservice.service-installation.service-role.bind",
      unbindAction: "managedservice.service-installation.service-role.unbind"
    }],
    maxSessionDurationSeconds: 15 * 60
  },
  status: "ACTIVE"
};

export const previewManagedServiceWorkload = previewManagedServiceRoleTemplate.spec.workloads[0]!;
