import type {
  ServiceLinkedRoleRelation,
  ServiceRoleTemplate,
  WorkloadRoleBinding
} from "@/features/auth/domain/serviceAuthorization";

export const managedServiceInstallationReader = {
  id: "managedservice.installation-reader",
  version: 1,
  product: "managedservice",
  purpose: "PAAS",
  workloadKind: "SERVICE_INSTALLATION",
  bindAction: "managedservice.service-installation.service-role.bind",
  unbindAction: "managedservice.service-installation.service-role.unbind"
} as const;

export type ManagedServiceAuthorizationObservation = {
  template: ServiceRoleTemplate;
  relation: ServiceLinkedRoleRelation | null;
  binding: WorkloadRoleBinding | null;
};

export type ManagedServiceAuthorizationLoad =
  | { status: "ready"; observation: ManagedServiceAuthorizationObservation }
  | { status: "expired" | "forbidden" | "unavailable" };

export function isManagedServiceInstallationReader(template: ServiceRoleTemplate): boolean {
  const workload = template.spec.workloads.find((item) => item.resourceKind === managedServiceInstallationReader.workloadKind);
  return template.id === managedServiceInstallationReader.id &&
    template.version === managedServiceInstallationReader.version &&
    template.status === "ACTIVE" &&
    template.spec.product === managedServiceInstallationReader.product &&
    template.spec.servicePurpose === managedServiceInstallationReader.purpose &&
    workload?.bindAction === managedServiceInstallationReader.bindAction &&
    workload.unbindAction === managedServiceInstallationReader.unbindAction;
}

export function sameTemplateReference(
  left: Pick<ServiceRoleTemplate, "id" | "version" | "contentDigest">,
  right: Pick<ServiceRoleTemplate, "id" | "version" | "contentDigest">
): boolean {
  return left.id === right.id && left.version === right.version && left.contentDigest === right.contentDigest;
}
