import type {
  ServiceLinkedRoleRelation,
  ServiceRoleTemplate,
  ServiceRoleTemplateReference,
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

export type BindManagedServiceRoleCommand = {
  template: ServiceRoleTemplateReference;
  requestId: string;
};

export type UnbindManagedServiceRoleCommand = {
  bindingId: string;
  resourceVersion: number;
  expectedTemplate: ServiceRoleTemplateReference;
  requestId: string;
};

export type ManagedServiceRoleBindingReceipt = {
  kind: "ServiceRoleBindingReceipt";
  serviceInstallationId: string;
  bindingId: string;
  roleId: string;
  template: ServiceRoleTemplateReference;
  status: "ACTIVE";
  resourceVersion: 1;
  createdAt: string;
};

export type ManagedServiceRoleUnbindingReceipt = {
  kind: "ServiceRoleUnbindingReceipt";
  serviceInstallationId: string;
  bindingId: string;
  roleId: string;
  template: ServiceRoleTemplateReference;
  status: "REVOKED";
  resourceVersion: 2;
  createdAt: string;
  revokedAt: string;
};

export type ManagedServiceAuthorizationMutationError =
  | "expired"
  | "forbidden"
  | "notFound"
  | "conflict"
  | "invalid"
  | "unknown";

export type ManagedServiceAuthorizationIntent = {
  accountId: string;
  installationId: string;
  kind: "bind" | "unbind";
  template: ServiceRoleTemplate;
  relation: ServiceLinkedRoleRelation | null;
  binding: WorkloadRoleBinding | null;
  requestId: string;
  phase: "review" | "submitting" | "failed";
  error: ManagedServiceAuthorizationMutationError | null;
  open: boolean;
};

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
