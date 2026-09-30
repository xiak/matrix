import type { RoleStatus, RoleTag } from "./roles";
import type { PolicyVersionReference } from "./accounts";

export type ServiceRoleTemplateStatus = "ACTIVE" | "RETIRED";
export type ServiceRoleTemplatePurpose = "IAM" | "PAAS" | "AUDIT" | "INSTALLATION_VERIFIER";
export type WorkloadRoleBindingStatus = "ACTIVE" | "REVOKED";

export type ServiceRoleTemplateReference = {
  id: string;
  version: number;
  contentDigest: string;
};

export type ServiceRoleWorkload = {
  resourceKind: string;
  bindAction: string;
  unbindAction: string;
};

// Release-owned authority. An ACTIVE template remains only an input to a
// product-owned consent flow; it is not Account consent or a resource grant.
export type ServiceRoleTemplate = ServiceRoleTemplateReference & {
  spec: {
    product: string;
    servicePurpose: ServiceRoleTemplatePurpose;
    roleName: string;
    roleDescription: string;
    policyVersion: PolicyVersionReference;
    workloads: ServiceRoleWorkload[];
    maxSessionDurationSeconds: number;
  };
  status: ServiceRoleTemplateStatus;
};

export type ServiceRoleTemplateDirectory = { items: ServiceRoleTemplate[] };

// SERVICE_LINKED Roles are deliberately outside the customer-managed Role
// repository and cannot be edited through ordinary Role commands.
export type ServiceLinkedRoleMetadata = {
  id: string;
  accountId: string;
  name: string;
  description: string;
  tags: RoleTag[];
  management: "SERVICE_LINKED";
  status: RoleStatus;
  maxSessionDurationSeconds: number;
  resourceVersion: number;
  currentTrustVersionId: string;
  createdAt: string;
  updatedAt: string;
};

export type ServiceLinkedRoleRelation = {
  role: ServiceLinkedRoleMetadata;
  template: ServiceRoleTemplateReference;
  servicePrincipal: {
    installationId: string;
    principalId: string;
    purpose: ServiceRoleTemplatePurpose;
  };
  permissionCeiling: PolicyVersionReference;
};

export type WorkloadRoleBinding = {
  id: string;
  accountId: string;
  roleId: string;
  template: ServiceRoleTemplateReference;
  workload: { kind: string; id: string };
  status: WorkloadRoleBindingStatus;
  resourceVersion: number;
  createdAt: string;
  updatedAt: string;
  revokedAt: string | null;
};

export type ServiceLinkedRoleListing = {
  relation: ServiceLinkedRoleRelation;
  bindingCount: number;
  activeBindingCount: number;
};

export type ServiceLinkedRoleDirectory = {
  accountId: string;
  items: ServiceLinkedRoleListing[];
  nextAfter: string | null;
};

export type ServiceLinkedRoleAccess = {
  relation: ServiceLinkedRoleRelation;
  bindings: WorkloadRoleBinding[];
  nextAfter: string | null;
};
