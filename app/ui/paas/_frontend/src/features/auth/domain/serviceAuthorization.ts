import type { RoleStatus, RoleTag } from "./roles";
import {
  admittedAuthorizationSubjects,
  admittedAuthorizationUserAuthenticationMethods,
  type AuthorizationProfileAction,
  type AuthorizationProfileEntry,
  type PolicyVersionReference
} from "./accounts";

export type ServiceRoleTemplateStatus = "ACTIVE" | "RETIRED";
export type ServiceRoleTemplatePurpose = "IAM" | "PAAS" | "AUDIT" | "INSTALLATION_VERIFIER";
export type WorkloadRoleBindingStatus = "ACTIVE" | "REVOKED";

export type ServiceRoleTemplateReference = {
  id: string;
  version: number;
  contentDigest: string;
};

export type ServicePrincipalReference = {
  installationId: string;
  principalId: string;
  purpose: ServiceRoleTemplatePurpose;
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

export type ServiceTemplateProfileCheck = {
  id: "product" | "servicePurpose" | "bindAction" | "unbindAction";
  passed: boolean;
  action?: string;
  resourceKind?: string;
};

export type ServiceTemplateProfileReview = {
  compatible: boolean;
  checks: ServiceTemplateProfileCheck[];
};

function declaresExactUserInstanceAction(action: AuthorizationProfileAction | undefined, workload: ServiceRoleWorkload): boolean {
  if (!action || action.resourceKind !== workload.resourceKind || action.scope !== "TENANT") return false;
  const subjects = admittedAuthorizationSubjects(action);
  const credentials = admittedAuthorizationUserAuthenticationMethods(action);
  return subjects.length === 1 && subjects[0] === "USER" &&
    credentials.length === 1 && credentials[0] === "LOGIN_SESSION" &&
    action.resourceShapes.some((shape) => shape.mode === "INSTANCE" && !shape.prefixAllowed);
}

// This is release compatibility only. It validates that an immutable template
// points at Actions the exact Profile snapshot actually declares; it does not
// create an Account relation, workload binding, RoleSession, or permission.
export function reviewServiceTemplateProfile(
  template: ServiceRoleTemplate,
  entry: AuthorizationProfileEntry
): ServiceTemplateProfileReview {
  const actions = new Map(entry.profile.actions.map((action) => [action.action, action]));
  const checks: ServiceTemplateProfileCheck[] = [
    { id: "product", passed: template.spec.product === entry.profile.product },
    { id: "servicePurpose", passed: template.spec.servicePurpose === entry.profile.callingService }
  ];
  for (const workload of template.spec.workloads) {
    checks.push({
      id: "bindAction",
      action: workload.bindAction,
      resourceKind: workload.resourceKind,
      passed: declaresExactUserInstanceAction(actions.get(workload.bindAction), workload)
    }, {
      id: "unbindAction",
      action: workload.unbindAction,
      resourceKind: workload.resourceKind,
      passed: declaresExactUserInstanceAction(actions.get(workload.unbindAction), workload)
    });
  }
  return { compatible: checks.every((check) => check.passed), checks };
}

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
  servicePrincipal: ServicePrincipalReference;
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
