// Closed capability vocabulary for the isolated access-management preview.
// This is not an IAM response, a grant, or a tenant-editable product profile.
// A live adapter must wait for IAM's fixed catalog query contract.
export const policyServices = ["regions", "paas", "database", "logs", "devops", "monitoring", "iam"] as const;
export type PolicyService = typeof policyServices[number];
export type ActionLevel = "read" | "list" | "write" | "permissions";
export const policyConditionKeys = ["sourceIp", "resourceTag", "notBefore", "notAfter"] as const;
export type PolicyConditionKey = typeof policyConditionKeys[number];

const requestConditions = ["sourceIp", "notBefore", "notAfter"] as const;
const operationScope = { granularity: "operation", conditions: requestConditions } as const;
const resourceScope = { granularity: "resource", conditions: policyConditionKeys } as const;

export const policyActions = [
  { id: "regions:list", service: "regions", level: "list", resourceType: "account", ...operationScope },
  { id: "regions:read", service: "regions", level: "read", resourceType: "region", ...resourceScope },
  { id: "regions:readNode", service: "regions", level: "read", resourceType: "node", ...resourceScope },
  { id: "regions:maintainNode", service: "regions", level: "write", resourceType: "node", ...resourceScope },
  { id: "paas:list", service: "paas", level: "list", resourceType: "account", ...operationScope },
  { id: "paas:read", service: "paas", level: "read", resourceType: "application", ...resourceScope },
  { id: "paas:create", service: "paas", level: "write", resourceType: "account", resultResourceType: "application", ...operationScope },
  { id: "paas:deploy", service: "paas", level: "write", resourceType: "application", ...resourceScope },
  { id: "paas:delete", service: "paas", level: "write", resourceType: "application", ...resourceScope },
  { id: "database:list", service: "database", level: "list", resourceType: "account", ...operationScope },
  { id: "database:read", service: "database", level: "read", resourceType: "instance", ...resourceScope },
  { id: "database:create", service: "database", level: "write", resourceType: "account", resultResourceType: "instance", ...operationScope },
  { id: "database:resize", service: "database", level: "write", resourceType: "instance", ...resourceScope },
  { id: "database:delete", service: "database", level: "write", resourceType: "instance", ...resourceScope },
  { id: "logs:list", service: "logs", level: "list", resourceType: "account", ...operationScope },
  { id: "logs:read", service: "logs", level: "read", resourceType: "topic", ...resourceScope },
  { id: "logs:search", service: "logs", level: "read", resourceType: "topic", ...resourceScope },
  { id: "logs:create", service: "logs", level: "write", resourceType: "account", resultResourceType: "topic", ...operationScope },
  { id: "logs:delete", service: "logs", level: "write", resourceType: "topic", ...resourceScope },
  { id: "devops:list", service: "devops", level: "list", resourceType: "account", ...operationScope },
  { id: "devops:read", service: "devops", level: "read", resourceType: "pipeline", ...resourceScope },
  { id: "devops:run", service: "devops", level: "write", resourceType: "pipeline", ...resourceScope },
  { id: "devops:edit", service: "devops", level: "write", resourceType: "pipeline", ...resourceScope },
  { id: "monitoring:list", service: "monitoring", level: "list", resourceType: "account", ...operationScope },
  { id: "monitoring:read", service: "monitoring", level: "read", resourceType: "monitor", ...resourceScope },
  { id: "monitoring:configure", service: "monitoring", level: "write", resourceType: "monitor", ...resourceScope },
  { id: "iam:list", service: "iam", level: "list", resourceType: "account", ...operationScope },
  { id: "iam:read", service: "iam", level: "read", resourceType: "user", ...resourceScope },
  { id: "iam:createUser", service: "iam", level: "permissions", resourceType: "account", resultResourceType: "user", ...operationScope },
  { id: "iam:grantUser", service: "iam", level: "permissions", resourceType: "user", ...resourceScope },
  { id: "iam:assumeRole", service: "iam", level: "permissions", resourceType: "role", ...resourceScope },
  { id: "iam:readAudit", service: "iam", level: "read", resourceType: "auditEvent", ...resourceScope },
  { id: "iam:listAudit", service: "iam", level: "list", resourceType: "account", ...operationScope }
] as const satisfies readonly { id: string; service: PolicyService; level: ActionLevel; resourceType: string; resultResourceType?: string; granularity: "operation" | "resource"; conditions: readonly PolicyConditionKey[] }[];

export type PolicyAction = typeof policyActions[number] & { resultResourceType?: string };

export function policyConditionsForActions(actions: readonly PolicyAction[]): PolicyConditionKey[] {
  return policyConditionKeys.filter((key) => actions.length > 0 && actions.every((action) => (action.conditions as readonly PolicyConditionKey[]).includes(key)));
}

export function policyResourceTypes(service: PolicyService): PolicyAction["resourceType"][] {
  return [...new Set(policyActions.filter((action) => action.service === service).map((action) => action.resourceType))];
}
