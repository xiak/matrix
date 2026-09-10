import ipaddr from "ipaddr.js";

// Closed MOCK vocabulary. Navigation labels and live IAM roles are not authorities.
// Resource granularity is an explicit per-action contract, not inferred from
// read/write/list categories or an operation's name.
export const policyServices = ["regions", "paas", "database", "logs", "devops", "monitoring", "iam"] as const;
export type PolicyService = typeof policyServices[number];
export type ActionLevel = "read" | "list" | "write" | "permissions";
export const policyConditionKeys = ["sourceIp", "resourceTag", "notBefore", "notAfter"] as const;
export type PolicyConditionKey = typeof policyConditionKeys[number];
const requestConditions = ["sourceIp", "notBefore", "notAfter"] as const;
// Explicit capability profiles, selected by each operation, not derived from
// its name, read/write classification, or a product's navigation entry.
const operationScope = { granularity: "operation", conditions: requestConditions } as const;
const resourceScope = { granularity: "resource", conditions: policyConditionKeys } as const;
export const policyActions = [
  { id: "regions:list", service: "regions", level: "list", resourceType: "account", ...operationScope },
  { id: "regions:read", service: "regions", level: "read", resourceType: "region", ...resourceScope },
  { id: "regions:readNode", service: "regions", level: "read", resourceType: "node", ...resourceScope },
  { id: "regions:maintainNode", service: "regions", level: "write", resourceType: "node", ...resourceScope },
  { id: "paas:list", service: "paas", level: "list", resourceType: "account", ...operationScope },
  { id: "paas:read", service: "paas", level: "read", resourceType: "application", ...resourceScope },
  { id: "paas:create", service: "paas", level: "write", resourceType: "account", ...operationScope },
  { id: "paas:deploy", service: "paas", level: "write", resourceType: "application", ...resourceScope },
  { id: "paas:delete", service: "paas", level: "write", resourceType: "application", ...resourceScope },
  { id: "database:list", service: "database", level: "list", resourceType: "account", ...operationScope },
  { id: "database:read", service: "database", level: "read", resourceType: "instance", ...resourceScope },
  { id: "database:create", service: "database", level: "write", resourceType: "account", ...operationScope },
  { id: "database:resize", service: "database", level: "write", resourceType: "instance", ...resourceScope },
  { id: "database:delete", service: "database", level: "write", resourceType: "instance", ...resourceScope },
  { id: "logs:list", service: "logs", level: "list", resourceType: "account", ...operationScope },
  { id: "logs:read", service: "logs", level: "read", resourceType: "topic", ...resourceScope },
  { id: "logs:search", service: "logs", level: "read", resourceType: "topic", ...resourceScope },
  { id: "logs:create", service: "logs", level: "write", resourceType: "account", ...operationScope },
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
  { id: "iam:createUser", service: "iam", level: "permissions", resourceType: "account", ...operationScope },
  { id: "iam:grantUser", service: "iam", level: "permissions", resourceType: "user", ...resourceScope },
  { id: "iam:assumeRole", service: "iam", level: "permissions", resourceType: "role", ...resourceScope },
  { id: "iam:readAudit", service: "iam", level: "read", resourceType: "auditEvent", ...resourceScope },
  { id: "iam:listAudit", service: "iam", level: "list", resourceType: "account", ...operationScope }
] as const satisfies readonly { id: string; service: PolicyService; level: ActionLevel; resourceType: string; granularity: "operation" | "resource"; conditions: readonly PolicyConditionKey[] }[];
export type PolicyAction = typeof policyActions[number];
export function policyConditionsForActions(actions: readonly PolicyAction[]): PolicyConditionKey[] {
  return policyConditionKeys.filter((key) => actions.length > 0 && actions.every((action) => (action.conditions as readonly PolicyConditionKey[]).includes(key)));
}
export function actionMatches(pattern: string, action: string): boolean {
  if (pattern === "*") return true;
  const [service, operation, extra] = pattern.split(":");
  const [targetService, targetOperation] = action.split(":");
  return extra === undefined && (service === "*" || service === targetService) && (operation === "*" || operation === targetOperation);
}
export function expandPolicyActions(patterns: readonly string[]): PolicyAction[] {
  return policyActions.filter((action) => patterns.some((pattern) => actionMatches(pattern, action.id)));
}
export function actionPatternValid(pattern: string): boolean {
  return pattern.length <= 128 && /^(?:\*|(?:[a-z]+|\*):(?:[a-zA-Z]+|\*))$/.test(pattern) && policyActions.some((action) => actionMatches(pattern, action.id));
}
export function policyResourceTypes(service: PolicyService): PolicyAction["resourceType"][] {
  return [...new Set(policyActions.filter((action) => action.service === service).map((action) => action.resourceType))];
}
export type PolicyResource = { service: PolicyService; tenant: string; region: string; type: string; id: string };
export function formatPolicyResource(value: PolicyResource): string {
  return ["matrix", value.service, value.tenant, value.region, value.type + "/" + value.id].join(":");
}
export function parsePolicyResource(value: string, pattern = true): PolicyResource | null {
  const match = /^matrix:([a-z]+):([A-Za-z0-9_-]{1,128}):([A-Za-z0-9_-]{1,64}|\*):([a-zA-Z]+)\/(.{1,128})$/.exec(value);
  if (!match) return null;
  const [, service, tenant, region, type, id] = match;
  if (!policyServices.includes(service as PolicyService) || !policyResourceTypes(service as PolicyService).some((entry) => entry === type)) return null;
  if (!/^(?:\*|[A-Za-z0-9][A-Za-z0-9._/-]*\*?)$/.test(id!) || id!.split("/").some((part) => !part || part === "." || part === "..")) return null;
  if (!pattern && (region === "*" || id!.includes("*"))) return null;
  if (type === "account" && (region !== "global" || id !== "account")) return null;
  return { service: service as PolicyService, tenant: tenant!, region: region!, type: type!, id: id! };
}
export function resourceMatches(pattern: string, resource: PolicyResource, tenant: string): boolean {
  if (resource.tenant !== tenant) return false;
  if (pattern === "*") return true;
  const scope = parsePolicyResource(pattern);
  if (!scope || scope.tenant !== tenant || scope.service !== resource.service || scope.type !== resource.type || (scope.region !== "*" && scope.region !== resource.region)) return false;
  return scope.id.endsWith("*") ? resource.id.startsWith(scope.id.slice(0, -1)) : scope.id === resource.id;
}
export function utcTimeValid(value: string): boolean {
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(value)) return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && [new Date(time).toISOString(), new Date(time).toISOString().replace(".000Z", "Z")].includes(value);
}
function parseIp(value: string) {
  if (value.length > 64 || /[%\s]/.test(value)) return null;
  // No shorthand/octal IPv4. Mapped IPv6 requests cannot evade an IPv4 deny.
  const dotted = value.includes(":") ? value.slice(value.lastIndexOf(":") + 1) : value;
  if (dotted.includes(".") && !/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(dotted)) return null;
  if (!value.includes(":") && !dotted.includes(".")) return null;
  try { return ipaddr.process(value); } catch { return null; }
}
export function sourceIpValid(value: string): boolean { return Boolean(parseIp(value)); }
function cidr(value: string): [ipaddr.IPv4 | ipaddr.IPv6, number] | null {
  const parts = value.split("/");
  if (parts.length !== 2 || !/^(0|[1-9]\d{0,2})$/.test(parts[1]!) || !parseIp(parts[0]!)) return null;
  try {
    let [address, bits] = ipaddr.parseCIDR(value);
    if (address instanceof ipaddr.IPv6 && address.isIPv4MappedAddress()) {
      if (bits < 96) return null;
      address = address.toIPv4Address(); bits -= 96;
    }
    return [address, bits];
  } catch { return null; }
}
export function sourceCidrValid(value: string): boolean { return Boolean(cidr(value)); }
export function sourceIpMatches(value: string, ranges: readonly string[]): boolean | null {
  const address = parseIp(value);
  if (!address) return null;
  let matched = false;
  for (const range of ranges) {
    const parsed = cidr(range);
    if (!parsed) return null;
    if (address.kind() === parsed[0].kind() && address.match(parsed)) matched = true;
  }
  return matched;
}
