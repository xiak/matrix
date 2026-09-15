import ipaddr from "ipaddr.js";
import { policyActions, policyResourceTypes, policyServices, type PolicyAction, type PolicyService } from "./previewAuthorizationCatalog";

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
