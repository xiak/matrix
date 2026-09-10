import { actionPatternValid, expandPolicyActions, parsePolicyResource, policyConditionKeys, policyConditionsForActions, policyServices, sourceCidrValid, utcTimeValid, type PolicyAction, type PolicyService } from "./policyLanguage";
import { AccessWorkspaceError } from "./accessWorkspaceError";

export type PolicyCondition = { resourceTag?: { key: string; value: string }[]; sourceIp?: string[]; notBefore?: string; notAfter?: string };
export type PolicyDocument = {
  version: "1";
  statement: { effect: "allow" | "deny"; action: string[]; resource: string[]; condition?: PolicyCondition }[];
};
export type PolicyDiagnostic =
  | { severity: "error"; code: AccessWorkspaceError["code"]; path: string }
  | { severity: "warning"; code: "permissionManagement" | "unrestrictedWrite" | "wildcardAction"; path: string }
  | { severity: "suggestion"; code: "duplicateStatement"; path: string };

// Compare structure, not effective permissions. Wildcards must not be expanded:
// their meaning can grow when a new action is registered.
export function policyStatementKey(statement: PolicyDocument["statement"][number]): string {
  const condition = statement.condition;
  return JSON.stringify({ effect: statement.effect, action: [...new Set(statement.action)].sort(), resource: [...new Set(statement.resource)].sort(),
    ...(condition ? { condition: {
      ...(condition.resourceTag ? { resourceTag: [...condition.resourceTag].sort((a, b) => a.key.localeCompare(b.key)).map(({ key, value }) => ({ key, value })) } : {}),
      ...(condition.sourceIp ? { sourceIp: [...new Set(condition.sourceIp)].sort() } : {}),
      ...(condition.notBefore ? { notBefore: condition.notBefore } : {}),
      ...(condition.notAfter ? { notAfter: condition.notAfter } : {})
    } } : {}) });
}

/** The executable parser is the only validation owner. Analyze valid documents
 * once; only a failed document needs bounded per-statement diagnostic passes. */
export function analyzePolicyDocument(text: string, accountId?: string): { document: PolicyDocument | null; diagnostics: PolicyDiagnostic[] } {
  let document: PolicyDocument;
  try { document = parsePolicyDocument(text, accountId); }
  catch (error) {
    const code = error instanceof AccessWorkspaceError ? error.code : "invalid";
    const root = { document: null, diagnostics: [{ severity: "error" as const, code, path: "$" }] };
    if (text.length > 65536) return root;
    let raw: PolicyDocument;
    try {
      raw = JSON.parse(text);
      if (!raw || !Array.isArray(raw.statement) || !raw.statement.length || raw.statement.length > 50) return root;
      // Establish that the envelope is valid using the very same parser.
      parsePolicyDocument(JSON.stringify({ ...raw, statement: [{ effect: "allow", action: ["logs:search"], resource: ["*"] }] }), accountId);
    } catch { return root; }
    const diagnostics: PolicyDiagnostic[] = [];
    raw.statement.forEach((statement, index) => {
      try { parsePolicyDocument(JSON.stringify({ ...raw, statement: [statement] }), accountId); }
      catch (failure) { diagnostics.push({ severity: "error", code: failure instanceof AccessWorkspaceError ? failure.code : "invalid", path: `$.statement[${index}]` }); }
    });
    return diagnostics.length ? { document: null, diagnostics } : root;
  }
  const diagnostics: PolicyDiagnostic[] = [];
  const seen = new Set<string>();
  document.statement.forEach((statement, index) => {
    const path = `$.statement[${index}]`;
    if (statement.effect === "allow") {
      const actions = expandPolicyActions(statement.action);
      if (actions.some((action) => action.level === "permissions")) diagnostics.push({ severity: "warning", code: "permissionManagement", path: path + ".action" });
      if (statement.action.some((action) => action.includes("*"))) diagnostics.push({ severity: "warning", code: "wildcardAction", path: path + ".action" });
      if (statement.resource.includes("*") && !statement.condition?.resourceTag && actions.some((action) => action.level === "write" || action.level === "permissions")) diagnostics.push({ severity: "warning", code: "unrestrictedWrite", path: path + ".resource" });
    }
    const key = policyStatementKey(statement);
    if (seen.has(key)) diagnostics.push({ severity: "suggestion", code: "duplicateStatement", path });
    seen.add(key);
  });
  return { document, diagnostics };
}
// Review signal only; effective access still requires request evaluation.
export function includesPermissionManagement(document: PolicyDocument): boolean {
  return document.statement.some((statement) => statement.effect === "allow" &&
    expandPolicyActions(statement.action).some((action) => action.level === "permissions"));
}
export function parsePolicyDocument(text: string, accountId?: string): PolicyDocument {
  if (text.length > 65536) throw new AccessWorkspaceError("invalid");
  let value: unknown;
  try { value = JSON.parse(text); } catch { throw new AccessWorkspaceError("invalid"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new AccessWorkspaceError("invalid");
  if (Object.keys(value).some((key) => !["version", "statement"].includes(key))) throw new AccessWorkspaceError("unsupportedPolicy");
  const document = value as PolicyDocument;
  if (document.version !== "1" || !Array.isArray(document.statement) || !document.statement.length || document.statement.length > 50) throw new AccessWorkspaceError("invalid");
  for (const statement of document.statement) {
    if (!statement || typeof statement !== "object" || Array.isArray(statement)) throw new AccessWorkspaceError("invalid");
    // Do not strip a condition/principal/unknown field and accidentally widen
    // its meaning. Unsupported drafts must stay editable and cannot be saved.
    if (Object.keys(statement).some((key) => !["effect", "action", "resource", "condition"].includes(key))) throw new AccessWorkspaceError("unsupportedPolicy");
    if (!["allow", "deny"].includes(statement.effect) ||
      !Array.isArray(statement.action) || !statement.action.length || !Array.isArray(statement.resource) || !statement.resource.length ||
      statement.action.length > 100 || statement.resource.length > 50 ||
      [...statement.action, ...statement.resource].some((item) => typeof item !== "string" || !item.trim() || item.length > 512)) throw new AccessWorkspaceError("invalid");
    if (statement.action.some((action) => !actionPatternValid(action))) throw new AccessWorkspaceError("unknownAction");
    const actions = expandPolicyActions(statement.action);
    const specific = statement.resource.filter((resource) => resource !== "*");
    if (statement.resource.includes("*") && specific.length) throw new AccessWorkspaceError("invalidResource");
    if (specific.length) {
      if (actions.some((action) => action.granularity === "operation")) throw new AccessWorkspaceError("invalidResource");
      const resources = specific.map((resource) => parsePolicyResource(resource));
      if (resources.some((resource) => !resource)) throw new AccessWorkspaceError("invalidResource");
      if (accountId && resources.some((resource) => resource!.tenant !== accountId)) throw new AccessWorkspaceError("tenantResource");
      if (resources.some((resource) => !actions.some((action) => action.service === resource!.service && action.resourceType === resource!.type)) ||
        actions.some((action) => !resources.some((resource) => resource!.service === action.service && resource!.type === action.resourceType))) throw new AccessWorkspaceError("invalidResource");
    }
    if (statement.condition !== undefined) {
      const condition = statement.condition;
      if (!condition || typeof condition !== "object" || Array.isArray(condition) || !Object.keys(condition).length) throw new AccessWorkspaceError("invalidCondition");
      if (Object.keys(condition).some((key) => !(policyConditionKeys as readonly string[]).includes(key))) throw new AccessWorkspaceError("unsupportedPolicy");
      const supported = policyConditionsForActions(actions);
      if (Object.keys(condition).some((key) => !(supported as readonly string[]).includes(key))) throw new AccessWorkspaceError("invalidCondition");
      if (condition.resourceTag !== undefined && (
        !Array.isArray(condition.resourceTag) || !condition.resourceTag.length || condition.resourceTag.length > 10 ||
        condition.resourceTag.some((tag) => !tag || typeof tag !== "object" || Array.isArray(tag) || Object.keys(tag).some((key) => !["key", "value"].includes(key)) ||
          typeof tag.key !== "string" || !tag.key.trim() || tag.key.length > 64 || typeof tag.value !== "string" || tag.value.length > 128 || /[<>\u0000-\u001f]/.test(tag.key + tag.value)) ||
        new Set(condition.resourceTag.map((tag) => tag.key)).size !== condition.resourceTag.length)) throw new AccessWorkspaceError("invalidCondition");
      if (condition.sourceIp !== undefined && (!Array.isArray(condition.sourceIp) || !condition.sourceIp.length || condition.sourceIp.length > 10 ||
        condition.sourceIp.some((range) => typeof range !== "string" || !sourceCidrValid(range)))) throw new AccessWorkspaceError("invalidCondition");
      for (const key of ["notBefore", "notAfter"] as const) if (condition[key] !== undefined && (typeof condition[key] !== "string" || !utcTimeValid(condition[key]))) throw new AccessWorkspaceError("invalidCondition");
      if (condition.notBefore && condition.notAfter && Date.parse(condition.notBefore) > Date.parse(condition.notAfter)) throw new AccessWorkspaceError("invalidCondition");
    }
  }
  return { version: "1", statement: document.statement.map((s) => ({ effect: s.effect, action: [...s.action], resource: [...s.resource], ...(s.condition ? { condition: structuredClone(s.condition) } : {}) })) };
}

export type PolicyServiceRule = {
  statement: number;
  actions: readonly PolicyAction[];
  patterns: readonly string[];
  resources: readonly string[];
  condition?: PolicyCondition;
};
export type PolicyServiceSummary = {
  key: string;
  service: PolicyService;
  effect: "allow" | "deny";
  actions: readonly PolicyAction[];
  rules: readonly PolicyServiceRule[];
};

/** A display projection, never an effective-access result or a persisted grant.
 * Preserve each statement's resources and conditions together. In particular,
 * do not union conditional branches into a broader resource/condition pair. */
export function summarizePolicyServices(document: PolicyDocument): PolicyServiceSummary[] {
  const groups = new Map<string, { service: PolicyService; effect: "allow" | "deny"; rules: PolicyServiceRule[] }>();
  document.statement.forEach((statement, index) => {
    const actions = expandPolicyActions(statement.action);
    for (const service of new Set(actions.map((action) => action.service))) {
      const selected = actions.filter((action) => action.service === service);
      const key = statement.effect + ":" + service;
      const group = groups.get(key) ?? { service, effect: statement.effect, rules: [] };
      group.rules.push({
        statement: index + 1, actions: selected, patterns: statement.action,
        resources: resourcesForPolicyActions(statement.resource, selected),
        ...(statement.condition ? { condition: statement.condition } : {})
      });
      groups.set(key, group);
    }
  });
  return (["allow", "deny"] as const).flatMap((effect) => policyServices.flatMap((service) => {
    const key = effect + ":" + service, group = groups.get(key);
    if (!group) return [];
    return [{ key, ...group, actions: [...new Map(group.rules.flatMap((rule) => rule.actions.map((action) => [action.id, action] as const))).values()] }];
  }));
}

export function resourcesForPolicyActions(resources: readonly string[], actions: readonly PolicyAction[]): string[] {
  return resources.filter((value) => {
    if (value === "*") return true;
    const resource = parsePolicyResource(value);
    return resource && actions.some((action) => action.service === resource.service && action.resourceType === resource.type);
  });
}
