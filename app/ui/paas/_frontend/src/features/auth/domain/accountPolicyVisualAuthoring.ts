import type { AccountPolicyDocument, AuthorizationProfileAction, AuthorizationProfileDirectory } from "./accounts";

export type VisualActionGroup = {
  product: string;
  resourceKind: string;
  actions: AuthorizationProfileAction[];
};

// The catalog describes current product declarations, not a grant or a frozen
// version. Keep authoring limited to exact TENANT actions; IAM remains the
// authority for publication and may reject a stale catalog.
export function visualActionGroups(directory: AuthorizationProfileDirectory): VisualActionGroup[] {
  const groups = new Map<string, VisualActionGroup>();
  for (const entry of directory.items) for (const action of entry.profile.actions) {
    if (action.scope !== "TENANT") continue;
    const key = `${entry.profile.product}\0${action.resourceKind}`;
    const group = groups.get(key) ?? { product: entry.profile.product, resourceKind: action.resourceKind, actions: [] };
    group.actions.push(action);
    groups.set(key, group);
  }
  return [...groups.values()].map((group) => ({ ...group, actions: group.actions.sort((a, b) => a.action.localeCompare(b.action)) }))
    .sort((a, b) => a.product.localeCompare(b.product) || a.resourceKind.localeCompare(b.resourceKind));
}

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function keysAre(value: Record<string, unknown>, required: string[], optional: string[] = []): boolean {
  return required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
}

export type VisualDraftResult =
  | { status: "ready"; document: AccountPolicyDocument }
  | { status: "jsonInvalid" | "shapeInvalid" | "catalogMismatch" };

const policyId = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

// This is only a quick authoring check for fields the form can create. IAM's
// publication validator remains authoritative for the complete policy grammar.
export function visualDraftHasIncompleteFields(document: AccountPolicyDocument): boolean {
  if (!document.statements.length) return true;
  const sids = new Set<string>();
  for (const statement of document.statements) {
    if (!policyId.test(statement.sid) || sids.has(statement.sid)) return true;
    sids.add(statement.sid);
    const resources = new Set<string>();
    for (const resource of statement.resources) {
      if (resource.match !== "ANY_IN_AUTHORITY" && !policyId.test(resource.id ?? "")) return true;
      const identity = `${resource.kind}\0${resource.match}\0${resource.id ?? ""}`;
      if (resources.has(identity)) return true;
      resources.add(identity);
    }
    const conditions = new Set<string>();
    for (const condition of statement.conditions ?? []) {
      const identity = `${condition.key}\0${condition.operator}`;
      if (conditions.has(identity)) return true;
      conditions.add(identity);
      if (condition.key === "iam.current-time") {
        if (condition.values.length !== 1 || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.[0-9]{0,5}[1-9])?Z$/.test(condition.values[0] ?? "") ||
            Number.isNaN(Date.parse(condition.values[0]!))) return true;
      } else if (condition.values.length < 1 || condition.values.length > 16 ||
        condition.values.some((value) => !policyId.test(value)) || new Set(condition.values).size !== condition.values.length) return true;
    }
  }
  return false;
}

// A JSON-to-visual switch must be lossless. Never drop an unknown property,
// action family, selector or condition merely because a form cannot show it.
export function visualDraftFromJSON(text: string, directory: AuthorizationProfileDirectory, allowEmpty = false): VisualDraftResult {
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { return { status: "jsonInvalid" }; }
  if (!record(parsed) || !keysAre(parsed, ["languageVersion", "scope", "statements"]) ||
      parsed.languageVersion !== "1" || parsed.scope !== "TENANT" || !Array.isArray(parsed.statements) ||
      (!allowEmpty && !parsed.statements.length) || parsed.statements.length > 64) {
    return { status: "shapeInvalid" };
  }
  const groups = visualActionGroups(directory);
  for (const statement of parsed.statements) {
    if (!record(statement) || !keysAre(statement, ["sid", "effect", "actions", "resources"], ["conditions"]) ||
        typeof statement.sid !== "string" || !["ALLOW", "DENY"].includes(String(statement.effect)) ||
        !Array.isArray(statement.actions) || !statement.actions.length || !statement.actions.every((action) => typeof action === "string") ||
        !Array.isArray(statement.resources) || !statement.resources.length || statement.resources.length > 64) return { status: "shapeInvalid" };
    if (statement.actions.length !== 1) return { status: "catalogMismatch" };
    const actionNames = statement.actions as string[];
    const group = groups.find((candidate) => candidate.actions.some((action) => action.action === actionNames[0]));
    if (!group) return { status: "catalogMismatch" };
    const selected = group.actions.filter((action) => actionNames.includes(action.action));
    if (statement.resources.some((resource: unknown) => !record(resource) ||
        !keysAre(resource, ["kind", "match"], ["id"]) || resource.kind !== group.resourceKind ||
        !["EXACT", "PREFIX_IN_AUTHORITY", "ANY_IN_AUTHORITY"].includes(String(resource.match)) ||
        (resource.match === "ANY_IN_AUTHORITY" ? Object.hasOwn(resource, "id") : typeof resource.id !== "string" || !resource.id.trim()) ||
        (resource.match === "EXACT" && selected.every((action) => action.resourceShapes.every((shape) => shape.mode === "COLLECTION")) && resource.id !== "collection") ||
        (resource.match === "PREFIX_IN_AUTHORITY" && selected.some((action) => !action.resourceShapes.some((shape) => shape.mode === "INSTANCE" && shape.prefixAllowed))))) {
      return { status: "catalogMismatch" };
    }
    if (statement.conditions !== undefined && (!Array.isArray(statement.conditions) || !statement.conditions.length || statement.conditions.length > 16 ||
        statement.conditions.some((condition: unknown) => !record(condition) ||
          !keysAre(condition, ["key", "operator", "values"]) ||
          !["iam.account-id", "iam.principal-id", "iam.current-time"].includes(String(condition.key)) ||
          !Array.isArray(condition.values) || !condition.values.length || !condition.values.every((value) => typeof value === "string" && Boolean(value.trim())) ||
          !(condition.key === "iam.current-time"
            ? ["DATE_GREATER_THAN_EQUALS", "DATE_LESS_THAN"].includes(String(condition.operator))
            : ["STRING_EQUALS", "STRING_NOT_EQUALS"].includes(String(condition.operator))) ||
          selected.some((action) => !(action.conditions ?? []).some((supported) => supported.key === condition.key))))) {
      return { status: "catalogMismatch" };
    }
  }
  return { status: "ready", document: parsed as AccountPolicyDocument };
}
