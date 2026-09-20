import { applyAccessWorkspaceCommand, type AccessWorkspace } from "../domain/accessWorkspace";
import { AccessWorkspaceError } from "../domain/accessWorkspaceError";
import { type PolicyDocument } from "../domain/policyDocument";
import { formatPolicyResource } from "../domain/policyLanguage";
import { policyActions, policyServices, type PolicyService } from "../domain/previewAuthorizationCatalog";
import type { AccountRepository } from "./iamRepository";

const at = "2026-09-08T09:00:00Z";
const document = (action: string[]): PolicyDocument => ({ version: "1", statement: [{ effect: "allow", action, resource: ["*"] }] });

export function initialAccessWorkspace(accountId: string): AccessWorkspace {
  const reviewerResource = formatPolicyResource({ service: "iam", tenant: accountId, region: "global", type: "role", id: "role-log-reviewer" });
  const taggedLogs = (productionOnly: boolean): PolicyDocument => ({ version: "1", statement: [{ effect: "allow", action: ["logs:search"], resource: ["*"], condition: { resourceTag: [{ key: "team", value: "delivery" }, ...(productionOnly ? [{ key: "environment", value: "production" }] : [])] } }] });
  const examples: { service: PolicyService; type: string; id: string; environment: string }[] = [
    { service: "regions", type: "region", id: "region-a", environment: "production" },
    { service: "regions", type: "node", id: "node-01", environment: "production" },
    { service: "paas", type: "application", id: "checkout-api", environment: "production" },
    { service: "paas", type: "application", id: "storefront-staging", environment: "staging" },
    { service: "database", type: "instance", id: "orders-postgres", environment: "production" },
    { service: "logs", type: "topic", id: "production/payment", environment: "production" },
    { service: "logs", type: "topic", id: "staging/storefront", environment: "staging" },
    { service: "logs", type: "topic", id: "archive/payment", environment: "production" },
    { service: "devops", type: "pipeline", id: "storefront-release", environment: "production" },
    { service: "monitoring", type: "monitor", id: "payment-health", environment: "production" },
    { service: "iam", type: "user", id: "principal-lin", environment: "production" },
    { service: "iam", type: "role", id: "role-pipeline", environment: "production" },
    { service: "iam", type: "role", id: "role-log-reviewer", environment: "production" },
    { service: "iam", type: "auditEvent", id: "event-01", environment: "production" }
  ];
  return {
    mode: "preview", accountId,
    testResources: [
      ...policyServices.map((service) => ({ id: service + "-account", reference: formatPolicyResource({ service, tenant: accountId, region: "global", type: "account", id: "account" }), tags: {} })),
      ...examples.map((entry) => ({ id: entry.service + "-" + entry.id, reference: formatPolicyResource({ ...entry, tenant: accountId, region: entry.service === "iam" ? "global" : "cn-shanghai-a" }), tags: { environment: entry.environment, team: "delivery" } }))
    ],
    testRequests: [
      { id: "path", request: { principalId: "principal-lin", action: "logs:search", resourceId: "logs-production/payment" } },
      { id: "duplicate", request: { principalId: "principal-qiao", action: "logs:search", resourceId: "logs-production/payment" } },
      { id: "tags", request: { principalId: "principal-qiao", action: "logs:search", resourceId: "logs-archive/payment" } },
      { id: "deny", request: { principalId: "principal-qiao", action: "paas:deploy", resourceId: "paas-checkout-api" } },
      { id: "boundary", request: { principalId: "principal-qiao", action: "paas:delete", resourceId: "paas-storefront-staging" } },
      { id: "ungranted", request: { principalId: "principal-wu", action: "logs:search", resourceId: "logs-production/payment" } }
    ],
    enterprises: [],
    userProfiles: {
      "principal-lin": { consoleAccess: true, programmaticAccess: true, passwordResetRequired: false, loginProtection: false, tags: [] },
      "principal-chen": { consoleAccess: true, programmaticAccess: false, passwordResetRequired: false, loginProtection: false, tags: [] },
      "principal-qiao": { consoleAccess: true, programmaticAccess: true, passwordResetRequired: false, loginProtection: false, tags: [{ key: "team", value: "delivery" }] },
      "principal-wu": { consoleAccess: true, programmaticAccess: false, passwordResetRequired: false, loginProtection: false, tags: [] }
    },
    userBoundaries: { "principal-qiao": "policy-delivery-boundary" }, roleSessions: [], pendingKeyCreation: null, pendingAccountRuleChange: null,
    enterpriseMembers: [{ id: "dev01", name: "Dev Member", department: "Delivery" }, { id: "ops01", name: "Ops Member", department: "Operations" }, { id: "audit01", name: "Audit Member", department: "Security" }],
    groups: [
      { id: "group-delivery", name: "DeliveryTeam", description: "Application delivery team", memberIds: ["principal-lin"], policyIds: ["policy-delivery"], createdAt: at },
      { id: "group-auditors", name: "SecurityAuditors", description: "Read-only security review", memberIds: ["principal-chen"], policyIds: ["policy-audit"], createdAt: at },
      { id: "group-operators", name: "ReleaseOperators", description: "Delivery grants and production log access; user boundaries still apply", memberIds: ["principal-qiao"], policyIds: ["policy-delivery", "policy-tag-logs"], createdAt: at }
    ],
    policies: [
      { id: "policy-admin", name: "MatrixAdministratorAccess", description: "Full administration of the current account", tags: [], kind: "system", systemCategory: "global", createdAt: at, updatedAt: at, defaultVersion: 1, lastVersion: 1, versions: [{ id: 1, document: document(["*"]), createdAt: at }] },
      { id: "policy-read", name: "MatrixReadOnlyAccess", description: "Read cloud resources without changes", tags: [], kind: "system", systemCategory: "global", createdAt: at, updatedAt: at, defaultVersion: 1, lastVersion: 1, versions: [{ id: 1, document: document(policyActions.filter((action) => action.level === "read" || action.level === "list").map((action) => action.id)), createdAt: at }] },
      { id: "policy-delivery", name: "MatrixDeliveryAccess", description: "Deploy applications and run pipelines", tags: [], kind: "system", systemCategory: "product", createdAt: at, updatedAt: at, defaultVersion: 1, lastVersion: 1, versions: [{ id: 1, document: document(["paas:*", "devops:*"]), createdAt: at }] },
      { id: "policy-audit", name: "MatrixAuditReadOnly", description: "Read audit events and security reports", tags: [], kind: "system", systemCategory: "product", createdAt: at, updatedAt: at, defaultVersion: 1, lastVersion: 1, versions: [{ id: 1, document: document(["iam:readAudit", "iam:listAudit"]), createdAt: at }] },
      { id: "policy-prod-logs", name: "ProductionLogReader", description: "Read log topics whose resource ID starts with production/; not tag-based", tags: [], kind: "custom", createdAt: at, updatedAt: at, defaultVersion: 1, lastVersion: 1, versions: [{ id: 1, document: { version: "1", statement: [{ effect: "allow", action: ["logs:search"], resource: [formatPolicyResource({ service: "logs", tenant: accountId, region: "*", type: "topic", id: "production/*" })] }] }, createdAt: at }] },
      { id: "policy-tag-logs", name: "ProductionLogsByTag", description: "Read topics tagged team=delivery AND environment=production, regardless of resource name", tags: [{ key: "purpose", value: "access-review" }], kind: "custom", createdAt: at, updatedAt: "2026-09-09T09:00:00Z", defaultVersion: 2, lastVersion: 2, versions: [{ id: 1, document: taggedLogs(false), createdAt: at }, { id: 2, document: taggedLogs(true), createdAt: "2026-09-09T09:00:00Z" }] },
      { id: "policy-production-guard", name: "ProtectProductionDeployments", description: "Deny deploying applications tagged environment=production; other actions are not denied by this rule", tags: [], kind: "custom", createdAt: at, updatedAt: at, defaultVersion: 1, lastVersion: 1, versions: [{ id: 1, document: { version: "1", statement: [{ effect: "deny", action: ["paas:deploy"], resource: ["*"], condition: { resourceTag: [{ key: "environment", value: "production" }] } }] }, createdAt: at }] },
      { id: "policy-delivery-boundary", name: "ReleaseOperatorBoundary", description: "Maximum scope: staging deployments, log search and the specific log-review role. This policy does not grant access by itself", tags: [], kind: "custom", createdAt: at, updatedAt: at, defaultVersion: 1, lastVersion: 1, versions: [{ id: 1, document: { version: "1", statement: [{ effect: "allow", action: ["paas:deploy"], resource: ["*"], condition: { resourceTag: [{ key: "environment", value: "staging" }] } }, { effect: "allow", action: ["logs:search"], resource: ["*"] }, { effect: "allow", action: ["iam:assumeRole"], resource: [reviewerResource] }] }, createdAt: at }] },
      { id: "policy-assume-reviewer", name: "AssumeLogReviewRole", description: "Allow requesting only ProductionLogReviewRole; the role must independently trust the caller", tags: [], kind: "custom", createdAt: at, updatedAt: at, defaultVersion: 1, lastVersion: 1, versions: [{ id: 1, document: { version: "1", statement: [{ effect: "allow", action: ["iam:assumeRole"], resource: [reviewerResource] }] }, createdAt: at }] }
    ],
    roles: [
      { id: "role-pipeline", name: "PipelineDeploymentRole", description: "Workload identity for application delivery", principalType: "service", principal: "devops.matrix.internal", trustedUserIds: [], tags: [], policyIds: ["policy-delivery"], sessionMinutes: 60, consoleAccess: false, createdAt: at },
      { id: "role-audit", name: "FederatedAuditRole", description: "Read-only role for enterprise SSO", principalType: "provider", principal: "idp-example", trustedUserIds: [], tags: [], policyIds: ["policy-audit"], sessionMinutes: 60, consoleAccess: true, createdAt: at },
      { id: "role-log-reviewer", name: "ProductionLogReviewRole", description: "Qiao can review production logs in a role session without inheriting personal deployment grants", principalType: "account", principal: accountId, trustedUserIds: ["principal-qiao"], tags: [], policyIds: ["policy-tag-logs"], sessionMinutes: 30, consoleAccess: true, createdAt: at }
    ],
    providers: [{ id: "idp-example", name: "EnterpriseSSO", protocol: "SAML", issuer: "https://identity.example.invalid/saml", audience: "matrix-cloud", metadata: '<EntityDescriptor entityID="https://identity.example.invalid/saml"></EntityDescriptor>', enabled: true, createdAt: at }],
    federations: [{ id: "federation-audit", name: "ExternalAuditor", subject: "audit@example.invalid", providerId: "idp-example", roleId: "role-audit", enabled: true, createdAt: at }],
    keys: [{ id: "MOCK-pipeline-key", ownerId: "principal-lin", status: "ENABLED", resourceVersion: 2, createdAt: at }],
    userPolicies: { "principal-lin": ["policy-prod-logs"], "principal-qiao": ["policy-tag-logs", "policy-production-guard", "policy-assume-reviewer"] },
    settings: { loginProtection: false, userSsoEnabled: false, userSsoProviderId: "" },
    personalMfa: { factorState: "never-bound", reauthenticationRequired: false, recoveryState: "idle" },
    events: [{ id: "event-sign-in", action: "sign-in", target: "preview-admin", at: "2026-09-09T01:10:00Z" }]
  };
}

export function createPreviewAccessWorkspace(accountId: string, userIds: () => string[], primaryPrincipalId: string): NonNullable<AccountRepository["workspace"]> & { reset(): void; snapshot(): AccessWorkspace; transact<T extends { workspace: AccessWorkspace }>(transition: (source: AccessWorkspace) => T): T } {
  let state = initialAccessWorkspace(accountId);
  const keyCreationResults = new Map<string, string>();
  const keyCreationRequest = (ownerId: string, requestId: string) => `${ownerId}\u0000${requestId}`;
  return {
    transact(transition) { const result = transition(structuredClone(state)); if (result.workspace.accountId !== accountId || result.workspace.mode !== "preview") throw new Error("INVALID_PREVIEW_WORKSPACE"); state = structuredClone(result.workspace); return result; },
    reset() { state = initialAccessWorkspace(accountId); keyCreationResults.clear(); },
    snapshot() { return structuredClone(state); },
    async read() { return structuredClone(state); },
    async execute(_credential, command) {
      const creationRequest = command.kind === "create-key" ? keyCreationRequest(command.ownerId, command.requestId) : null;
      if (creationRequest && keyCreationResults.has(creationRequest)) return { workspace: structuredClone(state) };
      if (command.kind === "inspect-key-creation" && command.resultMode === "not-found") throw new AccessWorkspaceError("keyResultNotFound");
      if (command.kind === "inspect-key-creation" && command.resultMode === "unavailable") throw new AccessWorkspaceError("keyResultUnavailable");
      const id = crypto.randomUUID();
      const resolvedKeyId = command.kind === "inspect-key-creation" ? keyCreationResults.get(keyCreationRequest(command.ownerId, command.requestId)) : undefined;
      if (command.kind === "inspect-key-creation" && !resolvedKeyId) throw new AccessWorkspaceError("keyResultNotFound");
      state = applyAccessWorkspaceCommand(state, command, { id, at: new Date().toISOString(), userIds: userIds(), primaryPrincipalId, resolvedKeyId });
      if (creationRequest) keyCreationResults.set(creationRequest, "MOCK-" + id);
      return {
        workspace: structuredClone(state),
        ...(command.kind === "create-key" && command.responseMode === "success"
          ? { issuedKey: { id: "MOCK-" + id, secret: "MOCK_NOT_A_CREDENTIAL_" + crypto.randomUUID() } }
          : {})
      };
    }
  };
}
