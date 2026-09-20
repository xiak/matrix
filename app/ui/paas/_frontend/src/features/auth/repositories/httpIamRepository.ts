import { requestJSON, requestToken } from "@/infrastructure/http/jsonRequest";
import { userRoles, type Account, type AccountIdentity, type AccountPrincipal, type AccountUser, type DirectoryPage, type IdentityRole, type UserRole, type UserRoleBinding } from "../domain/accounts";
import type {
  AuthenticatorState,
  NotificationContact,
  NotificationContactVerification,
  NotificationDeliveryObservation,
  TOTPEnrollment,
  TOTPEnrollmentConfirmation,
  TOTPEnrollmentStart
} from "../domain/personalSecurity";
import type { AuthenticationChallenge, LoginResult, SessionSummary } from "../domain/session";
import type {
  ChangePasswordCommand,
  AccountRepository,
  IamRepository,
  LoginCommand
} from "./iamRepository";

function accountRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("INVALID_IAM_RESPONSE");
  return value as Record<string, unknown>;
}

function exactKeys(wire: Record<string, unknown>, required: string[], optional: string[] = []) {
  const allowed = new Set([...required, ...optional]);
  if (required.some((key) => !(key in wire)) || Object.keys(wire).some((key) => !allowed.has(key))) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
}

function accountText(value: unknown): string {
  if (typeof value !== "string" || !value.length) throw new Error("INVALID_IAM_RESPONSE");
  return value;
}

function accountIdentifier(value: unknown): string {
  const result = accountText(value);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(result)) throw new Error("INVALID_IAM_RESPONSE");
  return result;
}

function accountVersion(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) throw new Error("INVALID_IAM_RESPONSE");
  return value;
}

function accountStatus(value: unknown): "ACTIVE" | "DISABLED" {
  if (value !== "ACTIVE" && value !== "DISABLED") throw new Error("INVALID_IAM_RESPONSE");
  return value;
}

function parseIdentityRole(value: unknown): IdentityRole {
  if (value !== "PLATFORM_OPERATOR" && !userRoles.includes(value as UserRole)) throw new Error("INVALID_IAM_RESPONSE");
  return value as IdentityRole;
}

function requireAccountKind(wire: Record<string, unknown>, kind: string) {
  if (wire.apiVersion !== "iam.matrix.xiak.com/v1" || wire.kind !== kind) throw new Error("INVALID_IAM_RESPONSE");
}

function parseAccount(value: unknown): Account {
  const wire = accountRecord(value);
  const organization = accountRecord(wire.organization);
  requireAccountKind(organization, "Organization");
  if (wire.loginAlias !== null && (typeof wire.loginAlias !== "string" || !/^[a-z][a-z0-9-]{1,61}[a-z0-9]$/.test(wire.loginAlias))) throw new Error("INVALID_IAM_RESPONSE");
  return {
    organization: { id: accountText(organization.id), displayName: accountText(organization.displayName), status: accountStatus(organization.status), resourceVersion: accountVersion(organization.resourceVersion) },
    primaryPrincipalId: accountText(wire.primaryPrincipalId), primaryLoginName: accountText(wire.primaryLoginName), loginAlias: wire.loginAlias
  };
}

function parseAccountPrincipal(value: unknown): AccountPrincipal {
  const wire = accountRecord(value);
  requireAccountKind(wire, "Principal");
  if (wire.type !== "USER" || (wire.mustChangePassword !== undefined && typeof wire.mustChangePassword !== "boolean")) throw new Error("INVALID_IAM_RESPONSE");
  return { id: accountText(wire.id), organizationId: accountText(wire.organizationId), loginName: accountText(wire.loginName),
    displayName: accountText(wire.displayName), status: accountStatus(wire.status), mustChangePassword: wire.mustChangePassword === true, resourceVersion: accountVersion(wire.resourceVersion) };
}

function parseRoleBinding(value: unknown): UserRoleBinding {
  const wire = accountRecord(value);
  requireAccountKind(wire, "RoleBinding");
  return { id: accountText(wire.id), principalId: accountText(wire.principalId), organizationId: accountText(wire.organizationId), role: parseIdentityRole(wire.role) };
}

function parseAccountIdentity(value: unknown): AccountIdentity {
  const wire = accountRecord(value);
  requireAccountKind(wire, "CurrentIdentity");
  if (!Array.isArray(wire.roles) || typeof wire.canCreateOrganizations !== "boolean") throw new Error("INVALID_IAM_RESPONSE");
  const account = parseAccount(wire.account);
  const principal = parseAccountPrincipal(wire.principal);
  const roles = wire.roles.map(parseIdentityRole);
  if (account.organization.id !== principal.organizationId || new Set(roles).size !== roles.length ||
      (wire.canCreateOrganizations && (principal.mustChangePassword || !roles.includes("PLATFORM_OPERATOR")))) throw new Error("INVALID_IAM_RESPONSE");
  return { account, principal, roles, canCreateOrganizations: wire.canCreateOrganizations };
}

function accountPage<T>(value: unknown, kind: string, parse: (item: unknown) => T): DirectoryPage<T> {
  const wire = accountRecord(value);
  requireAccountKind(wire, kind);
  if (!Array.isArray(wire.items) || wire.items.length > 100) throw new Error("INVALID_IAM_RESPONSE");
  return { items: wire.items.map(parse), nextAfter: wire.nextAfter === undefined ? null : accountText(wire.nextAfter) };
}

function accountHeaders(credential: string): HeadersInit { return { Authorization: `Bearer ${credential}` }; }

export const httpAccountRepository: AccountRepository = {
  async currentIdentity(credential) {
    return parseAccountIdentity(await requestJSON<unknown>("/api/iam/v1/auth/me", { headers: accountHeaders(credential) }));
  },
  async listUsers(credential, after) {
    return accountPage<AccountUser>(await requestJSON<unknown>(`/api/iam/v1/principals${after ? `?after=${encodeURIComponent(after)}` : ""}`, { headers: accountHeaders(credential) }), "PrincipalList", (value) => {
      const wire = accountRecord(value);
      if (!Array.isArray(wire.roleBindings)) throw new Error("INVALID_IAM_RESPONSE");
      const principal = parseAccountPrincipal(wire.principal);
      const roleBindings = wire.roleBindings.map(parseRoleBinding);
      if (roleBindings.some((binding) => binding.principalId !== principal.id || binding.organizationId !== principal.organizationId) ||
          new Set(roleBindings.map((binding) => binding.role)).size !== roleBindings.length) throw new Error("INVALID_IAM_RESPONSE");
      return { principal, roleBindings };
    });
  },
  async listAccounts(credential, after) {
    return accountPage(await requestJSON<unknown>(`/api/iam/v1/organizations${after ? `?after=${encodeURIComponent(after)}` : ""}`, { headers: accountHeaders(credential) }), "OrganizationAccountList", parseAccount);
  },
  async execute(credential, command) {
    const requestId = requestToken("ui-account-");
    let path: string;
    let body: object;
    switch (command.kind) {
      case "create-user": path = "/api/iam/v1/principals"; body = { loginName: command.loginName, displayName: command.displayName, initialPassword: command.initialPassword, initialRole: command.initialRole }; break;
      case "create-organization": path = "/api/iam/v1/organizations"; body = { id: command.id, displayName: command.displayName, administratorLoginName: command.administratorLoginName, administratorDisplayName: command.administratorDisplayName, initialPassword: command.initialPassword }; break;
      case "set-organization-status": path = `/api/iam/v1/organizations/${encodeURIComponent(command.organizationId)}:set-status`; body = { status: command.status, resourceVersion: command.resourceVersion }; break;
      case "recover-primary": path = `/api/iam/v1/organizations/${encodeURIComponent(command.organizationId)}:recover-administrator`; body = { principalId: command.principalId, initialPassword: command.initialPassword, resourceVersion: command.resourceVersion }; break;
      case "set-alias": path = "/api/iam/v1/organization:alias"; body = { alias: command.alias, resourceVersion: command.resourceVersion }; break;
      case "set-status": path = `/api/iam/v1/principals/${encodeURIComponent(command.principalId)}:set-status`; body = { status: command.status, resourceVersion: command.resourceVersion }; break;
      case "reset-password": path = `/api/iam/v1/principals/${encodeURIComponent(command.principalId)}:reset-password`; body = { initialPassword: command.initialPassword, resourceVersion: command.resourceVersion }; break;
      case "grant-role": path = "/api/iam/v1/role-bindings"; body = { principalId: command.principalId, role: command.role }; break;
      case "revoke-role": path = `/api/iam/v1/role-bindings/${encodeURIComponent(command.bindingId)}:revoke`; body = {}; break;
    }
    const result = await requestJSON<unknown>(path, { method: "POST", headers: { ...accountHeaders(credential), "Content-Type": "application/json" }, body: JSON.stringify({ ...body, requestId }) });
    if (command.kind === "create-organization" || command.kind === "set-alias" || command.kind === "set-organization-status" || command.kind === "recover-primary") {
      const account = parseAccount(result);
      if (command.kind === "create-organization" && (account.organization.id !== command.id || account.primaryLoginName !== command.administratorLoginName)) throw new Error("INVALID_IAM_RESPONSE");
      if (command.kind === "set-alias" && (account.loginAlias !== command.alias || account.organization.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
      if ((command.kind === "set-organization-status" || command.kind === "recover-primary") &&
          (account.organization.id !== command.organizationId || account.organization.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
      if (command.kind === "set-organization-status" && account.organization.status !== command.status) throw new Error("INVALID_IAM_RESPONSE");
      if (command.kind === "recover-primary" && account.primaryPrincipalId !== command.principalId) throw new Error("INVALID_IAM_RESPONSE");
      return;
    }
    if (command.kind === "grant-role") {
      const binding = parseRoleBinding(result);
      if (binding.principalId !== command.principalId || binding.role !== command.role) throw new Error("INVALID_IAM_RESPONSE");
      return;
    }
    if (command.kind === "revoke-role") {
      const wire = accountRecord(result);
      requireAccountKind(wire, "Revocation");
      if (wire.id !== command.bindingId) throw new Error("INVALID_IAM_RESPONSE");
      return;
    }
    const principal = parseAccountPrincipal(result);
    if (command.kind === "create-user" && principal.loginName !== command.loginName) throw new Error("INVALID_IAM_RESPONSE");
    if (command.kind !== "create-user" && (principal.id !== command.principalId || principal.resourceVersion <= command.resourceVersion)) throw new Error("INVALID_IAM_RESPONSE");
    if (command.kind === "set-status" && principal.status !== command.status) throw new Error("INVALID_IAM_RESPONSE");
    if ((command.kind === "create-user" || command.kind === "reset-password") && !principal.mustChangePassword) throw new Error("INVALID_IAM_RESPONSE");
  }
};

type ChangePasswordWire = {
  changedAt?: unknown;
  bootstrapFileRetirable?: unknown;
};

function authenticationTimestamp(value: unknown): string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return value;
}

function securityTimestamp(value: unknown): string {
  const result = accountText(value);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(result) ||
      Number.isNaN(Date.parse(result)) || new Date(result).toISOString().slice(0, 19) !== result.slice(0, 19)) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return result;
}

function timestampOrder(value: string): string {
  return value.slice(0, 19) + "." + value.slice(19, -1).slice(1).padEnd(6, "0");
}

function timestampMicros(value: string): bigint {
  const wholeSeconds = Date.parse(`${value.slice(0, 19)}Z`);
  const fractionalMicros = value.slice(19, -1).slice(1).padEnd(6, "0");
  return BigInt(wholeSeconds) * 1_000n + BigInt(fractionalMicros || "0");
}

function parseSession(value: unknown): SessionSummary {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "organizationId", "principalId", "status", "issuedAt", "expiresAt"]);
  if (wire.apiVersion !== "iam.matrix.xiak.com/v1" || wire.kind !== "Session" || wire.status !== "ACTIVE") {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const issuedAt = authenticationTimestamp(wire.issuedAt);
  const expiresAt = authenticationTimestamp(wire.expiresAt);
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) throw new Error("INVALID_IAM_RESPONSE");
  return {
    id: accountText(wire.id),
    organizationId: accountText(wire.organizationId),
    principalId: accountText(wire.principalId),
    status: "ACTIVE",
    issuedAt,
    expiresAt
  };
}

function parseAuthenticationChallenge(value: unknown): AuthenticationChallenge {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "purpose", "nextStep", "expiresAt"]);
  if (wire.apiVersion !== "iam.matrix.xiak.com/v1" || wire.kind !== "AuthenticationChallenge" || wire.purpose !== "LOGIN" ||
      (wire.nextStep !== "TOTP" && wire.nextStep !== "PASSWORD_CHANGE")) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return {
    id: accountText(wire.id),
    purpose: "LOGIN",
    nextStep: wire.nextStep,
    expiresAt: authenticationTimestamp(wire.expiresAt)
  };
}

function parseLogin(value: unknown): LoginResult {
  const wire = accountRecord(value);
  if (wire.outcome === "AUTHENTICATED") {
    exactKeys(wire, ["outcome", "session", "credential", "mustChangePassword"]);
    if (typeof wire.credential !== "string" || !wire.credential || typeof wire.mustChangePassword !== "boolean") {
      throw new Error("INVALID_IAM_RESPONSE");
    }
    return {
      outcome: "AUTHENTICATED",
      credential: wire.credential,
      mustChangePassword: wire.mustChangePassword,
      session: parseSession(wire.session)
    };
  }
  if (wire.outcome === "CHALLENGE_REQUIRED") {
    exactKeys(wire, ["outcome", "challenge", "challengeCredential"]);
    if (typeof wire.challengeCredential !== "string" || !wire.challengeCredential) throw new Error("INVALID_IAM_RESPONSE");
    return {
      outcome: "CHALLENGE_REQUIRED",
      challenge: parseAuthenticationChallenge(wire.challenge),
      challengeCredential: wire.challengeCredential
    };
  }
  throw new Error("INVALID_IAM_RESPONSE");
}

function securityMailAddress(value: unknown): string {
  if (typeof value !== "string" || value.length > 254) throw new Error("INVALID_IAM_RESPONSE");
  const separator = value.indexOf("@");
  if (separator <= 0 || separator !== value.lastIndexOf("@")) throw new Error("INVALID_IAM_RESPONSE");
  const local = value.slice(0, separator);
  const domain = value.slice(separator + 1);
  if (local.length > 64 || local.startsWith(".") || local.endsWith(".") || local.includes("..") ||
      !/^[A-Za-z0-9.!#$%&'*+\-/=?^_`{|}~]+$/.test(local) || domain !== domain.toLowerCase() ||
      domain.length > 253 || !domain.includes(".") || domain.split(".").some((label) =>
        !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new Error("INVALID_IAM_RESPONSE");
  return value;
}

function parseNotificationContact(value: unknown): NotificationContact {
  const wire = accountRecord(value);
  requireAccountKind(wire, "NotificationContact");
  const accountId = accountIdentifier(wire.accountId);
  const userId = accountIdentifier(wire.userId);
  if (wire.state === "NONE") {
    exactKeys(wire, ["apiVersion", "kind", "accountId", "userId", "state", "resourceVersion"], ["pendingVerificationId"]);
    if (wire.resourceVersion !== 0) throw new Error("INVALID_IAM_RESPONSE");
    return {
      accountId,
      userId,
      state: "NONE",
      resourceVersion: 0,
      pendingVerificationId: wire.pendingVerificationId === undefined ? null : accountIdentifier(wire.pendingVerificationId)
    };
  }
  if (wire.state !== "VERIFIED") throw new Error("INVALID_IAM_RESPONSE");
  exactKeys(wire, ["apiVersion", "kind", "accountId", "userId", "state", "resourceVersion", "email", "verifiedAt"]);
  return {
    accountId,
    userId,
    state: "VERIFIED",
    resourceVersion: accountVersion(wire.resourceVersion),
    email: securityMailAddress(wire.email),
    verifiedAt: securityTimestamp(wire.verifiedAt),
    pendingVerificationId: null
  };
}

function parseNotificationDelivery(value: unknown, issuedAt: string): NotificationDeliveryObservation {
  const wire = accountRecord(value);
  exactKeys(wire, ["state", "attempts", "updatedAt"], ["lastOutcome", "lastSmtpCode"]);
  const states = new Set(["PENDING", "IN_FLIGHT", "RETRY_WAIT", "ACCEPTED", "FAILED", "EXPIRED"]);
  const outcomes = new Set(["ACCEPTED", "REJECTED", "UNKNOWN", "UNAVAILABLE"]);
  if (typeof wire.state !== "string" || !states.has(wire.state) || typeof wire.attempts !== "number" ||
      !Number.isInteger(wire.attempts) || wire.attempts < 0 || wire.attempts > 5) throw new Error("INVALID_IAM_RESPONSE");
  const attempts = wire.attempts;
  const lastOutcome = wire.lastOutcome === undefined ? null : wire.lastOutcome;
  const lastSmtpCode = wire.lastSmtpCode === undefined ? null : wire.lastSmtpCode;
  if (lastOutcome !== null && (typeof lastOutcome !== "string" || !outcomes.has(lastOutcome)) ||
      lastSmtpCode !== null && (typeof lastSmtpCode !== "number" || !Number.isInteger(lastSmtpCode) || lastSmtpCode < 1 || lastSmtpCode > 599)) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  if (wire.state === "PENDING" && (attempts !== 0 || lastOutcome !== null) ||
      wire.state !== "PENDING" && wire.state !== "EXPIRED" && attempts === 0 ||
      wire.state === "IN_FLIGHT" && (attempts === 1 ? lastOutcome !== null : lastOutcome === null) ||
      wire.state === "RETRY_WAIT" && attempts >= 5 || wire.state === "EXPIRED" && attempts >= 5 ||
      lastOutcome === null && (lastSmtpCode !== null || attempts > 1 || wire.state === "EXPIRED" && attempts !== 0 || wire.state === "RETRY_WAIT" || wire.state === "ACCEPTED" || wire.state === "FAILED") ||
      lastOutcome === "ACCEPTED" && (wire.state !== "ACCEPTED" || lastSmtpCode !== 250) ||
      lastOutcome === "REJECTED" && (lastSmtpCode === null || lastSmtpCode < 400 || wire.state === "ACCEPTED" ||
        lastSmtpCode >= 500 && wire.state !== "FAILED" || lastSmtpCode < 500 && wire.state === "FAILED" && attempts !== 5) ||
      (lastOutcome === "UNKNOWN" || lastOutcome === "UNAVAILABLE") && (lastSmtpCode !== null || wire.state === "ACCEPTED" || wire.state === "FAILED" && attempts !== 5)) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const updatedAt = securityTimestamp(wire.updatedAt);
  if (timestampOrder(updatedAt) < timestampOrder(issuedAt)) throw new Error("INVALID_IAM_RESPONSE");
  return {
    state: wire.state as NotificationDeliveryObservation["state"],
    attempts,
    lastOutcome: lastOutcome as NotificationDeliveryObservation["lastOutcome"],
    lastSmtpCode,
    updatedAt
  };
}

function parseNotificationVerification(value: unknown): NotificationContactVerification {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "accountId", "userId", "requestId", "email", "state", "issuedAt", "expiresAt", "delivery"], ["completedAt"]);
  requireAccountKind(wire, "NotificationContactVerification");
  if (wire.state !== "PENDING" && wire.state !== "VERIFIED" && wire.state !== "CANCELLED" && wire.state !== "EXPIRED") {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const issuedAt = securityTimestamp(wire.issuedAt);
  const expiresAt = securityTimestamp(wire.expiresAt);
  if (timestampMicros(expiresAt) - timestampMicros(issuedAt) !== 10n * 60n * 1_000_000n) throw new Error("INVALID_IAM_RESPONSE");
  const completedAt = wire.completedAt === undefined ? null : securityTimestamp(wire.completedAt);
  if (wire.state === "PENDING") {
    if (completedAt !== null) throw new Error("INVALID_IAM_RESPONSE");
  } else if (completedAt === null || timestampOrder(completedAt) < timestampOrder(issuedAt) ||
      wire.state === "VERIFIED" && timestampOrder(completedAt) >= timestampOrder(expiresAt) ||
      wire.state === "EXPIRED" && timestampOrder(completedAt) !== timestampOrder(expiresAt)) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  return {
    id: accountIdentifier(wire.id),
    accountId: accountIdentifier(wire.accountId),
    userId: accountIdentifier(wire.userId),
    requestId: accountIdentifier(wire.requestId),
    email: securityMailAddress(wire.email),
    state: wire.state,
    issuedAt,
    expiresAt,
    completedAt,
    delivery: parseNotificationDelivery(wire.delivery, issuedAt)
  };
}

function parseAuthenticatorState(value: unknown): AuthenticatorState {
  const wire = accountRecord(value);
  requireAccountKind(wire, "AuthenticatorState");
  if (wire.enrollmentState === "NEVER_BOUND") {
    exactKeys(wire, ["apiVersion", "kind", "enrollmentState", "factorRevision"]);
    if (wire.factorRevision !== 1) throw new Error("INVALID_IAM_RESPONSE");
    return { enrollmentState: "NEVER_BOUND", factorRevision: 1, factorId: null };
  }
  if (wire.enrollmentState === "BOUND") {
    exactKeys(wire, ["apiVersion", "kind", "enrollmentState", "factorRevision", "factorId"]);
    const factorRevision = accountVersion(wire.factorRevision);
    if (factorRevision <= 1) throw new Error("INVALID_IAM_RESPONSE");
    return { enrollmentState: "BOUND", factorRevision, factorId: accountIdentifier(wire.factorId) };
  }
  if (wire.enrollmentState !== "RECOVERY_REQUIRED") throw new Error("INVALID_IAM_RESPONSE");
  exactKeys(wire, ["apiVersion", "kind", "enrollmentState", "factorRevision"], ["factorId"]);
  return {
    enrollmentState: "RECOVERY_REQUIRED",
    factorRevision: accountVersion(wire.factorRevision),
    factorId: wire.factorId === undefined ? null : accountIdentifier(wire.factorId)
  };
}

function parseTOTPEnrollment(value: unknown): TOTPEnrollment {
  const wire = accountRecord(value);
  exactKeys(wire, ["apiVersion", "kind", "id", "requestId", "factorRevision", "state", "createdAt", "expiresAt"], ["completedAt"]);
  requireAccountKind(wire, "TOTPEnrollment");
  if (wire.state !== "PENDING" && wire.state !== "CONFIRMED" && wire.state !== "CANCELLED" && wire.state !== "EXPIRED") {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const createdAt = securityTimestamp(wire.createdAt);
  const expiresAt = securityTimestamp(wire.expiresAt);
  if (timestampMicros(expiresAt) - timestampMicros(createdAt) !== 5n * 60n * 1_000_000n) throw new Error("INVALID_IAM_RESPONSE");
  const completedAt = wire.completedAt === undefined ? null : securityTimestamp(wire.completedAt);
  if (wire.state === "PENDING") {
    if (completedAt !== null) throw new Error("INVALID_IAM_RESPONSE");
  } else if (completedAt === null || timestampOrder(completedAt) < timestampOrder(createdAt) ||
      wire.state === "CONFIRMED" && timestampOrder(completedAt) >= timestampOrder(expiresAt)) {
    throw new Error("INVALID_IAM_RESPONSE");
  }
  const factorRevision = accountVersion(wire.factorRevision);
  if (factorRevision > 9_007_199_254_740_990) throw new Error("INVALID_IAM_RESPONSE");
  return {
    id: accountIdentifier(wire.id),
    requestId: accountIdentifier(wire.requestId),
    factorRevision,
    state: wire.state,
    createdAt,
    expiresAt,
    completedAt
  };
}

function parseTOTPEnrollmentStart(value: unknown): TOTPEnrollmentStart {
  const wire = accountRecord(value);
  if (wire.outcome === "APPLIED") {
    exactKeys(wire, ["outcome", "enrollment", "provisioning"]);
    const enrollment = parseTOTPEnrollment(wire.enrollment);
    const provisioning = accountRecord(wire.provisioning);
    exactKeys(provisioning, ["seed", "uri"]);
    if (enrollment.state !== "PENDING" || typeof provisioning.seed !== "string" || !provisioning.seed || provisioning.seed.length > 16384 ||
        typeof provisioning.uri !== "string" || !provisioning.uri || provisioning.uri.length > 16384) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
    return { outcome: "APPLIED", enrollment, provisioning: { seed: provisioning.seed, uri: provisioning.uri } };
  }
  if (wire.outcome !== "EQUAL_REPLAY") throw new Error("INVALID_IAM_RESPONSE");
  exactKeys(wire, ["outcome", "enrollment"]);
  return { outcome: "EQUAL_REPLAY", enrollment: parseTOTPEnrollment(wire.enrollment) };
}

function parseTOTPEnrollmentConfirmation(value: unknown, enrollmentId: string): TOTPEnrollmentConfirmation {
  const wire = accountRecord(value);
  exactKeys(wire, ["enrollment", "nextStep", "recoveryCodes"]);
  const enrollment = parseTOTPEnrollment(wire.enrollment);
  if (enrollment.id !== enrollmentId || enrollment.state !== "CONFIRMED" || wire.nextStep !== "REAUTHENTICATE" ||
      !Array.isArray(wire.recoveryCodes) || wire.recoveryCodes.length !== 10 ||
      wire.recoveryCodes.some((code) => typeof code !== "string" || !code || code.length > 16384) ||
      new Set(wire.recoveryCodes).size !== wire.recoveryCodes.length) throw new Error("INVALID_IAM_RESPONSE");
  return { enrollment, nextStep: "REAUTHENTICATE", recoveryCodes: wire.recoveryCodes as string[] };
}

export const httpIamRepository: IamRepository = {
  async login(command: LoginCommand): Promise<LoginResult> {
    const wire = await requestJSON<unknown>("/api/iam/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        loginName: command.loginName,
        password: command.password,
        requestId: requestToken("ui-login-")
      })
    });
    return parseLogin(wire);
  },

  authenticationChallenges: {
    async verify(command) {
      const wire = await requestJSON<unknown>(`/api/iam/v1/auth/challenges/${encodeURIComponent(command.challengeId)}:verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          requestId: requestToken("ui-login-challenge-"),
          challengeCredential: command.challengeCredential,
          code: command.code
        })
      });
      return parseLogin(wire);
    },
    async changePassword(command) {
      const wire = accountRecord(await requestJSON<unknown>(`/api/iam/v1/auth/challenges/${encodeURIComponent(command.challengeId)}:password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          requestId: requestToken("ui-login-challenge-password-"),
          challengeCredential: command.challengeCredential,
          newPassword: command.newPassword
        })
      }));
      exactKeys(wire, ["nextStep", "changedAt"]);
      if (wire.nextStep !== "REAUTHENTICATE") throw new Error("INVALID_IAM_RESPONSE");
      return { nextStep: "REAUTHENTICATE", changedAt: authenticationTimestamp(wire.changedAt) };
    }
  },

  async changePassword(
    credential: string,
    command: ChangePasswordCommand
  ): Promise<void> {
    const wire = await requestJSON<ChangePasswordWire>("/api/iam/v1/auth/password", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credential}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        currentPassword: command.currentPassword,
        newPassword: command.newPassword,
        revokeOtherSessions: command.revokeOtherSessions,
        requestId: requestToken("ui-password-")
      })
    });
    if (
      typeof wire.changedAt !== "string" ||
      typeof wire.bootstrapFileRetirable !== "boolean"
    ) {
      throw new Error("INVALID_IAM_RESPONSE");
    }
  },

  async logout(credential: string): Promise<void> {
    await requestJSON<unknown>("/api/iam/v1/auth/logout", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credential}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ requestId: requestToken("ui-logout-") })
    });
  },

  personalSecurity: {
    async notificationContact(credential) {
      return parseNotificationContact(await requestJSON<unknown>("/api/iam/v1/auth/notification-contact", {
        headers: accountHeaders(credential)
      }));
    },
    async startNotificationVerification(credential, command) {
      const email = securityMailAddress(command.email);
      const requestId = accountIdentifier(command.requestId);
      const verification = parseNotificationVerification(await requestJSON<unknown>("/api/iam/v1/auth/notification-contact/verifications", {
        method: "POST",
        headers: { ...accountHeaders(credential), "Content-Type": "application/json" },
        body: JSON.stringify({ email, password: accountText(command.password), requestId })
      }));
      if (verification.email !== email || verification.requestId !== requestId) throw new Error("INVALID_IAM_RESPONSE");
      return verification;
    },
    async notificationVerification(credential, verificationId) {
      const target = accountIdentifier(verificationId);
      const verification = parseNotificationVerification(await requestJSON<unknown>(
        `/api/iam/v1/auth/notification-contact/verifications/${encodeURIComponent(target)}`,
        { headers: accountHeaders(credential) }
      ));
      if (verification.id !== target) throw new Error("INVALID_IAM_RESPONSE");
      return verification;
    },
    async confirmNotificationVerification(credential, verificationId, command) {
      if (!/^[0-9]{8}$/.test(command.code)) throw new Error("INVALID_IAM_RESPONSE");
      const target = accountIdentifier(verificationId);
      const verification = parseNotificationVerification(await requestJSON<unknown>(
        `/api/iam/v1/auth/notification-contact/verifications/${encodeURIComponent(target)}:confirm`,
        {
          method: "POST",
          headers: { ...accountHeaders(credential), "Content-Type": "application/json" },
          body: JSON.stringify({ code: command.code, requestId: accountIdentifier(command.requestId) })
        }
      ));
      if (verification.id !== target) throw new Error("INVALID_IAM_RESPONSE");
      return verification;
    },
    async authenticatorState(credential) {
      return parseAuthenticatorState(await requestJSON<unknown>("/api/iam/v1/auth/authenticators", {
        headers: accountHeaders(credential)
      }));
    },
    async startTOTPEnrollment(credential, command) {
      const expectedFactorRevision = accountVersion(command.expectedFactorRevision);
      if (expectedFactorRevision > 9_007_199_254_740_990) throw new Error("INVALID_IAM_RESPONSE");
      const requestId = accountIdentifier(command.requestId);
      const result = parseTOTPEnrollmentStart(await requestJSON<unknown>("/api/iam/v1/auth/totp/enrollments", {
        method: "POST",
        headers: { ...accountHeaders(credential), "Content-Type": "application/json" },
        body: JSON.stringify({ requestId, password: accountText(command.password), expectedFactorRevision })
      }));
      if (result.enrollment.requestId !== requestId || result.enrollment.factorRevision !== expectedFactorRevision) {
        throw new Error("INVALID_IAM_RESPONSE");
      }
      return result;
    },
    async totpEnrollment(credential, enrollmentId) {
      const target = accountIdentifier(enrollmentId);
      const enrollment = parseTOTPEnrollment(await requestJSON<unknown>(
        `/api/iam/v1/auth/totp/enrollments/${encodeURIComponent(target)}`,
        { headers: accountHeaders(credential) }
      ));
      if (enrollment.id !== target) throw new Error("INVALID_IAM_RESPONSE");
      return enrollment;
    },
    async totpEnrollmentByRequest(credential, requestId) {
      const target = accountIdentifier(requestId);
      const enrollment = parseTOTPEnrollment(await requestJSON<unknown>(
        `/api/iam/v1/auth/totp/enrollments/by-request/${encodeURIComponent(target)}`,
        { headers: accountHeaders(credential) }
      ));
      if (enrollment.requestId !== target) throw new Error("INVALID_IAM_RESPONSE");
      return enrollment;
    },
    async cancelTOTPEnrollment(credential, enrollmentId) {
      const target = accountIdentifier(enrollmentId);
      const enrollment = parseTOTPEnrollment(await requestJSON<unknown>(
        `/api/iam/v1/auth/totp/enrollments/${encodeURIComponent(target)}`,
        { method: "DELETE", headers: accountHeaders(credential) }
      ));
      if (enrollment.id !== target || (enrollment.state !== "CANCELLED" && enrollment.state !== "EXPIRED")) {
        throw new Error("INVALID_IAM_RESPONSE");
      }
      return enrollment;
    },
    async confirmTOTPEnrollment(credential, enrollmentId, command) {
      const target = accountIdentifier(enrollmentId);
      if (!/^[0-9]{6}$/.test(command.code)) throw new Error("INVALID_IAM_RESPONSE");
      return parseTOTPEnrollmentConfirmation(await requestJSON<unknown>(
        `/api/iam/v1/auth/totp/enrollments/${encodeURIComponent(target)}:confirm`,
        {
          method: "POST",
          headers: { ...accountHeaders(credential), "Content-Type": "application/json" },
          body: JSON.stringify({ requestId: accountIdentifier(command.requestId), code: command.code })
        }
      ), target);
    }
  }
};
