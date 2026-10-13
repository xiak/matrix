import type { ServiceRoleTemplateReference } from "@/features/auth/domain/serviceAuthorization";
import type { ActivateQuotaCommand, CreateInstallationCommand, ServiceInstallation } from "./resources";

export const managedServiceCommandTypes = [
  "QUOTA_ACTIVATE", "INSTALLATION_CREATE", "INSTALLATION_TERMINATE", "SERVICE_ROLE_BIND", "SERVICE_ROLE_UNBIND"
] as const;
export type ManagedServiceCommandType = typeof managedServiceCommandTypes[number];

/** A bounded, non-secret server observation, never a resource-access permit. */
export type ManagedServiceCommandResult = {
  idempotencyKey: string;
  commandType: ManagedServiceCommandType;
  inputDigest: string;
  state: "IN_PROGRESS" | "SUCCEEDED" | "FAILED";
  target: { kind: "QUOTA_ENTITLEMENT" | "SERVICE_INSTALLATION"; id: string };
  operation: ServiceInstallation["operation"] | null;
  bindingId: string | null;
  completedAt: string | null;
};

export type ManagedServiceCommandOwner = {
  accountId: string;
  actorId: string;
} & ({ actorKind: "USER" } | { actorKind: "ROLE"; sourceUserId: string });

type ManagedServiceCommandBase = {
  owner: ManagedServiceCommandOwner;
  /** The caller's public Idempotency-Key, not an IAM-private request identity. */
  requestId: string;
  startedAt: string;
  targetId: string;
  targetLabel: string;
};

export type ManagedServiceCommandIntent = ManagedServiceCommandBase & (
  | { kind: "ACTIVATE_QUOTA"; payload: ActivateQuotaCommand }
  | { kind: "CREATE_INSTALLATION"; payload: CreateInstallationCommand }
  | { kind: "TERMINATE_INSTALLATION"; payload: { installationId: string } }
  | { kind: "BIND_SERVICE_ROLE"; payload: { installationId: string; template: ServiceRoleTemplateReference } }
  | { kind: "UNBIND_SERVICE_ROLE"; payload: {
    installationId: string;
    bindingId: string;
    resourceVersion: number;
    expectedTemplate: ServiceRoleTemplateReference;
  } }
);

export type ManagedServiceCommandError =
  | "expired"
  | "forbidden"
  | "notFound"
  | "conflict"
  | "invalid"
  | "storageUnavailable"
  | "unavailable"
  | "mismatch"
  | "operationFailed"
  | "unknown";

export type ManagedServiceCommandState = {
  intent: ManagedServiceCommandIntent;
  phase: "submitting" | "unknown" | "inProgress" | "failed" | "completed";
  error: ManagedServiceCommandError | null;
  slow: boolean;
  restored: boolean;
  checking?: boolean;
  result?: ManagedServiceCommandResult;
};

export function managedServiceCommandType(kind: ManagedServiceCommandIntent["kind"]): ManagedServiceCommandType {
  const types = {
    ACTIVATE_QUOTA: "QUOTA_ACTIVATE", CREATE_INSTALLATION: "INSTALLATION_CREATE",
    TERMINATE_INSTALLATION: "INSTALLATION_TERMINATE", BIND_SERVICE_ROLE: "SERVICE_ROLE_BIND",
    UNBIND_SERVICE_ROLE: "SERVICE_ROLE_UNBIND"
  } as const;
  return types[kind];
}

export function matchesManagedServiceCommandResult(intent: ManagedServiceCommandIntent, result: ManagedServiceCommandResult): boolean {
  if (result.idempotencyKey !== intent.requestId || result.commandType !== managedServiceCommandType(intent.kind)) return false;
  // Quota IDs are allocated by the authority, not selected as the Offering ID.
  if (intent.kind === "ACTIVATE_QUOTA") return result.target.kind === "QUOTA_ENTITLEMENT";
  const installationId = intent.kind === "CREATE_INSTALLATION" ? intent.payload.id : intent.payload.installationId;
  return result.target.kind === "SERVICE_INSTALLATION" && result.target.id === installationId &&
    (intent.kind !== "UNBIND_SERVICE_ROLE" || result.bindingId === intent.payload.bindingId);
}

export function sameManagedServiceCommandOwner(
  left: ManagedServiceCommandOwner,
  right: ManagedServiceCommandOwner
): boolean {
  return left.accountId === right.accountId && left.actorKind === right.actorKind && left.actorId === right.actorId &&
    (left.actorKind !== "ROLE" || (right.actorKind === "ROLE" && left.sourceUserId === right.sourceUserId));
}
