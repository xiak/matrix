import type { ServiceRoleTemplateReference } from "@/features/auth/domain/serviceAuthorization";
import type { ActivateQuotaCommand, CreateInstallationCommand } from "./resources";

export type ManagedServiceCommandOwner = {
  accountId: string;
  actorKind: "USER" | "ROLE";
  actorId: string;
};

type ManagedServiceCommandBase = {
  owner: ManagedServiceCommandOwner;
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
  | "unknown";

export type ManagedServiceCommandState = {
  intent: ManagedServiceCommandIntent;
  phase: "submitting" | "unknown" | "failed" | "completed";
  error: ManagedServiceCommandError | null;
  slow: boolean;
  restored: boolean;
};

export function sameManagedServiceCommandOwner(
  left: ManagedServiceCommandOwner,
  right: ManagedServiceCommandOwner
): boolean {
  return left.accountId === right.accountId && left.actorKind === right.actorKind && left.actorId === right.actorId;
}
