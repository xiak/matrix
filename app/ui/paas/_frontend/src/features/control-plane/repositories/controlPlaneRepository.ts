import type {
  ActivateQuotaCommand,
  ControlPlaneSnapshot,
  CreateInstallationCommand,
  QuotaEntitlement,
  ServiceInstallation
} from "../domain/resources";
import type {
  BindManagedServiceRoleCommand,
  ManagedServiceAuthorizationObservation,
  ManagedServiceRoleBindingReceipt,
  ManagedServiceRoleUnbindingReceipt,
  UnbindManagedServiceRoleCommand
} from "../domain/serviceAuthorization";

export interface ControlPlaneRepository {
  load(credential: string): Promise<ControlPlaneSnapshot>;
  getInstallation(credential: string, installationId: string): Promise<ServiceInstallation>;
  activateQuota(
    credential: string,
    command: ActivateQuotaCommand
  ): Promise<QuotaEntitlement>;
  createInstallation(
    credential: string,
    command: CreateInstallationCommand
  ): Promise<ServiceInstallation>;
  inspectServiceAuthorization?(
    credential: string,
    accountId: string,
    installationId: string
  ): Promise<ManagedServiceAuthorizationObservation>;
  bindServiceRole?(
    credential: string,
    installationId: string,
    command: BindManagedServiceRoleCommand
  ): Promise<ManagedServiceRoleBindingReceipt>;
  unbindServiceRole?(
    credential: string,
    installationId: string,
    command: UnbindManagedServiceRoleCommand
  ): Promise<ManagedServiceRoleUnbindingReceipt>;
}
