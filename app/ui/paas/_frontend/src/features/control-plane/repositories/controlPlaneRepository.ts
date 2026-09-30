import type {
  ActivateQuotaCommand,
  ControlPlaneSnapshot,
  CreateInstallationCommand,
  QuotaEntitlement,
  ServiceInstallation
} from "../domain/resources";
import type { ManagedServiceAuthorizationObservation } from "../domain/serviceAuthorization";

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
}
