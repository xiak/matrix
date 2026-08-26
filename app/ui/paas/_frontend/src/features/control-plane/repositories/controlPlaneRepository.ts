import type {
  ActivateQuotaCommand,
  ControlPlaneSnapshot,
  CreateInstallationCommand,
  QuotaEntitlement,
  ServiceInstallation
} from "../domain/resources";

export interface ControlPlaneRepository {
  load(credential: string): Promise<ControlPlaneSnapshot>;
  activateQuota(
    credential: string,
    command: ActivateQuotaCommand
  ): Promise<QuotaEntitlement>;
  createInstallation(
    credential: string,
    command: CreateInstallationCommand
  ): Promise<ServiceInstallation>;
}
