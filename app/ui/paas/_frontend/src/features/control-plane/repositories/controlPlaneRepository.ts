import type {
  ActivateQuotaCommand,
  ControlPlaneSnapshot,
  CreateInstallationCommand,
  QuotaEntitlement,
  ServiceDefinitionReference,
  ServiceInstallation
} from "../domain/resources";
import type {
  ServiceActivation,
  ServiceDefinitionDirectory
} from "../domain/serviceActivation";
import type {
  BindManagedServiceRoleCommand,
  ManagedServiceAuthorizationObservation,
  ManagedServiceRoleBindingReceipt,
  ManagedServiceRoleUnbindingReceipt,
  UnbindManagedServiceRoleCommand
} from "../domain/serviceAuthorization";
import type { ApplicationDirectoryPage, ApplicationReadSnapshot } from "../domain/application";

export const controlPlaneResourceKinds = [
  "offerings",
  "regions",
  "entitlements",
  "installations"
] as const;

export type ControlPlaneResourceKind = typeof controlPlaneResourceKinds[number];
export type ControlPlaneResourceSnapshot = Partial<ControlPlaneSnapshot>;

export interface ControlPlaneRepository {
  load(
    credential: string,
    resources: readonly ControlPlaneResourceKind[]
  ): Promise<ControlPlaneResourceSnapshot>;
  getInstallation(credential: string, installationId: string): Promise<ServiceInstallation>;
  listServiceDefinitions?(credential: string): Promise<ServiceDefinitionDirectory>;
  getServiceActivation?(credential: string, serviceId: string): Promise<ServiceActivation>;
  activateService?(
    credential: string,
    service: ServiceDefinitionReference,
    requestId: string
  ): Promise<ServiceActivation>;
  readApplication?(
    credential: string,
    applicationId: string
  ): Promise<ApplicationReadSnapshot>;
  listApplications?(
    credential: string,
    after?: string
  ): Promise<ApplicationDirectoryPage>;
  activateQuota(
    credential: string,
    command: ActivateQuotaCommand,
    requestId: string
  ): Promise<QuotaEntitlement>;
  createInstallation(
    credential: string,
    command: CreateInstallationCommand,
    requestId: string
  ): Promise<ServiceInstallation>;
  terminateInstallation?(
    credential: string,
    installationId: string,
    requestId: string
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
