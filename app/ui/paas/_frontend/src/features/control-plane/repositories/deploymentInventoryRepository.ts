import type {
  DeploymentInventory,
  DeploymentRuntimeSnapshot
} from "../domain/deployments";

export interface DeploymentInventoryRepository {
  load(credential: string, tenantId: string, signal?: AbortSignal): Promise<DeploymentInventory>;
  loadRuntime(
    credential: string,
    tenantId: string,
    deploymentId: string,
    signal?: AbortSignal
  ): Promise<DeploymentRuntimeSnapshot>;
}
