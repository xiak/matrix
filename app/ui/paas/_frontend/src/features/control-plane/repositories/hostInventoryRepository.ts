import type { HostInventory, HostLifecycleCommand, HostTarget } from "../domain/hosts";

export interface HostInventoryRepository {
  load(credential: string, signal?: AbortSignal): Promise<HostInventory>;
  transition(credential: string, command: HostLifecycleCommand): Promise<HostTarget>;
}
