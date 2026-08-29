import type { HostInventory } from "../domain/hosts";

export interface HostInventoryRepository {
  load(credential: string, signal?: AbortSignal): Promise<HostInventory>;
}
