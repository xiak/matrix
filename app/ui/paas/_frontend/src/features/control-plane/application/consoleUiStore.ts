import { create } from "zustand";
import type { ServiceId } from "../scenes/serviceDirectory";

export type HeaderPanel = "products" | "search" | "region" | "notifications" | "account";

type ConsoleUiState = {
  headerPanel: HeaderPanel | null;
  setHeaderPanel(panel: HeaderPanel | null): void;
  sidebarOverlayOpen: boolean;
  workspaceOpen: boolean;
  favoriteServices: ServiceId[];
  recentServices: ServiceId[];
  readMessageIds: string[];
  markMessagesRead(ids: readonly string[]): void;
  toggleFavoriteService(id: ServiceId): void;
  visitService(id: ServiceId): void;
  resetSessionUi(): void;
  openSidebar(): void;
  closeSidebar(): void;
  toggleWorkspace(): void;
  closeWorkspace(): void;
};

export const useConsoleUiStore = create<ConsoleUiState>((set) => ({
  headerPanel: null,
  setHeaderPanel: (headerPanel) => set({ headerPanel }),
  sidebarOverlayOpen: false,
  workspaceOpen: false,
  favoriteServices: [],
  recentServices: [],
  readMessageIds: [],
  markMessagesRead: (ids) => set((state) => ({ readMessageIds: [...new Set([...state.readMessageIds, ...ids])] })),
  toggleFavoriteService: (id) => set((state) => ({
    favoriteServices: state.favoriteServices.includes(id) ? state.favoriteServices.filter((item) => item !== id) : [...state.favoriteServices, id]
  })),
  visitService: (id) => set((state) => ({ recentServices: [id, ...state.recentServices.filter((item) => item !== id)].slice(0, 6) })),
  resetSessionUi: () => set({ headerPanel: null, sidebarOverlayOpen: false, workspaceOpen: false, favoriteServices: [], recentServices: [], readMessageIds: [] }),
  openSidebar: () => set({ sidebarOverlayOpen: true, workspaceOpen: false }),
  closeSidebar: () => set({ sidebarOverlayOpen: false }),
  toggleWorkspace: () => set((state) => ({
    workspaceOpen: !state.workspaceOpen,
    sidebarOverlayOpen: false
  })),
  closeWorkspace: () => set({ workspaceOpen: false })
}));
