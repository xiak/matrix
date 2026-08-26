import { create } from "zustand";

type ConsoleUiState = {
  sidebarOverlayOpen: boolean;
  workspaceOpen: boolean;
  openSidebar(): void;
  closeSidebar(): void;
  toggleWorkspace(): void;
  closeWorkspace(): void;
};

export const useConsoleUiStore = create<ConsoleUiState>((set) => ({
  sidebarOverlayOpen: false,
  workspaceOpen: true,
  openSidebar: () => set({ sidebarOverlayOpen: true, workspaceOpen: false }),
  closeSidebar: () => set({ sidebarOverlayOpen: false }),
  toggleWorkspace: () => set((state) => ({
    workspaceOpen: !state.workspaceOpen,
    sidebarOverlayOpen: false
  })),
  closeWorkspace: () => set({ workspaceOpen: false })
}));
