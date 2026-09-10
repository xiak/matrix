"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { createContext, useContext, useEffect, useState, useSyncExternalStore, type ComponentProps, type ReactNode } from "react";
import { useLeaveConfirmation } from "@ui/xiak";

function navigationState() {
  let pending: string | null = null;
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const listeners = new Set<() => void>();
  const finish = () => { clearTimeout(timeout); if (pending !== null) { pending = null; listeners.forEach(listener => listener()); } };
  return {
    snapshot: () => pending,
    subscribe(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    begin(path: string) { clearTimeout(timeout); pending = path; listeners.forEach(listener => listener()); timeout = setTimeout(finish, 12000); },
    finish,
  };
}
const NavigationContext = createContext<ReturnType<typeof navigationState> | null>(null);
export function NavigationProvider({ children }: { children: ReactNode }) {
  const [state] = useState(navigationState);
  const pathname = usePathname();
  useEffect(() => { state.finish(); }, [state, pathname]);
  useEffect(() => () => state.finish(), [state]);
  return <NavigationContext.Provider value={state}>{children}</NavigationContext.Provider>;
}
export function usePendingNavigation() {
  const state = useContext(NavigationContext);
  if (!state) throw new Error("NavigationProvider is required");
  return useSyncExternalStore(state.subscribe, state.snapshot, () => null);
}
export function PlatformLink({ href, onNavigate, ...props }: ComponentProps<typeof Link> & { href: string }) {
  const state = useContext(NavigationContext);
  const router = useRouter();
  const pathname = usePathname();
  const leave = useLeaveConfirmation();
  return <Link {...props} href={href} onNavigate={event => {
    event.preventDefault();
    onNavigate?.(event);
    if (pathname.replace(/\/$/, "") === href.replace(/\/$/, "")) return;
    leave(() => { state?.begin(href); router.push(href); });
  }} />;
}
