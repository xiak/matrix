"use client";

import { createContext, useContext, useState, useTransition, type ComponentProps, type ReactNode } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { UnsavedChangesProvider, useLeaveConfirmation } from "@ui/xiak";
import { consoleRouteHref, type ControlPlaneRouteSelection } from "../domain/selection";
import { parseControlPlanePathname } from "./parseControlPlaneRoute";

type NavigationOptions = { replace?: boolean; scroll?: boolean; onAccepted?(): void };
type ConsoleNavigationState = {
  selection: ControlPlaneRouteSelection;
  currentHref: string;
  pendingHref: string | null;
  pendingSelection: ControlPlaneRouteSelection | null;
  navigate(href: string, options?: NavigationOptions): void;
};

const NavigationContext = createContext<ConsoleNavigationState | null>(null);
const canonicalHref = (href: string) => {
  const url = new URL(href, "https://matrix.invalid");
  return `${url.pathname.replace(/\/$/, "")}/${url.search}${url.hash}`;
};

// Track the router's real transition, not a timer or a fabricated percentage.
// The provider stays mounted with the shell, including during interrupted visits.
export function ConsoleNavigationProvider({ selection, children }: { selection: ControlPlaneRouteSelection; children: ReactNode }) {
  return <UnsavedChangesProvider><ConsoleNavigationBoundary selection={selection}>{children}</ConsoleNavigationBoundary></UnsavedChangesProvider>;
}

function ConsoleNavigationBoundary({ selection, children }: { selection: ControlPlaneRouteSelection; children: ReactNode }) {
  const router = useRouter();
  const requestLeave = useLeaveConfirmation();
  const [isPending, startTransition] = useTransition();
  const [destination, setDestination] = useState<string | null>(null);
  const currentHref = consoleRouteHref(selection);
  const pendingHref = isPending ? destination : null;

  function navigate(href: string, options?: NavigationOptions) {
    const target = canonicalHref(href);
    // Read the committed URL at the interaction boundary, including entity queries.
    // The shell itself need not subscribe to every search-param change.
    const committed = typeof window !== "undefined" && /^\/console(?:\/|$)/.test(window.location.pathname)
      ? canonicalHref(window.location.pathname + window.location.search + window.location.hash)
      : currentHref;
    if (target === committed && !isPending) { options?.onAccepted?.(); return; }
    const proceed = () => {
      options?.onAccepted?.();
      setDestination(target);
      startTransition(() => {
        const navigate = options?.replace ? router.replace : router.push;
        if (options?.scroll === undefined) navigate(href);
        else navigate(href, { scroll: options.scroll });
      });
    };
    if (target.split("#")[0] === committed.split("#")[0]) proceed();
    else requestLeave(proceed);
  }

  return <NavigationContext.Provider value={{ selection, currentHref, pendingHref, pendingSelection: pendingHref ? parseControlPlanePathname(pendingHref.split(/[?#]/)[0] ?? "") : null, navigate }}>
    {children}
  </NavigationContext.Provider>;
}

export function useConsoleNavigation() {
  const navigation = useContext(NavigationContext);
  if (!navigation) throw new Error("Console navigation requires ConsoleNavigationProvider");
  return navigation;
}

// Next Link still owns prefetching, real anchor semantics and modified clicks.
// Outside a console shell the link retains its normal Next.js behavior.
export function ConsoleLink({ href, onNavigate, onAccepted, ...props }: Omit<ComponentProps<typeof Link>, "href"> & { href: string; onAccepted?(): void }) {
  const navigation = useContext(NavigationContext);
  if (!navigation || !/^\/console(?:\/|$)/.test(href)) return <Link {...props} href={href} onNavigate={(event) => {
    let cancelled = false;
    onNavigate?.({ preventDefault() { cancelled = true; event.preventDefault(); } });
    if (!cancelled) onAccepted?.();
  }} />;
  const pending = navigation.pendingHref === canonicalHref(href);
  return <Link {...props} href={href} aria-busy={pending || undefined} data-navigation-pending={pending ? "true" : undefined} onNavigate={(event) => {
    let cancelled = false;
    onNavigate?.({ preventDefault() { cancelled = true; } });
    event.preventDefault();
    if (!cancelled) navigation.navigate(href, { replace: props.replace, scroll: props.scroll, onAccepted });
  }} />;
}
