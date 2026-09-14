"use client";

import { createContext, useContext, useEffect, useRef, useState, useTransition, type ComponentProps, type ReactNode } from "react";
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
  contentFallbackVisible: boolean;
  navigate(href: string, options?: NavigationOptions): void;
};

export const ROUTE_CONTENT_FALLBACK_DELAY_MS = 200;

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
  const requestSequence = useRef(0);
  const [destination, setDestination] = useState<{ href: string; requestId: number } | null>(null);
  const [fallbackRequestId, setFallbackRequestId] = useState<number | null>(null);
  const currentHref = consoleRouteHref(selection);
  const pendingDestination = isPending ? destination : null;
  const pendingHref = pendingDestination?.href ?? null;
  const pendingRequestId = pendingDestination?.requestId ?? null;
  const contentFallbackVisible = pendingRequestId !== null && fallbackRequestId === pendingRequestId;

  // Navigation acknowledgement is immediate in the Header. A page-sized
  // fallback is intentionally deferred so cached and local routes can commit
  // atomically instead of flashing a skeleton for one or two frames.
  useEffect(() => {
    if (pendingRequestId === null) return;
    const timer = window.setTimeout(() => setFallbackRequestId(pendingRequestId), ROUTE_CONTENT_FALLBACK_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [pendingRequestId]);

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
      setDestination({ href: target, requestId: ++requestSequence.current });
      startTransition(() => {
        const navigate = options?.replace ? router.replace : router.push;
        // ContentPage owns its scroll viewport and route-position memory.
        // Next's document scroll handling otherwise advances that viewport by
        // its top inset, visually erasing the shared header/content gutter.
        navigate(href, { scroll: options?.scroll ?? false });
      });
    };
    if (target.split("#")[0] === committed.split("#")[0]) proceed();
    else requestLeave(proceed);
  }

  return <NavigationContext.Provider value={{ selection, currentHref, pendingHref, pendingSelection: pendingHref ? parseControlPlanePathname(pendingHref.split(/[?#]/)[0] ?? "") : null, contentFallbackVisible, navigate }}>
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
