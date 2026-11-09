"use client";

import { createContext, useContext, useLayoutEffect, useRef, useState, useTransition, type ComponentProps, type ReactNode } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { X } from "lucide-react";
import { useTranslations } from "next-intl";
import { Button, Card, EmptyState, UnsavedChangesProvider, useLeaveConfirmation } from "@ui/xiak";
import { consoleRouteHref, type ControlPlaneRouteSelection } from "../domain/selection";
import { parseControlPlanePathname } from "./parseControlPlaneRoute";

type NavigationOptions = { replace?: boolean; scroll?: boolean; onAccepted?(): void };
type ConsoleNavigationState = {
  selection: ControlPlaneRouteSelection;
  currentHref: string;
  pendingHref: string | null;
  pendingSelection: ControlPlaneRouteSelection | null;
  navigationFocusKey?: string;
  navigate(href: string, options?: NavigationOptions): void;
};

const NavigationContext = createContext<ConsoleNavigationState | null>(null);
const DirectoryQueryContext = createContext<Pick<URLSearchParams, "get" | "has"> | null>(null);

export function DirectoryQueryProvider({ pendingHref, regions, selectRegion, children }: {
  pendingHref?: string | null; regions?: readonly { id: string }[]; selectRegion?(id: string): void; children: ReactNode;
}) {
  const committed = useSearchParams();
  const query = pendingHref ? new URL(pendingHref, "https://matrix.invalid").searchParams : committed;
  const region = query?.get("region");
  useLayoutEffect(() => {
    if (region && (region === "all" || regions?.some((entry) => entry.id === region))) selectRegion?.(region);
  }, [region, regions, selectRegion]);
  return <DirectoryQueryContext.Provider value={query}>{children}</DirectoryQueryContext.Provider>;
}

export function useDirectoryQuery() {
  return useContext(DirectoryQueryContext);
}

// Next observes native same-page history changes. Editing a filter replaces
// this directory entry so Back still returns to the originating overview.
export function replaceDirectoryQuery(changes: Record<string, string | null>) {
  const url = new URL(window.location.href);
  for (const [name, value] of Object.entries(changes)) {
    if (value === null) url.searchParams.delete(name);
    else url.searchParams.set(name, value);
  }
  window.history.replaceState(null, "", url.pathname + url.search + url.hash);
}
export function DirectoryScope({ label, parameter = "scope", empty = false, children }: { label?: string; parameter?: string; empty?: boolean; children: ReactNode }) {
  const t = useTranslations("Collection");
  if (!label) return <>{children}</>;
  return <><Card.Header><Button size="small" variant="secondary" aria-label={t("removeFilter", { label })}
    onClick={(event) => {
      const owner = event.currentTarget.closest("article");
      const target = owner?.querySelector<HTMLElement>('input[type="search"], [role="tab"][aria-selected="true"]') ?? document.querySelector<HTMLElement>("h1[tabindex]");
      replaceDirectoryQuery({ [parameter]: null });
      target?.focus({ preventScroll: true });
    }}>{label}<X aria-hidden="true" /></Button></Card.Header>
    {empty ? <EmptyState title={t("noMatchingItems")} /> : children}</>;
}

export function useDirectoryTab(initial: string, allowed: readonly string[]): [string, (tab: string) => void] {
  const requested = useDirectoryQuery()?.get("tab");
  const [local, setLocal] = useState(initial);
  return [requested && allowed.includes(requested) ? requested : local, (tab) => {
    setLocal(tab);
    if (requested) replaceDirectoryQuery({ tab, scope: null });
  }];
}

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
  const [destination, setDestination] = useState<{ href: string; onAccepted?(): void } | null>(null);
  const currentHref = consoleRouteHref(selection);
  // Destination identity is urgent; only route content belongs to the router
  // transition. Regional loading feedback owns its own anti-flash delay.
  const pendingHref = isPending ? destination?.href ?? null : null;
  const previousHref = useRef(currentHref);
  const focusSequence = useRef(0);
  const [committedFocusKey, setCommittedFocusKey] = useState<string>();

  // Next restores document focus when an RSC navigation commits. Announce the
  // accepted destination immediately, then focus the same stable title once
  // more after commit so keyboard focus cannot fall back to the document.
  useLayoutEffect(() => {
    if (previousHref.current === currentHref) return;
    previousHref.current = currentHref;
    focusSequence.current += 1;
    setCommittedFocusKey(`committed:${focusSequence.current}:${currentHref}`);
  }, [currentHref]);
  const navigationFocusKey = pendingHref ? `pending:${pendingHref}` : committedFocusKey;

  // Overlay and compact-navigation dismissal is an accepted-navigation side
  // effect. Run it after the destination frame has reached the DOM so closing
  // a launcher can never reveal the old page for a frame.
  useLayoutEffect(() => { destination?.onAccepted?.(); }, [destination]);

  function navigate(href: string, options?: NavigationOptions) {
    const target = canonicalHref(href);
    // Read the committed URL at the interaction boundary, including entity queries.
    // The shell itself need not subscribe to every search-param change.
    const committed = typeof window !== "undefined" && /^\/console(?:\/|$)/.test(window.location.pathname)
      ? canonicalHref(window.location.pathname + window.location.search + window.location.hash)
      : currentHref;
    if (target === committed && !isPending) { options?.onAccepted?.(); return; }
    if (target === destination?.href && isPending) { options?.onAccepted?.(); return; }
    const proceed = () => {
      // An entity query changes this client-owned workspace, not its page.
      // Next integrates native history with useSearchParams without fetching
      // another RSC tree or replacing the persistent console shell.
      if (target.split(/[?#]/)[0] === committed.split(/[?#]/)[0]) {
        if (options?.replace) window.history.replaceState(null, "", href);
        else window.history.pushState(null, "", href);
        options?.onAccepted?.();
        return;
      }
      setDestination({ href: target, onAccepted: options?.onAccepted });
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

  return <NavigationContext.Provider value={{ selection, currentHref, pendingHref, pendingSelection: pendingHref ? parseControlPlanePathname(pendingHref.split(/[?#]/)[0] ?? "") : null, navigationFocusKey, navigate }}>
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
