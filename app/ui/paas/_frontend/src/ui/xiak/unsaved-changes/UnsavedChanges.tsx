"use client";

import { createContext, useContext, useEffect, useId, useLayoutEffect, useState, useSyncExternalStore, type ReactNode, type RefObject } from "react";
import { Button } from "../button/Button";
import { Dialog } from "../dialog/Dialog";

type LeaveAction = () => void | Promise<unknown>;
export type UnsavedChangesCopy = {
  title: string; description: string; stay: string; leave: string; close: string;
  busyTitle: string; busyDescription: string; failure: string; retry: string;
};
type DraftGuard = { dirty: boolean; busy: boolean; copy: UnsavedChangesCopy; focusRef: RefObject<HTMLElement | null> };
type Confirmation = { owner: string; draft: DraftGuard; action: LeaveAction; mode: "discard" | "busy" | "failed" };

// Only interaction metadata is registered. Feature drafts and credentials stay in their component.
function createLeaveGuard() {
  const drafts = new Map<string, DraftGuard>();
  const listeners = new Set<() => void>();
  let pending: Confirmation | null = null;
  let nested = false;
  let proceeding = false;
  const emit = () => listeners.forEach((listener) => listener());
  const active = () => [...drafts.entries()].find(([, draft]) => draft.busy) ?? [...drafts.entries()].find(([, draft]) => draft.dirty);
  function update(owner: string, draft?: DraftGuard) {
    if (draft && (draft.dirty || draft.busy)) drafts.set(owner, draft);
    else drafts.delete(owner);
    if (pending?.owner === owner) {
      if (!drafts.has(owner) || pending.mode === "busy" && !draft?.busy) pending = null;
      else if (draft) pending = { ...pending, draft, mode: draft.busy ? "busy" : pending.mode };
    }
    emit();
  }
  function run(confirmation: Confirmation) {
    pending = null;
    proceeding = true;
    emit();
    function failed() {
      const draft = drafts.get(confirmation.owner);
      if (draft) { pending = { ...confirmation, draft, mode: "failed" }; emit(); }
    }
    try {
      // Explicit cancel often calls the same guarded router. Authorize only this synchronous action.
      nested = true;
      const result = confirmation.action();
      if (result && typeof result.then === "function") void result.catch(failed).finally(() => { proceeding = false; });
      else proceeding = false;
    } catch { proceeding = false; failed(); }
    finally { nested = false; }
  }
  return {
    subscribe(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; },
    snapshot: () => pending,
    active: () => Boolean(active()),
    update,
    request(action: LeaveAction) {
      if (nested) { void action(); return; }
      if (pending || proceeding) return;
      const current = active();
      if (!current) { void action(); return; }
      const [owner, draft] = current;
      pending = { owner, draft, action, mode: draft.busy ? "busy" : "discard" };
      emit();
    },
    stay() { pending = null; emit(); },
    leave() {
      if (!pending || proceeding || pending.draft.busy) return;
      run(pending);
    }
  };
}

type LeaveGuard = ReturnType<typeof createLeaveGuard>;
const LeaveContext = createContext<LeaveGuard | null>(null);
const noConfirmation = () => null;

// Narrow public browser API contract; TS 5.9's DOM library predates Navigation.
type BrowserNavigation = EventTarget & {
  traverseTo(key: string): { committed: Promise<unknown>; finished: Promise<unknown> };
};
type TraverseEvent = Event & {
  navigationType: string; destination: { key: string; url: string; sameDocument: boolean };
};

function bindBrowserLeaveGuard(guard: LeaveGuard) {
  let listening = false;
  let allowedEntry: string | null = null;
  const navigation = (window as Window & { navigation?: BrowserNavigation }).navigation;
  function warn(event: BeforeUnloadEvent) { event.preventDefault(); event.returnValue = ""; }
  function sync() {
    const active = guard.active();
    if (active === listening) return;
    listening = active;
    if (active) window.addEventListener("beforeunload", warn);
    else window.removeEventListener("beforeunload", warn);
  }
  function traverse(event: Event) {
    const visit = event as TraverseEvent;
    if (visit.navigationType !== "traverse") return;
    if (visit.destination.key === allowedEntry) { allowedEntry = null; return; }
    if (!navigation || !guard.active() || !visit.cancelable || !visit.destination.sameDocument || !visit.destination.key) return;
    const destination = new URL(visit.destination.url);
    if (destination.origin !== window.location.origin || destination.pathname === window.location.pathname && destination.search === window.location.search) return;
    visit.preventDefault();
    guard.request(async () => {
      allowedEntry = visit.destination.key;
      try {
        const result = navigation.traverseTo(visit.destination.key);
        // Both promises can reject when a newer browser traversal interrupts this one.
        await Promise.all([result.committed, result.finished]);
      } finally { allowedEntry = null; }
    });
  }
  sync();
  const unsubscribe = guard.subscribe(sync);
  navigation?.addEventListener("navigate", traverse);
  return () => {
    unsubscribe();
    window.removeEventListener("beforeunload", warn);
    navigation?.removeEventListener("navigate", traverse);
  };
}

function LeaveConfirmation({ guard }: { guard: LeaveGuard }) {
  const confirmation = useSyncExternalStore(guard.subscribe, guard.snapshot, noConfirmation);
  if (!confirmation) return null;
  const { copy, focusRef } = confirmation.draft;
  const busy = confirmation.mode === "busy";
  return <Dialog open title={busy ? copy.busyTitle : copy.title} closeLabel={copy.close} onClose={guard.stay} fallbackFocusRef={focusRef}
    footer={<><Button variant="secondary" onClick={guard.stay}>{copy.stay}</Button>{!busy ? <Button variant="danger" onClick={guard.leave}>{confirmation.mode === "failed" ? copy.retry : copy.leave}</Button> : null}</>}>
    <p role={confirmation.mode === "failed" ? "alert" : undefined}>{busy ? copy.busyDescription : confirmation.mode === "failed" ? copy.failure : copy.description}</p>
  </Dialog>;
}

export function UnsavedChangesProvider({ children }: { children: ReactNode }) {
  const [guard] = useState(createLeaveGuard);
  useEffect(() => bindBrowserLeaveGuard(guard), [guard]);
  return <LeaveContext.Provider value={guard}>{children}<LeaveConfirmation guard={guard} /></LeaveContext.Provider>;
}

function useLeaveGuard() {
  const guard = useContext(LeaveContext);
  if (!guard) throw new Error("Unsaved changes require UnsavedChangesProvider");
  return guard;
}

/** Register committed status without subscribing the workflow or shell to confirmation state. */
export function useUnsavedChanges({ dirty, busy, copy, focusRef }: DraftGuard) {
  const guard = useLeaveGuard();
  const id = useId();
  useLayoutEffect(() => () => guard.update(id), [guard, id]);
  useLayoutEffect(() => { guard.update(id, { dirty, busy, copy, focusRef }); }, [guard, id, dirty, busy, copy, focusRef]);
  return guard.request;
}

export function useLeaveConfirmation() { return useLeaveGuard().request; }
