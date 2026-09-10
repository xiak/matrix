"use client";
import { createContext, useContext, useState, type ReactNode } from "react";

type View<T> = { query: string; records: T[]; selected: string | null };
type Views = Record<string, View<unknown>>;
const Context = createContext<{ views: Views; update(key: string, action: (view: View<unknown>) => View<unknown>): void } | null>(null);
const empty: View<never> = { query: "", records: [], selected: null };

/** Bounded navigation convenience only; not a collection API or permission cache. */
export function InspectedResources({ children }: { children: ReactNode }) {
  const [views, setViews] = useState<Views>({});
  return <Context.Provider value={{ views, update(key, action) { setViews(current => ({ ...current, [key]: action(current[key] ?? empty) })); } }}>{children}</Context.Provider>;
}
export function useInspected<T>(key: string) {
  const store = useContext(Context);
  if (!store) throw new Error("InspectedResources is required");
  return [store.views[key] ?? empty, (action: (view: View<T>) => View<T>) => store.update(key, current => action(current as View<T>))] as [View<T>, (action: (view: View<T>) => View<T>) => void];
}
