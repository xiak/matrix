"use client";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { ApiError } from "@/api/client";
import { validators, type InstalledProductList, type ProductID } from "@/api/installationContract";
import { useApi, useSession } from "../auth/SessionProvider";
import { observationLifetime, productCanMutate, validateInventory } from "./products";

type InventoryState = { status: "loading" | "ready" | "error"; value: InstalledProductList | null; receivedAt: number; error?: ApiError };
type ProductContextValue = InventoryState & { now: number; refresh(): void };
const ProductContext = createContext<ProductContextValue | null>(null);
export function ProductProvider({ children }: { children: ReactNode }) {
  const api = useApi();
  const session = useSession();
  const [revision, setRevision] = useState(0);
  const [state, setState] = useState<InventoryState>({ status: "loading", value: null, receivedAt: 0 });
  const [now, setNow] = useState(0);
  const refresh = useCallback(() => { setState({ status: "loading", value: null, receivedAt: 0 }); setRevision(value => value + 1); }, []);
  useEffect(() => {
    const controller = new AbortController();
    api.request<InstalledProductList>(validators, "InstalledProductList", "/api/platform/v1/installed-products", { signal: controller.signal, sessionId: session?.id }).then(value => {
      const inventory = validateInventory(value);
      const receivedAt = performance.now();
      if (!controller.signal.aborted) { setNow(receivedAt); setState({ status: "ready", value: inventory, receivedAt }); }
    }).catch(error => { if (!controller.signal.aborted) setState({ status: "error", value: null, receivedAt: 0, error: error instanceof ApiError ? error : new ApiError("CONTRACT") }); });
    return () => controller.abort();
  }, [api, session?.id, revision]);
  useEffect(() => {
    if (state.status !== "ready" || !state.value) return;
    const base = Date.parse(state.value.observedAt);
    const deadlines = state.value.products.map(product => state.receivedAt + observationLifetime - (base - Date.parse(product.observedAt))).filter(deadline => deadline > now);
    if (!deadlines.length) return;
    // Update only when a readiness boundary expires, never on a shell-wide clock tick.
    const timer = setTimeout(() => setNow(performance.now()), Math.max(1, Math.min(...deadlines) - performance.now() + 1));
    return () => clearTimeout(timer);
  }, [state, now]);
  const context = useMemo(() => ({ ...state, now, refresh }), [state, now, refresh]);
  return <ProductContext.Provider value={context}>{children}</ProductContext.Provider>;
}
export function useProducts() { const value = useContext(ProductContext); if (!value) throw new Error("ProductProvider is required"); return value; }
export function useProduct(id: ProductID) {
  const inventory = useProducts();
  const product = inventory.value?.products.find(item => item.id === id);
  const assertWritable = useCallback(() => {
    if (inventory.status !== "ready" || !productCanMutate(product, inventory.value!.observedAt, inventory.receivedAt, performance.now())) throw new ApiError("UNAVAILABLE");
  }, [inventory, product]);
  return { product, canMutate: inventory.status === "ready" && productCanMutate(product, inventory.value!.observedAt, inventory.receivedAt, inventory.now), assertWritable, inventory };
}
