"use client";
import { createContext, useContext, useEffect, useMemo, useState, useSyncExternalStore, type ReactNode } from "react";
import { createApiSession, type ApiSession } from "@/api/client";

const ApiContext = createContext<ApiSession | null>(null);
const noSession = () => null;
export function SessionProvider({ children, client }: { children: ReactNode; client?: ApiSession }) {
  const [api] = useState(() => client ?? createApiSession());
  useEffect(() => () => api.dispose(), [api]);
  return <ApiContext.Provider value={api}>{children}</ApiContext.Provider>;
}
export function useApi() {
  const api = useContext(ApiContext);
  if (!api) throw new Error("SessionProvider is required");
  return api;
}
export function useSession() {
  const api = useApi();
  return useSyncExternalStore(api.subscribe, api.snapshot, noSession);
}
export function useAccountApi() {
  const api = useApi();
  const session = useSession();
  return useMemo(() => api.forSession(session?.id ?? ""), [api, session?.id]);
}
