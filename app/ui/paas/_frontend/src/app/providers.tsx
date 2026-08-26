"use client";

import type { ReactNode } from "react";
import { SessionProvider } from "@/features/auth/application/SessionProvider";

export function ApplicationProviders({ children }: { children: ReactNode }) {
  return <SessionProvider>{children}</SessionProvider>;
}
