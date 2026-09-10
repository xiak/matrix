"use client";
import type { ReactNode } from "react";
import { UnsavedChangesProvider } from "@ui/xiak";
import { useSession } from "../auth/SessionProvider";
import { Login } from "../auth/Login";
import { ProductProvider } from "./ProductProvider";
import { NavigationProvider } from "./Navigation";
import { PlatformShell } from "./PlatformShell";

export function PlatformRoot({ children }: { children: ReactNode }) {
  const session = useSession();
  if (!session) return <Login />;
  return <ProductProvider key={session.id}><UnsavedChangesProvider><NavigationProvider><PlatformShell>{children}</PlatformShell></NavigationProvider></UnsavedChangesProvider></ProductProvider>;
}
