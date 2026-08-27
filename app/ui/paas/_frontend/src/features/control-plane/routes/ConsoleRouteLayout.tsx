"use client";

import type { ReactNode } from "react";
import { usePathname } from "next/navigation";
import { ConsoleShellRenderer } from "../renderers/ConsoleShellRenderer";
import { parseControlPlanePathname } from "./parseControlPlaneRoute";

export function ConsoleRouteLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname();

  return (
    <>
      <ConsoleShellRenderer selection={parseControlPlanePathname(pathname)} />
      {children}
    </>
  );
}
