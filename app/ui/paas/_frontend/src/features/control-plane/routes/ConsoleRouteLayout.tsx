"use client";

import type { ReactNode } from "react";
import { usePathname } from "next/navigation";
import { previewAccountRepository } from "@/features/auth/repositories/previewIamRepository";
import { uxPreviewEnabled } from "@/infrastructure/runtime/uxPreviewMode";
import { ConsoleShellRenderer } from "../renderers/ConsoleShellRenderer";
import { previewControlPlaneRepository } from "../repositories/previewControlPlaneRepository";
import { previewExperienceSnapshot } from "../repositories/previewExperienceSnapshot";
import { parseControlPlanePathname } from "./parseControlPlaneRoute";

export function ConsoleRouteLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname();

  return (
    <>
      <ConsoleShellRenderer
        accountRepository={uxPreviewEnabled ? previewAccountRepository : undefined}
        experience={uxPreviewEnabled ? previewExperienceSnapshot : undefined}
        repository={uxPreviewEnabled ? previewControlPlaneRepository : undefined}
        selection={parseControlPlanePathname(pathname)}
      />
      {children}
    </>
  );
}
