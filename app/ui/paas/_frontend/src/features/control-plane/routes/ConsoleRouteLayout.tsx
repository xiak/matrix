"use client";

import type { ReactNode } from "react";
import { usePathname } from "next/navigation";
import { previewAccountRepository } from "@/features/auth/repositories/previewIamRepository";
import { useLocalePreference } from "@/i18n/LocaleProvider";
import { uxPreviewEnabled } from "@/infrastructure/runtime/uxPreviewMode";
import { ConsoleShellRenderer } from "../renderers/ConsoleShellRenderer";
import { previewControlPlaneRepository } from "../repositories/previewControlPlaneRepository";
import { previewExperienceSnapshotForLocale } from "../repositories/previewExperienceSnapshot";
import { parseControlPlanePathname } from "./parseControlPlaneRoute";

export function ConsoleRouteLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const { locale } = useLocalePreference();

  return (
    <>
      <ConsoleShellRenderer
        accountRepository={uxPreviewEnabled ? previewAccountRepository : undefined}
        experience={uxPreviewEnabled ? previewExperienceSnapshotForLocale(locale) : undefined}
        repository={uxPreviewEnabled ? previewControlPlaneRepository : undefined}
        selection={parseControlPlanePathname(pathname)}
      />
      {children}
    </>
  );
}
