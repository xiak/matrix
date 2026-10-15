"use client";

import type { ReactNode } from "react";
import { SessionProvider } from "@/features/auth/application/SessionProvider";
import { previewIamRepository } from "@/features/auth/repositories/previewIamRepository";
import { uxPreviewEnabled } from "@/infrastructure/runtime/uxPreviewMode";
import { AppearanceProvider } from "@/preferences/AppearanceProvider";
import { ApplicationLoadRecovery } from "./ApplicationLoadRecovery";

export function ApplicationProviders({ children }: { children: ReactNode }) {
  return (
    <AppearanceProvider><SessionProvider repository={uxPreviewEnabled ? previewIamRepository : undefined}>
      <ApplicationLoadRecovery>{children}</ApplicationLoadRecovery>
    </SessionProvider></AppearanceProvider>
  );
}
