"use client";

import type { ReactNode } from "react";
import { SessionProvider } from "@/features/auth/application/SessionProvider";
import { previewIamRepository } from "@/features/auth/repositories/previewIamRepository";
import { uxPreviewEnabled } from "@/infrastructure/runtime/uxPreviewMode";

export function ApplicationProviders({ children }: { children: ReactNode }) {
  return (
    <SessionProvider repository={uxPreviewEnabled ? previewIamRepository : undefined}>
      {children}
    </SessionProvider>
  );
}
