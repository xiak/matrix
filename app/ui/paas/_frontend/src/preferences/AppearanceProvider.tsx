"use client";

import type { ReactNode } from "react";
import { ThemeProvider } from "next-themes";
import { LocaleProvider } from "@/i18n/LocaleProvider";

export const appearanceThemes = ["dark", "mixed", "light"] as const;

export function AppearanceProvider({ children }: { children: ReactNode }) {
  return (
    <ThemeProvider attribute="data-theme" themes={[...appearanceThemes]} defaultTheme="dark" enableColorScheme={false} storageKey="matrix.theme">
      <LocaleProvider>{children}</LocaleProvider>
    </ThemeProvider>
  );
}
