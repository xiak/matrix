import type { Metadata } from "next";
import type { ReactNode } from "react";
import { AppearanceProvider } from "@/preferences/AppearanceProvider";
import { SessionProvider } from "@/features/auth/SessionProvider";
import { PlatformRoot } from "@/features/platform/PlatformRoot";
import "@/styles/globals.css";

export const metadata: Metadata = { title: "Matrix Cloud · Private Cloud", description: "Matrix private-cloud platform", icons: { icon: "/brand/favicon.svg" } };
export default function RootLayout({ children }: { children: ReactNode }) {
  return <html lang="zh-CN" suppressHydrationWarning><body><AppearanceProvider><SessionProvider><PlatformRoot>{children}</PlatformRoot></SessionProvider></AppearanceProvider></body></html>;
}
