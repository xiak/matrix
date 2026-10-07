import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";
import { ApplicationProviders } from "./providers";
import "@/styles/globals.css";

export const dynamic = "error";

export const metadata: Metadata = {
  title: "Matrix Cloud · Matrix Control Plane",
  description: "Matrix Cloud 统一云控制台",
  applicationName: "Matrix Cloud",
  icons: {
    icon: [
      { url: "/brand/favicon.svg", type: "image/svg+xml" },
      { url: "/brand/favicon.ico", sizes: "any" }
    ],
    apple: "/brand/apple-touch-icon.png"
  }
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  colorScheme: "dark light"
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html data-theme="dark" lang="zh-CN" suppressHydrationWarning>
      <body>
        <ApplicationProviders>{children}</ApplicationProviders>
      </body>
    </html>
  );
}
