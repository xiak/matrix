import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";
import { ApplicationProviders } from "./providers";
import "@xterm/xterm/css/xterm.css";
import "@/styles/globals.css";

export const dynamic = "error";

export const metadata: Metadata = {
  title: "Matrix Control Plane",
  description: "Matrix PaaS 托管服务控制台",
  applicationName: "Matrix Control Plane"
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  colorScheme: "dark"
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="zh-CN">
      <body>
        <ApplicationProviders>{children}</ApplicationProviders>
      </body>
    </html>
  );
}
