import type { ReactNode } from "react";
import { ConsoleRouteLayout } from "@/features/control-plane/routes/ConsoleRouteLayout";

export default function ConsoleLayout({ children }: { children: ReactNode }) {
  return <ConsoleRouteLayout>{children}</ConsoleRouteLayout>;
}
