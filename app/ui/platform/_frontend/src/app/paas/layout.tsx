import type { ReactNode } from "react";
import { ProductGate } from "@/features/platform/ProductGate";
import { InspectedResources } from "@/features/resources/InspectedResources";
export default function Layout({ children }: { children: ReactNode }) { return <ProductGate id="APPLICATION_PAAS"><InspectedResources>{children}</InspectedResources></ProductGate>; }
