import { accountAccessViews } from "@/features/auth/domain/accounts";
import type { ManagedServiceProductId } from "./managedServiceProduct";

export type ConsoleSection =
  | "overview"
  | "messages"
  | "resources"
  | "applications"
  | "operations"
  | "catalog"
  | "quotas"
  | "installations"
  | "regions"
  | "devops"
  | "observability"
  | "logs"
  | "audit"
  | "access";

export type ControlPlaneRouteSelection = {
  section: ConsoleSection;
  view?: ServiceView;
  product?: ManagedServiceProductId;
};

// The same route contract drives static export and service-local navigation.
export const serviceViews = {
  access: accountAccessViews,
  devops: ["pipelines", "environments"],
  observability: ["health", "alerts"],
  logs: ["search", "topics", "collection"]
} as const;
export type ServiceView = typeof serviceViews[keyof typeof serviceViews][number];

export function consoleRouteHref({ section, view, product }: ControlPlaneRouteSelection): string {
  if (product) {
    const page = section === "installations" ? "instances/" : section === "quotas" ? "quotas/" : "";
    return `/console/products/${product}/${page}`;
  }
  return section === "overview" ? "/console/" : `/console/${section}/${view ? `${view}/` : ""}`;
}
