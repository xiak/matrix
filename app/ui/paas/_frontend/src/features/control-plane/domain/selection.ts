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
export type ServiceView = typeof serviceViews[keyof typeof serviceViews][number] | "specifications";

// Published specifications use the same authorized offerings as the catalog.
// Only operational product pages require the account's activation state.
export function productWorkspaceFor(selection: ControlPlaneRouteSelection) {
  return selection.section === "catalog" && selection.view === "specifications" ? undefined : selection.product;
}

export function hrefInRegion(href: string, regionId?: string): string {
  if (!regionId || regionId === "all") return href;
  const url = new URL(href, "https://matrix.invalid");
  url.searchParams.set("region", regionId);
  return url.pathname + url.search + url.hash;
}

export function consoleRouteHref({ section, view, product }: ControlPlaneRouteSelection): string {
  if (product) {
    const page = section === "installations" ? "instances/" : section === "quotas" ? "quotas/" : view === "specifications" ? "specifications/" : "";
    return `/console/products/${product}/${page}`;
  }
  return section === "overview" ? "/console/" : `/console/${section}/${view ? `${view}/` : ""}`;
}
