import { accountAccessViews } from "@/features/auth/domain/accounts";

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
  | "access";

export type ControlPlaneRouteSelection = {
  section: ConsoleSection;
  view?: ServiceView;
};

// The same route contract drives static export and service-local navigation.
export const serviceViews = {
  access: accountAccessViews,
  devops: ["pipelines", "environments"],
  observability: ["health", "alerts"],
  logs: ["search", "topics", "collection"]
} as const;
export type ServiceView = typeof serviceViews[keyof typeof serviceViews][number];

export function consoleRouteHref({ section, view }: ControlPlaneRouteSelection): string {
  return section === "overview" ? "/console/" : `/console/${section}/${view ? `${view}/` : ""}`;
}
