import { serviceViews, type ControlPlaneRouteSelection, type ServiceView } from "../domain/selection";

const known = new Set([
  "messages",
  "resources",
  "applications",
  "operations",
  "catalog",
  "quotas",
  "installations",
  "regions",
  "devops",
  "observability",
  "access",
  "logs"
]);

export function parseControlPlaneRoute(
  segments?: string[]
): ControlPlaneRouteSelection {
  const segment = segments?.[0];
  if (segment && known.has(segment)) {
    const section = segment as ControlPlaneRouteSelection["section"];
    const view = segments?.[1];
    const views: readonly string[] = section in serviceViews ? serviceViews[section as keyof typeof serviceViews] : [];
    return view && views.includes(view) ? { section, view: view as ServiceView } : { section };
  }
  return { section: "overview" };
}

export function parseControlPlanePathname(
  pathname: string
): ControlPlaneRouteSelection {
  const segments = pathname.split("/").filter(Boolean);
  if (segments[0] !== "console") return { section: "overview" };
  return parseControlPlaneRoute(segments.slice(1));
}
