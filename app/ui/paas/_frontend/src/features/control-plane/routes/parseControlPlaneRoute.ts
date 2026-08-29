import type { ControlPlaneRouteSelection } from "../domain/selection";

const known = new Set(["catalog", "quotas", "installations", "regions", "hosts", "access"]);

export function parseControlPlaneRoute(
  segments?: string[]
): ControlPlaneRouteSelection {
  const segment = segments?.[0];
  if (segment && known.has(segment)) {
    return { section: segment as ControlPlaneRouteSelection["section"] };
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
