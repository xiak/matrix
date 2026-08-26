import type { ControlPlaneRouteSelection } from "../domain/selection";

const known = new Set(["catalog", "quotas", "installations", "regions"]);

export function parseControlPlaneRoute(
  segments?: string[]
): ControlPlaneRouteSelection {
  const segment = segments?.[0];
  if (segment && known.has(segment)) {
    return { section: segment as ControlPlaneRouteSelection["section"] };
  }
  return { section: "overview" };
}
