import { describe, expect, it } from "vitest";
import {
  parseControlPlanePathname,
  parseControlPlaneRoute
} from "./parseControlPlaneRoute";

describe("parseControlPlaneRoute", () => {
  it.each([
    [undefined, "overview"],
    [[], "overview"],
    [["catalog"], "catalog"],
    [["quotas"], "quotas"],
    [["installations"], "installations"],
    [["regions"], "regions"],
    [["products"], "products"],
    [["resources"], "resources"],
    [["operations"], "operations"],
    [["devops"], "devops"],
    [["observability"], "observability"],
    [["access"], "access"],
    [["unknown"], "overview"]
  ] as const)("maps %j to %s", (segments, section) => {
    expect(parseControlPlaneRoute(segments ? [...segments] : undefined)).toEqual({ section });
  });

  it.each([
    ["/console/", "overview"],
    ["/console/catalog/", "catalog"],
    ["/console/quotas", "quotas"],
    ["/console/installations/", "installations"],
    ["/console/regions/", "regions"],
    ["/console/products/", "products"],
    ["/console/resources/", "resources"],
    ["/console/operations/", "operations"],
    ["/console/devops/", "devops"],
    ["/console/observability/", "observability"],
    ["/console/access/", "access"],
    ["/console/unknown/", "overview"],
    ["/", "overview"]
  ] as const)("maps pathname %s to %s", (pathname, section) => {
    expect(parseControlPlanePathname(pathname)).toEqual({ section });
  });
});
