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
    [["deployments"], "deployments"],
    [["regions"], "regions"],
    [["hosts"], "hosts"],
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
    ["/console/deployments/", "deployments"],
    ["/console/regions/", "regions"],
    ["/console/hosts/", "hosts"],
    ["/console/access/", "access"],
    ["/console/unknown/", "overview"],
    ["/", "overview"]
  ] as const)("maps pathname %s to %s", (pathname, section) => {
    expect(parseControlPlanePathname(pathname)).toEqual({ section });
  });
});
