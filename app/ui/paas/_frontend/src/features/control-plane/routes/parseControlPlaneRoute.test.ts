import { describe, expect, it } from "vitest";
import { parseControlPlaneRoute } from "./parseControlPlaneRoute";

describe("parseControlPlaneRoute", () => {
  it.each([
    [undefined, "overview"],
    [[], "overview"],
    [["catalog"], "catalog"],
    [["quotas"], "quotas"],
    [["installations"], "installations"],
    [["regions"], "regions"],
    [["unknown"], "overview"]
  ] as const)("maps %j to %s", (segments, section) => {
    expect(parseControlPlaneRoute(segments ? [...segments] : undefined)).toEqual({ section });
  });
});
