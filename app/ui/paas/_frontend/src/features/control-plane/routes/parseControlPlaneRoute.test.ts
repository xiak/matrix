import { describe, expect, it } from "vitest";
import { accountAccessViews } from "@/features/auth/domain/accounts";
import {
  parseControlPlanePathname,
  parseControlPlaneRoute
} from "./parseControlPlaneRoute";

describe("parseControlPlaneRoute", () => {
  it.each(accountAccessViews)("deep links to the access workspace %s", (view) => {
    expect(parseControlPlanePathname(`/console/access/${view}/`)).toEqual({ section: "access", view });
  });
  it.each([
    ["/console/logs/search/", { section: "logs", view: "search" }],
    ["/console/logs/topics/", { section: "logs", view: "topics" }],
    ["/console/logs/collection/", { section: "logs", view: "collection" }],
    ["/console/devops/pipelines/", { section: "devops", view: "pipelines" }],
    ["/console/devops/environments/", { section: "devops", view: "environments" }],
    ["/console/observability/alerts/", { section: "observability", view: "alerts" }],
    ["/console/observability/search/", { section: "observability" }]
  ])("resolves only pages owned by the selected service: %s", (path, expected) => {
    expect(parseControlPlanePathname(path as string)).toEqual(expected);
  });
  it.each([
    [undefined, "overview"],
    [[], "overview"],
    [["catalog"], "catalog"],
    [["quotas"], "quotas"],
    [["installations"], "installations"],
    [["regions"], "regions"],
    [["messages"], "messages"],
    [["resources"], "resources"],
    [["applications"], "applications"],
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
    ["/console/messages/", "messages"],
    ["/console/resources/", "resources"],
    ["/console/applications/", "applications"],
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
