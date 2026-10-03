import { describe, expect, it } from "vitest";
import type { AuthorizationProfileAction, AuthorizationProfileEntry } from "./accounts";
import { reviewServiceTemplateProfile, type ServiceRoleTemplate } from "./serviceAuthorization";

const template: ServiceRoleTemplate = {
  id: "managedservice.installation-reader",
  version: 1,
  contentDigest: `sha256:${"8".repeat(64)}`,
  spec: {
    product: "managedservice",
    servicePurpose: "PAAS",
    roleName: "ManagedServiceInstallationReader",
    roleDescription: "Read one consented installation.",
    policyVersion: { policyId: "system.reader", versionId: "version-reader-v1", contentDigest: `sha256:${"9".repeat(64)}` },
    workloads: [{
      resourceKind: "SERVICE_INSTALLATION",
      bindAction: "managedservice.service-installation.service-role.bind",
      unbindAction: "managedservice.service-installation.service-role.unbind"
    }],
    maxSessionDurationSeconds: 900
  },
  status: "ACTIVE"
};

const action = (name: string): AuthorizationProfileAction => ({
  action: name,
  resourceKind: "SERVICE_INSTALLATION",
  scope: "TENANT" as const,
  subjectTypes: ["USER"],
  resourceShapes: [{ mode: "INSTANCE" as const, prefixAllowed: false }]
});

const profile: AuthorizationProfileEntry = {
  profile: {
    product: "managedservice",
    revision: 4,
    callingService: "PAAS",
    actions: [action(template.spec.workloads[0]!.bindAction), action(template.spec.workloads[0]!.unbindAction)]
  },
  contentDigest: `sha256:${"2".repeat(64)}`
};

describe("service template and AuthorizationProfile release compatibility", () => {
  it("requires the exact product, purpose, USER login-session Actions and instance resource shape", () => {
    expect(reviewServiceTemplateProfile(template, profile)).toEqual({ compatible: true, checks: [
      { id: "product", passed: true },
      { id: "servicePurpose", passed: true },
      { id: "bindAction", action: template.spec.workloads[0]!.bindAction, resourceKind: "SERVICE_INSTALLATION", passed: true },
      { id: "unbindAction", action: template.spec.workloads[0]!.unbindAction, resourceKind: "SERVICE_INSTALLATION", passed: true }
    ] });
  });

  it.each<[string, AuthorizationProfileEntry]>([
    ["different product", { ...profile, profile: { ...profile.profile, product: "paas" } }],
    ["different purpose", { ...profile, profile: { ...profile.profile, callingService: "IAM" } }],
    ["missing unbind Action", { ...profile, profile: { ...profile.profile, actions: profile.profile.actions.slice(0, 1) } }],
    ["ROLE-expanded bind Action", { ...profile, profile: { ...profile.profile, actions: [{ ...profile.profile.actions[0]!, subjectTypes: ["USER", "ROLE"] }, profile.profile.actions[1]!] } }],
    ["access-key bind Action", { ...profile, profile: { ...profile.profile, actions: [{ ...profile.profile.actions[0]!, userAuthenticationMethods: ["ACCESS_KEY"] }, profile.profile.actions[1]!] } }]
  ])("fails closed for %s", (_name, changed) => {
    expect(reviewServiceTemplateProfile(template, changed).compatible).toBe(false);
  });
});
