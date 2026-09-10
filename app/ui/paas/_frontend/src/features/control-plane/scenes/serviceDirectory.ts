import type { ConsoleSection, ServiceView } from "../domain/selection";
import type { ConsoleNavigationItemScene, ExperienceIconKind, NavigationIconKind } from "./consoleScene";

// Categories help discovery; only services with an owned workspace are entries.
// Features such as pipelines, alerts and log topics stay inside their service.
export const serviceCategories = ["infrastructure", "applications", "databases", "storage", "delivery", "management"] as const;
export type ServiceCategory = typeof serviceCategories[number];

export const serviceDirectory = [
  { id: "regions", category: "infrastructure", group: "foundation", icon: "foundation", href: "/console/regions/", sections: ["regions"] },
  { id: "applications", category: "applications", group: "hosting", icon: "paas", href: "/console/applications/", sections: ["applications"] },
  { id: "postgresql", category: "databases", group: "relational", icon: "paas", href: "/console/installations/", sections: ["catalog", "quotas", "installations"] },
  { id: "logs", category: "storage", group: "logData", icon: "observability", href: "/console/logs/", sections: ["logs"] },
  { id: "devops", category: "delivery", group: "delivery", icon: "devops", href: "/console/devops/", sections: ["devops"] },
  { id: "monitoring", category: "delivery", group: "monitoring", icon: "observability", href: "/console/observability/", sections: ["observability"] },
  { id: "iam", category: "management", group: "identity", icon: "security", href: "/console/access/", sections: ["access"] }
] as const satisfies ReadonlyArray<{ id: string; category: ServiceCategory; group: string; icon: ExperienceIconKind; href: string; sections: readonly ConsoleSection[] }>;

export type ServiceId = typeof serviceDirectory[number]["id"];
export type ServiceDirectoryItem = typeof serviceDirectory[number] & {
  label: string;
  description: string;
  categoryLabel: string;
  groupLabel: string;
  keywords: readonly string[];
};

type ServicePage = { id: string; section: ConsoleSection; view?: ServiceView; icon: NavigationIconKind; group?: ConsoleNavigationItemScene["group"] };
export const serviceNavigation = {
  regions: [{ id: "regions", section: "regions", icon: "region" }],
  applications: [{ id: "applications", section: "applications", icon: "resources" }],
  postgresql: [
    { id: "installations", section: "installations", icon: "installation" },
    { id: "catalog", section: "catalog", icon: "catalog" },
    { id: "quotas", section: "quotas", icon: "quota" }
  ],
  devops: [
    { id: "devops", section: "devops", icon: "overview" },
    { id: "pipelines", section: "devops", view: "pipelines", icon: "pipeline" },
    { id: "environments", section: "devops", view: "environments", icon: "resources" }
  ],
  monitoring: [
    { id: "observability", section: "observability", icon: "overview" },
    { id: "health", section: "observability", view: "health", icon: "observability" },
    { id: "alerts", section: "observability", view: "alerts", icon: "operations" }
  ],
  logs: [
    { id: "logs", section: "logs", icon: "overview" },
    { id: "search", section: "logs", view: "search", icon: "catalog" },
    { id: "topics", section: "logs", view: "topics", icon: "resources" },
    { id: "collection", section: "logs", view: "collection", icon: "operations" }
  ],
  iam: [
    { id: "access", section: "access", icon: "overview" },
    { id: "users", section: "access", view: "users", icon: "users", group: "identity" },
    { id: "groups", section: "access", view: "groups", icon: "users", group: "identity" },
    { id: "federations", section: "access", view: "federations", icon: "tenants", group: "identity" },
    { id: "policies", section: "access", view: "policies", icon: "policy", group: "authorization" },
    { id: "simulator", section: "access", view: "simulator", icon: "policy", group: "authorization" },
    { id: "roles", section: "access", view: "roles", icon: "access", group: "authorization" },
    { id: "providers", section: "access", view: "providers", icon: "sso", group: "identityProviders" },
    { id: "user-sso", section: "access", view: "user-sso", icon: "sso", group: "identityProviders" },
    { id: "keys", section: "access", view: "keys", icon: "key", group: "security" },
    { id: "settings", section: "access", view: "settings", icon: "settings", group: "security" },
    { id: "tenants", section: "access", view: "tenants", icon: "tenants", group: "administration" }
  ]
} as const satisfies Record<ServiceId, readonly ServicePage[]>;
export type ServicePageId = typeof serviceNavigation[ServiceId][number]["id"];

export function serviceForSection(section: ConsoleSection) {
  return serviceDirectory.find((service) => (service.sections as readonly ConsoleSection[]).includes(section));
}

export function matchesService(service: ServiceDirectoryItem, query: string): boolean {
  const normalize = (value: string) => value.normalize("NFKC").toLowerCase();
  const words = normalize(query).trim().split(/\s+/).filter(Boolean);
  const text = normalize([service.label, service.description, service.categoryLabel, service.groupLabel, ...service.keywords].join(" "));
  return words.every((word) => text.includes(word));
}
