import type { ManagedServiceProductId } from "../domain/managedServiceProduct";
import type { ConsoleSection, ControlPlaneRouteSelection, ServiceView } from "../domain/selection";
import type { ConsoleNavigationItemScene, ExperienceIconKind, NavigationIconKind } from "./consoleScene";

// Categories help discovery; only services with an owned workspace are entries.
// Features such as pipelines, alerts and log topics stay inside their service.
export const serviceCategories = ["infrastructure", "applications", "databases", "analytics", "middleware", "delivery", "security", "management"] as const;
export type ServiceCategory = typeof serviceCategories[number];

export const serviceDirectory = [
  { id: "regions", discovery: "preview", category: "infrastructure", group: "foundation", icon: "foundation", href: "/console/regions/", sections: ["regions"] },
  { id: "applications", discovery: "platform", category: "applications", group: "hosting", icon: "paas", href: "/console/applications/", sections: ["applications"] },
  { id: "postgresql", discovery: "managed", category: "databases", group: "relational", icon: "paas", href: "/console/products/postgresql/", sections: ["catalog", "quotas", "installations"] },
  { id: "mysql", discovery: "managed", category: "databases", group: "relational", icon: "paas", href: "/console/products/mysql/", sections: ["catalog", "quotas", "installations"] },
  { id: "elasticsearch", discovery: "managed", category: "analytics", group: "searchAnalytics", icon: "observability", href: "/console/products/elasticsearch/", sections: ["catalog", "quotas", "installations"] },
  { id: "rabbitmq", discovery: "managed", category: "middleware", group: "messageQueue", icon: "paas", href: "/console/products/rabbitmq/", sections: ["catalog", "quotas", "installations"] },
  { id: "devops", discovery: "preview", category: "delivery", group: "delivery", icon: "devops", href: "/console/devops/", sections: ["devops"] },
  { id: "monitoring", discovery: "preview", category: "management", group: "monitoring", icon: "observability", href: "/console/observability/", sections: ["observability"] },
  { id: "logs", discovery: "preview", category: "management", group: "logData", icon: "observability", href: "/console/logs/", sections: ["logs"] },
  { id: "audit", discovery: "platform", category: "management", group: "governance", icon: "security", href: "/console/audit/", sections: ["audit"] },
  { id: "iam", discovery: "platform", category: "security", group: "identity", icon: "security", href: "/console/access/", sections: ["access"] }
] as const satisfies ReadonlyArray<{ id: string; discovery: "platform" | "managed" | "preview"; category: ServiceCategory; group: string; icon: ExperienceIconKind; href: string; sections: readonly ConsoleSection[] }>;

export type ServiceId = typeof serviceDirectory[number]["id"];
export type ServiceDirectoryItem = typeof serviceDirectory[number] & {
  label: string;
  description: string;
  categoryLabel: string;
  groupLabel: string;
  keywords: readonly string[];
};

type ServicePage = { id: string; section: ConsoleSection; view?: ServiceView; product?: ManagedServiceProductId; icon: NavigationIconKind; group?: ConsoleNavigationItemScene["group"] };

function managedProductPages(product: ManagedServiceProductId) {
  return [
    { id: "product-overview", section: "catalog", product, icon: "overview" },
    { id: "product-instances", section: "installations", product, icon: "installation" },
    { id: "product-quotas", section: "quotas", product, icon: "quota" }
  ] as const;
}

export const serviceNavigation = {
  regions: [{ id: "regions", section: "regions", icon: "region" }],
  applications: [{ id: "applications", section: "applications", icon: "resources" }],
  postgresql: managedProductPages("postgresql"),
  mysql: managedProductPages("mysql"),
  elasticsearch: managedProductPages("elasticsearch"),
  rabbitmq: managedProductPages("rabbitmq"),
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
  audit: [{ id: "audit", section: "audit", icon: "audit" }],
  iam: [
    { id: "access", section: "access", icon: "overview" },
    { id: "users", section: "access", view: "users", icon: "users", group: "identity" },
    { id: "groups", section: "access", view: "groups", icon: "users", group: "identity" },
    { id: "federations", section: "access", view: "federations", icon: "tenants", group: "identity" },
    { id: "policies", section: "access", view: "policies", icon: "policy", group: "authorization" },
    { id: "policy-configuration", section: "access", view: "policy-configuration", icon: "policy", group: "authorization" },
    { id: "access-diagnosis", section: "access", view: "access-diagnosis", icon: "access", group: "authorization" },
    { id: "roles", section: "access", view: "roles", icon: "access", group: "authorization" },
    { id: "service-authorizations", section: "access", view: "service-authorizations", icon: "access", group: "authorization" },
    { id: "providers", section: "access", view: "providers", icon: "sso", group: "identityProviders" },
    { id: "user-sso", section: "access", view: "user-sso", icon: "sso", group: "identityProviders" },
    { id: "keys", section: "access", view: "keys", icon: "key", group: "security" },
    { id: "sessions", section: "access", view: "sessions", icon: "sessions", group: "security" },
    { id: "access-analysis", section: "access", view: "access-analysis", icon: "audit", group: "security" },
    { id: "security-reports", section: "access", view: "security-reports", icon: "audit", group: "security" },
    { id: "settings", section: "access", view: "settings", icon: "settings", group: "security" },
    { id: "authorization-profiles", section: "access", view: "authorization-profiles", icon: "catalog", group: "administration" },
    { id: "tenants", section: "access", view: "tenants", icon: "tenants", group: "administration" }
  ]
} as const satisfies Record<ServiceId, readonly ServicePage[]>;
export type ServicePageId = typeof serviceNavigation[ServiceId][number]["id"];

export function serviceForSection(section: ConsoleSection) {
  return serviceDirectory.find((service) => (service.sections as readonly ConsoleSection[]).includes(section));
}

export function serviceForSelection(selection: ControlPlaneRouteSelection) {
  if (selection.product) return serviceDirectory.find((service) => service.id === selection.product);
  return serviceForSection(selection.section);
}

export function matchesService(service: ServiceDirectoryItem, query: string): boolean {
  const normalize = (value: string) => value.normalize("NFKC").toLowerCase();
  const words = normalize(query).trim().split(/\s+/).filter(Boolean);
  const text = normalize([service.label, service.description, service.categoryLabel, service.groupLabel, ...service.keywords].join(" "));
  return words.every((word) => text.includes(word));
}
