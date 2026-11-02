import type { ElasticsearchReference } from "./resources";

// One UI registration supplies static routes, discovery and product presentation.
export const managedServiceProducts = [
  { id: "postgresql", offeringId: "postgresql-18", category: "databases", group: "relational", icon: "paas", glyph: "database" },
  { id: "mysql", offeringId: "mysql-8.4", category: "databases", group: "relational", icon: "paas", glyph: "database" },
  { id: "elasticsearch", offeringId: "elasticsearch-8.19", category: "analytics", group: "searchAnalytics", icon: "observability", glyph: "search" },
  { id: "rabbitmq", offeringId: "rabbitmq-4.1", category: "middleware", group: "messageQueue", icon: "paas", glyph: "messages" },
  { id: "logstash", offeringId: "logstash-8.19", category: "analytics", group: "logData", icon: "observability", glyph: "logs" },
  { id: "kibana", offeringId: "kibana-8.19", connectionHint: "kibanaLoginHint", category: "analytics", group: "searchAnalytics", icon: "observability", glyph: "search" },
  { id: "redis", offeringId: "redis-8.2", connectionHint: "redisConnectionHint", category: "databases", group: "cache", icon: "paas", glyph: "database" }
] as const;

export type ManagedServiceProductId = typeof managedServiceProducts[number]["id"];

export function isManagedServiceProductId(value: string): value is ManagedServiceProductId {
  return managedServiceProducts.some((product) => product.id === value);
}

export function managedServiceProduct(id: ManagedServiceProductId) {
  return managedServiceProducts.find((product) => product.id === id)!;
}

// A frozen dependency contains only an exact resource identity and observation.
// Reading or selecting it is not evidence of permission to use it.
export function validElasticsearchReference(value: unknown, installationId: string): value is ElasticsearchReference {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const wire = value as Record<string, unknown>;
  return Object.keys(wire).length === 2 && typeof wire.installationId === "string" &&
    /^[a-z0-9][a-z0-9._-]{0,61}[a-z0-9]$/.test(wire.installationId) && wire.installationId !== installationId &&
    typeof wire.resourceVersion === "number" && Number.isSafeInteger(wire.resourceVersion) && wire.resourceVersion > 0;
}
