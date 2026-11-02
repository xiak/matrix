// One UI registration supplies static routes, discovery and product presentation.
export const managedServiceProducts = [
  { id: "postgresql", offeringId: "postgresql-18", category: "databases", group: "relational", icon: "paas", glyph: "database" },
  { id: "mysql", offeringId: "mysql-8.4", category: "databases", group: "relational", icon: "paas", glyph: "database" },
  { id: "elasticsearch", offeringId: "elasticsearch-8.19", category: "analytics", group: "searchAnalytics", icon: "observability", glyph: "search" },
  { id: "rabbitmq", offeringId: "rabbitmq-4.1", category: "middleware", group: "messageQueue", icon: "paas", glyph: "messages" },
  { id: "logstash", offeringId: "logstash-8.19", category: "analytics", group: "logData", icon: "observability", glyph: "logs" }
] as const;

export type ManagedServiceProductId = typeof managedServiceProducts[number]["id"];

export function isManagedServiceProductId(value: string): value is ManagedServiceProductId {
  return managedServiceProducts.some((product) => product.id === value);
}

export function managedServiceProduct(id: ManagedServiceProductId) {
  return managedServiceProducts.find((product) => product.id === id)!;
}
