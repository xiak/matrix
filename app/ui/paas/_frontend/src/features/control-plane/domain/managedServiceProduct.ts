export const managedServiceProducts = [
  {
    id: "postgresql",
    offeringId: "postgresql-18"
  },
  {
    id: "mysql",
    offeringId: "mysql-8.4"
  },
  {
    id: "elasticsearch",
    offeringId: "elasticsearch-8.19"
  },
  {
    id: "rabbitmq",
    offeringId: "rabbitmq-4.1"
  }
] as const;

export type ManagedServiceProductId = typeof managedServiceProducts[number]["id"];

export function isManagedServiceProductId(value: string): value is ManagedServiceProductId {
  return managedServiceProducts.some((product) => product.id === value);
}

export function managedServiceProduct(id: ManagedServiceProductId) {
  return managedServiceProducts.find((product) => product.id === id)!;
}
