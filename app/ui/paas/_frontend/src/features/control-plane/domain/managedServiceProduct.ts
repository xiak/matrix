export const managedServiceProducts = [
  {
    id: "postgresql",
    offeringId: "postgresql-18",
    contractProductId: "managedservice.postgresql"
  },
  {
    id: "mysql",
    offeringId: "mysql-8.4",
    contractProductId: "managedservice.mysql"
  },
  {
    id: "elasticsearch",
    offeringId: "elasticsearch-8.19",
    contractProductId: "managedservice.elasticsearch"
  },
  {
    id: "rabbitmq",
    offeringId: "rabbitmq-4.1",
    contractProductId: "managedservice.rabbitmq"
  }
] as const;

export type ManagedServiceProductId = typeof managedServiceProducts[number]["id"];

export function isManagedServiceProductId(value: string): value is ManagedServiceProductId {
  return managedServiceProducts.some((product) => product.id === value);
}

export function managedServiceProduct(id: ManagedServiceProductId) {
  return managedServiceProducts.find((product) => product.id === id)!;
}
