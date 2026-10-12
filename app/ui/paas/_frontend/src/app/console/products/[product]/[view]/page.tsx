import { managedServiceProducts } from "@/features/control-plane/domain/managedServiceProduct";

export function generateStaticParams() {
  return managedServiceProducts.flatMap(({ id }) => [
    { product: id, view: "instances" },
    { product: id, view: "quotas" }
  ]);
}

export const dynamicParams = false;

export default function Page() { return null; }
