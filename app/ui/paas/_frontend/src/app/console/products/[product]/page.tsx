import { managedServiceProducts } from "@/features/control-plane/domain/managedServiceProduct";

export function generateStaticParams() {
  return managedServiceProducts.map(({ id }) => ({ product: id }));
}

export const dynamicParams = false;

export default function Page() { return null; }
