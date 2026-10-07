import { serviceViews } from "@/features/control-plane/domain/selection";

export function generateStaticParams() {
  return serviceViews.observability.map((view) => ({ view }));
}

export const dynamicParams = false;

export default function Page() { return null; }
