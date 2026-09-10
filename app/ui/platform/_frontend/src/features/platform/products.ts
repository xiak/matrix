import { ApiError } from "@/api/client";
import type { InstalledProduct, InstalledProductList, ProductID } from "@/api/installationContract";

/** Compiled presentation metadata is not product inventory. */
export const productPresentation = {
  APPLICATION_PAAS: { routeKey: "paas", path: "/paas/configuration/", pages: ["applications", "configuration", "deployments", "operations"] },
  DEVOPS: { routeKey: "devops", path: "/devops/code/", pages: ["code", "pipelines", "runs"] },
} as const;
export const observationLifetime = 120000;
export function validateInventory(value: InstalledProductList) {
  const ids = new Set<ProductID>();
  for (const product of value.products) {
    if (!Object.hasOwn(productPresentation, product.id) || ids.has(product.id) || product.routeKey !== productPresentation[product.id].routeKey || Date.parse(product.observedAt) > Date.parse(value.observedAt)) throw new ApiError("CONTRACT");
    ids.add(product.id);
  }
  return value;
}
export function productCanMutate(product: InstalledProduct | undefined, observedAt: string, receivedAt: number, now: number) {
  const reference = Date.parse(observedAt) + Math.max(0, now - receivedAt);
  return Boolean(product?.state === "READY" && !product.reason && Number.isFinite(reference) && reference - Date.parse(product.observedAt) < observationLifetime);
}
