import { ApiError, resourcePath, type RequestOptions } from "@/api/client";
import { matchesContract } from "@/api/validation";
import { validators, type Operation } from "@/api/paasContract";
import { useAccountApi } from "../auth/SessionProvider";
import { useProduct } from "../platform/ProductProvider";

export function usePaasApi() {
  const api = useAccountApi();
  const { canMutate, assertWritable } = useProduct("APPLICATION_PAAS");
  return {
    canMutate,
    read<T>(kind: string, collection: string, id: string, signal?: AbortSignal) {
      return api.request<T>(validators, kind, `/api/paas/v1/${collection}/${resourcePath(id)}`, { signal });
    },
    async command(kind: string, path: string, body: unknown, options: RequestOptions) {
      assertWritable();
      if (!matchesContract(validators, kind, body)) throw new ApiError("INPUT");
      return api.request<Operation>(validators, "Operation", "/api/paas/v1/" + path, { ...options, body });
    }
  };
}
