import { useMemo } from "react";
import { ApiError, resourcePath, type RequestOptions } from "@/api/client";
import { matchesContract } from "@/api/validation";
import { validators, type PipelineDraftSpec } from "@/api/devopsContract";
import { useAccountApi } from "../auth/SessionProvider";
import { useProduct } from "../platform/ProductProvider";

export function pipelineDraft(repositoryBindingId: string): PipelineDraftSpec { return { repositoryBindingId, triggerPolicy: "CHANGE", verificationProfile: "GO_1_26_OFFLINE_V1", dependencyEgress: "NONE", reporterPolicy: "CHANGE_CHECK_V1" }; }
export function useDevopsApi() {
  const api = useAccountApi();
  const { canMutate, assertWritable } = useProduct("DEVOPS");
  return useMemo(() => ({
    canMutate,
    read<T>(kind: string, collection: string, id: string, signal?: AbortSignal) {
      return api.request<T>(validators, kind, `/api/devops/v1/${collection}/${resourcePath(id)}`, { signal });
    },
    fetch<T>(kind: string, path: string, signal?: AbortSignal) {
      return api.request<T>(validators, kind, "/api/devops/v1/" + path, { signal });
    },
    command<T>(responseKind: string, path: string, options: RequestOptions, requestKind?: string) {
      assertWritable();
      if (requestKind && !matchesContract(validators, requestKind, options.body)) throw new ApiError("INPUT");
      return api.request<T>(validators, responseKind, "/api/devops/v1/" + path, options);
    }
  }), [api, canMutate, assertWritable]);
}
