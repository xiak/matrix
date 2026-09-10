"use client";
import { useEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { ApiError, resourcePath } from "@/api/client";
import type { Pipeline, PipelineActivation, PipelineRevision, RepositoryBinding, SourceConnection } from "@/api/devopsContract";
import { Badge, Card, FormField, Input, PageSkeleton, useUnsavedChanges } from "@ui/xiak";
import { ResourceFacts } from "../resources/ResourceFacts";
import { ResourceCommand } from "../resources/ResourceCommand";
import { RequestFeedback } from "../platform/RequestFeedback";
import { useDevopsApi, pipelineDraft } from "./DevopsApi";
import { sourceIsFresh, useSourceFreshness } from "./SourceDetails";
import styles from "../platform/Workspace.module.css";

export function PipelineDetails({ value, update }: { value: Pipeline; update(value: Pipeline): void }) {
  const api = useDevopsApi(); const t = useTranslations("Devops"); const c = useTranslations("Collection");
  const d = useTranslations("Draft");
  const field = useRef<HTMLInputElement>(null);
  const [bindingId, setBindingId] = useState(value.draft.spec.repositoryBindingId);
  type Evidence = { revision?: PipelineRevision; binding: RepositoryBinding; connection: SourceConnection };
  const [observation, setObservation] = useState<{ api: typeof api; value: Pipeline; evidence?: Evidence; error?: unknown }>();
  // Old successful evidence cannot authorize a new resource or a failed reread.
  const current = observation?.api === api && observation.value === value ? observation : undefined;
  const evidence = current?.evidence;
  const error = current?.error;
  useUnsavedChanges({ dirty: bindingId !== value.draft.spec.repositoryBindingId, busy: false, focusRef: field, copy: { title: d("title"), description: d("description"), stay: d("stay"), leave: d("leave"), close: d("close"), busyTitle: d("busyTitle"), busyDescription: d("busyDescription"), failure: d("failure"), retry: d("retry") } });
  useEffect(() => {
    const controller = new AbortController();
    async function read() {
      const binding = await api.read<RepositoryBinding>("RepositoryBinding", "repository-bindings", value.draft.spec.repositoryBindingId, controller.signal);
      if (binding.metadata.id !== value.draft.spec.repositoryBindingId || binding.projectId !== value.projectId) throw new ApiError("CONTRACT");
      const connection = await api.read<SourceConnection>("SourceConnection", "source-connections", binding.spec.sourceConnectionId, controller.signal);
      if (connection.metadata.id !== binding.spec.sourceConnectionId) throw new ApiError("CONTRACT");
      const revision = value.activeRevision ? await api.fetch<PipelineRevision>("PipelineRevision", "pipelines/" + resourcePath(value.metadata.id) + "/revisions/" + resourcePath(value.activeRevision.id), controller.signal) : undefined;
      if (revision && (revision.pipelineId !== value.metadata.id || revision.id !== value.activeRevision?.id || revision.contentDigest !== value.activeRevision.contentDigest)) throw new ApiError("CONTRACT");
      if (!controller.signal.aborted) setObservation({ api, value, evidence: { binding, connection, revision } });
    }
    void read().catch(cause => { if (!controller.signal.aborted) setObservation({ api, value, error: cause }); });
    return () => controller.abort();
  }, [api, value]);
  const fresh = useSourceFreshness(evidence ? [evidence.binding, evidence.connection] : []);
  const sourceReady = Boolean(evidence && fresh && evidence.binding.status.health === "READY" && evidence.connection.status.health === "READY");
  return <div className={styles.stack}><Card><Card.Body className={styles.stack}>
    <ResourceFacts rows={[[c("id"), value.metadata.id], [t("projectId"), value.projectId], [t("bindingId"), value.draft.spec.repositoryBindingId], [t("profile"), value.draft.spec.verificationProfile], [t("activeRevision"), value.activeRevision?.id ?? t("noRevision")], [c("version"), value.metadata.resourceVersion]]} />
    <RequestFeedback error={error} />
    {!evidence && !error ? <PageSkeleton label={t("sourceHealth")} layout="cards" /> : <Badge status={sourceReady ? "success" : "warning"}>{t(sourceReady ? "health.READY" : "health.STALE")}</Badge>}
    <div><ResourceCommand label={t("activate")} disabled={!api.canMutate || !sourceReady} run={async idempotencyKey => {
      if (!evidence || !sourceIsFresh(evidence.binding) || !sourceIsFresh(evidence.connection)) throw new ApiError("UNAVAILABLE");
      const result = await api.command<PipelineActivation>("PipelineActivation", "pipelines/" + resourcePath(value.metadata.id) + "/activate", { method: "POST", version: value.metadata.resourceVersion, idempotencyKey });
      if (result.pipeline.metadata.id !== value.metadata.id || result.revision.pipelineId !== value.metadata.id) throw new ApiError("CONTRACT");
      update(result.pipeline);
    }} /></div>
    <FormField label={t("bindingId")}><Input ref={field} value={bindingId} disabled={!api.canMutate} onChange={event => setBindingId(event.target.value)} /></FormField><div><ResourceCommand label={t("updateDraft")} disabled={!api.canMutate || !bindingId || bindingId === value.draft.spec.repositoryBindingId} run={async idempotencyKey => { update(await api.command<Pipeline>("Pipeline", "pipelines/" + resourcePath(value.metadata.id) + "/draft", { method: "PUT", version: value.metadata.resourceVersion, idempotencyKey, body: { draft: pipelineDraft(bindingId) } }, "UpdatePipelineDraftRequest")); }} /></div>
  </Card.Body></Card>
  {evidence?.revision ? <Card><Card.Header><strong>{t("activeRevision")}</strong></Card.Header><Card.Body className={styles.stack}><ResourceFacts rows={[[c("id"), evidence.revision.id], [t("steps"), evidence.revision.spec.steps.map(step => step.kind).join(" → ")], [t("profile"), evidence.revision.spec.executorProfile]]} /><pre className={styles.code}>{JSON.stringify(evidence.revision.spec.limits, null, 2)}</pre><p className={styles.muted}>{evidence.revision.contentDigest}</p></Card.Body></Card> : null}
  </div>;
}
