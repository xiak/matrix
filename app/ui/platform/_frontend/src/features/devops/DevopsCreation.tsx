"use client";
import { useState } from "react";
import { useTranslations } from "next-intl";
import type { DevOpsProject, SourceConnection, RepositoryBinding, Pipeline } from "@/api/devopsContract";
import { FormField, Input } from "@ui/xiak";
import { CreationFlow } from "../resources/CreationFlow";
import { ResourceIdentityFields } from "../resources/ResourceIdentityFields";
import { ResourceFacts } from "../resources/ResourceFacts";
import { useDevopsApi, pipelineDraft } from "./DevopsApi";
import { SourceOperatorInstructions } from "./SourceOperatorInstructions";
import styles from "../platform/Workspace.module.css";

export type DevopsCollection = "projects" | "source-connections" | "repository-bindings" | "pipelines";
export type DevopsResource = DevOpsProject | SourceConnection | RepositoryBinding | Pipeline;
export const devopsKinds = { projects: "DevOpsProject", "source-connections": "SourceConnection", "repository-bindings": "RepositoryBinding", pipelines: "Pipeline" } as const;
export function DevopsCreation({ kind, label, onDone, onCancel }: { kind: DevopsCollection; label: string; onDone(): void; onCancel(): void }) {
  const t = useTranslations("Devops"); const c = useTranslations("Collection");
  const api = useDevopsApi();
  const [id, setId] = useState(""); const [name, setName] = useState("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const field = (key: keyof typeof fields, label: string, hint?: string) => <FormField key={key} label={label} hint={hint}><Input required value={fields[key] ?? ""} maxLength={key === "endpointOrigin" ? 512 : 256} onChange={event => setFields(current => ({ ...current, [key]: event.target.value }))} spellCheck={false} /></FormField>;
  const sourceSpec = { adapterId: "source-adapter-gitea-v1", endpointOrigin: fields.endpointOrigin ?? "", webhookSecretRef: fields.webhookSecretRef ?? "", fetchCredentialRef: fields.fetchCredentialRef ?? "", reportCredentialRef: fields.reportCredentialRef ?? "" };
  const extra = kind === "source-connections" ? <><p className={styles.muted}>{t("refsHint")}</p>{field("endpointOrigin", t("origin"), t("originHint"))}<div className={styles.fields}>{field("webhookSecretRef", t("webhookRef"))}{field("fetchCredentialRef", t("fetchRef"))}{field("reportCredentialRef", t("reportRef"))}</div></> :
    kind === "repository-bindings" ? <div className={styles.fields}>{field("projectId", t("projectId"))}{field("sourceConnectionId", t("connectionId"))}{field("externalRepositoryId", t("repositoryId"))}{field("repositoryPath", t("repositoryPath"))}{field("trustedDefaultBranch", t("defaultBranch"))}</div> :
    kind === "pipelines" ? <><div className={styles.fields}>{field("projectId", t("projectId"))}{field("repositoryBindingId", t("bindingId"))}</div><p className={styles.muted}>{t("readOnlyProfile")}</p><ResourceFacts rows={[[t("profile"), "GO_1_26_OFFLINE_V1"], [t("steps"), "go test ./... → go vet ./..."]]} /></> : null;
  return <CreationFlow title={c("createTitle", { resource: label })} dirty={Boolean(id || name || Object.values(fields).some(Boolean))} writable={api.canMutate} fields={<div className={styles.stack}><ResourceIdentityFields id={id} name={name} onId={setId} onName={setName} />{extra}</div>}
    review={<ResourceFacts rows={[[c("id"), id], [c("name"), name], ...Object.entries(fields)]} />} onDone={onDone} onCancel={onCancel}
    submit={async idempotencyKey => {
      let body: unknown = { id, name };
      if (kind === "source-connections") body = { id, name, spec: sourceSpec };
      if (kind === "repository-bindings") body = { id, name, projectId: fields.projectId, spec: { sourceConnectionId: fields.sourceConnectionId, externalRepositoryId: fields.externalRepositoryId, repositoryPath: fields.repositoryPath, trustedDefaultBranch: fields.trustedDefaultBranch } };
      if (kind === "pipelines") body = { id, name, projectId: fields.projectId, draft: pipelineDraft(fields.repositoryBindingId ?? "") };
      const value = await api.command<DevopsResource>(devopsKinds[kind], kind, { method: "POST", body, idempotencyKey }, "Create" + devopsKinds[kind] + "Request");
      return <div className={styles.stack}><ResourceFacts rows={[[c("id"), value.metadata.id], [c("name"), value.metadata.name], [c("version"), value.metadata.resourceVersion]]} />{value.kind === "SourceConnection" ? <SourceOperatorInstructions spec={value.spec} /> : null}</div>;
    }} />;
}
