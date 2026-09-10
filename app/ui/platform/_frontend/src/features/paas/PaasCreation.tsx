"use client";
import { useState } from "react";
import { useTranslations } from "next-intl";
import { ApiError } from "@/api/client";
import type { DeploymentSpec } from "@/api/paasContract";
import { FormField, Input, TextArea } from "@ui/xiak";
import { useApi } from "../auth/SessionProvider";
import { CreationFlow } from "../resources/CreationFlow";
import { ResourceFacts } from "../resources/ResourceFacts";
import { ResourceIdentityFields } from "../resources/ResourceIdentityFields";
import { usePaasApi } from "./PaasApi";
import { OperationSummary } from "./OperationSummary";
import styles from "../platform/Workspace.module.css";

type CreationKind = "application" | "configuration" | "configuration-revision" | "deployment";
export function PaasCreation({ kind, label, onCancel, onDone }: { kind: CreationKind; label: string; onCancel(): void; onDone(): void }) {
  const t = useTranslations("Paas"); const c = useTranslations("Collection");
  const api = usePaasApi(); const sessionApi = useApi();
  const [id, setId] = useState(""); const [name, setName] = useState("");
  const [parent, setParent] = useState("");
  const [content, setContent] = useState("{}");
  const [placement, setPlacement] = useState("");
  const [component, setComponent] = useState("");
  const [replicas, setReplicas] = useState("1");
  const parentLabel = kind === "configuration" ? t("applicationId") : kind === "configuration-revision" ? t("configurationId") : t("applicationRevision");
  const fields = <div className={styles.stack}><ResourceIdentityFields id={id} name={name} onId={setId} onName={setName} />
    {kind !== "application" ? <FormField label={parentLabel}><Input required maxLength={128} value={parent} onChange={event => setParent(event.target.value)} /></FormField> : null}
    {kind === "configuration-revision" ? <FormField label={t("values")} hint={t("valuesHint")}><TextArea required rows={8} maxLength={800000} value={content} onChange={event => setContent(event.target.value)} spellCheck={false} /></FormField> : null}
    {kind === "deployment" ? <div className={styles.fields}><FormField label={t("placementPolicy")}><Input required value={placement} onChange={event => setPlacement(event.target.value)} /></FormField><FormField label={t("component")}><Input required value={component} onChange={event => setComponent(event.target.value)} /></FormField><FormField label={t("replicas")}><Input required type="number" min={0} max={1000} value={replicas} onChange={event => setReplicas(event.target.value)} /></FormField></div> : null}
  </div>;
  return <CreationFlow title={c("createTitle", { resource: label })} dirty={Boolean(id || name || parent || placement || component || content !== "{}")} writable={api.canMutate} fields={fields}
    review={<div className={styles.stack}><ResourceFacts rows={[[c("id"), id], [c("name"), name], ...(kind !== "application" ? [[parentLabel, parent] as const] : [])]} />{kind === "configuration-revision" ? <pre className={styles.code}>{content}</pre> : null}{kind === "deployment" ? <ResourceFacts rows={[[t("placementPolicy"), placement], [t("component"), component], [t("replicas"), replicas]]} /> : null}</div>}
    onCancel={onCancel} onDone={onDone} submit={async idempotencyKey => {
      let body: unknown = { id, name }; let path = "applications"; let request = "CreateApplicationRequest";
      if (kind === "configuration") { body = { id, name, applicationId: parent }; path = "configurations"; request = "CreateConfigurationRequest"; }
      if (kind === "configuration-revision") {
        let values: Record<string, string>; try { values = JSON.parse(content); } catch { throw new ApiError("INPUT"); }
        if (!values || Array.isArray(values) || typeof values !== "object" || Object.values(values).some(value => typeof value !== "string")) throw new ApiError("INPUT");
        const contentDigest = await sessionApi.configurationDigest(values);
        body = { id, name, spec: { configurationId: parent, values, contentDigest } }; path = "configuration-revisions"; request = "CreateConfigurationRevisionRequest";
      }
      if (kind === "deployment") {
        const spec: DeploymentSpec = { applicationRevisionId: parent, placementPolicyId: placement, desiredState: "RUNNING", components: [{ name: component, replicas: Number(replicas) }] };
        body = { id, name, spec }; path = "deployments"; request = "CreateDeploymentRequest";
      }
      return <OperationSummary operation={await api.command(request, path, body, { method: "POST", idempotencyKey })} />;
    }} />;
}
