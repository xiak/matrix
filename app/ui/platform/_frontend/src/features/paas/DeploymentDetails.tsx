"use client";
import { useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { ApiError, resourcePath } from "@/api/client";
import type { Deployment, DeploymentSpec, Operation } from "@/api/paasContract";
import { Button, Card, FormField, Input, TextArea, useUnsavedChanges } from "@ui/xiak";
import { ResourceFacts } from "../resources/ResourceFacts";
import { ResourceCommand } from "../resources/ResourceCommand";
import { usePaasApi } from "./PaasApi";
import { OperationSummary } from "./OperationSummary";
import styles from "../platform/Workspace.module.css";

export function DeploymentDetails({ value }: { value: Deployment }) {
  const t = useTranslations("Paas"); const c = useTranslations("Collection");
  const api = usePaasApi();
  const d = useTranslations("Draft");
  const field = useRef<HTMLTextAreaElement>(null);
  const [spec, setSpec] = useState(JSON.stringify(value.spec, null, 2));
  const [editing, setEditing] = useState(false);
  const [generation, setGeneration] = useState("");
  const [operation, setOperation] = useState<Operation>();
  const leave = useUnsavedChanges({ dirty: editing && spec !== JSON.stringify(value.spec, null, 2), busy: false, focusRef: field, copy: { title: d("title"), description: d("description"), stay: d("stay"), leave: d("leave"), close: d("close"), busyTitle: d("busyTitle"), busyDescription: d("busyDescription"), failure: d("failure"), retry: d("retry") } });
  const path = "deployments/" + resourcePath(value.metadata.id);
  return <div className={styles.stack}><Card><Card.Body className={styles.stack}>
    <ResourceFacts rows={[[c("id"), value.metadata.id], [t("phase"), value.status.phase], [t("desired"), value.spec.desiredState], [t("generation"), value.generation], [t("applicationRevision"), value.spec.applicationRevisionId], [t("placementPolicy"), value.spec.placementPolicyId], [c("version"), value.metadata.resourceVersion]]} />
    <div className={styles.actions}><Button variant="secondary" disabled={!api.canMutate} onClick={() => leave(() => { setSpec(JSON.stringify(value.spec, null, 2)); setEditing(current => !current); })}>{editing ? c("cancel") : t("update")}</Button>
      <ResourceCommand label={t("stop")} disabled={!api.canMutate || value.spec.desiredState === "STOPPED"} danger run={async key => { setOperation(await api.command("DeploymentSpec", path, { ...value.spec, desiredState: "STOPPED" }, { method: "PUT", version: value.metadata.resourceVersion, idempotencyKey: key })); }} />
    </div>
    {editing ? <div className={styles.stack}><FormField label={t("deploymentSpec")}><TextArea ref={field} disabled={!api.canMutate} value={spec} rows={12} onChange={event => setSpec(event.target.value)} spellCheck={false} /></FormField><div><ResourceCommand label={c("save")} disabled={!api.canMutate} run={async key => { let body: DeploymentSpec; try { body = JSON.parse(spec); } catch { throw new ApiError("INPUT"); } setOperation(await api.command("DeploymentSpec", path, body, { method: "PUT", version: value.metadata.resourceVersion, idempotencyKey: key })); setEditing(false); }} /></div></div> : null}
  </Card.Body></Card><Card><Card.Header><strong>{t("rollback")}</strong></Card.Header><Card.Body className={styles.stack}><FormField label={t("targetGeneration")}><Input type="number" min={1} max={value.generation - 1} value={generation} onChange={event => setGeneration(event.target.value)} /></FormField><div><ResourceCommand label={t("rollback")} danger disabled={!api.canMutate || !generation || Number(generation) >= value.generation} run={async key => { setOperation(await api.command("RollbackDeploymentRequest", path + "/rollback", { sourceGeneration: Number(generation) }, { method: "POST", version: value.metadata.resourceVersion, idempotencyKey: key })); }} /></div></Card.Body></Card>
  {operation ? <OperationSummary operation={operation} /> : null}</div>;
}
