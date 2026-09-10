"use client";
import { useTranslations } from "next-intl";
import type { PipelineRun } from "@/api/devopsContract";
import { resourcePath } from "@/api/client";
import { Badge, Card, Steps } from "@ui/xiak";
import { ResourceFacts } from "../resources/ResourceFacts";
import { ResourceCommand } from "../resources/ResourceCommand";
import { useDevopsApi } from "./DevopsApi";
import { RunLogs } from "./RunLogs";
import styles from "../platform/Workspace.module.css";

const stages = ["RECEIVE", "FETCH", "VERIFY", "REPORT"] as const;
const terminal = new Set(["SUCCEEDED", "FAILED", "CANCELLED", "MANUAL_INTERVENTION"]);
export function RunDetails({ value, update }: { value: PipelineRun; update(value: PipelineRun): void }) {
  const t = useTranslations("Devops"); const c = useTranslations("Collection"); const api = useDevopsApi();
  return <div className={styles.stack}><Card><Card.Body className={styles.stack}>
    <Steps label={t("stage")} items={stages.map(stage => ({ id: stage, label: stage }))} current={stages.indexOf(value.status.stage)} />
    <ResourceFacts rows={[[c("id"), value.id], [t("state"), <Badge key="state" status={value.status.state === "SUCCEEDED" ? "success" : value.status.state === "FAILED" ? "danger" : "info"}>{t(`runStates.${value.status.state}`)}</Badge>], [t("pipelineId"), value.pipelineId], [t("activeRevision"), value.input.pipelineRevisionId], [t("headCommit"), value.input.change.headCommit], [t("baseCommit"), value.input.change.trustedBaseCommit], [t("observed"), value.status.observedAt], [t("reason"), value.status.reason], [t("inputDigest"), value.inputDigest]]} />
    <div className={styles.actions}><ResourceCommand label={t("cancelRun")} description={t("cancelHint")} disabled={!api.canMutate || terminal.has(value.status.state) || Boolean(value.status.cancellationRequestedAt)} danger run={async idempotencyKey => update(await api.command<PipelineRun>("PipelineRun", "runs/" + resourcePath(value.id) + "/cancel", { method: "POST", version: value.status.resourceVersion, idempotencyKey }))} />
      <ResourceCommand label={t("replay")} disabled={!api.canMutate || !terminal.has(value.status.state)} run={async idempotencyKey => update(await api.command<PipelineRun>("PipelineRun", "runs/" + resourcePath(value.id) + "/replay", { method: "POST", version: value.status.resourceVersion, idempotencyKey }))} /></div>
  </Card.Body></Card><RunLogs key={value.id} runId={value.id} /></div>;
}
