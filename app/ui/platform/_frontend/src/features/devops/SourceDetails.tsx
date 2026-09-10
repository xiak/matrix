"use client";
import { useEffect, useReducer } from "react";
import { useTranslations } from "next-intl";
import type { SourceConnection, RepositoryBinding } from "@/api/devopsContract";
import { resourcePath } from "@/api/client";
import { Badge, Card } from "@ui/xiak";
import { ResourceFacts } from "../resources/ResourceFacts";
import { ResourceCommand } from "../resources/ResourceCommand";
import { useDevopsApi } from "./DevopsApi";
import { SourceOperatorInstructions } from "./SourceOperatorInstructions";
import styles from "../platform/Workspace.module.css";

export function sourceIsFresh(value: SourceConnection | RepositoryBinding, now = Date.now()) { const age = now - Date.parse(value.status.observedAt); return age >= -5000 && age < 120000; }
/** Only this source panel rerenders when its observation expires. */
export function useSourceFreshness(values: readonly (SourceConnection | RepositoryBinding)[]) {
  const [, expire] = useReducer(value => value + 1, 0);
  const deadline = values.length ? Math.min(...values.map(value => Date.parse(value.status.observedAt))) + 120000 : 0;
  useEffect(() => {
    const remaining = deadline - Date.now();
    if (remaining <= 0 || remaining > 125000) return;
    const timer = setTimeout(expire, remaining + 1);
    return () => clearTimeout(timer);
  }, [deadline]);
  return values.length > 0 && values.every(value => sourceIsFresh(value));
}
export function SourceDetails({ value, update }: { value: SourceConnection | RepositoryBinding; update(value: SourceConnection | RepositoryBinding): void }) {
  const c = useTranslations("Collection"); const t = useTranslations("Devops");
  const api = useDevopsApi();
  const fresh = useSourceFreshness([value]);
  const health = fresh ? value.status.health : "STALE";
  return <Card><Card.Body className={styles.stack}><ResourceFacts rows={[[c("id"), value.metadata.id], [c("version"), value.metadata.resourceVersion], [t("sourceHealth"), <Badge key="health" status={health === "READY" ? "success" : "warning"}>{t(`health.${health}`)}</Badge>], [t("reason"), value.status.reason], [t("observed"), value.status.observedAt],
    ...(value.kind === "SourceConnection" ? [[t("origin"), value.spec.endpointOrigin]] : [[t("projectId"), value.projectId], [t("connectionId"), value.spec.sourceConnectionId], [t("repositoryPath"), value.spec.repositoryPath], [t("defaultBranch"), value.spec.trustedDefaultBranch]])] as [string, React.ReactNode][]} />
    <div><ResourceCommand label={t("recheck")} disabled={!api.canMutate} run={async idempotencyKey => update(await api.command(value.kind, `${value.kind === "SourceConnection" ? "source-connections" : "repository-bindings"}/${resourcePath(value.metadata.id)}/recheck`, { method: "POST", version: value.metadata.resourceVersion, idempotencyKey }))} /></div>
    {value.kind === "SourceConnection" ? <SourceOperatorInstructions spec={value.spec} /> : null}
  </Card.Body></Card>;
}
