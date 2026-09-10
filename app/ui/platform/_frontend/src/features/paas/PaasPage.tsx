"use client";
import { useState } from "react";
import { useTranslations } from "next-intl";
import type { Application, ApplicationRevision, Configuration, ConfigurationRevision, Deployment, Operation } from "@/api/paasContract";
import { Card, Tabs, useLeaveConfirmation } from "@ui/xiak";
import { ResourceWorkspace } from "../resources/ResourceWorkspace";
import { ResourceFacts } from "../resources/ResourceFacts";
import { usePaasApi } from "./PaasApi";
import { PaasCreation } from "./PaasCreation";
import { DeploymentDetails } from "./DeploymentDetails";
import { OperationSummary } from "./OperationSummary";
import styles from "../platform/Workspace.module.css";

type Resource = Application | ApplicationRevision | Configuration | ConfigurationRevision | Deployment | Operation;
const collection = { applications: "Application", "application-revisions": "ApplicationRevision", configurations: "Configuration", "configuration-revisions": "ConfigurationRevision", deployments: "Deployment", operations: "Operation" } as const;
type Collection = keyof typeof collection;
function Resources({ kind, label }: { kind: Collection; label: string }) {
  const api = usePaasApi(); const c = useTranslations("Collection"); const t = useTranslations("Paas");
  const creators = { applications: "application", configurations: "configuration", "configuration-revisions": "configuration-revision", deployments: "deployment", operations: undefined, "application-revisions": undefined } as const;
  const creation = creators[kind];
  return <ResourceWorkspace<Resource> resource={{ key: kind, label, id: value => value.kind === "Operation" ? value.id : value.metadata.id, name: value => value.kind === "Operation" ? value.action : value.metadata.name, state: value => value.kind === "Operation" ? value.state : value.kind === "Deployment" ? value.status.phase : value.kind, read: (id, signal) => api.read(collection[kind], kind, id, signal) }} writable={api.canMutate}
    creation={creation ? (done, cancel) => <PaasCreation kind={creation} label={label} onDone={done} onCancel={cancel} /> : undefined}>
    {value => value.kind === "Operation" ? <OperationSummary operation={value} /> : value.kind === "Deployment" ? <DeploymentDetails key={value.metadata.resourceVersion} value={value} /> :
      <Card><Card.Body className={styles.stack}><ResourceFacts rows={[[c("id"), value.metadata.id], [c("name"), value.metadata.name], [c("version"), value.metadata.resourceVersion], [c("updated"), value.metadata.updatedAt], ...(value.kind === "Configuration" ? [[t("applicationId"), value.applicationId] as const] : [])]} />
        {value.kind === "ConfigurationRevision" ? <><ResourceFacts rows={[[t("configurationId"), value.spec.configurationId], [t("contentDigest"), value.spec.contentDigest]]} /><pre className={styles.code}>{JSON.stringify(value.spec.values, null, 2)}</pre></> : value.kind === "ApplicationRevision" ? <pre className={styles.code}>{JSON.stringify(value.spec, null, 2)}</pre> : null}
      </Card.Body></Card>}
  </ResourceWorkspace>;
}
export function PaasPage({ page }: { page: "applications" | "configuration" | "deployments" | "operations" }) {
  const p = useTranslations("Platform"); const t = useTranslations("Paas");
  const [tab, setTab] = useState("primary");
  const leave = useLeaveConfirmation();
  if (page === "deployments" || page === "operations") return <Resources kind={page} label={p(`pages.${page}`)} />;
  const primary = page === "applications" ? "applications" : "configurations";
  const revision = page === "applications" ? "application-revisions" : "configuration-revisions";
  return <Tabs.Root value={tab} onValueChange={next => leave(() => setTab(next))}><Tabs.List aria-label={p(`pages.${page}`)}><Tabs.Trigger value="primary">{p(`pages.${page}`)}</Tabs.Trigger><Tabs.Trigger value="revisions">{t("revision")}</Tabs.Trigger></Tabs.List><Tabs.Content value="primary"><Resources kind={primary} label={p(`pages.${page}`)} /></Tabs.Content><Tabs.Content value="revisions"><Resources kind={revision} label={t("revision")} /></Tabs.Content></Tabs.Root>;
}
