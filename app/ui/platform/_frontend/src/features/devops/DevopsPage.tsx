"use client";
import { useState } from "react";
import { useTranslations } from "next-intl";
import type { PipelineRun } from "@/api/devopsContract";
import { Card, Tabs, useLeaveConfirmation } from "@ui/xiak";
import { ResourceWorkspace } from "../resources/ResourceWorkspace";
import { ResourceFacts } from "../resources/ResourceFacts";
import { DevopsCreation, devopsKinds, type DevopsCollection, type DevopsResource } from "./DevopsCreation";
import { useDevopsApi } from "./DevopsApi";
import { SourceDetails } from "./SourceDetails";
import { PipelineDetails } from "./PipelineDetails";
import { RunDetails } from "./RunDetails";

function Resources({ collection, label }: { collection: DevopsCollection; label: string }) {
  const api = useDevopsApi(); const c = useTranslations("Collection");
  return <ResourceWorkspace<DevopsResource> resource={{ key: collection, label, id: value => value.metadata.id, name: value => value.metadata.name, version: value => value.metadata.resourceVersion, state: value => value.kind === "Pipeline" ? value.activeRevision ? "ACTIVE" : "DRAFT" : value.kind === "SourceConnection" || value.kind === "RepositoryBinding" ? value.status.health : value.kind, read: (id, signal) => api.read(devopsKinds[collection], collection, id, signal) }} writable={api.canMutate} creation={(done, cancel) => <DevopsCreation kind={collection} label={label} onDone={done} onCancel={cancel} />}>
    {(value, update) => value.kind === "Pipeline" ? <PipelineDetails key={value.metadata.id + ":" + value.metadata.resourceVersion} value={value} update={update} /> : value.kind === "SourceConnection" || value.kind === "RepositoryBinding" ? <SourceDetails value={value} update={update} /> : <Card><Card.Body><ResourceFacts rows={[[c("id"), value.metadata.id], [c("name"), value.metadata.name], [c("version"), value.metadata.resourceVersion], [c("updated"), value.metadata.updatedAt]]} /></Card.Body></Card>}
  </ResourceWorkspace>;
}
export function DevopsPage({ page }: { page: "code" | "pipelines" | "runs" }) {
  const t = useTranslations("Devops"); const p = useTranslations("Platform");
  const api = useDevopsApi(); const [tab, setTab] = useState("projects");
  const leave = useLeaveConfirmation();
  if (page === "pipelines") return <Resources collection="pipelines" label={p("pages.pipelines")} />;
  if (page === "runs") return <ResourceWorkspace<PipelineRun> resource={{ key: "runs", label: p("pages.runs"), id: value => value.id, name: value => value.id, state: value => t(`runStates.${value.status.state}`), read: (id, signal) => api.read("PipelineRun", "runs", id, signal) }} writable={api.canMutate}>{(value, update) => <RunDetails value={value} update={update} />}</ResourceWorkspace>;
  const tabs = [{ id: "projects", label: t("project") }, { id: "source-connections", label: t("connection") }, { id: "repository-bindings", label: t("binding") }] as const;
  return <Tabs.Root value={tab} onValueChange={next => leave(() => setTab(next))}><Tabs.List aria-label={p("pages.code")}>{tabs.map(item => <Tabs.Trigger key={item.id} value={item.id}>{item.label}</Tabs.Trigger>)}</Tabs.List>{tabs.map(item => <Tabs.Content key={item.id} value={item.id}><Resources collection={item.id} label={item.label} /></Tabs.Content>)}</Tabs.Root>;
}
