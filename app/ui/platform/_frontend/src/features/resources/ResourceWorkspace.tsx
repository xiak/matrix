"use client";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { useTranslations } from "next-intl";
import { Plus, RefreshCw } from "lucide-react";
import { Badge, Button, Card, ContentPage, EmptyState, PageSkeleton, Table, TableToolbar, useLeaveConfirmation } from "@ui/xiak";
import { useInspected } from "./InspectedResources";
import { RequestFeedback } from "../platform/RequestFeedback";
import styles from "../platform/Workspace.module.css";

export type ResourcePresentation<T> = {
  key: string; label: string; id(value: T): string; name(value: T): string; state?(value: T): string;
  version?(value: T): number; read(id: string, signal: AbortSignal): Promise<T>;
};
export function ResourceWorkspace<T>({ resource, writable, creation, children }: {
  resource: ResourcePresentation<T>; writable: boolean;
  creation?: (done: () => void, cancel: () => void) => ReactNode;
  children(value: T, update: (value: T) => void): ReactNode;
}) {
  const t = useTranslations("Collection");
  const p = useTranslations("Platform");
  const leave = useLeaveConfirmation();
  const [view, setView] = useInspected<T>(resource.key);
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);
  function remember(value: T) {
    setView(current => ({ ...current, records: [value, ...current.records.filter(item => resource.id(item) !== resource.id(value))].slice(0, 50), selected: resource.id(value) }));
  }
  async function lookup(id: string) {
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    setBusy(true); setError(undefined);
    try { const value = await resource.read(id.trim(), controller.signal); if (!controller.signal.aborted) remember(value); }
    catch (cause) { if (!controller.signal.aborted) { setError(cause); setView(current => ({ ...current, selected: null, records: current.records.filter(item => resource.id(item) !== id.trim()) })); } }
    finally { if (!controller.signal.aborted) setBusy(false); }
  }
  const back = () => { active.current?.abort(); setBusy(false); setError(undefined); setCreating(false); setView(current => ({ ...current, selected: null })); };
  const selected = view.records.find(item => resource.id(item) === view.selected);
  if (creating && creation) return <>{creation(() => setCreating(false), () => { setCreating(false); setError(undefined); })}</>;
  if (selected) return <div className={styles.stack}>
    <ContentPage.Heading title={resource.name(selected)} back={{ label: t("back"), parentLabel: resource.label, onClick: () => leave(back) }} actions={<Button variant="ghost" aria-label={p("refresh")} disabled={busy} onClick={() => leave(() => lookup(resource.id(selected)))}><RefreshCw aria-hidden="true" />{p("refresh")}</Button>} focus />
    <RequestFeedback error={error} />
    {busy ? <PageSkeleton label={p("loading")} layout="cards" /> : children(selected, remember)}
  </div>;
  const query = view.query.toLowerCase().trim();
  const rows = view.records.filter(item => [resource.id(item), resource.name(item)].join(" ").toLowerCase().includes(query));
  return <div className={styles.stack}><ContentPage.Heading title={resource.label} />
    <Card><Card.Body className={styles.stack}>
      <form onSubmit={event => { event.preventDefault(); if (view.query.trim()) void lookup(view.query); }}>
        <TableToolbar search={{ label: t("query"), placeholder: t("queryPlaceholder"), value: view.query, onChange: query => setView(current => ({ ...current, query })) }}
          labels={{ filters: t("filters"), clearSearch: t("clearSearch"), clearFilters: t("clearFilters"), removeFilter: label => t("removeFilter", { label }) }}
          actions={creation ? <Button disabled={!writable} onClick={() => setCreating(true)}><Plus aria-hidden="true" />{t("create")}</Button> : undefined}
          tools={<Button type="submit" variant="secondary" disabled={busy || !view.query.trim()}>{t("lookup")}</Button>} />
      </form>
      <p className={styles.muted}>{t("queryHint")}</p><RequestFeedback error={error} />
      {busy ? <PageSkeleton label={p("loading")} layout="table" /> : rows.length ? <Table aria-label={t("inspected")}><thead><tr><th scope="col">{t("name")}</th>{resource.state ? <th scope="col">{t("state")}</th> : null}{resource.version ? <th scope="col">{t("version")}</th> : null}</tr></thead><tbody>{rows.map(item => <tr key={resource.id(item)}><td><div className={styles.resourceName}><button className={styles.link} onClick={() => lookup(resource.id(item))}>{resource.name(item)}</button><span className={styles.muted}>{resource.id(item)}</span></div></td>{resource.state ? <td><Badge>{resource.state(item)}</Badge></td> : null}{resource.version ? <td>{resource.version(item)}</td> : null}</tr>)}</tbody></Table> : <EmptyState title={t("empty")} description={t("emptyHint")} />}
    </Card.Body></Card>
  </div>;
}
