"use client";

import { ConsoleLink as Link } from "../routes/ConsoleNavigation";
import { useState } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { ArrowRight, FileSearch, FileText } from "lucide-react";
import { Table, TableToolbar, EmptyState, Badge, Button, Card, Statistic, Typography } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import type { ConsoleContentScene } from "../scenes/consoleScene";
import type { ExperienceLogs } from "../domain/experience";
import styles from "./LogServiceRenderer.module.css";

type LogEvent = ExperienceLogs["events"][number];
const levelStatus = { INFO: "info", WARN: "warning", ERROR: "danger" } as const;

function LogEvents({ events }: { events: LogEvent[] }) {
  const t = useTranslations("LogService");
  const format = useFormatter();
  return <div aria-label={t("recent")} className={styles.events} role="region" tabIndex={0}>
    <div className={styles.eventHeading}><span>{t("time")}</span><span>{t("level")}</span><span>{t("message")}</span></div>
    {events.map((event) => <details className={styles.event} key={event.id}>
      <summary aria-label={`${event.service} · ${event.level} · ${t("details")}`}>
        <time dateTime={event.timestamp}>{format.dateTime(new Date(event.timestamp), { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23", timeZone: "UTC" })}</time>
        <span><Badge status={levelStatus[event.level]}>{event.level}</Badge></span>
        <div><strong>{event.service}</strong><p>{event.message}</p></div>
      </summary>
      <dl className={styles.eventFields}><div><dt>{t("eventId")}</dt><dd>{event.id}</dd></div><div><dt>{t("trace")}</dt><dd>{event.traceId}</dd></div><div><dt>{t("topic")}</dt><dd>{event.topicId}</dd></div><div><dt>{t("time")}</dt><dd>{event.timestamp}</dd></div></dl>
    </details>)}
  </div>;
}

function LogSearch({ data }: { data: ExperienceLogs }) {
  const t = useTranslations("LogService");
  const toolbarLabels = useTableToolbarLabels();
  const [query, setQuery] = useState("");
  const [topic, setTopic] = useState("all");
  const [level, setLevel] = useState("all");
  const words = query.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean);
  const events = data.events.filter((event) => (topic === "all" || event.topicId === topic) && (level === "all" || event.level === level) && words.every((word) => [event.message, event.service, event.traceId, event.id].join(" ").normalize("NFKC").toLowerCase().includes(word)));
  return <Card>
    <TableToolbar labels={toolbarLabels} search={{ label: t("query"), placeholder: t("placeholder"), value: query, onChange: setQuery }} filters={[
      { id: "topic", label: t("topic"), value: topic, onChange: setTopic, options: [{ value: "all", label: t("allTopics") }, ...data.topics.map((item) => ({ value: item.id, label: item.name }))] },
      { id: "level", label: t("level"), value: level, onChange: setLevel, options: [{ value: "all", label: t("allLevels") }, ...Object.keys(levelStatus).map((item) => ({ value: item, label: item }))] }
    ]} status={t("count", { count: events.length })} />
    {events.length ? <LogEvents events={events} /> : <EmptyState title={t("empty")} description={t("emptyHint")} icon={<FileSearch />} action={<Button onClick={() => { setQuery(""); setTopic("all"); setLevel("all"); }} variant="secondary">{t("reset")}</Button>} />}
  <Card.Footer><span className={styles.resultCount}>{t("recentHint")}</span></Card.Footer>
  </Card>;
}

function LogTopics({ data, collection }: { data: ExperienceLogs; collection: boolean }) {
  const t = useTranslations("LogService");
  const format = useFormatter();
  return <Card>
    <Card.Header><div><Typography.Title as="h2" level={3}>{t(collection ? "collectionTitle" : "topicsTitle")}</Typography.Title><Typography.Text tone="muted">{t(collection ? "collectionHint" : "topicsHint")}</Typography.Text></div></Card.Header>
    <Table aria-label={t(collection ? "collectionTitle" : "topicsTitle")}><thead><tr><th scope="col">{t("topic")}</th><th scope="col">{t(collection ? "source" : "retention")}</th><th scope="col">{t(collection ? "path" : "stored")}</th><th scope="col">{t(collection ? "nodes" : "region")}</th><th scope="col">{t("status")}</th></tr></thead>
        <tbody>{data.topics.map((topic) => <tr key={topic.id}><td><strong>{topic.name}</strong><small>{topic.id}</small></td><td>{collection ? t(topic.source === "KUBERNETES" ? "kubernetes" : "host") : t("retentionDays", { count: topic.retentionDays })}</td><td>{collection ? <code>{topic.path}</code> : `${format.number(topic.storageGiB)} GiB`}</td><td>{collection ? format.number(topic.nodeCount) : topic.regionId}</td><td><Badge status={topic.state === "ACTIVE" ? "success" : "neutral"}>{t(topic.state === "ACTIVE" ? "active" : "paused")}</Badge></td></tr>)}</tbody>
      </Table>
    <Card.Footer><Link className={styles.textLink} href="/console/logs/search/">{t("allLogs")}<ArrowRight aria-hidden="true" /></Link></Card.Footer>
  </Card>;
}

export function LogServiceRenderer({ scene, regionId = "all" }: { scene: Extract<ConsoleContentScene, { kind: "logs" }>; regionId?: string }) {
  const t = useTranslations("LogService");
  const format = useFormatter();
  if (!scene.data) return <Card><EmptyState title={t("unavailable")} description={t("unavailableHint")} icon={<FileText />} /></Card>;
  const topics = scene.data.topics.filter((topic) => regionId === "all" || topic.regionId === regionId);
  const data = { topics, events: scene.data.events.filter((event) => topics.some((topic) => topic.id === event.topicId)) };
  const metrics = [
    { label: "topicCount", value: format.number(data.topics.length) },
    { label: "storage", value: `${format.number(data.topics.reduce((total, topic) => total + topic.storageGiB, 0), { maximumFractionDigits: 1 })} GiB` },
    { label: "indexed", value: format.number(data.events.length) },
    { label: "agents", value: format.number(data.topics.reduce((total, topic) => total + topic.nodeCount, 0)) }
  ] as const;
  return <div className={styles.stack}>
    {scene.view === "search" ? <LogSearch data={data} key={regionId} /> : scene.view === "topics" || scene.view === "collection" ? <LogTopics collection={scene.view === "collection"} data={data} /> : <>
      <section className={styles.welcome}><div><Typography.Eyebrow>Matrix · Log Service</Typography.Eyebrow><h2>{t("overviewTitle")}</h2><p>{t("overviewHint")}</p></div><div className={styles.actions}><Button asChild><Link href="/console/logs/search/">{t("openSearch")}<ArrowRight aria-hidden="true" /></Link></Button><Link className={styles.textLink} href="/console/logs/topics/">{t("viewTopics")}</Link></div></section>
      <section className={styles.metrics}>{metrics.map((metric) => <Statistic key={metric.label} label={t(metric.label)} value={metric.value} />)}</section>
      <Card><Card.Header><div><Typography.Title as="h2" level={3}>{t("recent")}</Typography.Title><Typography.Text tone="muted">{t("recentHint")}</Typography.Text></div><Link className={styles.textLink} href="/console/logs/search/">{t("allLogs")}<ArrowRight aria-hidden="true" /></Link></Card.Header><LogEvents events={data.events.slice(0, 4)} /></Card>
    </>}
  </div>;
}
