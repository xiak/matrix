"use client";
import { useEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { ApiError, resourcePath } from "@/api/client";
import type { PipelineRunLogChunk, PipelineRunLogPage } from "@/api/devopsContract";
import { Button, Card, EmptyState } from "@ui/xiak";
import { useDevopsApi } from "./DevopsApi";
import { RequestFeedback } from "../platform/RequestFeedback";
import styles from "../platform/Workspace.module.css";

export function mergeLogs(runId: string, afterSequence: number, previous: PipelineRunLogChunk[], page: PipelineRunLogPage) {
  if (page.runId !== runId || page.afterSequence !== afterSequence || page.nextSequence < afterSequence || page.chunks.some(chunk => chunk.sequence <= afterSequence || chunk.sequence > page.nextSequence)) throw new ApiError("CONTRACT");
  const seen = new Map(previous.map(chunk => [chunk.sequence, chunk]));
  for (const chunk of page.chunks) { if (seen.has(chunk.sequence) && JSON.stringify(seen.get(chunk.sequence)) !== JSON.stringify(chunk)) throw new ApiError("CONTRACT"); seen.set(chunk.sequence, chunk); }
  const chunks = [...seen.values()].sort((a,b) => a.sequence - b.sequence);
  let length = chunks.reduce((total, chunk) => total + chunk.content.length, 0);
  let clipped = false;
  while (length > 2 * 1024 * 1024 && chunks.length > 1) { length -= chunks.shift()!.content.length; clipped = true; }
  return { chunks, clipped };
}
export function RunLogs({ runId }: { runId: string }) {
  const t = useTranslations("Devops"); const api = useDevopsApi();
  const [chunks, setChunks] = useState<PipelineRunLogChunk[]>([]);
  const [page, setPage] = useState<PipelineRunLogPage>();
  const [clipped, setClipped] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);
  async function load() {
    const controller = new AbortController(); active.current = controller; setBusy(true); setError(undefined);
    try {
      const cursor = page?.nextSequence ?? 0;
      const next = await api.fetch<PipelineRunLogPage>("PipelineRunLogPage", "runs/" + resourcePath(runId) + "/logs?afterSequence=" + cursor, controller.signal);
      const merged = mergeLogs(runId, cursor, chunks, next);
      if (!controller.signal.aborted) { setChunks(merged.chunks); setPage(next); setClipped(current => current || merged.clipped); }
    } catch (cause) { if (!controller.signal.aborted) setError(cause); } finally { if (!controller.signal.aborted) setBusy(false); }
  }
  return <Card><Card.Header><strong>{t("logs")}</strong></Card.Header><Card.Body className={styles.stack}>
    <div className={styles.actions}><Button variant="secondary" disabled={busy} onClick={() => void load()}>{t(page?.hasMore ? "moreLogs" : "loadLogs")}</Button><Button variant="ghost" disabled={busy || !page} onClick={() => { setChunks([]); setPage(undefined); setClipped(false); }}>{t("clearLogs")}</Button></div><RequestFeedback error={error} busy={busy} />
    {chunks.length ? <pre className={styles.code} tabIndex={0} aria-label={t("logs")}>{chunks.map(chunk => "[" + chunk.sequence + " · " + chunk.step.kind + "]\n" + chunk.content).join("\n")}</pre> : <EmptyState title={t(page ? "logEmpty" : "noLogs")} />}
    {page ? <p className={styles.muted} role="status">{t(page.truncated ? "logTruncated" : page.hasMore ? "moreLogs" : "logsCurrent")}{clipped ? " · " + t("logWindowLimited") : ""}</p> : null}
  </Card.Body></Card>;
}
