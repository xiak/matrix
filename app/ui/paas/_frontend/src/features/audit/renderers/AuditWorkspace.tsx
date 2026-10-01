"use client";

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { RefreshCcw, ShieldCheck } from "lucide-react";
import { useEffectiveCredential } from "@/features/auth/application/RoleSessionProvider";
import { HttpProblem } from "@/infrastructure/http/jsonRequest";
import {
  Alert,
  Badge,
  Button,
  Card,
  ContentPage,
  EmptyState,
  FormField,
  Input,
  Select,
  Table,
  TablePagination,
  TableSkeleton,
  Typography
} from "@ui/xiak";
import {
  AUDIT_MAX_PAGE_SIZE,
  AUDIT_MAX_VERIFY_RECORDS,
  auditActions,
  auditActorTypes,
  type AuditActorType,
  type AuditChainVerification,
  type AuditQueryRequest,
  type AuditRecord,
  type AuditRecordPage
} from "../domain/audit";
import type { AuditRepository } from "../repositories/auditRepository";
import { httpAuditRepository } from "../repositories/httpAuditRepository";
import { previewAuditRepository } from "../repositories/previewAuditRepository";
import styles from "./AuditWorkspace.module.css";

type LoadError = "expired" | "forbidden" | "invalid" | "unavailable";
type DraftFilters = { from: string; to: string; action: string; actorType: AuditActorType; actorId: string; pageSize: number };

const emptyFilters: DraftFilters = { from: "", to: "", action: "", actorType: "USER", actorId: "", pageSize: 10 };
const actorIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function loadError(error: unknown): LoadError {
  if (error instanceof HttpProblem && error.status === 401) return "expired";
  if (error instanceof HttpProblem && error.status === 403) return "forbidden";
  if (error instanceof Error && error.message.startsWith("INVALID_")) return "invalid";
  return "unavailable";
}

function requestFrom(filters: DraftFilters): AuditQueryRequest {
  return {
    pageSize: filters.pageSize,
    from: filters.from ? new Date(filters.from).toISOString() : undefined,
    to: filters.to ? new Date(filters.to).toISOString() : undefined,
    action: filters.action ? filters.action as AuditQueryRequest["action"] : undefined,
    actor: filters.actorId ? { type: filters.actorType, id: filters.actorId } : undefined
  };
}

function RecordDetail({ record, onBack }: { record: AuditRecord; onBack(): void }) {
  const t = useTranslations("AuditService");
  const format = useFormatter();
  const event = record.event;
  return <section className={styles.stack}>
    <ContentPage.Heading title={t("detail.title", { sequence: record.sequence })} scrollKey={`audit-record:${record.sequence}`} back={{ label: t("actions.back"), onClick: onBack }} focus />
    <Card>
      <Card.Header className={styles.detailHeader}>
        <div><Badge status={event.result === "DENIED" ? "danger" : event.result === "ACCEPTED" ? "info" : "success"}>{t(`results.${event.result}`)}</Badge><Typography.Title as="h2" level={3}>{event.action}</Typography.Title></div>
        <span>{format.dateTime(new Date(event.occurredAt), { dateStyle: "medium", timeStyle: "long" })}</span>
      </Card.Header>
      <Card.Body className={styles.stack}>
        <section aria-labelledby="audit-event-context">
          <h3 id="audit-event-context" className={styles.sectionTitle}>{t("detail.context")}</h3>
          <dl className={styles.facts}>
            <div><dt>{t("columns.actor")}</dt><dd><strong>{event.actor.id}</strong><small>{t(`actorTypes.${event.actor.type}`)}</small></dd></div>
            <div><dt>{t("columns.target")}</dt><dd><strong>{event.target.id}</strong><small>{event.target.kind}</small></dd></div>
            <div><dt>{t("detail.source")}</dt><dd><strong>{event.action}</strong><small>{record.source}</small></dd></div>
            <div><dt>{t("detail.retention")}</dt><dd><strong>{t("detail.indefinite")}</strong><small>{t("detail.ingested", { time: format.dateTime(new Date(record.ingestedAt), { dateStyle: "medium", timeStyle: "long" }) })}</small></dd></div>
          </dl>
        </section>
        <section aria-labelledby="audit-request-evidence">
          <h3 id="audit-request-evidence" className={styles.sectionTitle}>{t("detail.requestEvidence")}</h3>
          <dl className={styles.evidence}>
            <div><dt>{t("detail.eventId")}</dt><dd><code>{event.eventId}</code></dd></div>
            <div><dt>{t("detail.requestId")}</dt><dd><code>{event.requestId}</code></dd></div>
            <div><dt>{t("detail.correlationId")}</dt><dd><code>{event.correlationId}</code></dd></div>
            {event.operationId ? <div><dt>{t("detail.operationId")}</dt><dd><code>{event.operationId}</code></dd></div> : null}
            {event.iamDecisionId ? <div><dt>{t("detail.decisionId")}</dt><dd><code>{event.iamDecisionId}</code></dd></div> : null}
            <div><dt>{t("detail.requestDigest")}</dt><dd><code>{event.requestDigest}</code></dd></div>
          </dl>
        </section>
        <section aria-labelledby="audit-chain-evidence">
          <h3 id="audit-chain-evidence" className={styles.sectionTitle}>{t("detail.chainEvidence")}</h3>
          <dl className={styles.evidence}>
            <div><dt>{t("detail.sequence")}</dt><dd><code>{record.sequence}</code></dd></div>
            <div><dt>{t("detail.previousHash")}</dt><dd><code>{record.previousHash}</code></dd></div>
            <div><dt>{t("detail.contentDigest")}</dt><dd><code>{record.contentDigest}</code></dd></div>
            <div><dt>{t("detail.recordHash")}</dt><dd><code>{record.recordHash}</code></dd></div>
          </dl>
        </section>
      </Card.Body>
    </Card>
  </section>;
}

function IntegrityWorkspace({ repository, credential, onBack }: { repository: AuditRepository; credential: string | null; onBack(): void }) {
  const t = useTranslations("AuditService");
  const format = useFormatter();
  const [fromSequence, setFromSequence] = useState("1");
  const [maximumRecords, setMaximumRecords] = useState("1000");
  const [result, setResult] = useState<AuditChainVerification | null>(null);
  const [error, setError] = useState<LoadError | null>(null);
  const [busy, setBusy] = useState(false);

  async function verify() {
    const from = Number(fromSequence);
    const maximum = Number(maximumRecords);
    if (!credential || !Number.isSafeInteger(from) || from < 1 || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > AUDIT_MAX_VERIFY_RECORDS) {
      setError("invalid");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setResult(await repository.verify(credential, { fromSequence: from, maximumRecords: maximum }));
    } catch (reason) {
      setResult(null);
      setError(loadError(reason));
    } finally {
      setBusy(false);
    }
  }

  return <section className={styles.stack}>
    <ContentPage.Heading title={t("verification.title")} scrollKey="audit-integrity" back={{ label: t("actions.back"), onClick: onBack }} focus />
    <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{t("verification.heading")}</Typography.Title><Typography.Text tone="muted">{t("verification.description")}</Typography.Text></div></Card.Header>
      <Card.Body className={styles.stack}>
        <Alert status="info">{t("verification.auditNotice")}</Alert>
        {error ? <Alert status="danger" role="alert">{t(`errors.${error}`)}</Alert> : null}
        <form className={styles.verifyForm} onSubmit={(event) => { event.preventDefault(); void verify(); }}>
          <FormField id="audit-from-sequence" label={t("verification.fromSequence")} hint={t("verification.fromSequenceHint")}>
            <Input id="audit-from-sequence" inputMode="numeric" min={1} step={1} type="number" value={fromSequence} onChange={(event) => setFromSequence(event.target.value)} />
          </FormField>
          <FormField id="audit-maximum-records" label={t("verification.maximumRecords")} hint={t("verification.maximumRecordsHint", { maximum: AUDIT_MAX_VERIFY_RECORDS })}>
            <Input id="audit-maximum-records" inputMode="numeric" min={1} max={AUDIT_MAX_VERIFY_RECORDS} step={1} type="number" value={maximumRecords} onChange={(event) => setMaximumRecords(event.target.value)} />
          </FormField>
          <Button disabled={busy} type="submit"><ShieldCheck aria-hidden="true" />{t(busy ? "verification.verifying" : "verification.verify")}</Button>
        </form>
        {result ? <section className={styles.verificationResult} aria-live="polite">
          <div className={styles.verificationHeading}><Badge status="success">{t("verification.verified")}</Badge><div><strong>{t(result.complete ? "verification.complete" : "verification.partial")}</strong><span>{t("verification.verifiedAt", { time: format.dateTime(new Date(result.verifiedAt), { dateStyle: "medium", timeStyle: "long" }) })}</span></div></div>
          <dl className={styles.facts}>
            <div><dt>{t("verification.range")}</dt><dd><strong>{result.fromSequence}–{result.toSequence}</strong><small>{t("verification.recordCount", { count: result.recordCount })}</small></dd></div>
            <div><dt>{t("verification.tenant")}</dt><dd><code>{result.tenantId}</code></dd></div>
            <div><dt>{t("verification.firstHash")}</dt><dd><code>{result.firstPreviousHash}</code></dd></div>
            <div><dt>{t("verification.lastHash")}</dt><dd><code>{result.lastRecordHash}</code></dd></div>
          </dl>
          {!result.complete && result.nextSequence ? <Button variant="secondary" onClick={() => { setFromSequence(String(result.nextSequence)); setResult(null); }}>{t("verification.continue", { sequence: result.nextSequence })}</Button> : null}
        </section> : null}
      </Card.Body>
    </Card>
  </section>;
}

export function AuditWorkspace({ preview = false }: { preview?: boolean }) {
  const t = useTranslations("AuditService");
  const collection = useTranslations("Collection");
  const format = useFormatter();
  const effectiveCredential = useEffectiveCredential();
  const credential = effectiveCredential ?? (preview ? "preview-audit-session" : null);
  const repository = preview ? previewAuditRepository : httpAuditRepository;
  const [draft, setDraft] = useState<DraftFilters>(emptyFilters);
  const [request, setRequest] = useState<AuditQueryRequest>(() => requestFrom(emptyFilters));
  const [cursors, setCursors] = useState<Array<string | undefined>>([undefined]);
  const [pageIndex, setPageIndex] = useState(0);
  const [page, setPage] = useState<AuditRecordPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<LoadError | null>(null);
  const [validation, setValidation] = useState<string | null>(null);
  const [refreshRevision, setRefreshRevision] = useState(0);
  const [selected, setSelected] = useState<AuditRecord | null>(null);
  const [verifying, setVerifying] = useState(false);
  const opener = useRef<number | null>(null);
  const restoreSequence = useRef<number | null>(null);
  const rowButtons = useRef(new Map<number, HTMLButtonElement>());
  const loadRevision = useRef(0);
  const cursor = cursors[pageIndex];

  useEffect(() => {
    const revision = ++loadRevision.current;
    void (async () => {
      await Promise.resolve();
      if (revision !== loadRevision.current) return;
      if (!credential) {
          setError("expired");
          setPage(null);
          return;
      }
      setLoading(true);
      setError(null);
      try {
        const next = await repository.query(credential, { ...request, cursor });
        if (revision === loadRevision.current) setPage(next);
      } catch (reason) {
        if (revision === loadRevision.current) setError(loadError(reason));
      } finally {
        if (revision === loadRevision.current) setLoading(false);
      }
    })();
  }, [credential, cursor, refreshRevision, repository, request]);

  useEffect(() => () => { loadRevision.current += 1; }, []);
  useLayoutEffect(() => {
    if (selected || restoreSequence.current === null) return;
    rowButtons.current.get(restoreSequence.current)?.focus({ preventScroll: true });
    restoreSequence.current = null;
  }, [selected]);

  const apply = useCallback(() => {
    if ((draft.from && Number.isNaN(Date.parse(draft.from))) || (draft.to && Number.isNaN(Date.parse(draft.to))) ||
      (draft.from && draft.to && Date.parse(draft.from) > Date.parse(draft.to)) ||
      (draft.actorId && !actorIdPattern.test(draft.actorId))) {
      setValidation(t("filters.invalid"));
      return;
    }
    setValidation(null);
    setPage(null);
    setCursors([undefined]);
    setPageIndex(0);
    setRequest(requestFrom(draft));
  }, [draft, t]);

  const reset = useCallback(() => {
    setDraft(emptyFilters);
    setValidation(null);
    setPage(null);
    setCursors([undefined]);
    setPageIndex(0);
    setRequest(requestFrom(emptyFilters));
  }, []);

  const actionOptions = useMemo(() => [{ value: "", label: t("filters.allActions") }, ...auditActions.map((action) => ({ value: action, label: action }))], [t]);
  const actorTypeOptions = useMemo(() => auditActorTypes.map((type) => ({ value: type, label: t(`actorTypes.${type}`) })), [t]);

  if (selected) return <RecordDetail record={selected} onBack={() => {
    restoreSequence.current = opener.current;
    setSelected(null);
  }} />;
  if (verifying) return <IntegrityWorkspace credential={credential} repository={repository} onBack={() => setVerifying(false)} />;

  const status = page ? t("directory.pageStatus", { page: pageIndex + 1, count: page.records.length }) : t("directory.loading");
  return <section className={styles.stack}>
    <ContentPage.Heading title={t("title")} scrollKey="audit-records" actions={<ContentPage.Commands label={collection("pageActions")} primary={{ id: "verify", label: t("actions.verify"), icon: <ShieldCheck aria-hidden="true" />, onSelect: () => setVerifying(true) }} />} />
    <Card aria-description={t("description")}>
      <Card.Header className={styles.directoryHeader}><div><Typography.Title as="h2" level={3}>{t("directory.heading")}</Typography.Title><Typography.Text tone="muted">{t("description")}</Typography.Text></div><Badge>{preview ? t("preview") : t("live")}</Badge></Card.Header>
      <Card.Body className={styles.stack}>
        <div className={styles.boundary}><ShieldCheck aria-hidden="true" /><p><strong>{t("boundary.title")}</strong><span>{t("boundary.description")}</span></p></div>
        <form className={styles.filters} onSubmit={(event) => { event.preventDefault(); apply(); }}>
          <FormField id="audit-from" label={t("filters.from")}><Input id="audit-from" type="datetime-local" value={draft.from} onChange={(event) => setDraft((current) => ({ ...current, from: event.target.value }))} /></FormField>
          <FormField id="audit-to" label={t("filters.to")}><Input id="audit-to" type="datetime-local" value={draft.to} onChange={(event) => setDraft((current) => ({ ...current, to: event.target.value }))} /></FormField>
          <FormField label={t("filters.action")}><Select aria-label={t("filters.action")} options={actionOptions} value={draft.action} onValueChange={(action) => setDraft((current) => ({ ...current, action }))} /></FormField>
          <FormField label={t("filters.actorType")}><Select aria-label={t("filters.actorType")} options={actorTypeOptions} value={draft.actorType} onValueChange={(actorType) => setDraft((current) => ({ ...current, actorType: actorType as AuditActorType }))} /></FormField>
          <FormField id="audit-actor-id" label={t("filters.actorId")} hint={t("filters.actorHint")}><Input id="audit-actor-id" maxLength={128} value={draft.actorId} onChange={(event) => setDraft((current) => ({ ...current, actorId: event.target.value }))} /></FormField>
          <FormField label={t("filters.pageSize")}><Select aria-label={t("filters.pageSize")} options={[10, 25, 50, 100, AUDIT_MAX_PAGE_SIZE].map((size) => ({ value: String(size), label: String(size) }))} value={String(draft.pageSize)} onValueChange={(size) => setDraft((current) => ({ ...current, pageSize: Number(size) }))} /></FormField>
          <div className={styles.filterActions}><Button disabled={loading} type="submit">{t("actions.query")}</Button><Button disabled={loading} type="button" variant="secondary" onClick={reset}>{t("actions.reset")}</Button><Button aria-label={t("actions.refresh")} disabled={loading} iconOnly size="small" type="button" variant="ghost" onClick={() => setRefreshRevision((value) => value + 1)}><RefreshCcw aria-hidden="true" /></Button></div>
        </form>
        {validation ? <Alert status="danger" role="alert">{validation}</Alert> : null}
        {error ? <EmptyState title={t("errors.title")} description={t(`errors.${error}`)} action={error !== "expired" ? <Button variant="secondary" onClick={() => setRefreshRevision((value) => value + 1)}>{t("actions.retry")}</Button> : undefined} /> : null}
        {!error && !page ? <TableSkeleton label={t("directory.loading")} labelVisible={false} rows={6} header={false} /> : null}
        {!error && page ? <div className={styles.collection} aria-busy={loading || undefined}>
          <div className={styles.collectionStatus}><span role="status">{status}</span>{loading ? <span>{t("directory.refreshing")}</span> : null}</div>
          {page.records.length ? <Table aria-label={t("directory.table")} className={styles.auditTable} mobileLayout="stack">
            <thead><tr><th scope="col">{t("columns.time")}</th><th scope="col">{t("columns.action")}</th><th scope="col">{t("columns.actor")}</th><th scope="col">{t("columns.target")}</th><th scope="col">{t("columns.result")}</th></tr></thead>
            <tbody>{page.records.map((record) => <tr key={record.sequence}>
              <td data-label={t("columns.time")}><button className={styles.recordLink} ref={(node) => { if (node) rowButtons.current.set(record.sequence, node); else rowButtons.current.delete(record.sequence); }} onClick={() => { opener.current = record.sequence; setSelected(record); }}>{format.dateTime(new Date(record.event.occurredAt), { dateStyle: "medium", timeStyle: "short" })}</button><small>#{record.sequence}</small></td>
              <td data-label={t("columns.action")}><code>{record.event.action}</code><small>{record.source}</small></td>
              <td data-label={t("columns.actor")}><strong>{record.event.actor.id}</strong><small>{t(`actorTypes.${record.event.actor.type}`)}</small></td>
              <td data-label={t("columns.target")}><strong>{record.event.target.id}</strong><small>{record.event.target.kind}</small></td>
              <td data-label={t("columns.result")}><Badge status={record.event.result === "DENIED" ? "danger" : record.event.result === "ACCEPTED" ? "info" : "success"}>{t(`results.${record.event.result}`)}</Badge></td>
            </tr>)}</tbody>
          </Table> : <EmptyState title={t("directory.empty")} description={t("directory.emptyHint")} action={<Button variant="secondary" onClick={reset}>{t("actions.reset")}</Button>} />}
          <Table.Footer note={t("directory.footer", { tenant: page.tenantId })}><TablePagination mode="cursor" disabled={loading} summary={t("directory.page", { page: pageIndex + 1 })}
            previous={{ label: t("actions.previous"), disabled: pageIndex === 0, onClick: () => setPageIndex((value) => Math.max(0, value - 1)) }}
            next={{ label: t("actions.next"), disabled: !page.nextCursor, onClick: () => { if (!page.nextCursor) return; setCursors((current) => [...current.slice(0, pageIndex + 1), page.nextCursor]); setPageIndex((value) => value + 1); } }} /></Table.Footer>
        </div> : null}
      </Card.Body>
    </Card>
  </section>;
}
