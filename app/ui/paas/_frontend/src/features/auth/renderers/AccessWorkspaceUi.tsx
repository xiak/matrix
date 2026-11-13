"use client";

import { Children, Fragment, cloneElement, isValidElement, useDeferredValue, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ComponentProps, type ReactNode, type Ref, type RefObject } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { Plus } from "lucide-react";
import { Alert, Button, Card, ContentPage, Dialog, EmptyState, FormField, Input, LoadingNotice, Table, TableToolbar, TablePagination, Tabs, Transfer, type PageCommand, type PageCommandsHandle } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { ConsoleLink, useDirectoryQuery } from "@/features/control-plane/routes/ConsoleNavigation";
import { useOptionalAccountAccess } from "../application/AccountAccessProvider";
import { useAccessDraft } from "./useAccessDraft";
import styles from "./AccountAccessRenderer.module.css";

const noop = () => {};

export function RelationshipLink({ view, id, tab, scope, label, enabled = true, children }: {
  view: "users" | "groups" | "roles" | "policies"; id: string; tab?: string; scope?: string; label?: string; enabled?: boolean; children: ReactNode;
}) {
  if (!enabled) return <span>{children}</span>;
  const query = new URLSearchParams({ id });
  if (tab) query.set("tab", tab);
  if (scope) query.set("scope", scope);
  return <ConsoleLink className={styles.relationshipLink} prefetch={false} href={`/console/access/${view}/?${query}`} aria-label={label}>{children}</ConsoleLink>;
}

// A relationship can be below an identity summary. Bring the selected tab
// into view once its data is mounted, including on a direct link or Back.
export function RelationshipTabs(props: ComponentProps<typeof Tabs.List>) {
  const list = useRef<HTMLDivElement>(null);
  const params = useDirectoryQuery();
  const tab = params?.get("tab");
  const scope = params?.get("scope");
  useLayoutEffect(() => {
    if (!tab) return;
    const frame = requestAnimationFrame(() => {
      const active = list.current?.querySelector<HTMLElement>('[role="tab"][aria-selected="true"]');
      active?.focus({ preventScroll: true });
      active?.scrollIntoView?.({ block: "nearest", inline: "nearest" });
    });
    return () => cancelAnimationFrame(frame);
  }, [tab, scope]);
  return <Tabs.List variant="underline" {...props} ref={list} />;
}

export function WorkspaceTime({ value, compact = false }: { value: string | null; compact?: boolean }) {
  const format = useFormatter();
  const t = useTranslations("IamWorkspace");
  if (!value) return <span>{t("neverUsed")}</span>;
  return <time dateTime={value} title={value}>{format.dateTime(new Date(value), compact
    ? { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }
    : { dateStyle: "medium", timeStyle: "short" })}</time>;
}

export function AuthorizationOverview({ title, hint, items }: {
  title: string;
  hint: string;
  items: readonly { label: string; value: ReactNode }[];
}) {
  const id = useId();
  return <section className={styles.grantOverview} aria-labelledby={id}>
    <div className={styles.grantOverviewHeading}><h3 id={id}>{title}</h3><p>{hint}</p></div>
    <dl>{items.map((item) => <div key={item.label}><dt>{item.label}</dt><dd>{item.value}</dd></div>)}</dl>
  </section>;
}

function labelCollectionCells(content: ReactNode, columns: readonly string[]) {
  const nodes = Children.toArray(content);
  const cells = nodes.length === 1 && isValidElement<{ children?: ReactNode }>(nodes[0]) && nodes[0].type === Fragment
    ? Children.toArray(nodes[0].props.children)
    : nodes;
  return cells.map((cell, index) => isValidElement<{ "data-label"?: string }>(cell)
    ? cloneElement(cell, { "data-label": cell.props["data-label"] ?? columns[index] })
    : cell);
}

const initialRelationshipPageSize = 10;

export function WorkspaceRelationshipDirectory<T extends { id: string; name: string }>({
  title, searchLabel, items, columns, row, keywords, status, footerNote, loadMore, emptyTitle, emptyDescription,
  busy = false, controls = "as-needed", loading
}: {
  title: string;
  searchLabel: string;
  items: T[];
  columns: string[];
  row(item: T, blocked: boolean): ReactNode;
  keywords?(item: T): string;
  status(shown: number, loaded: number): string;
  footerNote: ReactNode;
  loadMore?: { label: string; disabled?: boolean; reason?: string; onClick(): void };
  emptyTitle: string;
  emptyDescription?: string;
  loading?: { label: string; rows?: number };
  busy?: boolean;
  controls?: "always" | "as-needed";
}) {
  const t = useTranslations("IamWorkspace");
  const relationship = useTranslations("RelationshipDirectory");
  const toolbarLabels = useTableToolbarLabels();
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(initialRelationshipPageSize);
  const deferredQuery = useDeferredValue(query);
  const filtering = deferredQuery !== query;
  const filtered = useMemo(() => {
    const words = deferredQuery.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean);
    return items.filter((item) => words.every((word) => [item.name, item.id, keywords?.(item) ?? ""].join(" ").normalize("NFKC").toLowerCase().includes(word)));
  }, [deferredQuery, items, keywords]);
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pages);
  const visible = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const blocked = busy || filtering || Boolean(loading);
  const clearSearch = () => { setQuery(""); setPage(1); };
  const keepControls = controls === "always" || Boolean(loadMore || loading);
  const showSearch = keepControls || items.length > 1 || Boolean(query || deferredQuery);
  const showPagination = keepControls || items.length > initialRelationshipPageSize;

  return <>
    {showSearch && <TableToolbar labels={toolbarLabels} search={{ label: searchLabel, placeholder: relationship("searchPlaceholder"), value: query, onChange: (value) => { setQuery(value); setPage(1); } }} status={loading ? "" : status(filtered.length, items.length)} />}
    {loading ? <LoadingNotice label={loading.label} /> : null}
    {loading || visible.length ? <Table className={styles.relationshipTable} aria-label={title} aria-busy={blocked || undefined} mobileLayout="grid">
      <thead><tr>{columns.map((column) => <th scope="col" key={column}>{column}</th>)}</tr></thead>
      <tbody>{loading ? <Table.LoadingRows columns={columns.length} rows={loading.rows ?? 4} /> : visible.map((item) => <tr key={item.id}>{labelCollectionCells(row(item, blocked), columns)}</tr>)}</tbody>
    </Table> : <EmptyState compact title={query ? t("noResults") : emptyTitle} description={query ? t("noResultsHint") : emptyDescription}
      action={query ? <Button onClick={clearSearch} variant="secondary">{toolbarLabels.resetQuery}</Button> : undefined} />}
    {showPagination && <Table.Footer note={footerNote}><TablePagination page={currentPage} pages={pages} pageSize={pageSize} disabled={blocked}
      onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }}
      trailing={loadMore ? <Button disabled={loadMore.disabled} title={loadMore.reason} onClick={loadMore.onClick} size="small" variant="secondary">{loadMore.label}</Button> : null}
      labels={{ summary: t("page", { page: currentPage, pages }), pageSize: t("pageSize"), previous: t("previous"), next: t("next") }} /></Table.Footer>}
  </>;
}

export function WorkspaceCollection<T extends { id: string; name: string }>({ title, description, items, columns, row, create, secondaryActions = [], keywords, filter, embedded = false, status, loadMore, footerNote, intro, workflow, loading, unavailable, createActionRef, createFocusRef }: {
  title: string; description: string; items: T[]; columns: string[];
  row(item: T): ReactNode; create?: { label: string; disabled?: boolean; reason?: string; onClick(): void }; embedded?: boolean;
  secondaryActions?: readonly PageCommand[];
  keywords?(item: T): string;
  filter?: { label: string; options: { value: string; label: string }[]; defaultValue?: string; value?: string; onChange?(value: string): void; matches(item: T, value: string): boolean };
  status?: string;
  loadMore?: { label: string; disabled?: boolean; busy?: boolean; onClick(): void };
  footerNote?: ReactNode;
  intro?: ReactNode;
  workflow?: ReactNode;
  loading?: { label: string; rows?: number };
  unavailable?: { title: string; description?: string; action?: ReactNode };
  createActionRef?: RefObject<HTMLButtonElement | null>;
  createFocusRef?: Ref<PageCommandsHandle>;
}) {
  const t = useTranslations("IamWorkspace");
  const collection = useTranslations("Collection");
  const toolbarLabels = useTableToolbarLabels();
  const [query, setQuery] = useState("");
  const filterDefault = filter?.defaultValue ?? "all";
  const [localKind, setLocalKind] = useState(filterDefault);
  const kind = filter?.value ?? localKind;
  const setKind = (value: string) => { setLocalKind(value); filter?.onChange?.(value); };
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const deferredQuery = useDeferredValue(query);
  const words = useMemo(() => deferredQuery.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean), [deferredQuery]);
  const matches = useMemo(() => items.filter((item) => {
    const haystack = [item.name, item.id, keywords?.(item) ?? ""].join(" ").normalize("NFKC").toLowerCase();
    return words.every((word) => haystack.includes(word)) && (kind === "all" || !filter || filter.matches(item, kind));
  }), [filter, items, keywords, kind, words]);
  const pages = Math.max(1, Math.ceil(matches.length / pageSize));
  const currentPage = Math.min(page, pages);
  const reset = () => { setQuery(""); setKind(filterDefault); setPage(1); };
  const showQuery = !embedded || Boolean(create || filter || status || loadMore || loading || unavailable || query || deferredQuery) || items.length > 1;
  const showPages = !embedded || Boolean(loadMore) || items.length > initialRelationshipPageSize;
  const action = create ? <Button ref={createActionRef} disabled={create.disabled} title={create.reason} onClick={create.onClick} size="small"><Plus aria-hidden="true" />{create.label}</Button> : null;
  const primary = create ? { id: "create", label: create.label, icon: <Plus aria-hidden="true" />, disabled: create.disabled, disabledReason: create.disabled ? create.reason : undefined, onSelect: create.onClick } satisfies PageCommand : undefined;
  return <Card aria-description={description}>
    {!embedded ? <ContentPage.Heading title={title} scrollKey={`collection:${title}`} actions={!workflow && (primary || secondaryActions.length) ? <ContentPage.Commands label={collection("pageActions")} moreLabel={collection("moreActions")} primaryRef={createActionRef} focusRef={createFocusRef} primary={primary} secondary={secondaryActions} /> : undefined} /> : null}
    {!workflow && intro ? intro : null}
    {workflow ?? <>
    {showQuery && <TableToolbar labels={toolbarLabels} search={{ label: t("search"), value: query, onChange: (value) => { setQuery(value); setPage(1); } }}
      actions={embedded ? action : null}
      filters={filter ? [{ id: "kind", label: filter.label, options: [{ value: "all", label: t("all") }, ...filter.options], value: kind, onChange: (value) => { setKind(value); setPage(1); } }] : []}
      status={loading || unavailable ? "" : status ?? t("count", { count: matches.length })} />}
    {unavailable ? <EmptyState title={unavailable.title} description={unavailable.description} action={unavailable.action} />
      : <>
        {loading ? <LoadingNotice label={loading.label} /> : null}
        <Table aria-label={title} aria-busy={Boolean(loading) || deferredQuery !== query} mobileLayout="stack"><thead><tr>{columns.map((column) => <th scope="col" key={column}>{column}</th>)}</tr></thead><tbody>{loading
          ? <Table.LoadingRows columns={columns.length} rows={loading.rows ?? 4} />
          : matches.slice((currentPage - 1) * pageSize, currentPage * pageSize).map((item) => <tr key={item.id}>{labelCollectionCells(row(item), columns)}</tr>)}</tbody></Table>
        {!loading && !matches.length ? <EmptyState title={items.length ? t("noResults") : t("empty")} description={items.length ? t("noResultsHint") : t("emptyHint")} action={items.length ? <Button onClick={reset} variant="secondary">{toolbarLabels.resetQuery}</Button> : undefined} /> : null}
        {showPages && <Table.Footer note={footerNote}>
          <TablePagination page={currentPage} pages={pages} pageSize={pageSize} disabled={Boolean(loading) || deferredQuery !== query} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }}
            trailing={loadMore ? <Button disabled={loadMore.disabled || loadMore.busy} onClick={loadMore.onClick} size="small" variant="secondary">{loadMore.label}</Button> : null}
            labels={{ summary: t("page", { page: currentPage, pages }), pageSize: t("pageSize"), previous: t("previous"), next: t("next") }} />
        </Table.Footer>}
        {!showPages && footerNote ? <p className={styles.collectionNote}>{footerNote}</p> : null}
      </>}
    </>}
  </Card>;
}

export type WorkspaceInformation = ComponentProps<typeof ContentPage.Detail>["information"];

export function WorkspaceDetail({ title, onBack, backLabel, actions, children, information, embedded = false, focus = true, primaryActionRef, actionFocusRef }: {
  title: string; onBack(): void; actions?: { primary?: PageCommand; secondary?: readonly PageCommand[] }; children: ReactNode; embedded?: boolean;
  information?: WorkspaceInformation | null;
  backLabel?: string;
  focus?: boolean;
  primaryActionRef?: RefObject<HTMLButtonElement | null>;
  actionFocusRef?: Ref<PageCommandsHandle>;
}) {
  const t = useTranslations("IamWorkspace");
  const c = useTranslations("Collection");
  const commands = actions ? <ContentPage.Commands label={c("pageActions")} moreLabel={c("moreActions")} primaryRef={primaryActionRef} focusRef={actionFocusRef} {...actions} /> : undefined;
  const resolvedBackLabel = backLabel ?? t("back");
  return <div className={information ? styles.stack : styles.detailWorkspace}>
    {embedded ? <div className={styles.sectionHeading}><Button variant="ghost" onClick={onBack}>{resolvedBackLabel}</Button><h2 className={styles.detailTitle}>{title}</h2>{commands}</div>
      : <ContentPage.Heading title={title} scrollKey={`detail:${title}`} back={{ label: resolvedBackLabel, onClick: onBack }} actions={commands} focus={focus} />}
    {information ? <ContentPage.Detail information={information}>{children}</ContentPage.Detail> : children}
  </div>;
}

export function WorkspaceInlineForm({ title, onClose, onBack, onSubmit, children, backLabel, submitLabel, cancelLabel, submitDisabled, submitVariant, validationError, operation, draft }: {
  title: string; onClose(): void; onBack?(): void; onSubmit(): Promise<boolean>; children: ReactNode;
  backLabel?: string; submitLabel?: string; cancelLabel?: string; submitDisabled?: boolean; submitVariant?: ComponentProps<typeof Button>["variant"];
  validationError?: string; operation?: { busy: boolean; error?: string; clearError(): void };
  draft?: { dirty: boolean; title: string; description: string };
}) {
  const t = useTranslations("IamWorkspace");
  const access = useOptionalAccountAccess();
  const form = useRef<HTMLFormElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const submitting = useRef(false);
  const clearError = operation?.clearError ?? access?.clearWorkspaceError ?? noop;
  const busy = operation?.busy ?? access?.busy ?? false;
  const error = validationError ?? operation?.error ?? (access?.workspaceError ? t(`errors.${access.workspaceError}`) : undefined);
  const back = onBack ?? onClose;
  const requestLeave = useAccessDraft({ dirty: draft?.dirty ?? false, busy, title: draft?.title ?? title, description: draft?.description ?? "", form });
  useEffect(() => { clearError(); }, [clearError]);
  useLayoutEffect(() => { heading.current?.focus({ preventScroll: true }); }, [title]);
  useEffect(() => {
    if (!error || busy) return;
    const alert = form.current?.querySelector<HTMLElement>('[role="alert"]');
    alert?.focus({ preventScroll: true });
    alert?.scrollIntoView?.({ block: "nearest" });
  }, [error, busy]);
  const leave = () => requestLeave(back);
  return <section className={styles.stack} role="group" aria-label={title}>
    <div className={styles.sectionHeading}><Button type="button" variant="ghost" disabled={busy} onClick={leave}>{backLabel ?? t("back")}</Button><h3 className={styles.detailTitle} ref={heading} tabIndex={-1}>{title}</h3></div>
    <form ref={form} className={styles.stack} aria-busy={busy || undefined} onSubmit={async (event) => {
      event.preventDefault();
      if (submitting.current || busy || submitDisabled) return;
      submitting.current = true;
      clearError();
      try { if (await onSubmit()) onClose(); } finally { submitting.current = false; }
    }}>
      {error ? <Alert status="danger" tabIndex={-1}>{error}</Alert> : null}
      <fieldset className={styles.editorFields} disabled={busy}>{children}</fieldset>
      <div className={styles.actions}><Button type="submit" variant={submitVariant} disabled={busy || submitDisabled}>{submitLabel ?? t("save")}</Button><Button type="button" variant="secondary" disabled={busy} onClick={leave}>{cancelLabel ?? t("cancel")}</Button></div>
    </form>
  </section>;
}

export function WorkspaceDialog({ title, onClose, onSubmit, children, submitLabel, submitDisabled, submitVariant, validationError, size, fallbackFocusRef, operation, draft }: { title: string; onClose(): void; onSubmit(): Promise<boolean>; children: ReactNode; submitLabel?: string; submitDisabled?: boolean; submitVariant?: ComponentProps<typeof Button>["variant"]; validationError?: string; size?: ComponentProps<typeof Dialog>["size"]; fallbackFocusRef?: ComponentProps<typeof Dialog>["fallbackFocusRef"]; operation?: { busy: boolean; error?: string; clearError(): void }; draft?: { dirty: boolean; title: string; description: string } }) {
  const t = useTranslations("IamWorkspace");
  const access = useOptionalAccountAccess();
  const formId = useId();
  const form = useRef<HTMLFormElement>(null);
  const submitting = useRef(false);
  const clearError = operation?.clearError ?? access?.clearWorkspaceError ?? noop;
  const busy = operation?.busy ?? access?.busy ?? false;
  const error = validationError ?? operation?.error ?? (access?.workspaceError ? t(`errors.${access.workspaceError}`) : undefined);
  const requestLeave = useAccessDraft({ dirty: draft?.dirty ?? false, busy, title: draft?.title ?? title, description: draft?.description ?? "", form });
  const close = () => requestLeave(onClose);
  useEffect(() => { clearError(); }, [clearError]);
  useEffect(() => {
    if (!error || busy) return;
    const alert = form.current?.querySelector<HTMLElement>('[role="alert"]');
    alert?.focus({ preventScroll: true });
    alert?.scrollIntoView?.({ block: "nearest" });
  }, [error, busy]);
  return <Dialog open size={size} fallbackFocusRef={fallbackFocusRef} title={title} closeLabel={t("close")} onClose={close} busy={busy} footer={<><Button disabled={busy} onClick={close} variant="secondary">{t("cancel")}</Button><Button disabled={busy || submitDisabled} variant={submitVariant} type="submit" form={formId}>{submitLabel ?? t("save")}</Button></>}>
    <form id={formId} ref={form} className={styles.stack} onSubmit={async (event) => { event.preventDefault(); if (submitting.current || busy || submitDisabled) return; submitting.current = true; clearError(); try { if (await onSubmit()) onClose(); } finally { submitting.current = false; } }}>
      {error ? <Alert status="danger" tabIndex={-1}>{error}</Alert> : null}
      <fieldset className={styles.editorFields} disabled={busy}>{children}</fieldset>
    </form>
  </Dialog>;
}

export function WorkspaceDelete({ name, onClose, onConfirm, impact, hint, operation, draft }: { name: string; onClose(): void; onConfirm(): Promise<unknown>; impact?: ReactNode; hint?: ReactNode; operation?: { busy: boolean; error?: string; clearError(): void }; draft?: { dirty: boolean; title: string; description: string } }) {
  const t = useTranslations("IamWorkspace");
  const [confirmation, setConfirmation] = useState("");
  const id = useId();
  return <WorkspaceDialog title={t("deleteTitle", { name })} onClose={onClose} submitLabel={t("deleteConfirm")} submitDisabled={confirmation !== name} submitVariant="danger" onSubmit={async () => confirmation === name && Boolean(await onConfirm())} operation={operation} draft={draft}>
    <Alert status="warning">{hint ?? t("deleteHint")}</Alert>{impact}<strong>{name}</strong>
    <FormField id={id} label={t("confirmName")}><Input id={id} autoComplete="off" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></FormField>
    {confirmation && confirmation !== name ? <p className={styles.note}>{t("confirmName")}: {name}</p> : null}
  </WorkspaceDialog>;
}

export function workspaceSelectionLabels(t: ReturnType<typeof useTranslations<"IamWorkspace">>) {
  return {
    onlySelected: t("onlySelected"), selectedName: t("name"), searchSelected: t("searchSelected"),
    clearSearch: t("clear"), clearSelected: t("clearSelection"), noResults: t("noResults"),
    previous: t("previous"), next: t("next"), page: (page: number, pages: number) => t("page", { page, pages }),
    selectPage: t("selectPage"), clearPage: t("clearPage"),
    pageSelection: (selected: number, total: number) => t("pageSelection", { selected, total }),
    limit: (remaining: number, needed: number) => t("pageSelectionLimit", { remaining, needed })
  };
}

export function WorkspaceSelection({ label, options, value, onChange, limit = 30, footnote }: { label: string; options: { id: string; name: string; description?: string }[]; value: string[]; onChange(ids: string[]): void; limit?: number; footnote?: ReactNode }) {
  const t = useTranslations("IamWorkspace");
  const selectionLimit = Math.max(1, Math.floor(limit));
  const showLimit = options.length > selectionLimit || value.length >= selectionLimit;
  return <Transfer options={options.map((option) => ({ id: option.id, label: option.name, description: option.description }))} remaining={Math.max(0, selectionLimit - value.length)}
    selected={value.map((id) => { const option = options.find((entry) => entry.id === id); return { id, label: option?.name ?? id, description: option?.description }; })}
    onSelect={(ids, checked) => { const next = checked ? [...new Set([...value, ...ids])] : value.filter((id) => !ids.includes(id)); if (!checked || next.length <= selectionLimit) onChange(next); }} onClear={() => onChange([])}
    labels={{
      ...workspaceSelectionLabels(t), available: label, selected: t("selectCount", { count: value.length }),
      search: label + " · " + t("search"), empty: t("selectionEmpty"), noOptions: t("empty")
    }}
    footnote={footnote ?? (selectionLimit === 1 ? t("singleSelectionLimit") : showLimit ? t("selectionLimit", { limit: selectionLimit }) : undefined)} />;
}
