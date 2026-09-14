"use client";

import { useDeferredValue, useEffect, useId, useMemo, useRef, useState, type ComponentProps, type ReactNode } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { Plus } from "lucide-react";
import { Alert, Button, Card, ContentPage, Dialog, EmptyState, FormField, Input, Table, TableToolbar, TablePagination, Transfer, type PageCommand } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { useAccountAccess } from "../application/AccountAccessProvider";
import styles from "./AccountAccessRenderer.module.css";

export function WorkspaceTime({ value }: { value: string | null }) {
  const format = useFormatter();
  const t = useTranslations("IamWorkspace");
  return value ? <time dateTime={value} title={value}>{format.dateTime(new Date(value), { dateStyle: "medium", timeStyle: "short" })}</time> : <span>{t("neverUsed")}</span>;
}

export function WorkspaceCollection<T extends { id: string; name: string }>({ title, description, items, columns, row, create, keywords, filter, embedded = false, status, loadMore, footerNote }: {
  title: string; description: string; items: T[]; columns: string[];
  row(item: T): ReactNode; create?: { label: string; disabled?: boolean; reason?: string; onClick(): void }; embedded?: boolean;
  keywords?(item: T): string;
  filter?: { label: string; options: { value: string; label: string }[]; matches(item: T, value: string): boolean };
  status?: string;
  loadMore?: { label: string; disabled?: boolean; busy?: boolean; onClick(): void };
  footerNote?: ReactNode;
}) {
  const t = useTranslations("IamWorkspace");
  const collection = useTranslations("Collection");
  const toolbarLabels = useTableToolbarLabels();
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState("all");
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
  const reset = () => { setQuery(""); setKind("all"); setPage(1); };
  const action = create ? <Button disabled={create.disabled} title={create.reason} onClick={create.onClick} size="small"><Plus aria-hidden="true" />{create.label}</Button> : null;
  return <Card aria-description={description}>
    {!embedded ? <ContentPage.Heading title={title} actions={create ? <ContentPage.Commands label={collection("pageActions")} primary={{ id: "create", label: create.label, icon: <Plus aria-hidden="true" />, disabled: create.disabled, disabledReason: create.disabled ? create.reason : undefined, onSelect: create.onClick }} /> : undefined} /> : null}
    <TableToolbar labels={toolbarLabels} search={{ label: t("search"), value: query, onChange: (value) => { setQuery(value); setPage(1); } }}
      actions={embedded ? action : null}
      filters={filter ? [{ id: "kind", label: filter.label, options: [{ value: "all", label: t("all") }, ...filter.options], value: kind, onChange: (value) => { setKind(value); setPage(1); } }] : []}
      status={status ?? t("count", { count: matches.length })} />
    <Table aria-label={title} aria-busy={deferredQuery !== query}><thead><tr>{columns.map((column) => <th scope="col" key={column}>{column}</th>)}</tr></thead><tbody>{matches.slice((currentPage - 1) * pageSize, currentPage * pageSize).map((item) => <tr key={item.id}>{row(item)}</tr>)}</tbody></Table>
    {!matches.length ? <EmptyState title={items.length ? t("noResults") : t("empty")} description={items.length ? t("noResultsHint") : t("emptyHint")} action={items.length ? <Button onClick={reset} variant="secondary">{toolbarLabels.resetQuery}</Button> : undefined} /> : null}
    <Table.Footer note={footerNote}>
      <TablePagination page={currentPage} pages={pages} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }}
        trailing={loadMore ? <Button disabled={loadMore.disabled || loadMore.busy} onClick={loadMore.onClick} size="small" variant="secondary">{loadMore.label}</Button> : null}
        labels={{ summary: t("page", { page: currentPage, pages }), pageSize: t("pageSize"), previous: t("previous"), next: t("next") }} />
    </Table.Footer>
  </Card>;
}

export function WorkspaceDetail({ title, onBack, actions, children, embedded = false }: {
  title: string; onBack(): void; actions?: { primary?: PageCommand; secondary?: readonly PageCommand[] }; children: ReactNode; embedded?: boolean;
}) {
  const t = useTranslations("IamWorkspace");
  const c = useTranslations("Collection");
  const start = useRef<HTMLDivElement>(null);
  useEffect(() => {
    start.current?.scrollIntoView?.({ block: "start", behavior: "instant" });
  }, []);
  const commands = actions ? <ContentPage.Commands label={c("pageActions")} {...actions} /> : undefined;
  return <div ref={start} className={styles.detailWorkspace}>{embedded ? <div className={styles.sectionHeading}><Button variant="ghost" onClick={onBack}>{t("back")}</Button><h2 className={styles.detailTitle}>{title}</h2>{commands}</div> : <ContentPage.Heading title={title} back={{ label: t("back"), onClick: onBack }} actions={commands} focus />}{children}</div>;
}

export function WorkspaceDialog({ title, onClose, onSubmit, children, submitLabel, submitDisabled, submitVariant, validationError, size, fallbackFocusRef, operation }: { title: string; onClose(): void; onSubmit(): Promise<boolean>; children: ReactNode; submitLabel?: string; submitDisabled?: boolean; submitVariant?: ComponentProps<typeof Button>["variant"]; validationError?: string; size?: ComponentProps<typeof Dialog>["size"]; fallbackFocusRef?: ComponentProps<typeof Dialog>["fallbackFocusRef"]; operation?: { busy: boolean; error?: string; clearError(): void } }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const formId = useId();
  const form = useRef<HTMLFormElement>(null);
  const submitting = useRef(false);
  const clearError = operation?.clearError ?? access.clearWorkspaceError;
  const busy = operation?.busy ?? access.busy;
  const error = validationError ?? operation?.error ?? (access.workspaceError ? t(`errors.${access.workspaceError}`) : undefined);
  useEffect(() => { clearError(); }, [clearError]);
  useEffect(() => {
    if (!error || busy) return;
    const alert = form.current?.querySelector<HTMLElement>('[role="alert"]');
    alert?.focus({ preventScroll: true });
    alert?.scrollIntoView?.({ block: "nearest" });
  }, [error, busy]);
  return <Dialog open size={size} fallbackFocusRef={fallbackFocusRef} title={title} closeLabel={t("close")} onClose={onClose} busy={busy} footer={<><Button disabled={busy} onClick={onClose} variant="secondary">{t("cancel")}</Button><Button disabled={busy || submitDisabled} variant={submitVariant} type="submit" form={formId}>{submitLabel ?? t("save")}</Button></>}>
    <form id={formId} ref={form} className={styles.stack} onSubmit={async (event) => { event.preventDefault(); if (submitting.current || busy || submitDisabled) return; submitting.current = true; clearError(); try { if (await onSubmit()) onClose(); } finally { submitting.current = false; } }}>
      {error ? <Alert status="danger" tabIndex={-1}>{error}</Alert> : null}
      <fieldset className={styles.editorFields} disabled={busy}>{children}</fieldset>
    </form>
  </Dialog>;
}

export function WorkspaceDelete({ name, onClose, onConfirm, impact, operation }: { name: string; onClose(): void; onConfirm(): Promise<unknown>; impact?: ReactNode; operation?: { busy: boolean; error?: string; clearError(): void } }) {
  const t = useTranslations("IamWorkspace");
  const [confirmation, setConfirmation] = useState("");
  const id = useId();
  return <WorkspaceDialog title={t("deleteTitle", { name })} onClose={onClose} submitLabel={t("deleteConfirm")} onSubmit={async () => confirmation === name && Boolean(await onConfirm())} operation={operation}>
    <Alert status="warning">{t("deleteHint")}</Alert>{impact}<strong>{name}</strong>
    <FormField id={id} label={t("confirmName")}><Input id={id} autoComplete="off" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></FormField>
    {confirmation && confirmation !== name ? <p className={styles.note}>{t("confirmName")}: {name}</p> : null}
  </WorkspaceDialog>;
}

export function WorkspaceSelection({ label, options, value, onChange, limit = 30 }: { label: string; options: { id: string; name: string; description?: string }[]; value: string[]; onChange(ids: string[]): void; limit?: number }) {
  const t = useTranslations("IamWorkspace");
  const selectionLimit = Math.max(1, Math.floor(limit));
  const remove = (id: string) => onChange(value.filter((entry) => entry !== id));
  return <Transfer options={options.map((option) => ({ id: option.id, label: option.name, description: option.description }))} remaining={Math.max(0, selectionLimit - value.length)}
    selected={value.map((id) => { const option = options.find((entry) => entry.id === id); return { id, label: option?.name ?? id, description: option?.description }; })}
    onSelect={(ids, checked) => { const next = checked ? [...new Set([...value, ...ids])] : value.filter((id) => !ids.includes(id)); if (next.length <= selectionLimit) onChange(next); }} onRemove={remove} onClear={() => onChange([])}
    labels={{ available: label, selected: t("selectCount", { count: value.length }), search: label + " · " + t("search"), clearSearch: t("clear"), clearSelected: t("clearSelection"), empty: t("selectionEmpty"), emptyHint: t("selectionEmptyHint"), noResults: t("noResults"), noOptions: t("empty"), remove: (name) => t("removeSelection", { name }), previous: t("previous"), next: t("next"), page: (page, pages) => t("page", { page, pages }), selectPage: t("selectPage"), clearPage: t("clearPage"), pageSelection: (selected, total) => t("pageSelection", { selected, total }), limit: (remaining, needed) => t("pageSelectionLimit", { remaining, needed }) }}
    footnote={t(selectionLimit === 1 ? "singleSelectionLimit" : "selectionLimit")} />;
}
