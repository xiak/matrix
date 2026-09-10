"use client";

import { useEffect, useId, useRef, useState, type ComponentProps, type ReactNode } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { ChevronLeft, ChevronRight, Plus } from "lucide-react";
import { Alert, Button, Card, ContentPage, Dialog, EmptyState, FormField, Input, Select, Table, TableToolbar, Transfer } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { useAccountAccess } from "../application/AccountAccessProvider";
import styles from "./AccountAccessRenderer.module.css";

export function WorkspaceTime({ value }: { value: string | null }) {
  const format = useFormatter();
  const t = useTranslations("IamWorkspace");
  return value ? <time dateTime={value} title={value}>{format.dateTime(new Date(value), { dateStyle: "medium", timeStyle: "short" })}</time> : <span>{t("neverUsed")}</span>;
}

export function WorkspaceCollection<T extends { id: string; name: string }>({ title, description, items, columns, row, create, keywords, filter, embedded = false }: {
  title: string; description: string; items: T[]; columns: string[];
  row(item: T): ReactNode; create?: { label: string; onClick(): void }; embedded?: boolean;
  keywords?(item: T): string;
  filter?: { label: string; options: { value: string; label: string }[]; matches(item: T, value: string): boolean };
}) {
  const t = useTranslations("IamWorkspace");
  const toolbarLabels = useTableToolbarLabels();
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const words = query.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean);
  const matches = items.filter((item) => {
    const haystack = [item.name, item.id, keywords?.(item) ?? ""].join(" ").normalize("NFKC").toLowerCase();
    return words.every((word) => haystack.includes(word)) && (kind === "all" || !filter || filter.matches(item, kind));
  });
  const pages = Math.max(1, Math.ceil(matches.length / pageSize));
  const currentPage = Math.min(page, pages);
  const reset = () => { setQuery(""); setKind("all"); setPage(1); };
  const action = create ? <Button onClick={create.onClick} size="small"><Plus aria-hidden="true" />{create.label}</Button> : null;
  return <Card aria-description={description}>
    {!embedded ? <ContentPage.Heading title={title} actions={action} /> : null}
    <TableToolbar labels={toolbarLabels} search={{ label: t("search"), value: query, onChange: (value) => { setQuery(value); setPage(1); } }}
      actions={embedded ? action : null}
      filters={filter ? [{ id: "kind", label: filter.label, options: [{ value: "all", label: t("all") }, ...filter.options], value: kind, onChange: (value) => { setKind(value); setPage(1); } }] : []}
      status={t("count", { count: matches.length })} />
    <Table aria-label={title}><thead><tr>{columns.map((column) => <th scope="col" key={column}>{column}</th>)}</tr></thead><tbody>{matches.slice((currentPage - 1) * pageSize, currentPage * pageSize).map((item) => <tr key={item.id}>{row(item)}</tr>)}</tbody></Table>
    {!matches.length ? <EmptyState title={items.length ? t("noResults") : t("empty")} description={items.length ? t("noResultsHint") : t("emptyHint")} action={items.length ? <Button onClick={reset} variant="secondary">{toolbarLabels.resetQuery}</Button> : undefined} /> : null}
    <Card.Footer><span className={styles.note}>{t("page", { page: currentPage, pages })}</span><div className={styles.actions}><Select aria-label={t("pageSize")} options={[10, 20, 50].map((value) => ({ value: String(value), label: String(value) }))} value={String(pageSize)} onValueChange={(value) => { setPageSize(Number(value)); setPage(1); }} /><Button aria-label={t("previous")} disabled={currentPage <= 1} iconOnly onClick={() => setPage(currentPage - 1)} variant="secondary"><ChevronLeft aria-hidden="true" /></Button><Button aria-label={t("next")} disabled={currentPage >= pages} iconOnly onClick={() => setPage(currentPage + 1)} variant="secondary"><ChevronRight aria-hidden="true" /></Button></div></Card.Footer>
  </Card>;
}

export function WorkspaceDetail({ title, onBack, actions, children, embedded = false }: { title: string; onBack(): void; actions?: ReactNode; children: ReactNode; embedded?: boolean }) {
  const t = useTranslations("IamWorkspace");
  const start = useRef<HTMLDivElement>(null);
  useEffect(() => {
    start.current?.scrollIntoView?.({ block: "start", behavior: "instant" });
  }, []);
  return <div ref={start} className={styles.detailWorkspace}>{embedded ? <div className={styles.sectionHeading}><Button variant="ghost" onClick={onBack}>{t("back")}</Button><h2 className={styles.detailTitle}>{title}</h2>{actions}</div> : <ContentPage.Heading title={title} back={{ label: t("back"), onClick: onBack }} actions={actions} focus />}{children}</div>;
}

export function WorkspaceDialog({ title, onClose, onSubmit, children, submitLabel, submitDisabled, submitVariant, validationError, size, fallbackFocusRef }: { title: string; onClose(): void; onSubmit(): Promise<boolean>; children: ReactNode; submitLabel?: string; submitDisabled?: boolean; submitVariant?: ComponentProps<typeof Button>["variant"]; validationError?: string; size?: ComponentProps<typeof Dialog>["size"]; fallbackFocusRef?: ComponentProps<typeof Dialog>["fallbackFocusRef"] }) {
  const t = useTranslations("IamWorkspace");
  const access = useAccountAccess();
  const formId = useId();
  const form = useRef<HTMLFormElement>(null);
  const submitting = useRef(false);
  const clearError = access.clearWorkspaceError;
  const error = validationError ?? (access.workspaceError ? t(`errors.${access.workspaceError}`) : undefined);
  useEffect(() => { clearError(); }, [clearError]);
  useEffect(() => {
    if (!error || access.busy) return;
    const alert = form.current?.querySelector<HTMLElement>('[role="alert"]');
    alert?.focus({ preventScroll: true });
    alert?.scrollIntoView?.({ block: "nearest" });
  }, [error, access.busy]);
  return <Dialog open size={size} fallbackFocusRef={fallbackFocusRef} title={title} closeLabel={t("close")} onClose={onClose} busy={access.busy} footer={<><Button disabled={access.busy} onClick={onClose} variant="secondary">{t("cancel")}</Button><Button disabled={access.busy || submitDisabled} variant={submitVariant} type="submit" form={formId}>{submitLabel ?? t("save")}</Button></>}>
    <form id={formId} ref={form} className={styles.stack} onSubmit={async (event) => { event.preventDefault(); if (submitting.current || access.busy || submitDisabled) return; submitting.current = true; clearError(); try { if (await onSubmit()) onClose(); } finally { submitting.current = false; } }}>
      {error ? <Alert status="danger" tabIndex={-1}>{error}</Alert> : null}
      <fieldset className={styles.editorFields} disabled={access.busy}>{children}</fieldset>
    </form>
  </Dialog>;
}

export function WorkspaceDelete({ name, onClose, onConfirm, impact }: { name: string; onClose(): void; onConfirm(): Promise<unknown>; impact?: ReactNode }) {
  const t = useTranslations("IamWorkspace");
  const [confirmation, setConfirmation] = useState("");
  const id = useId();
  return <WorkspaceDialog title={t("deleteTitle", { name })} onClose={onClose} submitLabel={t("deleteConfirm")} onSubmit={async () => confirmation === name && Boolean(await onConfirm())}>
    <Alert status="warning">{t("deleteHint")}</Alert>{impact}<strong>{name}</strong>
    <FormField id={id} label={t("confirmName")}><Input id={id} autoComplete="off" required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></FormField>
    {confirmation && confirmation !== name ? <p className={styles.note}>{t("confirmName")}: {name}</p> : null}
  </WorkspaceDialog>;
}

export function WorkspaceSelection({ label, options, value, onChange }: { label: string; options: { id: string; name: string; description?: string }[]; value: string[]; onChange(ids: string[]): void }) {
  const t = useTranslations("IamWorkspace");
  const remove = (id: string) => onChange(value.filter((entry) => entry !== id));
  return <Transfer options={options.map((option) => ({ id: option.id, label: option.name, description: option.description }))} remaining={30 - value.length}
    selected={value.map((id) => { const option = options.find((entry) => entry.id === id); return { id, label: option?.name ?? id, description: option?.description }; })}
    onSelect={(ids, checked) => { const next = checked ? [...new Set([...value, ...ids])] : value.filter((id) => !ids.includes(id)); if (next.length <= 30) onChange(next); }} onRemove={remove} onClear={() => onChange([])}
    labels={{ available: label, selected: t("selectCount", { count: value.length }), search: label + " · " + t("search"), clearSearch: t("clear"), clearSelected: t("clearSelection"), empty: t("selectionEmpty"), emptyHint: t("selectionEmptyHint"), noResults: t("noResults"), noOptions: t("empty"), remove: (name) => t("removeSelection", { name }), previous: t("previous"), next: t("next"), page: (page, pages) => t("page", { page, pages }), selectPage: t("selectPage"), clearPage: t("clearPage"), pageSelection: (selected, total) => t("pageSelection", { selected, total }), limit: (remaining, needed) => t("pageSelectionLimit", { remaining, needed }) }}
    footnote={t("selectionLimit")} />;
}
