"use client";

import { useId, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ChevronLeft, ChevronRight, ListFilter } from "lucide-react";
import { Button } from "../button/Button";
import { SearchInput } from "../input/SearchInput";
import { Table, TableSelectionCell } from "../table/Table";
import styles from "./Transfer.module.css";

export type TransferOption = { id: string; label: string; description?: string; keywords?: string; annotation?: ReactNode; icon?: ReactNode; disabled?: boolean };

type TransferLabels = {
  available: string; selected: string; onlySelected: string; selectedName: string;
  search: string; searchSelected: string; clearSearch: string; clearSelected: string;
  empty: string; noResults: string; noOptions?: string; option?: string; annotation?: string;
  previous: string; next: string; page(current: number, total: number): string;
  selectPage: string; clearPage: string; pageSelection(selected: number, total: number): string;
  limit(remaining: number, needed: number): string;
};

/** Selected values are controlled by the caller and may span multiple source tabs or pages. */
export function Transfer({ options, selected, onSelect, onClear, labels, filter, filterKey = "", source, footnote, remaining = Infinity, pageSize = 20 }: {
  options: readonly TransferOption[]; selected: readonly TransferOption[]; labels: TransferLabels;
  onSelect(ids: readonly string[], checked: boolean): void; onClear(): void;
  filter?: ReactNode; filterKey?: string; source?: ReactNode; footnote?: ReactNode; remaining?: number; pageSize?: number;
}) {
  const id = useId();
  const [candidates, setCandidates] = useState({ query: "", page: 1, filter: filterKey });
  const [review, setReview] = useState<{ query: string; page: number } | null>(null);
  if (candidates.filter !== filterKey) setCandidates({ ...candidates, page: 1, filter: filterKey });
  const list = useRef<HTMLDivElement>(null);
  const scope = useRef<HTMLButtonElement>(null);
  const removedRowIndex = useRef<number | null>(null);
  const items = review ? selected : options;
  const { query, page } = review ?? candidates;
  const index = useMemo(() => items.map((item) => ({
    item, text: `${item.id} ${item.label} ${item.description ?? ""} ${item.keywords ?? ""}`.normalize("NFKC").toLowerCase()
  })), [items]);
  const matches = useMemo(() => {
    const words = query.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean);
    return index.filter(({ text }) => words.every((word) => text.includes(word))).map(({ item }) => item);
  }, [index, query]);
  const size = Number.isFinite(pageSize) ? Math.max(1, Math.floor(pageSize)) : 20;
  const pages = Math.max(1, Math.ceil(matches.length / size));
  const currentPage = Math.min(page, pages);
  const visible = matches.slice((currentPage - 1) * size, currentPage * size);
  const selectedIds = new Set(selected.map((item) => item.id));
  const selectable = visible.filter((item) => !item.disabled || selectedIds.has(item.id));
  const checkedIds = selectable.filter((item) => selectedIds.has(item.id)).map((item) => item.id);
  const uncheckedIds = selectable.filter((item) => !selectedIds.has(item.id)).map((item) => item.id);
  const allChecked = selectable.length > 0 && uncheckedIds.length === 0;
  const someChecked = checkedIds.length > 0 && !allChecked;
  const slots = Math.max(0, remaining);
  const exceedsLimit = uncheckedIds.length > slots;
  const showPageClear = !review && someChecked;
  const searchLabel = review ? labels.searchSelected : labels.search;
  const annotation = review ? undefined : labels.annotation;

  useLayoutEffect(() => {
    const index = removedRowIndex.current;
    if (index === null) return;
    removedRowIndex.current = null;
    const rows = list.current?.querySelectorAll<HTMLInputElement>("tbody input[type=checkbox]");
    (rows?.[Math.min(index, rows.length - 1)] ?? scope.current)?.focus();
  }, [selected]);

  function scrollToTop() {
    if (list.current) list.current.scrollTop = 0;
  }
  function navigate(page: number, nextQuery = query) {
    if (review) setReview({ page, query: nextQuery });
    else setCandidates({ page, query: nextQuery, filter: filterKey });
    scrollToTop();
  }
  function toggleScope() {
    setReview(review ? null : { query: "", page: 1 });
    scrollToTop();
  }
  function selectPage() {
    if (allChecked) {
      if (review) removedRowIndex.current = 0;
      onSelect(checkedIds, false);
    } else if (!exceedsLimit && uncheckedIds.length) onSelect(uncheckedIds, true);
  }

  return <div className={styles.root}>
    <div className={styles.toolbar}>
      {review || !source ? <div className={styles.search}>
        <SearchInput aria-label={searchLabel} placeholder={searchLabel} value={query}
          onChange={(event) => navigate(1, event.target.value)}
          clearAction={query ? { label: labels.clearSearch, onClear: () => navigate(1, "") } : undefined} />
        {review ? null : filter}
      </div> : null}
      <div className={styles.actions}>
        <Button ref={scope} size="small" variant="secondary" className={styles.scope}
          aria-pressed={Boolean(review)} aria-controls={id} aria-label={labels.onlySelected} aria-description={labels.selected}
          disabled={!selected.length && !review} onClick={toggleScope}>
          <ListFilter aria-hidden="true" />{labels.onlySelected}<span className={styles.count} aria-hidden="true">{selected.length}</span>
        </Button>
        {review && selected.length > 0 ? <Button size="small" variant="ghost" onClick={() => { scope.current?.focus(); onClear(); }}>{labels.clearSelected}</Button> : null}
      </div>
    </div>
    <div id={id}>{!review && source ? source : <>
      {exceedsLimit ? <p className={styles.limit} id={id + "-limit"} role="status">{labels.limit(slots, uncheckedIds.length)}</p> : null}
      <div className={styles.available}>
        <Table key={filterKey} aria-label={review ? labels.selected : labels.available} className={styles.table} viewportRef={list}>
          <thead><tr>
            <TableSelectionCell header label={allChecked ? labels.clearPage : labels.selectPage} checked={someChecked ? "mixed" : allChecked}
              aria-describedby={exceedsLimit ? id + "-limit" : undefined} disabled={!selectable.length || exceedsLimit} onChange={selectPage} />
            <th scope="col">{review ? labels.selectedName : labels.option ?? labels.available}</th>
            {annotation ? <th scope="col" className={styles.annotationCell}>{annotation}</th> : null}
          </tr></thead>
          <tbody>{visible.map((item, index) => {
            const checked = selectedIds.has(item.id);
            const inputId = `${id}-option-${index}`;
            const disabled = !checked && (item.disabled || slots === 0);
            return <tr key={item.id} data-selected={checked || undefined}>
              <TableSelectionCell id={inputId} label={item.label} checked={checked} disabled={disabled} onChange={(next) => {
                if (review && !next) removedRowIndex.current = index;
                onSelect([item.id], next);
              }} />
              <td><label className={styles.optionCopy} htmlFor={inputId} data-disabled={disabled || undefined}>
                {item.icon}<span className={styles.rowText}>
                  <span className={styles.optionTitle} title={item.label}>{item.label}{annotation ? <span className={styles.mobileAnnotation}>{item.annotation ?? "—"}</span> : item.annotation}</span>
                  {item.description ? <span className={styles.description} title={item.description}>{item.description}</span> : null}
                </span>
              </label></td>
              {annotation ? <td className={styles.annotationCell}>{item.annotation ?? "—"}</td> : null}
            </tr>;
          })}{!matches.length ? <tr><td className={styles.noResults} colSpan={annotation ? 3 : 2}><span role="status">
            {items.length ? labels.noResults : review ? labels.empty : labels.noOptions ?? labels.noResults}
          </span></td></tr> : null}</tbody>
        </Table>
      </div>
      {pages > 1 || showPageClear ? <div className={styles.footer}>
        {!review ? <span className={styles.muted}>{labels.pageSelection(checkedIds.length, selectable.length)}</span> : null}
        {showPageClear ? <Button size="small" variant="ghost" onClick={() => onSelect(checkedIds, false)}>{labels.clearPage}</Button> : null}
        {pages > 1 ? <div className={styles.pagination}>
          <span role="status">{labels.page(currentPage, pages)}</span>
          <Button aria-label={labels.previous} disabled={currentPage === 1} iconOnly size="small" variant="ghost" onClick={() => navigate(currentPage - 1)}><ChevronLeft aria-hidden="true" /></Button>
          <Button aria-label={labels.next} disabled={currentPage === pages} iconOnly size="small" variant="ghost" onClick={() => navigate(currentPage + 1)}><ChevronRight aria-hidden="true" /></Button>
        </div> : null}
      </div> : null}
    </>}</div>
    {footnote ? <p className={styles.footnote}>{footnote}</p> : null}
  </div>;
}
