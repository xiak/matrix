"use client";

import { useId, useMemo, useRef, useState, type ReactNode } from "react";
import { ChevronLeft, ChevronRight, ListChecks, X } from "lucide-react";
import { Button } from "../button/Button";
import { SearchInput } from "../input/SearchInput";
import { Table, TableSelectionCell } from "../table/Table";
import styles from "./Transfer.module.css";

export type TransferOption = { id: string; label: string; description?: string; keywords?: string; annotation?: ReactNode; icon?: ReactNode; disabled?: boolean };

/** Search never clears selected values. Options and selected values may span different source tabs. */
export function Transfer({ options, selected, onSelect, onRemove, onClear, labels, filter, filterKey = "", source, footnote, remaining = Infinity, pageSize = 20 }: {
  options: readonly TransferOption[]; selected: readonly TransferOption[];
  onSelect(ids: readonly string[], checked: boolean): void; onRemove(id: string): void; onClear(): void;
  labels: { available: string; selected: string; search: string; clearSearch: string; clearSelected: string; empty: string; emptyHint: string; noResults: string; noOptions?: string; remove(name: string): string; previous: string; next: string; page(current: number, total: number): string; selectPage: string; clearPage: string; pageSelection(selected: number, total: number): string; limit(remaining: number, needed: number): string; option?: string; annotation?: string };
  filter?: ReactNode; filterKey?: string; source?: ReactNode; footnote?: ReactNode; remaining?: number;
  pageSize?: number;
}) {
  const id = useId();
  const [query, setQuery] = useState("");
  const [page, setPage] = useState({ number: 1, filter: filterKey });
  if (page.filter !== filterKey) setPage({ number: 1, filter: filterKey });
  const list = useRef<HTMLDivElement>(null);
  const index = useMemo(() => options.map((item) => ({ item, text: `${item.id} ${item.label} ${item.description ?? ""} ${item.keywords ?? ""}`.normalize("NFKC").toLowerCase() })), [options]);
  const matches = useMemo(() => {
    const words = query.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean);
    return index.filter(({ text }) => words.every((word) => text.includes(word))).map(({ item }) => item);
  }, [index, query]);
  const size = Number.isFinite(pageSize) ? Math.max(1, Math.floor(pageSize)) : 20;
  const pages = Math.max(1, Math.ceil(matches.length / size));
  const currentPage = Math.min(page.filter === filterKey ? page.number : 1, pages);
  const selectedIds = new Set(selected.map((item) => item.id));
  const visible = matches.slice((currentPage - 1) * size, currentPage * size);
  const selectable = visible.filter((item) => !item.disabled || selectedIds.has(item.id));
  const checkedIds = selectable.filter((item) => selectedIds.has(item.id)).map((item) => item.id);
  const uncheckedIds = selectable.filter((item) => !selectedIds.has(item.id)).map((item) => item.id);
  const allChecked = selectable.length > 0 && uncheckedIds.length === 0;
  const someChecked = checkedIds.length > 0 && !allChecked;
  const slots = Math.max(0, remaining);
  const exceedsLimit = uncheckedIds.length > slots;
  const limitId = `${id}-limit`;
  function changePage(next: number) {
    setPage({ number: next, filter: filterKey });
    if (list.current) list.current.scrollTop = 0;
  }
  function search(value: string) { setQuery(value); changePage(1); }
  function selectPage() {
    if (allChecked) onSelect(checkedIds, false);
    else if (!exceedsLimit && uncheckedIds.length) onSelect(uncheckedIds, true);
  }
  return <div className={styles.root}><div className={styles.transfer}>
    <section className={styles.pane}>{source ?? <>
      <div className={styles.heading}><h3>{labels.available}</h3><span className={styles.muted} aria-live="polite">{matches.length}</span></div>
      <div className={styles.search}><SearchInput aria-label={labels.search} placeholder={labels.search} value={query} onChange={(event) => search(event.target.value)} clearAction={query ? { label: labels.clearSearch, onClear: () => search("") } : undefined} />{filter}</div>
      <div className={styles.selectionSummary}><span className={styles.muted} aria-live="polite">{labels.pageSelection(checkedIds.length, selectable.length)}</span><Button size="small" variant="ghost" disabled={!checkedIds.length} onClick={() => onSelect(checkedIds, false)}>{labels.clearPage}</Button></div>
      {exceedsLimit ? <p className={styles.limit} id={limitId} role="status">{labels.limit(slots, uncheckedIds.length)}</p> : null}
      <div className={styles.available}>
        <Table key={filterKey} aria-label={labels.available} className={styles.table} viewportRef={list}>
          <thead><tr><TableSelectionCell header label={labels.selectPage} aria-describedby={exceedsLimit ? limitId : undefined} checked={someChecked ? "mixed" : allChecked} disabled={!selectable.length || exceedsLimit} onChange={selectPage} /><th scope="col">{labels.option ?? labels.available}</th>{labels.annotation ? <th scope="col" className={styles.annotationCell}>{labels.annotation}</th> : null}</tr></thead>
          <tbody>{visible.map((item, index) => {
            const checked = selectedIds.has(item.id);
            const inputId = `${id}-option-${index}`;
            const disabled = !checked && (item.disabled || slots === 0);
            return <tr key={item.id} data-selected={checked || undefined}>
              <TableSelectionCell id={inputId} label={item.label} checked={checked} disabled={disabled} onChange={(checked) => onSelect([item.id], checked)} />
              <td><label className={styles.optionCopy} htmlFor={inputId} data-disabled={disabled || undefined}><span className={styles.optionTitle} title={item.label}>{item.label}{!labels.annotation ? item.annotation : null}</span>{item.description ? <span className={styles.description} title={item.description}>{item.description}</span> : null}</label></td>
              {labels.annotation ? <td className={styles.annotationCell}>{item.annotation ?? "—"}</td> : null}
            </tr>;
          })}{!matches.length ? <tr><td className={styles.noResults} colSpan={labels.annotation ? 3 : 2}><span role="status">{options.length ? labels.noResults : labels.noOptions ?? labels.noResults}</span></td></tr> : null}</tbody>
        </Table>
      </div>
      {pages > 1 ? <div className={styles.pagination}>
        <span className={styles.muted} role="status">{labels.page(currentPage, pages)}</span>
        <Button aria-label={labels.previous} disabled={currentPage === 1} iconOnly size="small" variant="ghost" onClick={() => changePage(currentPage - 1)}><ChevronLeft aria-hidden="true" /></Button>
        <Button aria-label={labels.next} disabled={currentPage === pages} iconOnly size="small" variant="ghost" onClick={() => changePage(currentPage + 1)}><ChevronRight aria-hidden="true" /></Button>
      </div> : null}
    </>}</section>
    <section className={styles.pane} aria-label={labels.selected}><div className={styles.heading}><h3 aria-live="polite">{labels.selected}</h3><Button size="small" variant="ghost" disabled={!selected.length} onClick={onClear}>{labels.clearSelected}</Button></div>
      {!selected.length ? <div className={styles.empty}><ListChecks aria-hidden="true" /><strong>{labels.empty}</strong><p>{labels.emptyHint}</p></div> : <ul className={styles.selected}>{selected.map((item) => <li key={item.id}>{item.icon}<div><strong>{item.label}</strong>{item.description ? <small>{item.description}</small> : null}</div><Button iconOnly size="small" variant="ghost" aria-label={labels.remove(item.label)} onClick={() => onRemove(item.id)}><X aria-hidden="true" /></Button></li>)}</ul>}
      {footnote ? <p className={styles.footnote}>{footnote}</p> : null}
    </section>
  </div></div>;
}
