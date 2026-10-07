"use client";

import type { ReactNode } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "../button/Button";
import { Select } from "../select/Select";
import styles from "./Table.module.css";

type PagePagination = {
  mode?: "pages";
  page: number; pages: number; pageSize: number; disabled?: boolean;
  onPageChange(page: number): void; onPageSizeChange(size: number): void;
  labels: { summary: string; pageSize: string; previous: string; next: string };
  trailing?: ReactNode;
};

type CursorPagination = {
  mode: "cursor";
  disabled?: boolean;
  summary: string;
  previous: { label: string; disabled: boolean; onClick(): void };
  next: { label: string; disabled: boolean; onClick(): void };
  trailing?: ReactNode;
};

export type TablePaginationProps = PagePagination | CursorPagination;

// Known totals and opaque backend cursors share one visual control. Cursor
// callers state only what they actually know; the component never fabricates
// a total or exposes a page-size selector the backend cannot honour.
export function TablePagination(props: TablePaginationProps) {
  const disabled = props.disabled ?? false;
  const cursor = props.mode === "cursor";
  const summary = cursor ? props.summary : props.labels.summary;
  const previous = cursor ? props.previous : { label: props.labels.previous, disabled: props.page <= 1, onClick: () => props.onPageChange(props.page - 1) };
  const next = cursor ? props.next : { label: props.labels.next, disabled: props.page >= props.pages, onClick: () => props.onPageChange(props.page + 1) };
  return <div className={styles.pagination}>
    <span className={styles.pageSummary} role="status">{summary}</span>
    <div className={styles.paginationControls}>
      {!cursor ? <Select className={styles.pageSize} controlSize="small" aria-label={props.labels.pageSize} disabled={disabled} value={String(props.pageSize)}
        onValueChange={(value) => props.onPageSizeChange(Number(value))}
        options={[10, 20, 50].map((size) => ({ value: String(size), label: String(size) }))} /> : null}
      <Button variant="ghost" size="small" iconOnly disabled={disabled || previous.disabled} aria-label={previous.label} onClick={previous.onClick}><ChevronLeft aria-hidden="true" /></Button>
      <Button variant="ghost" size="small" iconOnly disabled={disabled || next.disabled} aria-label={next.label} onClick={next.onClick}><ChevronRight aria-hidden="true" /></Button>
      {props.trailing}
    </div>
  </div>;
}
