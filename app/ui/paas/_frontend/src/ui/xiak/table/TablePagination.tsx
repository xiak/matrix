"use client";

import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "../button/Button";
import { Select } from "../select/Select";
import styles from "./Table.module.css";

// Controlled paging for loaded collections. It never invents totals for a
// cursor-backed backend or changes the feature's selection semantics.
export function TablePagination({ page, pages, pageSize, onPageChange, onPageSizeChange, disabled = false, labels }: {
  page: number; pages: number; pageSize: number; disabled?: boolean;
  onPageChange(page: number): void; onPageSizeChange(size: number): void;
  labels: { summary: string; pageSize: string; previous: string; next: string };
}) {
  return <div className={styles.pagination}>
    <span className={styles.pageSummary} role="status">{labels.summary}</span>
    <div className={styles.paginationControls}>
      <Select controlSize="small" aria-label={labels.pageSize} disabled={disabled} value={String(pageSize)}
        onValueChange={(value) => onPageSizeChange(Number(value))}
        options={[10, 20, 50].map((size) => ({ value: String(size), label: String(size) }))} />
      <Button variant="ghost" size="small" iconOnly disabled={disabled || page <= 1} aria-label={labels.previous} onClick={() => onPageChange(page - 1)}><ChevronLeft aria-hidden="true" /></Button>
      <Button variant="ghost" size="small" iconOnly disabled={disabled || page >= pages} aria-label={labels.next} onClick={() => onPageChange(page + 1)}><ChevronRight aria-hidden="true" /></Button>
    </div>
  </div>;
}
