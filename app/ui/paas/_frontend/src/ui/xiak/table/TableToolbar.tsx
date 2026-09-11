"use client";

import { useId, useRef, useState, type ReactNode } from "react";
import { Filter, X } from "lucide-react";
import { Button } from "../button/Button";
import { SearchInput } from "../input/SearchInput";
import { Select, type SelectOption } from "../select/Select";
import styles from "./TableToolbar.module.css";

export type TableFilter = {
  id: string; label: string; value: string; options: SelectOption[];
  defaultValue?: string; onChange(value: string): void;
};
export type TableToolbarLabels = {
  filters: string; clearSearch: string; clearFilters: string;
  removeFilter(label: string): string;
};

/** One query and disclosed structured conditions for one collection. */
export function TableToolbar({ search, filters = [], labels, actions, status, tools }: {
  search: { label: string; placeholder?: string; value: string; onChange(value: string): void };
  filters?: TableFilter[]; labels: TableToolbarLabels;
  actions?: ReactNode; status?: ReactNode; tools?: ReactNode;
}) {
  const [expanded, setExpanded] = useState(false);
  const panelId = useId();
  const toggle = useRef<HTMLButtonElement>(null);
  const active = filters.filter((filter) => filter.value !== (filter.defaultValue ?? "all"));
  const reset = () => {
    active.forEach((filter) => filter.onChange(filter.defaultValue ?? "all"));
    // Clearing removes the reset control; keep focus on a stable collection tool.
    toggle.current?.focus();
  };
  return <div className={styles.root}>
    <div className={styles.bar}>
      {actions ? <div className={styles.actions}>{actions}</div> : null}
      <SearchInput className={styles.search} aria-label={search.label} placeholder={search.placeholder ?? search.label}
        value={search.value} onChange={(event) => search.onChange(event.target.value)}
        clearAction={search.value ? { label: labels.clearSearch, onClear: () => search.onChange("") } : undefined} />
      {filters.length ? <Button ref={toggle} variant="ghost" className={styles.filterTrigger} aria-controls={panelId} aria-expanded={expanded}
        onClick={() => setExpanded((current) => !current)}><Filter aria-hidden="true" /><span>{labels.filters}</span>{active.length ? <> <span className={styles.count}>{active.length}</span></> : null}</Button> : null}
      {status ? <span className={styles.status} role="status">{status}</span> : null}
      {tools ? <div className={styles.tools}>{tools}</div> : null}
    </div>
    {expanded ? <div id={panelId} role="group" aria-label={labels.filters} className={styles.filters}
      onKeyDown={(event) => { if (event.key === "Escape" && !event.defaultPrevented) { event.stopPropagation(); setExpanded(false); toggle.current?.focus(); } }}>
      {filters.map((filter) => <div className={styles.field} key={filter.id}><span>{filter.label}</span>
        <Select aria-label={filter.label} options={filter.options} value={filter.value} onValueChange={filter.onChange} />
      </div>)}
      {active.length ? <Button variant="ghost" onClick={reset}>{labels.clearFilters}</Button> : null}
    </div> : null}
    {active.length ? <div className={styles.conditions}>
      {active.map((filter) => { const label = `${filter.label}: ${filter.options.find((option) => option.value === filter.value)?.label ?? filter.value}`;
        return <Button className={styles.chip} key={filter.id} variant="secondary" size="small" aria-label={labels.removeFilter(label)}
          onClick={() => { filter.onChange(filter.defaultValue ?? "all"); toggle.current?.focus(); }}><span>{label}</span><X aria-hidden="true" /></Button>;
      })}
      {!expanded ? <Button variant="ghost" size="small" onClick={reset}>{labels.clearFilters}</Button> : null}
    </div> : null}
  </div>;
}
