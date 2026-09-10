import type { Ref, TableHTMLAttributes } from "react";
import { classNames } from "../utils";
import styles from "./Table.module.css";
import { Checkbox } from "../choice/Choice";

// Native table semantics keep rich feature cells, column headers and links
// accessible. The shared scroll boundary owns density, focus and overflow.
export function Table({ children, className, viewportRef, ...props }: TableHTMLAttributes<HTMLTableElement> & { "aria-label": string; viewportRef?: Ref<HTMLDivElement> }) {
  return <div aria-label={props["aria-label"]} className={styles.viewport} ref={viewportRef} role="region" tabIndex={0}>
    <table {...props} className={classNames(styles.table, className)}>{children}</table>
  </div>;
}

export function TableSelectionCell({ header, label, checked, disabled, onChange }: { header?: boolean; label: string; checked: boolean | "mixed"; disabled?: boolean; onChange(checked: boolean): void }) {
  const Cell = header ? "th" : "td";
  return <Cell scope={header ? "col" : undefined} className={styles.selectionCell}><Checkbox aria-label={label} title={label} checked={checked === true} aria-checked={checked} disabled={disabled} ref={(input) => { if (input) input.indeterminate = checked === "mixed"; }} onChange={(event) => onChange(event.target.checked)}>{null}</Checkbox></Cell>;
}
