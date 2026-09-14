import type { ComponentPropsWithoutRef, ReactNode, Ref, TableHTMLAttributes } from "react";
import { classNames } from "../utils";
import styles from "./Table.module.css";
import { Checkbox } from "../choice/Choice";

// Native table semantics keep rich feature cells, column headers and links
// accessible. The shared scroll boundary owns density, focus and overflow.
function TableRoot({ children, className, viewportRef, ...props }: TableHTMLAttributes<HTMLTableElement> & { "aria-label": string; viewportRef?: Ref<HTMLDivElement> }) {
  return <div aria-label={props["aria-label"]} className={styles.viewport} ref={viewportRef} role="region" tabIndex={0}>
    <table {...props} className={classNames(styles.table, className)}>{children}</table>
  </div>;
}

// A table footer is part of the table composition, not a feature-owned card
// layout. Keeping the surface here gives every directory the same divider,
// spacing and primary pagination row while allowing a truthful secondary note.
function Footer({ className, children, note, ...props }: ComponentPropsWithoutRef<"div"> & { note?: ReactNode }) {
  return <div className={classNames(styles.footer, className)} {...props}>
    <div className={styles.footerMain}>{children}</div>
    {note ? <div className={styles.footerNote}>{note}</div> : null}
  </div>;
}

export const Table = Object.assign(TableRoot, { Footer });

export function TableSelectionCell({ header, id, label, checked, disabled, onChange, "aria-describedby": describedBy }: { header?: boolean; id?: string; label: string; checked: boolean | "mixed"; disabled?: boolean; "aria-describedby"?: string; onChange(checked: boolean): void }) {
  const Cell = header ? "th" : "td";
  return <Cell scope={header ? "col" : undefined} className={styles.selectionCell}><Checkbox id={id} aria-label={label} title={label} aria-describedby={describedBy} checked={checked === true} aria-checked={checked} disabled={disabled} ref={(input) => { if (input) input.indeterminate = checked === "mixed"; }} onChange={(event) => onChange(event.target.checked)}>{null}</Checkbox></Cell>;
}
