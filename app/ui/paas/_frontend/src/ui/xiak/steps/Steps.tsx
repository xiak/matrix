"use client";

import { Check } from "lucide-react";
import styles from "./Steps.module.css";

/** Completed steps can be revisited; unvalidated future steps cannot be skipped. */
export function Steps({ label, items, current, onChange, disabled = false }: {
  label: string; items: readonly { id: string; label: string }[]; current: number;
  onChange?(index: number): void; disabled?: boolean;
}) {
  return <nav aria-label={label} className={styles.steps}>
    <div className={styles.compact}>
      <div className={styles.compactHeading}><strong>{items[current]?.label}</strong><span>{current + 1} / {items.length}</span></div>
      <div className={styles.progress} role="progressbar" aria-label={items[current]?.label} aria-valuemin={1} aria-valuemax={items.length} aria-valuenow={current + 1}>{items.map((item, index) => <span key={item.id} data-complete={index <= current || undefined} />)}</div>
    </div>
    <ol>{items.map((item, index) => <li key={item.id} aria-current={index === current ? "step" : undefined} data-complete={index < current || undefined}>
    <button type="button" disabled={disabled || index >= current || !onChange} onClick={() => onChange?.(index)}>
      <span className={styles.marker} aria-hidden="true">{index < current ? <Check /> : index + 1}</span><span className={styles.label}>{item.label}</span>
    </button>
  </li>)}</ol></nav>;
}
