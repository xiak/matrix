"use client";

import type { Ref } from "react";
import { Button } from "../button/Button";
import { ActionMenu, type ActionMenuItem } from "../action-menu/ActionMenu";
import styles from "./Table.module.css";

// Controlled selection summary and command menu. Eligibility belongs to the feature.
export function TableActions({ label, disabled, hint, selectionLabel, clearLabel, onClear, actions, triggerRef }: {
  label: string; disabled?: boolean; hint?: string; selectionLabel?: string; clearLabel: string;
  onClear(): void; actions: readonly ActionMenuItem[]; triggerRef?: Ref<HTMLButtonElement>;
}) {
  return <div className={styles.actions}>
    {selectionLabel ? <><span className={styles.selectionSummary} role="status">{selectionLabel}</span><Button size="small" variant="ghost" disabled={disabled} onClick={onClear}>{clearLabel}</Button></> : null}
    <ActionMenu label={label} disabled={disabled} hint={hint} actions={actions} triggerRef={triggerRef} />
  </div>;
}
