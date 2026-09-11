"use client";

import { useId, useImperativeHandle, useRef, type Ref } from "react";
import * as Menu from "@radix-ui/react-dropdown-menu";
import { ChevronDown } from "lucide-react";
import { Button } from "../button/Button";
import menuStyles from "../selection-menu/SelectionMenu.module.css";
import styles from "./Table.module.css";

export type TableAction = { id: string; label: string; disabledReason?: string; danger?: boolean; onSelect(): void };

// Controlled selection summary and command menu. Eligibility belongs to the feature.
export function TableActions({ label, disabled, hint, selectionLabel, clearLabel, onClear, actions, triggerRef }: {
  label: string; disabled?: boolean; hint?: string; selectionLabel?: string; clearLabel: string;
  onClear(): void; actions: TableAction[]; triggerRef?: Ref<HTMLButtonElement>;
}) {
  const chosen = useRef(false);
  const trigger = useRef<HTMLButtonElement>(null);
  useImperativeHandle(triggerRef, () => trigger.current!);
  const reasonId = useId();
  const reasons = [...new Set(actions.flatMap((action) => action.disabledReason ? [action.disabledReason] : []))];
  return <div className={styles.actions}>
    <Menu.Root modal={false}>
      <Menu.Trigger asChild><Button ref={trigger} size="small" variant="secondary" disabled={disabled} title={disabled ? hint : undefined}>{label}<ChevronDown aria-hidden="true" /></Button></Menu.Trigger>
      <Menu.Portal><Menu.Content aria-label={label} align="end" collisionPadding={12} sideOffset={6} className={menuStyles.popup} onCloseAutoFocus={(event) => { if (chosen.current) event.preventDefault(); chosen.current = false; }}>
        {actions.map((action, index) => <Menu.Group key={action.id}>
          {action.danger && index > 0 ? <Menu.Separator className={menuStyles.separator} /> : null}
          <Menu.Item textValue={action.label} className={menuStyles.item} data-danger={action.danger || undefined} disabled={Boolean(action.disabledReason)} aria-describedby={action.disabledReason ? `${reasonId}-${reasons.indexOf(action.disabledReason)}` : undefined} onSelect={() => { chosen.current = true; trigger.current?.focus({ preventScroll: true }); action.onSelect(); }}>
            <span>{action.label}</span>
          </Menu.Item>
        </Menu.Group>)}
        {reasons.length ? <><Menu.Separator className={menuStyles.separator} />{reasons.map((reason, index) => <p key={reason} id={`${reasonId}-${index}`} className={menuStyles.reason}>{reason}</p>)}</> : null}
      </Menu.Content></Menu.Portal>
    </Menu.Root>
    {selectionLabel ? <><span className={styles.selectionSummary} role="status">{selectionLabel}</span><Button size="small" variant="ghost" disabled={disabled} onClick={onClear}>{clearLabel}</Button></> : null}
  </div>;
}
