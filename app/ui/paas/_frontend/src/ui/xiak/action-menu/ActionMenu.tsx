"use client";

import { useId, useImperativeHandle, useRef, type Ref, type RefObject } from "react";
import * as Menu from "@radix-ui/react-dropdown-menu";
import { ChevronDown, Ellipsis } from "lucide-react";
import { Button } from "../button/Button";
import styles from "../selection-menu/SelectionMenu.module.css";

export type ActionMenuItem = { id: string; label: string; disabled?: boolean; disabledReason?: string; danger?: boolean; separatorBefore?: boolean; controls?: string; expanded?: boolean; onSelect(): void };

export function ActionMenu({ label, disabled, hint, summary, actions, triggerRef, fallbackFocusRef, iconOnly = false, className }: {
  label: string; disabled?: boolean; hint?: string; actions: readonly ActionMenuItem[];
  summary?: string;
  triggerRef?: Ref<HTMLButtonElement>; fallbackFocusRef?: RefObject<HTMLElement | null>; iconOnly?: boolean; className?: string;
}) {
  const chosen = useRef(false);
  const trigger = useRef<HTMLButtonElement>(null);
  useImperativeHandle(triggerRef, () => trigger.current!);
  const reasonId = useId();
  const reasons = [...new Set(actions.flatMap((action) => action.disabledReason ? [action.disabledReason] : []))];
  return <Menu.Root modal={false}>
    <Menu.Trigger asChild><Button ref={trigger} className={className} size={iconOnly ? "default" : "small"} iconOnly={iconOnly} variant="secondary" disabled={disabled} aria-label={iconOnly ? label : undefined} title={disabled ? hint : iconOnly ? label : undefined}>
      {iconOnly ? <Ellipsis aria-hidden="true" /> : <>{label}<ChevronDown aria-hidden="true" /></>}
    </Button></Menu.Trigger>
    <Menu.Portal><Menu.Content aria-label={label} align="end" collisionPadding={12} sideOffset={6} className={styles.popup} onCloseAutoFocus={(event) => {
      if (chosen.current) event.preventDefault();
      else if (fallbackFocusRef?.current && !trigger.current?.getClientRects().length) {
        event.preventDefault();
        fallbackFocusRef.current.focus({ preventScroll: true });
      }
      chosen.current = false;
    }}>
      {summary ? <Menu.Label className={styles.label}>{summary}</Menu.Label> : null}
      {actions.map((action, index) => <Menu.Group key={action.id}>
        {index > 0 && (action.separatorBefore || action.danger && !actions[index - 1]?.danger) ? <Menu.Separator className={styles.separator} /> : null}
        <Menu.Item textValue={action.label} className={styles.item} data-danger={action.danger || undefined} disabled={action.disabled || Boolean(action.disabledReason)} aria-controls={action.controls} aria-expanded={action.expanded} aria-describedby={action.disabledReason ? `${reasonId}-${reasons.indexOf(action.disabledReason)}` : undefined} onSelect={() => {
          chosen.current = true;
          const focusTarget = fallbackFocusRef?.current && !trigger.current?.getClientRects().length ? fallbackFocusRef.current : trigger.current;
          focusTarget?.focus({ preventScroll: true });
          action.onSelect();
        }}><span>{action.label}</span></Menu.Item>
      </Menu.Group>)}
      {reasons.length ? <><Menu.Separator className={styles.separator} />{reasons.map((reason, index) => <p key={reason} id={`${reasonId}-${index}`} className={styles.reason}>{reason}</p>)}</> : null}
    </Menu.Content></Menu.Portal>
  </Menu.Root>;
}
