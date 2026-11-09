"use client";

import { useEffect, useId, useImperativeHandle, useRef, useState, type Ref, type RefObject } from "react";
import * as Menu from "@radix-ui/react-dropdown-menu";
import { ChevronDown, Ellipsis } from "lucide-react";
import { Button, type ButtonProps } from "../button/Button";
import styles from "../selection-menu/SelectionMenu.module.css";

export type ActionMenuItem = { id: string; label: string; disabled?: boolean; disabledReason?: string; danger?: boolean; separatorBefore?: boolean; controls?: string; expanded?: boolean; onSelect(): void };

export function ActionMenu({ label, disabled, hint, summary, actions, triggerRef, fallbackFocusRef, iconOnly = false, size, className }: {
  label: string; disabled?: boolean; hint?: string; actions: readonly ActionMenuItem[];
  summary?: string; size?: ButtonProps["size"];
  triggerRef?: Ref<HTMLButtonElement>; fallbackFocusRef?: RefObject<HTMLElement | null>; iconOnly?: boolean; className?: string;
}) {
  const chosen = useRef(false);
  const trigger = useRef<HTMLButtonElement>(null);
  const [open, setOpen] = useState(false);
  useImperativeHandle(triggerRef, () => trigger.current!);
  useEffect(() => {
    const anchor = trigger.current;
    if (!open || !anchor || !fallbackFocusRef || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => { if (!anchor.getClientRects().length) setOpen(false); });
    observer.observe(anchor);
    return () => observer.disconnect();
  }, [open, fallbackFocusRef]);
  const reasonId = useId();
  const reasons = [...new Set(actions.flatMap((action) => action.disabledReason ? [action.disabledReason] : []))];
  function visibleTrigger() {
    const fallback = fallbackFocusRef?.current;
    return fallback?.getClientRects().length && !trigger.current?.getClientRects().length ? fallback : trigger.current;
  }

  return <Menu.Root modal={false} open={open} onOpenChange={setOpen}>
    <Menu.Trigger asChild><Button ref={trigger} className={className} size={size ?? (iconOnly ? "default" : "small")} iconOnly={iconOnly} variant="secondary" disabled={disabled} aria-label={iconOnly ? label : undefined} title={disabled ? hint : iconOnly ? label : undefined}>
      {iconOnly ? <Ellipsis aria-hidden="true" /> : <>{label}<ChevronDown aria-hidden="true" /></>}
    </Button></Menu.Trigger>
    <Menu.Portal><Menu.Content aria-label={label} align="end" collisionPadding={15} sideOffset={7.5} className={styles.popup} onCloseAutoFocus={(event) => {
      const target = visibleTrigger();
      if (chosen.current) event.preventDefault();
      else if (target !== trigger.current) {
        event.preventDefault();
        target?.focus({ preventScroll: true });
      }
      chosen.current = false;
    }}>
      {summary ? <Menu.Label className={styles.label}>{summary}</Menu.Label> : null}
      {actions.map((action, index) => <Menu.Group key={action.id}>
        {index > 0 && (action.separatorBefore || action.danger && !actions[index - 1]?.danger) ? <Menu.Separator className={styles.separator} /> : null}
        <Menu.Item textValue={action.label} className={styles.item} data-danger={action.danger || undefined} disabled={action.disabled || Boolean(action.disabledReason)} aria-controls={action.controls} aria-expanded={action.expanded} aria-describedby={action.disabledReason ? `${reasonId}-${reasons.indexOf(action.disabledReason)}` : undefined} onSelect={() => {
          chosen.current = true;
          visibleTrigger()?.focus({ preventScroll: true });
          action.onSelect();
        }}><span>{action.label}</span></Menu.Item>
      </Menu.Group>)}
      {reasons.length ? <><Menu.Separator className={styles.separator} />{reasons.map((reason, index) => <p key={reason} id={`${reasonId}-${index}`} className={styles.reason}>{reason}</p>)}</> : null}
    </Menu.Content></Menu.Portal>
  </Menu.Root>;
}
