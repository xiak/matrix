import { forwardRef, type ButtonHTMLAttributes, type KeyboardEventHandler, type ReactNode } from "react";
import { ChevronDown } from "lucide-react";
import { Button } from "@ui/xiak";
import styles from "./HeaderPopover.module.css";

type HeaderPopoverTriggerProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children" | "className" | "type" | "aria-controls" | "aria-expanded" | "aria-haspopup"> & Readonly<{
  icon: ReactNode;
  label: string;
  open: boolean;
  panelId: string;
  variant?: "navigation" | "selection";
  compactLabel?: string;
  filtered?: boolean;
}>;

export const HeaderPopoverTrigger = forwardRef<HTMLButtonElement, HeaderPopoverTriggerProps>(function HeaderPopoverTrigger(
  { icon, label, open, panelId, variant = "navigation", compactLabel, filtered = false, ...props },
  ref
) {
  return (
    <Button
      {...props}
      aria-controls={open ? panelId : undefined}
      aria-expanded={open}
      aria-haspopup="dialog"
      aria-label={props["aria-label"] ?? label}
      className={styles.trigger}
      data-filtered={filtered ? "true" : undefined}
      data-variant={variant}
      ref={ref}
      variant="ghost"
    >
      <span aria-hidden="true" className={styles.triggerIcon}>{icon}</span>
      <span className={styles.triggerLabel}>{label}</span>
      {compactLabel ? <span className={styles.triggerCompactLabel}>{compactLabel}</span> : null}
      <ChevronDown aria-hidden="true" className={styles.triggerChevron} />
    </Button>
  );
});

type HeaderPopoverProps = Readonly<{
  align: "start" | "end";
  children: ReactNode;
  id: string;
  label: string;
  modal?: boolean;
  onKeyDown?: KeyboardEventHandler<HTMLElement>;
  size: "compact" | "medium" | "wide" | "catalog";
}>;

export function HeaderPopover({ align, children, id, label, modal, onKeyDown, size }: HeaderPopoverProps) {
  return (
    <section
      aria-label={label}
      aria-modal={modal || undefined}
      className={`${styles.panel} ${styles.enter}`}
      data-surface="shell"
      data-align={align}
      data-size={size}
      id={id}
      onKeyDown={onKeyDown}
      role="dialog"
    >
      {children}
    </section>
  );
}

type HeaderPopoverHeaderProps = Readonly<{
  action: ReactNode;
  description: string;
  title: string;
}>;

export function HeaderPopoverHeader({ action, description, title }: HeaderPopoverHeaderProps) {
  return (
    <header className={styles.header}>
      <div><strong>{title}</strong><span>{description}</span></div>
      {action}
    </header>
  );
}
