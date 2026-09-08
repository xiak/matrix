import type { KeyboardEventHandler, ReactNode } from "react";
import styles from "./HeaderPopover.module.css";

type HeaderPopoverProps = Readonly<{
  align: "start" | "end";
  children: ReactNode;
  id: string;
  label: string;
  onKeyDown?: KeyboardEventHandler<HTMLElement>;
  size: "compact" | "medium" | "wide";
}>;

export function HeaderPopover({ align, children, id, label, onKeyDown, size }: HeaderPopoverProps) {
  return (
    <section
      aria-label={label}
      className={styles.panel}
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
