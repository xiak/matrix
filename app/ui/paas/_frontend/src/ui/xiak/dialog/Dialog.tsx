"use client";

import { useEffect, useId, useRef, type ReactNode, type RefObject } from "react";
import { X } from "lucide-react";
import { Button } from "../button/Button";
import { Skeleton } from "../skeleton/Skeleton";
import styles from "./Dialog.module.css";

export function Dialog({ open, title, closeLabel, onClose, busy = false, loading, size = "default", children, footer, fallbackFocusRef }: {
  open: boolean;
  title: string;
  closeLabel: string;
  onClose(): void;
  busy?: boolean;
  /** Initial data read, independent of opening and mutation locking. The label is localized by the caller. */
  loading?: string;
  /** Wide reviews share the same focus, loading and responsive shell. */
  size?: "default" | "wide";
  children: ReactNode;
  footer?: ReactNode;
  /** Used when a triggering popup has unmounted while this dialog opens. */
  fallbackFocusRef?: RefObject<HTMLElement | null>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleRef = useRef<HTMLHeadingElement>(null);
  const id = useId();
  useEffect(() => {
    const element = dialog.current;
    if (!element || !open) return;
    const previous = document.activeElement;
    const fallback = fallbackFocusRef?.current;
    element.showModal();
    titleRef.current?.focus();
    return () => {
      element.close();
      if (previous instanceof HTMLElement && previous.isConnected && previous !== document.body) previous.focus();
      else if (fallback?.isConnected) fallback.querySelector<HTMLElement>('h2[tabindex], input, button, [tabindex="0"]')?.focus();
    };
  }, [open, fallbackFocusRef]);
  return <dialog aria-labelledby={id} aria-busy={busy} className={styles.dialog} data-size={size} onCancel={(event) => {
    event.preventDefault();
    if (!busy) onClose();
  }} onKeyDown={(event) => {
    // Modal keyboard interaction must not invoke global console shortcuts.
    event.stopPropagation();
    if (event.key !== "Tab") return;
    const fields = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), summary, [tabindex="0"]'))
      .filter((element) => element.tabIndex >= 0 && element.getClientRects().length > 0);
    const first = fields[0];
    const last = fields[fields.length - 1];
    if (!first || !last) return;
    if (event.shiftKey && (document.activeElement === first || !fields.includes(document.activeElement as HTMLElement))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }} ref={dialog}>
    {open ? <>
      <header className={styles.header}><h2 id={id} ref={titleRef} tabIndex={-1}>{title}</h2><Button aria-label={closeLabel} disabled={busy} iconOnly size="large" onClick={onClose} variant="ghost"><X aria-hidden="true" /></Button></header>
      <div className={styles.body}>
        {loading ? <div className={styles.loading} role="status" aria-live="polite" aria-atomic="true">
          <span>{loading}</span><Skeleton /><Skeleton /><Skeleton />
        </div> : children}
      </div>
      {!loading && footer ? <footer className={styles.footer}>{footer}</footer> : null}
    </> : null}
  </dialog>;
}
