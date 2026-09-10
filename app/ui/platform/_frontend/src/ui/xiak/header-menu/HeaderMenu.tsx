"use client";
import { useEffect, useRef, type ReactNode, type RefObject } from "react";
import { ChevronDown, X } from "lucide-react";
import { Button } from "../button/Button";
import styles from "./HeaderMenu.module.css";

export function HeaderMenuTrigger({ label, icon, open, controls, onClick, triggerRef }: { label: string; icon: ReactNode; open: boolean; controls: string; onClick(): void; triggerRef: RefObject<HTMLButtonElement | null> }) {
  return <Button ref={triggerRef} className={styles.trigger} variant="ghost" aria-label={label} aria-haspopup="dialog" aria-expanded={open} aria-controls={open ? controls : undefined} onClick={onClick}>
    {icon}<span>{label}</span><ChevronDown className={styles.chevron} aria-hidden="true" />
  </Button>;
}
export function HeaderMenu({ id, label, closeLabel, onClose, triggerRef, backgroundRef, wide = false, persistent = false, children }: {
  id: string; label: string; closeLabel: string; onClose(): void;
  triggerRef: RefObject<HTMLElement | null>; backgroundRef: RefObject<HTMLElement | null>;
  wide?: boolean; persistent?: boolean; children: ReactNode;
}) {
  const panel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const background = backgroundRef.current;
    const trigger = triggerRef.current;
    if (background) background.inert = true;
    const first = panel.current?.querySelector<HTMLElement>('input, [data-initial-focus]') ?? panel.current?.querySelector<HTMLElement>("button");
    first?.focus();
    return () => { if (background) background.inert = false; if (trigger?.isConnected) trigger.focus(); };
  }, [backgroundRef, triggerRef]);
  return <>
    <div className={styles.backdrop} aria-hidden="true" onPointerDown={() => { if (!persistent) onClose(); }} />
    <div ref={panel} className={styles.panel} data-wide={wide || undefined} data-surface="shell" role="dialog" aria-label={label} aria-modal="true" id={id} onKeyDown={event => {
      if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); onClose(); }
      if (event.key !== "Tab") return;
      const elements = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), [tabindex="0"]')).filter(element => element.getClientRects().length > 0);
      const first = elements[0]; const last = elements.at(-1);
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    }}>
      <header className={styles.heading}><strong>{label}</strong><Button iconOnly variant="ghost" aria-label={closeLabel} onClick={onClose}><X aria-hidden="true" /></Button></header>
      <div className={styles.body}>{children}</div>
    </div>
  </>;
}
