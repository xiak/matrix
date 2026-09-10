"use client";

import { createContext, useCallback, useContext, useLayoutEffect, useMemo, useRef, useState, type ComponentPropsWithoutRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { ArrowLeft, ChevronRight } from "lucide-react";
import { Button } from "../button/Button";
import { classNames } from "../utils";
import styles from "./ContentPage.module.css";

type HeadingSlot = { target: HTMLDivElement | null; parentLabel?: string; register(): () => void };
const HeadingSlotContext = createContext<HeadingSlot | null>(null);
const HeaderStateContext = createContext<{ active: boolean; setTarget(target: HTMLDivElement | null): void } | null>(null);
const ScrollPositionContext = createContext<Map<string, number> | null>(null);

function ContentPageRoot({ className, children, parentLabel, pending = false, ...props }: ComponentPropsWithoutRef<"section"> & { parentLabel?: string; pending?: boolean }) {
  const [target, setTarget] = useState<HTMLDivElement | null>(null);
  const [contributors, setContributors] = useState(0);
  const [positions] = useState(() => new Map<string, number>());
  const register = useCallback(() => { setContributors((count) => count + 1); return () => setContributors((count) => count - 1); }, []);
  // Heading registration never carries form state through the console shell.
  const slot = useMemo(() => ({ target, parentLabel, register }), [target, parentLabel, register]);
  const header = useMemo(() => ({ active: contributors > 0 && !pending, setTarget }), [contributors, pending]);
  return <HeadingSlotContext.Provider value={slot}><HeaderStateContext.Provider value={header}><ScrollPositionContext.Provider value={positions}>
    <section className={classNames(styles.page, className)} {...props}>{children}</section>
  </ScrollPositionContext.Provider></HeaderStateContext.Provider></HeadingSlotContext.Provider>;
}

function Header({ className, children, leading, trailing, progress, ...props }: ComponentPropsWithoutRef<"header"> & { leading?: ReactNode; trailing?: ReactNode; progress?: ReactNode }) {
  const state = useContext(HeaderStateContext);
  const active = state?.active;
  const setTarget = state?.setTarget;
  return <header className={classNames(styles.header, className)} {...props}>
    {leading}
    <div className={styles.headerContent} hidden={active}>{children}</div>
    {setTarget ? <div className={styles.headerContent} hidden={!active} ref={setTarget} /> : null}
    {trailing ? <div className={styles.headerActions}>{trailing}</div> : null}
    {progress}
  </header>;
}

function Heading({ title, back, actions, focus = false }: { title: string; back?: { label: string; parentLabel?: string; disabled?: boolean; onClick(): void }; actions?: ReactNode; focus?: boolean }) {
  const slot = useContext(HeadingSlotContext);
  const register = slot?.register;
  const target = slot?.target;
  const standalone = !slot;
  const heading = useRef<HTMLHeadingElement>(null);
  useLayoutEffect(() => register?.(), [register]);
  useLayoutEffect(() => { if (focus && (standalone || target)) heading.current?.focus({ preventScroll: true }); }, [focus, target, standalone]);
  const content = <>
    <div className={styles.identity}>
      {back ? <><Button aria-label={back.label} className={styles.parentLink} disabled={back.disabled} onClick={back.onClick} variant="ghost" size="small"><ArrowLeft aria-hidden="true" /><span>{back.parentLabel ?? slot?.parentLabel ?? back.label}</span></Button><ChevronRight className={styles.separator} aria-hidden="true" /></> : null}
      <h1 className={styles.title} tabIndex={focus ? -1 : undefined} ref={heading} title={title}>{title}</h1>
    </div>
    {actions ? <div className={styles.headerActions}>{actions}</div> : null}
  </>;
  if (!slot) return <header className={styles.standaloneHeading}>{content}</header>;
  return slot.target ? createPortal(content, slot.target) : null;
}

function Body({ children, className, pending = false, loading, transitionKey, ...props }: ComponentPropsWithoutRef<"div"> & {
  transitionKey?: string;
  pending?: boolean;
  loading?: ReactNode;
}) {
  const positions = useContext(ScrollPositionContext);
  const viewport = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => { if (!pending && transitionKey !== undefined && viewport.current) viewport.current.scrollTop = positions?.get(transitionKey) ?? 0; }, [pending, transitionKey, positions]);
  if (transitionKey === undefined) return <div className={classNames(styles.body, className)} {...props}>{children}</div>;
  return <div className={styles.stage}>
    <div {...props} ref={viewport} onScroll={(event) => {
      if (!pending && positions) {
        positions.delete(transitionKey);
        positions.set(transitionKey, event.currentTarget.scrollTop);
        if (positions.size > 64) positions.delete(positions.keys().next().value!);
      }
      props.onScroll?.(event);
    }} aria-busy={pending || props["aria-busy"]} className={classNames(styles.body, className)} key={transitionKey}>
      <div aria-hidden={pending || undefined} className={styles.enter} hidden={pending} inert={pending}>{children}</div>
    </div>
    {pending && loading ? <div className={classNames(styles.body, styles.pending)}>{loading}</div> : null}
  </div>;
}

export const ContentPage = Object.assign(ContentPageRoot, { Header, Heading, Body });
