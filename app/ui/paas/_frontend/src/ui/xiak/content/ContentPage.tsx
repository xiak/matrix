"use client";

import { createContext, useCallback, useContext, useId, useLayoutEffect, useMemo, useRef, useState, type ComponentPropsWithoutRef, type ReactNode, type Ref } from "react";
import { createPortal } from "react-dom";
import { ArrowLeft, ChevronRight } from "lucide-react";
import { Button } from "../button/Button";
import { classNames } from "../utils";
import styles from "./ContentPage.module.css";

type BackAction = { label: string; parentLabel?: string; disabled?: boolean; onClick(): void };
type PageHeading = { title: string; back?: BackAction; focus?: boolean };
type HeadingContribution = PageHeading & { owner: string };
type HeadingSlot = { target: HTMLDivElement | null; parentLabel?: string; update(value: HeadingContribution): void; remove(owner: string): void };
const HeadingSlotContext = createContext<HeadingSlot | null>(null);
const HeaderStateContext = createContext<{ heading: HeadingContribution | null; setTarget(target: HTMLDivElement | null): void } | null>(null);
const ScrollPositionContext = createContext<Map<string, number> | null>(null);

function ContentPageRoot({ className, children, parentLabel, pending = false, ...props }: ComponentPropsWithoutRef<"section"> & { parentLabel?: string; pending?: boolean }) {
  const [target, setTarget] = useState<HTMLDivElement | null>(null);
  const [heading, setHeading] = useState<HeadingContribution | null>(null);
  const [positions] = useState(() => new Map<string, number>());
  const remove = useCallback((owner: string) => setHeading((current) => current?.owner === owner ? null : current), []);
  // Only presentation metadata reaches the header. Actions keep their feature
  // providers through a portal; form state never travels through the shell.
  const slot = useMemo(() => ({ target, parentLabel, update: setHeading, remove }), [target, parentLabel, remove]);
  const header = useMemo(() => ({ heading: pending ? null : heading, setTarget }), [heading, pending]);
  return <HeadingSlotContext.Provider value={slot}><HeaderStateContext.Provider value={header}><ScrollPositionContext.Provider value={positions}>
    <section className={classNames(styles.page, className)} {...props}>{children}</section>
  </ScrollPositionContext.Provider></HeaderStateContext.Provider></HeadingSlotContext.Provider>;
}

function HeadingIdentity({ title, back, focus, headingRef }: Omit<PageHeading, "title"> & { title: ReactNode; headingRef?: Ref<HTMLHeadingElement> }) {
  return <div className={styles.identity}>
    {back ? <><Button aria-label={back.label} className={styles.parentLink} disabled={back.disabled} onClick={back.onClick} variant="ghost" size="small"><ArrowLeft aria-hidden="true" /><span>{back.parentLabel ?? back.label}</span></Button><ChevronRight className={styles.separator} aria-hidden="true" /></> : null}
    <h1 key="page-title" className={styles.title} tabIndex={focus ? -1 : undefined} ref={headingRef} title={typeof title === "string" ? title : undefined}>{title}</h1>
  </div>;
}

function Header({ className, title, back, leading, trailing, progress, ...props }: Omit<ComponentPropsWithoutRef<"header">, "children" | "title"> & { title: ReactNode; back?: BackAction; leading?: ReactNode; trailing?: ReactNode; progress?: ReactNode }) {
  const state = useContext(HeaderStateContext);
  const heading = state?.heading;
  const setTarget = state?.setTarget;
  const titleRef = useRef<HTMLHeadingElement>(null);
  const owner = heading?.owner;
  const focus = heading?.focus;
  useLayoutEffect(() => { if (focus) titleRef.current?.focus({ preventScroll: true }); }, [owner, focus]);
  return <header className={classNames(styles.header, className)} {...props}>
    {leading}
    <div className={styles.headerContent}>
      <HeadingIdentity title={heading?.title ?? title} back={heading ? heading.back : back} focus={focus} headingRef={titleRef} />
      {setTarget ? <div className={styles.headerActions} hidden={!heading} ref={setTarget} /> : null}
    </div>
    {trailing ? <div className={styles.headerActions}>{trailing}</div> : null}
    {progress}
  </header>;
}

function Heading({ title, back, actions, focus = false }: PageHeading & { actions?: ReactNode }) {
  const slot = useContext(HeadingSlotContext);
  const owner = useId();
  const update = slot?.update;
  const remove = slot?.remove;
  const target = slot?.target;
  const parentLabel = back?.parentLabel ?? slot?.parentLabel;
  const backLabel = back?.label;
  const backDisabled = back?.disabled;
  const onBack = back?.onClick;
  const hasBack = Boolean(onBack);
  const onBackRef = useRef(onBack);
  const invokeBack = useCallback(() => onBackRef.current?.(), []);
  const heading = useRef<HTMLHeadingElement>(null);
  useLayoutEffect(() => { onBackRef.current = onBack; }, [onBack]);
  useLayoutEffect(() => () => remove?.(owner), [remove, owner]);
  useLayoutEffect(() => {
    update?.({ owner, title, focus, back: hasBack && backLabel ? { label: backLabel, parentLabel, disabled: backDisabled, onClick: invokeBack } : undefined });
  }, [update, owner, title, focus, backLabel, parentLabel, backDisabled, hasBack, invokeBack]);
  useLayoutEffect(() => { if (!update && focus) heading.current?.focus({ preventScroll: true }); }, [update, focus]);
  if (!slot) return <header className={styles.standaloneHeading}><HeadingIdentity title={title} back={back} focus={focus} headingRef={heading} />{actions ? <div className={styles.headerActions}>{actions}</div> : null}</header>;
  return target && actions ? createPortal(actions, target) : null;
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
