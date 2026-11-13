"use client";

import { useEffect, useState, type ReactNode } from "react";
import { useContentPageLoading } from "../content/ContentPage";
import { Skeleton } from "./Skeleton";
import styles from "./PageSkeleton.module.css";

export type PageSkeletonLayout = "dashboard" | "table" | "cards" | "list" | "access";

export const LOADING_FEEDBACK_DELAY_MS = 200;

// A destination/region acknowledges the wait immediately. Placeholder DOM and
// animation are local and delayed, never the page identity or navigation shell.
export function LoadingFeedback({ label, children }: { label: string; children?: ReactNode }) {
  useContentPageLoading(label);
  const [visible, setVisible] = useState(false);
  const hasPlaceholder = children !== undefined && children !== null;
  useEffect(() => {
    if (!hasPlaceholder) return;
    const timer = window.setTimeout(() => setVisible(true), LOADING_FEEDBACK_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [hasPlaceholder]);
  return <div className={styles.root} role="status" aria-live="polite" aria-atomic="true">
    <p className={styles.label} data-visible="false">{label}</p>
    {visible ? children : null}
  </div>;
}

// Short reads are announced immediately. The nearest ContentPage owns their
// visual progress so transient text never enters and leaves the content flow.
export function LoadingNotice({ label }: { label: string }) {
  return <LoadingFeedback label={label} />;
}

function CardPlaceholders({ cards }: { cards: number }) {
  return <div aria-hidden="true" className={styles.cards}>
    {Array.from({ length: cards }, (_, index) => <div className={styles.metric} key={index}>
      <Skeleton className={styles.avatar} />
      <Skeleton className={styles.title} />
      <Skeleton className={styles.line} />
      <Skeleton className={styles.caption} />
    </div>)}
  </div>;
}

export function TableSkeleton({ label, rows = 4, header = true }: { label?: string; rows?: number; header?: boolean }) {
  const panel = <div className={styles.panel}>
    {header ? <div className={styles.panelHeader}><Skeleton className={styles.title} /><Skeleton className={styles.action} /></div> : null}
    {Array.from({ length: rows }, (_, index) => <div className={styles.row} key={index}>
      <div className={styles.identity}><Skeleton className={styles.line} /><Skeleton className={styles.caption} /></div>
      <Skeleton className={styles.cell} /><Skeleton className={styles.cell} /><Skeleton className={styles.status} />
    </div>)}
  </div>;
  if (!label) return panel;
  return <LoadingFeedback key={label} label={label}>
    <div aria-hidden="true">{panel}</div>
  </LoadingFeedback>;
}

export function CardGridSkeleton({ label, cards = 3 }: { label: string; cards?: number }) {
  return <LoadingFeedback key={`cards:${label}`} label={label}>
    <CardPlaceholders cards={cards} />
  </LoadingFeedback>;
}

// Layout-aware placeholders share the real controls' geometry and theme.
// The label is the only announced content; placeholder rows are not fake data.
export function PageSkeleton({ label, layout = "table" }: { label: string; layout?: PageSkeletonLayout }) {
  return <LoadingFeedback key={`${layout}:${label}`} label={label}>
    <div aria-hidden="true" className={styles.content}>
      {layout === "dashboard" ? <div className={styles.metrics}>{Array.from({ length: 4 }, (_, index) => <div className={styles.metric} key={index}><Skeleton className={styles.caption} /><Skeleton className={styles.value} /><Skeleton className={styles.line} /></div>)}</div> : null}
      {layout === "table" || layout === "list" || layout === "access" ? <div className={styles.toolbar}><Skeleton className={styles.search} /><Skeleton className={styles.action} /></div> : null}
      {layout === "access" ? <div className={styles.account}><Skeleton className={styles.avatar} /><Skeleton className={styles.title} /><Skeleton className={styles.title} /></div> : null}
      {layout === "cards" ? <CardPlaceholders cards={3} />
        : <div className={styles.panels} data-split={layout === "dashboard" ? "true" : undefined}><TableSkeleton />{layout === "dashboard" ? <TableSkeleton rows={3} /> : null}</div>}
    </div>
  </LoadingFeedback>;
}
