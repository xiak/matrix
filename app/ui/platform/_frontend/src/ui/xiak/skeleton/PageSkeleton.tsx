import { Skeleton } from "./Skeleton";
import styles from "./PageSkeleton.module.css";

export type PageSkeletonLayout = "dashboard" | "table" | "cards" | "list" | "access";

function SkeletonPanel({ rows = 4 }: { rows?: number }) {
  return <div className={styles.panel}>
    <div className={styles.panelHeader}><Skeleton className={styles.title} /><Skeleton className={styles.action} /></div>
    {Array.from({ length: rows }, (_, index) => <div className={styles.row} key={index}>
      <div className={styles.identity}><Skeleton className={styles.line} /><Skeleton className={styles.caption} /></div>
      <Skeleton className={styles.cell} /><Skeleton className={styles.cell} /><Skeleton className={styles.status} />
    </div>)}
  </div>;
}

// Layout-aware placeholders share the real controls' geometry and theme.
// The label is the only announced content; placeholder rows are not fake data.
export function PageSkeleton({ label, layout = "table" }: { label: string; layout?: PageSkeletonLayout }) {
  return <div className={styles.root} role="status" aria-live="polite" aria-atomic="true">
    <p className={styles.label}>{label}</p>
    <div aria-hidden="true" className={styles.content}>
      {layout === "dashboard" ? <div className={styles.metrics}>{Array.from({ length: 4 }, (_, index) => <div className={styles.metric} key={index}><Skeleton className={styles.caption} /><Skeleton className={styles.value} /><Skeleton className={styles.line} /></div>)}</div> : null}
      {layout === "table" || layout === "list" || layout === "access" ? <div className={styles.toolbar}><Skeleton className={styles.search} /><Skeleton className={styles.action} /></div> : null}
      {layout === "access" ? <div className={styles.account}><Skeleton className={styles.avatar} /><Skeleton className={styles.title} /><Skeleton className={styles.title} /></div> : null}
      {layout === "cards" ? <div className={styles.cards}>{Array.from({ length: 3 }, (_, index) => <div className={styles.metric} key={index}><Skeleton className={styles.avatar} /><Skeleton className={styles.title} /><Skeleton className={styles.line} /><Skeleton className={styles.caption} /></div>)}</div>
        : <div className={styles.panels} data-split={layout === "dashboard" ? "true" : undefined}><SkeletonPanel />{layout === "dashboard" ? <SkeletonPanel rows={3} /> : null}</div>}
    </div>
  </div>;
}
