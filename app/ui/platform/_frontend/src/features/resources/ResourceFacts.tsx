import type { ReactNode } from "react";
import styles from "../platform/Workspace.module.css";
export function ResourceFacts({ rows }: { rows: readonly (readonly [string, ReactNode])[] }) { return <dl className={styles.facts}>{rows.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value ?? "—"}</dd></div>)}</dl>; }
