import type { ReactNode } from "react";
import { Inbox } from "lucide-react";
import { Typography } from "../typography/Typography";
import styles from "./EmptyState.module.css";

export function EmptyState({ title, description, icon, action, compact = false }: { compact?: boolean; title: string; description?: string; icon?: ReactNode; action?: ReactNode }) {
  return <div className={styles.empty} data-compact={compact ? "true" : undefined}>
    <div aria-hidden="true" className={styles.icon}>{icon ?? <Inbox />}</div>
    <Typography.Title as="h3" level={3}>{title}</Typography.Title>
    {description ? <p>{description}</p> : null}
    {action ? <div className={styles.action}>{action}</div> : null}
  </div>;
}
