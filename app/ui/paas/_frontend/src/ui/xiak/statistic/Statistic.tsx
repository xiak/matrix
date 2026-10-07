import type { ReactNode } from "react";
import { Card } from "../card/Card";
import styles from "./Statistic.module.css";

export function Statistic({ label, value, hint, icon, status = "neutral" }: { label: string; value: ReactNode; hint?: string; icon?: ReactNode; status?: "neutral" | "info" | "success" | "warning" | "danger" }) {
  return <Card className={styles.card}><Card.Body className={styles.body}>
    <div className={styles.heading}><span>{label}</span>{icon ? <span aria-hidden="true" className={styles.icon} data-status={status}>{icon}</span> : null}</div>
    <strong className={styles.value}>{value}</strong>
    {hint ? <p className={styles.hint}>{hint}</p> : null}
  </Card.Body></Card>;
}
