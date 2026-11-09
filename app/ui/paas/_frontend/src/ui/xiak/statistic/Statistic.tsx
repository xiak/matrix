import { cloneElement, type ReactElement, type ReactNode } from "react";
import { ChevronRight } from "lucide-react";
import { Card } from "../card/Card";
import styles from "./Statistic.module.css";

export function Statistic({ label, value, hint, icon, link, hintLink, status = "neutral" }: { label: string; value: ReactNode; hint?: string; icon?: ReactNode; link?: ReactElement; hintLink?: ReactElement; status?: "neutral" | "info" | "success" | "warning" | "danger" }) {
  const body = <Card.Body className={styles.body}>
    <div className={styles.heading}><span className={styles.label}>{label}{link ? <ChevronRight aria-hidden="true" /> : null}</span>{icon ? <span aria-hidden="true" className={styles.icon} data-status={status}>{icon}</span> : null}</div>
    <strong className={styles.value}>{value}</strong>
    {hint && !hintLink ? <p className={styles.hint}>{hint}</p> : null}
  </Card.Body>;
  return <Card className={styles.card} data-secondary={hint && hintLink ? true : undefined}>
    {link ? cloneElement(link, undefined, body) : body}
    {hint && hintLink ? <div className={styles.secondary}>{cloneElement(hintLink, undefined, hint, <ChevronRight aria-hidden="true" />)}</div> : null}
  </Card>;
}
