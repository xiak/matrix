import type { ReactNode } from "react";
import styles from "./FormField.module.css";

export function FormField({ id, label, hint, error, children }: { id?: string; label: string; hint?: ReactNode; error?: ReactNode; children: ReactNode }) {
  return <div className={styles.field}>
    {id ? <><label htmlFor={id}>{label}</label>{children}</> : <label className={styles.implicit}><span>{label}</span>{children}</label>}
    {hint ? <p className={styles.hint} id={id ? `${id}-hint` : undefined}>{hint}</p> : null}
    {error ? <p className={styles.error} id={id ? `${id}-error` : undefined} role="alert">{error}</p> : null}
  </div>;
}
