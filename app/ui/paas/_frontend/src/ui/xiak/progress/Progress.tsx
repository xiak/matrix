import type { HTMLAttributes } from "react";
import { classNames } from "../utils";
import styles from "./Progress.module.css";

export function Progress({ className, value, max = 100, ...props }: Omit<HTMLAttributes<HTMLElement>, "children" | "role" | "aria-valuenow" | "aria-valuemin" | "aria-valuemax"> & { "aria-label": string; value?: number; max?: number }) {
  if (value === undefined) return <span {...props} role="progressbar" className={classNames(styles.progress, styles.indeterminate, className)}><span aria-hidden="true" className={styles.indicator} /></span>;
  return <progress {...props} className={classNames(styles.progress, className)} value={value} max={max} />;
}
