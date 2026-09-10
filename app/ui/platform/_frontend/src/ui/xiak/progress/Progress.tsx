import type { ProgressHTMLAttributes } from "react";
import { classNames } from "../utils";
import styles from "./Progress.module.css";

export function Progress({ className, max = 100, ...props }: ProgressHTMLAttributes<HTMLProgressElement> & { "aria-label": string }) {
  return <progress {...props} className={classNames(styles.progress, className)} max={max} />;
}
