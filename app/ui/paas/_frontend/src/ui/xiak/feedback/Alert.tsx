import type { HTMLAttributes, ReactNode } from "react";
import { CheckCircle2, ChevronDown, CircleAlert, Info, TriangleAlert } from "lucide-react";
import { classNames } from "../utils";
import styles from "./Alert.module.css";

const icons = { info: Info, success: CheckCircle2, warning: TriangleAlert, danger: CircleAlert };
export function Alert({ status = "info", children, className, ...props }: HTMLAttributes<HTMLDivElement> & { status?: keyof typeof icons; children: ReactNode }) {
  const Icon = icons[status];
  return <div role={status === "danger" ? "alert" : status === "success" ? "status" : undefined} {...props} className={classNames(styles.alert, className)} data-status={status}>
    <Icon aria-hidden="true" /><div>{children}</div>
  </div>;
}

export function HelpDisclosure({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return <details className={classNames(styles.help, className)}>
    <summary><Info aria-hidden="true" /><span>{label}</span><ChevronDown aria-hidden="true" /></summary>
    <div className={styles.helpBody}>{children}</div>
  </details>;
}
