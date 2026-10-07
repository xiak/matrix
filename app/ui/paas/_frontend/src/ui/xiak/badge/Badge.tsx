import type { ComponentPropsWithoutRef } from "react";
import { classNames } from "../utils";
import styles from "./Badge.module.css";

export type BadgeProps = ComponentPropsWithoutRef<"span"> & {
  status?: "neutral" | "info" | "success" | "warning" | "danger";
};

export function Badge({ className, status, ...props }: BadgeProps) {
  return (
    <span
      className={classNames(styles.badge, styles[status ?? "neutral"], className)}
      data-status={status}
      {...props}
    />
  );
}
