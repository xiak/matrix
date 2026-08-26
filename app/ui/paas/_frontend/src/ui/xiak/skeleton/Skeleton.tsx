import type { ComponentPropsWithoutRef } from "react";
import { classNames } from "../utils";
import styles from "./Skeleton.module.css";

export function Skeleton({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return (
    <div
      aria-hidden="true"
      className={classNames(styles.skeleton, className)}
      {...props}
    />
  );
}
