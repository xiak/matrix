import type { ComponentPropsWithoutRef } from "react";
import { classNames } from "../utils";
import styles from "./ContentLayout.module.css";

function ContentLayoutRoot({ className, variant = "page", ...props }: ComponentPropsWithoutRef<"div"> & { variant?: "page" | "detail" }) {
  const layout = <div className={classNames(styles.layout, variant === "detail" && styles.detail, className)} {...props} />;
  return variant === "detail" ? <div className={styles.detailFrame}>{layout}</div> : layout;
}

function Main({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={classNames(styles.main, className)} {...props} />;
}

function Aside({ className, ...props }: ComponentPropsWithoutRef<"aside">) {
  return <aside className={classNames(styles.aside, className)} {...props} />;
}

export const ContentLayout = Object.assign(ContentLayoutRoot, { Main, Aside });
