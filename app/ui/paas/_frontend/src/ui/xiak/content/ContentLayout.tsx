import type { ComponentPropsWithoutRef } from "react";
import { classNames } from "../utils";
import styles from "./ContentLayout.module.css";

function ContentLayoutRoot({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={classNames(styles.layout, className)} {...props} />;
}

function Main({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={classNames(styles.main, className)} {...props} />;
}

function Aside({ className, ...props }: ComponentPropsWithoutRef<"aside">) {
  return <aside className={classNames(styles.aside, className)} {...props} />;
}

export const ContentLayout = Object.assign(ContentLayoutRoot, { Main, Aside });
