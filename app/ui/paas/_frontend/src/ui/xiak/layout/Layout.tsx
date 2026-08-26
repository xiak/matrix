import type { ComponentPropsWithoutRef } from "react";
import { classNames } from "../utils";
import styles from "./Layout.module.css";

function LayoutRoot({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={classNames(styles.layout, className)} {...props} />;
}

function Header({ className, ...props }: ComponentPropsWithoutRef<"header">) {
  return <header className={classNames(styles.header, className)} {...props} />;
}

function Content({ className, ...props }: ComponentPropsWithoutRef<"main">) {
  return <main className={classNames(styles.content, className)} {...props} />;
}

function Workspace({ className, ...props }: ComponentPropsWithoutRef<"aside">) {
  return <aside className={classNames(styles.workspace, className)} {...props} />;
}

export const Layout = Object.assign(LayoutRoot, { Header, Content, Workspace });
