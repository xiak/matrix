import type { ComponentPropsWithoutRef } from "react";
import { classNames } from "../utils";
import styles from "./ContentPage.module.css";

function ContentPageRoot({ className, ...props }: ComponentPropsWithoutRef<"section">) {
  return <section className={classNames(styles.page, className)} {...props} />;
}

function Header({ className, ...props }: ComponentPropsWithoutRef<"header">) {
  return <header className={classNames(styles.header, className)} {...props} />;
}

function Body({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={classNames(styles.body, className)} {...props} />;
}

export const ContentPage = Object.assign(ContentPageRoot, { Header, Body });
