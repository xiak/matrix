import type { ComponentPropsWithoutRef } from "react";
import { classNames } from "../utils";
import styles from "./Card.module.css";

function CardRoot({ className, ...props }: ComponentPropsWithoutRef<"article">) {
  return <article className={classNames(styles.card, className)} {...props} />;
}

function Header({ className, ...props }: ComponentPropsWithoutRef<"header">) {
  return <header className={classNames(styles.header, className)} {...props} />;
}

function Body({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={classNames(styles.body, className)} {...props} />;
}

function Footer({ className, ...props }: ComponentPropsWithoutRef<"footer">) {
  return <footer className={classNames(styles.footer, className)} {...props} />;
}

export const Card = Object.assign(CardRoot, { Header, Body, Footer });
