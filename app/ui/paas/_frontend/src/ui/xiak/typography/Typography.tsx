import type { ComponentPropsWithoutRef, ElementType } from "react";
import { classNames } from "../utils";
import styles from "./Typography.module.css";

type TextProps = ComponentPropsWithoutRef<"span"> & {
  tone?: "default" | "muted" | "subtle" | "accent" | "danger";
};

function Text({ className, tone = "default", ...props }: TextProps) {
  return <span className={classNames(styles.text, styles[tone], className)} {...props} />;
}

type TitleProps = ComponentPropsWithoutRef<"h1"> & {
  as?: "h1" | "h2" | "h3";
  level?: 1 | 2 | 3;
};

function Title({ as, className, level = 1, ...props }: TitleProps) {
  const Component = (as ?? (`h${level}` as const)) as ElementType;
  return <Component className={classNames(styles.title, styles[`level${level}`], className)} {...props} />;
}

function Eyebrow({ className, ...props }: ComponentPropsWithoutRef<"span">) {
  return <span className={classNames(styles.eyebrow, className)} {...props} />;
}

function Code({ className, ...props }: ComponentPropsWithoutRef<"code">) {
  return <code className={classNames(styles.code, className)} {...props} />;
}

export const Typography = { Text, Title, Eyebrow, Code };
