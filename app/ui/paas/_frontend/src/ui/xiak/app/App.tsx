import type { ComponentPropsWithoutRef } from "react";
import { classNames } from "../utils";
import styles from "./App.module.css";

function AppRoot({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={classNames(styles.app, className)} {...props} />;
}

function Frame({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={classNames(styles.frame, className)} {...props} />;
}

function Background({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return (
    <div
      aria-hidden="true"
      className={classNames(styles.background, className)}
      {...props}
    />
  );
}

function Layers({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={classNames(styles.layers, className)} {...props} />;
}

function Layer({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={classNames(styles.layer, className)} {...props} />;
}

function Base({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={classNames(styles.base, className)} {...props} />;
}

export const App = Object.assign(AppRoot, {
  Frame,
  Background,
  Layers,
  Layer,
  Base
});
