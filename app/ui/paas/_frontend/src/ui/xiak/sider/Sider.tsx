import type { ComponentPropsWithoutRef } from "react";
import { classNames } from "../utils";
import styles from "./Sider.module.css";

function SiderRoot({ className, ...props }: ComponentPropsWithoutRef<"aside">) {
  return <aside className={classNames(styles.sider, className)} {...props} />;
}

function RailMenu({ className, ...props }: ComponentPropsWithoutRef<"nav">) {
  return <nav className={classNames(styles.rail, className)} {...props} />;
}

function ContextMenu({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={classNames(styles.context, className)} {...props} />;
}

function ResizeHandle({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return (
    <div
      aria-hidden="true"
      className={classNames(styles.resizeHandle, className)}
      {...props}
    />
  );
}

export const Sider = Object.assign(SiderRoot, {
  RailMenu,
  ContextMenu,
  ResizeHandle
});
