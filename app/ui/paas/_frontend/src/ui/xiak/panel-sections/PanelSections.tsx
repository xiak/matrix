import type { ComponentPropsWithoutRef } from "react";
import { classNames } from "../utils";
import styles from "./PanelSections.module.css";

function Sections({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div {...props} className={classNames(styles.sections, className)} />;
}

function Section({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div {...props} className={classNames(styles.section, className)} />;
}

/** Divided content groups share an inset and inherit their enclosing panel surface. */
export const PanelSections = Object.assign(Sections, { Section });
