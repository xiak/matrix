"use client";

import * as Primitive from "@radix-ui/react-tabs";
import { forwardRef, type ComponentProps, type ComponentPropsWithoutRef } from "react";
import { classNames } from "../utils";
import styles from "./Tabs.module.css";

// Radix supplies mount-animation and roving-focus styles. Their visual rules
// live in our CSS so SSR stays compatible with the host's style-src 'self'.
const StaticSurface = forwardRef<HTMLDivElement, ComponentPropsWithoutRef<"div">>(function StaticSurface(props, ref) {
  const attributes = { ...props };
  delete attributes.style;
  return <div {...attributes} ref={ref} />;
});

export const Tabs = {
  Root: function TabRoot({ className, ...props }: ComponentProps<typeof Primitive.Root>) {
    return <Primitive.Root {...props} className={classNames(styles.root, className)} />;
  },
  List: function TabList({ children, className, ...props }: Omit<ComponentProps<typeof Primitive.List>, "asChild" | "style">) {
    return <Primitive.List {...props} asChild><StaticSurface className={classNames(styles.list, className)}>{children}</StaticSurface></Primitive.List>;
  },
  Trigger: function TabTrigger({ className, ...props }: ComponentProps<typeof Primitive.Trigger>) {
    return <Primitive.Trigger {...props} className={classNames(styles.trigger, className)} />;
  },
  Content: function TabContent({ children, className, ...props }: Omit<ComponentProps<typeof Primitive.Content>, "asChild" | "style">) {
    return <Primitive.Content {...props} asChild><StaticSurface className={classNames(styles.content, className)}>{children}</StaticSurface></Primitive.Content>;
  }
};
