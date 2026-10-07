import { Slot } from "@radix-ui/react-slot";
import { forwardRef, type ButtonHTMLAttributes } from "react";
import { classNames } from "../utils";
import styles from "./Button.module.css";

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "small" | "default" | "large";
  block?: boolean;
  asChild?: boolean;
  iconOnly?: boolean;
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    asChild = false,
    iconOnly = false,
    block = false,
    className,
    size = "default",
    type = "button",
    variant = "primary",
    ...props
  },
  ref
) {
  const Element = asChild ? Slot : "button";
  return (
    <Element
      className={classNames(
        styles.button,
        styles[variant],
        styles[size],
        block && styles.block,
        iconOnly && styles.iconOnly,
        className
      )}
      ref={ref}
      type={asChild ? undefined : type}
      {...props}
    />
  );
});
