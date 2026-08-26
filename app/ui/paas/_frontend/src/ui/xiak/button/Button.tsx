import { forwardRef, type ButtonHTMLAttributes } from "react";
import { classNames } from "../utils";
import styles from "./Button.module.css";

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "small" | "default" | "large";
  block?: boolean;
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    block = false,
    className,
    size = "default",
    type = "button",
    variant = "primary",
    ...props
  },
  ref
) {
  return (
    <button
      className={classNames(
        styles.button,
        styles[variant],
        styles[size],
        block && styles.block,
        className
      )}
      ref={ref}
      type={type}
      {...props}
    />
  );
});
