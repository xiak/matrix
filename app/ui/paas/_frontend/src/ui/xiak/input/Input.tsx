import { forwardRef, type InputHTMLAttributes } from "react";
import { classNames } from "../utils";
import styles from "../form/Control.module.css";

export type InputProps = InputHTMLAttributes<HTMLInputElement> & {
  invalid?: boolean;
  controlSize?: "small" | "default" | "large";
};

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { className, invalid = false, controlSize = "default", ...props },
  ref
) {
  return (
    <input
      data-size={controlSize}
      aria-invalid={invalid || undefined}
      className={classNames(styles.control, className)}
      ref={ref}
      {...props}
    />
  );
});
