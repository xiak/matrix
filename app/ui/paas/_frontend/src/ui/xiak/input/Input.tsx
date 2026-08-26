import { forwardRef, type InputHTMLAttributes } from "react";
import { classNames } from "../utils";
import styles from "./Input.module.css";

export type InputProps = InputHTMLAttributes<HTMLInputElement> & {
  invalid?: boolean;
};

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { className, invalid = false, ...props },
  ref
) {
  return (
    <input
      aria-invalid={invalid || undefined}
      className={classNames(styles.input, className)}
      ref={ref}
      {...props}
    />
  );
});
