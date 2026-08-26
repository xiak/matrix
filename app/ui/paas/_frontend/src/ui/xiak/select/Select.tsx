import { forwardRef, type SelectHTMLAttributes } from "react";
import { classNames } from "../utils";
import styles from "./Select.module.css";

export const Select = forwardRef<
  HTMLSelectElement,
  SelectHTMLAttributes<HTMLSelectElement>
>(function Select({ className, ...props }, ref) {
  return (
    <select
      className={classNames(styles.select, className)}
      ref={ref}
      {...props}
    />
  );
});
