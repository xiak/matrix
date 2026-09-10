import { forwardRef, type TextareaHTMLAttributes } from "react";
import { classNames } from "../utils";
import styles from "../form/Control.module.css";

export const TextArea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement> & { invalid?: boolean }>(function TextArea({ className, invalid, rows = 5, ...props }, ref) {
  return <textarea {...props} aria-invalid={invalid || undefined} className={classNames(styles.control, styles.multiline, className)} ref={ref} rows={rows} />;
});
