"use client";

import { forwardRef, useId, type InputHTMLAttributes, type ReactNode } from "react";
import { classNames } from "../utils";
import styles from "./Choice.module.css";

type ChoiceProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type" | "size"> & { children: ReactNode };

export const Radio = forwardRef<HTMLInputElement, ChoiceProps & { variant?: "default" | "text" }>(function Radio({ children, className, variant = "default", ...props }, ref) {
  return <label className={classNames(styles.choice, className)} data-variant={variant}><input {...props} className={styles.input} ref={ref} type="radio" /><span>{children}</span></label>;
});

export const Checkbox = forwardRef<HTMLInputElement, ChoiceProps>(function Checkbox({ children, className, ...props }, ref) {
  return <label className={classNames(styles.choice, className)}><input {...props} className={styles.input} ref={ref} type="checkbox" /><span>{children}</span></label>;
});

export function RadioGroup<T extends string>({ label, options, value, onValueChange, disabled, variant = "default" }: {
  label: string;
  options: readonly { value: T; label: string; icon?: ReactNode }[];
  value: T;
  onValueChange(value: T): void;
  disabled?: boolean;
  variant?: "default" | "text";
}) {
  const name = useId();
  return <fieldset className={styles.group} data-variant={variant} disabled={disabled}>
    <legend>{label}</legend>
    <div className={styles.options}>{options.map((option) => <Radio checked={option.value === value} key={option.value} name={name} onChange={() => onValueChange(option.value)} value={option.value} variant={variant}>{option.icon}{option.label}</Radio>)}</div>
  </fieldset>;
}
