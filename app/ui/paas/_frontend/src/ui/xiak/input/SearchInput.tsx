"use client";

import { forwardRef, useImperativeHandle, useRef } from "react";
import { Search, X } from "lucide-react";
import { Input, type InputProps } from "./Input";
import { Button } from "../button/Button";
import { classNames } from "../utils";
import styles from "./SearchInput.module.css";

export const SearchInput = forwardRef<HTMLInputElement, InputProps & { "aria-label": string; clearAction?: { label: string; onClear(): void } }>(function SearchInput({ className, clearAction, ...props }, ref) {
  const input = useRef<HTMLInputElement>(null);
  useImperativeHandle(ref, () => input.current!);
  return <div className={classNames(styles.root, className)} data-clearable={clearAction ? "true" : undefined}>
    <Search aria-hidden="true" />
    <Input {...props} className={styles.input} ref={input} type="search" />
    {clearAction ? <Button aria-label={clearAction.label} className={styles.clear} disabled={props.disabled} iconOnly onClick={() => { clearAction.onClear(); input.current?.focus(); }} size="small" variant="ghost"><X aria-hidden="true" /></Button> : null}
  </div>;
});
