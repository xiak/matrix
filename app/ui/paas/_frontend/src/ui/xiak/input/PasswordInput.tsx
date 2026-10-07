"use client";

import { forwardRef, useId, useState } from "react";
import { Eye, EyeOff } from "lucide-react";
import { Input, type InputProps } from "./Input";
import styles from "./PasswordInput.module.css";

export type PasswordInputProps = Omit<InputProps, "type"> & {
  showLabel: string;
  hideLabel: string;
  capsLockLabel: string;
};

export const PasswordInput = forwardRef<HTMLInputElement, PasswordInputProps>(function PasswordInput(
  { showLabel, hideLabel, capsLockLabel, disabled, onKeyUp, onBlur, "aria-describedby": describedBy, ...props }, ref
) {
  const [revealed, setRevealed] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const capsId = useId();
  return (
    <div className={styles.field}>
      <div className={styles.control}>
        <Input {...props} aria-describedby={[describedBy, capsLock ? capsId : null].filter(Boolean).join(" ") || undefined}
          disabled={disabled} onBlur={(event) => { setCapsLock(false); onBlur?.(event); }}
          onKeyUp={(event) => { setCapsLock(event.getModifierState("CapsLock")); onKeyUp?.(event); }}
          ref={ref} type={revealed ? "text" : "password"} />
        <button aria-label={revealed ? hideLabel : showLabel} aria-pressed={revealed} className={styles.toggle}
          disabled={disabled} onClick={() => setRevealed(!revealed)} type="button">
          {revealed ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
        </button>
      </div>
      {capsLock ? <span className={styles.hint} id={capsId} role="status">{capsLockLabel}</span> : null}
    </div>
  );
});
