"use client";

import type { ReactNode } from "react";
import * as Menu from "@radix-ui/react-dropdown-menu";
import { Check, ChevronDown } from "lucide-react";
import styles from "./SelectionMenu.module.css";

export function SelectionMenu<T extends string>({ label, value, options, onValueChange, children }: {
  label: string;
  value: T;
  options: readonly { value: T; label: string; icon?: ReactNode }[];
  onValueChange(value: T): void;
  children: ReactNode;
}) {
  return (
    <Menu.Root modal={false}>
      <Menu.Trigger className={styles.trigger} aria-label={label}>
        {children}<ChevronDown aria-hidden="true" className={styles.chevron} />
      </Menu.Trigger>
      <Menu.Portal>
        <Menu.Content align="end" aria-label={label} className={styles.popup} collisionPadding={12} sideOffset={8}>
          <Menu.Label className={styles.label}>{label}</Menu.Label>
          <Menu.RadioGroup value={value} onValueChange={(next) => {
            const option = options.find((item) => item.value === next);
            if (option) onValueChange(option.value);
          }}>
            {options.map((option) => (
              <Menu.RadioItem className={styles.item} key={option.value} value={option.value}>
                {option.icon}<span>{option.label}</span>
                <Menu.ItemIndicator className={styles.check}><Check aria-hidden="true" /></Menu.ItemIndicator>
              </Menu.RadioItem>
            ))}
          </Menu.RadioGroup>
        </Menu.Content>
      </Menu.Portal>
    </Menu.Root>
  );
}
