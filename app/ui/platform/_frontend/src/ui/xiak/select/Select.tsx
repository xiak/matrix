"use client";

import { forwardRef, useEffect, useId, useRef, useState, type ButtonHTMLAttributes } from "react";
import * as Menu from "@radix-ui/react-dropdown-menu";
import { Check, ChevronDown } from "lucide-react";
import { classNames } from "../utils";
import controls from "../form/Control.module.css";
import menu from "../selection-menu/SelectionMenu.module.css";
import styles from "./Select.module.css";

export type SelectOption = { value: string; label: string; disabled?: boolean };
export type SelectProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "children" | "defaultValue" | "onChange" | "value" | "type"> & {
  options: readonly SelectOption[];
  value?: string;
  defaultValue?: string;
  onValueChange?(value: string): void;
  placeholder?: string;
  required?: boolean;
  invalid?: boolean;
  controlSize?: "small" | "default" | "large";
};

export const Select = forwardRef<HTMLButtonElement, SelectProps>(function Select({
  options, value, defaultValue, onValueChange, placeholder = "", required, invalid,
  controlSize = "default", className, disabled, name, form, onKeyDown, ...props
}, forwardedRef) {
  const initialValue = useRef(defaultValue ?? value ?? (placeholder ? "" : options.find((option) => !option.disabled)?.value ?? ""));
  const listId = useId();
  const [localValue, setLocalValue] = useState(initialValue.current);
  const selectedValue = value ?? localValue;
  const selected = options.find((option) => option.value === selectedValue);
  const [open, setOpen] = useState(false);
  const [validationFailed, setValidationFailed] = useState(false);
  const [portal, setPortal] = useState<HTMLElement | undefined>(undefined);
  const [shellSurface, setShellSurface] = useState(false);
  const [label, setLabel] = useState<string>();
  const trigger = useRef<HTMLButtonElement>(null);
  const native = useRef<HTMLSelectElement>(null);
  const popup = useRef<HTMLDivElement>(null);
  const interactedOutside = useRef(false);
  const onValueChangeRef = useRef(onValueChange);
  useEffect(() => { onValueChangeRef.current = onValueChange; }, [onValueChange]);

  function choose(next: string) {
    setLocalValue(next);
    setValidationFailed(false);
    if (next !== selectedValue) onValueChange?.(next);
  }

  useEffect(() => {
    const owner = native.current?.form;
    if (!owner) return;
    const reset = () => {
      setLocalValue(initialValue.current);
      setValidationFailed(false);
      onValueChangeRef.current?.(initialValue.current);
    };
    owner.addEventListener("reset", reset);
    return () => owner.removeEventListener("reset", reset);
  }, []);

  useEffect(() => {
    if (!open) return;
    const frame = requestAnimationFrame(() => {
      const active = popup.current?.querySelector<HTMLElement>('[aria-selected="true"]:not([data-disabled])')
        ?? popup.current?.querySelector<HTMLElement>('[role="option"]:not([data-disabled])');
      active?.focus();
    });
    return () => cancelAnimationFrame(frame);
  }, [open]);

  function changeOpen(next: boolean) {
    if (next && disabled) return;
    if (next) {
      interactedOutside.current = false;
      // A body portal is inert behind a native modal; stay inside its top layer.
      setPortal(trigger.current?.closest("dialog") ?? undefined);
      setShellSurface(Boolean(trigger.current?.closest('[data-surface="shell"]')));
      const fieldLabel = Array.from(trigger.current?.labels ?? []).map((element) => {
        const copy = element.cloneNode(true) as HTMLElement;
        copy.querySelectorAll('button, input, select, textarea, [aria-hidden="true"]').forEach((control) => control.remove());
        return copy.textContent?.trim();
      }).filter(Boolean).join(" ");
      setLabel(trigger.current?.getAttribute("aria-label") ?? (fieldLabel || undefined));
    }
    setOpen(next);
  }

  return <span className={styles.root}>
    <Menu.Root modal={false} open={open} onOpenChange={changeOpen}>
      <Menu.Trigger asChild disabled={disabled}>
        <button {...props} aria-haspopup="listbox" aria-controls={open ? listId : undefined} aria-expanded={open} aria-required={required || undefined}
          aria-invalid={invalid || validationFailed || props["aria-invalid"] || undefined}
          className={classNames(controls.control, styles.trigger, className)} data-size={controlSize}
          data-placeholder={!selected || undefined} disabled={disabled} form={form}
          onKeyDown={(event) => {
            onKeyDown?.(event);
            if (event.defaultPrevented || disabled) return;
            if (event.key === "ArrowUp") { event.preventDefault(); changeOpen(true); }
          }}
          ref={(element) => {
            trigger.current = element;
            if (typeof forwardedRef === "function") forwardedRef(element);
            else if (forwardedRef) forwardedRef.current = element;
          }} role="combobox" type="button">
          <span className={styles.value}>{selected?.label ?? placeholder}</span><ChevronDown aria-hidden="true" className={styles.icon} />
        </button>
      </Menu.Trigger>
      <Menu.Portal container={portal}>
        <Menu.Content align="start" aria-label={label} aria-labelledby={props["aria-labelledby"]} id={listId}
          className={classNames(menu.popup, styles.popup)} collisionPadding={8}
          data-surface={shellSurface ? "shell" : undefined} loop
          onCloseAutoFocus={(event) => { event.preventDefault(); if (!interactedOutside.current) trigger.current?.focus(); }}
          onEscapeKeyDown={(event) => { event.preventDefault(); event.stopPropagation(); setOpen(false); }}
          onInteractOutside={() => { interactedOutside.current = true; }}
          onKeyDown={(event) => {
            event.stopPropagation();
            // Match native select: Tab accepts the focused choice and closes;
            // the next Tab continues from the control in the form's order.
            if (event.key === "Tab") { event.preventDefault(); setOpen(false); }
          }}
          ref={popup} role="listbox" sideOffset={6}>
          {options.map((option) => <Menu.Item aria-selected={option.value === selectedValue}
            className={menu.item} disabled={option.disabled} key={option.value}
            onKeyDown={(event) => { if (event.key === "Tab" && !option.disabled) choose(option.value); }}
            onSelect={() => choose(option.value)} role="option" textValue={option.label}>
            <span>{option.label}</span>{option.value === selectedValue ? <span className={menu.check}><Check aria-hidden="true" /></span> : null}
          </Menu.Item>)}
        </Menu.Content>
      </Menu.Portal>
    </Menu.Root>
    {/* Native submission, validation and autofill stay behind the themed control. */}
    <select aria-hidden="true" className={styles.native} disabled={disabled} form={form} name={name}
      onChange={(event) => choose(event.target.value)} onInvalid={(event) => { event.preventDefault(); setValidationFailed(true); trigger.current?.focus(); }}
      ref={native} required={required} tabIndex={-1} value={selectedValue}>
      {!options.some((option) => option.value === "") ? <option value="">{placeholder}</option> : null}
      {options.map((option) => <option disabled={option.disabled} key={option.value} value={option.value}>{option.label}</option>)}
    </select>
  </span>;
});
