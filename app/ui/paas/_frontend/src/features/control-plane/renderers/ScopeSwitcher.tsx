"use client";

import { useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { Check, MapPin } from "lucide-react";
import { useTranslations } from "next-intl";
import type { ConsoleScopeScene } from "../scenes/consoleScene";
import { HeaderPopover, HeaderPopoverHeader, HeaderPopoverTrigger } from "./HeaderPopover";
import styles from "./ScopeSwitcher.module.css";

type RegionSwitcherProps = Readonly<{
  onRegionChange(value: string): void;
  regionId: string;
  scope: ConsoleScopeScene;
  open: boolean;
  onOpenChange(open: boolean): void;
}>;

type RegionOptionsProps = Readonly<{
  onChange(value: string): void;
  options: ConsoleScopeScene["regions"];
  value: string;
}>;

function RegionOptions({ onChange, options, value }: RegionOptionsProps) {
  const t = useTranslations("RegionScope");
  const selectedIndex = Math.max(0, options.findIndex((item) => item.id === value));
  const [activeIndex, setActiveIndex] = useState(selectedIndex);
  const items = useRef<Array<HTMLButtonElement | null>>([]);

  useEffect(() => {
    items.current[selectedIndex]?.focus();
  }, [selectedIndex]);

  function handleKeyDown(event: ReactKeyboardEvent<HTMLElement>) {
    if (!options.length) return;
    let nextIndex: number | undefined;
    if (event.key === "ArrowDown") nextIndex = (activeIndex + 1) % options.length;
    if (event.key === "ArrowUp") nextIndex = (activeIndex - 1 + options.length) % options.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = options.length - 1;
    if (nextIndex === undefined) return;
    event.preventDefault();
    event.stopPropagation();
    setActiveIndex(nextIndex);
    items.current[nextIndex]?.focus();
  }

  return (
    <div aria-label={t("list")} className={styles.options} onKeyDown={handleKeyDown} role="listbox">
      {options.map((item, index) => (
        <button
          aria-selected={item.id === value}
          className={styles.option}
          key={item.id}
          onClick={() => onChange(item.id)}
          onFocus={() => setActiveIndex(index)}
          ref={(node) => { items.current[index] = node; }}
          role="option"
          tabIndex={index === activeIndex ? 0 : -1}
          type="button"
        >
          <span><strong>{item.id === "all" ? t("all") : item.name}</strong><small>{item.id === "all" ? t("allHint") : item.id}</small></span>
          {item.id === value ? <Check aria-hidden="true" /> : null}
        </button>
      ))}
    </div>
  );
}

export function RegionSwitcher({ onRegionChange, onOpenChange, open, regionId, scope }: RegionSwitcherProps) {
  const t = useTranslations("RegionScope");
  const pickerId = "global-region-scope";
  const selectedName = regionId === "all" ? t("all") : scope.regions.find((item) => item.id === regionId)?.name ?? t("unspecified");
  const trigger = useRef<HTMLButtonElement>(null);

  function closeAndRestoreFocus() {
    onOpenChange(false);
    trigger.current?.focus();
  }

  return (
    <div className={styles.picker} onBlur={(event) => {
      if (!event.currentTarget.contains(event.relatedTarget)) onOpenChange(false);
    }}>
      <HeaderPopoverTrigger
        aria-label={t("trigger", { name: selectedName })}
        compactLabel={t("label")}
        filtered={regionId !== "all"}
        icon={<MapPin />}
        label={selectedName}
        onClick={() => open ? closeAndRestoreFocus() : onOpenChange(true)}
        onKeyDown={(event) => {
          if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
          event.preventDefault();
          onOpenChange(true);
        }}
        open={open}
        panelId={pickerId}
        ref={trigger}
        title={t("trigger", { name: selectedName })}
        variant="selection"
      />
      {open ? (
        <HeaderPopover align="end" id={pickerId} label={t("title")} onKeyDown={(event) => {
          if (event.key !== "Escape") return;
          event.preventDefault();
          event.stopPropagation();
          closeAndRestoreFocus();
        }} size="compact">
          <HeaderPopoverHeader action={<MapPin aria-hidden="true" className={styles.scopeIcon} />} description={scope.organization.name} title={t("title")} />
          <RegionOptions onChange={(id) => { onRegionChange(id); closeAndRestoreFocus(); }} options={scope.regions} value={regionId} />
          <p className={styles.scopeHint}>{t("hint")}</p>
        </HeaderPopover>
      ) : null}
    </div>
  );
}
