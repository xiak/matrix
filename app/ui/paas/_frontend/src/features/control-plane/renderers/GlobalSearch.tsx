"use client";

import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { ArrowUpRight, PackageSearch, Search, X } from "lucide-react";
import { useConsoleNavigation } from "../routes/ConsoleNavigation";
import { useTranslations } from "next-intl";
import { Button, EmptyState } from "@ui/xiak";
import type { GlobalSearchResultScene } from "../scenes/consoleScene";
import { ExperienceIconTile } from "./ExperienceIconTile";
import styles from "./GlobalSearch.module.css";
import toolStyles from "./HeaderTool.module.css";
import popoverStyles from "./HeaderPopover.module.css";

type GlobalSearchProps = Readonly<{
  open: boolean;
  inactive?: boolean;
  onOpenChange(open: boolean): void;
  results: GlobalSearchResultScene[];
  onChoose?(id: string): void;
}>;

const panelId = "global-search-results";
const optionId = (index: number) => `global-search-option-${index}`;

export function GlobalSearch({ open, onOpenChange, results, onChoose, inactive = false }: GlobalSearchProps) {
  const t = useTranslations("GlobalSearch");
  const navigation = useConsoleNavigation();
  const input = useRef<HTMLInputElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const options = useRef<HTMLDivElement>(null);
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const matches = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return (normalized ? results.filter((item) => [item.label, item.description, t(`categories.${item.category}`), item.category, ...(item.keywords ?? [])].some((value) => value.toLowerCase().includes(normalized))) : results).slice(0, 8);
  }, [query, results, t]);
  const selectedIndex = Math.min(activeIndex, Math.max(0, matches.length - 1));

  useEffect(() => {
    if (open) input.current?.focus();
  }, [open]);

  useEffect(() => {
    if (open) options.current?.querySelector(`#${optionId(selectedIndex)}`)?.scrollIntoView?.({ block: "nearest" });
  }, [open, selectedIndex]);

  useEffect(() => {
    const shortcut = (event: globalThis.KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== "k") return;
      event.preventDefault();
      if (inactive) return;
      onOpenChange(true);
      input.current?.focus();
    };
    window.addEventListener("keydown", shortcut);
    return () => window.removeEventListener("keydown", shortcut);
  }, [inactive, onOpenChange]);

  function closeAndRestoreFocus() {
    onOpenChange(false);
    const compact = typeof window.matchMedia === "function" && window.matchMedia("(max-width: 720px)").matches;
    (compact ? trigger : input).current?.focus();
  }

  function choose(item: GlobalSearchResultScene) {
    onOpenChange(false);
    setQuery("");
    setActiveIndex(0);
    navigation.navigate(item.href, { onAccepted: () => onChoose?.(item.id) });
  }

  function handleKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      closeAndRestoreFocus();
    }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      onOpenChange(true);
      if (matches.length) setActiveIndex((selectedIndex + (event.key === "ArrowDown" ? 1 : -1) + matches.length) % matches.length);
    }
    if (event.key === "Enter" && open && matches[selectedIndex]) {
      event.preventDefault();
      choose(matches[selectedIndex]);
    }
  }

  return (
    <div className={styles.root} inert={inactive} data-open={open ? "true" : undefined} onBlur={(event) => {
      if (!event.currentTarget.contains(event.relatedTarget)) onOpenChange(false);
    }}>
      <button aria-expanded={open} aria-label={t("open")} className={`${toolStyles.iconButton} ${styles.mobileTrigger}`} onClick={() => onOpenChange(true)} ref={trigger} title={t("shortcut")} type="button"><Search aria-hidden="true" /></button>
      <div className={styles.field}>
        <Search aria-hidden="true" />
        <input
          aria-activedescendant={open && matches.length ? optionId(selectedIndex) : undefined}
          aria-autocomplete="list"
          aria-controls={open ? panelId : undefined}
          aria-expanded={open}
          aria-label={t("placeholder")}
          autoComplete="off"
          onChange={(event) => { setQuery(event.target.value); setActiveIndex(0); onOpenChange(true); }}
          onClick={() => onOpenChange(true)}
          onFocus={() => onOpenChange(true)}
          onKeyDown={handleKeyDown}
          placeholder={t("placeholder")}
          ref={input}
          role="combobox"
          value={query}
        />
        <kbd aria-hidden="true">Ctrl / ⌘ K</kbd>
        <Button aria-label={t("close")} className={styles.closeButton} onClick={closeAndRestoreFocus} iconOnly size="small" variant="ghost"><X aria-hidden="true" /></Button>
      </div>
      {open ? (
        <div className={`${styles.panel} ${popoverStyles.enter}`} data-surface="shell">
          <div className={styles.heading}><strong>{query.trim() ? t("results") : t("quickAccess")}</strong><span aria-live="polite" role="status">{t("count", { count: matches.length })}</span></div>
          <div aria-label={t("results")} className={styles.results} id={panelId} ref={options} role="listbox">
            {matches.map((item, index) => (
              <button aria-selected={index === selectedIndex} className={styles.result} data-active={index === selectedIndex ? "true" : undefined} id={optionId(index)} key={item.id} onClick={() => choose(item)} onMouseDown={(event) => event.preventDefault()} onMouseEnter={() => setActiveIndex(index)} role="option" tabIndex={-1} type="button">
                <ExperienceIconTile kind={item.icon} />
                <span className={styles.copy}><strong>{item.label}</strong><small>{item.description}</small></span>
                <span className={styles.category}>{t(`categories.${item.category}`)}</span><ArrowUpRight aria-hidden="true" />
              </button>
            ))}
          </div>
          {!matches.length ? <EmptyState compact icon={<PackageSearch />} title={t("empty")} description={t("emptyHint")} /> : null}
          <div className={styles.footer}><span>{t("keyboard")}</span><span>{t("escape")}</span></div>
        </div>
      ) : null}
    </div>
  );
}
