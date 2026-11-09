"use client";

import { useId, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { SearchInput } from "@ui/xiak";
import styles from "./AccountAccessRenderer.module.css";

type StatementValue = { value: string; detail?: string; keywords?: string; key?: string };

export function PolicyStatementValues({ entries, field, sid }: {
  entries: readonly StatementValue[];
  field: "declaredActions" | "frozenListLabel" | "resources" | "conditions";
  sid: string;
}) {
  const t = useTranslations("AccountPolicyDirectory");
  const collection = useTranslations("Collection");
  const id = useId();
  const viewport = useRef<HTMLDivElement>(null);
  const [query, setQuery] = useState("");
  const label = t(field);
  const listLabel = t("statementValues", { label, sid });
  const searchable = entries.length > 5 || entries.reduce((length, entry) => length + entry.value.length + (entry.detail?.length ?? 0), 0) > 240;
  const words = query.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean);
  const matches = searchable && words.length ? entries.filter(({ value, detail, keywords }) => {
    const text = [value, detail, keywords].join(" ").normalize("NFKC").toLowerCase();
    return words.every((word) => text.includes(word));
  }) : entries;
  function changeQuery(value: string) {
    setQuery(value);
    if (viewport.current) viewport.current.scrollTop = 0;
  }

  if (!entries.length) return <span className={styles.note}>{t("none")}</span>;
  const rows = <ul aria-label={listLabel} className={styles.statementValues}>
    {matches.map((entry) => <li key={entry.key ?? entry.value}>
      <code>{entry.value}</code>{entry.detail ? <span>{entry.detail}</span> : null}
    </li>)}
  </ul>;
  if (!searchable) return rows;
  return <div className={styles.statementValueBrowser}>
    <div className={styles.statementFilter}>
      <SearchInput aria-label={t("searchStatementValues", { label, sid })} aria-controls={id}
        placeholder={t(`valueSearch.${field}`)} value={query} controlSize="small"
        onChange={(event) => changeQuery(event.target.value)}
        clearAction={query ? { label: collection("clearSearch"), onClear: () => changeQuery("") } : undefined} />
      <span role="status" aria-label={listLabel} aria-atomic="true" className={styles.statementCount}>{words.length
        ? t("valueMatches", { shown: matches.length, total: entries.length }) : t("valueCount", { count: entries.length })}</span>
    </div>
    <div id={id} role="region" aria-label={listLabel} className={styles.statementViewport} ref={viewport} tabIndex={0}>
      {matches.length ? rows : <p className={styles.statementNoMatches}>{t("noValueMatches")}</p>}
    </div>
  </div>;
}
