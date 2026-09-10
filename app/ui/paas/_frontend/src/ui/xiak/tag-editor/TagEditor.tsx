"use client";

import { useId } from "react";
import { Plus, X } from "lucide-react";
import { Button } from "../button/Button";
import { FormField } from "../form/FormField";
import { Input } from "../input/Input";
import styles from "./TagEditor.module.css";

/** Metadata only. Consumers own tag validation and any authorization meaning. */
export function TagEditor({ value, onChange, labels, error, limit = 10 }: {
  value: readonly { key: string; value: string }[];
  onChange(value: { key: string; value: string }[]): void;
  labels: { key(index: number): string; value(index: number): string; remove(index: number): string; add: string; empty: string; count: string };
  error?: string;
  limit?: number;
}) {
  const id = useId();
  return <div className={styles.root}>
    {value.length ? <div className={styles.rows}>{value.map((tag, index) => <div key={index} className={styles.row}>
      <FormField id={`${id}-key-${index}`} label={labels.key(index + 1)}><Input id={`${id}-key-${index}`} maxLength={64} invalid={Boolean(error)} aria-describedby={error ? id + "-error" : undefined} value={tag.key} onChange={(event) => onChange(value.map((entry, at) => at === index ? { ...entry, key: event.target.value } : entry))} /></FormField>
      <FormField id={`${id}-value-${index}`} label={labels.value(index + 1)}><Input id={`${id}-value-${index}`} maxLength={128} value={tag.value} onChange={(event) => onChange(value.map((entry, at) => at === index ? { ...entry, value: event.target.value } : entry))} /></FormField>
      <Button variant="ghost" iconOnly aria-label={labels.remove(index + 1)} onClick={() => onChange(value.filter((_, at) => at !== index))}><X aria-hidden="true" /></Button>
    </div>)}</div> : <p className={styles.empty}>{labels.empty}</p>}
    {error ? <p id={id + "-error"} role="alert" className={styles.error}>{error}</p> : null}
    <div className={styles.actions}><Button variant="secondary" disabled={value.length >= limit} onClick={() => onChange([...value, { key: "", value: "" }])}><Plus aria-hidden="true" />{labels.add}</Button><span>{labels.count}</span></div>
  </div>;
}
