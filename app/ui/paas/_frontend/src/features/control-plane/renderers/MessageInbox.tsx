"use client";

import { useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Bell, CheckCheck, ChevronDown, Megaphone, Workflow } from "lucide-react";
import { Button, Checkbox, EmptyState, RadioGroup, TableToolbar, Tabs } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import { useConsoleUiStore } from "../application/consoleUiStore";
import { ConsoleLink as Link } from "../routes/ConsoleNavigation";
import type { ConsoleMessageScene } from "../scenes/consoleScene";
import { useConsoleFormat } from "./useConsoleFormat";
import styles from "./MessageInbox.module.css";

const categories = ["all", "alert", "operation", "platform"] as const;
type MessageCategory = typeof categories[number];
const icons = { alert: Bell, operation: Workflow, platform: Megaphone };

function MessageItem({ message, read, expanded, onToggle, onNavigate }: { message: ConsoleMessageScene; read: boolean; expanded: boolean; onToggle(): void; onNavigate?(): void }) {
  const t = useTranslations("Notifications");
  const format = useConsoleFormat();
  const Icon = icons[message.category];
  const title = message.result ? `${message.title} · ${t(`results.${message.result}`)}` : message.title;
  return <li>
    <details className={styles.message} data-read={read} open={expanded}>
      <summary aria-label={t("summary", { title, state: t(read ? "read" : "unread") })} onClick={(event) => { event.preventDefault(); onToggle(); }}>
        <span aria-hidden="true" className={styles.icon} data-status={message.status}><Icon /></span>
        <span className={styles.copy}><strong>{title}</strong><small>{t(`categories.${message.category}`)} · {format.timestamp(message.createdAt)}</small></span>
        <span aria-hidden="true" className={styles.indicators}>{!read ? <span className={styles.unread} /> : null}<ChevronDown /></span>
      </summary>
      {expanded ? <div className={styles.detail}>
        <p>{message.description}</p>
        {message.category === "alert" ? <p className={styles.hint}>{t("alertReadHint")}</p> : null}
        {message.href ? <Button asChild size="small" variant="secondary"><Link href={message.href} onClick={onNavigate}>{t(`destinations.${message.category}`)}</Link></Button> : null}
      </div> : null}
    </details>
  </li>;
}

// The same inbox owns category, read-state and message details in both surfaces.
export function MessageInbox({ messages, compact = false, onNavigate }: { messages: ConsoleMessageScene[]; compact?: boolean; onNavigate?(): void }) {
  const t = useTranslations("Notifications");
  const toolbarLabels = useTableToolbarLabels();
  const readIds = useConsoleUiStore((state) => state.readMessageIds);
  const markRead = useConsoleUiStore((state) => state.markMessagesRead);
  const [category, setCategory] = useState<MessageCategory>("all");
  const [readFilter, setReadFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const filterControl = useRef<HTMLDivElement>(null);
  const unread = messages.filter((message) => !readIds.includes(message.id));
  const visible = messages.filter((message) => (category === "all" || message.category === category)
    && (readFilter === "all" || message.id === expandedId || readIds.includes(message.id) === (readFilter === "read"))
    && `${message.title} ${message.description} ${message.result ? t(`results.${message.result}`) : ""}`.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()));

  function toggleMessage(id: string) {
    if (expandedId === id) {
      setExpandedId(null);
      if (readFilter === "unread") (filterControl.current?.querySelector<HTMLInputElement>("input:checked") ?? filterControl.current?.querySelector<HTMLInputElement>("input"))?.focus();
    } else {
      setExpandedId(id);
      markRead([id]);
    }
  }

  return <div className={styles.root} data-compact={compact}>
    <Tabs.Root value={category} onValueChange={(value) => { setCategory(value as MessageCategory); setExpandedId(null); }}>
      <Tabs.List aria-label={t("categoryLabel")} className={styles.tabs}>
        {categories.map((item) => <Tabs.Trigger key={item} value={item}>{t(`categories.${item}`)}</Tabs.Trigger>)}
      </Tabs.List>
      {compact ? <div className={styles.toolbar}>
        <div className={styles.readFilter} ref={filterControl}>
          <Checkbox checked={readFilter === "unread"} onChange={(event) => { setReadFilter(event.target.checked ? "unread" : "all"); setExpandedId(null); }}>{t("onlyUnread")}</Checkbox>
        </div>
        <Button disabled={!unread.length} onClick={() => markRead(unread.map((item) => item.id))} size="small" variant="ghost">{t("markAllRead")}</Button>
      </div> : <TableToolbar labels={toolbarLabels} search={{ label: t("search"), placeholder: t("searchHint"), value: query, onChange: setQuery }} tools={<>
        <div className={styles.readFilter} ref={filterControl}><RadioGroup label={t("readFilter")} options={[{ value: "all", label: t("allStates") }, { value: "unread", label: t("unread") }, { value: "read", label: t("read") }]} value={readFilter} variant="text" onValueChange={(value) => { setReadFilter(value); setExpandedId(null); }} /></div>
        <Button disabled={!unread.length} onClick={() => markRead(unread.map((item) => item.id))} size="small" variant="ghost">{t("markAllRead")}</Button>
      </>} />}
      <Tabs.Content className={styles.content} key={`${category}:${readFilter}`} value={category}>
        {!visible.length ? <EmptyState compact icon={<CheckCheck />} title={t("empty")} description={t("emptyHint")} /> : <ul aria-label={t("messageList")} className={styles.list}>
          {visible.map((message) => <MessageItem key={message.id} message={message} read={readIds.includes(message.id)} expanded={message.id === expandedId} onToggle={() => toggleMessage(message.id)} onNavigate={onNavigate} />)}
        </ul>}
      </Tabs.Content>
    </Tabs.Root>
    <p className={styles.footnote}>{t("previewReadHint")}</p>
  </div>;
}
