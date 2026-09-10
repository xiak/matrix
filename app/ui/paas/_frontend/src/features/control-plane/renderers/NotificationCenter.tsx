"use client";

import { ConsoleLink as Link } from "../routes/ConsoleNavigation";
import { useEffect, useRef, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { Bell, ChevronRight, Workflow } from "lucide-react";
import { useTranslations } from "next-intl";
import type { ConsoleMessageScene } from "../scenes/consoleScene";
import { useConsoleUiStore } from "../application/consoleUiStore";
import { MessageInbox } from "./MessageInbox";
import { HeaderPopover, HeaderPopoverHeader } from "./HeaderPopover";
import headerToolStyles from "./HeaderTool.module.css";
import styles from "./NotificationCenter.module.css";

type NotificationCenterProps = Readonly<{
  activeOperationCount: number;
  messages: ConsoleMessageScene[];
  onOpenChange(open: boolean): void;
  open: boolean;
}>;

const panelId = "global-notification-center";

export function NotificationCenter({ activeOperationCount, messages, onOpenChange, open }: NotificationCenterProps) {
  const t = useTranslations("Notifications");
  const readIds = useConsoleUiStore((state) => state.readMessageIds);
  const count = messages.filter((message) => !readIds.includes(message.id)).length;
  const trigger = useRef<HTMLButtonElement>(null);
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (open) root.current?.querySelector<HTMLButtonElement>('[role="tab"]')?.focus();
  }, [open]);

  function closeAndRestoreFocus() {
    onOpenChange(false);
    trigger.current?.focus();
  }

  function handleKeyDown(event: ReactKeyboardEvent<HTMLElement>) {
    if (event.key !== "Escape") return;
    event.preventDefault();
    event.stopPropagation();
    closeAndRestoreFocus();
  }

  return (
    <div className={styles.root} ref={root}>
      <button
        aria-controls={open ? panelId : undefined}
        aria-expanded={open}
        aria-haspopup="dialog"
        aria-label={t(open ? "close" : "open", { count })}
        className={headerToolStyles.iconButton}
        onClick={() => onOpenChange(!open)}
        ref={trigger}
        title={t("title")}
        type="button"
      >
        <Bell aria-hidden="true" />{count ? <span>{count > 99 ? "99+" : count}</span> : null}
      </button>

      {open ? (
        <HeaderPopover align="end" id={panelId} label={t("title")} onKeyDown={handleKeyDown} size="medium">
          <HeaderPopoverHeader
            action={<Link href="/console/messages/" onClick={() => onOpenChange(false)}>{t("viewAll")}</Link>}
            description={t("count", { count })}
            title={t("title")}
          />
          {activeOperationCount > 0 ? <Link className={styles.activeTasks} href="/console/operations/" onClick={() => onOpenChange(false)}><Workflow aria-hidden="true" /><span><strong>{t("runningTasks", { count: activeOperationCount })}</strong><small>{t("taskProgressHint")}</small></span><ChevronRight aria-hidden="true" /></Link> : null}
          <MessageInbox compact messages={messages} onNavigate={() => onOpenChange(false)} />
        </HeaderPopover>
      ) : null}
    </div>
  );
}
