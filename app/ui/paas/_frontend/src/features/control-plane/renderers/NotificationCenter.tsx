"use client";

import Link from "next/link";
import { useEffect, useRef, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { Bell } from "lucide-react";
import { Badge } from "@ui/xiak";
import type { AlertScene } from "../scenes/consoleScene";
import { HeaderPopover, HeaderPopoverHeader } from "./HeaderPopover";
import headerToolStyles from "./HeaderTool.module.css";
import styles from "./NotificationCenter.module.css";

type NotificationCenterProps = Readonly<{
  count: number;
  notices: AlertScene[];
  onOpenChange(open: boolean): void;
  open: boolean;
}>;

const panelId = "global-notification-center";

export function NotificationCenter({ count, notices, onOpenChange, open }: NotificationCenterProps) {
  const trigger = useRef<HTMLButtonElement>(null);
  const firstNotice = useRef<HTMLAnchorElement>(null);
  const viewAll = useRef<HTMLAnchorElement>(null);
  useEffect(() => {
    if (open) (firstNotice.current ?? viewAll.current)?.focus();
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
    <div className={styles.root}>
      <button
        aria-controls={open ? panelId : undefined}
        aria-expanded={open}
        aria-haspopup="dialog"
        aria-label={`${open ? "关闭" : "打开"}通知中心，${count} 个待处理`}
        className={headerToolStyles.iconButton}
        onClick={() => onOpenChange(!open)}
        ref={trigger}
        type="button"
      >
        <Bell aria-hidden="true" />{count ? <span>{count}</span> : null}
      </button>

      {open ? (
        <HeaderPopover align="end" id={panelId} label="通知中心" onKeyDown={handleKeyDown} size="medium">
          <HeaderPopoverHeader
            action={<Link href="/console/observability/" onClick={() => onOpenChange(false)} ref={viewAll}>告警中心</Link>}
            description={`${count} 个事项需要处理`}
            title="通知中心"
          />
          <ul className={styles.list}>
            {notices.map((notice, index) => (
              <li key={notice.id}>
                <Link href="/console/observability/" onClick={() => onOpenChange(false)} ref={index === 0 ? firstNotice : undefined}>
                  <span data-status={notice.status} />
                  <span className={styles.copy}><strong>{notice.title}</strong><small>{notice.serviceName} · {notice.startedAt}</small></span>
                  <Badge status={notice.status}>{notice.severityLabel}</Badge>
                </Link>
              </li>
            ))}
          </ul>
        </HeaderPopover>
      ) : null}
    </div>
  );
}
