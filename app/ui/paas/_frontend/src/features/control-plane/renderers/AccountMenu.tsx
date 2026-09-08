"use client";

import Link from "next/link";
import {
  useEffect,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent
} from "react";
import { ChevronRight, LogOut, ShieldCheck } from "lucide-react";
import { HeaderPopover } from "./HeaderPopover";
import styles from "./AccountMenu.module.css";

export type AccountIdentity = Readonly<{
  accountType: string;
  loginName: string;
  principalId: string;
  tenant: Readonly<{
    id?: string;
    name: string;
  }>;
}>;

type AccountMenuProps = Readonly<{
  identity: AccountIdentity;
  onLogout(): void;
  onOpenChange(open: boolean): void;
  open: boolean;
  revoking: boolean;
}>;

const accountMenuId = "global-account-menu";

export function AccountMenu({ identity, onLogout, onOpenChange, open, revoking }: AccountMenuProps) {
  const trigger = useRef<HTMLButtonElement>(null);
  const items = useRef<Array<HTMLAnchorElement | HTMLButtonElement | null>>([]);
  const [activeItem, setActiveItem] = useState(0);

  useEffect(() => {
    if (open) items.current[activeItem]?.focus();
  }, [activeItem, open]);

  function focusItem(index: number) {
    setActiveItem(index);
    items.current[index]?.focus();
  }

  function closeAndRestoreFocus() {
    onOpenChange(false);
    trigger.current?.focus();
  }

  function handlePanelKeyDown(event: ReactKeyboardEvent<HTMLElement>) {
    if (event.key !== "Escape") return;
    event.preventDefault();
    event.stopPropagation();
    closeAndRestoreFocus();
  }

  function handleMenuKeyDown(event: ReactKeyboardEvent<HTMLUListElement>) {
    const availableItems = revoking ? [0] : [0, 1];
    const currentPosition = Math.max(0, availableItems.indexOf(activeItem));
    let nextPosition: number | undefined;

    if (event.key === "ArrowDown") nextPosition = (currentPosition + 1) % availableItems.length;
    if (event.key === "ArrowUp") nextPosition = (currentPosition - 1 + availableItems.length) % availableItems.length;
    if (event.key === "Home") nextPosition = 0;
    if (event.key === "End") nextPosition = availableItems.length - 1;
    if (nextPosition === undefined) return;

    event.preventDefault();
    focusItem(availableItems[nextPosition] ?? 0);
  }

  const initial = identity.loginName.slice(0, 1).toUpperCase();

  return (
    <div className={styles.root}>
      <button
        aria-controls={open ? accountMenuId : undefined}
        aria-expanded={open}
        aria-haspopup="dialog"
        aria-label={`${open ? "关闭" : "打开"}账号菜单，当前用户 ${identity.loginName}`}
        className={styles.trigger}
        onClick={() => {
          if (!open) setActiveItem(0);
          onOpenChange(!open);
        }}
        ref={trigger}
        type="button"
      >
        <span aria-hidden="true" className={styles.avatar}>{initial}</span>
      </button>

      {open ? (
        <HeaderPopover
          align="end"
          id={accountMenuId}
          label="账号菜单"
          onKeyDown={handlePanelKeyDown}
          size="compact"
        >
          <header className={styles.header}>
            <span aria-hidden="true" className={styles.panelAvatar}>{initial}</span>
            <div className={styles.identity}>
              <small>当前登录用户</small>
              <strong>{identity.loginName}</strong>
              <span>{identity.principalId}</span>
            </div>
          </header>

          <dl className={styles.metadata}>
            <div>
              <dt>当前租户</dt>
              <dd><strong>{identity.tenant.name}</strong>{identity.tenant.id ? <span>{identity.tenant.id}</span> : null}</dd>
            </div>
            <div><dt>账号类型</dt><dd>{identity.accountType}</dd></div>
          </dl>

          <div className={styles.actionSection}>
            <span className={styles.actionLabel}>账号操作</span>
            <ul aria-label="账号操作" className={styles.menu} onKeyDown={handleMenuKeyDown} role="menu">
              <li role="none">
                <Link
                  className={styles.menuItem}
                  href="/console/access/"
                  onClick={() => onOpenChange(false)}
                  ref={(node) => { items.current[0] = node; }}
                  role="menuitem"
                  tabIndex={activeItem === 0 ? 0 : -1}
                >
                  <span aria-hidden="true" className={styles.menuIcon}><ShieldCheck /></span>
                  <span className={styles.menuCopy}><strong>账号与权限</strong><small>用户、角色与租户</small></span>
                  <ChevronRight aria-hidden="true" className={styles.chevron} />
                </Link>
              </li>
              <li className={styles.separator} role="separator" />
              <li role="none">
                <button
                  aria-label="注销并撤销 IAM 会话"
                  className={`${styles.menuItem} ${styles.dangerItem}`}
                  disabled={revoking}
                  onClick={onLogout}
                  ref={(node) => { items.current[1] = node; }}
                  role="menuitem"
                  tabIndex={activeItem === 1 ? 0 : -1}
                  type="button"
                >
                  <span aria-hidden="true" className={styles.menuIcon}><LogOut /></span>
                  <span className={styles.menuCopy}><strong>{revoking ? "正在退出…" : "退出登录"}</strong><small>撤销当前 IAM 会话</small></span>
                  <span aria-hidden="true" className={styles.chevronSpace} />
                </button>
              </li>
            </ul>
          </div>
        </HeaderPopover>
      ) : null}
    </div>
  );
}
