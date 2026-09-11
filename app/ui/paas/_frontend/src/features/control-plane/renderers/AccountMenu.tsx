"use client";

import { ConsoleLink as Link } from "../routes/ConsoleNavigation";
import { useTranslations } from "next-intl";
import { AppearanceControls } from "@/preferences/AppearanceControls";
import { PanelSections } from "@ui/xiak";
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
  const t = useTranslations("AccountMenu");
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

  function handleMenuKeyDown(event: ReactKeyboardEvent<HTMLDivElement>) {
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
        aria-label={t(open ? "close" : "open", { name: identity.loginName })}
        className={styles.trigger}
        onClick={() => {
          if (!open) setActiveItem(0);
          onOpenChange(!open);
        }}
        ref={trigger}
        title={t("account", { name: identity.loginName })}
        type="button"
      >
        <span aria-hidden="true" className={styles.avatar}>{initial}</span>
      </button>

      {open ? (
        <HeaderPopover
          align="end"
          id={accountMenuId}
          label={t("title")}
          onKeyDown={handlePanelKeyDown}
          size="compact"
        >
          <PanelSections>
            <PanelSections.Section aria-label={t("signedIn")} role="group">
              <header className={styles.header}>
                <span aria-hidden="true" className={styles.panelAvatar}>{initial}</span>
                <div className={styles.identity}>
                  <small>{t("signedIn")}</small>
                  <strong>{identity.loginName}</strong>
                  <span>{identity.principalId}</span>
                </div>
              </header>
            </PanelSections.Section>

            <PanelSections.Section aria-label={t("tenant")} role="group">
              <dl className={styles.metadata}>
                <div>
                  <dt>{t("tenant")}</dt>
                  <dd><strong>{identity.tenant.name}</strong>{identity.tenant.id ? <span>{identity.tenant.id}</span> : null}</dd>
                </div>
                <div><dt>{t("type")}</dt><dd>{identity.accountType}</dd></div>
              </dl>
            </PanelSections.Section>

            <PanelSections.Section><AppearanceControls variant="panel" /></PanelSections.Section>
            <PanelSections aria-label={t("actions")} onKeyDown={handleMenuKeyDown} role="menu">
              <PanelSections.Section role="none">
                <span className={styles.actionLabel}>{t("actions")}</span>
                <Link
                  className={styles.menuItem}
                  href="/console/access/"
                  onClick={() => onOpenChange(false)}
                  ref={(node) => { items.current[0] = node; }}
                  role="menuitem"
                  tabIndex={activeItem === 0 ? 0 : -1}
                >
                  <span aria-hidden="true" className={styles.menuIcon}><ShieldCheck /></span>
                  <span className={styles.menuCopy}><strong>{t("access")}</strong><small>{t("accessHint")}</small></span>
                  <ChevronRight aria-hidden="true" className={styles.chevron} />
                </Link>
              </PanelSections.Section>
              <PanelSections.Section role="none">
                <button
                  aria-label={t("logoutLabel")}
                  className={`${styles.menuItem} ${styles.dangerItem}`}
                  disabled={revoking}
                  onClick={onLogout}
                  ref={(node) => { items.current[1] = node; }}
                  role="menuitem"
                  tabIndex={activeItem === 1 ? 0 : -1}
                  type="button"
                >
                  <span aria-hidden="true" className={styles.menuIcon}><LogOut /></span>
                  <span className={styles.menuCopy}><strong>{t(revoking ? "loggingOut" : "logout")}</strong><small>{t("logoutHint")}</small></span>
                  <span aria-hidden="true" className={styles.chevronSpace} />
                </button>
              </PanelSections.Section>
            </PanelSections>
          </PanelSections>
        </HeaderPopover>
      ) : null}
    </div>
  );
}
