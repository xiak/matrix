"use client";

import { useRef, type KeyboardEvent } from "react";
import { useTranslations } from "next-intl";
import { Grid2X2 } from "lucide-react";
import { HeaderPopover, HeaderPopoverTrigger } from "./HeaderPopover";
import { ServiceDirectory } from "./ServiceDirectory";
import styles from "./ProductLauncher.module.css";

type ProductLauncherProps = Readonly<{
  onOpenChange(open: boolean): void;
  open: boolean;
}>;

const panelId = "global-product-launcher";

export function ProductLauncher({ onOpenChange, open }: ProductLauncherProps) {
  const t = useTranslations("ServiceDirectory");
  const trigger = useRef<HTMLButtonElement>(null);

  function closeAndRestoreFocus() {
    onOpenChange(false);
    trigger.current?.focus();
  }

  function handleKeyDown(event: KeyboardEvent<HTMLElement>) {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      return;
    }
    if (event.key !== "Tab") return;
    const controls = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('input, button:not([disabled]):not([tabindex="-1"]), a[href]:not([tabindex="-1"])'));
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  }

  return (
    <div className={styles.root}>
      <HeaderPopoverTrigger
        aria-label={t(open ? "close" : "open")}
        icon={<Grid2X2 />}
        label={t("title")}
        onClick={() => open ? closeAndRestoreFocus() : onOpenChange(true)}
        open={open}
        panelId={panelId}
        ref={trigger}
        tabIndex={open ? -1 : undefined}
        title={t(open ? "close" : "open")}
      />
      {open ? (
        <HeaderPopover align="start" id={panelId} label={t("dialog")} modal onKeyDown={handleKeyDown} size="catalog">
          <ServiceDirectory onClose={closeAndRestoreFocus} onNavigate={() => onOpenChange(false)} />
        </HeaderPopover>
      ) : null}
    </div>
  );
}
