"use client";

import Link from "next/link";
import { useEffect, useRef, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { ChevronDown, ChevronRight, Grid2X2 } from "lucide-react";
import type { GlobalSearchResultScene } from "../scenes/consoleScene";
import { ExperienceIconTile } from "./ExperienceIconTile";
import { HeaderPopover, HeaderPopoverHeader } from "./HeaderPopover";
import styles from "./ProductLauncher.module.css";

type ProductLauncherProps = Readonly<{
  onOpenChange(open: boolean): void;
  open: boolean;
  products: GlobalSearchResultScene[];
}>;

const panelId = "global-product-launcher";

export function ProductLauncher({ onOpenChange, open, products }: ProductLauncherProps) {
  const trigger = useRef<HTMLButtonElement>(null);
  const firstProduct = useRef<HTMLAnchorElement>(null);
  const viewAll = useRef<HTMLAnchorElement>(null);

  useEffect(() => {
    if (open) (firstProduct.current ?? viewAll.current)?.focus();
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
        aria-label={`${open ? "关闭" : "打开"}产品与服务`}
        className={styles.trigger}
        onClick={() => onOpenChange(!open)}
        ref={trigger}
        type="button"
      >
        <Grid2X2 aria-hidden="true" /><span>产品</span><ChevronDown aria-hidden="true" />
      </button>

      {open ? (
        <HeaderPopover align="start" id={panelId} label="云产品入口" onKeyDown={handleKeyDown} size="wide">
          <HeaderPopoverHeader
            action={<Link href="/console/products/" onClick={() => onOpenChange(false)} ref={viewAll}>查看全部</Link>}
            description="按工作场景进入 Matrix Cloud"
            title="产品与服务"
          />
          <ul className={styles.grid}>
            {products.map((product, index) => (
              <li key={product.id}>
                <Link
                  className={styles.item}
                  href={product.href}
                  onClick={() => onOpenChange(false)}
                  ref={index === 0 ? firstProduct : undefined}
                >
                  <ExperienceIconTile kind={product.icon} />
                  <span className={styles.copy}><strong>{product.label}</strong><small>{product.description}</small></span>
                  <ChevronRight aria-hidden="true" />
                </Link>
              </li>
            ))}
          </ul>
        </HeaderPopover>
      ) : null}
    </div>
  );
}
