"use client";
import type { ReactNode } from "react";
import { useTranslations } from "next-intl";
import type { ProductID } from "@/api/installationContract";
import { Button, EmptyState, PageSkeleton } from "@ui/xiak";
import { useProduct } from "./ProductProvider";
import { RequestFeedback } from "./RequestFeedback";
import styles from "./Workspace.module.css";

export function ProductGate({ id, children }: { id: ProductID; children: ReactNode }) {
  const t = useTranslations("Platform");
  const { product, canMutate, inventory } = useProduct(id);
  if (inventory.status === "loading") return <PageSkeleton label={t("loadingProducts")} />;
  if (inventory.status === "error") return <div className={styles.stack}><RequestFeedback error={inventory.error} /><Button variant="secondary" onClick={inventory.refresh}>{t("refresh")}</Button></div>;
  if (!product) return <EmptyState title={t("emptyProducts")} description={t("emptyHint")} />;
  return <div className={styles.stack}>{!canMutate ? <div className={styles.feedback} role="status"><span><strong>{t("readOnly")}</strong><br />{t("readOnlyHint")}</span><Button variant="ghost" onClick={inventory.refresh}>{t("refresh")}</Button></div> : null}{children}</div>;
}
