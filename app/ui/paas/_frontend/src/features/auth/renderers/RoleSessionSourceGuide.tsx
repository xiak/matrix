"use client";

import { useId } from "react";
import { useTranslations } from "next-intl";
import { Badge } from "@ui/xiak";
import styles from "./RoleSessionSourceGuide.module.css";

const sourceTypes = ["USER", "SERVICE_ACCOUNT"] as const;

/**
 * Stable RoleSession source semantics shared by the isolated administrator
 * preview and the strict read client. It does not infer a source directory or
 * expose a session command.
 */
export function RoleSessionSourceGuide() {
  const t = useTranslations("RoleWorkspace.sourceGuide");
  const titleId = useId();

  return <section aria-labelledby={titleId} className={styles.root}>
    <div className={styles.heading}>
      <h4 id={titleId}>{t("title")}</h4>
      <p>{t("hint")}</p>
    </div>
    <div className={styles.types}>
      {sourceTypes.map((type) => <article key={type}>
        <div><Badge status={type === "USER" ? "neutral" : "info"}>{type}</Badge><strong>{t(`${type}.title`)}</strong></div>
        <p>{t(`${type}.description`)}</p>
        <small>{t(`${type}.evidence`)}</small>
      </article>)}
    </div>
    <p className={styles.boundary}>{t("boundary")}</p>
  </section>;
}
