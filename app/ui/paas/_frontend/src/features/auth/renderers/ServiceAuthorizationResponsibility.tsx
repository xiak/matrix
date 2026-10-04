"use client";

import { useId } from "react";
import { useTranslations } from "next-intl";
import { Badge } from "@ui/xiak";
import styles from "./ServiceAuthorizationResponsibility.module.css";

const owners = ["product", "iam", "tenant"] as const;

/**
 * Stable ownership context shared by isolated previews and fixed read clients.
 * It describes who owns each fact and deliberately exposes no publisher or
 * consent command.
 */
export function ServiceAuthorizationResponsibility() {
  const t = useTranslations("ServiceAuthorizationPreview.directory.responsibility");
  const titleId = useId();

  return <section aria-labelledby={titleId} className={styles.root}>
    <div className={styles.heading}>
      <h3 id={titleId}>{t("title")}</h3>
      <p>{t("hint")}</p>
    </div>
    <ol className={styles.stages}>
      {owners.map((owner, index) => <li key={owner}>
        <span className={styles.index} aria-hidden="true">{index + 1}</span>
        <div><strong>{t(`${owner}.title`)}</strong><small>{t(`${owner}.hint`)}</small></div>
        <Badge status="neutral">{t(`${owner}.state`)}</Badge>
      </li>)}
    </ol>
  </section>;
}
