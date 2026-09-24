"use client";

import { useEffect, useState } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { RefreshCcw, ShieldCheck } from "lucide-react";
import { Alert, Badge, Button, Card, Typography } from "@ui/xiak";
import type { AccountSecuritySettingsClient, AccountSecuritySettingsLoad } from "../application/AccountAccessProvider";
import styles from "./MfaPreviewExperience.module.css";

type ViewState = { client: AccountSecuritySettingsClient | null; result: AccountSecuritySettingsLoad | { status: "loading" } };

export function LiveAccountSecuritySettings({ client }: { client: AccountSecuritySettingsClient | null }) {
  const t = useTranslations("MfaPreview");
  const format = useFormatter();
  const [retry, setRetry] = useState(0);
  const [view, setView] = useState<ViewState>({ client, result: { status: "loading" } });

  useEffect(() => {
    if (!client) return;
    let current = true;
    void client.load().then((result) => {
      if (current) setView({ client, result });
    }, () => {
      if (current) setView({ client, result: { status: "unavailable" } });
    });
    return () => { current = false; };
  }, [client, retry]);

  const result = view.client === client ? view.result : { status: "loading" as const };
  const retryRead = () => { setView({ client, result: { status: "loading" } }); setRetry((value) => value + 1); };
  const canRetry = result.status === "routeUnavailable" || result.status === "unavailable";

  return <section aria-labelledby="live-account-security" className={styles.section}>
    <div className={styles.sectionHeading}>
      <div><p>{t("accountEyebrow")}</p><h2 id="live-account-security">{t("accountTitle")}</h2><span>{t("accountHint")}</span></div>
      <Badge status="success">LIVE</Badge>
    </div>
    <Card>
      <Card.Header><div className={styles.cardTitle}><span><ShieldCheck aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("accountControlTitle")}</Typography.Title><Typography.Text tone="muted">{t("accountControlHint")}</Typography.Text></div></div></Card.Header>
      <Card.Body className={styles.policyForm} aria-busy={result.status === "loading"}>
        {!client ? <Alert status="warning">{t("accountReadUnavailable")}</Alert> : null}
        {client && result.status === "loading" ? <Typography.Text role="status" tone="muted">{t("accountReadLoading")}</Typography.Text> : null}
        {result.status === "ready" ? <>
          <dl className={styles.facts}>
            <div><dt>{t("currentRule")}</dt><dd>{t(result.settings.mfa.requiredForUsers ? "required" : "optional")}</dd></div>
            <div><dt>{t("accountScope")}</dt><dd>{t("accountScopeValue")}</dd></div>
            <div><dt>{t("accountTarget")}</dt><dd><code>{result.settings.accountId}</code></dd></div>
            <div><dt>{t("accountReadVersion")}</dt><dd>{result.settings.resourceVersion}</dd></div>
            <div><dt>{t("accountReadUpdated")}</dt><dd><time dateTime={result.settings.updatedAt}>{format.dateTime(new Date(result.settings.updatedAt), { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}</time></dd></div>
          </dl>
          <Alert>{t("accountReadBoundary")}</Alert>
        </> : null}
        {result.status === "forbidden" ? <Alert status="warning">{t("accountReadDenied")}</Alert> : null}
        {canRetry ? <Alert status="danger">{t(result.status === "routeUnavailable" ? "accountReadRouteUnavailable" : "accountReadUnavailable")} <Button onClick={retryRead} size="small" variant="ghost"><RefreshCcw aria-hidden="true" />{t("accountReadRetry")}</Button></Alert> : null}
      </Card.Body>
    </Card>
  </section>;
}
