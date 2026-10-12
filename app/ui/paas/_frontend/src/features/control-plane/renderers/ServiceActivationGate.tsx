"use client";

import { useId, useState, type ReactNode } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, Checkbox, Typography } from "@ui/xiak";
import { Building2, CheckCircle2, KeyRound, PackageCheck } from "lucide-react";
import type { ServiceActivationAccess, ServiceActivationState } from "../domain/serviceActivation";
import styles from "./ServiceActivationGate.module.css";

export type ServiceActivationGateProps = {
  account: { id: string; name?: string };
  service: { key: string; name: string; description: string; termsVersion: string; icon: ReactNode };
  access: ServiceActivationAccess;
  state: ServiceActivationState;
  consent: ReactNode;
  enableLabel?: string;
  retryLabel?: string;
  unavailableHint?: ReactNode;
  failureHint?: ReactNode;
  onEnable(): void;
  requestAccess?: ReactNode;
  children: ReactNode;
};

// A product-level workflow. Public controls remain owned by @ui/xiak; a LIVE
// adapter must supply current activation facts and independent capabilities.
export function ServiceActivationGate({ account, service, access, state, consent, enableLabel, retryLabel, unavailableHint, failureHint, onEnable, requestAccess, children }: ServiceActivationGateProps) {
  const t = useTranslations("ServiceActivation");
  const titleId = useId();
  const [acknowledgement, setAcknowledgement] = useState<string | null>(null);
  const consentKey = JSON.stringify([account.id, service.key, service.termsVersion]);
  const accepted = acknowledgement === consentKey;
  const validEnabled = state.status === "enabled" && state.record.accountId === account.id && state.record.serviceKey === service.key;
  const status = state.status === "enabled" && !validEnabled ? "unavailable" : state.status;
  const busy = status === "checking" || status === "enabling";
  if (validEnabled && access.canUse) return <>{children}</>;

  return <Card aria-labelledby={titleId} className={styles.card}>
    <Card.Header className={styles.header}>
      <div className={styles.identity}>
        <span className={styles.icon}>{service.icon}</span>
        <div><Typography.Eyebrow>{t("eyebrow")}</Typography.Eyebrow><Typography.Title as="h2" id={titleId} level={2}>{service.name}</Typography.Title></div>
      </div>
      <Badge status={validEnabled ? "success" : status === "failed" ? "danger" : busy ? "info" : "neutral"}>{t(`states.${status}`)}</Badge>
    </Card.Header>
    <Card.Body className={styles.body}>
      <p className={styles.description}>{service.description}</p>
      <div className={styles.scope}><Building2 aria-hidden="true" /><div><small>{t("account")}</small><strong>{account.name ?? account.id}</strong>{account.name ? <span>{account.id}</span> : null}</div></div>
      <dl className={styles.facts}>
        <div><PackageCheck aria-hidden="true" /><dt>{t("scopeTitle")}</dt><dd>{t("scopeHint")}</dd></div>
        <div><KeyRound aria-hidden="true" /><dt>{t("permissionTitle")}</dt><dd>{t("permissionHint")}</dd></div>
        <div><CheckCircle2 aria-hidden="true" /><dt>{t("nextTitle")}</dt><dd>{t("nextHint")}</dd></div>
      </dl>
      {status === "unavailable" ? <Alert status="info">{unavailableHint ?? t("unavailableHint")}</Alert>
        : validEnabled ? <Alert status="info">{t("noUsePermission")}</Alert>
          : !access.canEnable && !busy ? <Alert status="info">{t("noEnablePermission")}</Alert>
            : status === "failed" ? <Alert status="danger">{failureHint ?? t("failedHint")}</Alert> : null}
    </Card.Body>
    <Card.Footer className={styles.footer}>
      {(status === "not-enabled" || status === "failed" || status === "enabling") && access.canEnable ? <form className={styles.consent} onSubmit={(event) => {
        event.preventDefault();
        if (accepted && !busy) onEnable();
      }}>
        <div><Checkbox checked={accepted} disabled={busy} onChange={(event) => setAcknowledgement(event.target.checked ? consentKey : null)}>{consent}</Checkbox><small>{t("termsVersion", { version: service.termsVersion })}</small></div>
        <Button disabled={!accepted || busy} type="submit">{status === "enabling" ? t("enabling") : status === "failed" ? retryLabel ?? t("retry") : enableLabel ?? t("enable")}</Button>
      </form> : <div className={styles.status} role={busy ? "status" : undefined}>
        <span>{t(busy ? status === "checking" ? "checkingHint" : "enablingHint" : status === "unavailable" ? "unavailableFooter" : validEnabled ? "enabledPermissionHint" : "contactHint")}</span>
        {status !== "unavailable" && !busy ? requestAccess : null}
      </div>}
    </Card.Footer>
  </Card>;
}
