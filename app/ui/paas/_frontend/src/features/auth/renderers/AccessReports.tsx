"use client";
import { useState } from "react";
import { useTranslations } from "next-intl";
import { Download } from "lucide-react";
import { Alert, Button, Card, Typography } from "@ui/xiak";
import type { AccessWorkspace } from "../domain/accessWorkspace";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import { buildAccessReport } from "../scenes/accessReport";
import styles from "./AccountAccessRenderer.module.css";

export function AccessReports({ workspace, scene }: { workspace: AccessWorkspace; scene: AccountAccessScene }) {
  const t = useTranslations("IamWorkspace");
  const [failed, setFailed] = useState(false);
  function download(kind: "credentials" | "security") {
    try {
      const report = buildAccessReport(kind, workspace, scene, new Date().toISOString());
      const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url; link.download = `matrix-mock-${kind}-report.json`; link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setFailed(false);
    } catch { setFailed(true); }
  }
  return <Card><Card.Header><Typography.Title as="h2" level={3}>{t("securityReport")}</Typography.Title></Card.Header><Card.Body className={styles.stack}><p className={styles.note}>{t("reportHint")}</p>{failed ? <Alert status="danger">{t("errors.unavailable")}</Alert> : null}<Button variant="secondary" onClick={() => download("credentials")}><Download aria-hidden="true" />{t("credentialReport")}</Button><Button variant="secondary" onClick={() => download("security")}><Download aria-hidden="true" />{t("securityReport")}</Button></Card.Body></Card>;
}
