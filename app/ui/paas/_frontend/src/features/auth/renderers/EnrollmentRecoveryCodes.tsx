"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { CheckCircle2, Copy, ShieldCheck } from "lucide-react";
import { Alert, Button, Checkbox } from "@ui/xiak";
import { useSession } from "../application/SessionProvider";
import securityStyles from "./MfaPreviewExperience.module.css";
import loginStyles from "./LoginRenderer.module.css";

export function EnrollmentRecoveryCodes() {
  const t = useTranslations("PersonalSecurity");
  const session = useSession();
  const [acknowledged, setAcknowledged] = useState(false);
  const [copied, setCopied] = useState(false);
  const material = session.enrollmentRecovery;

  if (!material) return null;

  async function copy() {
    try {
      if (!navigator.clipboard) return;
      await navigator.clipboard.writeText(material!.recoveryCodes.join("\n"));
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return <div className={loginStyles.challengeCompletion}>
    <CheckCircle2 aria-hidden="true" />
    <div className={loginStyles.cardHeading}>
      <h1>{t("recovery.title")}</h1>
      <p>{t("recovery.hint")}</p>
    </div>
    <Alert status="warning"><ShieldCheck aria-hidden="true" />{t("recovery.oneTime")}</Alert>
    <div className={securityStyles.secretHeader}>
      <div><strong>{t("recovery.codes")}</strong><p>{t("recovery.offline")}</p></div>
      <Button onClick={() => void copy()} size="small" variant="secondary"><Copy aria-hidden="true" />{t(copied ? "recovery.copied" : "recovery.copy")}</Button>
    </div>
    <ul aria-label={t("recovery.codes")} className={securityStyles.codes}>
      {material.recoveryCodes.map((code) => <li key={code}>{code}</li>)}
    </ul>
    <Checkbox checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)}>{t("recovery.saved")}</Checkbox>
    <Button block disabled={!acknowledged} onClick={session.acknowledgeEnrollmentRecovery}>{t("recovery.reauthenticate")}</Button>
  </div>;
}
