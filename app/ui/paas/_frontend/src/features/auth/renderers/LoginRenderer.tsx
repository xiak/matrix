"use client";

import { useTranslations } from "next-intl";
import { ChartNoAxesCombined, Database, Gauge, GitBranch, Layers3, MapPin, ShieldCheck } from "lucide-react";
import { App, Brand } from "@ui/xiak";
import { AppearanceControls } from "@/preferences/AppearanceControls";
import { uxPreviewEnabled } from "@/infrastructure/runtime/uxPreviewMode";
import { useSession } from "../application/SessionProvider";
import { AccountLoginForm } from "./AccountLoginForm";
import { PasswordChangeForm } from "./PasswordChangeForm";
import styles from "./LoginRenderer.module.css";

export function LoginRenderer({ returnTo = "/console/" }: { returnTo?: string }) {
  const session = useSession();
  const t = useTranslations("Auth");
  const firstLogin = Boolean(session.current && session.phase !== "authenticated");
  return <App.Frame><App.Background /><App.Layers><App.Layer>
    <div className={styles.page}>
      <header className={styles.header}>
        <Brand className={styles.mobileBrand} />
        <span className={styles.platformLabel}>{t("platform")}</span>
        <AppearanceControls />
      </header>
      <main className={styles.main}>
        <section aria-labelledby="brand-message" className={styles.brandPanel}>
          <Brand className={styles.signature} variant="signature" />
          <p className={styles.headline} id="brand-message">{t("headline")}<span>{t("headlineAccent")}</span></p>
          <p className={styles.lead}>{t(uxPreviewEnabled ? "lead" : "productionLead")}</p>
          <div className={styles.capabilities}>
            {uxPreviewEnabled ? <>
              <span><Layers3 aria-hidden="true" />{t("infrastructure")}</span>
              <span><GitBranch aria-hidden="true" />{t("delivery")}</span>
              <span><ChartNoAxesCombined aria-hidden="true" />{t("observability")}</span>
            </> : <>
              <span><Database aria-hidden="true" />{t("database")}</span>
              <span><Gauge aria-hidden="true" />{t("quotas")}</span>
              <span><MapPin aria-hidden="true" />{t("regions")}</span>
            </>}
          </div>
        </section>
        <section aria-label={t("region")} className={styles.loginCard}>
          {firstLogin ? <PasswordChangeForm returnTo={returnTo} /> : <AccountLoginForm returnTo={returnTo} />}
          <p className={styles.securityNote}><ShieldCheck aria-hidden="true" /><span>{t(uxPreviewEnabled ? "previewSecurity" : "security")}</span></p>
        </section>
      </main>
      <footer className={styles.footer}><span>Matrix Cloud <span aria-hidden="true">/</span> {t("footer")}</span>
        {uxPreviewEnabled ? <span className={styles.environment}><span aria-hidden="true" />{t("previewNote")}</span> : null}
      </footer>
    </div>
  </App.Layer></App.Layers></App.Frame>;
}
