"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { useTranslations } from "next-intl";
import { Alert, Button, Card, Checkbox, Dialog, Typography } from "@ui/xiak";
import { isChunkLoadFailure, reloadDocumentOnce } from "@/infrastructure/runtime/applicationLoadRecovery";
import styles from "./ApplicationLoadRecovery.module.css";

const RecoveryContext = createContext<((error: unknown) => boolean) | null>(null);
const reloadPage = () => reloadDocumentOnce(document);

/** Own only the failure signal and consent; keep sessions, drafts and secrets in their existing owners. */
export function ApplicationLoadRecovery({ children, reloadDocument = reloadPage }: { children: ReactNode; reloadDocument?(): void }) {
  const t = useTranslations("ApplicationRecovery");
  const detected = useRef(false);
  const requested = useRef(false);
  const reopen = useRef<HTMLButtonElement>(null);
  const [failed, setFailed] = useState(false);
  const [open, setOpen] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [reloading, setReloading] = useState(false);
  const [reloadFailed, setReloadFailed] = useState(false);
  const report = useCallback((error: unknown) => {
    if (!isChunkLoadFailure(error, window.location.origin)) return false;
    if (!detected.current) {
      detected.current = true;
      setFailed(true); setOpen(true);
    }
    return true;
  }, []);
  useEffect(() => {
    const rejected = (event: PromiseRejectionEvent) => { if (report(event.reason)) event.preventDefault(); };
    const failedScript = (event: ErrorEvent) => { if (report(event.error)) event.preventDefault(); };
    window.addEventListener("unhandledrejection", rejected);
    window.addEventListener("error", failedScript);
    return () => {
      window.removeEventListener("unhandledrejection", rejected);
      window.removeEventListener("error", failedScript);
    };
  }, [report]);

  function refresh() {
    if (!acknowledged || requested.current) return;
    requested.current = true; setReloading(true);
    try { reloadDocument(); } catch { setReloadFailed(true); }
  }
  return <RecoveryContext.Provider value={report}>
    {children}
    {failed ? <aside aria-label={t("title")} className={styles.notice}>
      <Alert status="warning">{t("notice")} <Button ref={reopen} size="small" variant="secondary" onClick={() => { setAcknowledged(false); setOpen(true); }}>{t("review")}</Button></Alert>
      <Dialog open={open} title={t("title")} closeLabel={t("close")} onClose={() => setOpen(false)} fallbackFocusRef={reopen}
        footer={<><Button onClick={() => setOpen(false)} variant="secondary">{t("stay")}</Button><Button disabled={!acknowledged || reloading} onClick={refresh}>{t(reloading ? "requested" : "reload")}</Button></>}>
        <div className={styles.content}>
          <p>{t("cause")}</p>
          <Alert status="warning">{t("sensitive")}</Alert>
          <p>{t("unknown")}</p>
          <Checkbox checked={acknowledged} disabled={reloading} onChange={(event) => setAcknowledged(event.target.checked)}>{t("acknowledge")}</Checkbox>
          {reloading ? <p role="status">{t("requestedHint")}</p> : null}
          {reloadFailed ? <Alert status="warning">{t("reloadFailed")}</Alert> : null}
        </div>
      </Dialog>
    </aside> : null}
  </RecoveryContext.Provider>;
}

/** Next's route boundary reports the same known failure; ordinary render errors only offer local reset. */
export function ApplicationRouteError({ error, reset }: { error: Error; reset(): void }) {
  const t = useTranslations("ApplicationRecovery");
  const report = useContext(RecoveryContext);
  const chunk = isChunkLoadFailure(error, typeof window === "undefined" ? "https://matrix.invalid" : window.location.origin);
  useEffect(() => { if (chunk) report?.(error); }, [chunk, error, report]);
  if (chunk && report) return null;
  return <main className={styles.fallback}>
    <Card><Card.Header><Typography.Title as="h1">{t("errorTitle")}</Typography.Title></Card.Header>
      <Card.Body><p>{t("errorHint")}</p><p>{t("unknown")}</p></Card.Body>
      <Card.Footer><Button onClick={reset} variant="secondary">{t("reset")}</Button></Card.Footer>
    </Card>
  </main>;
}
