"use client";

import { useId, useMemo, type ReactNode } from "react";
import { useTranslations } from "next-intl";
import qrcode from "qrcode-generator";
import type { TOTPProvisioning } from "../domain/session";
import styles from "./AuthenticatorSetupMaterial.module.css";

/** Presentation only: the calling ceremony owns eligibility and one-time custody. */
export function AuthenticatorSetupMaterial({ provisioning, copyAction }: { provisioning: TOTPProvisioning; copyAction?: ReactNode }) {
  const t = useTranslations("AuthenticatorSetup");
  const hintId = useId();
  const symbol = useMemo(() => {
    try {
      const uriBytes = new TextEncoder().encode(provisioning.uri);
      // The wire permits longer material than a useful on-screen QR. Keep
      // oversized inputs on the manual path without running the encoder.
      if (uriBytes.length > 1024) return null;
      const setup = new URL(provisioning.uri);
      if (setup.protocol !== "otpauth:" || setup.hostname !== "totp" || setup.username || setup.password || setup.port || setup.hash ||
          !/^[A-Z2-7]+$/i.test(provisioning.seed) || setup.searchParams.getAll("secret").length !== 1 ||
          setup.searchParams.get("secret") !== provisioning.seed) return null;
      const qr = qrcode(0, "M");
      // The encoder's Byte mode takes a binary string. Preserve UTF-8 bytes
      // without changing its global encoding function or canonicalizing the URI.
      qr.addData(String.fromCharCode(...uriBytes), "Byte");
      qr.make();
      const count = qr.getModuleCount();
      const runs: string[] = [];
      for (let row = 0; row < count; row++) {
        for (let column = 0; column < count;) {
          if (!qr.isDark(row, column)) { column++; continue; }
          const start = column;
          while (column < count && qr.isDark(row, column)) column++;
          const width = column - start;
          runs.push(`M${start + 4} ${row + 4}h${width}v1h-${width}z`);
        }
      }
      return { size: count + 8, path: runs.join("") };
    } catch {
      // Do not expose encoder errors or lose the independently usable manual key.
      return null;
    }
  }, [provisioning.uri, provisioning.seed]);

  return <div className={styles.material}>
    <div className={styles.methods}>
      {symbol ? <figure className={styles.scan}>
        <figcaption>{t("scan")}</figcaption>
        <svg aria-describedby={hintId} aria-label={t("qrLabel")} className={styles.symbol} role="img"
          shapeRendering="crispEdges" viewBox={`0 0 ${symbol.size} ${symbol.size}`}>
          <rect className={styles.paper} height={symbol.size} width={symbol.size} />
          <path d={symbol.path} />
        </svg>
      </figure> : null}
      <div className={styles.manual}>
        <strong>{t("manual")}</strong>
        <code>{provisioning.seed}</code>
        {copyAction}
        <p>{t("manualHint")}</p>
        <details><summary>{t("uri")}</summary><code>{provisioning.uri}</code></details>
      </div>
    </div>
    {!symbol ? <p className={styles.note} role="status">{t("qrUnavailable")}</p> : null}
    <p className={styles.note} id={hintId}>{t("private")}</p>
  </div>;
}
