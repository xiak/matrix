"use client";
import { useTranslations } from "next-intl";
import type { SourceConnectionSpec } from "@/api/devopsContract";
import { useSession } from "../auth/SessionProvider";
import styles from "../platform/Workspace.module.css";

export function safeCLIIdentity(value: string) { return /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value) ? value : "<reference>"; }
export function safeCLIOrigin(value: string) {
  if (!/^https:\/\/[a-z0-9.-]+(?::[1-9][0-9]{0,4})?$/.test(value)) return "<canonical-https-origin>";
  try { const url = new URL(value); if (url.origin !== value || url.hostname === "localhost" || url.hostname.endsWith(".localhost") || url.hostname.split(".").some(label => !label || label.length > 63 || label.startsWith("-") || label.endsWith("-"))) return "<canonical-https-origin>"; return value; } catch { return "<canonical-https-origin>"; }
}
export function SourceOperatorInstructions({ spec }: { spec: SourceConnectionSpec }) {
  const t = useTranslations("Devops"); const session = useSession()!;
  const tenant = safeCLIIdentity(session.organizationId);
  const commands = ([["WEBHOOK", spec.webhookSecretRef], ["FETCH", spec.fetchCredentialRef], ["REPORT", spec.reportCredentialRef]] as const).map(([purpose, reference]) => `mx devops source-credential apply --root <installation> --tenant ${tenant} --purpose ${purpose} --reference ${safeCLIIdentity(reference)} --from-file <private-file>`);
  commands.push(`mx devops source-trust apply --root <installation> --tenant ${tenant} --endpoint-origin ${safeCLIOrigin(spec.endpointOrigin)} --from-file <private-ca-file>`);
  return <details><summary>{t("operator")}</summary><div className={styles.stack}><p className={styles.muted}>{t("operatorHint")}</p><pre className={styles.code}>{commands.join("\n\n")}</pre></div></details>;
}
