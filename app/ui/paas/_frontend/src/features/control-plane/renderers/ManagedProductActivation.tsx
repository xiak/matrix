"use client";

import { useTranslations } from "next-intl";
import { Database, MessagesSquare, Search } from "lucide-react";
import { Alert, Badge, Button, FormField, Select } from "@ui/xiak";
import type { ReactNode } from "react";
import type { usePreviewServiceActivation } from "../application/previewServiceActivation";
import { previewActivationScenarios, type PreviewActivationScenario } from "../application/previewServiceActivation";
import type { useLiveServiceActivation } from "../application/liveServiceActivation";
import type { ManagedServiceProductId } from "../domain/managedServiceProduct";
import { ConsoleLink } from "../routes/ConsoleNavigation";
import { ServiceActivationGate } from "./ServiceActivationGate";
import styles from "./ServiceActivationGate.module.css";

export function ManagedProductActivation({ account, activation, children, preview, product }: {
  account: { id: string; name?: string };
  activation: ReturnType<typeof usePreviewServiceActivation> | ReturnType<typeof useLiveServiceActivation>;
  children: ReactNode;
  preview: boolean;
  product: ManagedServiceProductId;
}) {
  const t = useTranslations("ServiceActivation");
  const directory = useTranslations("ServiceDirectory");
  const Icon = product === "elasticsearch" ? Search : product === "rabbitmq" ? MessagesSquare : Database;
  const activationVersion = activation.state.status === "enabled"
    ? "enabledAt" in activation.state.activation ? activation.state.activation.enabledAt : activation.state.activation.activatedAt
    : "first-use";
  return <div className={styles.workspace}>
    {preview && activation.preview ? <details className={styles.preview}>
      <summary><Badge status="warning">MOCK</Badge> {t("previewControls")}</summary>
      <div className={styles.previewBody}>
        <FormField label={t("scenario")}><Select aria-label={t("scenario")} value={activation.scenario} options={previewActivationScenarios.map((value) => ({ value, label: t(`scenarios.${value}`) }))} onValueChange={(value) => activation.selectScenario(value as PreviewActivationScenario)} /></FormField>
        <FormField label={t("result")}><Select aria-label={t("result")} value={activation.simulateFailure ? "failure" : "success"} options={[{ value: "success", label: t("successResult") }, { value: "failure", label: t("failureResult") }]} onValueChange={(value) => activation.selectFailure(value === "failure")} /></FormField>
        <Button variant="ghost" onClick={activation.reset}>{t("reset")}</Button>
        <p className={styles.previewHint}>{t("previewHint")}</p>
      </div>
      {activation.resetFailed ? <Alert status="danger">{t("resetFailedHint")}</Alert> : null}
    </details> : null}
    <ServiceActivationGate
      key={JSON.stringify([account.id, product, activation.preview ? activation.scenario : "live", activationVersion])}
      account={account}
      service={{
        key: product,
        name: activation.definition?.displayName ?? directory(`services.${product}.name`),
        description: activation.definition?.description ?? directory(`services.${product}.description`),
        ...(activation.preview ? { noticeVersion: "mock-v1" } : {}),
        icon: <Icon aria-hidden="true" />
      }}
      state={activation.state}
      access={activation.access}
      consent={activation.preview ? t("mockConsent") : undefined}
      enableLabel={t(activation.preview ? "enableMock" : "enable")}
      retryLabel={t(activation.preview ? "retryMock" : "retry")}
      unavailableHint={t(preview ? "previewUnavailableHint" : "liveUnavailableHint")}
      failureHint={t(activation.preview ? "previewFailedHint" : "failedHint")}
      onEnable={() => void activation.enable()}
      requestAccess={<Button asChild variant="secondary"><ConsoleLink href="/console/access/">{t("openAccess")}</ConsoleLink></Button>}
    >{children}</ServiceActivationGate>
  </div>;
}
