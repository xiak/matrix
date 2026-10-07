"use client";

import { useTranslations } from "next-intl";
import { ArrowRight, Braces, ListFilter, SlidersHorizontal, Tags } from "lucide-react";
import { Button } from "@ui/xiak";
import { WorkspaceDetail } from "./AccessWorkspaceUi";
import styles from "./PolicyAuthoringWizard.module.css";

export const policyCreationMethods = ["visual", "json", "tags", "features"] as const;
export type PolicyCreationMethod = typeof policyCreationMethods[number];
export function policyCreationMethod(value?: string): PolicyCreationMethod {
  return policyCreationMethods.find((method) => method === value) ?? "visual";
}
const icons = { visual: ListFilter, json: Braces, tags: Tags, features: SlidersHorizontal };

/** Entry selection only. Every method opens the same content-area draft owner. */
export function PolicyCreationMethods({ onSelect, onClose }: { onSelect(method: PolicyCreationMethod): void; onClose(): void }) {
  const t = useTranslations("PolicyWizard");
  return <WorkspaceDetail title={t("chooseMethod")} onBack={onClose}>
    <p className={styles.note}>{t("chooseMethodHint")}</p>
    <div className={styles.methodGrid}>
      {policyCreationMethods.map((method) => {
        const Icon = icons[method];
        return <Button key={method} variant="secondary" className={styles.methodCard} onClick={() => onSelect(method)}>
          <Icon aria-hidden="true" /><span><strong>{t(`methods.${method}.title`)}</strong><span>{t(`methods.${method}.description`)}</span></span><ArrowRight aria-hidden="true" />
        </Button>;
      })}
    </div>
  </WorkspaceDetail>;
}
