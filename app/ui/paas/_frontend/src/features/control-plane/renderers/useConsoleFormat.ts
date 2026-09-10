"use client";

import { useFormatter, useTranslations } from "next-intl";
import type { Region } from "../domain/resources";

// Scenes keep raw values; locale and missing-value copy belong to presentation.
export function useConsoleFormat() {
  const format = useFormatter();
  const t = useTranslations("ConsoleValues");
  return {
    number: format.number,
    timestamp(value: string | null) {
      if (!value) return t("notObserved");
      const date = new Date(value);
      if (Number.isNaN(date.valueOf())) return t("unknownTime");
      return format.dateTime(date, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZoneName: "short" });
    },
    duration(seconds: number) {
      const minutes = Math.floor(seconds / 60);
      const remainder = seconds % 60;
      return [minutes ? format.number(minutes, { style: "unit", unit: "minute", unitDisplay: "short" }) : null,
        format.number(remainder, { style: "unit", unit: "second", unitDisplay: "short" })].filter(Boolean).join(" ");
    },
    resources(value: Region["capacity"] | null) {
      if (!value) return t("resourcesUnavailable");
      return `${format.number(value.cpuMillicores / 1000)} vCPU · ${format.number(value.memoryMiB)} MiB · ${format.number(value.storageGiB)} GiB`;
    }
  };
}
