import { useTranslations } from "next-intl";
import type { TableToolbarLabels } from "@ui/xiak";

export function useTableToolbarLabels(): TableToolbarLabels & { resetQuery: string } {
  const t = useTranslations("Collection");
  return { filters: t("filters"), clearSearch: t("clearSearch"), clearFilters: t("clearFilters"), resetQuery: t("resetQuery"), removeFilter: (label) => t("removeFilter", { label }) };
}
