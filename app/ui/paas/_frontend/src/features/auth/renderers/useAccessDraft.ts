"use client";

import { useMemo, type RefObject } from "react";
import { useTranslations } from "next-intl";
import { useUnsavedChanges } from "@ui/xiak";

/** Shared leave interaction; IAM workflow fields remain owned by their individual renderers. */
export function useAccessDraft({ dirty, busy, title, description, form }: {
  dirty: boolean; busy: boolean; title: string; description: string; form: RefObject<HTMLFormElement | null>;
}) {
  const t = useTranslations("DraftNavigation");
  const copy = useMemo(() => ({ title, description, stay: t("stay"), leave: t("leave"), close: t("close"), busyTitle: t("busyTitle"), busyDescription: t("busyDescription"), failure: t("failure"), retry: t("retry") }), [title, description, t]);
  return useUnsavedChanges({ dirty, busy, copy, focusRef: form });
}
