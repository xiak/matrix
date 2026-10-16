"use client";

import { useTranslations } from "next-intl";
import { Button, EmptyState } from "@ui/xiak";
import { useAccountAccess } from "../application/AccountAccessProvider";
import type { AccountDirectoryKind } from "../scenes/accountAccessScene";

export function AccountDirectoryReadFailure({ kind, onRetry }: { kind: AccountDirectoryKind; onRetry?(): void }) {
  const t = useTranslations("AccountAccess.directoryReadFailure");
  const access = useAccountAccess();
  return <section aria-label={t(`titles.${kind}`)} role="alert"><EmptyState title={t(`titles.${kind}`)} description={t("hint")} action={<Button
    disabled={access.loading || access.busy} onClick={() => { onRetry?.(); void access.retryDirectory(kind); }} variant="secondary">
    {t(access.loading ? "loading" : "retry")}
  </Button>} /></section>;
}
