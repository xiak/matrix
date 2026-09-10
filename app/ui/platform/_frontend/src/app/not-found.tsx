"use client";
import { useTranslations } from "next-intl";
import { Button, EmptyState } from "@ui/xiak";
import { PlatformLink } from "@/features/platform/Navigation";
export default function NotFound() { const t = useTranslations("Platform"); return <EmptyState title={t("notFound")} description={t("notFoundHint")} action={<Button asChild><PlatformLink href="/">{t("home")}</PlatformLink></Button>} />; }
