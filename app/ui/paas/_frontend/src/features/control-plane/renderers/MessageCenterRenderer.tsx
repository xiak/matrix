"use client";

import { useTranslations } from "next-intl";
import { Bell } from "lucide-react";
import { Badge, Card, ContentPage, EmptyState } from "@ui/xiak";
import { useConsoleUiStore } from "../application/consoleUiStore";
import type { ConsoleContentScene } from "../scenes/consoleScene";
import { MessageInbox } from "./MessageInbox";

export function MessageCenterRenderer({ scene }: { scene: Extract<ConsoleContentScene, { kind: "messages" }> }) {
  const t = useTranslations("Notifications");
  const readIds = useConsoleUiStore((state) => state.readMessageIds);
  const unread = scene.messages.filter((message) => !readIds.includes(message.id)).length;
  if (!scene.preview) return <EmptyState icon={<Bell />} title={t("unavailable")} description={t("unavailableHint")} />;
  return <Card>
    <ContentPage.Heading title={t("title")} actions={<Badge status={unread ? "info" : "neutral"}>{t("count", { count: unread })}</Badge>} />
    <MessageInbox messages={scene.messages} />
  </Card>;
}
