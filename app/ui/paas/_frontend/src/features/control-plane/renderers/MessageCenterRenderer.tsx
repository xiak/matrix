"use client";

import { useState } from "react";
import { ConsoleLink } from "../routes/ConsoleNavigation";
import { useTranslations } from "next-intl";
import { Bell } from "lucide-react";
import { Button, Card, ContentPage, EmptyState } from "@ui/xiak";
import { useConsoleUiStore } from "../application/consoleUiStore";
import type { ConsoleContentScene } from "../scenes/consoleScene";
import { MessageInbox } from "./MessageInbox";

export function MessageCenterRenderer({ scene }: { scene: Extract<ConsoleContentScene, { kind: "messages" }> }) {
  const t = useTranslations("Notifications");
  const readIds = useConsoleUiStore((state) => state.readMessageIds);
  const [visit, setVisit] = useState(0);
  const unread = scene.messages.filter((message) => !readIds.includes(message.id)).length;
  if (!scene.preview) return <EmptyState icon={<Bell />} title={t("unavailable")} description={t("unavailableHint")} />;
  return <Card>
    <ContentPage.Heading title={t("title")} actions={<Button asChild size="small" variant="ghost"><ConsoleLink href="/console/messages/?read=unread" onAccepted={() => setVisit((current) => current + 1)}>{t("count", { count: unread })}</ConsoleLink></Button>} />
    <MessageInbox key={visit} messages={scene.messages} />
  </Card>;
}
