"use client";
import { useTranslations } from "next-intl";
import { AlertCircle, CheckCircle2, LoaderCircle } from "lucide-react";
import { ApiError } from "@/api/client";
import styles from "./Workspace.module.css";

export function RequestFeedback({ error, busy, success }: { error?: unknown; busy?: boolean; success?: boolean }) {
  const errors = useTranslations("Errors");
  const t = useTranslations("Collection");
  if (error) return <div className={styles.feedback} data-tone="danger" role="alert"><AlertCircle aria-hidden="true" />{errors(error instanceof ApiError ? error.code : "NETWORK")}</div>;
  if (busy) return <div className={styles.feedback} role="status"><LoaderCircle className={styles.spin} aria-hidden="true" />{t("saving")}</div>;
  if (success) return <div className={styles.feedback} data-tone="success" role="status"><CheckCircle2 aria-hidden="true" />{t("success")}</div>;
  return null;
}
