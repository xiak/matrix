"use client";
import { useTranslations } from "next-intl";
import type { Operation } from "@/api/paasContract";
import { Badge, Card } from "@ui/xiak";
import { ResourceFacts } from "../resources/ResourceFacts";
import styles from "../platform/Workspace.module.css";
export function OperationSummary({ operation }: { operation: Operation }) {
  const t = useTranslations("Paas");
  const c = useTranslations("Collection");
  return <Card><Card.Body className={styles.stack}><strong>{t("requestAccepted")}</strong><ResourceFacts rows={[[t("operationId"), operation.id], [c("state"), <Badge key="state" status={operation.state === "SUCCEEDED" ? "success" : operation.state === "FAILED" ? "danger" : "info"}>{operation.state}</Badge>], [c("id"), operation.target.id], [c("updated"), operation.updatedAt]]} />{operation.error ? <p className={styles.muted}>{operation.error.code}</p> : null}</Card.Body></Card>;
}
