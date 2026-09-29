"use client";

import { useId, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Card, Typography } from "@ui/xiak";
import styles from "./SessionExpiryPreview.module.css";

type Scenario = "explicit" | "polling" | "absolute";
const scenarios: Scenario[] = ["explicit", "polling", "absolute"];

export function SessionExpiryPreview() {
  const t = useTranslations("OwnSessions.idlePreview");
  const name = useId();
  const [scenario, setScenario] = useState<Scenario>("explicit");

  return <Card className={styles.root}>
    <Card.Header className={styles.heading}>
      <div><Typography.Title as="h2" level={3}>{t("title")}</Typography.Title><Typography.Text tone="muted">{t("hint")}</Typography.Text></div>
      <Badge status="neutral">MOCK</Badge>
    </Card.Header>
    <Card.Body className={styles.body}>
      <fieldset className={styles.scenarios}>
        <legend>{t("scenarioLabel")}</legend>
        <div className={styles.choices}>{scenarios.map((item) => <label className={`${styles.choice} ${scenario === item ? styles.selected : ""}`} key={item}>
          <input checked={scenario === item} name={name} onChange={() => setScenario(item)} type="radio" value={item} />
          <span><strong>{t(`${item}.label`)}</strong><small>{t(`${item}.hint`)}</small></span>
        </label>)}</div>
      </fieldset>
      <Alert status={scenario === "explicit" ? "info" : "warning"}>
        <div className={styles.outcome}><strong>{t(`${scenario}.outcome`)}</strong><span>{t(`${scenario}.result`)}</span></div>
      </Alert>
      <p className={styles.boundary}>{t("boundary")}</p>
    </Card.Body>
  </Card>;
}
