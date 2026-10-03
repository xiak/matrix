"use client";

import { useLayoutEffect, useRef, useState } from "react";
import { Fingerprint } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, Typography } from "@ui/xiak";
import styles from "./MfaPreviewExperience.module.css";

type Stage = "summary" | "flow" | "review";
const previewStates = [
  { key: "notConfigured", status: "neutral" },
  { key: "configuredUnavailable", status: "warning" },
  { key: "availableRestricted", status: "info" }
] as const;

export function PasskeyConceptPreview() {
  const t = useTranslations("PasskeyPreview");
  const [stage, setStage] = useState<Stage>("summary");
  const sectionHeading = useRef<HTMLHeadingElement>(null);
  const flowHeading = useRef<HTMLHeadingElement>(null);
  const interacted = useRef(false);

  useLayoutEffect(() => {
    if (!interacted.current) return;
    (stage === "summary" ? sectionHeading : flowHeading).current?.focus({ preventScroll: true });
  }, [stage]);

  const moveTo = (next: Stage) => {
    interacted.current = true;
    setStage(next);
  };

  return <section aria-labelledby="passkey-concept" className={styles.section}>
    <div className={styles.sectionHeading}>
      <div>
        <p>{t("eyebrow")}</p>
        <h2 id="passkey-concept" ref={sectionHeading} tabIndex={-1}>{t("title")}</h2>
        <span>{t("hint")}</span>
      </div>
      <div className={styles.headingBadges}><Badge status="neutral">{t("concept")}</Badge><Badge status="warning">MOCK</Badge></div>
    </div>

    {stage === "summary" ? <Card>
      <Card.Header><div className={styles.cardTitle}><span><Fingerprint aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("cardTitle")}</Typography.Title><Typography.Text tone="muted">{t("cardHint")}</Typography.Text></div></div></Card.Header>
      <Card.Body className={styles.cardBody}>
        <dl className={styles.facts}>
          <div><dt>{t("protocol")}</dt><dd>{t("protocolValue")}</dd></div>
          <div><dt>{t("privateKey")}</dt><dd>{t("privateKeyValue")}</dd></div>
          <div><dt>{t("scope")}</dt><dd>{t("scopeValue")}</dd></div>
          <div><dt>{t("state")}</dt><dd>{t("notConnected")}</dd></div>
          <div><dt>{t("deviceDirectory")}</dt><dd>{t("deviceDirectoryValue")}</dd></div>
        </dl>
        <section aria-labelledby="passkey-state-guide" className={styles.stateGuide}>
          <div><h4 id="passkey-state-guide">{t("stateGuide.title")}</h4><p>{t("stateGuide.hint")}</p></div>
          <ul>{previewStates.map(({ key, status }) => <li key={key}><Badge status={status}>{t(`stateGuide.${key}.label`)}</Badge><span>{t(`stateGuide.${key}.description`)}</span></li>)}</ul>
        </section>
        <Alert>{t("boundary")}</Alert>
        <div className={styles.actions}><Button onClick={() => moveTo("flow")}>{t("explore")}</Button></div>
      </Card.Body>
    </Card> : null}

    {stage === "flow" ? <Card className={styles.flowCard}>
      <Card.Header><div><h3 className={styles.flowTitle} ref={flowHeading} tabIndex={-1}>{t("flowTitle")}</h3><Typography.Text tone="muted">{t("flowHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header>
      <Card.Body className={styles.flowBody}>
        <ol className={styles.ageFlow}>
          <li>{t("steps.reauthenticate")}</li>
          <li>{t("steps.challenge")}</li>
          <li>{t("steps.ceremony")}</li>
          <li>{t("steps.verify")}</li>
        </ol>
        <Alert status="warning">{t("noCeremony")}</Alert>
        <div className={styles.flowActions}><Button variant="ghost" onClick={() => moveTo("summary")}>{t("cancel")}</Button><Button onClick={() => moveTo("review")}>{t("review")}</Button></div>
      </Card.Body>
    </Card> : null}

    {stage === "review" ? <Card className={styles.flowCard}>
      <Card.Header><div><h3 className={styles.flowTitle} ref={flowHeading} tabIndex={-1}>{t("reviewTitle")}</h3><Typography.Text tone="muted">{t("reviewHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header>
      <Card.Body className={styles.flowBody}>
        <dl className={styles.facts}>
          <div><dt>{t("browserBoundary")}</dt><dd>{t("browserBoundaryValue")}</dd></div>
          <div><dt>{t("relyingParty")}</dt><dd>{t("relyingPartyValue")}</dd></div>
          <div><dt>{t("operationProof")}</dt><dd>{t("operationProofValue")}</dd></div>
          <div><dt>{t("sessionBoundary")}</dt><dd>{t("sessionBoundaryValue")}</dd></div>
          <div><dt>{t("riskHandling")}</dt><dd>{t("riskHandlingValue")}</dd></div>
          <div><dt>{t("failure")}</dt><dd>{t("failureValue")}</dd></div>
          <div><dt>{t("recovery")}</dt><dd>{t("recoveryValue")}</dd></div>
          <div><dt>{t("rollout")}</dt><dd>{t("rolloutValue")}</dd></div>
        </dl>
        <Alert>{t("reviewBoundary")}</Alert>
        <div className={styles.flowActions}><Button variant="ghost" onClick={() => moveTo("flow")}>{t("back")}</Button><Button onClick={() => moveTo("summary")}>{t("done")}</Button></div>
      </Card.Body>
    </Card> : null}
  </section>;
}
