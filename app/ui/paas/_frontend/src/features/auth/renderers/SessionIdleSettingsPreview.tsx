"use client";

import { useId, useLayoutEffect, useRef, useState } from "react";
import { Clock3 } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, FormField, Select, Typography } from "@ui/xiak";
import styles from "./MfaPreviewExperience.module.css";

type Stage = "summary" | "edit" | "review";

const timeoutOptions = [5, 10, 15, 30, 45, 60] as const;

export function SessionIdleSettingsPreview() {
  const t = useTranslations("SessionIdlePreview");
  const selectId = useId();
  const [currentMinutes, setCurrentMinutes] = useState(30);
  const [draftMinutes, setDraftMinutes] = useState(30);
  const [stage, setStage] = useState<Stage>("summary");
  const [saved, setSaved] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const editorHeading = useRef<HTMLHeadingElement>(null);

  useLayoutEffect(() => {
    if (stage === "summary") heading.current?.focus({ preventScroll: true });
    else editorHeading.current?.focus({ preventScroll: true });
  }, [stage]);

  const beginEdit = () => {
    setSaved(false);
    setDraftMinutes(currentMinutes);
    setStage("edit");
  };

  return <section aria-labelledby="session-idle-policy" className={styles.section}>
    <div className={styles.sectionHeading}>
      <div>
        <p>{t("eyebrow")}</p>
        <h2 id="session-idle-policy" ref={heading} tabIndex={-1}>{t("title")}</h2>
        <span>{t("hint")}</span>
      </div>
      <div className={styles.headingBadges}>
        <Badge status="neutral">{t("minutes", { minutes: currentMinutes })}</Badge>
        <Badge status="warning">MOCK</Badge>
      </div>
    </div>

    {saved ? <Alert status="success">{t("saved", { minutes: currentMinutes })}</Alert> : null}

    {stage === "summary" ? <Card>
      <Card.Header><div className={styles.cardTitle}><span><Clock3 aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("cardTitle")}</Typography.Title><Typography.Text tone="muted">{t("cardHint")}</Typography.Text></div></div></Card.Header>
      <Card.Body className={styles.policyForm}>
        <dl className={styles.facts}>
          <div><dt>{t("current")}</dt><dd>{t("minutes", { minutes: currentMinutes })}</dd></div>
          <div><dt>{t("scope")}</dt><dd>{t("scopeValue")}</dd></div>
          <div><dt>{t("renewal")}</dt><dd>{t("renewalValue")}</dd></div>
          <div><dt>{t("notActivity")}</dt><dd>{t("notActivityValue")}</dd></div>
          <div><dt>{t("hardLimit")}</dt><dd>{t("hardLimitValue")}</dd></div>
        </dl>
        <Alert>{t("mockBoundary")}</Alert>
        <div className={styles.flowActions}><Button onClick={beginEdit}>{t("edit")}</Button></div>
      </Card.Body>
    </Card> : null}

    {stage === "edit" ? <Card className={styles.flowCard}>
      <Card.Header><div><h3 className={styles.flowTitle} ref={editorHeading} tabIndex={-1}>{t("editTitle")}</h3><Typography.Text tone="muted">{t("editHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header>
      <Card.Body className={styles.flowBody}>
        <FormField id={selectId} label={t("fieldLabel")} hint={t("fieldHint")}>
          <Select id={selectId} value={String(draftMinutes)} onValueChange={(value) => setDraftMinutes(Number(value))} options={timeoutOptions.map((minutes) => ({ value: String(minutes), label: t("minutes", { minutes }) }))} />
        </FormField>
        <Alert status="warning">{t("protectedCap")}</Alert>
        <div className={styles.flowActions}><Button variant="ghost" onClick={() => setStage("summary")}>{t("cancel")}</Button><Button disabled={draftMinutes === currentMinutes} onClick={() => setStage("review")}>{t("review")}</Button></div>
      </Card.Body>
    </Card> : null}

    {stage === "review" ? <Card className={styles.flowCard}>
      <Card.Header><div><h3 className={styles.flowTitle} ref={editorHeading} tabIndex={-1}>{t("reviewTitle")}</h3><Typography.Text tone="muted">{t("reviewHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header>
      <Card.Body className={styles.flowBody}>
        <dl className={styles.facts}>
          <div><dt>{t("change")}</dt><dd>{t("minutes", { minutes: currentMinutes })} → {t("minutes", { minutes: draftMinutes })}</dd></div>
          <div><dt>{t("scope")}</dt><dd>{t("scopeValue")}</dd></div>
          <div><dt>{t("effective")}</dt><dd>{t("effectiveValue")}</dd></div>
          <div><dt>{t("protectedIdentity")}</dt><dd>{draftMinutes > 30 ? t("protectedIdentityCapped") : t("protectedIdentitySame")}</dd></div>
        </dl>
        <Alert>{t("reviewBoundary")}</Alert>
        <div className={styles.flowActions}><Button variant="ghost" onClick={() => setStage("edit")}>{t("back")}</Button><Button onClick={() => { setCurrentMinutes(draftMinutes); setSaved(true); setStage("summary"); }}>{t("applyMock")}</Button></div>
      </Card.Body>
    </Card> : null}
  </section>;
}
