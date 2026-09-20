"use client";

import { useEffect, useId, useLayoutEffect, useRef, useState, type FormEvent } from "react";
import { Mail } from "lucide-react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, FormField, Input, PasswordInput, Typography } from "@ui/xiak";
import styles from "./MfaPreviewExperience.module.css";

const demonstrationCode = "48392017";
const demonstrationPassword = "demo-password";
const contactSteps = ["address", "verify", "complete"] as const;

type ContactStage = "summary" | "address" | "verify";
type FocusTarget = "trigger" | "summary" | null;

function validAddress(value: string): boolean {
  const parts = value.split("@");
  if (parts.length !== 2) return false;
  const [local, domain] = parts;
  if (!local || local.length > 64 || !/^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/.test(local)) return false;
  return Boolean(domain && domain.length <= 253 && domain.includes(".") && domain.split(".").every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label)));
}

function ContactProgress({ current }: { current: number }) {
  const t = useTranslations("SecurityNotificationPreview");
  return <ol aria-label={t("progress")} className={styles.contactSteps}>
    {contactSteps.map((step, index) => <li aria-current={current === index ? "step" : undefined} data-active={index <= current ? "true" : undefined} key={step}>
      <span>{index + 1}</span><small>{t(`steps.${step}`)}</small>
    </li>)}
  </ol>;
}

export function SecurityNotificationAddressPreview() {
  const t = useTranslations("SecurityNotificationPreview");
  const auth = useTranslations("Auth");
  const [stage, setStage] = useState<ContactStage>("summary");
  const [address, setAddress] = useState("");
  const [password, setPassword] = useState("");
  const [pendingAddress, setPendingAddress] = useState<string | null>(null);
  const [verifiedAddress, setVerifiedAddress] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<"credentials" | "code" | null>(null);
  const [completed, setCompleted] = useState(false);
  const addressId = useId();
  const passwordId = useId();
  const codeId = useId();
  const trigger = useRef<HTMLButtonElement>(null);
  const summaryHeading = useRef<HTMLHeadingElement>(null);
  const flowHeading = useRef<HTMLHeadingElement>(null);
  const focusTarget = useRef<FocusTarget>(null);

  useEffect(() => {
    if (stage !== "summary") flowHeading.current?.focus();
  }, [stage]);
  useLayoutEffect(() => {
    if (stage !== "summary" || !focusTarget.current) return;
    const target = focusTarget.current;
    focusTarget.current = null;
    if (target === "summary") summaryHeading.current?.focus();
    else trigger.current?.focus();
  }, [stage]);

  const begin = () => {
    setCompleted(false);
    setError(null);
    setCode("");
    setStage(pendingAddress ? "verify" : "address");
  };
  const close = () => {
    focusTarget.current = "trigger";
    setError(null);
    setStage("summary");
  };
  const prepare = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const candidate = address.trim();
    if (!validAddress(candidate) || password !== demonstrationPassword) {
      setError("credentials");
      return;
    }
    setPendingAddress(candidate);
    setAddress(candidate);
    setPassword("");
    setCode("");
    setError(null);
    setStage("verify");
  };
  const confirm = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (code !== demonstrationCode || !pendingAddress) {
      setError("code");
      return;
    }
    setVerifiedAddress(pendingAddress);
    setPendingAddress(null);
    setCode("");
    setError(null);
    setCompleted(true);
    focusTarget.current = "summary";
    setStage("summary");
  };

  if (stage === "address") return <Card className={styles.flowCard}>
    <Card.Header><div><h2 className={styles.flowTitle} ref={flowHeading} tabIndex={-1}>{t("flowTitle")}</h2><Typography.Text tone="muted">{t("flowHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header>
    <Card.Body className={styles.flowBody}>
      <ContactProgress current={0} />
      <Alert status="warning">{t("mockBoundary")}</Alert>
      <form className={styles.form} onSubmit={prepare}>
        <FormField id={addressId} label={t("emailLabel")} hint={t("emailHint")}><Input autoComplete="email" id={addressId} onChange={(event) => { setAddress(event.target.value); setError(null); }} required value={address} /></FormField>
        <FormField id={passwordId} label={t("currentPassword")}><PasswordInput autoComplete="current-password" capsLockLabel={auth("capsLock")} hideLabel={auth("hidePassword")} id={passwordId} onChange={(event) => { setPassword(event.target.value); setError(null); }} showLabel={auth("showPassword")} value={password} /></FormField>
        <Alert>{t("demoPassword", { password: demonstrationPassword })}</Alert>
        {error === "credentials" ? <Alert status="danger">{t("invalidCredentials")}</Alert> : null}
        <p className={styles.boundary}><Mail aria-hidden="true" />{t("flowBoundary")}</p>
        <div className={styles.flowActions}><Button onClick={close} type="button" variant="ghost">{t("cancel")}</Button><Button disabled={!address.trim() || !password} type="submit">{t("createIntent")}</Button></div>
      </form>
    </Card.Body>
  </Card>;

  if (stage === "verify" && pendingAddress) return <Card className={styles.flowCard}>
    <Card.Header><div><h2 className={styles.flowTitle} ref={flowHeading} tabIndex={-1}>{t("verifyTitle")}</h2><Typography.Text tone="muted">{t("verifyHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header>
    <Card.Body className={styles.flowBody}>
      <ContactProgress current={1} />
      <dl className={styles.facts}>
        <div><dt>{t("address")}</dt><dd>{pendingAddress}</dd></div>
        <div><dt>{t("deliveryState")}</dt><dd><Badge status="success">{t("states.ACCEPTED")}</Badge></dd></div>
        <div><dt>{t("expires")}</dt><dd>{t("expiresValue")}</dd></div>
      </dl>
      <Alert status="warning">{t("acceptedBoundary")}</Alert>
      <Alert>{t("demoCode", { code: demonstrationCode })}</Alert>
      <form className={styles.form} onSubmit={confirm}>
        <FormField id={codeId} label={t("codeLabel")} hint={t("codeHint")}><Input autoComplete="one-time-code" id={codeId} inputMode="numeric" maxLength={8} onChange={(event) => { setCode(event.target.value.replace(/\D/g, "")); setError(null); }} pattern="[0-9]{8}" required value={code} /></FormField>
        {error === "code" ? <Alert status="danger">{t("invalidCode")}</Alert> : null}
        <p className={styles.boundary}><Mail aria-hidden="true" />{t("stateVocabulary")}</p>
        <div className={styles.flowActions}><Button onClick={close} type="button" variant="ghost">{t("closeForNow")}</Button><Button disabled={code.length !== 8} type="submit">{t("confirm")}</Button></div>
      </form>
    </Card.Body>
  </Card>;

  const state = verifiedAddress ? "VERIFIED" : pendingAddress ? "PENDING" : "NONE";
  return <section aria-labelledby="security-notification-address" className={styles.section}>
    <div className={styles.sectionHeading}><div><p>{t("eyebrow")}</p><h2 id="security-notification-address" ref={summaryHeading} tabIndex={-1}>{t("title")}</h2><span>{t("hint")}</span></div><Badge status={verifiedAddress ? "success" : pendingAddress ? "warning" : "neutral"}>{t(`states.${state}`)}</Badge></div>
    {completed ? <Alert status="success">{t("completed")}</Alert> : null}
    <Card><Card.Header><div className={styles.cardTitle}><span><Mail aria-hidden="true" /></span><div><Typography.Title as="h3" level={3}>{t("cardTitle")}</Typography.Title><Typography.Text tone="muted">{t("cardHint")}</Typography.Text></div></div></Card.Header><Card.Body className={styles.cardBody}>
      <dl className={styles.facts}>
        <div><dt>{t("address")}</dt><dd>{verifiedAddress ?? pendingAddress ?? t("notConfigured")}</dd></div>
        <div><dt>{t("state")}</dt><dd>{t(`states.${state}`)}</dd></div>
        <div><dt>{t("purpose")}</dt><dd>{t("purposeValue")}</dd></div>
        <div><dt>{t("owner")}</dt><dd>{t("ownerValue")}</dd></div>
        {pendingAddress ? <div><dt>{t("deliveryState")}</dt><dd>{t("states.ACCEPTED")}</dd></div> : null}
      </dl>
      {verifiedAddress ? <Alert>{t("firstSliceBoundary")}</Alert> : <div className={styles.actions}><Button ref={trigger} onClick={begin}>{t(pendingAddress ? "resume" : "start")}</Button></div>}
    </Card.Body></Card>
  </section>;
}
