"use client";

import { useId, useLayoutEffect, useRef, useState, type FormEvent } from "react";
import { useLocale, useTranslations } from "next-intl";
import { ArrowLeft, ArrowRight, LoaderCircle, ShieldCheck } from "lucide-react";
import { Alert, Button, FormField, Input } from "@ui/xiak";
import { useSession } from "../application/SessionProvider";
import styles from "./LoginRenderer.module.css";

/** A restricted first-factor ceremony. No Session or console route is available here. */
export function FirstEnrollmentForm() {
  const session = useSession();
  const t = useTranslations("FirstEnrollment");
  const errorText = useTranslations("Auth.errors");
  const locale = useLocale();
  const inputId = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const [email, setEmail] = useState("");
  const [contactCode, setContactCode] = useState("");
  const [factorCode, setFactorCode] = useState("");
  const challenge = session.challenge;
  const progress = session.firstEnrollment;
  const status = progress?.status ?? "INSPECTING";
  useLayoutEffect(() => { heading.current?.focus({ preventScroll: true }); }, [status]);
  if (!challenge || challenge.challenge.purpose !== "ENROLLMENT" || challenge.challenge.nextStep !== "ENROLLMENT") return null;
  const deadline = new Intl.DateTimeFormat(locale, { hour: "2-digit", minute: "2-digit" }).format(new Date(challenge.challenge.expiresAt));
  const busy = progress?.busy ?? false;

  async function startContact(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    await session.startFirstEnrollmentContact(email.trim());
  }
  async function confirmContact(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || contactCode.length !== 8) return;
    await session.confirmFirstEnrollmentContact(contactCode);
    setContactCode("");
  }
  async function confirmFactor(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || factorCode.length !== 6) return;
    await session.confirmFirstEnrollmentFactor(factorCode);
    setFactorCode("");
  }

  return <div aria-busy={busy || status === "INSPECTING"} className={styles.previewEnrollment}>
    <div className={styles.cardHeading}>
      <span className={styles.challengeIcon}><ShieldCheck aria-hidden="true" /></span>
      <h1 ref={heading} tabIndex={-1}>{t("title")}</h1>
      <p>{t("hint", { time: deadline })}</p>
    </div>
    <div className={styles.challengeIdentity}><span>{t("identity")}</span><strong>{challenge.loginName}</strong></div>
    <Alert status="warning">{t("boundary")}</Alert>

    {status === "INSPECTING" ? <p aria-live="polite" className={styles.previewChallengeHint}>
      <LoaderCircle aria-hidden="true" className={styles.spinner} /> {t("checking")}
    </p> : null}

    {status === "CONTACT_REQUIRED" ? <form className={styles.form} onSubmit={startContact}>
      <FormField id={`${inputId}-email`} label={t("contactLabel")} hint={t("contactHint")}>
        <Input autoComplete="email" disabled={busy} id={`${inputId}-email`} maxLength={254} onChange={(event) => { setEmail(event.target.value); session.clearError(); }}
          required type="email" value={email} />
      </FormField>
      {session.error ? <Alert status="danger">{errorText(session.error)}</Alert> : null}
      <Button block disabled={busy || !email.trim()} type="submit">{busy ? <LoaderCircle aria-hidden="true" className={styles.spinner} /> : null}{t("sendContactCode")}<ArrowRight aria-hidden="true" /></Button>
    </form> : null}

    {status === "CONTACT_PENDING" ? <form className={styles.form} onSubmit={confirmContact}>
      <Alert status="info">{t("contactSent", { email: progress?.verification?.email ?? "" })}</Alert>
      <FormField id={`${inputId}-contact-code`} label={t("contactCodeLabel")} hint={t("contactCodeHint")}>
        <Input autoComplete="one-time-code" disabled={busy} id={`${inputId}-contact-code`} inputMode="numeric" maxLength={8}
          onChange={(event) => { setContactCode(event.target.value.replace(/\D/g, "")); session.clearError(); }} pattern="[0-9]{8}" required value={contactCode} />
      </FormField>
      {session.error ? <Alert status="danger">{errorText(session.error)}</Alert> : null}
      <Button block disabled={busy || contactCode.length !== 8} type="submit">{busy ? <LoaderCircle aria-hidden="true" className={styles.spinner} /> : null}{t("verifyContact")}<ArrowRight aria-hidden="true" /></Button>
    </form> : null}

    {status === "TOTP_READY" ? <div className={styles.form}>
      <Alert status="success">{t("contactVerified")}</Alert>
      <p>{t("factorHint")}</p>
      <Button block disabled={busy} onClick={() => void session.startFirstEnrollmentFactor()}>{busy ? <LoaderCircle aria-hidden="true" className={styles.spinner} /> : null}{t("startFactor")}<ArrowRight aria-hidden="true" /></Button>
    </div> : null}

    {status === "TOTP_PENDING" && progress?.provisioning ? <form className={styles.form} onSubmit={confirmFactor}>
      <Alert status="warning">{t("seedBoundary")}</Alert>
      <div className={styles.recoverySecret}><div><span>{t("seedLabel")}</span><code>{progress.provisioning.seed}</code></div></div>
      <FormField id={`${inputId}-factor-code`} label={t("factorCodeLabel")} hint={t("factorCodeHint")}>
        <Input autoComplete="one-time-code" disabled={busy} id={`${inputId}-factor-code`} inputMode="numeric" maxLength={6}
          onChange={(event) => { setFactorCode(event.target.value.replace(/\D/g, "")); session.clearError(); }} pattern="[0-9]{6}" required value={factorCode} />
      </FormField>
      {session.error ? <Alert status="danger">{errorText(session.error)}</Alert> : null}
      <Button block disabled={busy || factorCode.length !== 6} type="submit">{busy ? <LoaderCircle aria-hidden="true" className={styles.spinner} /> : null}{t("confirmFactor")}<ArrowRight aria-hidden="true" /></Button>
    </form> : null}

    {status === "MATERIAL_LOST" || status === "OUTCOME_UNKNOWN" || status === "UNAVAILABLE" ?
      <Alert status="danger">{t(status === "MATERIAL_LOST" ? "materialLost" : status === "OUTCOME_UNKNOWN" ? "outcomeUnknown" : "unavailable")}</Alert> : null}

    <Button block disabled={busy} onClick={session.cancelAuthenticationChallenge} variant="ghost">
      <ArrowLeft aria-hidden="true" />{t("returnToSignIn")}
    </Button>
  </div>;
}
