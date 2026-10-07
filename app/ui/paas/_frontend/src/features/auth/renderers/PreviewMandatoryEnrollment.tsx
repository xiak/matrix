"use client";

import { useEffect, useId, useLayoutEffect, useRef, useState, type FormEvent } from "react";
import { useLocale, useTranslations } from "next-intl";
import { ArrowLeft, ArrowRight, CheckCircle2, ShieldCheck } from "lucide-react";
import { Alert, Button, Checkbox, FormField, Input } from "@ui/xiak";
import styles from "./LoginRenderer.module.css";

type Phase = "select" | "password" | "restart" | "contact" | "totp" | "codes" | "done" | "expired";
const demoSeed = "MTRXPREVIEWFIRSTFACTORNOTREAL";
const demoCodes = Array.from({ length: 10 }, (_, index) => `MTRX-FIRST-${String(index + 1).padStart(2, "0")}-DEMO`);
const demoCode = "624810";
const challengeLifetimeMs = 5 * 60_000;

/** Isolated DEV-only interaction prototype. No bearer, challenge credential,
 * enrollment request or recovery material reaches the IAM repository. */
export function PreviewMandatoryEnrollment({ onClose }: { onClose(): void }) {
  const t = useTranslations("EnrollmentPreview");
  const locale = useLocale();
  const id = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const [phase, setPhase] = useState<Phase>("select");
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [contact, setContact] = useState("preview@example.invalid");
  const [contactSent, setContactSent] = useState(false);
  const [contactCode, setContactCode] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState<"contactCode" | "totpCode" | null>(null);

  useLayoutEffect(() => { heading.current?.focus({ preventScroll: true }); }, [phase]);
  useEffect(() => {
    if (!expiresAt || !["password", "contact", "totp"].includes(phase)) return;
    const timer = window.setTimeout(() => {
      setContactCode(""); setTotpCode(""); setError(null); setPhase("expired");
    }, Math.max(0, expiresAt - Date.now()));
    return () => window.clearTimeout(timer);
  }, [expiresAt, phase]);

  const begin = (next: "password" | "totp") => {
    setExpiresAt(Date.now() + challengeLifetimeMs);
    setPhase(next);
  };
  const expireIfNeeded = () => {
    if (expiresAt !== null && Date.now() >= expiresAt) {
      setContactCode(""); setTotpCode(""); setError(null); setPhase("expired");
      return true;
    }
    return false;
  };
  const verifyContact = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (expireIfNeeded()) return;
    if (contactCode !== demoCode) { setError("contactCode"); return; }
    setError(null); setContactCode(""); setPhase("totp");
  };
  const verifyTotp = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (expireIfNeeded()) return;
    if (totpCode !== demoCode) { setError("totpCode"); return; }
    setError(null); setTotpCode(""); setPhase("codes");
  };
  const deadline = expiresAt === null ? null : new Intl.DateTimeFormat(locale, { hour: "2-digit", minute: "2-digit" }).format(new Date(expiresAt));

  return <div className={styles.previewEnrollment}>
    <div className={styles.cardHeading}>
      <span className={styles.challengeIcon}><ShieldCheck aria-hidden="true" /></span>
      <span className={styles.eyebrow}>{t("eyebrow")}</span>
      <h1 ref={heading} tabIndex={-1}>{t(`stages.${phase}.title`)}</h1>
      <p>{t(`stages.${phase}.hint`)}</p>
    </div>
    <div className={styles.challengeIdentity}><span>{t("identity")}</span><strong>preview-admin · org-xiak</strong></div>
    <Alert status="warning">{t("sessionBoundary")}</Alert>
    {deadline && ["password", "contact", "totp"].includes(phase) ? <p className={styles.previewChallengeHint}>{t("deadline", { time: deadline })}</p> : null}

    {phase === "select" ? <div className={styles.form}>
      <Button block onClick={() => begin("totp")}>{t("verifiedContactPath")}<ArrowRight aria-hidden="true" /></Button>
      <Button block variant="secondary" onClick={() => begin("password")}>{t("fullPath")}<ArrowRight aria-hidden="true" /></Button>
      <p className={styles.previewChallengeHint}>{t("selectBoundary")}</p>
    </div> : null}

    {phase === "password" ? <div className={styles.form}>
      <Alert status="info">{t("passwordBoundary")}</Alert>
      <Button block onClick={() => { if (expireIfNeeded()) return; setExpiresAt(null); setPhase("restart"); }}>{t("simulatePasswordChange")}<ArrowRight aria-hidden="true" /></Button>
    </div> : null}

    {phase === "restart" ? <div className={styles.form}>
      <Alert status="info">{t("restartBoundary")}</Alert>
      <Button block onClick={() => { setExpiresAt(Date.now() + challengeLifetimeMs); setPhase("contact"); }}>{t("simulateNewChallenge")}<ArrowRight aria-hidden="true" /></Button>
    </div> : null}

    {phase === "contact" ? <div className={styles.form}>
      <FormField id={id + "-email"} label={t("contactLabel")} hint={t("contactHint")}>
        <Input id={id + "-email"} type="email" value={contact} onChange={(event) => { setContact(event.target.value); setContactSent(false); setContactCode(""); }} />
      </FormField>
      <Button block variant="secondary" disabled={!contact.endsWith(".invalid") || contactSent} onClick={() => { if (!expireIfNeeded()) setContactSent(true); }}>{t(contactSent ? "contactSent" : "sendContactCode")}</Button>
      {contactSent ? <form className={styles.form} onSubmit={verifyContact}>
        <FormField id={id + "-contact-code"} label={t("contactCodeLabel")} hint={t("demoCodeHint")}>
          <Input id={id + "-contact-code"} autoComplete="one-time-code" inputMode="numeric" maxLength={6} value={contactCode} onChange={(event) => { setContactCode(event.target.value.replace(/\D/g, "")); setError(null); }} />
        </FormField>
        {error === "contactCode" ? <Alert status="danger">{t("invalidDemoCode")}</Alert> : null}
        <Button block disabled={contactCode.length !== 6} type="submit">{t("verifyContact")}<ArrowRight aria-hidden="true" /></Button>
      </form> : null}
      <p className={styles.previewChallengeHint}>{t("contactBoundary")}</p>
    </div> : null}

    {phase === "totp" ? <form className={styles.form} onSubmit={verifyTotp}>
      <Alert status="info">{t("totpBoundary")}</Alert>
      <div className={styles.recoverySecret}><div><span>{t("seedLabel")}</span><code>{demoSeed}</code></div></div>
      <FormField id={id + "-totp"} label={t("totpLabel")} hint={t("demoCodeHint")}>
        <Input id={id + "-totp"} autoComplete="one-time-code" inputMode="numeric" maxLength={6} value={totpCode} onChange={(event) => { setTotpCode(event.target.value.replace(/\D/g, "")); setError(null); }} />
      </FormField>
      {error === "totpCode" ? <Alert status="danger">{t("invalidDemoCode")}</Alert> : null}
      <Button block disabled={totpCode.length !== 6} type="submit">{t("confirmFactor")}<ArrowRight aria-hidden="true" /></Button>
    </form> : null}

    {phase === "codes" ? <div className={styles.form}>
      <Alert status="warning">{t("codesBoundary")}</Alert>
      <ul aria-label={t("codesLabel")} className={styles.previewCodeList}>{demoCodes.map((code) => <li key={code}><code>{code}</code></li>)}</ul>
      <Checkbox checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)}>{t("savedCodes")}</Checkbox>
      <Button block disabled={!acknowledged} onClick={() => { setAcknowledged(false); setPhase("done"); }}>{t("finishSetup")}<ArrowRight aria-hidden="true" /></Button>
    </div> : null}

    {phase === "done" ? <div className={styles.challengeCompletion}>
      <CheckCircle2 aria-hidden="true" />
      <Alert status="success">{t("doneBoundary")}</Alert>
      <Button block onClick={onClose}>{t("returnToSignIn")}<ArrowRight aria-hidden="true" /></Button>
    </div> : null}
    {phase === "expired" ? <Alert status="danger">{t("expiredBoundary")}</Alert> : null}
    {phase !== "done" ? <Button block variant="ghost" onClick={onClose}><ArrowLeft aria-hidden="true" />{t("returnToSignIn")}</Button> : null}
  </div>;
}
