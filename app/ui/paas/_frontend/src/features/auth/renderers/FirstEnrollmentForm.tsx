"use client";

import { useId, useLayoutEffect, useRef, useState, type FormEvent } from "react";
import { ArrowLeft, KeyRound, ShieldCheck } from "lucide-react";
import { Button, Input, Typography } from "@ui/xiak";
import { useSession } from "../application/SessionProvider";
import styles from "./LoginRenderer.module.css";

/** The challenge credential remains in provider memory; this form cannot enter the console. */
export function FirstEnrollmentForm() {
  const session = useSession();
  const fieldId = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const [email, setEmail] = useState("");
  const [contactCode, setContactCode] = useState("");
  const [factorCode, setFactorCode] = useState("");
  const challenge = session.challenge;
  const progress = session.firstEnrollment;
  const status = progress?.status ?? "INSPECTING";
  const busy = progress?.busy ?? false;
  useLayoutEffect(() => { heading.current?.focus({ preventScroll: true }); }, [status]);
  if (!challenge || challenge.challenge.purpose !== "ENROLLMENT" || challenge.challenge.nextStep !== "ENROLLMENT") return null;
  const expiresAt = new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit" })
    .format(new Date(challenge.challenge.expiresAt));

  async function startContact(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!busy) await session.startFirstEnrollmentContact(email.trim());
  }
  async function confirmContact(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!busy && contactCode.length === 8) await session.confirmFirstEnrollmentContact(contactCode);
    setContactCode("");
  }
  async function confirmFactor(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!busy && factorCode.length === 6) await session.confirmFirstEnrollmentFactor(factorCode);
    setFactorCode("");
  }

  return <div aria-busy={busy || status === "INSPECTING"} className={styles.enrollment}>
    <div className={styles.cardHeading}>
      <ShieldCheck aria-hidden="true" />
      <Typography.Title as="h2" level={2}><span ref={heading} tabIndex={-1}>首次设置身份验证器</span></Typography.Title>
      <Typography.Text tone="muted">{challenge.loginName} · 请在 {expiresAt} 前完成。此过程不创建登录会话。</Typography.Text>
    </div>
    <p className={styles.policy}>先验证通知邮箱，再绑定身份验证器。验证码和密钥只在本页处理，不会成为登录凭据。</p>

    {status === "INSPECTING" ? <p aria-live="polite">正在核对首次安全设置状态…</p> : null}

    {status === "CONTACT_REQUIRED" ? <form className={styles.form} onSubmit={startContact}>
      <label className={styles.field} htmlFor={`${fieldId}-email`}><span>通知邮箱</span>
        <Input autoComplete="email" disabled={busy} id={`${fieldId}-email`} maxLength={254}
          onChange={(event) => { setEmail(event.target.value); session.clearError(); }} required type="email" value={email} />
      </label>
      <p className={styles.policy}>请使用你能接收验证码的邮箱；已验证的邮箱不会在这里被替换。</p>
      {session.error ? <p className={styles.error} role="alert">{session.error}</p> : null}
      <Button block disabled={busy || !email.trim()} size="large" type="submit">发送邮箱验证码</Button>
    </form> : null}

    {status === "CONTACT_PENDING" ? <form className={styles.form} onSubmit={confirmContact}>
      <p className={styles.policy}>验证码请求已受理，目标邮箱是 {progress?.verification?.email ?? "指定邮箱"}。请以实际收到的邮件为准。</p>
      <label className={styles.field} htmlFor={`${fieldId}-contact`}><span>8 位邮箱验证码</span>
        <Input autoComplete="one-time-code" disabled={busy} id={`${fieldId}-contact`} inputMode="numeric" maxLength={8}
          onChange={(event) => { setContactCode(event.target.value.replace(/\D/g, "")); session.clearError(); }} pattern="[0-9]{8}" required value={contactCode} />
      </label>
      {session.error ? <p className={styles.error} role="alert">{session.error}</p> : null}
      <Button block disabled={busy || contactCode.length !== 8} size="large" type="submit">验证邮箱</Button>
    </form> : null}

    {status === "TOTP_READY" ? <div className={styles.form}>
      <p>邮箱已验证。下一步将显示一次性的身份验证器密钥。</p>
      <Button block disabled={busy} onClick={() => void session.startFirstEnrollmentFactor()} size="large">
        <KeyRound aria-hidden="true" />开始绑定身份验证器
      </Button>
    </div> : null}

    {status === "TOTP_PENDING" && progress?.provisioning ? <form className={styles.form} onSubmit={confirmFactor}>
      <p className={styles.policy}>在身份验证器应用中手动输入下列密钥。离开页面后密钥不会重新显示。</p>
      <code className={styles.enrollmentSeed} aria-label="身份验证器密钥">{progress.provisioning.seed}</code>
      <label className={styles.field} htmlFor={`${fieldId}-factor`}><span>身份验证器 6 位动态验证码</span>
        <Input autoComplete="one-time-code" disabled={busy} id={`${fieldId}-factor`} inputMode="numeric" maxLength={6}
          onChange={(event) => { setFactorCode(event.target.value.replace(/\D/g, "")); session.clearError(); }} pattern="[0-9]{6}" required value={factorCode} />
      </label>
      {session.error ? <p className={styles.error} role="alert">{session.error}</p> : null}
      <Button block disabled={busy || factorCode.length !== 6} size="large" type="submit">确认绑定并查看恢复码</Button>
    </form> : null}

    {status === "MATERIAL_LOST" || status === "OUTCOME_UNKNOWN" || status === "UNAVAILABLE" ?
      <p className={styles.error} role="alert">{status === "MATERIAL_LOST"
        ? "一次性密钥已经发出，但无法再次显示。请重新登录核对，勿重复创建。"
        : status === "OUTCOME_UNKNOWN" ? "上一步结果不确定。请重新登录核对，勿重复提交。"
          : "安全设置暂不可用或挑战已失效，请重新登录。"}</p> : null}

    <Button block disabled={busy} onClick={session.cancelAuthenticationChallenge} variant="ghost">
      <ArrowLeft aria-hidden="true" />返回登录
    </Button>
  </div>;
}
