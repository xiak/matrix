"use client";

import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { KeyRound, Mail, RefreshCcw, ShieldCheck, Smartphone } from "lucide-react";
import { Badge, Button, Card, Input, Skeleton, Typography } from "@ui/xiak";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import { usePersonalSecurity } from "../application/PersonalSecurityProvider";
import type {
  AuthenticatorState,
  NotificationContact,
  NotificationContactVerification,
  TOTPEnrollmentStart
} from "../domain/personalSecurity";
import styles from "./PersonalSecuritySettings.module.css";

type LoadState = "loading" | "ready" | "error";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <label className={styles.field}><span>{label}</span>{children}</label>;
}

function localTime(value: string): string {
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(new Date(value));
}

function deliveryText(verification: NotificationContactVerification): string {
  switch (verification.delivery.state) {
    case "PENDING": return "验证邮件等待投递。";
    case "IN_FLIGHT": return "验证邮件正在投递。";
    case "RETRY_WAIT": return "邮件服务暂时不可用，系统将在限定次数内重试。";
    case "ACCEPTED": return "邮件服务器已接受投递；这不代表收件人已经读取。";
    case "FAILED": return "邮件投递失败，本次验证仍可在到期前核对。";
    case "EXPIRED": return "验证已过期，请刷新状态后重新开始。";
  }
}

function flowMessage(scope: "contact-start" | "contact-confirm" | "enrollment-start" | "enrollment-confirm" | "cancel", failure: unknown): string {
  if (failure instanceof HttpProblem) {
    if (failure.status === 401) return "登录会话已经失效，请重新登录。";
    if (failure.status === 409) return "安全状态已经变化，请刷新后重新操作。";
    if (failure.status === 422) {
      if (scope === "contact-confirm") return "邮箱验证码不正确或已失效。";
      if (scope === "enrollment-confirm") return "动态验证码不正确或已失效。";
      return "当前密码或提交内容未通过校验。";
    }
    if (failure.status === 429) return "尝试次数过多，请稍后重试。";
  }
  if (scope === "contact-start") return "无法确认验证邮件是否已创建，请刷新状态后再决定是否重试。";
  if (scope === "contact-confirm") return "无法确认邮箱验证结果，请刷新状态后核对。";
  if (scope === "enrollment-start") return "无法确认绑定是否已开始，系统将按原请求查询结果。";
  if (scope === "enrollment-confirm") return "无法确认绑定结果，请重新登录后核对，切勿重复提交。";
  return "无法确认取消结果，请刷新状态后核对。";
}

export function PersonalSecuritySettings() {
  const client = usePersonalSecurity();
  const requestRevision = useRef(0);
  const contactRequest = useRef(requestToken("ui-security-contact-"));
  const contactConfirmRequest = useRef(requestToken("ui-security-contact-confirm-"));
  const enrollmentRequest = useRef(requestToken("ui-totp-enroll-"));
  const enrollmentConfirmRequest = useRef(requestToken("ui-totp-confirm-"));
  const [loadState, setLoadState] = useState<LoadState>(client ? "loading" : "error");
  const [contact, setContact] = useState<NotificationContact | null>(null);
  const [verification, setVerification] = useState<NotificationContactVerification | null>(null);
  const [factor, setFactor] = useState<AuthenticatorState | null>(null);
  const [enrollment, setEnrollment] = useState<TOTPEnrollmentStart | null>(null);
  const [email, setEmail] = useState("");
  const [contactPassword, setContactPassword] = useState("");
  const [contactCode, setContactCode] = useState("");
  const [factorPassword, setFactorPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!client) return;
    const revision = ++requestRevision.current;
    setLoadState("loading");
    try {
      const [nextContact, nextFactor] = await Promise.all([
        client.notificationContact(),
        client.authenticatorState()
      ]);
      if (revision !== requestRevision.current) return;
      let nextVerification: NotificationContactVerification | null = null;
      if (nextContact.state === "NONE" && nextContact.pendingVerificationId) {
        nextVerification = await client.notificationVerification(nextContact.pendingVerificationId);
        if (revision !== requestRevision.current) return;
      }
      setContact(nextContact);
      setVerification(nextVerification?.state === "PENDING" ? nextVerification : null);
      setFactor(nextFactor);
      setError(null);
      setLoadState("ready");
    } catch {
      if (revision === requestRevision.current) {
        setContact(null);
        setVerification(null);
        setFactor(null);
        setError("无法读取当前安全设置；不会保留旧快照。请重试。");
        setLoadState("error");
      }
    }
  }, [client]);

  useEffect(() => {
    const timer = window.setTimeout(() => { void load(); }, 0);
    return () => {
      window.clearTimeout(timer);
      requestRevision.current += 1;
    };
  }, [load]);

  function rotateContactRequest() {
    contactRequest.current = requestToken("ui-security-contact-");
  }

  function rotateEnrollmentRequest() {
    enrollmentRequest.current = requestToken("ui-totp-enroll-");
  }

  async function startContact(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client) return;
    setBusy(true);
    setError(null);
    try {
      const next = await client.startNotificationVerification({
        email,
        password: contactPassword,
        requestId: contactRequest.current
      });
      setVerification(next);
      setContactPassword("");
      setContactCode("");
      contactConfirmRequest.current = requestToken("ui-security-contact-confirm-");
    } catch (failure) {
      setError(flowMessage("contact-start", failure));
    } finally {
      setBusy(false);
    }
  }

  async function confirmContact(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client || !verification) return;
    setBusy(true);
    setError(null);
    try {
      await client.confirmNotificationVerification(verification.id, {
        code: contactCode,
        requestId: contactConfirmRequest.current
      });
      setContactCode("");
      await load();
    } catch (failure) {
      setError(flowMessage("contact-confirm", failure));
    } finally {
      setBusy(false);
    }
  }

  async function startEnrollment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client || !factor) return;
    setBusy(true);
    setError(null);
    const requestId = enrollmentRequest.current;
    try {
      const next = await client.startTOTPEnrollment({
        requestId,
        password: factorPassword,
        expectedFactorRevision: factor.factorRevision
      });
      setEnrollment(next);
      setFactorPassword("");
      setTotpCode("");
      enrollmentConfirmRequest.current = requestToken("ui-totp-confirm-");
    } catch (failure) {
      if (!(failure instanceof HttpProblem) || failure.status >= 500) {
        try {
          const existing = await client.totpEnrollmentByRequest(requestId);
          setEnrollment({ outcome: "EQUAL_REPLAY", enrollment: existing });
          setFactorPassword("");
          setError("原请求已创建绑定意图，但一次性密钥不能再次读取。请取消该意图后重新开始；不要重复确认。");
          return;
        } catch {
          // Preserve the original result uncertainty; NOT_FOUND is not proof
          // that a delayed write can be safely replaced with another intent.
        }
      }
      setError(flowMessage("enrollment-start", failure));
    } finally {
      setBusy(false);
    }
  }

  async function cancelEnrollment() {
    if (!client || !enrollment) return;
    setBusy(true);
    setError(null);
    try {
      await client.cancelTOTPEnrollment(enrollment.enrollment.id);
      setEnrollment(null);
      setTotpCode("");
      enrollmentRequest.current = requestToken("ui-totp-enroll-");
      enrollmentConfirmRequest.current = requestToken("ui-totp-confirm-");
      await load();
    } catch (failure) {
      setError(flowMessage("cancel", failure));
    } finally {
      setBusy(false);
    }
  }

  async function confirmEnrollment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client || !enrollment || enrollment.outcome !== "APPLIED") return;
    setBusy(true);
    setError(null);
    try {
      await client.confirmTOTPEnrollment(enrollment.enrollment.id, {
        code: totpCode,
        requestId: enrollmentConfirmRequest.current
      });
    } catch (failure) {
      setError(flowMessage("enrollment-confirm", failure));
      setBusy(false);
    }
  }

  function restartEnrollment() {
    setEnrollment(null);
    setTotpCode("");
    setError(null);
    enrollmentRequest.current = requestToken("ui-totp-enroll-");
    enrollmentConfirmRequest.current = requestToken("ui-totp-confirm-");
  }

  const verified = contact?.state === "VERIFIED";

  return <section aria-labelledby="personal-security-title" className={styles.root}>
    <div className={styles.heading}>
      <div>
        <Typography.Title as="h2" id="personal-security-title" level={3}>账号安全</Typography.Title>
        <Typography.Text tone="muted">验证安全通知邮箱并绑定 TOTP 身份验证器</Typography.Text>
      </div>
      <Badge status="info">当前登录用户</Badge>
    </div>
    <p className={styles.notice}><ShieldCheck aria-hidden="true" />邮箱仅用于安全通知和恢复证明，不是登录名。身份验证器密钥与恢复码不会进入浏览器存储。</p>
    {error ? <p className={styles.error} role="alert">{error}</p> : null}
    {!client ? <p className={styles.error} role="alert">当前发布未提供个人安全设置接口。</p> : null}
    {loadState === "error" && client ? <Button onClick={() => void load()} size="small" variant="secondary"><RefreshCcw aria-hidden="true" />重新读取</Button> : null}
    <div className={styles.cards}>
      <Card>
        <Card.Header className={styles.cardHeader}>
          <div className={styles.cardTitle}><Mail aria-hidden="true" /><div><Typography.Title as="h3" level={3}>安全通知邮箱</Typography.Title><Typography.Text tone="muted">绑定身份验证器前必须完成验证</Typography.Text></div></div>
          {loadState === "ready" ? <Badge status={verified ? "success" : verification ? "warning" : "neutral"}>{verified ? "已验证" : verification ? "待验证" : "未设置"}</Badge> : null}
        </Card.Header>
        <Card.Body className={styles.body}>
          {loadState === "loading" ? <><Skeleton /><Skeleton /></> : null}
          {loadState === "ready" && contact?.state === "VERIFIED" ? <dl className={styles.facts}>
            <div><dt>邮箱</dt><dd>{contact.email}</dd></div>
            <div><dt>验证时间</dt><dd>{localTime(contact.verifiedAt)}</dd></div>
            <div><dt>资源版本</dt><dd>v{contact.resourceVersion}</dd></div>
          </dl> : null}
          {loadState === "ready" && contact?.state === "NONE" && !verification ? <form className={styles.form} onSubmit={startContact}>
            <p className={styles.note}>当前阶段仅支持首次设置，不提供在线替换邮箱。提交当前密码后，系统向该地址发送 8 位验证码。</p>
            <Field label="通知邮箱"><Input autoComplete="email" inputMode="email" maxLength={254} onChange={(event) => { setEmail(event.target.value); rotateContactRequest(); }} required type="email" value={email} /></Field>
            <Field label="验证当前密码"><Input autoComplete="current-password" maxLength={128} onChange={(event) => { setContactPassword(event.target.value); rotateContactRequest(); }} required type="password" value={contactPassword} /></Field>
            <div className={styles.actions}><Button disabled={busy || !email || !contactPassword} type="submit">{busy ? "正在提交…" : "发送验证邮件"}</Button></div>
          </form> : null}
          {loadState === "ready" && verification ? <form className={styles.form} onSubmit={confirmContact}>
            <p className={styles.notice}>{deliveryText(verification)}</p>
            <dl className={styles.facts}>
              <div><dt>目标邮箱</dt><dd>{verification.email}</dd></div>
              <div><dt>到期时间</dt><dd>{localTime(verification.expiresAt)}</dd></div>
              <div><dt>投递尝试</dt><dd>{verification.delivery.attempts}</dd></div>
            </dl>
            <Field label="8 位邮箱验证码"><Input autoComplete="one-time-code" inputMode="numeric" maxLength={8} onChange={(event) => setContactCode(event.target.value.replace(/\D/g, ""))} pattern="[0-9]{8}" required value={contactCode} /></Field>
            <div className={styles.actions}><Button disabled={busy || contactCode.length !== 8} type="submit">{busy ? "正在验证…" : "确认邮箱"}</Button><Button disabled={busy} onClick={() => void load()} type="button" variant="ghost"><RefreshCcw aria-hidden="true" />刷新投递状态</Button></div>
          </form> : null}
        </Card.Body>
      </Card>

      <Card>
        <Card.Header className={styles.cardHeader}>
          <div className={styles.cardTitle}><Smartphone aria-hidden="true" /><div><Typography.Title as="h3" level={3}>TOTP 身份验证器</Typography.Title><Typography.Text tone="muted">登录时使用 6 位动态验证码</Typography.Text></div></div>
          {loadState === "ready" && factor ? <Badge status={factor.enrollmentState === "BOUND" ? "success" : factor.enrollmentState === "RECOVERY_REQUIRED" ? "warning" : "neutral"}>{factor.enrollmentState === "BOUND" ? "已绑定" : factor.enrollmentState === "RECOVERY_REQUIRED" ? "需要恢复" : "未绑定"}</Badge> : null}
        </Card.Header>
        <Card.Body className={styles.body}>
          {loadState === "loading" ? <><Skeleton /><Skeleton /></> : null}
          {loadState === "ready" && factor && !enrollment ? <>
            <dl className={styles.facts}>
              <div><dt>方式</dt><dd>TOTP · 6 位</dd></div>
              <div><dt>因子版本</dt><dd>v{factor.factorRevision}</dd></div>
              {factor.factorId ? <div><dt>因子 ID</dt><dd><Typography.Code>{factor.factorId}</Typography.Code></dd></div> : null}
            </dl>
            {factor.enrollmentState === "NEVER_BOUND" && !verified ? <p className={styles.warning}>请先验证安全通知邮箱，再开始绑定身份验证器。</p> : null}
            {factor.enrollmentState === "NEVER_BOUND" && verified ? <form className={styles.form} onSubmit={startEnrollment}>
              <p className={styles.note}>验证当前密码后，密钥只展示一次。请保持页面开启，直到验证动态码并保存恢复码。</p>
              <Field label="绑定当前密码"><Input autoComplete="current-password" maxLength={128} onChange={(event) => { setFactorPassword(event.target.value); rotateEnrollmentRequest(); }} required type="password" value={factorPassword} /></Field>
              <div className={styles.actions}><Button disabled={busy || !factorPassword} type="submit"><KeyRound aria-hidden="true" />{busy ? "正在创建…" : "开始绑定"}</Button></div>
            </form> : null}
            {factor.enrollmentState === "BOUND" ? <p className={styles.success}>身份验证器已绑定。下一次登录将先完成 TOTP 验证，再创建会话。</p> : null}
            {factor.enrollmentState === "RECOVERY_REQUIRED" ? <p className={styles.warning}>原身份验证器已进入恢复状态。请使用受支持的身份恢复流程，不要建立第二条普通绑定。</p> : null}
          </> : null}
          {loadState === "ready" && enrollment ? <form className={styles.form} onSubmit={confirmEnrollment}>
            <p className={styles.warning}>{enrollment.outcome === "APPLIED" ? "下面的密钥只显示一次。不得截图上传或交给平台管理员。" : "这是已存在请求的等值重放；服务端不会再次披露密钥，也不能在此确认。请取消后重新开始。"}</p>
            {enrollment.outcome === "APPLIED" ? <div className={styles.secret}>
              <strong>手动输入密钥</strong>
              <Typography.Code>{enrollment.provisioning.seed}</Typography.Code>
              <span>在身份验证器应用中选择基于时间的一次性密码。Matrix 不加载外部二维码或第三方脚本。</span>
              <details><summary>显示标准配置 URI</summary><Typography.Code>{enrollment.provisioning.uri}</Typography.Code></details>
            </div> : null}
            <dl className={styles.facts}>
              <div><dt>绑定意图 ID</dt><dd><Typography.Code>{enrollment.enrollment.id}</Typography.Code></dd></div>
              <div><dt>到期时间</dt><dd>{localTime(enrollment.enrollment.expiresAt)}</dd></div>
            </dl>
            {enrollment.outcome === "APPLIED" ? <Field label="6 位动态验证码"><Input autoComplete="one-time-code" inputMode="numeric" maxLength={6} onChange={(event) => setTotpCode(event.target.value.replace(/\D/g, ""))} pattern="[0-9]{6}" required value={totpCode} /></Field> : null}
            <div className={styles.actions}>
              {enrollment.enrollment.state === "PENDING" ? <Button disabled={busy} onClick={() => void cancelEnrollment()} type="button" variant="ghost">取消绑定意图</Button> : <Button disabled={busy} onClick={restartEnrollment} type="button" variant="ghost">重新开始</Button>}
              {enrollment.outcome === "APPLIED" ? <Button disabled={busy || totpCode.length !== 6} type="submit">{busy ? "正在确认…" : "确认并生成恢复码"}</Button> : null}
            </div>
          </form> : null}
        </Card.Body>
      </Card>
    </div>
  </section>;
}
