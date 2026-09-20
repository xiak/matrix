"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, CheckCircle2, KeyRound, ShieldCheck } from "lucide-react";
import { Button, Input, Typography } from "@ui/xiak";
import { useSession } from "../application/SessionProvider";
import styles from "./LoginRenderer.module.css";

export function AuthenticationChallengeForm() {
  const router = useRouter();
  const session = useSession();
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmedPassword, setConfirmedPassword] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  if (session.phase === "reauthentication-required") {
    return <>
      <div className={styles.cardHeading}>
        <CheckCircle2 aria-hidden="true" />
        <Typography.Title as="h2" level={2}>请重新登录</Typography.Title>
        <Typography.Text tone="muted">
          密码可能已经更新，所有旧会话与登录挑战均不再可信。请回到登录页，用新密码重新认证。
        </Typography.Text>
      </div>
      {session.error ? <p className={styles.error} role="alert">{session.error}</p> : null}
      <Button block onClick={session.acknowledgeReauthentication} size="large">
        <ArrowLeft aria-hidden="true" />返回登录
      </Button>
    </>;
  }

  const pending = session.challenge;
  if (!pending) return null;
  const request = pending;
  const changingPassword = request.challenge.nextStep === "PASSWORD_CHANGE";
  const busy = session.phase === "verifying-challenge" || session.phase === "changing-challenge-password";
  const expiresAt = new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit" })
    .format(new Date(request.challenge.expiresAt));

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    if (busy || code.length !== 6) return;
    const outcome = await session.verifyAuthenticationChallenge(code);
    setCode("");
    if (outcome === "authenticated") {
      router.replace(request.loginName.includes("@") ? "/console/access/" : "/console/");
    }
  }

  async function changePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    if (newPassword !== confirmedPassword) {
      setFormError("两次输入的新密码不一致");
      return;
    }
    if (await session.changeChallengePassword(newPassword)) {
      setNewPassword("");
      setConfirmedPassword("");
    }
  }

  return <>
    <div className={styles.cardHeading}>
      <ShieldCheck aria-hidden="true" />
      <Typography.Eyebrow>正在登录 · {request.loginName}</Typography.Eyebrow>
      <Typography.Title as="h2" level={2}>
        {changingPassword ? "设置你的正式密码" : "输入身份验证器验证码"}
      </Typography.Title>
      <Typography.Text tone="muted">
        {changingPassword
          ? "密码与 TOTP 已验证。完成改密后仍需重新登录，不会直接获得会话。"
          : `此步骤不会创建会话；挑战预计在 ${expiresAt} 失效。`}
      </Typography.Text>
    </div>
    {changingPassword ? <form className={styles.form} onSubmit={changePassword}>
      <label className={styles.field}>
        <span>新密码</span>
        <Input aria-describedby="challenge-password-policy" autoComplete="new-password" disabled={busy}
          maxLength={128} minLength={14} onChange={(event) => { setNewPassword(event.target.value); setFormError(null); }}
          required type="password" value={newPassword} />
      </label>
      <label className={styles.field}>
        <span>确认新密码</span>
        <Input autoComplete="new-password" disabled={busy} maxLength={128} minLength={14}
          onChange={(event) => { setConfirmedPassword(event.target.value); setFormError(null); }}
          required type="password" value={confirmedPassword} />
      </label>
      <p className={styles.policy} id="challenge-password-policy">
        14–128 字节，不含空格，并至少包含大写字母、小写字母、数字、符号中的三类。
      </p>
      {formError || session.error ? <p className={styles.error} role="alert">{formError ?? session.error}</p> : null}
      <Button block disabled={busy || !newPassword || !confirmedPassword} size="large" type="submit">
        <KeyRound aria-hidden="true" />{busy ? "正在更新密码…" : "更新密码"}
      </Button>
    </form> : <form className={styles.form} onSubmit={verify}>
      <label className={styles.field}>
        <span>6 位验证码</span>
        <Input autoComplete="one-time-code" disabled={busy} inputMode="numeric" maxLength={6}
          onChange={(event) => { setCode(event.target.value.replace(/\D/g, "")); session.clearError(); }}
          pattern="[0-9]{6}" required value={code} />
      </label>
      <p className={styles.policy}>打开绑定的身份验证器应用，输入当前动态验证码。</p>
      {session.error ? <p className={styles.error} role="alert">{session.error}</p> : null}
      <Button block disabled={busy || code.length !== 6} size="large" type="submit">
        <ShieldCheck aria-hidden="true" />{busy ? "正在验证…" : "验证并继续"}
      </Button>
    </form>}
    <Button block disabled={busy} onClick={session.cancelAuthenticationChallenge} variant="ghost">
      <ArrowLeft aria-hidden="true" />取消并返回登录
    </Button>
  </>;
}
