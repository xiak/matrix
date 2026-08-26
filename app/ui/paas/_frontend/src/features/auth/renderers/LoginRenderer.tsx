"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Boxes, KeyRound, LockKeyhole, Network, ShieldCheck } from "lucide-react";
import { App, Button, Input, Typography } from "@ui/xiak";
import { useSession } from "../application/SessionProvider";
import styles from "./LoginRenderer.module.css";

export function LoginRenderer() {
  const router = useRouter();
  const session = useSession();
  const [loginName, setLoginName] = useState("admin");
  const [password, setPassword] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmedPassword, setConfirmedPassword] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const firstLoginSession = Boolean(
    session.current && session.phase !== "authenticated"
  );

  async function submitLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    const outcome = await session.login(loginName.trim(), password);
    setPassword("");
    if (outcome === "authenticated") router.replace("/console/");
  }

  async function submitPasswordChange(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    if (newPassword !== confirmedPassword) {
      setFormError("两次输入的新密码不一致");
      return;
    }
    const accepted = await session.changePassword(currentPassword, newPassword);
    setCurrentPassword("");
    if (accepted) {
      setNewPassword("");
      setConfirmedPassword("");
      router.replace("/console/");
    }
  }

  async function exitFirstLoginSession() {
    const revoked = await session.logout();
    if (revoked) {
      setCurrentPassword("");
      setNewPassword("");
      setConfirmedPassword("");
      setFormError(null);
    }
  }

  return (
    <App.Frame>
      <App.Background />
      <App.Layers>
        <App.Layer>
          <main className={styles.loginPage}>
            <section className={styles.brandPanel} aria-labelledby="login-heading">
              <div className={styles.brandMark} aria-hidden="true">
                <Boxes />
              </div>
              <Typography.Eyebrow>Matrix PaaS Control Plane</Typography.Eyebrow>
              <Typography.Title id="login-heading">
                把平台能力放进一个清晰的控制面
              </Typography.Title>
              <p className={styles.lead}>
                在统一控制台中选择服务、激活配额并部署到受管区域。Phase 2
                首先交付可真实安装的 PostgreSQL 服务。
              </p>
              <div className={styles.capabilities}>
                <div><Network aria-hidden="true" /><span>区域与资源边界</span></div>
                <div><ShieldCheck aria-hidden="true" /><span>IAM 闭环授权</span></div>
                <div><KeyRound aria-hidden="true" /><span>凭据仅驻留页面内存</span></div>
              </div>
            </section>

            <section className={styles.loginCard} aria-label="登录 Matrix 控制台">
              <div className={styles.mobileMark} aria-hidden="true"><Boxes /></div>
              {firstLoginSession ? (
                <>
                  <div className={styles.cardHeading}>
                    <Typography.Eyebrow>首次登录 · {session.current?.loginName}</Typography.Eyebrow>
                    <Typography.Title as="h2" level={2}>设置你的正式密码</Typography.Title>
                    <Typography.Text tone="muted">
                      初始密码只能建立受限会话。完成更新后才能进入控制台。
                    </Typography.Text>
                  </div>
                  <form
                    id="password-change-form"
                    className={styles.form}
                    onSubmit={submitPasswordChange}
                  >
                    <label className={styles.field}>
                      <span>当前初始密码</span>
                      <Input
                        autoComplete="current-password"
                        maxLength={128}
                        name="currentPassword"
                        onChange={(event) => setCurrentPassword(event.target.value)}
                        required
                        type="password"
                        value={currentPassword}
                      />
                    </label>
                    <label className={styles.field}>
                      <span>新密码</span>
                      <Input
                        aria-describedby="password-policy"
                        autoComplete="new-password"
                        maxLength={128}
                        minLength={14}
                        name="newPassword"
                        onChange={(event) => setNewPassword(event.target.value)}
                        required
                        type="password"
                        value={newPassword}
                      />
                    </label>
                    <label className={styles.field}>
                      <span>确认新密码</span>
                      <Input
                        autoComplete="new-password"
                        maxLength={128}
                        minLength={14}
                        name="confirmedPassword"
                        onChange={(event) => setConfirmedPassword(event.target.value)}
                        required
                        type="password"
                        value={confirmedPassword}
                      />
                    </label>
                    <p className={styles.policy} id="password-policy">
                      14–128 字节，不含空格，并至少包含大写字母、小写字母、数字、符号中的三类。
                    </p>
                    {formError || session.error ? (
                      <p className={styles.error} role="alert">{formError ?? session.error}</p>
                    ) : null}
                    <div className={styles.actions}>
                      <Button
                        block
                        disabled={
                          session.phase === "changing-password" ||
                          !currentPassword ||
                          !newPassword ||
                          !confirmedPassword
                        }
                        size="large"
                        type="submit"
                      >
                        <KeyRound aria-hidden="true" />
                        {session.phase === "changing-password"
                          ? "正在更新密码…"
                          : "保存并进入控制台"}
                      </Button>
                      <Button
                        block
                        disabled={
                          session.phase === "changing-password" ||
                          session.phase === "revoking"
                        }
                        onClick={() => void exitFirstLoginSession()}
                        variant="ghost"
                      >
                        {session.phase === "revoking" ? "正在退出…" : "退出此会话"}
                      </Button>
                    </div>
                  </form>
                </>
              ) : (
                <>
                  <div className={styles.cardHeading}>
                    <Typography.Title as="h2" level={2}>欢迎回来</Typography.Title>
                    <Typography.Text tone="muted">
                      使用 Matrix IAM 用户名和密码继续
                    </Typography.Text>
                  </div>
                  <form id="login-form" className={styles.form} onSubmit={submitLogin}>
                    <label className={styles.field}>
                      <span>登录名</span>
                      <Input
                        autoComplete="username"
                        name="loginName"
                        onChange={(event) => setLoginName(event.target.value)}
                        required
                        value={loginName}
                      />
                    </label>
                    <label className={styles.field}>
                      <span>密码</span>
                      <Input
                        autoComplete="current-password"
                        maxLength={128}
                        name="password"
                        onChange={(event) => setPassword(event.target.value)}
                        required
                        type="password"
                        value={password}
                      />
                    </label>
                    {session.error ? (
                      <p className={styles.error} role="alert">{session.error}</p>
                    ) : null}
                    <Button
                      block
                      disabled={session.phase === "authenticating" || !loginName.trim() || !password}
                      size="large"
                      type="submit"
                    >
                      <LockKeyhole aria-hidden="true" />
                      {session.phase === "authenticating" ? "正在建立会话…" : "登录控制台"}
                    </Button>
                  </form>
                </>
              )}
              <p className={styles.securityNote}>
                刷新页面会清除会话；控制台不会把密码或 bearer 写入浏览器存储。
              </p>
            </section>
          </main>
        </App.Layer>
      </App.Layers>
    </App.Frame>
  );
}
