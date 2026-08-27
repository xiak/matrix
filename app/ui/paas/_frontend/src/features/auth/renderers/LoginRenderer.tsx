"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Boxes, Database, Gauge, KeyRound, LockKeyhole, MapPin, ShieldCheck } from "lucide-react";
import { App, Button, Input, Typography } from "@ui/xiak";
import { useSession } from "../application/SessionProvider";
import styles from "./LoginRenderer.module.css";

export function LoginRenderer() {
  const router = useRouter();
  const session = useSession();
  const [loginMode, setLoginMode] = useState<"primary" | "subaccount">("primary");
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
    const identifier = loginName.trim();
    if ((loginMode === "subaccount") !== identifier.includes("@")) {
      setFormError(loginMode === "subaccount" ? "请输入 子用户名@主账号ID或别名" : "请使用主账号登录名；子账号请切换登录方式");
      return;
    }
    const outcome = await session.login(identifier, password);
    setPassword("");
    if (outcome === "authenticated") router.replace(loginMode === "subaccount" ? "/console/access/" : "/console/");
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
      router.replace(session.current?.loginName.includes("@") ? "/console/access/" : "/console/");
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
              <Typography.Eyebrow>Matrix · Cloud Console</Typography.Eyebrow>
              <Typography.Title className={styles.brandTitle} id="login-heading">
                <span>让服务部署</span>
                <span>简单而有序</span>
              </Typography.Title>
              <p className={styles.lead}>
                集中管理数据库、服务配额与部署区域。
                从一个 PostgreSQL 实例开始。
              </p>
              <div className={styles.capabilities}>
                <div><Database aria-hidden="true" /><span>托管数据库</span></div>
                <div><Gauge aria-hidden="true" /><span>按需开通配额</span></div>
                <div><MapPin aria-hidden="true" /><span>选择区域部署</span></div>
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
                    <Typography.Title as="h2" level={2}>{loginMode === "primary" ? "主账号登录" : "子账号登录"}</Typography.Title>
                    <Typography.Text tone="muted">
                      {loginMode === "primary" ? "登录 Matrix，管理你的服务与资源" : "使用所属主账号的 ID 或专属别名登录"}
                    </Typography.Text>
                  </div>
                  <div aria-label="登录方式" className={styles.loginModes} role="group">
                    {(["primary", "subaccount"] as const).map((mode) => (
                      <Button aria-pressed={loginMode === mode} disabled={session.phase === "authenticating"} key={mode}
                        onClick={() => { setLoginMode(mode); setLoginName(""); setPassword(""); setFormError(null); session.clearError(); }}
                        variant={loginMode === mode ? "secondary" : "ghost"}>
                        {mode === "primary" ? "主账号" : "IAM 子账号"}
                      </Button>
                    ))}
                  </div>
                  <form id="login-form" className={styles.form} onSubmit={submitLogin}>
                    <label className={styles.field}>
                      <span>{loginMode === "primary" ? "登录名" : "子账号登录名"}</span>
                      <Input
                        autoComplete="username"
                        aria-describedby={loginMode === "subaccount" ? "subaccount-login-help" : undefined}
                        maxLength={loginMode === "primary" ? 64 : 193}
                        name="loginName"
                        onChange={(event) => setLoginName(event.target.value)}
                        placeholder={loginMode === "primary" ? "请输入主账号用户名" : "username@主账号ID或别名"}
                        required
                        type="text"
                        value={loginName}
                      />
                    </label>
                    {loginMode === "subaccount" ? <p className={styles.policy} id="subaccount-login-help">例如 developer@acme。别名可由管理员在「访问管理 → 用户设置」中设置，不是邮箱地址。</p> : null}
                    <label className={styles.field}>
                      <span>密码</span>
                      <Input
                        autoComplete="current-password"
                        maxLength={128}
                        name="password"
                        onChange={(event) => setPassword(event.target.value)}
                        placeholder="请输入密码"
                        required
                        type="password"
                        value={password}
                      />
                    </label>
                    {formError || session.error ? (
                      <p className={styles.error} role="alert">{formError ?? session.error}</p>
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
                <ShieldCheck aria-hidden="true" />
                <span>会话仅在当前页面保留，刷新后需重新登录。</span>
              </p>
            </section>
          </main>
        </App.Layer>
      </App.Layers>
    </App.Frame>
  );
}
