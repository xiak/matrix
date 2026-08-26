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

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const accepted = await session.login(loginName.trim(), password);
    setPassword("");
    if (accepted) router.replace("/console/");
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
              <div className={styles.cardHeading}>
                <Typography.Title as="h2" level={2}>欢迎回来</Typography.Title>
                <Typography.Text tone="muted">
                  使用 Matrix IAM 用户名和密码继续
                </Typography.Text>
              </div>
              <form id="login-form" className={styles.form} onSubmit={submit}>
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
