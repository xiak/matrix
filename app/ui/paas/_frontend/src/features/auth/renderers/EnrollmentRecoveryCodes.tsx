"use client";

import { useState } from "react";
import { CheckCircle2, Copy, ShieldCheck } from "lucide-react";
import { Button, Input, Typography } from "@ui/xiak";
import { useSession } from "../application/SessionProvider";
import loginStyles from "./LoginRenderer.module.css";
import styles from "./EnrollmentRecoveryCodes.module.css";

export function EnrollmentRecoveryCodes() {
  const session = useSession();
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const material = session.enrollmentRecovery;

  if (!material) return null;

  async function copyCodes() {
    try {
      if (!navigator.clipboard) return;
      await navigator.clipboard.writeText(material!.recoveryCodes.join("\n"));
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return <div className={styles.root}>
    <div className={loginStyles.cardHeading}>
      <CheckCircle2 aria-hidden="true" />
      <Typography.Title as="h2" level={2}>保存一次性恢复码</Typography.Title>
      <Typography.Text tone="muted">身份验证器已经绑定，原会话已失效。恢复码关闭页面后不能再次读取。</Typography.Text>
    </div>
    <p className={styles.warning}><ShieldCheck aria-hidden="true" />每个恢复码只能使用一次。请离线保存，不要发送给管理员或上传到工单。</p>
    <div className={styles.codeHeader}>
      <div><strong>恢复码</strong><span>共 10 个</span></div>
      <Button onClick={() => void copyCodes()} size="small" variant="secondary"><Copy aria-hidden="true" />{copied ? "已复制" : "复制全部"}</Button>
    </div>
    <ul aria-label="一次性恢复码" className={styles.codes}>
      {material.recoveryCodes.map((code) => <li key={code}>{code}</li>)}
    </ul>
    <label className={styles.confirmation}>
      <Input checked={saved} className={styles.checkbox} onChange={(event) => setSaved(event.target.checked)} type="checkbox" />
      <span>我已将恢复码保存到安全的离线位置</span>
    </label>
    <Button block disabled={!saved} onClick={session.acknowledgeEnrollmentRecovery}>完成并重新登录</Button>
  </div>;
}
