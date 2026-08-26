import Link from "next/link";
import { Boxes } from "lucide-react";
import { App, Typography } from "@ui/xiak";
import styles from "./not-found.module.css";

export default function NotFound() {
  return (
    <App.Frame>
      <App.Background />
      <main className={styles.notFound}>
        <Boxes aria-hidden="true" />
        <Typography.Eyebrow>404</Typography.Eyebrow>
        <Typography.Title>控制面中没有这个页面</Typography.Title>
        <Link href="/console/">返回控制面概览</Link>
      </main>
    </App.Frame>
  );
}
