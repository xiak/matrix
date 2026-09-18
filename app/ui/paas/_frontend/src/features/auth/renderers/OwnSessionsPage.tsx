"use client";

import { useEffect, useRef, useState } from "react";
import { useFormatter, useTranslations } from "next-intl";
import { LogOut, RefreshCcw, ShieldCheck, XCircle } from "lucide-react";
import { Alert, Badge, Button, Card, ContentPage, EmptyState, Table, TablePagination, TableSkeleton, Typography } from "@ui/xiak";
import { useOwnSessions } from "../application/OwnSessionsProvider";
import { useSession } from "../application/SessionProvider";
import styles from "./OwnSessionsPage.module.css";

export function OwnSessionsPage() {
  const t = useTranslations("OwnSessions");
  const collection = useTranslations("Collection");
  const format = useFormatter();
  const sessions = useOwnSessions();
  const session = useSession();
  const initiated = useRef(false);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [cursors, setCursors] = useState<Array<string | undefined>>([undefined]);
  const [cursorIndex, setCursorIndex] = useState(0);

  useEffect(() => {
    if (initiated.current || !sessions.supported) return;
    initiated.current = true;
    void sessions.load();
  }, [sessions]);

  const formatTime = (value: string) => format.dateTime(new Date(value), {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short"
  });

  const move = async (nextIndex: number, cursor?: string) => {
    if (!await sessions.load(cursor)) return;
    setConfirmingId(null);
    setCursorIndex(nextIndex);
  };

  const next = async () => {
    const cursor = sessions.page?.nextCursor;
    if (!cursor) return;
    if (!await sessions.load(cursor)) return;
    setConfirmingId(null);
    setCursors((current) => [...current.slice(0, cursorIndex + 1), cursor]);
    setCursorIndex((current) => current + 1);
  };

  const confirmRevoke = async (targetSessionId: string) => {
    await sessions.revoke(targetSessionId);
    setConfirmingId(null);
  };

  const page = sessions.page;
  const currentListed = page?.items.some((item) => item.id === page.currentSessionId) ?? false;
  const activeCursor = cursors[cursorIndex];
  const actions = <ContentPage.Commands label={collection("pageActions")} secondary={[{
    id: "refresh",
    label: t("refresh"),
    icon: <RefreshCcw aria-hidden="true" />,
    disabled: sessions.loading || Boolean(sessions.revokingId),
    onSelect: () => { void sessions.load(activeCursor); }
  }]} />;

  return <section aria-label={t("title")} aria-busy={sessions.loading || Boolean(sessions.revokingId)} className={styles.root}>
    <ContentPage.Heading title={t("title")} scrollKey="own-login-sessions" actions={actions} />
    <div className={styles.intro}>
      <div>
        <Typography.Title as="h2" level={3}>{t("scopeTitle")}</Typography.Title>
        <Typography.Text tone="muted">{t("description")}</Typography.Text>
      </div>
      <Alert status="info"><ShieldCheck aria-hidden="true" />{t("notDevices")}</Alert>
    </div>

    {sessions.error ? <Alert status="danger">{t(`errors.${sessions.error}`)}</Alert> : null}
    {sessions.success ? <Alert status="success">{t(`success.${sessions.success}`)}</Alert> : null}
    {sessions.uncertainTargetId ? <Alert status="warning" className={styles.uncertain}>
      <div><strong>{t("uncertainTitle")}</strong><span>{t("uncertain")}</span></div>
      <Button disabled={Boolean(sessions.revokingId)} onClick={() => { void sessions.revoke(sessions.uncertainTargetId!); }} size="small" variant="secondary">{t("retryOriginal")}</Button>
    </Alert> : null}

    {!sessions.supported ? <EmptyState title={t("unavailableTitle")} description={t("unavailableDescription")} icon={<XCircle />} /> : null}
    {sessions.supported ? <Card>
      <Card.Header className={styles.cardHeader}>
        <div><Typography.Title as="h2" level={3}>{t("activeTitle")}</Typography.Title><Typography.Text tone="muted">{t("activeHint")}</Typography.Text></div>
        {page ? <span className={styles.observed}><span>{t("observedAt")}</span><time dateTime={page.observedAt} title={page.observedAt}>{formatTime(page.observedAt)}</time></span> : null}
      </Card.Header>
      {sessions.loading && !page ? <TableSkeleton header={false} label={t("loading")} rows={3} /> : null}
      {page ? <>
        <Table aria-label={t("table")} className={styles.table}>
          <thead><tr><th scope="col">{t("sessionId")}</th><th scope="col">{t("issuedAt")}</th><th scope="col">{t("expiresAt")}</th><th scope="col">{t("status")}</th><th scope="col">{t("actions")}</th></tr></thead>
          <tbody>{page.items.map((item) => {
            const isCurrent = item.id === page.currentSessionId;
            const confirming = confirmingId === item.id;
            return <tr key={item.id}>
              <td><code className={styles.identifier}>{item.id}</code></td>
              <td><time dateTime={item.issuedAt} title={item.issuedAt}>{formatTime(item.issuedAt)}</time></td>
              <td><time dateTime={item.expiresAt} title={item.expiresAt}>{formatTime(item.expiresAt)}</time></td>
              <td><div className={styles.status}><Badge status={isCurrent ? "success" : "neutral"}>{t(isCurrent ? "current" : "active")}</Badge>{isCurrent ? <span>{t("currentHint")}</span> : null}</div></td>
              <td>{confirming ? <div className={styles.confirmation} role="group" aria-label={t("confirmTitle")}>
                <span>{t("confirmHint")}</span>
                <div><Button disabled={sessions.revokingId === item.id} onClick={() => { void confirmRevoke(item.id); }} size="small" variant="secondary">{t("confirm")}</Button><Button disabled={Boolean(sessions.revokingId)} onClick={() => setConfirmingId(null)} size="small" variant="ghost">{t("cancel")}</Button></div>
              </div> : isCurrent ? <Button disabled={session.phase === "revoking"} onClick={() => { void session.logout(); }} size="small" variant="ghost"><LogOut aria-hidden="true" />{t("exitCurrent")}</Button>
                : <Button disabled={Boolean(sessions.revokingId || sessions.uncertainTargetId)} onClick={() => { sessions.clearFeedback(); setConfirmingId(item.id); }} size="small" variant="ghost">{t("end")}</Button>}</td>
            </tr>;
          })}</tbody>
        </Table>
        {!page.items.length ? <EmptyState title={t("empty")} description={t("emptyHint")} /> : null}
        <Table.Footer note={<div className={styles.footerNotes}><span>{t("impact")}</span>{cursorIndex > 0 && !currentListed ? <span>{t("currentAbsent")}</span> : null}</div>}>
          <TablePagination mode="cursor" disabled={sessions.loading || Boolean(sessions.revokingId)} summary={t("page", { page: cursorIndex + 1 })}
            previous={{ label: t("previous"), disabled: cursorIndex === 0, onClick: () => { void move(cursorIndex - 1, cursors[cursorIndex - 1]); } }}
            next={{ label: t("next"), disabled: !page.nextCursor, onClick: () => { void next(); } }} />
        </Table.Footer>
      </> : sessions.loading ? null : <EmptyState title={t("loadTitle")} description={t("loadDescription")} action={<Button onClick={() => { void sessions.load(activeCursor); }} variant="secondary">{t("retryLoad")}</Button>} />}
    </Card> : null}
  </section>;
}
