"use client";

import { useDeferredValue, useMemo, useState } from "react";
import { useTranslations } from "next-intl";
import { UserRound } from "lucide-react";
import { Badge, Button, Card, EmptyState, Table, TablePagination, TableToolbar } from "@ui/xiak";
import { useTableToolbarLabels } from "@/i18n/useTableToolbarLabels";
import type { AccountAccessScene } from "../scenes/accountAccessScene";
import styles from "./AccessCredentials.module.css";

export function AccessKeyOwnerDirectory({ scene, busy = false, loading = false, onOpen, onReadPage }: {
  scene: AccountAccessScene;
  busy?: boolean;
  loading?: boolean;
  onOpen(userId: string): void;
  onReadPage?(after: string): void;
}) {
  const t = useTranslations("IamWorkspace");
  const account = useTranslations("AccountAccess");
  const toolbarLabels = useTableToolbarLabels();
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [cursorPage, setCursorPage] = useState(1);
  const deferredQuery = useDeferredValue(query);
  const filtering = deferredQuery !== query;
  const words = useMemo(() => deferredQuery.normalize("NFKC").trim().toLowerCase().split(/\s+/).filter(Boolean), [deferredQuery]);
  const filtered = useMemo(() => scene.users.filter((user) => {
    const text = [user.name, user.loginName, user.id, user.qualifiedName].join(" ").normalize("NFKC").toLowerCase();
    return words.every((word) => text.includes(word));
  }), [scene.users, words]);
  const cursorMode = cursorPage > 1 || !scene.directoryComplete;
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pages);
  const visible = cursorMode ? filtered : filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const blocked = busy || loading || filtering;
  const clearSearch = () => { setQuery(""); setPage(1); };
  const readFirstPage = () => { clearSearch(); setCursorPage(1); onReadPage?.(""); };
  const readNextPage = () => {
    if (!scene.nextUserPage || !onReadPage) return;
    clearSearch(); setCursorPage((current) => current + 1); onReadPage(scene.nextUserPage);
  };

  return <Card>
    <Card.Header className={styles.directoryHeader}>
      <div><h2 className={styles.directoryTitle}>{t("keyUserDirectory")}</h2><p className={styles.directoryHint}>{t("keyUserDirectoryHint")}</p></div>
      <Badge status="neutral">{t("keyLoadedUsers", { count: scene.users.length })}</Badge>
    </Card.Header>
    <TableToolbar labels={toolbarLabels} search={{ label: t("keySearchUsers"), placeholder: t("keySearchUsersPlaceholder"), value: query, onChange: (value) => { setQuery(value); setPage(1); } }}
      status={t("keyUserResults", { shown: filtered.length, loaded: scene.users.length })} />
    {filtered.length ? <Table aria-label={t("keyUserDirectory")} aria-busy={filtering || loading || undefined} mobileLayout="stack" className={styles.ownerDirectoryTable}>
      <thead><tr><th scope="col">{t("owner")}</th><th scope="col">{t("state")}</th></tr></thead>
      <tbody>{visible.map((user) => <tr key={user.id}>
        <td data-label={t("owner")}><button aria-label={t("keyManageNamed", { name: user.loginName })} className={`${styles.identity} ${styles.identityLink}`} disabled={blocked} onClick={() => onOpen(user.id)}><UserRound aria-hidden="true" /><span><strong>{user.name}</strong><small>{user.loginName} · {user.id}</small></span></button></td>
        <td data-label={t("state")}><Badge status={user.enabled ? "success" : "neutral"}>{t(user.enabled ? "enabled" : "disabled")}</Badge></td>
      </tr>)}</tbody>
    </Table> : <EmptyState title={t(query ? "keyNoMatchingUsers" : "keyNoUsers")} description={t(query ? "keyNoMatchingUsersHint" : "keyPrimary")}
      action={query ? <Button onClick={clearSearch} variant="secondary">{toolbarLabels.resetQuery}</Button> : undefined} />}
    <Table.Footer note={t(cursorMode ? "keyUserPageHintPartial" : "keyUserPageHintComplete")}>
      {cursorMode ? <TablePagination mode="cursor" disabled={blocked} summary={t("cursorPage", { page: cursorPage })}
        previous={{ label: account("firstPage"), disabled: cursorPage <= 1 || !onReadPage, onClick: readFirstPage }}
        next={{ label: account("nextPage"), disabled: !scene.nextUserPage || !onReadPage, onClick: readNextPage }} />
        : <TablePagination page={currentPage} pages={pages} pageSize={pageSize} disabled={blocked}
          onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }}
          labels={{ summary: t("page", { page: currentPage, pages }), pageSize: t("pageSize"), previous: t("previous"), next: t("next") }} />}
    </Table.Footer>
  </Card>;
}
