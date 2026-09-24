"use client";

import { useEffect, useId, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Button, FormField, Tabs, TextArea } from "@ui/xiak";
import { useAccountAccess, type AuthorizationProfileLoad } from "../application/AccountAccessProvider";
import type { AccountPolicyDocument, AuthorizationProfileDirectory } from "../domain/accounts";
import { visualDraftFromJSON } from "../domain/accountPolicyVisualAuthoring";
import { AccountPolicyVisualEditor } from "./AccountPolicyVisualEditor";
import styles from "./AccountAccessRenderer.module.css";

export type PolicyAuthorMode = "json" | "visual";

export function AccountPolicyDocumentAuthor({ text, onChange, error, onClearError, mode, onModeChange, onVisualReadyChange, allowEmpty = false, label, hint }: {
  text: string; onChange(text: string): void; error: boolean; onClearError(): void;
  mode: PolicyAuthorMode; onModeChange(mode: PolicyAuthorMode): void; onVisualReadyChange(ready: boolean): void;
  allowEmpty?: boolean; label: string; hint: string;
}) {
  const t = useTranslations("AccountPolicyDirectory");
  const access = useAccountAccess();
  const id = useId();
  const [visualError, setVisualError] = useState<string | null>(null);
  const [catalog, setCatalog] = useState<{ status: "idle" | "loading" } | AuthorizationProfileLoad>({ status: "idle" });
  const [visualDocument, setVisualDocument] = useState<AccountPolicyDocument | null>(null);
  const catalogRequest = useRef(0);
  useEffect(() => () => { catalogRequest.current += 1; }, []);
  const setVisualFromCatalog = (directory: AuthorizationProfileDirectory) => {
    const result = visualDraftFromJSON(text, directory, allowEmpty);
    if (result.status !== "ready") { onVisualReadyChange(false); setVisualError(t(`visualErrors.${result.status}`)); return; }
    setVisualError(null); setVisualDocument(result.document); onVisualReadyChange(true); onModeChange("visual");
  };
  const openVisual = () => {
    onClearError(); setVisualError(null); onVisualReadyChange(false);
    if (catalog.status === "ready") { setVisualFromCatalog(catalog.directory); return; }
    if (!access.authorizationProfiles) { setVisualError(t("visualCatalogUnavailable")); return; }
    onModeChange("visual"); setCatalog({ status: "loading" });
    const current = ++catalogRequest.current;
    void access.authorizationProfiles.load().then((result) => {
      if (current !== catalogRequest.current) return;
      setCatalog(result);
      if (result.status === "ready") setVisualFromCatalog(result.directory);
    });
  };
  return <>
    <Tabs.Root value={mode} onValueChange={(next) => { if (next === "json") { catalogRequest.current += 1; onModeChange("json"); onVisualReadyChange(false); setVisualError(null); } else if (next === "visual") openVisual(); }}>
      <Tabs.List aria-label={t("editorModes")}><Tabs.Trigger value="json">{t("jsonMode")}</Tabs.Trigger><Tabs.Trigger value="visual">{t("visualMode")}</Tabs.Trigger></Tabs.List>
      <Tabs.Content value="visual">{catalog.status === "ready" && visualDocument ?
        <AccountPolicyVisualEditor document={visualDocument} directory={catalog.directory} onChange={(document) => {
          setVisualDocument(document); onChange(JSON.stringify(document, null, 2)); onClearError();
        }} /> : catalog.status === "loading" ? <p className={styles.note} role="status">{t("visualLoading")}</p> :
          <div className={styles.policyVisualFailure}><Alert status="warning">{visualError ?? (catalog.status === "idle" || catalog.status === "ready" ? t("visualCatalogUnavailable") : t(`visualCatalogErrors.${catalog.status}`))}</Alert>
            {visualError ? <Button variant="secondary" onClick={() => { onModeChange("json"); onVisualReadyChange(false); setVisualError(null); }}>{t("returnToJson")}</Button> :
              catalog.status !== "expired" ? <Button variant="secondary" onClick={openVisual}>{t("retryCatalog")}</Button> : null}</div>}</Tabs.Content>
      <Tabs.Content value="json"><FormField id={id + "-document"} label={label} hint={hint}>
        <TextArea id={id + "-document"} className={styles.policyVersionEditor} rows={16} maxLength={65536} spellCheck={false} value={text} invalid={error}
          onChange={(event) => { onChange(event.target.value); onClearError(); }} />
      </FormField></Tabs.Content>
    </Tabs.Root>
    {visualError && mode === "json" ? <Alert status="warning">{visualError}</Alert> : null}
  </>;
}
