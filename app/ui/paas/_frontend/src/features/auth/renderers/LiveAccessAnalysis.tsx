"use client";

import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Alert, Badge, Button, Card, ContentPage, EmptyState, FormField, Input, RadioGroup, Select, Table, TablePagination, TableSkeleton, Tabs, Typography } from "@ui/xiak";
import { HttpProblem, requestToken } from "@/infrastructure/http/jsonRequest";
import type { AccessAnalysisClient } from "../application/AccountAccessProvider";
import type { AccountAccessView, IamAction } from "../domain/accounts";
import type { AccessAnalyzer, AccessAnalyzerAccess, AccessDispositionRule, AccessFinding, AccessFindingAccess, AccessFindingDirectory, AccessFindingStatusFilter, AccessObservationCoverage } from "../domain/accessAnalysis";
import { findActionCapability } from "../scenes/accountAccessScene";
import { WorkspaceDetail, WorkspaceTime } from "./AccessWorkspaceUi";
import { AccessFindingRecoveryBoundary, AccessRecoveryGapBoundary } from "./AccessRecoveryBoundary";
import { AccountReadBoundary, type AccountReadStatus } from "./AccountReadBoundary";
import styles from "./AccountAccessRenderer.module.css";

type Failure = "expired" | "forbidden" | "notFound" | "routeUnavailable" | "conflict" | "invalid" | "unavailable";
type FindingSelection = { analyzerId: string; findingId: string; targetId: string };
type AccessAnalysisMutation =
  | { operation: "create"; command: { type: "UNUSED_ACCESS" } }
  | { operation: "update"; analyzerId: string; command: { status: AccessAnalyzer["status"]; unusedAccessAgeDays: number; resourceVersion: number } }
  | { operation: "setDisposition"; analyzerId: string; command: { disposition: AccessDispositionRule; resourceVersion: number } }
  | { operation: "archive" | "unarchive"; analyzerId: string; findingId: string; command: { resourceVersion: number } };
type AccessAnalysisMutationIntent = AccessAnalysisMutation & {
  client: AccessAnalysisClient;
  phase: "submitting" | "unknown";
  requestId: string;
};

const findingBadge: Record<AccessFinding["status"], "warning" | "neutral" | "success"> = {
  ACTIVE: "warning",
  ARCHIVED: "neutral",
  RESOLVED: "success"
};

const coverageBadge: Record<AccessObservationCoverage["state"], "success" | "warning" | "neutral"> = {
  COMPLETE: "success",
  INSUFFICIENT_COVERAGE: "warning",
  NOT_INCLUDED: "neutral"
};

function failureCode(error: unknown): Failure {
  if (error instanceof HttpProblem) {
    if (error.status === 401) return "expired";
    if (error.status === 403) return "forbidden";
    if (error.status === 404) return error.code === "iam.route.notfound" ? "routeUnavailable" : "notFound";
    if (error.status === 409) return "conflict";
    if (error.status === 400 || error.status === 422) return "invalid";
  }
  return "unavailable";
}

function readStatus(error: Failure | null): Exclude<AccountReadStatus, "loading" | "ready" | "empty"> {
  if (error === "forbidden" || error === "notFound" || error === "routeUnavailable" || error === "expired" || error === "unavailable") return error;
  return "unavailable";
}

function findingTypeKey(type: AccessFinding["type"]): "unusedPassword" | "unusedAccessKey" | "unusedRole" {
  if (type === "UNUSED_PASSWORD") return "unusedPassword";
  if (type === "UNUSED_ACCESS_KEY") return "unusedAccessKey";
  return "unusedRole";
}

function targetView(finding: AccessFinding): { view: AccountAccessView; id?: string } {
  if (finding.type === "UNUSED_PASSWORD") return { view: "users", id: finding.target.id };
  if (finding.type === "UNUSED_ROLE") return { view: "roles", id: finding.target.id };
  return { view: "keys" };
}

type LiveAccessAnalysisProps = {
  client: AccessAnalysisClient;
  onNavigate(view: AccountAccessView, id?: string): void;
};

type LiveAccessAnalysisGenerationProps = LiveAccessAnalysisProps & {
  blockedIntent: AccessAnalysisMutationIntent | null;
  currentIntent: AccessAnalysisMutationIntent | null;
  onBegin(intent: AccessAnalysisMutationIntent): AccessAnalysisMutationIntent | null;
  onResolved(client: AccessAnalysisClient, requestId: string): void;
  onUnknown(client: AccessAnalysisClient, requestId: string): void;
};

export function LiveAccessAnalysis(props: LiveAccessAnalysisProps) {
  const [binding, setBinding] = useState(() => ({ client: props.client, generation: 0 }));
  const [intent, setIntent] = useState<AccessAnalysisMutationIntent | null>(null);
  let current = binding;
  if (binding.client !== props.client) {
    current = { client: props.client, generation: binding.generation + 1 };
    setBinding(current);
  }
  const currentIntent = intent?.client === props.client ? intent : null;
  const blockedIntent = intent && intent.client !== props.client ? intent : null;
  const begin = (candidate: AccessAnalysisMutationIntent) => {
    if (intent) {
      if (intent.client !== props.client) return null;
      const resumed = { ...intent, phase: "submitting" as const };
      setIntent(resumed);
      return resumed;
    }
    setIntent(candidate);
    return candidate;
  };
  const resolve = (source: AccessAnalysisClient, requestId: string) => setIntent((pending) =>
    pending?.client === source && pending.requestId === requestId ? null : pending);
  const markUnknown = (source: AccessAnalysisClient, requestId: string) => setIntent((pending) =>
    pending?.client === source && pending.requestId === requestId ? { ...pending, phase: "unknown" } : pending);
  return <LiveAccessAnalysisGeneration key={current.generation} {...props} blockedIntent={blockedIntent} currentIntent={currentIntent}
    onBegin={begin} onResolved={resolve} onUnknown={markUnknown} />;
}

function LiveAccessAnalysisGeneration({ blockedIntent, client, currentIntent, onBegin, onNavigate, onResolved, onUnknown }: LiveAccessAnalysisGenerationProps) {
  const t = useTranslations("IamWorkspace.accessAnalysis");
  const mounted = useRef(true);
  const [section, setSection] = useState<"coverage" | "unused" | "rule">("unused");
  const [analyzers, setAnalyzers] = useState<AccessAnalyzer[] | null>(() => client.canList ? null : []);
  const [analyzerAccess, setAnalyzerAccess] = useState<AccessAnalyzerAccess | null>(null);
  const [analyzersLoading, setAnalyzersLoading] = useState(client.canList);
  const [knownAnalyzerId, setKnownAnalyzerId] = useState("");
  const [filter, setFilter] = useState<AccessFindingStatusFilter>("ACTIVE");
  const [cursorStack, setCursorStack] = useState<Array<string | undefined>>([undefined]);
  const [pageIndex, setPageIndex] = useState(0);
  const [findings, setFindings] = useState<AccessFindingDirectory | null>(null);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [selectedReference, setSelectedReference] = useState<FindingSelection | null>(null);
  const [selected, setSelected] = useState<AccessFindingAccess | null>(null);
  const [selectedLoading, setSelectedLoading] = useState(false);
  const [selectedRevision, setSelectedRevision] = useState(0);
  const [detailError, setDetailError] = useState<Failure | null>(null);
  const [detailProblem, setDetailProblem] = useState<HttpProblem | null>(null);
  const [error, setError] = useState<Failure | null>(null);
  const [readProblem, setReadProblem] = useState<HttpProblem | null>(null);
  const [notice, setNotice] = useState<"created" | "updated" | "dispositionUpdated" | "archived" | "unarchived" | null>(null);
  const [busy, setBusy] = useState(false);
  const [reloadRevision, setReloadRevision] = useState(0);
  const currentClient = useRef<AccessAnalysisClient | null>(client);
  const analyzer = analyzerAccess?.analyzer ?? null;
  const selectedFinding = selected?.finding ?? null;
  const currentCursor = cursorStack[pageIndex];
  const analyzerCan = (action: IamAction) => Boolean(analyzerAccess &&
    findActionCapability(analyzerAccess.capabilities, action, "ACCESS_ANALYZER", analyzerAccess.analyzer.id)?.available);
  const canListFindings = analyzerCan("iam.access-finding.list");
  const canUpdateAnalyzer = analyzerCan("iam.access-analyzer.update");
  const canSetDisposition = analyzerCan("iam.access-analyzer.set-disposition");
  const presentedFindings = canListFindings ? findings : null;
  const presentedFindingsLoading = canListFindings && findingsLoading;

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  useLayoutEffect(() => {
    currentClient.current = client;
    return () => { if (currentClient.current === client) currentClient.current = null; };
  }, [client]);
  const ownsClient = () => mounted.current && currentClient.current === client;

  useEffect(() => {
    if (!client.canList) return;
    let active = true;
    void client.listAnalyzers().then(async (directory) => {
      if (!active) return;
      setReadProblem(null);
      setAnalyzers(directory.items);
      const first = directory.items[0];
      if (!first) { setAnalyzerAccess(null); return; }
      const access = await client.readAnalyzer(first.id);
      if (!active) return;
      setAnalyzerAccess(access);
      setFindingsLoading(findActionCapability(access.capabilities, "iam.access-finding.list", "ACCESS_ANALYZER", access.analyzer.id)?.available === true);
    }).catch((failure) => {
      if (!active) return;
      setAnalyzers(null);
      setReadProblem(failure instanceof HttpProblem ? failure : null);
      setError(failureCode(failure));
    }).finally(() => { if (active) setAnalyzersLoading(false); });
    return () => { active = false; };
  }, [client, reloadRevision]);

  useEffect(() => {
    if (!analyzer || !canListFindings) return;
    let active = true;
    void client.listFindings(analyzer.id, filter, currentCursor).then((directory) => {
      if (!active) return;
      setReadProblem(null);
      setFindings(directory);
    }).catch((failure) => {
      if (!active) return;
      setFindings(null);
      setReadProblem(failure instanceof HttpProblem ? failure : null);
      setError(failureCode(failure));
    }).finally(() => { if (active) setFindingsLoading(false); });
    return () => { active = false; };
  }, [analyzer, canListFindings, client, currentCursor, filter, reloadRevision]);

  useEffect(() => {
    if (!selectedReference) return;
    let active = true;
    void client.readFinding(selectedReference.analyzerId, selectedReference.findingId).then((finding) => {
      if (!active) return;
      setDetailProblem(null);
      setSelected(finding);
    }).catch((failure) => {
      if (!active) return;
      setSelected(null);
      setDetailProblem(failure instanceof HttpProblem ? failure : null);
      setDetailError(failureCode(failure));
    }).finally(() => { if (active) setSelectedLoading(false); });
    return () => { active = false; };
  }, [client, selectedReference, selectedRevision]);

  const changeFilter = (value: string) => {
    setFindingsLoading(true);
    setError(null);
    setReadProblem(null);
    setFilter(value as AccessFindingStatusFilter);
    setCursorStack([undefined]);
    setPageIndex(0);
    setSelectedReference(null);
    setSelected(null);
    setDetailError(null);
    setNotice(null);
  };

  const reload = () => {
    setAnalyzersLoading(true);
    setFindingsLoading(Boolean(analyzer));
    setError(null);
    setReadProblem(null);
    setReloadRevision((current) => current + 1);
  };

  const replaceFinding = (updated: AccessFinding, access?: AccessFindingAccess) => {
    setSelected((current) => current?.finding.id === updated.id ? access ?? { ...current, finding: updated } : current);
    setFindings((current) => current ? {
      ...current,
      items: filter === "ALL" || filter === updated.status
        ? current.items.map((item) => item.id === updated.id ? updated : item)
        : current.items.filter((item) => item.id !== updated.id)
    } : current);
  };

  const refreshAfterConflict = async (intent: AccessAnalysisMutationIntent) => {
    if (intent.operation === "create") {
      const directory = await client.listAnalyzers();
      if (!ownsClient()) return;
      setAnalyzers(directory.items);
      setFindingsLoading(directory.items.length > 0);
      return;
    }
    if (intent.operation === "update" || intent.operation === "setDisposition") {
      const latest = await client.readAnalyzer(intent.analyzerId);
      if (!ownsClient()) return;
      setAnalyzerAccess(latest);
      setAnalyzers([latest.analyzer]);
      setCursorStack([undefined]); setPageIndex(0); setFindings(null);
      setFindingsLoading(findActionCapability(latest.capabilities, "iam.access-finding.list", "ACCESS_ANALYZER", latest.analyzer.id)?.available === true);
      return;
    }
    setSelectedLoading(true);
    try {
      const latest = await client.readFinding(intent.analyzerId, intent.findingId);
      if (ownsClient()) replaceFinding(latest.finding, latest);
    } finally {
      if (ownsClient()) setSelectedLoading(false);
    }
  };

  const executeMutation = async (intent: AccessAnalysisMutationIntent) => {
    const findingMutation = intent.operation === "archive" || intent.operation === "unarchive";
    setBusy(true); setNotice(null);
    if (findingMutation) { setDetailError(null); setDetailProblem(null); }
    else { setError(null); setReadProblem(null); }
    let result: AccessAnalyzer | AccessFinding;
    try {
      if (intent.operation === "create") {
        result = await client.createAnalyzer({ ...intent.command, requestId: intent.requestId });
      } else if (intent.operation === "update") {
        result = await client.updateAnalyzer(intent.analyzerId, { ...intent.command, requestId: intent.requestId });
      } else if (intent.operation === "setDisposition") {
        result = await client.setDisposition(intent.analyzerId, { ...intent.command, requestId: intent.requestId });
      } else {
        const command = { ...intent.command, requestId: intent.requestId };
        result = intent.operation === "archive"
          ? await client.archiveFinding(intent.analyzerId, intent.findingId, command)
          : await client.unarchiveFinding(intent.analyzerId, intent.findingId, command);
      }
    } catch (failure) {
      const code = failureCode(failure);
      if (code === "unavailable") onUnknown(client, intent.requestId);
      else onResolved(client, intent.requestId);
      if (!ownsClient()) return;
      if (findingMutation) setDetailError(code); else setError(code);
      if (code === "expired") {
        setAnalyzers(null); setFindings(null); setSelectedReference(null); setSelected(null);
      } else if (code === "conflict") {
        try {
          await refreshAfterConflict(intent);
        } catch (readFailure) {
          if (ownsClient()) {
            const readCode = failureCode(readFailure);
            if (findingMutation) setDetailError(readCode); else setError(readCode);
          }
        }
      }
      if (ownsClient()) setBusy(false);
      return;
    }

    // A successful command and its authoritative follow-up read are separate
    // outcomes. Never turn an applied mutation into an outcome-unknown write
    // merely because the detail refresh failed.
    onResolved(client, intent.requestId);
    if (!ownsClient()) return;
    if (intent.operation === "create") { setNotice("created"); setSection("rule"); }
    else if (intent.operation === "update") setNotice("updated");
    else if (intent.operation === "setDisposition") setNotice("dispositionUpdated");
    else setNotice((result as AccessFinding).status === "ARCHIVED" ? "archived" : "unarchived");

    try {
      if (intent.operation === "create" || intent.operation === "update" || intent.operation === "setDisposition") {
        const analyzerId = (result as AccessAnalyzer).id;
        setKnownAnalyzerId(analyzerId);
        const latest = await client.readAnalyzer(analyzerId);
        if (!ownsClient()) return;
        setAnalyzerAccess(latest); setAnalyzers([latest.analyzer]);
        setReadProblem(null); setError(null);
        if (intent.operation === "update") {
          setCursorStack([undefined]); setPageIndex(0); setFindings(null);
        }
        setFindingsLoading(findActionCapability(latest.capabilities, "iam.access-finding.list", "ACCESS_ANALYZER", latest.analyzer.id)?.available === true);
      } else {
        const updated = result as AccessFinding;
        const latest = await client.readFinding(updated.analyzerId, updated.id);
        if (!ownsClient()) return;
        setDetailProblem(null); setDetailError(null);
        replaceFinding(latest.finding, latest);
      }
    } catch (failure) {
      if (!ownsClient()) return;
      const code = failureCode(failure);
      const problem = failure instanceof HttpProblem ? failure : null;
      if (findingMutation) {
        setSelected(null); setDetailProblem(problem); setDetailError(code);
      } else {
        setAnalyzerAccess(null); setAnalyzers(null); setFindings(null); setFindingsLoading(false);
        setReadProblem(problem); setError(code);
      }
    } finally { if (ownsClient()) setBusy(false); }
  };

  const startMutation = async (mutation: AccessAnalysisMutation) => {
    if (currentIntent || blockedIntent || busy) return;
    const prefix = mutation.operation === "create" ? "ui-access-analyzer-create-"
      : mutation.operation === "update" ? "ui-access-analyzer-update-"
        : mutation.operation === "setDisposition" ? "ui-access-analyzer-set-disposition-"
          : `ui-access-finding-${mutation.operation}-`;
    const candidate = { ...mutation, client, phase: "submitting" as const, requestId: requestToken(prefix) } as AccessAnalysisMutationIntent;
    const started = onBegin(candidate);
    if (started) await executeMutation(started);
  };

  const retryMutation = async () => {
    if (!currentIntent || busy) return;
    const started = onBegin(currentIntent);
    if (started) await executeMutation(started);
  };

  const createAnalyzer = async () => startMutation({ operation: "create", command: { type: "UNUSED_ACCESS" } });

  const openKnownAnalyzer = async () => {
    const analyzerId = knownAnalyzerId.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(analyzerId)) return;
    setAnalyzersLoading(true); setError(null); setReadProblem(null); setFindings(null);
    try {
      const access = await client.readAnalyzer(analyzerId);
      if (!ownsClient()) return;
      setAnalyzerAccess(access); setAnalyzers([access.analyzer]);
      setFindingsLoading(findActionCapability(access.capabilities, "iam.access-finding.list", "ACCESS_ANALYZER", access.analyzer.id)?.available === true);
    } catch (failure) {
      if (!ownsClient()) return;
      setAnalyzerAccess(null); setAnalyzers(null); setFindingsLoading(false);
      setReadProblem(failure instanceof HttpProblem ? failure : null); setError(failureCode(failure));
    } finally { if (ownsClient()) setAnalyzersLoading(false); }
  };

  const updateAnalyzer = async (next: { status: AccessAnalyzer["status"]; unusedAccessAgeDays: number }) => {
    if (!analyzer || !canUpdateAnalyzer) return;
    await startMutation({ operation: "update", analyzerId: analyzer.id, command: { ...next, resourceVersion: analyzer.resourceVersion } });
  };

  const setDisposition = async (disposition: AccessDispositionRule) => {
    if (!analyzer || !canSetDisposition) return;
    await startMutation({ operation: "setDisposition", analyzerId: analyzer.id, command: { disposition, resourceVersion: analyzer.resourceVersion } });
  };

  const transitionFinding = async (finding: AccessFinding) => {
    if (finding.status === "RESOLVED") return;
    const action = finding.status === "ACTIVE" ? "iam.access-finding.archive" : "iam.access-finding.unarchive";
    if (!selected || findActionCapability(selected.capabilities, action, "ACCESS_FINDING", finding.id)?.available !== true) return;
    await startMutation({
      operation: finding.status === "ACTIVE" ? "archive" : "unarchive",
      analyzerId: finding.analyzerId,
      findingId: finding.id,
      command: { resourceVersion: finding.resourceVersion }
    });
  };

  const retryingOriginal = Boolean(currentIntent && !busy);
  const writeBlocked = Boolean(busy || currentIntent || blockedIntent);
  const findingTransitionAction = selectedFinding?.status === "ACTIVE" ? "iam.access-finding.archive" : "iam.access-finding.unarchive";
  const canTransitionFinding = Boolean(selected && selectedFinding && selectedFinding.status !== "RESOLVED" &&
    findActionCapability(selected.capabilities, findingTransitionAction, "ACCESS_FINDING", selectedFinding.id)?.available);
  const mutationBoundary = retryingOriginal && currentIntent
    ? <Alert status="warning"><div className={styles.confirmation}><strong>{t("live.uncertainMutation", { id: currentIntent.requestId })}</strong><Button variant="secondary" onClick={() => void retryMutation()}>{t("live.retryOriginalMutation")}</Button></div></Alert>
    : blockedIntent
      ? <Alert status="warning">{t("live.foreignMutation", { id: blockedIntent.requestId })}</Alert>
      : null;

  if (selectedReference) return <WorkspaceDetail title={t("live.findingTitle", { id: selectedFinding?.target.id ?? selectedReference.targetId })} onBack={() => {
    setSelectedReference(null); setSelected(null); setDetailError(null); setNotice(null);
  }}>
    {mutationBoundary}
    {!selectedLoading && !selected && detailError ? <AccountReadBoundary status={readStatus(detailError)} loading={null}
      failure={{ title: t("live.loadFailedTitle"), description: t(`live.errors.${detailError}`) }} problem={detailProblem}
      onRetry={() => { setSelectedLoading(true); setDetailError(null); setDetailProblem(null); setSelectedRevision((current) => current + 1); }} /> : null}
    {selectedFinding && detailError ? <Alert status="danger"><div className={styles.confirmation}><strong>{t(`live.errors.${detailError}`)}</strong>{!currentIntent && detailError === "unavailable" ? <Button variant="secondary" onClick={() => {
      setSelected(null); setSelectedLoading(true); setDetailError(null); setSelectedRevision((current) => current + 1);
    }}>{t("live.retry")}</Button> : null}</div></Alert> : null}
    {notice ? <Alert status="success">{t(`live.notices.${notice}`)}</Alert> : null}
    <Alert status="info">{t("live.findingBoundary")}</Alert>
    {selectedLoading ? <Card><TableSkeleton header={false} label={t("live.loadingFindingDetail")} labelVisible={false} rows={5} /></Card> : null}
    {!selectedLoading && selectedFinding ? <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{selectedFinding.target.id}</Typography.Title><Typography.Text tone="muted">{selectedFinding.id}</Typography.Text></div><Badge status={findingBadge[selectedFinding.status]}>{t(`unused.lifecycle.${selectedFinding.status}`)}</Badge></Card.Header>
      <Card.Body className={styles.detail}>
        <dl className={styles.facts}>
          <div><dt>{t("unused.findingId")}</dt><dd><code>{selectedFinding.id}</code></dd></div>
          <div><dt>{t("unused.analyzerId")}</dt><dd><code>{selectedFinding.analyzerId}</code></dd></div>
          <div><dt>{t("unused.findingType")}</dt><dd>{t(`unused.types.${findingTypeKey(selectedFinding.type)}`)}</dd></div>
          <div><dt>{t("unused.status")}</dt><dd>{t(`unused.lifecycle.${selectedFinding.status}`)}</dd></div>
          <div><dt>{t("live.targetVersion")}</dt><dd>{selectedFinding.targetResourceVersion}</dd></div>
          <div><dt>{t("rule.resourceVersion")}</dt><dd>{selectedFinding.resourceVersion}</dd></div>
          <div><dt>{t("live.windowStartedAt")}</dt><dd><WorkspaceTime value={selectedFinding.windowStartedAt} /></dd></div>
          <div><dt>{t("live.observedAt")}</dt><dd><WorkspaceTime value={selectedFinding.observedAt} /></dd></div>
          <div><dt>{t("live.lastActivityAt")}</dt><dd>{selectedFinding.lastActivityAt ? <WorkspaceTime value={selectedFinding.lastActivityAt} /> : t("live.noActivity")}</dd></div>
          {selectedFinding.resolvedAt ? <div><dt>{t("live.resolvedAt")}</dt><dd><WorkspaceTime value={selectedFinding.resolvedAt} /></dd></div> : null}
          {selectedFinding.resolutionReason ? <div><dt>{t("live.resolutionReason")}</dt><dd>{t(`live.resolutionReasons.${selectedFinding.resolutionReason}`)}</dd></div> : null}
        </dl>
        <AccessFindingRecoveryBoundary evidence={selectedFinding} source="live" />
        <Alert status="warning">{selectedFinding.resolutionReason === "AUTOMATIC_DISPOSITION" ? t("live.automaticDispositionEvidence") : t("unused.noAutomaticAction")}</Alert>
      </Card.Body>
      <Card.Footer><div className={styles.actions}>
        {canTransitionFinding ? <Button disabled={writeBlocked} onClick={() => void transitionFinding(selectedFinding)}>{t(selectedFinding.status === "ACTIVE" ? "live.archive" : "live.unarchive")}</Button> : null}
        <Button variant="secondary" onClick={() => { const target = targetView(selectedFinding); onNavigate(target.view, target.id); }}>{t("unused.reviewTarget")}</Button>
      </div></Card.Footer>
    </Card> : null}
  </WorkspaceDetail>;

  return <div className={styles.detailWorkspace}>
    <ContentPage.Heading title={t("title")} scrollKey={`access-analysis-live:${client.accountId}`} />
    <Alert status="info">{t("live.connectedBoundary")}</Alert>
    {!client.canList ? <Card>
      <Card.Header><div><Typography.Title as="h2" level={3}>{t("live.knownAnalyzerTitle")}</Typography.Title><Typography.Text tone="muted">{t("live.knownAnalyzerHint")}</Typography.Text></div></Card.Header>
      <Card.Body><FormField id="known-access-analyzer-id" label={t("live.knownAnalyzerLabel")} hint={t("live.knownAnalyzerHint")}>
        <Input id="known-access-analyzer-id" autoComplete="off" maxLength={128} value={knownAnalyzerId} onChange={(event) => setKnownAnalyzerId(event.target.value)} />
      </FormField></Card.Body>
      <Card.Footer><Button disabled={analyzersLoading || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(knownAnalyzerId.trim())} onClick={() => void openKnownAnalyzer()}>{t("live.openKnownAnalyzer")}</Button></Card.Footer>
    </Card> : null}
    {mutationBoundary}
    {error && analyzers !== null && presentedFindings !== null ? <Alert status="danger"><strong>{t(`live.errors.${error}`)}</strong></Alert> : null}
    {notice ? <Alert status="success">{t(`live.notices.${notice}`)}</Alert> : null}
    <Tabs.Root value={section} onValueChange={(value) => setSection(value as typeof section)}>
      <Tabs.List aria-label={t("sections")} className={styles.accessAnalysisTabs}>
        <Tabs.Trigger value="coverage">{t("live.tabs.coverage")}</Tabs.Trigger>
        <Tabs.Trigger value="unused">{t("tabs.unused")}</Tabs.Trigger>
        <Tabs.Trigger value="rule">{t("tabs.rule")}</Tabs.Trigger>
      </Tabs.List>
      <AccountReadBoundary
        status={analyzersLoading ? "loading" : analyzers === null ? readStatus(error) : !analyzer ? "empty" : "ready"}
        loading={<Tabs.Content value={section}><Card><TableSkeleton header label={t("live.loading")} labelVisible={false} rows={4} /></Card></Tabs.Content>}
        empty={{ title: t(client.canList ? "live.noAnalyzerTitle" : "live.listDeniedTitle"), description: t(client.canList ? "live.noAnalyzerHint" : "live.listDeniedHint"), action: client.canCreate ? <Button disabled={writeBlocked} onClick={() => void createAnalyzer()}>{t("live.createAnalyzer")}</Button> : undefined }}
        failure={{ title: t("live.loadFailedTitle"), description: t(`live.errors.${error ?? "unavailable"}`) }}
        onRetry={knownAnalyzerId.trim() ? () => void openKnownAnalyzer() : client.canList ? reload : undefined} problem={readProblem}>
      {analyzer ? <>
        <Tabs.Content className={styles.stack} value="coverage">
          <AccountReadBoundary status={presentedFindingsLoading ? "loading" : presentedFindings ? "ready" : !canListFindings ? "forbidden" : readStatus(error)}
            loading={<Card><TableSkeleton header label={t("live.loadingCoverage")} labelVisible={false} rows={6} /></Card>}
            failure={{ title: t("live.loadFailedTitle"), description: t(`live.errors.${error ?? "unavailable"}`) }} onRetry={reload} problem={readProblem}>
          {presentedFindings ? <Card>
            <Card.Header><div><Typography.Title as="h2" level={3}>{t("external.coverageTitle")}</Typography.Title><Typography.Text tone="muted">{t("live.coverageHint")}</Typography.Text></div><Badge status="info"><WorkspaceTime value={presentedFindings.observedAt} /></Badge></Card.Header>
            <Card.Body className={styles.securityReportBody}><dl className={styles.activityEvidence}>{presentedFindings.coverage.map((entry) => <div key={entry.source}><dt>{t(`external.coverage.${entry.source}.title`)}</dt><dd><Badge status={coverageBadge[entry.state]}>{t(`external.coverageStates.${entry.state}`)}</Badge><span>{entry.reason ? t(`external.coverageReasons.${entry.reason}`) : t("live.coverageComplete")}</span>{entry.observedFrom && entry.observedThrough ? <small><WorkspaceTime value={entry.observedFrom} /> – <WorkspaceTime value={entry.observedThrough} /></small> : null}</dd></div>)}</dl></Card.Body>
          </Card> : null}
          </AccountReadBoundary>
          {presentedFindings ? <AccessRecoveryGapBoundary coverage={presentedFindings.coverage} /> : null}
        </Tabs.Content>
        <Tabs.Content className={styles.stack} value="unused">
          <Card>
            <Card.Header><div><Typography.Title as="h2" level={3}>{t("live.findingsTitle")}</Typography.Title><Typography.Text tone="muted">{t("live.findingsHint")}</Typography.Text></div><FormField id="live-access-finding-status" label={t("unused.status")}><Select id="live-access-finding-status" disabled={presentedFindingsLoading} value={filter} onValueChange={changeFilter} options={(['ALL', 'ACTIVE', 'ARCHIVED', 'RESOLVED'] as const).map((value) => ({ value, label: t(`live.filters.${value}`) }))} /></FormField></Card.Header>
            <AccountReadBoundary status={presentedFindingsLoading ? "loading" : presentedFindings ? "ready" : !canListFindings ? "forbidden" : readStatus(error)}
              loading={<TableSkeleton label={t("live.loadingFindings")} labelVisible={false} rows={6} />}
              failure={{ title: t("live.loadFailedTitle"), description: t(`live.errors.${error ?? "unavailable"}`) }} onRetry={reload} problem={readProblem}>
            {presentedFindings ? presentedFindings.items.length ? <Table aria-label={t("live.findingsTitle")} mobileLayout="stack"><thead><tr><th scope="col">{t("unused.principal")}</th><th scope="col">{t("unused.findingType")}</th><th scope="col">{t("unused.status")}</th><th scope="col">{t("live.observedAt")}</th></tr></thead><tbody>{presentedFindings.items.map((finding) => <tr key={finding.id}><td data-label={t("unused.principal")}><Table.PrimaryAction onClick={() => {
              setSelectedReference({ analyzerId: finding.analyzerId, findingId: finding.id, targetId: finding.target.id });
              setSelected(null); setSelectedLoading(true); setDetailError(null); setNotice(null);
            }}>{finding.target.id}</Table.PrimaryAction><small>{finding.id}</small></td><td data-label={t("unused.findingType")}>{t(`unused.types.${findingTypeKey(finding.type)}`)}</td><td data-label={t("unused.status")}><Badge status={findingBadge[finding.status]}>{t(`unused.lifecycle.${finding.status}`)}</Badge></td><td data-label={t("live.observedAt")}><WorkspaceTime value={finding.observedAt} /></td></tr>)}</tbody></Table> : <EmptyState title={t("live.noFindingsTitle")} description={t("live.noFindingsHint")} /> : null}
            </AccountReadBoundary>
            <Table.Footer note={t("live.cursorBoundary")}><TablePagination mode="cursor" disabled={presentedFindingsLoading} summary={t("live.page", { page: pageIndex + 1 })}
              previous={{ label: t("live.previous"), disabled: pageIndex === 0, onClick: () => { setFindingsLoading(true); setError(null); setPageIndex((current) => Math.max(0, current - 1)); } }}
              next={{ label: t("live.next"), disabled: !presentedFindings?.nextAfter, onClick: () => { if (!presentedFindings?.nextAfter) return; setFindingsLoading(true); setError(null); setCursorStack((current) => [...current.slice(0, pageIndex + 1), presentedFindings.nextAfter ?? undefined]); setPageIndex((current) => current + 1); } }} /></Table.Footer>
          </Card>
        </Tabs.Content>
        <Tabs.Content className={styles.stack} value="rule">
          <LiveAnalyzerRule analyzer={analyzer} busy={writeBlocked || !canUpdateAnalyzer} onSave={updateAnalyzer} />
          <LiveDispositionRule analyzer={analyzer} busy={writeBlocked || !canSetDisposition} onSave={setDisposition} />
        </Tabs.Content>
      </> : null}
      </AccountReadBoundary>
    </Tabs.Root>
  </div>;
}

function LiveAnalyzerRule({ analyzer, busy, onSave }: {
  analyzer: AccessAnalyzer;
  busy: boolean;
  onSave(value: { status: AccessAnalyzer["status"]; unusedAccessAgeDays: number }): Promise<void>;
}) {
  const t = useTranslations("IamWorkspace.accessAnalysis");
  const id = useId();
  const [days, setDays] = useState(String(analyzer.unusedAccessAgeDays));
  const [status, setStatus] = useState(analyzer.status);
  const value = Number(days);
  const invalid = !/^\d+$/.test(days) || !Number.isInteger(value) || value < 1 || value > 365;
  const unchanged = value === analyzer.unusedAccessAgeDays && status === analyzer.status;
  return <Card>
    <Card.Header><div><Typography.Title as="h2" level={3}>{t("rule.title")}</Typography.Title><Typography.Text tone="muted">{t("live.ruleHint")}</Typography.Text></div><Badge status={analyzer.status === "ACTIVE" ? "success" : "neutral"}>{t(`rule.statuses.${analyzer.status}`)}</Badge></Card.Header>
    <Card.Body className={styles.detail}>
      <dl className={styles.facts}>
        <div><dt>{t("rule.account")}</dt><dd><code>{analyzer.accountId}</code></dd></div>
        <div><dt>{t("rule.analyzerId")}</dt><dd><code>{analyzer.id}</code></dd></div>
        <div><dt>{t("rule.resourceVersion")}</dt><dd>{analyzer.resourceVersion}</dd></div>
      </dl>
      <FormField id={`${id}-days`} label={t("rule.window")} hint={t("rule.windowHint")} error={invalid ? t("rule.windowInvalid") : undefined}><Input id={`${id}-days`} disabled={busy} type="number" min={1} max={365} step={1} value={days} onChange={(event) => setDays(event.target.value)} /></FormField>
      <RadioGroup disabled={busy} label={t("rule.status")} value={status} onValueChange={(next) => setStatus(next as AccessAnalyzer["status"])} options={(['ACTIVE', 'DISABLED'] as const).map((next) => ({ value: next, label: t(`rule.statuses.${next}`) }))} />
      <Alert status="warning">{t("live.noAutomaticRemediation")}</Alert>
    </Card.Body>
    <Card.Footer><Button disabled={busy || invalid || unchanged} onClick={() => void onSave({ status, unusedAccessAgeDays: value })}>{t("live.saveRule")}</Button></Card.Footer>
  </Card>;
}

function LiveDispositionRule({ analyzer, busy, onSave }: {
  analyzer: AccessAnalyzer;
  busy: boolean;
  onSave(value: AccessDispositionRule): Promise<void>;
}) {
  const t = useTranslations("IamWorkspace.accessAnalysis.disposition");
  const id = useId();
  const [step, setStep] = useState<"summary" | "edit" | "review">("summary");
  const [mode, setMode] = useState<AccessDispositionRule["mode"]>(analyzer.disposition.mode);
  const [delayValue, setDelayValue] = useState(String(analyzer.disposition.findingDelayDays || 7));
  const delayDays = Number(delayValue);
  const automatic = mode === "DISABLE_UNUSED_ACCESS_KEYS";
  const invalidDelay = automatic && (!/^\d+$/.test(delayValue) || !Number.isInteger(delayDays) || delayDays < 1 || delayDays > 30);
  const nextDisposition: AccessDispositionRule = automatic
    ? { mode: "DISABLE_UNUSED_ACCESS_KEYS", findingDelayDays: delayDays }
    : { mode: "REVIEW_ONLY", findingDelayDays: 0 };
  const unchanged = nextDisposition.mode === analyzer.disposition.mode &&
    nextDisposition.findingDelayDays === analyzer.disposition.findingDelayDays;
  const save = async () => {
    if (invalidDelay || unchanged) return;
    await onSave(nextDisposition);
  };

  if (step === "edit") return <Card>
    <Card.Header><div><Typography.Title as="h2" level={3}>{t("editTitle")}</Typography.Title><Typography.Text tone="muted">{t("configurationHint")}</Typography.Text></div><Badge status="info">{t("live")}</Badge></Card.Header>
    <Card.Body className={styles.detail}>
      <Alert status="info">{t("liveWorkflowBoundary")}</Alert>
      <RadioGroup disabled={busy} label={t("mode")} value={mode} onValueChange={(value) => setMode(value as AccessDispositionRule["mode"])} options={(["REVIEW_ONLY", "DISABLE_UNUSED_ACCESS_KEYS"] as const).map((value) => ({ value, label: t(`modes.${value}`) }))} />
      {automatic ? <FormField id={`${id}-live-delay`} label={t("delay")} hint={t("delayHint")} error={invalidDelay ? t("delayInvalid") : undefined}><Input id={`${id}-live-delay`} disabled={busy} required type="number" min={1} max={30} step={1} invalid={invalidDelay} aria-describedby={`${id}-live-delay-hint${invalidDelay ? ` ${id}-live-delay-error` : ""}`} value={delayValue} onChange={(event) => setDelayValue(event.target.value)} /></FormField> : <Alert status="info">{t("reviewOnlyMeaning")}</Alert>}
      <Alert status="warning">{t("scopeBoundary")}</Alert>
      <Alert status="info">{t("permissionBoundary")}</Alert>
    </Card.Body>
    <Card.Footer><div className={styles.actions}><Button disabled={busy || invalidDelay || unchanged} onClick={() => setStep("review")}>{t("review")}</Button><Button variant="secondary" disabled={busy} onClick={() => setStep("summary")}>{t("cancel")}</Button></div></Card.Footer>
  </Card>;

  if (step === "review") return <Card>
    <Card.Header><div><Typography.Title as="h2" level={3}>{t("reviewTitle")}</Typography.Title><Typography.Text tone="muted">{t("reviewHint")}</Typography.Text></div><Badge status="warning">{t("liveWriteReview")}</Badge></Card.Header>
    <Card.Body className={styles.detail}>
      <dl className={styles.facts}>
        <div><dt>{t("account")}</dt><dd><code>{analyzer.accountId}</code></dd></div>
        <div><dt>{t("analyzerId")}</dt><dd><code>{analyzer.id}</code></dd></div>
        <div><dt>{t("nextResourceVersion")}</dt><dd>{analyzer.resourceVersion + 1}</dd></div>
        <div><dt>{t("mode")}</dt><dd className={styles.dispositionFact}><code>{nextDisposition.mode}</code><small>{t(`modes.${nextDisposition.mode}`)}</small></dd></div>
        <div><dt>{t("eligibleFinding")}</dt><dd><code>UNUSED_ACCESS_KEY</code></dd></div>
        <div><dt>{t("effect")}</dt><dd className={styles.dispositionFact}>{automatic ? <><code>DISABLE_ACCESS_KEY</code><small>{t("disableMeaning")}</small></> : t("noWriteEffect")}</dd></div>
        <div><dt>{t("delay")}</dt><dd>{automatic ? t("days", { count: delayDays }) : t("notApplicable")}</dd></div>
        <div><dt>{t("permission")}</dt><dd><code>iam.access-analyzer.set-disposition</code></dd></div>
      </dl>
      <Alert status="warning">{t("reviewBoundary")}</Alert>
      <Alert status="info">{t("safeguardsBoundary")}</Alert>
    </Card.Body>
    <Card.Footer><div className={styles.actions}><Button disabled={busy} onClick={() => void save()}>{t("applyLive")}</Button><Button variant="secondary" disabled={busy} onClick={() => setStep("edit")}>{t("backToEdit")}</Button></div></Card.Footer>
  </Card>;

  return <Card>
    <Card.Header><div><Typography.Title as="h2" level={3}>{t("title")}</Typography.Title><Typography.Text tone="muted">{t("liveHint")}</Typography.Text></div><Badge status={analyzer.disposition.mode === "REVIEW_ONLY" ? "neutral" : "warning"}>{t(`modes.${analyzer.disposition.mode}`)}</Badge></Card.Header>
    <Card.Body className={styles.detail}>
      <dl className={styles.facts}>
        <div><dt>{t("mode")}</dt><dd><code>{analyzer.disposition.mode}</code></dd></div>
        <div><dt>{t("eligibleFinding")}</dt><dd><code>UNUSED_ACCESS_KEY</code></dd></div>
        <div><dt>{t("effect")}</dt><dd>{analyzer.disposition.mode === "DISABLE_UNUSED_ACCESS_KEYS" ? <code>DISABLE_ACCESS_KEY</code> : t("noWriteEffect")}</dd></div>
        <div><dt>{t("delay")}</dt><dd>{analyzer.disposition.mode === "DISABLE_UNUSED_ACCESS_KEYS" ? t("days", { count: analyzer.disposition.findingDelayDays }) : t("notApplicable")}</dd></div>
        <div><dt>{t("permission")}</dt><dd><code>iam.access-analyzer.set-disposition</code></dd></div>
      </dl>
      <Alert status="warning">{t("summaryBoundary")}</Alert>
    </Card.Body>
    <Card.Footer><Button variant="secondary" disabled={busy} onClick={() => setStep("edit")}>{t("editLive")}</Button></Card.Footer>
  </Card>;
}
