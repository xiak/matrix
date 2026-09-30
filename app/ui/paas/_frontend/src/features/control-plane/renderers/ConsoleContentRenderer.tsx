import { Suspense, useCallback, useEffect, useLayoutEffect, useRef, useState, type MutableRefObject } from "react";
import { useSearchParams } from "next/navigation";
import { ConsoleLink as Link, useConsoleNavigation } from "../routes/ConsoleNavigation";
import { AccountAccessRenderer } from "@/features/auth/renderers/AccountAccessRenderer";
import {
  ArrowRight,
  ArrowLeft,
  CheckCircle2,
  Cpu,
  Database,
  HardDrive,
  MapPin,
  PackageCheck,
  Server,
  ShieldCheck
} from "lucide-react";
import {
  Alert,
  Table,
  TableSkeleton,
  PageSkeleton,
  EmptyState,
  Badge,
  Button,
  Card,
  ContentLayout,
  Typography
} from "@ui/xiak";
import type {
  ConsoleContentScene,
  InstallationScene,
  SceneStatus
} from "../scenes/consoleScene";
import { ExperienceContentRenderer, type ResourceScope } from "./ExperienceContentRenderer";
import styles from "./ConsoleContentRenderer.module.css";
import { ConsoleMetrics } from "./ConsoleMetrics";
import { useConsoleFormat } from "./useConsoleFormat";
import { useTranslations } from "next-intl";
import { LogServiceRenderer } from "./LogServiceRenderer";
import { MessageCenterRenderer } from "./MessageCenterRenderer";
import { ServiceAuthorizationChain } from "@/features/auth/renderers/ServiceAuthorizationChain";
import { ServiceAuthorizationConsentReview } from "@/features/auth/renderers/ServiceAuthorizationPreview";
import { useControlPlane } from "../application/ControlPlaneProvider";
import type { ManagedServiceAuthorizationLoad } from "../domain/serviceAuthorization";

function InstallationRows({ items, onOpen, triggerRefs }: {
  items: InstallationScene[];
  onOpen?(item: InstallationScene): void;
  triggerRefs?: MutableRefObject<Map<string, HTMLButtonElement>>;
}) {
  const t = useTranslations("ManagedService");
  const format = useConsoleFormat();
  if (items.length === 0) {
    return (
      <EmptyState
        description={t("instancesEmptyHint")}
        title={t("instancesEmpty")}
      />
    );
  }
  return (
    <Table aria-label={t("instancesTable")} mobileLayout="grid">
        <thead>
          <tr><th scope="col">{t("instance")}</th><th scope="col">{t("region")}</th><th scope="col">{t("status")}</th><th scope="col">{t("endpoint")}</th><th scope="col">{t("observed")}</th></tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <td>{onOpen ? <button className={styles.instanceLink} ref={(node) => {
                if (node) triggerRefs?.current.set(item.id, node);
                else triggerRefs?.current.delete(item.id);
              }} onClick={() => onOpen(item)}>{item.name}</button> : <strong>{item.name}</strong>}<small>{item.engine}</small></td>
              <td data-label={t("region")}>{item.regionName}</td>
              <td data-label={t("status")}><Badge status={item.status}>{t(`installationPhases.${item.phase}`)}</Badge></td>
              <td data-label={t("endpoint")} data-mobile-span="full"><Typography.Code>{item.endpoint ?? t("unassigned")}</Typography.Code></td>
              <td data-label={t("observed")} data-mobile-span="full">{format.timestamp(item.observedAt)}</td>
            </tr>
          ))}
        </tbody>
      </Table>
  );
}

function OverviewContent({ scene }: { scene: Extract<ConsoleContentScene, { kind: "overview" }> }) {
  const t = useTranslations("ManagedService");
  return (
    <ContentLayout>
      <ContentLayout.Main>
        <ConsoleMetrics metrics={scene.metrics} />

        <Card>
          <Card.Header>
            <div>
              <Typography.Title as="h2" level={3}>{t("recentInstances")}</Typography.Title>
              <Typography.Text tone="muted">{t("recentHint")}</Typography.Text>
            </div>
            <Link className={styles.textLink} href="/console/installations/">
              {t("viewAll")} <ArrowRight aria-hidden="true" />
            </Link>
          </Card.Header>
          <InstallationRows items={scene.recentInstallations} />
        </Card>
      </ContentLayout.Main>

      <ContentLayout.Aside>
        <Card className={styles.featureCard}>
          <Card.Body className={styles.featureCardBody}>
            <div className={styles.databaseIcon}><Database aria-hidden="true" /></div>
            <Typography.Eyebrow>{t("databaseEyebrow")}</Typography.Eyebrow>
            <Typography.Title as="h2" level={2}>
              {scene.offering?.name ?? "PostgreSQL"}
            </Typography.Title>
            <p>{scene.offering?.description ?? t("offeringUnavailable")}</p>
            <div className={styles.featureMeta}>
              <span><PackageCheck aria-hidden="true" /> {t("fixedArtifact")}</span>
              <span><HardDrive aria-hidden="true" /> {t("persistentStorage")}</span>
              <span><CheckCircle2 aria-hidden="true" /> {t("managedCredentials")}</span>
            </div>
            <Button asChild><Link href="/console/catalog/">
              {t("browseCatalog")} <ArrowRight aria-hidden="true" />
            </Link></Button>
          </Card.Body>
        </Card>
      </ContentLayout.Aside>
    </ContentLayout>
  );
}

function CatalogContent({ scene }: { scene: Extract<ConsoleContentScene, { kind: "catalog" }> }) {
  const t = useTranslations("ManagedService");
  if (scene.offerings.length === 0) {
    return <EmptyState title={t("catalogUnavailable")} description={t("catalogUnavailableHint")} />;
  }
  return (
    <div className={styles.catalogGrid}>
      {scene.offerings.map((offering) => (
        <Card className={styles.productCard} key={offering.id}>
          <Card.Body className={styles.productCardBody}>
            <div className={styles.productTopline}>
              <div className={styles.databaseIcon}><Database aria-hidden="true" /></div>
              <Badge status={offering.available ? "success" : "neutral"}>
                {offering.available ? t("activatable") : t("unavailable")}
              </Badge>
            </div>
            <Typography.Eyebrow>{offering.engine}</Typography.Eyebrow>
            <Typography.Title as="h2" level={2}>{offering.name}</Typography.Title>
            <p className={styles.productDescription}>{offering.description}</p>
            <dl className={styles.productFacts}>
              <div><dt>{t("engineVersion")}</dt><dd>{offering.version}</dd></div>
              <div><dt>{t("quotaShapes")}</dt><dd>{t("shapeCount", { count: offering.shapeCount })}</dd></div>
              <div><dt>{t("availableShapes")}</dt><dd>{offering.shapeSummary}</dd></div>
            </dl>
          </Card.Body>
          <Card.Footer>
            <Typography.Text tone="subtle">{t("noPayment")}</Typography.Text>
            <Button asChild><Link href="/console/quotas/">
              {t("configureQuota")} <ArrowRight aria-hidden="true" />
            </Link></Button>
          </Card.Footer>
        </Card>
      ))}
    </div>
  );
}

function QuotaContent({ scene }: { scene: Extract<ConsoleContentScene, { kind: "quotas" }> }) {
  const t = useTranslations("ManagedService");
  const format = useConsoleFormat();
  if (scene.entitlements.length === 0) {
    return (
      <EmptyState
        title={t("quotaEmpty")}
        description={t("quotaEmptyHint")}
      />
    );
  }
  return (
    <div className={styles.cardList}>
      {scene.entitlements.map((item) => {
        const status: SceneStatus = item.available > 0 ? "success" : "warning";
        return (
          <Card key={item.id}>
            <Card.Body className={styles.quotaRow}>
              <div className={styles.quotaIdentity}>
                <Database aria-hidden="true" />
                <div><strong>{item.offeringName}</strong><span>{item.shapeName} · {format.resources(item.resources)}</span></div>
              </div>
              <div className={styles.quotaNumbers}>
                <div><small>{t("activated")}</small><strong>{format.number(item.purchased)}</strong></div>
                <div><small>{t("inUse")}</small><strong>{format.number(item.inUse)}</strong></div>
                <div><small>{t("available")}</small><strong>{format.number(item.available)}</strong></div>
              </div>
              <div className={styles.quotaStatus}>
                <Badge status={status}>{item.available > 0 ? t("installable") : t("exhausted")}</Badge>
                <small>{format.timestamp(item.activatedAt)}</small>
              </div>
            </Card.Body>
          </Card>
        );
      })}
    </div>
  );
}

function LiveServiceAuthorizationCard({ accountId, installationId }: {
  accountId: string;
  installationId: string;
}) {
  const t = useTranslations("ManagedService");
  const { inspectServiceAuthorization } = useControlPlane();
  const [result, setResult] = useState<ManagedServiceAuthorizationLoad | { status: "loading" }>({ status: "loading" });
  const revision = useRef(0);

  const inspect = useCallback(() => {
    const current = ++revision.current;
    setResult({ status: "loading" });
    void inspectServiceAuthorization(accountId, installationId).then((next) => {
      if (revision.current === current) setResult(next);
    });
  }, [accountId, inspectServiceAuthorization, installationId]);

  useEffect(() => {
    const current = ++revision.current;
    void inspectServiceAuthorization(accountId, installationId).then((next) => {
      if (revision.current === current) setResult(next);
    });
    return () => { revision.current += 1; };
  }, [accountId, inspectServiceAuthorization, installationId]);

  const observation = result.status === "ready" ? result.observation : null;
  const accountAuthorized = observation?.relation?.role.status === "ACTIVE";
  const instanceBound = observation?.binding?.status === "ACTIVE";
  const authorized = Boolean(accountAuthorized && instanceBound);
  const stateLabel = result.status === "loading" ? t("authorizationChecking")
    : result.status === "ready" ? t(authorized ? "authorizationActive" : "authorizationPending")
      : t("authorizationUnavailableState");

  return <Card aria-label={t("serviceAuthorization")} className={styles.authorizationCard}>
    <Card.Header className={styles.authorizationHeading}>
      <span><ShieldCheck aria-hidden="true" /></span>
      <div><Typography.Eyebrow>{t("authorizationLiveEyebrow")}</Typography.Eyebrow><Typography.Title as="h3" level={3}>{t("serviceAuthorization")}</Typography.Title><Typography.Text tone="muted">{t("serviceAuthorizationHint")}</Typography.Text></div>
      <Badge status={authorized ? "success" : result.status === "ready" ? "info" : "neutral"}>{stateLabel}</Badge>
    </Card.Header>
    <Card.Body className={styles.authorizationBody} aria-busy={result.status === "loading"}>
      {result.status === "loading" ? <TableSkeleton header={false} label={t("authorizationLoading")} rows={2} /> : null}
      {result.status === "expired" || result.status === "forbidden" || result.status === "unavailable" ? <>
        <Alert status={result.status === "forbidden" ? "warning" : "danger"}>{t(`authorizationErrors.${result.status}`)}</Alert>
        {result.status === "unavailable" ? <div><Button onClick={inspect} variant="secondary">{t("retryAuthorization")}</Button></div> : null}
      </> : null}
      {observation ? <>
        <ServiceAuthorizationChain
          template={{ label: t("publishedTemplate", { version: observation.template.version }), tone: "success" }}
          account={{ label: accountAuthorized ? t("accountAuthorized") : t("accountAuthorizationPending"), tone: accountAuthorized ? "success" : undefined }}
          binding={{ label: instanceBound ? t("instanceBound") : t("resourceNotBound"), tone: instanceBound ? "success" : undefined }}
        />
        <dl className={styles.authorizationFacts}>
          <div><dt>{t("authorizationTemplate")}</dt><dd><Typography.Code>{observation.template.id}@v{observation.template.version}</Typography.Code><small><Typography.Code>{observation.template.contentDigest}</Typography.Code></small></dd></div>
          <div><dt>{t("authorizationPermissionCeiling")}</dt><dd><Typography.Code>{observation.template.spec.policyVersion.policyId}</Typography.Code><small><Typography.Code>{observation.template.spec.policyVersion.versionId}</Typography.Code></small></dd></div>
          <div><dt>{t("authorizationBinding")}</dt><dd>{observation.binding ? <Typography.Code>{observation.binding.id}</Typography.Code> : t("resourceNotBound")}<small>{observation.relation ? <Typography.Code>{observation.relation.role.id}</Typography.Code> : t("accountAuthorizationPending")}</small></dd></div>
        </dl>
        <Alert status={authorized ? "info" : "warning"}>{t(authorized ? "authorizationObservedBoundary" : "authorizationReleaseBoundary")}</Alert>
        <div className={styles.authorizationActions}>
          <Button disabled title={t("authorizationReleaseBoundary")}>{t(authorized ? "authorizationAlreadyActive" : "authorizePendingRelease")}</Button>
          <Link className={styles.textLink} href="/console/access/roles/">{t("openIamObservation")} <ArrowRight aria-hidden="true" /></Link>
        </div>
      </> : null}
    </Card.Body>
  </Card>;
}

function InstallationContent({ scene, preview, accountId }: {
  scene: Extract<ConsoleContentScene, { kind: "installations" }>;
  preview: boolean;
  accountId?: string;
}) {
  const t = useTranslations("ManagedService");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [review, setReview] = useState(false);
  const [stage, setStage] = useState(0);
  const [previewAuthorizedIds, setPreviewAuthorizedIds] = useState<Set<string>>(() => new Set());
  const heading = useRef<HTMLHeadingElement>(null);
  const authorizationTrigger = useRef<HTMLButtonElement>(null);
  const rowTriggers = useRef(new Map<string, HTMLButtonElement>());
  const returnToList = useRef<string | null>(null);
  const selected = scene.installations.find((item) => item.id === selectedId) ?? null;

  useLayoutEffect(() => {
    if (selected) {
      heading.current?.focus({ preventScroll: true });
      return;
    }
    if (!returnToList.current) return;
    const id = returnToList.current;
    returnToList.current = null;
    rowTriggers.current.get(id)?.focus({ preventScroll: true });
  }, [review, selected]);

  if (selected) {
    const previewAuthorized = previewAuthorizedIds.has(selected.id);
    const closeDetail = () => {
      if (review) {
        setReview(false);
        window.setTimeout(() => authorizationTrigger.current?.focus({ preventScroll: true }), 0);
        return;
      }
      returnToList.current = selected.id;
      setSelectedId(null);
    };
    return <section className={styles.installationDetail} aria-labelledby="managed-service-installation-detail-title">
      <div className={styles.detailHeading}>
        <Button variant="ghost" size="small" onClick={closeDetail}><ArrowLeft aria-hidden="true" />{t(review ? "backToInstance" : "backToInstances")}</Button>
        <div><Typography.Eyebrow>{t(review ? "authorizationEyebrow" : "instanceEyebrow")}</Typography.Eyebrow><h2 className={styles.detailTitle} id="managed-service-installation-detail-title" ref={heading} tabIndex={-1}>{review ? t("authorizationTitle", { name: selected.name }) : selected.name}</h2></div>
        <Badge status={review ? "warning" : selected.status}>{review ? "MOCK" : t(`installationPhases.${selected.phase}`)}</Badge>
      </div>

      {review && accountId ? <>
        <Alert status="warning">{t("authorizationPreviewBoundary")}</Alert>
        <ServiceAuthorizationConsentReview accountId={accountId} targetResourceId={selected.id} stage={stage} onStageChange={setStage} onClose={closeDetail} onPreviewAuthorize={preview ? () => {
          setPreviewAuthorizedIds((current) => new Set(current).add(selected.id));
          setReview(false);
          window.setTimeout(() => authorizationTrigger.current?.focus({ preventScroll: true }), 0);
        } : undefined} />
      </> : <>
        <dl className={styles.installationFacts}>
          <div><dt>{t("instanceId")}</dt><dd><Typography.Code>{selected.id}</Typography.Code></dd></div>
          <div><dt>{t("region")}</dt><dd>{selected.regionName}</dd></div>
          <div><dt>{t("status")}</dt><dd><Badge status={selected.status}>{t(`installationPhases.${selected.phase}`)}</Badge></dd></div>
          <div><dt>{t("endpoint")}</dt><dd><Typography.Code>{selected.endpoint ?? t("unassigned")}</Typography.Code></dd></div>
          <div><dt>{t("operationId")}</dt><dd><Typography.Code>{selected.operationId}</Typography.Code></dd></div>
        </dl>
        {preview && accountId ? <Card className={styles.authorizationCard}>
          <Card.Header className={styles.authorizationHeading}><span><ShieldCheck aria-hidden="true" /></span><div><Typography.Eyebrow>{t("authorizationEyebrow")}</Typography.Eyebrow><Typography.Title as="h3" level={3}>{t("serviceAuthorization")}</Typography.Title><Typography.Text tone="muted">{t("serviceAuthorizationHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header>
          <Card.Body className={styles.authorizationBody}>
            <ServiceAuthorizationChain template={{ label: t("illustrativeTemplate"), tone: "warning" }} account={{ label: t(previewAuthorized ? "previewAccountAuthorized" : "accountNotAuthorized"), tone: previewAuthorized ? "success" : undefined }} binding={{ label: t(previewAuthorized ? "previewInstanceBound" : "resourceNotBound"), tone: previewAuthorized ? "success" : undefined }} />
            <Alert status={previewAuthorized ? "success" : "info"}>{t(previewAuthorized ? "previewAuthorizationApplied" : "productEntryHint")}</Alert>
            {previewAuthorized ? <dl className={styles.authorizationFacts}>
              <div><dt>{t("authorizationTemplate")}</dt><dd><Typography.Code>preview.service-role-template.managed-service-installation-read.v1@v1</Typography.Code></dd></div>
              <div><dt>{t("authorizationBinding")}</dt><dd><Typography.Code>preview.workload-role-binding.{selected.id}</Typography.Code></dd></div>
              <div><dt>{t("instanceId")}</dt><dd><Typography.Code>{selected.id}</Typography.Code><small>MOCK · {t("previewBrowserOnly")}</small></dd></div>
            </dl> : null}
            <div><Button ref={authorizationTrigger} onClick={() => { setStage(0); setReview(true); }}>{t(previewAuthorized ? "reviewAuthorizationAgain" : "reviewAuthorization")}</Button></div>
          </Card.Body>
        </Card> : accountId ? <LiveServiceAuthorizationCard accountId={accountId} installationId={selected.id} /> : null}
      </>}
    </section>;
  }

  return (
    <Card>
      <Card.Header>
        <div>
          <Typography.Title as="h2" level={3}>{t("organizationInstances")}</Typography.Title>
          <Typography.Text tone="muted">{t("installationStateHint")}</Typography.Text>
        </div>
        <Badge status="info">{t("instanceCount", { count: scene.installations.length })}</Badge>
      </Card.Header>
      <InstallationRows items={scene.installations} onOpen={accountId ? (item) => setSelectedId(item.id) : undefined} triggerRefs={rowTriggers} />
    </Card>
  );
}

function RegionContent({ scene }: { scene: Extract<ConsoleContentScene, { kind: "regions" }> }) {
  const t = useTranslations("ManagedService");
  const format = useConsoleFormat();
  if (scene.regions.length === 0) {
    return <EmptyState title={t("regionsEmpty")} description={t("regionsEmptyHint")} />;
  }
  return (
    <div className={styles.regionGrid}>
      {scene.regions.map((region) => (
        <Card key={region.id}>
          <Card.Body className={styles.regionCard}>
            <div className={styles.regionIcon}><MapPin aria-hidden="true" /></div>
            <div className={styles.regionHeading}>
              <div><Typography.Title as="h2" level={3}>{region.name}</Typography.Title><span>{t("localProfile")}</span></div>
              <Badge status={region.status}>{t(`regionStates.${region.state}`)}</Badge>
            </div>
            <div className={styles.regionFacts}>
              <span><Cpu aria-hidden="true" /> {format.resources(region.capacity)}</span>
              <span><Server aria-hidden="true" /> {t("lastInspection")} {format.timestamp(region.inspectedAt)}</span>
            </div>
            <p>{t("regionSecurityHint")}</p>
          </Card.Body>
        </Card>
      ))}
    </div>
  );
}

function AccessContent({ pendingHref, view }: { pendingHref?: string | null; view: Extract<ConsoleContentScene, { kind: "access" }>["view"] }) {
  const { navigate } = useConsoleNavigation();
  const currentParams = useSearchParams();
  const params = pendingHref ? new URL(pendingHref, "https://matrix.invalid").searchParams : currentParams;
  const entityId = params.get("id") ?? undefined;
  const policyMethod = view === "create-policy" ? params.get("method") ?? undefined : undefined;
  return <AccountAccessRenderer key={view + ":" + (entityId ?? "") + ":" + (policyMethod ?? "")} view={view} entityId={entityId} policyMethod={policyMethod} onNavigate={(next, id, method) => {
    const query = new URLSearchParams();
    if (id) query.set("id", id);
    if (next === "create-policy" && method) query.set("method", method);
    navigate((next === "overview" ? "/console/access/" : `/console/access/${next}/`) + (query.size ? "?" + query.toString() : ""));
  }} />;
}

export function ConsoleContentRenderer({
  accountId,
  pendingHref,
  preview = false,
  scene,
  scope
}: {
  accountId?: string;
  pendingHref?: string | null;
  preview?: boolean;
  scene: ConsoleContentScene;
  scope?: ResourceScope;
}) {
  const t = useTranslations("AccountAccess");
  if (scene.kind === "logs") return <LogServiceRenderer regionId={scope?.regionId} scene={scene} />;
  if (scene.kind === "access") return <Suspense fallback={<PageSkeleton layout="access" label={t("loading")} />}><AccessContent pendingHref={pendingHref} view={scene.view} /></Suspense>;
  if (scene.kind === "messages") return <MessageCenterRenderer scene={scene} />;
  if (
    scene.kind === "cloud-overview" ||
    scene.kind === "resources" ||
    scene.kind === "operations" ||
    scene.kind === "devops" ||
    scene.kind === "observability"
  ) {
    return <ExperienceContentRenderer scene={scene} scope={scope} />;
  }
  if (scene.kind === "overview") return <OverviewContent scene={scene} />;
  if (scene.kind === "catalog") return <CatalogContent scene={scene} />;
  if (scene.kind === "quotas") return <QuotaContent scene={scene} />;
  if (scene.kind === "installations") return <InstallationContent scene={scene} preview={preview} accountId={accountId} />;
  return <RegionContent scene={scene} />;
}
