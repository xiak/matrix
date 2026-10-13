import { Suspense, useCallback, useEffect, useId, useLayoutEffect, useRef, useState, type MutableRefObject } from "react";
import { useSearchParams } from "next/navigation";
import { ConsoleLink as Link, useConsoleNavigation } from "../routes/ConsoleNavigation";
import { AccountAccessRenderer } from "@/features/auth/renderers/AccountAccessRenderer";
import type { AccountUserDetailTab } from "@/features/auth/renderers/AccountUserWorkspace";
import {
  ArrowRight,
  ArrowLeft,
  CheckCircle2,
  Cpu,
  Database,
  HardDrive,
  MapPin,
  MessagesSquare,
  PackageCheck,
  Search,
  Server,
  ShieldCheck,
  Trash2
} from "lucide-react";
import {
  Alert,
  Table,
  TableSkeleton,
  EmptyState,
  Badge,
  Button,
  Card,
  ContentLayout,
  FormField,
  Input,
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
import { ServiceAuthorizationConsentReview, ServiceAuthorizationUnbindReview } from "@/features/auth/renderers/ServiceAuthorizationPreview";
import { AuditWorkspace } from "@/features/audit/renderers/AuditWorkspace";
import { useControlPlane } from "../application/ControlPlaneProvider";
import { ConsoleContentLoadingRenderer } from "./ConsoleContentLoadingRenderer";
import type {
  ManagedServiceAuthorizationIntent,
  ManagedServiceAuthorizationLoad
} from "../domain/serviceAuthorization";
import type { InstallationReadLoad, InstallationTerminationIntent, ServiceInstallation, ServiceOffering } from "../domain/resources";
import { isManagedServiceProductId } from "../domain/managedServiceProduct";
import { consoleRouteHref } from "../domain/selection";

type InstallationDetailLoad =
  | { status: "idle" | "loading" }
  | InstallationReadLoad;

function installationDetailScene(summary: InstallationScene, installation: ServiceInstallation): InstallationScene {
  const status: SceneStatus = installation.phase === "READY"
    ? "success"
    : ["FAILED", "ROLLBACK_FAILED", "TERMINATION_FAILED"].includes(installation.phase)
      ? "danger"
      : ["PROVISIONING", "TERMINATING"].includes(installation.phase)
        ? "info"
        : installation.phase === "TERMINATED" ? "neutral" : "warning";
  return {
    ...summary,
    id: installation.id,
    name: installation.name,
    offeringId: installation.offeringId,
    phase: installation.phase,
    status,
    endpoint: installation.endpoint,
    operationId: installation.operation.id,
    operationKind: installation.operation.kind,
    safeFailureCode: installation.operation.safeFailureCode,
    resourceVersion: installation.resourceVersion,
    createdAt: installation.createdAt,
    observedAt: installation.operation.observedAt
  };
}

function OfferingIcon({ serviceId }: { serviceId: ServiceOffering["service"]["id"] }) {
  if (serviceId === "elasticsearch") return <Search aria-hidden="true" />;
  if (serviceId === "rabbitmq") return <MessagesSquare aria-hidden="true" />;
  return <Database aria-hidden="true" />;
}

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
            <div className={styles.databaseIcon}>{scene.offering ? <OfferingIcon serviceId={scene.offering.serviceId} /> : <Database aria-hidden="true" />}</div>
            <Typography.Eyebrow>{t("databaseEyebrow")}</Typography.Eyebrow>
            <Typography.Title as="h2" level={2}>
              {scene.offering?.name ?? t("managedDataServices")}
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

function CatalogContent({ scene, preview }: {
  scene: Extract<ConsoleContentScene, { kind: "catalog" }>;
  preview: boolean;
}) {
  const t = useTranslations("ManagedService");
  return (
    <div className={styles.catalogPage}>
      <Alert status={preview ? "warning" : "info"}>
        {t(preview ? "catalogVisibilityMockBoundary" : "catalogVisibilityBoundary", { count: scene.offerings.length })}
      </Alert>
      {scene.offerings.length === 0 ? <EmptyState title={t("catalogEmpty")} description={t("catalogEmptyHint")} /> : <div className={styles.catalogGrid}>
        {scene.offerings.map((offering) => (
          <Card className={styles.productCard} key={offering.id}>
            <Card.Header className={styles.productCardHeader}>
              <div className={styles.productIdentity}>
                <div className={styles.databaseIcon}><OfferingIcon serviceId={offering.serviceId} /></div>
                <div className={styles.productHeading}>
                  <Typography.Eyebrow>{offering.engine}</Typography.Eyebrow>
                  <Typography.Title as="h2" level={3}>{offering.name}</Typography.Title>
                </div>
              </div>
              <Badge status={offering.available ? "success" : "neutral"}>
                {offering.available ? t("activatable") : t("unavailable")}
              </Badge>
            </Card.Header>
            <Card.Body className={styles.productCardBody}>
              <p className={styles.productDescription}>{offering.description}</p>
              <dl className={styles.productFacts}>
                <div><dt>{t("engineVersion")}</dt><dd>{offering.version}</dd></div>
                <div><dt>{t("quotaShapes")}</dt><dd>{t("shapeCount", { count: offering.shapeCount })}</dd></div>
                <div><dt>{t("availableShapes")}</dt><dd>{offering.shapeSummary}</dd></div>
              </dl>
            </Card.Body>
            <Card.Footer className={styles.productCardFooter}>
              <Typography.Text tone="subtle">{t("serviceEntryHint")}</Typography.Text>
              {isManagedServiceProductId(offering.serviceId) ? <Button asChild><Link aria-label={t("openServiceNamed", { name: offering.name })} href={consoleRouteHref({ section: "catalog", product: offering.serviceId })}>
                {t("openService")} <ArrowRight aria-hidden="true" />
              </Link></Button> : <Typography.Text tone="subtle">{t("servicePageUnsupported")}</Typography.Text>}
            </Card.Footer>
          </Card>
        ))}
      </div>}
    </div>
  );
}

function ManagedProductContent({ preview, scene }: {
  preview: boolean;
  scene: Extract<ConsoleContentScene, { kind: "managed-product" }>;
}) {
  const t = useTranslations("ManagedService");
  const directory = useTranslations("ServiceDirectory");
  const productName = directory(`services.${scene.productId}.name`);
  const instanceHref = `/console/products/${scene.productId}/instances/`;
  const quotaHref = `/console/products/${scene.productId}/quotas/`;

  return (
    <div className={styles.productOverview}>
      <Alert status={preview ? "warning" : "info"}>{t(preview ? "productMockBoundary" : "productLiveBoundary")}</Alert>
      <Card className={styles.productOverviewCard}>
        <Card.Header className={styles.productOverviewHeader}>
          <div className={styles.productIdentity}>
            <div className={styles.databaseIcon}>{scene.offering ? <OfferingIcon serviceId={scene.offering.serviceId} /> : <Database aria-hidden="true" />}</div>
            <div className={styles.productHeading}>
              <Typography.Eyebrow>{t("managedCloudService")}</Typography.Eyebrow>
              <Typography.Title as="h2" level={2}>{productName}</Typography.Title>
            </div>
          </div>
          <Badge status={scene.offering?.available ? "success" : "neutral"}>
            {scene.offering?.available ? t(preview ? "previewCandidate" : "activatable") : t("unavailable")}
          </Badge>
        </Card.Header>
        <Card.Body className={styles.productOverviewBody}>
          <p className={styles.productDescription}>{scene.offering?.description ?? t("offeringUnavailable")}</p>
          <dl className={styles.productOverviewFacts}>
            <div><dt>{t("offeringId")}</dt><dd><Typography.Code>{scene.offering?.id ?? "—"}</Typography.Code></dd></div>
            <div><dt>{t("engineVersion")}</dt><dd>{scene.offering?.version ?? "—"}</dd></div>
            <div><dt>{t("activatedQuota")}</dt><dd>{scene.purchasedQuota}</dd></div>
            <div><dt>{t("availableQuota")}</dt><dd>{scene.availableQuota}</dd></div>
            <div><dt>{t("instances")}</dt><dd>{scene.instanceCount}</dd></div>
            <div><dt>{t("readyInstances")}</dt><dd>{scene.readyInstanceCount}</dd></div>
          </dl>
        </Card.Body>
        <Card.Footer className={styles.productOverviewFooter}>
          <Typography.Text tone="subtle">{t("productOwnershipHint")}</Typography.Text>
          <div>
            <Button asChild variant="secondary"><Link href={quotaHref}>{t("configureQuota")}</Link></Button>
            <Button asChild><Link href={instanceHref}>{t("openInstances")} <ArrowRight aria-hidden="true" /></Link></Button>
          </div>
        </Card.Footer>
      </Card>

      <Card>
        <Card.Header>
          <div>
            <Typography.Title as="h2" level={3}>{t("gettingStarted")}</Typography.Title>
            <Typography.Text tone="muted">{t("gettingStartedHint")}</Typography.Text>
          </div>
        </Card.Header>
        <Card.Body>
          <ol className={styles.productSteps}>
            {(["quota", "instance", "connect", "authorize"] as const).map((step, index) => (
              <li key={step}>
                <span>{index + 1}</span>
                <div><strong>{t(`steps.${step}.title`)}</strong><p>{t(`steps.${step}.hint`)}</p></div>
              </li>
            ))}
          </ol>
        </Card.Body>
      </Card>
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

function LiveServiceAuthorizationCard({ accountId, installationId, authorizationTrigger, unbindTrigger }: {
  accountId: string;
  installationId: string;
  authorizationTrigger: MutableRefObject<HTMLButtonElement | null>;
  unbindTrigger: MutableRefObject<HTMLButtonElement | null>;
}) {
  const t = useTranslations("ManagedService");
  const {
    beginServiceAuthorization,
    inspectServiceAuthorization,
    reopenServiceAuthorizationIntent,
    serviceAuthorizationIntent
  } = useControlPlane();
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
  const currentIntent = serviceAuthorizationIntent?.installationId === installationId ? serviceAuthorizationIntent : null;
  const blockedByAnotherIntent = Boolean(serviceAuthorizationIntent && !currentIntent);
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
          runtime={{ label: t("runtimeNotObserved") }}
        />
        <dl className={styles.authorizationFacts}>
          <div><dt>{t("authorizationTemplate")}</dt><dd><Typography.Code>{observation.template.id}@v{observation.template.version}</Typography.Code><small><Typography.Code>{observation.template.contentDigest}</Typography.Code></small></dd></div>
          <div><dt>{t("authorizationPermissionCeiling")}</dt><dd><Typography.Code>{observation.template.spec.policyVersion.policyId}</Typography.Code><small><Typography.Code>{observation.template.spec.policyVersion.versionId}</Typography.Code></small></dd></div>
          <div><dt>{t("authorizationBinding")}</dt><dd>{observation.binding ? <Typography.Code>{observation.binding.id}</Typography.Code> : t("resourceNotBound")}<small>{observation.relation ? <Typography.Code>{observation.relation.role.id}</Typography.Code> : t("accountAuthorizationPending")}</small></dd></div>
        </dl>
        <Alert status={authorized ? "info" : "warning"}>{t(authorized ? "authorizationObservedBoundary" : "authorizationWriteBoundary")}</Alert>
        {currentIntent && !currentIntent.open ? <Alert status="warning">{t("authorizationUnknownPreserved", { id: currentIntent.requestId })}</Alert> : null}
        {blockedByAnotherIntent ? <Alert status="warning">{t("authorizationAnotherIntent", { id: serviceAuthorizationIntent!.installationId })}</Alert> : null}
        <div className={styles.authorizationActions}>
          {currentIntent && !currentIntent.open ? <Button ref={currentIntent.kind === "unbind" ? unbindTrigger : authorizationTrigger} onClick={reopenServiceAuthorizationIntent}>{t("resumeAuthorization")}</Button>
            : <Button
              ref={authorized ? unbindTrigger : authorizationTrigger}
              disabled={blockedByAnotherIntent}
              onClick={() => beginServiceAuthorization(accountId, installationId, observation, authorized ? "unbind" : "bind")}
              variant={authorized ? "danger" : "primary"}
            >{t(authorized ? "reviewLiveUnbind" : accountAuthorized ? "reviewLiveBinding" : "reviewLiveAuthorization")}</Button>}
          <Link className={styles.textLink} href="/console/access/roles/">{t("openIamObservation")} <ArrowRight aria-hidden="true" /></Link>
        </div>
      </> : null}
    </Card.Body>
  </Card>;
}

function LiveServiceAuthorizationReview({ intent, onClose }: {
  intent: ManagedServiceAuthorizationIntent;
  onClose(): void;
}) {
  const t = useTranslations("ManagedService");
  const { submitServiceAuthorization, managedServiceCommand } = useControlPlane();
  const submitting = intent.phase === "submitting";
  const retryable = intent.phase === "review";
  const isBind = intent.kind === "bind";
  const relationActive = intent.relation?.role.status === "ACTIVE";

  return <Card className={styles.authorizationCard}>
    <Card.Header className={styles.authorizationHeading}>
      <span><ShieldCheck aria-hidden="true" /></span>
      <div><Typography.Eyebrow>{t("authorizationLiveWriteEyebrow")}</Typography.Eyebrow><Typography.Title as="h3" level={3}>{t(isBind ? "confirmLiveAuthorization" : "confirmLiveUnbind")}</Typography.Title><Typography.Text tone="muted">{t(isBind ? "confirmLiveAuthorizationHint" : "confirmLiveUnbindHint")}</Typography.Text></div>
      <Badge status={isBind ? "info" : "warning"}>{t(isBind ? "bindingAction" : "unbindingAction")}</Badge>
    </Card.Header>
    <Card.Body className={styles.authorizationBody} aria-busy={submitting}>
      <ServiceAuthorizationChain
        template={{ label: t("publishedTemplate", { version: intent.template.version }), tone: "success" }}
        account={{ label: relationActive ? t("accountAuthorized") : t("accountCreatedOnConfirmation"), tone: relationActive ? "success" : "neutral" }}
        binding={{ label: isBind ? t("bindingCreatedOnConfirmation") : t("instanceBound"), tone: isBind ? "neutral" : "success" }}
        runtime={{ label: t("runtimeNotObserved") }}
      />
      <dl className={styles.authorizationFacts}>
        <div><dt>{t("instanceId")}</dt><dd><Typography.Code>{intent.installationId}</Typography.Code><small>{t("exactWorkloadBoundary")}</small></dd></div>
        <div><dt>{t("authorizationTemplate")}</dt><dd><Typography.Code>{intent.template.id}@v{intent.template.version}</Typography.Code><small><Typography.Code>{intent.template.contentDigest}</Typography.Code></small></dd></div>
        <div><dt>{t("authorizationPermissionCeiling")}</dt><dd><Typography.Code>{intent.template.spec.policyVersion.policyId}</Typography.Code><small><Typography.Code>{intent.template.spec.policyVersion.versionId}</Typography.Code></small></dd></div>
        <div><dt>{t("authorizationAccount")}</dt><dd><Typography.Code>{intent.accountId}</Typography.Code><small>{t("accountDerivedBoundary")}</small></dd></div>
        <div><dt>{t("authorizationBinding")}</dt><dd>{intent.binding ? <Typography.Code>{intent.binding.id}</Typography.Code> : t("bindingNotCreated")}<small>{isBind ? t("bindAffectsExactResource") : t("unbindKeepsAccountRelation")}</small></dd></div>
        <div><dt>{t("authorizationRequest")}</dt><dd><Typography.Code>{intent.requestId}</Typography.Code><small>{t("idempotencyBoundary")}</small></dd></div>
      </dl>
      <Alert status={isBind ? "info" : "warning"}>{t(isBind ? "liveBindBoundary" : "liveUnbindBoundary")}</Alert>
      {intent.error && intent.error !== "unknown" ? <Alert status="danger">{t(`authorizationMutationErrors.${intent.error}`)}</Alert> : null}
      <div className={styles.authorizationActions}>
        {retryable ? <Button disabled={submitting || managedServiceCommand?.checking || managedServiceCommand?.phase === "unknown"}
          variant={isBind ? "primary" : "danger"} onClick={() => void submitServiceAuthorization()}>{t(submitting ? "authorizationSubmitting" : isBind ? "confirmAuthorization" : "confirmUnbind")}</Button> : null}
        <Button disabled={submitting} variant="secondary" onClick={onClose}>{t(intent.error === "unknown" ? "returnPreservingAuthorization" : "cancelAuthorization")}</Button>
      </div>
    </Card.Body>
  </Card>;
}

function InstallationTerminationReview({
  intent,
  onAccepted,
  onClose,
  preview
}: {
  intent: InstallationTerminationIntent;
  onAccepted(installation: ServiceInstallation): void;
  onClose(): void;
  preview: boolean;
}) {
  const t = useTranslations("ManagedService");
  const format = useConsoleFormat();
  const { submitInstallationTermination, managedServiceCommand } = useControlPlane();
  const [confirmation, setConfirmation] = useState("");
  const confirmationId = useId();
  const submitting = intent.phase === "submitting";
  const showSubmit = intent.phase === "review" || submitting;
  const confirmed = confirmation === intent.installation.id;

  return <Card aria-label={t("terminationReview")} className={styles.authorizationCard}>
    <Card.Header className={styles.authorizationHeading}>
      <span><Trash2 aria-hidden="true" /></span>
      <div>
        <Typography.Eyebrow>{t(preview ? "terminationPreviewEyebrow" : "terminationLiveEyebrow")}</Typography.Eyebrow>
        <Typography.Title as="h3" level={3}>{t("terminationReviewTitle", { name: intent.installation.name })}</Typography.Title>
        <Typography.Text tone="muted">{t("terminationReviewHint")}</Typography.Text>
      </div>
      <Badge status="warning">{preview ? "MOCK" : "LIVE"}</Badge>
    </Card.Header>
    <Card.Body className={styles.authorizationBody} aria-busy={submitting}>
      <Alert status="danger">{t(preview ? "terminationPreviewBoundary" : "terminationLiveBoundary")}</Alert>
      <dl className={styles.authorizationFacts}>
        <div><dt>{t("instanceId")}</dt><dd><Typography.Code>{intent.installation.id}</Typography.Code><small>{intent.installation.name}</small></dd></div>
        <div><dt>{t("product")}</dt><dd><Typography.Code>{intent.installation.offeringId}</Typography.Code><small>{intent.installation.engineVersion}</small></dd></div>
        <div><dt>{t("region")}</dt><dd><Typography.Code>{intent.installation.regionId}</Typography.Code></dd></div>
        <div><dt>{t("resourceVersion")}</dt><dd>{intent.installation.resourceVersion}<small>{t("terminationVersionObservation")}</small></dd></div>
        <div><dt>{t("authorizationRequest")}</dt><dd><Typography.Code>{intent.requestId}</Typography.Code><small>{t("idempotencyBoundary")}</small></dd></div>
        <div><dt>{t("createdAt")}</dt><dd>{format.timestamp(intent.installation.createdAt)}</dd></div>
      </dl>
      <FormField id={confirmationId} label={t("terminationConfirmationLabel")} hint={t("terminationConfirmationHint", { id: intent.installation.id })}>
        <Input
          autoComplete="off"
          id={confirmationId}
          onChange={(event) => setConfirmation(event.target.value)}
          placeholder={intent.installation.id}
          spellCheck={false}
          value={confirmation}
        />
      </FormField>
      {intent.error && intent.error !== "unknown" ? <Alert status="danger">{t(`terminationMutationErrors.${intent.error}`)}</Alert> : null}
      <div className={styles.authorizationActions}>
        {showSubmit ? <Button disabled={!confirmed || submitting || managedServiceCommand?.checking || managedServiceCommand?.phase === "unknown"} variant="danger" onClick={() => {
          void submitInstallationTermination().then((installation) => {
            if (installation) onAccepted(installation);
          });
        }}>{t(submitting ? "terminationSubmitting" : "confirmTermination")}</Button> : null}
        <Button disabled={submitting} variant="secondary" onClick={onClose}>{t(intent.error === "unknown" ? "returnPreservingTermination" : "cancelTermination")}</Button>
      </div>
    </Card.Body>
  </Card>;
}

function InstallationLifecycleCard({
  authorizationBusy,
  installation,
  preview,
  trigger
}: {
  authorizationBusy: boolean;
  installation: ServiceInstallation;
  preview: boolean;
  trigger: MutableRefObject<HTMLButtonElement | null>;
}) {
  const t = useTranslations("ManagedService");
  const {
    beginInstallationTermination,
    installationTerminationIntent,
    reopenInstallationTerminationIntent
  } = useControlPlane();
  const currentIntent = installationTerminationIntent?.installation.id === installation.id
    ? installationTerminationIntent
    : null;
  const blockedByAnotherIntent = Boolean(installationTerminationIntent && !currentIntent);
  const canTerminate = ["READY", "ROLLBACK_FAILED", "TERMINATION_FAILED"].includes(installation.phase);
  const terminating = installation.phase === "TERMINATION_PENDING" || installation.phase === "TERMINATING";

  return <Card aria-label={t("instanceLifecycle")} className={styles.authorizationCard}>
    <Card.Header className={styles.authorizationHeading}>
      <span><Trash2 aria-hidden="true" /></span>
      <div>
        <Typography.Eyebrow>{t(preview ? "terminationPreviewEyebrow" : "terminationLiveEyebrow")}</Typography.Eyebrow>
        <Typography.Title as="h3" level={3}>{t("instanceLifecycle")}</Typography.Title>
        <Typography.Text tone="muted">{t("instanceLifecycleHint")}</Typography.Text>
      </div>
      <Badge status={terminating ? "warning" : installation.phase === "TERMINATION_FAILED" ? "danger" : "neutral"}>{t(`installationPhases.${installation.phase}`)}</Badge>
    </Card.Header>
    <Card.Body className={styles.authorizationBody}>
      {terminating ? <Alert status="warning">{t("terminationInProgress")}</Alert> : null}
      {installation.phase === "TERMINATED" ? <Alert>{t("terminationCompleted")}</Alert> : null}
      {currentIntent && !currentIntent.open ? <Alert status="warning">{t("terminationUnknownPreserved", { id: currentIntent.requestId })}</Alert> : null}
      {blockedByAnotherIntent ? <Alert status="warning">{t("terminationAnotherIntent", { id: installationTerminationIntent!.installation.id })}</Alert> : null}
      {authorizationBusy ? <Alert status="warning">{t("terminationAuthorizationBusy")}</Alert> : null}
      {canTerminate ? <div className={styles.authorizationActions}>
        {currentIntent && !currentIntent.open
          ? <Button ref={trigger} onClick={reopenInstallationTerminationIntent} variant="danger">{t("resumeTermination")}</Button>
          : <Button ref={trigger} disabled={blockedByAnotherIntent || authorizationBusy} onClick={() => beginInstallationTermination(installation)} variant="danger">{t(installation.phase === "READY" ? "reviewTermination" : "reviewTerminationAgain")}</Button>}
      </div> : null}
    </Card.Body>
  </Card>;
}

function InstallationContent({ scene, preview, accountId }: {
  scene: Extract<ConsoleContentScene, { kind: "installations" }>;
  preview: boolean;
  accountId?: string;
}) {
  const t = useTranslations("ManagedService");
  const format = useConsoleFormat();
  const {
    closeInstallationTerminationIntent,
    closeServiceAuthorizationIntent,
    installationTerminationIntent,
    managedServiceCommand,
    readInstallation,
    serviceAuthorizationIntent
  } = useControlPlane();
  const [selectedSummary, setSelectedSummary] = useState<InstallationScene | null>(null);
  const [detailLoad, setDetailLoad] = useState<InstallationDetailLoad>({ status: "idle" });
  const [review, setReview] = useState<"authorize" | "unbind" | null>(null);
  const [stage, setStage] = useState(0);
  const [previewAccountAuthorized, setPreviewAccountAuthorized] = useState(false);
  const [previewBoundIds, setPreviewBoundIds] = useState<Set<string>>(() => new Set());
  const [previewUnboundIds, setPreviewUnboundIds] = useState<Set<string>>(() => new Set());
  const heading = useRef<HTMLHeadingElement>(null);
  const authorizationTrigger = useRef<HTMLButtonElement>(null);
  const unbindTrigger = useRef<HTMLButtonElement>(null);
  const terminationTrigger = useRef<HTMLButtonElement>(null);
  const rowTriggers = useRef(new Map<string, HTMLButtonElement>());
  const returnToList = useRef<string | null>(null);
  const detailReadRevision = useRef(0);
  useEffect(() => () => { detailReadRevision.current += 1; }, []);
  const selected = selectedSummary && detailLoad.status === "ready"
    ? installationDetailScene(selectedSummary, detailLoad.installation)
    : selectedSummary;
  const selectedId = selected?.id;
  const observedCommand = managedServiceCommand?.result;

  useEffect(() => {
    if (preview || !selectedId || observedCommand?.target.kind !== "SERVICE_INSTALLATION" || observedCommand.target.id !== selectedId) return;
    const revision = ++detailReadRevision.current;
    queueMicrotask(() => { if (revision === detailReadRevision.current) setDetailLoad({ status: "loading" }); });
    void readInstallation(selectedId).then((next) => { if (revision === detailReadRevision.current) setDetailLoad(next); });
    return () => { detailReadRevision.current += 1; };
  }, [observedCommand, preview, readInstallation, selectedId]);

  const openInstallation = useCallback((item: InstallationScene) => {
    setSelectedSummary(item);
    setReview(null);
    const revision = ++detailReadRevision.current;
    setDetailLoad({ status: "loading" });
    void readInstallation(item.id).then((result) => {
      if (revision === detailReadRevision.current) setDetailLoad(result);
    });
  }, [readInstallation]);

  useLayoutEffect(() => {
    if (selectedId) {
      heading.current?.focus({ preventScroll: true });
      return;
    }
    if (!returnToList.current) return;
    const id = returnToList.current;
    returnToList.current = null;
    rowTriggers.current.get(id)?.focus({ preventScroll: true });
  }, [review, selectedId]);

  if (selected) {
    const liveIntent = !preview && detailLoad.status === "ready" && serviceAuthorizationIntent?.installationId === selected.id && serviceAuthorizationIntent.open ? serviceAuthorizationIntent : null;
    const terminationIntent = detailLoad.status === "ready" && installationTerminationIntent?.installation.id === selected.id && installationTerminationIntent.open
      ? installationTerminationIntent
      : null;
    const detailError = detailLoad.status === "expired" || detailLoad.status === "forbidden" || detailLoad.status === "notFound" || detailLoad.status === "unavailable"
      ? detailLoad.status
      : null;
    const previewBound = previewBoundIds.has(selected.id);
    const previewUnbound = previewUnboundIds.has(selected.id);
    const previewBindingId = `preview.workload-role-binding.${selected.id}`;
    const closeDetail = () => {
      if (terminationIntent) {
        closeInstallationTerminationIntent();
        window.setTimeout(() => terminationTrigger.current?.focus({ preventScroll: true }), 0);
        return;
      }
      if (liveIntent) {
        closeServiceAuthorizationIntent();
        window.setTimeout(() => (liveIntent.kind === "unbind" ? unbindTrigger.current : authorizationTrigger.current)?.focus({ preventScroll: true }), 0);
        return;
      }
      if (review) {
        const previousReview = review;
        setReview(null);
        window.setTimeout(() => (previousReview === "unbind" ? unbindTrigger.current : authorizationTrigger.current)?.focus({ preventScroll: true }), 0);
        return;
      }
      returnToList.current = selected.id;
      detailReadRevision.current += 1;
      setSelectedSummary(null);
      setDetailLoad({ status: "idle" });
    };
    return <section className={styles.installationDetail} aria-labelledby="managed-service-installation-detail-title">
      <div className={styles.detailHeading}>
        <Button variant="ghost" size="small" onClick={closeDetail}><ArrowLeft aria-hidden="true" />{t(review || terminationIntent || liveIntent ? "backToInstance" : "backToInstances")}</Button>
        <div><Typography.Eyebrow>{t(terminationIntent ? preview ? "terminationPreviewEyebrow" : "terminationLiveEyebrow" : review ? "authorizationEyebrow" : liveIntent ? "authorizationLiveWriteEyebrow" : "instanceEyebrow")}</Typography.Eyebrow><h2 className={styles.detailTitle} id="managed-service-installation-detail-title" ref={heading} tabIndex={-1}>{terminationIntent ? t("terminationReviewTitle", { name: selected.name }) : review === "authorize" ? t("authorizationTitle", { name: selected.name }) : review === "unbind" ? t("unbindTitle", { name: selected.name }) : liveIntent ? t(liveIntent.kind === "bind" ? "authorizationTitle" : "unbindTitle", { name: selected.name }) : selected.name}</h2></div>
        <Badge status={terminationIntent || review ? "warning" : liveIntent || detailLoad.status === "loading" || detailLoad.status === "idle" ? "info" : detailError ? "warning" : selected.status}>
          {terminationIntent ? preview ? "MOCK" : "LIVE" : review ? "MOCK" : liveIntent ? "LIVE" : detailLoad.status === "loading" || detailLoad.status === "idle" ? t("instanceDetailLoadingBadge") : detailError ? t("instanceDetailUnavailableBadge") : t(`installationPhases.${selected.phase}`)}
        </Badge>
      </div>


      {detailLoad.status === "idle" || detailLoad.status === "loading" ? <TableSkeleton header={false} label={t("instanceDetailLoading")} rows={3} /> : detailError ? <EmptyState
        title={t("instanceDetailUnavailable")}
        description={t(`instanceDetailErrors.${detailError}`)}
        icon={<Database />}
        action={<Button onClick={() => openInstallation(selected)} variant="secondary">{t("retryInstanceDetail")}</Button>}
      /> : terminationIntent ? <InstallationTerminationReview intent={terminationIntent} preview={preview} onAccepted={(installation) => {
        setDetailLoad({ status: "ready", installation });
        window.setTimeout(() => terminationTrigger.current?.focus({ preventScroll: true }), 0);
      }} onClose={closeDetail} /> : liveIntent ? <LiveServiceAuthorizationReview intent={liveIntent} onClose={closeDetail} /> : review === "authorize" && accountId ? <>
        <Alert status="warning">{t("authorizationPreviewBoundary")}</Alert>
        <ServiceAuthorizationConsentReview accountId={accountId} targetResourceId={selected.id} stage={stage} onStageChange={setStage} onClose={closeDetail} onPreviewAuthorize={preview ? () => {
          setPreviewAccountAuthorized(true);
          setPreviewBoundIds((current) => new Set(current).add(selected.id));
          setPreviewUnboundIds((current) => { const next = new Set(current); next.delete(selected.id); return next; });
          setReview(null);
          window.setTimeout(() => unbindTrigger.current?.focus({ preventScroll: true }), 0);
        } : undefined} />
      </> : review === "unbind" && accountId && preview ? <>
        <Alert status="warning">{t("unbindPreviewBoundary")}</Alert>
        <ServiceAuthorizationUnbindReview accountId={accountId} targetResourceId={selected.id} bindingId={previewBindingId} otherBoundResourceCount={Math.max(0, previewBoundIds.size - 1)} onClose={closeDetail} onPreviewUnbind={() => {
          setPreviewBoundIds((current) => { const next = new Set(current); next.delete(selected.id); return next; });
          setPreviewUnboundIds((current) => new Set(current).add(selected.id));
          setReview(null);
          window.setTimeout(() => authorizationTrigger.current?.focus({ preventScroll: true }), 0);
        }} />
      </> : <>
        <dl className={styles.installationFacts}>
          <div><dt>{t("instanceId")}</dt><dd><Typography.Code>{selected.id}</Typography.Code></dd></div>
          <div><dt>{t("product")}</dt><dd>{selected.engine}<small><Typography.Code>{selected.offeringId}</Typography.Code></small></dd></div>
          <div><dt>{t("region")}</dt><dd>{selected.regionName}</dd></div>
          <div><dt>{t("status")}</dt><dd><Badge status={selected.status}>{t(`installationPhases.${selected.phase}`)}</Badge></dd></div>
          <div><dt>{t("endpoint")}</dt><dd><Typography.Code>{selected.endpoint ?? t("unassigned")}</Typography.Code></dd></div>
          <div><dt>{t("operationId")}</dt><dd><Typography.Code>{selected.operationId}</Typography.Code><small>{t(`operationKinds.${selected.operationKind}`)}</small></dd></div>
          <div><dt>{t("resourceVersion")}</dt><dd>{selected.resourceVersion}</dd></div>
          <div><dt>{t("createdAt")}</dt><dd>{format.timestamp(selected.createdAt)}</dd></div>
          {selected.safeFailureCode ? <div><dt>{t("safeFailureCode")}</dt><dd><Typography.Code>{selected.safeFailureCode}</Typography.Code></dd></div> : null}
        </dl>
        {preview && accountId ? <Card className={styles.authorizationCard}>
          <Card.Header className={styles.authorizationHeading}><span><ShieldCheck aria-hidden="true" /></span><div><Typography.Eyebrow>{t("authorizationEyebrow")}</Typography.Eyebrow><Typography.Title as="h3" level={3}>{t("serviceAuthorization")}</Typography.Title><Typography.Text tone="muted">{t("serviceAuthorizationHint")}</Typography.Text></div><Badge status="warning">MOCK</Badge></Card.Header>
          <Card.Body className={styles.authorizationBody}>
            <ServiceAuthorizationChain template={{ label: t("illustrativeTemplate"), tone: "warning" }} account={{ label: t(previewAccountAuthorized ? "previewAccountAuthorized" : "accountNotAuthorized"), tone: previewAccountAuthorized ? "success" : undefined }} binding={{ label: t(previewBound ? "previewInstanceBound" : "resourceNotBound"), tone: previewBound ? "success" : undefined }} runtime={{ label: t("runtimeNotObserved") }} />
            <Alert status={previewBound || previewUnbound ? "success" : "info"}>{t(previewBound ? "previewAuthorizationApplied" : previewUnbound ? "previewUnbindApplied" : "productEntryHint")}</Alert>
            {previewAccountAuthorized ? <dl className={styles.authorizationFacts}>
              <div><dt>{t("authorizationTemplate")}</dt><dd><Typography.Code>preview.service-role-template.managed-service-installation-read.v1@v1</Typography.Code></dd></div>
              <div><dt>{t("authorizationBinding")}</dt><dd>{previewBound ? <Typography.Code>{previewBindingId}</Typography.Code> : t("resourceNotBound")}</dd></div>
              <div><dt>{t("instanceId")}</dt><dd><Typography.Code>{selected.id}</Typography.Code><small>MOCK · {t("previewBrowserOnly")}</small></dd></div>
            </dl> : null}
            <div className={styles.authorizationActions}>
              {!previewBound ? <Button ref={authorizationTrigger} onClick={() => { setStage(0); setReview("authorize"); }}>{t(previewAccountAuthorized ? "reviewBinding" : "reviewAuthorization")}</Button> : null}
              {previewBound ? <Button ref={unbindTrigger} variant="danger" onClick={() => setReview("unbind")}>{t("reviewUnbind")}</Button> : null}
            </div>
          </Card.Body>
        </Card> : accountId && selected.phase === "READY" ? <LiveServiceAuthorizationCard accountId={accountId} installationId={selected.id} authorizationTrigger={authorizationTrigger} unbindTrigger={unbindTrigger} /> : null}
        {detailLoad.status === "ready" ? <InstallationLifecycleCard
          authorizationBusy={Boolean(serviceAuthorizationIntent)}
          installation={detailLoad.installation}
          preview={preview}
          trigger={terminationTrigger}
        /> : null}
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
      <Card.Body>
        <Alert status={preview ? "warning" : "info"}>
          {t(preview ? "instanceVisibilityMockBoundary" : "instanceVisibilityBoundary")}
        </Alert>
      </Card.Body>
      <InstallationRows items={scene.installations} onOpen={accountId ? openInstallation : undefined} triggerRefs={rowTriggers} />
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
  const requestedUserTab = view === "users" ? params.get("tab") : null;
  const userTab = requestedUserTab && ["identity", "access", "policies", "groups", "security", "keys"].includes(requestedUserTab) ? requestedUserTab as AccountUserDetailTab : undefined;
  return <AccountAccessRenderer key={view + ":" + (entityId ?? "") + ":" + (policyMethod ?? "") + ":" + (userTab ?? "")} view={view} entityId={entityId} policyMethod={policyMethod} userTab={userTab} onNavigate={(next, id, method, nextUserTab) => {
    const query = new URLSearchParams();
    if (id) query.set("id", id);
    if (next === "create-policy" && method) query.set("method", method);
    if (next === "users" && id && nextUserTab) query.set("tab", nextUserTab);
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
  if (scene.kind === "audit") return <AuditWorkspace preview={preview} />;
  if (scene.kind === "access") return <Suspense fallback={<ConsoleContentLoadingRenderer label={t("loading")} selection={{ section: "access", view: scene.view === "overview" ? undefined : scene.view }} />}><AccessContent pendingHref={pendingHref} view={scene.view} /></Suspense>;
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
  if (scene.kind === "managed-product") return <ManagedProductContent preview={preview} scene={scene} />;
  if (scene.kind === "catalog") return <CatalogContent scene={scene} preview={preview} />;
  if (scene.kind === "quotas") return <QuotaContent scene={scene} />;
  if (scene.kind === "installations") return <InstallationContent scene={scene} preview={preview} accountId={accountId} />;
  return <RegionContent scene={scene} />;
}
