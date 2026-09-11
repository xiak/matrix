import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { ConsoleLink as Link, useConsoleNavigation } from "../routes/ConsoleNavigation";
import { AccountAccessRenderer } from "@/features/auth/renderers/AccountAccessRenderer";
import {
  ArrowRight,
  CheckCircle2,
  Cpu,
  Database,
  HardDrive,
  MapPin,
  PackageCheck,
  Server
} from "lucide-react";
import {
  Table,
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

function InstallationRows({ items }: { items: InstallationScene[] }) {
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
    <Table aria-label={t("instancesTable")}>
        <thead>
          <tr><th scope="col">{t("instance")}</th><th scope="col">{t("region")}</th><th scope="col">{t("status")}</th><th scope="col">{t("endpoint")}</th><th scope="col">{t("observed")}</th></tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <td><strong>{item.name}</strong><small>{item.engine}</small></td>
              <td>{item.regionName}</td>
              <td><Badge status={item.status}>{t(`installationPhases.${item.phase}`)}</Badge></td>
              <td><Typography.Code>{item.endpoint ?? t("unassigned")}</Typography.Code></td>
              <td>{format.timestamp(item.observedAt)}</td>
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

function InstallationContent({ scene }: { scene: Extract<ConsoleContentScene, { kind: "installations" }> }) {
  const t = useTranslations("ManagedService");
  return (
    <Card>
      <Card.Header>
        <div>
          <Typography.Title as="h2" level={3}>{t("organizationInstances")}</Typography.Title>
          <Typography.Text tone="muted">{t("installationStateHint")}</Typography.Text>
        </div>
        <Badge status="info">{t("instanceCount", { count: scene.installations.length })}</Badge>
      </Card.Header>
      <InstallationRows items={scene.installations} />
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

function AccessContent({ view }: { view: Extract<ConsoleContentScene, { kind: "access" }>["view"] }) {
  const { navigate } = useConsoleNavigation();
  const params = useSearchParams();
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
  scene,
  scope
}: {
  scene: ConsoleContentScene;
  scope?: ResourceScope;
}) {
  const t = useTranslations("AccountAccess");
  if (scene.kind === "logs") return <LogServiceRenderer regionId={scope?.regionId} scene={scene} />;
  if (scene.kind === "access") return <Suspense fallback={<PageSkeleton layout="access" label={t("loading")} />}><AccessContent view={scene.view} /></Suspense>;
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
  if (scene.kind === "installations") return <InstallationContent scene={scene} />;
  return <RegionContent scene={scene} />;
}
