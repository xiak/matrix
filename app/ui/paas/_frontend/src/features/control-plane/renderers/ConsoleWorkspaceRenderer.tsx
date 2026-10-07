"use client";

import { useId, useState, type FormEvent } from "react";
import {
  Activity,
  Database,
  MapPin,
  PackagePlus,
  ServerCog,
  ShoppingCart
} from "lucide-react";
import { Alert, FormField, Badge, Button, Input, Select, Typography } from "@ui/xiak";
import { useControlPlane } from "../application/ControlPlaneProvider";
import type { ConsoleWorkspaceScene } from "../scenes/consoleScene";
import styles from "./ConsoleWorkspaceRenderer.module.css";
import { useTranslations } from "next-intl";
import { useConsoleFormat } from "./useConsoleFormat";

const installationIDPatternSource = "[a-z0-9][a-z0-9._\\-]{0,61}[a-z0-9]";
const installationIDPattern = new RegExp(`^${installationIDPatternSource}$`);

function QuotaOrder({
  scene
}: {
  scene: Extract<NonNullable<ConsoleWorkspaceScene>, { kind: "quota-order" }>;
}) {
  const t = useTranslations("ServiceWorkflow");
  const format = useConsoleFormat();
  const controlPlane = useControlPlane();
  const initialOffering = scene.options[0];
  const [offeringId, setOfferingId] = useState(initialOffering?.offeringId ?? "");
  const [shapeId, setShapeId] = useState(initialOffering?.shapes[0]?.id ?? "");
  const [instanceCount, setInstanceCount] = useState(1);
  const [accepted, setAccepted] = useState(false);
  const selectedOffering = scene.options.find((item) => item.offeringId === offeringId);
  const selectedShape = selectedOffering?.shapes.find((item) => item.id === shapeId);
  const canSubmit = Boolean(selectedShape && Number.isInteger(instanceCount) && instanceCount >= 1 && instanceCount <= 8);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSubmit) return;
    setAccepted(false);
    const success = await controlPlane.activateQuota({
      offeringId,
      quotaShapeId: shapeId,
      instanceCount
    });
    setAccepted(success);
  }

  return (
    <div className={styles.workspace}>
      <header className={styles.heading}>
        <div className={styles.headingIcon}><ShoppingCart aria-hidden="true" /></div>
        <div>
          <Typography.Eyebrow>{t("quotaEyebrow")}</Typography.Eyebrow>
          <Typography.Title as="h2" level={3}>{t("quotaTitle")}</Typography.Title>
        </div>
      </header>
      {scene.options.length === 0 ? (
        <Alert>{t("catalogEmpty")}</Alert>
      ) : (
        <form className={styles.form} onSubmit={submit}>
          <FormField label={t("offering")}>
            <Select
              onValueChange={(next) => {
                const nextOffering = scene.options.find((item) => item.offeringId === next);
                setOfferingId(next);
                setShapeId(nextOffering?.shapes[0]?.id ?? "");
                setAccepted(false);
              }}
              value={offeringId}
              options={scene.options.map((item) => ({ value: item.offeringId, label: item.offeringName }))}
            />
          </FormField>
          <FormField label={t("shape")}>
            <Select onValueChange={(next) => { setShapeId(next); setAccepted(false); }} value={shapeId}
              options={selectedOffering?.shapes.map((shape) => ({ value: shape.id, label: shape.label })) ?? []} />
          </FormField>
          {selectedShape ? (
            <div className={styles.resourceSummary}>
              <Database aria-hidden="true" />
              <div><strong>{selectedShape.label}</strong><span>{format.resources(selectedShape.resources)}</span></div>
            </div>
          ) : null}
          <FormField label={t("instanceCount")}>
            <Input
              max={8}
              min={1}
              onChange={(event) => { setInstanceCount(Number(event.target.value)); setAccepted(false); }}
              required
              type="number"
              value={instanceCount}
            />
          </FormField>
          <Alert>
            {t("quotaNotice")}
          </Alert>
          {accepted ? <Alert status="success">{t("quotaAccepted")}</Alert> : null}
          <Button
            block
            disabled={!canSubmit || controlPlane.mutation === "quota"}
            size="large"
            type="submit"
          >
            <PackagePlus aria-hidden="true" />
            {controlPlane.mutation === "quota" ? t("activating") : t("activate")}
          </Button>
        </form>
      )}
    </div>
  );
}

function InstallationOrder({
  scene
}: {
  scene: Extract<NonNullable<ConsoleWorkspaceScene>, { kind: "installation-order" }>;
}) {
  const t = useTranslations("ServiceWorkflow");
  const controlPlane = useControlPlane();
  const instanceIdField = useId();
  const [entitlementId, setEntitlementId] = useState(scene.entitlementOptions[0]?.entitlementId ?? "");
  const [regionId, setRegionId] = useState(scene.regionOptions[0]?.id ?? "");
  const [name, setName] = useState("postgres-primary");
  const [id, setId] = useState("postgres-primary");
  const [accepted, setAccepted] = useState(false);
  const selectedEntitlement = scene.entitlementOptions.find((item) => item.entitlementId === entitlementId);
  const canSubmit = Boolean(selectedEntitlement && scene.regionOptions.some((region) => region.id === regionId) && installationIDPattern.test(id) && name.trim());

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedEntitlement || !canSubmit) return;
    setAccepted(false);
    const success = await controlPlane.createInstallation({
      id,
      name: name.trim(),
      offeringId: selectedEntitlement.offeringId,
      quotaEntitlementId: entitlementId,
      regionId
    });
    setAccepted(success);
  }

  return (
    <div className={styles.workspace}>
      <header className={styles.heading}>
        <div className={styles.headingIcon}><ServerCog aria-hidden="true" /></div>
        <div>
          <Typography.Eyebrow>{t("installEyebrow")}</Typography.Eyebrow>
          <Typography.Title as="h2" level={3}>{t("installTitle")}</Typography.Title>
        </div>
      </header>
      {scene.entitlementOptions.length === 0 ? (
        <Alert>{t("quotaEmpty")}</Alert>
      ) : scene.regionOptions.length === 0 ? (
        <Alert>{t("regionsEmpty")}</Alert>
      ) : (
        <form className={styles.form} onSubmit={submit}>
          <FormField id={instanceIdField} hint={t("idHint")} label={t("instanceId")}>
            <Input
              id={instanceIdField}
              aria-describedby={`${instanceIdField}-hint`}
              minLength={2}
              maxLength={63}
              invalid={Boolean(id) && !installationIDPattern.test(id)}
              onChange={(event) => { setId(event.target.value); setAccepted(false); }}
              pattern={installationIDPatternSource}
              required
              value={id}
            />
          </FormField>
          <FormField label={t("displayName")}>
            <Input onChange={(event) => { setName(event.target.value); setAccepted(false); }} required value={name} />
          </FormField>
          <FormField label={t("quota")}>
            <Select onValueChange={(next) => { setEntitlementId(next); setAccepted(false); }} value={entitlementId}
              options={scene.entitlementOptions.map((item) => ({ value: item.entitlementId, label: `${item.label} · ${t("available", { count: item.available })}` }))} />
          </FormField>
          <FormField label={t("installRegion")}>
            <Select onValueChange={(next) => { setRegionId(next); setAccepted(false); }} value={regionId}
              options={scene.regionOptions.map((item) => ({ value: item.id, label: item.label }))} />
          </FormField>
          <div className={styles.resourceSummary}>
            <MapPin aria-hidden="true" />
            <div><strong>{t("localInstall")}</strong><span>{t("serverPolicy")}</span></div>
          </div>
          {accepted ? <Alert status="success">{t("installAccepted")}</Alert> : null}
          <Button block disabled={!canSubmit || controlPlane.mutation === "installation"} size="large" type="submit">
            <ServerCog aria-hidden="true" />
            {controlPlane.mutation === "installation" ? t("submitting") : t("install")}
          </Button>
        </form>
      )}
    </div>
  );
}

function PlatformStatus({
  scene
}: {
  scene: Extract<NonNullable<ConsoleWorkspaceScene>, { kind: "platform-status" }>;
}) {
  const t = useTranslations("ServiceWorkflow");
  const format = useConsoleFormat();
  const facts = [
    { icon: MapPin, key: "readyRegions", value: scene.readyRegions, status: scene.readyRegions > 0 ? "success" : "warning" },
    { icon: Activity, key: "activeOperations", value: scene.activeOperations, status: scene.activeOperations > 0 ? "info" : "neutral" },
    { icon: Database, key: "serviceCount", value: scene.serviceCount, status: "neutral" }
  ] as const;

  return (
    <div className={styles.workspace}>
      <header className={styles.heading}>
        <div className={styles.headingIcon}><Activity aria-hidden="true" /></div>
        <div>
          <Typography.Eyebrow>{t("statusEyebrow")}</Typography.Eyebrow>
          <Typography.Title as="h2" level={3}>{t("statusTitle")}</Typography.Title>
        </div>
      </header>
      <div className={styles.statusList}>
        {facts.map((fact) => {
          const Icon = fact.icon;
          return (
            <div className={styles.statusItem} key={fact.key}>
              <Icon aria-hidden="true" />
              <span>{t(fact.key)}</span>
              <Badge status={fact.status}>{format.number(fact.value)}</Badge>
            </div>
          );
        })}
      </div>
      <Alert>
        {t("statusNotice")}
      </Alert>
    </div>
  );
}

export function ConsoleWorkspaceRenderer({
  scene
}: {
  scene: NonNullable<ConsoleWorkspaceScene>;
}) {
  if (scene.kind === "quota-order") return <QuotaOrder scene={scene} />;
  if (scene.kind === "installation-order") return <InstallationOrder scene={scene} />;
  return <PlatformStatus scene={scene} />;
}
