"use client";

import { useMemo, useState, type FormEvent } from "react";
import {
  Activity,
  CheckCircle2,
  Database,
  MapPin,
  PackagePlus,
  ServerCog,
  ShoppingCart
} from "lucide-react";
import { Badge, Button, Input, Select, Typography } from "@ui/xiak";
import { useControlPlane } from "../application/ControlPlaneProvider";
import type { ConsoleWorkspaceScene } from "../scenes/consoleScene";
import styles from "./ConsoleWorkspaceRenderer.module.css";

const installationIDPatternSource = "[a-z0-9][a-z0-9._\\-]{0,61}[a-z0-9]";
const installationIDPattern = new RegExp(`^${installationIDPatternSource}$`);

function Field({
  children,
  label
}: {
  children: React.ReactNode;
  label: string;
}) {
  return <label className={styles.field}><span>{label}</span>{children}</label>;
}

function OrderNotice({ children }: { children: React.ReactNode }) {
  return <p className={styles.notice}>{children}</p>;
}

function QuotaOrder({
  feedback,
  scene
}: {
  feedback?: React.ReactNode;
  scene: Extract<NonNullable<ConsoleWorkspaceScene>, { kind: "quota-order" }>;
}) {
  const controlPlane = useControlPlane();
  const initialOffering = scene.options[0];
  const [offeringId, setOfferingId] = useState(initialOffering?.offeringId ?? "");
  const [shapeId, setShapeId] = useState(initialOffering?.shapes[0]?.id ?? "");
  const [instanceCount, setInstanceCount] = useState(1);
  const [accepted, setAccepted] = useState(false);
  const selectedOffering = scene.options.find((item) => item.offeringId === offeringId);
  const selectedShape = selectedOffering?.shapes.find((item) => item.id === shapeId);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
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
          <Typography.Eyebrow>Quota activation</Typography.Eyebrow>
          <Typography.Title as="h2" level={3}>激活服务配额</Typography.Title>
        </div>
      </header>
      {feedback}
      {scene.options.length === 0 ? (
        <OrderNotice>服务目录没有返回可激活的真实产品。</OrderNotice>
      ) : (
        <form className={styles.form} onSubmit={submit}>
          <Field label="服务产品">
            <Select
              onChange={(event) => {
                const nextOffering = scene.options.find((item) => item.offeringId === event.target.value);
                setOfferingId(event.target.value);
                setShapeId(nextOffering?.shapes[0]?.id ?? "");
                setAccepted(false);
              }}
              value={offeringId}
            >
              {scene.options.map((item) => <option key={item.offeringId} value={item.offeringId}>{item.offeringName}</option>)}
            </Select>
          </Field>
          <Field label="资源规格">
            <Select onChange={(event) => { setShapeId(event.target.value); setAccepted(false); }} value={shapeId}>
              {selectedOffering?.shapes.map((shape) => <option key={shape.id} value={shape.id}>{shape.label}</option>)}
            </Select>
          </Field>
          {selectedShape ? (
            <div className={styles.resourceSummary}>
              <Database aria-hidden="true" />
              <div><strong>{selectedShape.label}</strong><span>{selectedShape.resourceSummary}</span></div>
            </div>
          ) : null}
          <Field label="实例数量">
            <Input
              max={8}
              min={1}
              onChange={(event) => { setInstanceCount(Number(event.target.value)); setAccepted(false); }}
              required
              type="number"
              value={instanceCount}
            />
          </Field>
          <OrderNotice>
            此操作创建组织配额权益，不处理金额、支付、账单或折扣。
          </OrderNotice>
          {accepted ? <p className={styles.accepted}><CheckCircle2 aria-hidden="true" /> 配额已由平台确认</p> : null}
          <Button
            block
            disabled={!offeringId || !shapeId || instanceCount < 1 || controlPlane.mutation === "quota"}
            size="large"
            type="submit"
          >
            <PackagePlus aria-hidden="true" />
            {controlPlane.mutation === "quota" ? "正在激活…" : "确认激活配额"}
          </Button>
        </form>
      )}
    </div>
  );
}

function InstallationOrder({
  feedback,
  scene
}: {
  feedback?: React.ReactNode;
  scene: Extract<NonNullable<ConsoleWorkspaceScene>, { kind: "installation-order" }>;
}) {
  const controlPlane = useControlPlane();
  const [entitlementId, setEntitlementId] = useState(scene.entitlementOptions[0]?.entitlementId ?? "");
  const [regionId, setRegionId] = useState(scene.regionOptions[0]?.id ?? "");
  const [name, setName] = useState("postgres-primary");
  const [id, setId] = useState("postgres-primary");
  const [accepted, setAccepted] = useState(false);
  const selectedEntitlement = scene.entitlementOptions.find((item) => item.entitlementId === entitlementId);
  const selectedRegion = scene.regionOptions.find((item) => item.id === regionId);
  const canSubmit = Boolean(selectedEntitlement && selectedRegion && installationIDPattern.test(id) && name.trim());

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedEntitlement || !selectedRegion) return;
    setAccepted(false);
    const success = await controlPlane.createInstallation({
      id,
      name: name.trim(),
      offeringId: selectedEntitlement.offeringId,
      quotaEntitlementId: selectedEntitlement.entitlementId,
      regionId: selectedRegion.id
    });
    setAccepted(success);
  }

  return (
    <div className={styles.workspace}>
      <header className={styles.heading}>
        <div className={styles.headingIcon}><ServerCog aria-hidden="true" /></div>
        <div>
          <Typography.Eyebrow>Install service</Typography.Eyebrow>
          <Typography.Title as="h2" level={3}>安装 PostgreSQL</Typography.Title>
        </div>
      </header>
      {feedback}
      {scene.entitlementOptions.length === 0 ? (
        <OrderNotice>没有可用配额。请先激活 PostgreSQL 配额，或等待现有安装释放额度。</OrderNotice>
      ) : scene.regionOptions.length === 0 ? (
        <OrderNotice>没有就绪区域。安装器必须先完成本机能力检查。</OrderNotice>
      ) : (
        <form className={styles.form} onSubmit={submit}>
          <Field label="实例 ID">
            <Input
              invalid={Boolean(id) && !installationIDPattern.test(id)}
              onChange={(event) => { setId(event.target.value); setAccepted(false); }}
              pattern={installationIDPatternSource}
              required
              value={id}
            />
          </Field>
          <Field label="显示名称">
            <Input onChange={(event) => { setName(event.target.value); setAccepted(false); }} required value={name} />
          </Field>
          <Field label="配额">
            <Select onChange={(event) => { setEntitlementId(event.target.value); setAccepted(false); }} required value={selectedEntitlement?.entitlementId ?? ""}>
              <option disabled value="">请选择可用配额</option>
              {scene.entitlementOptions.map((item) => (
                <option key={item.entitlementId} value={item.entitlementId}>
                  {item.label} · 可用 {item.available}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="安装区域">
            <Select onChange={(event) => { setRegionId(event.target.value); setAccepted(false); }} required value={selectedRegion?.id ?? ""}>
              <option disabled value="">请选择就绪区域</option>
              {scene.regionOptions.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
            </Select>
          </Field>
          <div className={styles.resourceSummary}>
            <MapPin aria-hidden="true" />
            <div><strong>本机受管安装</strong><span>制品、端口和持久化策略由服务端决定</span></div>
          </div>
          {accepted ? <p className={styles.accepted}><CheckCircle2 aria-hidden="true" /> 安装任务已由平台接受</p> : null}
          <Button block disabled={!canSubmit || controlPlane.mutation === "installation"} size="large" type="submit">
            <ServerCog aria-hidden="true" />
            {controlPlane.mutation === "installation" ? "正在提交…" : "提交安装任务"}
          </Button>
        </form>
      )}
    </div>
  );
}

function PlatformStatus({
  feedback,
  scene
}: {
  feedback?: React.ReactNode;
  scene: Extract<NonNullable<ConsoleWorkspaceScene>, { kind: "platform-status" }>;
}) {
  const facts = useMemo(() => [
    { icon: MapPin, label: "就绪区域", value: scene.readyRegions, status: scene.readyRegions > 0 ? "success" : "warning" },
    { icon: Activity, label: "活动任务", value: scene.activeOperations, status: scene.activeOperations > 0 ? "info" : "neutral" },
    { icon: Database, label: "服务实例", value: scene.serviceCount, status: "neutral" }
  ] as const, [scene]);

  return (
    <div className={styles.workspace}>
      <header className={styles.heading}>
        <div className={styles.headingIcon}><Activity aria-hidden="true" /></div>
        <div>
          <Typography.Eyebrow>Live status</Typography.Eyebrow>
          <Typography.Title as="h2" level={3}>平台状态</Typography.Title>
        </div>
      </header>
      {feedback}
      <div className={styles.statusList}>
        {facts.map((fact) => {
          const Icon = fact.icon;
          return (
            <div className={styles.statusItem} key={fact.label}>
              <Icon aria-hidden="true" />
              <span>{fact.label}</span>
              <Badge status={fact.status}>{fact.value}</Badge>
            </div>
          );
        })}
      </div>
      <OrderNotice>
        数值来自当前组织的真实控制面快照。未知或失败状态不会被折算成健康。
      </OrderNotice>
    </div>
  );
}

export function ConsoleWorkspaceRenderer({
  feedback,
  scene
}: {
  feedback?: React.ReactNode;
  scene: NonNullable<ConsoleWorkspaceScene>;
}) {
  if (scene.kind === "quota-order") return <QuotaOrder feedback={feedback} scene={scene} />;
  if (scene.kind === "installation-order") return <InstallationOrder feedback={feedback} scene={scene} />;
  return <PlatformStatus feedback={feedback} scene={scene} />;
}
