"use client";
import { useTranslations } from "next-intl";
import { GitBranch, Layers3, ArrowUpRight } from "lucide-react";
import { Badge, Button, Card, ContentPage, EmptyState, PageSkeleton } from "@ui/xiak";
import { useSession } from "../auth/SessionProvider";
import { useProducts } from "./ProductProvider";
import { PlatformLink } from "./Navigation";
import { productPresentation, productCanMutate } from "./products";
import { RequestFeedback } from "./RequestFeedback";
import styles from "./Workspace.module.css";

export function Dashboard() {
  const t = useTranslations("Platform");
  const inventory = useProducts();
  const session = useSession()!;
  return <div className={styles.stack}>
    <ContentPage.Heading title={t("dashboardTitle")} />
    <div><p>{t("dashboardHint")}</p><span className={styles.muted}>{t("organization")} · {session.organizationId}</span></div>
    {inventory.status === "loading" ? <PageSkeleton label={t("loadingProducts")} /> : inventory.status === "error" ? <Card><Card.Body className={styles.stack}><RequestFeedback error={inventory.error} /><p>{t("discoveryHint")}</p><div className={styles.actions}><Button variant="secondary" onClick={inventory.refresh}>{t("refresh")}</Button><Button asChild variant="ghost"><PlatformLink href="/account/">{t("account")}</PlatformLink></Button></div></Card.Body></Card> : <>
      {inventory.value?.products.length ? <div className={styles.fields}>{inventory.value.products.map(product => {
        const Icon = product.id === "DEVOPS" ? GitBranch : Layers3;
        const fresh = productCanMutate(product, inventory.value!.observedAt, inventory.receivedAt, inventory.now);
        return <Card key={product.id}><Card.Header><div className={styles.actions}><Icon aria-hidden="true" /><strong>{t(`productNames.${product.id}`)}</strong><Badge status={fresh ? "success" : "warning"}>{t(`states.${product.state === "READY" && !fresh ? "STALE" : product.state}`)}</Badge></div></Card.Header><Card.Body className={styles.stack}><p>{t(`productDescriptions.${product.id}`)}</p><dl className={styles.facts}><div><dt>{t("version")}</dt><dd>{product.version}</dd></div><div><dt>{t("observed")}</dt><dd>{product.observedAt}</dd></div></dl><div><Button variant="secondary" asChild><PlatformLink href={productPresentation[product.id].path}>{t("openProduct")}<ArrowUpRight aria-hidden="true" /></PlatformLink></Button></div></Card.Body></Card>;
      })}</div> : <EmptyState title={t("emptyProducts")} description={t("emptyHint")} />}
      <p className={styles.muted}>{t("signedInventory")} · {inventory.value?.releaseId}</p>
    </>}
  </div>;
}
