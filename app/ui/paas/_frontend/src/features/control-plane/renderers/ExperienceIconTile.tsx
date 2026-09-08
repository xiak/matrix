import {
  Boxes,
  ChartNoAxesCombined,
  CloudCog,
  GitBranch,
  Layers3,
  ShieldCheck
} from "lucide-react";
import type { ExperienceIconKind } from "../scenes/consoleScene";
import styles from "./ExperienceIconTile.module.css";

const icons = {
  foundation: CloudCog,
  paas: Layers3,
  devops: GitBranch,
  observability: ChartNoAxesCombined,
  security: ShieldCheck
} satisfies Record<ExperienceIconKind, typeof Boxes>;

export function ExperienceIconTile({ kind }: { kind: ExperienceIconKind }) {
  const Icon = icons[kind];
  return <span aria-hidden="true" className={styles.tile} data-product={kind}><Icon /></span>;
}
