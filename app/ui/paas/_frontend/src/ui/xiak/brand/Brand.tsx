import { classNames } from "../utils";
import styles from "./Brand.module.css";

export function Brand({ variant = "lockup", responsive = false, className, decorative = false }: {
  variant?: "lockup" | "signature" | "symbol";
  responsive?: boolean;
  className?: string;
  decorative?: boolean;
}) {
  return <span aria-hidden={decorative || undefined} aria-label={decorative ? undefined : "Matrix Cloud"}
    className={classNames(styles.brand, styles[variant], responsive && styles.responsive, className)}
    role={decorative ? undefined : "img"} />;
}
