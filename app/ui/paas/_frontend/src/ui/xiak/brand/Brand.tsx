import { classNames } from "../utils";
import styles from "./Brand.module.css";

export function Brand({ variant = "lockup", className, decorative = false }: {
  variant?: "lockup" | "signature" | "symbol";
  className?: string;
  decorative?: boolean;
}) {
  return <span aria-hidden={decorative || undefined} aria-label={decorative ? undefined : "Matrix Cloud"}
    className={classNames(styles.brand, styles[variant], className)}
    role={decorative ? undefined : "img"} />;
}
