import type messages from "./messages/zh-CN.json";
import type { Locale as MatrixLocale } from "./LocaleProvider";

declare module "next-intl" {
  interface AppConfig {
    Locale: MatrixLocale;
    Messages: typeof messages;
  }
}
