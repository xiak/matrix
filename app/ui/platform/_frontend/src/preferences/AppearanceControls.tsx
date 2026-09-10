"use client";

import { useSyncExternalStore } from "react";
import { useTheme } from "next-themes";
import { useTranslations } from "next-intl";
import { Contrast, Languages, Monitor, Moon, Sun } from "lucide-react";
import { useLocalePreference } from "@/i18n/LocaleProvider";
import { RadioGroup, SelectionMenu } from "@ui/xiak";
import { appearanceThemes } from "./AppearanceProvider";
import styles from "./AppearanceControls.module.css";

const subscribe = () => () => {};
const themeIcons = { dark: Moon, mixed: Contrast, light: Sun, system: Monitor };

export function AppearanceControls({ variant = "toolbar" }: { variant?: "toolbar" | "panel" }) {
  const t = useTranslations("Preferences");
  const { locale, setLocale } = useLocalePreference();
  const { theme, setTheme } = useTheme();
  const mounted = useSyncExternalStore(subscribe, () => true, () => false);
  const currentTheme = mounted && (theme === "light" || theme === "mixed" || theme === "system") ? theme : "dark";
  const ThemeIcon = themeIcons[currentTheme];
  const themeOptions = [...appearanceThemes, "system" as const].map((value) => {
    const Icon = themeIcons[value];
    return { value, label: t(value), icon: <Icon aria-hidden="true" /> };
  });

  if (variant === "panel") return <div aria-label={t("label")} className={styles.panel} role="group">
    <RadioGroup label={t("theme")} value={currentTheme} onValueChange={setTheme} options={themeOptions.map(({ value, label }) => ({ value, label }))} />
    <RadioGroup label={t("language")} value={locale} onValueChange={setLocale} options={[
      { value: "zh-CN", label: "简体中文" }, { value: "en", label: "English" }
    ]} />
  </div>;

  return <div aria-label={t("label")} className={styles.controls} role="group">
    <SelectionMenu label={t("theme")} value={currentTheme} onValueChange={setTheme}
      options={themeOptions}>
      <ThemeIcon aria-hidden="true" /><span className={styles.themeLabel}>{t(currentTheme)}</span>
    </SelectionMenu>
    <SelectionMenu label={t("language")} value={locale} onValueChange={setLocale}
      options={[{ value: "zh-CN", label: "简体中文" }, { value: "en", label: "English" }]}>
      <Languages aria-hidden="true" /><span>{locale === "zh-CN" ? "简体中文" : "English"}</span>
    </SelectionMenu>
  </div>;
}
