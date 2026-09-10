"use client";

import { createContext, useContext, useEffect, useSyncExternalStore, type ReactNode } from "react";
import { NextIntlClientProvider } from "next-intl";
import en from "./messages/en.json";
import zhCN from "./messages/zh-CN.json";

export const locales = ["zh-CN", "en"] as const;
export type Locale = typeof locales[number];
export const defaultLocale: Locale = "zh-CN";
export const localeStorageKey = "matrix.locale";
const localeEvent = "matrix:locale";
const messages = { "zh-CN": zhCN, en };
let volatileLocale: Locale = defaultLocale;

function isLocale(value: unknown): value is Locale {
  return locales.some((locale) => locale === value);
}

function readLocale(): Locale {
  try {
    const value = window.localStorage.getItem(localeStorageKey);
    return isLocale(value) ? value : defaultLocale;
  } catch {
    return volatileLocale;
  }
}

function subscribe(listener: () => void) {
  const onStorage = (event: StorageEvent) => {
    if (event.key === localeStorageKey || event.key === null) listener();
  };
  window.addEventListener("storage", onStorage);
  window.addEventListener(localeEvent, listener);
  return () => {
    window.removeEventListener("storage", onStorage);
    window.removeEventListener(localeEvent, listener);
  };
}

function setLocale(locale: Locale) {
  if (!isLocale(locale)) return;
  volatileLocale = locale;
  try { window.localStorage.setItem(localeStorageKey, locale); } catch { /* Storage is optional. */ }
  window.dispatchEvent(new Event(localeEvent));
}

const LocaleContext = createContext<{ locale: Locale; setLocale: typeof setLocale } | null>(null);

export function LocaleProvider({ children }: { children: ReactNode }) {
  const locale = useSyncExternalStore(subscribe, readLocale, () => defaultLocale);
  useEffect(() => { document.documentElement.lang = locale; }, [locale]);
  return (
    <LocaleContext.Provider value={{ locale, setLocale }}>
      <NextIntlClientProvider locale={locale} messages={messages[locale]} timeZone="UTC">
        {children}
      </NextIntlClientProvider>
    </LocaleContext.Provider>
  );
}

export function useLocalePreference() {
  const context = useContext(LocaleContext);
  if (!context) throw new Error("useLocalePreference requires LocaleProvider");
  return context;
}
