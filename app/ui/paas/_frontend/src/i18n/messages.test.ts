import { describe, expect, it } from "vitest";
import { createTranslator } from "next-intl";
import { policyActions, policyConditionKeys, policyServices } from "@/features/auth/domain/policyLanguage";
import en from "./messages/en.json";
import zhCN from "./messages/zh-CN.json";

function leafKeys(messages: Record<string, unknown>, prefix = ""): string[] {
  return Object.entries(messages).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    return typeof value === "object" && value !== null ? leafKeys(value as Record<string, unknown>, path) : [path];
  }).sort();
}

describe("translation contracts", () => {
  it("provides names, descriptions and condition labels for every registered capability", () => {
    for (const messages of [en, zhCN]) {
      for (const service of policyServices) expect(messages.PolicyRules.services[service]).toBeTruthy();
      for (const action of policyActions) {
        expect(messages.PolicyRules.actionNames[action.id]).toBeTruthy();
        expect(messages.PolicyRules.actionDescriptions[action.id]).toBeTruthy();
        expect(messages.PolicyRules.types[action.resourceType]).toBeTruthy();
      }
      for (const key of policyConditionKeys) expect(messages.PolicyRules.conditionNames[key]).toBeTruthy();
    }
  });
  it("keeps the same translation keys in every supported locale", () => {
    expect(leafKeys(en)).toEqual(leafKeys(zhCN));
  });
  it.each(["zh-CN", "en"] as const)("formats every %s message with ICU, without missing-message fallbacks", (locale) => {
    const errors: unknown[] = [];
    const t = createTranslator({ locale, messages: locale === "en" ? en : zhCN, onError: (error) => errors.push(error) });
    for (const key of leafKeys(zhCN)) {
      const rendered = t(key as Parameters<typeof t>[0], { label: "状态: 启用", services: 2, service: "Logs", statements: 3, rules: 2, actions: 4, conditions: "Source IP", effect: "Allow", user: "preview-reader", path: "$.statement[0]", type: "topic", region: "region-a", name: "matrix-admin", count: 2, title: "Task finished", state: "Unread", shown: 2, loaded: 10, action: "Disable", page: 1, pages: 2, current: 2, total: 5, selected: 2, remaining: 10, needed: 20, index: 1, policies: 2, groups: 1, users: 3, number: 1, limit: 5, version: 2, decision: "Allow", max: 60, id: "org-preview", side: locale === "en" ? "Before" : "变更前" });
      expect(rendered.trim().length).toBeGreaterThan(0);
      expect(rendered).not.toContain("{name}");
    }
    expect(errors).toEqual([]);
  });
});
