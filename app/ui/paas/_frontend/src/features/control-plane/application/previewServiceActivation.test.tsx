import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ServiceActivationRecord } from "../domain/serviceActivation";
import {
  previewServiceActivationStorageKey, readPreviewServiceActivation,
  resetPreviewServiceActivation, usePreviewServiceActivation, writePreviewServiceActivation
} from "./previewServiceActivation";

const activation: ServiceActivationRecord = {
  accountId: "tenant-a", serviceKey: "postgresql", termsVersion: "mock-v1",
  acceptedBy: "owner-a", acceptedAt: "2026-10-12T01:00:00.000Z", enabledAt: "2026-10-12T01:00:00.000Z"
};
const stored = () => localStorage.getItem(previewServiceActivationStorageKey);

afterEach(() => { cleanup(); localStorage.clear(); });

describe("preview service activation", () => {
  it("shares activation across account actors, preserves first consent, and resets only one account/service", () => {
    writePreviewServiceActivation(localStorage, activation);
    writePreviewServiceActivation(localStorage, { ...activation, acceptedBy: "other-actor", acceptedAt: "2026-10-12T02:00:00.000Z", enabledAt: "2026-10-12T02:00:00.000Z" });
    writePreviewServiceActivation(localStorage, { ...activation, accountId: "tenant-b" });
    writePreviewServiceActivation(localStorage, { ...activation, serviceKey: "mysql" });
    expect(readPreviewServiceActivation(stored(), activation)).toEqual(activation);
    expect(readPreviewServiceActivation(stored(), { ...activation, accountId: "tenant-c" })).toBeNull();
    resetPreviewServiceActivation(localStorage, activation);
    expect(readPreviewServiceActivation(stored(), activation)).toBeNull();
    expect(readPreviewServiceActivation(stored(), { ...activation, accountId: "tenant-b" })).toBeTruthy();
    expect(readPreviewServiceActivation(stored(), { ...activation, serviceKey: "mysql" })).toBeTruthy();
  });

  it.each([
    { ...activation, bearer: "secret-must-not-persist" },
    { ...activation, enabledAt: "2026-10-11T01:00:00.000Z" },
    { ...activation, acceptedBy: "" },
    { ...activation, accountId: "../tenant" }
  ])("rejects malformed or secret-bearing consent evidence", (value) => {
    localStorage.setItem(previewServiceActivationStorageKey, JSON.stringify({ version: 1, activations: [value] }));
    expect(readPreviewServiceActivation(stored(), activation)).toBeNull();
    expect(() => writePreviewServiceActivation(localStorage, value)).toThrow("INVALID_PREVIEW_SERVICE_ACTIVATION");
  });

  it("rejects duplicate scopes, unsupported envelopes and oversized records", () => {
    for (const raw of ["broken", JSON.stringify({ version: 2, activations: [activation] }), JSON.stringify({ version: 1, activations: [activation, activation] }), JSON.stringify({ version: 1, activations: Array.from({ length: 65 }, (_, index) => ({ ...activation, accountId: `tenant-${index}` })) })]) {
      expect(readPreviewServiceActivation(raw, activation)).toBeNull();
    }
  });

  it("demonstrates independent enablement and resource permissions without changing either capability", () => {
    const { result } = renderHook(() => usePreviewServiceActivation({ accountId: activation.accountId, actorId: activation.acceptedBy, serviceKey: activation.serviceKey, preview: true }));
    act(() => result.current.selectScenario("product-user"));
    expect(result.current.access).toEqual({ canEnable: false, mayLoadWorkspace: true });
    act(() => result.current.enable());
    expect(stored()).toBeNull();

    act(() => result.current.selectScenario("activation-admin"));
    expect(result.current.access).toEqual({ canEnable: true, mayLoadWorkspace: false });
    act(() => result.current.enable());
    expect(result.current.state.status).toBe("enabled");
    expect(result.current.access).toEqual({ canEnable: true, mayLoadWorkspace: false });
    act(() => result.current.selectScenario("product-user"));
    expect(result.current.state.status).toBe("enabled");
    expect(result.current.access).toEqual({ canEnable: false, mayLoadWorkspace: true });
  });

  it("isolates replacement tenants/services immediately and ignores stored preview activation in LIVE", () => {
    writePreviewServiceActivation(localStorage, activation);
    const { result, rerender } = renderHook((props) => usePreviewServiceActivation(props), { initialProps: { accountId: "tenant-a", actorId: "owner-a", serviceKey: "postgresql", preview: true } });
    expect(result.current.state.status).toBe("enabled");
    rerender({ accountId: "tenant-b", actorId: "owner-a", serviceKey: "postgresql", preview: true });
    expect(result.current.state.status).toBe("not-enabled");
    rerender({ accountId: "tenant-a", actorId: "owner-a", serviceKey: "mysql", preview: true });
    expect(result.current.state.status).toBe("not-enabled");
    rerender({ accountId: "tenant-a", actorId: "owner-a", serviceKey: "postgresql", preview: false });
    expect(result.current.state.status).toBe("unavailable");
    expect(result.current.access).toEqual({ canEnable: false, mayLoadWorkspace: false });
    act(() => result.current.enable());
    expect(readPreviewServiceActivation(stored(), activation)).toEqual(activation);
  });

  it("keeps failure local and retries without fabricating enabled state when storage fails", () => {
    const { result } = renderHook(() => usePreviewServiceActivation({ accountId: "tenant-a", actorId: "owner-a", serviceKey: "postgresql", preview: true }));
    const write = vi.spyOn(Storage.prototype, "setItem").mockImplementationOnce(() => { throw new Error("STORAGE_UNAVAILABLE"); });
    act(() => result.current.enable());
    expect(result.current.state.status).toBe("failed");
    expect(stored()).toBeNull();
    act(() => result.current.enable());
    expect(result.current.state.status).toBe("enabled");
    expect(write).toHaveBeenCalledTimes(2);
  });

  it("keeps retained activation visible and reports a failed reset separately", () => {
    writePreviewServiceActivation(localStorage, activation);
    const { result } = renderHook(() => usePreviewServiceActivation({ accountId: "tenant-a", actorId: "owner-a", serviceKey: "postgresql", preview: true }));
    vi.spyOn(Storage.prototype, "removeItem").mockImplementationOnce(() => { throw new Error("STORAGE_UNAVAILABLE"); });
    act(() => result.current.reset());
    expect(result.current.state.status).toBe("enabled");
    expect(result.current.resetFailed).toBe(true);
    act(() => result.current.reset());
    expect(result.current.state.status).toBe("not-enabled");
    expect(result.current.resetFailed).toBe(false);
  });

  it("shows unavailable rather than unopened when browser storage cannot be read", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("STORAGE_UNAVAILABLE"); });
    const { result } = renderHook(() => usePreviewServiceActivation({ accountId: "tenant-a", actorId: "owner-a", serviceKey: "postgresql", preview: true }));
    expect(result.current.state.status).toBe("unavailable");
  });
});
