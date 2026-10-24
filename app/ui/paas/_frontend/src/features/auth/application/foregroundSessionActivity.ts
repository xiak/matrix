import { HttpProblem } from "@/infrastructure/http/jsonRequest";

export const foregroundSessionTouchThrottleMilliseconds = 60_000;

const modifierOnlyKeys = new Set([
  "Alt",
  "AltGraph",
  "CapsLock",
  "Control",
  "Fn",
  "FnLock",
  "Hyper",
  "Meta",
  "NumLock",
  "ScrollLock",
  "Shift",
  "Super",
  "Symbol",
  "SymbolLock"
]);

type ForegroundActivityEvent = Pick<Event, "isTrusted" | "type"> & { key?: string };

export function isExplicitForegroundSessionActivity(
  event: ForegroundActivityEvent,
  visibilityState: DocumentVisibilityState
): boolean {
  if (!event.isTrusted || visibilityState !== "visible") return false;
  if (event.type === "pointerdown" || event.type === "popstate") return true;
  return event.type === "keydown" && typeof event.key === "string" && event.key.length > 0 &&
    event.key !== "Unidentified" && !modifierOnlyKeys.has(event.key);
}

export type ForegroundSessionTouchReporter = {
  handle(event: ForegroundActivityEvent, visibilityState: DocumentVisibilityState): void;
  dispose(): void;
};

export function createForegroundSessionTouchReporter({
  expire,
  isCurrent,
  now,
  touch
}: {
  expire(): void;
  isCurrent(): boolean;
  now(): number;
  touch(): Promise<unknown>;
}): ForegroundSessionTouchReporter {
  let disposed = false;
  let inFlight = false;
  let lastAttemptAt = Number.NEGATIVE_INFINITY;

  return {
    handle(event, visibilityState) {
      if (disposed || inFlight || !isCurrent() || !isExplicitForegroundSessionActivity(event, visibilityState)) return;
      const attemptedAt = now();
      if (!Number.isFinite(attemptedAt) || attemptedAt - lastAttemptAt < foregroundSessionTouchThrottleMilliseconds) return;
      lastAttemptAt = attemptedAt;
      inFlight = true;
      let request: Promise<unknown>;
      try {
        request = touch();
      } catch (failure) {
        request = Promise.reject(failure);
      }
      void request.catch((failure: unknown) => {
        if (!disposed && isCurrent() && failure instanceof HttpProblem && failure.status === 401) expire();
      }).finally(() => {
        inFlight = false;
      });
    },
    dispose() {
      disposed = true;
    }
  };
}
