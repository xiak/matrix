/** Recognize the pinned Turbopack/webpack asset failure, never arbitrary API/runtime errors. */
export function isChunkLoadFailure(error: unknown, origin: string): boolean {
  try {
    if (!(error instanceof Error) || error.name !== "ChunkLoadError" || typeof error.message !== "string") return false;
    const turbopack = /^Failed to load chunk (\S+)(?:\s|$)/.exec(error.message)?.[1];
    const webpack = /^Loading chunk \S+ failed\.\s*\((?:error|missing|timeout): (\S+)\)$/.exec(error.message)?.[1];
    const reference = turbopack ?? webpack;
    if (!reference) return false;
    const url = new URL(reference, origin);
    return url.origin === origin && !url.search && !url.hash &&
      /^\/_next\/static\/chunks\/[A-Za-z0-9_.-]+\.js$/.test(url.pathname);
  } catch { return false; }
}

const requestedDocuments = new WeakSet<Document>();

/** The document, not a React mount, owns the irreversible navigation attempt. */
export function reloadDocumentOnce(current: Document): void {
  if (requestedDocuments.has(current) || !current.location) return;
  requestedDocuments.add(current);
  current.location.reload();
}
