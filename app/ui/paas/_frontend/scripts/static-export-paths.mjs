export function portableStaticExportPath(value) {
  const normalized = value.replaceAll("\\", "/");
  const segments = normalized.split("/");
  const nextSegment = segments.findIndex((segment) => segment.startsWith("__next."));
  if (nextSegment < 0 || segments.at(-1) !== "__PAGE__.txt") return normalized;

  const suffix = segments.slice(nextSegment);
  if (suffix.some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new Error("Next.js static export contains an unsafe page path");
  }
  return [...segments.slice(0, nextSegment), suffix.join(".")].join("/");
}
