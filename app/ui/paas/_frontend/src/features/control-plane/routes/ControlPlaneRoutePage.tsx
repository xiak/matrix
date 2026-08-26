import { ConsoleShellRenderer } from "../renderers/ConsoleShellRenderer";
import { parseControlPlaneRoute } from "./parseControlPlaneRoute";

export function ControlPlaneRoutePage({
  routeSegments
}: {
  routeSegments?: string[];
}) {
  return (
    <ConsoleShellRenderer selection={parseControlPlaneRoute(routeSegments)} />
  );
}
