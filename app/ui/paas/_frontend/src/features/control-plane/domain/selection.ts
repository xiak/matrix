export type ConsoleSection =
  | "overview"
  | "catalog"
  | "quotas"
  | "installations"
  | "deployments"
  | "regions"
  | "hosts"
  | "access";

export type ControlPlaneRouteSelection = {
  section: ConsoleSection;
};
