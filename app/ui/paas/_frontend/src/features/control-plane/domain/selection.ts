export type ConsoleSection =
  | "overview"
  | "catalog"
  | "quotas"
  | "installations"
  | "regions"
  | "hosts"
  | "access";

export type ControlPlaneRouteSelection = {
  section: ConsoleSection;
};
