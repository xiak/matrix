export type ConsoleSection =
  | "overview"
  | "catalog"
  | "quotas"
  | "installations"
  | "regions"
  | "access";

export type ControlPlaneRouteSelection = {
  section: ConsoleSection;
};
