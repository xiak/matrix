export type ConsoleSection =
  | "overview"
  | "catalog"
  | "quotas"
  | "installations"
  | "regions";

export type ControlPlaneRouteSelection = {
  section: ConsoleSection;
};
