export type ConsoleSection =
  | "overview"
  | "products"
  | "resources"
  | "operations"
  | "catalog"
  | "quotas"
  | "installations"
  | "regions"
  | "devops"
  | "observability"
  | "access";

export type ControlPlaneRouteSelection = {
  section: ConsoleSection;
};
