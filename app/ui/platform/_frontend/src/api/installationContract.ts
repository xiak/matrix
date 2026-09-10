// Generated from api/installation/v1/openapi.json. Run npm run generate:contracts.
import type { ContractValidators } from "./validation";
import * as compiled from "./installationValidate";

export type InstalledProduct = ({ "id": ProductID; "observedAt": Timestamp; "reason"?: ProductReason; "routeKey": string; "state": ProductState; "version": string; }) & (unknown) & (unknown) & (unknown) & (unknown);
export type InstalledProductList = { "apiVersion": "installation.matrix.xiak.com/v1"; "kind": "InstalledProductList"; "observedAt": Timestamp; "products": Array<InstalledProduct>; "releaseId": string; "releaseVersion": string; };
export type ProductID = "APPLICATION_PAAS" | "DEVOPS";
export type ProductReason = "DEPENDENCY_UNAVAILABLE" | "OBSERVATION_STALE";
export type ProductState = "READY" | "DEGRADED" | "UNAVAILABLE";
export type Timestamp = string;

export const validators: ContractValidators = compiled;
