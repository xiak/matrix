import { requestJSON } from "@/infrastructure/http/jsonRequest";
import { parseAuditChainVerification, parseAuditRecordPage, type AuditQueryRequest, type AuditVerifyRequest } from "../domain/audit";
import type { AuditRepository } from "./auditRepository";

function post(credential: string, body: unknown): RequestInit {
  return {
    method: "POST",
    headers: { Authorization: `Bearer ${credential}`, "Content-Type": "application/json" },
    body: JSON.stringify(body)
  };
}

export const httpAuditRepository: AuditRepository = {
  async query(credential: string, request: AuditQueryRequest) {
    return parseAuditRecordPage(await requestJSON<unknown>("/api/audit/v1/records:query", post(credential, request)), "TENANT");
  },
  async verify(credential: string, request: AuditVerifyRequest) {
    return parseAuditChainVerification(await requestJSON<unknown>("/api/audit/v1/integrity:verify", post(credential, request)), "TENANT");
  }
};
