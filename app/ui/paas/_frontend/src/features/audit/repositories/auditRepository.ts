import type { AuditChainVerification, AuditQueryRequest, AuditRecordPage, AuditVerifyRequest } from "../domain/audit";

export interface AuditRepository {
  query(credential: string, request: AuditQueryRequest): Promise<AuditRecordPage>;
  verify(credential: string, request: AuditVerifyRequest): Promise<AuditChainVerification>;
}
