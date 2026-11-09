import type { AuditChainVerification, AuditQueryRequest, AuditRecordPage, AuditVerifyRequest } from "../domain/audit";

export interface AuditRepository {
  query(credential: string, request: AuditQueryRequest, tenantId: string): Promise<AuditRecordPage>;
  verify(credential: string, request: AuditVerifyRequest, tenantId: string): Promise<AuditChainVerification>;
}
