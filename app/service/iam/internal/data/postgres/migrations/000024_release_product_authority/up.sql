SET LOCAL ROLE matrix_iam_owner;

-- DEVOPS user facts reuse the same immutable IAM decision archive as the
-- other products. Closed source-owned SYSTEM facts have no user decision by
-- design: this function proves only the current DEVOPS producer, its sealed
-- installation, and the registered target tenant. Go's Audit action catalog
-- then admits only the exact source/action/system-actor union; delivery's
-- transaction/outbox remains authoritative for the business payload.
CREATE OR REPLACE FUNCTION iam.read_audit_evidence(origin_tenant text, producer text,
    producer_purpose text, producer_installation text, event jsonb)
RETURNS TABLE (installation_id text, event_document jsonb, decision_document jsonb, verifier_principal_id text, decision_contract_version integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE
    proof_tenant text;
    sealed_installation text;
    verifier_id text;
    removal_id text;
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',origin_tenant,true);
    SELECT receipt.installation_id INTO sealed_installation FROM iam.bootstrap_receipts AS receipt
    WHERE receipt.organization_id=origin_tenant AND receipt.installation_id=producer_installation;
    IF NOT FOUND OR producer_purpose NOT IN ('IAM','PAAS','DEVOPS','AUDIT')
        OR NOT EXISTS(SELECT 1 FROM iam.service_credentials AS credential
            JOIN iam.principals AS principal ON principal.tenant_id=credential.tenant_id AND principal.id=credential.principal_id
            JOIN iam.accounts AS organization ON organization.id=credential.tenant_id
            WHERE credential.tenant_id=origin_tenant AND credential.principal_id=producer
                AND credential.purpose=producer_purpose AND credential.revoked_at IS NULL
                AND principal.principal_type='SERVICE_ACCOUNT' AND principal.status='ACTIVE' AND organization.status='ACTIVE') THEN RETURN; END IF;
    IF event ? 'installationId' THEN
        IF event ? 'tenantId' OR event->>'installationId' IS DISTINCT FROM sealed_installation THEN RETURN; END IF;
        proof_tenant := origin_tenant;
    ELSE
        proof_tenant := event->>'tenantId';
        IF NOT EXISTS(SELECT 1 FROM iam.account_roots AS root WHERE root.account_id=proof_tenant) THEN RETURN; END IF;
    END IF;
    SELECT credential.principal_id INTO verifier_id FROM iam.service_credentials AS credential
    WHERE credential.tenant_id=origin_tenant AND credential.purpose='INSTALLATION_VERIFIER';
    PERFORM set_config('matrix.iam_tenant_id',proof_tenant,true);
    IF producer_purpose='IAM' THEN
        SELECT r.id INTO removal_id FROM iam.audit_outbox o
          LEFT JOIN iam.authenticator_removals r ON r.tenant_id=o.tenant_id AND r.event_id=o.event_id
          WHERE o.tenant_id=proof_tenant AND o.event_id=event->>'eventId'
            AND o.event_document->>'action'='iam.authenticator.removed';
        IF FOUND THEN
            IF removal_id IS NULL THEN RETURN; END IF;
            PERFORM iam.assert_authenticator_removal(proof_tenant,removal_id);
        END IF;
        RETURN QUERY SELECT sealed_installation, outbox.event_document, NULL::jsonb, verifier_id, NULL::integer
        FROM iam.audit_outbox AS outbox WHERE outbox.tenant_id=proof_tenant AND outbox.event_id=event->>'eventId'
          AND (NOT outbox.event_document->'actor' ? 'accessKeyId' OR
            iam.access_key_authorization_evidence_matches(proof_tenant,outbox.event_document->>'iamDecisionId'));
    ELSIF producer_purpose='DEVOPS' AND NOT (event ? 'iamDecisionId') THEN
        RETURN QUERY SELECT sealed_installation, NULL::jsonb, NULL::jsonb, verifier_id, NULL::integer;
    ELSE
        RETURN QUERY SELECT sealed_installation, outbox.event_document, decision.document, verifier_id, decision.contract_version
        FROM iam.authorization_decisions AS decision
        JOIN iam.audit_outbox AS outbox ON outbox.tenant_id=decision.tenant_id
            AND outbox.event_document->>'action'='iam.authorization.decided'
            AND outbox.event_document->>'iamDecisionId'=decision.id
        WHERE decision.tenant_id=proof_tenant AND decision.id=event->>'iamDecisionId' AND decision.allowed
          AND (decision.policy_evidence IS NULL OR NOT EXISTS(
              SELECT 1 FROM jsonb_array_elements(decision.policy_evidence) e
              WHERE iam.recorded_policy_version_matches(e) IS DISTINCT FROM true))
          AND (decision.boundary_evidence IS NULL OR decision.boundary_evidence->>'state'<>'BOUND'
              OR iam.recorded_policy_version_matches(decision.boundary_evidence))
          AND iam.access_key_authorization_evidence_matches(proof_tenant,decision.id)
          AND (CASE WHEN decision.contract_version IN (3,4,5,6,7) AND decision.subject_type='ROLE' THEN
            decision.principal_id IS NULL AND decision.role_evidence IS NOT NULL
            AND iam.role_authorization_evidence(proof_tenant,decision.role_evidence->>'sessionId')=decision.role_evidence
            AND decision.role_id=decision.role_evidence->>'roleId' AND decision.source_principal_id=decision.role_evidence->>'sourceUserId'
            ELSE decision.role_evidence IS NULL END);
    END IF;
END
$function$;

CREATE OR REPLACE FUNCTION iam.release_product_authority_contract_ready()
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT to_regclass('iam.role_bindings') IS NULL
       AND to_regprocedure('iam.ensure_release_service(text,text,text,text,text)') IS NOT NULL
       AND to_regprocedure('iam.verify_release_service(text,text,text,text)') IS NOT NULL
       AND iam.resource_kind_for_action('platform.product.read') = 'INSTALLATION'
       AND iam.resource_kind_for_action('devops.pipeline.activate') = 'PIPELINE'
       AND EXISTS (
            SELECT 1
              FROM pg_catalog.pg_constraint AS constraint_row
              JOIN pg_catalog.pg_class AS class
                ON class.oid = constraint_row.conrelid
              JOIN pg_catalog.pg_namespace AS namespace
                ON namespace.oid = class.relnamespace
             WHERE namespace.nspname = 'iam'
               AND class.relname = 'service_credentials'
               AND constraint_row.conname = 'service_credentials_values_valid'
               AND constraint_row.contype = 'c'
               AND constraint_row.convalidated
               AND position('PLATFORM' IN pg_catalog.pg_get_constraintdef(constraint_row.oid)) > 0
               AND position('DEVOPS' IN pg_catalog.pg_get_constraintdef(constraint_row.oid)) > 0
       )
       AND EXISTS (
            SELECT 1 FROM iam.current_authorization_profiles() AS profile
             WHERE profile.product = 'platform'
       )
       AND EXISTS (
            SELECT 1 FROM iam.current_authorization_profiles() AS profile
             WHERE profile.product = 'devops'
       )
$function$;
REVOKE ALL ON FUNCTION iam.release_product_authority_contract_ready()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,
    matrix_iam_backup_custody,matrix_iam_notification_worker,
    matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;

DO $release_product_authority_readiness_cutover$
BEGIN
    IF to_regprocedure('iam.readiness_v87()') IS NOT NULL THEN
        DROP FUNCTION iam.readiness_v87();
    END IF;
    ALTER FUNCTION iam.readiness() RENAME TO readiness_v87;
END $release_product_authority_readiness_cutover$;
REVOKE ALL ON FUNCTION iam.readiness_v87()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,
    matrix_iam_backup_custody,matrix_iam_notification_worker,
    matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;

CREATE FUNCTION iam.readiness()
RETURNS TABLE(ready boolean,schema_version bigint,checked_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $function$
DECLARE predecessor record;
BEGIN
    SELECT * INTO predecessor FROM iam.readiness_v87();
    RETURN QUERY SELECT
        predecessor.ready AND iam.release_product_authority_contract_ready(),
        88::bigint,
        predecessor.checked_at;
END
$function$;
REVOKE ALL ON FUNCTION iam.readiness()
  FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,
    matrix_iam_backup_custody,matrix_iam_notification_worker,
    matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
GRANT EXECUTE ON FUNCTION iam.readiness() TO matrix_iam_api;
