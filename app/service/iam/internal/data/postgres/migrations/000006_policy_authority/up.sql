-- The seed document is supplied by the IAM Go policy/canonicalization owner.
-- This fragment runs inside the same IAM schema/data/function transaction.
DO $policy_cutover$
DECLARE
    seeds jsonb := __POLICY_SEED_DOCUMENT__;
    seed jsonb;
    legacy record;
    effective_now timestamptz(6) := transaction_timestamp();
BEGIN
    FOR seed IN SELECT value FROM jsonb_array_elements(seeds) LOOP
        INSERT INTO iam.policies(id,management,display_name,authority_scope,status,default_version_id,
            resource_version,created_at,updated_at)
        VALUES(seed->>'policyId','SYSTEM',seed->>'displayName',seed->>'scope','ACTIVE',seed->>'versionId',
            1,effective_now,effective_now) ON CONFLICT(id) DO NOTHING;
        IF NOT EXISTS(SELECT 1 FROM iam.policies AS policy WHERE policy.id=seed->>'policyId'
            AND policy.management='SYSTEM' AND policy.owner_tenant_id IS NULL AND policy.authority_scope=seed->>'scope') THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM system policy identity conflicts';
        END IF;
        INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at)
        VALUES(seed->>'policyId',seed->>'versionId',seed->>'scope',seed->'document',
            seed->>'canonicalDocument',seed->>'contentDigest',effective_now)
        ON CONFLICT(policy_id,id) DO NOTHING;
        IF NOT EXISTS(SELECT 1 FROM iam.policy_versions AS version
            WHERE version.policy_id=seed->>'policyId' AND version.id=seed->>'versionId'
            AND version.authority_scope=seed->>'scope' AND version.document=seed->'document'
            AND version.canonical_document=seed->>'canonicalDocument' AND version.content_digest=seed->>'contentDigest') THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM immutable policy version conflicts';
        END IF;
    END LOOP;

    IF to_regclass('iam.role_bindings') IS NOT NULL THEN
        -- The preflight holds an exclusive legacy-table lock. This migration-
        -- local owner policy permits copying every tenant, including disabled
        -- ones, without broadening any committed runtime access policy.
        EXECUTE 'CREATE POLICY policy_cutover_owner_read ON iam.role_bindings FOR SELECT TO matrix_iam_owner USING (true)';
        FOR legacy IN EXECUTE 'SELECT * FROM iam.role_bindings ORDER BY tenant_id,id' LOOP
            SELECT value INTO seed FROM jsonb_array_elements(seeds) WHERE value->>'legacyRole'=legacy.role_name;
            IF seed IS NULL THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM historical role has no explicit policy mapping';
            END IF;
            PERFORM set_config('matrix.iam_tenant_id',legacy.tenant_id,true);
            INSERT INTO iam.policy_attachments(tenant_id,id,principal_id,policy_id,resource_version,created_at,updated_at,revoked_at)
            VALUES(legacy.tenant_id,legacy.id,legacy.principal_id,seed->>'policyId',legacy.resource_version,
                legacy.created_at,legacy.updated_at,legacy.revoked_at);
        END LOOP;
    END IF;
END $policy_cutover$;

DROP FUNCTION IF EXISTS iam.put_role_binding(text,text,text,text,text,text,jsonb);
DROP FUNCTION IF EXISTS iam.lookup_role_binding_role(text,text);
DROP FUNCTION IF EXISTS iam.revoke_role_binding(text,text,text,text,jsonb);
DROP FUNCTION IF EXISTS iam.lookup_service_roles(text,text);
DROP TABLE IF EXISTS iam.role_bindings;

SET CONSTRAINTS iam.policies_default_version_fk IMMEDIATE;
