SET LOCAL ROLE matrix_iam_owner;
DO $verify_service_roles$
DECLARE seeds jsonb:=__SERVICE_ROLE_TEMPLATE_SEEDS__; seed jsonb;
BEGIN
    IF NOT iam.service_role_contract_ready() THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM service role storage contract is unavailable'; END IF;
    IF (SELECT schema_version FROM iam.readiness()) IS DISTINCT FROM 81::bigint THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM service role schema version is unavailable'; END IF;
    FOR seed IN SELECT value FROM jsonb_array_elements(seeds) LOOP
        IF NOT EXISTS(SELECT 1 FROM iam.service_role_templates template
          WHERE template.id=seed->>'id' AND template.version=(seed->>'version')::bigint
            AND template.canonical_spec=seed->>'canonicalSpec' AND template.content_digest=seed->>'contentDigest'
            AND (template.status=seed->>'status'
              OR (template.status='RETIRED' AND seed->>'status'='ACTIVE'))) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM service role template seed is unavailable'; END IF;
        IF NOT EXISTS(SELECT 1 FROM iam.policy_versions version JOIN iam.policies policy ON policy.id=version.policy_id
          WHERE version.policy_id=(seed->>'canonicalSpec')::jsonb#>>'{policyVersion,policyId}'
            AND version.id=(seed->>'canonicalSpec')::jsonb#>>'{policyVersion,versionId}'
            AND version.content_digest=(seed->>'canonicalSpec')::jsonb#>>'{policyVersion,contentDigest}'
            AND version.retired_at IS NULL AND policy.management='SYSTEM' AND policy.status='ACTIVE'
            AND policy.authority_scope='TENANT') THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM service role permission ceiling is unavailable'; END IF;
    END LOOP;
    IF EXISTS(SELECT 1 FROM iam.service_role_templates template WHERE template.status='ACTIVE'
      AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(seeds) AS catalog_entry(value)
        WHERE catalog_entry.value->>'id'=template.id AND (catalog_entry.value->>'version')::bigint=template.version
          AND catalog_entry.value->>'contentDigest'=template.content_digest AND catalog_entry.value->>'status'='ACTIVE')) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM active service role template set conflicts'; END IF;
END $verify_service_roles$;
