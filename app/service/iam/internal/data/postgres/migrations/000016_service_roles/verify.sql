SET LOCAL ROLE matrix_iam_owner;
DO $verify_service_roles$
DECLARE seeds jsonb:=__SERVICE_ROLE_TEMPLATE_SEEDS__; seed jsonb;
    tenant text; prior_tenant text:=current_setting('matrix.iam_tenant_id',true);
BEGIN
    IF NOT iam.service_role_contract_ready() THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM service role storage contract is unavailable'; END IF;
    IF (SELECT schema_version FROM iam.readiness()) IS DISTINCT FROM 83::bigint THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM service role schema version is unavailable'; END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc entry
        WHERE entry.oid=to_regprocedure('iam.list_service_role_templates(text,text,text)')
          AND entry.prorettype='jsonb'::regtype AND NOT entry.proretset AND entry.prosecdef
          AND entry.proowner='matrix_iam_owner'::regrole AND 'search_path=pg_catalog, pg_temp'=ANY(entry.proconfig))
      OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc entry
        WHERE entry.oid=to_regprocedure('iam.read_service_role_template(text,bigint,text)')
          AND entry.prorettype='jsonb'::regtype AND NOT entry.proretset AND entry.prosecdef
          AND entry.proowner='matrix_iam_owner'::regrole AND 'search_path=pg_catalog, pg_temp'=ANY(entry.proconfig))
      OR NOT has_function_privilege('matrix_iam_api','iam.list_service_role_templates(text,text,text)','EXECUTE')
      OR NOT has_function_privilege('matrix_iam_api','iam.read_service_role_template(text,bigint,text)','EXECUTE')
      OR has_function_privilege('matrix_iam_worker','iam.list_service_role_templates(text,text,text)','EXECUTE')
      OR has_function_privilege('matrix_iam_worker','iam.read_service_role_template(text,bigint,text)','EXECUTE')
      OR has_function_privilege('public','iam.list_service_role_templates(text,text,text)','EXECUTE')
      OR has_function_privilege('public','iam.read_service_role_template(text,bigint,text)','EXECUTE') THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM service role template read boundary is unavailable'; END IF;
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
    FOR tenant IN SELECT root.account_id FROM iam.account_roots root ORDER BY root.account_id COLLATE "C" LOOP
        PERFORM set_config('matrix.iam_tenant_id',tenant,true);
        IF EXISTS(
          SELECT 1 FROM iam.policy_attachments attachment
          JOIN iam.service_role_templates template
            ON template.canonical_spec::jsonb#>>'{policyVersion,policyId}'=attachment.policy_id
          WHERE attachment.tenant_id=tenant AND attachment.revoked_at IS NULL
        ) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM service role permission ceiling is directly attached'; END IF;
    END LOOP;
    PERFORM set_config('matrix.iam_tenant_id',COALESCE(prior_tenant,''),true);
END $verify_service_roles$;
