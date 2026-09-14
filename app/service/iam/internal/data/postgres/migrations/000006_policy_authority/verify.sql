DO $verify_policy_authority$
DECLARE table_name text; function_name text; protection record;
BEGIN
    IF to_regclass('iam.role_bindings') IS NOT NULL THEN
        RAISE EXCEPTION 'IAM legacy role authority remains writable';
    END IF;
    FOREACH function_name IN ARRAY ARRAY['iam.put_role_binding(text,text,text,text,text,text,jsonb)',
        'iam.lookup_role_binding_role(text,text)','iam.revoke_role_binding(text,text,text,text,jsonb)',
        'iam.lookup_service_roles(text,text)','iam.record_authorization(text,text,jsonb,jsonb)'] LOOP
        IF to_regprocedure(function_name) IS NOT NULL THEN
            RAISE EXCEPTION 'IAM legacy permission entrypoint remains present';
        END IF;
    END LOOP;
    FOREACH table_name IN ARRAY ARRAY['policies','policy_versions','policy_attachments'] LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class AS relation
            WHERE relation.oid=to_regclass('iam.'||table_name) AND relation.relrowsecurity AND relation.relforcerowsecurity
            AND relation.relowner='matrix_iam_owner'::regrole) THEN
            RAISE EXCEPTION 'IAM policy ownership or forced RLS is invalid';
        END IF;
    END LOOP;
    FOR protection IN SELECT * FROM (VALUES
        ('policies','policy_metadata_transitions'),('policies','policy_metadata_cannot_be_deleted'),
        ('policies','policy_metadata_cannot_be_truncated'),('policy_versions','policy_versions_are_immutable'),
        ('policy_versions','policy_versions_cannot_be_truncated'),('policy_attachments','policy_attachment_transitions'),
        ('policy_attachments','policy_attachments_cannot_be_deleted'),('policy_attachments','policy_attachments_cannot_be_truncated'),
        ('authorization_decisions','authorization_decisions_are_immutable'),('authorization_decisions','authorization_decisions_cannot_be_truncated')
    ) AS expected(table_name,trigger_name) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger AS trigger
            WHERE trigger.tgrelid=to_regclass('iam.'||protection.table_name) AND trigger.tgname=protection.trigger_name
            AND trigger.tgenabled='A' AND NOT trigger.tgisinternal) THEN
            RAISE EXCEPTION 'IAM policy history protection is invalid';
        END IF;
    END LOOP;
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint AS relationship
        WHERE relationship.conrelid='iam.policies'::regclass AND relationship.confrelid='iam.policy_versions'::regclass
        AND relationship.conname='policies_default_version_fk' AND relationship.contype='f'
        AND relationship.convalidated AND relationship.condeferrable) THEN
        RAISE EXCEPTION 'IAM default policy version is not constrained to its owner';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS lookup
        WHERE lookup.oid=to_regprocedure('iam.lookup_session(text)')
        AND cardinality(lookup.proallargtypes)=23 AND lookup.proargnames[23]='policies'
        AND lookup.proallargtypes[23]='jsonb'::regtype::oid) THEN
        RAISE EXCEPTION 'IAM session policy snapshot shape is invalid';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute AS evidence
        WHERE evidence.attrelid='iam.authorization_decisions'::regclass AND evidence.attname='policy_evidence'
          AND evidence.atttypid='jsonb'::regtype AND NOT evidence.attisdropped)
        OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS recorder
            WHERE recorder.oid=to_regprocedure('iam.record_authorization(text,text,jsonb,jsonb,jsonb)')
              AND recorder.prosecdef AND recorder.proowner='matrix_iam_owner'::regrole) THEN
        RAISE EXCEPTION 'IAM decision provenance contract is invalid';
    END IF;
    IF has_function_privilege('matrix_iam_api','iam.current_policy_snapshot(text,text)','EXECUTE')
        OR has_function_privilege('matrix_iam_worker','iam.current_policy_snapshot(text,text)','EXECUTE')
        OR has_function_privilege('public','iam.current_policy_snapshot(text,text)','EXECUTE') THEN
        RAISE EXCEPTION 'IAM internal policy projection is public';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS directory
        WHERE directory.oid=to_regprocedure('iam.list_policies(text,text,text,text)')
          AND directory.prorettype='jsonb'::regtype AND NOT directory.proretset
          AND directory.prosecdef AND directory.proowner='matrix_iam_owner'::regrole) THEN
        RAISE EXCEPTION 'IAM policy directory function shape is invalid';
    END IF;
END $verify_policy_authority$;

DO $verify_customer_policy_publication$
DECLARE function_name text;
BEGIN
    IF (SELECT schema_version FROM iam.readiness()) IS DISTINCT FROM 16::bigint THEN
        RAISE EXCEPTION 'IAM policy publication schema version is invalid';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid='iam.policy_versions'::regclass
       AND attname='retired_at' AND atttypid='timestamptz'::regtype AND NOT attnotnull AND NOT attisdropped)
       OR EXISTS(SELECT 1 FROM iam.policies p JOIN iam.policy_versions v ON v.policy_id=p.id AND v.id=p.default_version_id WHERE v.retired_at IS NOT NULL)
       OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='iam.policy_versions'::regclass
          AND tgname='policy_versions_are_immutable' AND tgenabled='A' AND tgfoid='iam.guard_policy_version_change()'::regprocedure) THEN
        RAISE EXCEPTION 'IAM policy version retirement shape or default is invalid';
    END IF;
    FOREACH function_name IN ARRAY ARRAY['iam.read_policy(text,text,text,text)',
        'iam.create_policy(text,text,text,text,text,text,text,text,jsonb)',
        'iam.list_policy_versions(text,text,text,text)','iam.read_policy_version(text,text,text,text,text)',
        'iam.create_policy_version(text,text,text,text,bigint,text,text,text,jsonb)','iam.set_default_policy_version(text,text,text,text,bigint,text,jsonb)',
        'iam.update_policy(text,text,text,text,bigint,text,jsonb)','iam.delete_policy(text,text,text,text,bigint,jsonb)','iam.delete_policy_version(text,text,text,text,text,bigint,jsonb)'] LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS entry WHERE entry.oid=to_regprocedure(function_name)
            AND entry.prorettype='jsonb'::regtype AND NOT entry.proretset AND entry.prosecdef
            AND entry.proowner='matrix_iam_owner'::regrole AND 'search_path=pg_catalog, pg_temp'=ANY(entry.proconfig))
           OR NOT has_function_privilege('matrix_iam_api',function_name,'EXECUTE')
           OR has_function_privilege('matrix_iam_worker',function_name,'EXECUTE')
           OR has_function_privilege('matrix_iam_credential_recovery',function_name,'EXECUTE')
           OR has_function_privilege('public',function_name,'EXECUTE') THEN
            RAISE EXCEPTION 'IAM policy publication function boundary is invalid';
        END IF;
    END LOOP;
    FOREACH function_name IN ARRAY ARRAY['iam.assert_customer_policy_document(text,text)','iam.policy_detail_snapshot(text,text)',
        'iam.policy_version_detail(text,text,text)','iam.guard_policy_version_change()','iam.lock_policy_publisher(text,text)','iam.lock_customer_policy_publisher(text,text,text)','iam.policy_version_intent_replayed(text,text,jsonb)'] LOOP
        IF to_regprocedure(function_name) IS NULL OR has_function_privilege('matrix_iam_api',function_name,'EXECUTE')
           OR has_function_privilege('matrix_iam_worker',function_name,'EXECUTE')
           OR has_function_privilege('matrix_iam_credential_recovery',function_name,'EXECUTE')
           OR has_function_privilege('public',function_name,'EXECUTE') THEN
            RAISE EXCEPTION 'IAM internal policy document boundary is invalid';
        END IF;
    END LOOP;
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_index WHERE indexrelid=to_regclass('iam.customer_policies_active_name_uq')
        AND indrelid='iam.policies'::regclass AND indisunique AND indisvalid AND indnkeyatts=2 AND indpred IS NOT NULL)
       OR iam.resource_kind_for_action('iam.policy.create') IS DISTINCT FROM 'ACCOUNT'
       OR iam.resource_kind_for_action('iam.policy.read') IS DISTINCT FROM 'POLICY'
       OR iam.is_platform_action('iam.policy.create') OR iam.is_platform_action('iam.policy.read') THEN
        RAISE EXCEPTION 'IAM customer policy identity or action mapping is invalid';
    END IF;
END $verify_customer_policy_publication$;
