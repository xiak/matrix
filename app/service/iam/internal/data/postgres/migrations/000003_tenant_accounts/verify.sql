DO $verify_accounts$
BEGIN
    IF (SELECT schema_version FROM iam.readiness()) IS DISTINCT FROM 6::bigint THEN
        RAISE EXCEPTION 'IAM account/proof schema version is incompatible';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc AS claim
         WHERE claim.oid=to_regprocedure('iam.claim_audit_event(text,integer)')
           AND claim.proallargtypes=ARRAY['text'::regtype::oid,'integer'::regtype::oid,
               'text'::regtype::oid,'text'::regtype::oid,'jsonb'::regtype::oid,
               'integer'::regtype::oid,'bigint'::regtype::oid,'timestamptz'::regtype::oid,'text'::regtype::oid]
           AND claim.proargnames[3:9]=ARRAY['tenant_id','event_id','event_document','attempts',
               'fencing_token','lease_expires_at','installation_id']
           AND claim.proargmodes[3:9]=ARRAY['t','t','t','t','t','t','t']::"char"[]
    ) THEN
        RAISE EXCEPTION 'IAM Audit claim owner/installation contract is incompatible';
    END IF;
    IF to_regclass('iam.accounts') IS NULL OR to_regclass('iam.organizations') IS NOT NULL
        OR to_regclass('iam.account_aliases') IS NULL OR to_regclass('iam.account_roots') IS NULL
        OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute
            WHERE attrelid='iam.login_index'::regclass AND attname='account_owner' AND NOT attisdropped)
        OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint
            WHERE conrelid='iam.login_index'::regclass AND contype='p' AND array_length(conkey,1)=2)
        OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint
            WHERE conrelid='iam.account_roots'::regclass AND contype='p')
        OR (SELECT count(*) FROM pg_catalog.pg_constraint
            WHERE conrelid='iam.account_roots'::regclass AND contype='f') <> 3
        OR to_regclass('iam.login_primary_name_uq') IS NOT NULL
        OR to_regclass('iam.login_primary_tenant_uq') IS NOT NULL
        OR to_regclass('iam.account_alias_active_uq') IS NULL THEN
        RAISE EXCEPTION 'IAM account identity constraints are unavailable';
    END IF;
    IF has_table_privilege('matrix_iam_api','iam.account_aliases','SELECT,INSERT,UPDATE,DELETE')
        OR has_table_privilege('matrix_iam_worker','iam.account_aliases','SELECT,INSERT,UPDATE,DELETE')
        OR has_table_privilege('public','iam.account_aliases','SELECT,INSERT,UPDATE,DELETE')
        OR has_table_privilege('matrix_iam_api','iam.account_roots','SELECT,INSERT,UPDATE,DELETE')
        OR has_table_privilege('matrix_iam_worker','iam.account_roots','SELECT,INSERT,UPDATE,DELETE')
        OR has_table_privilege('public','iam.account_roots','SELECT,INSERT,UPDATE,DELETE')
        OR has_function_privilege('matrix_iam_api','iam.account_snapshot(text)','EXECUTE')
        OR has_function_privilege('matrix_iam_api','iam.user_snapshot(text,text)','EXECUTE')
        OR has_function_privilege('public','iam.read_audit_evidence(text,text,text,text,jsonb)','EXECUTE')
        OR has_function_privilege('matrix_iam_worker','iam.read_audit_evidence(text,text,text,text,jsonb)','EXECUTE')
        OR NOT has_function_privilege('matrix_iam_api','iam.read_audit_evidence(text,text,text,text,jsonb)','EXECUTE')
        OR NOT has_function_privilege('matrix_iam_api','iam.read_account(text,text)','EXECUTE')
        OR NOT has_function_privilege('matrix_iam_api','iam.read_account_as_platform(text,text,text,text)','EXECUTE')
        OR NOT has_function_privilege('matrix_iam_api','iam.read_account_root(text,text,text,text)','EXECUTE')
        OR NOT has_function_privilege('matrix_iam_api','iam.list_users(text,text,text,text)','EXECUTE')
        OR NOT has_function_privilege('matrix_iam_api','iam.list_accounts(text,text,text,text)','EXECUTE')
        OR NOT has_function_privilege('matrix_iam_api','iam.create_account(text,text,text,text,text,text,text,text,text,jsonb)','EXECUTE')
        OR NOT has_function_privilege('matrix_iam_api','iam.set_account_status(text,text,text,text,text,bigint,jsonb)','EXECUTE')
        OR NOT has_function_privilege('matrix_iam_api','iam.recover_root_credentials(text,text,text,text,text,bigint,text,text,jsonb)','EXECUTE')
        OR NOT has_function_privilege('matrix_iam_api','iam.set_account_alias(text,text,text,text,bigint,jsonb)','EXECUTE')
        OR NOT has_function_privilege('matrix_iam_api','iam.change_user(text,text,text,text,bigint,text,text,jsonb)','EXECUTE')
        OR has_function_privilege('public','iam.create_account(text,text,text,text,text,text,text,text,text,jsonb)','EXECUTE')
        OR has_function_privilege('public','iam.read_account_as_platform(text,text,text,text)','EXECUTE')
        OR has_function_privilege('public','iam.read_account_root(text,text,text,text)','EXECUTE')
        OR has_function_privilege('public','iam.set_account_status(text,text,text,text,text,bigint,jsonb)','EXECUTE')
        OR has_function_privilege('public','iam.recover_root_credentials(text,text,text,text,text,bigint,text,text,jsonb)','EXECUTE')
        OR has_function_privilege('matrix_iam_worker','iam.create_account(text,text,text,text,text,text,text,text,text,jsonb)','EXECUTE')
        OR has_function_privilege('matrix_iam_worker','iam.set_account_status(text,text,text,text,text,bigint,jsonb)','EXECUTE')
        OR has_function_privilege('matrix_iam_worker','iam.recover_root_credentials(text,text,text,text,text,bigint,text,text,jsonb)','EXECUTE')
        OR to_regprocedure('iam.can_produce_audit(text,text,text,text)') IS NOT NULL
        OR to_regprocedure('iam.is_bootstrap_administrator(text,text)') IS NOT NULL
        OR to_regprocedure('iam.read_organization(text,text,text,text)') IS NOT NULL
        OR to_regprocedure('iam.set_organization_status(text,text,text,text,text,bigint,jsonb)') IS NOT NULL
        OR to_regprocedure('iam.recover_organization_administrator(text,text,text,text,text,bigint,text,text,jsonb)') IS NOT NULL
        OR to_regprocedure('iam.list_principals(text,text,text,text)') IS NOT NULL
        OR to_regprocedure('iam.create_organization(text,text,text,text,text,text,text,text,text,jsonb)') IS NOT NULL
        OR to_regprocedure('iam.change_subaccount(text,text,text,text,bigint,text,text,jsonb)') IS NOT NULL
        OR to_regprocedure('iam.principal_snapshot(text,text)') IS NOT NULL THEN
        RAISE EXCEPTION 'IAM account API boundary is invalid';
    END IF;
END
$verify_accounts$;
