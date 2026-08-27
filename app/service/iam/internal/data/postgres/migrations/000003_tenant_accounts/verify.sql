DO $verify_accounts$
BEGIN
    IF to_regclass('iam.account_aliases') IS NULL
        OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid='iam.login_index'::regclass AND attname='account_owner' AND attnotnull)
        OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid='iam.login_index'::regclass AND contype='p' AND array_length(conkey,1)=2)
        OR to_regclass('iam.login_primary_name_uq') IS NULL OR to_regclass('iam.login_primary_tenant_uq') IS NULL
        OR to_regclass('iam.account_alias_active_uq') IS NULL THEN
        RAISE EXCEPTION 'IAM account identity constraints are unavailable';
    END IF;
    IF has_table_privilege('matrix_iam_api','iam.account_aliases','SELECT,INSERT,UPDATE,DELETE')
        OR has_table_privilege('matrix_iam_worker','iam.account_aliases','SELECT,INSERT,UPDATE,DELETE')
        OR has_table_privilege('public','iam.account_aliases','SELECT,INSERT,UPDATE,DELETE')
        OR has_function_privilege('public','iam.create_organization(text,text,text,text,text,text,text,text,text,jsonb)','EXECUTE')
        OR has_function_privilege('matrix_iam_api','iam.account_snapshot(text)','EXECUTE')
        OR has_function_privilege('public','iam.can_produce_audit(text,text,text,text)','EXECUTE')
        OR has_function_privilege('matrix_iam_worker','iam.can_produce_audit(text,text,text,text)','EXECUTE')
        OR NOT has_function_privilege('matrix_iam_api','iam.can_produce_audit(text,text,text,text)','EXECUTE')
        OR NOT has_function_privilege('matrix_iam_api','iam.set_account_alias(text,text,text,text,bigint,jsonb)','EXECUTE') THEN
        RAISE EXCEPTION 'IAM account API boundary is invalid';
    END IF;
END
$verify_accounts$;
