DO $verify_local_recovery$
DECLARE function_name text; role_name text;
BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='matrix_iam_credential_recovery'
        AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls) THEN
        RAISE EXCEPTION 'IAM local recovery role is unavailable or overprivileged';
    END IF;
    IF EXISTS(SELECT 1 FROM pg_catalog.pg_roles AS inherited
        WHERE inherited.rolname <> 'matrix_iam_credential_recovery'
          AND pg_has_role('matrix_iam_credential_recovery',inherited.oid,'MEMBER')) THEN
        RAISE EXCEPTION 'IAM local recovery role inherits unrelated authority';
    END IF;
    FOREACH role_name IN ARRAY ARRAY['matrix_iam_owner','matrix_iam_migrator','matrix_iam_api','matrix_iam_worker'] LOOP
        IF pg_has_role('matrix_iam_credential_recovery',role_name,'MEMBER')
            OR (role_name IN ('matrix_iam_api','matrix_iam_worker') AND pg_has_role(role_name,'matrix_iam_credential_recovery','MEMBER')) THEN
            RAISE EXCEPTION 'IAM local recovery role membership is invalid';
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM information_schema.role_table_grants WHERE table_schema='iam'
        AND grantee='matrix_iam_credential_recovery') THEN
        RAISE EXCEPTION 'IAM local recovery role has table privileges';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class WHERE oid=to_regclass('iam.local_credential_recoveries')
        AND relrowsecurity AND relforcerowsecurity AND relowner='matrix_iam_owner'::regrole) THEN
        RAISE EXCEPTION 'IAM local recovery receipt RLS is unavailable';
    END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid='iam.local_credential_recoveries'::regclass
        AND tgname IN ('local_recovery_receipts_are_immutable','local_recovery_receipts_cannot_be_truncated')
        AND NOT tgisinternal AND tgenabled='A') <> 2 THEN
        RAISE EXCEPTION 'IAM local recovery receipt immutability is unavailable';
    END IF;
    FOREACH function_name IN ARRAY ARRAY[
        'iam.inspect_local_credential_recovery(jsonb,text,text)',
        'iam.recover_local_credentials(jsonb,jsonb,text,text,text,jsonb)'] LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc WHERE oid=to_regprocedure(function_name)
            AND prorettype='jsonb'::regtype AND NOT proretset AND prosecdef AND proowner='matrix_iam_owner'::regrole)
            OR NOT has_function_privilege('matrix_iam_credential_recovery',function_name,'EXECUTE') THEN
            RAISE EXCEPTION 'IAM local recovery function shape is unavailable';
        END IF;
        FOREACH role_name IN ARRAY ARRAY['public','matrix_iam_api','matrix_iam_worker'] LOOP
            IF has_function_privilege(role_name,function_name,'EXECUTE') THEN
                RAISE EXCEPTION 'IAM runtime can invoke local recovery';
            END IF;
        END LOOP;
    END LOOP;
    IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS procedure JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
        WHERE namespace.nspname='iam' AND has_function_privilege('matrix_iam_credential_recovery',procedure.oid,'EXECUTE')
        AND procedure.oid NOT IN ('iam.inspect_local_credential_recovery(jsonb,text,text)'::regprocedure,
            'iam.recover_local_credentials(jsonb,jsonb,text,text,text,jsonb)'::regprocedure)) THEN
        RAISE EXCEPTION 'IAM local recovery role can invoke unrelated functions';
    END IF;
END
$verify_local_recovery$;
