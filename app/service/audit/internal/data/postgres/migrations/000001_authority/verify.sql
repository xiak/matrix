DO $matrix_audit_verify$
DECLARE
    missing text;
BEGIN
    IF (SELECT schema_version FROM audit.readiness()) IS DISTINCT FROM 3::bigint THEN
        RAISE EXCEPTION 'Audit schema version is incompatible';
    END IF;
    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES
        ('matrix_audit_owner'), ('matrix_audit_migrator'),
        ('matrix_audit_runtime')
      ) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles AS role
         WHERE role.rolname = required.name
           AND NOT role.rolsuper AND NOT role.rolcreatedb
           AND NOT role.rolcreaterole AND NOT role.rolreplication
           AND NOT role.rolbypassrls AND NOT role.rolcanlogin
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing or overprivileged Audit roles: %', missing;
    END IF;

    IF NOT pg_has_role('matrix_audit_migrator', 'matrix_audit_owner', 'MEMBER')
       OR pg_has_role('matrix_audit_runtime', 'matrix_audit_owner', 'MEMBER')
       OR pg_has_role('matrix_audit_runtime', 'matrix_audit_migrator', 'MEMBER') THEN
        RAISE EXCEPTION 'Audit role membership boundary is invalid';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_namespace AS namespace
          JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = namespace.nspowner
         WHERE namespace.nspname = 'audit'
           AND owner_role.rolname = 'matrix_audit_owner'
    ) OR has_schema_privilege('public', 'audit', 'USAGE') THEN
        RAISE EXCEPTION 'Audit schema ownership or PUBLIC boundary is invalid';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES ('chain_heads'), ('records'), ('event_registry')) AS required(name)
     WHERE to_regclass('audit.' || required.name) IS NULL;
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing Audit tables: %', missing;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_class AS class
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
          JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = class.relowner
         WHERE namespace.nspname = 'audit'
           AND class.relkind IN ('r', 'p')
           AND owner_role.rolname <> 'matrix_audit_owner'
    ) THEN
        RAISE EXCEPTION 'Audit tables are not owner-role owned';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES ('chain_heads'), ('records')) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_class AS class
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
         WHERE namespace.nspname = 'audit'
           AND class.relname = required.name
           AND class.relrowsecurity AND class.relforcerowsecurity
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'Audit authority tables missing forced RLS: %', missing;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM information_schema.role_table_grants AS grant_row
         WHERE grant_row.table_schema = 'audit'
           AND grant_row.grantee IN ('matrix_audit_runtime', 'PUBLIC')
    ) THEN
        RAISE EXCEPTION 'Audit runtime or PUBLIC has direct table privileges';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES
        ('records_are_immutable'), ('records_cannot_be_truncated')
      ) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_trigger AS trigger_row
         WHERE trigger_row.tgrelid = 'audit.records'::regclass
           AND trigger_row.tgname = required.name
           AND NOT trigger_row.tgisinternal
    );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'Audit record immutability triggers are missing: %', missing;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM information_schema.columns AS column_row
         WHERE column_row.table_schema = 'audit'
           AND column_row.column_name IN (
                'attributes', 'body', 'payload', 'native_payload', 'path',
                'secret', 'credential'
           )
    ) THEN
        RAISE EXCEPTION 'Audit schema contains arbitrary or sensitive payload columns';
    END IF;

    IF to_regprocedure('audit.lookup_event(text,text)') IS NOT NULL
       OR to_regprocedure('audit.lock_tenant_head(text)') IS NOT NULL
       OR to_regprocedure('audit.current_tenant_id()') IS NOT NULL
       OR NOT has_function_privilege(
            'matrix_audit_runtime', 'audit.readiness()', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_audit_runtime', 'audit.lock_event(text,text)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_audit_runtime', 'audit.lookup_record(text,text)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_audit_runtime', 'audit.lock_chain_head(text)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_audit_runtime',
            'audit.append_record(text,text,text,bigint,jsonb,text,text,text,text,timestamptz)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_audit_runtime',
            'audit.read_records(text,bigint,integer,timestamptz,timestamptz,text,text,text)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_audit_runtime', 'audit.read_checkpoint(text,bigint)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_audit_runtime',
            'audit.lookup_paas_operation_record(text,text)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_audit_runtime', 'audit.read_chain(text,bigint,integer)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_audit_runtime', 'audit.assert_event(text,text,text,jsonb)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_audit_runtime',
            'audit.calculate_record_hash(text,bigint,text,text,timestamptz,text)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'Audit runtime function authority is invalid';
    END IF;

    IF to_regclass('audit.records_paas_operation_uq') IS NULL THEN
        RAISE EXCEPTION 'Audit PaaS operation identity is not unique';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES ('chain_heads'), ('records'), ('event_registry')) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'audit' AND table_name = required.name
           AND column_name = 'chain_id' AND is_generated = 'ALWAYS'
     ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE conrelid = ('audit.' || required.name)::regclass
           AND conname = required.name || '_authority_valid' AND convalidated
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'Audit exclusive authority partitions are invalid: %', missing;
    END IF;

    IF to_regnamespace('iam') IS NOT NULL
       AND has_schema_privilege('matrix_audit_runtime', 'iam', 'USAGE') THEN
        RAISE EXCEPTION 'Audit runtime role can access IAM schema';
    END IF;
END
$matrix_audit_verify$;
