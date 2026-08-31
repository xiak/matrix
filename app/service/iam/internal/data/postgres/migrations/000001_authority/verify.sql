DO $matrix_iam_verify$
DECLARE
    missing text;
BEGIN
    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES
        ('matrix_iam_owner'), ('matrix_iam_migrator'),
        ('matrix_iam_api'), ('matrix_iam_worker')
      ) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles AS role
         WHERE role.rolname = required.name
           AND NOT role.rolsuper AND NOT role.rolcreatedb
           AND NOT role.rolcreaterole AND NOT role.rolreplication
           AND NOT role.rolbypassrls AND NOT role.rolcanlogin
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing or overprivileged IAM roles: %', missing;
    END IF;

    IF NOT pg_has_role('matrix_iam_migrator', 'matrix_iam_owner', 'MEMBER')
       OR pg_has_role('matrix_iam_api', 'matrix_iam_owner', 'MEMBER')
       OR pg_has_role('matrix_iam_api', 'matrix_iam_migrator', 'MEMBER')
       OR pg_has_role('matrix_iam_worker', 'matrix_iam_owner', 'MEMBER')
       OR pg_has_role('matrix_iam_worker', 'matrix_iam_migrator', 'MEMBER') THEN
        RAISE EXCEPTION 'IAM role membership boundary is invalid';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_namespace AS namespace
          JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = namespace.nspowner
         WHERE namespace.nspname = 'iam'
           AND owner_role.rolname = 'matrix_iam_owner'
    ) OR has_schema_privilege('public', 'iam', 'USAGE') THEN
        RAISE EXCEPTION 'IAM schema ownership or PUBLIC boundary is invalid';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES
        ('bootstrap_receipts'), ('organizations'), ('principals'),
        ('role_bindings'), ('user_credentials'), ('login_index'),
        ('service_credentials'), ('service_credential_index'),
        ('sessions'), ('session_index'), ('authorization_decisions'),
        ('audit_outbox')
      ) AS required(name)
     WHERE to_regclass('iam.' || required.name) IS NULL;
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing IAM tables: %', missing;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_class AS class
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
          JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = class.relowner
         WHERE namespace.nspname = 'iam'
           AND class.relkind IN ('r', 'p')
           AND owner_role.rolname <> 'matrix_iam_owner'
    ) THEN
        RAISE EXCEPTION 'IAM tables are not owner-role owned';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES
        ('organizations'), ('principals'), ('role_bindings'),
        ('user_credentials'), ('service_credentials'), ('sessions'),
        ('authorization_decisions'), ('audit_outbox')
      ) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_class AS class
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
         WHERE namespace.nspname = 'iam'
           AND class.relname = required.name
           AND class.relrowsecurity AND class.relforcerowsecurity
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'IAM tenant tables missing forced RLS: %', missing;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM information_schema.role_table_grants AS grant_row
         WHERE grant_row.table_schema = 'iam'
           AND grant_row.grantee IN ('matrix_iam_api', 'matrix_iam_worker', 'PUBLIC')
    ) THEN
        RAISE EXCEPTION 'IAM runtime or PUBLIC has direct table privileges';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM information_schema.columns AS column_row
         WHERE column_row.table_schema = 'iam'
           AND column_row.column_name IN (
                'password', 'credential', 'credential_value', 'secret', 'token'
           )
    ) THEN
        RAISE EXCEPTION 'IAM schema contains plaintext credential columns';
    END IF;

    IF NOT has_function_privilege(
            'matrix_iam_api',
            'iam.apply_bootstrap(text,text,text,text,text,text,text,text,jsonb,jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege('matrix_iam_api', 'iam.bootstrap_status()', 'EXECUTE')
       OR NOT has_function_privilege('matrix_iam_api', 'iam.readiness()', 'EXECUTE')
       OR NOT has_function_privilege('matrix_iam_api', 'iam.lookup_login(text)', 'EXECUTE')
       OR NOT has_function_privilege(
            'matrix_iam_api',
            'iam.issue_session(text,text,text,text,text,integer,jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege('matrix_iam_api', 'iam.lookup_session(text)', 'EXECUTE')
       OR NOT has_function_privilege('matrix_iam_api', 'iam.lookup_service(text)', 'EXECUTE')
       OR NOT has_function_privilege(
            'matrix_iam_api', 'iam.lookup_service_roles(text,text)', 'EXECUTE'
       )
       OR NOT has_function_privilege('matrix_iam_api', 'iam.lookup_password(text,text)', 'EXECUTE')
       OR NOT has_function_privilege(
            'matrix_iam_api',
            'iam.record_authorization(text,text,jsonb,jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_api', 'iam.change_password(text,text,text,text,jsonb,text,boolean)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_api', 'iam.revoke_session(text,text,text,text,jsonb)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_api', 'iam.create_user(text,text,text,text,text,text,text,jsonb)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_api', 'iam.put_role_binding(text,text,text,text,text,text,jsonb)', 'EXECUTE'
       )
       OR NOT has_function_privilege('matrix_iam_api', 'iam.lookup_role_binding_role(text,text)', 'EXECUTE')
       OR has_function_privilege('matrix_iam_worker', 'iam.lookup_role_binding_role(text,text)', 'EXECUTE')
       OR NOT has_function_privilege(
            'matrix_iam_api', 'iam.revoke_role_binding(text,text,text,text,jsonb)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_worker', 'iam.claim_audit_event(text,integer)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_worker',
            'iam.complete_audit_event(text,text,bigint,text,integer,text)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_worker', 'iam.audit_outbox_snapshot()', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_iam_api', 'iam.claim_audit_event(text,integer)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_iam_worker', 'iam.lookup_login(text)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_iam_api', 'iam.audit_outbox_snapshot()', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_iam_worker',
            'iam.change_password(text,text,text,text,jsonb,text,boolean)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_iam_api', 'iam.resource_kind_for_action(text)', 'EXECUTE'
       )
       OR has_function_privilege('matrix_iam_api', 'iam.is_platform_action(text)', 'EXECUTE')
       OR has_function_privilege(
            'matrix_iam_api', 'iam.assert_allowed_decision(text,text,text,text,text,text)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_iam_api', 'iam.assert_user_audit_actor(text,text,jsonb)', 'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'IAM API/worker function authority is invalid';
    END IF;

    IF to_regprocedure('iam.change_password(text,text,text,text,jsonb)') IS NOT NULL
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_attribute AS column_definition
            WHERE column_definition.attrelid = 'iam.sessions'::regclass
              AND column_definition.attname = 'credential_version'
              AND column_definition.atttypid = 'bigint'::regtype
              AND NOT column_definition.attisdropped
       ) OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_attribute AS column_definition
            WHERE column_definition.attrelid = 'iam.user_credentials'::regclass
              AND column_definition.attname = 'credential_version'
              AND column_definition.atttypid = 'bigint'::regtype
              AND column_definition.attnotnull
              AND NOT column_definition.attisdropped
       ) THEN
        RAISE EXCEPTION 'IAM password/session contract is invalid';
    END IF;

    IF to_regnamespace('audit') IS NOT NULL AND (
        has_schema_privilege('matrix_iam_api', 'audit', 'USAGE')
        OR has_schema_privilege('matrix_iam_worker', 'audit', 'USAGE')
    ) THEN
        RAISE EXCEPTION 'IAM runtime roles can access Audit schema';
    END IF;

    IF iam.resource_kind_for_action('managedservice.offering.read') IS DISTINCT FROM 'SERVICE_OFFERING'
       OR iam.resource_kind_for_action('managedservice.region.read') IS DISTINCT FROM 'REGION'
       OR iam.resource_kind_for_action('managedservice.quota-entitlement.activate') IS DISTINCT FROM 'QUOTA_ENTITLEMENT'
       OR iam.resource_kind_for_action('managedservice.quota-entitlement.read') IS DISTINCT FROM 'QUOTA_ENTITLEMENT'
       OR iam.resource_kind_for_action('managedservice.service-installation.create') IS DISTINCT FROM 'SERVICE_INSTALLATION'
       OR iam.resource_kind_for_action('managedservice.service-installation.read') IS DISTINCT FROM 'SERVICE_INSTALLATION'
       OR iam.resource_kind_for_action('paas.execution-target.register') IS DISTINCT FROM 'EXECUTION_TARGET'
       OR iam.resource_kind_for_action('paas.execution-target.drain') IS DISTINCT FROM 'EXECUTION_TARGET'
       OR iam.resource_kind_for_action('paas.execution-target.activate') IS DISTINCT FROM 'EXECUTION_TARGET'
       OR iam.resource_kind_for_action('paas.execution-target.remove') IS DISTINCT FROM 'EXECUTION_TARGET'
       OR iam.resource_kind_for_action('paas.execution-pool.create') IS DISTINCT FROM 'EXECUTION_POOL'
       OR iam.resource_kind_for_action('paas.terminal-session.create') IS DISTINCT FROM 'TERMINAL_SESSION'
       OR iam.resource_kind_for_action('paas.terminal-session.close') IS DISTINCT FROM 'TERMINAL_SESSION'
       OR iam.resource_kind_for_action('unsupported') IS NOT NULL
       OR NOT iam.is_platform_action('paas.execution-target.register')
       OR NOT iam.is_platform_action('paas.execution-target.drain')
       OR NOT iam.is_platform_action('paas.execution-target.activate')
       OR NOT iam.is_platform_action('paas.execution-target.remove')
       OR iam.is_platform_action('paas.application.create')
       OR iam.is_platform_action('unsupported') THEN
        RAISE EXCEPTION 'IAM authorization action mapping is invalid';
    END IF;
END
$matrix_iam_verify$;
