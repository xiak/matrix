DO $matrix_delivery_verify$
DECLARE
    missing text;
    table_name text;
BEGIN
    IF to_regnamespace('delivery') IS NULL OR (
        SELECT owner_role.rolname
          FROM pg_catalog.pg_namespace AS namespace
          JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = namespace.nspowner
         WHERE namespace.nspname = 'delivery'
    ) IS DISTINCT FROM 'matrix_devops_owner' THEN
        RAISE EXCEPTION 'delivery schema ownership is invalid';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (
        VALUES
            ('matrix_devops_owner'), ('matrix_devops_migrator'),
            ('matrix_devops_api'), ('matrix_devops_worker')
      ) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles AS role
         WHERE role.rolname = required.name
           AND NOT role.rolcanlogin AND role.rolinherit
           AND NOT role.rolsuper AND NOT role.rolcreatedb
           AND NOT role.rolcreaterole AND NOT role.rolreplication
           AND NOT role.rolbypassrls
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing or overprivileged DevOps roles: %', missing;
    END IF;
    IF NOT pg_has_role('matrix_devops_migrator', 'matrix_devops_owner', 'MEMBER')
       OR pg_has_role('matrix_devops_api', 'matrix_devops_owner', 'MEMBER')
       OR pg_has_role('matrix_devops_api', 'matrix_devops_migrator', 'MEMBER')
       OR pg_has_role('matrix_devops_worker', 'matrix_devops_owner', 'MEMBER')
       OR pg_has_role('matrix_devops_worker', 'matrix_devops_migrator', 'MEMBER') THEN
        RAISE EXCEPTION 'DevOps role memberships are unsafe';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_auth_members AS membership
          JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = membership.member
         WHERE member_role.rolname IN ('matrix_devops_api', 'matrix_devops_worker')
    ) THEN
        RAISE EXCEPTION 'DevOps runtime group roles inherit another role';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (
        VALUES
            ('projects'), ('source_connections'), ('repository_bindings'),
            ('repository_binding_revisions'), ('pipelines'),
            ('pipeline_revisions'), ('mutations'), ('audit_outbox')
      ) AS required(name)
     WHERE to_regclass('delivery.' || required.name) IS NULL;
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing delivery tables: %', missing;
    END IF;

    SELECT string_agg(class.relname, ', ' ORDER BY class.relname)
      INTO missing
      FROM pg_catalog.pg_class AS class
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
      JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = class.relowner
     WHERE namespace.nspname = 'delivery' AND class.relkind = 'r'
       AND (
            owner_role.rolname <> 'matrix_devops_owner'
            OR NOT class.relrowsecurity OR NOT class.relforcerowsecurity
       );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'delivery table ownership or forced RLS is invalid: %', missing;
    END IF;

    SELECT string_agg(required.table_name, ', ' ORDER BY required.table_name)
      INTO missing
      FROM (
        VALUES
            ('projects'), ('source_connections'), ('repository_bindings'),
            ('repository_binding_revisions'), ('pipelines'),
            ('pipeline_revisions'), ('mutations'), ('audit_outbox')
     ) AS required(table_name)
     WHERE NOT EXISTS (
        SELECT 1 FROM information_schema.columns AS column_info
         WHERE column_info.table_schema = 'delivery'
           AND column_info.table_name = required.table_name
           AND column_info.column_name = 'tenant_id'
           AND column_info.ordinal_position = 1
     ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_policies AS policy
         WHERE policy.schemaname = 'delivery'
           AND policy.tablename = required.table_name
           AND policy.policyname = 'tenant_isolation'
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'delivery tenant-leading policy is missing: %', missing;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_policies AS policy
         WHERE policy.schemaname = 'delivery'
           AND policy.tablename = 'audit_outbox'
           AND policy.policyname = 'owner_dispatch'
           AND policy.permissive = 'PERMISSIVE'
           AND policy.cmd = 'ALL'
           AND policy.roles = ARRAY['matrix_devops_owner']::name[]
           AND policy.qual = 'true'
           AND policy.with_check = 'true'
    ) THEN
        RAISE EXCEPTION 'delivery Audit owner dispatch policy is missing or unsafe';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns AS column_info
         WHERE column_info.table_schema = 'delivery'
           AND column_info.table_name = 'audit_outbox'
           AND column_info.column_name = 'delivered_at'
           AND column_info.data_type = 'timestamp with time zone'
    ) THEN
        RAISE EXCEPTION 'delivery Audit completion timestamp is missing';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (
        VALUES
            ('repository_bindings_project_fk'),
            ('repository_bindings_connection_fk'),
            ('repository_binding_revisions_binding_fk'),
            ('repository_binding_revisions_project_fk'),
            ('repository_binding_revisions_connection_fk'),
            ('pipelines_project_fk'), ('pipelines_binding_fk'),
            ('pipeline_revisions_pipeline_fk'),
            ('pipeline_revisions_binding_snapshot_fk'),
            ('pipelines_active_revision_fk'),
            ('mutations_idempotency_uq'), ('audit_outbox_operation_fk'),
            ('audit_outbox_delivery_state_valid')
      ) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace AND conname = required.name
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing delivery constraints: %', missing;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace
           AND conname = 'pipelines_active_revision_fk'
           AND condeferrable AND condeferred
    ) THEN
        RAISE EXCEPTION 'Pipeline active revision ownership link is not deferred';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc AS procedure
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
          JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = procedure.proowner
         WHERE namespace.nspname = 'delivery'
           AND procedure.proname = 'commit_configuration_mutation'
           AND pg_catalog.pg_get_function_identity_arguments(procedure.oid) =
               'requested_kind text, expected_resource_version bigint, submitted_resource jsonb, submitted_secondary jsonb, submitted_mutation jsonb, submitted_result jsonb, submitted_audit_event jsonb'
           AND procedure.prosecdef
           AND 'search_path=pg_catalog, pg_temp' = ANY(procedure.proconfig)
           AND owner_role.rolname = 'matrix_devops_owner'
    ) THEN
        RAISE EXCEPTION 'delivery configuration transaction function is missing or unsafe';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (
        VALUES
            ('claim_audit_event',
             'requested_worker_id text, requested_lease_seconds integer'),
            ('complete_audit_event',
             'requested_tenant_id text, requested_event_id text, requested_worker_id text, expected_fencing_token bigint, requested_outcome text, requested_retry_at timestamp with time zone, requested_error_code text'),
            ('audit_outbox_snapshot', ''),
            ('readiness', ''),
            ('worker_readiness', '')
      ) AS required(name, arguments)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc AS procedure
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
          JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = procedure.proowner
         WHERE namespace.nspname = 'delivery'
           AND procedure.proname = required.name
           AND pg_catalog.pg_get_function_identity_arguments(procedure.oid) = required.arguments
           AND procedure.prosecdef
           AND 'search_path=pg_catalog, pg_temp' = ANY(procedure.proconfig)
           AND owner_role.rolname = 'matrix_devops_owner'
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'delivery Audit/readiness functions are missing or unsafe: %', missing;
    END IF;

    IF has_schema_privilege('matrix_devops_api', 'delivery', 'CREATE')
       OR has_schema_privilege('matrix_devops_worker', 'delivery', 'CREATE')
       OR NOT has_schema_privilege('matrix_devops_api', 'delivery', 'USAGE')
       OR NOT has_schema_privilege('matrix_devops_worker', 'delivery', 'USAGE')
       OR NOT has_function_privilege(
            'matrix_devops_api',
            'delivery.commit_configuration_mutation(text,bigint,jsonb,jsonb,jsonb,jsonb,jsonb)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_worker',
            'delivery.commit_configuration_mutation(text,bigint,jsonb,jsonb,jsonb,jsonb,jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_api', 'delivery.readiness()', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_worker', 'delivery.readiness()', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_worker', 'delivery.worker_readiness()', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_api', 'delivery.worker_readiness()', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_worker',
            'delivery.claim_audit_event(text,integer)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_api',
            'delivery.claim_audit_event(text,integer)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_worker',
            'delivery.complete_audit_event(text,text,text,bigint,text,timestamptz,text)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_api',
            'delivery.complete_audit_event(text,text,text,bigint,text,timestamptz,text)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_worker', 'delivery.audit_outbox_snapshot()', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_api', 'delivery.audit_outbox_snapshot()', 'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'delivery schema or function privileges are invalid';
    END IF;

    FOREACH table_name IN ARRAY ARRAY[
        'projects', 'source_connections', 'repository_bindings',
        'repository_binding_revisions', 'pipelines', 'pipeline_revisions',
        'mutations', 'audit_outbox'
    ]
    LOOP
        IF has_table_privilege(
            'matrix_devops_api', 'delivery.' || table_name,
            'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
        ) OR has_table_privilege(
            'matrix_devops_worker', 'delivery.' || table_name,
            'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
        ) THEN
            RAISE EXCEPTION 'unsafe direct table privilege on delivery.%', table_name;
        END IF;
        IF table_name <> 'audit_outbox'
           AND NOT has_table_privilege(
                'matrix_devops_api', 'delivery.' || table_name, 'SELECT'
           ) THEN
            RAISE EXCEPTION 'DevOps API cannot read delivery.%', table_name;
        END IF;
    END LOOP;
    IF has_table_privilege('matrix_devops_api', 'delivery.audit_outbox', 'SELECT') THEN
        RAISE EXCEPTION 'DevOps API can read the Audit outbox';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_namespace AS namespace
         WHERE namespace.nspname IN ('iam', 'audit', 'paas')
           AND (
                has_schema_privilege('matrix_devops_api', namespace.oid, 'USAGE')
                OR has_schema_privilege('matrix_devops_worker', namespace.oid, 'USAGE')
           )
    ) THEN
        RAISE EXCEPTION 'DevOps runtime roles cross a service schema boundary';
    END IF;
END
$matrix_delivery_verify$;
