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
            ('matrix_devops_api'), ('matrix_devops_worker'),
            ('matrix_devops_source_observer')
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
       OR pg_has_role('matrix_devops_worker', 'matrix_devops_migrator', 'MEMBER')
       OR pg_has_role('matrix_devops_source_observer', 'matrix_devops_owner', 'MEMBER')
       OR pg_has_role('matrix_devops_source_observer', 'matrix_devops_migrator', 'MEMBER') THEN
        RAISE EXCEPTION 'DevOps role memberships are unsafe';
    END IF;
    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_auth_members AS membership
          JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = membership.member
         WHERE member_role.rolname IN (
            'matrix_devops_api', 'matrix_devops_worker',
            'matrix_devops_source_observer'
         )
    ) THEN
        RAISE EXCEPTION 'DevOps runtime group roles inherit another role';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (
        VALUES
            ('projects'), ('source_connections'), ('repository_bindings'),
            ('repository_binding_revisions'), ('pipelines'),
            ('pipeline_revisions'), ('source_events'), ('pipeline_runs'),
            ('pipeline_run_tasks'), ('mutations'), ('audit_operations'),
            ('audit_outbox'), ('source_observation_tasks'),
            ('source_observer_heartbeat')
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
            ('pipeline_revisions'), ('source_events'), ('pipeline_runs'),
            ('pipeline_run_tasks'), ('mutations'), ('audit_operations'),
            ('audit_outbox'), ('source_observation_tasks')
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
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_policies AS policy
         WHERE policy.schemaname = 'delivery'
           AND policy.policyname = 'owner_schema_upgrade'
    ) THEN
        RAISE EXCEPTION 'temporary delivery schema-upgrade policy remains installed';
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
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns AS column_info
         WHERE column_info.table_schema = 'delivery'
           AND column_info.table_name = 'pipeline_runs'
           AND column_info.column_name = 'input_digest'
           AND column_info.is_nullable = 'NO'
    ) THEN
        RAISE EXCEPTION 'PipelineRun relational input digest is missing';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns AS column_info
         WHERE column_info.table_schema = 'delivery'
           AND column_info.table_name = 'pipeline_runs'
           AND column_info.column_name = 'cancellation_requested_at'
           AND column_info.data_type = 'timestamp with time zone'
    ) THEN
        RAISE EXCEPTION 'PipelineRun cancellation timestamp is missing';
    END IF;
    IF (
        SELECT count(*)
          FROM information_schema.columns AS column_info
         WHERE column_info.table_schema = 'delivery'
           AND column_info.table_name = 'pipeline_runs'
           AND (
                (column_info.column_name IN ('replay_of_run_id', 'replay_command_id')
                    AND column_info.is_nullable = 'YES')
                OR (column_info.column_name = 'creation_operation_id'
                    AND column_info.is_nullable = 'NO')
           )
    ) <> 3 THEN
        RAISE EXCEPTION 'PipelineRun replay identity columns are missing or unsafe';
    END IF;
    IF to_regclass('delivery.pipeline_runs_event_revision_original_uq') IS NULL
       OR EXISTS (
            SELECT 1 FROM pg_catalog.pg_constraint
             WHERE connamespace = 'delivery'::regnamespace
               AND conname = 'pipeline_runs_event_revision_uq'
       ) THEN
        RAISE EXCEPTION 'PipelineRun original-admission uniqueness is invalid';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_policies AS policy
         WHERE policy.schemaname = 'delivery'
           AND policy.tablename = 'pipeline_runs'
           AND policy.policyname = 'owner_run_worker'
           AND policy.permissive = 'PERMISSIVE'
           AND policy.cmd = 'ALL'
           AND policy.roles = ARRAY['matrix_devops_owner']::name[]
           AND policy.qual = 'true'
           AND policy.with_check = 'true'
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_policies AS policy
         WHERE policy.schemaname = 'delivery'
           AND policy.tablename = 'pipeline_run_tasks'
           AND policy.policyname = 'owner_run_worker'
           AND policy.permissive = 'PERMISSIVE'
           AND policy.cmd = 'ALL'
           AND policy.roles = ARRAY['matrix_devops_owner']::name[]
           AND policy.qual = 'true'
           AND policy.with_check = 'true'
    ) THEN
        RAISE EXCEPTION 'delivery run-worker owner policies are missing or unsafe';
    END IF;

    SELECT string_agg(required.table_name, ', ' ORDER BY required.table_name)
      INTO missing
      FROM (
        VALUES
            ('source_connections'), ('repository_bindings'),
            ('source_observation_tasks'), ('source_observer_heartbeat'),
            ('audit_operations'), ('audit_outbox')
      ) AS required(table_name)
     WHERE NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_policies AS policy
         WHERE policy.schemaname = 'delivery'
           AND policy.tablename = required.table_name
           AND policy.policyname = 'owner_source_observer'
           AND policy.permissive = 'PERMISSIVE'
           AND policy.cmd = 'ALL'
           AND policy.roles = ARRAY['matrix_devops_owner']::name[]
           AND policy.qual = 'true'
           AND policy.with_check = 'true'
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'delivery source-observer owner policies are missing or unsafe: %', missing;
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (
        VALUES
            ('repository_bindings_project_fk'),
            ('repository_bindings_connection_fk'),
            ('repository_bindings_source_repository_uq'),
            ('repository_binding_revisions_binding_fk'),
            ('repository_binding_revisions_project_fk'),
            ('repository_binding_revisions_connection_fk'),
            ('repository_binding_revisions_source_identity_uq'),
            ('pipelines_project_fk'), ('pipelines_binding_fk'),
            ('pipeline_revisions_pipeline_fk'),
            ('pipeline_revisions_binding_snapshot_fk'),
            ('pipeline_revisions_run_identity_uq'),
            ('pipelines_active_revision_fk'),
            ('source_events_delivery_uq'), ('source_events_run_identity_uq'),
            ('source_events_binding_snapshot_fk'),
            ('source_events_audit_operation_fk'),
            ('pipeline_runs_source_event_fk'), ('pipeline_runs_revision_fk'),
            ('pipeline_runs_audit_operation_fk'),
            ('pipeline_runs_replay_command_uq'),
            ('pipeline_runs_replay_source_fk'),
            ('pipeline_runs_replay_valid'),
            ('pipeline_runs_task_identity_uq'),
            ('pipeline_runs_input_digest_valid'),
            ('pipeline_runs_cancellation_valid'),
            ('pipeline_run_tasks_command_uq'), ('pipeline_run_tasks_run_fk'),
            ('pipeline_run_tasks_values_valid'),
            ('mutations_idempotency_uq'), ('mutations_audit_operation_fk'),
            ('audit_outbox_operation_fk'),
            ('audit_outbox_delivery_state_valid'),
            ('source_observation_tasks_values_valid'),
            ('source_observer_heartbeat_singleton'),
            ('source_observer_heartbeat_worker_valid')
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
          FROM pg_catalog.pg_constraint AS constraint_info
         WHERE constraint_info.connamespace = 'delivery'::regnamespace
           AND constraint_info.conname = 'audit_outbox_operation_fk'
           AND constraint_info.confrelid = 'delivery.audit_operations'::regclass
    ) THEN
        RAISE EXCEPTION 'delivery Audit outbox does not reference generalized operations';
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
            ('commit_run_admission',
             'submitted_event jsonb, submitted_runs jsonb, submitted_audit_events jsonb'),
            ('lock_pipeline_run_for_cancellation',
             'requested_run_id text'),
            ('commit_pipeline_run_cancellation',
             'expected_resource_version bigint, submitted_run_document jsonb, submitted_operation jsonb, submitted_cancellation_event jsonb, submitted_terminal_event jsonb'),
            ('lock_pipeline_run_for_replay',
             'requested_source_run_id text, expected_resource_version bigint'),
            ('commit_pipeline_run_replay',
             'expected_resource_version bigint, submitted_run_document jsonb, submitted_operation jsonb, submitted_audit_event jsonb'),
            ('claim_pipeline_run_task',
             'requested_worker_id text, requested_lease_seconds integer'),
            ('renew_pipeline_run_task',
             'requested_tenant_id text, requested_run_id text, requested_command_id text, requested_worker_id text, expected_fencing_token bigint, requested_lease_seconds integer'),
            ('advance_pipeline_run_task',
             'requested_tenant_id text, requested_run_id text, requested_command_id text, requested_worker_id text, expected_fencing_token bigint, requested_state text, requested_reason text, submitted_run_document jsonb, submitted_audit_event jsonb'),
            ('mark_pipeline_run_report_uncertain',
             'requested_tenant_id text, requested_run_id text, requested_command_id text, requested_worker_id text, expected_fencing_token bigint, requested_next_attempt_at timestamp with time zone'),
            ('defer_pipeline_run_reconciliation',
             'requested_tenant_id text, requested_run_id text, requested_command_id text, requested_worker_id text, expected_fencing_token bigint, requested_next_attempt_at timestamp with time zone'),
            ('claim_audit_event',
             'requested_worker_id text, requested_lease_seconds integer'),
            ('complete_audit_event',
             'requested_tenant_id text, requested_event_id text, requested_worker_id text, expected_fencing_token bigint, requested_outcome text, requested_retry_at timestamp with time zone, requested_error_code text'),
            ('audit_outbox_snapshot', ''),
            ('record_source_observer_heartbeat',
             'requested_worker_id text'),
            ('claim_source_observation',
             'requested_worker_id text, requested_lease_seconds integer'),
            ('complete_source_observation',
             'requested_tenant_id text, requested_resource_kind text, requested_resource_id text, expected_resource_version bigint, requested_worker_id text, expected_fencing_token bigint, submitted_resource jsonb, submitted_audit_event jsonb'),
            ('source_observer_readiness', ''),
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
        RAISE EXCEPTION 'delivery protected functions are missing or unsafe: %', missing;
    END IF;

    IF to_regprocedure(
        'delivery.advance_pipeline_run_task(text,text,text,text,bigint,text,text)'
    ) IS NOT NULL THEN
        RAISE EXCEPTION 'legacy PipelineRun transition function bypasses terminal Audit';
    END IF;

    IF has_schema_privilege('matrix_devops_api', 'delivery', 'CREATE')
       OR has_schema_privilege('matrix_devops_worker', 'delivery', 'CREATE')
       OR has_schema_privilege('matrix_devops_source_observer', 'delivery', 'CREATE')
       OR NOT has_schema_privilege('matrix_devops_api', 'delivery', 'USAGE')
       OR NOT has_schema_privilege('matrix_devops_worker', 'delivery', 'USAGE')
       OR NOT has_schema_privilege('matrix_devops_source_observer', 'delivery', 'USAGE')
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
            'matrix_devops_api',
            'delivery.lock_pipeline_run_for_cancellation(text)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_worker',
            'delivery.lock_pipeline_run_for_cancellation(text)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_api',
            'delivery.commit_pipeline_run_cancellation(bigint,jsonb,jsonb,jsonb,jsonb)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_worker',
            'delivery.commit_pipeline_run_cancellation(bigint,jsonb,jsonb,jsonb,jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_api',
            'delivery.lock_pipeline_run_for_replay(text,bigint)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_worker',
            'delivery.lock_pipeline_run_for_replay(text,bigint)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_api',
            'delivery.commit_pipeline_run_replay(bigint,jsonb,jsonb,jsonb)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_worker',
            'delivery.commit_pipeline_run_replay(bigint,jsonb,jsonb,jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_api',
            'delivery.commit_run_admission(jsonb,jsonb,jsonb)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_worker',
            'delivery.commit_run_admission(jsonb,jsonb,jsonb)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_api', 'delivery.readiness()', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_worker', 'delivery.readiness()', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_worker',
            'delivery.claim_pipeline_run_task(text,integer)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_api',
            'delivery.claim_pipeline_run_task(text,integer)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_worker',
            'delivery.renew_pipeline_run_task(text,text,text,text,bigint,integer)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_api',
            'delivery.renew_pipeline_run_task(text,text,text,text,bigint,integer)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_worker',
            'delivery.advance_pipeline_run_task(text,text,text,text,bigint,text,text,jsonb,jsonb)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_api',
            'delivery.advance_pipeline_run_task(text,text,text,text,bigint,text,text,jsonb,jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_worker',
            'delivery.mark_pipeline_run_report_uncertain(text,text,text,text,bigint,timestamp with time zone)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_api',
            'delivery.mark_pipeline_run_report_uncertain(text,text,text,text,bigint,timestamp with time zone)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_worker',
            'delivery.defer_pipeline_run_reconciliation(text,text,text,text,bigint,timestamp with time zone)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_api',
            'delivery.defer_pipeline_run_reconciliation(text,text,text,text,bigint,timestamp with time zone)',
            'EXECUTE'
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
       )
       OR NOT has_function_privilege(
            'matrix_devops_source_observer',
            'delivery.record_source_observer_heartbeat(text)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_source_observer',
            'delivery.claim_source_observation(text,integer)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_source_observer',
            'delivery.complete_source_observation(text,text,text,bigint,text,bigint,jsonb,jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_devops_source_observer',
            'delivery.source_observer_readiness()', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_api',
            'delivery.record_source_observer_heartbeat(text)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_worker',
            'delivery.record_source_observer_heartbeat(text)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_api',
            'delivery.claim_source_observation(text,integer)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_worker',
            'delivery.claim_source_observation(text,integer)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_api',
            'delivery.complete_source_observation(text,text,text,bigint,text,bigint,jsonb,jsonb)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_worker',
            'delivery.complete_source_observation(text,text,text,bigint,text,bigint,jsonb,jsonb)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_api',
            'delivery.source_observer_readiness()', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_devops_worker',
            'delivery.source_observer_readiness()', 'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'delivery schema or function privileges are invalid';
    END IF;

    FOREACH table_name IN ARRAY ARRAY[
        'projects', 'source_connections', 'repository_bindings',
        'repository_binding_revisions', 'pipelines', 'pipeline_revisions',
        'source_events', 'pipeline_runs', 'pipeline_run_tasks', 'mutations',
        'audit_operations', 'audit_outbox', 'source_observation_tasks',
        'source_observer_heartbeat'
    ]
    LOOP
        IF has_table_privilege(
            'matrix_devops_api', 'delivery.' || table_name,
            'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
        ) OR has_table_privilege(
            'matrix_devops_worker', 'delivery.' || table_name,
            'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
        ) OR has_table_privilege(
            'matrix_devops_source_observer', 'delivery.' || table_name,
            'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
        ) THEN
            RAISE EXCEPTION 'unsafe direct table privilege on delivery.%', table_name;
        END IF;
        IF table_name NOT IN (
            'pipeline_run_tasks', 'audit_outbox', 'audit_operations',
            'source_observation_tasks', 'source_observer_heartbeat'
        )
           AND NOT has_table_privilege(
                'matrix_devops_api', 'delivery.' || table_name, 'SELECT'
           ) THEN
            RAISE EXCEPTION 'DevOps API cannot read delivery.%', table_name;
        END IF;
    END LOOP;
    IF has_table_privilege('matrix_devops_api', 'delivery.pipeline_run_tasks', 'SELECT')
       OR has_table_privilege('matrix_devops_api', 'delivery.audit_outbox', 'SELECT')
       OR has_table_privilege('matrix_devops_api', 'delivery.audit_operations', 'SELECT')
       OR has_table_privilege('matrix_devops_api', 'delivery.source_observation_tasks', 'SELECT')
       OR has_table_privilege('matrix_devops_api', 'delivery.source_observer_heartbeat', 'SELECT') THEN
        RAISE EXCEPTION 'DevOps API can read internal Audit tables';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc AS function_info
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = function_info.pronamespace
         WHERE namespace.nspname = 'delivery'
           AND has_function_privilege(
                'matrix_devops_source_observer', function_info.oid, 'EXECUTE'
           )
           AND function_info.oid NOT IN (
                to_regprocedure(
                    'delivery.record_source_observer_heartbeat(text)'
                ),
                to_regprocedure(
                    'delivery.claim_source_observation(text,integer)'
                ),
                to_regprocedure(
                    'delivery.complete_source_observation(text,text,text,bigint,text,bigint,jsonb,jsonb)'
                ),
                to_regprocedure('delivery.source_observer_readiness()')
           )
    ) THEN
        RAISE EXCEPTION 'DevOps source observer can execute an undeclared delivery function';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_namespace AS namespace
         WHERE namespace.nspname IN ('iam', 'audit', 'paas')
           AND (
                has_schema_privilege('matrix_devops_api', namespace.oid, 'USAGE')
                OR has_schema_privilege('matrix_devops_worker', namespace.oid, 'USAGE')
                OR has_schema_privilege(
                    'matrix_devops_source_observer', namespace.oid, 'USAGE'
                )
           )
    ) THEN
        RAISE EXCEPTION 'DevOps runtime roles cross a service schema boundary';
    END IF;
END
$matrix_delivery_verify$;
