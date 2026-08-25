DO $matrix_verify$
DECLARE
    missing text;
BEGIN
    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (
        VALUES
            ('applications'),
            ('configurations'),
            ('configuration_revisions'),
            ('application_revisions'),
            ('placement_policies'),
            ('deployments'),
            ('deployment_generations'),
            ('operations'),
            ('execution_pools'),
            ('execution_targets'),
            ('execution_target_allocations'),
            ('adapter_commands'),
            ('adapter_receipts'),
            ('deployment_observations'),
            ('placement_decisions'),
            ('capacity_claims'),
            ('capacity_reservations')
      ) AS required(name)
     WHERE to_regclass('paas.' || required.name) IS NULL;
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing apphosting tables: %', missing;
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES ('matrix_paas_api'), ('matrix_paas_worker')) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_roles AS role
         WHERE role.rolname = required.name
           AND NOT role.rolsuper
           AND NOT role.rolcreatedb
           AND NOT role.rolcreaterole
           AND NOT role.rolreplication
           AND NOT role.rolbypassrls
           AND NOT role.rolcanlogin
    );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing or overprivileged apphosting roles: %', missing;
    END IF;

    SELECT string_agg(class.relname, ', ' ORDER BY class.relname)
      INTO missing
      FROM pg_catalog.pg_class AS class
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = class.relnamespace
     WHERE namespace.nspname = 'paas'
       AND class.relname IN (
            'applications',
            'configurations',
            'configuration_revisions',
            'application_revisions',
            'placement_policies',
            'deployments',
            'deployment_generations',
            'operations',
            'adapter_commands',
            'adapter_receipts',
            'deployment_observations',
            'placement_decisions',
            'capacity_reservations'
       )
       AND (NOT class.relrowsecurity OR NOT class.relforcerowsecurity);
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'tenant tables missing forced RLS: %', missing;
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (
        VALUES
            ('configurations_application_fk'),
            ('configuration_revisions_configuration_fk'),
            ('application_revisions_application_fk'),
            ('deployments_revision_fk'),
            ('deployments_policy_fk'),
            ('deployment_generations_deployment_fk'),
            ('deployment_generations_revision_fk'),
            ('deployment_generations_policy_fk'),
            ('deployment_generations_operation_uq'),
            ('deployment_generations_operation_fk'),
            ('operations_idempotency_uq'),
            ('execution_targets_pool_fk'),
            ('execution_target_allocations_target_fk'),
            ('adapter_commands_operation_action_uq'),
            ('adapter_commands_operation_fk'),
            ('adapter_commands_generation_fk'),
            ('adapter_commands_revision_fk'),
            ('adapter_commands_target_fk'),
            ('adapter_receipts_command_fk'),
            ('deployment_observations_command_fk'),
            ('deployment_observations_generation_fk'),
            ('deployment_observations_revision_fk'),
            ('placement_decisions_operation_uq'),
            ('placement_decisions_deployment_fk'),
            ('placement_decisions_generation_fk'),
            ('placement_decisions_revision_fk'),
            ('placement_decisions_policy_fk'),
            ('placement_decisions_target_fk'),
            ('capacity_claims_target_fk'),
            ('capacity_claims_reservation_fk'),
            ('capacity_reservations_decision_fk'),
            ('capacity_reservations_decision_uq'),
            ('capacity_reservations_claim_fk'),
            ('capacity_reservations_claim_uq')
      ) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_constraint
         WHERE conname = required.name
           AND connamespace = 'paas'::regnamespace
    );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing apphosting constraints: %', missing;
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (
        VALUES
            ('capacity_claims_reservation_fk'),
            ('deployment_generations_operation_fk')
      ) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_constraint
         WHERE conname = required.name
           AND connamespace = 'paas'::regnamespace
           AND condeferrable
           AND condeferred
    );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'required deferred ownership links are unsafe: %', missing;
    END IF;

    SELECT string_agg(required.table_name, ', ' ORDER BY required.table_name)
      INTO missing
      FROM (
        VALUES
            ('applications'),
            ('configurations'),
            ('configuration_revisions'),
            ('application_revisions'),
            ('placement_policies'),
            ('deployments'),
            ('deployment_generations'),
            ('operations'),
            ('adapter_commands'),
            ('adapter_receipts'),
            ('deployment_observations'),
            ('placement_decisions'),
            ('capacity_reservations')
      ) AS required(table_name)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_policies
         WHERE schemaname = 'paas'
           AND tablename = required.table_name
           AND policyname = 'tenant_isolation'
    );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing apphosting tenant policies: %', missing;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_class AS class
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = class.relnamespace
          JOIN pg_catalog.pg_roles AS owner_role
            ON owner_role.oid = class.relowner
         WHERE namespace.nspname = 'paas'
           AND class.relkind IN ('r', 'p')
           AND owner_role.rolname IN ('matrix_paas_api', 'matrix_paas_worker')
    ) THEN
        RAISE EXCEPTION 'application roles must not own PaaS tables';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM information_schema.columns
         WHERE table_schema = 'paas'
           AND table_name = 'capacity_claims'
           AND column_name IN (
                'tenant_id',
                'decision_id',
                'deployment_id',
                'application_revision_id'
           )
    ) THEN
        RAISE EXCEPTION 'platform capacity claims contain tenant ownership columns';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc AS procedure
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = procedure.pronamespace
         WHERE namespace.nspname = 'paas'
           AND procedure.proname = 'transition_capacity_reservation'
           AND pg_catalog.pg_get_function_identity_arguments(procedure.oid)
                = 'requested_reservation_id text, requested_action text, expected_resource_version bigint'
           AND procedure.prosecdef
           AND 'search_path=pg_catalog, pg_temp' = ANY(procedure.proconfig)
    ) THEN
        RAISE EXCEPTION 'tenant-scoped capacity transition function is missing or unsafe';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (
        VALUES
            (
                'submit_deployment',
                'submitted_deployment jsonb, submitted_generation jsonb, submitted_operation jsonb, expected_resource_version bigint'
            ),
            (
                'claim_operation',
                'requested_worker_id text, requested_lease_seconds integer'
            ),
            (
                'advance_operation',
                'requested_operation_id text, requested_worker_id text, expected_fencing_token bigint, requested_state text, requested_error jsonb, requested_next_attempt_at timestamp with time zone, release_lease boolean'
            ),
            (
                'update_deployment_status',
                'requested_deployment_id text, expected_resource_version bigint, expected_generation bigint, submitted_deployment jsonb'
            )
      ) AS required(name, identity_arguments)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc AS procedure
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = procedure.pronamespace
         WHERE namespace.nspname = 'paas'
           AND procedure.proname = required.name
           AND pg_catalog.pg_get_function_identity_arguments(procedure.oid)
                = required.identity_arguments
           AND procedure.prosecdef
           AND 'search_path=pg_catalog, pg_temp' = ANY(procedure.proconfig)
    );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'application transition functions are missing or unsafe: %', missing;
    END IF;

    IF has_schema_privilege('matrix_paas_api', 'paas', 'CREATE')
       OR has_schema_privilege('matrix_paas_worker', 'paas', 'CREATE')
       OR has_table_privilege(
            'matrix_paas_api',
            'paas.placement_decisions',
            'SELECT, INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_api',
            'paas.adapter_commands',
            'SELECT, INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_api',
            'paas.adapter_receipts',
            'SELECT, INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_api',
            'paas.deployment_observations',
            'SELECT, INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_api',
            'paas.deployments',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_api',
            'paas.deployment_generations',
            'INSERT, UPDATE, DELETE'
       ) THEN
        RAISE EXCEPTION 'API role can access worker-owned execution state';
    END IF;

    IF has_table_privilege(
            'matrix_paas_worker',
            'paas.applications',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.configurations',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.configuration_revisions',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.application_revisions',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.deployment_generations',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.operations',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.deployments',
            'INSERT, UPDATE, DELETE'
       ) THEN
        RAISE EXCEPTION 'worker role can rewrite authoritative or immutable input';
    END IF;

    IF NOT has_table_privilege(
            'matrix_paas_api',
            'paas.applications',
            'SELECT, INSERT'
       )
       OR NOT has_table_privilege(
            'matrix_paas_api',
            'paas.configuration_revisions',
            'SELECT, INSERT'
       )
       OR NOT has_table_privilege(
            'matrix_paas_api',
            'paas.operations',
            'SELECT, INSERT'
       )
       OR NOT has_table_privilege(
            'matrix_paas_worker',
            'paas.adapter_commands',
            'SELECT, INSERT'
       )
       OR NOT has_table_privilege(
            'matrix_paas_worker',
            'paas.placement_decisions',
            'SELECT, INSERT'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.transition_capacity_reservation(text, text, bigint)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_api',
            'paas.submit_deployment(jsonb, jsonb, jsonb, bigint)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.claim_operation(text, integer)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.advance_operation(text, text, bigint, text, jsonb, timestamptz, boolean)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.update_deployment_status(text, bigint, bigint, jsonb)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_paas_api',
            'paas.claim_operation(text, integer)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_paas_worker',
            'paas.submit_deployment(jsonb, jsonb, jsonb, bigint)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'application roles lack required current privileges';
    END IF;
END
$matrix_verify$;
