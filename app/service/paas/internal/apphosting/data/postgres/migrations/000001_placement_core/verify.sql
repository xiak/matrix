DO $matrix_verify$
DECLARE
    missing text;
BEGIN
    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (
        VALUES
            ('applications'),
            ('application_revisions'),
            ('placement_policies'),
            ('deployments'),
            ('execution_pools'),
            ('execution_targets'),
            ('execution_target_allocations'),
            ('placement_decisions'),
            ('capacity_claims'),
            ('capacity_reservations')
      ) AS required(name)
     WHERE to_regclass('paas.' || required.name) IS NULL;
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing FEAT-003 tables: %', missing;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_roles
         WHERE rolname = 'matrix_paas_runtime'
           AND NOT rolsuper
           AND NOT rolcreatedb
           AND NOT rolcreaterole
           AND NOT rolreplication
           AND NOT rolbypassrls
           AND NOT rolcanlogin
    ) THEN
        RAISE EXCEPTION 'matrix_paas_runtime role is missing or overprivileged';
    END IF;

    SELECT string_agg(class.relname, ', ' ORDER BY class.relname)
      INTO missing
      FROM pg_catalog.pg_class AS class
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = class.relnamespace
     WHERE namespace.nspname = 'paas'
       AND class.relname IN (
            'applications',
            'application_revisions',
            'placement_policies',
            'deployments',
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
            ('application_revisions_application_fk'),
            ('deployments_revision_fk'),
            ('deployments_policy_fk'),
            ('execution_targets_pool_fk'),
            ('execution_target_allocations_target_fk'),
            ('placement_decisions_operation_uq'),
            ('placement_decisions_deployment_fk'),
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
        RAISE EXCEPTION 'missing FEAT-003 constraints: %', missing;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_constraint
         WHERE conname = 'capacity_claims_reservation_fk'
           AND connamespace = 'paas'::regnamespace
           AND condeferrable
           AND condeferred
    ) THEN
        RAISE EXCEPTION 'capacity claim ownership link is not initially deferred';
    END IF;

    SELECT string_agg(required.table_name, ', ' ORDER BY required.table_name)
      INTO missing
      FROM (
        VALUES
            ('applications'),
            ('application_revisions'),
            ('placement_policies'),
            ('deployments'),
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
        RAISE EXCEPTION 'missing FEAT-003 tenant policies: %', missing;
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
           AND owner_role.rolname = 'matrix_paas_runtime'
    ) THEN
        RAISE EXCEPTION 'runtime role must not own PaaS tables';
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

    IF has_schema_privilege('matrix_paas_runtime', 'paas', 'CREATE')
       OR has_table_privilege(
            'matrix_paas_runtime',
            'paas.placement_decisions',
            'DELETE, TRUNCATE, REFERENCES, TRIGGER'
       )
       OR has_table_privilege(
            'matrix_paas_runtime',
            'paas.capacity_claims',
            'DELETE, TRUNCATE, REFERENCES, TRIGGER'
       )
       OR has_table_privilege(
            'matrix_paas_runtime',
            'paas.capacity_reservations',
            'DELETE, TRUNCATE, REFERENCES, TRIGGER'
       )
       OR has_any_column_privilege(
            'matrix_paas_runtime',
            'paas.capacity_claims',
            'UPDATE'
       )
       OR has_any_column_privilege(
            'matrix_paas_runtime',
            'paas.capacity_reservations',
            'UPDATE'
       ) THEN
        RAISE EXCEPTION 'runtime role has forbidden DDL, destructive, or direct claim mutation privileges';
    END IF;

    IF has_table_privilege('matrix_paas_runtime', 'paas.applications', 'INSERT, UPDATE, DELETE')
       OR has_table_privilege(
            'matrix_paas_runtime',
            'paas.application_revisions',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_runtime',
            'paas.placement_policies',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege('matrix_paas_runtime', 'paas.deployments', 'INSERT, UPDATE, DELETE') THEN
        RAISE EXCEPTION 'placement runtime role can mutate authoritative input resources';
    END IF;

    IF NOT has_table_privilege(
        'matrix_paas_runtime',
        'paas.capacity_claims',
        'SELECT, INSERT'
    ) OR NOT has_table_privilege(
        'matrix_paas_runtime',
        'paas.capacity_reservations',
        'SELECT, INSERT'
    ) OR NOT has_function_privilege(
        'matrix_paas_runtime',
        'paas.transition_capacity_reservation(text, text, bigint)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'runtime role lacks required capacity accounting privileges';
    END IF;
END
$matrix_verify$;
