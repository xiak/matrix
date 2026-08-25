DO $matrix_verify$
DECLARE
    missing text;
BEGIN
    SELECT string_agg(required.name, ', ' ORDER BY required.name)
    INTO missing
    FROM (
        VALUES
            ('tenant_releases'),
            ('placement_policies'),
            ('resource_pools'),
            ('runtime_targets'),
            ('runtime_target_allocations'),
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

    SELECT string_agg(c.relname, ', ' ORDER BY c.relname)
    INTO missing
    FROM pg_catalog.pg_class AS c
    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
    WHERE n.nspname = 'paas'
      AND c.relname IN (
          'tenant_releases',
          'placement_policies',
          'placement_decisions',
          'capacity_reservations'
      )
      AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'tenant tables missing forced RLS: %', missing;
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
    INTO missing
    FROM (
        VALUES
            ('placement_decisions_operation_uq'),
            ('placement_decisions_release_fk'),
            ('placement_decisions_policy_fk'),
            ('capacity_claims_target_fk'),
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

    SELECT string_agg(table_name, ', ' ORDER BY table_name)
    INTO missing
    FROM (
        VALUES
            ('tenant_releases'),
            ('placement_policies'),
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
        FROM pg_catalog.pg_class AS c
        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = c.relowner
        WHERE n.nspname = 'paas'
          AND c.relkind = 'r'
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
              'release_id',
              'workload_release_id'
          )
    ) THEN
        RAISE EXCEPTION 'platform capacity claims must not contain tenant ownership columns';
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
       ) THEN
        RAISE EXCEPTION 'runtime role has forbidden DDL or destructive privileges';
    END IF;

    IF NOT has_table_privilege(
        'matrix_paas_runtime',
        'paas.capacity_claims',
        'SELECT, INSERT'
    ) THEN
        RAISE EXCEPTION 'runtime role cannot maintain tenant-neutral capacity claims';
    END IF;
END
$matrix_verify$;
