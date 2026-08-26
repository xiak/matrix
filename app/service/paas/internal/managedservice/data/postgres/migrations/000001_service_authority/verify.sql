DO $matrix_managedservice_verify$
DECLARE
    missing text;
BEGIN
    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES
            ('quota_entitlements'), ('service_installations'),
            ('operations'), ('audit_outbox')
      ) AS required(name)
     WHERE to_regclass('managedservice.' || required.name) IS NULL;
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing managed-service tables: %', missing;
    END IF;

    SELECT string_agg(class.relname, ', ' ORDER BY class.relname)
      INTO missing
      FROM pg_catalog.pg_class AS class
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
     WHERE namespace.nspname = 'managedservice'
       AND class.relname IN (
            'quota_entitlements', 'service_installations', 'operations', 'audit_outbox'
       )
       AND (NOT class.relrowsecurity OR NOT class.relforcerowsecurity);
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'managed-service tables missing forced RLS: %', missing;
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES
            ('quota_entitlements_idempotency_uq'),
            ('service_installations_entitlement_fk'),
            ('operations_installation_uq'),
            ('operations_idempotency_uq'),
            ('operations_installation_fk'),
            ('managedservice_audit_operation_fk')
      ) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = required.name
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing managed-service invariants: %', missing;
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES
            ('append_audit_outbox'), ('claim_audit_event'),
            ('complete_audit_event'), ('audit_outbox_snapshot'),
            ('claim_operation'), ('complete_operation'),
            ('retry_operation'), ('fail_operation')
      ) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc AS procedure
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
         WHERE namespace.nspname = 'managedservice'
           AND procedure.proname = required.name
           AND procedure.prosecdef
           AND 'search_path=pg_catalog, pg_temp' = ANY(procedure.proconfig)
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'managed-service worker functions are missing or unsafe: %', missing;
    END IF;

    IF has_schema_privilege('matrix_paas_api', 'managedservice', 'CREATE')
       OR has_schema_privilege('matrix_paas_worker', 'managedservice', 'CREATE')
       OR has_table_privilege('matrix_paas_api', 'managedservice.operations', 'UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_api', 'managedservice.service_installations', 'UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_worker', 'managedservice.operations', 'INSERT, UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_worker', 'managedservice.service_installations', 'INSERT, UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_worker', 'managedservice.quota_entitlements', 'INSERT, UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_api', 'managedservice.audit_outbox', 'SELECT, INSERT, UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_worker', 'managedservice.audit_outbox', 'SELECT, INSERT, UPDATE, DELETE') THEN
        RAISE EXCEPTION 'managed-service runtime roles are overprivileged';
    END IF;
END
$matrix_managedservice_verify$;
