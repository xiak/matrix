DO $matrix_managedservice_verify$
DECLARE
    missing text;
BEGIN
    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES
            ('service_activations'), ('quota_entitlements'), ('service_installations'),
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
            'service_activations', 'quota_entitlements', 'service_installations', 'operations', 'audit_outbox'
       )
       AND (NOT class.relrowsecurity OR NOT class.relforcerowsecurity);
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'managed-service tables missing forced RLS: %', missing;
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES
            ('service_activations_idempotency_uq'),
            ('quota_entitlements_idempotency_uq'),
            ('quota_entitlements_catalog_valid'),
            ('service_installations_entitlement_fk'),
            ('service_installations_current_operation_fk'),
            ('service_installations_ids_valid'),
            ('service_installations_elasticsearch_valid'),
            ('service_installations_elasticsearch_fk'),
            ('operations_idempotency_uq'),
            ('operations_installation_fk'),
            ('managedservice_operations_kind_valid'),
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
            ('list_command_results'),
            ('protect_elasticsearch_dependency'),
            ('start_termination'), ('claim_operation'), ('complete_operation'),
            ('complete_termination_operation'), ('retry_operation'),
            ('fail_operation'), ('fail_cleanup_operation')
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
        RAISE EXCEPTION 'managed-service functions are missing or unsafe: %', missing;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_trigger AS trigger
         WHERE trigger.tgrelid = 'managedservice.service_installations'::regclass
           AND trigger.tgname = 'protect_elasticsearch_dependency'
           AND trigger.tgfoid = 'managedservice.protect_elasticsearch_dependency()'::regprocedure
           AND NOT trigger.tgisinternal AND trigger.tgenabled = 'O'
           -- Row-level BEFORE INSERT/UPDATE, limited to the immutable binding.
           AND trigger.tgtype = 23
           AND cardinality(trigger.tgattr::smallint[]) = 2
           AND trigger.tgattr::smallint[] @> ARRAY(
               SELECT attribute.attnum FROM pg_catalog.pg_attribute AS attribute
                WHERE attribute.attrelid = trigger.tgrelid
                  AND attribute.attname IN ('elasticsearch_installation_id', 'elasticsearch_resource_version')
                  AND NOT attribute.attisdropped
           )
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE conrelid = 'managedservice.service_installations'::regclass
           AND conname = 'service_installations_elasticsearch_fk'
           AND confrelid = conrelid AND contype = 'f' AND convalidated
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_index
         WHERE indexrelid = to_regclass('managedservice.service_installations_active_elasticsearch_idx')
           AND indrelid = 'managedservice.service_installations'::regclass
           AND indisvalid AND indisready
    ) OR has_function_privilege('public', 'managedservice.protect_elasticsearch_dependency()', 'EXECUTE')
       OR has_function_privilege('matrix_paas_api', 'managedservice.protect_elasticsearch_dependency()', 'EXECUTE')
       OR has_function_privilege('matrix_paas_worker', 'managedservice.protect_elasticsearch_dependency()', 'EXECUTE') THEN
        RAISE EXCEPTION 'managed-service dependency custody is missing or unsafe';
    END IF;

    IF to_regprocedure(
            'managedservice.list_command_results(text,text,text,text,text,integer,integer)'
       ) IS NULL
       OR NOT has_function_privilege(
            'matrix_paas_api',
            'managedservice.list_command_results(text,text,text,text,text,integer,integer)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_paas_worker',
            'managedservice.list_command_results(text,text,text,text,text,integer,integer)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'public',
            'managedservice.list_command_results(text,text,text,text,text,integer,integer)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'managed-service command result function privileges are invalid';
    END IF;

    IF has_schema_privilege('matrix_paas_api', 'managedservice', 'CREATE')
       OR has_schema_privilege('matrix_paas_worker', 'managedservice', 'CREATE')
       OR has_table_privilege('matrix_paas_api', 'managedservice.operations', 'UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_api', 'managedservice.service_installations', 'UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_worker', 'managedservice.operations', 'INSERT, UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_worker', 'managedservice.service_installations', 'INSERT, UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_worker', 'managedservice.quota_entitlements', 'INSERT, UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_worker', 'managedservice.service_activations', 'INSERT, UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_api', 'managedservice.service_activations', 'UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_api', 'managedservice.audit_outbox', 'SELECT, INSERT, UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_worker', 'managedservice.audit_outbox', 'SELECT, INSERT, UPDATE, DELETE') THEN
        RAISE EXCEPTION 'managed-service runtime roles are overprivileged';
    END IF;
END
$matrix_managedservice_verify$;
