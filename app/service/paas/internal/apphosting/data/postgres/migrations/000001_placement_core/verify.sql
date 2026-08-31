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
            ('audit_outbox'),
            ('execution_pools'),
            ('execution_targets'),
            ('execution_target_allocations'),
            ('adapter_commands'),
            ('adapter_receipts'),
            ('deployment_observations'),
            ('deployment_runtime_snapshots'),
            ('deployment_resource_snapshots'),
            ('terminal_sessions'),
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
            'audit_outbox',
            'execution_pools',
            'execution_targets',
            'adapter_commands',
            'adapter_receipts',
            'deployment_observations',
            'deployment_runtime_snapshots',
            'deployment_resource_snapshots',
            'terminal_sessions',
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
            ('operations_tenant_identity_uq'),
            ('operations_ids_valid'),
            ('operations_document_identity'),
            ('audit_outbox_operation_fk'),
            ('audit_outbox_terminal_session_fk'),
            ('audit_outbox_ids_valid'),
            ('audit_outbox_owner_valid'),
            ('audit_outbox_document_identity'),
            ('execution_targets_pool_fk'),
            ('execution_targets_installation_pool_fk'),
            ('execution_targets_installation_identity_valid'),
            ('execution_pools_installation_valid'),
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
            ('deployment_runtime_snapshots_deployment_fk'),
            ('deployment_runtime_snapshots_generation_fk'),
            ('deployment_runtime_snapshots_revision_fk'),
            ('deployment_runtime_snapshots_target_fk'),
            ('deployment_runtime_snapshots_decision_fk'),
            ('deployment_resource_snapshots_deployment_fk'),
            ('deployment_resource_snapshots_generation_fk'),
            ('deployment_resource_snapshots_revision_fk'),
            ('deployment_resource_snapshots_target_fk'),
            ('deployment_resource_snapshots_decision_fk'),
            ('terminal_sessions_global_id_uq'),
            ('terminal_sessions_idempotency_uq'),
            ('terminal_sessions_deployment_fk'),
            ('terminal_sessions_generation_fk'),
            ('terminal_sessions_revision_fk'),
            ('terminal_sessions_target_fk'),
            ('terminal_sessions_decision_fk'),
            ('terminal_sessions_ids_valid'),
            ('terminal_sessions_values_valid'),
            ('terminal_sessions_state_valid'),
            ('terminal_sessions_time_valid'),
            ('terminal_sessions_document_identity'),
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
            ('audit_outbox'),
            ('adapter_commands'),
            ('adapter_receipts'),
            ('deployment_observations'),
            ('deployment_runtime_snapshots'),
            ('deployment_resource_snapshots'),
            ('terminal_sessions'),
            ('placement_decisions'),
            ('capacity_reservations')
      ) AS required(table_name)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_policies
         WHERE schemaname = 'paas'
           AND tablename = required.table_name
           AND policyname = CASE WHEN required.table_name IN ('operations', 'audit_outbox')
                THEN 'authority_isolation' ELSE 'tenant_isolation' END
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

    IF to_regprocedure('paas.submit_deployment(jsonb,jsonb,jsonb,bigint)') IS NOT NULL THEN
        RAISE EXCEPTION 'removed pre-Audit submit_deployment signature still exists';
    END IF;

    IF to_regprocedure('paas.complete_audit_event(text,text,text,bigint,text,timestamptz,text)') IS NOT NULL
       OR to_regprocedure('paas.current_installation_id()') IS NULL THEN
        RAISE EXCEPTION 'Operation authority function contract is invalid';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (
        VALUES
            (
                'append_audit_outbox',
                'submitted_operation jsonb, submitted_audit_event jsonb'
            ),
            (
                'append_terminal_audit_outbox',
                'requested_session_id text, submitted_audit_event jsonb'
            ),
            (
                'lock_terminal_session_by_fingerprint',
                'requested_fingerprint text'
            ),
            (
                'lock_terminal_session',
                'requested_session_id text'
            ),
            (
                'lock_open_terminal_session',
                'requested_subject_type text, requested_subject_id text, requested_deployment_id text, requested_instance_id text'
            ),
            (
                'lock_current_terminal_runtime',
                'requested_deployment_id text, requested_instance_id text, requested_now timestamp with time zone'
            ),
            (
                'create_terminal_session',
                'submitted_stored jsonb, requested_ticket_digest text, submitted_audit_event jsonb'
            ),
            (
                'rotate_terminal_session_ticket',
                'requested_session_id text, requested_ticket_digest text'
            ),
            (
                'open_terminal_session_ticket',
                'requested_session_id text, requested_ticket_digest text'
            ),
            (
                'consume_terminal_session_ticket',
                'requested_session_id text, submitted_session jsonb'
            ),
            (
                'transition_terminal_session',
                'requested_session_id text, submitted_session jsonb, submitted_audit_event jsonb'
            ),
            (
                'create_apphosting_resource',
                'submitted_resource jsonb, submitted_operation jsonb, submitted_audit_event jsonb'
            ),
            (
                'admit_execution_resource',
                'submitted_resource jsonb, submitted_operation jsonb, submitted_audit_event jsonb, submitted_binding_ref text, submitted_identity_fingerprint text, expected_pool_version bigint, submitted_pool jsonb'
            ),
            (
                'refresh_execution_target',
                'expected_target_version bigint, submitted_target jsonb, expected_pool_version bigint, submitted_pool jsonb'
            ),
            (
                'store_execution_pool_observation',
                'expected_resource_version bigint, submitted_pool jsonb'
            ),
            (
                'submit_deployment',
                'submitted_deployment jsonb, submitted_generation jsonb, submitted_operation jsonb, submitted_audit_event jsonb, expected_resource_version bigint'
            ),
            (
                'claim_audit_event',
                'requested_worker_id text, requested_lease_seconds integer'
            ),
            (
                'complete_audit_event',
                'requested_tenant_id text, requested_installation_id text, requested_event_id text, requested_worker_id text, expected_fencing_token bigint, requested_outcome text, requested_retry_at timestamp with time zone, requested_error_code text'
            ),
            (
                'audit_outbox_snapshot',
                ''
            ),
            (
                'readiness',
                ''
            ),
            (
                'worker_readiness',
                ''
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
                'assert_current_operation_lease',
                'requested_operation_id text, requested_worker_id text, expected_fencing_token bigint'
            ),
            (
                'create_placement',
                'requested_operation_id text, requested_worker_id text, expected_fencing_token bigint, requested_request_digest text, submitted_decision jsonb, submitted_reservation jsonb, reuses_active_reservation boolean'
            ),
            (
                'prepare_adapter_command',
                'requested_operation_id text, requested_worker_id text, expected_fencing_token bigint, submitted_command jsonb'
            ),
            (
                'update_deployment_status',
                'requested_operation_id text, requested_worker_id text, expected_fencing_token bigint, requested_deployment_id text, expected_resource_version bigint, expected_generation bigint, submitted_deployment jsonb'
            ),
            (
                'record_adapter_receipt',
                'requested_operation_id text, requested_worker_id text, expected_fencing_token bigint, requested_command_id text, requested_request_digest text, requested_state text, requested_receipt_digest text, requested_normalized_error jsonb, requested_evidence jsonb, requested_observed_at timestamp with time zone'
            ),
            (
                'record_deployment_observation',
                'requested_operation_id text, requested_worker_id text, expected_fencing_token bigint, requested_command_id text, submitted_observation jsonb'
            ),
            (
                'release_operation_lease',
                'requested_operation_id text, requested_worker_id text, expected_fencing_token bigint, requested_next_attempt_at timestamp with time zone'
            ),
            (
                'transition_capacity_reservation',
                'requested_operation_id text, requested_worker_id text, expected_fencing_token bigint, requested_reservation_id text, requested_action text, expected_resource_version bigint'
            ),
            (
                'reconcile_local_execution_profile',
                'requested_installation_id text, expected_pool_version bigint, submitted_pool jsonb, expected_target_version bigint, submitted_target jsonb, expected_policy_version bigint, submitted_policy jsonb'
            ),
            (
                'next_deployment_runtime_candidate',
                'requested_after_tenant_id text, requested_after_deployment_id text'
            ),
            (
                'store_deployment_runtime_snapshot',
                'requested_tenant_id text, requested_deployment_id text, requested_generation bigint, requested_application_revision_id text, requested_execution_target_id text, requested_placement_decision_id text, requested_observed_at timestamp with time zone, requested_valid_until timestamp with time zone, submitted_document jsonb'
            ),
            (
                'store_deployment_telemetry_snapshot',
                'requested_tenant_id text, requested_deployment_id text, requested_generation bigint, requested_application_revision_id text, requested_execution_target_id text, requested_placement_decision_id text, requested_runtime_observed_at timestamp with time zone, requested_runtime_valid_until timestamp with time zone, submitted_runtime_document jsonb, requested_resource_observed_at timestamp with time zone, requested_resource_valid_until timestamp with time zone, submitted_resource_document jsonb'
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

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc AS procedure
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = procedure.pronamespace
         WHERE namespace.nspname = 'paas'
           AND procedure.proname = 'valid_deployment_resource_document'
           AND pg_catalog.pg_get_function_identity_arguments(procedure.oid)
                = 'resource_document jsonb'
           AND NOT procedure.prosecdef
           AND procedure.provolatile = 'i'
           AND procedure.proisstrict
           AND 'search_path=pg_catalog, pg_temp' = ANY(procedure.proconfig)
    ) THEN
        RAISE EXCEPTION 'Deployment resource validator is missing or unsafe';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_proc AS procedure
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = procedure.pronamespace
         WHERE namespace.nspname = 'paas'
           AND procedure.proname = 'terminal_session_snapshot'
           AND pg_catalog.pg_get_function_identity_arguments(procedure.oid)
                = 'session_row paas.terminal_sessions'
           AND NOT procedure.prosecdef
           AND procedure.provolatile = 'i'
           AND procedure.proisstrict
           AND 'search_path=pg_catalog, pg_temp' = ANY(procedure.proconfig)
    ) THEN
        RAISE EXCEPTION 'terminal session snapshot encoder is missing or unsafe';
    END IF;

    IF NOT paas.valid_deployment_resource_document(
        jsonb_build_object(
            'deploymentId', 'deployment-resource-verification',
            'generation', 1,
            'applicationRevisionId', 'application-revision-verification',
            'executionTargetId', 'execution-target-verification',
            'instances', jsonb_build_array(jsonb_build_object(
                'id', 'instance-0123456789abcdef0123456789abcdef',
                'cpu', jsonb_build_object('state', 'UNSUPPORTED'),
                'memory', jsonb_build_object('state', 'UNSUPPORTED'),
                'network', jsonb_build_object('state', 'UNSUPPORTED'),
                'blockIo', jsonb_build_object('state', 'UNSUPPORTED'),
                'storage', jsonb_build_object(
                    'state', 'AVAILABLE',
                    'value', jsonb_build_object(
                        'observedAt', '2026-08-31T00:00:00Z',
                        'validUntil', '2026-08-31T00:01:30Z',
                        'writableLayerBytes', 1,
                        'imageTotalBytes', 10,
                        'imageSharedBytes', 4,
                        'imageUniqueBytes', 6,
                        'volumesState', 'AVAILABLE',
                        'volumes', jsonb_build_object(
                            'count', 0,
                            'bytes', 0,
                            'sharedCount', 0,
                            'sharedBytes', 0
                        )
                    )
                )
            )),
            'observedAt', '2026-08-31T00:00:01Z'
        )
    ) THEN
        RAISE EXCEPTION 'Deployment resource validator rejects valid available storage';
    END IF;

    IF has_schema_privilege('matrix_paas_api', 'paas', 'CREATE')
       OR has_schema_privilege('matrix_paas_worker', 'paas', 'CREATE')
       OR has_table_privilege(
            'matrix_paas_api',
            'paas.applications',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_api',
            'paas.configurations',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_api',
            'paas.configuration_revisions',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_api',
            'paas.application_revisions',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_api',
            'paas.operations',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege('matrix_paas_api', 'paas.execution_pools', 'INSERT, UPDATE, DELETE')
       OR has_table_privilege('matrix_paas_api', 'paas.execution_targets', 'INSERT, UPDATE, DELETE')
       OR has_table_privilege(
            'matrix_paas_api',
            'paas.audit_outbox',
            'SELECT, INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_api',
            'paas.terminal_sessions',
            'SELECT, INSERT, UPDATE, DELETE'
       )
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
            'paas.deployment_runtime_snapshots',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_api',
            'paas.deployment_resource_snapshots',
            'INSERT, UPDATE, DELETE'
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
            'paas.audit_outbox',
            'SELECT, INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.terminal_sessions',
            'SELECT, INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.deployments',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.adapter_commands',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.adapter_receipts',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.deployment_observations',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.deployment_runtime_snapshots',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.deployment_resource_snapshots',
            'SELECT, INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.placement_decisions',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.capacity_claims',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.capacity_reservations',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.execution_pools',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.execution_targets',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.placement_policies',
            'INSERT, UPDATE, DELETE'
       )
       OR has_table_privilege(
            'matrix_paas_worker',
            'paas.execution_target_allocations',
            'INSERT, DELETE'
       ) THEN
        RAISE EXCEPTION 'worker role can rewrite authoritative or immutable input';
    END IF;

    IF NOT has_function_privilege('matrix_paas_api', 'paas.admit_execution_resource(jsonb,jsonb,jsonb,text,text,bigint,jsonb)', 'EXECUTE')
       OR NOT has_function_privilege('matrix_paas_api', 'paas.refresh_execution_target(bigint,jsonb,bigint,jsonb)', 'EXECUTE')
       OR EXISTS (
            SELECT 1
              FROM unnest(ARRAY[
                    'paas.lock_terminal_session_by_fingerprint(text)',
                    'paas.lock_terminal_session(text)',
                    'paas.lock_open_terminal_session(text,text,text,text)',
                    'paas.lock_current_terminal_runtime(text,text,timestamptz)',
                    'paas.create_terminal_session(jsonb,text,jsonb)',
                    'paas.rotate_terminal_session_ticket(text,text)',
                    'paas.open_terminal_session_ticket(text,text)',
                    'paas.consume_terminal_session_ticket(text,jsonb)',
                    'paas.transition_terminal_session(text,jsonb,jsonb)'
                   ]) AS terminal_function(signature)
             WHERE NOT has_function_privilege(
                    'matrix_paas_api', terminal_function.signature, 'EXECUTE'
                   )
                OR has_function_privilege(
                    'matrix_paas_worker', terminal_function.signature, 'EXECUTE'
                   )
       )
       OR EXISTS (
            SELECT 1
              FROM unnest(ARRAY[
                    'paas.terminal_session_snapshot(paas.terminal_sessions)',
                    'paas.append_terminal_audit_outbox(text,jsonb)'
                   ]) AS internal_terminal_function(signature)
             WHERE has_function_privilege(
                    'matrix_paas_api', internal_terminal_function.signature, 'EXECUTE'
                   )
                OR has_function_privilege(
                    'matrix_paas_worker', internal_terminal_function.signature, 'EXECUTE'
                   )
       )
       OR has_function_privilege('matrix_paas_worker', 'paas.admit_execution_resource(jsonb,jsonb,jsonb,text,text,bigint,jsonb)', 'EXECUTE')
       OR has_function_privilege('matrix_paas_worker', 'paas.refresh_execution_target(bigint,jsonb,bigint,jsonb)', 'EXECUTE')
       OR has_function_privilege('matrix_paas_api', 'paas.store_execution_pool_observation(bigint,jsonb)', 'EXECUTE')
       OR has_function_privilege('matrix_paas_worker', 'paas.store_execution_pool_observation(bigint,jsonb)', 'EXECUTE')
       OR NOT has_table_privilege(
            'matrix_paas_api',
            'paas.applications',
            'SELECT'
       )
       OR NOT has_table_privilege(
            'matrix_paas_api',
            'paas.configurations',
            'SELECT'
       )
       OR NOT has_table_privilege(
            'matrix_paas_api',
            'paas.configuration_revisions',
            'SELECT'
       )
       OR NOT has_table_privilege(
            'matrix_paas_api',
            'paas.application_revisions',
            'SELECT'
       )
       OR NOT has_table_privilege(
            'matrix_paas_api',
            'paas.operations',
            'SELECT'
       )
       OR NOT has_table_privilege(
            'matrix_paas_api',
            'paas.deployment_runtime_snapshots',
            'SELECT'
       )
       OR NOT has_table_privilege(
            'matrix_paas_api',
            'paas.deployment_resource_snapshots',
            'SELECT'
       )
       OR NOT has_table_privilege(
            'matrix_paas_worker',
            'paas.adapter_commands',
            'SELECT'
       )
       OR NOT has_table_privilege(
            'matrix_paas_worker',
            'paas.placement_decisions',
            'SELECT'
       )
       OR NOT has_table_privilege(
            'matrix_paas_worker',
            'paas.deployment_runtime_snapshots',
            'SELECT'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.assert_current_operation_lease(text, text, bigint)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.create_placement(text, text, bigint, text, jsonb, jsonb, boolean)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.prepare_adapter_command(text, text, bigint, jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.record_adapter_receipt(text, text, bigint, text, text, text, text, jsonb, jsonb, timestamptz)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.record_deployment_observation(text, text, bigint, text, jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.release_operation_lease(text, text, bigint, timestamptz)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.transition_capacity_reservation(text, text, bigint, text, text, bigint)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.reconcile_local_execution_profile(text, bigint, jsonb, bigint, jsonb, bigint, jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.next_deployment_runtime_candidate(text, text)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.store_deployment_runtime_snapshot(text, text, bigint, text, text, text, timestamptz, timestamptz, jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.store_deployment_telemetry_snapshot(text, text, bigint, text, text, text, timestamptz, timestamptz, jsonb, timestamptz, timestamptz, jsonb)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_paas_api',
            'paas.valid_deployment_resource_document(jsonb)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_paas_worker',
            'paas.valid_deployment_resource_document(jsonb)',
            'EXECUTE'
       )
       OR to_regprocedure(
            'paas.reconcile_local_execution_profile(bigint,jsonb,bigint,jsonb,bigint,jsonb)'
       ) IS NOT NULL
       OR NOT has_function_privilege(
            'matrix_paas_api',
            'paas.create_apphosting_resource(jsonb, jsonb, jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_api',
            'paas.submit_deployment(jsonb, jsonb, jsonb, jsonb, bigint)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.claim_audit_event(text, integer)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.complete_audit_event(text, text, text, text, bigint, text, timestamptz, text)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.audit_outbox_snapshot()',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_api',
            'paas.readiness()',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_paas_worker',
            'paas.readiness()',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_paas_worker',
            'paas.worker_readiness()',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_paas_api',
            'paas.worker_readiness()',
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
            'paas.update_deployment_status(text, text, bigint, text, bigint, bigint, jsonb)',
            'EXECUTE'
       )
       OR EXISTS (
            SELECT 1
              FROM unnest(ARRAY[
                    'paas.claim_audit_event(text, integer)',
                    'paas.complete_audit_event(text, text, text, text, bigint, text, timestamptz, text)',
                    'paas.audit_outbox_snapshot()',
                    'paas.worker_readiness()',
                    'paas.claim_operation(text, integer)',
                    'paas.advance_operation(text, text, bigint, text, jsonb, timestamptz, boolean)',
                    'paas.assert_current_operation_lease(text, text, bigint)',
                    'paas.create_placement(text, text, bigint, text, jsonb, jsonb, boolean)',
                    'paas.prepare_adapter_command(text, text, bigint, jsonb)',
                    'paas.update_deployment_status(text, text, bigint, text, bigint, bigint, jsonb)',
                    'paas.record_adapter_receipt(text, text, bigint, text, text, text, text, jsonb, jsonb, timestamptz)',
                    'paas.record_deployment_observation(text, text, bigint, text, jsonb)',
                    'paas.release_operation_lease(text, text, bigint, timestamptz)',
                    'paas.transition_capacity_reservation(text, text, bigint, text, text, bigint)',
                    'paas.reconcile_local_execution_profile(text, bigint, jsonb, bigint, jsonb, bigint, jsonb)',
                    'paas.next_deployment_runtime_candidate(text, text)',
                    'paas.store_deployment_runtime_snapshot(text, text, bigint, text, text, text, timestamptz, timestamptz, jsonb)',
                    'paas.store_deployment_telemetry_snapshot(text, text, bigint, text, text, text, timestamptz, timestamptz, jsonb, timestamptz, timestamptz, jsonb)'
                   ]) AS worker_function(signature)
             WHERE has_function_privilege(
                    'matrix_paas_api',
                    worker_function.signature,
                    'EXECUTE'
                   )
       )
       OR has_function_privilege(
            'matrix_paas_worker',
            'paas.create_apphosting_resource(jsonb, jsonb, jsonb)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_paas_worker',
            'paas.submit_deployment(jsonb, jsonb, jsonb, jsonb, bigint)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_paas_api',
            'paas.append_audit_outbox(jsonb, jsonb)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_paas_worker',
            'paas.append_audit_outbox(jsonb, jsonb)',
            'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'application roles lack required current privileges';
    END IF;
END
$matrix_verify$;
