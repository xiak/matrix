BEGIN;

DO $matrix_role$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['matrix_paas_api', 'matrix_paas_worker']
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = role_name
        ) THEN
            EXECUTE format(
                'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                'NOREPLICATION NOBYPASSRLS',
                role_name
            );
        ELSE
            EXECUTE format(
                'ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                'NOREPLICATION NOBYPASSRLS',
                role_name
            );
        END IF;
    END LOOP;
END
$matrix_role$;

CREATE SCHEMA IF NOT EXISTS paas AUTHORIZATION CURRENT_USER;
REVOKE ALL ON SCHEMA paas FROM PUBLIC;
GRANT USAGE ON SCHEMA paas TO matrix_paas_api, matrix_paas_worker;

CREATE OR REPLACE FUNCTION paas.current_tenant_id()
RETURNS text
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT CASE
        WHEN current_setting('matrix.tenant_id', true)
            COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        THEN current_setting('matrix.tenant_id', true)
        ELSE NULL
    END
$function$;

REVOKE ALL ON FUNCTION paas.current_tenant_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.current_tenant_id()
    TO matrix_paas_api, matrix_paas_worker;

CREATE TABLE IF NOT EXISTS paas.applications (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT applications_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT applications_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT applications_document_identity CHECK (
        document->>'apiVersion' = 'paas.matrix.xiak.com/v1'
        AND document->>'kind' = 'Application'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,kind}' = 'TENANT'
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
    )
);

CREATE TABLE IF NOT EXISTS paas.configurations (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    application_id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT configurations_application_fk FOREIGN KEY (tenant_id, application_id)
        REFERENCES paas.applications (tenant_id, id),
    CONSTRAINT configurations_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND application_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT configurations_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT configurations_document_identity CHECK (
        document->>'apiVersion' = 'paas.matrix.xiak.com/v1'
        AND document->>'kind' = 'Configuration'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,kind}' = 'TENANT'
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND document->>'applicationId' = application_id
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
    )
);

CREATE TABLE IF NOT EXISTS paas.configuration_revisions (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    configuration_id text COLLATE "C" NOT NULL,
    content_digest text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT configuration_revisions_configuration_fk FOREIGN KEY (
        tenant_id, configuration_id
    ) REFERENCES paas.configurations (tenant_id, id),
    CONSTRAINT configuration_revisions_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND configuration_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT configuration_revisions_digest_valid CHECK (
        content_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT configuration_revisions_immutable_version CHECK (resource_version = 1),
    CONSTRAINT configuration_revisions_document_identity CHECK (
        document->>'apiVersion' = 'paas.matrix.xiak.com/v1'
        AND document->>'kind' = 'ConfigurationRevision'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,kind}' = 'TENANT'
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND document#>>'{metadata,resourceVersion}' = '1'
        AND document#>>'{spec,configurationId}' = configuration_id
        AND document#>>'{spec,contentDigest}' = content_digest
    )
);

CREATE TABLE IF NOT EXISTS paas.application_revisions (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    application_id text COLLATE "C" NOT NULL,
    content_digest text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT application_revisions_application_fk FOREIGN KEY (tenant_id, application_id)
        REFERENCES paas.applications (tenant_id, id),
    CONSTRAINT application_revisions_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND application_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT application_revisions_digest_valid CHECK (
        content_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT application_revisions_immutable_version CHECK (resource_version = 1),
    CONSTRAINT application_revisions_document_identity CHECK (
        document->>'apiVersion' = 'paas.matrix.xiak.com/v1'
        AND document->>'kind' = 'ApplicationRevision'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,kind}' = 'TENANT'
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND document#>>'{metadata,resourceVersion}' = '1'
        AND document#>>'{spec,applicationId}' = application_id
        AND document#>>'{spec,contentDigest}' = content_digest
    )
);

CREATE TABLE IF NOT EXISTS paas.placement_policies (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT placement_policies_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT placement_policies_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT placement_policies_document_identity CHECK (
        document->>'apiVersion' = 'paas.matrix.xiak.com/v1'
        AND document->>'kind' = 'PlacementPolicy'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,kind}' = 'TENANT'
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
    )
);

CREATE TABLE IF NOT EXISTS paas.deployments (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    generation bigint NOT NULL,
    application_revision_id text COLLATE "C" NOT NULL,
    policy_id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT deployments_revision_fk FOREIGN KEY (tenant_id, application_revision_id)
        REFERENCES paas.application_revisions (tenant_id, id),
    CONSTRAINT deployments_policy_fk FOREIGN KEY (tenant_id, policy_id)
        REFERENCES paas.placement_policies (tenant_id, id),
    CONSTRAINT deployments_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT deployments_version_valid CHECK (
        generation BETWEEN 1 AND 9007199254740991
        AND resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT deployments_document_identity CHECK (
        document->>'apiVersion' = 'paas.matrix.xiak.com/v1'
        AND document->>'kind' = 'Deployment'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,kind}' = 'TENANT'
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND CASE
            WHEN document->>'generation' ~ '^[1-9][0-9]*$'
            THEN (document->>'generation')::numeric = generation
            ELSE false
        END
        AND document#>>'{spec,applicationRevisionId}' = application_revision_id
        AND document#>>'{spec,placementPolicyId}' = policy_id
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
    )
);

CREATE TABLE IF NOT EXISTS paas.deployment_generations (
    tenant_id text COLLATE "C" NOT NULL,
    deployment_id text COLLATE "C" NOT NULL,
    generation bigint NOT NULL,
    application_revision_id text COLLATE "C" NOT NULL,
    policy_id text COLLATE "C" NOT NULL,
    content_digest text COLLATE "C" NOT NULL,
    created_by_operation_id text COLLATE "C" NOT NULL,
    created_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id, generation),
    CONSTRAINT deployment_generations_deployment_fk FOREIGN KEY (tenant_id, deployment_id)
        REFERENCES paas.deployments (tenant_id, id),
    CONSTRAINT deployment_generations_revision_fk FOREIGN KEY (
        tenant_id, application_revision_id
    ) REFERENCES paas.application_revisions (tenant_id, id),
    CONSTRAINT deployment_generations_policy_fk FOREIGN KEY (tenant_id, policy_id)
        REFERENCES paas.placement_policies (tenant_id, id),
    CONSTRAINT deployment_generations_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND deployment_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND application_revision_id COLLATE "C"
            ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND policy_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND created_by_operation_id COLLATE "C"
            ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT deployment_generations_values_valid CHECK (
        generation BETWEEN 1 AND 9007199254740991
        AND content_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT deployment_generations_document_identity CHECK (
        document->>'apiVersion' = 'paas.matrix.xiak.com/v1'
        AND document->>'kind' = 'DeploymentGeneration'
        AND document#>>'{scope,kind}' = 'TENANT'
        AND document#>>'{scope,tenantId}' = tenant_id
        AND document->>'deploymentId' = deployment_id
        AND document#>>'{spec,applicationRevisionId}' = application_revision_id
        AND document#>>'{spec,placementPolicyId}' = policy_id
        AND document->>'contentDigest' = content_digest
        AND document->>'createdByOperationId' = created_by_operation_id
        AND (document->>'createdAt')::timestamptz = created_at
        AND CASE
            WHEN document->>'generation' ~ '^[1-9][0-9]*$'
            THEN (document->>'generation')::numeric = generation
            ELSE false
        END
    )
);

CREATE TABLE IF NOT EXISTS paas.operations (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    action text COLLATE "C" NOT NULL,
    target_kind text COLLATE "C" NOT NULL,
    target_id text COLLATE "C" NOT NULL,
    idempotency_fingerprint text COLLATE "C" NOT NULL,
    request_digest text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL,
    attempt bigint NOT NULL,
    next_attempt_at timestamptz(6) NOT NULL,
    lease_owner text COLLATE "C",
    lease_expires_at timestamptz(6),
    fencing_token bigint NOT NULL DEFAULT 0,
    error jsonb,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    terminal_at timestamptz(6),
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT operations_idempotency_uq UNIQUE (tenant_id, idempotency_fingerprint),
    CONSTRAINT operations_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND target_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND (lease_owner IS NULL OR lease_owner COLLATE "C"
            ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
    ),
    CONSTRAINT operations_digests_valid CHECK (
        idempotency_fingerprint COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND request_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT operations_action_valid CHECK (
        action IN (
            'DEPLOY',
            'UPDATE',
            'STOP',
            'ROLLBACK'
        )
    ),
    CONSTRAINT operations_state_valid CHECK (
        state IN (
            'ACCEPTED',
            'PLANNING',
            'QUEUED',
            'EXECUTING',
            'VERIFYING',
            'RECONCILING',
            'SUCCEEDED',
            'FAILED',
            'CANCELLED',
            'MANUAL_INTERVENTION'
        )
    ),
    CONSTRAINT operations_attempt_valid CHECK (
        attempt BETWEEN 1 AND 4294967295
        AND fencing_token BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT operations_lease_valid CHECK (
        (lease_owner IS NULL AND lease_expires_at IS NULL)
        OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
    ),
    CONSTRAINT operations_terminal_valid CHECK (
        (
            state IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION')
            AND terminal_at IS NOT NULL
            AND lease_owner IS NULL
            AND lease_expires_at IS NULL
        )
        OR (
            state NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION')
            AND terminal_at IS NULL
        )
    ),
    CONSTRAINT operations_error_valid CHECK (
        (state IN ('FAILED', 'MANUAL_INTERVENTION') AND error IS NOT NULL)
        OR (state NOT IN ('FAILED', 'MANUAL_INTERVENTION') AND error IS NULL)
    ),
    CONSTRAINT operations_time_valid CHECK (
        updated_at >= created_at
        AND next_attempt_at >= created_at
        AND (terminal_at IS NULL OR terminal_at BETWEEN created_at AND updated_at)
    ),
    CONSTRAINT operations_document_identity CHECK (
        document->>'apiVersion' = 'paas.matrix.xiak.com/v1'
        AND document->>'kind' = 'Operation'
        AND document->>'id' = id
        AND document#>>'{scope,kind}' = 'TENANT'
        AND document#>>'{scope,tenantId}' = tenant_id
        AND document->>'action' = action
        AND document#>>'{target,kind}' = target_kind
        AND document#>>'{target,id}' = target_id
        AND document->>'idempotencyFingerprint' = idempotency_fingerprint
        AND document->>'requestDigest' = request_digest
        AND document->>'state' = state
        AND document->'error' IS NOT DISTINCT FROM error
        AND (document->>'createdAt')::timestamptz = created_at
        AND (document->>'updatedAt')::timestamptz = updated_at
        AND (
            (terminal_at IS NULL AND NOT (document ? 'terminalAt'))
            OR (document->>'terminalAt')::timestamptz = terminal_at
        )
        AND CASE
            WHEN document->>'attempt' ~ '^[1-9][0-9]*$'
            THEN (document->>'attempt')::numeric = attempt
            ELSE false
        END
    )
);

CREATE INDEX IF NOT EXISTS operations_claim_idx
    ON paas.operations (next_attempt_at, created_at, tenant_id, id)
    WHERE state NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION');

DO $matrix_generation_operation_link$
BEGIN
	IF NOT EXISTS (
		SELECT 1
		FROM pg_catalog.pg_constraint
		WHERE conname = 'deployment_generations_operation_uq'
		  AND connamespace = 'paas'::regnamespace
	) THEN
		ALTER TABLE paas.deployment_generations
			ADD CONSTRAINT deployment_generations_operation_uq
			UNIQUE (tenant_id, created_by_operation_id);
	END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint
        WHERE conname = 'deployment_generations_operation_fk'
          AND connamespace = 'paas'::regnamespace
    ) THEN
        ALTER TABLE paas.deployment_generations
            ADD CONSTRAINT deployment_generations_operation_fk
            FOREIGN KEY (tenant_id, created_by_operation_id)
            REFERENCES paas.operations (tenant_id, id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
END
$matrix_generation_operation_link$;

CREATE TABLE IF NOT EXISTS paas.execution_pools (
    id text COLLATE "C" PRIMARY KEY,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    CONSTRAINT execution_pools_id_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT execution_pools_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT execution_pools_document_identity CHECK (
        document->>'apiVersion' = 'paas.matrix.xiak.com/v1'
        AND document->>'kind' = 'ExecutionPool'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,kind}' = 'PLATFORM'
        AND NOT (document#>'{metadata,scope}' ? 'tenantId')
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
    )
);

CREATE TABLE IF NOT EXISTS paas.execution_targets (
    id text COLLATE "C" PRIMARY KEY,
    execution_pool_id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    CONSTRAINT execution_targets_pool_fk FOREIGN KEY (execution_pool_id)
        REFERENCES paas.execution_pools (id),
    CONSTRAINT execution_targets_id_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT execution_targets_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT execution_targets_document_identity CHECK (
        document->>'apiVersion' = 'paas.matrix.xiak.com/v1'
        AND document->>'kind' = 'ExecutionTarget'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,kind}' = 'PLATFORM'
        AND NOT (document#>'{metadata,scope}' ? 'tenantId')
        AND document#>>'{spec,executionPoolId}' = execution_pool_id
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
    )
);

CREATE INDEX IF NOT EXISTS execution_targets_pool_idx
    ON paas.execution_targets (execution_pool_id, id);

CREATE TABLE IF NOT EXISTS paas.execution_target_allocations (
    execution_target_id text COLLATE "C" PRIMARY KEY,
    lock_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT execution_target_allocations_target_fk FOREIGN KEY (execution_target_id)
        REFERENCES paas.execution_targets (id),
    CONSTRAINT execution_target_allocations_version_valid CHECK (lock_version >= 0)
);

CREATE TABLE IF NOT EXISTS paas.adapter_commands (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    operation_id text COLLATE "C" NOT NULL,
    action text COLLATE "C" NOT NULL,
    deployment_id text COLLATE "C" NOT NULL,
    deployment_generation bigint NOT NULL,
    application_revision_id text COLLATE "C" NOT NULL,
    execution_target_id text COLLATE "C" NOT NULL,
    request_digest text COLLATE "C" NOT NULL,
    binding_ref text COLLATE "C" NOT NULL,
    deadline timestamptz(6) NOT NULL,
    created_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT adapter_commands_operation_action_uq UNIQUE (
        tenant_id, operation_id, action
    ),
    CONSTRAINT adapter_commands_operation_fk FOREIGN KEY (tenant_id, operation_id)
        REFERENCES paas.operations (tenant_id, id),
    CONSTRAINT adapter_commands_generation_fk FOREIGN KEY (
        tenant_id, deployment_id, deployment_generation
    ) REFERENCES paas.deployment_generations (tenant_id, deployment_id, generation),
    CONSTRAINT adapter_commands_revision_fk FOREIGN KEY (
        tenant_id, application_revision_id
    ) REFERENCES paas.application_revisions (tenant_id, id),
    CONSTRAINT adapter_commands_target_fk FOREIGN KEY (execution_target_id)
        REFERENCES paas.execution_targets (id),
    CONSTRAINT adapter_commands_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND operation_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND deployment_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND application_revision_id COLLATE "C"
            ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND execution_target_id COLLATE "C"
            ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND binding_ref COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT adapter_commands_values_valid CHECK (
        deployment_generation BETWEEN 1 AND 9007199254740991
        AND request_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND action IN (
            'VALIDATE_DEPLOYMENT',
            'APPLY_DEPLOYMENT',
            'OBSERVE_DEPLOYMENT',
            'STOP_DEPLOYMENT',
            'ROLLBACK_DEPLOYMENT'
        )
        AND deadline >= created_at
    ),
    CONSTRAINT adapter_commands_document_identity CHECK (
        document->>'operationId' = operation_id
        AND document->>'commandId' = id
        AND document->>'action' = action
        AND document#>>'{scope,kind}' = 'TENANT'
        AND document#>>'{scope,tenantId}' = tenant_id
        AND document->>'deploymentId' = deployment_id
        AND document->>'applicationRevisionId' = application_revision_id
        AND document->>'executionTargetId' = execution_target_id
        AND document->>'requestDigest' = request_digest
        AND document->>'bindingRef' = binding_ref
        AND (document->>'deadline')::timestamptz = deadline
    )
);

CREATE TABLE IF NOT EXISTS paas.adapter_receipts (
    tenant_id text COLLATE "C" NOT NULL,
    command_id text COLLATE "C" NOT NULL,
    request_digest text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL,
    receipt_digest text COLLATE "C",
    normalized_error jsonb,
    evidence jsonb NOT NULL,
    observed_at timestamptz(6) NOT NULL,
    PRIMARY KEY (tenant_id, command_id),
    CONSTRAINT adapter_receipts_command_fk FOREIGN KEY (tenant_id, command_id)
        REFERENCES paas.adapter_commands (tenant_id, id),
    CONSTRAINT adapter_receipts_values_valid CHECK (
        request_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND (receipt_digest IS NULL OR receipt_digest COLLATE "C"
            ~ '^sha256:[0-9a-f]{64}$')
        AND state IN ('SUCCEEDED', 'IN_PROGRESS', 'FAILED', 'UNKNOWN')
        AND jsonb_typeof(evidence) = 'array'
        AND (
            (state IN ('FAILED', 'UNKNOWN') AND normalized_error IS NOT NULL)
            OR (state NOT IN ('FAILED', 'UNKNOWN') AND normalized_error IS NULL)
        )
        AND (state <> 'SUCCEEDED' OR receipt_digest IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS paas.deployment_observations (
    tenant_id text COLLATE "C" NOT NULL,
    command_id text COLLATE "C" NOT NULL,
    deployment_id text COLLATE "C" NOT NULL,
    deployment_generation bigint NOT NULL,
    application_revision_id text COLLATE "C" NOT NULL,
    phase text COLLATE "C" NOT NULL,
    ready_components bigint NOT NULL,
    receipt_digest text COLLATE "C" NOT NULL,
    observed_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, command_id),
    CONSTRAINT deployment_observations_command_fk FOREIGN KEY (tenant_id, command_id)
        REFERENCES paas.adapter_commands (tenant_id, id),
    CONSTRAINT deployment_observations_generation_fk FOREIGN KEY (
        tenant_id, deployment_id, deployment_generation
    ) REFERENCES paas.deployment_generations (tenant_id, deployment_id, generation),
    CONSTRAINT deployment_observations_revision_fk FOREIGN KEY (
        tenant_id, application_revision_id
    ) REFERENCES paas.application_revisions (tenant_id, id),
    CONSTRAINT deployment_observations_values_valid CHECK (
        deployment_generation BETWEEN 1 AND 9007199254740991
        AND ready_components BETWEEN 0 AND 4294967295
        AND receipt_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND phase IN ('APPLYING', 'READY', 'DEGRADED', 'FAILED', 'STOPPING', 'STOPPED')
    ),
    CONSTRAINT deployment_observations_document_identity CHECK (
        document->>'deploymentId' = deployment_id
        AND document->>'applicationRevisionId' = application_revision_id
        AND document->>'phase' = phase
        AND document->>'receiptDigest' = receipt_digest
        AND (document->>'observedAt')::timestamptz = observed_at
        AND CASE
            WHEN document->>'generation' ~ '^[1-9][0-9]*$'
            THEN (document->>'generation')::numeric = deployment_generation
            ELSE false
        END
        AND CASE
            WHEN document->>'readyComponents' ~ '^(0|[1-9][0-9]*)$'
            THEN (document->>'readyComponents')::numeric = ready_components
            ELSE false
        END
    )
);

CREATE TABLE IF NOT EXISTS paas.placement_decisions (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    operation_id text COLLATE "C" NOT NULL,
    request_digest text COLLATE "C" NOT NULL,
    deployment_id text COLLATE "C" NOT NULL,
    deployment_generation bigint NOT NULL,
    deployment_resource_version bigint NOT NULL,
    application_revision_id text COLLATE "C" NOT NULL,
    policy_id text COLLATE "C" NOT NULL,
    policy_resource_version bigint NOT NULL,
    requested_isolation text COLLATE "C" NOT NULL,
    outcome text COLLATE "C" NOT NULL,
    execution_target_id text COLLATE "C",
    execution_target_resource_version bigint,
    granted_isolation text COLLATE "C",
    candidate_digest text COLLATE "C" NOT NULL,
    reason jsonb,
    decided_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT placement_decisions_operation_uq UNIQUE (tenant_id, operation_id),
    CONSTRAINT placement_decisions_scheduled_identity_uq UNIQUE (
        tenant_id, id, deployment_id, execution_target_id, granted_isolation
    ),
    CONSTRAINT placement_decisions_deployment_fk FOREIGN KEY (tenant_id, deployment_id)
        REFERENCES paas.deployments (tenant_id, id),
    CONSTRAINT placement_decisions_generation_fk FOREIGN KEY (
        tenant_id, deployment_id, deployment_generation
    ) REFERENCES paas.deployment_generations (tenant_id, deployment_id, generation),
    CONSTRAINT placement_decisions_revision_fk FOREIGN KEY (tenant_id, application_revision_id)
        REFERENCES paas.application_revisions (tenant_id, id),
    CONSTRAINT placement_decisions_policy_fk FOREIGN KEY (tenant_id, policy_id)
        REFERENCES paas.placement_policies (tenant_id, id),
    CONSTRAINT placement_decisions_target_fk FOREIGN KEY (execution_target_id)
        REFERENCES paas.execution_targets (id),
    CONSTRAINT placement_decisions_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND operation_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT placement_decisions_digests_valid CHECK (
        request_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND candidate_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT placement_decisions_versions_valid CHECK (
        deployment_generation BETWEEN 1 AND 9007199254740991
        AND deployment_resource_version BETWEEN 1 AND 9007199254740991
        AND policy_resource_version BETWEEN 1 AND 9007199254740991
        AND (
            execution_target_resource_version IS NULL
            OR execution_target_resource_version BETWEEN 1 AND 9007199254740991
        )
    ),
    CONSTRAINT placement_decisions_isolation_valid CHECK (
        requested_isolation IN ('WORKLOAD', 'TENANT', 'HOST')
        AND (granted_isolation IS NULL OR granted_isolation = requested_isolation)
    ),
    CONSTRAINT placement_decisions_outcome_valid CHECK (
        (
            outcome = 'SCHEDULED'
            AND execution_target_id IS NOT NULL
            AND execution_target_resource_version IS NOT NULL
            AND granted_isolation = requested_isolation
            AND reason IS NULL
        )
        OR (
            outcome = 'UNSCHEDULABLE'
            AND execution_target_id IS NULL
            AND execution_target_resource_version IS NULL
            AND granted_isolation IS NULL
            AND reason IS NOT NULL
        )
    ),
    CONSTRAINT placement_decisions_document_identity CHECK (
        document->>'apiVersion' = 'paas.matrix.xiak.com/v1'
        AND document->>'kind' = 'PlacementDecision'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,kind}' = 'TENANT'
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND document->>'deploymentId' = deployment_id
        AND CASE
            WHEN document->>'deploymentGeneration' ~ '^[1-9][0-9]*$'
            THEN (document->>'deploymentGeneration')::numeric = deployment_generation
            ELSE false
        END
        AND document->>'applicationRevisionId' = application_revision_id
        AND document->>'placementPolicyId' = policy_id
        AND document->>'requestedIsolationGuarantee' = requested_isolation
        AND document->>'outcome' = outcome
        AND document->>'candidateSetDigest' = candidate_digest
        AND CASE
            WHEN document->>'deploymentResourceVersion' ~ '^[1-9][0-9]*$'
            THEN (document->>'deploymentResourceVersion')::numeric = deployment_resource_version
            ELSE false
        END
        AND CASE
            WHEN document->>'policyResourceVersion' ~ '^[1-9][0-9]*$'
            THEN (document->>'policyResourceVersion')::numeric = policy_resource_version
            ELSE false
        END
        AND (
            (execution_target_id IS NULL AND NOT (document ? 'executionTargetId'))
            OR document->>'executionTargetId' = execution_target_id
        )
        AND (
            (
                execution_target_resource_version IS NULL
                AND NOT (document ? 'executionTargetResourceVersion')
            )
            OR CASE
                WHEN document->>'executionTargetResourceVersion' ~ '^[1-9][0-9]*$'
                THEN (document->>'executionTargetResourceVersion')::numeric
                    = execution_target_resource_version
                ELSE false
            END
        )
        AND (
            (granted_isolation IS NULL AND NOT (document ? 'grantedIsolationGuarantee'))
            OR document->>'grantedIsolationGuarantee' = granted_isolation
        )
        AND reason IS NOT DISTINCT FROM document->'reason'
        AND (document->>'decidedAt')::timestamptz = decided_at
    )
);

CREATE TABLE IF NOT EXISTS paas.capacity_claims (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    execution_target_id text COLLATE "C" NOT NULL,
    isolation text COLLATE "C" NOT NULL,
    cpu_millis bigint NOT NULL,
    memory_bytes bigint NOT NULL,
    workload_slots bigint NOT NULL,
    state text COLLATE "C" NOT NULL,
    lease_expires_at timestamptz(6),
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT capacity_claims_identity_uq UNIQUE (id, execution_target_id, isolation),
    CONSTRAINT capacity_claims_target_fk FOREIGN KEY (execution_target_id)
        REFERENCES paas.execution_targets (id),
    CONSTRAINT capacity_claims_isolation_valid CHECK (
        isolation IN ('WORKLOAD', 'TENANT', 'HOST')
    ),
    CONSTRAINT capacity_claims_resources_valid CHECK (
        cpu_millis >= 0 AND memory_bytes >= 0 AND workload_slots > 0
    ),
    CONSTRAINT capacity_claims_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT capacity_claims_state_valid CHECK (
        (state = 'PENDING' AND lease_expires_at IS NOT NULL)
        OR (state IN ('ACTIVE', 'RELEASED') AND lease_expires_at IS NULL)
    ),
    CONSTRAINT capacity_claims_time_valid CHECK (updated_at >= created_at)
);

CREATE INDEX IF NOT EXISTS capacity_claims_target_consuming_idx
    ON paas.capacity_claims (execution_target_id, state, lease_expires_at, id)
    WHERE state IN ('PENDING', 'ACTIVE');

CREATE TABLE IF NOT EXISTS paas.capacity_reservations (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    decision_id text COLLATE "C" NOT NULL,
    deployment_id text COLLATE "C" NOT NULL,
    execution_target_id text COLLATE "C" NOT NULL,
    isolation text COLLATE "C" NOT NULL,
    capacity_claim_id uuid NOT NULL,
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT capacity_reservations_decision_uq UNIQUE (tenant_id, decision_id),
    CONSTRAINT capacity_reservations_claim_uq UNIQUE (capacity_claim_id),
    CONSTRAINT capacity_reservations_decision_fk FOREIGN KEY (
        tenant_id, decision_id, deployment_id, execution_target_id, isolation
    ) REFERENCES paas.placement_decisions (
        tenant_id, id, deployment_id, execution_target_id, granted_isolation
    ),
    CONSTRAINT capacity_reservations_claim_fk FOREIGN KEY (
        capacity_claim_id, execution_target_id, isolation
    ) REFERENCES paas.capacity_claims (id, execution_target_id, isolation),
    CONSTRAINT capacity_reservations_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND decision_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND deployment_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT capacity_reservations_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT capacity_reservations_time_valid CHECK (updated_at >= created_at)
);

DO $matrix_capacity_claim_link$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint
        WHERE conname = 'capacity_claims_reservation_fk'
          AND connamespace = 'paas'::regnamespace
    ) THEN
        ALTER TABLE paas.capacity_claims
            ADD CONSTRAINT capacity_claims_reservation_fk
            FOREIGN KEY (id)
            REFERENCES paas.capacity_reservations (capacity_claim_id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
END
$matrix_capacity_claim_link$;

ALTER TABLE paas.applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.applications FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.configurations FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.configuration_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.configuration_revisions FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.application_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.application_revisions FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.placement_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.placement_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.deployments ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.deployments FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.deployment_generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.deployment_generations FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.operations FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.adapter_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.adapter_commands FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.adapter_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.adapter_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.deployment_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.deployment_observations FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.placement_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.placement_decisions FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.capacity_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.capacity_reservations FORCE ROW LEVEL SECURITY;

DO $matrix_policy$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
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
    ]
    LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_policies
            WHERE schemaname = 'paas'
              AND tablename = table_name
              AND policyname = 'tenant_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY tenant_isolation ON paas.%I '
                'USING (tenant_id = paas.current_tenant_id()) '
                'WITH CHECK (tenant_id = paas.current_tenant_id())',
                table_name
            );
        END IF;
    END LOOP;
END
$matrix_policy$;

CREATE OR REPLACE FUNCTION paas.submit_deployment(
    submitted_deployment jsonb,
    submitted_generation jsonb,
    submitted_operation jsonb,
    expected_resource_version bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    effective_now timestamptz(6);
    deployment_id text;
    operation_id text;
    operation_action text;
    new_generation bigint;
    new_resource_version bigint;
    current_generation bigint;
    current_resource_version bigint;
    current_document jsonb;
BEGIN
    effective_tenant_id := paas.current_tenant_id();
    effective_now := transaction_timestamp();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'valid transaction-local tenant context is required';
    END IF;
    IF jsonb_typeof(submitted_deployment) <> 'object'
       OR jsonb_typeof(submitted_generation) <> 'object'
       OR jsonb_typeof(submitted_operation) <> 'object' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'deployment submission documents must be objects';
    END IF;
    IF expected_resource_version IS NULL
       OR expected_resource_version NOT BETWEEN 0 AND 9007199254740991 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'expected Deployment resource version is invalid';
    END IF;

    deployment_id := submitted_deployment#>>'{metadata,id}';
    operation_id := submitted_operation->>'id';
    operation_action := submitted_operation->>'action';
    IF deployment_id IS NULL
       OR deployment_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR operation_id IS NULL
       OR operation_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_deployment#>>'{metadata,scope,kind}' <> 'TENANT'
       OR submitted_deployment#>>'{metadata,scope,tenantId}' <> effective_tenant_id
       OR submitted_generation#>>'{scope,kind}' <> 'TENANT'
       OR submitted_generation#>>'{scope,tenantId}' <> effective_tenant_id
       OR submitted_operation#>>'{scope,kind}' <> 'TENANT'
       OR submitted_operation#>>'{scope,tenantId}' <> effective_tenant_id
       OR submitted_generation->>'deploymentId' <> deployment_id
       OR submitted_operation#>>'{target,kind}' <> 'Deployment'
       OR submitted_operation#>>'{target,id}' <> deployment_id
       OR submitted_generation->>'createdByOperationId' <> operation_id
       OR submitted_generation->'spec' IS DISTINCT FROM submitted_deployment->'spec'
       OR submitted_operation->>'state' <> 'ACCEPTED'
       OR submitted_operation->'error' IS NOT NULL
       OR submitted_operation ? 'terminalAt'
       OR submitted_deployment#>>'{status,phase}' <> 'PENDING'
       OR submitted_deployment#>>'{status,currentOperationId}' <> operation_id
       OR submitted_deployment#>'{status}' ? 'placementDecisionId' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'deployment submission identities or initial state are invalid';
    END IF;
    IF submitted_deployment->>'generation' !~ '^[1-9][0-9]*$'
       OR submitted_generation->>'generation' !~ '^[1-9][0-9]*$'
       OR submitted_deployment#>>'{metadata,resourceVersion}' !~ '^[1-9][0-9]*$'
       OR submitted_operation->>'attempt' <> '1' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'deployment submission versions are invalid';
    END IF;
    new_generation := (submitted_deployment->>'generation')::bigint;
    new_resource_version :=
        (submitted_deployment#>>'{metadata,resourceVersion}')::bigint;
    IF (submitted_generation->>'generation')::bigint <> new_generation
       OR new_generation NOT BETWEEN 1 AND 9007199254740991
       OR new_resource_version NOT BETWEEN 1 AND 9007199254740991
       OR submitted_generation->>'contentDigest' COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR submitted_operation->>'idempotencyFingerprint' COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR submitted_operation->>'requestDigest' COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR (submitted_operation->>'createdAt')::timestamptz <> effective_now
       OR (submitted_operation->>'updatedAt')::timestamptz <> effective_now
       OR (submitted_generation->>'createdAt')::timestamptz <> effective_now
       OR (submitted_deployment#>>'{metadata,updatedAt}')::timestamptz <> effective_now THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'deployment submission digest or database time is invalid';
    END IF;

    SELECT deployment.generation,
           deployment.resource_version,
           deployment.document
      INTO current_generation,
           current_resource_version,
           current_document
      FROM paas.deployments AS deployment
     WHERE deployment.tenant_id = effective_tenant_id
       AND deployment.id = deployment_id
     FOR UPDATE;

    IF NOT FOUND THEN
        IF expected_resource_version <> 0 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MX409',
                MESSAGE = 'Deployment resource version conflict';
        END IF;
        IF new_generation <> 1
           OR new_resource_version <> 1
           OR operation_action <> 'DEPLOY'
           OR submitted_deployment#>>'{status,observedGeneration}' <> '0'
           OR submitted_deployment#>>'{status,readyComponents}' <> '0'
           OR submitted_deployment#>'{status}' ? 'observedApplicationRevisionId'
           OR (submitted_deployment#>>'{metadata,createdAt}')::timestamptz
                <> effective_now THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'new Deployment must start at generation and resource version one';
        END IF;
    ELSE
        IF expected_resource_version <> current_resource_version THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MX409',
                MESSAGE = 'Deployment resource version conflict';
        END IF;
        IF current_generation = 9007199254740991
           OR current_resource_version = 9007199254740991
           OR new_generation <> current_generation + 1
           OR new_resource_version <> current_resource_version + 1
           OR operation_action NOT IN ('UPDATE', 'STOP', 'ROLLBACK')
           OR (operation_action = 'STOP'
               AND submitted_deployment#>>'{spec,desiredState}' <> 'STOPPED')
           OR (operation_action IN ('UPDATE', 'ROLLBACK')
               AND submitted_deployment#>>'{spec,desiredState}' <> 'RUNNING')
           OR submitted_deployment->'metadata' - ARRAY['resourceVersion', 'updatedAt']
                IS DISTINCT FROM
                current_document->'metadata' - ARRAY['resourceVersion', 'updatedAt']
           OR submitted_deployment->'status' - ARRAY[
                'phase', 'placementDecisionId', 'currentOperationId'
              ] IS DISTINCT FROM
              current_document->'status' - ARRAY[
                'phase', 'placementDecisionId', 'currentOperationId'
              ] THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'Deployment update does not preserve immutable identity or observed state';
        END IF;
    END IF;

    INSERT INTO paas.operations (
        tenant_id,
        id,
        action,
        target_kind,
        target_id,
        idempotency_fingerprint,
        request_digest,
        state,
        attempt,
        next_attempt_at,
        fencing_token,
        created_at,
        updated_at,
        document
    ) VALUES (
        effective_tenant_id,
        operation_id,
        operation_action,
        submitted_operation#>>'{target,kind}',
        deployment_id,
        submitted_operation->>'idempotencyFingerprint',
        submitted_operation->>'requestDigest',
        'ACCEPTED',
        1,
        effective_now,
        0,
        effective_now,
        effective_now,
        submitted_operation
    );

    IF current_document IS NULL THEN
        INSERT INTO paas.deployments (
            tenant_id,
            id,
            generation,
            application_revision_id,
            policy_id,
            resource_version,
            document
        ) VALUES (
            effective_tenant_id,
            deployment_id,
            new_generation,
            submitted_deployment#>>'{spec,applicationRevisionId}',
            submitted_deployment#>>'{spec,placementPolicyId}',
            new_resource_version,
            submitted_deployment
        );
    ELSE
        UPDATE paas.deployments AS deployment
           SET generation = new_generation,
               application_revision_id =
                    submitted_deployment#>>'{spec,applicationRevisionId}',
               policy_id = submitted_deployment#>>'{spec,placementPolicyId}',
               resource_version = new_resource_version,
               document = submitted_deployment
         WHERE deployment.tenant_id = effective_tenant_id
           AND deployment.id = deployment_id;
    END IF;

    INSERT INTO paas.deployment_generations (
        tenant_id,
        deployment_id,
        generation,
        application_revision_id,
        policy_id,
        content_digest,
        created_by_operation_id,
        created_at,
        document
    ) VALUES (
        effective_tenant_id,
        deployment_id,
        new_generation,
        submitted_generation#>>'{spec,applicationRevisionId}',
        submitted_generation#>>'{spec,placementPolicyId}',
        submitted_generation->>'contentDigest',
        operation_id,
        effective_now,
        submitted_generation
    );
END
$function$;

REVOKE ALL ON FUNCTION paas.submit_deployment(jsonb, jsonb, jsonb, bigint)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.submit_deployment(jsonb, jsonb, jsonb, bigint)
    TO matrix_paas_api;

CREATE OR REPLACE FUNCTION paas.claim_operation(
    requested_worker_id text,
    requested_lease_seconds integer
)
RETURNS TABLE (
    tenant_id text,
    operation_id text,
    operation_state text,
    attempt bigint,
    fencing_token bigint,
    lease_expires_at timestamptz,
    document jsonb
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_lease_seconds IS NULL
       OR requested_lease_seconds NOT BETWEEN 1 AND 300 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'operation claim parameters are invalid';
    END IF;

    RETURN QUERY
    WITH candidate AS MATERIALIZED (
        SELECT operation.tenant_id,
               operation.id
          FROM paas.operations AS operation
         WHERE operation.state NOT IN (
                'SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION'
               )
           AND operation.next_attempt_at <= transaction_timestamp()
           AND (
                operation.lease_owner IS NULL
                OR operation.lease_expires_at <= transaction_timestamp()
               )
         ORDER BY operation.next_attempt_at,
                  operation.created_at,
                  operation.tenant_id COLLATE "C",
                  operation.id COLLATE "C"
         FOR UPDATE SKIP LOCKED
         LIMIT 1
    ), updated AS (
        UPDATE paas.operations AS operation
           SET lease_owner = requested_worker_id,
               lease_expires_at = transaction_timestamp()
                    + make_interval(secs => requested_lease_seconds),
               fencing_token = operation.fencing_token + 1,
               attempt = CASE
                    WHEN operation.fencing_token = 0 THEN operation.attempt
                    ELSE operation.attempt + 1
               END,
               updated_at = transaction_timestamp(),
               document = jsonb_set(
                    jsonb_set(
                        operation.document,
                        '{attempt}',
                        to_jsonb(CASE
                            WHEN operation.fencing_token = 0 THEN operation.attempt
                            ELSE operation.attempt + 1
                        END),
                        false
                    ),
                    '{updatedAt}',
                    to_jsonb(to_char(
                        transaction_timestamp() AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
                    )),
                    false
               )
          FROM candidate
         WHERE operation.tenant_id = candidate.tenant_id
           AND operation.id = candidate.id
        RETURNING operation.tenant_id,
                  operation.id,
                  operation.state,
                  operation.attempt,
                  operation.fencing_token,
                  operation.lease_expires_at,
                  operation.document
    )
    SELECT updated.tenant_id,
           updated.id,
           updated.state,
           updated.attempt,
           updated.fencing_token,
           updated.lease_expires_at,
           updated.document
      FROM updated;
END
$function$;

REVOKE ALL ON FUNCTION paas.claim_operation(text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.claim_operation(text, integer)
    TO matrix_paas_worker;

CREATE OR REPLACE FUNCTION paas.advance_operation(
    requested_operation_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_state text,
    requested_error jsonb,
    requested_next_attempt_at timestamptz,
    release_lease boolean
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    current_state text;
    current_worker_id text;
    current_fencing_token bigint;
    current_lease_expires_at timestamptz;
    current_next_attempt_at timestamptz;
    current_document jsonb;
    transition_allowed boolean;
    terminal boolean;
    next_document jsonb;
BEGIN
    effective_tenant_id := paas.current_tenant_id();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'valid transaction-local tenant context is required';
    END IF;
    IF requested_operation_id IS NULL
       OR requested_operation_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR expected_fencing_token IS NULL
       OR expected_fencing_token NOT BETWEEN 1 AND 9007199254740991
       OR release_lease IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'operation transition identity is invalid';
    END IF;

    SELECT operation.state,
           operation.lease_owner,
           operation.fencing_token,
           operation.lease_expires_at,
           operation.next_attempt_at,
           operation.document
      INTO current_state,
           current_worker_id,
           current_fencing_token,
           current_lease_expires_at,
           current_next_attempt_at,
           current_document
      FROM paas.operations AS operation
     WHERE operation.tenant_id = effective_tenant_id
       AND operation.id = requested_operation_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0002',
            MESSAGE = 'Operation not found in tenant scope';
    END IF;
    IF current_worker_id IS DISTINCT FROM requested_worker_id
       OR current_fencing_token <> expected_fencing_token
       OR current_lease_expires_at IS NULL
       OR current_lease_expires_at <= transaction_timestamp() THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'Operation lease or fencing token is stale';
    END IF;

    transition_allowed :=
        (current_state = 'ACCEPTED'
            AND requested_state IN ('PLANNING', 'FAILED', 'CANCELLED'))
        OR (current_state = 'PLANNING'
            AND requested_state IN ('QUEUED', 'FAILED', 'CANCELLED'))
        OR (current_state = 'QUEUED'
            AND requested_state IN ('EXECUTING', 'FAILED', 'CANCELLED'))
        OR (current_state = 'EXECUTING'
            AND requested_state IN (
                'VERIFYING', 'RECONCILING', 'FAILED', 'CANCELLED'
            ))
        OR (current_state = 'VERIFYING'
            AND requested_state IN ('SUCCEEDED', 'RECONCILING', 'FAILED'))
        OR (current_state = 'RECONCILING'
            AND requested_state IN (
                'EXECUTING', 'VERIFYING', 'FAILED', 'CANCELLED',
                'MANUAL_INTERVENTION'
            ));
    IF NOT transition_allowed THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'Operation state transition is invalid';
    END IF;

    terminal := requested_state IN (
        'SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION'
    );
    IF (requested_state IN ('FAILED', 'MANUAL_INTERVENTION')
            AND (requested_error IS NULL OR jsonb_typeof(requested_error) <> 'object'))
       OR (requested_state NOT IN ('FAILED', 'MANUAL_INTERVENTION')
            AND requested_error IS NOT NULL)
       OR (terminal AND NOT release_lease)
       OR (terminal AND requested_next_attempt_at IS NOT NULL)
       OR (NOT terminal AND NOT release_lease
            AND requested_next_attempt_at IS NOT NULL)
       OR (NOT terminal AND release_lease
            AND (requested_next_attempt_at IS NULL
                OR requested_next_attempt_at < transaction_timestamp())) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Operation transition completion fields are invalid';
    END IF;

    next_document := current_document - 'error' - 'terminalAt';
    next_document := jsonb_set(
        jsonb_set(
            next_document,
            '{state}',
            to_jsonb(requested_state),
            false
        ),
        '{updatedAt}',
        to_jsonb(to_char(
            transaction_timestamp() AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
        )),
        false
    );
    IF requested_error IS NOT NULL THEN
        next_document := jsonb_set(
            next_document,
            '{error}',
            requested_error,
            true
        );
    END IF;
    IF terminal THEN
        next_document := jsonb_set(
            next_document,
            '{terminalAt}',
            to_jsonb(to_char(
                transaction_timestamp() AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
            )),
            true
        );
    END IF;

    UPDATE paas.operations AS operation
       SET state = requested_state,
           next_attempt_at = CASE
                WHEN release_lease AND NOT terminal THEN requested_next_attempt_at
                ELSE current_next_attempt_at
           END,
           lease_owner = CASE WHEN release_lease THEN NULL ELSE current_worker_id END,
           lease_expires_at = CASE
                WHEN release_lease THEN NULL
                ELSE current_lease_expires_at
           END,
           error = requested_error,
           updated_at = transaction_timestamp(),
           terminal_at = CASE WHEN terminal THEN transaction_timestamp() ELSE NULL END,
           document = next_document
     WHERE operation.tenant_id = effective_tenant_id
       AND operation.id = requested_operation_id;

    RETURN next_document;
END
$function$;

REVOKE ALL ON FUNCTION paas.advance_operation(
    text, text, bigint, text, jsonb, timestamptz, boolean
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.advance_operation(
    text, text, bigint, text, jsonb, timestamptz, boolean
) TO matrix_paas_worker;

CREATE OR REPLACE FUNCTION paas.update_deployment_status(
    requested_deployment_id text,
    expected_resource_version bigint,
    expected_generation bigint,
    submitted_deployment jsonb
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    current_generation bigint;
    current_resource_version bigint;
    current_phase text;
    next_phase text;
    current_observed_generation bigint;
    next_observed_generation bigint;
    current_document jsonb;
    transition_allowed boolean;
BEGIN
    effective_tenant_id := paas.current_tenant_id();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'valid transaction-local tenant context is required';
    END IF;
    IF requested_deployment_id IS NULL
       OR requested_deployment_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR expected_resource_version IS NULL
       OR expected_resource_version NOT BETWEEN 1 AND 9007199254740991
       OR expected_generation IS NULL
       OR expected_generation NOT BETWEEN 1 AND 9007199254740991
       OR jsonb_typeof(submitted_deployment) <> 'object' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Deployment status update identity is invalid';
    END IF;

    SELECT deployment.generation,
           deployment.resource_version,
           deployment.document#>>'{status,phase}',
           CASE
                WHEN deployment.document#>>'{status,observedGeneration}'
                    ~ '^(0|[1-9][0-9]*)$'
                THEN (deployment.document#>>'{status,observedGeneration}')::bigint
                ELSE NULL
           END,
           deployment.document
      INTO current_generation,
           current_resource_version,
           current_phase,
           current_observed_generation,
           current_document
      FROM paas.deployments AS deployment
     WHERE deployment.tenant_id = effective_tenant_id
       AND deployment.id = requested_deployment_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0002',
            MESSAGE = 'Deployment not found in tenant scope';
    END IF;
    IF current_resource_version <> expected_resource_version
       OR current_generation <> expected_generation THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX409',
            MESSAGE = 'Deployment status resource version or generation conflict';
    END IF;
    IF current_observed_generation IS NULL
       OR current_resource_version = 9007199254740991
       OR submitted_deployment#>>'{metadata,id}' <> requested_deployment_id
       OR submitted_deployment#>>'{metadata,scope,kind}' <> 'TENANT'
       OR submitted_deployment#>>'{metadata,scope,tenantId}' <> effective_tenant_id
       OR submitted_deployment->>'generation' <> current_generation::text
       OR submitted_deployment->'spec' IS DISTINCT FROM current_document->'spec'
       OR submitted_deployment->'metadata' - ARRAY['resourceVersion', 'updatedAt']
            IS DISTINCT FROM
            current_document->'metadata' - ARRAY['resourceVersion', 'updatedAt']
       OR submitted_deployment#>>'{metadata,resourceVersion}'
            <> (current_resource_version + 1)::text
       OR (submitted_deployment#>>'{metadata,updatedAt}')::timestamptz
            <> transaction_timestamp()
       OR submitted_deployment#>>'{status,currentOperationId}'
            IS DISTINCT FROM current_document#>>'{status,currentOperationId}'
       OR submitted_deployment#>>'{status,observedGeneration}'
            !~ '^(0|[1-9][0-9]*)$' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Deployment status update attempted to change desired state or identity';
    END IF;

    next_phase := submitted_deployment#>>'{status,phase}';
    next_observed_generation :=
        (submitted_deployment#>>'{status,observedGeneration}')::bigint;
    transition_allowed := next_phase = current_phase
        OR (current_phase = 'PENDING'
            AND next_phase IN ('PLACING', 'STOPPING', 'FAILED'))
        OR (current_phase = 'PLACING'
            AND next_phase IN ('APPLYING', 'FAILED'))
        OR (current_phase = 'APPLYING'
            AND next_phase IN ('READY', 'DEGRADED', 'FAILED'))
        OR (current_phase = 'READY'
            AND next_phase IN ('DEGRADED', 'FAILED', 'STOPPING'))
        OR (current_phase = 'DEGRADED'
            AND next_phase IN ('READY', 'FAILED', 'STOPPING'))
        OR (current_phase = 'STOPPING'
            AND next_phase IN ('STOPPED', 'FAILED'));
    IF NOT transition_allowed
       OR next_observed_generation < current_observed_generation
       OR next_observed_generation > current_generation THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'Deployment status transition or observation generation is invalid';
    END IF;

    UPDATE paas.deployments AS deployment
       SET resource_version = current_resource_version + 1,
           document = submitted_deployment
     WHERE deployment.tenant_id = effective_tenant_id
       AND deployment.id = requested_deployment_id;
    RETURN current_resource_version + 1;
END
$function$;

REVOKE ALL ON FUNCTION paas.update_deployment_status(text, bigint, bigint, jsonb)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.update_deployment_status(text, bigint, bigint, jsonb)
    TO matrix_paas_worker;

CREATE OR REPLACE FUNCTION paas.transition_capacity_reservation(
    requested_reservation_id text,
    requested_action text,
    expected_resource_version bigint
)
RETURNS TABLE (
    claim_state text,
    claim_resource_version bigint,
    changed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    current_claim_id uuid;
    current_state text;
    current_lease_expires_at timestamptz;
    current_claim_version bigint;
    current_reservation_version bigint;
    next_state text;
BEGIN
    effective_tenant_id := paas.current_tenant_id();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'valid transaction-local tenant context is required';
    END IF;
    IF requested_reservation_id IS NULL
       OR requested_reservation_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'capacity reservation identity is invalid';
    END IF;
    IF requested_action NOT IN ('ACTIVATE', 'RELEASE', 'EXPIRE') THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'capacity reservation action is invalid';
    END IF;
    IF expected_resource_version IS NULL
       OR expected_resource_version NOT BETWEEN 1 AND 9007199254740991 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'capacity reservation resource version is invalid';
    END IF;

    SELECT claim.id,
           claim.state,
           claim.lease_expires_at,
           claim.resource_version,
           reservation.resource_version
      INTO current_claim_id,
           current_state,
           current_lease_expires_at,
           current_claim_version,
           current_reservation_version
      FROM paas.capacity_reservations AS reservation
      JOIN paas.capacity_claims AS claim
        ON claim.id = reservation.capacity_claim_id
     WHERE reservation.tenant_id = effective_tenant_id
       AND reservation.id = requested_reservation_id
     FOR UPDATE OF reservation, claim;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0002',
            MESSAGE = 'capacity reservation not found in tenant scope';
    END IF;
    IF current_claim_version <> current_reservation_version THEN
        RAISE EXCEPTION USING
            ERRCODE = 'XX001',
            MESSAGE = 'capacity reservation version invariant is broken';
    END IF;

    IF (requested_action = 'ACTIVATE' AND current_state = 'ACTIVE')
       OR (requested_action IN ('RELEASE', 'EXPIRE') AND current_state = 'RELEASED') THEN
        RETURN QUERY SELECT current_state, current_claim_version, false;
        RETURN;
    END IF;
    IF current_claim_version <> expected_resource_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'capacity reservation resource version conflict';
    END IF;
    IF current_claim_version = 9007199254740991 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22003',
            MESSAGE = 'capacity reservation resource version exhausted';
    END IF;

    CASE requested_action
        WHEN 'ACTIVATE' THEN
            IF current_state <> 'PENDING' THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    MESSAGE = 'only a pending capacity reservation can be activated';
            END IF;
            IF current_lease_expires_at <= transaction_timestamp() THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    MESSAGE = 'an expired capacity reservation cannot be activated';
            END IF;
            next_state := 'ACTIVE';
        WHEN 'RELEASE' THEN
            IF current_state NOT IN ('PENDING', 'ACTIVE') THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    MESSAGE = 'capacity reservation cannot be released from its current state';
            END IF;
            next_state := 'RELEASED';
        WHEN 'EXPIRE' THEN
            IF current_state <> 'PENDING' THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    MESSAGE = 'only a pending capacity reservation can expire';
            END IF;
            IF current_lease_expires_at > transaction_timestamp() THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000',
                    MESSAGE = 'a live capacity reservation cannot expire';
            END IF;
            next_state := 'RELEASED';
    END CASE;

    UPDATE paas.capacity_claims AS claim
       SET state = next_state,
           lease_expires_at = NULL,
           resource_version = claim.resource_version + 1,
           updated_at = transaction_timestamp()
     WHERE claim.id = current_claim_id
     RETURNING claim.resource_version INTO current_claim_version;

    UPDATE paas.capacity_reservations AS reservation
       SET resource_version = current_claim_version,
           updated_at = transaction_timestamp()
     WHERE reservation.tenant_id = effective_tenant_id
       AND reservation.id = requested_reservation_id;

    RETURN QUERY SELECT next_state, current_claim_version, true;
END
$function$;

REVOKE ALL ON FUNCTION paas.transition_capacity_reservation(text, text, bigint)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.transition_capacity_reservation(text, text, bigint)
    TO matrix_paas_worker;

REVOKE ALL ON ALL TABLES IN SCHEMA paas FROM PUBLIC;
GRANT SELECT, INSERT ON paas.applications TO matrix_paas_api;
GRANT SELECT, INSERT ON paas.configurations TO matrix_paas_api;
GRANT SELECT, INSERT ON paas.configuration_revisions TO matrix_paas_api;
GRANT SELECT, INSERT ON paas.application_revisions TO matrix_paas_api;
GRANT SELECT ON paas.placement_policies TO matrix_paas_api;
GRANT SELECT ON paas.deployments TO matrix_paas_api;
GRANT SELECT ON paas.deployment_generations TO matrix_paas_api;
GRANT SELECT, INSERT ON paas.operations TO matrix_paas_api;

GRANT SELECT ON paas.applications TO matrix_paas_worker;
GRANT SELECT ON paas.configurations TO matrix_paas_worker;
GRANT SELECT ON paas.configuration_revisions TO matrix_paas_worker;
GRANT SELECT ON paas.application_revisions TO matrix_paas_worker;
GRANT SELECT ON paas.placement_policies TO matrix_paas_worker;
GRANT SELECT ON paas.deployments TO matrix_paas_worker;
GRANT SELECT ON paas.deployment_generations TO matrix_paas_worker;
GRANT SELECT ON paas.operations TO matrix_paas_worker;
GRANT SELECT ON paas.execution_pools TO matrix_paas_worker;
GRANT SELECT ON paas.execution_targets TO matrix_paas_worker;
GRANT SELECT, UPDATE (lock_version)
    ON paas.execution_target_allocations TO matrix_paas_worker;
GRANT SELECT, INSERT ON paas.adapter_commands TO matrix_paas_worker;
GRANT SELECT, INSERT ON paas.adapter_receipts TO matrix_paas_worker;
GRANT SELECT, INSERT ON paas.deployment_observations TO matrix_paas_worker;
GRANT SELECT, INSERT ON paas.placement_decisions TO matrix_paas_worker;
GRANT SELECT, INSERT ON paas.capacity_claims TO matrix_paas_worker;
GRANT SELECT, INSERT ON paas.capacity_reservations TO matrix_paas_worker;

COMMIT;
