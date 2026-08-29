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
            AND COALESCE(current_setting('matrix.installation_id', true), '') = ''
        THEN current_setting('matrix.tenant_id', true)
        ELSE NULL
    END
$function$;

REVOKE ALL ON FUNCTION paas.current_tenant_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.current_tenant_id()
    TO matrix_paas_api, matrix_paas_worker;

CREATE OR REPLACE FUNCTION paas.current_installation_id()
RETURNS text
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT CASE
        WHEN current_setting('matrix.installation_id', true)
            COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND COALESCE(current_setting('matrix.tenant_id', true), '') = ''
        THEN current_setting('matrix.installation_id', true)
        ELSE NULL
    END
$function$;

REVOKE ALL ON FUNCTION paas.current_installation_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.current_installation_id()
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

-- Change only authority metadata; retained tenant Operations and outbox facts
-- keep their documents and identities. Existing tenant foreign keys remain
-- tenant-only and cannot reference an installation Operation.
DO $matrix_operation_authority_upgrade$
BEGIN
    IF to_regclass('paas.operations') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'paas' AND table_name = 'operations'
           AND column_name = 'installation_id'
    ) THEN
        ALTER TABLE paas.audit_outbox DROP CONSTRAINT audit_outbox_operation_fk;
        ALTER TABLE paas.deployment_generations DROP CONSTRAINT IF EXISTS deployment_generations_operation_fk;
        IF to_regclass('paas.adapter_commands') IS NOT NULL THEN
            ALTER TABLE paas.adapter_commands DROP CONSTRAINT adapter_commands_operation_fk;
        END IF;
        ALTER TABLE paas.operations
            DROP CONSTRAINT operations_pkey,
            DROP CONSTRAINT operations_idempotency_uq,
            ALTER COLUMN tenant_id DROP NOT NULL,
            ADD COLUMN installation_id text COLLATE "C",
            ADD COLUMN authority_key text COLLATE "C" GENERATED ALWAYS AS (
                CASE WHEN installation_id IS NOT NULL THEN 'installation:' || installation_id
                     ELSE 'tenant:' || tenant_id END
            ) STORED,
            ADD PRIMARY KEY (authority_key, id),
            ADD CONSTRAINT operations_tenant_identity_uq UNIQUE (tenant_id, id),
            ADD CONSTRAINT operations_idempotency_uq UNIQUE (authority_key, idempotency_fingerprint);
        -- ACCESS EXCLUSIVE remains held through COMMIT. Validate retained FKs
        -- as owner, then restore forced RLS in the shared policy section below.
        ALTER TABLE paas.operations NO FORCE ROW LEVEL SECURITY;
        ALTER TABLE paas.audit_outbox
            DROP CONSTRAINT audit_outbox_pkey,
            ALTER COLUMN tenant_id DROP NOT NULL,
            ADD COLUMN installation_id text COLLATE "C",
            ADD COLUMN authority_key text COLLATE "C" GENERATED ALWAYS AS (
                CASE WHEN installation_id IS NOT NULL THEN 'installation:' || installation_id
                     ELSE 'tenant:' || tenant_id END
            ) STORED,
            ADD PRIMARY KEY (authority_key, event_id),
            ADD CONSTRAINT audit_outbox_operation_fk FOREIGN KEY (authority_key, operation_id)
                REFERENCES paas.operations (authority_key, id);
        IF to_regclass('paas.adapter_commands') IS NOT NULL THEN
            ALTER TABLE paas.adapter_commands ADD CONSTRAINT adapter_commands_operation_fk
                FOREIGN KEY (tenant_id, operation_id) REFERENCES paas.operations (tenant_id, id);
        END IF;
    END IF;
END
$matrix_operation_authority_upgrade$;

CREATE TABLE IF NOT EXISTS paas.operations (
    tenant_id text COLLATE "C",
    installation_id text COLLATE "C",
    authority_key text COLLATE "C" GENERATED ALWAYS AS (
        CASE WHEN installation_id IS NOT NULL THEN 'installation:' || installation_id
             ELSE 'tenant:' || tenant_id END
    ) STORED,
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
    PRIMARY KEY (authority_key, id),
    CONSTRAINT operations_tenant_identity_uq UNIQUE (tenant_id, id),
    CONSTRAINT operations_idempotency_uq UNIQUE (authority_key, idempotency_fingerprint),
    CONSTRAINT operations_digests_valid CHECK (
        idempotency_fingerprint COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND request_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
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
    )
);

CREATE TABLE IF NOT EXISTS paas.audit_outbox (
    tenant_id text COLLATE "C",
    installation_id text COLLATE "C",
    authority_key text COLLATE "C" GENERATED ALWAYS AS (
        CASE WHEN installation_id IS NOT NULL THEN 'installation:' || installation_id
             ELSE 'tenant:' || tenant_id END
    ) STORED,
    event_id text COLLATE "C" NOT NULL,
    operation_id text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL,
    available_at timestamptz(6) NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    lease_owner text COLLATE "C",
    lease_expires_at timestamptz(6),
    fencing_token bigint NOT NULL DEFAULT 0,
    last_error_code text COLLATE "C",
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    delivered_at timestamptz(6),
    document jsonb NOT NULL,
    PRIMARY KEY (authority_key, event_id),
    CONSTRAINT audit_outbox_operation_fk FOREIGN KEY (authority_key, operation_id)
        REFERENCES paas.operations (authority_key, id),
    CONSTRAINT audit_outbox_status_valid CHECK (
        status IN ('PENDING', 'LEASED', 'RETRY', 'DELIVERED', 'DEAD_LETTER')
    ),
    CONSTRAINT audit_outbox_attempt_valid CHECK (
        attempts BETWEEN 0 AND 100
        AND fencing_token BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT audit_outbox_lease_valid CHECK (
        (status = 'LEASED' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (status <> 'LEASED' AND lease_owner IS NULL AND lease_expires_at IS NULL)
    ),
    CONSTRAINT audit_outbox_terminal_valid CHECK (
        (status = 'DELIVERED' AND delivered_at IS NOT NULL AND last_error_code IS NULL)
        OR (status = 'DEAD_LETTER' AND delivered_at IS NULL AND last_error_code IS NOT NULL)
        OR (status NOT IN ('DELIVERED', 'DEAD_LETTER')
            AND delivered_at IS NULL AND last_error_code IS NULL)
    ),
    CONSTRAINT audit_outbox_time_valid CHECK (
        available_at >= created_at
        AND updated_at >= created_at
        AND (delivered_at IS NULL OR delivered_at BETWEEN created_at AND updated_at)
    )
);

ALTER TABLE paas.operations
    DROP CONSTRAINT IF EXISTS operations_action_valid,
    DROP CONSTRAINT IF EXISTS operations_ids_valid,
    DROP CONSTRAINT IF EXISTS operations_document_identity;
ALTER TABLE paas.operations
    ADD CONSTRAINT operations_action_valid CHECK (
        (installation_id IS NULL AND action IN (
            'CREATE_APPLICATION', 'CREATE_CONFIGURATION', 'CREATE_CONFIGURATION_REVISION',
            'CREATE_APPLICATION_REVISION', 'DEPLOY', 'UPDATE', 'STOP', 'ROLLBACK'
        )) OR (installation_id IS NOT NULL AND action IN (
            'CREATE_EXECUTION_POOL', 'REGISTER_EXECUTION_TARGET'
        ) AND state = 'SUCCEEDED' AND lease_owner IS NULL AND attempt = 1)
    ),
    ADD CONSTRAINT operations_ids_valid CHECK (
        (tenant_id IS NULL) <> (installation_id IS NULL)
        AND (tenant_id IS NULL OR tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
        AND (installation_id IS NULL OR installation_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND target_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND (lease_owner IS NULL OR lease_owner COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
    ),
    ADD CONSTRAINT operations_document_identity CHECK ((
        document->>'apiVersion' = 'paas.matrix.xiak.com/v1'
        AND document->>'kind' = 'Operation'
        AND document->>'id' = id
        AND ((tenant_id IS NOT NULL
            AND document#>>'{scope,kind}' = 'TENANT'
            AND document#>>'{scope,tenantId}' = tenant_id
            AND NOT (document ? 'installationId'))
          OR (installation_id IS NOT NULL
            AND document#>>'{scope,kind}' = 'PLATFORM'
            AND NOT (document#>'{scope}' ? 'tenantId')
            AND document->>'installationId' = installation_id
            AND document#>>'{requestedBy,type}' = 'USER'
            AND target_kind = CASE action
                WHEN 'CREATE_EXECUTION_POOL' THEN 'ExecutionPool'
                WHEN 'REGISTER_EXECUTION_TARGET' THEN 'ExecutionTarget' END))
        AND document->>'action' = action
        AND document#>>'{target,kind}' = target_kind
        AND document#>>'{target,id}' = target_id
        AND document->>'idempotencyFingerprint' = idempotency_fingerprint
        AND document->>'requestDigest' = request_digest
        AND document->>'state' = state
        AND document->'error' IS NOT DISTINCT FROM error
        AND (document->>'createdAt')::timestamptz = created_at
        AND (document->>'updatedAt')::timestamptz = updated_at
        AND ((terminal_at IS NULL AND NOT (document ? 'terminalAt'))
             OR (document->>'terminalAt')::timestamptz = terminal_at)
        AND CASE WHEN document->>'attempt' ~ '^[1-9][0-9]*$'
            THEN (document->>'attempt')::numeric = attempt ELSE false END
    ) IS TRUE);

ALTER TABLE paas.audit_outbox
    DROP CONSTRAINT IF EXISTS audit_outbox_ids_valid,
    DROP CONSTRAINT IF EXISTS audit_outbox_document_identity;
ALTER TABLE paas.audit_outbox
    ADD CONSTRAINT audit_outbox_ids_valid CHECK (
        (tenant_id IS NULL) <> (installation_id IS NULL)
        AND (tenant_id IS NULL OR tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
        AND (installation_id IS NULL OR installation_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
        AND event_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND operation_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND (lease_owner IS NULL OR lease_owner COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
        AND (last_error_code IS NULL OR last_error_code COLLATE "C" ~ '^[A-Z][A-Z0-9_]{0,63}$')
    ),
    ADD CONSTRAINT audit_outbox_document_identity CHECK ((
        document->>'schemaVersion' = 'v1'
        AND document->>'eventId' = event_id
        AND (document->>'tenantId') IS NOT DISTINCT FROM tenant_id
        AND (document->>'installationId') IS NOT DISTINCT FROM installation_id
        AND (document ? 'tenantId') = (tenant_id IS NOT NULL)
        AND (document ? 'installationId') = (installation_id IS NOT NULL)
        AND document->>'operationId' = operation_id
        AND document->>'requestDigest' COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND (document->>'occurredAt')::timestamptz = created_at
    ) IS TRUE);

DROP INDEX IF EXISTS paas.audit_outbox_claim_idx;
CREATE INDEX audit_outbox_claim_idx
    ON paas.audit_outbox (available_at, created_at, authority_key, event_id)
    WHERE status IN ('PENDING', 'RETRY', 'LEASED');

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

-- The built-in local target and admitted nodes share one installation-owned
-- pool. Only an admitted node carries a protected binding and certificate
-- fingerprint; the local target remains worker-observed and cannot be claimed
-- by the installation admission API.
ALTER TABLE paas.execution_pools ADD COLUMN IF NOT EXISTS installation_id text COLLATE "C";
ALTER TABLE paas.execution_targets
    ADD COLUMN IF NOT EXISTS installation_id text COLLATE "C",
    ADD COLUMN IF NOT EXISTS binding_ref text COLLATE "C",
    ADD COLUMN IF NOT EXISTS identity_fingerprint text COLLATE "C";
CREATE UNIQUE INDEX IF NOT EXISTS execution_pools_installation_identity_uq
    ON paas.execution_pools (installation_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS execution_targets_binding_uq
    ON paas.execution_targets (installation_id, binding_ref);
CREATE UNIQUE INDEX IF NOT EXISTS execution_targets_fingerprint_uq
    ON paas.execution_targets (installation_id, identity_fingerprint);
ALTER TABLE paas.execution_pools DROP CONSTRAINT IF EXISTS execution_pools_installation_valid;
ALTER TABLE paas.execution_pools ADD CONSTRAINT execution_pools_installation_valid CHECK (
    installation_id IS NULL OR installation_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
);
ALTER TABLE paas.execution_targets
    DROP CONSTRAINT IF EXISTS execution_targets_installation_identity_valid,
    DROP CONSTRAINT IF EXISTS execution_targets_installation_pool_fk;
ALTER TABLE paas.execution_targets
    ADD CONSTRAINT execution_targets_installation_pool_fk FOREIGN KEY (installation_id, execution_pool_id)
        REFERENCES paas.execution_pools (installation_id, id),
    ADD CONSTRAINT execution_targets_installation_identity_valid CHECK ((
        (installation_id IS NULL AND binding_ref IS NULL AND identity_fingerprint IS NULL
            AND document#>>'{spec,infrastructureAdapter,name}' = 'localmachine')
        OR (installation_id IS NOT NULL AND binding_ref IS NULL AND identity_fingerprint IS NULL
            AND installation_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND id = 'execution-target-local'
            AND execution_pool_id = 'execution-pool-local'
            AND document#>>'{metadata,name}' = 'local'
            AND document#>>'{metadata,labels,matrix-profile}' = 'local-compose'
            AND document#>>'{metadata,labels,matrix-machine-fingerprint}' COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
            AND document#>>'{spec,infrastructureAdapter,name}' = 'localmachine')
        OR (installation_id IS NOT NULL AND binding_ref IS NOT NULL AND identity_fingerprint IS NOT NULL
            AND installation_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND binding_ref COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND identity_fingerprint COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
            AND document#>>'{spec,infrastructureAdapter,name}' <> 'localmachine'
            AND document#>>'{metadata,labels,matrix-machine-fingerprint}' = identity_fingerprint)
    ) IS TRUE);

ALTER TABLE paas.execution_pools ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.execution_pools FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.execution_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.execution_targets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS installation_read ON paas.execution_pools;
DROP POLICY IF EXISTS installation_read ON paas.execution_targets;
DROP POLICY IF EXISTS placement_read ON paas.execution_pools;
DROP POLICY IF EXISTS placement_read ON paas.execution_targets;
CREATE POLICY installation_read ON paas.execution_pools FOR SELECT TO matrix_paas_api
    USING (installation_id = paas.current_installation_id());
CREATE POLICY installation_read ON paas.execution_targets FOR SELECT TO matrix_paas_api
    USING (installation_id = paas.current_installation_id());
CREATE POLICY placement_read ON paas.execution_pools FOR SELECT TO matrix_paas_worker USING (true);
CREATE POLICY placement_read ON paas.execution_targets FOR SELECT TO matrix_paas_worker USING (true);

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
ALTER TABLE paas.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.audit_outbox FORCE ROW LEVEL SECURITY;
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

DROP POLICY IF EXISTS tenant_isolation ON paas.operations;
DROP POLICY IF EXISTS tenant_isolation ON paas.audit_outbox;
DO $matrix_operation_authority_policies$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['operations', 'audit_outbox']
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_policies
             WHERE schemaname = 'paas' AND tablename = table_name
               AND policyname = 'authority_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY authority_isolation ON paas.%I '
                'USING (tenant_id = paas.current_tenant_id() OR installation_id = paas.current_installation_id()) '
                'WITH CHECK (tenant_id = paas.current_tenant_id() OR installation_id = paas.current_installation_id())',
                table_name
            );
        END IF;
    END LOOP;
END
$matrix_operation_authority_policies$;

CREATE OR REPLACE FUNCTION paas.append_audit_outbox(
    submitted_operation jsonb,
    submitted_audit_event jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    effective_installation_id text;
    effective_now timestamptz(6);
    expected_action text;
    expected_result text;
BEGIN
    effective_tenant_id := paas.current_tenant_id();
    effective_installation_id := paas.current_installation_id();
    effective_now := transaction_timestamp();
    IF effective_tenant_id IS NULL AND effective_installation_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'exactly one transaction-local authority context is required';
    END IF;
    IF jsonb_typeof(submitted_operation) IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_audit_event) IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_audit_event->'actor') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_audit_event->'target') IS DISTINCT FROM 'object'
       OR NOT (submitted_audit_event ?& ARRAY[
            'schemaVersion', 'eventId', 'actor',
            'iamDecisionId', 'action', 'target', 'operationId',
            'requestDigest', 'result', 'requestId', 'occurredAt'
       ])
       OR NOT ((submitted_audit_event->'actor') ?& ARRAY['type', 'id'])
       OR NOT ((submitted_audit_event->'target') ?& ARRAY['kind', 'id'])
       OR (submitted_audit_event - ARRAY[
            'schemaVersion', 'eventId', 'tenantId', 'installationId', 'actor',
            'iamDecisionId', 'action', 'target', 'operationId',
            'requestDigest', 'result', 'requestId', 'auditId',
            'traceparent', 'occurredAt'
       ]) <> '{}'::jsonb
       OR ((submitted_audit_event->'actor') - ARRAY['type', 'id'])
            <> '{}'::jsonb
       OR ((submitted_audit_event->'target') - ARRAY['kind', 'id'])
            <> '{}'::jsonb THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Audit event contract is invalid';
    END IF;

    expected_action := CASE submitted_operation->>'action'
        WHEN 'CREATE_APPLICATION' THEN 'paas.application.created'
        WHEN 'CREATE_CONFIGURATION' THEN 'paas.configuration.created'
        WHEN 'CREATE_CONFIGURATION_REVISION'
            THEN 'paas.configuration-revision.created'
        WHEN 'CREATE_APPLICATION_REVISION'
            THEN 'paas.application-revision.created'
        WHEN 'DEPLOY' THEN 'paas.deployment.created'
        WHEN 'UPDATE' THEN 'paas.deployment.updated'
        WHEN 'STOP' THEN 'paas.deployment.stopped'
        WHEN 'ROLLBACK' THEN 'paas.deployment.rolled-back'
        WHEN 'CREATE_EXECUTION_POOL' THEN 'paas.execution-pool.created'
        WHEN 'REGISTER_EXECUTION_TARGET' THEN 'paas.execution-target.registered'
        ELSE NULL
    END;
    expected_result := CASE
        WHEN submitted_operation->>'action' IN (
            'CREATE_APPLICATION',
            'CREATE_CONFIGURATION',
            'CREATE_CONFIGURATION_REVISION',
            'CREATE_APPLICATION_REVISION',
            'CREATE_EXECUTION_POOL',
            'REGISTER_EXECUTION_TARGET'
        ) THEN 'SUCCEEDED'
        ELSE 'ACCEPTED'
    END;
    IF expected_action IS NULL
       OR submitted_audit_event->>'schemaVersion' IS DISTINCT FROM 'v1'
       OR COALESCE(submitted_audit_event->>'eventId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_audit_event->>'tenantId' IS DISTINCT FROM effective_tenant_id
       OR submitted_audit_event->>'installationId' IS DISTINCT FROM effective_installation_id
       OR (submitted_audit_event ? 'tenantId') <> (effective_tenant_id IS NOT NULL)
       OR (submitted_audit_event ? 'installationId') <> (effective_installation_id IS NOT NULL)
       OR ((effective_installation_id IS NOT NULL) <> (submitted_operation->>'action' IN (
            'CREATE_EXECUTION_POOL', 'REGISTER_EXECUTION_TARGET'
       )))
       OR (effective_installation_id IS NOT NULL
            AND submitted_audit_event#>>'{actor,type}' IS DISTINCT FROM 'USER')
       OR COALESCE(submitted_audit_event#>>'{actor,id}', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_audit_event#>>'{actor,type}' NOT IN (
            'USER', 'SERVICE_ACCOUNT', 'AGENT', 'SYSTEM_USER'
       )
       OR submitted_audit_event->'actor'
            IS DISTINCT FROM submitted_operation->'requestedBy'
       OR COALESCE(submitted_audit_event->>'iamDecisionId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_audit_event->>'action' IS DISTINCT FROM expected_action
       OR submitted_audit_event->'target'
            IS DISTINCT FROM submitted_operation->'target'
       OR submitted_audit_event->>'operationId' <> submitted_operation->>'id'
       OR submitted_audit_event->>'requestDigest'
            <> submitted_operation->>'requestDigest'
       OR submitted_audit_event->>'requestDigest' COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR submitted_audit_event->>'result' IS DISTINCT FROM expected_result
       OR COALESCE(submitted_audit_event->>'requestId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR (submitted_audit_event ? 'auditId'
            AND COALESCE(submitted_audit_event->>'auditId', '') COLLATE "C"
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
       OR (submitted_audit_event ? 'traceparent'
            AND (jsonb_typeof(submitted_audit_event->'traceparent') <> 'string'
                OR octet_length(submitted_audit_event->>'traceparent') > 55))
       OR (submitted_audit_event->>'occurredAt')::timestamptz <> effective_now
       OR (submitted_operation->>'createdAt')::timestamptz <> effective_now THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Audit event identity or correlation is invalid';
    END IF;

    INSERT INTO paas.audit_outbox (
        tenant_id,
        installation_id,
        event_id,
        operation_id,
        status,
        available_at,
        attempts,
        fencing_token,
        created_at,
        updated_at,
        document
    ) VALUES (
        effective_tenant_id,
        effective_installation_id,
        submitted_audit_event->>'eventId',
        submitted_operation->>'id',
        'PENDING',
        effective_now,
        0,
        0,
        effective_now,
        effective_now,
        submitted_audit_event
    );
END
$function$;

REVOKE ALL ON FUNCTION paas.append_audit_outbox(jsonb, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION paas.append_audit_outbox(jsonb, jsonb)
    FROM matrix_paas_api, matrix_paas_worker;

CREATE OR REPLACE FUNCTION paas.store_execution_pool_observation(
    expected_resource_version bigint, submitted_pool jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    current_pool paas.execution_pools%ROWTYPE;
    effective_installation_id text := paas.current_installation_id();
    total_count bigint;
    maximum_ready_count bigint;
    degraded_count bigint;
    ready_count bigint;
    next_version bigint;
BEGIN
    IF effective_installation_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'installation context is required';
    END IF;
    SELECT * INTO current_pool FROM paas.execution_pools
     WHERE installation_id = effective_installation_id AND id = submitted_pool#>>'{metadata,id}' FOR UPDATE;
    IF NOT FOUND OR current_pool.resource_version IS DISTINCT FROM expected_resource_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'execution pool changed concurrently';
    END IF;
    SELECT count(*), count(*) FILTER (
        WHERE document#>>'{status,health}' = 'READY' AND document#>>'{spec,desiredState}' = 'ACTIVE'
          AND (document#>>'{status,observedAt}')::timestamptz > transaction_timestamp() - CASE
              WHEN binding_ref IS NULL THEN interval '5 minutes' ELSE interval '15 seconds' END
          AND (document#>>'{status,observedAt}')::timestamptz <= transaction_timestamp() + interval '2 seconds'
    ), count(*) FILTER (
        WHERE document#>>'{status,health}' = 'DEGRADED'
          AND (document#>>'{status,observedAt}')::timestamptz > transaction_timestamp() - CASE
              WHEN binding_ref IS NULL THEN interval '5 minutes' ELSE interval '15 seconds' END
          AND (document#>>'{status,observedAt}')::timestamptz <= transaction_timestamp() + interval '2 seconds'
    ) INTO total_count, maximum_ready_count, degraded_count FROM paas.execution_targets
     WHERE installation_id = effective_installation_id AND execution_pool_id = current_pool.id;
    ready_count := (submitted_pool#>>'{status,readyExecutionTargetCount}')::bigint;
    next_version := expected_resource_version + CASE
        WHEN ((current_pool.document->'status') - 'observedAt') IS DISTINCT FROM ((submitted_pool->'status') - 'observedAt') THEN 1 ELSE 0 END;
    IF NOT ((
        (((current_pool.document #- '{metadata,resourceVersion}') #- '{metadata,updatedAt}') - 'status')
            = (((submitted_pool #- '{metadata,resourceVersion}') #- '{metadata,updatedAt}') - 'status')
        AND submitted_pool#>>'{metadata,resourceVersion}' = next_version::text
        AND (submitted_pool#>>'{metadata,updatedAt}')::timestamptz = transaction_timestamp()
        AND (submitted_pool#>>'{status,observedAt}')::timestamptz = transaction_timestamp()
        AND submitted_pool#>>'{status,executionTargetCount}' = total_count::text
        AND ready_count BETWEEN 0 AND maximum_ready_count
        AND submitted_pool#>>'{status,phase}' = CASE WHEN ready_count = total_count THEN 'READY'
            WHEN ready_count > 0 OR degraded_count > 0 THEN 'DEGRADED' ELSE 'UNAVAILABLE' END
        AND ((submitted_pool->'status') - ARRAY['phase','executionTargetCount','readyExecutionTargetCount','observedAt']) = '{}'::jsonb
    ) IS TRUE) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'execution pool observation cannot change desired authority';
    END IF;
    UPDATE paas.execution_pools SET resource_version = next_version, document = submitted_pool WHERE id = current_pool.id;
END
$function$;
REVOKE ALL ON FUNCTION paas.store_execution_pool_observation(bigint, jsonb) FROM PUBLIC, matrix_paas_api, matrix_paas_worker;

CREATE OR REPLACE FUNCTION paas.admit_execution_resource(
    submitted_resource jsonb, submitted_operation jsonb, submitted_audit_event jsonb,
    submitted_binding_ref text, submitted_identity_fingerprint text,
    expected_pool_version bigint, submitted_pool jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_installation_id text := paas.current_installation_id();
    resource_kind text := submitted_resource->>'kind';
    resource_id text := submitted_resource#>>'{metadata,id}';
    expected_action text;
BEGIN
    IF effective_installation_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'installation context is required';
    END IF;
    expected_action := CASE resource_kind WHEN 'ExecutionPool' THEN 'CREATE_EXECUTION_POOL'
        WHEN 'ExecutionTarget' THEN 'REGISTER_EXECUTION_TARGET' END;
    IF NOT ((
        expected_action IS NOT NULL
        AND jsonb_typeof(submitted_resource) = 'object'
        AND jsonb_typeof(submitted_operation) = 'object'
        AND submitted_resource->>'apiVersion' = 'paas.matrix.xiak.com/v1'
        AND resource_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND submitted_resource#>>'{metadata,scope,kind}' = 'PLATFORM'
        AND NOT (submitted_resource#>'{metadata,scope}' ? 'tenantId')
        AND submitted_resource#>>'{metadata,resourceVersion}' = '1'
        AND (submitted_resource#>>'{metadata,createdAt}')::timestamptz = transaction_timestamp()
        AND (submitted_resource#>>'{metadata,updatedAt}')::timestamptz = transaction_timestamp()
        AND submitted_operation->>'installationId' = effective_installation_id
        AND submitted_operation->>'action' = expected_action
        AND submitted_operation#>>'{target,kind}' = resource_kind
        AND submitted_operation#>>'{target,id}' = resource_id
        AND submitted_operation->>'state' = 'SUCCEEDED'
        AND submitted_operation->>'attempt' = '1'
        AND NOT (submitted_operation ? 'error')
        AND (submitted_operation->>'createdAt')::timestamptz = transaction_timestamp()
        AND (submitted_operation->>'updatedAt')::timestamptz = transaction_timestamp()
        AND (submitted_operation->>'terminalAt')::timestamptz = transaction_timestamp()
    ) IS TRUE) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'execution admission identity or operation is invalid';
    END IF;
    IF resource_kind = 'ExecutionPool' THEN
        IF resource_id = 'execution-pool-local'
           OR submitted_binding_ref IS NOT NULL OR submitted_identity_fingerprint IS NOT NULL
           OR expected_pool_version IS NOT NULL OR submitted_pool IS NOT NULL
           OR submitted_resource->'status' IS DISTINCT FROM jsonb_build_object(
               'phase', 'UNAVAILABLE', 'executionTargetCount', 0, 'readyExecutionTargetCount', 0,
               'observedAt', submitted_resource#>'{metadata,createdAt}') THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'new execution pool must be empty';
        END IF;
        INSERT INTO paas.execution_pools (id, installation_id, resource_version, document)
            VALUES (resource_id, effective_installation_id, 1, submitted_resource);
    ELSE
        -- Pool locking serializes registration and observation updates. Global
        -- unique target IDs preserve existing placement FKs; installation and
        -- binding constraints prevent borrowing another installation's node.
        PERFORM 1 FROM paas.execution_pools WHERE installation_id = effective_installation_id
            AND id = submitted_resource#>>'{spec,executionPoolId}' FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'MX404', MESSAGE = 'execution pool is not registered';
        END IF;
        IF resource_id = 'execution-target-local' OR NOT ((
            submitted_binding_ref IS NOT NULL AND submitted_identity_fingerprint IS NOT NULL
            AND submitted_resource#>>'{spec,desiredState}' = 'ACTIVE'
            AND submitted_resource#>>'{status,health}' = 'READY'
            AND submitted_resource#>>'{metadata,labels,matrix-machine-fingerprint}' = submitted_identity_fingerprint
            AND (submitted_resource#>>'{status,observedAt}')::timestamptz > transaction_timestamp() - interval '15 seconds'
            AND (submitted_resource#>>'{status,observedAt}')::timestamptz <= transaction_timestamp() + interval '2 seconds'
            AND submitted_pool#>>'{metadata,id}' = submitted_resource#>>'{spec,executionPoolId}'
        ) IS TRUE) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'node registration requires a fresh identity-bound observation';
        END IF;
        IF (SELECT count(*) FROM paas.execution_targets
             WHERE installation_id = effective_installation_id AND binding_ref IS NOT NULL) >= 128 THEN
            RAISE EXCEPTION USING ERRCODE = 'MX409', MESSAGE = 'execution target admission limit reached';
        END IF;
        INSERT INTO paas.execution_targets (id, installation_id, execution_pool_id, binding_ref, identity_fingerprint, resource_version, document)
            VALUES (resource_id, effective_installation_id, submitted_resource#>>'{spec,executionPoolId}',
                submitted_binding_ref, submitted_identity_fingerprint, 1, submitted_resource);
        INSERT INTO paas.execution_target_allocations (execution_target_id) VALUES (resource_id);
        PERFORM paas.store_execution_pool_observation(expected_pool_version, submitted_pool);
    END IF;
    INSERT INTO paas.operations (installation_id, id, action, target_kind, target_id, idempotency_fingerprint,
        request_digest, state, attempt, next_attempt_at, fencing_token, created_at, updated_at, terminal_at, document)
        VALUES (effective_installation_id, submitted_operation->>'id', expected_action, resource_kind, resource_id,
            submitted_operation->>'idempotencyFingerprint', submitted_operation->>'requestDigest', 'SUCCEEDED', 1,
            transaction_timestamp(), 0, transaction_timestamp(), transaction_timestamp(), transaction_timestamp(), submitted_operation);
    PERFORM paas.append_audit_outbox(submitted_operation, submitted_audit_event);
END
$function$;
REVOKE ALL ON FUNCTION paas.admit_execution_resource(jsonb,jsonb,jsonb,text,text,bigint,jsonb) FROM PUBLIC, matrix_paas_worker;
GRANT EXECUTE ON FUNCTION paas.admit_execution_resource(jsonb,jsonb,jsonb,text,text,bigint,jsonb) TO matrix_paas_api;

CREATE OR REPLACE FUNCTION paas.refresh_execution_target(
    expected_target_version bigint, submitted_target jsonb,
    expected_pool_version bigint, submitted_pool jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_installation_id text := paas.current_installation_id();
    current_target paas.execution_targets%ROWTYPE;
    next_version bigint;
BEGIN
    IF effective_installation_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'installation context is required';
    END IF;
    PERFORM 1 FROM paas.execution_pools WHERE installation_id = effective_installation_id
        AND id = submitted_pool#>>'{metadata,id}' FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MX404', MESSAGE = 'execution pool is not registered';
    END IF;
    SELECT * INTO current_target FROM paas.execution_targets
        WHERE installation_id = effective_installation_id AND id = submitted_target#>>'{metadata,id}' FOR UPDATE;
    IF NOT FOUND OR current_target.resource_version IS DISTINCT FROM expected_target_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'execution target changed concurrently';
    END IF;
    next_version := expected_target_version + CASE
        WHEN ((current_target.document->'status') - ARRAY['observedAt','usage'])
            IS DISTINCT FROM ((submitted_target->'status') - ARRAY['observedAt','usage']) THEN 1 ELSE 0 END;
    IF NOT ((
        (((current_target.document #- '{metadata,resourceVersion}') #- '{metadata,updatedAt}') - 'status')
            = (((submitted_target #- '{metadata,resourceVersion}') #- '{metadata,updatedAt}') - 'status')
        AND submitted_target#>>'{metadata,resourceVersion}' = next_version::text
        AND (submitted_target#>>'{metadata,updatedAt}')::timestamptz = transaction_timestamp()
        AND current_target.execution_pool_id = submitted_pool#>>'{metadata,id}'
        AND (submitted_target#>>'{status,observedAt}')::timestamptz >= (current_target.document#>>'{status,observedAt}')::timestamptz
        AND (submitted_target#>>'{status,observedAt}')::timestamptz <= transaction_timestamp() + interval '2 seconds'
        AND (submitted_target#>>'{status,health}' = 'UNAVAILABLE'
             OR (submitted_target#>>'{status,observedAt}')::timestamptz > transaction_timestamp() - interval '15 seconds')
    ) IS TRUE) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'node refresh cannot change desired authority or identity';
    END IF;
    UPDATE paas.execution_targets SET resource_version = next_version, document = submitted_target WHERE id = current_target.id;
    PERFORM paas.store_execution_pool_observation(expected_pool_version, submitted_pool);
END
$function$;
REVOKE ALL ON FUNCTION paas.refresh_execution_target(bigint,jsonb,bigint,jsonb) FROM PUBLIC, matrix_paas_worker;
GRANT EXECUTE ON FUNCTION paas.refresh_execution_target(bigint,jsonb,bigint,jsonb) TO matrix_paas_api;

CREATE OR REPLACE FUNCTION paas.create_apphosting_resource(
    submitted_resource jsonb,
    submitted_operation jsonb,
    submitted_audit_event jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    effective_now timestamptz(6);
    resource_kind text;
    resource_id text;
    operation_id text;
    expected_operation_action text;
BEGIN
    effective_tenant_id := paas.current_tenant_id();
    effective_now := transaction_timestamp();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'valid transaction-local tenant context is required';
    END IF;
    IF jsonb_typeof(submitted_resource) <> 'object'
       OR jsonb_typeof(submitted_operation) <> 'object'
       OR jsonb_typeof(submitted_audit_event) <> 'object' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'resource submission documents must be objects';
    END IF;

    resource_kind := submitted_resource->>'kind';
    resource_id := submitted_resource#>>'{metadata,id}';
    operation_id := submitted_operation->>'id';
    expected_operation_action := CASE resource_kind
        WHEN 'Application' THEN 'CREATE_APPLICATION'
        WHEN 'Configuration' THEN 'CREATE_CONFIGURATION'
        WHEN 'ConfigurationRevision' THEN 'CREATE_CONFIGURATION_REVISION'
        WHEN 'ApplicationRevision' THEN 'CREATE_APPLICATION_REVISION'
        ELSE NULL
    END;
    IF submitted_resource->>'apiVersion' <> 'paas.matrix.xiak.com/v1'
       OR expected_operation_action IS NULL
       OR COALESCE(resource_id, '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_resource#>>'{metadata,scope,kind}' <> 'TENANT'
       OR submitted_resource#>>'{metadata,scope,tenantId}' <> effective_tenant_id
       OR submitted_resource#>>'{metadata,resourceVersion}' <> '1'
       OR (submitted_resource#>>'{metadata,createdAt}')::timestamptz <> effective_now
       OR (submitted_resource#>>'{metadata,updatedAt}')::timestamptz <> effective_now
       OR COALESCE(operation_id, '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_operation->>'apiVersion' <> 'paas.matrix.xiak.com/v1'
       OR submitted_operation->>'kind' <> 'Operation'
       OR submitted_operation#>>'{scope,kind}' <> 'TENANT'
       OR submitted_operation#>>'{scope,tenantId}' <> effective_tenant_id
       OR submitted_operation->>'action' <> expected_operation_action
       OR submitted_operation#>>'{target,kind}' <> resource_kind
       OR submitted_operation#>>'{target,id}' <> resource_id
       OR submitted_operation->>'idempotencyFingerprint' COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR submitted_operation->>'requestDigest' COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR submitted_operation->>'state' <> 'SUCCEEDED'
       OR submitted_operation->>'attempt' <> '1'
       OR submitted_operation->'error' IS NOT NULL
       OR (submitted_operation->>'createdAt')::timestamptz <> effective_now
       OR (submitted_operation->>'updatedAt')::timestamptz <> effective_now
       OR (submitted_operation->>'terminalAt')::timestamptz <> effective_now THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'resource submission identity or state is invalid';
    END IF;

    INSERT INTO paas.operations (
        tenant_id, id, action, target_kind, target_id,
        idempotency_fingerprint, request_digest, state, attempt,
        next_attempt_at, fencing_token, created_at, updated_at,
        terminal_at, document
    ) VALUES (
        effective_tenant_id,
        operation_id,
        expected_operation_action,
        resource_kind,
        resource_id,
        submitted_operation->>'idempotencyFingerprint',
        submitted_operation->>'requestDigest',
        'SUCCEEDED',
        1,
        effective_now,
        0,
        effective_now,
        effective_now,
        effective_now,
        submitted_operation
    );

    CASE resource_kind
        WHEN 'Application' THEN
            INSERT INTO paas.applications (
                tenant_id, id, resource_version, document
            ) VALUES (
                effective_tenant_id, resource_id, 1, submitted_resource
            );
        WHEN 'Configuration' THEN
            INSERT INTO paas.configurations (
                tenant_id, id, application_id, resource_version, document
            ) VALUES (
                effective_tenant_id,
                resource_id,
                submitted_resource->>'applicationId',
                1,
                submitted_resource
            );
        WHEN 'ConfigurationRevision' THEN
            INSERT INTO paas.configuration_revisions (
                tenant_id, id, configuration_id, content_digest,
                resource_version, document
            ) VALUES (
                effective_tenant_id,
                resource_id,
                submitted_resource#>>'{spec,configurationId}',
                submitted_resource#>>'{spec,contentDigest}',
                1,
                submitted_resource
            );
        WHEN 'ApplicationRevision' THEN
            INSERT INTO paas.application_revisions (
                tenant_id, id, application_id, content_digest,
                resource_version, document
            ) VALUES (
                effective_tenant_id,
                resource_id,
                submitted_resource#>>'{spec,applicationId}',
                submitted_resource#>>'{spec,contentDigest}',
                1,
                submitted_resource
            );
    END CASE;

    PERFORM paas.append_audit_outbox(submitted_operation, submitted_audit_event);
END
$function$;

REVOKE ALL ON FUNCTION paas.create_apphosting_resource(jsonb, jsonb, jsonb)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.create_apphosting_resource(jsonb, jsonb, jsonb)
    TO matrix_paas_api;

DROP FUNCTION IF EXISTS paas.submit_deployment(jsonb, jsonb, jsonb, bigint);
CREATE OR REPLACE FUNCTION paas.submit_deployment(
    submitted_deployment jsonb,
    submitted_generation jsonb,
    submitted_operation jsonb,
    submitted_audit_event jsonb,
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
       OR jsonb_typeof(submitted_operation) <> 'object'
       OR jsonb_typeof(submitted_audit_event) <> 'object' THEN
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
       OR submitted_deployment#>>'{status,currentOperationId}' <> operation_id THEN
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
           OR submitted_deployment#>'{status}' ? 'placementDecisionId'
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
           OR (submitted_deployment->'metadata') - ARRAY['resourceVersion', 'updatedAt']
                IS DISTINCT FROM
                (current_document->'metadata') - ARRAY['resourceVersion', 'updatedAt']
           OR (submitted_deployment->'status') - ARRAY['phase', 'currentOperationId']
                IS DISTINCT FROM
              (current_document->'status') - ARRAY['phase', 'currentOperationId'] THEN
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

    PERFORM paas.append_audit_outbox(submitted_operation, submitted_audit_event);
END
$function$;

REVOKE ALL ON FUNCTION paas.submit_deployment(jsonb, jsonb, jsonb, jsonb, bigint)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.submit_deployment(jsonb, jsonb, jsonb, jsonb, bigint)
    TO matrix_paas_api;

DROP FUNCTION IF EXISTS paas.claim_audit_event(text, integer);
CREATE FUNCTION paas.claim_audit_event(
    requested_worker_id text,
    requested_lease_seconds integer
)
RETURNS TABLE (
    tenant_id text,
    installation_id text,
    event_id text,
    attempts integer,
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
            MESSAGE = 'Audit claim parameters are invalid';
    END IF;
    RETURN QUERY
    WITH candidate AS (
        SELECT pending.authority_key,
               pending.event_id
          FROM paas.audit_outbox AS pending
         WHERE pending.attempts < 100
           AND (
                (pending.status IN ('PENDING', 'RETRY')
                    AND pending.available_at <= transaction_timestamp())
                OR (pending.status = 'LEASED'
                    AND pending.lease_expires_at <= transaction_timestamp())
           )
         ORDER BY pending.available_at,
                  pending.created_at,
                  pending.authority_key COLLATE "C",
                  pending.event_id COLLATE "C"
         LIMIT 1
         FOR UPDATE SKIP LOCKED
    )
    UPDATE paas.audit_outbox AS claimed
       SET status = 'LEASED',
           attempts = claimed.attempts + 1,
           lease_owner = requested_worker_id,
           lease_expires_at = transaction_timestamp()
                + make_interval(secs => requested_lease_seconds),
           fencing_token = claimed.fencing_token + 1,
           last_error_code = NULL,
           updated_at = transaction_timestamp()
      FROM candidate
     WHERE claimed.authority_key = candidate.authority_key
       AND claimed.event_id = candidate.event_id
    RETURNING claimed.tenant_id,
              claimed.installation_id,
              claimed.event_id,
              claimed.attempts,
              claimed.fencing_token,
              claimed.lease_expires_at,
              claimed.document;
END
$function$;

REVOKE ALL ON FUNCTION paas.claim_audit_event(text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.claim_audit_event(text, integer)
    TO matrix_paas_worker;

DROP FUNCTION IF EXISTS paas.complete_audit_event(text, text, text, bigint, text, timestamptz, text);
CREATE OR REPLACE FUNCTION paas.complete_audit_event(
    requested_tenant_id text,
    requested_installation_id text,
    requested_event_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_outcome text,
    requested_retry_at timestamptz,
    requested_error_code text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    affected_rows bigint;
    effective_authority_key text;
BEGIN
    requested_tenant_id := NULLIF(requested_tenant_id, '');
    requested_installation_id := NULLIF(requested_installation_id, '');
    IF (requested_tenant_id IS NULL) = (requested_installation_id IS NULL)
       OR (requested_tenant_id IS NOT NULL AND requested_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
       OR (requested_installation_id IS NOT NULL AND requested_installation_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
       OR requested_event_id IS NULL
       OR requested_event_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR expected_fencing_token IS NULL
       OR expected_fencing_token NOT BETWEEN 1 AND 9007199254740991
       OR requested_outcome IS NULL
       OR requested_outcome NOT IN ('DELIVERED', 'RETRY', 'DEAD_LETTER')
       OR (requested_outcome = 'RETRY'
            AND (requested_retry_at IS NULL
                OR requested_retry_at <= transaction_timestamp()
                OR requested_retry_at > transaction_timestamp() + interval '24 hours'))
       OR (requested_outcome <> 'RETRY' AND requested_retry_at IS NOT NULL)
       OR (requested_outcome = 'DEAD_LETTER'
            AND (requested_error_code IS NULL
                OR requested_error_code COLLATE "C"
                    !~ '^[A-Z][A-Z0-9_]{0,63}$'))
       OR (requested_outcome <> 'DEAD_LETTER'
            AND requested_error_code IS NOT NULL) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Audit completion parameters are invalid';
    END IF;

    effective_authority_key := CASE WHEN requested_installation_id IS NOT NULL
        THEN 'installation:' || requested_installation_id ELSE 'tenant:' || requested_tenant_id END;
    UPDATE paas.audit_outbox AS event
       SET status = requested_outcome,
           available_at = CASE
                WHEN requested_outcome = 'RETRY' THEN requested_retry_at
                ELSE event.available_at
           END,
           lease_owner = NULL,
           lease_expires_at = NULL,
           last_error_code = CASE
                WHEN requested_outcome = 'DEAD_LETTER'
                    THEN requested_error_code
                ELSE NULL
           END,
           delivered_at = CASE
                WHEN requested_outcome = 'DELIVERED'
                    THEN transaction_timestamp()
                ELSE NULL
           END,
           updated_at = transaction_timestamp()
     WHERE event.authority_key = effective_authority_key
       AND event.event_id = requested_event_id
       AND event.status = 'LEASED'
       AND event.lease_owner = requested_worker_id
       AND event.fencing_token = expected_fencing_token
       AND event.lease_expires_at > clock_timestamp();
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'Audit event lease or fencing token is stale';
    END IF;
END
$function$;

REVOKE ALL ON FUNCTION paas.complete_audit_event(
    text, text, text, text, bigint, text, timestamptz, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.complete_audit_event(
    text, text, text, text, bigint, text, timestamptz, text
) TO matrix_paas_worker;

CREATE OR REPLACE FUNCTION paas.audit_outbox_snapshot()
RETURNS TABLE (
    pending_count bigint,
    leased_count bigint,
    retry_count bigint,
    delivered_count bigint,
    dead_letter_count bigint,
    expired_lease_count bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT
        count(*) FILTER (WHERE status = 'PENDING'),
        count(*) FILTER (WHERE status = 'LEASED'),
        count(*) FILTER (WHERE status = 'RETRY'),
        count(*) FILTER (WHERE status = 'DELIVERED'),
        count(*) FILTER (WHERE status = 'DEAD_LETTER'),
        count(*) FILTER (
            WHERE status = 'LEASED'
              AND lease_expires_at <= transaction_timestamp()
        )
    FROM paas.audit_outbox
$function$;

REVOKE ALL ON FUNCTION paas.audit_outbox_snapshot() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.audit_outbox_snapshot()
    TO matrix_paas_worker;

CREATE OR REPLACE FUNCTION paas.readiness()
RETURNS TABLE (ready boolean, schema_version bigint, checked_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT
        to_regclass('paas.applications') IS NOT NULL
        AND to_regclass('paas.operations') IS NOT NULL
        AND to_regclass('paas.audit_outbox') IS NOT NULL
        AND to_regprocedure('paas.current_installation_id()') IS NOT NULL
        AND to_regprocedure('paas.complete_audit_event(text,text,text,text,bigint,text,timestamptz,text)') IS NOT NULL
        AND to_regprocedure('paas.admit_execution_resource(jsonb,jsonb,jsonb,text,text,bigint,jsonb)') IS NOT NULL
        AND to_regprocedure('paas.refresh_execution_target(bigint,jsonb,bigint,jsonb)') IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
              FROM paas.audit_outbox AS outbox
             WHERE outbox.status = 'DEAD_LETTER'
                OR outbox.attempts >= 100
        ),
        2::bigint,
        transaction_timestamp()
$function$;

REVOKE ALL ON FUNCTION paas.readiness() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.readiness() TO matrix_paas_api;

CREATE OR REPLACE FUNCTION paas.worker_readiness()
RETURNS TABLE (ready boolean, schema_version bigint, checked_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT
        to_regclass('paas.operations') IS NOT NULL
        AND to_regclass('paas.execution_targets') IS NOT NULL
        AND to_regclass('paas.adapter_commands') IS NOT NULL
        AND to_regprocedure('paas.current_installation_id()') IS NOT NULL
        AND to_regprocedure('paas.claim_operation(text,integer)') IS NOT NULL
        AND to_regprocedure(
            'paas.advance_operation(text,text,bigint,text,jsonb,timestamptz,boolean)'
        ) IS NOT NULL
        AND to_regprocedure(
            'paas.reconcile_local_execution_profile(text,bigint,jsonb,bigint,jsonb,bigint,jsonb)'
        ) IS NOT NULL
        AND to_regprocedure(
            'paas.reconcile_local_execution_profile(bigint,jsonb,bigint,jsonb,bigint,jsonb)'
        ) IS NULL,
        2::bigint,
        transaction_timestamp()
$function$;

REVOKE ALL ON FUNCTION paas.worker_readiness() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.worker_readiness() TO matrix_paas_worker;

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
    current_updated_at timestamptz;
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
           operation.updated_at,
           operation.document
      INTO current_state,
           current_worker_id,
           current_fencing_token,
           current_lease_expires_at,
           current_next_attempt_at,
           current_updated_at,
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
                OR requested_next_attempt_at <= current_updated_at)) THEN
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

CREATE OR REPLACE FUNCTION paas.assert_current_operation_lease(
    requested_operation_id text,
    requested_worker_id text,
    expected_fencing_token bigint
)
RETURNS TABLE (
    operation_action text,
    deployment_id text,
    operation_state text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
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
       OR expected_fencing_token NOT BETWEEN 1 AND 9007199254740991 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Operation lease identity is invalid';
    END IF;

    RETURN QUERY
    SELECT operation.action,
           operation.target_id,
           operation.state
      FROM paas.operations AS operation
     WHERE operation.tenant_id = effective_tenant_id
       AND operation.id = requested_operation_id
       AND operation.target_kind = 'Deployment'
       AND operation.lease_owner = requested_worker_id
       AND operation.fencing_token = expected_fencing_token
       AND operation.lease_expires_at > clock_timestamp()
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'Operation lease or fencing token is stale';
    END IF;
END
$function$;

REVOKE ALL ON FUNCTION paas.assert_current_operation_lease(text, text, bigint)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.assert_current_operation_lease(text, text, bigint)
    TO matrix_paas_worker;

CREATE OR REPLACE FUNCTION paas.create_placement(
    requested_operation_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_request_digest text,
    submitted_decision jsonb,
    submitted_reservation jsonb,
    reuses_active_reservation boolean
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    operation_action text;
    operation_deployment_id text;
    operation_state text;
    decision_id text;
    decision_outcome text;
    decision_target_id text;
    decision_isolation text;
    decision_generation bigint;
    decision_revision_id text;
    decision_policy_id text;
    decision_time timestamptz(6);
    current_generation bigint;
    current_resource_version bigint;
    generation_revision_id text;
    generation_policy_id text;
    claim_id uuid;
BEGIN
    effective_tenant_id := paas.current_tenant_id();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'valid transaction-local tenant context is required';
    END IF;
    IF requested_request_digest IS NULL
       OR requested_request_digest COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
       OR jsonb_typeof(submitted_decision) <> 'object'
       OR (submitted_reservation IS NOT NULL
           AND jsonb_typeof(submitted_reservation) <> 'object')
       OR reuses_active_reservation IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'placement submission is invalid';
    END IF;

    SELECT lease.operation_action,
           lease.deployment_id,
           lease.operation_state
      INTO operation_action,
           operation_deployment_id,
           operation_state
      FROM paas.assert_current_operation_lease(
            requested_operation_id,
            requested_worker_id,
            expected_fencing_token
           ) AS lease;
    IF operation_state <> 'PLANNING' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'placement requires a planning Operation';
    END IF;

    decision_id := submitted_decision#>>'{metadata,id}';
    decision_outcome := submitted_decision->>'outcome';
    decision_target_id := submitted_decision->>'executionTargetId';
    decision_isolation := submitted_decision->>'grantedIsolationGuarantee';
    decision_revision_id := submitted_decision->>'applicationRevisionId';
    decision_policy_id := submitted_decision->>'placementPolicyId';
    IF submitted_decision->>'deploymentGeneration' !~ '^[1-9][0-9]*$'
       OR submitted_decision#>>'{metadata,resourceVersion}' <> '1'
       OR submitted_decision->>'deploymentResourceVersion' !~ '^[1-9][0-9]*$'
       OR submitted_decision->>'policyResourceVersion' !~ '^[1-9][0-9]*$'
       OR submitted_decision->>'executionTargetResourceVersion'
            !~ '^[1-9][0-9]*$' AND decision_outcome = 'SCHEDULED'
       OR submitted_decision#>>'{metadata,scope,kind}' <> 'TENANT'
       OR submitted_decision#>>'{metadata,scope,tenantId}' <> effective_tenant_id
       OR submitted_decision->>'deploymentId' <> operation_deployment_id
       OR decision_id IS NULL
       OR decision_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_decision->>'candidateSetDigest' COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR decision_outcome NOT IN ('SCHEDULED', 'UNSCHEDULABLE') THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'PlacementDecision identity is invalid';
    END IF;
    decision_generation := (submitted_decision->>'deploymentGeneration')::bigint;
    decision_time := (submitted_decision->>'decidedAt')::timestamptz;

    SELECT deployment.generation,
           deployment.resource_version,
           generation.application_revision_id,
           generation.policy_id
      INTO current_generation,
           current_resource_version,
           generation_revision_id,
           generation_policy_id
      FROM paas.deployments AS deployment
      JOIN paas.deployment_generations AS generation
        ON generation.tenant_id = deployment.tenant_id
       AND generation.deployment_id = deployment.id
       AND generation.generation = deployment.generation
     WHERE deployment.tenant_id = effective_tenant_id
       AND deployment.id = operation_deployment_id
       AND generation.created_by_operation_id = requested_operation_id
     FOR UPDATE OF deployment;
    IF NOT FOUND
       OR current_generation <> decision_generation
       OR current_resource_version
            <> (submitted_decision->>'deploymentResourceVersion')::bigint
       OR generation_revision_id <> decision_revision_id
       OR generation_policy_id <> decision_policy_id
       OR decision_time <> transaction_timestamp() THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'PlacementDecision does not bind the current Operation generation';
    END IF;

    IF decision_outcome = 'UNSCHEDULABLE' THEN
        IF operation_action = 'STOP'
           OR submitted_reservation IS NOT NULL
           OR reuses_active_reservation THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'unschedulable placement cannot reserve or reuse capacity';
        END IF;
    ELSIF reuses_active_reservation THEN
        IF operation_action <> 'STOP'
           OR submitted_reservation IS NOT NULL
           OR NOT EXISTS (
                SELECT 1
                  FROM paas.deployments AS deployment
                  JOIN paas.placement_decisions AS previous_decision
                    ON previous_decision.tenant_id = deployment.tenant_id
                   AND previous_decision.id =
                        deployment.document#>>'{status,placementDecisionId}'
                  JOIN paas.capacity_reservations AS reservation
                    ON reservation.tenant_id = previous_decision.tenant_id
                   AND reservation.decision_id = previous_decision.id
                  JOIN paas.capacity_claims AS claim
                    ON claim.id = reservation.capacity_claim_id
                 WHERE deployment.tenant_id = effective_tenant_id
                   AND deployment.id = operation_deployment_id
                   AND claim.state = 'ACTIVE'
                   AND previous_decision.execution_target_id = decision_target_id
                   AND previous_decision.granted_isolation = decision_isolation
              ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'stop placement requires the current active reservation';
        END IF;
    ELSE
        IF operation_action NOT IN ('DEPLOY', 'UPDATE', 'ROLLBACK')
           OR submitted_reservation IS NULL
           OR submitted_reservation->>'id' COLLATE "C"
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
           OR submitted_reservation->>'decisionId' <> decision_id
           OR submitted_reservation->>'deploymentId' <> operation_deployment_id
           OR submitted_reservation->>'executionTargetId' <> decision_target_id
           OR submitted_reservation->>'isolation' <> decision_isolation
           OR submitted_reservation->>'state' <> 'PENDING'
           OR submitted_reservation->>'resourceVersion' <> '1'
           OR submitted_reservation->>'cpuMillis' !~ '^(0|[1-9][0-9]*)$'
           OR submitted_reservation->>'memoryBytes' !~ '^(0|[1-9][0-9]*)$'
           OR submitted_reservation->>'workloadSlots' !~ '^[1-9][0-9]*$'
           OR (submitted_reservation->>'leaseExpiresAt')::timestamptz
                <= transaction_timestamp() THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'scheduled placement reservation is invalid';
        END IF;
    END IF;

    INSERT INTO paas.placement_decisions (
        tenant_id, id, operation_id, request_digest, deployment_id,
        deployment_generation, deployment_resource_version,
        application_revision_id, policy_id, policy_resource_version,
        requested_isolation, outcome, execution_target_id,
        execution_target_resource_version, granted_isolation,
        candidate_digest, reason, decided_at, document
    ) VALUES (
        effective_tenant_id,
        decision_id,
        requested_operation_id,
        requested_request_digest,
        operation_deployment_id,
        decision_generation,
        (submitted_decision->>'deploymentResourceVersion')::bigint,
        decision_revision_id,
        decision_policy_id,
        (submitted_decision->>'policyResourceVersion')::bigint,
        submitted_decision->>'requestedIsolationGuarantee',
        decision_outcome,
        NULLIF(decision_target_id, ''),
        CASE WHEN decision_outcome = 'SCHEDULED'
            THEN (submitted_decision->>'executionTargetResourceVersion')::bigint
            ELSE NULL END,
        NULLIF(decision_isolation, ''),
        submitted_decision->>'candidateSetDigest',
        submitted_decision->'reason',
        decision_time,
        submitted_decision
    );

    IF submitted_reservation IS NULL THEN
        RETURN;
    END IF;
    INSERT INTO paas.capacity_claims (
        execution_target_id, isolation, cpu_millis, memory_bytes,
        workload_slots, state, lease_expires_at, resource_version,
        created_at, updated_at
    ) VALUES (
        decision_target_id,
        decision_isolation,
        (submitted_reservation->>'cpuMillis')::bigint,
        (submitted_reservation->>'memoryBytes')::bigint,
        (submitted_reservation->>'workloadSlots')::bigint,
        'PENDING',
        (submitted_reservation->>'leaseExpiresAt')::timestamptz,
        1,
        decision_time,
        decision_time
    ) RETURNING id INTO claim_id;

    INSERT INTO paas.capacity_reservations (
        tenant_id, id, decision_id, deployment_id, execution_target_id,
        isolation, capacity_claim_id, resource_version, created_at, updated_at
    ) VALUES (
        effective_tenant_id,
        submitted_reservation->>'id',
        decision_id,
        operation_deployment_id,
        decision_target_id,
        decision_isolation,
        claim_id,
        1,
        decision_time,
        decision_time
    );
END
$function$;

REVOKE ALL ON FUNCTION paas.create_placement(
    text, text, bigint, text, jsonb, jsonb, boolean
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.create_placement(
    text, text, bigint, text, jsonb, jsonb, boolean
) TO matrix_paas_worker;

CREATE OR REPLACE FUNCTION paas.prepare_adapter_command(
    requested_operation_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    submitted_command jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    operation_action text;
    operation_deployment_id text;
    operation_state text;
    expected_action text;
    operation_attempt bigint;
    deployment_generation bigint;
    application_revision_id text;
    application_id text;
    execution_target_id text;
    submitted_action text;
    submitted_command_id text;
    submitted_request_digest text;
    submitted_binding_ref text;
    submitted_deadline timestamptz(6);
    stored_command_id text;
    stored_deployment_generation bigint;
    stored_application_revision_id text;
    stored_execution_target_id text;
    stored_request_digest text;
    stored_binding_ref text;
BEGIN
    effective_tenant_id := paas.current_tenant_id();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'valid transaction-local tenant context is required';
    END IF;
    IF jsonb_typeof(submitted_command) <> 'object' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'adapter command must be an object';
    END IF;
    SELECT lease.operation_action,
           lease.deployment_id,
           lease.operation_state
      INTO operation_action,
           operation_deployment_id,
           operation_state
      FROM paas.assert_current_operation_lease(
            requested_operation_id,
            requested_worker_id,
            expected_fencing_token
           ) AS lease;

    submitted_action := submitted_command->>'action';
    submitted_command_id := submitted_command->>'commandId';
    submitted_request_digest := submitted_command->>'requestDigest';
    submitted_binding_ref := submitted_command->>'bindingRef';
    IF operation_action IN ('DEPLOY', 'UPDATE') THEN
        expected_action := 'APPLY_DEPLOYMENT';
    ELSIF operation_action = 'ROLLBACK' THEN
        expected_action := 'ROLLBACK_DEPLOYMENT';
    ELSIF operation_action = 'STOP' THEN
        expected_action := 'STOP_DEPLOYMENT';
    ELSE
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'Operation action cannot execute a Deployment';
    END IF;
    IF submitted_action = 'OBSERVE_DEPLOYMENT' THEN
        IF operation_state NOT IN ('VERIFYING', 'RECONCILING') THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'observation command requires verifying or reconciling state';
        END IF;
    ELSIF submitted_action = expected_action THEN
        IF operation_state NOT IN ('QUEUED', 'EXECUTING', 'RECONCILING') THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'effect command requires queued, executing, or reconciling state';
        END IF;
    ELSE
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'adapter command action does not match Operation';
    END IF;

    SELECT operation.attempt,
           generation.generation,
           generation.application_revision_id,
           revision.application_id,
           decision.execution_target_id
      INTO operation_attempt,
           deployment_generation,
           application_revision_id,
           application_id,
           execution_target_id
      FROM paas.deployment_generations AS generation
      JOIN paas.operations AS operation
        ON operation.tenant_id = generation.tenant_id
       AND operation.id = generation.created_by_operation_id
      JOIN paas.application_revisions AS revision
        ON revision.tenant_id = generation.tenant_id
       AND revision.id = generation.application_revision_id
      JOIN paas.placement_decisions AS decision
        ON decision.tenant_id = generation.tenant_id
       AND decision.operation_id = generation.created_by_operation_id
       AND decision.deployment_id = generation.deployment_id
       AND decision.deployment_generation = generation.generation
     WHERE generation.tenant_id = effective_tenant_id
       AND generation.created_by_operation_id = requested_operation_id
       AND generation.deployment_id = operation_deployment_id
       AND decision.outcome = 'SCHEDULED';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0002',
            MESSAGE = 'scheduled Operation generation was not found';
    END IF;

    IF submitted_command_id IS NULL
       OR submitted_command_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_request_digest IS NULL
       OR submitted_request_digest COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
       OR submitted_binding_ref IS NULL
       OR submitted_binding_ref COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_command->>'operationId' <> requested_operation_id
       OR submitted_command#>>'{scope,kind}' <> 'TENANT'
       OR submitted_command#>>'{scope,tenantId}' <> effective_tenant_id
       OR submitted_command->>'deploymentId' <> operation_deployment_id
       OR submitted_command->>'applicationRevisionId' <> application_revision_id
       OR submitted_command->>'applicationId' <> application_id
       OR submitted_command->>'executionTargetId' <> execution_target_id
       OR submitted_command->>'attempt' !~ '^[1-9][0-9]*$'
       OR (submitted_command->>'attempt')::bigint <> operation_attempt
       OR submitted_command->>'deadline' IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'adapter command identity is invalid';
    END IF;
    submitted_deadline := (submitted_command->>'deadline')::timestamptz;
    IF submitted_deadline <= clock_timestamp() THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'adapter command deadline has expired';
    END IF;

    SELECT command.id,
           command.deployment_generation,
           command.application_revision_id,
           command.execution_target_id,
           command.request_digest,
           command.binding_ref
      INTO stored_command_id,
           stored_deployment_generation,
           stored_application_revision_id,
           stored_execution_target_id,
           stored_request_digest,
           stored_binding_ref
      FROM paas.adapter_commands AS command
     WHERE command.tenant_id = effective_tenant_id
       AND command.operation_id = requested_operation_id
       AND command.action = submitted_action
     FOR UPDATE;
    IF FOUND THEN
        IF stored_command_id <> submitted_command_id
           OR stored_deployment_generation <> deployment_generation
           OR stored_application_revision_id <> application_revision_id
           OR stored_execution_target_id <> execution_target_id
           OR stored_request_digest <> submitted_request_digest
           OR stored_binding_ref <> submitted_binding_ref THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MX409',
                MESSAGE = 'adapter command replay conflicts with stored intent';
        END IF;
        UPDATE paas.adapter_commands AS command
           SET deadline = submitted_deadline,
               document = submitted_command
         WHERE command.tenant_id = effective_tenant_id
           AND command.id = stored_command_id;
        RETURN submitted_command;
    END IF;

    INSERT INTO paas.adapter_commands (
        tenant_id, id, operation_id, action, deployment_id,
        deployment_generation, application_revision_id, execution_target_id,
        request_digest, binding_ref, deadline, created_at, document
    ) VALUES (
        effective_tenant_id,
        submitted_command_id,
        requested_operation_id,
        submitted_action,
        operation_deployment_id,
        deployment_generation,
        application_revision_id,
        execution_target_id,
        submitted_request_digest,
        submitted_binding_ref,
        submitted_deadline,
        transaction_timestamp(),
        submitted_command
    );
    RETURN submitted_command;
END
$function$;

REVOKE ALL ON FUNCTION paas.prepare_adapter_command(text, text, bigint, jsonb)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.prepare_adapter_command(text, text, bigint, jsonb)
    TO matrix_paas_worker;

DROP FUNCTION IF EXISTS paas.update_deployment_status(text, bigint, bigint, jsonb);

CREATE OR REPLACE FUNCTION paas.update_deployment_status(
    requested_operation_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
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
    operation_action text;
    operation_deployment_id text;
    operation_state text;
BEGIN
    effective_tenant_id := paas.current_tenant_id();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'valid transaction-local tenant context is required';
    END IF;
    SELECT lease.operation_action,
           lease.deployment_id,
           lease.operation_state
      INTO operation_action,
           operation_deployment_id,
           operation_state
      FROM paas.assert_current_operation_lease(
            requested_operation_id,
            requested_worker_id,
            expected_fencing_token
           ) AS lease;
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
    IF operation_deployment_id <> requested_deployment_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'Operation cannot mutate another Deployment';
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
       OR (submitted_deployment->'metadata') - ARRAY['resourceVersion', 'updatedAt']
            IS DISTINCT FROM
            (current_document->'metadata') - ARRAY['resourceVersion', 'updatedAt']
       OR submitted_deployment#>>'{metadata,resourceVersion}'
            <> (current_resource_version + 1)::text
       OR (submitted_deployment#>>'{metadata,updatedAt}')::timestamptz
            <> transaction_timestamp()
       OR submitted_deployment#>>'{status,currentOperationId}'
            IS DISTINCT FROM current_document#>>'{status,currentOperationId}'
       OR current_document#>>'{status,currentOperationId}'
            <> requested_operation_id
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

REVOKE ALL ON FUNCTION paas.update_deployment_status(
    text, text, bigint, text, bigint, bigint, jsonb
)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.update_deployment_status(
    text, text, bigint, text, bigint, bigint, jsonb
)
    TO matrix_paas_worker;

CREATE OR REPLACE FUNCTION paas.record_adapter_receipt(
    requested_operation_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_command_id text,
    requested_request_digest text,
    requested_state text,
    requested_receipt_digest text,
    requested_normalized_error jsonb,
    requested_evidence jsonb,
    requested_observed_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    operation_action text;
    operation_deployment_id text;
    operation_state text;
    command_request_digest text;
    current_state text;
    current_receipt_digest text;
    current_normalized_error jsonb;
    current_evidence jsonb;
    current_observed_at timestamptz(6);
BEGIN
    effective_tenant_id := paas.current_tenant_id();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'valid transaction-local tenant context is required';
    END IF;
    SELECT lease.operation_action,
           lease.deployment_id,
           lease.operation_state
      INTO operation_action,
           operation_deployment_id,
           operation_state
      FROM paas.assert_current_operation_lease(
            requested_operation_id,
            requested_worker_id,
            expected_fencing_token
           ) AS lease;
    IF operation_state <> 'EXECUTING' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'adapter receipt requires an executing Operation';
    END IF;
    IF requested_command_id IS NULL
       OR requested_command_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_request_digest IS NULL
       OR requested_request_digest COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
       OR requested_state NOT IN ('SUCCEEDED', 'IN_PROGRESS', 'FAILED', 'UNKNOWN')
       OR requested_evidence IS NULL
       OR jsonb_typeof(requested_evidence) <> 'array'
       OR requested_observed_at IS NULL
       OR (requested_receipt_digest IS NOT NULL
           AND requested_receipt_digest COLLATE "C"
                !~ '^sha256:[0-9a-f]{64}$')
       OR (requested_state IN ('FAILED', 'UNKNOWN')
           AND (requested_normalized_error IS NULL
                OR jsonb_typeof(requested_normalized_error) <> 'object'))
       OR (requested_state NOT IN ('FAILED', 'UNKNOWN')
           AND requested_normalized_error IS NOT NULL)
       OR (requested_state = 'SUCCEEDED' AND requested_receipt_digest IS NULL) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'adapter receipt is invalid';
    END IF;

    SELECT command.request_digest
      INTO command_request_digest
      FROM paas.adapter_commands AS command
     WHERE command.tenant_id = effective_tenant_id
       AND command.id = requested_command_id
       AND command.operation_id = requested_operation_id
       AND command.deployment_id = operation_deployment_id;
    IF NOT FOUND OR command_request_digest <> requested_request_digest THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX409',
            MESSAGE = 'adapter receipt does not match command intent';
    END IF;

    SELECT receipt.state,
           receipt.receipt_digest,
           receipt.normalized_error,
           receipt.evidence,
           receipt.observed_at
      INTO current_state,
           current_receipt_digest,
           current_normalized_error,
           current_evidence,
           current_observed_at
      FROM paas.adapter_receipts AS receipt
     WHERE receipt.tenant_id = effective_tenant_id
       AND receipt.command_id = requested_command_id
     FOR UPDATE;
    IF FOUND THEN
        IF current_state = requested_state
           AND current_receipt_digest IS NOT DISTINCT FROM requested_receipt_digest
           AND current_normalized_error IS NOT DISTINCT FROM requested_normalized_error
           AND current_evidence = requested_evidence
           AND current_observed_at = requested_observed_at THEN
            RETURN false;
        END IF;
        IF current_state IN ('SUCCEEDED', 'FAILED') THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MX409',
                MESSAGE = 'terminal adapter receipt cannot be replaced';
        END IF;
        UPDATE paas.adapter_receipts AS receipt
           SET state = requested_state,
               receipt_digest = requested_receipt_digest,
               normalized_error = requested_normalized_error,
               evidence = requested_evidence,
               observed_at = requested_observed_at
         WHERE receipt.tenant_id = effective_tenant_id
           AND receipt.command_id = requested_command_id;
        RETURN true;
    END IF;

    INSERT INTO paas.adapter_receipts (
        tenant_id, command_id, request_digest, state, receipt_digest,
        normalized_error, evidence, observed_at
    ) VALUES (
        effective_tenant_id,
        requested_command_id,
        requested_request_digest,
        requested_state,
        requested_receipt_digest,
        requested_normalized_error,
        requested_evidence,
        requested_observed_at
    );
    RETURN true;
END
$function$;

REVOKE ALL ON FUNCTION paas.record_adapter_receipt(
    text, text, bigint, text, text, text, text, jsonb, jsonb, timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.record_adapter_receipt(
    text, text, bigint, text, text, text, text, jsonb, jsonb, timestamptz
) TO matrix_paas_worker;

CREATE OR REPLACE FUNCTION paas.record_deployment_observation(
    requested_operation_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_command_id text,
    submitted_observation jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    operation_action text;
    operation_deployment_id text;
    operation_state text;
    command_generation bigint;
    command_revision_id text;
    current_document jsonb;
    current_observed_at timestamptz(6);
    submitted_observed_at timestamptz(6);
BEGIN
    effective_tenant_id := paas.current_tenant_id();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'valid transaction-local tenant context is required';
    END IF;
    IF jsonb_typeof(submitted_observation) <> 'object' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Deployment observation must be an object';
    END IF;
    SELECT lease.operation_action,
           lease.deployment_id,
           lease.operation_state
      INTO operation_action,
           operation_deployment_id,
           operation_state
      FROM paas.assert_current_operation_lease(
            requested_operation_id,
            requested_worker_id,
            expected_fencing_token
           ) AS lease;
    IF operation_state NOT IN ('VERIFYING', 'RECONCILING') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'Deployment observation requires verification or reconciliation';
    END IF;
    SELECT command.deployment_generation,
           command.application_revision_id
      INTO command_generation,
           command_revision_id
      FROM paas.adapter_commands AS command
     WHERE command.tenant_id = effective_tenant_id
       AND command.id = requested_command_id
       AND command.operation_id = requested_operation_id
       AND command.action = 'OBSERVE_DEPLOYMENT'
       AND command.deployment_id = operation_deployment_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0002',
            MESSAGE = 'Deployment observation command was not found';
    END IF;
    IF submitted_observation->>'deploymentId' <> operation_deployment_id
       OR submitted_observation->>'generation' !~ '^[1-9][0-9]*$'
       OR (submitted_observation->>'generation')::bigint <> command_generation
       OR submitted_observation->>'applicationRevisionId' <> command_revision_id
       OR submitted_observation->>'phase' NOT IN (
            'APPLYING', 'READY', 'DEGRADED', 'FAILED', 'STOPPING', 'STOPPED'
          )
       OR submitted_observation->>'readyComponents' !~ '^(0|[1-9][0-9]*)$'
       OR submitted_observation->>'receiptDigest' COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR submitted_observation->>'observedAt' IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Deployment observation identity is invalid';
    END IF;
    submitted_observed_at := (submitted_observation->>'observedAt')::timestamptz;

    SELECT observation.document,
           observation.observed_at
      INTO current_document,
           current_observed_at
      FROM paas.deployment_observations AS observation
     WHERE observation.tenant_id = effective_tenant_id
       AND observation.command_id = requested_command_id
     FOR UPDATE;
    IF FOUND THEN
        IF current_document = submitted_observation THEN
            RETURN false;
        END IF;
        IF submitted_observed_at <= current_observed_at THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MX409',
                MESSAGE = 'stale Deployment observation cannot replace a newer one';
        END IF;
        UPDATE paas.deployment_observations AS observation
           SET phase = submitted_observation->>'phase',
               ready_components =
                    (submitted_observation->>'readyComponents')::bigint,
               receipt_digest = submitted_observation->>'receiptDigest',
               observed_at = submitted_observed_at,
               document = submitted_observation
         WHERE observation.tenant_id = effective_tenant_id
           AND observation.command_id = requested_command_id;
        RETURN true;
    END IF;

    INSERT INTO paas.deployment_observations (
        tenant_id, command_id, deployment_id, deployment_generation,
        application_revision_id, phase, ready_components, receipt_digest,
        observed_at, document
    ) VALUES (
        effective_tenant_id,
        requested_command_id,
        operation_deployment_id,
        command_generation,
        command_revision_id,
        submitted_observation->>'phase',
        (submitted_observation->>'readyComponents')::bigint,
        submitted_observation->>'receiptDigest',
        submitted_observed_at,
        submitted_observation
    );
    RETURN true;
END
$function$;

REVOKE ALL ON FUNCTION paas.record_deployment_observation(
    text, text, bigint, text, jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.record_deployment_observation(
    text, text, bigint, text, jsonb
) TO matrix_paas_worker;

CREATE OR REPLACE FUNCTION paas.release_operation_lease(
    requested_operation_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_next_attempt_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    operation_action text;
    operation_deployment_id text;
    operation_state text;
    current_updated_at timestamptz;
    current_document jsonb;
    next_document jsonb;
BEGIN
    effective_tenant_id := paas.current_tenant_id();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'valid transaction-local tenant context is required';
    END IF;
    SELECT lease.operation_action,
           lease.deployment_id,
           lease.operation_state
      INTO operation_action,
           operation_deployment_id,
           operation_state
      FROM paas.assert_current_operation_lease(
            requested_operation_id,
            requested_worker_id,
            expected_fencing_token
           ) AS lease;
    SELECT operation.updated_at,
           operation.document
      INTO current_updated_at,
           current_document
      FROM paas.operations AS operation
     WHERE operation.tenant_id = effective_tenant_id
       AND operation.id = requested_operation_id;
    IF operation_state <> 'RECONCILING'
       OR requested_next_attempt_at IS NULL
       OR requested_next_attempt_at <= current_updated_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Operation lease release requires reconciliation backoff';
    END IF;
    next_document := jsonb_set(
        current_document,
        '{updatedAt}',
        to_jsonb(to_char(
            transaction_timestamp() AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
        )),
        false
    );
    UPDATE paas.operations AS operation
       SET next_attempt_at = requested_next_attempt_at,
           lease_owner = NULL,
           lease_expires_at = NULL,
           updated_at = transaction_timestamp(),
           document = next_document
     WHERE operation.tenant_id = effective_tenant_id
       AND operation.id = requested_operation_id;
    RETURN next_document;
END
$function$;

REVOKE ALL ON FUNCTION paas.release_operation_lease(text, text, bigint, timestamptz)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.release_operation_lease(text, text, bigint, timestamptz)
    TO matrix_paas_worker;

DROP FUNCTION IF EXISTS paas.transition_capacity_reservation(text, text, bigint);

CREATE OR REPLACE FUNCTION paas.transition_capacity_reservation(
    requested_operation_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
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
    operation_action text;
    operation_deployment_id text;
    operation_state text;
BEGIN
    effective_tenant_id := paas.current_tenant_id();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'valid transaction-local tenant context is required';
    END IF;
    SELECT lease.operation_action,
           lease.deployment_id,
           lease.operation_state
      INTO operation_action,
           operation_deployment_id,
           operation_state
      FROM paas.assert_current_operation_lease(
            requested_operation_id,
            requested_worker_id,
            expected_fencing_token
           ) AS lease;
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
       AND reservation.deployment_id = operation_deployment_id
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

REVOKE ALL ON FUNCTION paas.transition_capacity_reservation(
    text, text, bigint, text, text, bigint
)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.transition_capacity_reservation(
    text, text, bigint, text, text, bigint
)
    TO matrix_paas_worker;

DROP FUNCTION IF EXISTS paas.reconcile_local_execution_profile(
    bigint, jsonb, bigint, jsonb, bigint, jsonb
);

CREATE OR REPLACE FUNCTION paas.reconcile_local_execution_profile(
    requested_installation_id text,
    expected_pool_version bigint,
    submitted_pool jsonb,
    expected_target_version bigint,
    submitted_target jsonb,
    expected_policy_version bigint,
    submitted_policy jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    pool_id text;
    target_id text;
    policy_id text;
    next_pool_version bigint;
    next_target_version bigint;
    next_policy_version bigint;
    affected_rows bigint;
    current_pool jsonb;
    current_pool_installation_id text;
    current_target jsonb;
    current_target_installation_id text;
    current_policy jsonb;
    total_count bigint;
    ready_count bigint;
    degraded_count bigint;
BEGIN
    effective_tenant_id := paas.current_tenant_id();
    IF effective_tenant_id IS NULL
       OR requested_installation_id IS NULL
       OR requested_installation_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR jsonb_typeof(submitted_pool) <> 'object'
       OR jsonb_typeof(submitted_target) <> 'object'
       OR jsonb_typeof(submitted_policy) <> 'object'
       OR expected_pool_version IS NULL
       OR expected_pool_version NOT BETWEEN 0 AND 9007199254740991
       OR expected_target_version IS NULL
       OR expected_target_version NOT BETWEEN 0 AND 9007199254740991
       OR expected_policy_version IS NULL
       OR expected_policy_version NOT BETWEEN 0 AND 9007199254740991 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'local execution profile input is invalid';
    END IF;
    pool_id := submitted_pool#>>'{metadata,id}';
    target_id := submitted_target#>>'{metadata,id}';
    policy_id := submitted_policy#>>'{metadata,id}';
    next_pool_version := CASE
        WHEN expected_pool_version = 0 THEN 1
        ELSE expected_pool_version + 1
    END;
    next_target_version := CASE
        WHEN expected_target_version = 0 THEN 1
        ELSE expected_target_version + 1
    END;
    next_policy_version := CASE
        WHEN expected_policy_version = 0 THEN 1
        ELSE expected_policy_version
    END;
    IF pool_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR target_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR policy_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR pool_id <> 'execution-pool-local'
       OR target_id <> 'execution-target-local'
       OR policy_id <> 'placement-policy-local'
       OR next_pool_version NOT BETWEEN 1 AND 9007199254740991
       OR next_target_version NOT BETWEEN 1 AND 9007199254740991
       OR next_policy_version NOT BETWEEN 1 AND 9007199254740991
       OR submitted_pool->>'apiVersion' <> 'paas.matrix.xiak.com/v1'
       OR submitted_pool->>'kind' <> 'ExecutionPool'
       OR submitted_pool#>>'{metadata,name}' <> 'local'
       OR submitted_pool#>>'{metadata,scope,kind}' <> 'PLATFORM'
       OR submitted_pool#>'{metadata,labels}'
            <> '{"matrix-profile":"local-compose"}'::jsonb
       OR submitted_pool#>'{spec,executionTargetSelector,matchLabels}'
            <> '{"matrix-profile":"local-compose"}'::jsonb
       OR submitted_pool#>'{spec,allowedIsolationGuarantees}'
            <> '["WORKLOAD"]'::jsonb
       OR submitted_pool#>>'{metadata,resourceVersion}' <> next_pool_version::text
       OR submitted_target->>'apiVersion' <> 'paas.matrix.xiak.com/v1'
       OR submitted_target->>'kind' <> 'ExecutionTarget'
       OR submitted_target#>>'{metadata,name}' <> 'local'
       OR submitted_target#>>'{metadata,scope,kind}' <> 'PLATFORM'
       OR submitted_target#>>'{metadata,labels,matrix-profile}' <> 'local-compose'
       OR submitted_target#>>'{metadata,labels,matrix-machine-fingerprint}'
            COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
       OR submitted_target#>>'{metadata,resourceVersion}' <> next_target_version::text
       OR submitted_target#>>'{spec,executionPoolId}' <> pool_id
       OR submitted_target#>>'{spec,infrastructureAdapter,kind}' <> 'INFRASTRUCTURE'
       OR submitted_target#>>'{spec,infrastructureAdapter,name}' <> 'localmachine'
       OR submitted_target#>>'{spec,infrastructureAdapter,contractVersion}' <> 'v1'
       OR submitted_target#>>'{spec,deploymentExecutor,kind}' <> 'DEPLOYMENT_EXECUTOR'
       OR submitted_target#>>'{spec,deploymentExecutor,name}' <> 'compose'
       OR submitted_target#>>'{spec,deploymentExecutor,contractVersion}' <> 'v1'
       OR submitted_target#>'{spec,gatewayAdapter}' IS NOT NULL
       OR submitted_target#>>'{spec,desiredState}' <> 'ACTIVE'
       OR (CASE submitted_target#>>'{status,health}'
            WHEN 'READY' THEN
                submitted_target#>'{status,supportedIsolationGuarantees}'
                    <> '["WORKLOAD"]'::jsonb
            WHEN 'DEGRADED' THEN
                submitted_target#>'{status,supportedIsolationGuarantees}' <> '[]'::jsonb
            WHEN 'UNAVAILABLE' THEN
                submitted_target#>'{status,supportedIsolationGuarantees}' <> '[]'::jsonb
            WHEN 'UNKNOWN' THEN
                submitted_target#>'{status,supportedIsolationGuarantees}' <> '[]'::jsonb
            ELSE true
          END)
       OR submitted_policy->>'apiVersion' <> 'paas.matrix.xiak.com/v1'
       OR submitted_policy->>'kind' <> 'PlacementPolicy'
       OR submitted_policy#>>'{metadata,name}' <> 'default-local'
       OR submitted_policy#>>'{metadata,scope,kind}' <> 'TENANT'
       OR submitted_policy#>>'{metadata,scope,tenantId}' <> effective_tenant_id
       OR submitted_policy#>'{metadata,labels}'
            <> '{"matrix-profile":"local-compose","purpose":"default"}'::jsonb
       OR submitted_policy#>>'{spec,requiredIsolationGuarantee}' <> 'WORKLOAD'
       OR submitted_policy#>'{spec,eligibleExecutionPoolIds}'
            <> jsonb_build_array(pool_id)
       OR submitted_policy#>'{spec,executionTargetSelector,matchLabels}'
            <> '{"matrix-profile":"local-compose"}'::jsonb
       OR submitted_policy#>>'{spec,strategy}' <> 'FIRST_FIT'
       OR submitted_policy#>>'{metadata,resourceVersion}' <> next_policy_version::text THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'local execution profile document is invalid';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM paas.execution_targets AS target
         WHERE target.execution_pool_id = pool_id
           AND target.installation_id IS NULL
           AND target.id <> target_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX409',
            MESSAGE = 'local execution pool has ambiguous retained membership';
    END IF;

    SELECT pool.document, pool.installation_id
      INTO current_pool, current_pool_installation_id
      FROM paas.execution_pools AS pool
     WHERE pool.id = pool_id
     FOR UPDATE;
    IF expected_pool_version = 0 THEN
        IF FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                MESSAGE = 'local execution pool changed concurrently';
        END IF;
        INSERT INTO paas.execution_pools (
            id, installation_id, resource_version, document
        ) VALUES (pool_id, requested_installation_id, 1, submitted_pool)
        ON CONFLICT DO NOTHING;
    ELSE
        IF NOT FOUND
           OR current_pool_installation_id IS DISTINCT FROM requested_installation_id
                AND current_pool_installation_id IS NOT NULL
           OR (current_pool#>>'{metadata,resourceVersion}')::bigint <> expected_pool_version THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                MESSAGE = 'local execution pool changed concurrently';
        END IF;
        IF (((current_pool #- '{metadata,resourceVersion}') #- '{metadata,updatedAt}') - 'status') <>
           (((submitted_pool #- '{metadata,resourceVersion}') #- '{metadata,updatedAt}') - 'status') THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MX409',
                MESSAGE = 'local execution pool authority conflicts';
        END IF;
        UPDATE paas.execution_pools AS pool
           SET installation_id = requested_installation_id,
               resource_version = next_pool_version,
               document = submitted_pool
         WHERE pool.id = pool_id
           AND (pool.installation_id IS NULL OR pool.installation_id = requested_installation_id)
           AND pool.resource_version = expected_pool_version;
    END IF;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'local execution pool changed concurrently';
    END IF;

    SELECT target.document, target.installation_id
      INTO current_target, current_target_installation_id
      FROM paas.execution_targets AS target
     WHERE target.id = target_id
     FOR UPDATE;
    IF expected_target_version = 0 THEN
        IF FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                MESSAGE = 'local execution target changed concurrently';
        END IF;
        INSERT INTO paas.execution_targets (
            id, installation_id, execution_pool_id, resource_version, document
        ) VALUES (target_id, requested_installation_id, pool_id, 1, submitted_target)
        ON CONFLICT DO NOTHING;
    ELSE
        IF NOT FOUND
           OR current_target_installation_id IS DISTINCT FROM requested_installation_id
                AND current_target_installation_id IS NOT NULL
           OR (current_target#>>'{metadata,resourceVersion}')::bigint <> expected_target_version THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                MESSAGE = 'local execution target changed concurrently';
        END IF;
        IF (((current_target #- '{metadata,resourceVersion}') #- '{metadata,updatedAt}') - 'status') <>
           (((submitted_target #- '{metadata,resourceVersion}') #- '{metadata,updatedAt}') - 'status') THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MX409',
                MESSAGE = 'local execution target authority conflicts';
        END IF;
        UPDATE paas.execution_targets AS target
           SET installation_id = requested_installation_id,
               resource_version = next_target_version,
               document = submitted_target
         WHERE target.id = target_id
           AND (target.installation_id IS NULL OR target.installation_id = requested_installation_id)
           AND target.resource_version = expected_target_version;
    END IF;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'local execution target changed concurrently';
    END IF;

    SELECT count(*), count(*) FILTER (
        WHERE target.document#>>'{status,health}' = 'READY'
          AND target.document#>>'{spec,desiredState}' = 'ACTIVE'
          AND (target.document#>>'{status,observedAt}')::timestamptz > transaction_timestamp() - CASE
              WHEN target.binding_ref IS NULL THEN interval '5 minutes' ELSE interval '15 seconds' END
          AND (target.document#>>'{status,observedAt}')::timestamptz <= transaction_timestamp() + interval '2 seconds'
    ), count(*) FILTER (
        WHERE target.document#>>'{status,health}' = 'DEGRADED'
          AND (target.document#>>'{status,observedAt}')::timestamptz > transaction_timestamp() - CASE
              WHEN target.binding_ref IS NULL THEN interval '5 minutes' ELSE interval '15 seconds' END
          AND (target.document#>>'{status,observedAt}')::timestamptz <= transaction_timestamp() + interval '2 seconds'
    ) INTO total_count, ready_count, degraded_count
      FROM paas.execution_targets AS target
     WHERE target.installation_id = requested_installation_id
       AND target.execution_pool_id = pool_id;
    IF total_count NOT BETWEEN 1 AND 129
       OR submitted_pool#>>'{status,executionTargetCount}' <> total_count::text
       OR submitted_pool#>>'{status,readyExecutionTargetCount}' <> ready_count::text
       OR submitted_pool#>>'{status,phase}' <> (CASE WHEN ready_count = total_count THEN 'READY'
            WHEN ready_count > 0 OR degraded_count > 0 THEN 'DEGRADED' ELSE 'UNAVAILABLE' END) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'local execution pool status is inconsistent with installation targets',
            DETAIL = format(
                'stored total=%s ready=%s degraded=%s submitted total=%s ready=%s phase=%s',
                total_count, ready_count, degraded_count,
                submitted_pool#>>'{status,executionTargetCount}',
                submitted_pool#>>'{status,readyExecutionTargetCount}',
                submitted_pool#>>'{status,phase}'
            );
    END IF;

    IF expected_policy_version = 0 THEN
        INSERT INTO paas.placement_policies (
            tenant_id, id, resource_version, document
        ) VALUES (effective_tenant_id, policy_id, 1, submitted_policy)
        ON CONFLICT DO NOTHING;
        GET DIAGNOSTICS affected_rows = ROW_COUNT;
        IF affected_rows <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                MESSAGE = 'local placement policy changed concurrently';
        END IF;
    ELSE
        SELECT policy.document
          INTO current_policy
          FROM paas.placement_policies AS policy
         WHERE policy.tenant_id = effective_tenant_id
           AND policy.id = policy_id
           AND policy.resource_version = expected_policy_version
         FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                MESSAGE = 'local placement policy changed concurrently';
        END IF;
        IF current_policy <> submitted_policy THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MX409',
                MESSAGE = 'local placement policy conflicts';
        END IF;
    END IF;

    INSERT INTO paas.execution_target_allocations (execution_target_id)
    VALUES (target_id)
    ON CONFLICT DO NOTHING;
    RETURN true;
END
$function$;

REVOKE ALL ON FUNCTION paas.reconcile_local_execution_profile(
    text, bigint, jsonb, bigint, jsonb, bigint, jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paas.reconcile_local_execution_profile(
    text, bigint, jsonb, bigint, jsonb, bigint, jsonb
) TO matrix_paas_worker;

REVOKE ALL ON ALL TABLES IN SCHEMA paas FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA paas
    FROM matrix_paas_api, matrix_paas_worker;
GRANT SELECT ON paas.applications TO matrix_paas_api;
GRANT SELECT ON paas.configurations TO matrix_paas_api;
GRANT SELECT ON paas.configuration_revisions TO matrix_paas_api;
GRANT SELECT ON paas.application_revisions TO matrix_paas_api;
GRANT SELECT ON paas.placement_policies TO matrix_paas_api;
GRANT SELECT ON paas.deployments TO matrix_paas_api;
GRANT SELECT ON paas.deployment_generations TO matrix_paas_api;
GRANT SELECT ON paas.operations TO matrix_paas_api;
GRANT SELECT ON paas.execution_pools TO matrix_paas_api;
GRANT SELECT ON paas.execution_targets TO matrix_paas_api;

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
GRANT SELECT ON paas.adapter_commands TO matrix_paas_worker;
GRANT SELECT ON paas.adapter_receipts TO matrix_paas_worker;
GRANT SELECT ON paas.deployment_observations TO matrix_paas_worker;
GRANT SELECT ON paas.placement_decisions TO matrix_paas_worker;
GRANT SELECT ON paas.capacity_claims TO matrix_paas_worker;
GRANT SELECT ON paas.capacity_reservations TO matrix_paas_worker;

COMMIT;
