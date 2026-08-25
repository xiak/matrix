BEGIN;

DO $matrix_role$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'matrix_paas_runtime'
    ) THEN
        CREATE ROLE matrix_paas_runtime
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;
    ELSE
        ALTER ROLE matrix_paas_runtime
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;
    END IF;
END
$matrix_role$;

CREATE SCHEMA IF NOT EXISTS paas AUTHORIZATION CURRENT_USER;
REVOKE ALL ON SCHEMA paas FROM PUBLIC;
GRANT USAGE ON SCHEMA paas TO matrix_paas_runtime;

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
GRANT EXECUTE ON FUNCTION paas.current_tenant_id() TO matrix_paas_runtime;

CREATE TABLE IF NOT EXISTS paas.tenant_releases (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT tenant_releases_tenant_id_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT tenant_releases_id_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT tenant_releases_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT tenant_releases_document_identity CHECK (
        document->>'apiVersion' = 'matrix.paas.io/paas/v1'
        AND document->>'kind' = 'WorkloadRelease'
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

CREATE TABLE IF NOT EXISTS paas.placement_policies (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT placement_policies_tenant_id_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT placement_policies_id_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT placement_policies_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT placement_policies_document_identity CHECK (
        document->>'apiVersion' = 'matrix.paas.io/paas/v1'
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

CREATE TABLE IF NOT EXISTS paas.resource_pools (
    id text COLLATE "C" PRIMARY KEY,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    CONSTRAINT resource_pools_id_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT resource_pools_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT resource_pools_document_identity CHECK (
        document->>'apiVersion' = 'matrix.paas.io/paas/v1'
        AND document->>'kind' = 'ResourcePool'
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

CREATE TABLE IF NOT EXISTS paas.runtime_targets (
    id text COLLATE "C" PRIMARY KEY,
    resource_pool_id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    CONSTRAINT runtime_targets_pool_fk FOREIGN KEY (resource_pool_id)
        REFERENCES paas.resource_pools (id),
    CONSTRAINT runtime_targets_id_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT runtime_targets_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT runtime_targets_document_identity CHECK (
        document->>'apiVersion' = 'matrix.paas.io/paas/v1'
        AND document->>'kind' = 'RuntimeTarget'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,kind}' = 'PLATFORM'
        AND NOT (document#>'{metadata,scope}' ? 'tenantId')
        AND document#>>'{spec,resourcePoolId}' = resource_pool_id
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
    )
);

CREATE INDEX IF NOT EXISTS runtime_targets_pool_idx
    ON paas.runtime_targets (resource_pool_id, id);

CREATE TABLE IF NOT EXISTS paas.runtime_target_allocations (
    target_id text COLLATE "C" PRIMARY KEY,
    lock_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT runtime_target_allocations_target_fk FOREIGN KEY (target_id)
        REFERENCES paas.runtime_targets (id),
    CONSTRAINT runtime_target_allocations_version_valid CHECK (lock_version >= 0)
);

CREATE TABLE IF NOT EXISTS paas.placement_decisions (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    operation_id text COLLATE "C" NOT NULL,
    request_digest text COLLATE "C" NOT NULL,
    release_id text COLLATE "C" NOT NULL,
    policy_id text COLLATE "C" NOT NULL,
    policy_resource_version bigint NOT NULL,
    requested_isolation text COLLATE "C" NOT NULL,
    outcome text COLLATE "C" NOT NULL,
    runtime_target_id text COLLATE "C",
    runtime_target_resource_version bigint,
    granted_isolation text COLLATE "C",
    candidate_digest text COLLATE "C" NOT NULL,
    reason jsonb,
    decided_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT placement_decisions_operation_uq UNIQUE (tenant_id, operation_id),
    CONSTRAINT placement_decisions_scheduled_identity_uq UNIQUE (
        tenant_id,
        id,
        release_id,
        runtime_target_id,
        granted_isolation
    ),
    CONSTRAINT placement_decisions_release_fk FOREIGN KEY (tenant_id, release_id)
        REFERENCES paas.tenant_releases (tenant_id, id),
    CONSTRAINT placement_decisions_policy_fk FOREIGN KEY (tenant_id, policy_id)
        REFERENCES paas.placement_policies (tenant_id, id),
    CONSTRAINT placement_decisions_target_fk FOREIGN KEY (runtime_target_id)
        REFERENCES paas.runtime_targets (id),
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
        policy_resource_version BETWEEN 1 AND 9007199254740991
        AND (
            runtime_target_resource_version IS NULL
            OR runtime_target_resource_version BETWEEN 1 AND 9007199254740991
        )
    ),
    CONSTRAINT placement_decisions_isolation_valid CHECK (
        requested_isolation IN (
            'SHARED_COMPOSE',
            'DEDICATED_COMPOSE',
            'DEDICATED_HOST',
            'K8S_NAMESPACE',
            'PHYSICAL_HOST'
        )
        AND (
            granted_isolation IS NULL
            OR granted_isolation = requested_isolation
        )
    ),
    CONSTRAINT placement_decisions_outcome_valid CHECK (
        (
            outcome = 'SCHEDULED'
            AND runtime_target_id IS NOT NULL
            AND runtime_target_resource_version IS NOT NULL
            AND granted_isolation = requested_isolation
            AND reason IS NULL
        )
        OR (
            outcome = 'UNSCHEDULABLE'
            AND runtime_target_id IS NULL
            AND runtime_target_resource_version IS NULL
            AND granted_isolation IS NULL
            AND reason IS NOT NULL
        )
    ),
    CONSTRAINT placement_decisions_document_identity CHECK (
        document->>'apiVersion' = 'matrix.paas.io/paas/v1'
        AND document->>'kind' = 'PlacementDecision'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,kind}' = 'TENANT'
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND document->>'workloadReleaseId' = release_id
        AND document->>'placementPolicyId' = policy_id
        AND document->>'requestedIsolationClass' = requested_isolation
        AND document->>'outcome' = outcome
        AND document->>'candidateSetDigest' = candidate_digest
        AND CASE
            WHEN document->>'policyResourceVersion' ~ '^[1-9][0-9]*$'
            THEN (document->>'policyResourceVersion')::numeric = policy_resource_version
            ELSE false
        END
        AND (
            (runtime_target_id IS NULL AND NOT (document ? 'runtimeTargetId'))
            OR document->>'runtimeTargetId' = runtime_target_id
        )
        AND (
            (
                runtime_target_resource_version IS NULL
                AND NOT (document ? 'runtimeTargetResourceVersion')
            )
            OR CASE
                WHEN document->>'runtimeTargetResourceVersion' ~ '^[1-9][0-9]*$'
                THEN (document->>'runtimeTargetResourceVersion')::numeric
                    = runtime_target_resource_version
                ELSE false
            END
        )
        AND (
            (granted_isolation IS NULL AND NOT (document ? 'grantedIsolationClass'))
            OR document->>'grantedIsolationClass' = granted_isolation
        )
        AND reason IS NOT DISTINCT FROM document->'reason'
        AND (document->>'decidedAt')::timestamptz = decided_at
    )
);

CREATE TABLE IF NOT EXISTS paas.capacity_claims (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    runtime_target_id text COLLATE "C" NOT NULL,
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
    CONSTRAINT capacity_claims_identity_uq UNIQUE (
        id,
        runtime_target_id,
        isolation
    ),
    CONSTRAINT capacity_claims_target_fk FOREIGN KEY (runtime_target_id)
        REFERENCES paas.runtime_targets (id),
    CONSTRAINT capacity_claims_isolation_valid CHECK (
        isolation IN (
            'SHARED_COMPOSE',
            'DEDICATED_COMPOSE',
            'DEDICATED_HOST',
            'K8S_NAMESPACE',
            'PHYSICAL_HOST'
        )
    ),
    CONSTRAINT capacity_claims_resources_valid CHECK (
        cpu_millis >= 0
        AND memory_bytes >= 0
        AND workload_slots > 0
    ),
    CONSTRAINT capacity_claims_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT capacity_claims_state_valid CHECK (
        (
            state = 'PENDING'
            AND lease_expires_at IS NOT NULL
        )
        OR (
            state IN ('ACTIVE', 'RELEASED')
            AND lease_expires_at IS NULL
        )
    ),
    CONSTRAINT capacity_claims_time_valid CHECK (updated_at >= created_at)
);

CREATE INDEX IF NOT EXISTS capacity_claims_target_consuming_idx
    ON paas.capacity_claims (
        runtime_target_id,
        state,
        lease_expires_at,
        id
    )
    WHERE state IN ('PENDING', 'ACTIVE');

CREATE TABLE IF NOT EXISTS paas.capacity_reservations (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    decision_id text COLLATE "C" NOT NULL,
    release_id text COLLATE "C" NOT NULL,
    runtime_target_id text COLLATE "C" NOT NULL,
    isolation text COLLATE "C" NOT NULL,
    capacity_claim_id uuid NOT NULL,
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT capacity_reservations_decision_uq UNIQUE (tenant_id, decision_id),
    CONSTRAINT capacity_reservations_claim_uq UNIQUE (capacity_claim_id),
    CONSTRAINT capacity_reservations_decision_fk FOREIGN KEY (
        tenant_id,
        decision_id,
        release_id,
        runtime_target_id,
        isolation
    ) REFERENCES paas.placement_decisions (
        tenant_id,
        id,
        release_id,
        runtime_target_id,
        granted_isolation
    ),
    CONSTRAINT capacity_reservations_claim_fk FOREIGN KEY (
        capacity_claim_id,
        runtime_target_id,
        isolation
    ) REFERENCES paas.capacity_claims (
        id,
        runtime_target_id,
        isolation
    ),
    CONSTRAINT capacity_reservations_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND decision_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT capacity_reservations_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT capacity_reservations_time_valid CHECK (updated_at >= created_at)
);

ALTER TABLE paas.tenant_releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.tenant_releases FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.placement_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.placement_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.placement_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.placement_decisions FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.capacity_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.capacity_reservations FORCE ROW LEVEL SECURITY;

DO $matrix_policy$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'tenant_releases',
        'placement_policies',
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

REVOKE ALL ON ALL TABLES IN SCHEMA paas FROM PUBLIC;
GRANT SELECT ON paas.tenant_releases TO matrix_paas_runtime;
GRANT SELECT ON paas.placement_policies TO matrix_paas_runtime;
GRANT SELECT ON paas.resource_pools TO matrix_paas_runtime;
GRANT SELECT ON paas.runtime_targets TO matrix_paas_runtime;
GRANT SELECT, UPDATE (lock_version)
    ON paas.runtime_target_allocations TO matrix_paas_runtime;
GRANT SELECT, INSERT ON paas.placement_decisions TO matrix_paas_runtime;
GRANT SELECT, INSERT ON paas.capacity_claims TO matrix_paas_runtime;
GRANT UPDATE (state, lease_expires_at, resource_version, updated_at)
    ON paas.capacity_claims TO matrix_paas_runtime;
GRANT SELECT, INSERT ON paas.capacity_reservations TO matrix_paas_runtime;

COMMIT;
