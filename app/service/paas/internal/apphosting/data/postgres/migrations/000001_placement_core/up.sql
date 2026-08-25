BEGIN;

DO $matrix_role$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'matrix_paas_runtime'
    ) THEN
        CREATE ROLE matrix_paas_runtime
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    ELSE
        ALTER ROLE matrix_paas_runtime
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
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
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT deployments_document_identity CHECK (
        document->>'apiVersion' = 'paas.matrix.xiak.com/v1'
        AND document->>'kind' = 'Deployment'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,kind}' = 'TENANT'
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND document#>>'{spec,applicationRevisionId}' = application_revision_id
        AND document#>>'{spec,placementPolicyId}' = policy_id
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
    )
);

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

CREATE TABLE IF NOT EXISTS paas.placement_decisions (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    operation_id text COLLATE "C" NOT NULL,
    request_digest text COLLATE "C" NOT NULL,
    deployment_id text COLLATE "C" NOT NULL,
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
        deployment_resource_version BETWEEN 1 AND 9007199254740991
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
ALTER TABLE paas.application_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.application_revisions FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.placement_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.placement_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE paas.deployments ENABLE ROW LEVEL SECURITY;
ALTER TABLE paas.deployments FORCE ROW LEVEL SECURITY;
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
        'application_revisions',
        'placement_policies',
        'deployments',
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
    TO matrix_paas_runtime;

REVOKE ALL ON ALL TABLES IN SCHEMA paas FROM PUBLIC;
GRANT SELECT ON paas.applications TO matrix_paas_runtime;
GRANT SELECT ON paas.application_revisions TO matrix_paas_runtime;
GRANT SELECT ON paas.placement_policies TO matrix_paas_runtime;
GRANT SELECT ON paas.deployments TO matrix_paas_runtime;
GRANT SELECT ON paas.execution_pools TO matrix_paas_runtime;
GRANT SELECT ON paas.execution_targets TO matrix_paas_runtime;
GRANT SELECT, UPDATE (lock_version)
    ON paas.execution_target_allocations TO matrix_paas_runtime;
GRANT SELECT, INSERT ON paas.placement_decisions TO matrix_paas_runtime;
GRANT SELECT, INSERT ON paas.capacity_claims TO matrix_paas_runtime;
GRANT SELECT, INSERT ON paas.capacity_reservations TO matrix_paas_runtime;

COMMIT;
