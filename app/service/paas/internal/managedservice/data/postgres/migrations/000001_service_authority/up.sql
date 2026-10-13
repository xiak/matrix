BEGIN;

DO $matrix_managedservice_roles$
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
        END IF;
    END LOOP;
END
$matrix_managedservice_roles$;

CREATE SCHEMA IF NOT EXISTS managedservice AUTHORIZATION CURRENT_USER;
REVOKE ALL ON SCHEMA managedservice FROM PUBLIC;
GRANT USAGE ON SCHEMA managedservice TO matrix_paas_api, matrix_paas_worker;

CREATE OR REPLACE FUNCTION managedservice.current_tenant_id()
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

REVOKE ALL ON FUNCTION managedservice.current_tenant_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION managedservice.current_tenant_id()
    TO matrix_paas_api, matrix_paas_worker;

CREATE TABLE IF NOT EXISTS managedservice.service_activations (
    tenant_id text COLLATE "C" NOT NULL,
    service_id text COLLATE "C" NOT NULL,
    service_revision bigint NOT NULL,
    service_digest text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL DEFAULT 1,
    idempotency_key text COLLATE "C" NOT NULL,
    request_digest text COLLATE "C" NOT NULL,
    activated_by_type text COLLATE "C" NOT NULL,
    activated_by_id text COLLATE "C" NOT NULL,
    iam_decision_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    activated_at timestamptz(6) NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, service_id),
    CONSTRAINT service_activations_idempotency_uq
        UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT service_activations_identity_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND service_id COLLATE "C" ~ '^[a-z0-9][a-z0-9._-]{0,61}[a-z0-9]$'
        AND service_revision BETWEEN 1 AND 9007199254740991
        AND service_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND resource_version = 1
        AND idempotency_key COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND activated_by_type IN ('USER', 'ROLE')
        AND activated_by_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND iam_decision_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    )
);

-- The direct predecessor admitted only USER activators. Replace its named
-- constraint in-place so retained rows stay valid while the current Profile
-- can persist an exact ROLE actor. Replaying this migration is equivalent.
ALTER TABLE managedservice.service_activations
    DROP CONSTRAINT IF EXISTS service_activations_identity_valid;
ALTER TABLE managedservice.service_activations
    ADD CONSTRAINT service_activations_identity_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND service_id COLLATE "C" ~ '^[a-z0-9][a-z0-9._-]{0,61}[a-z0-9]$'
        AND service_revision BETWEEN 1 AND 9007199254740991
        AND service_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND resource_version = 1
        AND idempotency_key COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND activated_by_type IN ('USER', 'ROLE')
        AND activated_by_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND iam_decision_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ) NOT VALID;
ALTER TABLE managedservice.service_activations
    VALIDATE CONSTRAINT service_activations_identity_valid;

CREATE TABLE IF NOT EXISTS managedservice.quota_entitlements (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    offering_id text COLLATE "C" NOT NULL,
    quota_shape_id text COLLATE "C" NOT NULL,
    purchased_count integer NOT NULL,
    reserved_count integer NOT NULL DEFAULT 0,
    consumed_count integer NOT NULL DEFAULT 0,
    resource_version bigint NOT NULL DEFAULT 1,
    idempotency_key text COLLATE "C" NOT NULL,
    request_digest text COLLATE "C" NOT NULL,
    activated_by_type text COLLATE "C" NOT NULL,
    activated_by_id text COLLATE "C" NOT NULL,
    iam_decision_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    activated_at timestamptz(6) NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT quota_entitlements_idempotency_uq
        UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT quota_entitlements_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND offering_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND quota_shape_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND idempotency_key COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND activated_by_type IN ('USER', 'SERVICE_ACCOUNT')
        AND activated_by_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND iam_decision_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT quota_entitlements_catalog_valid CHECK (
        (offering_id = 'postgresql-18'
            AND quota_shape_id IN ('pg-small', 'pg-medium'))
        OR (offering_id = 'mysql-8.4'
            AND quota_shape_id IN ('mysql-small', 'mysql-medium'))
        OR (offering_id = 'elasticsearch-8.19'
            AND quota_shape_id IN ('elasticsearch-small', 'elasticsearch-medium'))
        OR (offering_id = 'rabbitmq-4.1'
            AND quota_shape_id IN ('rabbitmq-small', 'rabbitmq-medium'))
    ),
    CONSTRAINT quota_entitlements_counts_valid CHECK (
        purchased_count BETWEEN 1 AND 100
        AND reserved_count BETWEEN 0 AND purchased_count
        AND consumed_count BETWEEN 0 AND purchased_count
        AND reserved_count + consumed_count <= purchased_count
    ),
    CONSTRAINT quota_entitlements_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT quota_entitlements_digest_valid CHECK (
        request_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
    )
);

CREATE TABLE IF NOT EXISTS managedservice.service_installations (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    name text NOT NULL,
    offering_id text COLLATE "C" NOT NULL,
    engine_version text COLLATE "C" NOT NULL,
    quota_entitlement_id text COLLATE "C" NOT NULL,
    region_id text COLLATE "C" NOT NULL,
    phase text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    endpoint text,
    credential_reference text COLLATE "C",
    current_operation_id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz(6) NOT NULL DEFAULT transaction_timestamp(),
    observed_at timestamptz(6) NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT service_installations_entitlement_fk
        FOREIGN KEY (tenant_id, quota_entitlement_id)
        REFERENCES managedservice.quota_entitlements (tenant_id, id),
    CONSTRAINT service_installations_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[a-z0-9][a-z0-9._-]{1,62}$'
        AND (
            (offering_id = 'postgresql-18' AND engine_version = '18')
            OR (offering_id = 'mysql-8.4' AND engine_version = '8.4')
            OR (offering_id = 'elasticsearch-8.19' AND engine_version = '8.19.23')
            OR (offering_id = 'rabbitmq-4.1' AND engine_version = '4.1.8')
        )
        AND quota_entitlement_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND region_id = 'local-primary'
    ),
    CONSTRAINT service_installations_name_valid CHECK (
        octet_length(name) BETWEEN 1 AND 128
        AND name = btrim(name)
        AND strpos(name, chr(13)) = 0
        AND strpos(name, chr(10)) = 0
    ),
    CONSTRAINT service_installations_phase_valid CHECK (
        phase IN (
            'PENDING', 'PROVISIONING', 'READY', 'FAILED', 'ROLLBACK_FAILED',
            'TERMINATION_PENDING', 'TERMINATING', 'TERMINATION_FAILED', 'TERMINATED'
        )
    ),
    CONSTRAINT service_installations_result_valid CHECK (
        (phase IN ('READY', 'TERMINATION_PENDING', 'TERMINATING', 'TERMINATION_FAILED')
            AND endpoint IS NOT NULL AND credential_reference IS NOT NULL)
        OR (phase NOT IN ('READY', 'TERMINATION_PENDING', 'TERMINATING', 'TERMINATION_FAILED')
            AND endpoint IS NULL AND credential_reference IS NULL)
    ),
    CONSTRAINT service_installations_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT service_installations_time_valid CHECK (observed_at >= created_at)
);

-- This repository is pre-v1 and owns one replayable current schema instead of
-- a chain of obsolete development migrations. Re-applying the current source
-- must upgrade the immediately preceding PostgreSQL-only catalog without
-- changing any existing row.
ALTER TABLE managedservice.quota_entitlements
    DROP CONSTRAINT IF EXISTS quota_entitlements_catalog_valid;
ALTER TABLE managedservice.quota_entitlements
    ADD CONSTRAINT quota_entitlements_catalog_valid CHECK (
        (offering_id = 'postgresql-18'
            AND quota_shape_id IN ('pg-small', 'pg-medium'))
        OR (offering_id = 'mysql-8.4'
            AND quota_shape_id IN ('mysql-small', 'mysql-medium'))
        OR (offering_id = 'elasticsearch-8.19'
            AND quota_shape_id IN ('elasticsearch-small', 'elasticsearch-medium'))
        OR (offering_id = 'rabbitmq-4.1'
            AND quota_shape_id IN ('rabbitmq-small', 'rabbitmq-medium'))
    );

ALTER TABLE managedservice.service_installations
    DROP CONSTRAINT IF EXISTS service_installations_ids_valid;
ALTER TABLE managedservice.service_installations
    ADD CONSTRAINT service_installations_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[a-z0-9][a-z0-9._-]{1,62}$'
        AND (
            (offering_id = 'postgresql-18' AND engine_version = '18')
            OR (offering_id = 'mysql-8.4' AND engine_version = '8.4')
            OR (offering_id = 'elasticsearch-8.19' AND engine_version = '8.19.23')
            OR (offering_id = 'rabbitmq-4.1' AND engine_version = '4.1.8')
        )
        AND quota_entitlement_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND region_id = 'local-primary'
    );

CREATE TABLE IF NOT EXISTS managedservice.operations (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    installation_id text COLLATE "C" NOT NULL,
    kind text COLLATE "C" NOT NULL,
    quota_release text COLLATE "C" NOT NULL,
    phase text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    safe_failure_code text COLLATE "C",
    idempotency_key text COLLATE "C" NOT NULL,
    request_digest text COLLATE "C" NOT NULL,
    requested_by_type text COLLATE "C" NOT NULL,
    requested_by_id text COLLATE "C" NOT NULL,
    iam_decision_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL DEFAULT 1,
    attempts integer NOT NULL DEFAULT 0,
    lease_owner text COLLATE "C",
    lease_expires_at timestamptz(6),
    fencing_token bigint NOT NULL DEFAULT 0,
    next_attempt_at timestamptz(6) NOT NULL DEFAULT transaction_timestamp(),
    observed_at timestamptz(6) NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT operations_idempotency_uq UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT operations_installation_fk
        FOREIGN KEY (tenant_id, installation_id)
        REFERENCES managedservice.service_installations (tenant_id, id),
    CONSTRAINT managedservice_operations_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND installation_id COLLATE "C" ~ '^[a-z0-9][a-z0-9._-]{1,62}$'
        AND idempotency_key COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND requested_by_type IN ('USER', 'SERVICE_ACCOUNT')
        AND requested_by_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND iam_decision_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT managedservice_operations_phase_valid CHECK (
        phase IN ('PENDING', 'PROVISIONING', 'READY', 'FAILED')
        AND ((phase = 'FAILED') = (safe_failure_code IS NOT NULL))
    ),
    CONSTRAINT managedservice_operations_kind_valid CHECK (
        (kind = 'PROVISION' AND quota_release = 'NONE')
        OR (kind = 'TERMINATE' AND quota_release IN ('RESERVED', 'CONSUMED'))
    ),
    CONSTRAINT managedservice_operations_failure_valid CHECK (
        safe_failure_code IS NULL
        OR safe_failure_code COLLATE "C" ~ '^[A-Z][A-Z0-9_]{1,63}$'
    ),
    CONSTRAINT managedservice_operations_digest_valid CHECK (
        request_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT managedservice_operations_lease_valid CHECK (
        attempts BETWEEN 0 AND 100
        AND fencing_token BETWEEN 0 AND 9007199254740991
        AND ((lease_owner IS NULL) = (lease_expires_at IS NULL))
    ),
    CONSTRAINT managedservice_operations_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    )
);

-- The only supported development predecessor has one provisioning operation
-- per installation. Preserve it as the current operation while replacing the
-- one-operation model with an explicit provision/terminate history.
ALTER TABLE managedservice.operations
    ADD COLUMN IF NOT EXISTS kind text COLLATE "C" NOT NULL DEFAULT 'PROVISION';
ALTER TABLE managedservice.operations
    ADD COLUMN IF NOT EXISTS quota_release text COLLATE "C" NOT NULL DEFAULT 'NONE';
ALTER TABLE managedservice.service_installations
    ADD COLUMN IF NOT EXISTS current_operation_id text COLLATE "C";
UPDATE managedservice.service_installations AS installation
   SET current_operation_id = operation.id
  FROM managedservice.operations AS operation
 WHERE installation.current_operation_id IS NULL
   AND operation.tenant_id = installation.tenant_id
   AND operation.installation_id = installation.id;
ALTER TABLE managedservice.service_installations
    ALTER COLUMN current_operation_id SET NOT NULL;

ALTER TABLE managedservice.operations
    DROP CONSTRAINT IF EXISTS operations_installation_uq;
ALTER TABLE managedservice.operations
    DROP CONSTRAINT IF EXISTS managedservice_operations_kind_valid;
ALTER TABLE managedservice.operations
    ADD CONSTRAINT managedservice_operations_kind_valid CHECK (
        (kind = 'PROVISION' AND quota_release = 'NONE')
        OR (kind = 'TERMINATE' AND quota_release IN ('RESERVED', 'CONSUMED'))
    );
ALTER TABLE managedservice.service_installations
    DROP CONSTRAINT IF EXISTS service_installations_current_operation_fk;
ALTER TABLE managedservice.service_installations
    ADD CONSTRAINT service_installations_current_operation_fk
        FOREIGN KEY (tenant_id, current_operation_id)
        REFERENCES managedservice.operations (tenant_id, id)
        DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX IF NOT EXISTS managedservice_operations_installation_idx
    ON managedservice.operations (tenant_id, installation_id, observed_at DESC, id COLLATE "C");

ALTER TABLE managedservice.service_installations
    DROP CONSTRAINT IF EXISTS service_installations_phase_valid;
ALTER TABLE managedservice.service_installations
    ADD CONSTRAINT service_installations_phase_valid CHECK (
        phase IN (
            'PENDING', 'PROVISIONING', 'READY', 'FAILED', 'ROLLBACK_FAILED',
            'TERMINATION_PENDING', 'TERMINATING', 'TERMINATION_FAILED', 'TERMINATED'
        )
    );
ALTER TABLE managedservice.service_installations
    DROP CONSTRAINT IF EXISTS service_installations_result_valid;
ALTER TABLE managedservice.service_installations
    ADD CONSTRAINT service_installations_result_valid CHECK (
        (phase IN ('READY', 'TERMINATION_PENDING', 'TERMINATING', 'TERMINATION_FAILED')
            AND endpoint IS NOT NULL AND credential_reference IS NOT NULL)
        OR (phase NOT IN ('READY', 'TERMINATION_PENDING', 'TERMINATING', 'TERMINATION_FAILED')
            AND endpoint IS NULL AND credential_reference IS NULL)
    );

CREATE OR REPLACE FUNCTION managedservice.start_termination(
    requested_installation_id text,
    requested_operation_id text,
    requested_idempotency_key text,
    requested_digest text,
    requested_actor_type text,
    requested_actor_id text,
    requested_iam_decision_id text,
    requested_request_id text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    current_phase text;
    release_kind text;
BEGIN
    effective_tenant_id := managedservice.current_tenant_id();
    IF effective_tenant_id IS NULL
       OR requested_installation_id IS NULL
       OR requested_installation_id COLLATE "C" !~ '^[a-z0-9][a-z0-9._-]{1,62}$'
       OR requested_operation_id IS NULL
       OR requested_operation_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_idempotency_key IS NULL
       OR requested_idempotency_key COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_digest IS NULL
       OR requested_digest COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
       OR requested_actor_type NOT IN ('USER', 'SERVICE_ACCOUNT')
       OR requested_actor_id IS NULL
       OR requested_actor_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_iam_decision_id IS NULL
       OR requested_iam_decision_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_request_id IS NULL
       OR requested_request_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'managed-service termination request is invalid';
    END IF;
    SELECT phase
      INTO current_phase
      FROM managedservice.service_installations
     WHERE tenant_id = effective_tenant_id
       AND id = requested_installation_id
     FOR UPDATE;
    IF current_phase IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MX404', MESSAGE = 'managed-service installation is absent';
    END IF;
    release_kind := CASE
        WHEN current_phase IN ('READY', 'TERMINATION_FAILED') THEN 'CONSUMED'
        WHEN current_phase = 'ROLLBACK_FAILED' THEN 'RESERVED'
        ELSE NULL
    END;
    IF release_kind IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MX409', MESSAGE = 'managed-service installation cannot terminate from its current state';
    END IF;
    INSERT INTO managedservice.operations (
        tenant_id, id, installation_id, kind, quota_release,
        idempotency_key, request_digest, requested_by_type, requested_by_id,
        iam_decision_id, request_id
    ) VALUES (
        effective_tenant_id, requested_operation_id, requested_installation_id,
        'TERMINATE', release_kind, requested_idempotency_key, requested_digest,
        requested_actor_type, requested_actor_id, requested_iam_decision_id,
        requested_request_id
    );
    UPDATE managedservice.service_installations
       SET phase = 'TERMINATION_PENDING',
           current_operation_id = requested_operation_id,
           resource_version = resource_version + 1,
           observed_at = transaction_timestamp()
     WHERE tenant_id = effective_tenant_id
       AND id = requested_installation_id;
END
$function$;

REVOKE ALL ON FUNCTION managedservice.start_termination(
    text, text, text, text, text, text, text, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION managedservice.start_termination(
    text, text, text, text, text, text, text, text
) TO matrix_paas_api;

CREATE TABLE IF NOT EXISTS managedservice.audit_outbox (
    tenant_id text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    operation_id text COLLATE "C",
    status text COLLATE "C" NOT NULL,
    available_at timestamptz(6) NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    lease_owner text COLLATE "C",
    lease_expires_at timestamptz(6),
    fencing_token bigint NOT NULL DEFAULT 0,
    last_error_code text COLLATE "C",
    delivered_at timestamptz(6),
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, event_id),
    CONSTRAINT managedservice_audit_operation_fk
        FOREIGN KEY (tenant_id, operation_id)
        REFERENCES managedservice.operations (tenant_id, id),
    CONSTRAINT managedservice_audit_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND event_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND (operation_id IS NULL OR operation_id COLLATE "C"
            ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
    ),
    CONSTRAINT managedservice_audit_delivery_valid CHECK (
        status IN ('PENDING', 'LEASED', 'RETRY', 'DELIVERED', 'DEAD_LETTER')
        AND attempts BETWEEN 0 AND 100
        AND fencing_token BETWEEN 0 AND 9007199254740991
        AND ((lease_owner IS NULL) = (lease_expires_at IS NULL))
        AND (last_error_code IS NULL OR last_error_code COLLATE "C"
            ~ '^[A-Z][A-Z0-9_]{0,63}$')
        AND ((status = 'DELIVERED') = (delivered_at IS NOT NULL))
    ),
    CONSTRAINT managedservice_audit_document_identity CHECK (
        document->>'schemaVersion' = 'v1'
        AND document->>'eventId' = event_id
        AND document->>'tenantId' = tenant_id
        AND document->>'action' IN (
            'managedservice.service-activation.activated',
            'managedservice.quota-entitlement.activated',
            'managedservice.service-installation.created',
            'managedservice.service-installation.ready',
            'managedservice.service-installation.termination-requested',
            'managedservice.service-installation.terminated'
        )
        AND (
            (operation_id IS NULL
                AND document->>'action' IN (
                    'managedservice.service-activation.activated',
                    'managedservice.quota-entitlement.activated'
                )
                AND NOT (document ? 'operationId'))
            OR (operation_id IS NOT NULL
                AND document->>'action' = 'managedservice.service-installation.created'
                AND document->>'operationId' = operation_id)
            OR (operation_id IS NOT NULL
                AND document->>'action' = 'managedservice.service-installation.ready'
                AND NOT (document ? 'operationId'))
            OR (operation_id IS NOT NULL
                AND document->>'action' IN (
                    'managedservice.service-installation.termination-requested',
                    'managedservice.service-installation.terminated'
                )
                AND document->>'operationId' = operation_id)
        )
    )
);

ALTER TABLE managedservice.audit_outbox
    DROP CONSTRAINT IF EXISTS managedservice_audit_document_identity;
ALTER TABLE managedservice.audit_outbox
    ADD CONSTRAINT managedservice_audit_document_identity CHECK (
        document->>'schemaVersion' = 'v1'
        AND document->>'eventId' = event_id
        AND document->>'tenantId' = tenant_id
        AND document->>'action' IN (
            'managedservice.service-activation.activated',
            'managedservice.quota-entitlement.activated',
            'managedservice.service-installation.created',
            'managedservice.service-installation.ready',
            'managedservice.service-installation.termination-requested',
            'managedservice.service-installation.terminated'
        )
        AND (
            (operation_id IS NULL
                AND document->>'action' IN (
                    'managedservice.service-activation.activated',
                    'managedservice.quota-entitlement.activated'
                )
                AND NOT (document ? 'operationId'))
            OR (operation_id IS NOT NULL
                AND document->>'action' = 'managedservice.service-installation.created'
                AND document->>'operationId' = operation_id)
            OR (operation_id IS NOT NULL
                AND document->>'action' = 'managedservice.service-installation.ready'
                AND NOT (document ? 'operationId'))
            OR (operation_id IS NOT NULL
                AND document->>'action' IN (
                    'managedservice.service-installation.termination-requested',
                    'managedservice.service-installation.terminated'
                )
                AND document->>'operationId' = operation_id)
        )
    );

CREATE INDEX IF NOT EXISTS managedservice_audit_delivery_idx
    ON managedservice.audit_outbox (status, available_at, created_at);

ALTER TABLE managedservice.service_activations ENABLE ROW LEVEL SECURITY;
ALTER TABLE managedservice.service_activations FORCE ROW LEVEL SECURITY;
ALTER TABLE managedservice.quota_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE managedservice.quota_entitlements FORCE ROW LEVEL SECURITY;
ALTER TABLE managedservice.service_installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE managedservice.service_installations FORCE ROW LEVEL SECURITY;
ALTER TABLE managedservice.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE managedservice.operations FORCE ROW LEVEL SECURITY;
ALTER TABLE managedservice.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE managedservice.audit_outbox FORCE ROW LEVEL SECURITY;

DO $matrix_managedservice_policy$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'service_activations', 'quota_entitlements', 'service_installations', 'operations', 'audit_outbox'
    ]
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_policies
             WHERE schemaname = 'managedservice'
               AND tablename = table_name
               AND policyname = 'tenant_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY tenant_isolation ON managedservice.%I '
                'USING (tenant_id = managedservice.current_tenant_id()) '
                'WITH CHECK (tenant_id = managedservice.current_tenant_id())',
                table_name
            );
        END IF;
    END LOOP;
END
$matrix_managedservice_policy$;

-- Recover the sanitized outcome of a recent, closed managed-service command
-- without granting the API role direct access to the immutable Audit outbox.
-- The caller supplies only the already-authenticated actor lineage; tenant
-- scope always comes from the transaction-local authority setting.
CREATE OR REPLACE FUNCTION managedservice.list_command_results(
    requested_command_type text,
    requested_actor_type text,
    requested_actor_id text,
    requested_source_user_id text,
    requested_source_service_principal_id text,
    requested_retention_seconds integer,
    requested_limit integer
)
RETURNS TABLE (
    idempotency_key text,
    request_digest text,
    target_id text,
    operation_id text,
    operation_kind text,
    operation_phase text,
    operation_safe_failure_code text,
    operation_observed_at timestamptz,
    completed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    expected_action text;
    expected_operation_kind text;
BEGIN
    effective_tenant_id := managedservice.current_tenant_id();
    IF requested_command_type NOT IN (
            'QUOTA_ACTIVATE', 'INSTALLATION_CREATE', 'INSTALLATION_TERMINATE'
       )
       OR requested_actor_type NOT IN ('USER', 'ROLE')
       OR requested_actor_id IS NULL
       OR requested_actor_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_retention_seconds IS NULL
       OR requested_retention_seconds NOT BETWEEN 1 AND 604800
       OR requested_limit IS NULL
       OR requested_limit NOT BETWEEN 1 AND 100
       OR (requested_actor_type = 'USER' AND (
            COALESCE(requested_source_user_id, '') <> ''
            OR COALESCE(requested_source_service_principal_id, '') <> ''
       ))
       OR (requested_actor_type = 'ROLE' AND (
            (COALESCE(requested_source_user_id, '') = '') =
                (COALESCE(requested_source_service_principal_id, '') = '')
            OR (COALESCE(requested_source_user_id, '') <> '' AND
                requested_source_user_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
            OR (COALESCE(requested_source_service_principal_id, '') <> '' AND
                requested_source_service_principal_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
       )) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'managed-service command result parameters are invalid';
    END IF;

    IF requested_command_type = 'QUOTA_ACTIVATE' THEN
        RETURN QUERY
        SELECT entitlement.idempotency_key,
               entitlement.request_digest,
               entitlement.id,
               NULL::text, NULL::text, NULL::text, NULL::text,
               NULL::timestamptz,
               entitlement.activated_at
          FROM managedservice.quota_entitlements AS entitlement
          JOIN managedservice.audit_outbox AS event
            ON event.tenant_id = entitlement.tenant_id
           AND event.document->>'action' = 'managedservice.quota-entitlement.activated'
           AND event.document->>'result' = 'SUCCEEDED'
           AND event.document#>>'{target,kind}' = 'QuotaEntitlement'
           AND event.document#>>'{target,id}' = entitlement.id
           AND event.document->>'requestDigest' = entitlement.request_digest
           AND event.document->>'requestId' = entitlement.request_id
           AND (event.document->>'occurredAt')::timestamptz = entitlement.activated_at
         WHERE entitlement.tenant_id = effective_tenant_id
           AND entitlement.activated_at >= transaction_timestamp() -
                make_interval(secs => requested_retention_seconds)
           AND event.document#>>'{actor,type}' = requested_actor_type
           AND event.document#>>'{actor,id}' = requested_actor_id
           AND CASE
                WHEN requested_actor_type = 'USER' THEN
                    NOT (event.document->'actor' ? 'accessKeyId')
                    AND NOT (event.document->'actor' ? 'roleSession')
                ELSE
                    COALESCE(event.document#>>'{actor,roleSession,sourceUserId}', '') =
                        COALESCE(requested_source_user_id, '')
                    AND COALESCE(event.document#>>'{actor,roleSession,sourceServicePrincipalId}', '') =
                        COALESCE(requested_source_service_principal_id, '')
               END
         ORDER BY entitlement.activated_at DESC, entitlement.id COLLATE "C"
         LIMIT requested_limit;
        RETURN;
    END IF;

    IF requested_command_type = 'INSTALLATION_CREATE' THEN
        expected_action := 'managedservice.service-installation.created';
        expected_operation_kind := 'PROVISION';
    ELSE
        expected_action := 'managedservice.service-installation.termination-requested';
        expected_operation_kind := 'TERMINATE';
    END IF;
    RETURN QUERY
    SELECT operation.idempotency_key,
           operation.request_digest,
           operation.installation_id,
           operation.id,
           operation.kind,
           operation.phase,
           operation.safe_failure_code,
           operation.observed_at,
           CASE
                WHEN operation.phase IN ('PENDING', 'PROVISIONING') THEN NULL::timestamptz
                ELSE operation.observed_at
           END
      FROM managedservice.operations AS operation
      JOIN managedservice.audit_outbox AS event
        ON event.tenant_id = operation.tenant_id
       AND event.operation_id = operation.id
       AND event.document->>'action' = expected_action
       AND event.document->>'result' = 'ACCEPTED'
       AND event.document#>>'{target,kind}' = 'ServiceInstallation'
       AND event.document#>>'{target,id}' = operation.installation_id
       AND event.document->>'operationId' = operation.id
       AND event.document->>'requestDigest' = operation.request_digest
       AND event.document->>'requestId' = operation.request_id
     WHERE operation.tenant_id = effective_tenant_id
       AND operation.kind = expected_operation_kind
       AND event.created_at >= transaction_timestamp() -
            make_interval(secs => requested_retention_seconds)
       AND event.document#>>'{actor,type}' = requested_actor_type
       AND event.document#>>'{actor,id}' = requested_actor_id
       AND CASE
            WHEN requested_actor_type = 'USER' THEN
                NOT (event.document->'actor' ? 'accessKeyId')
                AND NOT (event.document->'actor' ? 'roleSession')
            ELSE
                COALESCE(event.document#>>'{actor,roleSession,sourceUserId}', '') =
                    COALESCE(requested_source_user_id, '')
                AND COALESCE(event.document#>>'{actor,roleSession,sourceServicePrincipalId}', '') =
                    COALESCE(requested_source_service_principal_id, '')
           END
     ORDER BY event.created_at DESC, operation.id COLLATE "C"
     LIMIT requested_limit;
END
$function$;
REVOKE ALL ON FUNCTION managedservice.list_command_results(
    text, text, text, text, text, integer, integer
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION managedservice.list_command_results(
    text, text, text, text, text, integer, integer
) TO matrix_paas_api;

CREATE OR REPLACE FUNCTION managedservice.append_audit_outbox(
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
    target_id text;
    target_operation_id text;
BEGIN
    effective_tenant_id := managedservice.current_tenant_id();
    effective_now := transaction_timestamp();
    IF effective_tenant_id IS NULL
       OR jsonb_typeof(submitted_audit_event) <> 'object'
       OR jsonb_typeof(submitted_audit_event->'actor') <> 'object'
       OR jsonb_typeof(submitted_audit_event->'target') <> 'object'
       OR NOT (submitted_audit_event ?& ARRAY[
            'schemaVersion', 'eventId', 'tenantId', 'actor',
            'iamDecisionId', 'action', 'target', 'requestDigest',
            'result', 'requestId', 'occurredAt'
       ])
       OR NOT ((submitted_audit_event->'actor') ?& ARRAY['type', 'id'])
       OR NOT ((submitted_audit_event->'target') ?& ARRAY['kind', 'id'])
       OR (submitted_audit_event - ARRAY[
            'schemaVersion', 'eventId', 'tenantId', 'actor',
            'iamDecisionId', 'action', 'target', 'operationId',
            'requestDigest', 'result', 'requestId', 'occurredAt'
       ]) <> '{}'::jsonb
       OR ((submitted_audit_event->'target') - ARRAY['kind', 'id']) <> '{}'::jsonb THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'managed-service Audit event contract is invalid';
    END IF;

    target_id := submitted_audit_event#>>'{target,id}';
    target_operation_id := submitted_audit_event->>'operationId';
    IF submitted_audit_event->>'schemaVersion' <> 'v1'
       OR COALESCE(submitted_audit_event->>'eventId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_audit_event->>'tenantId' <> effective_tenant_id
       OR submitted_audit_event#>>'{actor,type}' NOT IN ('USER', 'ROLE', 'SERVICE_ACCOUNT')
       OR NOT paas.subject_reference_valid(submitted_audit_event->'actor')
       OR COALESCE(submitted_audit_event->>'iamDecisionId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(target_id, '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_audit_event->>'requestDigest', '') COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR COALESCE(submitted_audit_event->>'requestId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR (submitted_audit_event->>'occurredAt')::timestamptz <> effective_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'managed-service Audit event identity is invalid';
    END IF;

    IF submitted_audit_event->>'action' = 'managedservice.service-activation.activated' THEN
        IF submitted_audit_event#>>'{target,kind}' <> 'ServiceActivation'
           OR submitted_audit_event->>'result' <> 'SUCCEEDED'
           OR submitted_audit_event#>>'{actor,type}' NOT IN ('USER', 'ROLE')
           OR submitted_audit_event ? 'operationId'
           OR NOT EXISTS (
                SELECT 1
                  FROM managedservice.service_activations AS activation
                 WHERE activation.tenant_id = effective_tenant_id
                   AND activation.service_id = target_id
                   AND activation.request_digest = submitted_audit_event->>'requestDigest'
                   AND activation.activated_by_type = submitted_audit_event#>>'{actor,type}'
                   AND activation.activated_by_id = submitted_audit_event#>>'{actor,id}'
                   AND activation.iam_decision_id = submitted_audit_event->>'iamDecisionId'
                   AND activation.request_id = submitted_audit_event->>'requestId'
                   AND activation.activated_at = effective_now
           ) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'service activation Audit fact is not transactionally correlated';
        END IF;
        target_operation_id := NULL;
    ELSIF submitted_audit_event->>'action' = 'managedservice.quota-entitlement.activated' THEN
        IF submitted_audit_event#>>'{target,kind}' <> 'QuotaEntitlement'
           OR submitted_audit_event->>'result' <> 'SUCCEEDED'
           OR submitted_audit_event ? 'operationId'
           OR NOT EXISTS (
                SELECT 1
                  FROM managedservice.quota_entitlements AS entitlement
                 WHERE entitlement.tenant_id = effective_tenant_id
                   AND entitlement.id = target_id
                   AND entitlement.request_digest = submitted_audit_event->>'requestDigest'
                   AND entitlement.activated_by_type = submitted_audit_event#>>'{actor,type}'
                   AND entitlement.activated_by_id = submitted_audit_event#>>'{actor,id}'
                   AND entitlement.iam_decision_id = submitted_audit_event->>'iamDecisionId'
                   AND entitlement.request_id = submitted_audit_event->>'requestId'
                   AND entitlement.activated_at = effective_now
           ) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'quota Audit fact is not transactionally correlated';
        END IF;
        target_operation_id := NULL;
    ELSIF submitted_audit_event->>'action' = 'managedservice.service-installation.created' THEN
        IF submitted_audit_event#>>'{target,kind}' <> 'ServiceInstallation'
           OR submitted_audit_event->>'result' <> 'ACCEPTED'
           OR COALESCE(target_operation_id, '') COLLATE "C"
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
           OR NOT EXISTS (
                SELECT 1
                  FROM managedservice.operations AS operation
                  JOIN managedservice.service_installations AS installation
                    ON installation.tenant_id = operation.tenant_id
                   AND installation.id = operation.installation_id
                 WHERE operation.tenant_id = effective_tenant_id
                   AND operation.id = target_operation_id
                   AND operation.installation_id = target_id
                   AND operation.request_digest = submitted_audit_event->>'requestDigest'
                   AND operation.requested_by_type = submitted_audit_event#>>'{actor,type}'
                   AND operation.requested_by_id = submitted_audit_event#>>'{actor,id}'
                   AND operation.iam_decision_id = submitted_audit_event->>'iamDecisionId'
                   AND operation.request_id = submitted_audit_event->>'requestId'
                   AND installation.created_at = effective_now
           ) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'installation Audit fact is not transactionally correlated';
        END IF;
    ELSIF submitted_audit_event->>'action' = 'managedservice.service-installation.termination-requested' THEN
        IF submitted_audit_event#>>'{target,kind}' <> 'ServiceInstallation'
           OR submitted_audit_event->>'result' <> 'ACCEPTED'
           OR COALESCE(target_operation_id, '') COLLATE "C"
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
           OR NOT EXISTS (
                SELECT 1
                  FROM managedservice.operations AS operation
                  JOIN managedservice.service_installations AS installation
                    ON installation.tenant_id = operation.tenant_id
                   AND installation.id = operation.installation_id
                 WHERE operation.tenant_id = effective_tenant_id
                   AND operation.id = target_operation_id
                   AND operation.kind = 'TERMINATE'
                   AND operation.installation_id = target_id
                   AND operation.request_digest = submitted_audit_event->>'requestDigest'
                   AND operation.requested_by_type = submitted_audit_event#>>'{actor,type}'
                   AND operation.requested_by_id = submitted_audit_event#>>'{actor,id}'
                   AND operation.iam_decision_id = submitted_audit_event->>'iamDecisionId'
                   AND operation.request_id = submitted_audit_event->>'requestId'
                   AND operation.observed_at = effective_now
                   AND installation.current_operation_id = operation.id
                   AND installation.phase = 'TERMINATION_PENDING'
           ) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'termination Audit fact is not transactionally correlated';
        END IF;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'managed-service API cannot append this Audit action';
    END IF;

    INSERT INTO managedservice.audit_outbox (
        tenant_id, event_id, operation_id, status, available_at,
        attempts, fencing_token, created_at, updated_at, document
    ) VALUES (
        effective_tenant_id, submitted_audit_event->>'eventId', target_operation_id,
        'PENDING', effective_now, 0, 0, effective_now, effective_now,
        submitted_audit_event
    );
END
$function$;

REVOKE ALL ON FUNCTION managedservice.append_audit_outbox(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION managedservice.append_audit_outbox(jsonb) TO matrix_paas_api;

CREATE OR REPLACE FUNCTION managedservice.claim_audit_event(
    requested_worker_id text,
    requested_lease_seconds integer
)
RETURNS TABLE (
    tenant_id text,
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
       OR requested_worker_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_lease_seconds IS NULL
       OR requested_lease_seconds NOT BETWEEN 1 AND 300 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Audit claim parameters are invalid';
    END IF;
    RETURN QUERY
    WITH candidate AS (
        SELECT pending.tenant_id, pending.event_id
          FROM managedservice.audit_outbox AS pending
         WHERE pending.attempts < 100
           AND ((pending.status IN ('PENDING', 'RETRY')
                    AND pending.available_at <= transaction_timestamp())
                OR (pending.status = 'LEASED'
                    AND pending.lease_expires_at <= transaction_timestamp()))
         ORDER BY pending.available_at, pending.created_at,
                  pending.tenant_id COLLATE "C", pending.event_id COLLATE "C"
         LIMIT 1
         FOR UPDATE SKIP LOCKED
    )
    UPDATE managedservice.audit_outbox AS claimed
       SET status = 'LEASED', attempts = claimed.attempts + 1,
           lease_owner = requested_worker_id,
           lease_expires_at = transaction_timestamp()
                + make_interval(secs => requested_lease_seconds),
           fencing_token = claimed.fencing_token + 1,
           last_error_code = NULL, updated_at = transaction_timestamp()
      FROM candidate
     WHERE claimed.tenant_id = candidate.tenant_id
       AND claimed.event_id = candidate.event_id
    RETURNING claimed.tenant_id, claimed.event_id, claimed.attempts,
              claimed.fencing_token, claimed.lease_expires_at, claimed.document;
END
$function$;

REVOKE ALL ON FUNCTION managedservice.claim_audit_event(text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION managedservice.claim_audit_event(text, integer) TO matrix_paas_worker;

CREATE OR REPLACE FUNCTION managedservice.complete_audit_event(
    requested_tenant_id text,
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
BEGIN
    IF requested_tenant_id IS NULL
       OR requested_tenant_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_event_id IS NULL
       OR requested_event_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR expected_fencing_token IS NULL
       OR expected_fencing_token NOT BETWEEN 1 AND 9007199254740991
       OR requested_outcome NOT IN ('DELIVERED', 'RETRY', 'DEAD_LETTER')
       OR (requested_outcome = 'RETRY'
            AND (requested_retry_at IS NULL
                OR requested_retry_at <= transaction_timestamp()
                OR requested_retry_at > transaction_timestamp() + interval '24 hours'))
       OR (requested_outcome <> 'RETRY' AND requested_retry_at IS NOT NULL)
       OR (requested_outcome = 'DEAD_LETTER'
            AND (requested_error_code IS NULL
                OR requested_error_code COLLATE "C" !~ '^[A-Z][A-Z0-9_]{0,63}$'))
       OR (requested_outcome <> 'DEAD_LETTER' AND requested_error_code IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Audit completion parameters are invalid';
    END IF;

    UPDATE managedservice.audit_outbox AS event
       SET status = requested_outcome,
           available_at = CASE WHEN requested_outcome = 'RETRY'
                THEN requested_retry_at ELSE event.available_at END,
           lease_owner = NULL, lease_expires_at = NULL,
           last_error_code = CASE WHEN requested_outcome = 'DEAD_LETTER'
                THEN requested_error_code ELSE NULL END,
           delivered_at = CASE WHEN requested_outcome = 'DELIVERED'
                THEN transaction_timestamp() ELSE NULL END,
           updated_at = transaction_timestamp()
     WHERE event.tenant_id = requested_tenant_id
       AND event.event_id = requested_event_id
       AND event.status = 'LEASED'
       AND event.lease_owner = requested_worker_id
       AND event.fencing_token = expected_fencing_token
       AND event.lease_expires_at > clock_timestamp();
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'MX412', MESSAGE = 'Audit event lease or fencing token is stale';
    END IF;
END
$function$;

REVOKE ALL ON FUNCTION managedservice.complete_audit_event(
    text, text, text, bigint, text, timestamptz, text
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION managedservice.complete_audit_event(
    text, text, text, bigint, text, timestamptz, text
) TO matrix_paas_worker;

CREATE OR REPLACE FUNCTION managedservice.audit_outbox_snapshot()
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
    SELECT count(*) FILTER (WHERE status = 'PENDING'),
           count(*) FILTER (WHERE status = 'LEASED'),
           count(*) FILTER (WHERE status = 'RETRY'),
           count(*) FILTER (WHERE status = 'DELIVERED'),
           count(*) FILTER (WHERE status = 'DEAD_LETTER'),
           count(*) FILTER (WHERE status = 'LEASED'
                AND lease_expires_at <= transaction_timestamp())
      FROM managedservice.audit_outbox
$function$;

REVOKE ALL ON FUNCTION managedservice.audit_outbox_snapshot() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION managedservice.audit_outbox_snapshot() TO matrix_paas_worker;

-- The result row grew with operation kind, protected result references and
-- installation version. PostgreSQL cannot replace a table-returning function
-- whose row shape changes, so the offline profile migration drops this one
-- worker entrypoint before recreating and re-granting it below.
DROP FUNCTION IF EXISTS managedservice.claim_operation(text, integer);
CREATE FUNCTION managedservice.claim_operation(
    requested_worker_id text,
    requested_lease_seconds integer
)
RETURNS TABLE (
    tenant_id text,
    operation_id text,
    operation_kind text,
    installation_id text,
    installation_name text,
    offering_id text,
    engine_version text,
    quota_entitlement_id text,
    region_id text,
    installation_endpoint text,
    installation_credential_reference text,
    quota_shape_id text,
    fencing_token bigint,
    attempt integer,
    created_at timestamptz,
    installation_resource_version bigint,
    observed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_lease_seconds IS NULL
       OR requested_lease_seconds NOT BETWEEN 1 AND 300 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'managed-service claim parameters are invalid';
    END IF;
    RETURN QUERY
    WITH candidate AS (
        SELECT pending.tenant_id, pending.id
          FROM managedservice.operations AS pending
          JOIN managedservice.service_installations AS installation
            ON installation.tenant_id = pending.tenant_id
           AND installation.current_operation_id = pending.id
         WHERE pending.phase IN ('PENDING', 'PROVISIONING')
           AND pending.attempts < 100
           AND pending.next_attempt_at <= transaction_timestamp()
           AND (pending.lease_owner IS NULL OR pending.lease_expires_at <= transaction_timestamp())
         ORDER BY pending.next_attempt_at, pending.observed_at,
                  pending.tenant_id COLLATE "C", pending.id COLLATE "C"
         LIMIT 1
         FOR UPDATE SKIP LOCKED
    ), claimed AS (
        UPDATE managedservice.operations AS operation
           SET phase = 'PROVISIONING',
               attempts = operation.attempts + 1,
               lease_owner = requested_worker_id,
               lease_expires_at = transaction_timestamp() + make_interval(secs => requested_lease_seconds),
               fencing_token = operation.fencing_token + 1,
               resource_version = operation.resource_version + 1,
               observed_at = transaction_timestamp()
          FROM candidate
         WHERE operation.tenant_id = candidate.tenant_id
           AND operation.id = candidate.id
         RETURNING operation.*
    ), marked AS (
        UPDATE managedservice.service_installations AS installation
           SET phase = CASE claimed.kind
                    WHEN 'PROVISION' THEN 'PROVISIONING'
                    WHEN 'TERMINATE' THEN 'TERMINATING'
                END,
               resource_version = installation.resource_version + 1,
               observed_at = transaction_timestamp()
          FROM claimed
         WHERE installation.tenant_id = claimed.tenant_id
           AND installation.id = claimed.installation_id
           AND installation.current_operation_id = claimed.id
         RETURNING installation.*
    )
    SELECT claimed.tenant_id,
           claimed.id,
           claimed.kind,
           marked.id,
           marked.name,
           marked.offering_id,
           marked.engine_version,
           marked.quota_entitlement_id,
           marked.region_id,
           marked.endpoint,
           marked.credential_reference,
           entitlement.quota_shape_id,
           claimed.fencing_token,
           claimed.attempts,
           marked.created_at,
           marked.resource_version,
           claimed.observed_at
      FROM claimed
      JOIN marked ON marked.tenant_id = claimed.tenant_id
                 AND marked.id = claimed.installation_id
      JOIN managedservice.quota_entitlements AS entitlement
        ON entitlement.tenant_id = marked.tenant_id
       AND entitlement.id = marked.quota_entitlement_id;
END
$function$;

CREATE OR REPLACE FUNCTION managedservice.complete_operation(
    requested_tenant_id text,
    requested_operation_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_endpoint text,
    requested_credential_reference text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    target_installation_id text;
    target_entitlement_id text;
BEGIN
    IF requested_endpoint IS NULL OR octet_length(requested_endpoint) NOT BETWEEN 1 AND 256
       OR strpos(requested_endpoint, chr(13)) <> 0 OR strpos(requested_endpoint, chr(10)) <> 0
       OR requested_credential_reference IS NULL
       OR requested_credential_reference COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'managed-service completion result is invalid';
    END IF;
    SELECT operation.installation_id, installation.quota_entitlement_id
      INTO target_installation_id, target_entitlement_id
      FROM managedservice.operations AS operation
      JOIN managedservice.service_installations AS installation
        ON installation.tenant_id = operation.tenant_id
       AND installation.id = operation.installation_id
      JOIN managedservice.quota_entitlements AS entitlement
        ON entitlement.tenant_id = installation.tenant_id
       AND entitlement.id = installation.quota_entitlement_id
     WHERE operation.tenant_id = requested_tenant_id
       AND operation.id = requested_operation_id
       AND operation.kind = 'PROVISION'
       AND operation.phase = 'PROVISIONING'
       AND operation.lease_owner = requested_worker_id
       AND operation.fencing_token = expected_fencing_token
       AND operation.lease_expires_at > transaction_timestamp()
       AND installation.current_operation_id = operation.id
     FOR UPDATE OF operation, installation, entitlement;
    IF target_installation_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'managed-service completion lease conflicts';
    END IF;
    UPDATE managedservice.quota_entitlements
       SET reserved_count = reserved_count - 1,
           consumed_count = consumed_count + 1,
           resource_version = resource_version + 1
     WHERE tenant_id = requested_tenant_id AND id = target_entitlement_id
       AND reserved_count > 0;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'managed-service quota completion conflicts';
    END IF;
    UPDATE managedservice.service_installations
       SET phase = 'READY', endpoint = requested_endpoint,
           credential_reference = requested_credential_reference,
           resource_version = resource_version + 1,
           observed_at = transaction_timestamp()
     WHERE tenant_id = requested_tenant_id AND id = target_installation_id;
    UPDATE managedservice.operations
       SET phase = 'READY', safe_failure_code = NULL,
           lease_owner = NULL, lease_expires_at = NULL,
           resource_version = resource_version + 1,
           observed_at = transaction_timestamp()
     WHERE tenant_id = requested_tenant_id AND id = requested_operation_id;
    INSERT INTO managedservice.audit_outbox (
        tenant_id, event_id, operation_id, status, available_at,
        attempts, fencing_token, created_at, updated_at, document
    )
    SELECT operation.tenant_id,
           'audit-' || md5('managedservice.service-installation.ready:' || operation.id),
           operation.id,
           'PENDING', transaction_timestamp(), 0, 0,
           transaction_timestamp(), transaction_timestamp(),
           jsonb_build_object(
                'schemaVersion', 'v1',
                'eventId', 'audit-' || md5(
                    'managedservice.service-installation.ready:' || operation.id
                ),
                'tenantId', operation.tenant_id,
                'actor', jsonb_build_object(
                    'type', operation.requested_by_type,
                    'id', operation.requested_by_id
                ),
                'iamDecisionId', operation.iam_decision_id,
                'action', 'managedservice.service-installation.ready',
                'target', jsonb_build_object(
                    'kind', 'ServiceInstallation',
                    'id', operation.installation_id
                ),
				'requestDigest', operation.request_digest,
                'result', 'SUCCEEDED',
                'requestId', operation.request_id,
                'occurredAt', to_char(
                    transaction_timestamp() AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
                )
           )
      FROM managedservice.operations AS operation
     WHERE operation.tenant_id = requested_tenant_id
       AND operation.id = requested_operation_id
       AND operation.phase = 'READY';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'managed-service ready Audit fact conflicts';
    END IF;
END
$function$;

CREATE OR REPLACE FUNCTION managedservice.complete_termination_operation(
    requested_tenant_id text,
    requested_operation_id text,
    requested_worker_id text,
    expected_fencing_token bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    target_installation_id text;
    target_entitlement_id text;
    target_quota_release text;
BEGIN
    SELECT operation.installation_id, installation.quota_entitlement_id,
           operation.quota_release
      INTO target_installation_id, target_entitlement_id, target_quota_release
      FROM managedservice.operations AS operation
      JOIN managedservice.service_installations AS installation
        ON installation.tenant_id = operation.tenant_id
       AND installation.id = operation.installation_id
      JOIN managedservice.quota_entitlements AS entitlement
        ON entitlement.tenant_id = installation.tenant_id
       AND entitlement.id = installation.quota_entitlement_id
     WHERE operation.tenant_id = requested_tenant_id
       AND operation.id = requested_operation_id
       AND operation.kind = 'TERMINATE'
       AND operation.phase = 'PROVISIONING'
       AND operation.lease_owner = requested_worker_id
       AND operation.fencing_token = expected_fencing_token
       AND operation.lease_expires_at > transaction_timestamp()
       AND installation.current_operation_id = operation.id
     FOR UPDATE OF operation, installation, entitlement;
    IF target_installation_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'managed-service termination lease conflicts';
    END IF;
    IF target_quota_release = 'CONSUMED' THEN
        UPDATE managedservice.quota_entitlements
           SET consumed_count = consumed_count - 1,
               resource_version = resource_version + 1
         WHERE tenant_id = requested_tenant_id AND id = target_entitlement_id
           AND consumed_count > 0;
    ELSIF target_quota_release = 'RESERVED' THEN
        UPDATE managedservice.quota_entitlements
           SET reserved_count = reserved_count - 1,
               resource_version = resource_version + 1
         WHERE tenant_id = requested_tenant_id AND id = target_entitlement_id
           AND reserved_count > 0;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'managed-service termination quota evidence conflicts';
    END IF;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'managed-service termination quota conflicts';
    END IF;
    UPDATE managedservice.service_installations
       SET phase = 'TERMINATED', endpoint = NULL, credential_reference = NULL,
           resource_version = resource_version + 1,
           observed_at = transaction_timestamp()
     WHERE tenant_id = requested_tenant_id AND id = target_installation_id;
    UPDATE managedservice.operations
       SET phase = 'READY', safe_failure_code = NULL,
           lease_owner = NULL, lease_expires_at = NULL,
           resource_version = resource_version + 1,
           observed_at = transaction_timestamp()
     WHERE tenant_id = requested_tenant_id AND id = requested_operation_id;
    INSERT INTO managedservice.audit_outbox (
        tenant_id, event_id, operation_id, status, available_at,
        attempts, fencing_token, created_at, updated_at, document
    )
    SELECT operation.tenant_id,
           'audit-' || md5('managedservice.service-installation.terminated:' || operation.id),
           operation.id, 'PENDING', transaction_timestamp(), 0, 0,
           transaction_timestamp(), transaction_timestamp(),
           jsonb_build_object(
                'schemaVersion', 'v1',
                'eventId', 'audit-' || md5(
                    'managedservice.service-installation.terminated:' || operation.id
                ),
                'tenantId', operation.tenant_id,
                'actor', jsonb_build_object(
                    'type', operation.requested_by_type,
                    'id', operation.requested_by_id
                ),
                'iamDecisionId', operation.iam_decision_id,
                'action', 'managedservice.service-installation.terminated',
                'target', jsonb_build_object(
                    'kind', 'ServiceInstallation',
                    'id', operation.installation_id
                ),
                'operationId', operation.id,
                'requestDigest', operation.request_digest,
                'result', 'SUCCEEDED',
                'requestId', operation.request_id,
                'occurredAt', to_char(
                    transaction_timestamp() AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
                )
           )
      FROM managedservice.operations AS operation
     WHERE operation.tenant_id = requested_tenant_id
       AND operation.id = requested_operation_id
       AND operation.phase = 'READY';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'managed-service terminated Audit fact conflicts';
    END IF;
END
$function$;

CREATE OR REPLACE FUNCTION managedservice.retry_operation(
    requested_tenant_id text,
    requested_operation_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_delay_seconds integer
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF requested_delay_seconds IS NULL OR requested_delay_seconds NOT BETWEEN 1 AND 300 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'managed-service retry delay is invalid';
    END IF;
    UPDATE managedservice.operations
       SET lease_owner = NULL, lease_expires_at = NULL,
           next_attempt_at = transaction_timestamp() + make_interval(secs => requested_delay_seconds),
           resource_version = resource_version + 1,
           observed_at = transaction_timestamp()
     WHERE tenant_id = requested_tenant_id
       AND id = requested_operation_id
       AND phase = 'PROVISIONING'
       AND lease_owner = requested_worker_id
       AND fencing_token = expected_fencing_token
       AND lease_expires_at > transaction_timestamp();
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'managed-service retry lease conflicts';
    END IF;
END
$function$;

CREATE OR REPLACE FUNCTION managedservice.fail_operation(
    requested_tenant_id text,
    requested_operation_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_failure_code text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    target_installation_id text;
    target_entitlement_id text;
    target_operation_kind text;
BEGIN
    IF requested_failure_code IS NULL
       OR requested_failure_code COLLATE "C" !~ '^[A-Z][A-Z0-9_]{1,63}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'managed-service failure code is invalid';
    END IF;
    SELECT operation.installation_id, installation.quota_entitlement_id,
           operation.kind
      INTO target_installation_id, target_entitlement_id, target_operation_kind
      FROM managedservice.operations AS operation
      JOIN managedservice.service_installations AS installation
        ON installation.tenant_id = operation.tenant_id
       AND installation.id = operation.installation_id
      JOIN managedservice.quota_entitlements AS entitlement
        ON entitlement.tenant_id = installation.tenant_id
       AND entitlement.id = installation.quota_entitlement_id
     WHERE operation.tenant_id = requested_tenant_id
       AND operation.id = requested_operation_id
       AND operation.phase = 'PROVISIONING'
       AND operation.lease_owner = requested_worker_id
       AND operation.fencing_token = expected_fencing_token
       AND operation.lease_expires_at > transaction_timestamp()
       AND installation.current_operation_id = operation.id
     FOR UPDATE OF operation, installation, entitlement;
    IF target_installation_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'managed-service failure lease conflicts';
    END IF;
    IF target_operation_kind = 'PROVISION' THEN
        UPDATE managedservice.quota_entitlements
           SET reserved_count = reserved_count - 1,
               resource_version = resource_version + 1
         WHERE tenant_id = requested_tenant_id AND id = target_entitlement_id
           AND reserved_count > 0;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'managed-service quota failure conflicts';
        END IF;
    END IF;
    UPDATE managedservice.service_installations
       SET phase = CASE target_operation_kind
                WHEN 'PROVISION' THEN 'FAILED'
                WHEN 'TERMINATE' THEN 'TERMINATION_FAILED'
            END,
           endpoint = CASE WHEN target_operation_kind = 'PROVISION' THEN NULL ELSE endpoint END,
           credential_reference = CASE WHEN target_operation_kind = 'PROVISION' THEN NULL ELSE credential_reference END,
           resource_version = resource_version + 1,
           observed_at = transaction_timestamp()
     WHERE tenant_id = requested_tenant_id AND id = target_installation_id;
    UPDATE managedservice.operations
       SET phase = 'FAILED', safe_failure_code = requested_failure_code,
           lease_owner = NULL, lease_expires_at = NULL,
           resource_version = resource_version + 1,
           observed_at = transaction_timestamp()
     WHERE tenant_id = requested_tenant_id AND id = requested_operation_id;
END
$function$;

CREATE OR REPLACE FUNCTION managedservice.fail_cleanup_operation(
    requested_tenant_id text,
    requested_operation_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_failure_code text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    target_installation_id text;
BEGIN
    IF requested_failure_code IS NULL
       OR requested_failure_code COLLATE "C" !~ '^[A-Z][A-Z0-9_]{1,63}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'managed-service cleanup failure code is invalid';
    END IF;
    SELECT operation.installation_id
      INTO target_installation_id
      FROM managedservice.operations AS operation
      JOIN managedservice.service_installations AS installation
        ON installation.tenant_id = operation.tenant_id
       AND installation.id = operation.installation_id
     WHERE operation.tenant_id = requested_tenant_id
       AND operation.id = requested_operation_id
       AND operation.kind = 'PROVISION'
       AND operation.phase = 'PROVISIONING'
       AND operation.lease_owner = requested_worker_id
       AND operation.fencing_token = expected_fencing_token
       AND operation.lease_expires_at > transaction_timestamp()
       AND installation.current_operation_id = operation.id
     FOR UPDATE OF operation, installation;
    IF target_installation_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'managed-service cleanup failure lease conflicts';
    END IF;
    UPDATE managedservice.service_installations
       SET phase = 'ROLLBACK_FAILED', endpoint = NULL, credential_reference = NULL,
           resource_version = resource_version + 1,
           observed_at = transaction_timestamp()
     WHERE tenant_id = requested_tenant_id AND id = target_installation_id;
    UPDATE managedservice.operations
       SET phase = 'FAILED', safe_failure_code = requested_failure_code,
           lease_owner = NULL, lease_expires_at = NULL,
           resource_version = resource_version + 1,
           observed_at = transaction_timestamp()
     WHERE tenant_id = requested_tenant_id AND id = requested_operation_id;
END
$function$;

REVOKE ALL ON FUNCTION managedservice.claim_operation(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION managedservice.complete_operation(text, text, text, bigint, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION managedservice.complete_termination_operation(text, text, text, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION managedservice.retry_operation(text, text, text, bigint, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION managedservice.fail_operation(text, text, text, bigint, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION managedservice.fail_cleanup_operation(text, text, text, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION managedservice.claim_operation(text, integer) TO matrix_paas_worker;
GRANT EXECUTE ON FUNCTION managedservice.complete_operation(text, text, text, bigint, text, text) TO matrix_paas_worker;
GRANT EXECUTE ON FUNCTION managedservice.complete_termination_operation(text, text, text, bigint) TO matrix_paas_worker;
GRANT EXECUTE ON FUNCTION managedservice.retry_operation(text, text, text, bigint, integer) TO matrix_paas_worker;
GRANT EXECUTE ON FUNCTION managedservice.fail_operation(text, text, text, bigint, text) TO matrix_paas_worker;
GRANT EXECUTE ON FUNCTION managedservice.fail_cleanup_operation(text, text, text, bigint, text) TO matrix_paas_worker;

REVOKE ALL ON ALL TABLES IN SCHEMA managedservice FROM PUBLIC;
GRANT SELECT ON managedservice.service_activations TO matrix_paas_api;
GRANT SELECT ON managedservice.quota_entitlements,
    managedservice.service_installations,
    managedservice.operations
    TO matrix_paas_api, matrix_paas_worker;
GRANT INSERT ON managedservice.service_activations TO matrix_paas_api;
GRANT INSERT, UPDATE ON managedservice.quota_entitlements TO matrix_paas_api;
GRANT INSERT ON managedservice.service_installations TO matrix_paas_api;
GRANT INSERT ON managedservice.operations TO matrix_paas_api;

COMMIT;
