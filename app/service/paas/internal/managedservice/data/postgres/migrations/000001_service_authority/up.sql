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
    ),
    CONSTRAINT quota_entitlements_catalog_valid CHECK (
        offering_id = 'postgresql-18'
        AND quota_shape_id IN ('pg-small', 'pg-medium')
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
        AND offering_id = 'postgresql-18'
        AND engine_version = '18'
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
        phase IN ('PENDING', 'PROVISIONING', 'READY', 'FAILED')
    ),
    CONSTRAINT service_installations_result_valid CHECK (
        (phase = 'READY' AND endpoint IS NOT NULL AND credential_reference IS NOT NULL)
        OR (phase <> 'READY' AND endpoint IS NULL AND credential_reference IS NULL)
    ),
    CONSTRAINT service_installations_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT service_installations_time_valid CHECK (observed_at >= created_at)
);

CREATE TABLE IF NOT EXISTS managedservice.operations (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    installation_id text COLLATE "C" NOT NULL,
    phase text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    safe_failure_code text COLLATE "C",
    idempotency_key text COLLATE "C" NOT NULL,
    request_digest text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL DEFAULT 1,
    attempts integer NOT NULL DEFAULT 0,
    lease_owner text COLLATE "C",
    lease_expires_at timestamptz(6),
    fencing_token bigint NOT NULL DEFAULT 0,
    next_attempt_at timestamptz(6) NOT NULL DEFAULT transaction_timestamp(),
    observed_at timestamptz(6) NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT operations_installation_uq UNIQUE (tenant_id, installation_id),
    CONSTRAINT operations_idempotency_uq UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT operations_installation_fk
        FOREIGN KEY (tenant_id, installation_id)
        REFERENCES managedservice.service_installations (tenant_id, id),
    CONSTRAINT managedservice_operations_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND installation_id COLLATE "C" ~ '^[a-z0-9][a-z0-9._-]{1,62}$'
        AND idempotency_key COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT managedservice_operations_phase_valid CHECK (
        phase IN ('PENDING', 'PROVISIONING', 'READY', 'FAILED')
        AND ((phase = 'FAILED') = (safe_failure_code IS NOT NULL))
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

ALTER TABLE managedservice.quota_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE managedservice.quota_entitlements FORCE ROW LEVEL SECURITY;
ALTER TABLE managedservice.service_installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE managedservice.service_installations FORCE ROW LEVEL SECURITY;
ALTER TABLE managedservice.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE managedservice.operations FORCE ROW LEVEL SECURITY;

DO $matrix_managedservice_policy$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'quota_entitlements', 'service_installations', 'operations'
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

CREATE OR REPLACE FUNCTION managedservice.claim_operation(
    requested_worker_id text,
    requested_lease_seconds integer
)
RETURNS TABLE (
    tenant_id text,
    operation_id text,
    installation_id text,
    installation_name text,
    offering_id text,
    engine_version text,
    quota_entitlement_id text,
    region_id text,
    quota_shape_id text,
    fencing_token bigint,
    attempt integer,
    created_at timestamptz,
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
           SET phase = 'PROVISIONING',
               resource_version = installation.resource_version + 1,
               observed_at = transaction_timestamp()
          FROM claimed
         WHERE installation.tenant_id = claimed.tenant_id
           AND installation.id = claimed.installation_id
         RETURNING installation.*
    )
    SELECT claimed.tenant_id,
           claimed.id,
           marked.id,
           marked.name,
           marked.offering_id,
           marked.engine_version,
           marked.quota_entitlement_id,
           marked.region_id,
           entitlement.quota_shape_id,
           claimed.fencing_token,
           claimed.attempts,
           marked.created_at,
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
       AND operation.phase = 'PROVISIONING'
       AND operation.lease_owner = requested_worker_id
       AND operation.fencing_token = expected_fencing_token
       AND operation.lease_expires_at > transaction_timestamp()
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
BEGIN
    IF requested_failure_code IS NULL
       OR requested_failure_code COLLATE "C" !~ '^[A-Z][A-Z0-9_]{1,63}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'managed-service failure code is invalid';
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
       AND operation.phase = 'PROVISIONING'
       AND operation.lease_owner = requested_worker_id
       AND operation.fencing_token = expected_fencing_token
       AND operation.lease_expires_at > transaction_timestamp()
     FOR UPDATE OF operation, installation, entitlement;
    IF target_installation_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'managed-service failure lease conflicts';
    END IF;
    UPDATE managedservice.quota_entitlements
       SET reserved_count = reserved_count - 1,
           resource_version = resource_version + 1
     WHERE tenant_id = requested_tenant_id AND id = target_entitlement_id
       AND reserved_count > 0;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'managed-service quota failure conflicts';
    END IF;
    UPDATE managedservice.service_installations
       SET phase = 'FAILED', endpoint = NULL, credential_reference = NULL,
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
REVOKE ALL ON FUNCTION managedservice.retry_operation(text, text, text, bigint, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION managedservice.fail_operation(text, text, text, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION managedservice.claim_operation(text, integer) TO matrix_paas_worker;
GRANT EXECUTE ON FUNCTION managedservice.complete_operation(text, text, text, bigint, text, text) TO matrix_paas_worker;
GRANT EXECUTE ON FUNCTION managedservice.retry_operation(text, text, text, bigint, integer) TO matrix_paas_worker;
GRANT EXECUTE ON FUNCTION managedservice.fail_operation(text, text, text, bigint, text) TO matrix_paas_worker;

REVOKE ALL ON ALL TABLES IN SCHEMA managedservice FROM PUBLIC;
GRANT SELECT ON managedservice.quota_entitlements,
    managedservice.service_installations,
    managedservice.operations
    TO matrix_paas_api, matrix_paas_worker;
GRANT INSERT, UPDATE ON managedservice.quota_entitlements TO matrix_paas_api;
GRANT INSERT ON managedservice.service_installations,
    managedservice.operations TO matrix_paas_api;

COMMIT;
