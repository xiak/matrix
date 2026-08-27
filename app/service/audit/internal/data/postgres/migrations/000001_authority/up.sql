BEGIN;
SET LOCAL ROLE matrix_audit_owner;

REVOKE ALL ON SCHEMA audit FROM PUBLIC;

CREATE OR REPLACE FUNCTION audit.current_chain_id()
RETURNS text
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT CASE
        WHEN current_setting('matrix.audit_chain_id', true)
            COLLATE "C" ~ '^(tenant:|installation:)[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        THEN current_setting('matrix.audit_chain_id', true)
        ELSE NULL
    END
$function$;

-- Existing tenant facts retain their bytes, sequence and hashes. Only storage
-- partition metadata changes; immutable records are never updated or copied.
DO $matrix_audit_partition_upgrade$
BEGIN
    IF to_regclass('audit.tenant_heads') IS NOT NULL THEN
        ALTER TABLE audit.tenant_heads RENAME TO chain_heads;
    END IF;
    IF to_regclass('audit.records') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'audit' AND table_name = 'records'
           AND column_name = 'chain_id'
    ) THEN
        ALTER TABLE audit.event_registry DROP CONSTRAINT event_registry_record_fk;
        ALTER TABLE audit.records DROP CONSTRAINT records_pkey;
        ALTER TABLE audit.chain_heads DROP CONSTRAINT tenant_heads_pkey;
        ALTER TABLE audit.chain_heads DROP CONSTRAINT tenant_heads_values_valid;
        ALTER TABLE audit.records DROP CONSTRAINT records_values_valid;
        ALTER TABLE audit.event_registry DROP CONSTRAINT event_registry_values_valid;
        ALTER TABLE audit.chain_heads
            ALTER COLUMN tenant_id DROP NOT NULL,
            ADD COLUMN installation_id text COLLATE "C",
            ADD COLUMN chain_id text COLLATE "C" GENERATED ALWAYS AS (
                CASE WHEN installation_id IS NOT NULL THEN 'installation:' || installation_id
                     ELSE 'tenant:' || tenant_id END
            ) STORED;
        ALTER TABLE audit.records
            ALTER COLUMN tenant_id DROP NOT NULL,
            ADD COLUMN installation_id text COLLATE "C",
            ADD COLUMN chain_id text COLLATE "C" GENERATED ALWAYS AS (
                CASE WHEN installation_id IS NOT NULL THEN 'installation:' || installation_id
                     ELSE 'tenant:' || tenant_id END
            ) STORED;
        ALTER TABLE audit.event_registry
            ALTER COLUMN tenant_id DROP NOT NULL,
            ADD COLUMN installation_id text COLLATE "C",
            ADD COLUMN chain_id text COLLATE "C" GENERATED ALWAYS AS (
                CASE WHEN installation_id IS NOT NULL THEN 'installation:' || installation_id
                     ELSE 'tenant:' || tenant_id END
            ) STORED;
        ALTER TABLE audit.chain_heads ADD PRIMARY KEY (chain_id);
        ALTER TABLE audit.records ADD PRIMARY KEY (chain_id, sequence);
        -- The preceding DDL holds ACCESS EXCLUSIVE locks until COMMIT. The
        -- non-superuser owner must see every retained row to validate the FK;
        -- restore forced RLS before another connection can access the table.
        ALTER TABLE audit.records NO FORCE ROW LEVEL SECURITY;
        ALTER TABLE audit.event_registry ADD CONSTRAINT event_registry_record_fk
            FOREIGN KEY (chain_id, sequence) REFERENCES audit.records (chain_id, sequence);
        ALTER TABLE audit.records FORCE ROW LEVEL SECURITY;
        DROP INDEX IF EXISTS audit.records_paas_operation_uq;
    END IF;
END
$matrix_audit_partition_upgrade$;

CREATE TABLE IF NOT EXISTS audit.chain_heads (
    tenant_id text COLLATE "C",
    installation_id text COLLATE "C",
    chain_id text COLLATE "C" GENERATED ALWAYS AS (
        CASE WHEN installation_id IS NOT NULL THEN 'installation:' || installation_id
             ELSE 'tenant:' || tenant_id END
    ) STORED PRIMARY KEY,
    last_sequence bigint NOT NULL DEFAULT 0,
    last_record_hash text COLLATE "C" NOT NULL DEFAULT
        'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    updated_at timestamptz(6) NOT NULL
);

CREATE TABLE IF NOT EXISTS audit.records (
    tenant_id text COLLATE "C",
    installation_id text COLLATE "C",
    chain_id text COLLATE "C" GENERATED ALWAYS AS (
        CASE WHEN installation_id IS NOT NULL THEN 'installation:' || installation_id
             ELSE 'tenant:' || tenant_id END
    ) STORED,
    sequence bigint NOT NULL,
    source text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    event_document jsonb NOT NULL,
    canonical_document text COLLATE "C" NOT NULL,
    content_digest text COLLATE "C" NOT NULL,
    previous_hash text COLLATE "C" NOT NULL,
    record_hash text COLLATE "C" NOT NULL,
    ingested_at timestamptz(6) NOT NULL,
    retention text COLLATE "C" NOT NULL,
    PRIMARY KEY (chain_id, sequence),
    CONSTRAINT records_event_uq UNIQUE (source, event_id)
);

CREATE TABLE IF NOT EXISTS audit.event_registry (
    source text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    tenant_id text COLLATE "C",
    installation_id text COLLATE "C",
    chain_id text COLLATE "C" GENERATED ALWAYS AS (
        CASE WHEN installation_id IS NOT NULL THEN 'installation:' || installation_id
             ELSE 'tenant:' || tenant_id END
    ) STORED,
    sequence bigint NOT NULL,
    canonical_document text COLLATE "C" NOT NULL,
    content_digest text COLLATE "C" NOT NULL,
    record_hash text COLLATE "C" NOT NULL,
    PRIMARY KEY (source, event_id),
    CONSTRAINT event_registry_record_fk FOREIGN KEY (
        chain_id, sequence
    ) REFERENCES audit.records (chain_id, sequence)
);

DO $matrix_audit_values$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['chain_heads', 'records', 'event_registry']
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_constraint
             WHERE conrelid = ('audit.' || table_name)::regclass
               AND conname = table_name || '_authority_valid'
        ) THEN
            EXECUTE format(
                'ALTER TABLE audit.%I ADD CONSTRAINT %I CHECK ('
                '((tenant_id IS NULL) <> (installation_id IS NULL)) '
                'AND (tenant_id IS NULL OR tenant_id COLLATE "C" ~ '
                '''^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'') '
                'AND (installation_id IS NULL OR installation_id COLLATE "C" ~ '
                '''^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$''))',
                table_name, table_name || '_authority_valid'
            );
        END IF;
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conrelid = 'audit.chain_heads'::regclass AND conname = 'chain_heads_values_valid') THEN
        ALTER TABLE audit.chain_heads ADD CONSTRAINT chain_heads_values_valid CHECK (
            last_sequence BETWEEN 0 AND 9007199254740991
            AND last_record_hash COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
            AND (last_sequence > 0 OR last_record_hash =
                'sha256:0000000000000000000000000000000000000000000000000000000000000000')
        );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conrelid = 'audit.records'::regclass AND conname = 'records_values_valid') THEN
        ALTER TABLE audit.records ADD CONSTRAINT records_values_valid CHECK ((
            sequence BETWEEN 1 AND 9007199254740991
            AND source IN ('IAM', 'PAAS', 'AUDIT')
            AND event_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND length(canonical_document) BETWEEN 1 AND 131072
            AND canonical_document LIKE '{"canonicalVersion":"matrix.audit.canonical-event.v1",%'
            AND content_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
            AND previous_hash COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
            AND record_hash COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
            AND retention = 'INDEFINITE'
            AND event_document->>'apiVersion' = 'audit.matrix.xiak.com/v1'
            AND event_document->>'kind' = 'AuditEvent'
            AND event_document->>'eventId' = event_id
            AND (event_document->>'tenantId') IS NOT DISTINCT FROM tenant_id
            AND (event_document->>'installationId') IS NOT DISTINCT FROM installation_id
            AND (event_document ? 'tenantId') = (tenant_id IS NOT NULL)
            AND (event_document ? 'installationId') = (installation_id IS NOT NULL)
        ) IS TRUE);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conrelid = 'audit.event_registry'::regclass AND conname = 'event_registry_values_valid') THEN
        ALTER TABLE audit.event_registry ADD CONSTRAINT event_registry_values_valid CHECK (
            source IN ('IAM', 'PAAS', 'AUDIT')
            AND event_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND sequence BETWEEN 1 AND 9007199254740991
            AND content_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
            AND record_hash COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        );
    END IF;
END
$matrix_audit_values$;

DROP INDEX IF EXISTS audit.records_tenant_time_desc_idx;
DROP INDEX IF EXISTS audit.records_tenant_action_desc_idx;
DROP INDEX IF EXISTS audit.records_tenant_actor_desc_idx;
CREATE INDEX IF NOT EXISTS records_chain_time_desc_idx
    ON audit.records (chain_id, ingested_at DESC, sequence DESC);
CREATE INDEX IF NOT EXISTS records_chain_action_desc_idx
    ON audit.records (chain_id, (event_document->>'action'), sequence DESC);
CREATE INDEX IF NOT EXISTS records_chain_actor_desc_idx
    ON audit.records (chain_id, (event_document#>>'{actor,id}'), sequence DESC);
CREATE UNIQUE INDEX IF NOT EXISTS records_paas_operation_uq
    ON audit.records (chain_id, (event_document->>'operationId')) WHERE source = 'PAAS';

ALTER TABLE audit.chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.chain_heads FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.records ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.records FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON audit.chain_heads;
DROP POLICY IF EXISTS tenant_isolation ON audit.records;
DROP FUNCTION IF EXISTS audit.current_tenant_id();
DO $matrix_audit_policies$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['chain_heads', 'records']
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_policies
             WHERE schemaname = 'audit' AND tablename = table_name
               AND policyname = 'authority_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY authority_isolation ON audit.%I '
                'USING (chain_id = audit.current_chain_id()) '
                'WITH CHECK (chain_id = audit.current_chain_id())',
                table_name
            );
        END IF;
    END LOOP;
END
$matrix_audit_policies$;

DROP FUNCTION IF EXISTS audit.lock_tenant_head(text);
DROP FUNCTION IF EXISTS audit.assert_event(text, text, text, jsonb);
DROP FUNCTION IF EXISTS audit.calculate_record_hash(text, bigint, text, text, timestamptz, text);
DROP FUNCTION IF EXISTS audit.append_record(text, text, text, bigint, jsonb, text, text, text, text, timestamptz);
DROP FUNCTION IF EXISTS audit.read_records(text, bigint, integer, timestamptz, timestamptz, text, text, text);
DROP FUNCTION IF EXISTS audit.read_checkpoint(text, bigint);
DROP FUNCTION IF EXISTS audit.lookup_paas_operation_record(text, text);
DROP FUNCTION IF EXISTS audit.read_chain(text, bigint, integer);

CREATE OR REPLACE FUNCTION audit.reject_record_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '42501',
        MESSAGE = 'Audit records are immutable';
END
$function$;

DROP TRIGGER IF EXISTS records_are_immutable ON audit.records;
CREATE TRIGGER records_are_immutable
BEFORE UPDATE OR DELETE ON audit.records
FOR EACH ROW EXECUTE FUNCTION audit.reject_record_mutation();

DROP TRIGGER IF EXISTS records_cannot_be_truncated ON audit.records;
CREATE TRIGGER records_cannot_be_truncated
BEFORE TRUNCATE ON audit.records
FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_record_mutation();

CREATE OR REPLACE FUNCTION audit.assert_event(
    submitted_source text,
    submitted_event_id text,
    submitted_chain_id text,
    submitted_event jsonb
)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    expected_source text;
    expected_target_kind text;
    expected_result text;
    iam_decision_permitted boolean;
    iam_decision_required boolean;
    operation_required boolean;
    action_name text;
    platform_only boolean;
BEGIN
    action_name := submitted_event->>'action';
    platform_only := action_name IN (
        'paas.execution-pool.created', 'paas.execution-target.registered',
        'audit.platform-records.read', 'audit.platform-integrity.verified'
    );
    SELECT contract.source, contract.target_kind, contract.result,
           contract.iam_permitted, contract.iam_required,
           contract.operation_required
      INTO expected_source, expected_target_kind, expected_result,
           iam_decision_permitted, iam_decision_required,
           operation_required
      FROM (VALUES
        ('iam.bootstrap.applied', 'IAM', 'INSTALLATION', 'SUCCEEDED', false, false, false),
        ('iam.session.issued', 'IAM', 'SESSION', 'SUCCEEDED', false, false, false),
        ('iam.session.revoked', 'IAM', 'SESSION', 'SUCCEEDED', true, false, false),
        ('iam.password.changed', 'IAM', 'PRINCIPAL', 'SUCCEEDED', false, false, false),
        ('iam.principal.created', 'IAM', 'PRINCIPAL', 'SUCCEEDED', true, true, false),
        ('iam.role-binding.put', 'IAM', 'ROLE_BINDING', 'SUCCEEDED', true, true, false),
        ('iam.role-binding.revoked', 'IAM', 'ROLE_BINDING', 'SUCCEEDED', true, true, false),
        ('iam.authorization.decided', 'IAM', 'AUTHORIZATION_DECISION', NULL, true, true, false),
        ('paas.application.created', 'PAAS', 'APPLICATION', 'SUCCEEDED', true, true, true),
        ('paas.configuration.created', 'PAAS', 'CONFIGURATION', 'SUCCEEDED', true, true, true),
        ('paas.configuration-revision.created', 'PAAS', 'CONFIGURATION_REVISION', 'SUCCEEDED', true, true, true),
        ('paas.application-revision.created', 'PAAS', 'APPLICATION_REVISION', 'SUCCEEDED', true, true, true),
        ('paas.deployment.created', 'PAAS', 'DEPLOYMENT', 'ACCEPTED', true, true, true),
        ('paas.deployment.updated', 'PAAS', 'DEPLOYMENT', 'ACCEPTED', true, true, true),
        ('paas.deployment.stopped', 'PAAS', 'DEPLOYMENT', 'ACCEPTED', true, true, true),
        ('paas.deployment.rolled-back', 'PAAS', 'DEPLOYMENT', 'ACCEPTED', true, true, true),
        ('managedservice.quota-entitlement.activated', 'PAAS', 'QUOTA_ENTITLEMENT', 'SUCCEEDED', true, true, false),
        ('managedservice.service-installation.created', 'PAAS', 'SERVICE_INSTALLATION', 'ACCEPTED', true, true, true),
        ('managedservice.service-installation.ready', 'PAAS', 'SERVICE_INSTALLATION', 'SUCCEEDED', true, true, false),
        ('audit.records.read', 'AUDIT', 'AUDIT_RECORDS', 'SUCCEEDED', true, true, false),
        ('audit.integrity.verified', 'AUDIT', 'AUDIT_CHAIN', 'SUCCEEDED', true, true, false),
        ('paas.execution-pool.created', 'PAAS', 'EXECUTION_POOL', 'SUCCEEDED', true, true, true),
        ('paas.execution-target.registered', 'PAAS', 'EXECUTION_TARGET', 'SUCCEEDED', true, true, true),
        ('audit.platform-records.read', 'AUDIT', 'AUDIT_RECORDS', 'SUCCEEDED', true, true, false),
        ('audit.platform-integrity.verified', 'AUDIT', 'AUDIT_CHAIN', 'SUCCEEDED', true, true, false)
      ) AS contract(
        action, source, target_kind, result, iam_permitted,
        iam_required, operation_required
      )
     WHERE contract.action = action_name;
    IF action_name = 'iam.authorization.decided' THEN
        IF submitted_event->>'result' IN ('ALLOWED', 'DENIED') THEN
            expected_result := submitted_event->>'result';
        END IF;
    END IF;
    IF jsonb_typeof(submitted_event) <> 'object'
       OR jsonb_typeof(submitted_event->'actor') <> 'object'
       OR jsonb_typeof(submitted_event->'target') <> 'object'
       OR jsonb_typeof(submitted_event->'apiVersion') <> 'string'
       OR jsonb_typeof(submitted_event->'kind') <> 'string'
       OR jsonb_typeof(submitted_event->'eventId') <> 'string'
       OR jsonb_typeof(submitted_event->'action') <> 'string'
       OR jsonb_typeof(submitted_event->'result') <> 'string'
       OR jsonb_typeof(submitted_event->'requestDigest') <> 'string'
       OR jsonb_typeof(submitted_event->'requestId') <> 'string'
       OR jsonb_typeof(submitted_event->'correlationId') <> 'string'
       OR jsonb_typeof(submitted_event->'occurredAt') <> 'string'
       OR NOT (submitted_event ?& ARRAY[
            'apiVersion', 'kind', 'eventId', 'actor', 'action',
            'target', 'result', 'requestDigest', 'requestId',
            'correlationId', 'occurredAt'
       ])
       OR NOT ((submitted_event->'actor') ?& ARRAY['type', 'id'])
       OR NOT ((submitted_event->'target') ?& ARRAY['kind', 'id'])
       OR (submitted_event - ARRAY[
            'apiVersion', 'kind', 'eventId', 'tenantId', 'installationId', 'actor',
            'iamDecisionId', 'action', 'target', 'result', 'requestDigest',
            'requestId', 'correlationId', 'operationId', 'traceparent',
            'occurredAt'
       ]) <> '{}'::jsonb
       OR ((submitted_event->'actor') - ARRAY['type', 'id']) <> '{}'::jsonb
       OR ((submitted_event->'target') - ARRAY['kind', 'id']) <> '{}'::jsonb
       OR jsonb_typeof(submitted_event#>'{actor,type}') <> 'string'
       OR jsonb_typeof(submitted_event#>'{actor,id}') <> 'string'
       OR jsonb_typeof(submitted_event#>'{target,kind}') <> 'string'
       OR jsonb_typeof(submitted_event#>'{target,id}') <> 'string'
       OR (submitted_event ? 'iamDecisionId'
            AND jsonb_typeof(submitted_event->'iamDecisionId') <> 'string')
       OR (submitted_event ? 'operationId'
            AND jsonb_typeof(submitted_event->'operationId') <> 'string')
       OR (submitted_event ? 'traceparent'
            AND jsonb_typeof(submitted_event->'traceparent') <> 'string')
       OR octet_length(submitted_event::text) > 131072
       OR submitted_event->>'apiVersion' IS DISTINCT FROM 'audit.matrix.xiak.com/v1'
       OR submitted_event->>'kind' IS DISTINCT FROM 'AuditEvent'
       OR submitted_event->>'eventId' IS DISTINCT FROM submitted_event_id
       OR (platform_only AND (
            left(submitted_chain_id, 13) IS DISTINCT FROM 'installation:'
            OR jsonb_typeof(submitted_event->'installationId') IS DISTINCT FROM 'string'
            OR submitted_event->>'installationId' IS DISTINCT FROM substr(submitted_chain_id, 14)
            OR submitted_event ? 'tenantId'
            OR submitted_event#>>'{actor,type}' IS DISTINCT FROM 'USER'
          ))
       OR (NOT platform_only AND (
            left(submitted_chain_id, 7) IS DISTINCT FROM 'tenant:'
            OR jsonb_typeof(submitted_event->'tenantId') IS DISTINCT FROM 'string'
            OR submitted_event->>'tenantId' IS DISTINCT FROM substr(submitted_chain_id, 8)
            OR submitted_event ? 'installationId'
          ))
       OR submitted_source IS DISTINCT FROM expected_source
       OR submitted_event#>>'{target,kind}' IS DISTINCT FROM expected_target_kind
       OR submitted_event->>'result' IS DISTINCT FROM expected_result
       OR COALESCE(submitted_event_id, '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_chain_id, '') COLLATE "C"
            !~ '^(tenant:|installation:)[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_event#>>'{actor,id}', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_event#>>'{actor,type}' NOT IN ('USER', 'SERVICE_ACCOUNT', 'SYSTEM')
       OR COALESCE(submitted_event#>>'{target,id}', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_event->>'requestDigest', '') COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR COALESCE(submitted_event->>'requestId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_event->>'correlationId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR (submitted_event ? 'iamDecisionId' AND
            COALESCE(submitted_event->>'iamDecisionId', '') COLLATE "C"
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
       OR (submitted_event ? 'operationId' AND
            COALESCE(submitted_event->>'operationId', '') COLLATE "C"
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
       OR (submitted_event ? 'traceparent' AND (
            COALESCE(submitted_event->>'traceparent', '') COLLATE "C"
                !~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'
            OR split_part(submitted_event->>'traceparent', '-', 2) = repeat('0', 32)
            OR split_part(submitted_event->>'traceparent', '-', 3) = repeat('0', 16)
       ))
       OR COALESCE(submitted_event->>'occurredAt', '') COLLATE "C"
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
       OR NOT pg_input_is_valid(
            COALESCE(submitted_event->>'occurredAt', ''), 'timestamptz'
       )
       OR (iam_decision_required AND NOT (submitted_event ? 'iamDecisionId'))
       OR (NOT iam_decision_permitted AND submitted_event ? 'iamDecisionId')
       OR (operation_required AND NOT (submitted_event ? 'operationId'))
       OR (NOT operation_required AND submitted_event ? 'operationId')
       OR (action_name = 'iam.authorization.decided'
            AND submitted_event#>>'{target,id}' IS DISTINCT FROM
                submitted_event->>'iamDecisionId') THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'closed sanitized Audit event is invalid';
    END IF;
END
$function$;

CREATE OR REPLACE FUNCTION audit.readiness()
RETURNS TABLE (ready boolean, schema_version bigint, checked_at timestamptz)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT
        to_regclass('audit.chain_heads') IS NOT NULL
        AND to_regclass('audit.records') IS NOT NULL
        AND to_regclass('audit.event_registry') IS NOT NULL,
        2::bigint,
        transaction_timestamp()
$function$;

CREATE OR REPLACE FUNCTION audit.lock_event(
    submitted_source text,
    submitted_event_id text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF submitted_source NOT IN ('IAM', 'PAAS', 'AUDIT')
       OR COALESCE(submitted_event_id, '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Audit event identity is invalid';
    END IF;
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'matrix.audit.event.v1:' || submitted_source || ':' || submitted_event_id,
            0
        )
    );
END
$function$;

DROP FUNCTION IF EXISTS audit.lookup_event(text, text);
CREATE OR REPLACE FUNCTION audit.lookup_record(
    submitted_source text,
    submitted_event_id text
)
RETURNS SETOF audit.records
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    stored_chain_id text;
    stored_sequence bigint;
BEGIN
    IF submitted_source NOT IN ('IAM', 'PAAS', 'AUDIT')
       OR COALESCE(submitted_event_id, '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Audit event identity is invalid';
    END IF;
    SELECT registry.chain_id, registry.sequence
      INTO stored_chain_id, stored_sequence
      FROM audit.event_registry AS registry
     WHERE registry.source = submitted_source
       AND registry.event_id = submitted_event_id;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    PERFORM set_config('matrix.audit_chain_id', stored_chain_id, true);
    RETURN QUERY
    SELECT record.*
      FROM audit.records AS record
     WHERE record.chain_id = stored_chain_id
       AND record.sequence = stored_sequence;
END
$function$;

CREATE OR REPLACE FUNCTION audit.calculate_record_hash(
    submitted_chain_id text,
    submitted_sequence bigint,
    submitted_content_digest text,
    submitted_previous_hash text,
    submitted_ingested_at timestamptz,
    submitted_retention text
)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT 'sha256:' || encode(
        sha256(
            convert_to(CASE WHEN left(submitted_chain_id, 13) = 'installation:'
                THEN 'matrix.audit.record.platform.v1' ELSE 'matrix.audit.record.v1' END, 'UTF8')
            || decode('00', 'hex')
            || int4send(octet_length(substr(submitted_chain_id, strpos(submitted_chain_id, ':') + 1)))
            || convert_to(substr(submitted_chain_id, strpos(submitted_chain_id, ':') + 1), 'UTF8')
            || int8send(submitted_sequence)
            || decode(substr(submitted_content_digest, 8), 'hex')
            || decode(substr(submitted_previous_hash, 8), 'hex')
            || int4send(27)
            || convert_to(
                to_char(
                    submitted_ingested_at AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
                ),
                'UTF8'
            )
            || int4send(octet_length(submitted_retention))
            || convert_to(submitted_retention, 'UTF8')
        ),
        'hex'
    )
$function$;

CREATE OR REPLACE FUNCTION audit.lock_chain_head(submitted_chain_id text)
RETURNS TABLE (
    last_sequence bigint,
    last_record_hash text,
    ingested_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF COALESCE(submitted_chain_id, '') COLLATE "C"
            !~ '^(tenant:|installation:)[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Audit authority identity is invalid';
    END IF;
    PERFORM set_config('matrix.audit_chain_id', submitted_chain_id, true);
    INSERT INTO audit.chain_heads (
        tenant_id, installation_id, last_sequence, last_record_hash, updated_at
    ) VALUES (
        CASE WHEN left(submitted_chain_id, 7) = 'tenant:' THEN substr(submitted_chain_id, 8) END,
        CASE WHEN left(submitted_chain_id, 13) = 'installation:' THEN substr(submitted_chain_id, 14) END,
        0,
        'sha256:0000000000000000000000000000000000000000000000000000000000000000',
        transaction_timestamp()
    ) ON CONFLICT (chain_id) DO NOTHING;
    RETURN QUERY
    SELECT head.last_sequence, head.last_record_hash,
           transaction_timestamp()
      FROM audit.chain_heads AS head
     WHERE head.chain_id = submitted_chain_id
     FOR UPDATE;
END
$function$;

CREATE OR REPLACE FUNCTION audit.append_record(
    submitted_source text,
    submitted_event_id text,
    submitted_chain_id text,
    submitted_sequence bigint,
    submitted_event_document jsonb,
    submitted_canonical_document text,
    submitted_content_digest text,
    submitted_previous_hash text,
    submitted_record_hash text,
    submitted_ingested_at timestamptz
)
RETURNS TABLE (
    outcome text,
    stored_sequence bigint,
    stored_record_hash text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    existing audit.event_registry%ROWTYPE;
    head audit.chain_heads%ROWTYPE;
    canonical jsonb;
BEGIN
    PERFORM audit.assert_event(
        submitted_source, submitted_event_id,
        submitted_chain_id, submitted_event_document
    );
    SELECT * INTO existing
      FROM audit.event_registry
     WHERE source = submitted_source AND event_id = submitted_event_id;
    IF FOUND THEN
        IF existing.chain_id = submitted_chain_id
           AND existing.canonical_document = submitted_canonical_document
           AND existing.content_digest = submitted_content_digest
           AND ((existing.canonical_document::jsonb->'event') - 'occurredAt') =
               (submitted_event_document - 'occurredAt')
           AND (existing.canonical_document::jsonb#>>'{event,occurredAt}')::timestamptz =
               (submitted_event_document->>'occurredAt')::timestamptz THEN
            RETURN QUERY SELECT 'DUPLICATE', existing.sequence, existing.record_hash;
            RETURN;
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            MESSAGE = 'Audit event replay content conflicts';
    END IF;
    IF NOT pg_input_is_valid(submitted_canonical_document, 'jsonb') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Audit canonical document is invalid';
    END IF;
    canonical := submitted_canonical_document::jsonb;
    IF submitted_sequence IS NULL
       OR submitted_sequence NOT BETWEEN 1 AND 9007199254740991
       OR COALESCE(submitted_content_digest, '') COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR COALESCE(submitted_previous_hash, '') COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR COALESCE(submitted_record_hash, '') COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR length(submitted_canonical_document) NOT BETWEEN 1 AND 131072
       OR submitted_canonical_document NOT LIKE
            '{"canonicalVersion":"matrix.audit.canonical-event.v1",%'
       OR jsonb_typeof(canonical) <> 'object'
       OR jsonb_typeof(canonical->'event') <> 'object'
       OR (canonical - ARRAY['canonicalVersion', 'source', 'event']) <> '{}'::jsonb
       OR canonical->>'canonicalVersion' IS DISTINCT FROM
            'matrix.audit.canonical-event.v1'
       OR canonical->>'source' IS DISTINCT FROM submitted_source
       OR canonical#>>'{event,eventId}' IS DISTINCT FROM submitted_event_id
       OR ((canonical->'event') - 'occurredAt') IS DISTINCT FROM
            (submitted_event_document - 'occurredAt')
       OR COALESCE(canonical#>>'{event,occurredAt}', '') COLLATE "C"
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{6}Z$'
       OR NOT pg_input_is_valid(
            COALESCE(canonical#>>'{event,occurredAt}', ''), 'timestamptz'
       )
       OR submitted_content_digest IS DISTINCT FROM 'sha256:' || encode(
            sha256(convert_to(submitted_canonical_document, 'UTF8')),
            'hex'
       )
       OR submitted_ingested_at IS NULL
       OR submitted_record_hash IS DISTINCT FROM audit.calculate_record_hash(
            submitted_chain_id,
            submitted_sequence,
            submitted_content_digest,
            submitted_previous_hash,
            submitted_ingested_at,
            'INDEFINITE'
       )
       OR submitted_ingested_at IS DISTINCT FROM transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Audit record input is invalid';
    END IF;
    IF (canonical#>>'{event,occurredAt}')::timestamptz IS DISTINCT FROM
       (submitted_event_document->>'occurredAt')::timestamptz THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Audit event time is not canonical';
    END IF;
    PERFORM set_config('matrix.audit_chain_id', submitted_chain_id, true);
    SELECT * INTO head
      FROM audit.chain_heads
     WHERE chain_id = submitted_chain_id
     FOR UPDATE;
    IF NOT FOUND
       OR submitted_sequence <> head.last_sequence + 1
       OR submitted_previous_hash <> head.last_record_hash THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Audit chain head is stale';
    END IF;
    INSERT INTO audit.records (
        tenant_id, installation_id, sequence, source, event_id, event_document,
        canonical_document, content_digest, previous_hash, record_hash,
        ingested_at, retention
    ) VALUES (
        submitted_event_document->>'tenantId', submitted_event_document->>'installationId',
        submitted_sequence, submitted_source, submitted_event_id, submitted_event_document,
        submitted_canonical_document, submitted_content_digest,
        submitted_previous_hash, submitted_record_hash,
        submitted_ingested_at, 'INDEFINITE'
    );
    INSERT INTO audit.event_registry (
        source, event_id, tenant_id, installation_id, sequence, canonical_document,
        content_digest, record_hash
    ) VALUES (
        submitted_source, submitted_event_id,
        submitted_event_document->>'tenantId', submitted_event_document->>'installationId',
        submitted_sequence, submitted_canonical_document,
        submitted_content_digest, submitted_record_hash
    );
    UPDATE audit.chain_heads
       SET last_sequence = submitted_sequence,
           last_record_hash = submitted_record_hash,
           updated_at = submitted_ingested_at
     WHERE chain_id = submitted_chain_id;
    RETURN QUERY SELECT 'ACCEPTED', submitted_sequence, submitted_record_hash;
END
$function$;

DROP FUNCTION IF EXISTS audit.read_records(text, bigint, integer);
CREATE OR REPLACE FUNCTION audit.read_records(
    submitted_chain_id text,
    submitted_before_sequence bigint,
    submitted_page_size integer,
    submitted_from timestamptz,
    submitted_to timestamptz,
    submitted_action text,
    submitted_actor_type text,
    submitted_actor_id text
)
RETURNS SETOF audit.records
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF COALESCE(submitted_chain_id, '') COLLATE "C"
            !~ '^(tenant:|installation:)[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_before_sequence IS NULL
       OR submitted_before_sequence NOT BETWEEN 1 AND 9007199254740992
       OR submitted_page_size IS NULL
       OR submitted_page_size NOT BETWEEN 1 AND 201
       OR (submitted_from IS NOT NULL AND submitted_to IS NOT NULL
            AND submitted_to < submitted_from)
       OR (submitted_action IS NOT NULL AND submitted_action NOT IN (
            'iam.bootstrap.applied', 'iam.session.issued',
            'iam.session.revoked', 'iam.password.changed',
            'iam.principal.created', 'iam.role-binding.put',
            'iam.role-binding.revoked', 'iam.authorization.decided',
            'paas.application.created', 'paas.configuration.created',
            'paas.configuration-revision.created',
            'paas.application-revision.created', 'paas.deployment.created',
            'paas.deployment.updated', 'paas.deployment.stopped',
            'paas.deployment.rolled-back',
            'managedservice.quota-entitlement.activated',
            'managedservice.service-installation.created',
            'managedservice.service-installation.ready', 'audit.records.read',
            'audit.integrity.verified',
            'paas.execution-pool.created', 'paas.execution-target.registered',
            'audit.platform-records.read', 'audit.platform-integrity.verified'
       ))
       OR ((submitted_actor_type IS NULL) <> (submitted_actor_id IS NULL))
       OR (submitted_actor_type IS NOT NULL AND submitted_actor_type NOT IN (
            'USER', 'SERVICE_ACCOUNT', 'SYSTEM'
       ))
       OR (submitted_actor_id IS NOT NULL AND submitted_actor_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Audit query input is invalid';
    END IF;
    PERFORM set_config('matrix.audit_chain_id', submitted_chain_id, true);
    RETURN QUERY
    SELECT record.*
      FROM audit.records AS record
     WHERE record.chain_id = submitted_chain_id
       AND record.sequence < submitted_before_sequence
       AND (
            submitted_from IS NULL
            OR (record.event_document->>'occurredAt')::timestamptz >= submitted_from
       )
       AND (
            submitted_to IS NULL
            OR (record.event_document->>'occurredAt')::timestamptz <= submitted_to
       )
       AND (
            submitted_action IS NULL
            OR record.event_document->>'action' = submitted_action
       )
       AND (
            submitted_actor_type IS NULL
            OR (
                record.event_document#>>'{actor,type}' = submitted_actor_type
                AND record.event_document#>>'{actor,id}' = submitted_actor_id
            )
       )
     ORDER BY record.sequence DESC
     LIMIT submitted_page_size;
END
$function$;

CREATE OR REPLACE FUNCTION audit.read_checkpoint(
    submitted_chain_id text,
    submitted_sequence bigint
)
RETURNS TABLE (record_hash text)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF COALESCE(submitted_chain_id, '') COLLATE "C"
            !~ '^(tenant:|installation:)[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_sequence IS NULL
       OR submitted_sequence NOT BETWEEN 1 AND 9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Audit checkpoint input is invalid';
    END IF;
    PERFORM set_config('matrix.audit_chain_id', submitted_chain_id, true);
    RETURN QUERY
    SELECT record.record_hash
      FROM audit.records AS record
     WHERE record.chain_id = submitted_chain_id
       AND record.sequence = submitted_sequence;
END
$function$;

CREATE OR REPLACE FUNCTION audit.lookup_paas_operation_record(
    submitted_chain_id text,
    submitted_operation_id text
)
RETURNS SETOF audit.records
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF COALESCE(submitted_chain_id, '') COLLATE "C"
            !~ '^(tenant:|installation:)[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_operation_id, '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'PaaS Audit operation lookup is invalid';
    END IF;
    PERFORM set_config('matrix.audit_chain_id', submitted_chain_id, true);
    RETURN QUERY
    SELECT record.*
      FROM audit.records AS record
     WHERE record.chain_id = submitted_chain_id
       AND record.source = 'PAAS'
       AND record.event_document->>'operationId' = submitted_operation_id;
END
$function$;

CREATE OR REPLACE FUNCTION audit.read_chain(
    submitted_chain_id text,
    submitted_from_sequence bigint,
    submitted_maximum_records integer
)
RETURNS SETOF audit.records
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF COALESCE(submitted_chain_id, '') COLLATE "C"
            !~ '^(tenant:|installation:)[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_from_sequence IS NULL
       OR submitted_from_sequence NOT BETWEEN 1 AND 9007199254740991
       OR submitted_maximum_records IS NULL
       OR submitted_maximum_records NOT BETWEEN 1 AND 10001 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Audit chain input is invalid';
    END IF;
    PERFORM set_config('matrix.audit_chain_id', submitted_chain_id, true);
    RETURN QUERY
    SELECT record.*
      FROM audit.records AS record
     WHERE record.chain_id = submitted_chain_id
       AND record.sequence >= submitted_from_sequence
     ORDER BY record.sequence
     LIMIT submitted_maximum_records;
END
$function$;

REVOKE ALL ON ALL TABLES IN SCHEMA audit FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA audit FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA audit FROM matrix_audit_runtime;
REVOKE ALL ON SCHEMA audit FROM matrix_audit_runtime;
GRANT USAGE ON SCHEMA audit TO matrix_audit_runtime;
GRANT EXECUTE ON FUNCTION audit.readiness()
    TO matrix_audit_runtime;
GRANT EXECUTE ON FUNCTION audit.lock_event(text, text)
    TO matrix_audit_runtime;
GRANT EXECUTE ON FUNCTION audit.lookup_record(text, text)
    TO matrix_audit_runtime;
GRANT EXECUTE ON FUNCTION audit.lock_chain_head(text)
    TO matrix_audit_runtime;
GRANT EXECUTE ON FUNCTION audit.append_record(
    text, text, text, bigint, jsonb, text, text, text, text, timestamptz
) TO matrix_audit_runtime;
GRANT EXECUTE ON FUNCTION audit.read_records(
    text, bigint, integer, timestamptz, timestamptz, text, text, text
)
    TO matrix_audit_runtime;
GRANT EXECUTE ON FUNCTION audit.read_checkpoint(text, bigint)
    TO matrix_audit_runtime;
GRANT EXECUTE ON FUNCTION audit.lookup_paas_operation_record(text, text)
    TO matrix_audit_runtime;
GRANT EXECUTE ON FUNCTION audit.read_chain(text, bigint, integer)
    TO matrix_audit_runtime;

ALTER DEFAULT PRIVILEGES FOR ROLE matrix_audit_owner IN SCHEMA audit
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE matrix_audit_owner IN SCHEMA audit
    REVOKE ALL ON FUNCTIONS FROM PUBLIC;

COMMIT;
