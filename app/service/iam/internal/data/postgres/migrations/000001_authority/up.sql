BEGIN;
SET LOCAL ROLE matrix_iam_owner;

REVOKE ALL ON SCHEMA iam FROM PUBLIC;

CREATE OR REPLACE FUNCTION iam.current_tenant_id()
RETURNS text
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT CASE
        WHEN current_setting('matrix.iam_tenant_id', true)
            COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        THEN current_setting('matrix.iam_tenant_id', true)
        ELSE NULL
    END
$function$;

CREATE TABLE IF NOT EXISTS iam.bootstrap_receipts (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    installation_id text COLLATE "C" NOT NULL UNIQUE,
    content_digest text COLLATE "C" NOT NULL,
    organization_id text COLLATE "C" NOT NULL,
    applied_at timestamptz(6) NOT NULL,
    CONSTRAINT bootstrap_receipts_identity_valid CHECK (
        installation_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND organization_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND content_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
    )
);

CREATE TABLE IF NOT EXISTS iam.organizations (
    id text COLLATE "C" PRIMARY KEY,
    display_name text NOT NULL,
    status text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    CONSTRAINT organizations_values_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND length(display_name) BETWEEN 1 AND 128
        AND btrim(display_name) = display_name
        AND status IN ('ACTIVE', 'DISABLED')
        AND resource_version BETWEEN 1 AND 9007199254740991
        AND updated_at >= created_at
    )
);

CREATE TABLE IF NOT EXISTS iam.principals (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    principal_type text COLLATE "C" NOT NULL,
    login_name text COLLATE "C",
    display_name text NOT NULL,
    status text COLLATE "C" NOT NULL,
    must_change_password boolean NOT NULL DEFAULT false,
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT principals_organization_fk FOREIGN KEY (tenant_id)
        REFERENCES iam.organizations (id),
    CONSTRAINT principals_login_uq UNIQUE (tenant_id, login_name),
    CONSTRAINT principals_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND principal_type IN ('USER', 'SERVICE_ACCOUNT')
        AND status IN ('ACTIVE', 'DISABLED')
        AND length(display_name) BETWEEN 1 AND 128
        AND btrim(display_name) = display_name
        AND resource_version BETWEEN 1 AND 9007199254740991
        AND updated_at >= created_at
        AND (
            (
                principal_type = 'USER'
                AND login_name COLLATE "C" ~ '^[a-z][a-z0-9._-]{2,63}$'
            )
            OR (
                principal_type = 'SERVICE_ACCOUNT'
                AND login_name IS NULL
                AND NOT must_change_password
            )
        )
    )
);

CREATE TABLE IF NOT EXISTS iam.role_bindings (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    principal_id text COLLATE "C" NOT NULL,
    role_name text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    revoked_at timestamptz(6),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT role_bindings_principal_fk FOREIGN KEY (tenant_id, principal_id)
        REFERENCES iam.principals (tenant_id, id),
    CONSTRAINT role_bindings_active_uq UNIQUE NULLS NOT DISTINCT (
        tenant_id, principal_id, role_name, revoked_at
    ),
    CONSTRAINT role_bindings_values_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND principal_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND role_name IN (
            'ORGANIZATION_ADMIN', 'PAAS_DEVELOPER', 'PAAS_VIEWER',
            'AUDIT_READER', 'INSTALLATION_VERIFIER'
        )
        AND resource_version BETWEEN 1 AND 9007199254740991
        AND updated_at >= created_at
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    )
);

CREATE TABLE IF NOT EXISTS iam.user_credentials (
    tenant_id text COLLATE "C" NOT NULL,
    principal_id text COLLATE "C" NOT NULL,
    password_hash text COLLATE "C" NOT NULL,
    changed_at timestamptz(6) NOT NULL,
    PRIMARY KEY (tenant_id, principal_id),
    CONSTRAINT user_credentials_principal_fk FOREIGN KEY (tenant_id, principal_id)
        REFERENCES iam.principals (tenant_id, id),
    CONSTRAINT user_credentials_hash_valid CHECK (
        length(password_hash) BETWEEN 64 AND 512
        AND password_hash LIKE '$matrix-iam-v1$argon2id$v=19$%'
    )
);

CREATE TABLE IF NOT EXISTS iam.login_index (
    login_name text COLLATE "C" PRIMARY KEY,
    tenant_id text COLLATE "C" NOT NULL,
    principal_id text COLLATE "C" NOT NULL,
    CONSTRAINT login_index_principal_fk FOREIGN KEY (tenant_id, principal_id)
        REFERENCES iam.principals (tenant_id, id),
    CONSTRAINT login_index_values_valid CHECK (
        login_name COLLATE "C" ~ '^[a-z][a-z0-9._-]{2,63}$'
    )
);

CREATE TABLE IF NOT EXISTS iam.service_credentials (
    tenant_id text COLLATE "C" NOT NULL,
    principal_id text COLLATE "C" NOT NULL,
    purpose text COLLATE "C" NOT NULL,
    lookup_digest text COLLATE "C" NOT NULL,
    verification_digest text COLLATE "C" NOT NULL,
    created_at timestamptz(6) NOT NULL,
    revoked_at timestamptz(6),
    PRIMARY KEY (tenant_id, principal_id),
    CONSTRAINT service_credentials_principal_fk FOREIGN KEY (tenant_id, principal_id)
        REFERENCES iam.principals (tenant_id, id),
    CONSTRAINT service_credentials_purpose_uq UNIQUE (tenant_id, purpose),
    CONSTRAINT service_credentials_values_valid CHECK (
        purpose IN ('IAM', 'PAAS', 'AUDIT', 'APISIX', 'INSTALLATION_VERIFIER')
        AND lookup_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND verification_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND lookup_digest <> verification_digest
        AND (revoked_at IS NULL OR revoked_at >= created_at)
    )
);

CREATE TABLE IF NOT EXISTS iam.service_credential_index (
    lookup_digest text COLLATE "C" PRIMARY KEY,
    tenant_id text COLLATE "C" NOT NULL,
    principal_id text COLLATE "C" NOT NULL,
    CONSTRAINT service_credential_index_credential_fk FOREIGN KEY (tenant_id, principal_id)
        REFERENCES iam.service_credentials (tenant_id, principal_id),
    CONSTRAINT service_credential_index_digest_valid CHECK (
        lookup_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
    )
);

CREATE TABLE IF NOT EXISTS iam.sessions (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    principal_id text COLLATE "C" NOT NULL,
    verification_digest text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL,
    issued_at timestamptz(6) NOT NULL,
    expires_at timestamptz(6) NOT NULL,
    revoked_at timestamptz(6),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT sessions_principal_fk FOREIGN KEY (tenant_id, principal_id)
        REFERENCES iam.principals (tenant_id, id),
    CONSTRAINT sessions_values_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND principal_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND verification_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND status IN ('ACTIVE', 'REVOKED')
        AND expires_at > issued_at
        AND (
            (status = 'ACTIVE' AND revoked_at IS NULL)
            OR (status = 'REVOKED' AND revoked_at IS NOT NULL AND revoked_at >= issued_at)
        )
    )
);

CREATE TABLE IF NOT EXISTS iam.session_index (
    lookup_digest text COLLATE "C" PRIMARY KEY,
    tenant_id text COLLATE "C" NOT NULL,
    session_id text COLLATE "C" NOT NULL,
    CONSTRAINT session_index_session_fk FOREIGN KEY (tenant_id, session_id)
        REFERENCES iam.sessions (tenant_id, id),
    CONSTRAINT session_index_digest_valid CHECK (
        lookup_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
    )
);

CREATE TABLE IF NOT EXISTS iam.authorization_decisions (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    principal_id text COLLATE "C" NOT NULL,
    allowed boolean NOT NULL,
    action_name text COLLATE "C" NOT NULL,
    target_kind text COLLATE "C" NOT NULL,
    target_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    decided_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT authorization_decisions_principal_fk FOREIGN KEY (tenant_id, principal_id)
        REFERENCES iam.principals (tenant_id, id),
    CONSTRAINT authorization_decisions_values_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND target_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND document->>'apiVersion' = 'iam.matrix.xiak.com/v1'
        AND document->>'kind' = 'AuthorizationDecision'
        AND document->>'id' = id
        AND document->>'action' = action_name
        AND document#>>'{resource,kind}' = target_kind
        AND document#>>'{resource,id}' = target_id
        AND document->>'requestId' = request_id
    )
);

CREATE TABLE IF NOT EXISTS iam.audit_outbox (
    tenant_id text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    event_document jsonb NOT NULL,
    status text COLLATE "C" NOT NULL DEFAULT 'PENDING',
    attempts integer NOT NULL DEFAULT 0,
    fencing_token bigint NOT NULL DEFAULT 0,
    worker_id text COLLATE "C",
    lease_expires_at timestamptz(6),
    next_attempt_at timestamptz(6) NOT NULL,
    error_code text COLLATE "C",
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    PRIMARY KEY (tenant_id, event_id),
    CONSTRAINT audit_outbox_event_uq UNIQUE (event_id),
    CONSTRAINT audit_outbox_values_valid CHECK (
        event_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND status IN ('PENDING', 'IN_FLIGHT', 'RETRY', 'DELIVERED', 'DEAD_LETTER')
        AND attempts BETWEEN 0 AND 100
        AND fencing_token BETWEEN 0 AND 9007199254740991
        AND updated_at >= created_at
        AND (error_code IS NULL OR error_code COLLATE "C" ~ '^[a-z][a-z0-9.]{2,127}$')
        AND (
            (status = 'IN_FLIGHT' AND worker_id IS NOT NULL AND lease_expires_at IS NOT NULL)
            OR (status <> 'IN_FLIGHT' AND worker_id IS NULL AND lease_expires_at IS NULL)
        )
    )
);

ALTER TABLE iam.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.organizations FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.principals FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.role_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.role_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.user_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.user_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.service_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.service_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.authorization_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.authorization_decisions FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.audit_outbox FORCE ROW LEVEL SECURITY;

DO $matrix_iam_policies$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'principals', 'role_bindings', 'user_credentials',
        'service_credentials', 'sessions', 'authorization_decisions'
    ]
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_policies
             WHERE schemaname = 'iam' AND tablename = table_name
               AND policyname = 'tenant_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY tenant_isolation ON iam.%I '
                'USING (tenant_id = iam.current_tenant_id()) '
                'WITH CHECK (tenant_id = iam.current_tenant_id())',
                table_name
            );
        END IF;
    END LOOP;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_policies
         WHERE schemaname = 'iam' AND tablename = 'organizations'
           AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON iam.organizations
            USING (id = iam.current_tenant_id())
            WITH CHECK (id = iam.current_tenant_id());
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_policies
         WHERE schemaname = 'iam' AND tablename = 'audit_outbox'
           AND policyname = 'tenant_or_dispatcher'
    ) THEN
        CREATE POLICY tenant_or_dispatcher ON iam.audit_outbox
            USING (
                tenant_id = iam.current_tenant_id()
                OR current_setting('matrix.iam_dispatcher', true) = 'trusted'
            )
            WITH CHECK (
                tenant_id = iam.current_tenant_id()
                OR current_setting('matrix.iam_dispatcher', true) = 'trusted'
            );
    END IF;
END
$matrix_iam_policies$;

CREATE OR REPLACE FUNCTION iam.assert_audit_event(
    submitted_event jsonb,
    expected_tenant_id text,
    expected_action text,
    expected_target_kind text,
    expected_target_id text,
    expected_result text
)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF jsonb_typeof(submitted_event) <> 'object'
       OR jsonb_typeof(submitted_event->'actor') <> 'object'
       OR jsonb_typeof(submitted_event->'target') <> 'object'
       OR jsonb_typeof(submitted_event->'apiVersion') <> 'string'
       OR jsonb_typeof(submitted_event->'kind') <> 'string'
       OR jsonb_typeof(submitted_event->'eventId') <> 'string'
       OR jsonb_typeof(submitted_event->'tenantId') <> 'string'
       OR jsonb_typeof(submitted_event->'action') <> 'string'
       OR jsonb_typeof(submitted_event->'result') <> 'string'
       OR jsonb_typeof(submitted_event->'requestDigest') <> 'string'
       OR jsonb_typeof(submitted_event->'requestId') <> 'string'
       OR jsonb_typeof(submitted_event->'correlationId') <> 'string'
       OR jsonb_typeof(submitted_event->'occurredAt') <> 'string'
       OR NOT (submitted_event ?& ARRAY[
            'apiVersion', 'kind', 'eventId', 'tenantId', 'actor', 'action',
            'target', 'result', 'requestDigest', 'requestId',
            'correlationId', 'occurredAt'
       ])
       OR NOT ((submitted_event->'actor') ?& ARRAY['type', 'id'])
       OR NOT ((submitted_event->'target') ?& ARRAY['kind', 'id'])
       OR (submitted_event - ARRAY[
            'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
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
       OR submitted_event->>'tenantId' IS DISTINCT FROM expected_tenant_id
       OR submitted_event->>'action' IS DISTINCT FROM expected_action
       OR submitted_event#>>'{target,kind}' IS DISTINCT FROM expected_target_kind
       OR submitted_event#>>'{target,id}' IS DISTINCT FROM expected_target_id
       OR submitted_event->>'result' IS DISTINCT FROM expected_result
       OR COALESCE(submitted_event->>'eventId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
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
       OR submitted_event ? 'operationId'
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
       OR (expected_action IN (
            'iam.bootstrap.applied', 'iam.session.issued',
            'iam.password.changed'
       ) AND submitted_event ? 'iamDecisionId')
       OR (expected_action IN (
            'iam.principal.created', 'iam.role-binding.put',
            'iam.role-binding.revoked', 'iam.authorization.decided'
       ) AND NOT (submitted_event ? 'iamDecisionId'))
       OR (expected_action = 'iam.authorization.decided'
            AND submitted_event#>>'{target,id}' IS DISTINCT FROM
                submitted_event->>'iamDecisionId') THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'sanitized IAM Audit event is invalid';
    END IF;
    IF (submitted_event->>'occurredAt')::timestamptz IS DISTINCT FROM
       transaction_timestamp() THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'IAM Audit event must use database transaction time';
    END IF;
END
$function$;

CREATE OR REPLACE FUNCTION iam.apply_bootstrap(
    submitted_installation_id text,
    submitted_content_digest text,
    submitted_organization_id text,
    submitted_organization_name text,
    submitted_administrator_id text,
    submitted_login_name text,
    submitted_administrator_name text,
    submitted_password_hash text,
    submitted_services jsonb,
    submitted_audit_event jsonb
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    existing iam.bootstrap_receipts%ROWTYPE;
    effective_now timestamptz(6) := transaction_timestamp();
    service jsonb;
    expected_purpose text;
    service_id text;
    lookup_digest text;
    verification_digest text;
    index integer;
BEGIN
    SELECT * INTO existing
      FROM iam.bootstrap_receipts
     WHERE singleton
     FOR UPDATE;
    IF FOUND THEN
        IF existing.installation_id = submitted_installation_id
           AND existing.content_digest = submitted_content_digest THEN
            RETURN 'EQUAL_REPLAY';
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            MESSAGE = 'IAM bootstrap conflicts with installed authority';
    END IF;
    IF submitted_installation_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_organization_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_administrator_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_login_name COLLATE "C" !~ '^[a-z][a-z0-9._-]{2,63}$'
       OR submitted_content_digest COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
       OR submitted_password_hash NOT LIKE '$matrix-iam-v1$argon2id$v=19$%'
       OR jsonb_typeof(submitted_services) <> 'array'
       OR jsonb_array_length(submitted_services) <> 5 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'IAM bootstrap input is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id', submitted_organization_id, true);
    PERFORM iam.assert_audit_event(
        submitted_audit_event,
        submitted_organization_id,
        'iam.bootstrap.applied',
        'INSTALLATION',
        submitted_installation_id,
        'SUCCEEDED'
    );
    INSERT INTO iam.organizations (
        id, display_name, status, resource_version, created_at, updated_at
    ) VALUES (
        submitted_organization_id, submitted_organization_name,
        'ACTIVE', 1, effective_now, effective_now
    );
    INSERT INTO iam.principals (
        tenant_id, id, principal_type, login_name, display_name, status,
        must_change_password, resource_version, created_at, updated_at
    ) VALUES (
        submitted_organization_id, submitted_administrator_id, 'USER',
        submitted_login_name, submitted_administrator_name, 'ACTIVE',
        true, 1, effective_now, effective_now
    );
    INSERT INTO iam.user_credentials (
        tenant_id, principal_id, password_hash, changed_at
    ) VALUES (
        submitted_organization_id, submitted_administrator_id,
        submitted_password_hash, effective_now
    );
    INSERT INTO iam.login_index (login_name, tenant_id, principal_id)
    VALUES (
        submitted_login_name, submitted_organization_id,
        submitted_administrator_id
    );
    INSERT INTO iam.role_bindings (
        tenant_id, id, principal_id, role_name, resource_version,
        created_at, updated_at
    ) VALUES (
        submitted_organization_id, 'bootstrap-admin-binding',
        submitted_administrator_id, 'ORGANIZATION_ADMIN', 1,
        effective_now, effective_now
    );
    FOR index IN 0..4 LOOP
        service := submitted_services->index;
        expected_purpose := (ARRAY[
            'IAM', 'PAAS', 'AUDIT', 'APISIX', 'INSTALLATION_VERIFIER'
        ])[index + 1];
        IF jsonb_typeof(service) <> 'object'
           OR NOT (service ?& ARRAY[
                'purpose', 'principalId', 'lookupDigest', 'verificationDigest'
           ])
           OR (service - ARRAY[
                'purpose', 'principalId', 'lookupDigest', 'verificationDigest'
           ]) <> '{}'::jsonb
           OR service->>'purpose' <> expected_purpose
           OR service->>'principalId' COLLATE "C"
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
           OR service->>'lookupDigest' COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
           OR service->>'verificationDigest' COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
           OR service->>'lookupDigest' = service->>'verificationDigest' THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'IAM bootstrap service inventory is invalid';
        END IF;
        service_id := service->>'principalId';
        lookup_digest := service->>'lookupDigest';
        verification_digest := service->>'verificationDigest';
        INSERT INTO iam.principals (
            tenant_id, id, principal_type, display_name, status,
            must_change_password, resource_version, created_at, updated_at
        ) VALUES (
            submitted_organization_id, service_id, 'SERVICE_ACCOUNT',
            expected_purpose, 'ACTIVE', false, 1, effective_now, effective_now
        );
        INSERT INTO iam.service_credentials (
            tenant_id, principal_id, purpose, lookup_digest,
            verification_digest, created_at
        ) VALUES (
            submitted_organization_id, service_id, expected_purpose,
            lookup_digest, verification_digest, effective_now
        );
        INSERT INTO iam.service_credential_index (
            lookup_digest, tenant_id, principal_id
        ) VALUES (lookup_digest, submitted_organization_id, service_id);
        IF expected_purpose = 'INSTALLATION_VERIFIER' THEN
            INSERT INTO iam.role_bindings (
                tenant_id, id, principal_id, role_name, resource_version,
                created_at, updated_at
            ) VALUES (
                submitted_organization_id, 'bootstrap-verifier-binding',
                service_id, 'INSTALLATION_VERIFIER', 1,
                effective_now, effective_now
            );
        END IF;
    END LOOP;
    INSERT INTO iam.bootstrap_receipts (
        installation_id, content_digest, organization_id, applied_at
    ) VALUES (
        submitted_installation_id, submitted_content_digest,
        submitted_organization_id, effective_now
    );
    INSERT INTO iam.audit_outbox (
        tenant_id, event_id, event_document, next_attempt_at,
        created_at, updated_at
    ) VALUES (
        submitted_organization_id, submitted_audit_event->>'eventId',
        submitted_audit_event, effective_now, effective_now, effective_now
    );
    RETURN 'APPLIED';
END
$function$;

CREATE OR REPLACE FUNCTION iam.bootstrap_status()
RETURNS TABLE (
    state text,
    installation_id text,
    organization_id text,
    content_digest text,
    applied_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    RETURN QUERY
    SELECT 'READY'::text, receipt.installation_id, receipt.organization_id,
           receipt.content_digest, receipt.applied_at
      FROM iam.bootstrap_receipts AS receipt
     WHERE receipt.singleton;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'UNINITIALIZED'::text, NULL::text, NULL::text,
                            NULL::text, NULL::timestamptz;
    END IF;
END
$function$;

CREATE OR REPLACE FUNCTION iam.readiness()
RETURNS TABLE (ready boolean, schema_version bigint, checked_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    PERFORM set_config('matrix.iam_dispatcher', 'trusted', true);
    RETURN QUERY
    SELECT EXISTS (
               SELECT 1 FROM iam.bootstrap_receipts AS receipt
                WHERE receipt.singleton
           ) AND NOT EXISTS (
               SELECT 1 FROM iam.audit_outbox AS outbox
                WHERE outbox.status = 'DEAD_LETTER' OR outbox.attempts >= 100
           ),
           1::bigint,
           transaction_timestamp();
END
$function$;

CREATE OR REPLACE FUNCTION iam.resource_kind_for_action(submitted_action text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT CASE submitted_action
        WHEN 'iam.principal.create' THEN 'ORGANIZATION'
        WHEN 'iam.principal.read' THEN 'PRINCIPAL'
        WHEN 'iam.role-binding.put' THEN 'PRINCIPAL'
        WHEN 'iam.role-binding.revoke' THEN 'ROLE_BINDING'
        WHEN 'iam.session.revoke' THEN 'SESSION'
        WHEN 'paas.application.create' THEN 'APPLICATION'
        WHEN 'paas.application.read' THEN 'APPLICATION'
        WHEN 'paas.configuration.create' THEN 'CONFIGURATION'
        WHEN 'paas.configuration.read' THEN 'CONFIGURATION'
        WHEN 'paas.configuration-revision.create' THEN 'CONFIGURATION_REVISION'
        WHEN 'paas.configuration-revision.read' THEN 'CONFIGURATION_REVISION'
        WHEN 'paas.application-revision.create' THEN 'APPLICATION_REVISION'
        WHEN 'paas.application-revision.read' THEN 'APPLICATION_REVISION'
        WHEN 'paas.deployment.create' THEN 'DEPLOYMENT'
        WHEN 'paas.deployment.update' THEN 'DEPLOYMENT'
        WHEN 'paas.deployment.rollback' THEN 'DEPLOYMENT'
        WHEN 'paas.deployment.stop' THEN 'DEPLOYMENT'
        WHEN 'paas.deployment.read' THEN 'DEPLOYMENT'
        WHEN 'paas.operation.read' THEN 'OPERATION'
        WHEN 'audit.record.read' THEN 'AUDIT_RECORD'
        WHEN 'audit.integrity.verify' THEN 'AUDIT_CHAIN'
        WHEN 'installation.verify' THEN 'INSTALLATION'
        ELSE NULL
    END
$function$;

CREATE OR REPLACE FUNCTION iam.lookup_login(submitted_login_name text)
RETURNS TABLE (
    tenant_id text,
    principal_id text,
    password_hash text,
    organization_status text,
    principal_status text,
    must_change_password boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    indexed iam.login_index%ROWTYPE;
BEGIN
    SELECT * INTO indexed
      FROM iam.login_index
     WHERE login_name = submitted_login_name;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    PERFORM set_config('matrix.iam_tenant_id', indexed.tenant_id, true);
    RETURN QUERY
    SELECT organization.id, principal.id, credential.password_hash,
           organization.status, principal.status,
           principal.must_change_password
      FROM iam.organizations AS organization
      JOIN iam.principals AS principal
        ON principal.tenant_id = organization.id
       AND principal.id = indexed.principal_id
      JOIN iam.user_credentials AS credential
        ON credential.tenant_id = principal.tenant_id
       AND credential.principal_id = principal.id
     WHERE organization.id = indexed.tenant_id
       AND principal.login_name = submitted_login_name;
END
$function$;

CREATE OR REPLACE FUNCTION iam.issue_session(
    submitted_session_id text,
    submitted_tenant_id text,
    submitted_principal_id text,
    submitted_lookup_digest text,
    submitted_verification_digest text,
    submitted_lifetime_seconds integer,
    submitted_audit_event jsonb
)
RETURNS TABLE (issued_at timestamptz, expires_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_now timestamptz(6) := transaction_timestamp();
    effective_expires_at timestamptz(6);
BEGIN
    IF submitted_session_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_tenant_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_principal_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_lookup_digest COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
       OR submitted_verification_digest COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
       OR submitted_lookup_digest = submitted_verification_digest
       OR submitted_lifetime_seconds NOT BETWEEN 60 AND 86400 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'session input is invalid';
    END IF;
    effective_expires_at := effective_now + make_interval(secs => submitted_lifetime_seconds);
    PERFORM set_config('matrix.iam_tenant_id', submitted_tenant_id, true);
    IF NOT EXISTS (
        SELECT 1
          FROM iam.organizations AS organization
          JOIN iam.principals AS principal
            ON principal.tenant_id = organization.id
         WHERE organization.id = submitted_tenant_id
           AND organization.status = 'ACTIVE'
           AND principal.id = submitted_principal_id
           AND principal.principal_type = 'USER'
           AND principal.status = 'ACTIVE'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'session subject is unavailable';
    END IF;
    PERFORM iam.assert_audit_event(
        submitted_audit_event, submitted_tenant_id,
        'iam.session.issued', 'SESSION', submitted_session_id, 'SUCCEEDED'
    );
    INSERT INTO iam.sessions (
        tenant_id, id, principal_id, verification_digest, status,
        issued_at, expires_at
    ) VALUES (
        submitted_tenant_id, submitted_session_id, submitted_principal_id,
        submitted_verification_digest, 'ACTIVE', effective_now,
        effective_expires_at
    );
    INSERT INTO iam.session_index (lookup_digest, tenant_id, session_id)
    VALUES (submitted_lookup_digest, submitted_tenant_id, submitted_session_id);
    INSERT INTO iam.audit_outbox (
        tenant_id, event_id, event_document, next_attempt_at,
        created_at, updated_at
    ) VALUES (
        submitted_tenant_id, submitted_audit_event->>'eventId',
        submitted_audit_event, effective_now, effective_now, effective_now
    );
    RETURN QUERY SELECT effective_now, effective_expires_at;
END
$function$;

CREATE OR REPLACE FUNCTION iam.lookup_session(submitted_lookup_digest text)
RETURNS TABLE (
    organization_id text,
    organization_display_name text,
    organization_status text,
    organization_resource_version bigint,
    organization_created_at timestamptz,
    organization_updated_at timestamptz,
    principal_id text,
    principal_type text,
    principal_login_name text,
    principal_display_name text,
    principal_status text,
    principal_must_change_password boolean,
    principal_resource_version bigint,
    principal_created_at timestamptz,
    principal_updated_at timestamptz,
    session_id text,
    session_status text,
    session_issued_at timestamptz,
    session_expires_at timestamptz,
    session_revoked_at timestamptz,
    verification_digest text,
    roles text[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    indexed iam.session_index%ROWTYPE;
BEGIN
    SELECT * INTO indexed
      FROM iam.session_index
     WHERE lookup_digest = submitted_lookup_digest;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    PERFORM set_config('matrix.iam_tenant_id', indexed.tenant_id, true);
    RETURN QUERY
    SELECT organization.id, organization.display_name, organization.status,
           organization.resource_version, organization.created_at,
           organization.updated_at,
           principal.id, principal.principal_type, principal.login_name,
           principal.display_name, principal.status,
           principal.must_change_password, principal.resource_version,
           principal.created_at, principal.updated_at,
           session.id, session.status, session.issued_at, session.expires_at,
           session.revoked_at, session.verification_digest,
           COALESCE(ARRAY(
               SELECT binding.role_name
                 FROM iam.role_bindings AS binding
                WHERE binding.tenant_id = principal.tenant_id
                  AND binding.principal_id = principal.id
                  AND binding.revoked_at IS NULL
                ORDER BY binding.role_name
           ), ARRAY[]::text[])
      FROM iam.sessions AS session
      JOIN iam.organizations AS organization ON organization.id = session.tenant_id
      JOIN iam.principals AS principal
        ON principal.tenant_id = session.tenant_id
       AND principal.id = session.principal_id
     WHERE session.tenant_id = indexed.tenant_id
       AND session.id = indexed.session_id
       AND session.status = 'ACTIVE'
       AND session.revoked_at IS NULL
       AND session.expires_at > transaction_timestamp()
       AND organization.status = 'ACTIVE'
       AND principal.status = 'ACTIVE';
END
$function$;

CREATE OR REPLACE FUNCTION iam.lookup_service(submitted_lookup_digest text)
RETURNS TABLE (
    tenant_id text,
    principal_id text,
    purpose text,
    verification_digest text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    indexed iam.service_credential_index%ROWTYPE;
BEGIN
    SELECT * INTO indexed
      FROM iam.service_credential_index
     WHERE lookup_digest = submitted_lookup_digest;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    PERFORM set_config('matrix.iam_tenant_id', indexed.tenant_id, true);
    RETURN QUERY
    SELECT credential.tenant_id, credential.principal_id,
           credential.purpose, credential.verification_digest
      FROM iam.service_credentials AS credential
      JOIN iam.organizations AS organization ON organization.id = credential.tenant_id
      JOIN iam.principals AS principal
        ON principal.tenant_id = credential.tenant_id
       AND principal.id = credential.principal_id
     WHERE credential.tenant_id = indexed.tenant_id
       AND credential.principal_id = indexed.principal_id
       AND credential.revoked_at IS NULL
       AND organization.status = 'ACTIVE'
       AND principal.status = 'ACTIVE';
END
$function$;

CREATE OR REPLACE FUNCTION iam.record_authorization(
    submitted_tenant_id text,
    submitted_principal_id text,
    submitted_decision jsonb,
    submitted_audit_event jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_now timestamptz(6) := transaction_timestamp();
    actor_type text;
    expected_kind text;
    decision_allowed boolean;
    expected_result text;
BEGIN
    IF submitted_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_principal_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR jsonb_typeof(submitted_decision) <> 'object'
       OR jsonb_typeof(submitted_decision->'resource') <> 'object'
       OR jsonb_typeof(submitted_decision->'allowed') <> 'boolean'
       OR NOT (submitted_decision ?& ARRAY[
            'apiVersion', 'kind', 'id', 'allowed', 'reason', 'action',
            'resource', 'requestId', 'decidedAt'
       ])
       OR (submitted_decision - ARRAY[
            'apiVersion', 'kind', 'id', 'allowed', 'reason', 'tenantId',
            'subject', 'action', 'resource', 'requestId', 'decidedAt'
       ]) <> '{}'::jsonb
       OR NOT ((submitted_decision->'resource') ?& ARRAY['kind', 'id'])
       OR ((submitted_decision->'resource') - ARRAY['kind', 'id']) <> '{}'::jsonb
       OR submitted_decision->>'apiVersion' IS DISTINCT FROM
            'iam.matrix.xiak.com/v1'
       OR submitted_decision->>'kind' IS DISTINCT FROM 'AuthorizationDecision'
       OR COALESCE(submitted_decision->>'id', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_decision#>>'{resource,id}', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_decision->>'requestId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_decision->>'decidedAt', '') COLLATE "C"
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
       OR NOT pg_input_is_valid(
            COALESCE(submitted_decision->>'decidedAt', ''), 'timestamptz'
       )
       OR (submitted_decision->>'decidedAt')::timestamptz IS DISTINCT FROM
            effective_now THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'authorization decision is invalid';
    END IF;

    expected_kind := iam.resource_kind_for_action(submitted_decision->>'action');
    IF expected_kind IS NULL
       OR submitted_decision#>>'{resource,kind}' IS DISTINCT FROM expected_kind THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'authorization action and resource are invalid';
    END IF;

    PERFORM set_config('matrix.iam_tenant_id', submitted_tenant_id, true);
    SELECT principal.principal_type INTO actor_type
      FROM iam.organizations AS organization
      JOIN iam.principals AS principal
        ON principal.tenant_id = organization.id
     WHERE organization.id = submitted_tenant_id
       AND organization.status = 'ACTIVE'
       AND principal.id = submitted_principal_id
       AND principal.status = 'ACTIVE';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'authorization subject is unavailable';
    END IF;

    decision_allowed := (submitted_decision->>'allowed')::boolean;
    expected_result := CASE WHEN decision_allowed THEN 'ALLOWED' ELSE 'DENIED' END;
    IF submitted_decision->>'reason' IS DISTINCT FROM expected_result
       OR (decision_allowed AND (
            NOT (submitted_decision ?& ARRAY['tenantId', 'subject'])
            OR jsonb_typeof(submitted_decision->'subject') <> 'object'
            OR ((submitted_decision->'subject') - ARRAY['type', 'id']) <> '{}'::jsonb
            OR NOT ((submitted_decision->'subject') ?& ARRAY['type', 'id'])
            OR submitted_decision->>'tenantId' IS DISTINCT FROM submitted_tenant_id
            OR submitted_decision#>>'{subject,type}' IS DISTINCT FROM actor_type
            OR submitted_decision#>>'{subject,id}' IS DISTINCT FROM submitted_principal_id
       ))
       OR (NOT decision_allowed AND (
            submitted_decision ? 'tenantId' OR submitted_decision ? 'subject'
       )) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'authorization decision authority is invalid';
    END IF;

    PERFORM iam.assert_audit_event(
        submitted_audit_event,
        submitted_tenant_id,
        'iam.authorization.decided',
        'AUTHORIZATION_DECISION',
        submitted_decision->>'id',
        expected_result
    );
    IF submitted_audit_event->>'iamDecisionId' IS DISTINCT FROM
            submitted_decision->>'id'
       OR submitted_audit_event->>'requestId' IS DISTINCT FROM
            submitted_decision->>'requestId'
       OR submitted_audit_event#>>'{actor,type}' IS DISTINCT FROM actor_type
       OR submitted_audit_event#>>'{actor,id}' IS DISTINCT FROM
            submitted_principal_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'authorization Audit event authority is invalid';
    END IF;

    INSERT INTO iam.authorization_decisions (
        tenant_id, id, principal_id, allowed, action_name, target_kind,
        target_id, request_id, decided_at, document
    ) VALUES (
        submitted_tenant_id,
        submitted_decision->>'id',
        submitted_principal_id,
        decision_allowed,
        submitted_decision->>'action',
        submitted_decision#>>'{resource,kind}',
        submitted_decision#>>'{resource,id}',
        submitted_decision->>'requestId',
        effective_now,
        submitted_decision
    );
    INSERT INTO iam.audit_outbox (
        tenant_id, event_id, event_document, next_attempt_at,
        created_at, updated_at
    ) VALUES (
        submitted_tenant_id,
        submitted_audit_event->>'eventId',
        submitted_audit_event,
        effective_now,
        effective_now,
        effective_now
    );
END
$function$;

CREATE OR REPLACE FUNCTION iam.claim_audit_event(
    submitted_worker_id text,
    submitted_lease_seconds integer
)
RETURNS TABLE (
    tenant_id text,
    event_id text,
    event_document jsonb,
    attempts integer,
    fencing_token bigint,
    lease_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF COALESCE(submitted_worker_id, '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_lease_seconds IS NULL
       OR submitted_lease_seconds NOT BETWEEN 1 AND 300 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Audit claim input is invalid';
    END IF;
    PERFORM set_config('matrix.iam_dispatcher', 'trusted', true);
    RETURN QUERY
    WITH candidate AS (
        SELECT outbox.tenant_id, outbox.event_id
          FROM iam.audit_outbox AS outbox
         WHERE outbox.attempts < 100
           AND (
                (
                    outbox.status IN ('PENDING', 'RETRY')
                    AND outbox.next_attempt_at <= transaction_timestamp()
                )
                OR (
                    outbox.status = 'IN_FLIGHT'
                    AND outbox.lease_expires_at <= transaction_timestamp()
                )
           )
         ORDER BY outbox.created_at, outbox.event_id
         FOR UPDATE SKIP LOCKED
         LIMIT 1
    ), claimed AS (
        UPDATE iam.audit_outbox AS outbox
           SET status = 'IN_FLIGHT',
               attempts = outbox.attempts + 1,
               fencing_token = outbox.fencing_token + 1,
               worker_id = submitted_worker_id,
               lease_expires_at = transaction_timestamp()
                    + make_interval(secs => submitted_lease_seconds),
               error_code = NULL,
               updated_at = transaction_timestamp()
          FROM candidate
         WHERE outbox.tenant_id = candidate.tenant_id
           AND outbox.event_id = candidate.event_id
        RETURNING outbox.*
    )
    SELECT claimed.tenant_id, claimed.event_id, claimed.event_document,
           claimed.attempts, claimed.fencing_token, claimed.lease_expires_at
      FROM claimed;
END
$function$;

CREATE OR REPLACE FUNCTION iam.complete_audit_event(
    submitted_event_id text,
    submitted_worker_id text,
    submitted_fencing_token bigint,
    submitted_outcome text,
    submitted_retry_seconds integer,
    submitted_error_code text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    changed integer;
BEGIN
    IF submitted_outcome IS NULL
       OR submitted_outcome NOT IN ('DELIVERED', 'RETRY', 'DEAD_LETTER')
       OR COALESCE(submitted_event_id, '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_worker_id, '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_fencing_token IS NULL
       OR submitted_fencing_token NOT BETWEEN 1 AND 9007199254740991
       OR submitted_retry_seconds IS NULL
       OR (submitted_outcome = 'RETRY' AND submitted_retry_seconds NOT BETWEEN 1 AND 86400)
       OR (submitted_outcome <> 'RETRY' AND submitted_retry_seconds <> 0)
       OR (submitted_outcome = 'DELIVERED' AND submitted_error_code IS NOT NULL)
       OR (submitted_outcome <> 'DELIVERED'
            AND COALESCE(submitted_error_code, '') COLLATE "C"
                !~ '^[a-z][a-z0-9.]{2,127}$') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Audit completion input is invalid';
    END IF;
    PERFORM set_config('matrix.iam_dispatcher', 'trusted', true);
    UPDATE iam.audit_outbox AS outbox
       SET status = submitted_outcome,
           worker_id = NULL,
           lease_expires_at = NULL,
           next_attempt_at = CASE
                WHEN submitted_outcome = 'RETRY' THEN transaction_timestamp()
                    + make_interval(secs => submitted_retry_seconds)
                ELSE outbox.next_attempt_at
           END,
           error_code = submitted_error_code,
           updated_at = transaction_timestamp()
     WHERE outbox.event_id = submitted_event_id
       AND outbox.status = 'IN_FLIGHT'
       AND outbox.worker_id = submitted_worker_id
       AND outbox.fencing_token = submitted_fencing_token;
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001',
            MESSAGE = 'Audit outbox lease or fencing token is stale';
    END IF;
END
$function$;

REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA iam FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA iam
    FROM matrix_iam_api, matrix_iam_worker;
REVOKE ALL ON SCHEMA iam FROM matrix_iam_api, matrix_iam_worker;
GRANT USAGE ON SCHEMA iam TO matrix_iam_api, matrix_iam_worker;
GRANT EXECUTE ON FUNCTION iam.bootstrap_status() TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.readiness() TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.lookup_login(text) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.apply_bootstrap(
    text, text, text, text, text, text, text, text, jsonb, jsonb
) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.issue_session(
    text, text, text, text, text, integer, jsonb
) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.lookup_session(text) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.lookup_service(text) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.record_authorization(
    text, text, jsonb, jsonb
) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.claim_audit_event(text, integer) TO matrix_iam_worker;
GRANT EXECUTE ON FUNCTION iam.complete_audit_event(
    text, text, bigint, text, integer, text
) TO matrix_iam_worker;

ALTER DEFAULT PRIVILEGES FOR ROLE matrix_iam_owner IN SCHEMA iam
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE matrix_iam_owner IN SCHEMA iam
    REVOKE ALL ON FUNCTIONS FROM PUBLIC;

COMMIT;
