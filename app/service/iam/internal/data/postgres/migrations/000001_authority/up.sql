SET LOCAL ROLE matrix_iam_owner;

REVOKE ALL ON SCHEMA iam FROM PUBLIC;

-- Account is the current ownership aggregate. Upgrade the pre-release table
-- name before any current definition is compiled; never create two sources of
-- ownership truth.
DO $account_table_cutover$
BEGIN
    IF to_regclass('iam.accounts') IS NULL AND to_regclass('iam.organizations') IS NOT NULL THEN
        ALTER TABLE iam.organizations RENAME TO accounts;
    ELSIF to_regclass('iam.accounts') IS NOT NULL AND to_regclass('iam.organizations') IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM account ownership tables conflict';
    END IF;
END $account_table_cutover$;

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
    administrator_principal_id text COLLATE "C" NOT NULL,
    applied_at timestamptz(6) NOT NULL,
    CONSTRAINT bootstrap_receipts_identity_valid CHECK (
        installation_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND organization_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND administrator_principal_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND content_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
    )
);

CREATE TABLE IF NOT EXISTS iam.accounts (
    id text COLLATE "C" PRIMARY KEY,
    display_name text NOT NULL,
    status text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    CONSTRAINT accounts_values_valid CHECK (
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
    CONSTRAINT principals_account_fk FOREIGN KEY (tenant_id)
        REFERENCES iam.accounts (id),
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

CREATE TABLE IF NOT EXISTS iam.policies (
    id text COLLATE "C" PRIMARY KEY,
    management text COLLATE "C" NOT NULL,
    owner_tenant_id text COLLATE "C" REFERENCES iam.accounts(id),
    display_name text NOT NULL,
    authority_scope text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL,
    default_version_id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    UNIQUE (id, authority_scope),
    CONSTRAINT policies_values_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND default_version_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND octet_length(display_name) BETWEEN 1 AND 128 AND btrim(display_name)=display_name
        AND display_name !~ '[[:cntrl:]]'
        AND status IN ('ACTIVE','RETIRED')
        AND resource_version BETWEEN 1 AND 9007199254740991 AND updated_at >= created_at
        AND ((management='SYSTEM' AND owner_tenant_id IS NULL AND id LIKE 'system._%'
              AND authority_scope IN ('TENANT','INSTALLATION','INSTALLATION_PROBE'))
          OR (management='CUSTOMER' AND owner_tenant_id IS NOT NULL AND id NOT LIKE 'system.%'
              AND authority_scope='TENANT'))
    )
);

CREATE TABLE IF NOT EXISTS iam.policy_versions (
    policy_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    authority_scope text COLLATE "C" NOT NULL,
    document jsonb NOT NULL,
    canonical_document text NOT NULL,
    content_digest text COLLATE "C" NOT NULL,
    created_at timestamptz(6) NOT NULL,
    PRIMARY KEY (policy_id,id),
    FOREIGN KEY (policy_id,authority_scope) REFERENCES iam.policies(id,authority_scope),
    CONSTRAINT policy_versions_content_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND octet_length(canonical_document) BETWEEN 1 AND 65536
        AND jsonb_typeof(document)='object' AND document ?& ARRAY['languageVersion','scope','statements']
        AND jsonb_typeof(document->'languageVersion')='string'
        AND jsonb_typeof(document->'scope')='string'
        AND document->>'languageVersion'='1' AND document->>'scope'=authority_scope
        AND jsonb_typeof(document->'statements')='array'
        AND jsonb_array_length(document->'statements') BETWEEN 1 AND 64
        AND canonical_document::jsonb=document
        AND content_digest = 'sha256:' || encode(sha256(
            convert_to('matrix.iam.policy.v1','UTF8') || decode('00','hex') || convert_to(canonical_document,'UTF8')), 'hex')
    )
);

ALTER TABLE iam.policies DROP CONSTRAINT IF EXISTS policies_default_version_fk;
ALTER TABLE iam.policies ADD CONSTRAINT policies_default_version_fk
    FOREIGN KEY (id,default_version_id) REFERENCES iam.policy_versions(policy_id,id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE IF NOT EXISTS iam.policy_attachments (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    principal_id text COLLATE "C" NOT NULL,
    target_kind text COLLATE "C" NOT NULL,
    policy_id text COLLATE "C" NOT NULL,
    authority_scope text COLLATE "C" NOT NULL,
    installation_id text COLLATE "C",
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    revoked_at timestamptz(6),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT policy_attachments_principal_fk FOREIGN KEY (tenant_id, principal_id)
        REFERENCES iam.principals (tenant_id, id),
    FOREIGN KEY (policy_id,authority_scope) REFERENCES iam.policies(id,authority_scope)
);

CREATE UNIQUE INDEX IF NOT EXISTS policy_attachments_active_uq ON iam.policy_attachments
    (tenant_id,principal_id,policy_id) WHERE revoked_at IS NULL;

ALTER TABLE iam.policy_attachments DROP CONSTRAINT IF EXISTS policy_attachments_values_valid;
ALTER TABLE iam.policy_attachments ADD CONSTRAINT policy_attachments_values_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND principal_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND policy_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND target_kind IN ('USER','SERVICE_ACCOUNT')
        AND ((authority_scope='TENANT' AND installation_id IS NULL)
          OR (authority_scope='INSTALLATION' AND target_kind='USER'
              AND installation_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' AND installation_id IS NOT NULL)
          OR (authority_scope='INSTALLATION_PROBE' AND target_kind='SERVICE_ACCOUNT'
              AND installation_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' AND installation_id IS NOT NULL))
        AND resource_version BETWEEN 1 AND 9007199254740991
        AND updated_at >= created_at
        AND (revoked_at IS NULL OR (revoked_at = updated_at AND revoked_at >= created_at AND resource_version >= 2))
    );

CREATE OR REPLACE FUNCTION iam.reject_policy_history_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM policy history is immutable';
END $function$;

CREATE OR REPLACE FUNCTION iam.guard_policy_metadata_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF ROW(NEW.id,NEW.management,NEW.owner_tenant_id,NEW.authority_scope,NEW.created_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.management,OLD.owner_tenant_id,OLD.authority_scope,OLD.created_at)
        OR OLD.status='RETIRED' OR NEW.resource_version <> OLD.resource_version+1
        OR NEW.updated_at <> transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM policy metadata transition is invalid';
    END IF;
    RETURN NEW;
END $function$;

CREATE OR REPLACE FUNCTION iam.guard_policy_attachment_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE subject_kind text; policy_scope text; policy_owner text; sealed_installation text;
BEGIN
    IF TG_OP='UPDATE' THEN
        IF ROW(NEW.tenant_id,NEW.id,NEW.principal_id,NEW.target_kind,NEW.policy_id,NEW.authority_scope,NEW.installation_id,NEW.created_at)
            IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.principal_id,OLD.target_kind,OLD.policy_id,OLD.authority_scope,OLD.installation_id,OLD.created_at)
            OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
            OR NEW.resource_version <> OLD.resource_version+1 OR NEW.updated_at <> transaction_timestamp()
            OR NEW.revoked_at <> NEW.updated_at THEN
            RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM attachment is immutable except terminal revocation';
        END IF;
        RETURN NEW;
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',NEW.tenant_id,true);
    SELECT principal.principal_type INTO subject_kind FROM iam.principals AS principal
        WHERE principal.tenant_id=NEW.tenant_id AND principal.id=NEW.principal_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='23503', MESSAGE='IAM attachment subject is unavailable';
    END IF;
    SELECT policy.authority_scope,policy.owner_tenant_id INTO policy_scope,policy_owner
        FROM iam.policies AS policy WHERE policy.id=NEW.policy_id FOR KEY SHARE;
    IF NOT FOUND OR (policy_owner IS NOT NULL AND policy_owner<>NEW.tenant_id)
        OR (NEW.target_kind IS NOT NULL AND NEW.target_kind<>subject_kind)
        OR (NEW.authority_scope IS NOT NULL AND NEW.authority_scope<>policy_scope) THEN
        RAISE EXCEPTION USING ERRCODE='23503', MESSAGE='IAM attachment policy ownership conflicts';
    END IF;
    NEW.target_kind := subject_kind;
    NEW.authority_scope := policy_scope;
    IF policy_scope='TENANT' THEN
        IF NEW.installation_id IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='IAM tenant attachment cannot select an installation';
        END IF;
    ELSE
        SELECT receipt.installation_id INTO sealed_installation FROM iam.bootstrap_receipts AS receipt WHERE receipt.singleton;
        IF sealed_installation IS NULL OR (NEW.installation_id IS NOT NULL AND NEW.installation_id<>sealed_installation)
            OR (policy_scope='INSTALLATION' AND subject_kind<>'USER')
            OR (policy_scope='INSTALLATION_PROBE' AND subject_kind<>'SERVICE_ACCOUNT') THEN
            RAISE EXCEPTION USING ERRCODE='23503', MESSAGE='IAM installation attachment ownership conflicts';
        END IF;
        NEW.installation_id := sealed_installation;
    END IF;
    RETURN NEW;
END $function$;

DROP TRIGGER IF EXISTS policy_metadata_transitions ON iam.policies;
CREATE TRIGGER policy_metadata_transitions BEFORE UPDATE ON iam.policies
    FOR EACH ROW EXECUTE FUNCTION iam.guard_policy_metadata_change();
DROP TRIGGER IF EXISTS policy_metadata_cannot_be_deleted ON iam.policies;
CREATE TRIGGER policy_metadata_cannot_be_deleted BEFORE DELETE ON iam.policies
    FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS policy_metadata_cannot_be_truncated ON iam.policies;
CREATE TRIGGER policy_metadata_cannot_be_truncated BEFORE TRUNCATE ON iam.policies
    FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS policy_versions_are_immutable ON iam.policy_versions;
CREATE TRIGGER policy_versions_are_immutable BEFORE UPDATE OR DELETE ON iam.policy_versions
    FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS policy_versions_cannot_be_truncated ON iam.policy_versions;
CREATE TRIGGER policy_versions_cannot_be_truncated BEFORE TRUNCATE ON iam.policy_versions
    FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS policy_attachment_transitions ON iam.policy_attachments;
CREATE TRIGGER policy_attachment_transitions BEFORE INSERT OR UPDATE ON iam.policy_attachments
    FOR EACH ROW EXECUTE FUNCTION iam.guard_policy_attachment_change();
DROP TRIGGER IF EXISTS policy_attachments_cannot_be_deleted ON iam.policy_attachments;
CREATE TRIGGER policy_attachments_cannot_be_deleted BEFORE DELETE ON iam.policy_attachments
    FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS policy_attachments_cannot_be_truncated ON iam.policy_attachments;
CREATE TRIGGER policy_attachments_cannot_be_truncated BEFORE TRUNCATE ON iam.policy_attachments
    FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.policies ENABLE ALWAYS TRIGGER policy_metadata_transitions;
ALTER TABLE iam.policies ENABLE ALWAYS TRIGGER policy_metadata_cannot_be_deleted;
ALTER TABLE iam.policies ENABLE ALWAYS TRIGGER policy_metadata_cannot_be_truncated;
ALTER TABLE iam.policy_versions ENABLE ALWAYS TRIGGER policy_versions_are_immutable;
ALTER TABLE iam.policy_versions ENABLE ALWAYS TRIGGER policy_versions_cannot_be_truncated;
ALTER TABLE iam.policy_attachments ENABLE ALWAYS TRIGGER policy_attachment_transitions;
ALTER TABLE iam.policy_attachments ENABLE ALWAYS TRIGGER policy_attachments_cannot_be_deleted;
ALTER TABLE iam.policy_attachments ENABLE ALWAYS TRIGGER policy_attachments_cannot_be_truncated;

ALTER TABLE iam.policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS policies_owner_isolation ON iam.policies;
CREATE POLICY policies_owner_isolation ON iam.policies
    USING (owner_tenant_id IS NULL OR owner_tenant_id=iam.current_tenant_id())
    WITH CHECK (owner_tenant_id IS NULL OR owner_tenant_id=iam.current_tenant_id());
ALTER TABLE iam.policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS policy_versions_owner_isolation ON iam.policy_versions;
CREATE POLICY policy_versions_owner_isolation ON iam.policy_versions
    USING (EXISTS(SELECT 1 FROM iam.policies AS policy WHERE policy.id=policy_versions.policy_id))
    WITH CHECK (EXISTS(SELECT 1 FROM iam.policies AS policy WHERE policy.id=policy_versions.policy_id));

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

-- Credential lineage is a monotonic per-user generation, not wall-clock order.
-- Existing credentials start at generation one; legacy sessions stay unbound.
ALTER TABLE iam.user_credentials ADD COLUMN IF NOT EXISTS credential_version bigint NOT NULL DEFAULT 1
    CHECK (credential_version > 0);

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
        purpose IN ('IAM', 'PAAS', 'AUDIT', 'INSTALLATION_VERIFIER')
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
    resource_version bigint NOT NULL,
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
        AND resource_version BETWEEN 1 AND 9007199254740991
        AND expires_at > issued_at
        AND (
            (status = 'ACTIVE' AND revoked_at IS NULL)
            OR (status = 'REVOKED' AND revoked_at IS NOT NULL AND revoked_at >= issued_at)
        )
    )
);

-- Retained pre-extension sessions have no credential epoch and must log in
-- again. Transaction timestamps cannot prove which password issued them;
-- neither migration replay nor explicit retention may bless those rows.
ALTER TABLE iam.sessions ADD COLUMN IF NOT EXISTS credential_version bigint CHECK (credential_version > 0);

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

-- Historical decisions retain NULL provenance; it is never guessed from
-- current permissions. Every new record must use the evidence-bound function.
ALTER TABLE iam.authorization_decisions ADD COLUMN IF NOT EXISTS policy_evidence jsonb;
ALTER TABLE iam.authorization_decisions DROP CONSTRAINT IF EXISTS authorization_policy_evidence_valid;
ALTER TABLE iam.authorization_decisions ADD CONSTRAINT authorization_policy_evidence_valid CHECK (
    policy_evidence IS NULL OR (jsonb_typeof(policy_evidence)='array' AND jsonb_array_length(policy_evidence)<=256)
);
DROP TRIGGER IF EXISTS authorization_decisions_are_immutable ON iam.authorization_decisions;
CREATE TRIGGER authorization_decisions_are_immutable BEFORE UPDATE OR DELETE ON iam.authorization_decisions
    FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS authorization_decisions_cannot_be_truncated ON iam.authorization_decisions;
CREATE TRIGGER authorization_decisions_cannot_be_truncated BEFORE TRUNCATE ON iam.authorization_decisions
    FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.authorization_decisions ENABLE ALWAYS TRIGGER authorization_decisions_are_immutable;
ALTER TABLE iam.authorization_decisions ENABLE ALWAYS TRIGGER authorization_decisions_cannot_be_truncated;

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
            (status = 'DEAD_LETTER' AND error_code IS NOT NULL)
            OR (status <> 'DEAD_LETTER' AND error_code IS NULL)
        )
        AND (
            (status = 'IN_FLIGHT' AND worker_id IS NOT NULL AND lease_expires_at IS NOT NULL)
            OR (status <> 'IN_FLIGHT' AND worker_id IS NULL AND lease_expires_at IS NULL)
        )
    )
);

ALTER TABLE iam.accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.accounts FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.principals FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_attachments FORCE ROW LEVEL SECURITY;
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
        'principals', 'policy_attachments', 'user_credentials',
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
         WHERE schemaname = 'iam' AND tablename = 'accounts'
           AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON iam.accounts
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
DECLARE
    local_recovery boolean := expected_action = 'iam.installation-primary.credentials-recovered';
    platform_lifecycle boolean := expected_action IN (
        'iam.account.created','iam.account.disabled','iam.account.enabled','iam.account-root.credentials-recovered',
        'iam.tenant.created','iam.tenant.disabled','iam.tenant.enabled','iam.tenant-administrator.recovered',
        'iam.installation-primary.credentials-recovered',
        'iam.platform-policy-attachment.created','iam.platform-policy-attachment.revoked');
BEGIN
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
       OR ((submitted_event->'target') - ARRAY['kind', 'id', 'tenantId']) <> '{}'::jsonb
       OR (expected_action IN ('iam.account-root.credentials-recovered','iam.tenant-administrator.recovered','iam.installation-primary.credentials-recovered') AND (
            jsonb_typeof(submitted_event#>'{target,tenantId}') IS DISTINCT FROM 'string'
            OR COALESCE(submitted_event#>>'{target,tenantId}','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
          ))
       OR (expected_action NOT IN ('iam.account-root.credentials-recovered','iam.tenant-administrator.recovered','iam.installation-primary.credentials-recovered') AND (submitted_event->'target') ? 'tenantId')
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
       OR (NOT platform_lifecycle AND (
            jsonb_typeof(submitted_event->'tenantId') IS DISTINCT FROM 'string'
            OR submitted_event->>'tenantId' IS DISTINCT FROM expected_tenant_id
            OR submitted_event ? 'installationId'
          ))
       OR (platform_lifecycle AND (
            submitted_event ? 'tenantId'
            OR jsonb_typeof(submitted_event->'installationId') IS DISTINCT FROM 'string'
            OR (NOT local_recovery AND submitted_event#>>'{actor,type}' IS DISTINCT FROM 'USER')
            OR (local_recovery AND (submitted_event#>>'{actor,type}' IS DISTINCT FROM 'SYSTEM'
                OR submitted_event#>>'{actor,id}' IS DISTINCT FROM 'iam-local-recovery'))
            OR NOT EXISTS(SELECT 1 FROM iam.bootstrap_receipts AS receipt
                WHERE receipt.organization_id=expected_tenant_id AND receipt.installation_id=submitted_event->>'installationId')
          ))
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
            'iam.password.changed', 'iam.user.password-changed', 'iam.installation-primary.credentials-recovered'
        ) AND submitted_event ? 'iamDecisionId')
        OR (expected_action IN (
            'iam.account.created', 'iam.account.disabled', 'iam.account.enabled',
            'iam.account-root.credentials-recovered', 'iam.account.alias-set',
            'iam.user.created', 'iam.user.status-set', 'iam.user.password-reset',
            'iam.policy-attachment.created', 'iam.policy-attachment.revoked',
            'iam.platform-policy-attachment.created', 'iam.platform-policy-attachment.revoked',
            'iam.principal.created', 'iam.role-binding.put',
            'iam.role-binding.revoked', 'iam.authorization.decided',
            'iam.organization.created', 'iam.account-alias.set',
            'iam.principal.status-set', 'iam.password.reset',
            'iam.tenant.created', 'iam.tenant.disabled', 'iam.tenant.enabled', 'iam.tenant-administrator.recovered'
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
       OR jsonb_array_length(submitted_services) <> 4 THEN
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
    INSERT INTO iam.accounts (
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
    INSERT INTO iam.account_roots(account_id,principal_id,login_name)
    VALUES(submitted_organization_id,submitted_administrator_id,submitted_login_name);
    INSERT INTO iam.bootstrap_receipts (
        installation_id, content_digest, organization_id,
        administrator_principal_id, applied_at
    ) VALUES (
        submitted_installation_id, submitted_content_digest,
        submitted_organization_id, submitted_administrator_id, effective_now
    );
    INSERT INTO iam.policy_attachments (
        tenant_id, id, principal_id, policy_id, resource_version,
        created_at, updated_at
    ) VALUES (
        submitted_organization_id, 'bootstrap-admin-binding',
        submitted_administrator_id, 'system.account-administrator', 1,
        effective_now, effective_now
    );
    INSERT INTO iam.policy_attachments (
        tenant_id, id, principal_id, policy_id, resource_version,
        created_at, updated_at
    ) VALUES (
        submitted_organization_id, 'bootstrap-platform-operator-binding',
        submitted_administrator_id, 'system.platform-operator', 1,
        effective_now, effective_now
    );
    FOR index IN 0..3 LOOP
        service := submitted_services->index;
        expected_purpose := (ARRAY[
            'IAM', 'PAAS', 'AUDIT', 'INSTALLATION_VERIFIER'
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
            INSERT INTO iam.policy_attachments (
                tenant_id, id, principal_id, policy_id, resource_version,
                created_at, updated_at
            ) VALUES (
                submitted_organization_id, 'bootstrap-verifier-binding',
                service_id, 'system.installation-verifier', 1,
                effective_now, effective_now
            );
        END IF;
    END LOOP;
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
           ) AND to_regprocedure('iam.read_audit_evidence(text,text,text,text,jsonb)') IS NOT NULL
           AND to_regclass('iam.role_bindings') IS NULL
           AND to_regprocedure('iam.record_authorization(text,text,jsonb,jsonb)') IS NULL
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS directory
                WHERE directory.oid=to_regprocedure('iam.list_policies(text,text,text,text)')
                  AND directory.prorettype='jsonb'::regtype AND NOT directory.proretset
                  AND directory.prosecdef AND directory.proowner='matrix_iam_owner'::regrole)
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS recorder
                WHERE recorder.oid=to_regprocedure('iam.record_authorization(text,text,jsonb,jsonb,jsonb)')
                  AND recorder.prosecdef AND recorder.proowner='matrix_iam_owner'::regrole)
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS lookup
                WHERE lookup.oid=to_regprocedure('iam.lookup_session(text)')
                  AND cardinality(lookup.proallargtypes)=23 AND lookup.proargnames[23]='policies'
                  AND lookup.proallargtypes[23]='jsonb'::regtype::oid)
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_attribute AS evidence
                WHERE evidence.attrelid='iam.authorization_decisions'::regclass AND evidence.attname='policy_evidence'
                  AND evidence.atttypid='jsonb'::regtype AND NOT evidence.attisdropped)
           AND (SELECT count(*) FROM pg_catalog.pg_class AS policy_table
                WHERE policy_table.oid IN (to_regclass('iam.policies'),to_regclass('iam.policy_versions'),to_regclass('iam.policy_attachments'))
                  AND policy_table.relrowsecurity AND policy_table.relforcerowsecurity
                  AND policy_table.relowner='matrix_iam_owner'::regrole)=3
           AND (SELECT count(*) FROM pg_catalog.pg_trigger AS protection
                WHERE protection.tgrelid='iam.authorization_decisions'::regclass
                  AND protection.tgname IN ('authorization_decisions_are_immutable','authorization_decisions_cannot_be_truncated')
                  AND NOT protection.tgisinternal AND protection.tgenabled='A')=2
            AND to_regprocedure('iam.set_account_status(text,text,text,text,text,bigint,jsonb)') IS NOT NULL
            AND to_regprocedure('iam.recover_root_credentials(text,text,text,text,text,bigint,text,text,jsonb)') IS NOT NULL
            AND to_regprocedure('iam.read_account_root(text,text,text,text)') IS NOT NULL
            AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS snapshot
                WHERE snapshot.oid=to_regprocedure('iam.account_management_snapshot(text)')
                  AND snapshot.prorettype='jsonb'::regtype AND NOT snapshot.proretset
                  AND NOT snapshot.prosecdef AND snapshot.proowner='matrix_iam_owner'::regrole)
            AND to_regprocedure('iam.set_organization_status(text,text,text,text,text,bigint,jsonb)') IS NULL
            AND to_regprocedure('iam.recover_organization_administrator(text,text,text,text,text,bigint,text,text,jsonb)') IS NULL
           AND to_regprocedure('iam.change_password(text,text,text,text,jsonb,text,boolean)') IS NOT NULL
           AND to_regprocedure('iam.change_password(text,text,text,text,jsonb)') IS NULL
           AND (SELECT count(*) FROM pg_catalog.pg_proc AS recovery
                WHERE recovery.oid IN (
                    to_regprocedure('iam.inspect_local_credential_recovery(jsonb,text,text)'),
                    to_regprocedure('iam.recover_local_credentials(jsonb,jsonb,text,text,text,jsonb)'))
                  AND recovery.prorettype='jsonb'::regtype AND NOT recovery.proretset
                  AND recovery.prosecdef AND recovery.proowner='matrix_iam_owner'::regrole) = 2
           AND EXISTS (SELECT 1 FROM pg_catalog.pg_class AS receipt
                WHERE receipt.oid=to_regclass('iam.local_credential_recoveries')
                  AND receipt.relrowsecurity AND receipt.relforcerowsecurity
                  AND receipt.relowner='matrix_iam_owner'::regrole)
           AND (SELECT count(*) FROM pg_catalog.pg_trigger AS protection
                WHERE protection.tgrelid=to_regclass('iam.local_credential_recoveries')
                  AND protection.tgname IN ('local_recovery_receipts_are_immutable','local_recovery_receipts_cannot_be_truncated')
                  AND NOT protection.tgisinternal AND protection.tgenabled='A') = 2
           AND EXISTS (
               SELECT 1 FROM pg_catalog.pg_attribute AS column_definition
                WHERE column_definition.attrelid = 'iam.sessions'::regclass
                  AND column_definition.attname = 'credential_version'
                  AND column_definition.atttypid = 'bigint'::regtype
                  AND NOT column_definition.attisdropped
           )
           AND EXISTS (
               SELECT 1 FROM pg_catalog.pg_attribute AS column_definition
                WHERE column_definition.attrelid = 'iam.user_credentials'::regclass
                  AND column_definition.attname = 'credential_version'
                  AND column_definition.atttypid = 'bigint'::regtype
                  AND column_definition.attnotnull
                  AND NOT column_definition.attisdropped
           )
           AND EXISTS (
               SELECT 1 FROM pg_catalog.pg_proc AS claim
                WHERE claim.oid = to_regprocedure('iam.claim_audit_event(text,integer)')
                  AND claim.proallargtypes = ARRAY['text'::regtype::oid, 'integer'::regtype::oid,
                      'text'::regtype::oid, 'text'::regtype::oid, 'jsonb'::regtype::oid,
                      'integer'::regtype::oid, 'bigint'::regtype::oid, 'timestamptz'::regtype::oid, 'text'::regtype::oid]
                  AND claim.proargnames[3:9] = ARRAY['tenant_id','event_id','event_document','attempts',
                      'fencing_token','lease_expires_at','installation_id']
                  AND claim.proargmodes[3:9] = ARRAY['t','t','t','t','t','t','t']::"char"[]
           )
           AND NOT EXISTS (
               SELECT 1 FROM iam.audit_outbox AS outbox
                WHERE outbox.status = 'DEAD_LETTER' OR outbox.attempts >= 100
           ),
           7::bigint,
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
        WHEN 'iam.account.create' THEN 'ACCOUNT'
        WHEN 'iam.account.read' THEN 'ACCOUNT'
        WHEN 'iam.account.set-status' THEN 'ACCOUNT'
        WHEN 'iam.account.recover-root-credentials' THEN 'ACCOUNT'
        WHEN 'iam.account.alias-set' THEN 'ACCOUNT'
        WHEN 'iam.user.list' THEN 'ACCOUNT'
        WHEN 'iam.user.set-status' THEN 'USER'
        WHEN 'iam.user.reset-password' THEN 'USER'
        WHEN 'iam.user.create' THEN 'ACCOUNT'
        WHEN 'iam.user.read' THEN 'USER'
        WHEN 'iam.policy.list' THEN 'ACCOUNT'
        WHEN 'iam.platform-policy.list' THEN 'INSTALLATION'
        WHEN 'iam.policy-attachment.create' THEN 'USER'
        WHEN 'iam.policy-attachment.revoke' THEN 'POLICY_ATTACHMENT'
        WHEN 'iam.platform-policy-attachment.create' THEN 'USER'
        WHEN 'iam.platform-policy-attachment.revoke' THEN 'POLICY_ATTACHMENT'
        WHEN 'iam.session.revoke' THEN 'SESSION'
        WHEN 'paas.execution-pool.create' THEN 'EXECUTION_POOL'
        WHEN 'paas.execution-pool.read' THEN 'EXECUTION_POOL'
        WHEN 'paas.execution-target.register' THEN 'EXECUTION_TARGET'
        WHEN 'paas.execution-target.read' THEN 'EXECUTION_TARGET'
        WHEN 'paas.platform-operation.read' THEN 'OPERATION'
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
        WHEN 'managedservice.offering.read' THEN 'SERVICE_OFFERING'
        WHEN 'managedservice.region.read' THEN 'REGION'
        WHEN 'managedservice.quota-entitlement.activate' THEN 'QUOTA_ENTITLEMENT'
        WHEN 'managedservice.quota-entitlement.read' THEN 'QUOTA_ENTITLEMENT'
        WHEN 'managedservice.service-installation.create' THEN 'SERVICE_INSTALLATION'
        WHEN 'managedservice.service-installation.read' THEN 'SERVICE_INSTALLATION'
        WHEN 'audit.record.read' THEN 'AUDIT_RECORD'
        WHEN 'audit.integrity.verify' THEN 'AUDIT_CHAIN'
        WHEN 'audit.platform-record.read' THEN 'AUDIT_RECORD'
        WHEN 'audit.platform-integrity.verify' THEN 'AUDIT_CHAIN'
        WHEN 'installation.verify' THEN 'INSTALLATION'
        ELSE NULL
    END
$function$;

CREATE OR REPLACE FUNCTION iam.is_platform_action(submitted_action text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT COALESCE(submitted_action IN (
        'iam.account.create', 'iam.account.read',
        'iam.account.set-status', 'iam.account.recover-root-credentials',
        'iam.platform-policy-attachment.create', 'iam.platform-policy-attachment.revoke', 'iam.platform-policy.list',
        'paas.execution-pool.create', 'paas.execution-pool.read',
        'paas.execution-target.register', 'paas.execution-target.read',
        'paas.platform-operation.read', 'audit.platform-record.read',
        'audit.platform-integrity.verify'
    ), false)
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
      FROM iam.accounts AS organization
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
    password_version bigint;
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
    SELECT credential.credential_version INTO password_version
      FROM iam.accounts AS organization
      JOIN iam.principals AS principal ON principal.tenant_id = organization.id
      JOIN iam.user_credentials AS credential
        ON credential.tenant_id = principal.tenant_id AND credential.principal_id = principal.id
     WHERE organization.id = submitted_tenant_id AND organization.status = 'ACTIVE'
       AND principal.id = submitted_principal_id AND principal.principal_type = 'USER'
       AND principal.status = 'ACTIVE';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'session subject is unavailable';
    END IF;
    PERFORM iam.assert_audit_event(
        submitted_audit_event, submitted_tenant_id,
        'iam.session.issued', 'SESSION', submitted_session_id, 'SUCCEEDED'
    );
    INSERT INTO iam.sessions (
        tenant_id, id, principal_id, verification_digest, status, resource_version,
        issued_at, expires_at, credential_version
    ) VALUES (
        submitted_tenant_id, submitted_session_id, submitted_principal_id,
        submitted_verification_digest, 'ACTIVE', 1, effective_now,
        effective_expires_at, password_version
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

CREATE OR REPLACE FUNCTION iam.current_policy_snapshot(tenant text, principal text)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'policy',jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','Policy',
            'id',p.id,'management',p.management,'accountId',p.owner_tenant_id,'displayName',p.display_name,
            'scope',p.authority_scope,'status',p.status,'defaultVersionId',p.default_version_id,
            'resourceVersion',p.resource_version,'createdAt',p.created_at,'updatedAt',p.updated_at)),
        'version',jsonb_build_object('policyId',v.policy_id,'versionId',v.id,'document',v.document,'contentDigest',v.content_digest),
        'attachment',jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','PolicyAttachment',
            'id',a.id,'accountId',a.tenant_id,'target',jsonb_build_object('kind',a.target_kind,'id',a.principal_id),
            'policyId',a.policy_id,'scope',a.authority_scope,'installationId',a.installation_id,
            'resourceVersion',a.resource_version,'createdAt',a.created_at,'updatedAt',a.updated_at))) ORDER BY a.id), '[]'::jsonb)
    FROM (SELECT attachment.* FROM iam.policy_attachments AS attachment
        JOIN iam.policies AS available ON available.id=attachment.policy_id AND available.status='ACTIVE'
        WHERE attachment.tenant_id=tenant AND attachment.principal_id=principal AND attachment.revoked_at IS NULL
        ORDER BY attachment.id LIMIT 257) AS a
    JOIN iam.policies AS p ON p.id=a.policy_id
    JOIN iam.policy_versions AS v ON v.policy_id=p.id AND v.id=p.default_version_id
$function$;

DROP FUNCTION IF EXISTS iam.lookup_session(text);
CREATE FUNCTION iam.lookup_session(submitted_lookup_digest text)
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
    policies jsonb
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
           iam.current_policy_snapshot(principal.tenant_id,principal.id)
      FROM iam.sessions AS session
      JOIN iam.accounts AS organization ON organization.id = session.tenant_id
      JOIN iam.principals AS principal
        ON principal.tenant_id = session.tenant_id
       AND principal.id = session.principal_id
      JOIN iam.user_credentials AS credential
        ON credential.tenant_id = principal.tenant_id
       AND credential.principal_id = principal.id
     WHERE session.tenant_id = indexed.tenant_id
       AND session.id = indexed.session_id
       AND session.status = 'ACTIVE'
       AND session.revoked_at IS NULL
       AND session.expires_at > transaction_timestamp()
       AND session.credential_version = credential.credential_version
       AND organization.status = 'ACTIVE'
       AND principal.status = 'ACTIVE';
END
$function$;

DROP FUNCTION IF EXISTS iam.lookup_service(text);
CREATE FUNCTION iam.lookup_service(submitted_lookup_digest text)
RETURNS TABLE (
    tenant_id text,
    principal_id text,
    purpose text,
    verification_digest text,
    installation_id text
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
           credential.purpose, credential.verification_digest, receipt.installation_id
      FROM iam.service_credentials AS credential
      JOIN iam.accounts AS organization ON organization.id = credential.tenant_id
      JOIN iam.principals AS principal
        ON principal.tenant_id = credential.tenant_id
       AND principal.id = credential.principal_id
      JOIN iam.bootstrap_receipts AS receipt ON receipt.organization_id = credential.tenant_id
     WHERE credential.tenant_id = indexed.tenant_id
       AND credential.principal_id = indexed.principal_id
       AND credential.revoked_at IS NULL
       AND organization.status = 'ACTIVE'
       AND principal.status = 'ACTIVE';
END
$function$;

CREATE OR REPLACE FUNCTION iam.lookup_service_policies(
    submitted_tenant_id text,
    submitted_principal_id text
)
RETURNS TABLE (policies jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF submitted_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_principal_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'IAM service subject is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id', submitted_tenant_id, true);
    RETURN QUERY
    SELECT iam.current_policy_snapshot(principal.tenant_id,principal.id)
      FROM iam.accounts AS organization
      JOIN iam.principals AS principal
        ON principal.tenant_id = organization.id
     WHERE organization.id = submitted_tenant_id
       AND organization.status = 'ACTIVE'
       AND principal.id = submitted_principal_id
       AND principal.principal_type = 'SERVICE_ACCOUNT'
       AND principal.status = 'ACTIVE'
       AND EXISTS (
           SELECT 1
             FROM iam.service_credentials AS credential
            WHERE credential.tenant_id = principal.tenant_id
              AND credential.principal_id = principal.id
              AND credential.revoked_at IS NULL
       );
END
$function$;

DROP FUNCTION IF EXISTS iam.record_authorization(text,text,jsonb,jsonb);
CREATE OR REPLACE FUNCTION iam.record_authorization(
    submitted_tenant_id text,
    submitted_principal_id text,
    submitted_decision jsonb,
    submitted_audit_event jsonb,
    submitted_policy_evidence jsonb
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
    platform_action boolean;
    evidence jsonb;
    previous_attachment text COLLATE "C" := '';
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
            'subject', 'installationId', 'action', 'resource', 'requestId', 'decidedAt'
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
      FROM iam.accounts AS organization
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
    platform_action := iam.is_platform_action(submitted_decision->>'action');
    IF decision_allowed AND actor_type='USER' AND EXISTS(SELECT 1 FROM iam.principals AS principal
        WHERE principal.tenant_id=submitted_tenant_id AND principal.id=submitted_principal_id AND principal.must_change_password) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='authorization subject requires credential replacement';
    END IF;
    IF jsonb_typeof(submitted_policy_evidence) IS DISTINCT FROM 'array'
        OR jsonb_array_length(submitted_policy_evidence)>256
        OR (decision_allowed AND jsonb_array_length(submitted_policy_evidence)=0) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='authorization policy evidence is invalid';
    END IF;
    FOR evidence IN SELECT value FROM jsonb_array_elements(submitted_policy_evidence) LOOP
        IF jsonb_typeof(evidence) IS DISTINCT FROM 'object'
            OR NOT evidence ?& ARRAY['attachmentId','resourceVersion','version']
            OR (evidence-ARRAY['attachmentId','resourceVersion','version']) <> '{}'::jsonb
            OR COALESCE(evidence->>'attachmentId','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            OR evidence->>'attachmentId' COLLATE "C" <= previous_attachment
            OR jsonb_typeof(evidence->'resourceVersion') IS DISTINCT FROM 'number'
            OR COALESCE(evidence->>'resourceVersion','') !~ '^[1-9][0-9]{0,15}$'
            OR jsonb_typeof(evidence->'version') IS DISTINCT FROM 'object'
            OR NOT (evidence->'version') ?& ARRAY['policyId','versionId','contentDigest']
            OR ((evidence->'version')-ARRAY['policyId','versionId','contentDigest']) <> '{}'::jsonb THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='authorization policy evidence shape is invalid';
        END IF;
        IF NOT EXISTS(SELECT 1 FROM iam.policy_attachments AS attachment
            JOIN iam.policies AS policy ON policy.id=attachment.policy_id
            JOIN iam.policy_versions AS version ON version.policy_id=policy.id AND version.id=policy.default_version_id
            WHERE attachment.tenant_id=submitted_tenant_id AND attachment.principal_id=submitted_principal_id
              AND attachment.target_kind=actor_type AND attachment.id=evidence->>'attachmentId'
              AND attachment.resource_version=(evidence->>'resourceVersion')::bigint
              AND attachment.revoked_at IS NULL AND policy.status='ACTIVE'
              AND (policy.owner_tenant_id IS NULL OR policy.owner_tenant_id=submitted_tenant_id)
              AND policy.id=evidence#>>'{version,policyId}' AND version.id=evidence#>>'{version,versionId}'
              AND version.content_digest=evidence#>>'{version,contentDigest}'
              AND attachment.authority_scope=CASE WHEN platform_action THEN 'INSTALLATION'
                  WHEN submitted_decision->>'action'='installation.verify' THEN 'INSTALLATION_PROBE' ELSE 'TENANT' END) THEN
            RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='authorization policy evidence is not current for its subject';
        END IF;
        previous_attachment := evidence->>'attachmentId';
    END LOOP;
    expected_result := CASE WHEN decision_allowed THEN 'ALLOWED' ELSE 'DENIED' END;
    IF submitted_decision->>'reason' IS DISTINCT FROM expected_result
       OR (decision_allowed AND (
            NOT (submitted_decision ? 'subject')
            OR jsonb_typeof(submitted_decision->'subject') <> 'object'
            OR ((submitted_decision->'subject') - ARRAY['type', 'id']) <> '{}'::jsonb
            OR NOT ((submitted_decision->'subject') ?& ARRAY['type', 'id'])
            OR submitted_decision#>>'{subject,type}' IS DISTINCT FROM actor_type
            OR submitted_decision#>>'{subject,id}' IS DISTINCT FROM submitted_principal_id
            OR (NOT platform_action AND (
                submitted_decision ? 'installationId'
                OR submitted_decision->>'tenantId' IS DISTINCT FROM submitted_tenant_id
            ))
            OR (platform_action AND (
                submitted_decision ? 'tenantId'
                OR jsonb_typeof(submitted_decision->'installationId') IS DISTINCT FROM 'string'
                OR actor_type <> 'USER'
                OR NOT EXISTS (
                    SELECT 1 FROM iam.bootstrap_receipts AS receipt
                     WHERE receipt.organization_id = submitted_tenant_id
                       AND receipt.installation_id = submitted_decision->>'installationId'
                )
                OR NOT EXISTS (
                    SELECT 1 FROM iam.policy_attachments AS binding
                    JOIN iam.principals AS principal
                      ON principal.tenant_id = binding.tenant_id AND principal.id = binding.principal_id
                     WHERE binding.tenant_id = submitted_tenant_id
                       AND binding.principal_id = submitted_principal_id
                       AND binding.authority_scope = 'INSTALLATION'
                       AND binding.revoked_at IS NULL
                       AND NOT principal.must_change_password
                )
            ))
        ))
        OR (NOT decision_allowed AND (
            submitted_decision ? 'tenantId' OR submitted_decision ? 'installationId' OR submitted_decision ? 'subject'
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
        target_id, request_id, decided_at, document, policy_evidence
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
        submitted_decision,
        submitted_policy_evidence
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

CREATE OR REPLACE FUNCTION iam.assert_allowed_decision(
    submitted_tenant_id text,
    submitted_actor_principal_id text,
    submitted_decision_id text,
    submitted_action text,
    submitted_target_kind text,
    submitted_target_id text
)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF submitted_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_actor_principal_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_decision_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_target_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'authorization reference is invalid';
    END IF;
    IF iam.resource_kind_for_action(submitted_action) IS NULL
       OR iam.resource_kind_for_action(submitted_action) IS DISTINCT FROM submitted_target_kind THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'authorization action is not current';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id', submitted_tenant_id, true);
    IF NOT EXISTS (
        SELECT 1
          FROM iam.authorization_decisions AS decision
         WHERE decision.tenant_id = submitted_tenant_id
           AND decision.id = submitted_decision_id
           AND decision.principal_id = submitted_actor_principal_id
           AND decision.allowed
           AND decision.action_name = submitted_action
           AND decision.target_kind = submitted_target_kind
           AND decision.target_id = submitted_target_id
           AND decision.decided_at = transaction_timestamp()
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'authorization decision is unavailable';
    END IF;
END
$function$;

CREATE OR REPLACE FUNCTION iam.assert_user_audit_actor(
    submitted_tenant_id text,
    submitted_actor_principal_id text,
    submitted_audit_event jsonb
)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id', submitted_tenant_id, true);
    IF submitted_audit_event#>>'{actor,type}' IS DISTINCT FROM 'USER'
       OR submitted_audit_event#>>'{actor,id}' IS DISTINCT FROM submitted_actor_principal_id
       OR NOT EXISTS (
            SELECT 1
              FROM iam.principals AS principal
             WHERE principal.tenant_id = submitted_tenant_id
               AND principal.id = submitted_actor_principal_id
               AND principal.principal_type = 'USER'
               AND principal.status = 'ACTIVE'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Audit actor is unavailable';
    END IF;
END
$function$;

CREATE OR REPLACE FUNCTION iam.lookup_password(
    submitted_tenant_id text,
    submitted_principal_id text
)
RETURNS TABLE (password_hash text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF submitted_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_principal_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'password subject is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id', submitted_tenant_id, true);
    RETURN QUERY
    SELECT credential.password_hash
      FROM iam.user_credentials AS credential
      JOIN iam.accounts AS organization ON organization.id = credential.tenant_id
      JOIN iam.principals AS principal
        ON principal.tenant_id = credential.tenant_id
       AND principal.id = credential.principal_id
     WHERE credential.tenant_id = submitted_tenant_id
       AND credential.principal_id = submitted_principal_id
       AND organization.status = 'ACTIVE'
       AND principal.principal_type = 'USER'
       AND principal.status = 'ACTIVE';
END
$function$;

DROP FUNCTION IF EXISTS iam.change_password(text,text,text,text,jsonb);
CREATE OR REPLACE FUNCTION iam.change_password(
    submitted_tenant_id text,
    submitted_principal_id text,
    submitted_expected_password_hash text,
    submitted_new_password_hash text,
    submitted_audit_event jsonb,
    submitted_session_id text,
    submitted_revoke_other_sessions boolean
)
RETURNS TABLE (changed_at timestamptz, bootstrap_file_retirable boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_now timestamptz(6) := transaction_timestamp();
    changed integer;
    retirable boolean;
    subject iam.principals%ROWTYPE;
    current_session iam.sessions%ROWTYPE;
    previous_version bigint;
    revoke_others boolean;
BEGIN
    IF submitted_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_principal_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_expected_password_hash NOT LIKE '$matrix-iam-v1$argon2id$v=19$%'
       OR submitted_new_password_hash NOT LIKE '$matrix-iam-v1$argon2id$v=19$%'
       OR submitted_expected_password_hash = submitted_new_password_hash
       OR COALESCE(submitted_session_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_revoke_other_sessions IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'password mutation is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id', submitted_tenant_id, true);
    -- All credential changes share the principal lock with reset/recovery and
    -- platform grants; the caller cannot select a session in the public API.
    PERFORM 1 FROM iam.accounts AS organization
     WHERE organization.id=submitted_tenant_id AND organization.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='password organization is unavailable';
    END IF;
    SELECT * INTO subject FROM iam.principals AS principal
     WHERE principal.tenant_id = submitted_tenant_id AND principal.id = submitted_principal_id
       AND principal.principal_type = 'USER' AND principal.status = 'ACTIVE' FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'password subject is unavailable';
    END IF;
    SELECT credential.credential_version INTO previous_version FROM iam.user_credentials AS credential
     WHERE credential.tenant_id = submitted_tenant_id AND credential.principal_id = submitted_principal_id
       AND credential.password_hash = submitted_expected_password_hash FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'password changed concurrently';
    END IF;
    SELECT * INTO current_session FROM iam.sessions AS session
     WHERE session.tenant_id = submitted_tenant_id AND session.principal_id = submitted_principal_id
       AND session.id = submitted_session_id AND session.status = 'ACTIVE'
       AND session.revoked_at IS NULL AND session.expires_at > effective_now FOR UPDATE;
    IF NOT FOUND OR current_session.credential_version IS DISTINCT FROM previous_version THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'password session is unavailable';
    END IF;
    revoke_others := subject.must_change_password OR submitted_revoke_other_sessions;
    PERFORM iam.assert_audit_event(
        submitted_audit_event, submitted_tenant_id,
        'iam.user.password-changed', 'USER', submitted_principal_id, 'SUCCEEDED'
    );
    PERFORM iam.assert_user_audit_actor(
        submitted_tenant_id, submitted_principal_id, submitted_audit_event
    );
    UPDATE iam.user_credentials AS credential
       SET password_hash = submitted_new_password_hash,
           changed_at = effective_now,
           credential_version = previous_version + 1
     WHERE credential.tenant_id = submitted_tenant_id
       AND credential.principal_id = submitted_principal_id
       AND credential.password_hash = submitted_expected_password_hash;
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'password changed concurrently';
    END IF;
    UPDATE iam.principals AS principal
       SET must_change_password = false,
           resource_version = principal.resource_version + 1,
           updated_at = effective_now
     WHERE principal.tenant_id = submitted_tenant_id
       AND principal.id = submitted_principal_id
       AND principal.principal_type = 'USER'
       AND principal.status = 'ACTIVE';
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'password subject is unavailable';
    END IF;
    UPDATE iam.sessions AS session
       SET status = 'REVOKED', revoked_at = effective_now,
           resource_version = session.resource_version + 1
     WHERE session.tenant_id = submitted_tenant_id AND session.principal_id = submitted_principal_id
       AND session.id <> submitted_session_id AND session.status = 'ACTIVE'
       AND (revoke_others OR session.credential_version IS DISTINCT FROM previous_version);
    -- Only still-active sessions admitted by this password change advance to
    -- the new credential epoch. Revoked sessions are never restored.
    UPDATE iam.sessions AS session
       SET credential_version = previous_version + 1, resource_version = session.resource_version + 1
     WHERE session.tenant_id = submitted_tenant_id AND session.principal_id = submitted_principal_id
       AND session.status = 'ACTIVE' AND session.revoked_at IS NULL AND session.expires_at > effective_now;
    SELECT EXISTS (
        SELECT 1
          FROM iam.bootstrap_receipts AS receipt
         WHERE receipt.singleton
           AND receipt.organization_id = submitted_tenant_id
           AND receipt.administrator_principal_id = submitted_principal_id
    ) INTO retirable;
    INSERT INTO iam.audit_outbox (
        tenant_id, event_id, event_document, next_attempt_at,
        created_at, updated_at
    ) VALUES (
        submitted_tenant_id, submitted_audit_event->>'eventId',
        submitted_audit_event, effective_now, effective_now, effective_now
    );
    RETURN QUERY SELECT effective_now, retirable;
END
$function$;

CREATE OR REPLACE FUNCTION iam.revoke_session(
    submitted_tenant_id text,
    submitted_session_id text,
    submitted_actor_principal_id text,
    submitted_decision_id text,
    submitted_audit_event jsonb
)
RETURNS TABLE (resource_version bigint, revoked_at timestamptz, applied boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_now timestamptz(6) := transaction_timestamp();
    stored iam.sessions%ROWTYPE;
BEGIN
    IF submitted_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_session_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_actor_principal_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR (submitted_decision_id IS NOT NULL AND submitted_decision_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'session revocation is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id', submitted_tenant_id, true);
    PERFORM 1 FROM iam.accounts AS organization
     WHERE organization.id=submitted_tenant_id AND organization.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='session organization is unavailable';
    END IF;
    -- Discover the immutable principal reference without locking the session
    -- ahead of password/reset/recovery, which all lock its principal first.
    SELECT * INTO stored FROM iam.sessions AS session
     WHERE session.tenant_id=submitted_tenant_id AND session.id=submitted_session_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='session is unavailable';
    END IF;
    PERFORM 1 FROM iam.principals AS principal
     WHERE principal.tenant_id=submitted_tenant_id AND principal.id=stored.principal_id FOR UPDATE;
    SELECT * INTO stored
      FROM iam.sessions AS session
     WHERE session.tenant_id = submitted_tenant_id
       AND session.id = submitted_session_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'session is unavailable';
    END IF;
    IF submitted_decision_id IS NULL THEN
        IF stored.principal_id <> submitted_actor_principal_id
           OR submitted_audit_event ? 'iamDecisionId' THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'session self-revocation is forbidden';
        END IF;
    ELSE
        PERFORM iam.assert_allowed_decision(
            submitted_tenant_id, submitted_actor_principal_id,
            submitted_decision_id, 'iam.session.revoke', 'SESSION', submitted_session_id
        );
        IF submitted_audit_event->>'iamDecisionId' IS DISTINCT FROM submitted_decision_id THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'session decision correlation is invalid';
        END IF;
    END IF;
    IF stored.status = 'REVOKED' THEN
        RETURN QUERY SELECT stored.resource_version, stored.revoked_at, false;
        RETURN;
    END IF;
    PERFORM iam.assert_audit_event(
        submitted_audit_event, submitted_tenant_id,
        'iam.session.revoked', 'SESSION', submitted_session_id, 'SUCCEEDED'
    );
    PERFORM iam.assert_user_audit_actor(
        submitted_tenant_id, submitted_actor_principal_id, submitted_audit_event
    );
    UPDATE iam.sessions AS session
       SET status = 'REVOKED',
           resource_version = session.resource_version + 1,
           revoked_at = effective_now
     WHERE session.tenant_id = submitted_tenant_id
       AND session.id = submitted_session_id;
    INSERT INTO iam.audit_outbox (
        tenant_id, event_id, event_document, next_attempt_at,
        created_at, updated_at
    ) VALUES (
        submitted_tenant_id, submitted_audit_event->>'eventId',
        submitted_audit_event, effective_now, effective_now, effective_now
    );
    RETURN QUERY SELECT stored.resource_version + 1, effective_now, true;
END
$function$;

CREATE OR REPLACE FUNCTION iam.create_user(
    submitted_tenant_id text,
    submitted_principal_id text,
    submitted_login_name text,
    submitted_display_name text,
    submitted_password_hash text,
    submitted_actor_principal_id text,
    submitted_decision_id text,
    submitted_audit_event jsonb
)
RETURNS TABLE (created_at timestamptz, updated_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_now timestamptz(6) := transaction_timestamp();
BEGIN
    IF submitted_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_principal_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_login_name COLLATE "C" !~ '^[a-z][a-z0-9._-]{2,63}$'
       OR length(submitted_display_name) NOT BETWEEN 1 AND 128
       OR btrim(submitted_display_name) <> submitted_display_name
       OR submitted_password_hash NOT LIKE '$matrix-iam-v1$argon2id$v=19$%' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'user mutation is invalid';
    END IF;
    PERFORM iam.assert_allowed_decision(
        submitted_tenant_id, submitted_actor_principal_id,
        submitted_decision_id, 'iam.user.create', 'ACCOUNT', submitted_tenant_id
    );
    PERFORM iam.assert_audit_event(
        submitted_audit_event, submitted_tenant_id,
        'iam.user.created', 'USER', submitted_principal_id, 'SUCCEEDED'
    );
    PERFORM iam.assert_user_audit_actor(
        submitted_tenant_id, submitted_actor_principal_id, submitted_audit_event
    );
    IF submitted_audit_event->>'iamDecisionId' IS DISTINCT FROM submitted_decision_id THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'user decision correlation is invalid';
    END IF;
    INSERT INTO iam.principals (
        tenant_id, id, principal_type, login_name, display_name, status,
        must_change_password, resource_version, created_at, updated_at
    ) VALUES (
        submitted_tenant_id, submitted_principal_id, 'USER', submitted_login_name,
        submitted_display_name, 'ACTIVE', true, 1, effective_now, effective_now
    );
    INSERT INTO iam.user_credentials (
        tenant_id, principal_id, password_hash, changed_at
    ) VALUES (
        submitted_tenant_id, submitted_principal_id,
        submitted_password_hash, effective_now
    );
    INSERT INTO iam.login_index (login_name, tenant_id, principal_id)
    VALUES (submitted_login_name, submitted_tenant_id, submitted_principal_id);
    INSERT INTO iam.audit_outbox (
        tenant_id, event_id, event_document, next_attempt_at,
        created_at, updated_at
    ) VALUES (
        submitted_tenant_id, submitted_audit_event->>'eventId',
        submitted_audit_event, effective_now, effective_now, effective_now
    );
    RETURN QUERY SELECT effective_now, effective_now;
END
$function$;

CREATE OR REPLACE FUNCTION iam.lookup_policy(submitted_tenant_id text, submitted_policy_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE result jsonb;
BEGIN
    IF COALESCE(submitted_tenant_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_policy_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy reference is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',submitted_tenant_id,true);
    SELECT jsonb_strip_nulls(jsonb_build_object(
        'apiVersion','iam.matrix.xiak.com/v1','kind','Policy','id',p.id,
        'management',p.management,'accountId',p.owner_tenant_id,'displayName',p.display_name,
        'scope',p.authority_scope,'status',p.status,'defaultVersionId',p.default_version_id,
        'resourceVersion',p.resource_version,'createdAt',p.created_at,'updatedAt',p.updated_at))
      INTO result FROM iam.policies AS p
     WHERE p.id=submitted_policy_id AND (p.owner_tenant_id IS NULL OR p.owner_tenant_id=submitted_tenant_id);
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.lookup_policy_attachment(submitted_tenant_id text, submitted_attachment_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE result jsonb;
BEGIN
    IF COALESCE(submitted_tenant_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_attachment_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy attachment reference is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',submitted_tenant_id,true);
    SELECT jsonb_strip_nulls(jsonb_build_object(
        'apiVersion','iam.matrix.xiak.com/v1','kind','PolicyAttachment','id',a.id,'accountId',a.tenant_id,
        'target',jsonb_build_object('kind',a.target_kind,'id',a.principal_id),'policyId',a.policy_id,
        'scope',a.authority_scope,'installationId',a.installation_id,'resourceVersion',a.resource_version,
        'createdAt',a.created_at,'updatedAt',a.updated_at,'revokedAt',a.revoked_at))
      INTO result FROM iam.policy_attachments AS a
     WHERE a.tenant_id=submitted_tenant_id AND a.id=submitted_attachment_id;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.list_policies(
    submitted_tenant_id text, submitted_actor_principal_id text, submitted_decision_id text, submitted_scope text
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    installation text;
    items jsonb;
BEGIN
    IF submitted_scope IS NULL OR submitted_scope NOT IN ('TENANT','INSTALLATION') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy directory scope is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',submitted_tenant_id,true);
    IF NOT EXISTS(SELECT 1 FROM iam.principals AS p JOIN iam.accounts AS o ON o.id=p.tenant_id
        WHERE p.tenant_id=submitted_tenant_id AND p.id=submitted_actor_principal_id
          AND p.principal_type='USER' AND p.status='ACTIVE' AND NOT p.must_change_password AND o.status='ACTIVE') THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy directory actor is unavailable';
    END IF;
    IF submitted_scope='INSTALLATION' THEN
        SELECT installation_id INTO installation FROM iam.bootstrap_receipts WHERE organization_id=submitted_tenant_id;
        IF installation IS NULL THEN
            RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy directory installation is unavailable';
        END IF;
        PERFORM iam.assert_allowed_decision(submitted_tenant_id,submitted_actor_principal_id,submitted_decision_id,
            'iam.platform-policy.list','INSTALLATION',installation);
    ELSE
        PERFORM iam.assert_allowed_decision(submitted_tenant_id,submitted_actor_principal_id,submitted_decision_id,
            'iam.policy.list','ACCOUNT',submitted_tenant_id);
    END IF;
    SELECT COALESCE(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
        'apiVersion','iam.matrix.xiak.com/v1','kind','Policy','id',p.id,'management',p.management,
        'accountId',p.owner_tenant_id,'displayName',p.display_name,'scope',p.authority_scope,'status',p.status,
        'defaultVersionId',p.default_version_id,'resourceVersion',p.resource_version,
        'createdAt',p.created_at,'updatedAt',p.updated_at)) ORDER BY p.id COLLATE "C"),'[]'::jsonb)
      INTO items FROM (SELECT * FROM iam.policies
        WHERE authority_scope=submitted_scope AND (owner_tenant_id IS NULL OR owner_tenant_id=submitted_tenant_id)
        ORDER BY id COLLATE "C" LIMIT 257) AS p;
    IF jsonb_array_length(items)>256 THEN
        RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='policy directory exceeds its read budget';
    END IF;
    RETURN jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','PolicyList',
        'accountId',submitted_tenant_id,'scope',submitted_scope,'installationId',installation,'items',items));
END $function$;

CREATE OR REPLACE FUNCTION iam.create_policy_attachment(
    submitted_tenant_id text, submitted_attachment_id text, submitted_principal_id text,
    submitted_policy_id text, submitted_policy_version bigint, submitted_actor_principal_id text,
    submitted_decision_id text, submitted_audit_event jsonb
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_now timestamptz(6) := transaction_timestamp();
    stored iam.policy_attachments%ROWTYPE;
    policy iam.policies%ROWTYPE;
    target iam.principals%ROWTYPE;
    action_name text;
    event_action text;
BEGIN
    IF COALESCE(submitted_tenant_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_attachment_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_principal_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_policy_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_policy_version IS NULL OR submitted_policy_version NOT BETWEEN 1 AND 9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy attachment input is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',submitted_tenant_id,true);
    PERFORM 1 FROM iam.accounts WHERE id=submitted_tenant_id AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account is unavailable'; END IF;
    SELECT * INTO target FROM iam.principals
     WHERE tenant_id=submitted_tenant_id AND id=submitted_principal_id AND principal_type='USER' AND status='ACTIVE' FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='attachment target is unavailable'; END IF;
    SELECT * INTO policy FROM iam.policies
     WHERE id=submitted_policy_id AND status='ACTIVE'
       AND (owner_tenant_id IS NULL OR owner_tenant_id=submitted_tenant_id) FOR SHARE;
    IF NOT FOUND OR policy.authority_scope NOT IN ('TENANT','INSTALLATION') THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='attachment policy is unavailable';
    END IF;
    IF policy.resource_version <> submitted_policy_version THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy revision conflicts';
    END IF;
    IF policy.authority_scope='INSTALLATION' AND (target.must_change_password OR NOT EXISTS (
        SELECT 1 FROM iam.bootstrap_receipts WHERE organization_id=submitted_tenant_id
    )) THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='platform target is unavailable'; END IF;
    action_name := CASE policy.authority_scope WHEN 'INSTALLATION' THEN 'iam.platform-policy-attachment.create'
                   ELSE 'iam.policy-attachment.create' END;
    event_action := CASE policy.authority_scope WHEN 'INSTALLATION' THEN 'iam.platform-policy-attachment.created'
                    ELSE 'iam.policy-attachment.created' END;
    PERFORM iam.assert_allowed_decision(submitted_tenant_id,submitted_actor_principal_id,submitted_decision_id,
        action_name,'USER',submitted_principal_id);
    PERFORM iam.assert_audit_event(submitted_audit_event,submitted_tenant_id,event_action,'POLICY_ATTACHMENT',submitted_attachment_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(submitted_tenant_id,submitted_actor_principal_id,submitted_audit_event);
    IF submitted_audit_event->>'iamDecisionId' IS DISTINCT FROM submitted_decision_id THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='attachment decision correlation is invalid';
    END IF;
    SELECT * INTO stored FROM iam.policy_attachments
     WHERE tenant_id=submitted_tenant_id AND id=submitted_attachment_id FOR UPDATE;
    IF FOUND THEN
        IF stored.principal_id<>submitted_principal_id OR stored.policy_id<>submitted_policy_id OR stored.revoked_at IS NOT NULL
           OR NOT EXISTS (SELECT 1 FROM iam.audit_outbox WHERE tenant_id=submitted_tenant_id
               AND event_document->>'action'=event_action AND event_document#>>'{target,id}'=stored.id
               AND event_document->>'requestId'=submitted_audit_event->>'requestId'
               AND event_document->>'requestDigest'=submitted_audit_event->>'requestDigest'
               AND event_document#>>'{actor,id}'=submitted_actor_principal_id) THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='attachment intent conflicts';
        END IF;
        RETURN iam.lookup_policy_attachment(submitted_tenant_id,stored.id);
    END IF;
    INSERT INTO iam.policy_attachments(tenant_id,id,principal_id,policy_id,resource_version,created_at,updated_at)
    VALUES(submitted_tenant_id,submitted_attachment_id,submitted_principal_id,submitted_policy_id,1,effective_now,effective_now);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
    VALUES(submitted_tenant_id,submitted_audit_event->>'eventId',submitted_audit_event,effective_now,effective_now,effective_now);
    RETURN iam.lookup_policy_attachment(submitted_tenant_id,submitted_attachment_id);
END $function$;

DROP FUNCTION IF EXISTS iam.revoke_policy_attachment(text,text,text,text,jsonb);
CREATE OR REPLACE FUNCTION iam.revoke_policy_attachment(
    submitted_tenant_id text, submitted_attachment_id text, submitted_resource_version bigint,
    submitted_actor_principal_id text, submitted_decision_id text, submitted_audit_event jsonb
)
RETURNS TABLE(resource_version bigint, revoked_at timestamptz, applied boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_now timestamptz(6) := transaction_timestamp();
    stored iam.policy_attachments%ROWTYPE;
    action_name text;
    event_action text;
BEGIN
    IF COALESCE(submitted_tenant_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_attachment_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_resource_version IS NULL OR submitted_resource_version NOT BETWEEN 1 AND 9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='attachment revocation input is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',submitted_tenant_id,true);
    PERFORM 1 FROM iam.accounts WHERE id=submitted_tenant_id AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account is unavailable'; END IF;
    SELECT * INTO stored FROM iam.policy_attachments
     WHERE tenant_id=submitted_tenant_id AND id=submitted_attachment_id;
    IF NOT FOUND OR stored.target_kind<>'USER' OR stored.authority_scope NOT IN ('TENANT','INSTALLATION') THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='attachment is unavailable';
    END IF;
    PERFORM 1 FROM iam.principals WHERE tenant_id=submitted_tenant_id AND id=stored.principal_id FOR UPDATE;
    PERFORM 1 FROM iam.policies WHERE id=stored.policy_id FOR SHARE;
    SELECT * INTO stored FROM iam.policy_attachments
     WHERE tenant_id=submitted_tenant_id AND id=submitted_attachment_id FOR UPDATE;
    action_name := CASE stored.authority_scope WHEN 'INSTALLATION' THEN 'iam.platform-policy-attachment.revoke'
                   ELSE 'iam.policy-attachment.revoke' END;
    event_action := CASE stored.authority_scope WHEN 'INSTALLATION' THEN 'iam.platform-policy-attachment.revoked'
                    ELSE 'iam.policy-attachment.revoked' END;
    PERFORM iam.assert_allowed_decision(submitted_tenant_id,submitted_actor_principal_id,submitted_decision_id,
        action_name,'POLICY_ATTACHMENT',submitted_attachment_id);
    IF stored.policy_id='system.account-administrator' AND EXISTS (
        SELECT 1 FROM iam.account_roots WHERE account_id=submitted_tenant_id AND principal_id=stored.principal_id
    ) THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='primary authority is protected'; END IF;
    PERFORM iam.assert_audit_event(submitted_audit_event,submitted_tenant_id,event_action,'POLICY_ATTACHMENT',submitted_attachment_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(submitted_tenant_id,submitted_actor_principal_id,submitted_audit_event);
    IF submitted_audit_event->>'iamDecisionId' IS DISTINCT FROM submitted_decision_id THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='attachment decision correlation is invalid';
    END IF;
    IF stored.revoked_at IS NOT NULL THEN
        IF stored.resource_version<>submitted_resource_version+1 OR NOT EXISTS (
            SELECT 1 FROM iam.audit_outbox WHERE tenant_id=submitted_tenant_id
            AND event_document->>'action'=event_action AND event_document#>>'{target,id}'=stored.id
            AND event_document->>'requestId'=submitted_audit_event->>'requestId'
            AND event_document->>'requestDigest'=submitted_audit_event->>'requestDigest'
            AND event_document#>>'{actor,id}'=submitted_actor_principal_id
        ) THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='revocation intent conflicts'; END IF;
        RETURN QUERY SELECT stored.resource_version,stored.revoked_at,false;
        RETURN;
    END IF;
    IF stored.resource_version<>submitted_resource_version OR stored.resource_version=9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='attachment revision conflicts';
    END IF;
    UPDATE iam.policy_attachments AS attachment SET resource_version=stored.resource_version+1,
        updated_at=effective_now,revoked_at=effective_now
     WHERE attachment.tenant_id=submitted_tenant_id AND attachment.id=submitted_attachment_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
    VALUES(submitted_tenant_id,submitted_audit_event->>'eventId',submitted_audit_event,effective_now,effective_now,effective_now);
    RETURN QUERY SELECT stored.resource_version+1,effective_now,true;
END $function$;

DROP FUNCTION IF EXISTS iam.claim_audit_event(text, integer);
CREATE FUNCTION iam.claim_audit_event(
    submitted_worker_id text,
    submitted_lease_seconds integer
)
RETURNS TABLE (
    tenant_id text,
    event_id text,
    event_document jsonb,
    attempts integer,
    fencing_token bigint,
    lease_expires_at timestamptz,
    installation_id text
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
           claimed.attempts, claimed.fencing_token, claimed.lease_expires_at,
           COALESCE(receipt.installation_id, '')
      FROM claimed
      LEFT JOIN iam.bootstrap_receipts AS receipt
        ON receipt.organization_id = claimed.tenant_id;
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
       OR (submitted_outcome = 'DEAD_LETTER'
            AND COALESCE(submitted_error_code, '') COLLATE "C"
                !~ '^[a-z][a-z0-9.]{2,127}$')
       OR (submitted_outcome <> 'DEAD_LETTER'
            AND submitted_error_code IS NOT NULL) THEN
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
           error_code = CASE
                WHEN submitted_outcome = 'DEAD_LETTER' THEN submitted_error_code
                ELSE NULL
           END,
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

CREATE OR REPLACE FUNCTION iam.audit_outbox_snapshot()
RETURNS TABLE (
    pending_count bigint,
    leased_count bigint,
    retry_count bigint,
    delivered_count bigint,
    dead_letter_count bigint,
    expired_lease_count bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    PERFORM set_config('matrix.iam_dispatcher', 'trusted', true);
    RETURN QUERY SELECT
        count(*) FILTER (WHERE status = 'PENDING'),
        count(*) FILTER (WHERE status = 'IN_FLIGHT'),
        count(*) FILTER (WHERE status = 'RETRY'),
        count(*) FILTER (WHERE status = 'DELIVERED'),
        count(*) FILTER (WHERE status = 'DEAD_LETTER'),
        count(*) FILTER (
            WHERE status = 'IN_FLIGHT'
              AND lease_expires_at <= transaction_timestamp()
        )
    FROM iam.audit_outbox;
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
GRANT EXECUTE ON FUNCTION iam.lookup_service_policies(text, text) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.lookup_password(text, text) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.record_authorization(
    text, text, jsonb, jsonb, jsonb
) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.change_password(
    text, text, text, text, jsonb, text, boolean
) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.revoke_session(
    text, text, text, text, jsonb
) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.create_user(
    text, text, text, text, text, text, text, jsonb
) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.create_policy_attachment(
    text, text, text, text, bigint, text, text, jsonb
) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.lookup_policy(text, text) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.list_policies(text, text, text, text) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.lookup_policy_attachment(text, text) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.revoke_policy_attachment(
    text, text, bigint, text, text, jsonb
) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.claim_audit_event(text, integer) TO matrix_iam_worker;
GRANT EXECUTE ON FUNCTION iam.complete_audit_event(
    text, text, bigint, text, integer, text
) TO matrix_iam_worker;
GRANT EXECUTE ON FUNCTION iam.audit_outbox_snapshot() TO matrix_iam_worker;

ALTER DEFAULT PRIVILEGES FOR ROLE matrix_iam_owner IN SCHEMA iam
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE matrix_iam_owner IN SCHEMA iam
    REVOKE ALL ON FUNCTIONS FROM PUBLIC;
