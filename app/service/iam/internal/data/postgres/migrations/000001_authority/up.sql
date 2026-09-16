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
    deleted_at timestamptz(6),
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
        AND (deleted_at IS NULL OR (
            principal_type = 'USER'
            AND status = 'DISABLED'
            AND NOT must_change_password
            AND deleted_at >= created_at
            AND updated_at = deleted_at
        ))
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

-- A deleted USER remains as an irreversible identity tombstone so historical
-- resource/audit references and the tenant-local login-name reservation never
-- change meaning. Retained pre-extension principals are live by definition.
ALTER TABLE iam.principals ADD COLUMN IF NOT EXISTS deleted_at timestamptz(6);
ALTER TABLE iam.principals DROP CONSTRAINT IF EXISTS principals_values_valid;
ALTER TABLE iam.principals ADD CONSTRAINT principals_values_valid CHECK (
    tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    AND principal_type IN ('USER', 'SERVICE_ACCOUNT')
    AND status IN ('ACTIVE', 'DISABLED')
    AND length(display_name) BETWEEN 1 AND 128
    AND btrim(display_name) = display_name
    AND resource_version BETWEEN 1 AND 9007199254740991
    AND updated_at >= created_at
    AND (deleted_at IS NULL OR (
        principal_type = 'USER'
        AND status = 'DISABLED'
        AND NOT must_change_password
        AND deleted_at >= created_at
        AND updated_at = deleted_at
    ))
    AND (
        (principal_type = 'USER' AND login_name COLLATE "C" ~ '^[a-z][a-z0-9._-]{2,63}$')
        OR (principal_type = 'SERVICE_ACCOUNT' AND login_name IS NULL AND NOT must_change_password)
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
    retired_at timestamptz(6),
    contract_version integer NOT NULL,
    compilation jsonb,
    PRIMARY KEY (policy_id,id),
    FOREIGN KEY (policy_id,authority_scope) REFERENCES iam.policies(id,authority_scope),
    CONSTRAINT policy_versions_content_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND octet_length(canonical_document) BETWEEN 1 AND 131072
        AND jsonb_typeof(document)='object' AND document ?& ARRAY['languageVersion','scope','statements']
        AND jsonb_typeof(document->'languageVersion')='string'
        AND jsonb_typeof(document->'scope')='string'
        AND document->>'languageVersion'='1' AND document->>'scope'=authority_scope
        AND jsonb_typeof(document->'statements')='array'
        AND jsonb_array_length(document->'statements') BETWEEN 1 AND 64
        AND contract_version IN (1,2)
    )
);

ALTER TABLE iam.policy_versions ADD COLUMN IF NOT EXISTS retired_at timestamptz(6);
-- Only rows present before this transaction's seed/publication phase can be
-- legacy. The preflight has already checked Root management eligibility.
DO $policy_version_contract_cutover$
BEGIN
    LOCK TABLE iam.policy_versions IN ACCESS EXCLUSIVE MODE;
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid='iam.policy_versions'::regclass
        AND attname='contract_version' AND NOT attisdropped) THEN
        ALTER TABLE iam.policy_versions NO FORCE ROW LEVEL SECURITY;
        DROP TRIGGER IF EXISTS policy_versions_are_immutable ON iam.policy_versions;
        ALTER TABLE iam.policy_versions ADD COLUMN contract_version integer;
        UPDATE iam.policy_versions SET contract_version=1;
        ALTER TABLE iam.policy_versions ALTER COLUMN contract_version SET NOT NULL;
        ALTER TABLE iam.policy_versions FORCE ROW LEVEL SECURITY;
    END IF;
END $policy_version_contract_cutover$;
ALTER TABLE iam.policy_versions ADD COLUMN IF NOT EXISTS compilation jsonb;
ALTER TABLE iam.policy_versions DROP CONSTRAINT IF EXISTS policy_versions_content_valid;
ALTER TABLE iam.policy_versions ADD CONSTRAINT policy_versions_content_valid CHECK (COALESCE(
    id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    AND octet_length(canonical_document) BETWEEN 1 AND 131072
    AND (canonical_document IS JSON OBJECT WITH UNIQUE KEYS)
    AND jsonb_typeof(document)='object' AND document ?& ARRAY['languageVersion','scope','statements']
    AND document-ARRAY['languageVersion','scope','statements']='{}'::jsonb
    AND jsonb_typeof(document->'languageVersion')='string' AND document->>'languageVersion'='1'
    AND jsonb_typeof(document->'scope')='string' AND document->>'scope'=authority_scope
    AND jsonb_typeof(document->'statements')='array' AND jsonb_array_length(document->'statements') BETWEEN 1 AND 64
    AND contract_version IN (1,2)
    AND CASE WHEN contract_version=1 THEN
        compilation IS NULL AND octet_length(canonical_document)<=65536 AND canonical_document::jsonb=document
        AND content_digest='sha256:'||encode(sha256(convert_to('matrix.iam.policy.v1','UTF8')||decode('00','hex')||convert_to(canonical_document,'UTF8')),'hex')
      ELSE
        compilation IS NOT NULL AND jsonb_typeof(compilation)='object'
        AND compilation ?& ARRAY['compilationVersion','profiles','resolvedStatements']
        AND compilation-ARRAY['compilationVersion','profiles','resolvedStatements']='{}'::jsonb
        AND compilation->>'compilationVersion'='1' AND jsonb_typeof(compilation->'compilationVersion')='string'
        AND jsonb_typeof(compilation->'profiles')='array' AND jsonb_array_length(compilation->'profiles') BETWEEN 1 AND 16
        AND jsonb_typeof(compilation->'resolvedStatements')='array' AND jsonb_array_length(compilation->'resolvedStatements')=jsonb_array_length(document->'statements')
        AND canonical_document::jsonb=compilation||jsonb_build_object('document',document)
        AND content_digest='sha256:'||encode(sha256(convert_to('matrix.iam.policy-compilation.v1','UTF8')||decode('00','hex')||convert_to(canonical_document,'UTF8')),'hex')
      END, false));
ALTER TABLE iam.policy_versions DROP CONSTRAINT IF EXISTS policy_versions_retirement_valid;
ALTER TABLE iam.policy_versions ADD CONSTRAINT policy_versions_retirement_valid CHECK (retired_at IS NULL OR retired_at>=created_at);

CREATE OR REPLACE FUNCTION iam.policy_version_snapshot(version iam.policy_versions)
RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_build_object('canonical',version.canonical_document,'value',jsonb_strip_nulls(jsonb_build_object('policyId',version.policy_id,'versionId',version.id,
        'document',version.document,'contentDigest',version.content_digest,'contractVersion',version.contract_version,
        'compilation',version.compilation)));
$function$;
REVOKE ALL ON FUNCTION iam.policy_version_snapshot(iam.policy_versions) FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;

CREATE OR REPLACE FUNCTION iam.policy_version_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a
        WHERE a.attrelid='iam.policy_versions'::regclass AND a.attname='contract_version'
          AND a.atttypid='integer'::regtype AND a.attnotnull AND NOT a.attisdropped
          AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attrdef d WHERE d.adrelid=a.attrelid AND d.adnum=a.attnum))
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a
        WHERE a.attrelid='iam.policy_versions'::regclass AND a.attname='compilation'
          AND a.atttypid='jsonb'::regtype AND NOT a.attnotnull AND NOT a.attisdropped
          AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attrdef d WHERE d.adrelid=a.attrelid AND d.adnum=a.attnum))
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid='iam.policy_versions'::regclass
          AND c.conname='policy_versions_content_valid' AND c.contype='c' AND c.convalidated)
      AND (SELECT count(*) FROM pg_catalog.pg_proc p WHERE p.pronamespace='iam'::regnamespace
          AND p.proname IN ('create_policy','create_policy_version'))=2
      AND (SELECT count(*) FROM pg_catalog.pg_proc p WHERE p.oid IN (
          to_regprocedure('iam.create_policy(text,text,text,text,text,text,text,text,jsonb,integer)'),
          to_regprocedure('iam.create_policy_version(text,text,text,text,bigint,text,text,text,jsonb,integer)'))
          AND p.pronargdefaults=0 AND p.pronargs=10 AND p.prorettype='jsonb'::regtype
          AND NOT p.proretset AND p.prosecdef AND p.proowner='matrix_iam_owner'::regrole)=2
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('iam.policy_version_snapshot(iam.policy_versions)')
          AND p.pronargs=1 AND p.pronargdefaults=0 AND p.prorettype='jsonb'::regtype AND NOT p.proretset
          AND NOT p.prosecdef AND p.proowner='matrix_iam_owner'::regrole)
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('iam.recorded_policy_version_matches(jsonb)')
          AND p.pronargs=1 AND p.pronargdefaults=0 AND p.prorettype='boolean'::regtype AND NOT p.proretset
          AND NOT p.prosecdef AND p.proowner='matrix_iam_owner'::regrole)
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
          WHERE p.oid IN (to_regprocedure('iam.policy_version_snapshot(iam.policy_versions)'),to_regprocedure('iam.assert_policy_compilation(text,text,text)'),
              to_regprocedure('iam.recorded_policy_version_matches(jsonb)'))
          AND a.privilege_type='EXECUTE' AND a.grantee<>p.proowner)
      AND to_regprocedure('iam.assert_policy_compilation(text,text,text)') IS NOT NULL
      AND to_regprocedure('iam.assert_customer_policy_document(text,text)') IS NULL;
$function$;
REVOKE ALL ON FUNCTION iam.policy_version_contract_ready() FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;

ALTER TABLE iam.policies DROP CONSTRAINT IF EXISTS policies_default_version_fk;
ALTER TABLE iam.policies ADD CONSTRAINT policies_default_version_fk
    FOREIGN KEY (id,default_version_id) REFERENCES iam.policy_versions(policy_id,id)
    DEFERRABLE INITIALLY DEFERRED;

DO $policy_attachment_target_upgrade$
BEGIN
    IF to_regclass('iam.policy_attachments') IS NOT NULL THEN
        IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='iam' AND table_name='policy_attachments' AND column_name='principal_id')
           AND EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='iam' AND table_name='policy_attachments' AND column_name='target_id') THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM attachment target columns conflict';
        ELSIF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='iam' AND table_name='policy_attachments' AND column_name='principal_id') THEN
            ALTER TABLE iam.policy_attachments RENAME COLUMN principal_id TO target_id;
        END IF;
    END IF;
END $policy_attachment_target_upgrade$;

CREATE TABLE IF NOT EXISTS iam.policy_attachments (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    target_id text COLLATE "C" NOT NULL,
    target_kind text COLLATE "C" NOT NULL,
    policy_id text COLLATE "C" NOT NULL,
    authority_scope text COLLATE "C" NOT NULL,
    installation_id text COLLATE "C",
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    revoked_at timestamptz(6),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (policy_id,authority_scope) REFERENCES iam.policies(id,authority_scope)
);

ALTER TABLE iam.policy_attachments DROP CONSTRAINT IF EXISTS policy_attachments_principal_fk;
ALTER TABLE iam.policy_attachments DROP CONSTRAINT IF EXISTS policy_attachments_target_fk;
DROP INDEX IF EXISTS iam.policy_attachments_active_uq;
CREATE UNIQUE INDEX policy_attachments_active_uq ON iam.policy_attachments
    (tenant_id,target_kind,target_id,policy_id) WHERE revoked_at IS NULL;

ALTER TABLE iam.policy_attachments DROP CONSTRAINT IF EXISTS policy_attachments_values_valid;
ALTER TABLE iam.policy_attachments ADD CONSTRAINT policy_attachments_values_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND target_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND policy_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND target_kind IN ('USER','SERVICE_ACCOUNT','GROUP','ROLE')
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

-- Product declarations are installation-wide release metadata, not tenant
-- permissions. Only the migration owner may register or select a declaration.
CREATE TABLE IF NOT EXISTS iam.authorization_profiles (
    product text NOT NULL,
    revision bigint NOT NULL,
    canonical_document text NOT NULL,
    content_digest text NOT NULL,
    created_at timestamptz(6) NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(product,revision),
    CONSTRAINT authorization_profiles_valid CHECK (
        product COLLATE "C" ~ '^[a-z][a-z0-9_-]{0,63}$'
        AND revision BETWEEN 1 AND 9007199254740991
        AND octet_length(canonical_document) BETWEEN 1 AND 65536
        AND jsonb_typeof(canonical_document::jsonb)='object'
        AND canonical_document::jsonb ?& ARRAY['apiVersion','kind','product','revision','callingService','actions']
        AND canonical_document::jsonb-ARRAY['apiVersion','kind','product','revision','callingService','actions']='{}'::jsonb
        AND jsonb_typeof(canonical_document::jsonb->'apiVersion')='string'
        AND jsonb_typeof(canonical_document::jsonb->'kind')='string'
        AND jsonb_typeof(canonical_document::jsonb->'product')='string'
        AND jsonb_typeof(canonical_document::jsonb->'callingService')='string'
        AND canonical_document::jsonb->>'apiVersion'='iam.matrix.xiak.com/v1'
        AND canonical_document::jsonb->>'kind'='AuthorizationProfile'
        AND canonical_document::jsonb->>'product'=product
        AND jsonb_typeof(canonical_document::jsonb->'revision')='number'
        AND (canonical_document::jsonb->>'revision')::bigint=revision
        AND canonical_document::jsonb->>'callingService' COLLATE "C" ~ '^[A-Z][A-Z0-9_-]{0,63}$'
        AND jsonb_typeof(canonical_document::jsonb->'actions')='array'
        AND jsonb_array_length(canonical_document::jsonb->'actions') BETWEEN 1 AND 128
        AND content_digest='sha256:'||encode(sha256(
            convert_to('matrix.iam.authorization-profile.v1','UTF8')||decode('00','hex')||convert_to(canonical_document,'UTF8')),'hex')
    )
);
CREATE TABLE IF NOT EXISTS iam.authorization_profile_heads (
    product text PRIMARY KEY,
    revision bigint NOT NULL,
    adopted_at timestamptz(6) NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY(product,revision) REFERENCES iam.authorization_profiles(product,revision)
);
CREATE OR REPLACE FUNCTION iam.guard_authorization_profile_head_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF NEW.product IS DISTINCT FROM OLD.product OR NEW.revision<=OLD.revision
        OR NEW.adopted_at IS DISTINCT FROM transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM profile current selection is invalid';
    END IF;
    RETURN NEW;
END
$function$;
DROP TRIGGER IF EXISTS authorization_profiles_are_immutable ON iam.authorization_profiles;
CREATE TRIGGER authorization_profiles_are_immutable BEFORE UPDATE OR DELETE ON iam.authorization_profiles
FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS authorization_profiles_cannot_be_truncated ON iam.authorization_profiles;
CREATE TRIGGER authorization_profiles_cannot_be_truncated BEFORE TRUNCATE ON iam.authorization_profiles
FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS authorization_profile_heads_advance ON iam.authorization_profile_heads;
CREATE TRIGGER authorization_profile_heads_advance BEFORE UPDATE ON iam.authorization_profile_heads
FOR EACH ROW EXECUTE FUNCTION iam.guard_authorization_profile_head_change();
DROP TRIGGER IF EXISTS authorization_profile_heads_cannot_be_deleted ON iam.authorization_profile_heads;
CREATE TRIGGER authorization_profile_heads_cannot_be_deleted BEFORE DELETE ON iam.authorization_profile_heads
FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS authorization_profile_heads_cannot_be_truncated ON iam.authorization_profile_heads;
CREATE TRIGGER authorization_profile_heads_cannot_be_truncated BEFORE TRUNCATE ON iam.authorization_profile_heads
FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.authorization_profiles ENABLE ALWAYS TRIGGER authorization_profiles_are_immutable;
ALTER TABLE iam.authorization_profiles ENABLE ALWAYS TRIGGER authorization_profiles_cannot_be_truncated;
ALTER TABLE iam.authorization_profile_heads ENABLE ALWAYS TRIGGER authorization_profile_heads_advance;
ALTER TABLE iam.authorization_profile_heads ENABLE ALWAYS TRIGGER authorization_profile_heads_cannot_be_deleted;
ALTER TABLE iam.authorization_profile_heads ENABLE ALWAYS TRIGGER authorization_profile_heads_cannot_be_truncated;

DO $profile_registration$
DECLARE
    seeds jsonb := __AUTHORIZATION_PROFILE_SEEDS__;
    seed jsonb;
BEGIN
    LOCK TABLE iam.authorization_profile_heads IN SHARE ROW EXCLUSIVE MODE;
    FOR seed IN SELECT value FROM jsonb_array_elements(seeds->'archive')
        ORDER BY value->>'product',(value->>'revision')::bigint LOOP
        INSERT INTO iam.authorization_profiles(product,revision,canonical_document,content_digest)
        VALUES(seed->>'product',(seed->>'revision')::bigint,seed->>'canonicalDocument',seed->>'contentDigest')
        ON CONFLICT(product,revision) DO NOTHING;
        IF NOT EXISTS(SELECT 1 FROM iam.authorization_profiles archive
            WHERE archive.product=seed->>'product' AND archive.revision=(seed->>'revision')::bigint
              AND archive.canonical_document=seed->>'canonicalDocument' AND archive.content_digest=seed->>'contentDigest') THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM immutable product registration conflicts';
        END IF;
    END LOOP;
    FOR seed IN SELECT value FROM jsonb_array_elements(seeds->'heads') ORDER BY value->>'product' LOOP
        IF NOT EXISTS(SELECT 1 FROM iam.authorization_profiles archive
            WHERE archive.product=seed->>'product' AND archive.revision=(seed->>'revision')::bigint
              AND archive.content_digest=seed->>'contentDigest')
            OR EXISTS(SELECT 1 FROM iam.authorization_profile_heads head
                WHERE head.product=seed->>'product' AND head.revision>(seed->>'revision')::bigint) THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM current product selection conflicts';
        END IF;
        INSERT INTO iam.authorization_profile_heads(product,revision)
        VALUES(seed->>'product',(seed->>'revision')::bigint)
        ON CONFLICT(product) DO UPDATE SET revision=EXCLUDED.revision,adopted_at=transaction_timestamp()
        WHERE iam.authorization_profile_heads.revision<EXCLUDED.revision;
    END LOOP;
    IF EXISTS(SELECT 1 FROM iam.authorization_profile_heads head
        WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(seeds->'heads') expected
            WHERE expected->>'product'=head.product)) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM current product set conflicts';
    END IF;
END
$profile_registration$;

CREATE OR REPLACE FUNCTION iam.current_authorization_profiles()
RETURNS TABLE(product text,revision bigint,canonical_document text,content_digest text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    -- Hold the selected heads until this authorization transaction completes.
    RETURN QUERY SELECT archive.product,archive.revision,archive.canonical_document,archive.content_digest
    FROM iam.authorization_profile_heads head JOIN iam.authorization_profiles archive
      ON archive.product=head.product AND archive.revision=head.revision
    ORDER BY head.product FOR SHARE OF head;
END
$function$;
CREATE OR REPLACE FUNCTION iam.lookup_authorization_profile(expected_product text,expected_revision bigint,expected_digest text)
RETURNS TABLE(product text,revision bigint,canonical_document text,content_digest text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
    SELECT archive.product,archive.revision,archive.canonical_document,archive.content_digest
    FROM iam.authorization_profiles archive
    WHERE archive.product=expected_product AND archive.revision=expected_revision AND archive.content_digest=expected_digest
$function$;

CREATE OR REPLACE FUNCTION iam.guard_policy_metadata_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF ROW(NEW.id,NEW.management,NEW.owner_tenant_id,NEW.authority_scope,NEW.created_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.management,OLD.owner_tenant_id,OLD.authority_scope,OLD.created_at)
        OR OLD.status='RETIRED' OR NEW.resource_version <> OLD.resource_version+1
        OR NEW.updated_at <> transaction_timestamp()
        OR EXISTS(SELECT 1 FROM iam.policy_versions v WHERE v.policy_id=NEW.id AND v.id=NEW.default_version_id AND v.retired_at IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM policy metadata transition is invalid';
    END IF;
    RETURN NEW;
END $function$;

CREATE OR REPLACE FUNCTION iam.guard_policy_version_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.contract_version IS DISTINCT FROM 2 THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM new policy version requires compiled content'; END IF;
        PERFORM iam.assert_policy_compilation(NEW.canonical_document,NEW.content_digest,NEW.authority_scope);
        IF NEW.retired_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM policy version must begin active'; END IF;
        RETURN NEW;
    END IF;
    IF TG_OP='DELETE' THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM policy content cannot be deleted'; END IF;
    IF to_jsonb(NEW)-'retired_at' IS DISTINCT FROM to_jsonb(OLD)-'retired_at'
       OR OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL OR NEW.retired_at<>transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM policy content is immutable except terminal retirement';
    END IF;
    PERFORM 1 FROM iam.policies p WHERE p.id=OLD.policy_id AND p.management='CUSTOMER'
       AND p.status='ACTIVE' AND p.default_version_id<>OLD.id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM policy version cannot be retired'; END IF;
    RETURN NEW;
END $function$;

CREATE OR REPLACE FUNCTION iam.guard_policy_attachment_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE subject_kind text; policy_scope text; policy_owner text; sealed_installation text;
BEGIN
    IF TG_OP='UPDATE' THEN
        IF ROW(NEW.tenant_id,NEW.id,NEW.target_id,NEW.target_kind,NEW.policy_id,NEW.authority_scope,NEW.installation_id,NEW.created_at)
            IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.target_id,OLD.target_kind,OLD.policy_id,OLD.authority_scope,OLD.installation_id,OLD.created_at)
            OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
            OR NEW.resource_version <> OLD.resource_version+1 OR NEW.updated_at <> transaction_timestamp()
            OR NEW.revoked_at <> NEW.updated_at THEN
            RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM attachment is immutable except terminal revocation';
        END IF;
        RETURN NEW;
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',NEW.tenant_id,true);
    IF NEW.target_kind='GROUP' THEN
        PERFORM 1 FROM iam.groups AS target_group
         WHERE target_group.tenant_id=NEW.tenant_id AND target_group.id=NEW.target_id AND target_group.deleted_at IS NULL
         FOR KEY SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE='23503', MESSAGE='IAM attachment group is unavailable';
        END IF;
        subject_kind := 'GROUP';
    ELSIF NEW.target_kind='ROLE' THEN
        PERFORM 1 FROM iam.roles target_role WHERE target_role.tenant_id=NEW.tenant_id
          AND target_role.id=NEW.target_id AND target_role.deleted_at IS NULL FOR KEY SHARE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23503', MESSAGE='IAM attachment role is unavailable'; END IF;
        subject_kind := 'ROLE';
    ELSE
        SELECT principal.principal_type INTO subject_kind FROM iam.principals AS principal
            WHERE principal.tenant_id=NEW.tenant_id AND principal.id=NEW.target_id;
    END IF;
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
CREATE TRIGGER policy_versions_are_immutable BEFORE INSERT OR UPDATE OR DELETE ON iam.policy_versions
    FOR EACH ROW EXECUTE FUNCTION iam.guard_policy_version_change();
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

-- Exact archived meaning is a stored decision invariant, independent of heads.
-- This private predicate does not authenticate a producer or grant permission.
CREATE OR REPLACE FUNCTION iam.authorization_decision_profile_matches(decision jsonb)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $function$
    SELECT COALESCE(EXISTS(
        SELECT 1 FROM iam.authorization_profiles archive
        CROSS JOIN LATERAL jsonb_array_elements(archive.canonical_document::jsonb->'actions') action
        CROSS JOIN LATERAL jsonb_array_elements(action->'resourceShapes') shape
        WHERE decision->'profile'=jsonb_build_object('product',archive.product,'revision',archive.revision,'contentDigest',archive.content_digest)
          AND action->'action'=decision->'action'
          AND action->'resourceKind'=decision#>'{resource,kind}'
          AND (decision->'allowed'='false'::jsonb OR CASE WHEN action ? 'subjectTypes'
            THEN action->'subjectTypes' ? (decision#>>'{subject,type}')
            ELSE decision#>>'{subject,type}'=CASE WHEN action->>'scope'='INSTALLATION_PROBE' THEN 'SERVICE_ACCOUNT' ELSE 'USER' END END)
          AND (CASE WHEN decision->'allowed'='true'::jsonb THEN
            CASE WHEN action->>'scope'='INSTALLATION' THEN
              decision ? 'installationId' AND NOT decision ? 'tenantId' AND decision#>>'{subject,type}'='USER'
            WHEN action->>'scope' IN ('TENANT','INSTALLATION_PROBE') THEN
              decision ? 'tenantId' AND NOT decision ? 'installationId'
            ELSE false END
          ELSE decision->'allowed'='false'::jsonb AND NOT decision ?| ARRAY['tenantId','installationId','subject'] END)
          AND shape->'mode'=decision->'resourceMode'
          AND (CASE WHEN shape->>'mode'='INSTANCE' THEN NOT decision ? 'collectionUsage'
               WHEN shape->>'mode'='COLLECTION' THEN decision#>>'{resource,id}'='collection'
                 AND decision->'collectionUsage'=shape->'collectionUsage'
                 AND decision->>'collectionUsage' IN ('COLLECTION_LIST','COLLECTION_CREATE')
               ELSE false END)
    ),false)
$function$;

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
ALTER TABLE iam.authorization_decisions ADD COLUMN IF NOT EXISTS boundary_evidence jsonb;
ALTER TABLE iam.authorization_decisions ALTER COLUMN principal_id DROP NOT NULL;
ALTER TABLE iam.authorization_decisions ADD COLUMN IF NOT EXISTS subject_type text COLLATE "C";
ALTER TABLE iam.authorization_decisions ADD COLUMN IF NOT EXISTS role_id text COLLATE "C";
ALTER TABLE iam.authorization_decisions ADD COLUMN IF NOT EXISTS source_principal_id text COLLATE "C";
ALTER TABLE iam.authorization_decisions ADD COLUMN IF NOT EXISTS role_evidence jsonb;
ALTER TABLE iam.authorization_decisions DROP CONSTRAINT IF EXISTS authorization_decisions_source_principal_fk;
ALTER TABLE iam.authorization_decisions ADD CONSTRAINT authorization_decisions_source_principal_fk
    FOREIGN KEY(tenant_id,source_principal_id) REFERENCES iam.principals(tenant_id,id);
-- No default, fallback, or repeat-time backfill. Only pre-cutover rows enter
-- contract1, and the enclosing transaction must validate every complete row.
-- ACCESS EXCLUSIVE plus transactional DDL exposes no mutable/RLS-free window.
DO $decision_contract_cutover$
BEGIN
    LOCK TABLE iam.authorization_decisions IN ACCESS EXCLUSIVE MODE;
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute
        WHERE attrelid='iam.authorization_decisions'::regclass AND attname='contract_version' AND NOT attisdropped) THEN
        ALTER TABLE iam.authorization_decisions NO FORCE ROW LEVEL SECURITY;
        DROP TRIGGER IF EXISTS authorization_decisions_are_immutable ON iam.authorization_decisions;
        ALTER TABLE iam.authorization_decisions ADD COLUMN contract_version integer;
        UPDATE iam.authorization_decisions SET contract_version=1;
        ALTER TABLE iam.authorization_decisions ALTER COLUMN contract_version SET NOT NULL;
        ALTER TABLE iam.authorization_decisions FORCE ROW LEVEL SECURITY;
    END IF;
END $decision_contract_cutover$;
ALTER TABLE iam.authorization_decisions ADD COLUMN IF NOT EXISTS profile_product text COLLATE "C";
ALTER TABLE iam.authorization_decisions ADD COLUMN IF NOT EXISTS profile_revision bigint;
ALTER TABLE iam.authorization_decisions ADD COLUMN IF NOT EXISTS profile_content_digest text COLLATE "C";
ALTER TABLE iam.authorization_decisions ADD COLUMN IF NOT EXISTS resource_mode text COLLATE "C";
ALTER TABLE iam.authorization_decisions ADD COLUMN IF NOT EXISTS collection_usage text COLLATE "C";
ALTER TABLE iam.authorization_decisions DROP CONSTRAINT IF EXISTS authorization_decision_contract_valid;
ALTER TABLE iam.authorization_decisions ADD CONSTRAINT authorization_decision_contract_valid CHECK (COALESCE(
    contract_version IN (1,2,3)
    AND (CASE WHEN contract_version IN (1,2) THEN principal_id IS NOT NULL AND subject_type IS NULL AND role_id IS NULL AND source_principal_id IS NULL AND role_evidence IS NULL
      ELSE subject_type IS NOT NULL AND policy_evidence IS NOT NULL AND boundary_evidence IS NOT NULL AND
        CASE WHEN subject_type='ROLE' THEN principal_id IS NULL AND role_id IS NOT NULL AND source_principal_id IS NOT NULL
          AND jsonb_typeof(role_evidence)='object' AND role_evidence->>'roleId'=role_id AND role_evidence->>'sourceUserId'=source_principal_id
          AND jsonb_typeof(role_evidence->'sessionId')='string' AND role_evidence->>'sessionId' COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        ELSE subject_type IN ('USER','SERVICE_ACCOUNT') AND principal_id IS NOT NULL AND role_id IS NULL AND source_principal_id IS NULL AND role_evidence IS NULL END END)
    AND jsonb_typeof(document)='object'
    AND document ?& ARRAY['apiVersion','kind','id','allowed','reason','action','resource','requestId','decidedAt']
    AND (document-ARRAY['apiVersion','kind','id','allowed','reason','action','resource','requestId','decidedAt',
        'tenantId','installationId','subject','profile','resourceMode','collectionUsage','correlationId'])='{}'::jsonb
    AND jsonb_typeof(document->'allowed')='boolean' AND document->>'allowed'=allowed::text
    AND jsonb_typeof(document->'apiVersion')='string' AND jsonb_typeof(document->'kind')='string'
    AND jsonb_typeof(document->'id')='string' AND jsonb_typeof(document->'action')='string'
    AND jsonb_typeof(document->'requestId')='string' AND jsonb_typeof(document->'reason')='string'
    AND document->>'reason'=CASE WHEN allowed THEN 'ALLOWED' ELSE 'DENIED' END
    AND document->>'apiVersion'='iam.matrix.xiak.com/v1' AND document->>'kind'='AuthorizationDecision'
    AND document->>'id'=id AND document->>'action'=action_name AND document->>'requestId'=request_id
    AND jsonb_typeof(document->'resource')='object' AND document->'resource'=jsonb_build_object('kind',target_kind,'id',target_id)
    AND jsonb_typeof(document->'decidedAt')='string'
    AND document->>'decidedAt' COLLATE "C" ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
    AND pg_input_is_valid(document->>'decidedAt','timestamptz')
    AND (document->>'decidedAt')::timestamptz=decided_at
    AND (CASE WHEN allowed THEN
        jsonb_typeof(document->'subject')='object'
        AND document->'subject' ?& ARRAY['type','id']
        AND (CASE WHEN contract_version=3 AND subject_type='ROLE' THEN
          document->'subject'=jsonb_build_object('type','ROLE','id',role_id,'roleSession',jsonb_build_object('sessionId',role_evidence->>'sessionId','sourceUserId',source_principal_id))
          AND NOT document ? 'installationId'
          ELSE ((document->'subject')-ARRAY['type','id'])='{}'::jsonb AND document#>>'{subject,id}'=principal_id
            AND document#>>'{subject,type}' IN ('USER','SERVICE_ACCOUNT')
            AND (contract_version<>3 OR document#>>'{subject,type}'=subject_type) END)
        AND jsonb_typeof(document#>'{subject,id}')='string'
        AND jsonb_typeof(document#>'{subject,type}')='string'
        AND ((document ? 'tenantId' AND NOT document ? 'installationId' AND jsonb_typeof(document->'tenantId')='string' AND document->>'tenantId'=tenant_id)
          OR (document ? 'installationId' AND NOT document ? 'tenantId'
            AND jsonb_typeof(document->'installationId')='string' AND document->>'installationId' COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'))
      ELSE NOT document ?| ARRAY['tenantId','installationId','subject'] END)
    AND (CASE WHEN contract_version=1 THEN
        profile_product IS NULL AND profile_revision IS NULL AND profile_content_digest IS NULL AND resource_mode IS NULL AND collection_usage IS NULL
        AND NOT document ?| ARRAY['profile','resourceMode','collectionUsage','correlationId']
      WHEN contract_version IN (2,3) THEN
        profile_product IS NOT NULL AND profile_revision IS NOT NULL AND profile_content_digest IS NOT NULL AND resource_mode IS NOT NULL
        AND document ?& ARRAY['profile','resourceMode','correlationId']
        AND document->'profile'=jsonb_build_object('product',profile_product,'revision',profile_revision,'contentDigest',profile_content_digest)
        AND document->>'resourceMode'=resource_mode
        AND jsonb_typeof(document->'correlationId')='string'
        AND document->>'correlationId' COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND (CASE WHEN resource_mode='INSTANCE' THEN collection_usage IS NULL AND NOT document ? 'collectionUsage'
             WHEN resource_mode='COLLECTION' THEN collection_usage IS NOT NULL AND document->>'collectionUsage'=collection_usage
             ELSE false END)
        AND iam.authorization_decision_profile_matches(document)
      ELSE false END),false));
ALTER TABLE iam.authorization_decisions DROP CONSTRAINT IF EXISTS authorization_boundary_evidence_valid;
ALTER TABLE iam.authorization_decisions ADD CONSTRAINT authorization_boundary_evidence_valid CHECK (
    boundary_evidence IS NULL OR jsonb_typeof(boundary_evidence)='object'
);
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
       OR (CASE WHEN submitted_event#>>'{actor,type}'='ROLE' THEN
            expected_action NOT IN ('iam.authorization.decided','iam.role-session.exited')
            OR ((submitted_event->'actor')-ARRAY['type','id','roleSession'])<>'{}'::jsonb
            OR jsonb_typeof(submitted_event#>'{actor,roleSession}') IS DISTINCT FROM 'object'
            OR ((submitted_event#>'{actor,roleSession}')-ARRAY['sessionId','sourceUserId'])<>'{}'::jsonb
            OR jsonb_typeof(submitted_event#>'{actor,roleSession,sessionId}') IS DISTINCT FROM 'string'
            OR jsonb_typeof(submitted_event#>'{actor,roleSession,sourceUserId}') IS DISTINCT FROM 'string'
            OR COALESCE(submitted_event#>>'{actor,roleSession,sessionId}','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            OR COALESCE(submitted_event#>>'{actor,roleSession,sourceUserId}','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
          ELSE ((submitted_event->'actor') - ARRAY['type','id']) <> '{}'::jsonb END)
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
       OR submitted_event#>>'{actor,type}' NOT IN ('USER', 'SERVICE_ACCOUNT', 'SYSTEM', 'ROLE')
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
            'iam.password.changed', 'iam.user.password-changed', 'iam.installation-primary.credentials-recovered',
            'iam.role-session.revoked','iam.role-session.exited'
        ) AND submitted_event ? 'iamDecisionId')
        OR (expected_action IN (
            'iam.account.created', 'iam.account.disabled', 'iam.account.enabled',
            'iam.account-root.credentials-recovered', 'iam.account.alias-set',
            'iam.user.created', 'iam.user.updated', 'iam.user.deleted',
            'iam.user.permission-boundary.set','iam.user.permission-boundary.removed',
            'iam.policy.created','iam.policy.updated','iam.policy.deleted','iam.policy-version.created','iam.policy-version.deleted','iam.policy.default-version-set','iam.group.created','iam.group.updated','iam.group.deleted',
            'iam.role.created','iam.role.updated','iam.role.disabled','iam.role.enabled','iam.role.trust-set','iam.role.deleted',
            'iam.role.permission-boundary.set','iam.role.permission-boundary.removed',
            'iam.role-session.issued','iam.role-session.admin-revoked',
            'iam.group-membership.created','iam.group-membership.removed',
            'iam.user.status-set', 'iam.user.password-reset',
            'iam.policy-attachment.created', 'iam.policy-attachment.revoked',
            'iam.platform-policy-attachment.created', 'iam.platform-policy-attachment.revoked',
            'iam.principal.created', 'iam.role-binding.put',
            'iam.role-binding.revoked', 'iam.authorization.decided',
            'iam.organization.created', 'iam.account-alias.set',
            'iam.principal.status-set', 'iam.password.reset',
            'iam.tenant.created', 'iam.tenant.disabled', 'iam.tenant.enabled', 'iam.tenant-administrator.recovered'
       ) AND NOT (submitted_event ? 'iamDecisionId'))
       OR (expected_action = 'iam.role-session.exited' AND (
            submitted_event#>>'{actor,type}' IS DISTINCT FROM 'ROLE'
            OR submitted_event#>>'{actor,roleSession,sessionId}' IS DISTINCT FROM submitted_event#>>'{target,id}'))
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
        tenant_id, id, target_id, policy_id, resource_version,
        created_at, updated_at
    ) VALUES (
        submitted_organization_id, 'bootstrap-admin-binding',
        submitted_administrator_id, 'system.account-administrator', 1,
        effective_now, effective_now
    );
    INSERT INTO iam.policy_attachments (
        tenant_id, id, target_id, policy_id, resource_version,
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
                tenant_id, id, target_id, policy_id, resource_version,
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

-- Shared private ABI/row-protection verification, valid even before bootstrap.
CREATE OR REPLACE FUNCTION iam.authorization_decision_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS recorder
                WHERE recorder.oid=to_regprocedure('iam.record_authorization(text,text,jsonb,jsonb,jsonb,jsonb,integer,jsonb)')
                  AND recorder.prosecdef AND recorder.proowner='matrix_iam_owner'::regrole
                  AND recorder.proargnames=ARRAY['submitted_tenant_id','submitted_subject_id','input_authorization','submitted_audit_event',
                    'submitted_policy_evidence','submitted_boundary_evidence','input_contract_version','submitted_role_evidence']
                  AND recorder.pronargs=8 AND recorder.pronargdefaults=0 AND recorder.provariadic=0
                  AND recorder.prorettype='void'::regtype AND NOT recorder.proretset
                  AND recorder.proallargtypes IS NULL AND recorder.proargmodes IS NULL
                  AND recorder.provolatile='v' AND recorder.proparallel='u' AND NOT recorder.proisstrict AND NOT recorder.proleakproof)
           AND to_regprocedure('iam.record_authorization(text,text,jsonb,jsonb,jsonb,jsonb,integer)') IS NULL
           AND to_regprocedure('iam.record_authorization(text,text,jsonb,jsonb,jsonb,jsonb)') IS NULL
           AND (SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='iam' AND p.proname='record_authorization')=1
           AND NOT EXISTS(SELECT 1 FROM (VALUES
                ('contract_version','integer'::regtype,true),('profile_product','text'::regtype,false),
                ('profile_revision','bigint'::regtype,false),('profile_content_digest','text'::regtype,false),
                ('resource_mode','text'::regtype,false),('collection_usage','text'::regtype,false),
                ('principal_id','text'::regtype,false),('subject_type','text'::regtype,false),('role_id','text'::regtype,false),
                ('source_principal_id','text'::regtype,false),('role_evidence','jsonb'::regtype,false)) expected(name,type_oid,required)
                LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid='iam.authorization_decisions'::regclass AND a.attname=expected.name AND NOT a.attisdropped
                WHERE a.attnum IS NULL OR a.atttypid<>expected.type_oid OR a.attnotnull<>expected.required OR a.atthasdef)
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid='iam.authorization_decisions'::regclass
                AND c.conname='authorization_decision_contract_valid' AND c.contype='c' AND c.convalidated)
           AND NOT EXISTS(SELECT 1 FROM (VALUES
                ('authorization_decisions_principal_fk','iam.principals',ARRAY['tenant_id','principal_id']),
                ('authorization_decisions_source_principal_fk','iam.principals',ARRAY['tenant_id','source_principal_id']),
                ('authorization_decisions_role_fk','iam.roles',ARRAY['tenant_id','role_id'])) expected(name,target_table,source_columns)
                WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid='iam.authorization_decisions'::regclass
                  AND c.conname=expected.name AND c.contype='f' AND c.confrelid=to_regclass(expected.target_table)
                  AND c.convalidated AND NOT c.condeferrable AND c.confupdtype='a' AND c.confdeltype='a' AND c.confmatchtype='s'
                  AND ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(number,position)
                    JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.number ORDER BY k.position)=expected.source_columns
                  AND ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(number,position)
                    JOIN pg_catalog.pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.number ORDER BY k.position)=ARRAY['tenant_id','id']))
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc evidence
                WHERE evidence.oid=to_regprocedure('iam.read_audit_evidence(text,text,text,text,jsonb)')
                  AND evidence.prosecdef AND evidence.proowner='matrix_iam_owner'::regrole AND evidence.proretset
                  AND cardinality(evidence.proallargtypes)=10
                  AND evidence.proallargtypes[6:10]=ARRAY['text'::regtype::oid,'jsonb'::regtype::oid,'jsonb'::regtype::oid,'text'::regtype::oid,'integer'::regtype::oid]
                  AND evidence.proargnames[6:10]=ARRAY['installation_id','event_document','decision_document','verifier_principal_id','decision_contract_version'])
           AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) permission
                WHERE p.oid IN (to_regprocedure('iam.record_authorization(text,text,jsonb,jsonb,jsonb,jsonb,integer,jsonb)'),to_regprocedure('iam.read_audit_evidence(text,text,text,text,jsonb)'))
                  AND (permission.grantee NOT IN (p.proowner,'matrix_iam_api'::regrole)
                    OR (permission.grantee='matrix_iam_api'::regrole AND (permission.is_grantable OR permission.privilege_type<>'EXECUTE'))))
           AND has_function_privilege('matrix_iam_api','iam.record_authorization(text,text,jsonb,jsonb,jsonb,jsonb,integer,jsonb)','EXECUTE')
           AND has_function_privilege('matrix_iam_api','iam.read_audit_evidence(text,text,text,text,jsonb)','EXECUTE')
           AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
                WHERE p.oid IN (to_regprocedure('iam.record_authorization(text,text,jsonb,jsonb,jsonb,jsonb,integer,jsonb)'),to_regprocedure('iam.read_audit_evidence(text,text,text,text,jsonb)'))
                  AND NOT COALESCE((SELECT count(*)=1 AND bool_and(
                    (SELECT array_agg(parse_ident(btrim(component.name),true) ORDER BY component.position)
                     FROM unnest(string_to_array(substr(config.setting,strpos(config.setting,'=')+1),','))
                       WITH ORDINALITY AS component(name,position))=ARRAY[ARRAY['pg_catalog'],ARRAY['pg_temp']])
                    FROM unnest(p.proconfig) AS config(setting) WHERE split_part(config.setting,'=',1)='search_path'),false))
           AND to_regprocedure('iam.assert_allowed_decision(text,text,text,text,text,text)') IS NULL
           AND to_regprocedure('iam.assert_allowed_decision(text,text,text,text,text,text,text,text)') IS NOT NULL
           AND (SELECT count(*) FROM pg_catalog.pg_trigger protection WHERE protection.tgrelid='iam.authorization_decisions'::regclass
                AND protection.tgname IN ('authorization_decisions_are_immutable','authorization_decisions_cannot_be_truncated')
                AND protection.tgenabled='A' AND NOT protection.tgisinternal AND protection.tgfoid=to_regprocedure('iam.reject_policy_history_change()'))=2
$function$;

-- This private check is shared by migration verification and live readiness.
-- A matching schema number alone does not prove the callable session ABI.
CREATE OR REPLACE FUNCTION iam.policy_attachment_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='iam' AND p.proname IN ('create_policy_attachment','revoke_policy_attachment'))=2
      AND NOT EXISTS(SELECT 1 FROM (VALUES
        ('iam.create_policy_attachment(text,text,text,text,text,bigint,text,text,jsonb,text)',10,false,'jsonb'::regtype),
        ('iam.revoke_policy_attachment(text,text,bigint,text,text,jsonb,text)',7,true,'record'::regtype)
        ) expected(signature,arguments,returns_set,result_type)
        LEFT JOIN pg_proc p ON p.oid=to_regprocedure(expected.signature)
        WHERE p.oid IS NULL OR NOT p.prosecdef OR p.proowner<>'matrix_iam_owner'::regrole
          OR p.pronargs<>expected.arguments OR p.pronargdefaults<>0 OR p.provariadic<>0
          OR p.provolatile<>'v' OR p.proparallel<>'u' OR p.proisstrict OR p.proleakproof
          OR p.proargnames[expected.arguments] IS DISTINCT FROM 'actor_session_id'
          OR p.proretset<>expected.returns_set OR p.prorettype<>expected.result_type
          OR (NOT expected.returns_set AND (p.proallargtypes IS NOT NULL OR p.proargmodes IS NOT NULL))
          OR (expected.returns_set AND (cardinality(p.proallargtypes) IS DISTINCT FROM 10
            OR cardinality(p.proargnames) IS DISTINCT FROM 10 OR cardinality(p.proargmodes) IS DISTINCT FROM 10
            OR p.proargnames[8:10] IS DISTINCT FROM ARRAY['resource_version','revoked_at','applied']
            OR p.proallargtypes[8:10] IS DISTINCT FROM ARRAY['bigint'::regtype::oid,'timestamptz'::regtype::oid,'boolean'::regtype::oid]
            OR p.proargmodes[8:10] IS DISTINCT FROM ARRAY['t','t','t']::"char"[]))
          OR NOT has_function_privilege('matrix_iam_api',p.oid,'EXECUTE')
          OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) permission
            WHERE permission.grantee NOT IN (p.proowner,'matrix_iam_api'::regrole)
              OR (permission.grantee='matrix_iam_api'::regrole AND permission.is_grantable))
          OR NOT COALESCE((SELECT count(*)=1 AND bool_and(
            (SELECT array_agg(parse_ident(btrim(component.name),true) ORDER BY component.position)
             FROM unnest(string_to_array(substr(config.setting,strpos(config.setting,'=')+1),','))
               WITH ORDINALITY AS component(name,position))=ARRAY[ARRAY['pg_catalog'],ARRAY['pg_temp']])
            FROM unnest(p.proconfig) AS config(setting) WHERE split_part(config.setting,'=',1)='search_path'),false))
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
           AND to_regprocedure('iam.current_authorization_profiles()') IS NOT NULL
           AND to_regprocedure('iam.lookup_authorization_profile(text,bigint,text)') IS NOT NULL
           AND EXISTS(SELECT 1 FROM iam.authorization_profile_heads)
           AND (SELECT count(*) FROM pg_catalog.pg_proc p
                WHERE p.oid IN (to_regprocedure('iam.resource_kind_for_action(text)'),to_regprocedure('iam.is_platform_action(text)'))
                  AND p.provolatile='s' AND p.proparallel='u' AND NOT p.prosecdef AND NOT p.proretset AND p.proowner='matrix_iam_owner'::regrole
                  AND NOT has_function_privilege('public',p.oid,'EXECUTE')
                  AND NOT has_function_privilege('matrix_iam_api',p.oid,'EXECUTE')
                  AND NOT has_function_privilege('matrix_iam_worker',p.oid,'EXECUTE')
                  AND NOT has_function_privilege('matrix_iam_credential_recovery',p.oid,'EXECUTE'))=2
           AND to_regclass('iam.role_bindings') IS NULL
           AND (SELECT count(*) FROM pg_catalog.pg_class AS group_table
                WHERE group_table.oid IN (to_regclass('iam.groups'),to_regclass('iam.group_memberships'))
                  AND group_table.relrowsecurity AND group_table.relforcerowsecurity
                  AND group_table.relowner='matrix_iam_owner'::regrole)=2
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid='iam.policy_attachments'::regclass
                AND attname='target_id' AND atttypid='text'::regtype AND attnotnull AND NOT attisdropped)
           AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid='iam.policy_attachments'::regclass
                AND attname='principal_id' AND NOT attisdropped)
           AND iam.policy_attachment_contract_ready()
           AND iam.role_contract_ready()
           AND to_regprocedure('iam.create_group(text,text,text,text,text,text,jsonb)') IS NOT NULL
           AND (SELECT count(*) FROM pg_catalog.pg_proc AS policy_entry
                WHERE policy_entry.oid IN (to_regprocedure('iam.read_policy(text,text,text,text)'),
                    to_regprocedure('iam.create_policy(text,text,text,text,text,text,text,text,jsonb,integer)'),
                    to_regprocedure('iam.list_policy_versions(text,text,text,text)'),
                    to_regprocedure('iam.read_policy_version(text,text,text,text,text)'),
                    to_regprocedure('iam.create_policy_version(text,text,text,text,bigint,text,text,text,jsonb,integer)'),
                    to_regprocedure('iam.set_default_policy_version(text,text,text,text,bigint,text,jsonb)'),
                    to_regprocedure('iam.update_policy(text,text,text,text,bigint,text,jsonb)'),
                    to_regprocedure('iam.delete_policy(text,text,text,text,bigint,jsonb)'),
                    to_regprocedure('iam.delete_policy_version(text,text,text,text,text,bigint,jsonb)'))
                  AND policy_entry.prorettype='jsonb'::regtype AND NOT policy_entry.proretset
                  AND policy_entry.prosecdef AND policy_entry.proowner='matrix_iam_owner'::regrole)=9
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid='iam.policy_versions'::regclass
                AND attname='retired_at' AND atttypid='timestamptz'::regtype AND NOT attnotnull AND NOT attisdropped)
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='iam.policy_versions'::regclass
                AND tgname='policy_versions_are_immutable' AND tgenabled='A'
                AND tgfoid=to_regprocedure('iam.guard_policy_version_change()'))
           AND to_regprocedure('iam.create_group_membership(text,text,text,text,text,text,jsonb)') IS NOT NULL
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS removal
                WHERE removal.oid=to_regprocedure('iam.remove_group_membership(text,text,text,text,text,bigint,jsonb)')
                  AND removal.prosecdef AND removal.proowner='matrix_iam_owner'::regrole AND removal.proretset
                  AND removal.proargnames[8:9]=ARRAY['membership','applied']
                  AND removal.proallargtypes[8:9]=ARRAY['jsonb'::regtype::oid,'boolean'::regtype::oid])
           AND to_regprocedure('iam.record_authorization(text,text,jsonb,jsonb)') IS NULL
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS directory
                WHERE directory.oid=to_regprocedure('iam.list_policies(text,text,text,text)')
                  AND directory.prorettype='jsonb'::regtype AND NOT directory.proretset
                  AND directory.prosecdef AND directory.proowner='matrix_iam_owner'::regrole)
           AND iam.authorization_decision_contract_ready()
           AND iam.policy_version_contract_ready()
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS lookup
                WHERE lookup.oid=to_regprocedure('iam.lookup_session(text)')
                  AND cardinality(lookup.proallargtypes)=24 AND lookup.proargnames[23:24]=ARRAY['policies','boundary']
                  AND lookup.proallargtypes[23:24]=ARRAY['jsonb'::regtype::oid,'jsonb'::regtype::oid])
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_attribute AS evidence
                WHERE evidence.attrelid='iam.authorization_decisions'::regclass AND evidence.attname='policy_evidence'
                  AND evidence.atttypid='jsonb'::regtype AND NOT evidence.attisdropped)
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_attribute AS evidence
                WHERE evidence.attrelid='iam.authorization_decisions'::regclass AND evidence.attname='boundary_evidence'
                  AND evidence.atttypid='jsonb'::regtype AND NOT evidence.attisdropped)
           AND EXISTS(SELECT 1 FROM pg_catalog.pg_class AS boundary_table
                WHERE boundary_table.oid=to_regclass('iam.user_permission_boundaries')
                  AND boundary_table.relrowsecurity AND boundary_table.relforcerowsecurity
                  AND boundary_table.relowner='matrix_iam_owner'::regrole)
           AND (SELECT count(*) FROM pg_catalog.pg_proc AS boundary_entry
                WHERE boundary_entry.oid IN (
                    to_regprocedure('iam.read_user_permission_boundary(text,text,text,text)'),
                    to_regprocedure('iam.change_user_permission_boundary(text,text,text,text,bigint,text,bigint,text,jsonb,text)'))
                  AND boundary_entry.prorettype='jsonb'::regtype AND NOT boundary_entry.proretset
                  AND boundary_entry.prosecdef AND boundary_entry.proowner='matrix_iam_owner'::regrole)=2
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
            AND to_regprocedure('iam.read_user(text,text,text,text)') IS NOT NULL
            AND to_regprocedure('iam.update_user(text,text,text,text,text,bigint,jsonb)') IS NOT NULL
            AND to_regprocedure('iam.delete_user(text,text,text,text,bigint,jsonb)') IS NOT NULL
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
               SELECT 1 FROM pg_catalog.pg_attribute AS column_definition
                WHERE column_definition.attrelid = 'iam.principals'::regclass
                  AND column_definition.attname = 'deleted_at'
                  AND column_definition.atttypid = 'timestamptz'::regtype
                  AND NOT column_definition.attnotnull
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
           28::bigint,
           transaction_timestamp();
END
$function$;

-- Current projections come from the registered source declaration, never a
-- second CASE catalog. Callers hold current_authorization_profiles() locks for
-- the transaction; historical proof uses exact archive references separately.
CREATE OR REPLACE FUNCTION iam.resource_kind_for_action(submitted_action text)
RETURNS text LANGUAGE sql STABLE PARALLEL UNSAFE
SET search_path = pg_catalog, pg_temp AS $function$
    SELECT (SELECT action->>'resourceKind'
      FROM iam.authorization_profile_heads head
      JOIN iam.authorization_profiles archive ON archive.product=head.product AND archive.revision=head.revision
      CROSS JOIN LATERAL jsonb_array_elements(archive.canonical_document::jsonb->'actions') action
     WHERE head.product=split_part(submitted_action,'.',1) AND action->>'action'=submitted_action)
$function$;

CREATE OR REPLACE FUNCTION iam.is_platform_action(submitted_action text)
RETURNS boolean LANGUAGE sql STABLE PARALLEL UNSAFE
SET search_path = pg_catalog, pg_temp AS $function$
    SELECT (SELECT CASE WHEN action->>'scope' IN ('TENANT','INSTALLATION','INSTALLATION_PROBE')
                        THEN action->>'scope'='INSTALLATION' END
        FROM iam.authorization_profile_heads head
        JOIN iam.authorization_profiles archive ON archive.product=head.product AND archive.revision=head.revision
        CROSS JOIN LATERAL jsonb_array_elements(archive.canonical_document::jsonb->'actions') action
        WHERE head.product=split_part(submitted_action,'.',1)
          AND action->>'action'=submitted_action)
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
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    RETURN (SELECT COALESCE(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
        'policy',jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','Policy',
            'id',p.id,'management',p.management,'accountId',p.owner_tenant_id,'displayName',p.display_name,
            'scope',p.authority_scope,'status',p.status,'defaultVersionId',p.default_version_id,
            'resourceVersion',p.resource_version,'createdAt',p.created_at,'updatedAt',p.updated_at)),
        'version',iam.policy_version_snapshot(v),
        'attachment',jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','PolicyAttachment',
            'id',a.id,'accountId',a.tenant_id,'target',jsonb_build_object('kind',a.target_kind,'id',a.target_id),
            'policyId',a.policy_id,'scope',a.authority_scope,'installationId',a.installation_id,
            'resourceVersion',a.resource_version,'createdAt',a.created_at,'updatedAt',a.updated_at)),
        'membership',a.membership)) ORDER BY a.id), '[]'::jsonb)
    FROM (SELECT sources.* FROM (
        SELECT attachment.*,NULL::jsonb AS membership FROM iam.policy_attachments AS attachment
        JOIN iam.principals AS subject ON subject.tenant_id=attachment.tenant_id
            AND subject.id=attachment.target_id AND subject.principal_type=attachment.target_kind
        JOIN iam.policies AS available ON available.id=attachment.policy_id AND available.status='ACTIVE'
        WHERE attachment.tenant_id=tenant AND subject.id=principal AND attachment.revoked_at IS NULL
        UNION ALL
        SELECT attachment.*,iam.group_membership_snapshot(tenant,member.id) AS membership
        FROM iam.group_memberships AS member
        JOIN iam.principals AS subject ON subject.tenant_id=member.tenant_id AND subject.id=member.user_id
            AND subject.principal_type='USER' AND subject.status='ACTIVE' AND subject.deleted_at IS NULL
        JOIN iam.groups AS g ON g.tenant_id=member.tenant_id AND g.id=member.group_id AND g.deleted_at IS NULL
        JOIN iam.policy_attachments AS attachment ON attachment.tenant_id=member.tenant_id
            AND attachment.target_kind='GROUP' AND attachment.target_id=g.id AND attachment.revoked_at IS NULL
        JOIN iam.policies AS available ON available.id=attachment.policy_id AND available.status='ACTIVE'
        WHERE member.tenant_id=tenant AND member.user_id=principal AND member.removed_at IS NULL
    ) AS sources ORDER BY sources.id LIMIT 257) AS a
    JOIN iam.policies AS p ON p.id=a.policy_id
    JOIN iam.policy_versions AS v ON v.policy_id=p.id AND v.id=p.default_version_id AND v.retired_at IS NULL);
END
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
    policies jsonb,
    boundary jsonb
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
           iam.current_policy_snapshot(principal.tenant_id,principal.id),
           iam.current_user_boundary(principal.tenant_id,principal.id)
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
DROP FUNCTION IF EXISTS iam.record_authorization(text,text,jsonb,jsonb,jsonb);
DROP FUNCTION IF EXISTS iam.record_authorization(text,text,jsonb,jsonb,jsonb,jsonb);
DROP FUNCTION IF EXISTS iam.record_authorization(text,text,jsonb,jsonb,jsonb,jsonb,integer);
CREATE OR REPLACE FUNCTION iam.record_authorization(
    submitted_tenant_id text,
    submitted_subject_id text,
    input_authorization jsonb,
    submitted_audit_event jsonb,
    submitted_policy_evidence jsonb,
    submitted_boundary_evidence jsonb,
    input_contract_version integer,
    submitted_role_evidence jsonb
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
    submitted_request jsonb;
    submitted_decision jsonb;
    binding_key text;
    expected_subject jsonb;
BEGIN
    IF input_contract_version IS DISTINCT FROM 3 OR submitted_role_evidence IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='authorization contract version is invalid';
    END IF;
    IF jsonb_typeof(input_authorization) IS DISTINCT FROM 'object'
        OR NOT input_authorization ?& ARRAY['request','decision']
        OR (input_authorization-ARRAY['request','decision'])<>'{}'::jsonb
        OR jsonb_typeof(input_authorization->'request') IS DISTINCT FROM 'object'
        OR jsonb_typeof(input_authorization->'decision') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='authorization command is invalid';
    END IF;
    submitted_request := input_authorization->'request';
    submitted_decision := input_authorization->'decision';
    IF NOT submitted_request ?& ARRAY['action','resource','requestId','correlationId','profile','resourceMode']
        OR (submitted_request-ARRAY['action','resource','requestId','correlationId','profile','resourceMode','collectionUsage'])<>'{}'::jsonb THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='authorization request is invalid';
    END IF;
    FOREACH binding_key IN ARRAY ARRAY['action','resource','requestId','correlationId','profile','resourceMode','collectionUsage'] LOOP
        IF (submitted_request ? binding_key)<>(submitted_decision ? binding_key)
            OR submitted_request->binding_key IS DISTINCT FROM submitted_decision->binding_key THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='authorization request binding differs';
        END IF;
    END LOOP;
    FOREACH binding_key IN ARRAY ARRAY['action','requestId','correlationId','resourceMode'] LOOP
        IF jsonb_typeof(submitted_request->binding_key) IS DISTINCT FROM 'string' THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='authorization request binding is invalid';
        END IF;
    END LOOP;
    IF jsonb_typeof(submitted_request->'profile') IS DISTINCT FROM 'object'
        OR COALESCE(submitted_request->>'correlationId','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='authorization request profile is invalid';
    END IF;
    -- Lock current selection for the complete transaction, not merely lookup.
    PERFORM * FROM iam.current_authorization_profiles();
    IF NOT EXISTS(SELECT 1 FROM iam.authorization_profile_heads head
        JOIN iam.authorization_profiles archive ON archive.product=head.product AND archive.revision=head.revision
        WHERE submitted_request->'profile'=jsonb_build_object('product',archive.product,'revision',archive.revision,'contentDigest',archive.content_digest))
        OR NOT iam.authorization_decision_profile_matches(submitted_decision) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='authorization profile or target is not current';
    END IF;
    IF submitted_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_subject_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR jsonb_typeof(submitted_decision) <> 'object'
       OR jsonb_typeof(submitted_decision->'resource') <> 'object'
       OR jsonb_typeof(submitted_decision->'allowed') <> 'boolean'
       OR NOT (submitted_decision ?& ARRAY[
            'apiVersion', 'kind', 'id', 'allowed', 'reason', 'action',
            'resource', 'requestId', 'decidedAt', 'profile', 'resourceMode', 'correlationId'
       ])
       OR (submitted_decision - ARRAY[
            'apiVersion', 'kind', 'id', 'allowed', 'reason', 'tenantId',
            'subject', 'installationId', 'action', 'resource', 'requestId', 'decidedAt', 'profile', 'resourceMode', 'collectionUsage', 'correlationId'
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
    platform_action := iam.is_platform_action(submitted_decision->>'action');
    IF expected_kind IS NULL OR platform_action IS NULL
       OR submitted_decision#>>'{resource,kind}' IS DISTINCT FROM expected_kind THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'authorization action and resource are invalid';
    END IF;

    PERFORM set_config('matrix.iam_tenant_id', submitted_tenant_id, true);
    IF submitted_role_evidence <> 'null'::jsonb THEN
        actor_type:='ROLE';
        PERFORM iam.assert_current_role_authorization(submitted_tenant_id,submitted_subject_id,submitted_role_evidence);
        expected_subject:=jsonb_build_object('type','ROLE','id',submitted_subject_id,'roleSession',jsonb_build_object(
          'sessionId',submitted_role_evidence->>'sessionId','sourceUserId',submitted_role_evidence->>'sourceUserId'));
    ELSE
      SELECT principal.principal_type INTO actor_type
      FROM iam.accounts AS organization
      JOIN iam.principals AS principal
        ON principal.tenant_id = organization.id
     WHERE organization.id = submitted_tenant_id
       AND organization.status = 'ACTIVE'
       AND principal.id = submitted_subject_id
       AND principal.status = 'ACTIVE';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'authorization subject is unavailable';
    END IF;
      expected_subject:=jsonb_build_object('type',actor_type,'id',submitted_subject_id);
    END IF;

    decision_allowed := (submitted_decision->>'allowed')::boolean;
    IF decision_allowed AND actor_type='USER' AND EXISTS(SELECT 1 FROM iam.principals AS principal
        WHERE principal.tenant_id=submitted_tenant_id AND principal.id=submitted_subject_id AND principal.must_change_password) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='authorization subject requires credential replacement';
    END IF;
    IF jsonb_typeof(submitted_policy_evidence) IS DISTINCT FROM 'array'
        OR jsonb_array_length(submitted_policy_evidence)>256
        OR (decision_allowed AND jsonb_array_length(submitted_policy_evidence)=0) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='authorization policy evidence is invalid';
    END IF;
    FOR evidence IN SELECT value FROM jsonb_array_elements(submitted_policy_evidence) LOOP
        IF jsonb_typeof(evidence) IS DISTINCT FROM 'object'
            OR NOT evidence ?& ARRAY['attachmentId','resourceVersion','version','contractVersion']
            OR (evidence-ARRAY['attachmentId','resourceVersion','version','membershipId','membershipResourceVersion','contractVersion','compilation']) <> '{}'::jsonb
            OR COALESCE(evidence->>'attachmentId','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            OR evidence->>'attachmentId' COLLATE "C" <= previous_attachment
            OR jsonb_typeof(evidence->'resourceVersion') IS DISTINCT FROM 'number'
            OR COALESCE(evidence->>'resourceVersion','') !~ '^[1-9][0-9]{0,15}$'
            OR jsonb_typeof(evidence->'version') IS DISTINCT FROM 'object'
            OR NOT (evidence->'version') ?& ARRAY['policyId','versionId','contentDigest']
            OR ((evidence->'version')-ARRAY['policyId','versionId','contentDigest']) <> '{}'::jsonb
            OR (evidence ? 'membershipId')<>(evidence ? 'membershipResourceVersion')
            OR (evidence ? 'membershipId' AND (
                jsonb_typeof(evidence->'membershipId') IS DISTINCT FROM 'string'
                OR COALESCE(evidence->>'membershipId','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
                OR jsonb_typeof(evidence->'membershipResourceVersion') IS DISTINCT FROM 'number'
                OR COALESCE(evidence->>'membershipResourceVersion','') !~ '^[1-9][0-9]{0,15}$')) THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='authorization policy evidence shape is invalid';
        END IF;
        IF NOT EXISTS(SELECT 1 FROM iam.policy_attachments AS attachment
            JOIN iam.policies AS policy ON policy.id=attachment.policy_id
            JOIN iam.policy_versions AS version ON version.policy_id=policy.id AND version.id=policy.default_version_id AND version.retired_at IS NULL
            WHERE attachment.tenant_id=submitted_tenant_id AND attachment.id=evidence->>'attachmentId'
              AND ((NOT evidence ? 'membershipId' AND attachment.target_id=submitted_subject_id AND attachment.target_kind=actor_type)
                OR (actor_type='USER' AND attachment.target_kind='GROUP' AND attachment.authority_scope='TENANT'
                    AND evidence ? 'membershipId' AND EXISTS(
                        SELECT 1 FROM iam.group_memberships AS membership
                        JOIN iam.groups AS g ON g.tenant_id=membership.tenant_id AND g.id=membership.group_id AND g.deleted_at IS NULL
                        WHERE membership.tenant_id=submitted_tenant_id AND membership.id=evidence->>'membershipId'
                          AND membership.group_id=attachment.target_id AND membership.user_id=submitted_subject_id
                          AND membership.resource_version=(evidence->>'membershipResourceVersion')::bigint
                          AND membership.removed_at IS NULL)))
              AND attachment.resource_version=(evidence->>'resourceVersion')::bigint
              AND attachment.revoked_at IS NULL AND policy.status='ACTIVE'
              AND (policy.owner_tenant_id IS NULL OR policy.owner_tenant_id=submitted_tenant_id)
              AND policy.id=evidence#>>'{version,policyId}' AND version.id=evidence#>>'{version,versionId}'
              AND version.content_digest=evidence#>>'{version,contentDigest}'
              AND evidence->'contractVersion'=to_jsonb(version.contract_version)
              AND ((version.contract_version=1 AND NOT evidence ? 'compilation')
                  OR (version.contract_version=2 AND evidence->'compilation'=version.compilation))
              AND attachment.authority_scope=CASE WHEN platform_action THEN 'INSTALLATION'
                  WHEN submitted_decision->>'action'='installation.verify' THEN 'INSTALLATION_PROBE' ELSE 'TENANT' END) THEN
            RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='authorization policy evidence is not current for its subject';
        END IF;
        previous_attachment := evidence->>'attachmentId';
    END LOOP;
    IF actor_type='ROLE' THEN
      IF submitted_boundary_evidence IS DISTINCT FROM '{"state":"NOT_APPLICABLE"}'::jsonb THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role cannot submit a user boundary'; END IF;
    ELSE
      PERFORM iam.assert_current_user_boundary_evidence(submitted_tenant_id,submitted_subject_id,
        submitted_decision->>'action',submitted_boundary_evidence);
    END IF;
    expected_result := CASE WHEN decision_allowed THEN 'ALLOWED' ELSE 'DENIED' END;
    IF submitted_decision->>'reason' IS DISTINCT FROM expected_result
       OR (decision_allowed AND (
            NOT (submitted_decision ? 'subject')
            OR jsonb_typeof(submitted_decision->'subject') <> 'object'
            OR submitted_decision->'subject' IS DISTINCT FROM expected_subject
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
                      ON principal.tenant_id = binding.tenant_id AND principal.id = binding.target_id
                     WHERE binding.tenant_id = submitted_tenant_id
                       AND binding.target_id = submitted_subject_id
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
       OR submitted_audit_event->>'correlationId' IS DISTINCT FROM
            submitted_decision->>'correlationId'
       OR submitted_audit_event->'actor' IS DISTINCT FROM expected_subject THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'authorization Audit event authority is invalid';
    END IF;

    INSERT INTO iam.authorization_decisions (
        tenant_id, id, principal_id, allowed, action_name, target_kind,
        target_id, request_id, decided_at, document, policy_evidence, boundary_evidence,
        contract_version, profile_product, profile_revision, profile_content_digest, resource_mode, collection_usage,
        subject_type, role_id, source_principal_id, role_evidence
    ) VALUES (
        submitted_tenant_id,
        submitted_decision->>'id',
        CASE WHEN actor_type='ROLE' THEN NULL ELSE submitted_subject_id END,
        decision_allowed,
        submitted_decision->>'action',
        submitted_decision#>>'{resource,kind}',
        submitted_decision#>>'{resource,id}',
        submitted_decision->>'requestId',
        effective_now,
        submitted_decision,
        submitted_policy_evidence,
        submitted_boundary_evidence,
        3,
        submitted_decision#>>'{profile,product}',
        (submitted_decision#>>'{profile,revision}')::bigint,
        submitted_decision#>>'{profile,contentDigest}',
        submitted_decision->>'resourceMode',
        submitted_decision->>'collectionUsage',
        actor_type, CASE WHEN actor_type='ROLE' THEN submitted_subject_id ELSE NULL END,
        CASE WHEN actor_type='ROLE' THEN submitted_role_evidence->>'sourceUserId' ELSE NULL END,
        nullif(submitted_role_evidence,'null'::jsonb)
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

DROP FUNCTION IF EXISTS iam.assert_allowed_decision(text,text,text,text,text,text);
CREATE OR REPLACE FUNCTION iam.assert_allowed_decision(
    submitted_tenant_id text,
    submitted_actor_principal_id text,
    submitted_decision_id text,
    submitted_action text,
    submitted_target_kind text,
    submitted_target_id text,
    submitted_resource_mode text,
    submitted_collection_usage text
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
           AND decision.contract_version = 3 AND decision.subject_type='USER'
           AND EXISTS(SELECT 1 FROM iam.authorization_profile_heads head
             JOIN iam.authorization_profiles archive ON archive.product=head.product AND archive.revision=head.revision
             WHERE head.product=decision.profile_product AND head.revision=decision.profile_revision
               AND archive.content_digest=decision.profile_content_digest)
           AND decision.resource_mode = submitted_resource_mode
           AND decision.collection_usage IS NOT DISTINCT FROM submitted_collection_usage
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
        ,'INSTANCE',NULL);
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
    ,'INSTANCE',NULL);
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
        'target',jsonb_build_object('kind',a.target_kind,'id',a.target_id),'policyId',a.policy_id,
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
            'iam.platform-policy.list','INSTALLATION',installation,'INSTANCE',NULL);
    ELSE
        PERFORM iam.assert_allowed_decision(submitted_tenant_id,submitted_actor_principal_id,submitted_decision_id,
            'iam.policy.list','ACCOUNT',submitted_tenant_id,'INSTANCE',NULL);
    END IF;
    SELECT COALESCE(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
        'apiVersion','iam.matrix.xiak.com/v1','kind','Policy','id',p.id,'management',p.management,
        'accountId',p.owner_tenant_id,'displayName',p.display_name,'scope',p.authority_scope,'status',p.status,
        'defaultVersionId',p.default_version_id,'resourceVersion',p.resource_version,
        'createdAt',p.created_at,'updatedAt',p.updated_at)) ORDER BY p.id COLLATE "C"),'[]'::jsonb)
      INTO items FROM (SELECT * FROM iam.policies
        WHERE authority_scope=submitted_scope AND status='ACTIVE' AND (owner_tenant_id IS NULL OR owner_tenant_id=submitted_tenant_id)
        ORDER BY id COLLATE "C" LIMIT 257) AS p;
    IF jsonb_array_length(items)>256 THEN
        RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='policy directory exceeds its read budget';
    END IF;
    RETURN jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','PolicyList',
        'accountId',submitted_tenant_id,'scope',submitted_scope,'installationId',installation,'items',items));
END $function$;

DROP FUNCTION IF EXISTS iam.create_policy_attachment(text,text,text,text,bigint,text,text,jsonb);
DROP FUNCTION IF EXISTS iam.create_policy_attachment(text,text,text,text,text,bigint,text,text,jsonb);
CREATE OR REPLACE FUNCTION iam.create_policy_attachment(
    submitted_tenant_id text, submitted_attachment_id text, submitted_target_kind text, submitted_target_id text,
    submitted_policy_id text, submitted_policy_version bigint, submitted_actor_principal_id text,
    submitted_decision_id text, submitted_audit_event jsonb, actor_session_id text
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_now timestamptz(6) := transaction_timestamp();
    stored iam.policy_attachments%ROWTYPE;
    policy iam.policies%ROWTYPE;
    target_user iam.principals%ROWTYPE;
    action_name text;
    event_action text;
BEGIN
    IF COALESCE(submitted_tenant_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_attachment_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_target_kind IS NULL OR submitted_target_kind NOT IN ('USER','GROUP','ROLE')
       OR COALESCE(actor_session_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_target_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_policy_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_policy_version IS NULL OR submitted_policy_version NOT BETWEEN 1 AND 9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy attachment input is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',submitted_tenant_id,true);
    PERFORM 1 FROM iam.accounts WHERE id=submitted_tenant_id AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account is unavailable'; END IF;
    -- Lock both real USER rows in one stable order, including self-targets.
    -- Credential, logout and platform-grant writers serialize on these rows.
    -- The decision already holds an actor FK KEY SHARE: protect mutable
    -- identity state without competing to upgrade that immutable key reference.
    PERFORM 1 FROM iam.principals p WHERE p.tenant_id=submitted_tenant_id
        AND (p.id=submitted_actor_principal_id OR (submitted_target_kind='USER' AND p.id=submitted_target_id))
        ORDER BY p.id FOR NO KEY UPDATE;
    PERFORM 1 FROM iam.principals p WHERE p.tenant_id=submitted_tenant_id AND p.id=submitted_actor_principal_id
        AND p.principal_type='USER' AND p.status='ACTIVE' AND p.deleted_at IS NULL AND NOT p.must_change_password;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='attachment actor is unavailable'; END IF;
    PERFORM 1 FROM iam.user_credentials c JOIN iam.sessions s
        ON s.tenant_id=c.tenant_id AND s.principal_id=c.principal_id
        WHERE c.tenant_id=submitted_tenant_id AND c.principal_id=submitted_actor_principal_id AND s.id=actor_session_id
          AND s.status='ACTIVE' AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
          AND s.credential_version=c.credential_version FOR SHARE OF c,s;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='attachment session is unavailable'; END IF;
    IF submitted_target_kind='USER' THEN
        SELECT * INTO target_user FROM iam.principals
         WHERE tenant_id=submitted_tenant_id AND id=submitted_target_id AND principal_type='USER' AND status='ACTIVE'
           AND deleted_at IS NULL FOR NO KEY UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='attachment target is unavailable'; END IF;
    ELSIF submitted_target_kind='GROUP' THEN
        PERFORM 1 FROM iam.groups
         WHERE tenant_id=submitted_tenant_id AND id=submitted_target_id AND deleted_at IS NULL FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='attachment group is unavailable'; END IF;
    ELSE
        PERFORM iam.assert_role_writer(submitted_tenant_id,submitted_actor_principal_id,actor_session_id,NULL);
        PERFORM 1 FROM iam.roles WHERE tenant_id=submitted_tenant_id AND id=submitted_target_id AND deleted_at IS NULL FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='attachment role is unavailable'; END IF;
    END IF;
    SELECT * INTO policy FROM iam.policies
     WHERE id=submitted_policy_id AND status='ACTIVE'
       AND (owner_tenant_id IS NULL OR owner_tenant_id=submitted_tenant_id) FOR SHARE;
    IF NOT FOUND OR policy.authority_scope NOT IN ('TENANT','INSTALLATION')
       OR (submitted_target_kind IN ('GROUP','ROLE') AND policy.authority_scope<>'TENANT') THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='attachment policy is unavailable';
    END IF;
    IF policy.resource_version <> submitted_policy_version THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy revision conflicts';
    END IF;
    IF policy.authority_scope='INSTALLATION' AND (target_user.must_change_password OR NOT EXISTS (
        SELECT 1 FROM iam.bootstrap_receipts WHERE organization_id=submitted_tenant_id
    )) THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='platform target is unavailable'; END IF;
    action_name := CASE WHEN submitted_target_kind='GROUP' THEN 'iam.group-policy-attachment.create'
                   WHEN submitted_target_kind='ROLE' THEN 'iam.role-policy-attachment.create'
                   WHEN policy.authority_scope='INSTALLATION' THEN 'iam.platform-policy-attachment.create'
                   ELSE 'iam.policy-attachment.create' END;
    event_action := CASE policy.authority_scope WHEN 'INSTALLATION' THEN 'iam.platform-policy-attachment.created'
                    ELSE 'iam.policy-attachment.created' END;
    PERFORM iam.assert_allowed_decision(submitted_tenant_id,submitted_actor_principal_id,submitted_decision_id,
        action_name,submitted_target_kind,submitted_target_id,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(submitted_audit_event,submitted_tenant_id,event_action,'POLICY_ATTACHMENT',submitted_attachment_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(submitted_tenant_id,submitted_actor_principal_id,submitted_audit_event);
    IF submitted_audit_event->>'iamDecisionId' IS DISTINCT FROM submitted_decision_id THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='attachment decision correlation is invalid';
    END IF;
    SELECT * INTO stored FROM iam.policy_attachments
     WHERE tenant_id=submitted_tenant_id AND id=submitted_attachment_id FOR UPDATE;
    IF FOUND THEN
        IF stored.target_kind<>submitted_target_kind OR stored.target_id<>submitted_target_id
           OR stored.policy_id<>submitted_policy_id OR stored.revoked_at IS NOT NULL
           OR NOT EXISTS (SELECT 1 FROM iam.audit_outbox WHERE tenant_id=submitted_tenant_id
               AND event_document->>'action'=event_action AND event_document#>>'{target,id}'=stored.id
               AND event_document->>'requestId'=submitted_audit_event->>'requestId'
               AND event_document->>'requestDigest'=submitted_audit_event->>'requestDigest'
               AND event_document#>>'{actor,id}'=submitted_actor_principal_id) THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='attachment intent conflicts';
        END IF;
        RETURN iam.lookup_policy_attachment(submitted_tenant_id,stored.id);
    END IF;
    INSERT INTO iam.policy_attachments(tenant_id,id,target_kind,target_id,policy_id,resource_version,created_at,updated_at)
    VALUES(submitted_tenant_id,submitted_attachment_id,submitted_target_kind,submitted_target_id,submitted_policy_id,1,effective_now,effective_now);
    IF submitted_target_kind='ROLE' THEN
        UPDATE iam.roles r SET security_generation=r.security_generation+1 WHERE r.tenant_id=submitted_tenant_id AND r.id=submitted_target_id;
    END IF;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
    VALUES(submitted_tenant_id,submitted_audit_event->>'eventId',submitted_audit_event,effective_now,effective_now,effective_now);
    RETURN iam.lookup_policy_attachment(submitted_tenant_id,submitted_attachment_id);
END $function$;

DROP FUNCTION IF EXISTS iam.revoke_policy_attachment(text,text,text,text,jsonb);
DROP FUNCTION IF EXISTS iam.revoke_policy_attachment(text,text,bigint,text,text,jsonb);
CREATE OR REPLACE FUNCTION iam.revoke_policy_attachment(
    submitted_tenant_id text, submitted_attachment_id text, submitted_resource_version bigint,
    submitted_actor_principal_id text, submitted_decision_id text, submitted_audit_event jsonb, actor_session_id text
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
       OR COALESCE(actor_session_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_resource_version IS NULL OR submitted_resource_version NOT BETWEEN 1 AND 9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='attachment revocation input is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',submitted_tenant_id,true);
    PERFORM 1 FROM iam.accounts WHERE id=submitted_tenant_id AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account is unavailable'; END IF;
    SELECT * INTO stored FROM iam.policy_attachments
     WHERE tenant_id=submitted_tenant_id AND id=submitted_attachment_id;
    IF NOT FOUND OR stored.target_kind NOT IN ('USER','GROUP','ROLE') OR stored.authority_scope NOT IN ('TENANT','INSTALLATION')
       OR (stored.target_kind IN ('GROUP','ROLE') AND stored.authority_scope<>'TENANT') THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='attachment is unavailable';
    END IF;
    -- The immutable target may be read before locking; mutation locks always
    -- start with the same sorted actor/USER set as attachment creation.
    PERFORM 1 FROM iam.principals p WHERE p.tenant_id=submitted_tenant_id
        AND (p.id=submitted_actor_principal_id OR (stored.target_kind='USER' AND p.id=stored.target_id))
        ORDER BY p.id FOR NO KEY UPDATE;
    PERFORM 1 FROM iam.principals p WHERE p.tenant_id=submitted_tenant_id AND p.id=submitted_actor_principal_id
        AND p.principal_type='USER' AND p.status='ACTIVE' AND p.deleted_at IS NULL AND NOT p.must_change_password;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='attachment actor is unavailable'; END IF;
    PERFORM 1 FROM iam.user_credentials c JOIN iam.sessions s
        ON s.tenant_id=c.tenant_id AND s.principal_id=c.principal_id
        WHERE c.tenant_id=submitted_tenant_id AND c.principal_id=submitted_actor_principal_id AND s.id=actor_session_id
          AND s.status='ACTIVE' AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
          AND s.credential_version=c.credential_version FOR SHARE OF c,s;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='attachment session is unavailable'; END IF;
    IF stored.target_kind='GROUP' THEN
        PERFORM 1 FROM iam.groups WHERE tenant_id=submitted_tenant_id AND id=stored.target_id FOR UPDATE;
    ELSIF stored.target_kind='ROLE' THEN
        PERFORM iam.assert_role_writer(submitted_tenant_id,submitted_actor_principal_id,actor_session_id,NULL);
        PERFORM 1 FROM iam.roles WHERE tenant_id=submitted_tenant_id AND id=stored.target_id AND deleted_at IS NULL FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='attachment role is unavailable'; END IF;
    ELSE
        PERFORM 1 FROM iam.principals WHERE tenant_id=submitted_tenant_id AND id=stored.target_id FOR NO KEY UPDATE;
    END IF;
    PERFORM 1 FROM iam.policies WHERE id=stored.policy_id FOR SHARE;
    SELECT * INTO stored FROM iam.policy_attachments
     WHERE tenant_id=submitted_tenant_id AND id=submitted_attachment_id FOR UPDATE;
    action_name := CASE WHEN stored.target_kind='GROUP' THEN 'iam.group-policy-attachment.revoke'
                   WHEN stored.target_kind='ROLE' THEN 'iam.role-policy-attachment.revoke'
                   WHEN stored.authority_scope='INSTALLATION' THEN 'iam.platform-policy-attachment.revoke'
                   ELSE 'iam.policy-attachment.revoke' END;
    event_action := CASE stored.authority_scope WHEN 'INSTALLATION' THEN 'iam.platform-policy-attachment.revoked'
                    ELSE 'iam.policy-attachment.revoked' END;
    PERFORM iam.assert_allowed_decision(submitted_tenant_id,submitted_actor_principal_id,submitted_decision_id,
        action_name,'POLICY_ATTACHMENT',submitted_attachment_id,'INSTANCE',NULL);
    IF stored.target_kind='USER' AND stored.policy_id='system.account-administrator' AND EXISTS (
        SELECT 1 FROM iam.account_roots WHERE account_id=submitted_tenant_id AND principal_id=stored.target_id
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
    IF stored.target_kind='ROLE' THEN
        UPDATE iam.roles r SET security_generation=r.security_generation+1 WHERE r.tenant_id=submitted_tenant_id AND r.id=stored.target_id;
    END IF;
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
GRANT EXECUTE ON FUNCTION iam.current_authorization_profiles() TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.lookup_authorization_profile(text,bigint,text) TO matrix_iam_api;
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
    text, text, jsonb, jsonb, jsonb, jsonb, integer, jsonb
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
    text, text, text, text, text, bigint, text, text, jsonb, text
) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.lookup_policy(text, text) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.list_policies(text, text, text, text) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.lookup_policy_attachment(text, text) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.revoke_policy_attachment(
    text, text, bigint, text, text, jsonb, text
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
