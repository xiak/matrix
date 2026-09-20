SET LOCAL ROLE matrix_iam_owner;

-- TOTP custody has a different purpose and multi-key lifetime from AccessKey.
-- No seed or raw wrapping key can be submitted through registration.
CREATE TABLE IF NOT EXISTS iam.totp_wrapping_registry (
    installation_id text COLLATE "C" NOT NULL REFERENCES iam.bootstrap_receipts(installation_id),
    key_id text COLLATE "C" NOT NULL CHECK(key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    format_version integer NOT NULL CHECK(format_version=1),
    material_commitment text NOT NULL CHECK(material_commitment ~ '^sha256:[0-9a-f]{64}$'),
    registered_at timestamptz(6) NOT NULL,
    PRIMARY KEY(installation_id,key_id)
);
CREATE TABLE IF NOT EXISTS iam.totp_keysets (
    installation_id text COLLATE "C" NOT NULL REFERENCES iam.bootstrap_receipts(installation_id),
    revision bigint NOT NULL CHECK(revision>0),
    registration jsonb NOT NULL CHECK(jsonb_typeof(registration)='object' AND octet_length(registration::text)<=8192),
    registered_at timestamptz(6) NOT NULL,
    PRIMARY KEY(installation_id,revision)
);

-- The factor retains its immutable encrypted seed identity across enrollment,
-- use and revocation. Unrecognized preparation rows never gain runtime rights.
CREATE TABLE IF NOT EXISTS iam.totp_authenticators (
    id text COLLATE "C" NOT NULL CHECK(id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    tenant_id text COLLATE "C" NOT NULL,
    user_id text COLLATE "C" NOT NULL,
    installation_id text COLLATE "C" NOT NULL,
    key_id text COLLATE "C" NOT NULL,
    format_version integer NOT NULL CHECK(format_version=1),
    nonce bytea NOT NULL CHECK(octet_length(nonce)=12),
    ciphertext bytea NOT NULL CHECK(octet_length(ciphertext)=36),
    state text NOT NULL CHECK(state IN ('PENDING','ACTIVE','REVOKED')),
    last_consumed_step bigint NOT NULL CHECK(last_consumed_step>=-1),
    created_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(installation_id,key_id) REFERENCES iam.totp_wrapping_registry(installation_id,key_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS totp_one_active ON iam.totp_authenticators(tenant_id,user_id) WHERE state='ACTIVE';
CREATE UNIQUE INDEX IF NOT EXISTS totp_one_pending ON iam.totp_authenticators(tenant_id,user_id) WHERE state='PENDING';
ALTER TABLE iam.totp_authenticators ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.totp_authenticators FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON iam.totp_authenticators;
CREATE POLICY tenant_isolation ON iam.totp_authenticators
    USING(tenant_id=iam.current_tenant_id() OR current_setting('matrix.iam_totp_custody',true)='trusted')
    WITH CHECK(tenant_id=iam.current_tenant_id());

DO $protection$
DECLARE relation_name text; operation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['totp_wrapping_registry','totp_keysets','totp_authenticators'] LOOP
        FOREACH operation_name IN ARRAY ARRAY['update','delete','truncate'] LOOP
            -- The preparation release can only preserve seed rows. Enabling
            -- MFA must replace this with the real lifecycle transition guard.
            EXECUTE format('DROP TRIGGER IF EXISTS cannot_%s ON iam.%I',operation_name,relation_name);
            EXECUTE format('CREATE TRIGGER cannot_%s BEFORE %s ON iam.%I FOR EACH %s EXECUTE FUNCTION iam.reject_policy_history_change()',
                operation_name,upper(operation_name),relation_name,CASE WHEN operation_name='truncate' THEN 'STATEMENT' ELSE 'ROW' END);
            EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER cannot_%s',relation_name,operation_name);
        END LOOP;
    END LOOP;
END $protection$;

CREATE OR REPLACE FUNCTION iam.register_totp_keyset(document jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; latest iam.totp_keysets%ROWTYPE;
    key_document jsonb; previous_id text:=''; active_found boolean:=false;
    supplied_revision bigint; active_id text; effective_now timestamptz(6);
BEGIN
    IF document IS NULL OR jsonb_typeof(document)<>'object' OR octet_length(document::text)>8192
        OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(document) k)<>
            ARRAY['activeKeyId','contentDigest','keys','keysetRevision','scope']
        OR jsonb_typeof(document->'scope')<>'object'
        OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(document->'scope') k)<>ARRAY['bootstrapDigest','installationId']
        OR jsonb_typeof(document->'keys')<>'array' OR jsonb_array_length(document->'keys') NOT BETWEEN 1 AND 8
        OR jsonb_typeof(document->'keysetRevision')<>'number'
        OR COALESCE(document->>'keysetRevision','') !~ '^[1-9][0-9]{0,18}$'
        OR COALESCE(document->>'contentDigest','') !~ '^sha256:[0-9a-f]{64}$'
        OR jsonb_typeof(document->'contentDigest')<>'string' OR jsonb_typeof(document->'activeKeyId')<>'string'
        OR COALESCE(document->>'activeKeyId','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='TOTP registration is invalid';
    END IF;
    supplied_revision:=(document->>'keysetRevision')::bigint; active_id:=document->>'activeKeyId';
    SELECT * INTO receipt FROM iam.bootstrap_receipts WHERE singleton FOR SHARE;
    IF NOT FOUND OR document->'scope'<>jsonb_build_object('installationId',receipt.installation_id,'bootstrapDigest',receipt.content_digest) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='TOTP installation is unavailable';
    END IF;
    -- Startup only, never Argon2 work. Runtime readers hold SHARE until their
    -- transaction finishes, so registration cannot overtake a checked request.
    LOCK TABLE iam.totp_keysets IN SHARE ROW EXCLUSIVE MODE;
    SELECT * INTO latest FROM iam.totp_keysets WHERE installation_id=receipt.installation_id ORDER BY revision DESC LIMIT 1;
    IF FOUND AND (supplied_revision<latest.revision OR (supplied_revision=latest.revision AND document<>latest.registration)) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='TOTP keyset history conflicts';
    END IF;
    FOR key_document IN SELECT value FROM jsonb_array_elements(document->'keys') LOOP
        IF jsonb_typeof(key_document)<>'object'
            OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(key_document) k)<>ARRAY['formatVersion','keyId','materialCommitment']
            OR jsonb_typeof(key_document->'keyId')<>'string'
            OR COALESCE(key_document->>'keyId','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            OR (key_document->>'keyId') COLLATE "C"<=previous_id COLLATE "C"
            OR key_document->'formatVersion'<>'1'::jsonb
            OR jsonb_typeof(key_document->'materialCommitment')<>'string'
            OR COALESCE(key_document->>'materialCommitment','') !~ '^sha256:[0-9a-f]{64}$' THEN
            RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='TOTP key commitment is invalid';
        END IF;
        previous_id:=key_document->>'keyId'; active_found:=active_found OR previous_id=active_id;
        IF EXISTS(SELECT 1 FROM iam.totp_wrapping_registry r WHERE r.installation_id=receipt.installation_id AND r.key_id=previous_id
            AND (r.format_version<>(key_document->>'formatVersion')::integer OR r.material_commitment<>key_document->>'materialCommitment')) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='TOTP key identity conflicts';
        END IF;
    END LOOP;
    IF NOT active_found OR EXISTS(SELECT 1 FROM iam.totp_wrapping_registry r WHERE r.installation_id<>receipt.installation_id
        OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(document->'keys') k WHERE k->>'keyId'=r.key_id)) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='TOTP retirement is not supported';
    END IF;
    IF supplied_revision=latest.revision THEN RETURN; END IF;
    effective_now:=clock_timestamp();
    INSERT INTO iam.totp_wrapping_registry(installation_id,key_id,format_version,material_commitment,registered_at)
        SELECT receipt.installation_id,k->>'keyId',(k->>'formatVersion')::integer,k->>'materialCommitment',effective_now
        FROM jsonb_array_elements(document->'keys') k ON CONFLICT DO NOTHING;
    INSERT INTO iam.totp_keysets(installation_id,revision,registration,registered_at)
        VALUES(receipt.installation_id,supplied_revision,document,effective_now);
END $function$;

-- Shared validation, not a grant to read the tables. Both the locked runtime
-- transaction and the read-only backup snapshot use this exact invariant.
CREATE OR REPLACE FUNCTION iam.totp_keyset_snapshot()
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; latest iam.totp_keysets%ROWTYPE; key_count integer;
BEGIN
    SELECT * INTO receipt FROM iam.bootstrap_receipts WHERE singleton;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='TOTP installation is unavailable'; END IF;
    SELECT * INTO latest FROM iam.totp_keysets WHERE installation_id=receipt.installation_id ORDER BY revision DESC LIMIT 1;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='TOTP custody is unavailable'; END IF;
    SELECT count(*) INTO key_count FROM (SELECT 1 FROM iam.totp_wrapping_registry LIMIT 9) bounded;
    IF latest.registration->'scope'<>jsonb_build_object('installationId',receipt.installation_id,'bootstrapDigest',receipt.content_digest)
        OR latest.registration->>'keysetRevision'<>latest.revision::text
        OR key_count<>jsonb_array_length(latest.registration->'keys') OR key_count NOT BETWEEN 1 AND 8
        OR EXISTS(SELECT 1 FROM iam.totp_wrapping_registry r WHERE r.installation_id<>receipt.installation_id
            OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(latest.registration->'keys') k
                WHERE k=jsonb_build_object('keyId',r.key_id,'formatVersion',r.format_version,'materialCommitment',r.material_commitment))) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='TOTP custody is incompatible';
    END IF;
    RETURN latest.registration;
END $function$;

CREATE OR REPLACE FUNCTION iam.read_totp_custody()
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE registration jsonb; prior_custody_scope text; has_authenticators boolean;
BEGIN
    LOCK TABLE iam.totp_keysets IN SHARE MODE;
    registration:=iam.totp_keyset_snapshot();
    prior_custody_scope:=current_setting('matrix.iam_totp_custody',true);
    PERFORM set_config('matrix.iam_totp_custody','trusted',true);
    SELECT EXISTS(SELECT 1 FROM iam.totp_authenticators f
        LEFT JOIN iam.totp_wrapping_registry k ON (k.installation_id,k.key_id)=(f.installation_id,f.key_id)
        WHERE (f.enrollment_session_id IS NULL AND f.recovery_id IS NULL) OR f.installation_id<>registration#>>'{scope,installationId}'
            OR k.key_id IS NULL OR f.format_version IS DISTINCT FROM k.format_version OR f.format_version IS DISTINCT FROM 1
            OR octet_length(f.nonce) IS DISTINCT FROM 12 OR octet_length(f.ciphertext) IS DISTINCT FROM 36
            OR f.state IS NULL OR f.state NOT IN ('PENDING','ACTIVE','REVOKED')) INTO has_authenticators;
    PERFORM set_config('matrix.iam_totp_custody',COALESCE(prior_custody_scope,''),true);
    RETURN jsonb_build_object('keyset',registration,'hasUnrecognizedAuthenticators',has_authenticators);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_totp_backup_custody()
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE registration jsonb; required_keys jsonb; prior_custody_scope text;
BEGIN
    IF session_user<>'matrix_iam_backup_custody_login'
        OR NOT pg_has_role(session_user,'matrix_iam_backup_custody','USAGE')
        OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=session_user
            AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls))
        OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname NOT IN (session_user,'matrix_iam_backup_custody')
            AND pg_has_role(session_user,r.oid,'MEMBER'))
        OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relnamespace='iam'::regnamespace
            AND c.relkind IN ('r','p','v','m','f')
            AND has_table_privilege(session_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
        OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.pronamespace='iam'::regnamespace
            AND p.oid<>to_regprocedure('iam.read_totp_backup_custody()') AND has_function_privilege(session_user,p.oid,'EXECUTE'))
        OR current_setting('transaction_isolation')<>'repeatable read'
        OR current_setting('transaction_read_only')<>'on' THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='TOTP backup custody context is forbidden';
    END IF;
    IF NOT iam.totp_custody_contract_ready() OR NOT iam.totp_backup_custody_contract_ready()
        OR (SELECT schema_version FROM iam.readiness())<>39 THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='TOTP backup custody shape is unavailable';
    END IF;
    registration:=iam.totp_keyset_snapshot();
    prior_custody_scope:=current_setting('matrix.iam_totp_custody',true);
    PERFORM set_config('matrix.iam_totp_custody','trusted',true);
    IF EXISTS(SELECT 1 FROM iam.totp_authenticators f
        LEFT JOIN iam.totp_wrapping_registry k ON (k.installation_id,k.key_id)=(f.installation_id,f.key_id)
        WHERE f.installation_id<>registration#>>'{scope,installationId}'
            OR k.key_id IS NULL OR f.format_version IS DISTINCT FROM k.format_version OR f.format_version IS DISTINCT FROM 1
            OR f.state IS NULL OR f.state NOT IN ('PENDING','ACTIVE','REVOKED')
            OR octet_length(f.nonce) IS DISTINCT FROM 12 OR octet_length(f.ciphertext) IS DISTINCT FROM 36) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='TOTP backup references are unavailable';
    END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('keyId',k.key_id,'formatVersion',k.format_version,
        'commitment',k.material_commitment) ORDER BY k.key_id COLLATE "C"),'[]'::jsonb) INTO required_keys
        FROM iam.totp_wrapping_registry k WHERE EXISTS(SELECT 1 FROM iam.totp_authenticators f
            WHERE (f.installation_id,f.key_id)=(k.installation_id,k.key_id));
    PERFORM set_config('matrix.iam_totp_custody',COALESCE(prior_custody_scope,''),true);
    RETURN jsonb_build_object('apiVersion','installation.matrix.xiak.com/v1','kind','IAMTOTPBackupCustody',
        'purpose','IAM_TOTP_BACKUP_CUSTODY','installationId',registration#>>'{scope,installationId}',
        'bootstrapDigest',registration#>>'{scope,bootstrapDigest}','keysetRevision',registration->'keysetRevision',
        'requiredKeys',required_keys);
END $function$;

REVOKE ALL ON iam.totp_wrapping_registry,iam.totp_keysets,iam.totp_authenticators
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody;
REVOKE ALL ON FUNCTION iam.register_totp_keyset(jsonb),iam.read_totp_custody()
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.register_totp_keyset(jsonb),iam.read_totp_custody() TO matrix_iam_api;
REVOKE ALL ON FUNCTION iam.totp_keyset_snapshot(),iam.read_totp_backup_custody()
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody;
REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM matrix_iam_backup_custody;
REVOKE ALL ON SCHEMA iam FROM matrix_iam_backup_custody;
GRANT USAGE ON SCHEMA iam TO matrix_iam_backup_custody;
GRANT EXECUTE ON FUNCTION iam.read_totp_backup_custody() TO matrix_iam_backup_custody;

CREATE OR REPLACE FUNCTION iam.totp_custody_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT COALESCE(
        (SELECT count(*)=3 FROM pg_catalog.pg_class c WHERE c.oid IN (
            to_regclass('iam.totp_wrapping_registry'),to_regclass('iam.totp_keysets'),to_regclass('iam.totp_authenticators'))
            AND c.relowner='matrix_iam_owner'::regrole
            AND NOT has_table_privilege('matrix_iam_api',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
            AND NOT has_table_privilege('matrix_iam_worker',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
            AND NOT has_table_privilege('matrix_iam_credential_recovery',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
            AND NOT has_table_privilege('public',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'))
        AND EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=to_regclass('iam.totp_authenticators') AND c.relrowsecurity AND c.relforcerowsecurity)
        AND EXISTS(SELECT 1 FROM pg_catalog.pg_policies p WHERE p.schemaname='iam' AND p.tablename='totp_authenticators'
            AND p.policyname='tenant_isolation' AND p.with_check='(tenant_id = iam.current_tenant_id())')
        AND (SELECT count(*)=8 FROM pg_catalog.pg_trigger t WHERE t.tgrelid IN (
            to_regclass('iam.totp_wrapping_registry'),to_regclass('iam.totp_keysets'),to_regclass('iam.totp_authenticators'))
            AND t.tgname IN ('cannot_update','cannot_delete','cannot_truncate') AND t.tgenabled='A'
            AND t.tgfoid=to_regprocedure('iam.reject_policy_history_change()'))
        AND EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('iam.totp_authenticators')
            AND t.tgname='cannot_update' AND t.tgenabled='A' AND t.tgfoid=to_regprocedure('iam.guard_totp_transition()'))
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid IN (
            to_regclass('iam.totp_wrapping_registry'),to_regclass('iam.totp_keysets'),to_regclass('iam.totp_authenticators')) AND NOT c.convalidated)
        AND (SELECT count(*)=2 FROM pg_catalog.pg_proc p WHERE p.oid IN (
            to_regprocedure('iam.register_totp_keyset(jsonb)'),to_regprocedure('iam.read_totp_custody()'))
            AND p.proowner='matrix_iam_owner'::regrole AND p.prosecdef AND NOT p.proretset
            AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
            AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) permission
                WHERE permission.grantee NOT IN (p.proowner,'matrix_iam_api'::regrole)
                    OR (permission.grantee='matrix_iam_api'::regrole AND permission.is_grantable))
            AND has_function_privilege('matrix_iam_api',p.oid,'EXECUTE')
            AND NOT has_function_privilege('public',p.oid,'EXECUTE')
            AND NOT has_function_privilege('matrix_iam_worker',p.oid,'EXECUTE')
            AND NOT has_function_privilege('matrix_iam_credential_recovery',p.oid,'EXECUTE'))
        AND (SELECT prorettype='void'::regtype FROM pg_catalog.pg_proc WHERE oid=to_regprocedure('iam.register_totp_keyset(jsonb)'))
        AND (SELECT prorettype='jsonb'::regtype FROM pg_catalog.pg_proc WHERE oid=to_regprocedure('iam.read_totp_custody()')),false)
$function$;
REVOKE ALL ON FUNCTION iam.totp_custody_contract_ready() FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;

CREATE OR REPLACE FUNCTION iam.totp_backup_custody_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT COALESCE(
        EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname='matrix_iam_backup_custody'
            AND NOT r.rolsuper AND NOT r.rolcanlogin AND NOT r.rolcreatedb AND NOT r.rolcreaterole
            AND NOT r.rolreplication AND NOT r.rolbypassrls)
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname<>'matrix_iam_backup_custody'
            AND pg_has_role('matrix_iam_backup_custody',r.oid,'MEMBER'))
        AND NOT pg_has_role('matrix_iam_api','matrix_iam_backup_custody','MEMBER')
        AND NOT pg_has_role('matrix_iam_worker','matrix_iam_backup_custody','MEMBER')
        AND NOT pg_has_role('matrix_iam_credential_recovery','matrix_iam_backup_custody','MEMBER')
        AND has_schema_privilege('matrix_iam_backup_custody','iam','USAGE')
        AND NOT has_schema_privilege('matrix_iam_backup_custody','iam','CREATE')
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relnamespace='iam'::regnamespace
            AND c.relkind IN ('r','p','v','m','f')
            AND has_table_privilege('matrix_iam_backup_custody',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.pronamespace='iam'::regnamespace
            AND p.oid<>to_regprocedure('iam.read_totp_backup_custody()')
            AND has_function_privilege('matrix_iam_backup_custody',p.oid,'EXECUTE'))
        AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('iam.read_totp_backup_custody()')
            AND p.proowner='matrix_iam_owner'::regrole AND p.prosecdef AND NOT p.proretset
            AND p.prorettype='jsonb'::regtype AND p.provolatile='s' AND p.pronargs=0
            AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
            AND has_function_privilege('matrix_iam_backup_custody',p.oid,'EXECUTE')
            AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) permission
                WHERE permission.grantee NOT IN (p.proowner,'matrix_iam_backup_custody'::regrole)
                    OR (permission.grantee='matrix_iam_backup_custody'::regrole AND permission.is_grantable)))
        AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('iam.totp_keyset_snapshot()')
            AND p.proowner='matrix_iam_owner'::regrole AND NOT p.prosecdef AND NOT p.proretset
            AND p.prorettype='jsonb'::regtype AND p.provolatile='s' AND p.pronargs=0
            AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
            AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) permission
                WHERE permission.grantee<>p.proowner)),false)
$function$;
REVOKE ALL ON FUNCTION iam.totp_backup_custody_contract_ready()
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody;

-- The enrollment is the PENDING phase of the same immutable factor, not a
-- second credential. Nullable lineage preserves unrecognized preparation
-- rows; those rows can never acquire runtime enrollment/authentication rights.
ALTER TABLE iam.totp_authenticators ADD COLUMN IF NOT EXISTS enrollment_session_id text COLLATE "C";
ALTER TABLE iam.totp_authenticators ADD COLUMN IF NOT EXISTS enrollment_request_id text COLLATE "C";
ALTER TABLE iam.totp_authenticators ADD COLUMN IF NOT EXISTS enrollment_digest text;
ALTER TABLE iam.totp_authenticators ADD COLUMN IF NOT EXISTS enrollment_revision bigint;
ALTER TABLE iam.totp_authenticators ADD COLUMN IF NOT EXISTS credential_generation bigint;
ALTER TABLE iam.totp_authenticators ADD COLUMN IF NOT EXISTS expires_at timestamptz(6);
ALTER TABLE iam.totp_authenticators ADD COLUMN IF NOT EXISTS enrollment_outcome text;
ALTER TABLE iam.totp_authenticators ADD COLUMN IF NOT EXISTS completed_at timestamptz(6);
ALTER TABLE iam.totp_authenticators ADD COLUMN IF NOT EXISTS bound_revision bigint;
ALTER TABLE iam.totp_authenticators ADD COLUMN IF NOT EXISTS bound_event_id text COLLATE "C";
ALTER TABLE iam.totp_authenticators ADD COLUMN IF NOT EXISTS revoked_at timestamptz(6);
ALTER TABLE iam.totp_authenticators ADD COLUMN IF NOT EXISTS recovery_id text COLLATE "C";
CREATE UNIQUE INDEX IF NOT EXISTS totp_factor_user_identity ON iam.totp_authenticators(tenant_id,user_id,id);
CREATE UNIQUE INDEX IF NOT EXISTS totp_enrollment_intent ON iam.totp_authenticators(tenant_id,user_id,enrollment_request_id)
    WHERE enrollment_request_id IS NOT NULL;
DROP INDEX IF EXISTS iam.totp_unrecognized_lineage;
CREATE INDEX totp_unrecognized_lineage ON iam.totp_authenticators(id)
    WHERE enrollment_session_id IS NULL AND recovery_id IS NULL;
ALTER TABLE iam.totp_authenticators DROP CONSTRAINT IF EXISTS totp_enrollment_lineage;
DO $lineage$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid='iam.totp_authenticators'::regclass AND conname='totp_enrollment_lineage') THEN
        ALTER TABLE iam.totp_authenticators ADD CONSTRAINT totp_enrollment_lineage CHECK(
            (enrollment_session_id IS NULL AND recovery_id IS NULL AND enrollment_request_id IS NULL AND enrollment_digest IS NULL
                AND enrollment_revision IS NULL AND credential_generation IS NULL AND expires_at IS NULL
                AND enrollment_outcome IS NULL AND completed_at IS NULL AND bound_revision IS NULL
                AND bound_event_id IS NULL AND revoked_at IS NULL)
            OR (((enrollment_session_id IS NOT NULL AND recovery_id IS NULL)
                    OR (enrollment_session_id IS NULL AND recovery_id IS NOT NULL)) AND enrollment_request_id IS NOT NULL
                AND enrollment_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
                AND enrollment_digest IS NOT NULL AND enrollment_digest ~ '^sha256:[0-9a-f]{64}$'
                AND enrollment_revision IS NOT NULL AND enrollment_revision BETWEEN 1 AND 9007199254740990
                AND credential_generation IS NOT NULL AND credential_generation>0
                AND expires_at IS NOT NULL AND expires_at>created_at AND expires_at<=created_at+interval '5 minutes'
                AND (recovery_id IS NOT NULL OR expires_at=created_at+interval '5 minutes')
                AND enrollment_outcome IS NOT NULL
                AND ((state='PENDING' AND enrollment_outcome='PENDING' AND completed_at IS NULL
                    AND bound_revision IS NULL AND bound_event_id IS NULL AND revoked_at IS NULL AND last_consumed_step=-1)
                OR (state='ACTIVE' AND enrollment_outcome='CONFIRMED' AND completed_at IS NOT NULL
                    AND bound_revision IS NOT NULL AND bound_revision=enrollment_revision+1 AND bound_event_id IS NOT NULL
                    AND revoked_at IS NULL AND last_consumed_step BETWEEN 0 AND 8446743359)
                OR (state='REVOKED' AND revoked_at IS NOT NULL AND completed_at IS NOT NULL
                    AND ((enrollment_outcome IN ('CANCELLED','EXPIRED') AND bound_revision IS NULL
                        AND bound_event_id IS NULL AND last_consumed_step=-1)
                    OR (enrollment_outcome='CONFIRMED' AND bound_revision IS NOT NULL AND bound_revision=enrollment_revision+1
                        AND bound_event_id IS NOT NULL AND last_consumed_step BETWEEN 0 AND 8446743359)))))
        );
    END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid='iam.totp_authenticators'::regclass AND conname='totp_enrollment_session') THEN
        ALTER TABLE iam.totp_authenticators ADD CONSTRAINT totp_enrollment_session
            FOREIGN KEY(tenant_id,enrollment_session_id) REFERENCES iam.sessions(tenant_id,id);
        ALTER TABLE iam.totp_authenticators ADD CONSTRAINT totp_bound_fact
            FOREIGN KEY(tenant_id,bound_event_id) REFERENCES iam.audit_outbox(tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED;
    END IF;
END $lineage$;

-- Only the actual pre-MFA table-absent source may initialize retained users.
-- The existing account_roots index enumerates all verified Account roots
-- without weakening tenant RLS. Equal replay cannot repair missing authority
-- by inventing NEVER_BOUND or erase a previously recorded recovery condition.
DO $retained_mfa_storage$
DECLARE tenant text; prior_tenant text:=current_setting('matrix.iam_tenant_id',true);
BEGIN
    IF to_regclass('iam.user_mfa_states') IS NOT NULL THEN RETURN; END IF;
    CREATE TABLE iam.user_mfa_states (
    tenant_id text COLLATE "C" NOT NULL,
    user_id text COLLATE "C" NOT NULL,
    revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
    enrollment_state text NOT NULL CHECK(enrollment_state IN ('NEVER_BOUND','BOUND','RECOVERY_REQUIRED')),
    factor_id text COLLATE "C",
    PRIMARY KEY(tenant_id,user_id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(tenant_id,user_id,factor_id) REFERENCES iam.totp_authenticators(tenant_id,user_id,id),
    CONSTRAINT user_mfa_states_shape CHECK((enrollment_state='BOUND' AND factor_id IS NOT NULL AND revision>1)
        OR (enrollment_state IN ('NEVER_BOUND','RECOVERY_REQUIRED') AND factor_id IS NULL)),
    CONSTRAINT user_mfa_states_never_bound CHECK(enrollment_state<>'NEVER_BOUND' OR revision=1)
    );
    FOR tenant IN SELECT r.account_id FROM iam.account_roots r ORDER BY r.account_id COLLATE "C" LOOP
        PERFORM set_config('matrix.iam_tenant_id',tenant,true);
        INSERT INTO iam.user_mfa_states(tenant_id,user_id,revision,enrollment_state)
            SELECT p.tenant_id,p.id,1,CASE WHEN EXISTS(SELECT 1 FROM iam.totp_authenticators f
                    WHERE f.tenant_id=p.tenant_id AND f.user_id=p.id) THEN 'RECOVERY_REQUIRED' ELSE 'NEVER_BOUND' END
            FROM iam.principals p WHERE p.tenant_id=tenant AND p.principal_type='USER';
    END LOOP;
    PERFORM set_config('matrix.iam_tenant_id',COALESCE(prior_tenant,''),true);
END $retained_mfa_storage$;
ALTER TABLE iam.user_mfa_states ADD COLUMN IF NOT EXISTS recovery_id text COLLATE "C";
ALTER TABLE iam.user_mfa_states DROP CONSTRAINT IF EXISTS user_mfa_recovery_shape;
ALTER TABLE iam.user_mfa_states ADD CONSTRAINT user_mfa_recovery_shape CHECK(
    recovery_id IS NULL OR (enrollment_state='RECOVERY_REQUIRED' AND revision>1));

-- Only an actual newly inserted USER gains the initial state. A missing row
-- during authentication is never interpreted as permission to enroll.
CREATE OR REPLACE FUNCTION iam.initialize_user_mfa_state()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF NEW.principal_type='USER' THEN
        INSERT INTO iam.user_mfa_states(tenant_id,user_id,revision,enrollment_state)
            VALUES(NEW.tenant_id,NEW.id,1,'NEVER_BOUND');
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS initialize_mfa ON iam.principals;
CREATE TRIGGER initialize_mfa AFTER INSERT ON iam.principals FOR EACH ROW EXECUTE FUNCTION iam.initialize_user_mfa_state();
ALTER TABLE iam.principals ENABLE ALWAYS TRIGGER initialize_mfa;

CREATE TABLE IF NOT EXISTS iam.authentication_challenges (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL CHECK(id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    user_id text COLLATE "C" NOT NULL,
    lookup_digest text NOT NULL UNIQUE CHECK(lookup_digest ~ '^sha256:[0-9a-f]{64}$'),
    verification_digest text NOT NULL CHECK(verification_digest ~ '^sha256:[0-9a-f]{64}$'),
    credential_generation bigint NOT NULL CHECK(credential_generation>0),
    password_attempt_id text COLLATE "C" NOT NULL,
    password_attempt_sequence bigint NOT NULL CHECK(password_attempt_sequence>0),
    account_version bigint NOT NULL CHECK(account_version>0),
    principal_version bigint NOT NULL CHECK(principal_version>0),
    mfa_revision bigint NOT NULL CHECK(mfa_revision>0),
    factor_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_digest text NOT NULL CHECK(request_digest ~ '^sha256:[0-9a-f]{64}$'),
    next_step text NOT NULL DEFAULT 'TOTP' CHECK(next_step IN ('TOTP','PASSWORD_CHANGE')),
    source_challenge_id text COLLATE "C",
    password_challenge_id text COLLATE "C",
    verified_step bigint CHECK(verified_step BETWEEN 0 AND 8446743359),
    password_changed_event_id text COLLATE "C",
    password_change_request_id text COLLATE "C",
    state text NOT NULL CHECK(state IN ('PENDING','CONSUMED','CANCELLED','EXPIRED')),
    created_at timestamptz(6) NOT NULL,
    expires_at timestamptz(6) NOT NULL,
    attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
    completed_at timestamptz(6),
    session_id text COLLATE "C",
    issuance_event_id text COLLATE "C",
    PRIMARY KEY(tenant_id,id),
    UNIQUE(tenant_id,session_id),
    UNIQUE(tenant_id,source_challenge_id),
    UNIQUE(tenant_id,password_challenge_id),
    UNIQUE(tenant_id,password_changed_event_id),
    FOREIGN KEY(tenant_id,user_id,factor_id) REFERENCES iam.totp_authenticators(tenant_id,user_id,id),
    FOREIGN KEY(tenant_id,session_id) REFERENCES iam.sessions(tenant_id,id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,issuance_event_id) REFERENCES iam.audit_outbox(tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,source_challenge_id) REFERENCES iam.authentication_challenges(tenant_id,id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,password_challenge_id) REFERENCES iam.authentication_challenges(tenant_id,id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,password_changed_event_id) REFERENCES iam.audit_outbox(tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT authentication_challenges_secrets CHECK(lookup_digest<>verification_digest),
    CONSTRAINT authentication_challenges_lifetime CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
    CONSTRAINT authentication_challenges_phase CHECK((next_step='TOTP' AND source_challenge_id IS NULL AND expires_at=created_at+interval '5 minutes'
            AND ((state='CONSUMED' AND verified_step IS NOT NULL) OR (state<>'CONSUMED' AND verified_step IS NULL)))
        OR (next_step='PASSWORD_CHANGE' AND source_challenge_id IS NOT NULL AND source_challenge_id<>id AND verified_step IS NOT NULL AND attempts=0)),
    CONSTRAINT authentication_challenges_completion CHECK((state='PENDING' AND completed_at IS NULL AND session_id IS NULL AND issuance_event_id IS NULL
            AND password_challenge_id IS NULL AND password_changed_event_id IS NULL AND password_change_request_id IS NULL)
        OR (state='CONSUMED' AND completed_at IS NOT NULL AND completed_at>=created_at AND completed_at<expires_at AND (
            (next_step='TOTP' AND password_changed_event_id IS NULL AND password_change_request_id IS NULL AND (
                (session_id IS NOT NULL AND issuance_event_id IS NOT NULL AND password_challenge_id IS NULL)
                OR (session_id IS NULL AND issuance_event_id IS NULL AND password_challenge_id IS NOT NULL AND password_challenge_id<>id)))
            OR (next_step='PASSWORD_CHANGE' AND session_id IS NULL AND issuance_event_id IS NULL AND password_challenge_id IS NULL
                AND password_changed_event_id IS NOT NULL AND password_change_request_id IS NOT NULL
                AND password_change_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')))
        OR (state IN ('CANCELLED','EXPIRED') AND completed_at IS NOT NULL AND session_id IS NULL AND issuance_event_id IS NULL
            AND password_challenge_id IS NULL AND password_changed_event_id IS NULL AND password_change_request_id IS NULL))
);
CREATE INDEX IF NOT EXISTS authentication_challenges_user ON iam.authentication_challenges(tenant_id,user_id,expires_at) WHERE state='PENDING';
ALTER TABLE iam.authentication_challenges ADD COLUMN IF NOT EXISTS recovery_id text COLLATE "C";
ALTER TABLE iam.authentication_challenges DROP CONSTRAINT IF EXISTS authentication_challenges_next_step_check;
ALTER TABLE iam.authentication_challenges ADD CONSTRAINT authentication_challenges_next_step_check
    CHECK(next_step IN ('TOTP','PASSWORD_CHANGE','RECOVER','ENROLLMENT'));
ALTER TABLE iam.authentication_challenges DROP CONSTRAINT IF EXISTS authentication_challenges_phase;
ALTER TABLE iam.authentication_challenges ADD CONSTRAINT authentication_challenges_phase CHECK(
    (next_step IN ('TOTP','RECOVER') AND source_challenge_id IS NULL AND expires_at=created_at+interval '5 minutes'
        AND ((state='CONSUMED' AND ((recovery_id IS NOT NULL AND verified_step IS NULL)
            OR (next_step='TOTP' AND recovery_id IS NULL AND verified_step IS NOT NULL)))
            OR (state<>'CONSUMED' AND verified_step IS NULL AND recovery_id IS NULL)))
    OR (next_step='PASSWORD_CHANGE' AND source_challenge_id IS NOT NULL AND source_challenge_id<>id
        AND verified_step IS NOT NULL AND attempts=0 AND recovery_id IS NULL)
    OR (next_step='ENROLLMENT' AND source_challenge_id IS NOT NULL AND source_challenge_id<>id AND recovery_id IS NOT NULL
        AND ((state='CONSUMED' AND verified_step IS NOT NULL) OR (state<>'CONSUMED' AND verified_step IS NULL))));
ALTER TABLE iam.authentication_challenges DROP CONSTRAINT IF EXISTS authentication_challenges_completion;
ALTER TABLE iam.authentication_challenges ADD CONSTRAINT authentication_challenges_completion CHECK(
    (state='PENDING' AND completed_at IS NULL AND session_id IS NULL AND issuance_event_id IS NULL
        AND password_challenge_id IS NULL AND password_changed_event_id IS NULL AND password_change_request_id IS NULL)
    OR (state='CONSUMED' AND completed_at IS NOT NULL AND completed_at>=created_at AND completed_at<expires_at AND (
        (next_step='TOTP' AND recovery_id IS NULL AND password_changed_event_id IS NULL AND password_change_request_id IS NULL AND (
            (session_id IS NOT NULL AND issuance_event_id IS NOT NULL AND password_challenge_id IS NULL)
            OR (session_id IS NULL AND issuance_event_id IS NULL AND password_challenge_id IS NOT NULL AND password_challenge_id<>id)))
        OR (next_step='PASSWORD_CHANGE' AND session_id IS NULL AND issuance_event_id IS NULL AND password_challenge_id IS NULL
            AND password_changed_event_id IS NOT NULL AND password_change_request_id IS NOT NULL
            AND password_change_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
        OR (next_step IN ('TOTP','RECOVER','ENROLLMENT') AND recovery_id IS NOT NULL AND session_id IS NULL AND issuance_event_id IS NULL
            AND password_challenge_id IS NULL AND password_changed_event_id IS NULL AND password_change_request_id IS NULL)))
    OR (state IN ('CANCELLED','EXPIRED') AND completed_at IS NOT NULL AND session_id IS NULL AND issuance_event_id IS NULL
        AND password_challenge_id IS NULL AND password_changed_event_id IS NULL AND password_change_request_id IS NULL));

-- One persistent budget per USER, shared by every factor/challenge/replica.
-- The reservation commits before code verification; failure/abandonment does
-- not refund it. Successful completion must be in the final effect transaction.
CREATE TABLE IF NOT EXISTS iam.totp_attempts (
    tenant_id text COLLATE "C" NOT NULL,
    user_id text COLLATE "C" NOT NULL,
    attempt_id text COLLATE "C" NOT NULL,
    sequence bigint NOT NULL CHECK(sequence>0),
    purpose text NOT NULL CHECK(purpose IN ('ENROLLMENT','LOGIN')),
    reference_id text COLLATE "C" NOT NULL,
    source_session_id text COLLATE "C",
    credential_generation bigint NOT NULL CHECK(credential_generation>0),
    mfa_revision bigint NOT NULL CHECK(mfa_revision>0),
    state text NOT NULL CHECK(state IN ('RESERVED','SUCCEEDED','REJECTED','ABANDONED')),
    window_started_at timestamptz(6) NOT NULL,
    used_attempts integer NOT NULL CHECK(used_attempts BETWEEN 1 AND 5),
    reserved_at timestamptz(6) NOT NULL,
    expires_at timestamptz(6) NOT NULL,
    completed_at timestamptz(6),
    PRIMARY KEY(tenant_id,user_id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(tenant_id,source_session_id) REFERENCES iam.sessions(tenant_id,id),
    CONSTRAINT totp_attempts_source CHECK((purpose='ENROLLMENT' AND source_session_id IS NOT NULL) OR (purpose='LOGIN' AND source_session_id IS NULL)),
    CONSTRAINT totp_attempts_lease CHECK(expires_at=reserved_at+interval '30 seconds'),
    CONSTRAINT totp_attempts_completion CHECK((state='RESERVED' AND completed_at IS NULL) OR (state<>'RESERVED' AND completed_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS iam.mfa_recovery_batches (
    tenant_id text COLLATE "C" NOT NULL,
    user_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    factor_id text COLLATE "C" NOT NULL,
    mfa_revision bigint NOT NULL CHECK(mfa_revision>1),
    event_id text COLLATE "C" NOT NULL,
    created_at timestamptz(6) NOT NULL,
    revoked_at timestamptz(6),
    PRIMARY KEY(tenant_id,id),
    UNIQUE(tenant_id,event_id),
    FOREIGN KEY(tenant_id,user_id,factor_id) REFERENCES iam.totp_authenticators(tenant_id,user_id,id),
    FOREIGN KEY(tenant_id,event_id) REFERENCES iam.audit_outbox(tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED
);
CREATE UNIQUE INDEX IF NOT EXISTS mfa_one_recovery_batch ON iam.mfa_recovery_batches(tenant_id,user_id) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS iam.mfa_recovery_codes (
    tenant_id text COLLATE "C" NOT NULL,
    batch_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    verification_digest text NOT NULL CHECK(verification_digest ~ '^sha256:[0-9a-f]{64}$'),
    consumed_at timestamptz(6),
    PRIMARY KEY(tenant_id,batch_id,id),
    FOREIGN KEY(tenant_id,batch_id) REFERENCES iam.mfa_recovery_batches(tenant_id,id)
);
ALTER TABLE iam.mfa_recovery_batches ADD COLUMN IF NOT EXISTS revocation_recovery_id text COLLATE "C";
ALTER TABLE iam.mfa_recovery_codes ADD COLUMN IF NOT EXISTS recovery_id text COLLATE "C";
ALTER TABLE iam.mfa_recovery_codes DROP CONSTRAINT IF EXISTS recovery_consumption_shape;
ALTER TABLE iam.mfa_recovery_codes ADD CONSTRAINT recovery_consumption_shape CHECK((consumed_at IS NULL)=(recovery_id IS NULL));
ALTER TABLE iam.mfa_recovery_batches DROP CONSTRAINT IF EXISTS recovery_revocation_shape;
ALTER TABLE iam.mfa_recovery_batches ADD CONSTRAINT recovery_revocation_shape CHECK((revoked_at IS NULL)=(revocation_recovery_id IS NULL));
ALTER TABLE iam.totp_attempts DROP CONSTRAINT IF EXISTS totp_attempts_purpose_check;
ALTER TABLE iam.totp_attempts ADD CONSTRAINT totp_attempts_purpose_check
    CHECK(purpose IN ('ENROLLMENT','LOGIN','RECOVERY_CODE','RECOVERY_CONFIRM'));
ALTER TABLE iam.totp_attempts DROP CONSTRAINT IF EXISTS totp_attempts_source;
ALTER TABLE iam.totp_attempts ADD CONSTRAINT totp_attempts_source CHECK(
    (purpose='ENROLLMENT' AND source_session_id IS NOT NULL)
    OR (purpose IN ('LOGIN','RECOVERY_CODE','RECOVERY_CONFIRM') AND source_session_id IS NULL));

-- Two irreversible effects, not a Session or a generic receipt. This lineage
-- proves how recovery-required arose; an unknown retained factor does not.
CREATE TABLE IF NOT EXISTS iam.authenticator_recoveries (
    tenant_id text COLLATE "C" NOT NULL,
    user_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL CHECK(id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_id text COLLATE "C" NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_digest text NOT NULL CHECK(request_digest ~ '^sha256:[0-9a-f]{64}$'),
    old_batch_id text COLLATE "C" NOT NULL,
    code_id text COLLATE "C" NOT NULL,
    factor_id text COLLATE "C" NOT NULL,
    source_challenge_id text COLLATE "C" NOT NULL,
    challenge_id text COLLATE "C" NOT NULL,
    credential_generation bigint NOT NULL CHECK(credential_generation>0),
    previous_revision bigint NOT NULL CHECK(previous_revision>1),
    revision bigint NOT NULL CONSTRAINT authenticator_recoveries_revision_check CHECK(revision=previous_revision+1 AND revision<9007199254740991),
    started_event_id text COLLATE "C" NOT NULL,
    state text NOT NULL CHECK(state IN ('STARTED','COMPLETED','SUPERSEDED')),
    created_at timestamptz(6) NOT NULL,
    expires_at timestamptz(6) NOT NULL CONSTRAINT authenticator_recoveries_expires_at_check CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
    completed_at timestamptz(6),
    completed_event_id text COLLATE "C",
    completion_request_id text COLLATE "C",
    completion_digest text,
    new_batch_id text COLLATE "C",
    superseded_by text COLLATE "C",
    PRIMARY KEY(tenant_id,id),
    UNIQUE(tenant_id,user_id,id),
    UNIQUE(tenant_id,user_id,revision),
    UNIQUE(tenant_id,user_id,request_id),
    UNIQUE(tenant_id,old_batch_id,code_id),
    UNIQUE(tenant_id,factor_id),
    UNIQUE(tenant_id,source_challenge_id),
    UNIQUE(tenant_id,challenge_id),
    UNIQUE(tenant_id,started_event_id),
    UNIQUE(tenant_id,completed_event_id),
    UNIQUE(tenant_id,new_batch_id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(tenant_id,old_batch_id,code_id) REFERENCES iam.mfa_recovery_codes(tenant_id,batch_id,id),
    FOREIGN KEY(tenant_id,user_id,factor_id) REFERENCES iam.totp_authenticators(tenant_id,user_id,id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,source_challenge_id) REFERENCES iam.authentication_challenges(tenant_id,id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,challenge_id) REFERENCES iam.authentication_challenges(tenant_id,id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,started_event_id) REFERENCES iam.audit_outbox(tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,completed_event_id) REFERENCES iam.audit_outbox(tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,new_batch_id) REFERENCES iam.mfa_recovery_batches(tenant_id,id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,user_id,superseded_by) REFERENCES iam.authenticator_recoveries(tenant_id,user_id,id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT authenticator_recovery_completion CHECK(
        (state='STARTED' AND completed_at IS NULL AND completed_event_id IS NULL AND completion_request_id IS NULL
            AND completion_digest IS NULL AND new_batch_id IS NULL AND superseded_by IS NULL)
        OR (state='COMPLETED' AND completed_at IS NOT NULL AND completed_at>=created_at AND completed_at<expires_at
            AND completed_event_id IS NOT NULL AND completion_request_id IS NOT NULL AND completion_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND completion_digest IS NOT NULL AND completion_digest ~ '^sha256:[0-9a-f]{64}$' AND new_batch_id IS NOT NULL AND superseded_by IS NULL)
        OR (state='SUPERSEDED' AND completed_at IS NOT NULL AND completed_at>=created_at AND superseded_by IS NOT NULL AND superseded_by<>id
            AND completed_event_id IS NULL AND completion_request_id IS NULL AND completion_digest IS NULL AND new_batch_id IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS authenticator_one_recovery ON iam.authenticator_recoveries(tenant_id,user_id) WHERE state='STARTED';
DO $recovery_lineage$
DECLARE relation_name text; column_name text;
BEGIN
    FOR relation_name,column_name IN SELECT * FROM (VALUES
        ('totp_authenticators','recovery_id'),('user_mfa_states','recovery_id'),('authentication_challenges','recovery_id'),
        ('mfa_recovery_batches','revocation_recovery_id'),('mfa_recovery_codes','recovery_id')) r(t,c) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('iam.'||relation_name) AND conname='recovery_lineage') THEN
            EXECUTE format('ALTER TABLE iam.%I ADD CONSTRAINT recovery_lineage FOREIGN KEY(tenant_id,%I) REFERENCES iam.authenticator_recoveries(tenant_id,id) DEFERRABLE INITIALLY DEFERRED',relation_name,column_name);
        END IF;
    END LOOP;
END $recovery_lineage$;

ALTER TABLE iam.sessions ADD COLUMN IF NOT EXISTS authentication_method text;
ALTER TABLE iam.sessions ADD COLUMN IF NOT EXISTS authenticated_at timestamptz(6);
ALTER TABLE iam.sessions ADD COLUMN IF NOT EXISTS mfa_revision bigint;
-- Legacy NULLs remain unknown, never relabelled as an actual MFA ceremony.
DO $session_authentication$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid='iam.sessions'::regclass AND conname='session_authentication_fact') THEN
        ALTER TABLE iam.sessions ADD CONSTRAINT session_authentication_fact CHECK(
            (authentication_method IS NULL AND authenticated_at IS NULL AND mfa_revision IS NULL)
            OR (authentication_method IS NOT NULL AND authentication_method IN ('PASSWORD','PASSWORD_TOTP')
                AND authenticated_at IS NOT NULL AND mfa_revision IS NOT NULL AND mfa_revision>0));
    END IF;
END $session_authentication$;

DO $mfa_isolation$
DECLARE relation_name text; operation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['user_mfa_states','authentication_challenges','totp_attempts','mfa_recovery_batches','mfa_recovery_codes','authenticator_recoveries'] LOOP
        EXECUTE format('ALTER TABLE iam.%I ENABLE ROW LEVEL SECURITY',relation_name);
        EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',relation_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON iam.%I',relation_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON iam.%I USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id())',relation_name);
        EXECUTE format('REVOKE ALL ON iam.%I FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker',relation_name);
        FOREACH operation_name IN ARRAY ARRAY['delete','truncate'] LOOP
            EXECUTE format('DROP TRIGGER IF EXISTS cannot_%s ON iam.%I',operation_name,relation_name);
            EXECUTE format('CREATE TRIGGER cannot_%s BEFORE %s ON iam.%I FOR EACH %s EXECUTE FUNCTION iam.reject_policy_history_change()',
                operation_name,upper(operation_name),relation_name,CASE WHEN operation_name='truncate' THEN 'STATEMENT' ELSE 'ROW' END);
            EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER cannot_%s',relation_name,operation_name);
        END LOOP;
    END LOOP;
END $mfa_isolation$;

-- Issued identity/verifiers never change. Only a matching irreversible
-- recovery completion can consume a code or terminate its original batch.
CREATE OR REPLACE FUNCTION iam.guard_recovery_material()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF TG_TABLE_NAME='mfa_recovery_codes' THEN
        IF OLD.consumed_at IS NULL AND OLD.recovery_id IS NULL AND NEW.consumed_at=transaction_timestamp() AND NEW.recovery_id IS NOT NULL
            AND (to_jsonb(NEW)-ARRAY['consumed_at','recovery_id'])=(to_jsonb(OLD)-ARRAY['consumed_at','recovery_id']) THEN RETURN NEW; END IF;
    ELSIF TG_TABLE_NAME='mfa_recovery_batches' THEN
        IF OLD.revoked_at IS NULL AND OLD.revocation_recovery_id IS NULL AND NEW.revoked_at=transaction_timestamp() AND NEW.revocation_recovery_id IS NOT NULL
            AND (to_jsonb(NEW)-ARRAY['revoked_at','revocation_recovery_id'])=(to_jsonb(OLD)-ARRAY['revoked_at','revocation_recovery_id']) THEN RETURN NEW; END IF;
    END IF;
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery material is immutable';
END $function$;
DO $recovery_material$
DECLARE relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['mfa_recovery_batches','mfa_recovery_codes'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS cannot_update ON iam.%I',relation_name);
        EXECUTE format('CREATE TRIGGER cannot_update BEFORE UPDATE ON iam.%I FOR EACH ROW EXECUTE FUNCTION iam.guard_recovery_material()',relation_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER cannot_update',relation_name);
    END LOOP;
END $recovery_material$;

CREATE OR REPLACE FUNCTION iam.lock_mfa_user(tenant text,subject_id text)
RETURNS iam.user_mfa_states LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result iam.user_mfa_states%ROWTYPE;
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts a WHERE a.id=tenant AND a.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication context is unavailable'; END IF;
    PERFORM 1 FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=subject_id
        AND p.principal_type='USER' AND p.status='ACTIVE' AND p.deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication context is unavailable'; END IF;
    PERFORM 1 FROM iam.user_credentials c WHERE c.tenant_id=tenant AND c.principal_id=subject_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication context is unavailable'; END IF;
    SELECT * INTO result FROM iam.user_mfa_states m WHERE m.tenant_id=tenant AND m.user_id=subject_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication state is unavailable'; END IF;
    IF result.enrollment_state='NEVER_BOUND' AND EXISTS(SELECT 1 FROM iam.totp_authenticators f
        WHERE f.tenant_id=tenant AND f.user_id=subject_id AND (f.state='ACTIVE' OR f.enrollment_outcome='CONFIRMED'
            OR (f.enrollment_session_id IS NULL AND f.recovery_id IS NULL))) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication history is unavailable';
    END IF;
    IF result.enrollment_state='BOUND' AND NOT EXISTS(SELECT 1 FROM iam.totp_authenticators f
        WHERE f.tenant_id=tenant AND f.user_id=subject_id AND f.id=result.factor_id AND f.state='ACTIVE'
            AND f.bound_revision=result.revision AND f.enrollment_outcome='CONFIRMED' AND f.bound_event_id IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication factor is unavailable';
    END IF;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.login_authentication_state(tenant text,subject_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE value iam.user_mfa_states%ROWTYPE;
BEGIN
    value:=iam.lock_mfa_user(tenant,subject_id);
    RETURN jsonb_strip_nulls(jsonb_build_object('state',value.enrollment_state,'revision',value.revision,'factorId',value.factor_id));
END $function$;

-- Called inside existing Session/Role reads. A retained password-only Session
-- cannot gain MFA evidence from today's User settings, and a later weaker
-- state cannot revive a previous revision. Physical revocation also remains.
CREATE OR REPLACE FUNCTION iam.session_mfa_eligible(tenant text,subject_id text,session_id text)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT COALESCE((SELECT
        (m.enrollment_state='NEVER_BOUND' AND m.revision=1
            AND NOT EXISTS(SELECT 1 FROM iam.totp_authenticators f WHERE f.tenant_id=m.tenant_id AND f.user_id=m.user_id
                AND (f.state='ACTIVE' OR f.enrollment_outcome='CONFIRMED' OR (f.enrollment_session_id IS NULL AND f.recovery_id IS NULL)))
            AND ((s.authentication_method IS NULL AND s.mfa_revision IS NULL)
                OR (s.authentication_method='PASSWORD' AND s.mfa_revision=m.revision)))
        OR (m.enrollment_state='BOUND' AND s.authentication_method='PASSWORD_TOTP' AND s.mfa_revision=m.revision
            AND EXISTS(SELECT 1 FROM iam.totp_authenticators f WHERE f.tenant_id=m.tenant_id AND f.user_id=m.user_id
                AND f.id=m.factor_id AND f.state='ACTIVE' AND f.bound_revision=m.revision))
        FROM iam.user_mfa_states m JOIN iam.sessions s ON s.tenant_id=m.tenant_id AND s.principal_id=m.user_id
        WHERE m.tenant_id=tenant AND m.user_id=subject_id AND s.id=session_id),false)
$function$;

REVOKE ALL ON FUNCTION iam.initialize_user_mfa_state(),iam.lock_mfa_user(text,text),iam.login_authentication_state(text,text),iam.session_mfa_eligible(text,text,text)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker;
GRANT EXECUTE ON FUNCTION iam.login_authentication_state(text,text) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.guard_totp_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF (OLD.enrollment_session_id IS NULL AND OLD.recovery_id IS NULL) OR OLD.state='REVOKED'
        OR (to_jsonb(NEW)-ARRAY['state','last_consumed_step','enrollment_outcome','completed_at','bound_revision','bound_event_id','revoked_at'])
            IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','last_consumed_step','enrollment_outcome','completed_at','bound_revision','bound_event_id','revoked_at']) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='factor history is immutable';
    END IF;
    IF OLD.state='PENDING' THEN
        IF NEW.state='ACTIVE' AND NEW.enrollment_outcome='CONFIRMED' AND NEW.completed_at=transaction_timestamp()
            AND NEW.bound_revision=OLD.enrollment_revision+1 AND NEW.bound_event_id IS NOT NULL
            AND NEW.revoked_at IS NULL AND NEW.last_consumed_step>=0 THEN RETURN NEW; END IF;
        IF NEW.state='REVOKED' AND NEW.enrollment_outcome IN ('CANCELLED','EXPIRED')
            AND NEW.completed_at=transaction_timestamp() AND NEW.revoked_at=transaction_timestamp()
            AND NEW.last_consumed_step=OLD.last_consumed_step AND NEW.bound_revision IS NULL AND NEW.bound_event_id IS NULL THEN RETURN NEW; END IF;
    ELSIF OLD.state='ACTIVE' THEN
        IF (NEW.enrollment_outcome,NEW.completed_at,NEW.bound_revision,NEW.bound_event_id)
            IS DISTINCT FROM (OLD.enrollment_outcome,OLD.completed_at,OLD.bound_revision,OLD.bound_event_id) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='factor completion is immutable';
        END IF;
        IF NEW.state='ACTIVE' AND NEW.last_consumed_step>OLD.last_consumed_step AND NEW.revoked_at IS NULL THEN RETURN NEW; END IF;
        IF NEW.state='REVOKED' AND NEW.last_consumed_step=OLD.last_consumed_step AND NEW.revoked_at=transaction_timestamp() THEN RETURN NEW; END IF;
    END IF;
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='factor transition is invalid';
END $function$;
DROP TRIGGER IF EXISTS cannot_update ON iam.totp_authenticators;
CREATE TRIGGER cannot_update BEFORE UPDATE ON iam.totp_authenticators FOR EACH ROW EXECUTE FUNCTION iam.guard_totp_transition();
ALTER TABLE iam.totp_authenticators ENABLE ALWAYS TRIGGER cannot_update;

CREATE OR REPLACE FUNCTION iam.guard_user_mfa_transition()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.user_id<>OLD.user_id OR NEW.revision<>OLD.revision+1
        OR NEW.enrollment_state='NEVER_BOUND' THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='MFA qualification cannot be restored by rewriting history';
    END IF;
    IF NEW.enrollment_state='BOUND' AND NOT EXISTS(SELECT 1 FROM iam.totp_authenticators f
        WHERE f.tenant_id=NEW.tenant_id AND f.user_id=NEW.user_id AND f.id=NEW.factor_id
            AND f.state='ACTIVE' AND f.bound_revision=NEW.revision AND f.enrollment_outcome='CONFIRMED') THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='MFA factor completion is required';
    END IF;
    IF NEW.enrollment_state='RECOVERY_REQUIRED' AND NOT EXISTS(SELECT 1 FROM iam.authenticator_recoveries r
        WHERE r.tenant_id=NEW.tenant_id AND r.user_id=NEW.user_id AND r.id=NEW.recovery_id AND r.state='STARTED'
            AND r.previous_revision=OLD.revision AND r.revision=NEW.revision) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='MFA recovery origin is required';
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS guard_transition ON iam.user_mfa_states;
CREATE TRIGGER guard_transition BEFORE UPDATE ON iam.user_mfa_states FOR EACH ROW EXECUTE FUNCTION iam.guard_user_mfa_transition();
ALTER TABLE iam.user_mfa_states ENABLE ALWAYS TRIGGER guard_transition;

CREATE OR REPLACE FUNCTION iam.lock_mfa_session(tenant text,subject_id text,caller_id text)
RETURNS bigint LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE generation bigint; caller iam.sessions%ROWTYPE;
BEGIN
    PERFORM iam.lock_mfa_user(tenant,subject_id);
    SELECT c.credential_version INTO generation FROM iam.user_credentials c WHERE c.tenant_id=tenant AND c.principal_id=subject_id;
    IF EXISTS(SELECT 1 FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=subject_id AND p.must_change_password) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication context is unavailable';
    END IF;
    SELECT * INTO caller FROM iam.sessions s WHERE s.tenant_id=tenant AND s.principal_id=subject_id AND s.id=caller_id FOR UPDATE;
    IF NOT FOUND OR caller.status<>'ACTIVE' OR caller.revoked_at IS NOT NULL OR caller.expires_at<=clock_timestamp()
        OR caller.credential_version IS DISTINCT FROM generation OR NOT iam.session_mfa_eligible(tenant,subject_id,caller_id) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication context is unavailable';
    END IF;
    RETURN generation;
END $function$;

CREATE OR REPLACE FUNCTION iam.totp_enrollment_snapshot(tenant text,factor text)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','TOTPEnrollment',
        'id',f.id,'requestId',f.enrollment_request_id,'factorRevision',f.enrollment_revision,
        'state',CASE WHEN f.state='PENDING' AND f.expires_at<=clock_timestamp() THEN 'EXPIRED' ELSE f.enrollment_outcome END,
        'createdAt',f.created_at,'expiresAt',f.expires_at,'completedAt',
            CASE WHEN f.state='PENDING' AND f.expires_at<=clock_timestamp() THEN f.expires_at ELSE f.completed_at END))
        FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.id=factor AND f.enrollment_session_id IS NOT NULL
$function$;

CREATE OR REPLACE FUNCTION iam.start_totp_enrollment(tenant text,subject_id text,caller_id text,expected_revision bigint,
    request_id text,intent_digest text,attempt text,attempt_sequence bigint,factor_id text,
    installation text,bootstrap_digest text,key_id text,nonce bytea,ciphertext bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE original iam.totp_authenticators%ROWTYPE; state iam.user_mfa_states%ROWTYPE;
    generation bigint; registry jsonb; issued_at timestamptz(6):=transaction_timestamp();
BEGIN
    registry:=iam.read_totp_custody()->'keyset';
    IF registry->'scope' IS DISTINCT FROM jsonb_build_object('installationId',installation,'bootstrapDigest',bootstrap_digest)
        OR registry->>'activeKeyId' IS DISTINCT FROM key_id THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='TOTP material is unavailable';
    END IF;
    state:=iam.lock_mfa_user(tenant,subject_id);
    generation:=iam.lock_mfa_session(tenant,subject_id,caller_id);
    IF COALESCE(request_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR COALESCE(factor_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR COALESCE(intent_digest,'') !~ '^sha256:[0-9a-f]{64}$'
        OR expected_revision IS NULL OR expected_revision NOT BETWEEN 1 AND 9007199254740990
        OR octet_length(nonce) IS DISTINCT FROM 12 OR octet_length(ciphertext) IS DISTINCT FROM 36 THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='TOTP enrollment input is invalid';
    END IF;
    PERFORM iam.consume_password_attempt(tenant,subject_id,caller_id,attempt,attempt_sequence,'TOTP_ENROLLMENT',intent_digest);
    SELECT * INTO original FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.user_id=subject_id
        AND f.enrollment_request_id=start_totp_enrollment.request_id;
    IF FOUND THEN
        IF original.enrollment_session_id<>caller_id OR original.credential_generation<>generation
            OR original.enrollment_revision<>expected_revision OR original.enrollment_digest<>intent_digest THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='TOTP enrollment intent conflicts';
        END IF;
        RETURN jsonb_build_object('outcome','EQUAL_REPLAY','enrollment',iam.totp_enrollment_snapshot(tenant,original.id));
    END IF;
    IF state.enrollment_state<>'NEVER_BOUND' OR state.revision<>expected_revision OR state.factor_id IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='TOTP enrollment state conflicts';
    END IF;
    PERFORM 1 FROM iam.notification_contacts c WHERE c.tenant_id=tenant AND c.user_id=subject_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='verified security contact is required'; END IF;
    IF EXISTS(SELECT 1 FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.user_id=subject_id
        AND f.state='PENDING' AND f.expires_at>clock_timestamp()) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='TOTP enrollment is already pending';
    END IF;
    UPDATE iam.totp_authenticators f SET state='REVOKED',enrollment_outcome='EXPIRED',completed_at=issued_at,revoked_at=issued_at
        WHERE f.tenant_id=tenant AND f.user_id=subject_id AND f.state='PENDING' AND f.expires_at<=clock_timestamp();
    IF issued_at+interval '5 minutes'<=clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='TOTP enrollment has expired';
    END IF;
    INSERT INTO iam.totp_authenticators(id,tenant_id,user_id,installation_id,key_id,format_version,nonce,ciphertext,state,
        last_consumed_step,created_at,enrollment_session_id,enrollment_request_id,enrollment_digest,enrollment_revision,
        credential_generation,expires_at,enrollment_outcome)
    VALUES(factor_id,tenant,subject_id,installation,key_id,1,nonce,ciphertext,'PENDING',-1,issued_at,caller_id,
        request_id,intent_digest,expected_revision,generation,issued_at+interval '5 minutes','PENDING');
    RETURN jsonb_build_object('outcome','APPLIED','enrollment',iam.totp_enrollment_snapshot(tenant,factor_id));
END $function$;

CREATE OR REPLACE FUNCTION iam.read_totp_enrollment(tenant text,subject_id text,caller_id text,factor text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM iam.lock_mfa_session(tenant,subject_id,caller_id);
    IF NOT EXISTS(SELECT 1 FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.user_id=subject_id
        AND f.id=factor AND f.enrollment_session_id IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='TOTP enrollment is unavailable';
    END IF;
    -- After a lost confirmation response a freshly authenticated same USER
    -- may inspect only this completion, never recover the original seed/codes.
    RETURN iam.totp_enrollment_snapshot(tenant,factor);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_authenticator_state(tenant text,subject_id text,caller_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE state iam.user_mfa_states%ROWTYPE;
BEGIN
    PERFORM iam.lock_mfa_session(tenant,subject_id,caller_id);
    SELECT * INTO STRICT state FROM iam.user_mfa_states m WHERE m.tenant_id=tenant AND m.user_id=subject_id;
    RETURN jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AuthenticatorState',
        'enrollmentState',state.enrollment_state,'factorRevision',state.revision,'factorId',state.factor_id));
END $function$;

CREATE OR REPLACE FUNCTION iam.read_totp_enrollment_by_request(tenant text,subject_id text,caller_id text,request_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE factor text;
BEGIN
    PERFORM iam.lock_mfa_session(tenant,subject_id,caller_id);
    SELECT f.id INTO factor FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.user_id=subject_id
        AND f.enrollment_request_id=request_id AND f.enrollment_session_id IS NOT NULL;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='TOTP enrollment was not found'; END IF;
    RETURN iam.totp_enrollment_snapshot(tenant,factor);
END $function$;

CREATE OR REPLACE FUNCTION iam.cancel_totp_enrollment(tenant text,subject_id text,caller_id text,factor text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE original iam.totp_authenticators%ROWTYPE;
BEGIN
    PERFORM iam.lock_mfa_session(tenant,subject_id,caller_id);
    SELECT * INTO original FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.user_id=subject_id AND f.id=factor FOR UPDATE;
    IF NOT FOUND OR original.enrollment_session_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='TOTP enrollment is unavailable';
    END IF;
    IF original.state='ACTIVE' OR original.enrollment_outcome='CONFIRMED' THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='confirmed factor cannot be cancelled';
    END IF;
    IF original.state='PENDING' THEN
        UPDATE iam.totp_authenticators f SET state='REVOKED',
            enrollment_outcome=CASE WHEN original.expires_at<=clock_timestamp() THEN 'EXPIRED' ELSE 'CANCELLED' END,
            completed_at=transaction_timestamp(),revoked_at=transaction_timestamp()
            WHERE f.tenant_id=tenant AND f.id=factor;
    END IF;
    RETURN iam.totp_enrollment_snapshot(tenant,factor);
END $function$;

REVOKE ALL ON FUNCTION iam.guard_totp_transition(),iam.guard_user_mfa_transition(),iam.lock_mfa_session(text,text,text),iam.totp_enrollment_snapshot(text,text),
    iam.start_totp_enrollment(text,text,text,bigint,text,text,text,bigint,text,text,text,text,bytea,bytea),
    iam.read_authenticator_state(text,text,text),iam.read_totp_enrollment_by_request(text,text,text,text),
    iam.read_totp_enrollment(text,text,text,text),iam.cancel_totp_enrollment(text,text,text,text)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker;
GRANT EXECUTE ON FUNCTION iam.start_totp_enrollment(text,text,text,bigint,text,text,text,bigint,text,text,text,text,bytea,bytea),
    iam.read_authenticator_state(text,text,text),iam.read_totp_enrollment_by_request(text,text,text,text),
    iam.read_totp_enrollment(text,text,text,text),iam.cancel_totp_enrollment(text,text,text,text) TO matrix_iam_api;

-- Lookup begins with a domain-separated secret digest, before its tenant is
-- known. Only this narrow definer query uses the read scope; no runtime role
-- can select the table even by setting the GUC itself.
DROP POLICY IF EXISTS tenant_isolation ON iam.authentication_challenges;
CREATE POLICY tenant_isolation ON iam.authentication_challenges
    USING(tenant_id=iam.current_tenant_id() OR current_setting('matrix.iam_challenge_lookup',true)='trusted')
    WITH CHECK(tenant_id=iam.current_tenant_id());

CREATE OR REPLACE FUNCTION iam.create_login_challenge(tenant text,subject_id text,attempt text,attempt_sequence bigint,
    challenge_id text,lookup_digest text,verification_digest text,request_id text,request_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE state iam.user_mfa_states%ROWTYPE; generation bigint; effective_now timestamptz(6);
    account_version bigint; principal_version bigint; original_factor text; next_step text:='TOTP'; batch iam.mfa_recovery_batches%ROWTYPE;
BEGIN
    IF COALESCE(challenge_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR COALESCE(request_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR COALESCE(lookup_digest,'') !~ '^sha256:[0-9a-f]{64}$' OR COALESCE(verification_digest,'') !~ '^sha256:[0-9a-f]{64}$'
        OR lookup_digest=verification_digest OR COALESCE(request_digest,'') !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authentication challenge is invalid';
    END IF;
    state:=iam.lock_mfa_user(tenant,subject_id);
    original_factor:=state.factor_id;
    IF state.enrollment_state='RECOVERY_REQUIRED' THEN
        batch:=iam.lock_recovery_batch(tenant,subject_id);
        original_factor:=batch.factor_id; next_step:='RECOVER';
    ELSIF state.enrollment_state<>'BOUND' THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication challenge is unavailable';
    END IF;
    generation:=iam.consume_password_attempt(tenant,subject_id,NULL,attempt,attempt_sequence,'LOGIN',NULL);
    SELECT a.resource_version INTO account_version FROM iam.accounts a WHERE a.id=tenant;
    SELECT p.resource_version INTO principal_version FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=subject_id;
    effective_now:=clock_timestamp();
    IF (SELECT count(*) FROM iam.authentication_challenges c WHERE c.tenant_id=tenant AND c.user_id=subject_id
        AND c.state='PENDING' AND c.expires_at>effective_now)>=3 THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication challenge is unavailable';
    END IF;
    INSERT INTO iam.authentication_challenges(tenant_id,id,user_id,lookup_digest,verification_digest,credential_generation,
        password_attempt_id,password_attempt_sequence,account_version,principal_version,mfa_revision,factor_id,request_id,request_digest,next_step,state,created_at,expires_at)
        VALUES(tenant,challenge_id,subject_id,lookup_digest,verification_digest,generation,attempt,attempt_sequence,account_version,principal_version,
            state.revision,original_factor,request_id,request_digest,next_step,'PENDING',effective_now,effective_now+interval '5 minutes');
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AuthenticationChallenge',
        'id',challenge_id,'purpose','LOGIN','nextStep',next_step,'expiresAt',effective_now+interval '5 minutes');
END $function$;

CREATE OR REPLACE FUNCTION iam.lookup_authentication_challenge(submitted_lookup text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb; prior_scope text;
BEGIN
    IF COALESCE(submitted_lookup,'') !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authentication lookup is invalid';
    END IF;
    prior_scope:=current_setting('matrix.iam_challenge_lookup',true);
    PERFORM set_config('matrix.iam_challenge_lookup','trusted',true);
    SELECT jsonb_build_object('accountId',c.tenant_id,'userId',c.user_id,'id',c.id,'nextStep',c.next_step,'verificationDigest',c.verification_digest)
        INTO result FROM iam.authentication_challenges c WHERE c.lookup_digest=submitted_lookup;
    PERFORM set_config('matrix.iam_challenge_lookup',COALESCE(prior_scope,''),true);
    RETURN result;
END $function$;

-- Password-only knowledge can never create this lineage. RECOVERY_REQUIRED
-- from unrecognized retained state is intentionally ineligible here.
CREATE OR REPLACE FUNCTION iam.lock_recovery_batch(tenant text,subject_id text)
RETURNS iam.mfa_recovery_batches LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE state iam.user_mfa_states%ROWTYPE; batch iam.mfa_recovery_batches%ROWTYPE; original iam.totp_authenticators%ROWTYPE;
BEGIN
    state:=iam.lock_mfa_user(tenant,subject_id);
    SELECT * INTO batch FROM iam.mfa_recovery_batches b WHERE b.tenant_id=tenant AND b.user_id=subject_id AND b.revoked_at IS NULL FOR UPDATE;
    IF NOT FOUND OR batch.revocation_recovery_id IS NOT NULL
        OR (SELECT count(*) FROM iam.mfa_recovery_codes c WHERE c.tenant_id=tenant AND c.batch_id=batch.id)<>10 THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='recovery context is unavailable';
    END IF;
    SELECT * INTO original FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.user_id=subject_id AND f.id=batch.factor_id FOR UPDATE;
    IF NOT FOUND OR original.enrollment_outcome IS DISTINCT FROM 'CONFIRMED' OR original.bound_revision IS DISTINCT FROM batch.mfa_revision
        OR original.bound_event_id IS DISTINCT FROM batch.event_id THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='recovery context is unavailable';
    END IF;
    IF state.enrollment_state='BOUND' AND state.factor_id=original.id AND state.revision=batch.mfa_revision AND original.state='ACTIVE' THEN RETURN batch; END IF;
    IF state.enrollment_state='RECOVERY_REQUIRED' AND original.state='REVOKED' AND EXISTS(SELECT 1 FROM iam.authenticator_recoveries r
        WHERE r.tenant_id=tenant AND r.user_id=subject_id AND r.id=state.recovery_id AND r.revision=state.revision
            AND r.state='STARTED' AND r.old_batch_id=batch.id) THEN RETURN batch; END IF;
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='recovery context is unavailable';
END $function$;

CREATE OR REPLACE FUNCTION iam.lock_recovery_login(tenant text,subject_id text,challenge_id text)
RETURNS iam.authentication_challenges LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE batch iam.mfa_recovery_batches%ROWTYPE; challenge iam.authentication_challenges%ROWTYPE; state iam.user_mfa_states%ROWTYPE;
BEGIN
    batch:=iam.lock_recovery_batch(tenant,subject_id);
    SELECT * INTO state FROM iam.user_mfa_states m WHERE m.tenant_id=tenant AND m.user_id=subject_id;
    SELECT * INTO challenge FROM iam.authentication_challenges c WHERE c.tenant_id=tenant AND c.user_id=subject_id AND c.id=challenge_id FOR UPDATE;
    IF NOT FOUND OR challenge.state<>'PENDING' OR challenge.source_challenge_id IS NOT NULL OR challenge.recovery_id IS NOT NULL
        OR challenge.mfa_revision<>state.revision OR challenge.factor_id<>batch.factor_id
        OR challenge.next_step IS DISTINCT FROM (CASE WHEN state.enrollment_state='BOUND' THEN 'TOTP' ELSE 'RECOVER' END)
        OR challenge.credential_generation IS DISTINCT FROM (SELECT c.credential_version FROM iam.user_credentials c WHERE c.tenant_id=tenant AND c.principal_id=subject_id)
        OR challenge.account_version IS DISTINCT FROM (SELECT a.resource_version FROM iam.accounts a WHERE a.id=tenant)
        OR challenge.principal_version IS DISTINCT FROM (SELECT p.resource_version FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=subject_id)
        OR challenge.expires_at<=clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='recovery challenge is unavailable';
    END IF;
    RETURN challenge;
END $function$;

CREATE OR REPLACE FUNCTION iam.lock_recovery_challenge(tenant text,subject_id text,challenge_id text)
RETURNS iam.totp_authenticators LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE batch iam.mfa_recovery_batches%ROWTYPE; state iam.user_mfa_states%ROWTYPE; recovery iam.authenticator_recoveries%ROWTYPE;
    factor iam.totp_authenticators%ROWTYPE; challenge iam.authentication_challenges%ROWTYPE;
BEGIN
    batch:=iam.lock_recovery_batch(tenant,subject_id);
    SELECT * INTO state FROM iam.user_mfa_states m WHERE m.tenant_id=tenant AND m.user_id=subject_id;
    SELECT * INTO recovery FROM iam.authenticator_recoveries r WHERE r.tenant_id=tenant AND r.user_id=subject_id AND r.id=state.recovery_id;
    IF NOT FOUND OR state.enrollment_state<>'RECOVERY_REQUIRED' OR recovery.state<>'STARTED' OR recovery.challenge_id<>challenge_id THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='recovery challenge is unavailable';
    END IF;
    SELECT * INTO factor FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.user_id=subject_id AND f.id=recovery.factor_id FOR UPDATE;
    IF NOT FOUND OR factor.state<>'PENDING' OR factor.recovery_id IS DISTINCT FROM recovery.id
        OR factor.enrollment_revision IS DISTINCT FROM state.revision OR factor.enrollment_session_id IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='recovery factor is unavailable';
    END IF;
    SELECT * INTO challenge FROM iam.authentication_challenges c WHERE c.tenant_id=tenant AND c.user_id=subject_id AND c.id=challenge_id FOR UPDATE;
    IF NOT FOUND OR challenge.state<>'PENDING' OR challenge.next_step<>'ENROLLMENT' OR challenge.recovery_id IS DISTINCT FROM recovery.id
        OR challenge.source_challenge_id IS DISTINCT FROM recovery.source_challenge_id OR challenge.factor_id<>factor.id
        OR challenge.mfa_revision<>state.revision OR challenge.expires_at<>recovery.expires_at OR factor.expires_at<>recovery.expires_at
        OR challenge.credential_generation<>recovery.credential_generation OR factor.credential_generation<>recovery.credential_generation
        OR challenge.credential_generation IS DISTINCT FROM (SELECT c.credential_version FROM iam.user_credentials c WHERE c.tenant_id=tenant AND c.principal_id=subject_id)
        OR challenge.account_version IS DISTINCT FROM (SELECT a.resource_version FROM iam.accounts a WHERE a.id=tenant)
        OR challenge.principal_version IS DISTINCT FROM (SELECT p.resource_version FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=subject_id)
        OR challenge.expires_at<=clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='recovery challenge is unavailable';
    END IF;
    RETURN factor;
END $function$;

CREATE OR REPLACE FUNCTION iam.lock_totp_verification(tenant text,subject_id text,caller_id text,reference_id text,purpose text)
RETURNS iam.totp_authenticators LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE state iam.user_mfa_states%ROWTYPE; factor iam.totp_authenticators%ROWTYPE;
    challenge iam.authentication_challenges%ROWTYPE; generation bigint;
BEGIN
    IF purpose IS NULL OR NOT ((purpose='ENROLLMENT' AND caller_id IS NOT NULL)
        OR (purpose IN ('LOGIN','RECOVERY_CODE','RECOVERY_CONFIRM') AND caller_id IS NULL)) THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='TOTP verification purpose is invalid';
    END IF;
    IF purpose='RECOVERY_CODE' THEN
        challenge:=iam.lock_recovery_login(tenant,subject_id,reference_id);
        SELECT * INTO factor FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.user_id=subject_id AND f.id=challenge.factor_id;
        RETURN factor;
    ELSIF purpose='RECOVERY_CONFIRM' THEN
        RETURN iam.lock_recovery_challenge(tenant,subject_id,reference_id);
    END IF;
    state:=iam.lock_mfa_user(tenant,subject_id);
    SELECT c.credential_version INTO generation FROM iam.user_credentials c WHERE c.tenant_id=tenant AND c.principal_id=subject_id;
    IF purpose='ENROLLMENT' THEN
        PERFORM iam.lock_mfa_session(tenant,subject_id,caller_id);
        SELECT * INTO factor FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.user_id=subject_id AND f.id=reference_id FOR UPDATE;
        IF NOT FOUND OR state.enrollment_state<>'NEVER_BOUND' OR factor.state<>'PENDING'
            OR factor.enrollment_session_id IS DISTINCT FROM caller_id OR factor.credential_generation IS DISTINCT FROM generation
            OR factor.enrollment_revision IS DISTINCT FROM state.revision OR factor.expires_at<=clock_timestamp() THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='TOTP verification is unavailable';
        END IF;
    ELSE
        SELECT * INTO factor FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.user_id=subject_id AND f.id=state.factor_id FOR UPDATE;
        IF NOT FOUND OR state.enrollment_state<>'BOUND' OR factor.state<>'ACTIVE' OR factor.bound_revision<>state.revision THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='TOTP verification is unavailable';
        END IF;
        SELECT * INTO challenge FROM iam.authentication_challenges c WHERE c.tenant_id=tenant AND c.user_id=subject_id AND c.id=reference_id FOR UPDATE;
        IF NOT FOUND OR challenge.state<>'PENDING' OR challenge.next_step<>'TOTP' OR challenge.factor_id<>factor.id OR challenge.mfa_revision<>state.revision
            OR challenge.credential_generation<>generation OR challenge.expires_at<=clock_timestamp()
            OR challenge.account_version IS DISTINCT FROM (SELECT a.resource_version FROM iam.accounts a WHERE a.id=tenant)
            OR challenge.principal_version IS DISTINCT FROM (SELECT p.resource_version FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=subject_id) THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='TOTP verification is unavailable';
        END IF;
    END IF;
    RETURN factor;
END $function$;

CREATE OR REPLACE FUNCTION iam.reserve_totp_attempt(tenant text,subject_id text,caller_id text,reference_id text,purpose text,attempt_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE factor iam.totp_authenticators%ROWTYPE; previous iam.totp_attempts%ROWTYPE;
    generation bigint; revision bigint; effective_now timestamptz(6); window_start timestamptz(6); used integer;
BEGIN
    IF COALESCE(attempt_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='TOTP attempt is invalid';
    END IF;
    factor:=iam.lock_totp_verification(tenant,subject_id,caller_id,reference_id,purpose);
    SELECT c.credential_version INTO generation FROM iam.user_credentials c WHERE c.tenant_id=tenant AND c.principal_id=subject_id;
    SELECT m.revision INTO revision FROM iam.user_mfa_states m WHERE m.tenant_id=tenant AND m.user_id=subject_id;
    SELECT * INTO previous FROM iam.totp_attempts a WHERE a.tenant_id=tenant AND a.user_id=subject_id FOR UPDATE;
    effective_now:=clock_timestamp();
    IF previous.state='RESERVED' AND previous.expires_at>effective_now THEN RETURN NULL; END IF;
    IF previous.attempt_id=reserve_totp_attempt.attempt_id THEN RETURN NULL; END IF;
    IF previous.window_started_at+interval '10 minutes'>effective_now THEN
        IF previous.used_attempts>=5 THEN RETURN NULL; END IF;
        window_start:=previous.window_started_at; used:=previous.used_attempts+1;
    ELSE
        window_start:=effective_now; used:=1;
    END IF;
    IF purpose IN ('LOGIN','RECOVERY_CODE','RECOVERY_CONFIRM') THEN
        IF (SELECT c.attempts FROM iam.authentication_challenges c WHERE c.tenant_id=tenant AND c.id=reference_id)>=5 THEN RETURN NULL; END IF;
        UPDATE iam.authentication_challenges c SET attempts=attempts+1 WHERE c.tenant_id=tenant AND c.id=reference_id;
    END IF;
    INSERT INTO iam.totp_attempts AS a(tenant_id,user_id,attempt_id,sequence,purpose,reference_id,source_session_id,
        credential_generation,mfa_revision,state,window_started_at,used_attempts,reserved_at,expires_at)
        VALUES(tenant,subject_id,attempt_id,COALESCE(previous.sequence,0)+1,purpose,reference_id,caller_id,
            generation,revision,'RESERVED',window_start,used,effective_now,effective_now+interval '30 seconds')
        ON CONFLICT(tenant_id,user_id) DO UPDATE SET attempt_id=EXCLUDED.attempt_id,sequence=EXCLUDED.sequence,purpose=EXCLUDED.purpose,
            reference_id=EXCLUDED.reference_id,source_session_id=EXCLUDED.source_session_id,credential_generation=EXCLUDED.credential_generation,
            mfa_revision=EXCLUDED.mfa_revision,state='RESERVED',window_started_at=EXCLUDED.window_started_at,used_attempts=EXCLUDED.used_attempts,
            reserved_at=EXCLUDED.reserved_at,expires_at=EXCLUDED.expires_at,completed_at=NULL;
    RETURN jsonb_build_object('id',attempt_id,'sequence',COALESCE(previous.sequence,0)+1);
END $function$;

CREATE OR REPLACE FUNCTION iam.lock_mfa_attempt(tenant text,subject_id text,caller_id text,reference_id text,purpose text,attempt_id text,attempt_sequence bigint)
RETURNS iam.totp_attempts LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE attempt iam.totp_attempts%ROWTYPE; effective_now timestamptz(6);
BEGIN
    SELECT * INTO attempt FROM iam.totp_attempts a WHERE a.tenant_id=tenant AND a.user_id=subject_id FOR UPDATE;
    effective_now:=clock_timestamp();
    IF NOT FOUND OR attempt.attempt_id IS DISTINCT FROM lock_mfa_attempt.attempt_id OR attempt.sequence IS DISTINCT FROM attempt_sequence
        OR attempt.purpose IS DISTINCT FROM purpose OR attempt.reference_id IS DISTINCT FROM reference_id OR attempt.source_session_id IS DISTINCT FROM caller_id
        OR attempt.state<>'RESERVED' OR attempt.expires_at<=effective_now
        OR attempt.credential_generation IS DISTINCT FROM (SELECT c.credential_version FROM iam.user_credentials c WHERE c.tenant_id=tenant AND c.principal_id=subject_id)
        OR attempt.mfa_revision IS DISTINCT FROM (SELECT m.revision FROM iam.user_mfa_states m WHERE m.tenant_id=tenant AND m.user_id=subject_id) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='TOTP attempt is unavailable';
    END IF;
    RETURN attempt;
END $function$;

CREATE OR REPLACE FUNCTION iam.read_totp_attempt(tenant text,subject_id text,caller_id text,reference_id text,purpose text,attempt_id text,attempt_sequence bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE factor iam.totp_authenticators%ROWTYPE; attempt iam.totp_attempts%ROWTYPE;
BEGIN
    IF purpose IS NULL OR purpose NOT IN ('ENROLLMENT','LOGIN','RECOVERY_CONFIRM') THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='TOTP attempt purpose is invalid';
    END IF;
    factor:=iam.lock_totp_verification(tenant,subject_id,caller_id,reference_id,purpose);
    attempt:=iam.lock_mfa_attempt(tenant,subject_id,caller_id,reference_id,purpose,attempt_id,attempt_sequence);
    RETURN jsonb_build_object('factorId',factor.id,'installationId',factor.installation_id,'keyId',factor.key_id,'formatVersion',factor.format_version,
        'nonce',encode(factor.nonce,'base64'),'ciphertext',encode(factor.ciphertext,'base64'),'lastConsumedStep',factor.last_consumed_step,
        'databaseTime',clock_timestamp(),'factorRevision',attempt.mfa_revision,
        'mustChangePassword',(SELECT p.must_change_password FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=subject_id));
END $function$;

CREATE OR REPLACE FUNCTION iam.reject_totp_attempt(tenant text,subject_id text,attempt_id text,attempt_sequence bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts a WHERE a.id=tenant FOR SHARE;
    PERFORM 1 FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=subject_id FOR UPDATE;
    UPDATE iam.totp_attempts a SET state=CASE WHEN a.expires_at>clock_timestamp() THEN 'REJECTED' ELSE 'ABANDONED' END,completed_at=clock_timestamp()
        WHERE a.tenant_id=tenant AND a.user_id=subject_id AND a.attempt_id=reject_totp_attempt.attempt_id
            AND a.sequence=attempt_sequence AND a.state='RESERVED';
END $function$;

CREATE OR REPLACE FUNCTION iam.read_recovery_attempt(tenant text,subject_id text,challenge_id text,attempt_id text,attempt_sequence bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE challenge iam.authentication_challenges%ROWTYPE; batch iam.mfa_recovery_batches%ROWTYPE;
BEGIN
    challenge:=iam.lock_recovery_login(tenant,subject_id,challenge_id);
    PERFORM iam.lock_mfa_attempt(tenant,subject_id,NULL,challenge_id,'RECOVERY_CODE',attempt_id,attempt_sequence);
    SELECT * INTO batch FROM iam.mfa_recovery_batches b WHERE b.tenant_id=tenant AND b.user_id=subject_id AND b.revoked_at IS NULL;
    RETURN jsonb_build_object('batchId',batch.id,
        'installationId',(SELECT f.installation_id FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.id=batch.factor_id),
        'codes',(SELECT jsonb_agg(jsonb_build_object('id',c.id,'verificationDigest',c.verification_digest,'consumed',c.consumed_at IS NOT NULL)
            ORDER BY c.id COLLATE "C") FROM iam.mfa_recovery_codes c WHERE c.tenant_id=tenant AND c.batch_id=batch.id));
END $function$;

CREATE OR REPLACE FUNCTION iam.authenticator_recovery_snapshot(tenant text,recovery_id text)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AuthenticatorRecovery',
        'id',r.id,'requestId',r.request_id,
        'state',CASE WHEN r.state='STARTED' AND r.expires_at<=statement_timestamp() THEN 'EXPIRED' ELSE r.state END,
        'createdAt',r.created_at,'expiresAt',r.expires_at,
        'completedAt',CASE WHEN r.state='STARTED' AND r.expires_at<=statement_timestamp() THEN r.expires_at ELSE r.completed_at END))
    FROM iam.authenticator_recoveries r WHERE r.tenant_id=tenant AND r.id=recovery_id
$function$;

CREATE OR REPLACE FUNCTION iam.inspect_authenticator_recovery(tenant text,subject_id text,challenge_id text,request_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE recovery_id text;
BEGIN
    PERFORM iam.lock_recovery_login(tenant,subject_id,challenge_id);
    SELECT r.id INTO recovery_id FROM iam.authenticator_recoveries r WHERE r.tenant_id=tenant AND r.user_id=subject_id AND r.request_id=inspect_authenticator_recovery.request_id;
    IF NOT FOUND THEN RETURN NULL; END IF;
    RETURN iam.authenticator_recovery_snapshot(tenant,recovery_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.guard_authenticator_recovery()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF OLD.state<>'STARTED' OR NEW.state NOT IN ('COMPLETED','SUPERSEDED') OR NEW.completed_at IS DISTINCT FROM transaction_timestamp()
        OR (to_jsonb(NEW)-ARRAY['state','completed_at','completed_event_id','completion_request_id','completion_digest','new_batch_id','superseded_by'])
            IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','completed_at','completed_event_id','completion_request_id','completion_digest','new_batch_id','superseded_by']) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery completion is immutable';
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS cannot_update ON iam.authenticator_recoveries;
CREATE TRIGGER cannot_update BEFORE UPDATE ON iam.authenticator_recoveries FOR EACH ROW EXECUTE FUNCTION iam.guard_authenticator_recovery();
ALTER TABLE iam.authenticator_recoveries ENABLE ALWAYS TRIGGER cannot_update;

CREATE OR REPLACE FUNCTION iam.start_authenticator_recovery(tenant text,subject_id text,source_id text,attempt_id text,attempt_sequence bigint,
    code_id text,code_digest text,recovery_id text,factor_id text,challenge_id text,lookup_digest text,verification_digest text,
    key_id text,nonce bytea,ciphertext bytea,notification_id text,audit_event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE original iam.authentication_challenges%ROWTYPE; batch iam.mfa_recovery_batches%ROWTYPE; state iam.user_mfa_states%ROWTYPE;
    old_recovery iam.authenticator_recoveries%ROWTYPE; contact record; installation text; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF EXISTS(SELECT 1 FROM unnest(ARRAY[code_id,recovery_id,factor_id,challenge_id,key_id,notification_id]) i(value)
            WHERE value IS NULL OR value COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
        OR challenge_id=source_id OR lookup_digest IS NULL OR lookup_digest !~ '^sha256:[0-9a-f]{64}$'
        OR verification_digest IS NULL OR verification_digest !~ '^sha256:[0-9a-f]{64}$' OR lookup_digest=verification_digest
        OR code_digest IS NULL OR code_digest !~ '^sha256:[0-9a-f]{64}$'
        OR nonce IS NULL OR octet_length(nonce)<>12 OR ciphertext IS NULL OR octet_length(ciphertext)<>36 THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery input is invalid';
    END IF;
    PERFORM iam.read_recovery_attempt(tenant,subject_id,source_id,attempt_id,attempt_sequence);
    SELECT * INTO original FROM iam.authentication_challenges c WHERE c.tenant_id=tenant AND c.id=source_id;
    SELECT * INTO state FROM iam.user_mfa_states m WHERE m.tenant_id=tenant AND m.user_id=subject_id;
    SELECT * INTO batch FROM iam.mfa_recovery_batches b WHERE b.tenant_id=tenant AND b.user_id=subject_id AND b.revoked_at IS NULL;
    PERFORM 1 FROM iam.mfa_recovery_codes c WHERE c.tenant_id=tenant AND c.batch_id=batch.id AND c.id=code_id
        AND c.verification_digest=code_digest AND c.consumed_at IS NULL AND c.recovery_id IS NULL FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='recovery code is unavailable'; END IF;
    SELECT f.installation_id INTO installation FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.id=batch.factor_id;
    IF NOT EXISTS(SELECT 1 FROM iam.totp_keysets s WHERE s.installation_id=installation AND s.revision=
            (SELECT max(k.revision) FROM iam.totp_keysets k WHERE k.installation_id=installation)
            AND s.registration->>'activeKeyId'=key_id)
        OR NOT EXISTS(SELECT 1 FROM iam.totp_wrapping_registry k WHERE k.installation_id=installation AND k.key_id=start_authenticator_recovery.key_id) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='recovery protection is unavailable';
    END IF;
    SELECT c.* INTO contact FROM iam.notification_contacts c WHERE c.tenant_id=tenant AND c.user_id=subject_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='verified security contact is required'; END IF;
    PERFORM iam.assert_audit_event(audit_event,tenant,'iam.authenticator.recovery-started','PRINCIPAL',subject_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,subject_id,audit_event);
    IF EXISTS(SELECT 1 FROM iam.authenticator_recoveries r WHERE r.tenant_id=tenant AND r.user_id=subject_id AND r.request_id=audit_event->>'requestId') THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='recovery intent already exists';
    END IF;
    SELECT * INTO old_recovery FROM iam.authenticator_recoveries r WHERE r.tenant_id=tenant AND r.user_id=subject_id AND r.id=state.recovery_id FOR UPDATE;
    IF FOUND THEN
        UPDATE iam.authenticator_recoveries r SET state='SUPERSEDED',completed_at=effective_now,superseded_by=recovery_id
            WHERE r.tenant_id=tenant AND r.id=old_recovery.id;
        UPDATE iam.totp_authenticators f SET state='REVOKED',enrollment_outcome=CASE WHEN f.expires_at<=clock_timestamp() THEN 'EXPIRED' ELSE 'CANCELLED' END,
            completed_at=effective_now,revoked_at=effective_now WHERE f.tenant_id=tenant AND f.id=old_recovery.factor_id AND f.state='PENDING';
    END IF;
    INSERT INTO iam.authenticator_recoveries(tenant_id,user_id,id,request_id,request_digest,old_batch_id,code_id,factor_id,
        source_challenge_id,challenge_id,credential_generation,previous_revision,revision,started_event_id,state,created_at,expires_at)
        VALUES(tenant,subject_id,recovery_id,audit_event->>'requestId',audit_event->>'requestDigest',batch.id,code_id,factor_id,
            source_id,challenge_id,original.credential_generation,state.revision,state.revision+1,audit_event->>'eventId','STARTED',effective_now,original.expires_at);
    UPDATE iam.mfa_recovery_codes c SET consumed_at=effective_now,recovery_id=start_authenticator_recovery.recovery_id
        WHERE c.tenant_id=tenant AND c.batch_id=batch.id AND c.id=code_id;
    UPDATE iam.totp_authenticators f SET state='REVOKED',revoked_at=effective_now WHERE f.tenant_id=tenant AND f.id=batch.factor_id AND f.state='ACTIVE';
    INSERT INTO iam.totp_authenticators(tenant_id,user_id,id,installation_id,key_id,format_version,nonce,ciphertext,state,last_consumed_step,created_at,
        enrollment_request_id,enrollment_digest,enrollment_revision,credential_generation,expires_at,enrollment_outcome,recovery_id)
        VALUES(tenant,subject_id,factor_id,installation,key_id,1,nonce,ciphertext,'PENDING',-1,effective_now,
            audit_event->>'requestId',audit_event->>'requestDigest',state.revision+1,original.credential_generation,original.expires_at,'PENDING',recovery_id);
    UPDATE iam.user_mfa_states m SET enrollment_state='RECOVERY_REQUIRED',factor_id=NULL,revision=state.revision+1,recovery_id=start_authenticator_recovery.recovery_id
        WHERE m.tenant_id=tenant AND m.user_id=subject_id;
    UPDATE iam.totp_attempts a SET state='SUCCEEDED',completed_at=clock_timestamp() WHERE a.tenant_id=tenant AND a.user_id=subject_id;
    UPDATE iam.sessions s SET status='REVOKED',revoked_at=effective_now,resource_version=s.resource_version+1
        WHERE s.tenant_id=tenant AND s.principal_id=subject_id AND s.status='ACTIVE' AND s.revoked_at IS NULL;
    UPDATE iam.authentication_challenges c SET state='CONSUMED',completed_at=effective_now,recovery_id=start_authenticator_recovery.recovery_id
        WHERE c.tenant_id=tenant AND c.id=source_id;
    UPDATE iam.authentication_challenges c SET state='CANCELLED',completed_at=effective_now
        WHERE c.tenant_id=tenant AND c.user_id=subject_id AND c.state='PENDING';
    INSERT INTO iam.authentication_challenges(tenant_id,user_id,id,lookup_digest,verification_digest,credential_generation,password_attempt_id,password_attempt_sequence,
        account_version,principal_version,mfa_revision,factor_id,request_id,request_digest,next_step,source_challenge_id,recovery_id,state,created_at,expires_at)
        VALUES(tenant,subject_id,challenge_id,lookup_digest,verification_digest,original.credential_generation,original.password_attempt_id,original.password_attempt_sequence,
            original.account_version,original.principal_version,state.revision+1,factor_id,audit_event->>'requestId',audit_event->>'requestDigest',
            'ENROLLMENT',source_id,recovery_id,'PENDING',effective_now,original.expires_at);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
        VALUES(tenant,audit_event->>'eventId',audit_event,effective_now,effective_now,effective_now);
    INSERT INTO iam.security_notifications(tenant_id,id,user_id,installation_id,verification_id,event_id,kind,email,contact_revision,created_at,state,next_attempt_at,updated_at)
        VALUES(tenant,notification_id,subject_id,installation,contact.verification_id,audit_event->>'eventId','RECOVERY_STARTED',contact.email,
            contact.resource_version,effective_now,'PENDING',effective_now,effective_now);
    RETURN jsonb_build_object('recovery',iam.authenticator_recovery_snapshot(tenant,recovery_id),
        'challenge',jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AuthenticationChallenge',
            'id',challenge_id,'purpose','RECOVERY','nextStep','ENROLLMENT','expiresAt',original.expires_at));
END $function$;

REVOKE ALL ON FUNCTION iam.create_login_challenge(text,text,text,bigint,text,text,text,text,text),iam.lookup_authentication_challenge(text),
    iam.lock_totp_verification(text,text,text,text,text),iam.reserve_totp_attempt(text,text,text,text,text,text),
    iam.read_totp_attempt(text,text,text,text,text,text,bigint),iam.reject_totp_attempt(text,text,text,bigint)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker;
GRANT EXECUTE ON FUNCTION iam.create_login_challenge(text,text,text,bigint,text,text,text,text,text),iam.lookup_authentication_challenge(text),
    iam.reserve_totp_attempt(text,text,text,text,text,text),iam.read_totp_attempt(text,text,text,text,text,text,bigint),iam.reject_totp_attempt(text,text,text,bigint)
    TO matrix_iam_api;

-- Crypto verification uses read_totp_attempt's database time and locked factor.
-- Only these effect functions can consume that reservation. A caller cannot
-- commit a consumed code independently of its binding/session and outbox.
CREATE OR REPLACE FUNCTION iam.consume_totp_attempt(tenant text,subject_id text,caller_id text,reference_id text,purpose text,
    attempt_id text,attempt_sequence bigint,verified_step bigint)
RETURNS iam.totp_authenticators LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE factor iam.totp_authenticators%ROWTYPE; current_step bigint;
BEGIN
    PERFORM iam.read_totp_attempt(tenant,subject_id,caller_id,reference_id,purpose,attempt_id,attempt_sequence);
    factor:=iam.lock_totp_verification(tenant,subject_id,caller_id,reference_id,purpose);
    current_step:=floor(extract(epoch FROM clock_timestamp())/30)::bigint;
    IF verified_step IS NULL OR verified_step<=factor.last_consumed_step
        OR verified_step<greatest(0,current_step-1) OR verified_step>least(8446743359,current_step+1) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='TOTP verification is unavailable';
    END IF;
    UPDATE iam.totp_attempts a SET state='SUCCEEDED',completed_at=clock_timestamp()
        WHERE a.tenant_id=tenant AND a.user_id=subject_id;
    RETURN factor;
END $function$;

CREATE OR REPLACE FUNCTION iam.assert_recovery_codes(batch_id text,notification_id text,recovery_codes jsonb)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE code jsonb;
BEGIN
    IF COALESCE(batch_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR COALESCE(notification_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR recovery_codes IS NULL OR jsonb_typeof(recovery_codes)<>'array'
        OR jsonb_array_length(recovery_codes)<>10 OR octet_length(recovery_codes::text)>4096 THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery batch is invalid';
    END IF;
    FOR code IN SELECT value FROM jsonb_array_elements(recovery_codes) LOOP
        IF jsonb_typeof(code)<>'object'
            OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(code) k) IS DISTINCT FROM ARRAY['id','verificationDigest']
            OR jsonb_typeof(code->'id') IS DISTINCT FROM 'string'
            OR COALESCE(code->>'id','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            OR jsonb_typeof(code->'verificationDigest') IS DISTINCT FROM 'string'
            OR COALESCE(code->>'verificationDigest','') !~ '^sha256:[0-9a-f]{64}$' THEN
            RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery batch is invalid';
        END IF;
    END LOOP;
    IF (SELECT count(DISTINCT value->>'id') FROM jsonb_array_elements(recovery_codes))<>10
        OR (SELECT count(DISTINCT value->>'verificationDigest') FROM jsonb_array_elements(recovery_codes))<>10 THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='recovery batch is invalid';
    END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.confirm_totp_enrollment(tenant text,subject_id text,caller_id text,factor_id text,
    attempt_id text,attempt_sequence bigint,verified_step bigint,batch_id text,recovery_codes jsonb,notification_id text,audit_event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE factor iam.totp_authenticators%ROWTYPE; contact record; next_revision bigint;
BEGIN
    PERFORM iam.assert_recovery_codes(batch_id,notification_id,recovery_codes);
    factor:=iam.consume_totp_attempt(tenant,subject_id,caller_id,factor_id,'ENROLLMENT',attempt_id,attempt_sequence,verified_step);
    SELECT c.* INTO contact FROM iam.notification_contacts c WHERE c.tenant_id=tenant AND c.user_id=subject_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='verified security contact is required'; END IF;
    PERFORM iam.assert_audit_event(audit_event,tenant,'iam.authenticator.bound','PRINCIPAL',subject_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,subject_id,audit_event);
    next_revision:=factor.enrollment_revision+1;
    UPDATE iam.totp_authenticators f SET state='ACTIVE',enrollment_outcome='CONFIRMED',completed_at=transaction_timestamp(),
        bound_revision=next_revision,bound_event_id=audit_event->>'eventId',last_consumed_step=verified_step
        WHERE f.tenant_id=tenant AND f.id=factor_id;
    UPDATE iam.user_mfa_states m SET enrollment_state='BOUND',factor_id=confirm_totp_enrollment.factor_id,revision=next_revision
        WHERE m.tenant_id=tenant AND m.user_id=subject_id;
    INSERT INTO iam.mfa_recovery_batches(tenant_id,id,user_id,factor_id,mfa_revision,event_id,created_at)
        VALUES(tenant,batch_id,subject_id,factor_id,next_revision,audit_event->>'eventId',transaction_timestamp());
    INSERT INTO iam.mfa_recovery_codes(tenant_id,batch_id,id,verification_digest)
        SELECT tenant,batch_id,value->>'id',value->>'verificationDigest' FROM jsonb_array_elements(recovery_codes);
    -- No old password Session is promoted by completing enrollment. A fresh
    -- password and a not-yet-consumed TOTP must create the next real Session.
    UPDATE iam.sessions s SET status='REVOKED',revoked_at=transaction_timestamp(),resource_version=s.resource_version+1
        WHERE s.tenant_id=tenant AND s.principal_id=subject_id AND s.status='ACTIVE' AND s.revoked_at IS NULL;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
        VALUES(tenant,audit_event->>'eventId',audit_event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
    INSERT INTO iam.security_notifications(tenant_id,id,user_id,installation_id,verification_id,event_id,kind,email,contact_revision,created_at,state,next_attempt_at,updated_at)
        VALUES(tenant,notification_id,subject_id,factor.installation_id,contact.verification_id,audit_event->>'eventId','AUTHENTICATOR_BOUND',
            contact.email,contact.resource_version,transaction_timestamp(),'PENDING',transaction_timestamp(),transaction_timestamp());
    RETURN iam.totp_enrollment_snapshot(tenant,factor_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.confirm_authenticator_recovery(tenant text,subject_id text,challenge_id text,
    attempt_id text,attempt_sequence bigint,verified_step bigint,batch_id text,recovery_codes jsonb,notification_id text,audit_event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE factor iam.totp_authenticators%ROWTYPE; recovery iam.authenticator_recoveries%ROWTYPE; contact record;
    effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    PERFORM iam.assert_recovery_codes(batch_id,notification_id,recovery_codes);
    factor:=iam.consume_totp_attempt(tenant,subject_id,NULL,challenge_id,'RECOVERY_CONFIRM',attempt_id,attempt_sequence,verified_step);
    SELECT * INTO recovery FROM iam.authenticator_recoveries r WHERE r.tenant_id=tenant AND r.user_id=subject_id AND r.id=factor.recovery_id FOR UPDATE;
    SELECT c.* INTO contact FROM iam.notification_contacts c WHERE c.tenant_id=tenant AND c.user_id=subject_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='verified security contact is required'; END IF;
    PERFORM iam.assert_audit_event(audit_event,tenant,'iam.authenticator.recovered','PRINCIPAL',subject_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,subject_id,audit_event);
    UPDATE iam.authenticator_recoveries r SET state='COMPLETED',completed_at=effective_now,completed_event_id=audit_event->>'eventId',
        completion_request_id=audit_event->>'requestId',completion_digest=audit_event->>'requestDigest',new_batch_id=batch_id
        WHERE r.tenant_id=tenant AND r.id=recovery.id;
    UPDATE iam.mfa_recovery_batches b SET revoked_at=effective_now,revocation_recovery_id=recovery.id WHERE b.tenant_id=tenant AND b.id=recovery.old_batch_id;
    UPDATE iam.totp_authenticators f SET state='ACTIVE',enrollment_outcome='CONFIRMED',completed_at=effective_now,
        bound_revision=recovery.revision+1,bound_event_id=audit_event->>'eventId',last_consumed_step=verified_step
        WHERE f.tenant_id=tenant AND f.id=factor.id;
    UPDATE iam.user_mfa_states m SET enrollment_state='BOUND',factor_id=factor.id,revision=recovery.revision+1,recovery_id=NULL
        WHERE m.tenant_id=tenant AND m.user_id=subject_id;
    INSERT INTO iam.mfa_recovery_batches(tenant_id,id,user_id,factor_id,mfa_revision,event_id,created_at)
        VALUES(tenant,batch_id,subject_id,factor.id,recovery.revision+1,audit_event->>'eventId',effective_now);
    INSERT INTO iam.mfa_recovery_codes(tenant_id,batch_id,id,verification_digest)
        SELECT tenant,batch_id,value->>'id',value->>'verificationDigest' FROM jsonb_array_elements(recovery_codes);
    UPDATE iam.authentication_challenges c SET state='CONSUMED',completed_at=effective_now,verified_step=confirm_authenticator_recovery.verified_step
        WHERE c.tenant_id=tenant AND c.id=challenge_id;
    UPDATE iam.authentication_challenges c SET state='CANCELLED',completed_at=effective_now WHERE c.tenant_id=tenant AND c.user_id=subject_id AND c.state='PENDING';
    UPDATE iam.sessions s SET status='REVOKED',revoked_at=effective_now,resource_version=s.resource_version+1
        WHERE s.tenant_id=tenant AND s.principal_id=subject_id AND s.status='ACTIVE' AND s.revoked_at IS NULL;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
        VALUES(tenant,audit_event->>'eventId',audit_event,effective_now,effective_now,effective_now);
    INSERT INTO iam.security_notifications(tenant_id,id,user_id,installation_id,verification_id,event_id,kind,email,contact_revision,created_at,state,next_attempt_at,updated_at)
        VALUES(tenant,notification_id,subject_id,factor.installation_id,contact.verification_id,audit_event->>'eventId','AUTHENTICATOR_RECOVERED',
            contact.email,contact.resource_version,effective_now,'PENDING',effective_now,effective_now);
    RETURN iam.authenticator_recovery_snapshot(tenant,recovery.id);
END $function$;

CREATE OR REPLACE FUNCTION iam.complete_login_challenge(tenant text,subject_id text,challenge_id text,
    attempt_id text,attempt_sequence bigint,verified_step bigint,session_id text,lookup_digest text,verification_digest text,
    lifetime_seconds integer,audit_event jsonb)
RETURNS TABLE(issued_at timestamptz,expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE factor iam.totp_authenticators%ROWTYPE; generation bigint; effective_now timestamptz(6):=transaction_timestamp();
    effective_expiry timestamptz(6);
BEGIN
    IF COALESCE(session_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR COALESCE(lookup_digest,'') !~ '^sha256:[0-9a-f]{64}$'
        OR COALESCE(verification_digest,'') !~ '^sha256:[0-9a-f]{64}$'
        OR lookup_digest=verification_digest OR lifetime_seconds IS NULL OR lifetime_seconds NOT BETWEEN 60 AND 86400 THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='session input is invalid';
    END IF;
    factor:=iam.consume_totp_attempt(tenant,subject_id,NULL,challenge_id,'LOGIN',attempt_id,attempt_sequence,verified_step);
    IF (SELECT p.must_change_password FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=subject_id) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='restricted password stage is required';
    END IF;
    SELECT c.credential_version INTO generation FROM iam.user_credentials c WHERE c.tenant_id=tenant AND c.principal_id=subject_id;
    PERFORM iam.assert_audit_event(audit_event,tenant,'iam.session.issued','SESSION',session_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,subject_id,audit_event);
    effective_expiry:=effective_now+make_interval(secs=>lifetime_seconds);
    -- Password success alone did not reset the guessing budget. Only this
    -- completed ceremony can reset its still-current original attempt; a
    -- later failed/in-flight password attempt is never erased by an old one.
    UPDATE iam.password_attempts b SET used_attempts=0,window_started_at=clock_timestamp()
        FROM iam.authentication_challenges c WHERE c.tenant_id=tenant AND c.id=challenge_id
            AND b.tenant_id=tenant AND b.principal_id=subject_id AND b.state='SUCCEEDED'
            AND b.attempt_id=c.password_attempt_id AND b.attempt_sequence=c.password_attempt_sequence;
    UPDATE iam.totp_authenticators f SET last_consumed_step=verified_step WHERE f.tenant_id=tenant AND f.id=factor.id;
    INSERT INTO iam.sessions(tenant_id,id,principal_id,verification_digest,status,resource_version,issued_at,expires_at,
        credential_version,authentication_method,authenticated_at,mfa_revision)
        VALUES(tenant,session_id,subject_id,verification_digest,'ACTIVE',1,effective_now,effective_expiry,generation,
            'PASSWORD_TOTP',effective_now,factor.bound_revision);
    INSERT INTO iam.session_index(lookup_digest,tenant_id,session_id) VALUES(lookup_digest,tenant,session_id);
    UPDATE iam.authentication_challenges c SET state='CONSUMED',completed_at=effective_now,session_id=complete_login_challenge.session_id
        ,issuance_event_id=audit_event->>'eventId',verified_step=complete_login_challenge.verified_step
        WHERE c.tenant_id=tenant AND c.id=challenge_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
        VALUES(tenant,audit_event->>'eventId',audit_event,effective_now,effective_now,effective_now);
    RETURN QUERY SELECT effective_now,effective_expiry;
END $function$;

-- A successful forced login consumes its OTP but issues no Session. Its
-- successor has a fresh secret and cannot outlive the original login intent.
CREATE OR REPLACE FUNCTION iam.begin_password_challenge(tenant text,subject_id text,challenge_id text,
    attempt_id text,attempt_sequence bigint,verified_step bigint,password_challenge_id text,
    lookup_digest text,verification_digest text,request_id text,request_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE factor iam.totp_authenticators%ROWTYPE; original iam.authentication_challenges%ROWTYPE;
    effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF COALESCE(password_challenge_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' OR password_challenge_id=challenge_id
        OR COALESCE(lookup_digest,'') !~ '^sha256:[0-9a-f]{64}$' OR COALESCE(verification_digest,'') !~ '^sha256:[0-9a-f]{64}$'
        OR lookup_digest=verification_digest OR COALESCE(request_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR COALESCE(request_digest,'') !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='password challenge is invalid';
    END IF;
    factor:=iam.consume_totp_attempt(tenant,subject_id,NULL,challenge_id,'LOGIN',attempt_id,attempt_sequence,verified_step);
    IF NOT (SELECT p.must_change_password FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=subject_id) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='password challenge is unavailable';
    END IF;
    SELECT * INTO original FROM iam.authentication_challenges c WHERE c.tenant_id=tenant AND c.id=challenge_id;
    UPDATE iam.totp_authenticators f SET last_consumed_step=begin_password_challenge.verified_step WHERE f.tenant_id=tenant AND f.id=factor.id;
    UPDATE iam.authentication_challenges c SET state='CONSUMED',completed_at=effective_now,
        verified_step=begin_password_challenge.verified_step,password_challenge_id=begin_password_challenge.password_challenge_id
        WHERE c.tenant_id=tenant AND c.id=challenge_id;
    INSERT INTO iam.authentication_challenges(tenant_id,id,user_id,lookup_digest,verification_digest,credential_generation,
        password_attempt_id,password_attempt_sequence,account_version,principal_version,mfa_revision,factor_id,request_id,request_digest,
        next_step,source_challenge_id,verified_step,state,created_at,expires_at)
        VALUES(tenant,password_challenge_id,subject_id,lookup_digest,verification_digest,original.credential_generation,
            original.password_attempt_id,original.password_attempt_sequence,original.account_version,original.principal_version,
            original.mfa_revision,original.factor_id,request_id,request_digest,'PASSWORD_CHANGE',original.id,verified_step,
            'PENDING',effective_now,original.expires_at);
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AuthenticationChallenge','id',password_challenge_id,
        'purpose','LOGIN','nextStep','PASSWORD_CHANGE','expiresAt',original.expires_at);
END $function$;

CREATE OR REPLACE FUNCTION iam.lock_password_challenge(tenant text,subject_id text,challenge_id text)
RETURNS iam.authentication_challenges LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE state iam.user_mfa_states%ROWTYPE; factor iam.totp_authenticators%ROWTYPE;
    challenge iam.authentication_challenges%ROWTYPE; original iam.authentication_challenges%ROWTYPE;
BEGIN
    state:=iam.lock_mfa_user(tenant,subject_id);
    SELECT * INTO factor FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.user_id=subject_id AND f.id=state.factor_id FOR UPDATE;
    IF NOT FOUND OR state.enrollment_state<>'BOUND' OR factor.state<>'ACTIVE' OR factor.bound_revision<>state.revision THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='password challenge is unavailable';
    END IF;
    SELECT * INTO challenge FROM iam.authentication_challenges c WHERE c.tenant_id=tenant AND c.user_id=subject_id AND c.id=challenge_id FOR UPDATE;
    IF NOT FOUND OR challenge.next_step<>'PASSWORD_CHANGE' OR challenge.state<>'PENDING' OR challenge.factor_id<>factor.id
        OR challenge.mfa_revision<>state.revision OR challenge.expires_at<=clock_timestamp()
        OR challenge.credential_generation IS DISTINCT FROM (SELECT c.credential_version FROM iam.user_credentials c WHERE c.tenant_id=tenant AND c.principal_id=subject_id)
        OR challenge.account_version IS DISTINCT FROM (SELECT a.resource_version FROM iam.accounts a WHERE a.id=tenant)
        OR challenge.principal_version IS DISTINCT FROM (SELECT p.resource_version FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=subject_id)
        OR NOT (SELECT p.must_change_password FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=subject_id) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='password challenge is unavailable';
    END IF;
    SELECT * INTO original FROM iam.authentication_challenges c WHERE c.tenant_id=tenant AND c.id=challenge.source_challenge_id;
    IF NOT FOUND OR original.next_step<>'TOTP' OR original.state<>'CONSUMED' OR original.password_challenge_id IS DISTINCT FROM challenge.id
        OR (original.user_id,original.credential_generation,original.mfa_revision,original.factor_id,original.verified_step,original.completed_at,original.expires_at)
            IS DISTINCT FROM (challenge.user_id,challenge.credential_generation,challenge.mfa_revision,challenge.factor_id,challenge.verified_step,challenge.created_at,challenge.expires_at) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='password challenge is unavailable';
    END IF;
    RETURN challenge;
END $function$;

CREATE OR REPLACE FUNCTION iam.read_password_challenge(tenant text,subject_id text,challenge_id text)
RETURNS TABLE(password_hash text,credential_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM iam.lock_password_challenge(tenant,subject_id,challenge_id);
    RETURN QUERY SELECT c.password_hash,c.credential_version FROM iam.user_credentials c WHERE c.tenant_id=tenant AND c.principal_id=subject_id;
END $function$;

CREATE OR REPLACE FUNCTION iam.change_challenge_password(tenant text,subject_id text,challenge_id text,
    expected_generation bigint,expected_password_hash text,new_password_hash text,audit_event jsonb)
RETURNS timestamptz LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE challenge iam.authentication_challenges%ROWTYPE; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF expected_generation IS NULL OR expected_generation NOT BETWEEN 1 AND 9007199254740990
        OR COALESCE(expected_password_hash,'') NOT LIKE '$matrix-iam-v1$argon2id$v=19$%'
        OR COALESCE(new_password_hash,'') NOT LIKE '$matrix-iam-v1$argon2id$v=19$%' OR expected_password_hash=new_password_hash THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='password mutation is invalid';
    END IF;
    challenge:=iam.lock_password_challenge(tenant,subject_id,challenge_id);
    IF challenge.credential_generation<>expected_generation OR NOT EXISTS(SELECT 1 FROM iam.user_credentials c
        WHERE c.tenant_id=tenant AND c.principal_id=subject_id AND c.password_hash=expected_password_hash) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='password challenge is unavailable';
    END IF;
    PERFORM iam.assert_audit_event(audit_event,tenant,'iam.user.password-changed','USER',subject_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,subject_id,audit_event);
    UPDATE iam.user_credentials c SET password_hash=new_password_hash,credential_version=expected_generation+1,changed_at=effective_now
        WHERE c.tenant_id=tenant AND c.principal_id=subject_id;
    UPDATE iam.principals p SET must_change_password=false,resource_version=resource_version+1,updated_at=effective_now
        WHERE p.tenant_id=tenant AND p.id=subject_id;
    UPDATE iam.sessions s SET status='REVOKED',revoked_at=effective_now,resource_version=resource_version+1
        WHERE s.tenant_id=tenant AND s.principal_id=subject_id AND s.status='ACTIVE' AND s.revoked_at IS NULL;
    UPDATE iam.authentication_challenges c SET state='CONSUMED',completed_at=effective_now,
        password_changed_event_id=audit_event->>'eventId',password_change_request_id=audit_event->>'requestId'
        WHERE c.tenant_id=tenant AND c.id=challenge_id;
    UPDATE iam.authentication_challenges c SET state='CANCELLED',completed_at=effective_now
        WHERE c.tenant_id=tenant AND c.user_id=subject_id AND c.state='PENDING';
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
        VALUES(tenant,audit_event->>'eventId',audit_event,effective_now,effective_now,effective_now);
    RETURN effective_now;
END $function$;
REVOKE ALL ON FUNCTION iam.begin_password_challenge(text,text,text,text,bigint,bigint,text,text,text,text,text),
    iam.lock_password_challenge(text,text,text),iam.read_password_challenge(text,text,text),
    iam.change_challenge_password(text,text,text,bigint,text,text,jsonb)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker;
GRANT EXECUTE ON FUNCTION iam.begin_password_challenge(text,text,text,text,bigint,bigint,text,text,text,text,text),
    iam.read_password_challenge(text,text,text),iam.change_challenge_password(text,text,text,bigint,text,text,jsonb) TO matrix_iam_api;

REVOKE ALL ON FUNCTION iam.consume_totp_attempt(text,text,text,text,text,text,bigint,bigint),
    iam.confirm_totp_enrollment(text,text,text,text,text,bigint,bigint,text,jsonb,text,jsonb),
    iam.complete_login_challenge(text,text,text,text,bigint,bigint,text,text,text,integer,jsonb)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker;
GRANT EXECUTE ON FUNCTION iam.confirm_totp_enrollment(text,text,text,text,text,bigint,bigint,text,jsonb,text,jsonb),
    iam.complete_login_challenge(text,text,text,text,bigint,bigint,text,text,text,integer,jsonb) TO matrix_iam_api;

-- Every successful binding has one immutable original factor/USER/Session,
-- one recovery batch and one safety notice. Deferred checks admit the single
-- transaction, not a separately committed 'factor first, audit later' workflow.
CREATE OR REPLACE FUNCTION iam.verify_totp_binding()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE tenant text; binding_event_id text; factor iam.totp_authenticators%ROWTYPE; batch iam.mfa_recovery_batches%ROWTYPE;
    notice record; original_contact record; event jsonb; expected_action text; expected_notice text;
BEGIN
    tenant:=NEW.tenant_id;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    CASE TG_TABLE_NAME
        WHEN 'totp_authenticators' THEN
            IF NEW.enrollment_outcome IS DISTINCT FROM 'CONFIRMED' THEN RETURN NULL; END IF;
            binding_event_id:=NEW.bound_event_id;
        WHEN 'audit_outbox' THEN
            IF NEW.event_document->>'action' NOT IN ('iam.authenticator.bound','iam.authenticator.recovered') THEN RETURN NULL; END IF;
            binding_event_id:=NEW.event_id;
        WHEN 'security_notifications' THEN
            IF NEW.kind NOT IN ('AUTHENTICATOR_BOUND','AUTHENTICATOR_RECOVERED') THEN RETURN NULL; END IF;
            binding_event_id:=NEW.event_id;
        WHEN 'mfa_recovery_batches' THEN binding_event_id:=NEW.event_id;
        WHEN 'mfa_recovery_codes' THEN
            SELECT b.event_id INTO binding_event_id FROM iam.mfa_recovery_batches b WHERE b.tenant_id=tenant AND b.id=NEW.batch_id;
        ELSE RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='binding verification source is invalid';
    END CASE;
    SELECT f.* INTO factor FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.bound_event_id=binding_event_id;
    IF NOT FOUND OR factor.enrollment_outcome<>'CONFIRMED' OR factor.bound_revision IS NULL
        OR NOT ((factor.recovery_id IS NULL AND EXISTS(SELECT 1 FROM iam.sessions s
            WHERE s.tenant_id=tenant AND s.id=factor.enrollment_session_id AND s.principal_id=factor.user_id))
            OR (factor.enrollment_session_id IS NULL AND EXISTS(SELECT 1 FROM iam.authenticator_recoveries r
                WHERE r.tenant_id=tenant AND r.user_id=factor.user_id AND r.id=factor.recovery_id AND r.factor_id=factor.id
                    AND r.state='COMPLETED' AND r.completed_event_id=factor.bound_event_id)))
        OR NOT EXISTS(SELECT 1 FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=factor.user_id AND p.principal_type='USER') THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='binding origin is missing';
    END IF;
    expected_action:=CASE WHEN factor.recovery_id IS NULL THEN 'iam.authenticator.bound' ELSE 'iam.authenticator.recovered' END;
    expected_notice:=CASE WHEN factor.recovery_id IS NULL THEN 'AUTHENTICATOR_BOUND' ELSE 'AUTHENTICATOR_RECOVERED' END;
    SELECT o.event_document INTO event FROM iam.audit_outbox o WHERE o.tenant_id=tenant AND o.event_id=binding_event_id;
    IF event IS NULL OR event->>'action' IS DISTINCT FROM expected_action
        OR event->'actor' IS DISTINCT FROM jsonb_build_object('type','USER','id',factor.user_id)
        OR event->'target' IS DISTINCT FROM jsonb_build_object('kind','PRINCIPAL','id',factor.user_id)
        OR event->>'tenantId' IS DISTINCT FROM tenant OR event->>'result' IS DISTINCT FROM 'SUCCEEDED'
        OR (event->>'occurredAt')::timestamptz IS DISTINCT FROM factor.completed_at
        OR event ?| ARRAY['installationId','iamDecisionId','operationId'] THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='binding fact differs';
    END IF;
    SELECT b.* INTO batch FROM iam.mfa_recovery_batches b WHERE b.tenant_id=tenant AND b.event_id=binding_event_id;
    IF NOT FOUND OR (batch.user_id,batch.factor_id,batch.mfa_revision,batch.created_at)
        IS DISTINCT FROM (factor.user_id,factor.id,factor.bound_revision,factor.completed_at)
        OR (SELECT count(*) FROM iam.mfa_recovery_codes c WHERE c.tenant_id=tenant AND c.batch_id=batch.id)<>10 THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='binding recovery batch differs';
    END IF;
    SELECT n.* INTO notice FROM iam.security_notifications n
        WHERE n.tenant_id=tenant AND n.event_id=binding_event_id AND n.kind=expected_notice;
    IF NOT FOUND OR (notice.user_id,notice.installation_id,notice.created_at,notice.contact_revision)
        IS DISTINCT FROM (factor.user_id,factor.installation_id,factor.completed_at,1::bigint) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='binding security notice differs';
    END IF;
    SELECT v.* INTO original_contact FROM iam.notification_contact_verifications v
        WHERE v.tenant_id=tenant AND v.id=notice.verification_id AND v.user_id=factor.user_id;
    IF NOT FOUND OR original_contact.state<>'VERIFIED' OR original_contact.email IS DISTINCT FROM notice.email THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='binding notice has no verified recipient';
    END IF;
    RETURN NULL;
END $function$;
REVOKE ALL ON FUNCTION iam.verify_totp_binding()
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker;

DO $binding_integrity$
DECLARE relation_name text;
BEGIN
    -- security_notifications is installed by the mail owner after this file;
    -- its trigger is attached there under the same atomic migration boundary.
    FOREACH relation_name IN ARRAY ARRAY['totp_authenticators','audit_outbox','mfa_recovery_batches','mfa_recovery_codes'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS verify_totp_binding ON iam.%I',relation_name);
        EXECUTE format('CREATE CONSTRAINT TRIGGER verify_totp_binding AFTER INSERT OR UPDATE ON iam.%I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.verify_totp_binding()',relation_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER verify_totp_binding',relation_name);
    END LOOP;
END $binding_integrity$;

-- Authentication facts belong to the original ceremony, not today's User
-- settings. Password changes may advance the Session's credential generation
-- under their existing proof, but cannot invent or upgrade its MFA facts.
CREATE OR REPLACE FUNCTION iam.guard_session_authentication()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF (NEW.authentication_method,NEW.authenticated_at,NEW.mfa_revision)
        IS DISTINCT FROM (OLD.authentication_method,OLD.authenticated_at,OLD.mfa_revision) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='session authentication facts are immutable';
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS authentication_fact_is_immutable ON iam.sessions;
CREATE TRIGGER authentication_fact_is_immutable BEFORE UPDATE ON iam.sessions FOR EACH ROW EXECUTE FUNCTION iam.guard_session_authentication();
ALTER TABLE iam.sessions ENABLE ALWAYS TRIGGER authentication_fact_is_immutable;

CREATE OR REPLACE FUNCTION iam.guard_authentication_challenge()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF OLD.state<>'PENDING' OR (to_jsonb(NEW)-ARRAY['state','attempts','completed_at','session_id','issuance_event_id','password_challenge_id','verified_step','password_changed_event_id','password_change_request_id','recovery_id'])
        IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','attempts','completed_at','session_id','issuance_event_id','password_challenge_id','verified_step','password_changed_event_id','password_change_request_id','recovery_id'])
        OR (OLD.next_step='PASSWORD_CHANGE' AND NEW.verified_step IS DISTINCT FROM OLD.verified_step)
        OR (OLD.next_step='ENROLLMENT' AND NEW.recovery_id IS DISTINCT FROM OLD.recovery_id) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='challenge identity and completion are immutable';
    END IF;
    IF NEW.state='PENDING' AND NEW.attempts=OLD.attempts+1 THEN RETURN NEW; END IF;
    IF NEW.state<>'PENDING' AND NEW.attempts=OLD.attempts AND NEW.completed_at=transaction_timestamp() THEN RETURN NEW; END IF;
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='challenge transition is invalid';
END $function$;
DROP TRIGGER IF EXISTS cannot_update ON iam.authentication_challenges;
CREATE TRIGGER cannot_update BEFORE UPDATE ON iam.authentication_challenges FOR EACH ROW EXECUTE FUNCTION iam.guard_authentication_challenge();
ALTER TABLE iam.authentication_challenges ENABLE ALWAYS TRIGGER cannot_update;

CREATE OR REPLACE FUNCTION iam.verify_challenge_session()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE challenge iam.authentication_challenges%ROWTYPE; session iam.sessions%ROWTYPE;
    factor iam.totp_authenticators%ROWTYPE; event jsonb;
    original iam.authentication_challenges%ROWTYPE; successor iam.authentication_challenges%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME='sessions' THEN
        IF NEW.authentication_method IS DISTINCT FROM 'PASSWORD_TOTP' THEN RETURN NULL; END IF;
        SELECT * INTO challenge FROM iam.authentication_challenges c WHERE c.tenant_id=NEW.tenant_id AND c.session_id=NEW.id;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='MFA session has no completed challenge'; END IF;
    ELSE
        SELECT * INTO challenge FROM iam.authentication_challenges c WHERE c.tenant_id=NEW.tenant_id AND c.id=NEW.id;
        IF NOT FOUND THEN RETURN NULL; END IF;
        -- Recovery never creates a Session; its original login, consumed code
        -- and rebinding successor are checked by their own deferred proof.
        IF challenge.recovery_id IS NOT NULL THEN RETURN NULL; END IF;
        IF challenge.next_step='PASSWORD_CHANGE' OR challenge.password_challenge_id IS NOT NULL THEN
            IF challenge.next_step='PASSWORD_CHANGE' THEN
                successor:=challenge;
                SELECT * INTO original FROM iam.authentication_challenges c WHERE c.tenant_id=challenge.tenant_id AND c.id=challenge.source_challenge_id;
            ELSE
                original:=challenge;
                SELECT * INTO successor FROM iam.authentication_challenges c WHERE c.tenant_id=challenge.tenant_id AND c.id=challenge.password_challenge_id;
            END IF;
            IF original.id IS NULL OR successor.id IS NULL OR original.next_step<>'TOTP' OR original.state<>'CONSUMED'
                OR successor.next_step<>'PASSWORD_CHANGE' OR original.password_challenge_id IS DISTINCT FROM successor.id
                OR successor.source_challenge_id IS DISTINCT FROM original.id
                OR (original.tenant_id,original.user_id,original.credential_generation,original.password_attempt_id,original.password_attempt_sequence,
                    original.account_version,original.principal_version,original.mfa_revision,original.factor_id,original.verified_step,original.completed_at,original.expires_at)
                    IS DISTINCT FROM (successor.tenant_id,successor.user_id,successor.credential_generation,successor.password_attempt_id,successor.password_attempt_sequence,
                    successor.account_version,successor.principal_version,successor.mfa_revision,successor.factor_id,successor.verified_step,successor.created_at,successor.expires_at) THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='password challenge has no exact authenticated predecessor';
            END IF;
            SELECT * INTO factor FROM iam.totp_authenticators f WHERE f.tenant_id=original.tenant_id AND f.user_id=original.user_id AND f.id=original.factor_id;
            IF NOT FOUND OR factor.enrollment_outcome IS DISTINCT FROM 'CONFIRMED' OR factor.bound_revision IS DISTINCT FROM original.mfa_revision
                OR factor.last_consumed_step<original.verified_step THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='password challenge has no original confirmed factor';
            END IF;
            IF successor.state='CONSUMED' THEN
                SELECT o.event_document INTO event FROM iam.audit_outbox o WHERE o.tenant_id=successor.tenant_id AND o.event_id=successor.password_changed_event_id;
                IF NOT FOUND OR event->>'action' IS DISTINCT FROM 'iam.user.password-changed' OR event->>'tenantId' IS DISTINCT FROM successor.tenant_id
                    OR event->'actor' IS DISTINCT FROM jsonb_build_object('type','USER','id',successor.user_id)
                    OR event->'target' IS DISTINCT FROM jsonb_build_object('kind','USER','id',successor.user_id)
                    OR event->>'result' IS DISTINCT FROM 'SUCCEEDED' OR event->>'requestId' IS DISTINCT FROM successor.password_change_request_id
                    OR (event->>'occurredAt')::timestamptz IS DISTINCT FROM successor.completed_at
                    OR event ?| ARRAY['installationId','iamDecisionId','operationId'] THEN
                    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='password challenge has no matching completion fact';
                END IF;
            END IF;
            RETURN NULL;
        END IF;
        IF challenge.state<>'CONSUMED' THEN RETURN NULL; END IF;
    END IF;
    SELECT * INTO session FROM iam.sessions s WHERE s.tenant_id=challenge.tenant_id AND s.id=challenge.session_id;
    IF NOT FOUND OR challenge.state<>'CONSUMED' OR (session.principal_id,session.authentication_method,session.mfa_revision,session.authenticated_at,session.issued_at)
        IS DISTINCT FROM (challenge.user_id,'PASSWORD_TOTP'::text,challenge.mfa_revision,challenge.completed_at,challenge.completed_at)
        OR session.credential_version IS NULL OR session.credential_version<challenge.credential_generation THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='MFA session differs from its original challenge';
    END IF;
    SELECT * INTO factor FROM iam.totp_authenticators f WHERE f.tenant_id=challenge.tenant_id AND f.user_id=challenge.user_id AND f.id=challenge.factor_id;
    IF NOT FOUND OR factor.enrollment_outcome IS DISTINCT FROM 'CONFIRMED' OR factor.bound_revision IS DISTINCT FROM challenge.mfa_revision THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='MFA challenge has no original confirmed factor';
    END IF;
    SELECT o.event_document INTO event FROM iam.audit_outbox o WHERE o.tenant_id=challenge.tenant_id AND o.event_id=challenge.issuance_event_id;
    IF NOT FOUND OR event->>'action' IS DISTINCT FROM 'iam.session.issued' OR event->>'tenantId' IS DISTINCT FROM challenge.tenant_id
        OR event->'actor' IS DISTINCT FROM jsonb_build_object('type','USER','id',challenge.user_id)
        OR event->'target' IS DISTINCT FROM jsonb_build_object('kind','SESSION','id',challenge.session_id)
        OR event->>'result' IS DISTINCT FROM 'SUCCEEDED' OR (event->>'occurredAt')::timestamptz IS DISTINCT FROM session.issued_at
        OR event ?| ARRAY['installationId','iamDecisionId','operationId'] THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='MFA session has no matching issuance fact';
    END IF;
    RETURN NULL;
END $function$;
DROP TRIGGER IF EXISTS verify_challenge_session ON iam.authentication_challenges;
CREATE CONSTRAINT TRIGGER verify_challenge_session AFTER INSERT OR UPDATE ON iam.authentication_challenges DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.verify_challenge_session();
ALTER TABLE iam.authentication_challenges ENABLE ALWAYS TRIGGER verify_challenge_session;
DROP TRIGGER IF EXISTS verify_challenge_session ON iam.sessions;
CREATE CONSTRAINT TRIGGER verify_challenge_session AFTER INSERT OR UPDATE ON iam.sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.verify_challenge_session();
ALTER TABLE iam.sessions ENABLE ALWAYS TRIGGER verify_challenge_session;
REVOKE ALL ON FUNCTION iam.guard_session_authentication(),iam.guard_authentication_challenge(),iam.verify_challenge_session()
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker;

CREATE OR REPLACE FUNCTION iam.verify_authenticator_recovery()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE recovery iam.authenticator_recoveries%ROWTYPE; original iam.authentication_challenges%ROWTYPE; child iam.authentication_challenges%ROWTYPE;
    batch iam.mfa_recovery_batches%ROWTYPE; factor iam.totp_authenticators%ROWTYPE; old_factor iam.totp_authenticators%ROWTYPE;
    code iam.mfa_recovery_codes%ROWTYPE; event jsonb; notice record; selected_id text; tenant text:=NEW.tenant_id;
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    CASE TG_TABLE_NAME
        WHEN 'authenticator_recoveries' THEN selected_id:=NEW.id;
        WHEN 'mfa_recovery_batches' THEN selected_id:=NEW.revocation_recovery_id;
        WHEN 'audit_outbox' THEN
            IF NEW.event_document->>'action' NOT IN ('iam.authenticator.recovery-started','iam.authenticator.recovered') THEN RETURN NULL; END IF;
            SELECT r.id INTO selected_id FROM iam.authenticator_recoveries r WHERE r.tenant_id=tenant
                AND (r.started_event_id=NEW.event_id OR r.completed_event_id=NEW.event_id);
            IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery fact has no origin'; END IF;
        WHEN 'security_notifications' THEN
            IF NEW.kind NOT IN ('RECOVERY_STARTED','AUTHENTICATOR_RECOVERED') THEN RETURN NULL; END IF;
            SELECT r.id INTO selected_id FROM iam.authenticator_recoveries r WHERE r.tenant_id=tenant
                AND (r.started_event_id=NEW.event_id OR r.completed_event_id=NEW.event_id);
            IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery notice has no origin'; END IF;
        ELSE selected_id:=NEW.recovery_id;
    END CASE;
    IF selected_id IS NULL THEN RETURN NULL; END IF;
    SELECT * INTO recovery FROM iam.authenticator_recoveries r WHERE r.tenant_id=tenant AND r.id=selected_id;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery origin is missing'; END IF;
    CASE TG_TABLE_NAME
        WHEN 'totp_authenticators' THEN
            IF NEW.id<>recovery.factor_id OR NEW.user_id<>recovery.user_id THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery factor reference differs'; END IF;
        WHEN 'mfa_recovery_codes' THEN
            IF (NEW.batch_id,NEW.id) IS DISTINCT FROM (recovery.old_batch_id,recovery.code_id) THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery consumed code reference differs'; END IF;
        WHEN 'mfa_recovery_batches' THEN
            IF NEW.id<>recovery.old_batch_id OR NEW.user_id<>recovery.user_id OR recovery.state<>'COMPLETED' THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery batch reference differs'; END IF;
        WHEN 'authentication_challenges' THEN
            IF NEW.id NOT IN (recovery.source_challenge_id,recovery.challenge_id) OR NEW.user_id<>recovery.user_id THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery challenge reference differs'; END IF;
        WHEN 'user_mfa_states' THEN
            IF NEW.user_id<>recovery.user_id OR NEW.revision<>recovery.revision THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery state reference differs'; END IF;
        ELSE NULL;
    END CASE;
    SELECT * INTO original FROM iam.authentication_challenges c WHERE c.tenant_id=tenant AND c.id=recovery.source_challenge_id;
    SELECT * INTO child FROM iam.authentication_challenges c WHERE c.tenant_id=tenant AND c.id=recovery.challenge_id;
    SELECT * INTO batch FROM iam.mfa_recovery_batches b WHERE b.tenant_id=tenant AND b.id=recovery.old_batch_id;
    SELECT * INTO code FROM iam.mfa_recovery_codes c WHERE c.tenant_id=tenant AND c.batch_id=batch.id AND c.id=recovery.code_id;
    SELECT * INTO factor FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.id=recovery.factor_id;
    SELECT * INTO old_factor FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.id=batch.factor_id;
    IF original.id IS NULL OR child.id IS NULL OR batch.id IS NULL OR code.id IS NULL OR factor.id IS NULL OR old_factor.id IS NULL
        OR (original.user_id,child.user_id,batch.user_id,factor.user_id,old_factor.user_id)
            IS DISTINCT FROM (recovery.user_id,recovery.user_id,recovery.user_id,recovery.user_id,recovery.user_id)
        OR original.state<>'CONSUMED' OR original.next_step NOT IN ('TOTP','RECOVER') OR original.source_challenge_id IS NOT NULL
        OR (original.recovery_id,original.factor_id,original.mfa_revision,original.credential_generation,original.completed_at,original.expires_at)
            IS DISTINCT FROM (recovery.id,batch.factor_id,recovery.previous_revision,recovery.credential_generation,recovery.created_at,recovery.expires_at)
        OR (code.consumed_at,code.recovery_id) IS DISTINCT FROM (recovery.created_at,recovery.id)
        OR old_factor.state<>'REVOKED' OR old_factor.revoked_at IS NULL OR old_factor.revoked_at>recovery.created_at
        OR (old_factor.bound_revision,old_factor.bound_event_id) IS DISTINCT FROM (batch.mfa_revision,batch.event_id)
        OR (child.next_step,child.source_challenge_id,child.recovery_id,child.factor_id,child.mfa_revision,child.credential_generation,child.created_at,child.expires_at)
            IS DISTINCT FROM ('ENROLLMENT'::text,original.id,recovery.id,factor.id,recovery.revision,recovery.credential_generation,recovery.created_at,recovery.expires_at)
        OR (child.password_attempt_id,child.password_attempt_sequence,child.account_version,child.principal_version)
            IS DISTINCT FROM (original.password_attempt_id,original.password_attempt_sequence,original.account_version,original.principal_version)
        OR (factor.recovery_id,factor.enrollment_request_id,factor.enrollment_digest,factor.enrollment_revision,factor.credential_generation,factor.created_at,factor.expires_at)
            IS DISTINCT FROM (recovery.id,recovery.request_id,recovery.request_digest,recovery.revision,recovery.credential_generation,recovery.created_at,recovery.expires_at)
        OR factor.enrollment_session_id IS NOT NULL OR factor.installation_id<>old_factor.installation_id THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery lineage differs';
    END IF;
    IF original.next_step='TOTP' THEN
        IF recovery.previous_revision<>batch.mfa_revision OR old_factor.revoked_at<>recovery.created_at THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery lost factor differs';
        END IF;
    ELSIF NOT EXISTS(SELECT 1 FROM iam.authenticator_recoveries r WHERE r.tenant_id=tenant AND r.user_id=recovery.user_id
        AND r.old_batch_id=batch.id AND r.revision=recovery.previous_revision AND r.state='SUPERSEDED'
        AND r.superseded_by=recovery.id AND r.completed_at=recovery.created_at) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery continuation has no predecessor';
    END IF;
    SELECT o.event_document INTO event FROM iam.audit_outbox o WHERE o.tenant_id=tenant AND o.event_id=recovery.started_event_id;
    IF event IS NULL OR event->>'action' IS DISTINCT FROM 'iam.authenticator.recovery-started'
        OR event->>'tenantId' IS DISTINCT FROM tenant OR event->>'result' IS DISTINCT FROM 'SUCCEEDED'
        OR event->'actor' IS DISTINCT FROM jsonb_build_object('type','USER','id',recovery.user_id)
        OR event->'target' IS DISTINCT FROM jsonb_build_object('kind','PRINCIPAL','id',recovery.user_id)
        OR (event->>'occurredAt')::timestamptz IS DISTINCT FROM recovery.created_at
        OR event->>'requestId' IS DISTINCT FROM recovery.request_id OR event->>'requestDigest' IS DISTINCT FROM recovery.request_digest
        OR event ?| ARRAY['installationId','iamDecisionId','operationId'] THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery start fact differs';
    END IF;
    IF recovery.state='COMPLETED' THEN
        IF (child.state,child.completed_at,factor.enrollment_outcome,factor.completed_at,factor.bound_revision,factor.bound_event_id,
            batch.revoked_at,batch.revocation_recovery_id)
            IS DISTINCT FROM ('CONSUMED'::text,recovery.completed_at,'CONFIRMED'::text,recovery.completed_at,recovery.revision+1,recovery.completed_event_id,
                recovery.completed_at,recovery.id)
            OR child.verified_step IS NULL OR factor.last_consumed_step<child.verified_step
            OR NOT EXISTS(SELECT 1 FROM iam.mfa_recovery_batches b WHERE b.tenant_id=tenant AND b.user_id=recovery.user_id
                AND b.id=recovery.new_batch_id AND b.factor_id=factor.id AND b.event_id=recovery.completed_event_id AND b.mfa_revision=recovery.revision+1) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery completion differs';
        END IF;
        SELECT o.event_document INTO event FROM iam.audit_outbox o WHERE o.tenant_id=tenant AND o.event_id=recovery.completed_event_id;
        IF event->>'requestId' IS DISTINCT FROM recovery.completion_request_id OR event->>'requestDigest' IS DISTINCT FROM recovery.completion_digest THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery completion intent differs';
        END IF;
        -- The confirmed factor/batch/notice use the same binding verifier as
        -- first enrollment, with the exact recovery origin instead of a Session.
    ELSIF recovery.state='SUPERSEDED' THEN
        IF factor.state<>'REVOKED' OR factor.enrollment_outcome NOT IN ('CANCELLED','EXPIRED') OR factor.revoked_at<>recovery.completed_at
            OR child.state NOT IN ('CANCELLED','EXPIRED') OR child.completed_at>recovery.completed_at
            OR NOT EXISTS(SELECT 1 FROM iam.authenticator_recoveries r WHERE r.tenant_id=tenant AND r.user_id=recovery.user_id
                AND r.id=recovery.superseded_by AND r.old_batch_id=batch.id AND r.previous_revision=recovery.revision AND r.created_at=recovery.completed_at) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery replacement differs';
        END IF;
    ELSIF factor.state<>'PENDING' OR child.state NOT IN ('PENDING','CANCELLED','EXPIRED') THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='unfinished recovery has an invalid factor';
    END IF;
    SELECT n.* INTO notice FROM iam.security_notifications n WHERE n.tenant_id=tenant AND n.event_id=recovery.started_event_id AND n.kind='RECOVERY_STARTED';
    IF NOT FOUND OR (notice.user_id,notice.installation_id,notice.created_at,notice.contact_revision)
        IS DISTINCT FROM (recovery.user_id,factor.installation_id,recovery.created_at,1::bigint)
        OR NOT EXISTS(SELECT 1 FROM iam.notification_contact_verifications v WHERE v.tenant_id=tenant AND v.id=notice.verification_id
            AND v.user_id=recovery.user_id AND v.state='VERIFIED' AND v.email=notice.email) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='recovery notice differs';
    END IF;
    RETURN NULL;
END $function$;
DO $recovery_integrity$
DECLARE relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['authenticator_recoveries','mfa_recovery_batches','mfa_recovery_codes','totp_authenticators',
        'authentication_challenges','user_mfa_states','audit_outbox'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS verify_authenticator_recovery ON iam.%I',relation_name);
        EXECUTE format('CREATE CONSTRAINT TRIGGER verify_authenticator_recovery AFTER INSERT OR UPDATE ON iam.%I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.verify_authenticator_recovery()',relation_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER verify_authenticator_recovery',relation_name);
    END LOOP;
END $recovery_integrity$;
REVOKE ALL ON FUNCTION iam.lock_recovery_batch(text,text),iam.lock_recovery_login(text,text,text),iam.lock_recovery_challenge(text,text,text),
    iam.lock_mfa_attempt(text,text,text,text,text,text,bigint),iam.read_recovery_attempt(text,text,text,text,bigint),
    iam.authenticator_recovery_snapshot(text,text),iam.inspect_authenticator_recovery(text,text,text,text),
    iam.guard_recovery_material(),iam.guard_authenticator_recovery(),iam.assert_recovery_codes(text,text,jsonb),iam.verify_authenticator_recovery(),
    iam.start_authenticator_recovery(text,text,text,text,bigint,text,text,text,text,text,text,text,text,bytea,bytea,text,jsonb),
    iam.confirm_authenticator_recovery(text,text,text,text,bigint,bigint,text,jsonb,text,jsonb)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker;
GRANT EXECUTE ON FUNCTION iam.read_recovery_attempt(text,text,text,text,bigint),iam.inspect_authenticator_recovery(text,text,text,text),
    iam.start_authenticator_recovery(text,text,text,text,bigint,text,text,text,text,text,text,text,text,bytea,bytea,text,jsonb),
    iam.confirm_authenticator_recovery(text,text,text,text,bigint,bigint,text,jsonb,text,jsonb) TO matrix_iam_api;


-- Readiness and migration verification share this concrete authentication
-- contract. Custody alone cannot prove challenge isolation, one-time effects,
-- or the meaning and immutability of a Session's authentication facts.
CREATE OR REPLACE FUNCTION iam.totp_authentication_contract_ready()
RETURNS boolean LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE expected record; column_spec record; entry pg_proc%ROWTYPE; relation_id oid;
BEGIN
    FOR expected IN SELECT * FROM (VALUES
        ('user_mfa_states','tenant_id,user_id,revision,enrollment_state,factor_id,recovery_id','text,text,bigint,text,text,text','factor_id,recovery_id','tenant_id,user_id,factor_id,recovery_id',true),
        ('authentication_challenges','tenant_id,id,user_id,lookup_digest,verification_digest,credential_generation,password_attempt_id,password_attempt_sequence,account_version,principal_version,mfa_revision,factor_id,request_id,request_digest,next_step,source_challenge_id,password_challenge_id,verified_step,password_changed_event_id,password_change_request_id,state,created_at,expires_at,attempts,completed_at,session_id,issuance_event_id,recovery_id',
            'text,text,text,text,text,bigint,text,bigint,bigint,bigint,bigint,text,text,text,text,text,text,bigint,text,text,text,timestamptz,timestamptz,integer,timestamptz,text,text,text',
            'source_challenge_id,password_challenge_id,verified_step,password_changed_event_id,password_change_request_id,completed_at,session_id,issuance_event_id,recovery_id',
            'tenant_id,id,user_id,password_attempt_id,factor_id,request_id,source_challenge_id,password_challenge_id,password_changed_event_id,password_change_request_id,session_id,issuance_event_id,recovery_id',true),
        ('totp_attempts','tenant_id,user_id,attempt_id,sequence,purpose,reference_id,source_session_id,credential_generation,mfa_revision,state,window_started_at,used_attempts,reserved_at,expires_at,completed_at',
            'text,text,text,bigint,text,text,text,bigint,bigint,text,timestamptz,integer,timestamptz,timestamptz,timestamptz',
            'source_session_id,completed_at','tenant_id,user_id,attempt_id,reference_id,source_session_id',true),
        ('mfa_recovery_batches','tenant_id,user_id,id,factor_id,mfa_revision,event_id,created_at,revoked_at,revocation_recovery_id',
            'text,text,text,text,bigint,text,timestamptz,timestamptz,text','revoked_at,revocation_recovery_id','tenant_id,user_id,id,factor_id,event_id,revocation_recovery_id',true),
        ('mfa_recovery_codes','tenant_id,batch_id,id,verification_digest,consumed_at,recovery_id',
            'text,text,text,text,timestamptz,text','consumed_at,recovery_id','tenant_id,batch_id,id,recovery_id',true),
        ('totp_authenticators','enrollment_session_id,enrollment_request_id,enrollment_digest,enrollment_revision,credential_generation,expires_at,enrollment_outcome,completed_at,bound_revision,bound_event_id,revoked_at,recovery_id',
            'text,text,text,bigint,bigint,timestamptz,text,timestamptz,bigint,text,timestamptz,text',
            'enrollment_session_id,enrollment_request_id,enrollment_digest,enrollment_revision,credential_generation,expires_at,enrollment_outcome,completed_at,bound_revision,bound_event_id,revoked_at,recovery_id',
            'enrollment_session_id,enrollment_request_id,bound_event_id,recovery_id',false),
        ('authenticator_recoveries','tenant_id,user_id,id,request_id,request_digest,old_batch_id,code_id,factor_id,source_challenge_id,challenge_id,credential_generation,previous_revision,revision,started_event_id,state,created_at,expires_at,completed_at,completed_event_id,completion_request_id,completion_digest,new_batch_id,superseded_by',
            'text,text,text,text,text,text,text,text,text,text,bigint,bigint,bigint,text,text,timestamptz,timestamptz,timestamptz,text,text,text,text,text',
            'completed_at,completed_event_id,completion_request_id,completion_digest,new_batch_id,superseded_by',
            'tenant_id,user_id,id,request_id,old_batch_id,code_id,factor_id,source_challenge_id,challenge_id,started_event_id,completed_event_id,completion_request_id,new_batch_id,superseded_by',true),
        ('sessions','authentication_method,authenticated_at,mfa_revision','text,timestamptz,bigint',
            'authentication_method,authenticated_at,mfa_revision','',false)
    ) e(relation_name,columns,types,nullable,c_columns,whole_table) LOOP
        relation_id:=to_regclass('iam.'||expected.relation_name);
        IF relation_id IS NULL OR NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=relation_id AND c.relkind='r'
            AND c.relowner='matrix_iam_owner'::regrole AND c.relrowsecurity AND c.relforcerowsecurity) THEN RETURN false; END IF;
        IF expected.whole_table THEN
            IF (SELECT count(*) FROM pg_attribute a WHERE a.attrelid=relation_id AND a.attnum>0 AND NOT a.attisdropped)
                    <>cardinality(string_to_array(expected.columns,','))
                OR (SELECT count(*) FROM pg_policies WHERE schemaname='iam' AND tablename=expected.relation_name)<>1
                OR NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='iam' AND tablename=expected.relation_name
                    AND policyname='tenant_isolation' AND cmd='ALL' AND roles=ARRAY['public']::name[] AND permissive='PERMISSIVE'
                    AND with_check='(tenant_id = iam.current_tenant_id())'
                    AND qual=CASE WHEN expected.relation_name='authentication_challenges'
                        THEN '((tenant_id = iam.current_tenant_id()) OR (current_setting(''matrix.iam_challenge_lookup''::text, true) = ''trusted''::text))'
                        ELSE '(tenant_id = iam.current_tenant_id())' END)
                OR EXISTS(SELECT 1 FROM (VALUES('public'),('matrix_iam_api'),('matrix_iam_worker'),('matrix_iam_credential_recovery'),
                    ('matrix_iam_backup_custody'),('matrix_iam_notification_worker')) r(name)
                    WHERE has_table_privilege(r.name,relation_id,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                        OR has_any_column_privilege(r.name,relation_id,'SELECT,INSERT,UPDATE,REFERENCES'))
                OR EXISTS(SELECT 1 FROM pg_class c, LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
                    WHERE c.oid=relation_id AND a.grantee<>c.relowner) THEN RETURN false; END IF;
        END IF;
        FOR column_spec IN SELECT * FROM unnest(string_to_array(expected.columns,','),string_to_array(expected.types,','))
            c(name,type_name) LOOP
            IF NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=relation_id AND a.attname=column_spec.name
                AND a.attnum>0 AND NOT a.attisdropped AND a.atttypid=to_regtype(column_spec.type_name)
                AND a.attnotnull=(NOT column_spec.name=ANY(string_to_array(expected.nullable,',')))
                AND a.attgenerated='' AND a.attidentity=''
                AND (column_spec.type_name<>'timestamptz' OR a.atttypmod=6)
                AND (NOT column_spec.name=ANY(string_to_array(expected.c_columns,',')) OR a.attcollation='"C"'::regcollation)) THEN RETURN false; END IF;
        END LOOP;
    END LOOP;

    FOR expected IN SELECT * FROM (VALUES
        ('user_mfa_states','p','tenant_id,user_id',NULL::text,NULL::text,false),
        ('user_mfa_states','f','tenant_id,user_id','iam.principals','tenant_id,id',false),
        ('user_mfa_states','f','tenant_id,user_id,factor_id','iam.totp_authenticators','tenant_id,user_id,id',false),
        ('authentication_challenges','p','tenant_id,id',NULL,NULL,false),
        ('authentication_challenges','u','lookup_digest',NULL,NULL,false),
        ('authentication_challenges','u','tenant_id,session_id',NULL,NULL,false),
        ('authentication_challenges','u','tenant_id,source_challenge_id',NULL,NULL,false),
        ('authentication_challenges','u','tenant_id,password_challenge_id',NULL,NULL,false),
        ('authentication_challenges','u','tenant_id,password_changed_event_id',NULL,NULL,false),
        ('authentication_challenges','f','tenant_id,user_id,factor_id','iam.totp_authenticators','tenant_id,user_id,id',false),
        ('authentication_challenges','f','tenant_id,session_id','iam.sessions','tenant_id,id',true),
        ('authentication_challenges','f','tenant_id,issuance_event_id','iam.audit_outbox','tenant_id,event_id',true),
        ('authentication_challenges','f','tenant_id,source_challenge_id','iam.authentication_challenges','tenant_id,id',true),
        ('authentication_challenges','f','tenant_id,password_challenge_id','iam.authentication_challenges','tenant_id,id',true),
        ('authentication_challenges','f','tenant_id,password_changed_event_id','iam.audit_outbox','tenant_id,event_id',true),
        ('totp_attempts','p','tenant_id,user_id',NULL,NULL,false),
        ('totp_attempts','f','tenant_id,user_id','iam.principals','tenant_id,id',false),
        ('totp_attempts','f','tenant_id,source_session_id','iam.sessions','tenant_id,id',false),
        ('mfa_recovery_batches','p','tenant_id,id',NULL,NULL,false),
        ('mfa_recovery_batches','u','tenant_id,event_id',NULL,NULL,false),
        ('mfa_recovery_batches','f','tenant_id,user_id,factor_id','iam.totp_authenticators','tenant_id,user_id,id',false),
        ('mfa_recovery_batches','f','tenant_id,event_id','iam.audit_outbox','tenant_id,event_id',true),
        ('mfa_recovery_codes','p','tenant_id,batch_id,id',NULL,NULL,false),
        ('mfa_recovery_codes','f','tenant_id,batch_id','iam.mfa_recovery_batches','tenant_id,id',false),
        ('totp_authenticators','f','tenant_id,enrollment_session_id','iam.sessions','tenant_id,id',false),
        ('totp_authenticators','f','tenant_id,bound_event_id','iam.audit_outbox','tenant_id,event_id',true),
        ('authenticator_recoveries','p','tenant_id,id',NULL,NULL,false),
        ('authenticator_recoveries','u','tenant_id,user_id,id',NULL,NULL,false),
        ('authenticator_recoveries','u','tenant_id,user_id,revision',NULL,NULL,false),
        ('authenticator_recoveries','u','tenant_id,user_id,request_id',NULL,NULL,false),
        ('authenticator_recoveries','u','tenant_id,old_batch_id,code_id',NULL,NULL,false),
        ('authenticator_recoveries','u','tenant_id,factor_id',NULL,NULL,false),
        ('authenticator_recoveries','u','tenant_id,source_challenge_id',NULL,NULL,false),
        ('authenticator_recoveries','u','tenant_id,challenge_id',NULL,NULL,false),
        ('authenticator_recoveries','u','tenant_id,started_event_id',NULL,NULL,false),
        ('authenticator_recoveries','u','tenant_id,completed_event_id',NULL,NULL,false),
        ('authenticator_recoveries','u','tenant_id,new_batch_id',NULL,NULL,false),
        ('authenticator_recoveries','f','tenant_id,user_id','iam.principals','tenant_id,id',false),
        ('authenticator_recoveries','f','tenant_id,old_batch_id,code_id','iam.mfa_recovery_codes','tenant_id,batch_id,id',false),
        ('authenticator_recoveries','f','tenant_id,user_id,factor_id','iam.totp_authenticators','tenant_id,user_id,id',true),
        ('authenticator_recoveries','f','tenant_id,source_challenge_id','iam.authentication_challenges','tenant_id,id',true),
        ('authenticator_recoveries','f','tenant_id,challenge_id','iam.authentication_challenges','tenant_id,id',true),
        ('authenticator_recoveries','f','tenant_id,started_event_id','iam.audit_outbox','tenant_id,event_id',true),
        ('authenticator_recoveries','f','tenant_id,completed_event_id','iam.audit_outbox','tenant_id,event_id',true),
        ('authenticator_recoveries','f','tenant_id,new_batch_id','iam.mfa_recovery_batches','tenant_id,id',true),
        ('authenticator_recoveries','f','tenant_id,user_id,superseded_by','iam.authenticator_recoveries','tenant_id,user_id,id',true),
        ('user_mfa_states','f','tenant_id,recovery_id','iam.authenticator_recoveries','tenant_id,id',true),
        ('totp_authenticators','f','tenant_id,recovery_id','iam.authenticator_recoveries','tenant_id,id',true),
        ('authentication_challenges','f','tenant_id,recovery_id','iam.authenticator_recoveries','tenant_id,id',true),
        ('mfa_recovery_codes','f','tenant_id,recovery_id','iam.authenticator_recoveries','tenant_id,id',true),
        ('mfa_recovery_batches','f','tenant_id,revocation_recovery_id','iam.authenticator_recoveries','tenant_id,id',true)
    ) e(relation_name,kind,columns,reference_table,reference_columns,deferred) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=to_regclass('iam.'||expected.relation_name)
            AND c.contype::text=expected.kind AND c.convalidated AND c.conenforced
            AND c.condeferrable=expected.deferred AND c.condeferred=expected.deferred
            AND ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(number,position)
                JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.number ORDER BY k.position)=string_to_array(expected.columns,',')
            AND (expected.kind<>'f' OR (c.confrelid=to_regclass(expected.reference_table) AND c.confupdtype='a' AND c.confdeltype='a' AND c.confmatchtype='s'
                AND ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(number,position)
                    JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.number ORDER BY k.position)=string_to_array(expected.reference_columns,',')))) THEN RETURN false; END IF;
    END LOOP;
    FOR expected IN SELECT * FROM (VALUES
        ('user_mfa_states','user_mfa_states_revision_check,user_mfa_states_enrollment_state_check,user_mfa_states_shape,user_mfa_states_never_bound,user_mfa_recovery_shape'),
        ('authenticator_recoveries','authenticator_recoveries_id_check,authenticator_recoveries_request_id_check,authenticator_recoveries_request_digest_check,authenticator_recoveries_credential_generation_check,authenticator_recoveries_previous_revision_check,authenticator_recoveries_revision_check,authenticator_recoveries_state_check,authenticator_recoveries_expires_at_check,authenticator_recovery_completion'),
        ('authentication_challenges','authentication_challenges_id_check,authentication_challenges_lookup_digest_check,authentication_challenges_verification_digest_check,authentication_challenges_credential_generation_check,authentication_challenges_password_attempt_sequence_check,authentication_challenges_account_version_check,authentication_challenges_principal_version_check,authentication_challenges_mfa_revision_check,authentication_challenges_request_id_check,authentication_challenges_request_digest_check,authentication_challenges_next_step_check,authentication_challenges_verified_step_check,authentication_challenges_state_check,authentication_challenges_attempts_check,authentication_challenges_secrets,authentication_challenges_lifetime,authentication_challenges_phase,authentication_challenges_completion'),
        ('totp_attempts','totp_attempts_sequence_check,totp_attempts_purpose_check,totp_attempts_credential_generation_check,totp_attempts_mfa_revision_check,totp_attempts_state_check,totp_attempts_used_attempts_check,totp_attempts_source,totp_attempts_lease,totp_attempts_completion'),
        ('mfa_recovery_batches','mfa_recovery_batches_mfa_revision_check,recovery_revocation_shape'),
        ('mfa_recovery_codes','mfa_recovery_codes_verification_digest_check,recovery_consumption_shape'),
        ('totp_authenticators','totp_enrollment_lineage'),
        ('sessions','session_authentication_fact')
    ) e(relation_name,names) LOOP
        IF EXISTS(SELECT 1 FROM unnest(string_to_array(expected.names,',')) n(name)
            WHERE NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=to_regclass('iam.'||expected.relation_name)
                AND c.conname=n.name AND c.contype='c' AND c.convalidated AND c.conenforced)) THEN RETURN false; END IF;
    END LOOP;
    FOR expected IN SELECT * FROM (VALUES
        ('totp_authenticators','totp_one_active','tenant_id,user_id',true,'(state = ''ACTIVE''::text)'),
        ('totp_authenticators','totp_one_pending','tenant_id,user_id',true,'(state = ''PENDING''::text)'),
        ('totp_authenticators','totp_factor_user_identity','tenant_id,user_id,id',true,NULL),
        ('totp_authenticators','totp_enrollment_intent','tenant_id,user_id,enrollment_request_id',true,'(enrollment_request_id IS NOT NULL)'),
        ('totp_authenticators','totp_unrecognized_lineage','id',false,'((enrollment_session_id IS NULL) AND (recovery_id IS NULL))'),
        ('authenticator_recoveries','authenticator_one_recovery','tenant_id,user_id',true,'(state = ''STARTED''::text)'),
        ('authentication_challenges','authentication_challenges_user','tenant_id,user_id,expires_at',false,'(state = ''PENDING''::text)'),
        ('mfa_recovery_batches','mfa_one_recovery_batch','tenant_id,user_id',true,'(revoked_at IS NULL)')
    ) e(relation_name,name,columns,unique_key,predicate) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_index i JOIN pg_class index_class ON index_class.oid=i.indexrelid
            JOIN pg_am method ON method.oid=index_class.relam
            WHERE i.indexrelid=to_regclass('iam.'||expected.name) AND i.indrelid=to_regclass('iam.'||expected.relation_name)
            AND i.indisvalid AND i.indisready AND i.indislive AND i.indisunique=expected.unique_key AND i.indexprs IS NULL
            AND i.indnkeyatts=cardinality(string_to_array(expected.columns,',')) AND i.indnatts=i.indnkeyatts AND method.amname='btree'
            AND pg_get_expr(i.indpred,i.indrelid) IS NOT DISTINCT FROM expected.predicate
            AND ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(number,position)
                JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.number ORDER BY k.position)=string_to_array(expected.columns,',')) THEN RETURN false; END IF;
    END LOOP;
    FOR expected IN SELECT * FROM (
        SELECT relation_name,'cannot_delete'::text AS name,'iam.reject_policy_history_change()'::text AS signature,11 AS event_type,false AS deferred
            FROM unnest(ARRAY['user_mfa_states','authentication_challenges','totp_attempts','mfa_recovery_batches','mfa_recovery_codes','authenticator_recoveries']) r(relation_name)
        UNION ALL SELECT relation_name,'cannot_truncate','iam.reject_policy_history_change()',34,false
            FROM unnest(ARRAY['user_mfa_states','authentication_challenges','totp_attempts','mfa_recovery_batches','mfa_recovery_codes','authenticator_recoveries']) r(relation_name)
        UNION ALL SELECT relation_name,'verify_authenticator_recovery','iam.verify_authenticator_recovery()',21,true
            FROM unnest(ARRAY['authenticator_recoveries','mfa_recovery_batches','mfa_recovery_codes','totp_authenticators','authentication_challenges','user_mfa_states','audit_outbox','security_notifications']) r(relation_name)
        UNION ALL SELECT * FROM (VALUES
            ('principals','initialize_mfa','iam.initialize_user_mfa_state()',5,false),
            ('user_mfa_states','guard_transition','iam.guard_user_mfa_transition()',19,false),
            ('totp_authenticators','cannot_update','iam.guard_totp_transition()',19,false),
            ('mfa_recovery_batches','cannot_update','iam.guard_recovery_material()',19,false),
            ('mfa_recovery_codes','cannot_update','iam.guard_recovery_material()',19,false),
            ('authenticator_recoveries','cannot_update','iam.guard_authenticator_recovery()',19,false),
            ('sessions','authentication_fact_is_immutable','iam.guard_session_authentication()',19,false),
            ('authentication_challenges','cannot_update','iam.guard_authentication_challenge()',19,false),
            ('totp_authenticators','verify_totp_binding','iam.verify_totp_binding()',21,true),
            ('audit_outbox','verify_totp_binding','iam.verify_totp_binding()',21,true),
            ('mfa_recovery_batches','verify_totp_binding','iam.verify_totp_binding()',21,true),
            ('mfa_recovery_codes','verify_totp_binding','iam.verify_totp_binding()',21,true),
            ('security_notifications','verify_totp_binding','iam.verify_totp_binding()',21,true),
            ('authentication_challenges','verify_challenge_session','iam.verify_challenge_session()',21,true),
            ('sessions','verify_challenge_session','iam.verify_challenge_session()',21,true)
        ) t(relation_name,name,signature,event_type,deferred)
    ) e LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=to_regclass('iam.'||expected.relation_name) AND t.tgname=expected.name
            AND NOT t.tgisinternal AND t.tgenabled='A' AND t.tgfoid=to_regprocedure(expected.signature) AND t.tgtype=expected.event_type
            AND t.tgdeferrable=expected.deferred AND t.tginitdeferred=expected.deferred AND t.tgqual IS NULL) THEN RETURN false; END IF;
    END LOOP;

    FOR expected IN SELECT * FROM (VALUES
        ('iam.lock_recovery_batch(text,text)',false,'iam.mfa_recovery_batches','v','tenant,subject_id'),
        ('iam.lock_recovery_login(text,text,text)',false,'iam.authentication_challenges','v','tenant,subject_id,challenge_id'),
        ('iam.lock_recovery_challenge(text,text,text)',false,'iam.totp_authenticators','v','tenant,subject_id,challenge_id'),
        ('iam.lock_mfa_attempt(text,text,text,text,text,text,bigint)',false,'iam.totp_attempts','v','tenant,subject_id,caller_id,reference_id,purpose,attempt_id,attempt_sequence'),
        ('iam.read_recovery_attempt(text,text,text,text,bigint)',true,'jsonb','v','tenant,subject_id,challenge_id,attempt_id,attempt_sequence'),
        ('iam.authenticator_recovery_snapshot(text,text)',false,'jsonb','s','tenant,recovery_id'),
        ('iam.inspect_authenticator_recovery(text,text,text,text)',true,'jsonb','v','tenant,subject_id,challenge_id,request_id'),
        ('iam.guard_recovery_material()',false,'trigger','v',''),
        ('iam.guard_authenticator_recovery()',false,'trigger','v',''),
        ('iam.assert_recovery_codes(text,text,jsonb)',false,'void','v','batch_id,notification_id,recovery_codes'),
        ('iam.verify_authenticator_recovery()',false,'trigger','v',''),
        ('iam.start_authenticator_recovery(text,text,text,text,bigint,text,text,text,text,text,text,text,text,bytea,bytea,text,jsonb)',true,'jsonb','v','tenant,subject_id,source_id,attempt_id,attempt_sequence,code_id,code_digest,recovery_id,factor_id,challenge_id,lookup_digest,verification_digest,key_id,nonce,ciphertext,notification_id,audit_event'),
        ('iam.confirm_authenticator_recovery(text,text,text,text,bigint,bigint,text,jsonb,text,jsonb)',true,'jsonb','v','tenant,subject_id,challenge_id,attempt_id,attempt_sequence,verified_step,batch_id,recovery_codes,notification_id,audit_event'),
        ('iam.login_authentication_state(text,text)',true,'jsonb','v','tenant,subject_id'),
        ('iam.read_authenticator_state(text,text,text)',true,'jsonb','v','tenant,subject_id,caller_id'),
        ('iam.start_totp_enrollment(text,text,text,bigint,text,text,text,bigint,text,text,text,text,bytea,bytea)',true,'jsonb','v','tenant,subject_id,caller_id,expected_revision,request_id,intent_digest,attempt,attempt_sequence,factor_id,installation,bootstrap_digest,key_id,nonce,ciphertext'),
        ('iam.read_totp_enrollment(text,text,text,text)',true,'jsonb','v','tenant,subject_id,caller_id,factor'),
        ('iam.read_totp_enrollment_by_request(text,text,text,text)',true,'jsonb','v','tenant,subject_id,caller_id,request_id'),
        ('iam.cancel_totp_enrollment(text,text,text,text)',true,'jsonb','v','tenant,subject_id,caller_id,factor'),
        ('iam.create_login_challenge(text,text,text,bigint,text,text,text,text,text)',true,'jsonb','v','tenant,subject_id,attempt,attempt_sequence,challenge_id,lookup_digest,verification_digest,request_id,request_digest'),
        ('iam.lookup_authentication_challenge(text)',true,'jsonb','v','submitted_lookup'),
        ('iam.reserve_totp_attempt(text,text,text,text,text,text)',true,'jsonb','v','tenant,subject_id,caller_id,reference_id,purpose,attempt_id'),
        ('iam.read_totp_attempt(text,text,text,text,text,text,bigint)',true,'jsonb','v','tenant,subject_id,caller_id,reference_id,purpose,attempt_id,attempt_sequence'),
        ('iam.reject_totp_attempt(text,text,text,bigint)',true,'void','v','tenant,subject_id,attempt_id,attempt_sequence'),
        ('iam.confirm_totp_enrollment(text,text,text,text,text,bigint,bigint,text,jsonb,text,jsonb)',true,'jsonb','v','tenant,subject_id,caller_id,factor_id,attempt_id,attempt_sequence,verified_step,batch_id,recovery_codes,notification_id,audit_event'),
        ('iam.complete_login_challenge(text,text,text,text,bigint,bigint,text,text,text,integer,jsonb)',true,'TABLE(issued_at timestamp with time zone, expires_at timestamp with time zone)','v','tenant,subject_id,challenge_id,attempt_id,attempt_sequence,verified_step,session_id,lookup_digest,verification_digest,lifetime_seconds,audit_event,issued_at,expires_at'),
        ('iam.begin_password_challenge(text,text,text,text,bigint,bigint,text,text,text,text,text)',true,'jsonb','v','tenant,subject_id,challenge_id,attempt_id,attempt_sequence,verified_step,password_challenge_id,lookup_digest,verification_digest,request_id,request_digest'),
        ('iam.read_password_challenge(text,text,text)',true,'TABLE(password_hash text, credential_generation bigint)','v','tenant,subject_id,challenge_id,password_hash,credential_generation'),
        ('iam.change_challenge_password(text,text,text,bigint,text,text,jsonb)',true,'timestamp with time zone','v','tenant,subject_id,challenge_id,expected_generation,expected_password_hash,new_password_hash,audit_event'),
        ('iam.initialize_user_mfa_state()',false,'trigger','v',''),
        ('iam.lock_mfa_user(text,text)',false,'iam.user_mfa_states','v','tenant,subject_id'),
        ('iam.session_mfa_eligible(text,text,text)',false,'boolean','s','tenant,subject_id,session_id'),
        ('iam.guard_totp_transition()',false,'trigger','v',''),
        ('iam.guard_user_mfa_transition()',false,'trigger','v',''),
        ('iam.lock_mfa_session(text,text,text)',false,'bigint','v','tenant,subject_id,caller_id'),
        ('iam.totp_enrollment_snapshot(text,text)',false,'jsonb','s','tenant,factor'),
        ('iam.lock_totp_verification(text,text,text,text,text)',false,'iam.totp_authenticators','v','tenant,subject_id,caller_id,reference_id,purpose'),
        ('iam.consume_totp_attempt(text,text,text,text,text,text,bigint,bigint)',false,'iam.totp_authenticators','v','tenant,subject_id,caller_id,reference_id,purpose,attempt_id,attempt_sequence,verified_step'),
        ('iam.lock_password_challenge(text,text,text)',false,'iam.authentication_challenges','v','tenant,subject_id,challenge_id'),
        ('iam.verify_totp_binding()',false,'trigger','v',''),
        ('iam.guard_session_authentication()',false,'trigger','v',''),
        ('iam.guard_authentication_challenge()',false,'trigger','v',''),
        ('iam.verify_challenge_session()',false,'trigger','v',''),
        ('iam.totp_authentication_contract_ready()',false,'boolean','s','')
    ) e(signature,api_callable,result_type,volatility,names) LOOP
        SELECT p.* INTO entry FROM pg_proc p WHERE p.oid=to_regprocedure(expected.signature);
        IF NOT FOUND THEN RETURN false; END IF;
        IF entry.proowner<>'matrix_iam_owner'::regrole OR entry.prosecdef<>expected.api_callable
            OR entry.proretset<>(left(expected.result_type,6)='TABLE(')
            OR pg_get_function_result(entry.oid)<>expected.result_type OR entry.prokind<>'f'
            OR entry.proargnames IS DISTINCT FROM (CASE WHEN expected.names='' THEN NULL ELSE string_to_array(expected.names,',') END)
            OR entry.pronargdefaults<>0 OR entry.provariadic<>0 OR entry.proisstrict OR entry.proleakproof
            OR entry.provolatile::text<>expected.volatility OR entry.proparallel<>'u'
            OR entry.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']
            OR has_function_privilege('matrix_iam_api',entry.oid,'EXECUTE')<>expected.api_callable
            OR EXISTS(SELECT 1 FROM (VALUES('public'),('matrix_iam_worker'),('matrix_iam_credential_recovery'),
                ('matrix_iam_backup_custody'),('matrix_iam_notification_worker')) r(name)
                WHERE has_function_privilege(r.name,entry.oid,'EXECUTE'))
            OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(entry.proacl,acldefault('f',entry.proowner))) permission
                WHERE permission.grantee<>entry.proowner
                    AND (NOT expected.api_callable OR permission.grantee<>'matrix_iam_api'::regrole OR permission.is_grantable))
            OR (SELECT count(*) FROM pg_proc p WHERE p.pronamespace=entry.pronamespace AND p.proname=entry.proname)<>1 THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END $function$;
REVOKE ALL ON FUNCTION iam.totp_authentication_contract_ready()
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker;
