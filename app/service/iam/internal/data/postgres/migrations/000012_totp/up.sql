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

-- Actual encrypted seed storage is distinct from its wrapping registry. This
-- preparation executable refuses EVERY retained factor row, not just ACTIVE.
-- There is deliberately no runtime mutation grant/enrollment function yet.
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
    SELECT EXISTS(SELECT 1 FROM iam.totp_authenticators) INTO has_authenticators;
    PERFORM set_config('matrix.iam_totp_custody',COALESCE(prior_custody_scope,''),true);
    RETURN jsonb_build_object('keyset',registration,'hasAuthenticators',has_authenticators);
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
        OR (SELECT schema_version FROM iam.readiness())<>36 THEN
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
        AND (SELECT count(*)=9 FROM pg_catalog.pg_trigger t WHERE t.tgrelid IN (
            to_regclass('iam.totp_wrapping_registry'),to_regclass('iam.totp_keysets'),to_regclass('iam.totp_authenticators'))
            AND t.tgname IN ('cannot_update','cannot_delete','cannot_truncate') AND t.tgenabled='A'
            AND t.tgfoid=to_regprocedure('iam.reject_policy_history_change()'))
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
