SET LOCAL ROLE matrix_iam_owner;

-- Credential lookup indexes are deliberately separate from account ownership.
-- They contain no secrets and have no PUBLIC or runtime table grants.
DO $login_index_key_cutover$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint AS pk
        WHERE pk.conrelid='iam.login_index'::regclass AND pk.contype='p'
          AND (SELECT array_agg(attribute.attname ORDER BY key.ordinality)
               FROM unnest(pk.conkey) WITH ORDINALITY AS key(attnum,ordinality)
               JOIN pg_catalog.pg_attribute AS attribute
                 ON attribute.attrelid=pk.conrelid AND attribute.attnum=key.attnum)
              = ARRAY['tenant_id','login_name']::name[]
    ) THEN
        IF to_regclass('iam.account_roots') IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM login index conflicts with root relation';
        END IF;
        ALTER TABLE iam.login_index DROP CONSTRAINT IF EXISTS login_index_pkey;
        ALTER TABLE iam.login_index ADD PRIMARY KEY (tenant_id, login_name);
    END IF;
END $login_index_key_cutover$;

CREATE TABLE IF NOT EXISTS iam.account_roots (
    account_id text COLLATE "C" PRIMARY KEY REFERENCES iam.accounts(id),
    principal_id text COLLATE "C" NOT NULL,
    login_name text COLLATE "C" NOT NULL UNIQUE,
    CONSTRAINT account_roots_principal_fk FOREIGN KEY(account_id,principal_id)
        REFERENCES iam.principals(tenant_id,id),
    CONSTRAINT account_roots_login_fk FOREIGN KEY(account_id,login_name)
        REFERENCES iam.login_index(tenant_id,login_name),
    CONSTRAINT account_roots_values_valid CHECK (
        account_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND principal_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND login_name COLLATE "C" ~ '^[a-z][a-z0-9._-]{2,63}$')
);

-- The migration owner must inspect every retained Account and USER while the
-- old tables already enforce tenant RLS. These policies exist only inside the
-- surrounding migration transaction and are removed before commit.
DROP POLICY IF EXISTS account_root_cutover_owner_read ON iam.accounts;
CREATE POLICY account_root_cutover_owner_read ON iam.accounts
    FOR SELECT TO matrix_iam_owner USING (true);
DROP POLICY IF EXISTS account_root_cutover_owner_read ON iam.principals;
CREATE POLICY account_root_cutover_owner_read ON iam.principals
    FOR SELECT TO matrix_iam_owner USING (true);

DO $root_relation_cutover$
BEGIN
    IF EXISTS(SELECT 1 FROM pg_catalog.pg_attribute
        WHERE attrelid='iam.login_index'::regclass AND attname='account_owner' AND NOT attisdropped) THEN
        EXECUTE 'INSERT INTO iam.account_roots(account_id,principal_id,login_name)
            SELECT tenant_id,principal_id,login_name FROM iam.login_index WHERE account_owner
            ON CONFLICT(account_id) DO NOTHING';
        IF EXISTS(SELECT 1 FROM iam.login_index AS login WHERE login.account_owner
            AND NOT EXISTS(SELECT 1 FROM iam.account_roots AS root
                WHERE root.account_id=login.tenant_id AND root.principal_id=login.principal_id
                    AND root.login_name=login.login_name)) THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM root relation conflicts';
        END IF;
        DROP INDEX IF EXISTS iam.login_primary_name_uq;
        DROP INDEX IF EXISTS iam.login_primary_tenant_uq;
        ALTER TABLE iam.login_index DROP COLUMN account_owner;
    END IF;

    -- The original single-account release predates account_owner. Its sealed
    -- bootstrap receipt is the authoritative relation between the home
    -- Account and original primary USER; the login index supplies only that
    -- USER's immutable login name.
    INSERT INTO iam.account_roots(account_id,principal_id,login_name)
    SELECT receipt.organization_id,receipt.administrator_principal_id,login.login_name
      FROM iam.bootstrap_receipts AS receipt
      JOIN iam.login_index AS login
        ON login.tenant_id=receipt.organization_id
       AND login.principal_id=receipt.administrator_principal_id
      JOIN iam.principals AS principal
        ON principal.tenant_id=login.tenant_id AND principal.id=login.principal_id
       AND principal.principal_type='USER' AND principal.login_name=login.login_name
    ON CONFLICT(account_id) DO NOTHING;

    IF EXISTS (
        SELECT 1 FROM iam.bootstrap_receipts AS receipt
        LEFT JOIN iam.account_roots AS root ON root.account_id=receipt.organization_id
        WHERE root.principal_id IS DISTINCT FROM receipt.administrator_principal_id
    ) OR EXISTS (
        SELECT 1 FROM iam.accounts AS account
        LEFT JOIN iam.account_roots AS root ON root.account_id=account.id
        WHERE root.account_id IS NULL
    ) OR EXISTS (
        SELECT 1 FROM iam.account_roots AS root
        JOIN iam.principals AS principal
          ON principal.tenant_id=root.account_id AND principal.id=root.principal_id
        LEFT JOIN iam.login_index AS login
          ON login.tenant_id=root.account_id AND login.principal_id=root.principal_id
         AND login.login_name=root.login_name
        WHERE principal.principal_type<>'USER' OR principal.login_name<>root.login_name
           OR login.principal_id IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM root relation is incomplete or conflicts';
    END IF;
END $root_relation_cutover$;

DROP POLICY account_root_cutover_owner_read ON iam.principals;
DROP POLICY account_root_cutover_owner_read ON iam.accounts;

-- The pre-settings source had no account-wide MFA switch. Establish its
-- explicit initial value once; equal replay must not repair damaged settings.
DO $account_security_settings$
DECLARE columns_present integer; tenant text; prior_tenant text:=current_setting('matrix.iam_tenant_id',true);
BEGIN
    SELECT count(*) INTO columns_present FROM pg_catalog.pg_attribute
    WHERE attrelid='iam.accounts'::regclass AND NOT attisdropped
      AND attname IN ('security_settings_version','mfa_required_for_users','security_settings_updated_at');
    IF columns_present=0 THEN
        IF to_regprocedure('iam.read_account_security_settings(text,text,text)') IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM security settings authority is missing';
        END IF;
        ALTER TABLE iam.accounts ADD COLUMN security_settings_version bigint NOT NULL DEFAULT 1;
        ALTER TABLE iam.accounts ADD COLUMN mfa_required_for_users boolean NOT NULL DEFAULT false;
        ALTER TABLE iam.accounts ADD COLUMN security_settings_updated_at timestamptz(6);
        FOR tenant IN SELECT r.account_id FROM iam.account_roots r ORDER BY r.account_id COLLATE "C" LOOP
            PERFORM set_config('matrix.iam_tenant_id',tenant,true);
            UPDATE iam.accounts SET security_settings_updated_at=created_at WHERE id=tenant;
        END LOOP;
        ALTER TABLE iam.accounts ALTER COLUMN security_settings_updated_at SET NOT NULL;
        ALTER TABLE iam.accounts ADD CONSTRAINT account_security_settings_initial CHECK(
            security_settings_version=1 AND NOT mfa_required_for_users
            AND security_settings_updated_at=created_at AND isfinite(security_settings_updated_at));
        PERFORM set_config('matrix.iam_tenant_id',COALESCE(prior_tenant,''),true);
    ELSIF columns_present<>3 THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM security settings authority is incomplete';
    END IF;
END $account_security_settings$;

ALTER TABLE iam.accounts DROP CONSTRAINT IF EXISTS account_security_settings_initial;
ALTER TABLE iam.accounts DROP CONSTRAINT IF EXISTS account_security_settings_values;
ALTER TABLE iam.accounts ADD CONSTRAINT account_security_settings_values CHECK(
    security_settings_version BETWEEN 1 AND 9007199254740991 AND isfinite(security_settings_updated_at)
    AND security_settings_updated_at>=created_at
    AND (security_settings_version<>1 OR (NOT mfa_required_for_users AND security_settings_updated_at=created_at)));

-- This immutable completion is the settings lineage, not a general receipt.
-- Its StepUp foreign key is added by the existing MFA migration after that
-- table exists on a clean installation.
CREATE TABLE IF NOT EXISTS iam.account_security_settings_changes (
    tenant_id text COLLATE "C" NOT NULL REFERENCES iam.accounts(id),
    user_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    step_up_id text COLLATE "C" NOT NULL,
    source_session_id text COLLATE "C" NOT NULL,
    expected_version bigint NOT NULL CHECK(expected_version BETWEEN 1 AND 9007199254740990),
    previous_required_for_users boolean NOT NULL,
    required_for_users boolean NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    decision_id text COLLATE "C" NOT NULL,
    request_digest text NOT NULL CHECK(request_digest ~ '^sha256:[0-9a-f]{64}$'),
    created_at timestamptz(6) NOT NULL CHECK(isfinite(created_at)),
    PRIMARY KEY(tenant_id,user_id,request_id),
    UNIQUE(tenant_id,expected_version),
    UNIQUE(tenant_id,step_up_id),
    UNIQUE(tenant_id,event_id),
    CHECK(previous_required_for_users<>required_for_users),
    FOREIGN KEY(tenant_id,user_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(tenant_id,source_session_id) REFERENCES iam.sessions(tenant_id,id),
    FOREIGN KEY(tenant_id,decision_id) REFERENCES iam.authorization_decisions(tenant_id,id),
    FOREIGN KEY(tenant_id,event_id) REFERENCES iam.audit_outbox(tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE iam.account_security_settings_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.account_security_settings_changes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON iam.account_security_settings_changes;
CREATE POLICY tenant_isolation ON iam.account_security_settings_changes
    USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id());
REVOKE ALL ON iam.account_security_settings_changes FROM PUBLIC,matrix_iam_api,matrix_iam_worker,
    matrix_iam_notification_worker,matrix_iam_credential_recovery,matrix_iam_authentication_recovery,matrix_iam_backup_custody;
DO $immutable_settings$
DECLARE operation_name text;
BEGIN
    FOREACH operation_name IN ARRAY ARRAY['update','delete','truncate'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS cannot_%s ON iam.account_security_settings_changes',operation_name);
        EXECUTE format('CREATE TRIGGER cannot_%s BEFORE %s ON iam.account_security_settings_changes FOR EACH %s EXECUTE FUNCTION iam.reject_policy_history_change()',
            operation_name,upper(operation_name),CASE WHEN operation_name='truncate' THEN 'STATEMENT' ELSE 'ROW' END);
        EXECUTE format('ALTER TABLE iam.account_security_settings_changes ENABLE ALWAYS TRIGGER cannot_%s',operation_name);
    END LOOP;
END $immutable_settings$;

-- Creation stays 1/false. Updates must already have their exact same-transaction
-- completion; the deferred proof below also checks consumed StepUp and outbox.
CREATE OR REPLACE FUNCTION iam.guard_account_security_settings()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.security_settings_version IS DISTINCT FROM 1 OR NEW.mfa_required_for_users IS DISTINCT FROM false
           OR NEW.security_settings_updated_at IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM initial security settings are invalid';
        END IF;
        NEW.security_settings_updated_at:=NEW.created_at;
    ELSIF ROW(NEW.security_settings_version,NEW.mfa_required_for_users,NEW.security_settings_updated_at)
        IS DISTINCT FROM ROW(OLD.security_settings_version,OLD.mfa_required_for_users,OLD.security_settings_updated_at) THEN
        IF NEW.security_settings_version<>OLD.security_settings_version+1
            OR NEW.mfa_required_for_users=OLD.mfa_required_for_users
            OR NEW.security_settings_updated_at IS DISTINCT FROM transaction_timestamp()
            OR NOT EXISTS(SELECT 1 FROM iam.account_security_settings_changes c WHERE c.tenant_id=NEW.id
                AND c.expected_version=OLD.security_settings_version AND c.previous_required_for_users=OLD.mfa_required_for_users
                AND c.required_for_users=NEW.mfa_required_for_users AND c.created_at=NEW.security_settings_updated_at) THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='IAM security settings mutation has no completion';
        END IF;
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS guard_security_settings ON iam.accounts;
CREATE TRIGGER guard_security_settings BEFORE INSERT OR UPDATE ON iam.accounts
    FOR EACH ROW EXECUTE FUNCTION iam.guard_account_security_settings();
ALTER TABLE iam.accounts ENABLE ALWAYS TRIGGER guard_security_settings;

CREATE OR REPLACE FUNCTION iam.read_account_security_settings(tenant text,actor text,decision text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.accounts%ROWTYPE;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.security-settings.read','ACCOUNT',tenant,'INSTANCE',NULL);
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    SELECT a.* INTO stored FROM iam.accounts a WHERE a.id=tenant AND a.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='IAM account is unavailable'; END IF;
    IF stored.security_settings_version IS NULL OR stored.security_settings_version NOT BETWEEN 1 AND 9007199254740991
       OR NOT isfinite(stored.security_settings_updated_at) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM security settings authority is invalid';
    END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AccountSecuritySettings',
        'accountId',stored.id,'resourceVersion',stored.security_settings_version,
        'mfa',jsonb_build_object('requiredForUsers',stored.mfa_required_for_users),
        'updatedAt',to_char(stored.security_settings_updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $function$;

CREATE OR REPLACE FUNCTION iam.security_settings_change_snapshot(tenant text,actor text,command_id text)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AccountSecuritySettingsChange',
        'requestId',c.request_id,'expectedResourceVersion',c.expected_version,'callerSessionEnded',true,
        'settings',jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AccountSecuritySettings',
            'accountId',c.tenant_id,'resourceVersion',c.expected_version+1,'mfa',jsonb_build_object('requiredForUsers',c.required_for_users),
            'updatedAt',to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')))
    FROM iam.account_security_settings_changes c WHERE c.tenant_id=tenant AND c.user_id=actor AND c.request_id=command_id
$function$;

CREATE OR REPLACE FUNCTION iam.assert_security_settings_change(tenant text,actor text,command_id text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.account_security_settings_changes%ROWTYPE; proof record; current_account iam.accounts%ROWTYPE; fact jsonb; notice record;
BEGIN
    SELECT * INTO receipt FROM iam.account_security_settings_changes c WHERE c.tenant_id=tenant AND c.user_id=actor AND c.request_id=command_id;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='settings completion is missing'; END IF;
    SELECT * INTO proof FROM iam.step_ups p WHERE p.tenant_id=tenant AND p.id=receipt.step_up_id;
    IF NOT FOUND OR (proof.user_id,proof.request_id,proof.source_session_id,proof.operation,proof.state,proof.consumed_at,
        proof.expected_settings_version,proof.required_for_users) IS DISTINCT FROM
        (actor,command_id,receipt.source_session_id,'SECURITY_SETTINGS_UPDATE'::text,'CONSUMED'::text,receipt.created_at,
         receipt.expected_version,receipt.required_for_users)
        OR NOT EXISTS(SELECT 1 FROM iam.sessions s WHERE s.tenant_id=tenant AND s.id=receipt.source_session_id
            AND s.principal_id=actor AND s.credential_version=proof.credential_generation
            AND s.authentication_method='PASSWORD_TOTP' AND s.mfa_revision=proof.mfa_revision
            AND s.security_settings_version=receipt.expected_version) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='settings proof differs';
    END IF;
    SELECT * INTO current_account FROM iam.accounts a WHERE a.id=tenant;
    IF NOT FOUND OR current_account.security_settings_version<receipt.expected_version+1
        OR (current_account.security_settings_version=receipt.expected_version+1 AND
            (current_account.mfa_required_for_users,current_account.security_settings_updated_at)
                IS DISTINCT FROM (receipt.required_for_users,receipt.created_at))
        OR (receipt.expected_version=1 AND receipt.previous_required_for_users)
        OR (receipt.expected_version>1 AND NOT EXISTS(SELECT 1 FROM iam.account_security_settings_changes previous
            WHERE previous.tenant_id=tenant AND previous.expected_version=receipt.expected_version-1
                AND previous.required_for_users=receipt.previous_required_for_users AND previous.created_at<=receipt.created_at)) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='settings lineage differs';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM iam.authorization_decisions d WHERE d.tenant_id=tenant AND d.id=receipt.decision_id
        AND d.principal_id=actor AND d.subject_type='USER' AND d.contract_version=4 AND d.access_key_id IS NULL AND d.allowed
        AND d.action_name='iam.security-settings.update' AND d.target_kind='ACCOUNT' AND d.target_id=tenant
        AND d.resource_mode='INSTANCE' AND d.collection_usage IS NULL AND d.request_id=command_id AND d.decided_at=receipt.created_at) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='settings historical decision differs';
    END IF;
    SELECT o.event_document INTO fact FROM iam.audit_outbox o WHERE o.tenant_id=tenant AND o.event_id=receipt.event_id;
    IF fact IS NULL OR fact->>'action' IS DISTINCT FROM 'iam.security-settings.updated'
        OR fact->>'tenantId' IS DISTINCT FROM tenant OR fact->>'result' IS DISTINCT FROM 'SUCCEEDED'
        OR fact->'actor' IS DISTINCT FROM jsonb_build_object('type','USER','id',actor)
        OR fact->'target' IS DISTINCT FROM jsonb_build_object('kind','ACCOUNT','id',tenant)
        OR fact->>'iamDecisionId' IS DISTINCT FROM receipt.decision_id OR fact->>'requestId' IS DISTINCT FROM command_id
        OR fact->>'correlationId' IS DISTINCT FROM command_id OR fact->>'requestDigest' IS DISTINCT FROM receipt.request_digest
        OR (fact->>'occurredAt')::timestamptz IS DISTINCT FROM receipt.created_at OR fact ?| ARRAY['installationId','operationId'] THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='settings immutable fact differs';
    END IF;
    SELECT n.* INTO notice FROM iam.security_notifications n WHERE n.tenant_id=tenant AND n.id=receipt.event_id;
    IF NOT FOUND OR (notice.user_id,notice.event_id,notice.kind,notice.created_at,notice.contact_revision)
        IS DISTINCT FROM (actor,receipt.event_id,'SECURITY_SETTINGS_CHANGED'::text,receipt.created_at,1::bigint)
        OR notice.installation_id IS DISTINCT FROM (SELECT f.installation_id FROM iam.totp_authenticators f
            WHERE f.tenant_id=tenant AND f.id=proof.factor_id AND f.user_id=actor)
        OR NOT EXISTS(SELECT 1 FROM iam.notification_contact_verifications v WHERE v.tenant_id=tenant AND v.id=notice.verification_id
            AND v.user_id=actor AND v.state='VERIFIED' AND v.email=notice.email AND v.completed_at<=receipt.created_at) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='settings security notice differs';
    END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.verify_security_settings_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE tenant text; actor text; command_id text;
BEGIN
    CASE TG_TABLE_NAME
        WHEN 'accounts' THEN
            IF NEW.security_settings_version=1 THEN RETURN NULL; END IF;
            tenant:=NEW.id;
            PERFORM set_config('matrix.iam_tenant_id',tenant,true);
            SELECT c.user_id,c.request_id INTO actor,command_id FROM iam.account_security_settings_changes c
                WHERE c.tenant_id=tenant AND c.expected_version=NEW.security_settings_version-1;
        WHEN 'account_security_settings_changes' THEN tenant:=NEW.tenant_id; actor:=NEW.user_id; command_id:=NEW.request_id;
        WHEN 'step_ups' THEN
            IF NEW.operation<>'SECURITY_SETTINGS_UPDATE' OR NEW.state<>'CONSUMED' THEN RETURN NULL; END IF;
            tenant:=NEW.tenant_id; actor:=NEW.user_id; command_id:=NEW.request_id;
        WHEN 'audit_outbox' THEN
            IF NEW.event_document->>'action'<>'iam.security-settings.updated' THEN RETURN NULL; END IF;
            tenant:=NEW.tenant_id; actor:=NEW.event_document#>>'{actor,id}'; command_id:=NEW.event_document->>'requestId';
        WHEN 'security_notifications' THEN
            IF NEW.kind<>'SECURITY_SETTINGS_CHANGED' THEN RETURN NULL; END IF;
            tenant:=NEW.tenant_id; actor:=NEW.user_id;
            PERFORM set_config('matrix.iam_tenant_id',tenant,true);
            SELECT c.request_id INTO command_id FROM iam.account_security_settings_changes c
                WHERE c.tenant_id=tenant AND c.user_id=actor AND c.event_id=NEW.event_id;
        ELSE RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='settings proof source is invalid';
    END CASE;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM iam.assert_security_settings_change(tenant,actor,command_id);
    RETURN NULL;
END $function$;
DO $settings_proof$
DECLARE relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['accounts','account_security_settings_changes','audit_outbox'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS verify_security_settings_change ON iam.%I',relation_name);
        EXECUTE format('CREATE CONSTRAINT TRIGGER verify_security_settings_change AFTER INSERT OR UPDATE ON iam.%I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.verify_security_settings_change()',relation_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER verify_security_settings_change',relation_name);
    END LOOP;
END $settings_proof$;

CREATE OR REPLACE FUNCTION iam.lock_account_security_settings(tenant text,actor text,caller text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM iam.assert_authentication_open();
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts a WHERE a.id=tenant AND a.status='ACTIVE' FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='settings account is unavailable'; END IF;
    PERFORM iam.lock_mfa_session(tenant,actor,caller);
    IF (SELECT s.authentication_method FROM iam.sessions s WHERE s.tenant_id=tenant AND s.id=caller) IS DISTINCT FROM 'PASSWORD_TOTP' THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='settings authentication is unavailable';
    END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.update_account_security_settings(tenant text,actor text,caller text,decision text,
    command_id text,proof_id text,expected_version bigint,required_for_users boolean,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE previous iam.account_security_settings_changes%ROWTYPE; stored iam.accounts%ROWTYPE; proof record; contact record; installation text;
BEGIN
    PERFORM iam.lock_account_security_settings(tenant,actor,caller);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.security-settings.update','ACCOUNT',tenant,'INSTANCE',NULL);
    IF command_id IS NULL OR command_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740990 OR required_for_users IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='settings command is invalid';
    END IF;
    SELECT * INTO previous FROM iam.account_security_settings_changes c WHERE c.tenant_id=tenant AND c.user_id=actor AND c.request_id=command_id;
    IF FOUND THEN
        IF (previous.step_up_id,previous.expected_version,previous.required_for_users,previous.request_digest)
            IS DISTINCT FROM (proof_id,expected_version,required_for_users,event->>'requestDigest') THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='settings command differs';
        END IF;
        PERFORM iam.assert_security_settings_change(tenant,actor,command_id);
        RETURN jsonb_build_object('outcome','EQUAL_REPLAY','change',iam.security_settings_change_snapshot(tenant,actor,command_id));
    END IF;
    SELECT * INTO stored FROM iam.accounts a WHERE a.id=tenant;
    IF stored.security_settings_version<>expected_version OR stored.mfa_required_for_users=required_for_users THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='settings version or value differs';
    END IF;
    proof:=iam.lock_step_up(tenant,actor,caller,proof_id);
    IF proof.operation<>'SECURITY_SETTINGS_UPDATE' OR proof.state<>'PROVED' OR proof.request_id IS DISTINCT FROM command_id
        OR proof.expected_settings_version IS DISTINCT FROM expected_version OR proof.required_for_users IS DISTINCT FROM required_for_users
        OR event->>'requestId' IS DISTINCT FROM command_id THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='settings command proof differs';
    END IF;
    -- Audit shape and exact same-transaction decision are checked before any
    -- effect. All following writes, including deferred lineage, commit together.
    SELECT c.* INTO contact FROM iam.notification_contacts c WHERE c.tenant_id=tenant AND c.user_id=actor FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='verified security contact is required'; END IF;
    SELECT f.installation_id INTO installation FROM iam.totp_authenticators f WHERE f.tenant_id=tenant AND f.id=proof.factor_id AND f.user_id=actor;
    PERFORM iam.append_account_event(tenant,actor,decision,'iam.security-settings.updated','ACCOUNT',tenant,event);
    IF proof.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='settings proof expired'; END IF;
    INSERT INTO iam.account_security_settings_changes(tenant_id,user_id,request_id,step_up_id,source_session_id,expected_version,
        previous_required_for_users,required_for_users,event_id,decision_id,request_digest,created_at)
        VALUES(tenant,actor,command_id,proof_id,caller,expected_version,stored.mfa_required_for_users,required_for_users,
            event->>'eventId',decision,event->>'requestDigest',transaction_timestamp());
    UPDATE iam.step_ups p SET state='CONSUMED',consumed_at=transaction_timestamp() WHERE p.tenant_id=tenant AND p.id=proof_id;
    UPDATE iam.accounts a SET security_settings_version=expected_version+1,mfa_required_for_users=required_for_users,
        security_settings_updated_at=transaction_timestamp() WHERE a.id=tenant;
    -- One fixed notice per original fact. Receipt replay returns above and
    -- never chooses a new recipient or creates another notification.
    INSERT INTO iam.security_notifications(tenant_id,id,user_id,installation_id,verification_id,event_id,kind,email,contact_revision,created_at,state,next_attempt_at,updated_at)
        VALUES(tenant,event->>'eventId',actor,installation,contact.verification_id,event->>'eventId','SECURITY_SETTINGS_CHANGED',
            contact.email,contact.resource_version,transaction_timestamp(),'PENDING',transaction_timestamp(),transaction_timestamp());
    RETURN jsonb_build_object('outcome','APPLIED','change',iam.security_settings_change_snapshot(tenant,actor,command_id));
END $function$;

CREATE OR REPLACE FUNCTION iam.read_security_settings_change(tenant text,actor text,decision text,command_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.security-settings.read','ACCOUNT',tenant,'INSTANCE',NULL);
    IF NOT EXISTS(SELECT 1 FROM iam.account_security_settings_changes c WHERE c.tenant_id=tenant AND c.user_id=actor AND c.request_id=command_id) THEN
        RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='settings change was not found';
    END IF;
    PERFORM iam.assert_security_settings_change(tenant,actor,command_id);
    RETURN iam.security_settings_change_snapshot(tenant,actor,command_id);
END $function$;
REVOKE ALL ON FUNCTION iam.security_settings_change_snapshot(text,text,text),iam.assert_security_settings_change(text,text,text),iam.verify_security_settings_change()
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_notification_worker,matrix_iam_credential_recovery,matrix_iam_authentication_recovery,matrix_iam_backup_custody;
REVOKE ALL ON FUNCTION iam.lock_account_security_settings(text,text,text),iam.update_account_security_settings(text,text,text,text,text,text,bigint,boolean,jsonb),
    iam.read_security_settings_change(text,text,text,text)
    FROM PUBLIC,matrix_iam_worker,matrix_iam_notification_worker,matrix_iam_credential_recovery,matrix_iam_authentication_recovery,matrix_iam_backup_custody;
GRANT EXECUTE ON FUNCTION iam.lock_account_security_settings(text,text,text),iam.update_account_security_settings(text,text,text,text,text,text,bigint,boolean,jsonb),
    iam.read_security_settings_change(text,text,text,text) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.account_security_settings_mutation_ready()
RETURNS boolean LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE expected record; entry pg_proc%ROWTYPE; relation_oid oid:=to_regclass('iam.account_security_settings_changes');
    denied_role text;
BEGIN
    IF relation_oid IS NULL OR NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=relation_oid AND c.relkind='r'
        AND c.relowner='matrix_iam_owner'::regrole AND c.relrowsecurity AND c.relforcerowsecurity)
        OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=relation_oid AND p.polname='tenant_isolation'
            AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]) THEN RETURN false; END IF;
    IF (SELECT count(*) FROM pg_attribute a WHERE a.attrelid=relation_oid AND a.attnum>0 AND NOT a.attisdropped)<>12 THEN RETURN false; END IF;
    FOR expected IN SELECT * FROM (VALUES
        ('tenant_id','text',-1),('user_id','text',-1),('request_id','text',-1),('step_up_id','text',-1),('source_session_id','text',-1),
        ('expected_version','bigint',-1),('previous_required_for_users','boolean',-1),('required_for_users','boolean',-1),
        ('event_id','text',-1),('decision_id','text',-1),('request_digest','text',-1),('created_at','timestamptz',6)
    ) e(name,kind,precision) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=relation_oid AND a.attname=expected.name
            AND a.atttypid=expected.kind::regtype AND a.atttypmod=expected.precision AND a.attnotnull AND NOT a.attisdropped)
            THEN RETURN false; END IF;
    END LOOP;
    FOR expected IN SELECT * FROM (VALUES
        ('p','tenant_id,user_id,request_id',NULL,NULL,false),
        ('u','tenant_id,expected_version',NULL,NULL,false),('u','tenant_id,step_up_id',NULL,NULL,false),('u','tenant_id,event_id',NULL,NULL,false),
        ('f','tenant_id','iam.accounts','id',false),('f','tenant_id,user_id','iam.principals','tenant_id,id',false),
        ('f','tenant_id,source_session_id','iam.sessions','tenant_id,id',false),
        ('f','tenant_id,decision_id','iam.authorization_decisions','tenant_id,id',false),
        ('f','tenant_id,event_id','iam.audit_outbox','tenant_id,event_id',true),('f','tenant_id,step_up_id','iam.step_ups','tenant_id,id',false)
    ) e(kind,columns,reference_table,reference_columns,deferred) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=relation_oid AND c.contype::text=expected.kind
            AND c.convalidated AND c.conenforced AND c.condeferrable=expected.deferred AND c.condeferred=expected.deferred
            AND ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(number,position)
                JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.number ORDER BY k.position)=string_to_array(expected.columns,',')
            AND (expected.kind<>'f' OR (c.confrelid=to_regclass(expected.reference_table) AND c.confupdtype='a' AND c.confdeltype='a' AND c.confmatchtype='s'
                AND ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(number,position)
                    JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.number ORDER BY k.position)=string_to_array(expected.reference_columns,',')))) THEN RETURN false; END IF;
    END LOOP;
    IF (SELECT count(*) FROM pg_constraint c WHERE c.conrelid=relation_oid AND c.contype='c' AND c.convalidated AND c.conenforced)<>5 THEN RETURN false; END IF;
    FOR expected IN SELECT * FROM (VALUES ('cannot_update',19),('cannot_delete',11),('cannot_truncate',34)) e(name,kind) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=relation_oid AND t.tgname=expected.name
            AND t.tgenabled='A' AND NOT t.tgisinternal AND t.tgtype=expected.kind AND t.tgnargs=0 AND t.tgqual IS NULL
            AND t.tgfoid=to_regprocedure('iam.reject_policy_history_change()')) THEN RETURN false; END IF;
    END LOOP;
    FOR expected IN SELECT unnest(ARRAY['accounts','account_security_settings_changes','step_ups','audit_outbox','security_notifications']) AS name LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=to_regclass('iam.'||expected.name)
            AND t.tgname='verify_security_settings_change' AND t.tgenabled='A' AND NOT t.tgisinternal
            AND t.tgtype=21 AND t.tgnargs=0 AND t.tgqual IS NULL AND t.tgdeferrable AND t.tginitdeferred
            AND t.tgfoid=to_regprocedure('iam.verify_security_settings_change()')) THEN RETURN false; END IF;
    END LOOP;
    FOR expected IN SELECT * FROM (VALUES
        ('iam.lock_account_security_settings(text,text,text)',true,'void','v','tenant,actor,caller'),
        ('iam.update_account_security_settings(text,text,text,text,text,text,bigint,boolean,jsonb)',true,'jsonb','v','tenant,actor,caller,decision,command_id,proof_id,expected_version,required_for_users,event'),
        ('iam.read_security_settings_change(text,text,text,text)',true,'jsonb','v','tenant,actor,decision,command_id'),
        ('iam.security_settings_change_snapshot(text,text,text)',false,'jsonb','s','tenant,actor,command_id'),
        ('iam.assert_security_settings_change(text,text,text)',false,'void','v','tenant,actor,command_id'),
        ('iam.verify_security_settings_change()',false,'trigger','v','')
    ) e(signature,api,result,volatility,arguments) LOOP
        SELECT * INTO entry FROM pg_proc p WHERE p.oid=to_regprocedure(expected.signature);
        IF NOT FOUND OR entry.proowner<>'matrix_iam_owner'::regrole OR entry.prosecdef<>expected.api OR entry.proretset
            OR entry.prorettype<>expected.result::regtype OR entry.provolatile::text<>expected.volatility OR entry.proparallel<>'u'
            OR COALESCE(entry.proargnames,ARRAY[]::text[])<>string_to_array(expected.arguments,',')
            OR entry.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']::text[]
            OR has_function_privilege('matrix_iam_api',entry.oid,'EXECUTE')<>expected.api THEN RETURN false; END IF;
        FOREACH denied_role IN ARRAY ARRAY['public','matrix_iam_worker','matrix_iam_notification_worker','matrix_iam_credential_recovery','matrix_iam_authentication_recovery','matrix_iam_backup_custody'] LOOP
            IF has_function_privilege(denied_role,entry.oid,'EXECUTE') THEN RETURN false; END IF;
        END LOOP;
    END LOOP;
    FOREACH denied_role IN ARRAY ARRAY['public','matrix_iam_api','matrix_iam_worker','matrix_iam_notification_worker','matrix_iam_credential_recovery','matrix_iam_authentication_recovery','matrix_iam_backup_custody'] LOOP
        IF has_table_privilege(denied_role,relation_oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
            OR has_any_column_privilege(denied_role,relation_oid,'SELECT,INSERT,UPDATE,REFERENCES') THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END $function$;
REVOKE ALL ON FUNCTION iam.account_security_settings_mutation_ready() FROM PUBLIC,matrix_iam_api,matrix_iam_worker,
    matrix_iam_notification_worker,matrix_iam_credential_recovery,matrix_iam_authentication_recovery,matrix_iam_backup_custody;

CREATE OR REPLACE FUNCTION iam.account_security_settings_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT iam.account_security_settings_mutation_ready() AND (SELECT count(*) FROM pg_catalog.pg_attribute a
        JOIN (VALUES ('security_settings_version','bigint'::regtype::oid,-1),
                     ('mfa_required_for_users','boolean'::regtype::oid,-1),
                     ('security_settings_updated_at','timestamptz'::regtype::oid,6)) e(name,kind,precision)
          ON a.attname=e.name AND a.atttypid=e.kind AND a.atttypmod=e.precision
        WHERE a.attrelid='iam.accounts'::regclass AND a.attnotnull AND NOT a.attisdropped)=3
    AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid='iam.accounts'::regclass
        AND c.conname='account_security_settings_values' AND c.contype='c' AND c.convalidated)
    AND EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid='iam.accounts'::regclass
        AND t.tgname='guard_security_settings' AND t.tgenabled='A' AND NOT t.tgisinternal
        AND t.tgtype=23 AND t.tgnargs=0 AND t.tgqual IS NULL
        AND t.tgfoid=to_regprocedure('iam.guard_account_security_settings()'))
    AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('iam.read_account_security_settings(text,text,text)')
        AND p.proowner='matrix_iam_owner'::regrole AND p.prosecdef AND NOT p.proretset
        AND p.prorettype='jsonb'::regtype AND p.provolatile='v' AND p.proparallel='u'
        AND p.proargnames=ARRAY['tenant','actor','decision']::text[]
        AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]
        AND has_function_privilege('matrix_iam_api',p.oid,'EXECUTE')
        AND NOT has_function_privilege('public',p.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_worker',p.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_notification_worker',p.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_credential_recovery',p.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_authentication_recovery',p.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_backup_custody',p.oid,'EXECUTE'))
    AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('iam.guard_account_security_settings()')
        AND p.proowner='matrix_iam_owner'::regrole AND NOT p.prosecdef AND NOT p.proretset
        AND p.prorettype='trigger'::regtype AND p.provolatile='v' AND p.proparallel='u'
        AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]
        AND NOT has_function_privilege('public',p.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_api',p.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_worker',p.oid,'EXECUTE'))
$function$;

REVOKE ALL ON FUNCTION iam.guard_account_security_settings() FROM PUBLIC,matrix_iam_api,matrix_iam_worker;
REVOKE ALL ON FUNCTION iam.account_security_settings_contract_ready() FROM PUBLIC,matrix_iam_api,matrix_iam_worker;
REVOKE ALL ON FUNCTION iam.read_account_security_settings(text,text,text) FROM PUBLIC,matrix_iam_worker;
GRANT EXECUTE ON FUNCTION iam.read_account_security_settings(text,text,text) TO matrix_iam_api;

CREATE TABLE IF NOT EXISTS iam.account_aliases (
    alias text COLLATE "C" PRIMARY KEY,
    tenant_id text COLLATE "C" NOT NULL REFERENCES iam.accounts (id),
    active boolean NOT NULL,
    CONSTRAINT account_alias_valid CHECK (alias COLLATE "C" ~ '^[a-z][a-z0-9-]{1,61}[a-z0-9]$')
);
CREATE UNIQUE INDEX IF NOT EXISTS account_alias_active_uq ON iam.account_aliases (tenant_id) WHERE active;

DROP FUNCTION IF EXISTS iam.is_bootstrap_administrator(text,text);

CREATE OR REPLACE FUNCTION iam.lookup_login(submitted_login_name text)
RETURNS TABLE (tenant_id text, principal_id text, password_hash text,
    organization_status text, principal_status text, must_change_password boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE
    indexed iam.login_index%ROWTYPE;
    local_name text := split_part(submitted_login_name, '@', 1);
    account_name text := split_part(submitted_login_name, '@', 2);
    target_tenant text;
    tenant_count integer;
BEGIN
    IF submitted_login_name IS NULL OR submitted_login_name COLLATE "C"
        !~ '^[a-z][a-z0-9._-]{2,63}(@[A-Za-z0-9][A-Za-z0-9._:-]{0,127})?$' THEN RETURN; END IF;
	IF strpos(submitted_login_name, '@') = 0 THEN
		SELECT login.* INTO indexed FROM iam.account_roots AS root
		JOIN iam.login_index AS login ON login.tenant_id=root.account_id AND login.principal_id=root.principal_id
			AND login.login_name=root.login_name WHERE root.login_name=local_name;
    ELSE
        SELECT count(DISTINCT candidates.id), min(candidates.id) INTO tenant_count, target_tenant
        FROM (
			SELECT root.account_id AS id FROM iam.account_roots AS root
			WHERE root.account_id = account_name
            UNION
            SELECT alias.tenant_id FROM iam.account_aliases AS alias
            WHERE alias.alias = account_name AND alias.active
        ) AS candidates;
        IF tenant_count <> 1 THEN RETURN; END IF;
		SELECT * INTO indexed FROM iam.login_index AS login
		WHERE login.tenant_id = target_tenant AND login.login_name = local_name
			AND NOT EXISTS(SELECT 1 FROM iam.account_roots AS root
				WHERE root.account_id=login.tenant_id AND root.principal_id=login.principal_id);
    END IF;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM set_config('matrix.iam_tenant_id', indexed.tenant_id, true);
    RETURN QUERY SELECT organization.id, principal.id, credential.password_hash,
        organization.status, principal.status, principal.must_change_password
    FROM iam.accounts AS organization
    JOIN iam.principals AS principal ON principal.tenant_id = organization.id AND principal.id = indexed.principal_id
    JOIN iam.user_credentials AS credential ON credential.tenant_id = principal.tenant_id AND credential.principal_id = principal.id
    WHERE organization.id = indexed.tenant_id AND principal.login_name = local_name AND principal.principal_type = 'USER';
END
$function$;

-- A registered tenant alone is not append authority. Historical facts are
-- read from this IAM installation only; current producer credentials remain
-- mandatory, while original user/session/tenant activation is not reevaluated.
DROP FUNCTION IF EXISTS iam.can_produce_audit(text,text,text,text);
CREATE INDEX IF NOT EXISTS audit_outbox_decision_fact_idx
ON iam.audit_outbox (tenant_id,(event_document->>'iamDecisionId'))
WHERE event_document->>'action'='iam.authorization.decided';
DROP FUNCTION IF EXISTS iam.read_audit_evidence(text,text,text,text,jsonb);
-- Historical version evidence is checked against immutable storage, never a
-- current default/head, live attachment or present user permission. Only a
-- protected contract-1 row permits the original evidence without new fields.
CREATE OR REPLACE FUNCTION iam.recorded_policy_version_matches(evidence jsonb)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT EXISTS(SELECT 1 FROM iam.policy_versions v
        WHERE v.policy_id=evidence#>>'{version,policyId}' AND v.id=evidence#>>'{version,versionId}'
          AND v.content_digest=evidence#>>'{version,contentDigest}'
          AND ((v.contract_version=1 AND NOT evidence ? 'compilation'
                AND (NOT evidence ? 'contractVersion' OR evidence->'contractVersion'='1'::jsonb))
            OR (v.contract_version=2 AND evidence->'contractVersion'='2'::jsonb
                AND evidence->'compilation'=v.compilation
                AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(v.compilation->'profiles') r
                    WHERE NOT EXISTS(SELECT 1 FROM iam.authorization_profiles p
                        WHERE p.product=r->>'product' AND to_jsonb(p.revision)=r->'revision'
                          AND p.content_digest=r->>'contentDigest')))));
$function$;
REVOKE ALL ON FUNCTION iam.recorded_policy_version_matches(jsonb) FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;

CREATE OR REPLACE FUNCTION iam.read_audit_evidence(origin_tenant text, producer text,
    producer_purpose text, producer_installation text, event jsonb)
RETURNS TABLE (installation_id text, event_document jsonb, decision_document jsonb, verifier_principal_id text, decision_contract_version integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE
    proof_tenant text;
    sealed_installation text;
    verifier_id text;
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',origin_tenant,true);
    SELECT receipt.installation_id INTO sealed_installation FROM iam.bootstrap_receipts AS receipt
    WHERE receipt.organization_id=origin_tenant AND receipt.installation_id=producer_installation;
    IF NOT FOUND OR producer_purpose NOT IN ('IAM','PAAS','AUDIT')
        OR NOT EXISTS(SELECT 1 FROM iam.service_credentials AS credential
            JOIN iam.principals AS principal ON principal.tenant_id=credential.tenant_id AND principal.id=credential.principal_id
            JOIN iam.accounts AS organization ON organization.id=credential.tenant_id
            WHERE credential.tenant_id=origin_tenant AND credential.principal_id=producer
                AND credential.purpose=producer_purpose AND credential.revoked_at IS NULL
                AND principal.principal_type='SERVICE_ACCOUNT' AND principal.status='ACTIVE' AND organization.status='ACTIVE') THEN RETURN; END IF;
    IF event ? 'installationId' THEN
        IF event ? 'tenantId' OR event->>'installationId' IS DISTINCT FROM sealed_installation THEN RETURN; END IF;
        proof_tenant := origin_tenant;
    ELSE
        proof_tenant := event->>'tenantId';
        IF NOT EXISTS(SELECT 1 FROM iam.account_roots AS root WHERE root.account_id=proof_tenant) THEN RETURN; END IF;
    END IF;
    -- The original verifier actor remains historical evidence even after its
    -- own credential is revoked. It is never the producer's current credential.
    SELECT credential.principal_id INTO verifier_id FROM iam.service_credentials AS credential
    WHERE credential.tenant_id=origin_tenant AND credential.purpose='INSTALLATION_VERIFIER';
    PERFORM set_config('matrix.iam_tenant_id',proof_tenant,true);
    IF producer_purpose='IAM' THEN
        RETURN QUERY SELECT sealed_installation, outbox.event_document, NULL::jsonb, verifier_id, NULL::integer
        FROM iam.audit_outbox AS outbox WHERE outbox.tenant_id=proof_tenant AND outbox.event_id=event->>'eventId'
          AND (NOT outbox.event_document->'actor' ? 'accessKeyId' OR
            iam.access_key_authorization_evidence_matches(proof_tenant,outbox.event_document->>'iamDecisionId'));
    ELSE
        RETURN QUERY SELECT sealed_installation, outbox.event_document, decision.document, verifier_id, decision.contract_version
        FROM iam.authorization_decisions AS decision
        JOIN iam.audit_outbox AS outbox ON outbox.tenant_id=decision.tenant_id
            AND outbox.event_document->>'action'='iam.authorization.decided'
            AND outbox.event_document->>'iamDecisionId'=decision.id
        WHERE decision.tenant_id=proof_tenant AND decision.id=event->>'iamDecisionId' AND decision.allowed
          AND (decision.policy_evidence IS NULL OR NOT EXISTS(
              SELECT 1 FROM jsonb_array_elements(decision.policy_evidence) e
              WHERE iam.recorded_policy_version_matches(e) IS DISTINCT FROM true))
          AND (decision.boundary_evidence IS NULL OR decision.boundary_evidence->>'state'<>'BOUND'
              OR iam.recorded_policy_version_matches(decision.boundary_evidence))
          AND iam.access_key_authorization_evidence_matches(proof_tenant,decision.id)
          AND (CASE WHEN decision.contract_version IN (3,4) AND decision.subject_type='ROLE' THEN
            decision.principal_id IS NULL AND decision.role_evidence IS NOT NULL
            AND iam.role_authorization_evidence(proof_tenant,decision.role_evidence->>'sessionId')=decision.role_evidence
            AND decision.role_id=decision.role_evidence->>'roleId' AND decision.source_principal_id=decision.role_evidence->>'sourceUserId'
            ELSE decision.role_evidence IS NULL END);
    END IF;
END
$function$;

-- Private projections name every public field; table rows and credentials are
-- never serialized wholesale. Callers set an exact tenant before using them.
CREATE OR REPLACE FUNCTION iam.account_snapshot(tenant text)
RETURNS jsonb LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM set_config('matrix.iam_tenant_id', tenant, true);
    SELECT jsonb_build_object(
        'apiVersion','iam.matrix.xiak.com/v1','kind','Account',
        'id',account.id,'displayName',account.display_name,'status',account.status,
        'rootIdentity',jsonb_build_object('principalId',root.principal_id,'loginName',root.login_name),
        'loginAlias',(SELECT alias.alias FROM iam.account_aliases AS alias WHERE alias.tenant_id=tenant AND alias.active),
        'resourceVersion',account.resource_version,'createdAt',account.created_at,'updatedAt',account.updated_at
    ) INTO result FROM iam.accounts AS account
    JOIN iam.account_roots AS root ON root.account_id=account.id
    WHERE account.id=tenant;
    RETURN result;
END
$function$;

-- Target protection facts remain private to IAM. They let the use case build
-- an actor-relative capability projection without exposing a database flag or
-- weakening the command's later lock-time checks.
CREATE OR REPLACE FUNCTION iam.account_management_snapshot(tenant text)
RETURNS jsonb LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM set_config('matrix.iam_tenant_id', tenant, true);
    SELECT jsonb_build_object(
        'account',iam.account_snapshot(tenant),
        'systemAccount',EXISTS(SELECT 1 FROM iam.bootstrap_receipts AS receipt
            WHERE receipt.organization_id=tenant),
        'rootHasInstallationAuthority',EXISTS(
            SELECT 1 FROM iam.account_roots AS root
            JOIN iam.policy_attachments AS attachment
              ON attachment.tenant_id=root.account_id AND attachment.target_id=root.principal_id
            WHERE root.account_id=tenant AND attachment.authority_scope='INSTALLATION'
              AND attachment.revoked_at IS NULL)
    ) INTO result FROM iam.accounts AS account WHERE account.id=tenant;
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.user_snapshot(tenant text, user_id text)
RETURNS jsonb LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $function$
    SELECT jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','User',
        'id',p.id,'accountId',p.tenant_id,'loginName',p.login_name,
        'displayName',p.display_name,'status',p.status,'mustChangePassword',p.must_change_password,
        'resourceVersion',p.resource_version,'createdAt',p.created_at,'updatedAt',p.updated_at)
    FROM iam.principals AS p WHERE p.tenant_id=tenant AND p.id=user_id
      AND p.principal_type='USER' AND p.deleted_at IS NULL
$function$;

CREATE OR REPLACE FUNCTION iam.user_access_snapshot(tenant text, user_id text)
RETURNS jsonb LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $function$
    SELECT jsonb_build_object(
        'user',iam.user_snapshot(tenant,p.id),
        'policyAttachments',COALESCE((
            SELECT jsonb_agg(iam.lookup_policy_attachment(tenant,selected.id) ORDER BY selected.id)
            FROM (SELECT attachment.id FROM iam.policy_attachments AS attachment
                WHERE attachment.tenant_id=tenant AND attachment.target_id=p.id AND attachment.target_kind='USER'
                  AND attachment.revoked_at IS NULL
                ORDER BY attachment.id LIMIT 257) AS selected
        ),'[]'::jsonb)
    )
    FROM iam.principals AS p
    WHERE p.tenant_id=tenant AND p.id=user_id AND p.principal_type='USER'
      AND p.deleted_at IS NULL
      AND NOT EXISTS(SELECT 1 FROM iam.account_roots AS root
          WHERE root.account_id=tenant AND root.principal_id=p.id)
$function$;

CREATE OR REPLACE FUNCTION iam.read_account(tenant text, principal text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id', tenant, true);
    IF NOT EXISTS (SELECT 1 FROM iam.principals AS p JOIN iam.accounts AS o ON o.id = p.tenant_id
        WHERE p.tenant_id = tenant AND p.id = principal AND p.principal_type = 'USER'
        AND p.status = 'ACTIVE' AND o.status = 'ACTIVE') THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account is unavailable';
    END IF;
    RETURN iam.account_snapshot(tenant);
END
$function$;

CREATE OR REPLACE FUNCTION iam.list_users(tenant text, actor text, decision text, after_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.user.list','ACCOUNT',tenant,'INSTANCE',NULL);
    PERFORM set_config('matrix.iam_tenant_id', tenant, true);
    IF after_id IS NULL OR (after_id <> '' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='page boundary is invalid';
    END IF;
    SELECT COALESCE(jsonb_agg(iam.user_access_snapshot(tenant,p.id) ORDER BY p.id),'[]'::jsonb) INTO result
    FROM (SELECT principal.id FROM iam.principals AS principal WHERE principal.tenant_id=tenant
        AND principal.principal_type='USER' AND principal.deleted_at IS NULL
        AND principal.id > after_id COLLATE "C"
        AND NOT EXISTS(SELECT 1 FROM iam.account_roots AS root
            WHERE root.account_id=tenant AND root.principal_id=principal.id)
        ORDER BY principal.id LIMIT 101) AS p;
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.read_user(tenant text, actor text, decision text, user_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.user.read','USER',user_id,'INSTANCE',NULL);
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts AS account WHERE account.id=tenant AND account.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='user account is unavailable'; END IF;
    result := iam.user_access_snapshot(tenant,user_id);
    IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='user is unavailable'; END IF;
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.list_accounts(tenant text, actor text, decision text, after_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb := '[]'::jsonb; candidate record;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account.read','ACCOUNT','collection','COLLECTION','COLLECTION_LIST');
    IF after_id IS NULL OR (after_id <> '' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='page boundary is invalid';
    END IF;
    FOR candidate IN SELECT root.account_id FROM iam.account_roots AS root
        WHERE root.account_id > after_id COLLATE "C" ORDER BY root.account_id LIMIT 101 LOOP
        result := result || jsonb_build_array(iam.account_management_snapshot(candidate.account_id));
    END LOOP;
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.read_account_as_platform(tenant text, actor text, decision text, target_tenant text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account.read','ACCOUNT',target_tenant,'INSTANCE',NULL);
    result := iam.account_management_snapshot(target_tenant);
    IF result IS NULL OR result->'account' IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account is unavailable';
    END IF;
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.read_account_root(tenant text, actor text, decision text, target_tenant text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account.recover-root-credentials','ACCOUNT',target_tenant,'INSTANCE',NULL);
    PERFORM set_config('matrix.iam_tenant_id',target_tenant,true);
    SELECT jsonb_build_object('principalId',root.principal_id,'loginName',root.login_name)
      INTO result FROM iam.account_roots AS root WHERE root.account_id=target_tenant;
    IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account root is unavailable'; END IF;
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.append_account_event(tenant text, actor text, decision text,
    action text, target_kind text, target_id text, event jsonb)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM iam.assert_audit_event(event,tenant,action,target_kind,target_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision
        OR NOT EXISTS(SELECT 1 FROM iam.authorization_decisions AS original
            WHERE original.tenant_id=tenant AND original.id=decision AND original.principal_id=actor
                AND original.request_id=event->>'requestId' AND original.request_id=event->>'correlationId'
                AND original.decided_at=transaction_timestamp()) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='account decision correlation is invalid';
    END IF;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
    VALUES(tenant,event->>'eventId',event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
END
$function$;

CREATE OR REPLACE FUNCTION iam.create_account(tenant text, actor text, decision text,
    new_id text, display_name text, primary_id text, login_name text, primary_name text, password_hash text, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb; effective_now timestamptz := transaction_timestamp();
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account.create','ACCOUNT','collection','COLLECTION','COLLECTION_CREATE');
    IF new_id IS NULL OR primary_id IS NULL OR login_name IS NULL OR password_hash IS NULL
        OR new_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR primary_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR login_name COLLATE "C" !~ '^[a-z][a-z0-9._-]{2,63}$'
        OR password_hash NOT LIKE '$matrix-iam-v1$argon2id$v=19$%'
        OR length(display_name) NOT BETWEEN 1 AND 128 OR btrim(display_name) <> display_name
        OR length(primary_name) NOT BETWEEN 1 AND 128 OR btrim(primary_name) <> primary_name THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='account opening is invalid';
    END IF;
    IF EXISTS (SELECT 1 FROM iam.account_aliases AS alias WHERE alias.alias=new_id) THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='account namespace is reserved';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',new_id,true);
    INSERT INTO iam.accounts(id,display_name,status,resource_version,created_at,updated_at)
    VALUES(new_id,display_name,'ACTIVE',1,effective_now,effective_now);
    INSERT INTO iam.principals(tenant_id,id,principal_type,login_name,display_name,status,
        must_change_password,resource_version,created_at,updated_at)
    VALUES(new_id,primary_id,'USER',login_name,primary_name,'ACTIVE',true,1,effective_now,effective_now);
    INSERT INTO iam.user_credentials(tenant_id,principal_id,password_hash,changed_at)
    VALUES(new_id,primary_id,password_hash,effective_now);
    INSERT INTO iam.login_index(login_name,tenant_id,principal_id) VALUES(login_name,new_id,primary_id);
    INSERT INTO iam.account_roots(account_id,principal_id,login_name) VALUES(new_id,primary_id,login_name);
    INSERT INTO iam.policy_attachments(tenant_id,id,target_id,policy_id,resource_version,created_at,updated_at)
    VALUES(new_id,'primary-admin-binding',primary_id,'system.account-administrator',1,effective_now,effective_now);
    result := iam.account_snapshot(new_id);
    PERFORM iam.append_account_event(tenant,actor,decision,'iam.account.created','ACCOUNT',new_id,event);
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.set_account_status(tenant text, actor text, decision text,
    target_tenant text, new_status text, expected_version bigint, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE stored iam.accounts%ROWTYPE;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account.set-status','ACCOUNT',target_tenant,'INSTANCE',NULL);
    IF new_status IS NULL OR new_status NOT IN ('ACTIVE','DISABLED') OR expected_version IS NULL OR expected_version < 1 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='account status change is invalid';
    END IF;
    IF new_status='DISABLED' AND EXISTS(SELECT 1 FROM iam.bootstrap_receipts AS receipt WHERE receipt.organization_id=target_tenant) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='installation service account is protected';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',target_tenant,true);
    SELECT * INTO stored FROM iam.accounts AS account WHERE account.id=target_tenant FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account is unavailable'; END IF;
    IF stored.resource_version <> expected_version THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='account version conflicts';
    END IF;
    IF stored.status=new_status THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='account status already matches'; END IF;
    UPDATE iam.accounts AS account SET status=new_status,resource_version=account.resource_version+1,updated_at=transaction_timestamp()
    WHERE account.id=target_tenant;
    IF new_status='DISABLED' THEN
        UPDATE iam.sessions AS session SET status='REVOKED',revoked_at=transaction_timestamp(),resource_version=session.resource_version+1
        WHERE session.tenant_id=target_tenant AND session.status='ACTIVE';
    END IF;
    PERFORM iam.append_account_event(tenant,actor,decision,
        CASE WHEN new_status='DISABLED' THEN 'iam.account.disabled' ELSE 'iam.account.enabled' END,'ACCOUNT',target_tenant,event);
    RETURN iam.account_snapshot(target_tenant);
END
$function$;

CREATE OR REPLACE FUNCTION iam.recover_root_credentials(tenant text, actor text, decision text,
    target_tenant text, primary_id text, expected_version bigint, new_password_hash text, new_binding_id text, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE stored_version bigint;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account.recover-root-credentials','ACCOUNT',target_tenant,'INSTANCE',NULL);
    IF expected_version IS NULL OR expected_version < 1 OR new_password_hash IS NULL
        OR new_password_hash NOT LIKE '$matrix-iam-v1$argon2id$v=19$%'
        OR event#>>'{target,tenantId}' IS DISTINCT FROM target_tenant
        OR COALESCE(new_binding_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='root credential recovery is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',target_tenant,true);
    SELECT account.resource_version INTO stored_version FROM iam.accounts AS account WHERE account.id=target_tenant FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account is unavailable'; END IF;
    IF stored_version <> expected_version THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='account version conflicts'; END IF;
    -- Serialize all credential takeover checks with platform grants on this USER.
    PERFORM 1 FROM iam.account_roots AS root JOIN iam.principals AS principal
        ON principal.tenant_id=root.account_id AND principal.id=root.principal_id
        WHERE root.account_id=target_tenant AND root.principal_id=primary_id
          AND principal.principal_type='USER' FOR UPDATE OF principal;
    IF NOT FOUND OR EXISTS(SELECT 1 FROM iam.policy_attachments AS binding WHERE binding.tenant_id=target_tenant
        AND binding.target_id=primary_id AND binding.target_kind='USER' AND binding.authority_scope='INSTALLATION' AND binding.revoked_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='root credential recovery is forbidden';
    END IF;
    UPDATE iam.principals AS principal SET status='ACTIVE',must_change_password=true,
        resource_version=principal.resource_version+1,updated_at=transaction_timestamp()
    WHERE principal.tenant_id=target_tenant AND principal.id=primary_id;
    UPDATE iam.user_credentials AS credential SET password_hash=new_password_hash,changed_at=transaction_timestamp(),
        credential_version=credential.credential_version+1
    WHERE credential.tenant_id=target_tenant AND credential.principal_id=primary_id;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='primary credential is unavailable'; END IF;
    UPDATE iam.sessions AS session SET status='REVOKED',revoked_at=transaction_timestamp(),resource_version=session.resource_version+1
    WHERE session.tenant_id=target_tenant AND session.principal_id=primary_id AND session.status='ACTIVE';
    INSERT INTO iam.policy_attachments(tenant_id,id,target_id,policy_id,resource_version,created_at,updated_at)
    SELECT target_tenant,new_binding_id,primary_id,'system.account-administrator',1,transaction_timestamp(),transaction_timestamp()
    WHERE NOT EXISTS(SELECT 1 FROM iam.policy_attachments AS binding WHERE binding.tenant_id=target_tenant
        AND binding.target_id=primary_id AND binding.target_kind='USER' AND binding.policy_id='system.account-administrator' AND binding.revoked_at IS NULL);
    UPDATE iam.accounts AS account SET resource_version=account.resource_version+1,updated_at=transaction_timestamp()
    WHERE account.id=target_tenant;
    PERFORM iam.append_account_event(tenant,actor,decision,'iam.account-root.credentials-recovered','USER',primary_id,event);
    RETURN iam.account_snapshot(target_tenant);
END
$function$;

CREATE OR REPLACE FUNCTION iam.set_account_alias(tenant text, actor text, decision text,
    new_alias text, expected_version bigint, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE stored_version bigint;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account.alias-set','ACCOUNT',tenant,'INSTANCE',NULL);
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    IF new_alias IS NULL OR new_alias COLLATE "C" !~ '^[a-z][a-z0-9-]{1,61}[a-z0-9]$'
        OR expected_version IS NULL OR expected_version < 1 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='account alias is invalid';
    END IF;
    SELECT o.resource_version INTO stored_version FROM iam.accounts AS o WHERE o.id=tenant FOR UPDATE;
    IF stored_version IS DISTINCT FROM expected_version THEN
        RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='account version changed';
    END IF;
    IF EXISTS(SELECT 1 FROM iam.account_roots AS root WHERE root.account_id=new_alias AND root.account_id<>tenant)
        OR EXISTS(SELECT 1 FROM iam.account_aliases AS alias WHERE alias.alias=new_alias AND alias.tenant_id<>tenant) THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='account alias is reserved';
    END IF;
    UPDATE iam.account_aliases AS alias SET active=false WHERE alias.tenant_id=tenant AND alias.active;
    INSERT INTO iam.account_aliases(alias,tenant_id,active) VALUES(new_alias,tenant,true)
    ON CONFLICT(alias) DO UPDATE SET active=true WHERE iam.account_aliases.tenant_id=EXCLUDED.tenant_id;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='account alias is reserved'; END IF;
    UPDATE iam.accounts AS o SET resource_version=o.resource_version+1,updated_at=transaction_timestamp() WHERE o.id=tenant;
    PERFORM iam.append_account_event(tenant,actor,decision,'iam.account.alias-set','ACCOUNT',tenant,event);
    RETURN iam.account_snapshot(tenant);
END
$function$;

CREATE OR REPLACE FUNCTION iam.update_user(tenant text, actor text, decision text,
    user_id text, submitted_display_name text, expected_version bigint, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE stored iam.principals%ROWTYPE;
BEGIN
    IF submitted_display_name IS NULL OR length(submitted_display_name) NOT BETWEEN 1 AND 128
        OR btrim(submitted_display_name)<>submitted_display_name OR expected_version IS NULL OR expected_version<1 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='user profile mutation is invalid';
    END IF;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.user.update','USER',user_id,'INSTANCE',NULL);
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts AS account WHERE account.id=tenant AND account.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='user account is unavailable'; END IF;
    SELECT * INTO stored FROM iam.principals AS principal
     WHERE principal.tenant_id=tenant AND principal.id=user_id FOR UPDATE;
    IF NOT FOUND OR stored.principal_type<>'USER' OR stored.deleted_at IS NOT NULL
        OR EXISTS(SELECT 1 FROM iam.account_roots AS root
            WHERE root.account_id=tenant AND root.principal_id=user_id) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='user is not manageable';
    END IF;
    IF expected_version<>stored.resource_version OR stored.resource_version=9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='user version changed';
    END IF;
    PERFORM iam.assert_audit_event(event,tenant,'iam.user.updated','USER',user_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='user decision correlation is invalid';
    END IF;
    UPDATE iam.principals AS principal
       SET display_name=submitted_display_name,resource_version=principal.resource_version+1,
           updated_at=transaction_timestamp()
     WHERE principal.tenant_id=tenant AND principal.id=user_id;
    PERFORM iam.append_account_event(tenant,actor,decision,'iam.user.updated','USER',user_id,event);
    RETURN iam.user_snapshot(tenant,user_id);
END
$function$;

CREATE OR REPLACE FUNCTION iam.delete_user(tenant text, actor text, decision text,
    user_id text, expected_version bigint, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE
    stored iam.principals%ROWTYPE;
    effective_now timestamptz(6) := transaction_timestamp();
    changed integer;
BEGIN
    IF expected_version IS NULL OR expected_version<1 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='user deletion is invalid';
    END IF;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.user.delete','USER',user_id,'INSTANCE',NULL);
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts AS account WHERE account.id=tenant AND account.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='user account is unavailable'; END IF;
    SELECT * INTO stored FROM iam.principals AS principal
     WHERE principal.tenant_id=tenant AND principal.id=user_id FOR UPDATE;
    IF NOT FOUND OR stored.principal_type<>'USER' OR stored.deleted_at IS NOT NULL OR user_id=actor
        OR EXISTS(SELECT 1 FROM iam.account_roots AS root
            WHERE root.account_id=tenant AND root.principal_id=user_id)
        OR EXISTS(SELECT 1 FROM iam.policy_attachments AS attachment
            WHERE attachment.tenant_id=tenant AND attachment.target_id=user_id AND attachment.target_kind='USER'
              AND attachment.authority_scope='INSTALLATION' AND attachment.revoked_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='user is not deletable';
    END IF;
    IF expected_version<>stored.resource_version OR stored.resource_version=9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='user version changed';
    END IF;
    IF stored.status<>'DISABLED' THEN
        RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='user must be disabled before deletion';
    END IF;
    PERFORM iam.assert_audit_event(event,tenant,'iam.user.deleted','USER',user_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='user decision correlation is invalid';
    END IF;
    -- Policy grant/revoke and deletion all acquire the principal before its
    -- attachments. Sorting closes multi-row deadlock ambiguity.
    PERFORM target_group.id FROM iam.groups AS target_group
      JOIN iam.group_memberships AS membership
        ON membership.tenant_id=target_group.tenant_id AND membership.group_id=target_group.id
     WHERE membership.tenant_id=tenant AND membership.user_id=delete_user.user_id AND membership.removed_at IS NULL
     ORDER BY target_group.id FOR UPDATE OF target_group;
    PERFORM membership.id FROM iam.group_memberships AS membership
     WHERE membership.tenant_id=tenant AND membership.user_id=delete_user.user_id AND membership.removed_at IS NULL
     ORDER BY membership.id FOR UPDATE;
    PERFORM attachment.id FROM iam.policy_attachments AS attachment
     WHERE attachment.tenant_id=tenant AND attachment.target_id=user_id AND attachment.target_kind='USER'
     ORDER BY attachment.id FOR UPDATE;
    PERFORM iam.delete_user_access_keys(tenant,actor,decision,user_id,event);
    UPDATE iam.principals AS principal
       SET status='DISABLED',must_change_password=false,
           resource_version=principal.resource_version+1,updated_at=effective_now,deleted_at=effective_now
     WHERE principal.tenant_id=tenant AND principal.id=user_id;
    DELETE FROM iam.user_credentials AS credential
     WHERE credential.tenant_id=tenant AND credential.principal_id=user_id;
    GET DIAGNOSTICS changed=ROW_COUNT;
    IF changed<>1 THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='user credential is unavailable';
    END IF;
    UPDATE iam.sessions AS session
       SET status='REVOKED',revoked_at=effective_now,resource_version=session.resource_version+1
     WHERE session.tenant_id=tenant AND session.principal_id=user_id AND session.status='ACTIVE';
    UPDATE iam.policy_attachments AS attachment
       SET resource_version=attachment.resource_version+1,updated_at=effective_now,revoked_at=effective_now
     WHERE attachment.tenant_id=tenant AND attachment.target_id=user_id AND attachment.target_kind='USER' AND attachment.revoked_at IS NULL;
    UPDATE iam.group_memberships AS membership
       SET resource_version=membership.resource_version+1,updated_at=effective_now,
           removed_at=effective_now,removed_by=actor
     WHERE membership.tenant_id=tenant AND membership.user_id=delete_user.user_id AND membership.removed_at IS NULL;
    UPDATE iam.user_permission_boundaries AS boundary
       SET resource_version=boundary.resource_version+1,updated_at=effective_now,revoked_at=effective_now
     WHERE boundary.tenant_id=tenant AND boundary.user_id=delete_user.user_id AND boundary.revoked_at IS NULL;
    PERFORM iam.append_account_event(tenant,actor,decision,'iam.user.deleted','USER',user_id,event);
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','UserDeletion',
        'accountId',tenant,'id',user_id,'loginName',stored.login_name,
        'resourceVersion',stored.resource_version+1,'deletedAt',effective_now);
END
$function$;

CREATE OR REPLACE FUNCTION iam.change_user(tenant text, actor text, decision text,
    user_id text, expected_version bigint, new_status text, new_password_hash text, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE stored iam.principals%ROWTYPE; action text; event_action text;
BEGIN
    IF (new_status IS NULL) = (new_password_hash IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='user change is invalid';
    END IF;
    IF new_status IS NOT NULL THEN action := 'iam.user.set-status'; event_action := 'iam.user.status-set';
    ELSE action := 'iam.user.reset-password'; event_action := 'iam.user.password-reset'; END IF;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,action,'USER',user_id,'INSTANCE',NULL);
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts AS organization
        WHERE organization.id=tenant AND organization.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='user account is unavailable';
    END IF;
    SELECT * INTO stored FROM iam.principals AS p WHERE p.tenant_id=tenant AND p.id=user_id FOR UPDATE;
    IF NOT FOUND OR stored.principal_type <> 'USER' OR stored.deleted_at IS NOT NULL OR user_id=actor
        OR EXISTS(SELECT 1 FROM iam.account_roots AS root WHERE root.account_id=tenant AND root.principal_id=user_id)
        OR EXISTS(SELECT 1 FROM iam.policy_attachments AS binding
            WHERE binding.tenant_id=tenant AND binding.target_id=user_id AND binding.target_kind='USER'
              AND binding.authority_scope='INSTALLATION' AND binding.revoked_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='user is not manageable';
    END IF;
    IF expected_version IS NULL OR expected_version < 1 OR expected_version <> stored.resource_version THEN
        RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='user version changed';
    END IF;
    IF (new_status IS NOT NULL AND new_status NOT IN ('ACTIVE','DISABLED'))
        OR (new_password_hash IS NOT NULL AND new_password_hash NOT LIKE '$matrix-iam-v1$argon2id$v=19$%') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='user change is invalid';
    END IF;
    UPDATE iam.principals AS p SET status=COALESCE(new_status,p.status),
        must_change_password=CASE WHEN new_password_hash IS NULL THEN p.must_change_password ELSE true END,
        resource_version=p.resource_version+1,updated_at=transaction_timestamp() WHERE p.tenant_id=tenant AND p.id=user_id;
    IF new_password_hash IS NOT NULL THEN
        UPDATE iam.user_credentials AS c SET password_hash=new_password_hash,changed_at=transaction_timestamp(),
            credential_version=c.credential_version+1
        WHERE c.tenant_id=tenant AND c.principal_id=user_id;
    END IF;
    UPDATE iam.sessions AS s SET status='REVOKED',revoked_at=transaction_timestamp(),resource_version=s.resource_version+1
    WHERE s.tenant_id=tenant AND s.principal_id=user_id AND s.status='ACTIVE';
    PERFORM iam.append_account_event(tenant,actor,decision,event_action,'USER',user_id,event);
    RETURN iam.user_snapshot(tenant,user_id);
END
$function$;

DROP FUNCTION IF EXISTS iam.read_organization(text,text,text,text);
DROP FUNCTION IF EXISTS iam.set_organization_status(text,text,text,text,text,bigint,jsonb);
DROP FUNCTION IF EXISTS iam.recover_organization_administrator(text,text,text,text,text,bigint,text,text,jsonb);
DROP FUNCTION IF EXISTS iam.list_principals(text,text,text,text);
DROP FUNCTION IF EXISTS iam.create_organization(text,text,text,text,text,text,text,text,text,jsonb);
DROP FUNCTION IF EXISTS iam.change_subaccount(text,text,text,text,bigint,text,text,jsonb);
DROP FUNCTION IF EXISTS iam.principal_snapshot(text,text);

REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM PUBLIC, matrix_iam_api, matrix_iam_worker;
REVOKE ALL ON FUNCTION iam.account_snapshot(text), iam.account_management_snapshot(text), iam.user_snapshot(text,text),
    iam.user_access_snapshot(text,text),
    iam.append_account_event(text,text,text,text,text,text,jsonb) FROM PUBLIC, matrix_iam_api, matrix_iam_worker;
REVOKE ALL ON FUNCTION iam.read_account(text,text), iam.read_account_as_platform(text,text,text,text),
    iam.read_account_root(text,text,text,text), iam.set_account_status(text,text,text,text,text,bigint,jsonb),
    iam.recover_root_credentials(text,text,text,text,text,bigint,text,text,jsonb),
    iam.read_audit_evidence(text,text,text,text,jsonb),
    iam.list_users(text,text,text,text), iam.list_accounts(text,text,text,text),
    iam.create_account(text,text,text,text,text,text,text,text,text,jsonb),
    iam.set_account_alias(text,text,text,text,bigint,jsonb),
    iam.read_user(text,text,text,text),
    iam.update_user(text,text,text,text,text,bigint,jsonb),
    iam.delete_user(text,text,text,text,bigint,jsonb),
    iam.change_user(text,text,text,text,bigint,text,text,jsonb) FROM PUBLIC, matrix_iam_worker;
GRANT EXECUTE ON FUNCTION iam.read_account(text,text), iam.read_account_as_platform(text,text,text,text),
    iam.read_account_root(text,text,text,text), iam.set_account_status(text,text,text,text,text,bigint,jsonb),
    iam.recover_root_credentials(text,text,text,text,text,bigint,text,text,jsonb),
    iam.read_audit_evidence(text,text,text,text,jsonb),
    iam.list_users(text,text,text,text), iam.list_accounts(text,text,text,text),
    iam.create_account(text,text,text,text,text,text,text,text,text,jsonb),
    iam.set_account_alias(text,text,text,text,bigint,jsonb),
    iam.read_user(text,text,text,text),
    iam.update_user(text,text,text,text,text,bigint,jsonb),
    iam.delete_user(text,text,text,text,bigint,jsonb),
    iam.change_user(text,text,text,text,bigint,text,text,jsonb) TO matrix_iam_api;
