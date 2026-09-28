SET LOCAL ROLE matrix_iam_owner;

-- Authentication recovery is an installation-owned circuit breaker around a
-- destructive database restore. These receipts are authority history, not a
-- generic command journal and not permission to authenticate a USER.
CREATE TABLE IF NOT EXISTS iam.authentication_recovery_closures (
    command_id text COLLATE "C" PRIMARY KEY,
    installation_id text COLLATE "C" NOT NULL,
    home_tenant_id text COLLATE "C" NOT NULL,
    epoch bigint NOT NULL UNIQUE CHECK(epoch BETWEEN 1 AND 9223372036854775807),
    origin text COLLATE "C" NOT NULL CHECK(origin IN ('SOURCE','RESTORED')),
    intent_digest text COLLATE "C" NOT NULL CHECK(intent_digest ~ '^sha256:[0-9a-f]{64}$'),
    intent_document jsonb,
    closure_document jsonb NOT NULL CHECK(jsonb_typeof(closure_document)='object'),
    closed_event_id text COLLATE "C" NOT NULL UNIQUE,
    closed_event_document jsonb NOT NULL CHECK(jsonb_typeof(closed_event_document)='object'),
    closed_at timestamptz(6) NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES iam.bootstrap_receipts(installation_id),
    FOREIGN KEY(home_tenant_id,closed_event_id) REFERENCES iam.audit_outbox(tenant_id,event_id),
    CHECK((origin='SOURCE' AND jsonb_typeof(intent_document)='object') OR (origin='RESTORED' AND intent_document IS NULL)),
    CHECK(closure_document->>'commandId'=command_id AND closure_document->>'installationId'=installation_id
      AND (closure_document->>'epoch')::bigint=epoch AND closure_document->>'recoveryIntentDigest'=intent_digest
      AND closure_document->>'state'='CLOSED' AND (closure_document->>'closedAt')::timestamptz=closed_at),
    CHECK(closed_event_document->>'eventId'=closed_event_id)
);

-- Historical closures have no snapshot. Keep their immutable bytes, but
-- never backfill current qualification or treat them as new recovery input.
ALTER TABLE iam.authentication_recovery_closures ADD COLUMN IF NOT EXISTS security_snapshot_document jsonb;
ALTER TABLE iam.authentication_recovery_closures DROP CONSTRAINT IF EXISTS authentication_recovery_snapshot_shape;
ALTER TABLE iam.authentication_recovery_closures ADD CONSTRAINT authentication_recovery_snapshot_shape CHECK(COALESCE(
    (security_snapshot_document IS NULL AND NOT closure_document ? 'securitySnapshotDigest')
    OR (security_snapshot_document IS NOT NULL AND jsonb_typeof(security_snapshot_document)='object'
      AND octet_length(security_snapshot_document::text)<=2097152
      AND security_snapshot_document->>'commandId'=command_id
      AND security_snapshot_document->>'installationId'=installation_id
      AND (security_snapshot_document->>'epoch')::bigint=epoch
      AND security_snapshot_document->>'recoveryIntentDigest'=intent_digest
      AND (security_snapshot_document->>'closedAt')::timestamptz=closed_at
      AND closure_document->>'securitySnapshotDigest' ~ '^sha256:[0-9a-f]{64}$'),false));

CREATE TABLE IF NOT EXISTS iam.authentication_recovery_reconciliations (
    command_id text COLLATE "C" PRIMARY KEY REFERENCES iam.authentication_recovery_closures(command_id),
    installation_id text COLLATE "C" NOT NULL,
    home_tenant_id text COLLATE "C" NOT NULL,
    closure_digest text COLLATE "C" NOT NULL CHECK(closure_digest ~ '^sha256:[0-9a-f]{64}$'),
    reconciled_event_id text COLLATE "C" NOT NULL UNIQUE,
    reconciled_event_document jsonb NOT NULL CHECK(jsonb_typeof(reconciled_event_document)='object'),
    reconciled_at timestamptz(6) NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES iam.bootstrap_receipts(installation_id),
    FOREIGN KEY(home_tenant_id,reconciled_event_id) REFERENCES iam.audit_outbox(tenant_id,event_id),
    CHECK(reconciled_event_document->>'eventId'=reconciled_event_id)
);

CREATE TABLE IF NOT EXISTS iam.authentication_recovery_completions (
    command_id text COLLATE "C" PRIMARY KEY REFERENCES iam.authentication_recovery_reconciliations(command_id),
    installation_id text COLLATE "C" NOT NULL,
    home_tenant_id text COLLATE "C" NOT NULL,
    closure_digest text COLLATE "C" NOT NULL CHECK(closure_digest ~ '^sha256:[0-9a-f]{64}$'),
    completion_document jsonb NOT NULL CHECK(jsonb_typeof(completion_document)='object'),
    reopened_event_id text COLLATE "C" NOT NULL UNIQUE,
    reopened_event_document jsonb NOT NULL CHECK(jsonb_typeof(reopened_event_document)='object'),
    completed_at timestamptz(6) NOT NULL,
    FOREIGN KEY(installation_id) REFERENCES iam.bootstrap_receipts(installation_id),
    FOREIGN KEY(home_tenant_id,reopened_event_id) REFERENCES iam.audit_outbox(tenant_id,event_id),
    CHECK(completion_document->>'commandId'=command_id AND completion_document->>'installationId'=installation_id
      AND completion_document->>'closureDigest'=closure_digest AND completion_document->>'state'='REOPENED'
      AND (completion_document->>'completedAt')::timestamptz=completed_at),
    CHECK(reopened_event_document->>'eventId'=reopened_event_id)
);

CREATE TABLE IF NOT EXISTS iam.authentication_recovery_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    epoch bigint NOT NULL CHECK(epoch BETWEEN 0 AND 9223372036854775807),
    state text COLLATE "C" NOT NULL CHECK(state IN ('OPEN','CLOSED')),
    active_command_id text COLLATE "C" REFERENCES iam.authentication_recovery_closures(command_id),
    updated_at timestamptz(6) NOT NULL,
    CHECK((state='OPEN' AND active_command_id IS NULL) OR (state='CLOSED' AND active_command_id IS NOT NULL))
);
INSERT INTO iam.authentication_recovery_state(singleton,epoch,state,active_command_id,updated_at)
VALUES(true,0,'OPEN',NULL,transaction_timestamp()) ON CONFLICT(singleton) DO NOTHING;

-- Existing recovery codes and AccessKeys came from the restored snapshot and
-- may have escaped before recovery. Fence their identities permanently. New
-- material created after reopen is absent and remains usable.
CREATE TABLE IF NOT EXISTS iam.authentication_recovery_code_fences (
    tenant_id text COLLATE "C" NOT NULL,
    batch_id text COLLATE "C" NOT NULL,
    command_id text COLLATE "C" NOT NULL REFERENCES iam.authentication_recovery_completions(command_id),
    closure_digest text COLLATE "C" NOT NULL CHECK(closure_digest ~ '^sha256:[0-9a-f]{64}$'),
    fenced_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,batch_id),
    FOREIGN KEY(tenant_id,batch_id) REFERENCES iam.mfa_recovery_batches(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS iam.authentication_recovery_access_key_fences (
    access_key_id text COLLATE "C" PRIMARY KEY REFERENCES iam.access_keys(id),
    command_id text COLLATE "C" NOT NULL REFERENCES iam.authentication_recovery_completions(command_id),
    closure_digest text COLLATE "C" NOT NULL CHECK(closure_digest ~ '^sha256:[0-9a-f]{64}$'),
    fenced_at timestamptz(6) NOT NULL
);

-- One materialized replay floor per USER, not a fabricated password/OTP
-- attempt. It carries the sealed source window until a real later attempt
-- takes over, and avoids scanning the full closure JSON on every login.
CREATE TABLE IF NOT EXISTS iam.authentication_recovery_attempt_floors (
    tenant_id text COLLATE "C" NOT NULL,
    user_id text COLLATE "C" NOT NULL,
    command_id text COLLATE "C" NOT NULL REFERENCES iam.authentication_recovery_completions(command_id),
    password_generation bigint,
    password_window_started_at timestamptz(6),
    password_used_attempts integer,
    password_sequence bigint,
    totp_window_started_at timestamptz(6),
    totp_used_attempts integer,
    totp_sequence bigint,
    PRIMARY KEY(tenant_id,user_id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES iam.principals(tenant_id,id),
    CONSTRAINT authentication_recovery_password_floor_valid CHECK(COALESCE(
      (password_generation IS NULL AND password_window_started_at IS NULL AND password_used_attempts IS NULL AND password_sequence IS NULL)
      OR (password_generation>0 AND password_window_started_at IS NOT NULL AND password_used_attempts BETWEEN 0 AND 5 AND password_sequence>0),false)),
    CONSTRAINT authentication_recovery_totp_floor_valid CHECK(COALESCE(
      (totp_window_started_at IS NULL AND totp_used_attempts IS NULL AND totp_sequence IS NULL)
      OR (totp_window_started_at IS NOT NULL AND totp_used_attempts BETWEEN 1 AND 5 AND totp_sequence>0),false))
);
ALTER TABLE iam.authentication_recovery_attempt_floors ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.authentication_recovery_attempt_floors FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON iam.authentication_recovery_attempt_floors;
CREATE POLICY tenant_isolation ON iam.authentication_recovery_attempt_floors TO matrix_iam_owner
    USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id());

CREATE OR REPLACE FUNCTION iam.guard_authentication_recovery_attempt_floor()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF TG_OP NOT IN ('INSERT','UPDATE')
      OR current_setting('matrix.iam_authentication_recovery',true) IS DISTINCT FROM 'trusted'
      OR NOT pg_has_role(session_user,'matrix_iam_authentication_recovery','USAGE')
      OR NOT EXISTS(SELECT 1 FROM iam.authentication_recovery_state s
        JOIN iam.authentication_recovery_completions c ON c.command_id=s.active_command_id
        WHERE s.singleton AND s.state='CLOSED' AND s.active_command_id=NEW.command_id
          AND c.completed_at=transaction_timestamp()) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication attempt floor is recovery-owned';
    END IF;
    IF TG_OP='UPDATE' AND (NEW.tenant_id<>OLD.tenant_id OR NEW.user_id<>OLD.user_id
      OR NOT EXISTS(SELECT 1 FROM iam.authentication_recovery_closures n,iam.authentication_recovery_closures o
        WHERE n.command_id=NEW.command_id AND o.command_id=OLD.command_id AND n.epoch>o.epoch)) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='authentication attempt floor recovery cannot regress';
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS authentication_attempt_floor_owned ON iam.authentication_recovery_attempt_floors;
CREATE TRIGGER authentication_attempt_floor_owned BEFORE INSERT OR UPDATE OR DELETE ON iam.authentication_recovery_attempt_floors
    FOR EACH ROW EXECUTE FUNCTION iam.guard_authentication_recovery_attempt_floor();
ALTER TABLE iam.authentication_recovery_attempt_floors ENABLE ALWAYS TRIGGER authentication_attempt_floor_owned;

CREATE OR REPLACE FUNCTION iam.reject_authentication_recovery_history_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication recovery history is immutable';
END $function$;
DROP TRIGGER IF EXISTS authentication_attempt_floor_no_truncate ON iam.authentication_recovery_attempt_floors;
CREATE TRIGGER authentication_attempt_floor_no_truncate BEFORE TRUNCATE ON iam.authentication_recovery_attempt_floors
    FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_authentication_recovery_history_change();
ALTER TABLE iam.authentication_recovery_attempt_floors ENABLE ALWAYS TRIGGER authentication_attempt_floor_no_truncate;
DO $protect_authentication_recovery_history$
DECLARE relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['authentication_recovery_closures','authentication_recovery_reconciliations',
        'authentication_recovery_completions','authentication_recovery_code_fences','authentication_recovery_access_key_fences'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS authentication_recovery_history_is_immutable ON iam.%I',relation_name);
        EXECUTE format('CREATE TRIGGER authentication_recovery_history_is_immutable BEFORE UPDATE OR DELETE ON iam.%I '
          'FOR EACH ROW EXECUTE FUNCTION iam.reject_authentication_recovery_history_change()',relation_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER authentication_recovery_history_is_immutable',relation_name);
        EXECUTE format('DROP TRIGGER IF EXISTS authentication_recovery_history_cannot_truncate ON iam.%I',relation_name);
        EXECUTE format('CREATE TRIGGER authentication_recovery_history_cannot_truncate BEFORE TRUNCATE ON iam.%I '
          'FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_authentication_recovery_history_change()',relation_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER authentication_recovery_history_cannot_truncate',relation_name);
    END LOOP;
END $protect_authentication_recovery_history$;

CREATE OR REPLACE FUNCTION iam.guard_authentication_recovery_state()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF current_setting('matrix.iam_authentication_recovery',true) IS DISTINCT FROM 'trusted'
      OR TG_OP<>'UPDATE' OR NOT OLD.singleton OR NOT NEW.singleton OR NEW.updated_at<>transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication recovery state is protected';
    END IF;
    IF OLD.state='OPEN' THEN
        IF NEW.state<>'CLOSED' OR NEW.epoch<>OLD.epoch+1 OR NEW.active_command_id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='authentication recovery close transition is invalid';
        END IF;
    ELSIF OLD.state='CLOSED' THEN
        IF NEW.state<>'OPEN' OR NEW.epoch<>OLD.epoch OR NEW.active_command_id IS NOT NULL
          OR NOT EXISTS(SELECT 1 FROM iam.authentication_recovery_completions c WHERE c.command_id=OLD.active_command_id) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='authentication recovery reopen transition is invalid';
        END IF;
    ELSE
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='authentication recovery state is invalid';
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS authentication_recovery_state_transition ON iam.authentication_recovery_state;
CREATE TRIGGER authentication_recovery_state_transition BEFORE UPDATE OR DELETE ON iam.authentication_recovery_state
FOR EACH ROW EXECUTE FUNCTION iam.guard_authentication_recovery_state();
ALTER TABLE iam.authentication_recovery_state ENABLE ALWAYS TRIGGER authentication_recovery_state_transition;
DROP TRIGGER IF EXISTS authentication_recovery_state_cannot_truncate ON iam.authentication_recovery_state;
CREATE TRIGGER authentication_recovery_state_cannot_truncate BEFORE TRUNCATE ON iam.authentication_recovery_state
FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_authentication_recovery_history_change();
ALTER TABLE iam.authentication_recovery_state ENABLE ALWAYS TRIGGER authentication_recovery_state_cannot_truncate;

-- Every product API transaction takes a shared lock. close/reconcile take the
-- exclusive row lock, so the CLOSED receipt cannot overtake an in-flight
-- authority decision. Direct use of the API or credential-recovery login is
-- fenced by current_tenant_id as well as the Go transaction boundary.
CREATE OR REPLACE FUNCTION iam.assert_authentication_open()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE recovery_state text;
BEGIN
    PERFORM set_config('matrix.iam_authentication_recovery','trusted',true);
    SELECT state INTO recovery_state FROM iam.authentication_recovery_state WHERE singleton FOR SHARE;
    IF NOT FOUND OR recovery_state<>'OPEN' THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='IAM authentication authority is closed';
    END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.current_tenant_id()
RETURNS text LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE recovery_state text; tenant text;
BEGIN
    IF session_user IN ('matrix_iam_api_login','matrix_iam_credential_recovery_login') THEN
        PERFORM set_config('matrix.iam_authentication_recovery','trusted',true);
        SELECT state INTO recovery_state FROM iam.authentication_recovery_state WHERE singleton FOR SHARE;
        IF NOT FOUND OR recovery_state<>'OPEN' THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='IAM authentication authority is closed';
        END IF;
    END IF;
    tenant:=current_setting('matrix.iam_tenant_id',true);
    IF tenant COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN RETURN tenant; END IF;
    RETURN NULL;
END $function$;

-- The normal authority's existing recovery GUC is not a global read bypass.
-- Only these two purpose-limited database identities may enumerate Accounts
-- while an internal snapshot producer has explicitly entered this scope.
DROP POLICY IF EXISTS authentication_snapshot_accounts ON iam.accounts;
CREATE POLICY authentication_snapshot_accounts ON iam.accounts FOR SELECT TO matrix_iam_owner
    USING(current_setting('matrix.iam_authentication_snapshot',true)='trusted'
      AND (session_user='matrix_iam_backup_custody_login'
        OR pg_has_role(session_user,'matrix_iam_authentication_recovery','USAGE')));

-- One closed authority projection serves the RR backup snapshot and the
-- SERIALIZABLE close/reopen transaction. It deliberately excludes sessions,
-- attempts, OTP steps, pending ceremonies and delivery leases from the
-- qualification digest. Replay floors travel separately in the same result.
-- No runtime role can call this internal function directly. Its bounded
-- result contains neither verifier material nor complete policy documents.
CREATE OR REPLACE FUNCTION iam.authentication_security_projection()
RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; account record; entry record;
    prior_tenant text:=current_setting('matrix.iam_tenant_id',true);
    prior_snapshot text:=current_setting('matrix.iam_authentication_snapshot',true);
    authority_digest bytea:=sha256(convert_to('matrix.iam.authentication-state.v3','UTF8'));
    accounts jsonb:='[]'::jsonb; users jsonb; result jsonb; items integer:=0; account_count integer; user_count integer;
BEGIN
    IF current_user<>'matrix_iam_owner' OR NOT (
      (session_user='matrix_iam_backup_custody_login' AND current_setting('transaction_isolation')='repeatable read'
        AND current_setting('transaction_read_only')='on')
      OR (pg_has_role(session_user,'matrix_iam_authentication_recovery','USAGE')
        AND current_setting('transaction_isolation')='serializable' AND current_setting('transaction_read_only')='off')) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication snapshot context is forbidden';
    END IF;
    SELECT * INTO receipt FROM iam.bootstrap_receipts WHERE singleton;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication snapshot installation is unavailable'; END IF;
    PERFORM set_config('matrix.iam_authentication_snapshot','trusted',true);
    SELECT count(*) INTO account_count FROM (SELECT 1 FROM iam.accounts LIMIT 3001) bounded;
    IF account_count NOT BETWEEN 1 AND 1500 OR EXISTS(
      SELECT 1 FROM iam.accounts a LEFT JOIN iam.account_roots r ON r.account_id=a.id WHERE r.account_id IS NULL)
      OR (SELECT count(*) FROM iam.account_roots)<>account_count THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication snapshot account set is unavailable';
    END IF;
    PERFORM set_config('matrix.iam_authentication_snapshot',COALESCE(prior_snapshot,''),true);
    PERFORM set_config('matrix.iam_tenant_id','',true);
    -- The fixed-size previous digest plus one typed JSON tuple is an
    -- unambiguous, bounded-memory fold. SQL owns this private projection;
    -- it is not the public Audit canonical or the FILE snapshot encoding.
    FOR entry IN
      SELECT * FROM (SELECT 1 ordinal,p.product key,p.revision::text subkey,
        jsonb_build_array('profile',p.product,p.revision,p.content_digest) document FROM iam.authorization_profiles p
      UNION ALL SELECT 2,h.product,'',jsonb_build_array('profile-head',h.product,h.revision) FROM iam.authorization_profile_heads h
      UNION ALL SELECT 3,p.id,'',jsonb_build_array('system-policy',p.id,p.management,p.authority_scope,p.status,p.default_version_id,p.resource_version)
        FROM iam.policies p WHERE p.owner_tenant_id IS NULL
      UNION ALL SELECT 4,v.policy_id,v.id,jsonb_build_array('system-policy-version',v.policy_id,v.id,v.authority_scope,
        v.content_digest,v.contract_version,v.retired_at IS NOT NULL,
        CASE WHEN v.compilation IS NULL THEN NULL ELSE encode(sha256(convert_to(v.compilation::text,'UTF8')),'hex') END)
        FROM iam.policy_versions v JOIN iam.policies p ON p.id=v.policy_id WHERE p.owner_tenant_id IS NULL) projection
      ORDER BY ordinal,key COLLATE "C",subkey COLLATE "C"
    LOOP
        authority_digest:=sha256(authority_digest||convert_to(entry.document::text,'UTF8'));
    END LOOP;
    FOR account IN SELECT r.account_id,r.principal_id,r.login_name FROM iam.account_roots r ORDER BY r.account_id COLLATE "C" LOOP
        PERFORM set_config('matrix.iam_tenant_id',account.account_id,true);
        -- Count only enough to reject overflow before allocating the JSON
        -- array. This is a transport bound, never an Account creation quota.
        SELECT count(*) INTO user_count FROM (SELECT 1 FROM iam.principals p
          WHERE p.tenant_id=account.account_id AND p.principal_type='USER' LIMIT 3001-items) bounded;
        IF user_count=0 OR items+1+user_count>3000 THEN
            RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication snapshot item limit exceeded';
        END IF;
        IF NOT EXISTS(SELECT 1 FROM iam.principals p WHERE p.tenant_id=account.account_id AND p.id=account.principal_id
            AND p.principal_type='USER' AND p.login_name=account.login_name AND p.deleted_at IS NULL)
          OR EXISTS(SELECT 1 FROM iam.principals p
            LEFT JOIN iam.user_credentials c ON c.tenant_id=p.tenant_id AND c.principal_id=p.id
            LEFT JOIN iam.user_mfa_states m ON m.tenant_id=p.tenant_id AND m.user_id=p.id
            LEFT JOIN iam.totp_authenticators f ON f.tenant_id=m.tenant_id AND f.user_id=m.user_id AND f.id=m.factor_id
            WHERE p.tenant_id=account.account_id AND p.principal_type='USER'
              AND (m.user_id IS NULL OR (p.deleted_at IS NULL)<>(c.principal_id IS NOT NULL)
                OR (c.principal_id IS NOT NULL AND NOT iam.valid_password_history(c.password_history,c.password_history_digest,c.credential_version,c.password_changed_at))
                OR (m.enrollment_state='BOUND' AND (f.id IS NULL OR f.state<>'ACTIVE' OR NOT EXISTS(
                    SELECT 1 FROM iam.mfa_recovery_batches b WHERE b.tenant_id=p.tenant_id AND b.user_id=p.id
                      AND b.factor_id=f.id AND b.mfa_revision=m.revision AND b.revoked_at IS NULL))))) THEN
            RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication snapshot user qualification is unavailable';
        END IF;
        -- REMOVED is a proved historical transition, never an inference from
        -- an absent active factor. Validate every permanent completion even
        -- after rebinding; pending ceremonies and mutable delivery leases do
        -- not enter the qualification digest.
        FOR entry IN SELECT r.id FROM iam.authenticator_removals r
          WHERE r.tenant_id=account.account_id ORDER BY r.id COLLATE "C" LOOP
            PERFORM iam.assert_authenticator_removal(account.account_id,entry.id);
        END LOOP;
        SELECT COALESCE(jsonb_agg(jsonb_build_object('userId',p.id,'factorId',COALESCE(m.factor_id,''),
            'lastConsumedStep',CASE WHEN m.factor_id IS NULL THEN -1 ELSE f.last_consumed_step END,
            'passwordAttempts',CASE WHEN replay.password_window IS NULL THEN NULL ELSE jsonb_build_object(
                'windowStartedAt',rtrim(rtrim(to_char(replay.password_window AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z',
                'usedAttempts',replay.password_used,'sequence',replay.password_sequence) END,
            'totpAttempts',CASE WHEN replay.totp_window IS NULL THEN NULL ELSE jsonb_build_object(
                'windowStartedAt',rtrim(rtrim(to_char(replay.totp_window AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z',
                'usedAttempts',replay.totp_used,'sequence',replay.totp_sequence) END) ORDER BY p.id COLLATE "C"),'[]'::jsonb)
          INTO users FROM iam.principals p
          JOIN iam.user_mfa_states m ON m.tenant_id=p.tenant_id AND m.user_id=p.id
          LEFT JOIN iam.totp_authenticators f ON f.tenant_id=m.tenant_id AND f.id=m.factor_id
          LEFT JOIN iam.password_attempts pw ON pw.tenant_id=p.tenant_id AND pw.principal_id=p.id
          LEFT JOIN iam.totp_attempts otp ON otp.tenant_id=p.tenant_id AND otp.user_id=p.id
          LEFT JOIN iam.user_credentials credential ON credential.tenant_id=p.tenant_id AND credential.principal_id=p.id
          LEFT JOIN iam.authentication_recovery_attempt_floors rf ON rf.tenant_id=p.tenant_id AND rf.user_id=p.id
          CROSS JOIN LATERAL (SELECT
            CASE WHEN rf.password_generation=credential.credential_version AND rf.password_sequence>=COALESCE(pw.attempt_sequence,0)
              THEN rf.password_window_started_at WHEN pw.credential_version=credential.credential_version THEN pw.window_started_at END AS password_window,
            CASE WHEN rf.password_generation=credential.credential_version AND rf.password_sequence>=COALESCE(pw.attempt_sequence,0)
              THEN rf.password_used_attempts WHEN pw.credential_version=credential.credential_version THEN pw.used_attempts END AS password_used,
            CASE WHEN rf.password_generation=credential.credential_version AND rf.password_sequence>=COALESCE(pw.attempt_sequence,0)
              THEN rf.password_sequence WHEN pw.credential_version=credential.credential_version THEN pw.attempt_sequence END AS password_sequence,
            CASE WHEN rf.totp_sequence>=COALESCE(otp.sequence,0) THEN rf.totp_window_started_at ELSE otp.window_started_at END AS totp_window,
            CASE WHEN rf.totp_sequence>=COALESCE(otp.sequence,0) THEN rf.totp_used_attempts ELSE otp.used_attempts END AS totp_used,
            CASE WHEN rf.totp_sequence>=COALESCE(otp.sequence,0) THEN rf.totp_sequence ELSE otp.sequence END AS totp_sequence) replay
          WHERE p.tenant_id=account.account_id AND p.principal_type='USER';
        items:=items+1+jsonb_array_length(users);
        IF jsonb_array_length(users)<>user_count THEN
            RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication snapshot user set is incomplete';
        END IF;
        accounts:=accounts||jsonb_build_array(jsonb_build_object('accountId',account.account_id,'users',users));
        IF octet_length(accounts::text)>2097152 THEN
            RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication snapshot byte limit exceeded';
        END IF;
        FOR entry IN
          SELECT * FROM (SELECT 1 ordinal,a.id key,''::text subkey,jsonb_build_array('account',a.id,a.status,a.resource_version,
            a.security_settings_version,a.mfa_required_for_users,account.principal_id,account.login_name) document
            FROM iam.accounts a WHERE a.id=account.account_id
          UNION ALL SELECT 2,a.alias,'',jsonb_build_array('alias',a.tenant_id,a.alias,a.active)
            FROM iam.account_aliases a WHERE a.tenant_id=account.account_id
          UNION ALL SELECT 3,p.id,'',jsonb_build_array('principal',p.tenant_id,p.id,p.principal_type,p.login_name,p.status,
            p.must_change_password,p.resource_version,p.deleted_at IS NOT NULL,c.credential_version,
            CASE WHEN c.password_hash IS NULL THEN NULL ELSE encode(sha256(convert_to(c.password_hash,'UTF8')),'hex') END,
            extract(epoch FROM c.password_changed_at),encode(c.password_history_digest,'hex'))
            FROM iam.principals p LEFT JOIN iam.user_credentials c ON c.tenant_id=p.tenant_id AND c.principal_id=p.id
            WHERE p.tenant_id=account.account_id
          UNION ALL SELECT 4,m.user_id,'',jsonb_build_array('mfa',m.tenant_id,m.user_id,m.revision,m.enrollment_state,m.factor_id,m.recovery_id,m.removal_id)
            FROM iam.user_mfa_states m WHERE m.tenant_id=account.account_id
          UNION ALL SELECT 5,f.id,'',jsonb_build_array('active-factor',f.tenant_id,f.user_id,f.id,f.installation_id,f.key_id,
            f.format_version,encode(sha256(f.nonce||f.ciphertext),'hex'),f.enrollment_revision,f.removal_id)
            FROM iam.totp_authenticators f WHERE f.tenant_id=account.account_id AND f.state='ACTIVE'
          UNION ALL SELECT 6,b.id,'',jsonb_build_array('recovery-batch',b.tenant_id,b.user_id,b.id,b.factor_id,b.mfa_revision,b.event_id,
            b.revoked_at IS NOT NULL,b.revocation_recovery_id,b.regeneration_id,b.revocation_regeneration_id,b.revocation_replacement_factor_id,b.revocation_removal_id)
            FROM iam.mfa_recovery_batches b WHERE b.tenant_id=account.account_id
          UNION ALL SELECT 7,c.user_id,'',jsonb_build_array('contact',c.tenant_id,c.user_id,c.email,c.resource_version,c.verification_id)
            FROM iam.notification_contacts c WHERE c.tenant_id=account.account_id
          UNION ALL SELECT 8,p.id,'',jsonb_build_array('customer-policy',p.id,p.owner_tenant_id,p.management,p.authority_scope,
            p.status,p.default_version_id,p.resource_version) FROM iam.policies p WHERE p.owner_tenant_id=account.account_id
          UNION ALL SELECT 9,v.policy_id,v.id,jsonb_build_array('customer-policy-version',v.policy_id,v.id,v.authority_scope,
            v.content_digest,v.contract_version,v.retired_at IS NOT NULL,
            CASE WHEN v.compilation IS NULL THEN NULL ELSE encode(sha256(convert_to(v.compilation::text,'UTF8')),'hex') END)
            FROM iam.policy_versions v JOIN iam.policies p ON p.id=v.policy_id WHERE p.owner_tenant_id=account.account_id
          UNION ALL SELECT 10,a.id,'',jsonb_build_array('attachment',a.tenant_id,a.id,a.target_kind,a.target_id,a.policy_id,
            a.authority_scope,a.installation_id,a.resource_version,a.revoked_at IS NOT NULL) FROM iam.policy_attachments a WHERE a.tenant_id=account.account_id
          UNION ALL SELECT 11,b.id,'',jsonb_build_array('user-boundary',b.tenant_id,b.id,b.user_id,b.policy_id,b.resource_version,b.revoked_at IS NOT NULL)
            FROM iam.user_permission_boundaries b WHERE b.tenant_id=account.account_id
          UNION ALL SELECT 12,g.id,'',jsonb_build_array('group',g.tenant_id,g.id,g.resource_version,g.deleted_at IS NOT NULL)
            FROM iam.groups g WHERE g.tenant_id=account.account_id
          UNION ALL SELECT 13,m.id,'',jsonb_build_array('membership',m.tenant_id,m.id,m.group_id,m.user_id,m.resource_version,m.removed_at IS NOT NULL)
            FROM iam.group_memberships m WHERE m.tenant_id=account.account_id
          UNION ALL SELECT 14,r.id,'',jsonb_build_array('role',r.tenant_id,r.id,r.status,r.resource_version,r.current_trust_version_id,
            r.security_generation,r.deleted_at IS NOT NULL) FROM iam.roles r WHERE r.tenant_id=account.account_id
          UNION ALL SELECT 15,v.role_id,v.id,jsonb_build_array('role-trust',v.tenant_id,v.role_id,v.id,v.content_digest)
            FROM iam.role_trust_versions v WHERE v.tenant_id=account.account_id
          UNION ALL SELECT 16,b.id,'',jsonb_build_array('role-boundary',b.tenant_id,b.id,b.role_id,b.policy_id,b.resource_version,b.revoked_at IS NOT NULL)
            FROM iam.role_permission_boundaries b WHERE b.tenant_id=account.account_id
          UNION ALL SELECT 17,COALESCE(g.user_id,g.group_id),CASE WHEN g.user_id IS NULL THEN 'GROUP' ELSE 'USER' END,
            jsonb_build_array('role-source',g.tenant_id,g.user_id,g.group_id,g.generation)
            FROM iam.role_source_authority_generations g WHERE g.tenant_id=account.account_id
          UNION ALL SELECT 18,c.principal_id,'',jsonb_build_array('service-credential',c.tenant_id,c.principal_id,c.purpose,
            c.lookup_digest,c.verification_digest,c.revoked_at IS NOT NULL) FROM iam.service_credentials c WHERE c.tenant_id=account.account_id
          UNION ALL SELECT 19,r.command_id,'',jsonb_build_array('local-recovery',r.tenant_id,r.installation_id,r.primary_principal_id,
            r.bootstrap_digest,r.command_id,r.input_commitment,r.completed_result) FROM iam.local_credential_recoveries r WHERE r.tenant_id=account.account_id
          UNION ALL SELECT 20,r.id,'',jsonb_build_array('authenticator-removal',r.tenant_id,r.user_id,r.id,r.request_id,
            r.step_up_id,r.factor_id,r.batch_id,r.previous_revision,r.revision,r.event_id,r.request_digest,r.notification_id,
            extract(epoch FROM r.created_at),p.source_session_id,p.credential_generation,p.principal_version,
            extract(epoch FROM p.proved_at),p.verified_step)
            FROM iam.authenticator_removals r JOIN iam.step_ups p ON p.tenant_id=r.tenant_id AND p.id=r.step_up_id
            WHERE r.tenant_id=account.account_id
          UNION ALL SELECT 21,f.id,'',jsonb_build_array('confirmed-rebinding',f.tenant_id,f.user_id,f.id,f.removal_id,
            f.enrollment_revision,f.bound_revision,f.bound_event_id,extract(epoch FROM f.completed_at))
            FROM iam.totp_authenticators f WHERE f.tenant_id=account.account_id AND f.removal_id IS NOT NULL
              AND f.enrollment_outcome='CONFIRMED') projection
          ORDER BY ordinal,key COLLATE "C",subkey COLLATE "C"
        LOOP
            authority_digest:=sha256(authority_digest||convert_to(entry.document::text,'UTF8'));
        END LOOP;
    END LOOP;
    PERFORM set_config('matrix.iam_tenant_id',COALESCE(prior_tenant,''),true);
    result:=jsonb_build_object('authenticationStateDigest','sha256:'||encode(authority_digest,'hex'),'accounts',accounts);
    RETURN result;
END $function$;
REVOKE ALL ON FUNCTION iam.authentication_security_projection() FROM PUBLIC,matrix_iam_api,matrix_iam_worker,
    matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery;

CREATE OR REPLACE FUNCTION iam.assert_authentication_recovery_event(submitted_event jsonb,expected_action text,
    expected_installation text,expected_command text,expected_request_digest text,expected_time timestamptz)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stage text; expected_event_id text;
BEGIN
    stage:=CASE expected_action
      WHEN 'iam.authentication-recovery.closed' THEN 'closed'
      WHEN 'iam.authentication-recovery.reconciled' THEN 'reconciled'
      WHEN 'iam.authentication-recovery.reopened' THEN 'reopened'
      ELSE NULL END;
    IF stage IS NULL OR expected_installation COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR expected_command COLLATE "C" !~ '^cmd-[0-9a-f]{32}$'
      OR expected_request_digest COLLATE "C" !~ '^sha256:[0-9a-f]{64}$' OR expected_time IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authentication recovery Audit expectation is invalid';
    END IF;
    expected_event_id:='event-auth-recovery-'||stage||'-'||substr(expected_command,5);
    IF jsonb_typeof(submitted_event) IS DISTINCT FROM 'object'
      OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(submitted_event) key) IS DISTINCT FROM
        ARRAY['action','actor','apiVersion','correlationId','eventId','installationId','kind','occurredAt','requestDigest','requestId','result','target']
      OR jsonb_typeof(submitted_event->'actor') IS DISTINCT FROM 'object'
      OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(submitted_event->'actor') key) IS DISTINCT FROM ARRAY['id','type']
      OR jsonb_typeof(submitted_event->'target') IS DISTINCT FROM 'object'
      OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(submitted_event->'target') key) IS DISTINCT FROM ARRAY['id','kind']
      OR submitted_event->>'apiVersion' IS DISTINCT FROM 'audit.matrix.xiak.com/v1'
      OR submitted_event->>'kind' IS DISTINCT FROM 'AuditEvent'
      OR submitted_event->>'eventId' IS DISTINCT FROM expected_event_id
      OR submitted_event->>'installationId' IS DISTINCT FROM expected_installation
      OR submitted_event#>>'{actor,type}' IS DISTINCT FROM 'SYSTEM'
      OR submitted_event#>>'{actor,id}' IS DISTINCT FROM 'iam-authentication-recovery'
      OR submitted_event->>'action' IS DISTINCT FROM expected_action
      OR submitted_event#>>'{target,kind}' IS DISTINCT FROM 'INSTALLATION'
      OR submitted_event#>>'{target,id}' IS DISTINCT FROM expected_installation
      OR submitted_event->>'result' IS DISTINCT FROM 'SUCCEEDED'
      OR submitted_event->>'requestDigest' IS DISTINCT FROM expected_request_digest
      OR submitted_event->>'requestId' IS DISTINCT FROM expected_command
      OR submitted_event->>'correlationId' IS DISTINCT FROM expected_command
      OR jsonb_typeof(submitted_event->'occurredAt') IS DISTINCT FROM 'string'
      OR COALESCE(submitted_event->>'occurredAt','') COLLATE "C" !~
        '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
      OR NOT pg_input_is_valid(COALESCE(submitted_event->>'occurredAt',''),'timestamptz')
      OR (submitted_event->>'occurredAt')::timestamptz IS DISTINCT FROM expected_time
      OR octet_length(submitted_event::text)>131072 THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authentication recovery Audit event is invalid';
    END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.prepare_authentication_recovery_close(intent jsonb,intent_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; current_state iam.authentication_recovery_state%ROWTYPE;
    stored iam.authentication_recovery_closures%ROWTYPE; projection jsonb; effective_now timestamptz(6):=transaction_timestamp();
    numeric_epoch bigint;
BEGIN
    IF NOT pg_has_role(session_user,'matrix_iam_authentication_recovery','USAGE')
      OR current_setting('transaction_isolation')<>'serializable' OR current_setting('transaction_read_only')<>'off' THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication recovery transaction context is forbidden';
    END IF;
    PERFORM set_config('matrix.iam_authentication_recovery','trusted',true);
    IF jsonb_typeof(intent) IS DISTINCT FROM 'object'
      OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(intent) key) IS DISTINCT FROM ARRAY[
        'apiVersion','authenticationStateDigest','backupDigest','backupId','commandId','epoch','installationId','kind','purpose',
        'sourceReleaseDigest','sourceReleaseId','targetReleaseDigest','targetReleaseId','totpCustodyDigest']
      OR intent->>'apiVersion'<>'installation.matrix.xiak.com/v1' OR intent->>'kind'<>'IAMAuthenticationRecoveryIntent'
      OR intent->>'purpose'<>'IAM_AUTHENTICATION_BACKUP_RECOVERY'
      OR COALESCE(intent->>'installationId','') COLLATE "C" !~ '^mxi-[0-9a-f]{32}$'
      OR jsonb_typeof(intent->'epoch') IS DISTINCT FROM 'number' OR COALESCE(intent->>'epoch','') !~ '^[1-9][0-9]{0,18}$'
      OR (intent->>'epoch')::numeric>9223372036854775807
      OR COALESCE(intent->>'commandId','') COLLATE "C" !~ '^cmd-[0-9a-f]{32}$'
      OR COALESCE(intent->>'backupId','') COLLATE "C" !~ '^backup-[0-9a-f]{32}$'
      OR COALESCE(intent->>'sourceReleaseId','') COLLATE "C" !~ '^matrix-v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-[0-9A-Za-z][0-9A-Za-z.-]{0,63})?-[0-9a-f]{12}$'
      OR COALESCE(intent->>'targetReleaseId','') COLLATE "C" !~ '^matrix-v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-[0-9A-Za-z][0-9A-Za-z.-]{0,63})?-[0-9a-f]{12}$'
      OR intent_digest COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
      OR intent->>'backupDigest' !~ '^sha256:[0-9a-f]{64}$' OR intent->>'sourceReleaseDigest' !~ '^sha256:[0-9a-f]{64}$'
      OR intent->>'targetReleaseDigest' !~ '^sha256:[0-9a-f]{64}$' OR intent->>'totpCustodyDigest' !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authentication recovery intent is invalid';
    END IF;
    IF jsonb_typeof(intent->'authenticationStateDigest') IS DISTINCT FROM 'string'
      OR intent->>'authenticationStateDigest' !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authentication recovery qualification is invalid';
    END IF;
    numeric_epoch:=(intent->>'epoch')::bigint;
    SELECT * INTO receipt FROM iam.bootstrap_receipts WHERE singleton AND installation_id=intent->>'installationId' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication recovery installation is forbidden'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',receipt.organization_id,true);
    SELECT * INTO stored FROM iam.authentication_recovery_closures c WHERE c.command_id=intent->>'commandId';
    IF FOUND THEN
        IF stored.origin<>'SOURCE' OR stored.intent_digest<>intent_digest OR stored.intent_document<>intent THEN
            RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication recovery close conflicts';
        END IF;
        IF stored.security_snapshot_document IS NULL THEN
            RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication recovery snapshot is unavailable';
        END IF;
        RETURN stored.security_snapshot_document;
    END IF;
    SELECT * INTO current_state FROM iam.authentication_recovery_state WHERE singleton FOR UPDATE;
    IF NOT FOUND OR current_state.state<>'OPEN' OR numeric_epoch<>current_state.epoch+1
      OR EXISTS(SELECT 1 FROM iam.authentication_recovery_closures c WHERE c.epoch=numeric_epoch) THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication recovery epoch conflicts';
    END IF;
    projection:=iam.authentication_security_projection();
    IF projection->>'authenticationStateDigest' IS DISTINCT FROM intent->>'authenticationStateDigest' THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='backup authentication qualification is not current';
    END IF;
    RETURN jsonb_build_object('apiVersion','installation.matrix.xiak.com/v1','kind','IAMAuthenticationRecoverySecuritySnapshot',
      'purpose','IAM_AUTHENTICATION_BACKUP_RECOVERY','installationId',receipt.installation_id,
      'bootstrapDigest',receipt.content_digest,'epoch',numeric_epoch,'commandId',intent->>'commandId',
      'recoveryIntentDigest',intent_digest,
      'closedAt',rtrim(rtrim(to_char(effective_now AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z',
      'authenticationStateDigest',projection->'authenticationStateDigest','accounts',projection->'accounts');
END $function$;

-- No old-signature execute path survives the shape replacement. Prepare and
-- seal run under one caller-owned SERIALIZABLE transaction; neither the JSON
-- projection nor an uncommitted candidate grants installation permission.
DROP FUNCTION IF EXISTS iam.close_authentication_recovery(jsonb,text,jsonb);
CREATE OR REPLACE FUNCTION iam.close_authentication_recovery(intent jsonb,intent_digest text,closed_event jsonb,
    security_snapshot jsonb,security_snapshot_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; stored iam.authentication_recovery_closures%ROWTYPE;
    expected_snapshot jsonb; closure jsonb; effective_now timestamptz(6);
BEGIN
    IF jsonb_typeof(security_snapshot) IS DISTINCT FROM 'object'
      OR octet_length(security_snapshot::text)>2097152
      OR security_snapshot_digest IS NULL OR security_snapshot_digest COLLATE "C" !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authentication recovery snapshot is invalid';
    END IF;
    expected_snapshot:=iam.prepare_authentication_recovery_close(intent,intent_digest);
    IF security_snapshot IS DISTINCT FROM expected_snapshot THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication recovery snapshot conflicts';
    END IF;
    SELECT * INTO stored FROM iam.authentication_recovery_closures c WHERE c.command_id=intent->>'commandId';
    IF FOUND THEN
        IF stored.closure_document->>'securitySnapshotDigest' IS DISTINCT FROM security_snapshot_digest THEN
            RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication recovery snapshot digest conflicts';
        END IF;
        RETURN stored.closure_document;
    END IF;
    SELECT * INTO receipt FROM iam.bootstrap_receipts WHERE singleton;
    effective_now:=(expected_snapshot->>'closedAt')::timestamptz;
    PERFORM set_config('matrix.iam_tenant_id',receipt.organization_id,true);
    closure:=jsonb_build_object('apiVersion','installation.matrix.xiak.com/v1','kind','IAMAuthenticationRecoveryClosure',
      'purpose','IAM_AUTHENTICATION_BACKUP_RECOVERY','installationId',receipt.installation_id,'epoch',intent->'epoch',
      'state','CLOSED','commandId',intent->>'commandId','backupId',intent->>'backupId','backupDigest',intent->>'backupDigest',
      'recoveryIntentDigest',intent_digest,'totpCustodyDigest',intent->>'totpCustodyDigest',
      'closedAt',expected_snapshot->'closedAt','securitySnapshotDigest',security_snapshot_digest);
    PERFORM iam.assert_authentication_recovery_event(closed_event,'iam.authentication-recovery.closed',receipt.installation_id,
      intent->>'commandId',intent_digest,effective_now);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(receipt.organization_id,closed_event->>'eventId',closed_event,effective_now,effective_now,effective_now);
    INSERT INTO iam.authentication_recovery_closures(command_id,installation_id,home_tenant_id,epoch,origin,intent_digest,
      intent_document,closure_document,security_snapshot_document,closed_event_id,closed_event_document,closed_at)
      VALUES(intent->>'commandId',receipt.installation_id,receipt.organization_id,(intent->>'epoch')::bigint,'SOURCE',intent_digest,
        intent,closure,security_snapshot,closed_event->>'eventId',closed_event,effective_now);
    UPDATE iam.authentication_recovery_state SET epoch=(intent->>'epoch')::bigint,state='CLOSED',
      active_command_id=intent->>'commandId',updated_at=effective_now WHERE singleton;
    RETURN closure;
END $function$;

-- The signed private caller verifies canonical bytes/digest before entering
-- this transaction. IAM additionally proves the restored qualification and
-- complete Account/USER/factor set under the same exclusive authority barrier.
-- Neither the caller's subset nor a digest alone establishes completeness.
CREATE OR REPLACE FUNCTION iam.assert_authentication_recovery_snapshot(closure jsonb,security_snapshot jsonb)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; projection jsonb; expected_scope jsonb; submitted_scope jsonb;
BEGIN
    SELECT * INTO receipt FROM iam.bootstrap_receipts WHERE singleton;
    IF receipt.installation_id IS NULL OR jsonb_typeof(security_snapshot) IS DISTINCT FROM 'object'
      OR octet_length(security_snapshot::text)>2097152
      OR security_snapshot->>'installationId' IS DISTINCT FROM receipt.installation_id
      OR security_snapshot->>'bootstrapDigest' IS DISTINCT FROM receipt.content_digest
      OR security_snapshot->>'installationId' IS DISTINCT FROM closure->>'installationId'
      OR security_snapshot->>'commandId' IS DISTINCT FROM closure->>'commandId'
      OR security_snapshot->'epoch' IS DISTINCT FROM closure->'epoch'
      OR security_snapshot->>'recoveryIntentDigest' IS DISTINCT FROM closure->>'recoveryIntentDigest'
      OR security_snapshot->>'closedAt' IS DISTINCT FROM closure->>'closedAt'
      OR jsonb_typeof(security_snapshot->'accounts') IS DISTINCT FROM 'array'
      OR (closure->>'closedAt')::timestamptz>transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication recovery snapshot scope conflicts';
    END IF;
    projection:=iam.authentication_security_projection();
    IF security_snapshot->>'authenticationStateDigest' IS DISTINCT FROM projection->>'authenticationStateDigest' THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='restored authentication qualification conflicts';
    END IF;
    SELECT jsonb_agg(jsonb_build_object('accountId',a->'accountId','users',(
        SELECT jsonb_agg(u-'lastConsumedStep'-'passwordAttempts'-'totpAttempts' ORDER BY u->>'userId' COLLATE "C")
        FROM jsonb_array_elements(a->'users') u)) ORDER BY a->>'accountId' COLLATE "C") INTO expected_scope
        FROM jsonb_array_elements(projection->'accounts') a;
    SELECT jsonb_agg(jsonb_build_object('accountId',a->'accountId','users',(
        SELECT jsonb_agg(u-'lastConsumedStep'-'passwordAttempts'-'totpAttempts' ORDER BY u->>'userId' COLLATE "C")
        FROM jsonb_array_elements(a->'users') u)) ORDER BY a->>'accountId' COLLATE "C") INTO submitted_scope
        FROM jsonb_array_elements(security_snapshot->'accounts') a;
    IF submitted_scope IS DISTINCT FROM expected_scope THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='restored authentication subject set conflicts';
    END IF;
END $function$;
REVOKE ALL ON FUNCTION iam.assert_authentication_recovery_snapshot(jsonb,jsonb) FROM PUBLIC,matrix_iam_api,matrix_iam_worker,
    matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery;

DROP FUNCTION IF EXISTS iam.reconcile_authentication_recovery(jsonb,text,jsonb,jsonb);
CREATE OR REPLACE FUNCTION iam.reconcile_authentication_recovery(closure jsonb,closure_digest text,
    closed_event jsonb,reconciled_event jsonb,security_snapshot jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; current_state iam.authentication_recovery_state%ROWTYPE;
    stored iam.authentication_recovery_closures%ROWTYPE; reconciled iam.authentication_recovery_reconciliations%ROWTYPE;
    effective_now timestamptz(6):=transaction_timestamp(); numeric_epoch bigint; closed_time timestamptz(6);
BEGIN
    IF NOT pg_has_role(session_user,'matrix_iam_authentication_recovery','USAGE')
      OR current_setting('transaction_isolation')<>'serializable' OR current_setting('transaction_read_only')<>'off' THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication recovery transaction context is forbidden';
    END IF;
    PERFORM set_config('matrix.iam_authentication_recovery','trusted',true);
    IF jsonb_typeof(closure) IS DISTINCT FROM 'object'
      OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(closure) key) IS DISTINCT FROM ARRAY[
        'apiVersion','backupDigest','backupId','closedAt','commandId','epoch','installationId','kind','purpose',
        'recoveryIntentDigest','securitySnapshotDigest','state','totpCustodyDigest']
      OR closure->>'apiVersion'<>'installation.matrix.xiak.com/v1' OR closure->>'kind'<>'IAMAuthenticationRecoveryClosure'
      OR closure->>'purpose'<>'IAM_AUTHENTICATION_BACKUP_RECOVERY' OR closure->>'state'<>'CLOSED'
      OR COALESCE(closure->>'installationId','') COLLATE "C" !~ '^mxi-[0-9a-f]{32}$'
      OR jsonb_typeof(closure->'epoch') IS DISTINCT FROM 'number' OR COALESCE(closure->>'epoch','') !~ '^[1-9][0-9]{0,18}$'
      OR (closure->>'epoch')::numeric>9223372036854775807
      OR COALESCE(closure->>'commandId','') COLLATE "C" !~ '^cmd-[0-9a-f]{32}$'
      OR COALESCE(closure->>'backupId','') COLLATE "C" !~ '^backup-[0-9a-f]{32}$'
      OR closure->>'backupDigest' !~ '^sha256:[0-9a-f]{64}$' OR closure->>'recoveryIntentDigest' !~ '^sha256:[0-9a-f]{64}$'
      OR closure->>'totpCustodyDigest' !~ '^sha256:[0-9a-f]{64}$' OR closure_digest !~ '^sha256:[0-9a-f]{64}$'
      OR jsonb_typeof(closure->'securitySnapshotDigest') IS DISTINCT FROM 'string'
      OR closure->>'securitySnapshotDigest' !~ '^sha256:[0-9a-f]{64}$'
      OR jsonb_typeof(closure->'closedAt') IS DISTINCT FROM 'string'
      OR NOT pg_input_is_valid(COALESCE(closure->>'closedAt',''),'timestamptz') THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authentication recovery closure is invalid';
    END IF;
    numeric_epoch:=(closure->>'epoch')::bigint; closed_time:=(closure->>'closedAt')::timestamptz;
    SELECT * INTO receipt FROM iam.bootstrap_receipts WHERE singleton AND installation_id=closure->>'installationId' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication recovery installation is forbidden'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',receipt.organization_id,true);
    SELECT * INTO stored FROM iam.authentication_recovery_closures c WHERE c.command_id=closure->>'commandId';
    IF FOUND THEN
        IF stored.closure_document<>closure OR stored.security_snapshot_document IS DISTINCT FROM security_snapshot THEN
            RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication recovery closure conflicts'; END IF;
        SELECT * INTO reconciled FROM iam.authentication_recovery_reconciliations r WHERE r.command_id=stored.command_id;
        IF NOT FOUND OR reconciled.closure_digest<>closure_digest THEN
            RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='source authority cannot be reconciled as restored';
        END IF;
        RETURN stored.closure_document;
    END IF;
    SELECT * INTO current_state FROM iam.authentication_recovery_state WHERE singleton FOR UPDATE;
    IF NOT FOUND OR current_state.state<>'OPEN' OR numeric_epoch<>current_state.epoch+1
      OR EXISTS(SELECT 1 FROM iam.authentication_recovery_closures c WHERE c.epoch=numeric_epoch) THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication recovery reconciliation conflicts';
    END IF;
    PERFORM iam.assert_authentication_recovery_snapshot(closure,security_snapshot);
    PERFORM iam.assert_authentication_recovery_event(closed_event,'iam.authentication-recovery.closed',receipt.installation_id,
      closure->>'commandId',closure->>'recoveryIntentDigest',closed_time);
    PERFORM iam.assert_authentication_recovery_event(reconciled_event,'iam.authentication-recovery.reconciled',receipt.installation_id,
      closure->>'commandId',closure_digest,effective_now);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at) VALUES
      (receipt.organization_id,closed_event->>'eventId',closed_event,effective_now,effective_now,effective_now),
      (receipt.organization_id,reconciled_event->>'eventId',reconciled_event,effective_now,effective_now,effective_now);
    INSERT INTO iam.authentication_recovery_closures(command_id,installation_id,home_tenant_id,epoch,origin,intent_digest,
      intent_document,closure_document,security_snapshot_document,closed_event_id,closed_event_document,closed_at)
      VALUES(closure->>'commandId',receipt.installation_id,receipt.organization_id,numeric_epoch,'RESTORED',closure->>'recoveryIntentDigest',
        NULL,closure,security_snapshot,closed_event->>'eventId',closed_event,closed_time);
    INSERT INTO iam.authentication_recovery_reconciliations(command_id,installation_id,home_tenant_id,closure_digest,
      reconciled_event_id,reconciled_event_document,reconciled_at)
      VALUES(closure->>'commandId',receipt.installation_id,receipt.organization_id,closure_digest,
        reconciled_event->>'eventId',reconciled_event,effective_now);
    UPDATE iam.authentication_recovery_state SET epoch=numeric_epoch,state='CLOSED',active_command_id=closure->>'commandId',updated_at=effective_now
      WHERE singleton;
    RETURN closure;
END $function$;

DROP FUNCTION IF EXISTS iam.reopen_authentication_recovery(jsonb,text,jsonb);
CREATE OR REPLACE FUNCTION iam.reopen_authentication_recovery(closure jsonb,closure_digest text,reopened_event jsonb,security_snapshot jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; current_state iam.authentication_recovery_state%ROWTYPE;
    stored iam.authentication_recovery_closures%ROWTYPE; reconciled iam.authentication_recovery_reconciliations%ROWTYPE;
    completed iam.authentication_recovery_completions%ROWTYPE; completion jsonb;
    effective_now timestamptz(6):=transaction_timestamp(); current_step bigint; tenant record;
BEGIN
    IF NOT pg_has_role(session_user,'matrix_iam_authentication_recovery','USAGE')
      OR current_setting('transaction_isolation')<>'serializable' OR current_setting('transaction_read_only')<>'off' THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication recovery transaction context is forbidden';
    END IF;
    PERFORM set_config('matrix.iam_authentication_recovery','trusted',true);
    IF jsonb_typeof(closure) IS DISTINCT FROM 'object' OR closure->>'state'<>'CLOSED'
      OR COALESCE(closure->>'commandId','') COLLATE "C" !~ '^cmd-[0-9a-f]{32}$'
      OR COALESCE(closure->>'installationId','') COLLATE "C" !~ '^mxi-[0-9a-f]{32}$'
      OR jsonb_typeof(closure->'epoch') IS DISTINCT FROM 'number' OR COALESCE(closure->>'epoch','') !~ '^[1-9][0-9]{0,18}$'
      OR (closure->>'epoch')::numeric>9223372036854775807 OR closure_digest !~ '^sha256:[0-9a-f]{64}$'
      OR jsonb_typeof(closure->'securitySnapshotDigest') IS DISTINCT FROM 'string'
      OR closure->>'securitySnapshotDigest' !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authentication recovery reopen input is invalid';
    END IF;
    SELECT * INTO completed FROM iam.authentication_recovery_completions c WHERE c.command_id=closure->>'commandId';
    IF FOUND THEN
        IF completed.closure_digest<>closure_digest OR NOT EXISTS(SELECT 1 FROM iam.authentication_recovery_closures c
          WHERE c.command_id=completed.command_id AND c.closure_document=closure AND c.security_snapshot_document=security_snapshot) THEN
            RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication recovery completion conflicts';
        END IF;
        RETURN completed.completion_document;
    END IF;
    SELECT * INTO current_state FROM iam.authentication_recovery_state WHERE singleton FOR UPDATE;
    SELECT * INTO receipt FROM iam.bootstrap_receipts WHERE singleton AND installation_id=closure->>'installationId' FOR SHARE;
    SELECT * INTO stored FROM iam.authentication_recovery_closures c WHERE c.command_id=closure->>'commandId';
    SELECT * INTO reconciled FROM iam.authentication_recovery_reconciliations r WHERE r.command_id=closure->>'commandId';
    IF receipt.installation_id IS NULL OR stored.command_id IS NULL OR reconciled.command_id IS NULL
      OR stored.closure_document<>closure OR reconciled.closure_digest<>closure_digest
      OR stored.security_snapshot_document IS DISTINCT FROM security_snapshot
      OR current_state.state<>'CLOSED' OR current_state.epoch<>(closure->>'epoch')::bigint
      OR current_state.active_command_id<>closure->>'commandId' OR effective_now<=stored.closed_at THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication recovery reopen conflicts';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',receipt.organization_id,true);
    PERFORM iam.assert_authentication_recovery_snapshot(closure,security_snapshot);
    PERFORM iam.assert_authentication_recovery_event(reopened_event,'iam.authentication-recovery.reopened',receipt.installation_id,
      closure->>'commandId',closure_digest,effective_now);
    completion:=jsonb_build_object('apiVersion','installation.matrix.xiak.com/v1','kind','IAMAuthenticationRecoveryCompletion',
      'purpose','IAM_AUTHENTICATION_BACKUP_RECOVERY','installationId',receipt.installation_id,'epoch',(closure->>'epoch')::bigint,
      'state','REOPENED','commandId',closure->>'commandId','closureDigest',closure_digest,'completedAt',effective_now,
      'securitySnapshotDigest',closure->>'securitySnapshotDigest');
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(receipt.organization_id,reopened_event->>'eventId',reopened_event,effective_now,effective_now,effective_now);
    INSERT INTO iam.authentication_recovery_completions(command_id,installation_id,home_tenant_id,closure_digest,
      completion_document,reopened_event_id,reopened_event_document,completed_at)
      VALUES(closure->>'commandId',receipt.installation_id,receipt.organization_id,closure_digest,completion,
        reopened_event->>'eventId',reopened_event,effective_now);

    current_step:=floor(extract(epoch FROM clock_timestamp())/30)::bigint;
    FOR tenant IN SELECT root.account_id FROM iam.account_roots root ORDER BY root.account_id COLLATE "C" LOOP
        PERFORM set_config('matrix.iam_tenant_id',tenant.account_id,true);
        IF EXISTS(SELECT 1 FROM iam.user_credentials c WHERE c.tenant_id=tenant.account_id
            AND c.credential_version>=9007199254740991) THEN
            RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication credential generation is exhausted';
        END IF;
        UPDATE iam.user_credentials SET credential_version=credential_version+1,changed_at=effective_now
          WHERE tenant_id=tenant.account_id;
        UPDATE iam.sessions SET status='REVOKED',revoked_at=effective_now,resource_version=resource_version+1
          WHERE tenant_id=tenant.account_id AND status='ACTIVE';
        UPDATE iam.role_sessions SET revoked_at=effective_now
          WHERE tenant_id=tenant.account_id AND revoked_at IS NULL;
        UPDATE iam.password_attempts SET state='ABANDONED',completed_at=effective_now
          WHERE tenant_id=tenant.account_id AND state='RESERVED';
        UPDATE iam.totp_attempts SET state='ABANDONED',completed_at=effective_now
          WHERE tenant_id=tenant.account_id AND state='RESERVED';
        UPDATE iam.authentication_challenges SET state='CANCELLED',completed_at=effective_now
          WHERE tenant_id=tenant.account_id AND state='PENDING';
        INSERT INTO iam.authentication_recovery_attempt_floors(tenant_id,user_id,command_id,
          password_generation,password_window_started_at,password_used_attempts,password_sequence,
          totp_window_started_at,totp_used_attempts,totp_sequence)
          SELECT tenant.account_id,u->>'userId',closure->>'commandId',
            CASE WHEN u->'passwordAttempts'<>'null'::jsonb THEN c.credential_version END,
            (u#>>'{passwordAttempts,windowStartedAt}')::timestamptz,(u#>>'{passwordAttempts,usedAttempts}')::integer,
            (u#>>'{passwordAttempts,sequence}')::bigint,
            (u#>>'{totpAttempts,windowStartedAt}')::timestamptz,(u#>>'{totpAttempts,usedAttempts}')::integer,
            (u#>>'{totpAttempts,sequence}')::bigint
          FROM jsonb_array_elements(security_snapshot->'accounts') a
          CROSS JOIN LATERAL jsonb_array_elements(a->'users') u
          LEFT JOIN iam.user_credentials c ON c.tenant_id=tenant.account_id AND c.principal_id=u->>'userId'
          WHERE a->>'accountId'=tenant.account_id
          ON CONFLICT(tenant_id,user_id) DO UPDATE SET command_id=EXCLUDED.command_id,
            password_generation=EXCLUDED.password_generation,password_window_started_at=EXCLUDED.password_window_started_at,
            password_used_attempts=EXCLUDED.password_used_attempts,password_sequence=EXCLUDED.password_sequence,
            totp_window_started_at=EXCLUDED.totp_window_started_at,totp_used_attempts=EXCLUDED.totp_used_attempts,totp_sequence=EXCLUDED.totp_sequence;
        UPDATE iam.totp_authenticators f SET last_consumed_step=greatest(f.last_consumed_step,current_step,(u->>'lastConsumedStep')::bigint)
          FROM jsonb_array_elements(security_snapshot->'accounts') a CROSS JOIN LATERAL jsonb_array_elements(a->'users') u
          WHERE a->>'accountId'=tenant.account_id AND f.tenant_id=tenant.account_id AND f.user_id=u->>'userId'
            AND f.id=u->>'factorId' AND f.state='ACTIVE'
            AND greatest(current_step,(u->>'lastConsumedStep')::bigint)>f.last_consumed_step;
        INSERT INTO iam.authentication_recovery_code_fences(tenant_id,batch_id,command_id,closure_digest,fenced_at)
          SELECT tenant_id,id,closure->>'commandId',closure_digest,effective_now FROM iam.mfa_recovery_batches
          WHERE tenant_id=tenant.account_id ON CONFLICT(tenant_id,batch_id) DO NOTHING;
        INSERT INTO iam.authentication_recovery_access_key_fences(access_key_id,command_id,closure_digest,fenced_at)
          SELECT id,closure->>'commandId',closure_digest,effective_now FROM iam.access_keys
          WHERE tenant_id=tenant.account_id ON CONFLICT(access_key_id) DO NOTHING;
    END LOOP;
    UPDATE iam.authentication_recovery_state SET state='OPEN',active_command_id=NULL,updated_at=effective_now WHERE singleton;
    RETURN completion;
END $function$;

-- The readiness predicate is also the migration verifier's one owner for the
-- private ABI and role separation. It intentionally returns false while the
-- authority is CLOSED.
CREATE OR REPLACE FUNCTION iam.authentication_recovery_contract_ready()
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE ready boolean;
BEGIN
    PERFORM set_config('matrix.iam_authentication_recovery','trusted',true);
    SELECT
      EXISTS(SELECT 1 FROM iam.authentication_recovery_state s WHERE s.singleton AND s.state='OPEN')
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname='matrix_iam_authentication_recovery'
        AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls)
      AND NOT EXISTS(SELECT 1 FROM information_schema.role_table_grants g WHERE g.table_schema='iam' AND g.grantee='matrix_iam_authentication_recovery')
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('iam.authentication_security_projection()')
        AND p.proowner='matrix_iam_owner'::regrole AND NOT p.prosecdef AND NOT p.proretset
        AND p.prorettype='jsonb'::regtype AND p.provolatile='v' AND p.pronargs=0
        AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) permission
          WHERE permission.grantee<>p.proowner))
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('iam.assert_authentication_recovery_snapshot(jsonb,jsonb)')
        AND p.proowner='matrix_iam_owner'::regrole AND NOT p.prosecdef AND NOT p.proretset
        AND p.prorettype='void'::regtype AND p.provolatile='v' AND p.pronargs=2 AND p.pronargdefaults=0
        AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) permission
          WHERE permission.grantee<>p.proowner))
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid='iam.accounts'::regclass
        AND p.polname='authentication_snapshot_accounts' AND p.polcmd='r'
        AND p.polroles=ARRAY['matrix_iam_owner'::regrole::oid] AND p.polpermissive)
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a
        WHERE a.attrelid='iam.authentication_recovery_closures'::regclass AND a.attname='security_snapshot_document'
          AND a.atttypid='jsonb'::regtype AND NOT a.attisdropped AND NOT a.attnotnull
          AND NOT a.atthasdef AND a.attgenerated='' AND a.attidentity='')
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c
        WHERE c.conrelid='iam.authentication_recovery_closures'::regclass
          AND c.conname='authentication_recovery_snapshot_shape' AND c.contype='c' AND c.convalidated)
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=to_regclass('iam.authentication_recovery_attempt_floors')
        AND c.relowner='matrix_iam_owner'::regrole AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
        AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) permission
          WHERE permission.grantee<>c.relowner))
      AND NOT EXISTS(SELECT 1 FROM (VALUES
        ('tenant_id','text',true),('user_id','text',true),('command_id','text',true),
        ('password_generation','bigint',false),('password_window_started_at','timestamp with time zone',false),
        ('password_used_attempts','integer',false),('password_sequence','bigint',false),
        ('totp_window_started_at','timestamp with time zone',false),('totp_used_attempts','integer',false),('totp_sequence','bigint',false)
      ) expected(name,type,required) FULL JOIN (
        SELECT a.* FROM pg_catalog.pg_attribute a WHERE a.attrelid=to_regclass('iam.authentication_recovery_attempt_floors')
          AND a.attnum>0 AND NOT a.attisdropped
      ) actual ON actual.attname=expected.name
      WHERE expected.name IS NULL OR actual.attname IS NULL OR actual.atttypid<>expected.type::regtype
        OR actual.attnotnull<>expected.required OR actual.atthasdef OR actual.attgenerated<>'' OR actual.attidentity<>''
        OR actual.attacl IS NOT NULL
        OR (expected.type='text' AND actual.attcollation<>'"C"'::regcollation)
        OR (expected.type='timestamp with time zone' AND actual.atttypmod<>6))
      AND (SELECT count(*) FROM pg_catalog.pg_constraint c
        WHERE c.conrelid=to_regclass('iam.authentication_recovery_attempt_floors')
          AND c.conname IN ('authentication_recovery_password_floor_valid','authentication_recovery_totp_floor_valid')
          AND c.contype='c' AND c.convalidated)=2
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c
        WHERE c.conrelid=to_regclass('iam.authentication_recovery_attempt_floors') AND c.contype='p'
          AND c.conkey=ARRAY[1,2]::smallint[] AND NOT c.condeferrable)
      AND (SELECT count(*) FROM pg_catalog.pg_constraint c
        WHERE c.conrelid=to_regclass('iam.authentication_recovery_attempt_floors') AND c.contype='f' AND c.convalidated
          AND c.confupdtype='a' AND c.confdeltype='a' AND NOT c.condeferrable
          AND ((c.confrelid='iam.principals'::regclass AND c.conkey=ARRAY[1,2]::smallint[]
            AND c.confkey=ARRAY[(SELECT attnum FROM pg_catalog.pg_attribute WHERE attrelid=c.confrelid AND attname='tenant_id'),
              (SELECT attnum FROM pg_catalog.pg_attribute WHERE attrelid=c.confrelid AND attname='id')]::smallint[])
          OR (c.confrelid='iam.authentication_recovery_completions'::regclass AND c.conkey=ARRAY[3]::smallint[]
            AND c.confkey=ARRAY[1]::smallint[])))=2
      AND (SELECT count(*) FROM pg_catalog.pg_policy p
        WHERE p.polrelid=to_regclass('iam.authentication_recovery_attempt_floors'))=1
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid=to_regclass('iam.authentication_recovery_attempt_floors')
        AND p.polname='tenant_isolation' AND p.polcmd='*' AND p.polpermissive
        AND p.polroles=ARRAY['matrix_iam_owner'::regrole::oid]
        AND pg_get_expr(p.polqual,p.polrelid)='(tenant_id = iam.current_tenant_id())'
        AND pg_get_expr(p.polwithcheck,p.polrelid)='(tenant_id = iam.current_tenant_id())')
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('iam.guard_authentication_recovery_attempt_floor()')
        AND p.proowner='matrix_iam_owner'::regrole AND NOT p.prosecdef AND NOT p.proretset
        AND p.prorettype='trigger'::regtype AND p.provolatile='v' AND p.pronargs=0
        AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) permission
          WHERE permission.grantee<>p.proowner))
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('iam.authentication_recovery_attempt_floors')
        AND t.tgname='authentication_attempt_floor_owned' AND t.tgenabled='A' AND NOT t.tgisinternal
        AND t.tgtype=31 AND t.tgfoid=to_regprocedure('iam.guard_authentication_recovery_attempt_floor()'))
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('iam.authentication_recovery_attempt_floors')
        AND t.tgname='authentication_attempt_floor_no_truncate' AND t.tgenabled='A' AND NOT t.tgisinternal
        AND t.tgtype=34 AND t.tgfoid=to_regprocedure('iam.reject_authentication_recovery_history_change()'))
      AND to_regprocedure('iam.close_authentication_recovery(jsonb,text,jsonb)') IS NULL
      AND to_regprocedure('iam.reconcile_authentication_recovery(jsonb,text,jsonb,jsonb)') IS NULL
      AND to_regprocedure('iam.reopen_authentication_recovery(jsonb,text,jsonb)') IS NULL
      AND (SELECT count(*) FROM pg_catalog.pg_proc p WHERE p.oid IN (
        to_regprocedure('iam.prepare_authentication_recovery_close(jsonb,text)'),
        to_regprocedure('iam.close_authentication_recovery(jsonb,text,jsonb,jsonb,text)'),
        to_regprocedure('iam.reconcile_authentication_recovery(jsonb,text,jsonb,jsonb,jsonb)'),
        to_regprocedure('iam.reopen_authentication_recovery(jsonb,text,jsonb,jsonb)'))
        AND p.prosecdef AND p.proowner='matrix_iam_owner'::regrole AND p.prorettype='jsonb'::regtype AND NOT p.proretset
        AND p.provolatile='v' AND p.pronargdefaults=0 AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) permission
          WHERE permission.grantee NOT IN (p.proowner,'matrix_iam_authentication_recovery'::regrole::oid)))=4
      AND (SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='iam' AND has_function_privilege('matrix_iam_authentication_recovery',p.oid,'EXECUTE'))=4
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname<>'matrix_iam_authentication_recovery'
        AND pg_has_role('matrix_iam_authentication_recovery',r.oid,'MEMBER'))
      AND (SELECT count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid IN (
        'iam.authentication_recovery_closures'::regclass,'iam.authentication_recovery_reconciliations'::regclass,
        'iam.authentication_recovery_completions'::regclass,'iam.authentication_recovery_code_fences'::regclass,
        'iam.authentication_recovery_access_key_fences'::regclass)
        AND t.tgname IN ('authentication_recovery_history_is_immutable','authentication_recovery_history_cannot_truncate')
        AND t.tgenabled='A' AND NOT t.tgisinternal)=10
      AND (SELECT count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid='iam.authentication_recovery_state'::regclass
        AND t.tgname IN ('authentication_recovery_state_transition','authentication_recovery_state_cannot_truncate')
        AND t.tgenabled='A' AND NOT t.tgisinternal)=2
      AND has_function_privilege('matrix_iam_api','iam.assert_authentication_open()','EXECUTE')
      AND NOT has_function_privilege('matrix_iam_credential_recovery','iam.assert_authentication_open()','EXECUTE')
      AND NOT has_function_privilege('matrix_iam_authentication_recovery','iam.assert_authentication_open()','EXECUTE')
      INTO ready;
    RETURN COALESCE(ready,false);
END $function$;

REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM matrix_iam_authentication_recovery;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA iam FROM matrix_iam_authentication_recovery;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA iam FROM matrix_iam_authentication_recovery;
REVOKE ALL ON iam.authentication_recovery_state,iam.authentication_recovery_closures,
  iam.authentication_recovery_reconciliations,iam.authentication_recovery_completions,
  iam.authentication_recovery_code_fences,iam.authentication_recovery_access_key_fences,iam.authentication_recovery_attempt_floors
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker,
    matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.reject_authentication_recovery_history_change(),iam.guard_authentication_recovery_state(),
  iam.guard_authentication_recovery_attempt_floor(),
  iam.assert_authentication_recovery_event(jsonb,text,text,text,text,timestamptz),
  iam.authentication_recovery_contract_ready(),iam.assert_authentication_open(),
  iam.prepare_authentication_recovery_close(jsonb,text),iam.close_authentication_recovery(jsonb,text,jsonb,jsonb,text),
  iam.reconcile_authentication_recovery(jsonb,text,jsonb,jsonb,jsonb),
  iam.reopen_authentication_recovery(jsonb,text,jsonb,jsonb),iam.current_tenant_id()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker,
    matrix_iam_authentication_recovery;
GRANT USAGE ON SCHEMA iam TO matrix_iam_authentication_recovery;
GRANT EXECUTE ON FUNCTION iam.prepare_authentication_recovery_close(jsonb,text),iam.close_authentication_recovery(jsonb,text,jsonb,jsonb,text),
  iam.reconcile_authentication_recovery(jsonb,text,jsonb,jsonb,jsonb),iam.reopen_authentication_recovery(jsonb,text,jsonb,jsonb)
  TO matrix_iam_authentication_recovery;
GRANT EXECUTE ON FUNCTION iam.assert_authentication_open() TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.current_tenant_id() TO matrix_iam_owner,matrix_iam_api,matrix_iam_worker;
