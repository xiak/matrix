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

CREATE OR REPLACE FUNCTION iam.reject_authentication_recovery_history_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication recovery history is immutable';
END $function$;
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

CREATE OR REPLACE FUNCTION iam.close_authentication_recovery(intent jsonb,intent_digest text,closed_event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; current_state iam.authentication_recovery_state%ROWTYPE;
    stored iam.authentication_recovery_closures%ROWTYPE; closure jsonb; effective_now timestamptz(6):=transaction_timestamp();
    numeric_epoch bigint;
BEGIN
    PERFORM set_config('matrix.iam_authentication_recovery','trusted',true);
    IF jsonb_typeof(intent) IS DISTINCT FROM 'object'
      OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(intent) key) IS DISTINCT FROM ARRAY[
        'apiVersion','backupDigest','backupId','commandId','epoch','installationId','kind','purpose',
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
    numeric_epoch:=(intent->>'epoch')::bigint;
    SELECT * INTO receipt FROM iam.bootstrap_receipts WHERE singleton AND installation_id=intent->>'installationId' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication recovery installation is forbidden'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',receipt.organization_id,true);
    SELECT * INTO stored FROM iam.authentication_recovery_closures c WHERE c.command_id=intent->>'commandId';
    IF FOUND THEN
        IF stored.origin<>'SOURCE' OR stored.intent_digest<>intent_digest OR stored.intent_document<>intent THEN
            RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication recovery close conflicts';
        END IF;
        RETURN stored.closure_document;
    END IF;
    SELECT * INTO current_state FROM iam.authentication_recovery_state WHERE singleton FOR UPDATE;
    IF NOT FOUND OR current_state.state<>'OPEN' OR numeric_epoch<>current_state.epoch+1
      OR EXISTS(SELECT 1 FROM iam.authentication_recovery_closures c WHERE c.epoch=numeric_epoch) THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication recovery epoch conflicts';
    END IF;
    closure:=jsonb_build_object('apiVersion','installation.matrix.xiak.com/v1','kind','IAMAuthenticationRecoveryClosure',
      'purpose','IAM_AUTHENTICATION_BACKUP_RECOVERY','installationId',receipt.installation_id,'epoch',numeric_epoch,
      'state','CLOSED','commandId',intent->>'commandId','backupId',intent->>'backupId','backupDigest',intent->>'backupDigest',
      'recoveryIntentDigest',intent_digest,'totpCustodyDigest',intent->>'totpCustodyDigest','closedAt',effective_now);
    PERFORM iam.assert_authentication_recovery_event(closed_event,'iam.authentication-recovery.closed',receipt.installation_id,
      intent->>'commandId',intent_digest,effective_now);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(receipt.organization_id,closed_event->>'eventId',closed_event,effective_now,effective_now,effective_now);
    INSERT INTO iam.authentication_recovery_closures(command_id,installation_id,home_tenant_id,epoch,origin,intent_digest,
      intent_document,closure_document,closed_event_id,closed_event_document,closed_at)
      VALUES(intent->>'commandId',receipt.installation_id,receipt.organization_id,numeric_epoch,'SOURCE',intent_digest,
        intent,closure,closed_event->>'eventId',closed_event,effective_now);
    UPDATE iam.authentication_recovery_state SET epoch=numeric_epoch,state='CLOSED',active_command_id=intent->>'commandId',updated_at=effective_now
      WHERE singleton;
    RETURN closure;
END $function$;

CREATE OR REPLACE FUNCTION iam.reconcile_authentication_recovery(closure jsonb,closure_digest text,
    closed_event jsonb,reconciled_event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; current_state iam.authentication_recovery_state%ROWTYPE;
    stored iam.authentication_recovery_closures%ROWTYPE; reconciled iam.authentication_recovery_reconciliations%ROWTYPE;
    effective_now timestamptz(6):=transaction_timestamp(); numeric_epoch bigint; closed_time timestamptz(6);
BEGIN
    PERFORM set_config('matrix.iam_authentication_recovery','trusted',true);
    IF jsonb_typeof(closure) IS DISTINCT FROM 'object'
      OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(closure) key) IS DISTINCT FROM ARRAY[
        'apiVersion','backupDigest','backupId','closedAt','commandId','epoch','installationId','kind','purpose',
        'recoveryIntentDigest','state','totpCustodyDigest']
      OR closure->>'apiVersion'<>'installation.matrix.xiak.com/v1' OR closure->>'kind'<>'IAMAuthenticationRecoveryClosure'
      OR closure->>'purpose'<>'IAM_AUTHENTICATION_BACKUP_RECOVERY' OR closure->>'state'<>'CLOSED'
      OR COALESCE(closure->>'installationId','') COLLATE "C" !~ '^mxi-[0-9a-f]{32}$'
      OR jsonb_typeof(closure->'epoch') IS DISTINCT FROM 'number' OR COALESCE(closure->>'epoch','') !~ '^[1-9][0-9]{0,18}$'
      OR (closure->>'epoch')::numeric>9223372036854775807
      OR COALESCE(closure->>'commandId','') COLLATE "C" !~ '^cmd-[0-9a-f]{32}$'
      OR COALESCE(closure->>'backupId','') COLLATE "C" !~ '^backup-[0-9a-f]{32}$'
      OR closure->>'backupDigest' !~ '^sha256:[0-9a-f]{64}$' OR closure->>'recoveryIntentDigest' !~ '^sha256:[0-9a-f]{64}$'
      OR closure->>'totpCustodyDigest' !~ '^sha256:[0-9a-f]{64}$' OR closure_digest !~ '^sha256:[0-9a-f]{64}$'
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
        IF stored.closure_document<>closure THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication recovery closure conflicts'; END IF;
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
    PERFORM iam.assert_authentication_recovery_event(closed_event,'iam.authentication-recovery.closed',receipt.installation_id,
      closure->>'commandId',closure->>'recoveryIntentDigest',closed_time);
    PERFORM iam.assert_authentication_recovery_event(reconciled_event,'iam.authentication-recovery.reconciled',receipt.installation_id,
      closure->>'commandId',closure_digest,effective_now);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at) VALUES
      (receipt.organization_id,closed_event->>'eventId',closed_event,effective_now,effective_now,effective_now),
      (receipt.organization_id,reconciled_event->>'eventId',reconciled_event,effective_now,effective_now,effective_now);
    INSERT INTO iam.authentication_recovery_closures(command_id,installation_id,home_tenant_id,epoch,origin,intent_digest,
      intent_document,closure_document,closed_event_id,closed_event_document,closed_at)
      VALUES(closure->>'commandId',receipt.installation_id,receipt.organization_id,numeric_epoch,'RESTORED',closure->>'recoveryIntentDigest',
        NULL,closure,closed_event->>'eventId',closed_event,closed_time);
    INSERT INTO iam.authentication_recovery_reconciliations(command_id,installation_id,home_tenant_id,closure_digest,
      reconciled_event_id,reconciled_event_document,reconciled_at)
      VALUES(closure->>'commandId',receipt.installation_id,receipt.organization_id,closure_digest,
        reconciled_event->>'eventId',reconciled_event,effective_now);
    UPDATE iam.authentication_recovery_state SET epoch=numeric_epoch,state='CLOSED',active_command_id=closure->>'commandId',updated_at=effective_now
      WHERE singleton;
    RETURN closure;
END $function$;

CREATE OR REPLACE FUNCTION iam.reopen_authentication_recovery(closure jsonb,closure_digest text,reopened_event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; current_state iam.authentication_recovery_state%ROWTYPE;
    stored iam.authentication_recovery_closures%ROWTYPE; reconciled iam.authentication_recovery_reconciliations%ROWTYPE;
    completed iam.authentication_recovery_completions%ROWTYPE; completion jsonb;
    effective_now timestamptz(6):=transaction_timestamp(); current_step bigint; tenant record;
BEGIN
    PERFORM set_config('matrix.iam_authentication_recovery','trusted',true);
    IF jsonb_typeof(closure) IS DISTINCT FROM 'object' OR closure->>'state'<>'CLOSED'
      OR COALESCE(closure->>'commandId','') COLLATE "C" !~ '^cmd-[0-9a-f]{32}$'
      OR COALESCE(closure->>'installationId','') COLLATE "C" !~ '^mxi-[0-9a-f]{32}$'
      OR jsonb_typeof(closure->'epoch') IS DISTINCT FROM 'number' OR COALESCE(closure->>'epoch','') !~ '^[1-9][0-9]{0,18}$'
      OR (closure->>'epoch')::numeric>9223372036854775807 OR closure_digest !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authentication recovery reopen input is invalid';
    END IF;
    SELECT * INTO completed FROM iam.authentication_recovery_completions c WHERE c.command_id=closure->>'commandId';
    IF FOUND THEN
        IF completed.closure_digest<>closure_digest OR NOT EXISTS(SELECT 1 FROM iam.authentication_recovery_closures c
          WHERE c.command_id=completed.command_id AND c.closure_document=closure) THEN
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
      OR current_state.state<>'CLOSED' OR current_state.epoch<>(closure->>'epoch')::bigint
      OR current_state.active_command_id<>closure->>'commandId' OR effective_now<=stored.closed_at THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication recovery reopen conflicts';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',receipt.organization_id,true);
    PERFORM iam.assert_authentication_recovery_event(reopened_event,'iam.authentication-recovery.reopened',receipt.installation_id,
      closure->>'commandId',closure_digest,effective_now);
    completion:=jsonb_build_object('apiVersion','installation.matrix.xiak.com/v1','kind','IAMAuthenticationRecoveryCompletion',
      'purpose','IAM_AUTHENTICATION_BACKUP_RECOVERY','installationId',receipt.installation_id,'epoch',(closure->>'epoch')::bigint,
      'state','REOPENED','commandId',closure->>'commandId','closureDigest',closure_digest,'completedAt',effective_now);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(receipt.organization_id,reopened_event->>'eventId',reopened_event,effective_now,effective_now,effective_now);
    INSERT INTO iam.authentication_recovery_completions(command_id,installation_id,home_tenant_id,closure_digest,
      completion_document,reopened_event_id,reopened_event_document,completed_at)
      VALUES(closure->>'commandId',receipt.installation_id,receipt.organization_id,closure_digest,completion,
        reopened_event->>'eventId',reopened_event,effective_now);

    current_step:=floor(extract(epoch FROM effective_now)/30)::bigint;
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
        UPDATE iam.totp_authenticators SET last_consumed_step=greatest(last_consumed_step,current_step)
          WHERE tenant_id=tenant.account_id AND state='ACTIVE' AND last_consumed_step<current_step;
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
      AND (SELECT count(*) FROM pg_catalog.pg_proc p WHERE p.oid IN (
        to_regprocedure('iam.close_authentication_recovery(jsonb,text,jsonb)'),
        to_regprocedure('iam.reconcile_authentication_recovery(jsonb,text,jsonb,jsonb)'),
        to_regprocedure('iam.reopen_authentication_recovery(jsonb,text,jsonb)'))
        AND p.prosecdef AND p.proowner='matrix_iam_owner'::regrole AND p.prorettype='jsonb'::regtype AND NOT p.proretset)=3
      AND (SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='iam' AND has_function_privilege('matrix_iam_authentication_recovery',p.oid,'EXECUTE'))=3
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
  iam.authentication_recovery_code_fences,iam.authentication_recovery_access_key_fences
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker,
    matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.reject_authentication_recovery_history_change(),iam.guard_authentication_recovery_state(),
  iam.assert_authentication_recovery_event(jsonb,text,text,text,text,timestamptz),
  iam.authentication_recovery_contract_ready(),iam.assert_authentication_open(),
  iam.close_authentication_recovery(jsonb,text,jsonb),iam.reconcile_authentication_recovery(jsonb,text,jsonb,jsonb),
  iam.reopen_authentication_recovery(jsonb,text,jsonb),iam.current_tenant_id()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker,
    matrix_iam_authentication_recovery;
GRANT USAGE ON SCHEMA iam TO matrix_iam_authentication_recovery;
GRANT EXECUTE ON FUNCTION iam.close_authentication_recovery(jsonb,text,jsonb),
  iam.reconcile_authentication_recovery(jsonb,text,jsonb,jsonb),iam.reopen_authentication_recovery(jsonb,text,jsonb)
  TO matrix_iam_authentication_recovery;
GRANT EXECUTE ON FUNCTION iam.assert_authentication_open() TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.current_tenant_id() TO matrix_iam_owner,matrix_iam_api,matrix_iam_worker;
