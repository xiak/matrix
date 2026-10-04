SET LOCAL ROLE matrix_iam_owner;

CREATE OR REPLACE FUNCTION iam.valid_security_report_metadata(value jsonb, tenant text, report_id text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE observed timestamptz; expires timestamptz; users bigint; keys bigint; rows bigint; csv_bytes bigint;
BEGIN
    IF value IS NULL OR jsonb_typeof(value)<>'object'
      OR NOT value ?& ARRAY['apiVersion','kind','id','accountId','formatVersion','observedAt','expiresAt',
        'documentDigest','csvContentDigest','userCount','accessKeyCount','rowCount','csvBytes']
      OR value-ARRAY['apiVersion','kind','id','accountId','formatVersion','observedAt','expiresAt',
        'documentDigest','csvContentDigest','userCount','accessKeyCount','rowCount','csvBytes']<>'{}'::jsonb
      OR value->>'apiVersion'<>'iam.matrix.xiak.com/v1' OR value->>'kind'<>'AccountSecurityReportMetadata'
      OR value->>'id' IS DISTINCT FROM report_id OR value->>'accountId' IS DISTINCT FROM tenant
      OR value->>'formatVersion'<>'1' OR value->>'documentDigest' !~ '^sha256:[0-9a-f]{64}$'
      OR value->>'csvContentDigest' !~ '^sha256:[0-9a-f]{64}$'
      OR NOT pg_input_is_valid(value->>'observedAt','timestamp with time zone')
      OR NOT pg_input_is_valid(value->>'expiresAt','timestamp with time zone')
      OR value->>'userCount' !~ '^[0-9]{1,4}$' OR value->>'accessKeyCount' !~ '^[0-9]{1,5}$'
      OR value->>'rowCount' !~ '^[1-9][0-9]{0,4}$' OR value->>'csvBytes' !~ '^[1-9][0-9]{0,7}$' THEN RETURN false; END IF;
    observed:=(value->>'observedAt')::timestamptz; expires:=(value->>'expiresAt')::timestamptz;
    users:=(value->>'userCount')::bigint; keys:=(value->>'accessKeyCount')::bigint;
    rows:=(value->>'rowCount')::bigint; csv_bytes:=(value->>'csvBytes')::bigint;
    RETURN isfinite(observed) AND isfinite(expires) AND expires=observed+interval '7 days'
      AND users BETWEEN 1 AND 1000 AND keys BETWEEN 0 AND 2000
      AND rows=1+users+keys AND rows<=3001 AND csv_bytes BETWEEN 1 AND 4194304;
END $function$;

CREATE TABLE IF NOT EXISTS iam.security_report_receipts (
    tenant_id text COLLATE "C" NOT NULL,
    report_id text COLLATE "C" NOT NULL,
    actor_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    request_digest text NOT NULL,
    metadata jsonb NOT NULL,
    decision_id text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    completed_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,report_id),
    UNIQUE(tenant_id,actor_id,request_id),
    FOREIGN KEY(tenant_id,actor_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(tenant_id,decision_id) REFERENCES iam.authorization_decisions(tenant_id,id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,event_id) REFERENCES iam.audit_outbox(tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED,
    CHECK(report_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND request_digest ~ '^sha256:[0-9a-f]{64}$' AND isfinite(completed_at)),
    CONSTRAINT security_report_receipt_metadata CHECK(iam.valid_security_report_metadata(metadata,tenant_id,report_id))
);

CREATE TABLE IF NOT EXISTS iam.security_report_contents (
    tenant_id text COLLATE "C" NOT NULL,
    report_id text COLLATE "C" NOT NULL,
    report_document jsonb NOT NULL,
    canonical_document text NOT NULL,
    csv_document bytea NOT NULL,
    expires_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,report_id),
    FOREIGN KEY(tenant_id,report_id) REFERENCES iam.security_report_receipts(tenant_id,report_id),
    CHECK(isfinite(expires_at) AND octet_length(canonical_document) BETWEEN 1 AND 4194304
      AND octet_length(csv_document) BETWEEN 1 AND 4194304)
);

CREATE TABLE IF NOT EXISTS iam.security_report_downloads (
    tenant_id text COLLATE "C" NOT NULL,
    actor_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    report_id text COLLATE "C" NOT NULL,
    request_digest text NOT NULL,
    decision_id text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    started_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,actor_id,request_id),
    FOREIGN KEY(tenant_id,actor_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(tenant_id,report_id) REFERENCES iam.security_report_receipts(tenant_id,report_id),
    FOREIGN KEY(tenant_id,decision_id) REFERENCES iam.authorization_decisions(tenant_id,id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,event_id) REFERENCES iam.audit_outbox(tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED,
    CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' AND request_digest ~ '^sha256:[0-9a-f]{64}$'
      AND isfinite(started_at))
);

DO $security_report_isolation$
DECLARE relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['security_report_receipts','security_report_contents','security_report_downloads'] LOOP
        EXECUTE format('ALTER TABLE iam.%I ENABLE ROW LEVEL SECURITY',relation_name);
        EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',relation_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON iam.%I',relation_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON iam.%I USING (tenant_id=iam.current_tenant_id()) WITH CHECK (tenant_id=iam.current_tenant_id())',relation_name);
    END LOOP;
END $security_report_isolation$;

CREATE OR REPLACE FUNCTION iam.guard_security_report_content_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF TG_OP='DELETE' AND current_setting('matrix.iam_security_report_cleanup',true) IS NOT DISTINCT FROM OLD.report_id
      AND OLD.expires_at<=clock_timestamp() THEN RETURN OLD; END IF;
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security report content is immutable';
END $function$;
DROP TRIGGER IF EXISTS security_report_content_update ON iam.security_report_contents;
CREATE TRIGGER security_report_content_update BEFORE UPDATE ON iam.security_report_contents
  FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.security_report_contents ENABLE ALWAYS TRIGGER security_report_content_update;
DROP TRIGGER IF EXISTS security_report_content_truncate ON iam.security_report_contents;
CREATE TRIGGER security_report_content_truncate BEFORE TRUNCATE ON iam.security_report_contents
  FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.security_report_contents ENABLE ALWAYS TRIGGER security_report_content_truncate;
DROP TRIGGER IF EXISTS security_report_content_delete ON iam.security_report_contents;
CREATE TRIGGER security_report_content_delete BEFORE DELETE ON iam.security_report_contents
  FOR EACH ROW EXECUTE FUNCTION iam.guard_security_report_content_change();
ALTER TABLE iam.security_report_contents ENABLE ALWAYS TRIGGER security_report_content_delete;

DO $security_report_history$
DECLARE relation_name text; operation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['security_report_receipts','security_report_downloads'] LOOP
      FOREACH operation_name IN ARRAY ARRAY['update','delete','truncate'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS cannot_%s ON iam.%I',operation_name,relation_name);
        EXECUTE format('CREATE TRIGGER cannot_%s BEFORE %s ON iam.%I FOR EACH %s EXECUTE FUNCTION iam.reject_policy_history_change()',
          operation_name,operation_name,relation_name,CASE WHEN operation_name='truncate' THEN 'STATEMENT' ELSE 'ROW' END);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER cannot_%s',relation_name,operation_name);
      END LOOP;
    END LOOP;
END $security_report_history$;

CREATE OR REPLACE FUNCTION iam.assert_security_report_actor(tenant text,actor text,actor_session text,
  decision text,action_name text,report_id text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF COALESCE(tenant,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor_session,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(report_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security report subject is invalid'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts a WHERE a.id=tenant AND a.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security report account is unavailable'; END IF;
    PERFORM iam.lock_mfa_session(tenant,actor,actor_session);
    IF action_name='iam.security-report.create' THEN
      PERFORM iam.assert_allowed_decision(tenant,actor,decision,action_name,'ACCOUNT',tenant,'INSTANCE',NULL);
    ELSIF action_name IN ('iam.security-report.read','iam.security-report.download') THEN
      PERFORM iam.assert_allowed_decision(tenant,actor,decision,action_name,'SECURITY_REPORT',report_id,'INSTANCE',NULL);
    ELSE RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security report action is invalid'; END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.security_report_snapshot(tenant text,actor text,actor_session text,decision text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE users jsonb; keys jsonb; settings_version bigint;
BEGIN
    PERFORM iam.assert_security_report_actor(tenant,actor,actor_session,decision,'iam.security-report.create',tenant);
    SELECT a.security_settings_version INTO settings_version FROM iam.accounts a WHERE a.id=tenant;
    IF settings_version NOT BETWEEN 1 AND 9007199254740991 THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='security report settings are invalid'; END IF;
    IF (SELECT count(*) FROM iam.principals p WHERE p.tenant_id=tenant AND p.principal_type='USER' AND p.deleted_at IS NULL)>1000
      OR (SELECT count(*) FROM iam.access_keys k WHERE k.tenant_id=tenant AND k.deleted_at IS NULL)>2000 THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='security report capacity exceeded'; END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('id',p.id,'loginName',p.login_name,'displayName',p.display_name,
      'status',p.status,'root',r.principal_id IS NOT NULL,'mustChangePassword',p.must_change_password,
      'resourceVersion',p.resource_version,'createdAt',to_char(p.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'mfa',CASE WHEN m.user_id IS NULL OR m.enrollment_state NOT IN ('NEVER_BOUND','BOUND','RECOVERY_REQUIRED','REMOVED')
        THEN jsonb_build_object('enrollmentState','UNKNOWN')
        ELSE jsonb_build_object('enrollmentState',m.enrollment_state,'factorRevision',m.revision) END,
      'lastPasswordLogin',CASE
        WHEN latest.unknown_at IS NOT NULL AND (latest.known_at IS NULL OR latest.unknown_at>=latest.known_at)
          THEN jsonb_build_object('state','UNKNOWN')
        WHEN latest.known_at IS NULL THEN jsonb_build_object('state','NOT_OBSERVED_IN_RETAINED_IAM_STATE')
        ELSE jsonb_build_object('state','OBSERVED','observedAt',to_char(latest.known_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) END)
      ORDER BY p.id COLLATE "C"),'[]'::jsonb) INTO users
    FROM iam.principals p LEFT JOIN iam.account_roots r ON r.account_id=p.tenant_id AND r.principal_id=p.id
    LEFT JOIN iam.user_mfa_states m ON m.tenant_id=p.tenant_id AND m.user_id=p.id
    LEFT JOIN LATERAL (SELECT
      max(s.issued_at) FILTER (WHERE s.credential_version IS NOT NULL) AS known_at,
      max(s.issued_at) FILTER (WHERE s.credential_version IS NULL) AS unknown_at
      FROM iam.sessions s WHERE s.tenant_id=p.tenant_id
      AND s.principal_id=p.id AND s.authentication_method IN ('PASSWORD','PASSWORD_TOTP')) latest ON true
    WHERE p.tenant_id=tenant AND p.principal_type='USER' AND p.deleted_at IS NULL;
    SELECT COALESCE(jsonb_agg(jsonb_strip_nulls(jsonb_build_object('id',k.id,'userId',k.user_id,'status',k.status,
      'networkRestrictions',k.network_restrictions,'resourceVersion',k.resource_version,
      'createdAt',to_char(k.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'lastAuthorization',latest.observation)) ORDER BY k.id COLLATE "C"),'[]'::jsonb) INTO keys
    FROM iam.access_keys k LEFT JOIN LATERAL (
      SELECT jsonb_build_object('evaluatedAt',to_char(e.evaluated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'allowed',d.allowed,'product',d.profile_product,'action',d.action_name,'sourceIp',d.document#>>'{networkContext,sourceIp}') AS observation
      FROM iam.access_key_authorization_evidence e JOIN iam.authorization_decisions d
        ON d.tenant_id=e.tenant_id AND d.id=e.decision_id
      WHERE e.tenant_id=k.tenant_id AND e.access_key_id=k.id AND d.document#>>'{networkContext,sourceIp}' IS NOT NULL
      ORDER BY e.evaluated_at DESC,e.decision_id DESC LIMIT 1) latest ON true
    WHERE k.tenant_id=tenant AND k.deleted_at IS NULL;
    RETURN jsonb_build_object('observedAt',to_char(transaction_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'accountSecuritySettingsVersion',settings_version,'users',users,'accessKeys',keys);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_security_report_by_request(tenant text,actor text,actor_session text,decision text,
  request_id text,request_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.security_report_receipts%ROWTYPE;
BEGIN
    PERFORM iam.assert_security_report_actor(tenant,actor,actor_session,decision,'iam.security-report.create',tenant);
    IF COALESCE(request_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(request_digest,'') !~ '^sha256:[0-9a-f]{64}$' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security report request is invalid'; END IF;
    SELECT * INTO stored FROM iam.security_report_receipts r WHERE r.tenant_id=tenant AND r.actor_id=actor AND r.request_id=read_security_report_by_request.request_id;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF stored.request_digest IS DISTINCT FROM request_digest THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='security report request conflicts'; END IF;
    RETURN stored.metadata;
END $function$;

CREATE OR REPLACE FUNCTION iam.valid_security_report(value jsonb,canonical_document text,csv_document bytea,tenant text,report_id text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE metadata jsonb; users text[]; sorted_users text[]; keys text[]; sorted_keys text[];
BEGIN
    IF value IS NULL OR jsonb_typeof(value)<>'object' OR value-ARRAY['metadata','accountSecuritySettingsVersion','coverage','users','accessKeys']<>'{}'::jsonb
      OR NOT value ?& ARRAY['metadata','accountSecuritySettingsVersion','coverage','users','accessKeys'] THEN RETURN false; END IF;
    metadata:=value->'metadata';
    IF NOT iam.valid_security_report_metadata(metadata,tenant,report_id)
      OR value->>'accountSecuritySettingsVersion' !~ '^[1-9][0-9]{0,15}$'
      OR (value->>'accountSecuritySettingsVersion')::numeric>9007199254740991
      OR value->'coverage' IS DISTINCT FROM '[{"source":"IAM_ACCOUNT","state":"COMPLETE"},{"source":"IAM_USERS","state":"COMPLETE"},{"source":"IAM_LOGIN_SESSIONS","state":"COMPLETE"},{"source":"IAM_ACCESS_KEYS","state":"COMPLETE"},{"source":"IAM_ROLE_ACTIVITY","state":"NOT_INCLUDED"},{"source":"PAAS_RESULTS","state":"NOT_INCLUDED"},{"source":"AUDIT_STATISTICS","state":"NOT_INCLUDED"},{"source":"NOTIFICATION_DELIVERY","state":"NOT_INCLUDED"},{"source":"EXTERNAL_RISK","state":"NOT_INCLUDED"}]'::jsonb
      OR jsonb_typeof(value->'users')<>'array' OR jsonb_typeof(value->'accessKeys')<>'array'
      OR jsonb_array_length(value->'users')<>(metadata->>'userCount')::integer
      OR jsonb_array_length(value->'accessKeys')<>(metadata->>'accessKeyCount')::integer
      OR (SELECT count(*) FROM jsonb_array_elements(value->'users') u WHERE u->>'root'='true')<>1
      OR octet_length(canonical_document)>4194304 OR octet_length(csv_document)<>(metadata->>'csvBytes')::integer
      OR 'sha256:'||encode(sha256(convert_to(canonical_document,'UTF8')),'hex')<>metadata->>'documentDigest'
      OR 'sha256:'||encode(sha256(csv_document),'hex')<>metadata->>'csvContentDigest'
      OR canonical_document::jsonb IS DISTINCT FROM jsonb_build_object('accountId',tenant,'formatVersion',1,
        'observedAt',metadata->'observedAt','expiresAt',metadata->'expiresAt',
        'accountSecuritySettingsVersion',value->'accountSecuritySettingsVersion','coverage',value->'coverage',
        'users',value->'users','accessKeys',value->'accessKeys') THEN RETURN false; END IF;
    SELECT array_agg(u->>'id' ORDER BY ordinality),array_agg(u->>'id' ORDER BY (u->>'id') COLLATE "C")
      INTO users,sorted_users FROM jsonb_array_elements(value->'users') WITH ORDINALITY entry(u,ordinality);
    SELECT array_agg(k->>'id' ORDER BY ordinality),array_agg(k->>'id' ORDER BY (k->>'id') COLLATE "C")
      INTO keys,sorted_keys FROM jsonb_array_elements(value->'accessKeys') WITH ORDINALITY entry(k,ordinality);
    IF users IS DISTINCT FROM sorted_users OR cardinality(users)<>cardinality(ARRAY(SELECT DISTINCT item FROM unnest(users) item))
      OR keys IS DISTINCT FROM sorted_keys OR cardinality(keys)<>cardinality(ARRAY(SELECT DISTINCT item FROM unnest(keys) item))
      OR EXISTS(SELECT 1 FROM jsonb_array_elements(value->'accessKeys') k WHERE NOT (k->>'userId'=ANY(users))) THEN RETURN false; END IF;
    RETURN true;
EXCEPTION WHEN others THEN RETURN false;
END $function$;

CREATE OR REPLACE FUNCTION iam.create_security_report(tenant text,actor text,actor_session text,decision text,
  request_id text,request_digest text,report_id text,report_document jsonb,canonical_document text,csv_document bytea,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE previous iam.security_report_receipts%ROWTYPE; metadata jsonb;
BEGIN
    PERFORM iam.assert_security_report_actor(tenant,actor,actor_session,decision,'iam.security-report.create',tenant);
    SELECT * INTO previous FROM iam.security_report_receipts r WHERE r.tenant_id=tenant AND r.actor_id=actor AND r.request_id=create_security_report.request_id;
    IF FOUND THEN
      IF previous.request_digest IS DISTINCT FROM request_digest THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='security report request conflicts'; END IF;
      RETURN jsonb_build_object('outcome','EQUAL_REPLAY','metadata',previous.metadata);
    END IF;
    metadata:=report_document->'metadata';
    IF NOT iam.valid_security_report(report_document,canonical_document,csv_document,tenant,report_id)
      OR (metadata->>'observedAt')::timestamptz IS DISTINCT FROM transaction_timestamp()
      OR event->>'requestId' IS DISTINCT FROM request_id OR event->>'requestDigest' IS DISTINCT FROM request_digest THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security report content is invalid'; END IF;
    PERFORM iam.assert_audit_event(event,tenant,'iam.security-report.created','SECURITY_REPORT',report_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security report decision differs'; END IF;
    PERFORM set_config('matrix.iam_security_report_cleanup','*',true);
    FOR previous IN SELECT r.* FROM iam.security_report_receipts r JOIN iam.security_report_contents c
      ON c.tenant_id=r.tenant_id AND c.report_id=r.report_id WHERE c.tenant_id=tenant AND c.expires_at<=clock_timestamp()
      ORDER BY c.report_id FOR UPDATE OF c LOOP
        PERFORM set_config('matrix.iam_security_report_cleanup',previous.report_id,true);
        DELETE FROM iam.security_report_contents c WHERE c.tenant_id=tenant AND c.report_id=previous.report_id;
    END LOOP;
    IF (SELECT count(*) FROM iam.security_report_contents c WHERE c.tenant_id=tenant)>=20 THEN
      RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security report active quota reached'; END IF;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
    INSERT INTO iam.security_report_receipts(tenant_id,report_id,actor_id,request_id,request_digest,metadata,decision_id,event_id,completed_at)
      VALUES(tenant,report_id,actor,request_id,request_digest,metadata,decision,event->>'eventId',transaction_timestamp());
    INSERT INTO iam.security_report_contents(tenant_id,report_id,report_document,canonical_document,csv_document,expires_at)
      VALUES(tenant,report_id,report_document,canonical_document,csv_document,(metadata->>'expiresAt')::timestamptz);
    RETURN jsonb_build_object('outcome','APPLIED','metadata',metadata);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_security_report(tenant text,actor text,actor_session text,decision text,report_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.assert_security_report_actor(tenant,actor,actor_session,decision,'iam.security-report.read',report_id);
    SELECT c.report_document INTO result FROM iam.security_report_contents c WHERE c.tenant_id=tenant
      AND c.report_id=read_security_report.report_id AND c.expires_at>clock_timestamp();
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security report not found'; END IF;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.download_security_report(tenant text,actor text,actor_session text,decision text,
  report_id text,request_id text,event jsonb)
RETURNS TABLE(metadata jsonb,csv_document bytea) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE previous iam.security_report_downloads%ROWTYPE; request_digest text:=event->>'requestDigest';
BEGIN
    PERFORM iam.assert_security_report_actor(tenant,actor,actor_session,decision,'iam.security-report.download',report_id);
    SELECT * INTO previous FROM iam.security_report_downloads d WHERE d.tenant_id=tenant AND d.actor_id=actor AND d.request_id=download_security_report.request_id;
    IF FOUND AND (previous.report_id IS DISTINCT FROM report_id OR previous.request_digest IS DISTINCT FROM request_digest) THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='security report download conflicts'; END IF;
    SELECT r.metadata,c.csv_document INTO metadata,csv_document FROM iam.security_report_receipts r JOIN iam.security_report_contents c
      ON c.tenant_id=r.tenant_id AND c.report_id=r.report_id
      WHERE r.tenant_id=tenant AND r.report_id=download_security_report.report_id AND c.expires_at>clock_timestamp();
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security report not found'; END IF;
    IF previous.report_id IS NOT NULL THEN RETURN NEXT; RETURN; END IF;
    PERFORM iam.assert_audit_event(event,tenant,'iam.security-report.download-started','SECURITY_REPORT',report_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision OR event->>'requestId' IS DISTINCT FROM request_id THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security report download decision differs'; END IF;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
    INSERT INTO iam.security_report_downloads(tenant_id,actor_id,request_id,report_id,request_digest,decision_id,event_id,started_at)
      VALUES(tenant,actor,request_id,report_id,request_digest,decision,event->>'eventId',transaction_timestamp());
    RETURN NEXT;
END $function$;

CREATE OR REPLACE FUNCTION iam.assert_security_report_receipt()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE fact jsonb; expected_action text; expected_target_id text; expected_occurred_at timestamptz;
BEGIN
    expected_action:=CASE WHEN TG_TABLE_NAME='security_report_receipts' THEN 'iam.security-report.create' ELSE 'iam.security-report.download' END;
    expected_target_id:=CASE WHEN TG_TABLE_NAME='security_report_receipts' THEN NEW.tenant_id ELSE NEW.report_id END;
    IF TG_TABLE_NAME='security_report_receipts' THEN expected_occurred_at:=NEW.completed_at;
    ELSE expected_occurred_at:=NEW.started_at; END IF;
    IF NOT EXISTS(SELECT 1 FROM iam.authorization_decisions d WHERE d.tenant_id=NEW.tenant_id AND d.id=NEW.decision_id
      AND d.principal_id=NEW.actor_id AND d.allowed AND d.action_name=expected_action
      AND d.target_kind=CASE WHEN expected_action='iam.security-report.create' THEN 'ACCOUNT' ELSE 'SECURITY_REPORT' END
      AND d.target_id=expected_target_id AND d.resource_mode='INSTANCE' AND d.collection_usage IS NULL) THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='security report decision proof differs'; END IF;
    SELECT o.event_document INTO fact FROM iam.audit_outbox o WHERE o.tenant_id=NEW.tenant_id AND o.event_id=NEW.event_id;
    IF fact IS NULL OR fact->>'action' IS DISTINCT FROM (CASE WHEN expected_action='iam.security-report.create' THEN 'iam.security-report.created' ELSE 'iam.security-report.download-started' END)
      OR fact->>'tenantId' IS DISTINCT FROM NEW.tenant_id OR fact->'actor' IS DISTINCT FROM jsonb_build_object('type','USER','id',NEW.actor_id)
      OR fact->'target' IS DISTINCT FROM jsonb_build_object('kind','SECURITY_REPORT','id',CASE WHEN TG_TABLE_NAME='security_report_receipts' THEN NEW.report_id ELSE NEW.report_id END)
      OR fact->>'iamDecisionId' IS DISTINCT FROM NEW.decision_id OR fact->>'requestId' IS DISTINCT FROM NEW.request_id
      OR fact->>'correlationId' IS DISTINCT FROM NEW.request_id OR fact->>'requestDigest' IS DISTINCT FROM NEW.request_digest
      OR (fact->>'occurredAt')::timestamptz IS DISTINCT FROM expected_occurred_at
      OR fact ?| ARRAY['installationId','operationId'] OR fact->>'result'<>'SUCCEEDED' THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='security report audit proof differs'; END IF;
    RETURN NULL;
END $function$;
DROP TRIGGER IF EXISTS security_report_receipt_complete ON iam.security_report_receipts;
CREATE CONSTRAINT TRIGGER security_report_receipt_complete AFTER INSERT ON iam.security_report_receipts
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.assert_security_report_receipt();
ALTER TABLE iam.security_report_receipts ENABLE ALWAYS TRIGGER security_report_receipt_complete;
DROP TRIGGER IF EXISTS security_report_download_complete ON iam.security_report_downloads;
CREATE CONSTRAINT TRIGGER security_report_download_complete AFTER INSERT ON iam.security_report_downloads
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.assert_security_report_receipt();
ALTER TABLE iam.security_report_downloads ENABLE ALWAYS TRIGGER security_report_download_complete;

REVOKE ALL ON TABLE iam.security_report_receipts,iam.security_report_contents,iam.security_report_downloads
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.valid_security_report_metadata(jsonb,text,text),iam.guard_security_report_content_change(),
  iam.assert_security_report_actor(text,text,text,text,text,text),iam.valid_security_report(jsonb,text,bytea,text,text),
  iam.assert_security_report_receipt()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.security_report_snapshot(text,text,text,text),iam.read_security_report_by_request(text,text,text,text,text,text),
  iam.create_security_report(text,text,text,text,text,text,text,jsonb,text,bytea,jsonb),iam.read_security_report(text,text,text,text,text),
  iam.download_security_report(text,text,text,text,text,text,jsonb)
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
GRANT EXECUTE ON FUNCTION iam.security_report_snapshot(text,text,text,text),iam.read_security_report_by_request(text,text,text,text,text,text),
  iam.create_security_report(text,text,text,text,text,text,text,jsonb,text,bytea,jsonb),iam.read_security_report(text,text,text,text,text),
  iam.download_security_report(text,text,text,text,text,text,jsonb) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.security_report_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
  SELECT (SELECT count(*)=3 FROM pg_class relation WHERE relation.oid IN (
      to_regclass('iam.security_report_receipts'),to_regclass('iam.security_report_contents'),to_regclass('iam.security_report_downloads'))
      AND relation.relowner='matrix_iam_owner'::regrole AND relation.relrowsecurity AND relation.relforcerowsecurity
      AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) privilege
        WHERE privilege.grantee<>relation.relowner))
    AND (SELECT count(*)=3 FROM pg_policies p WHERE p.schemaname='iam' AND p.tablename IN (
      'security_report_receipts','security_report_contents','security_report_downloads') AND p.policyname='tenant_isolation'
      AND p.qual='(tenant_id = iam.current_tenant_id())' AND p.with_check='(tenant_id = iam.current_tenant_id())')
    AND (SELECT count(*)=5 FROM pg_proc f WHERE f.oid IN (
      to_regprocedure('iam.security_report_snapshot(text,text,text,text)'),
      to_regprocedure('iam.read_security_report_by_request(text,text,text,text,text,text)'),
      to_regprocedure('iam.create_security_report(text,text,text,text,text,text,text,jsonb,text,bytea,jsonb)'),
      to_regprocedure('iam.read_security_report(text,text,text,text,text)'),
      to_regprocedure('iam.download_security_report(text,text,text,text,text,text,jsonb)'))
      AND f.proowner='matrix_iam_owner'::regrole AND f.prosecdef AND f.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
      AND has_function_privilege('matrix_iam_api',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_worker',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_credential_recovery',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_backup_custody',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_notification_worker',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_authentication_recovery',f.oid,'EXECUTE'))
    AND EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid='iam.security_report_receipts'::regclass
      AND c.conname='security_report_receipt_metadata' AND c.contype='c' AND c.convalidated)
    AND (SELECT count(*)=3 FROM pg_trigger t WHERE t.tgrelid='iam.security_report_contents'::regclass AND NOT t.tgisinternal
      AND t.tgname IN ('security_report_content_update','security_report_content_truncate','security_report_content_delete') AND t.tgenabled='A')
    AND (SELECT count(*)=6 FROM pg_trigger t WHERE t.tgrelid IN (
        'iam.security_report_receipts'::regclass,'iam.security_report_downloads'::regclass) AND NOT t.tgisinternal
      AND t.tgname IN ('cannot_update','cannot_delete','cannot_truncate') AND t.tgenabled='A'
      AND t.tgfoid=to_regprocedure('iam.reject_policy_history_change()'))
    AND EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid='iam.security_report_receipts'::regclass
      AND t.tgname='security_report_receipt_complete' AND t.tgenabled='A' AND t.tgfoid=to_regprocedure('iam.assert_security_report_receipt()'))
    AND EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid='iam.security_report_downloads'::regclass
      AND t.tgname='security_report_download_complete' AND t.tgenabled='A' AND t.tgfoid=to_regprocedure('iam.assert_security_report_receipt()'))
$function$;
REVOKE ALL ON FUNCTION iam.security_report_contract_ready()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;

DO $security_report_readiness_cutover$
BEGIN
    IF to_regprocedure('iam.readiness_v60()') IS NOT NULL THEN DROP FUNCTION iam.readiness_v60(); END IF;
    ALTER FUNCTION iam.readiness() RENAME TO readiness_v60;
END $security_report_readiness_cutover$;
REVOKE ALL ON FUNCTION iam.readiness_v60() FROM PUBLIC,matrix_iam_api,matrix_iam_worker,
  matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery;
CREATE FUNCTION iam.readiness()
RETURNS TABLE(ready boolean,schema_version bigint,checked_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE predecessor record;
BEGIN
    SELECT * INTO predecessor FROM iam.readiness_v60();
    RETURN QUERY SELECT predecessor.ready AND iam.security_report_contract_ready(),61::bigint,predecessor.checked_at;
END $function$;
REVOKE ALL ON FUNCTION iam.readiness() FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,
  matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery;
GRANT EXECUTE ON FUNCTION iam.readiness() TO matrix_iam_api;
