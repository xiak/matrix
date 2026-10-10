SET LOCAL ROLE matrix_iam_owner;

-- An AccessKey's management status and the supported-recovery fence are
-- independent. Historical intent rows are immutable: schema 83 accepts their
-- old result shape for replay, derives the state at the original completion,
-- and requires every new non-delete result to persist the explicit state.
CREATE OR REPLACE FUNCTION iam.access_key_result_valid(action_name text,value jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE legacy_expected text[]; current_expected text[]; actual text[]; field text; version bigint;
BEGIN
    legacy_expected:=CASE WHEN action_name='iam.access-key.delete'
      THEN ARRAY['accountId','apiVersion','deletedAt','id','kind','resourceVersion','userId']
      ELSE ARRAY['accountId','apiVersion','createdAt','id','kind','networkRestrictions','resourceVersion','status','updatedAt','userId'] END;
    current_expected:=CASE WHEN action_name='iam.access-key.delete' THEN legacy_expected
      ELSE ARRAY['accountId','apiVersion','createdAt','credentialState','id','kind','networkRestrictions','resourceVersion','status','updatedAt','userId'] END;
    SELECT array_agg(key ORDER BY key) INTO actual FROM jsonb_object_keys(value) key;
    IF value IS NULL OR jsonb_typeof(value)<>'object'
       OR (actual IS DISTINCT FROM legacy_expected AND actual IS DISTINCT FROM current_expected)
       OR value->>'apiVersion' IS DISTINCT FROM 'iam.matrix.xiak.com/v1'
       OR jsonb_typeof(value->'resourceVersion') IS DISTINCT FROM 'number'
       OR (value->>'resourceVersion') !~ '^[1-9][0-9]{0,15}$' THEN RETURN false; END IF;
    FOREACH field IN ARRAY actual LOOP
        IF field NOT IN ('resourceVersion','networkRestrictions') AND jsonb_typeof(value->field) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
    END LOOP;
    FOREACH field IN ARRAY ARRAY['accountId','id','userId'] LOOP
        IF (value->>field) COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN RETURN false; END IF;
    END LOOP;
    version:=(value->>'resourceVersion')::bigint;
    IF version>9007199254740991 THEN RETURN false; END IF;
    IF action_name='iam.access-key.delete' THEN
        IF value->>'kind'<>'AccessKeyDeletion' OR version<2 OR NOT pg_input_is_valid(value->>'deletedAt','timestamp with time zone') THEN RETURN false; END IF;
        RETURN isfinite((value->>'deletedAt')::timestamptz);
    END IF;
    IF action_name NOT IN ('iam.access-key.create','iam.access-key.set-status','iam.access-key.set-network-restrictions') OR value->>'kind'<>'AccessKey'
       OR value->>'status' NOT IN ('ENABLED','DISABLED') OR NOT pg_input_is_valid(value->>'createdAt','timestamp with time zone')
       OR NOT pg_input_is_valid(value->>'updatedAt','timestamp with time zone')
       OR NOT iam.valid_access_key_network_restrictions(value->'networkRestrictions')
       OR (value ? 'credentialState' AND value->>'credentialState' NOT IN ('CURRENT','RECOVERY_FENCED')) THEN RETURN false; END IF;
    RETURN isfinite((value->>'updatedAt')::timestamptz) AND isfinite((value->>'createdAt')::timestamptz)
      AND (value->>'updatedAt')::timestamptz>=(value->>'createdAt')::timestamptz
      AND ((action_name='iam.access-key.create' AND version=1 AND value->>'status'='ENABLED' AND value->>'createdAt'=value->>'updatedAt')
        OR (action_name IN ('iam.access-key.set-status','iam.access-key.set-network-restrictions') AND version>=2));
END $function$;

ALTER TABLE iam.access_key_intents DROP CONSTRAINT IF EXISTS access_key_intent_credential_state;
ALTER TABLE iam.access_key_intents ADD CONSTRAINT access_key_intent_credential_state CHECK(
  action_name='iam.access-key.delete' OR
  COALESCE(result ? 'credentialState'
    AND jsonb_typeof(result->'credentialState')='string'
    AND result->>'credentialState' IN ('CURRENT','RECOVERY_FENCED'),false)) NOT VALID;

CREATE OR REPLACE FUNCTION iam.access_key_snapshot(tenant text,key_id text)
RETURNS jsonb LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AccessKey','id',k.id,
      'accountId',k.tenant_id,'userId',k.user_id,'status',k.status,
      'credentialState',CASE WHEN EXISTS(SELECT 1 FROM iam.authentication_recovery_access_key_fences fence
        WHERE fence.access_key_id=k.id) THEN 'RECOVERY_FENCED' ELSE 'CURRENT' END,
      'resourceVersion',k.resource_version,'networkRestrictions',k.network_restrictions,
      'createdAt',k.created_at,'updatedAt',k.updated_at)
      FROM iam.access_keys k WHERE k.tenant_id=tenant AND k.id=key_id AND k.deleted_at IS NULL AND k.format_version IS NOT NULL
$function$;

CREATE OR REPLACE FUNCTION iam.access_key_intent_result(tenant text,actor text,target_user text,key_id text,
    action_name text,request_id text,request_digest text)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.access_key_intents%ROWTYPE; completion jsonb;
BEGIN
    IF COALESCE(request_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(request_digest,'') COLLATE "C" !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='access key intent is invalid'; END IF;
    SELECT * INTO stored FROM iam.access_key_intents i WHERE i.tenant_id=tenant AND i.actor_id=actor AND i.request_id=access_key_intent_result.request_id;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF stored.user_id IS DISTINCT FROM target_user OR stored.action_name IS DISTINCT FROM action_name
       OR stored.request_digest IS DISTINCT FROM request_digest OR (action_name<>'iam.access-key.create' AND stored.key_id IS DISTINCT FROM key_id) THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='access key intent conflicts'; END IF;
    completion:=stored.result;
    IF action_name<>'iam.access-key.delete' AND NOT completion ? 'credentialState' THEN
        completion:=completion||jsonb_build_object('credentialState',CASE WHEN EXISTS(
          SELECT 1 FROM iam.authentication_recovery_access_key_fences fence
          WHERE fence.access_key_id=stored.key_id AND fence.fenced_at<=stored.completed_at)
          THEN 'RECOVERY_FENCED' ELSE 'CURRENT' END);
    END IF;
    RETURN jsonb_build_object('outcome','EQUAL_REPLAY',
      CASE WHEN action_name='iam.access-key.delete' THEN 'deletion' ELSE 'key' END,completion);
END $function$;

-- Format 1 remains valid only for immutable retained receipts and content.
-- All newly generated reports use format 2 and carry credentialState.
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
      OR value->>'formatVersion' NOT IN ('1','2') OR value->>'documentDigest' !~ '^sha256:[0-9a-f]{64}$'
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
      'credentialState',CASE WHEN fence.access_key_id IS NULL THEN 'CURRENT' ELSE 'RECOVERY_FENCED' END,
      'networkRestrictions',k.network_restrictions,'resourceVersion',k.resource_version,
      'createdAt',to_char(k.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'lastAuthorization',latest.observation)) ORDER BY k.id COLLATE "C"),'[]'::jsonb) INTO keys
    FROM iam.access_keys k
    LEFT JOIN iam.authentication_recovery_access_key_fences fence ON fence.access_key_id=k.id
    LEFT JOIN LATERAL (
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

CREATE OR REPLACE FUNCTION iam.valid_security_report(value jsonb,canonical_document text,csv_document bytea,tenant text,report_id text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE metadata jsonb; users text[]; sorted_users text[]; keys text[]; sorted_keys text[];
BEGIN
    IF value IS NULL OR jsonb_typeof(value)<>'object' OR value-ARRAY['metadata','accountSecuritySettingsVersion','coverage','users','accessKeys']<>'{}'::jsonb
      OR NOT value ?& ARRAY['metadata','accountSecuritySettingsVersion','coverage','users','accessKeys'] THEN RETURN false; END IF;
    metadata:=value->'metadata';
    IF NOT iam.valid_security_report_metadata(metadata,tenant,report_id) OR metadata->>'formatVersion'<>'2'
      OR value->>'accountSecuritySettingsVersion' !~ '^[1-9][0-9]{0,15}$'
      OR (value->>'accountSecuritySettingsVersion')::numeric>9007199254740991
      OR value->'coverage' IS DISTINCT FROM '[{"source":"IAM_ACCOUNT","state":"COMPLETE"},{"source":"IAM_USERS","state":"COMPLETE"},{"source":"IAM_LOGIN_SESSIONS","state":"COMPLETE"},{"source":"IAM_ACCESS_KEYS","state":"COMPLETE"},{"source":"IAM_ROLE_ACTIVITY","state":"NOT_INCLUDED"},{"source":"PAAS_RESULTS","state":"NOT_INCLUDED"},{"source":"AUDIT_STATISTICS","state":"NOT_INCLUDED"},{"source":"NOTIFICATION_DELIVERY","state":"NOT_INCLUDED"},{"source":"EXTERNAL_RISK","state":"NOT_INCLUDED"}]'::jsonb
      OR jsonb_typeof(value->'users')<>'array' OR jsonb_typeof(value->'accessKeys')<>'array'
      OR jsonb_array_length(value->'users')<>(metadata->>'userCount')::integer
      OR jsonb_array_length(value->'accessKeys')<>(metadata->>'accessKeyCount')::integer
      OR (SELECT count(*) FROM jsonb_array_elements(value->'users') u WHERE u->>'root'='true')<>1
      OR EXISTS(SELECT 1 FROM jsonb_array_elements(value->'accessKeys') k
        WHERE jsonb_typeof(k)<>'object' OR NOT (k ? 'credentialState')
          OR jsonb_typeof(k->'credentialState')<>'string'
          OR k->>'credentialState' NOT IN ('CURRENT','RECOVERY_FENCED'))
      OR octet_length(canonical_document)>4194304 OR octet_length(csv_document)<>(metadata->>'csvBytes')::integer
      OR 'sha256:'||encode(sha256(convert_to(canonical_document,'UTF8')),'hex')<>metadata->>'documentDigest'
      OR 'sha256:'||encode(sha256(csv_document),'hex')<>metadata->>'csvContentDigest'
      OR canonical_document::jsonb IS DISTINCT FROM jsonb_build_object('accountId',tenant,'formatVersion',2,
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

CREATE OR REPLACE FUNCTION iam.access_key_credential_state_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
  SELECT EXISTS(SELECT 1 FROM pg_constraint constraint_row
      WHERE constraint_row.conrelid='iam.access_key_intents'::regclass
        AND constraint_row.conname='access_key_intent_credential_state'
        AND constraint_row.contype='c' AND NOT constraint_row.convalidated)
    AND (SELECT count(*)=5 FROM pg_proc function_row WHERE function_row.oid IN (
      to_regprocedure('iam.access_key_result_valid(text,jsonb)'),
      to_regprocedure('iam.access_key_snapshot(text,text)'),
      to_regprocedure('iam.access_key_intent_result(text,text,text,text,text,text,text)'),
      to_regprocedure('iam.security_report_snapshot(text,text,text,text)'),
      to_regprocedure('iam.valid_security_report(jsonb,text,bytea,text,text)'))
      AND function_row.proowner='matrix_iam_owner'::regrole
      AND function_row.proconfig=ARRAY['search_path=pg_catalog, pg_temp'])
$function$;
REVOKE ALL ON FUNCTION iam.access_key_credential_state_contract_ready()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;

DO $access_key_credential_state_readiness_cutover$
BEGIN
    IF to_regprocedure('iam.readiness_v81()') IS NOT NULL THEN DROP FUNCTION iam.readiness_v81(); END IF;
    ALTER FUNCTION iam.readiness() RENAME TO readiness_v81;
END $access_key_credential_state_readiness_cutover$;
REVOKE ALL ON FUNCTION iam.readiness_v81() FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,
  matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
CREATE FUNCTION iam.readiness()
RETURNS TABLE(ready boolean,schema_version bigint,checked_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE predecessor record;
BEGIN
    SELECT * INTO predecessor FROM iam.readiness_v81();
    RETURN QUERY SELECT predecessor.ready AND iam.access_key_credential_state_contract_ready(),83::bigint,predecessor.checked_at;
END $function$;
REVOKE ALL ON FUNCTION iam.readiness() FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,
  matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
GRANT EXECUTE ON FUNCTION iam.readiness() TO matrix_iam_api;
