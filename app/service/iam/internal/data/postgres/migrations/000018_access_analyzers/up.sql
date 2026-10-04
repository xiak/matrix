SET LOCAL ROLE matrix_iam_owner;

CREATE TABLE IF NOT EXISTS iam.access_analyzers (
    tenant_id text COLLATE "C" NOT NULL,
    analyzer_id text COLLATE "C" NOT NULL,
    analyzer_type text NOT NULL,
    status text NOT NULL,
    unused_access_age_days integer NOT NULL,
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,analyzer_id),
    UNIQUE(tenant_id,analyzer_type),
    FOREIGN KEY(tenant_id) REFERENCES iam.accounts(id),
    CHECK(analyzer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' AND analyzer_type='UNUSED_ACCESS'
      AND status IN ('ACTIVE','DISABLED') AND unused_access_age_days BETWEEN 1 AND 365
      AND resource_version BETWEEN 1 AND 9007199254740991 AND isfinite(created_at) AND isfinite(updated_at)
      AND updated_at>=created_at)
);

CREATE TABLE IF NOT EXISTS iam.access_analyzer_observations (
    tenant_id text COLLATE "C" NOT NULL,
    analyzer_id text COLLATE "C" NOT NULL,
    source text NOT NULL,
    state text NOT NULL,
    observed_from timestamptz(6),
    observed_through timestamptz(6),
    reason text NOT NULL,
    PRIMARY KEY(tenant_id,analyzer_id,source),
    FOREIGN KEY(tenant_id,analyzer_id) REFERENCES iam.access_analyzers(tenant_id,analyzer_id),
    CHECK(source IN ('IAM_PASSWORD_SESSIONS','IAM_ACCESS_KEY_AUTHORIZATIONS','IAM_ROLE_SESSIONS','IAM_ROLE_AUTHORIZATIONS','PAAS_RESULTS','EXTERNAL_FEDERATION')),
    CHECK((source IN ('IAM_PASSWORD_SESSIONS','IAM_ACCESS_KEY_AUTHORIZATIONS','IAM_ROLE_SESSIONS','IAM_ROLE_AUTHORIZATIONS')
        AND state='INSUFFICIENT_COVERAGE' AND reason='SOURCE_NOT_READY' AND observed_from IS NOT NULL
        AND observed_through IS NOT NULL AND isfinite(observed_from) AND isfinite(observed_through) AND observed_through>=observed_from)
      OR (source IN ('PAAS_RESULTS','EXTERNAL_FEDERATION') AND state='NOT_INCLUDED'
        AND reason='SOURCE_NOT_IMPLEMENTED' AND observed_from IS NULL AND observed_through IS NULL))
);

CREATE TABLE IF NOT EXISTS iam.access_analyzer_receipts (
    tenant_id text COLLATE "C" NOT NULL,
    actor_id text COLLATE "C" NOT NULL,
    action_name text NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    request_digest text NOT NULL,
    analyzer_id text COLLATE "C" NOT NULL,
    result_document jsonb NOT NULL,
    decision_id text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    completed_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,actor_id,action_name,request_id),
    FOREIGN KEY(tenant_id,actor_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(tenant_id,analyzer_id) REFERENCES iam.access_analyzers(tenant_id,analyzer_id),
    FOREIGN KEY(tenant_id,decision_id) REFERENCES iam.authorization_decisions(tenant_id,id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,event_id) REFERENCES iam.audit_outbox(tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED,
    CHECK(action_name IN ('iam.access-analyzer.create','iam.access-analyzer.update')
      AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' AND request_digest ~ '^sha256:[0-9a-f]{64}$'
      AND isfinite(completed_at))
);

DO $access_analyzer_isolation$
DECLARE relation_name text; operation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['access_analyzers','access_analyzer_observations','access_analyzer_receipts'] LOOP
        EXECUTE format('ALTER TABLE iam.%I ENABLE ROW LEVEL SECURITY',relation_name);
        EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',relation_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON iam.%I',relation_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON iam.%I USING (tenant_id=iam.current_tenant_id()) WITH CHECK (tenant_id=iam.current_tenant_id())',relation_name);
    END LOOP;
    FOREACH operation_name IN ARRAY ARRAY['update','delete','truncate'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS cannot_%s ON iam.access_analyzer_receipts',operation_name);
        EXECUTE format('CREATE TRIGGER cannot_%s BEFORE %s ON iam.access_analyzer_receipts FOR EACH %s EXECUTE FUNCTION iam.reject_policy_history_change()',
          operation_name,operation_name,CASE WHEN operation_name='truncate' THEN 'STATEMENT' ELSE 'ROW' END);
        EXECUTE format('ALTER TABLE iam.access_analyzer_receipts ENABLE ALWAYS TRIGGER cannot_%s',operation_name);
    END LOOP;
END $access_analyzer_isolation$;

CREATE OR REPLACE FUNCTION iam.valid_access_analyzer(value jsonb,tenant text,analyzer text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE created timestamptz; updated timestamptz; version numeric; age numeric;
BEGIN
    IF value IS NULL OR jsonb_typeof(value)<>'object'
      OR NOT value ?& ARRAY['apiVersion','kind','id','accountId','type','status','unusedAccessAgeDays','resourceVersion','createdAt','updatedAt']
      OR value-ARRAY['apiVersion','kind','id','accountId','type','status','unusedAccessAgeDays','resourceVersion','createdAt','updatedAt']<>'{}'::jsonb
      OR value->>'apiVersion'<>'iam.matrix.xiak.com/v1' OR value->>'kind'<>'AccessAnalyzer'
      OR value->>'id' IS DISTINCT FROM analyzer OR value->>'accountId' IS DISTINCT FROM tenant
      OR value->>'type'<>'UNUSED_ACCESS' OR value->>'status' NOT IN ('ACTIVE','DISABLED')
      OR value->>'unusedAccessAgeDays' !~ '^[0-9]{1,3}$' OR value->>'resourceVersion' !~ '^[1-9][0-9]{0,15}$'
      OR NOT pg_input_is_valid(value->>'createdAt','timestamptz') OR NOT pg_input_is_valid(value->>'updatedAt','timestamptz') THEN RETURN false; END IF;
    age:=(value->>'unusedAccessAgeDays')::numeric; version:=(value->>'resourceVersion')::numeric;
    created:=(value->>'createdAt')::timestamptz; updated:=(value->>'updatedAt')::timestamptz;
    RETURN age BETWEEN 1 AND 365 AND version BETWEEN 1 AND 9007199254740991
      AND isfinite(created) AND isfinite(updated) AND updated>=created;
EXCEPTION WHEN others THEN RETURN false;
END $function$;

CREATE OR REPLACE FUNCTION iam.access_analyzer_document(tenant text,analyzer text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AccessAnalyzer','id',a.analyzer_id,
      'accountId',a.tenant_id,'type',a.analyzer_type,'status',a.status,'unusedAccessAgeDays',a.unused_access_age_days,
      'resourceVersion',a.resource_version,'createdAt',a.created_at,'updatedAt',a.updated_at)
      FROM iam.access_analyzers a WHERE a.tenant_id=tenant AND a.analyzer_id=analyzer
$function$;

CREATE OR REPLACE FUNCTION iam.assert_access_analyzer_actor(tenant text,actor text,actor_session text,
  decision text,action_name text,analyzer text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF COALESCE(tenant,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor_session,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(analyzer,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analyzer subject is invalid'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts a WHERE a.id=tenant AND a.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='access analyzer account is unavailable'; END IF;
    PERFORM iam.lock_mfa_session(tenant,actor,actor_session);
    IF action_name IN ('iam.access-analyzer.create','iam.access-analyzer.list') THEN
      PERFORM iam.assert_allowed_decision(tenant,actor,decision,action_name,'ACCOUNT',tenant,'INSTANCE',NULL);
    ELSIF action_name IN ('iam.access-analyzer.read','iam.access-analyzer.update','iam.access-finding.list') THEN
      PERFORM iam.assert_allowed_decision(tenant,actor,decision,action_name,'ACCESS_ANALYZER',analyzer,'INSTANCE',NULL);
    ELSE RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analyzer action is invalid'; END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.create_access_analyzer(tenant text,actor text,actor_session text,decision text,
  request_id text,request_digest text,analyzer_document jsonb,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE previous iam.access_analyzer_receipts%ROWTYPE; analyzer text:=analyzer_document->>'id'; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    PERFORM iam.assert_access_analyzer_actor(tenant,actor,actor_session,decision,'iam.access-analyzer.create',tenant);
    IF COALESCE(request_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(request_digest,'') !~ '^sha256:[0-9a-f]{64}$' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analyzer request is invalid'; END IF;
    SELECT * INTO previous FROM iam.access_analyzer_receipts r WHERE r.tenant_id=tenant AND r.actor_id=actor
      AND r.action_name='iam.access-analyzer.create' AND r.request_id=create_access_analyzer.request_id;
    IF FOUND THEN
      IF previous.request_digest IS DISTINCT FROM request_digest THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='access analyzer request conflicts'; END IF;
      RETURN previous.result_document;
    END IF;
    IF NOT iam.valid_access_analyzer(analyzer_document,tenant,analyzer) OR analyzer_document->>'status'<>'ACTIVE'
      OR analyzer_document->>'resourceVersion'<>'1' OR (analyzer_document->>'createdAt')::timestamptz IS DISTINCT FROM effective_now
      OR (analyzer_document->>'updatedAt')::timestamptz IS DISTINCT FROM effective_now
      OR event->>'requestId' IS DISTINCT FROM request_id OR event->>'requestDigest' IS DISTINCT FROM request_digest THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analyzer content is invalid'; END IF;
    IF EXISTS(SELECT 1 FROM iam.access_analyzers a WHERE a.tenant_id=tenant AND a.analyzer_type=analyzer_document->>'type') THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='access analyzer already exists'; END IF;
    PERFORM iam.assert_audit_event(event,tenant,'iam.access-analyzer.created','ACCESS_ANALYZER',analyzer,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analyzer decision differs'; END IF;
    INSERT INTO iam.access_analyzers(tenant_id,analyzer_id,analyzer_type,status,unused_access_age_days,resource_version,created_at,updated_at)
      VALUES(tenant,analyzer,analyzer_document->>'type',analyzer_document->>'status',(analyzer_document->>'unusedAccessAgeDays')::integer,1,effective_now,effective_now);
    INSERT INTO iam.access_analyzer_observations(tenant_id,analyzer_id,source,state,observed_from,observed_through,reason)
      SELECT tenant,analyzer,source,
        CASE WHEN ordinal<=4 THEN 'INSUFFICIENT_COVERAGE' ELSE 'NOT_INCLUDED' END,
        CASE WHEN ordinal<=4 THEN effective_now ELSE NULL END,CASE WHEN ordinal<=4 THEN effective_now ELSE NULL END,
        CASE WHEN ordinal<=4 THEN 'SOURCE_NOT_READY' ELSE 'SOURCE_NOT_IMPLEMENTED' END
      FROM unnest(ARRAY['IAM_PASSWORD_SESSIONS','IAM_ACCESS_KEY_AUTHORIZATIONS','IAM_ROLE_SESSIONS','IAM_ROLE_AUTHORIZATIONS','PAAS_RESULTS','EXTERNAL_FEDERATION']) WITH ORDINALITY AS s(source,ordinal);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    INSERT INTO iam.access_analyzer_receipts(tenant_id,actor_id,action_name,request_id,request_digest,analyzer_id,result_document,decision_id,event_id,completed_at)
      VALUES(tenant,actor,'iam.access-analyzer.create',request_id,request_digest,analyzer,analyzer_document,decision,event->>'eventId',effective_now);
    RETURN analyzer_document;
END $function$;

CREATE OR REPLACE FUNCTION iam.list_access_analyzers(tenant text,actor text,actor_session text,decision text,after_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.assert_access_analyzer_actor(tenant,actor,actor_session,decision,'iam.access-analyzer.list',tenant);
    IF COALESCE(after_id,'')<>'' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analyzer page is invalid'; END IF;
    SELECT COALESCE(jsonb_agg(iam.access_analyzer_document(tenant,a.analyzer_id) ORDER BY a.analyzer_id),'[]'::jsonb) INTO result
      FROM (SELECT analyzer_id FROM iam.access_analyzers WHERE tenant_id=tenant
        AND (COALESCE(after_id,'')='' OR analyzer_id>after_id COLLATE "C") ORDER BY analyzer_id LIMIT 101) a;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.read_access_analyzer(tenant text,actor text,actor_session text,decision text,analyzer text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.assert_access_analyzer_actor(tenant,actor,actor_session,decision,'iam.access-analyzer.read',analyzer);
    result:=iam.access_analyzer_document(tenant,analyzer);
    IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='access analyzer not found'; END IF;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.update_access_analyzer(tenant text,actor text,actor_session text,decision text,analyzer text,
  request_id text,request_digest text,new_status text,new_age integer,expected_version bigint,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE previous iam.access_analyzer_receipts%ROWTYPE; stored iam.access_analyzers%ROWTYPE; result jsonb; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    PERFORM iam.assert_access_analyzer_actor(tenant,actor,actor_session,decision,'iam.access-analyzer.update',analyzer);
    IF COALESCE(request_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' OR COALESCE(request_digest,'') !~ '^sha256:[0-9a-f]{64}$'
      OR new_status NOT IN ('ACTIVE','DISABLED') OR new_age NOT BETWEEN 1 AND 365 OR expected_version NOT BETWEEN 1 AND 9007199254740991 THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analyzer update is invalid'; END IF;
    SELECT * INTO previous FROM iam.access_analyzer_receipts r WHERE r.tenant_id=tenant AND r.actor_id=actor
      AND r.action_name='iam.access-analyzer.update' AND r.request_id=update_access_analyzer.request_id;
    IF FOUND THEN
      IF previous.request_digest IS DISTINCT FROM request_digest OR previous.analyzer_id IS DISTINCT FROM analyzer THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='access analyzer update conflicts'; END IF;
      RETURN previous.result_document;
    END IF;
    SELECT * INTO stored FROM iam.access_analyzers a WHERE a.tenant_id=tenant AND a.analyzer_id=analyzer FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='access analyzer not found'; END IF;
    IF stored.resource_version IS DISTINCT FROM expected_version THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='access analyzer version conflicts'; END IF;
    PERFORM iam.assert_audit_event(event,tenant,'iam.access-analyzer.updated','ACCESS_ANALYZER',analyzer,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision OR event->>'requestId' IS DISTINCT FROM request_id
      OR event->>'requestDigest' IS DISTINCT FROM request_digest OR (event->>'occurredAt')::timestamptz IS DISTINCT FROM effective_now THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analyzer update decision differs'; END IF;
    UPDATE iam.access_analyzers a SET status=new_status,unused_access_age_days=new_age,
      resource_version=stored.resource_version+1,updated_at=effective_now WHERE a.tenant_id=tenant AND a.analyzer_id=analyzer;
    IF stored.status='ACTIVE' AND new_status='DISABLED' THEN
      UPDATE iam.access_analyzer_observations o SET observed_through=effective_now WHERE o.tenant_id=tenant AND o.analyzer_id=analyzer AND o.observed_from IS NOT NULL;
    ELSIF stored.status='DISABLED' AND new_status='ACTIVE' THEN
      UPDATE iam.access_analyzer_observations o SET observed_from=effective_now,observed_through=effective_now WHERE o.tenant_id=tenant AND o.analyzer_id=analyzer AND o.observed_from IS NOT NULL;
    END IF;
    result:=iam.access_analyzer_document(tenant,analyzer);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    INSERT INTO iam.access_analyzer_receipts(tenant_id,actor_id,action_name,request_id,request_digest,analyzer_id,result_document,decision_id,event_id,completed_at)
      VALUES(tenant,actor,'iam.access-analyzer.update',request_id,request_digest,analyzer,result,decision,event->>'eventId',effective_now);
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.list_access_findings(tenant text,actor text,actor_session text,decision text,analyzer text,after_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE analyzer_status text; effective_now timestamptz(6):=transaction_timestamp(); coverage jsonb;
BEGIN
    PERFORM iam.assert_access_analyzer_actor(tenant,actor,actor_session,decision,'iam.access-finding.list',analyzer);
    IF COALESCE(after_id,'')<>'' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access finding page is invalid'; END IF;
    SELECT a.status INTO analyzer_status FROM iam.access_analyzers a WHERE a.tenant_id=tenant AND a.analyzer_id=analyzer;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='access analyzer not found'; END IF;
    SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object('source',o.source,'state',o.state,
      'observedFrom',o.observed_from,'observedThrough',CASE WHEN analyzer_status='ACTIVE' AND o.observed_from IS NOT NULL THEN effective_now ELSE o.observed_through END,
      'reason',o.reason)) ORDER BY array_position(ARRAY['IAM_PASSWORD_SESSIONS','IAM_ACCESS_KEY_AUTHORIZATIONS','IAM_ROLE_SESSIONS','IAM_ROLE_AUTHORIZATIONS','PAAS_RESULTS','EXTERNAL_FEDERATION'],o.source))
      INTO coverage FROM iam.access_analyzer_observations o WHERE o.tenant_id=tenant AND o.analyzer_id=analyzer;
    IF jsonb_array_length(COALESCE(coverage,'[]'::jsonb))<>6 THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='access analyzer coverage is incomplete'; END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AccessFindingList','accountId',tenant,
      'analyzerId',analyzer,'observedAt',effective_now,'coverage',coverage,'items','[]'::jsonb);
END $function$;

CREATE OR REPLACE FUNCTION iam.assert_access_analyzer_receipt()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE fact jsonb; expected_event_action text; expected_target_kind text; expected_target_id text;
BEGIN
    expected_event_action:=CASE NEW.action_name WHEN 'iam.access-analyzer.create' THEN 'iam.access-analyzer.created' ELSE 'iam.access-analyzer.updated' END;
    expected_target_kind:=CASE NEW.action_name WHEN 'iam.access-analyzer.create' THEN 'ACCOUNT' ELSE 'ACCESS_ANALYZER' END;
    expected_target_id:=CASE NEW.action_name WHEN 'iam.access-analyzer.create' THEN NEW.tenant_id ELSE NEW.analyzer_id END;
    IF NOT iam.valid_access_analyzer(NEW.result_document,NEW.tenant_id,NEW.analyzer_id) OR NOT EXISTS(
      SELECT 1 FROM iam.authorization_decisions d WHERE d.tenant_id=NEW.tenant_id AND d.id=NEW.decision_id
        AND d.principal_id=NEW.actor_id AND d.allowed AND d.action_name=NEW.action_name
        AND d.target_kind=expected_target_kind AND d.target_id=expected_target_id AND d.resource_mode='INSTANCE' AND d.collection_usage IS NULL) THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='access analyzer decision proof differs'; END IF;
    SELECT o.event_document INTO fact FROM iam.audit_outbox o WHERE o.tenant_id=NEW.tenant_id AND o.event_id=NEW.event_id;
    IF fact IS NULL OR fact->>'action' IS DISTINCT FROM expected_event_action OR fact->>'tenantId' IS DISTINCT FROM NEW.tenant_id
      OR fact->'actor' IS DISTINCT FROM jsonb_build_object('type','USER','id',NEW.actor_id)
      OR fact->'target' IS DISTINCT FROM jsonb_build_object('kind','ACCESS_ANALYZER','id',NEW.analyzer_id)
      OR fact->>'iamDecisionId' IS DISTINCT FROM NEW.decision_id OR fact->>'requestId' IS DISTINCT FROM NEW.request_id
      OR fact->>'correlationId' IS DISTINCT FROM NEW.request_id OR fact->>'requestDigest' IS DISTINCT FROM NEW.request_digest
      OR (fact->>'occurredAt')::timestamptz IS DISTINCT FROM NEW.completed_at OR fact ?| ARRAY['installationId','operationId']
      OR fact->>'result'<>'SUCCEEDED' THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='access analyzer audit proof differs'; END IF;
    RETURN NULL;
END $function$;
DROP TRIGGER IF EXISTS access_analyzer_receipt_complete ON iam.access_analyzer_receipts;
CREATE CONSTRAINT TRIGGER access_analyzer_receipt_complete AFTER INSERT ON iam.access_analyzer_receipts
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.assert_access_analyzer_receipt();
ALTER TABLE iam.access_analyzer_receipts ENABLE ALWAYS TRIGGER access_analyzer_receipt_complete;

REVOKE ALL ON TABLE iam.access_analyzers,iam.access_analyzer_observations,iam.access_analyzer_receipts
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.valid_access_analyzer(jsonb,text,text),iam.access_analyzer_document(text,text),
  iam.assert_access_analyzer_actor(text,text,text,text,text,text),iam.assert_access_analyzer_receipt()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.create_access_analyzer(text,text,text,text,text,text,jsonb,jsonb),
  iam.list_access_analyzers(text,text,text,text,text),iam.read_access_analyzer(text,text,text,text,text),
  iam.update_access_analyzer(text,text,text,text,text,text,text,text,integer,bigint,jsonb),
  iam.list_access_findings(text,text,text,text,text,text)
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
GRANT EXECUTE ON FUNCTION iam.create_access_analyzer(text,text,text,text,text,text,jsonb,jsonb),
  iam.list_access_analyzers(text,text,text,text,text),iam.read_access_analyzer(text,text,text,text,text),
  iam.update_access_analyzer(text,text,text,text,text,text,text,text,integer,bigint,jsonb),
  iam.list_access_findings(text,text,text,text,text,text) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.access_analyzer_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
  SELECT (SELECT count(*)=3 FROM pg_class relation WHERE relation.oid IN (
      to_regclass('iam.access_analyzers'),to_regclass('iam.access_analyzer_observations'),to_regclass('iam.access_analyzer_receipts'))
      AND relation.relowner='matrix_iam_owner'::regrole AND relation.relrowsecurity AND relation.relforcerowsecurity
      AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) privilege WHERE privilege.grantee<>relation.relowner))
    AND (SELECT count(*)=3 FROM pg_policies p WHERE p.schemaname='iam' AND p.tablename IN (
      'access_analyzers','access_analyzer_observations','access_analyzer_receipts') AND p.policyname='tenant_isolation'
      AND p.qual='(tenant_id = iam.current_tenant_id())' AND p.with_check='(tenant_id = iam.current_tenant_id())')
    AND (SELECT count(*)=5 FROM pg_proc f WHERE f.oid IN (
      to_regprocedure('iam.create_access_analyzer(text,text,text,text,text,text,jsonb,jsonb)'),
      to_regprocedure('iam.list_access_analyzers(text,text,text,text,text)'),
      to_regprocedure('iam.read_access_analyzer(text,text,text,text,text)'),
      to_regprocedure('iam.update_access_analyzer(text,text,text,text,text,text,text,text,integer,bigint,jsonb)'),
      to_regprocedure('iam.list_access_findings(text,text,text,text,text,text)'))
      AND f.proowner='matrix_iam_owner'::regrole AND f.prosecdef AND f.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
      AND has_function_privilege('matrix_iam_api',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_worker',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_credential_recovery',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_backup_custody',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_notification_worker',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_authentication_recovery',f.oid,'EXECUTE'))
    AND (SELECT count(*)=3 FROM pg_trigger t WHERE t.tgrelid='iam.access_analyzer_receipts'::regclass AND NOT t.tgisinternal
      AND t.tgname IN ('cannot_update','cannot_delete','cannot_truncate') AND t.tgenabled='A'
      AND t.tgfoid=to_regprocedure('iam.reject_policy_history_change()'))
    AND EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid='iam.access_analyzer_receipts'::regclass AND NOT t.tgisinternal
      AND t.tgname='access_analyzer_receipt_complete' AND t.tgenabled='A' AND t.tgfoid=to_regprocedure('iam.assert_access_analyzer_receipt()'))
$function$;
REVOKE ALL ON FUNCTION iam.access_analyzer_contract_ready()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;

DO $access_analyzer_readiness_cutover$
BEGIN
    IF to_regprocedure('iam.readiness_v61()') IS NOT NULL THEN DROP FUNCTION iam.readiness_v61(); END IF;
    ALTER FUNCTION iam.readiness() RENAME TO readiness_v61;
END $access_analyzer_readiness_cutover$;
REVOKE ALL ON FUNCTION iam.readiness_v61() FROM PUBLIC,matrix_iam_api,matrix_iam_worker,
  matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery;
CREATE FUNCTION iam.readiness()
RETURNS TABLE(ready boolean,schema_version bigint,checked_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE predecessor record;
BEGIN
    SELECT * INTO predecessor FROM iam.readiness_v61();
    RETURN QUERY SELECT predecessor.ready AND iam.access_analyzer_contract_ready(),62::bigint,predecessor.checked_at;
END $function$;
REVOKE ALL ON FUNCTION iam.readiness() FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,
  matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery;
GRANT EXECUTE ON FUNCTION iam.readiness() TO matrix_iam_api;
