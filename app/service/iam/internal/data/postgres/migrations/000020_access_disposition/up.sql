SET LOCAL ROLE matrix_iam_owner;

-- Automatic disposition is an explicit Account-owned rule. Existing
-- analyzers stay review-only; applying this migration cannot create a write
-- path or mutate any governed resource.
ALTER TABLE iam.access_analyzers ADD COLUMN IF NOT EXISTS disposition_mode text NOT NULL DEFAULT 'REVIEW_ONLY';
ALTER TABLE iam.access_analyzers ADD COLUMN IF NOT EXISTS disposition_delay_days integer NOT NULL DEFAULT 0;
ALTER TABLE iam.access_analyzers DROP CONSTRAINT IF EXISTS access_analyzers_check;
ALTER TABLE iam.access_analyzers DROP CONSTRAINT IF EXISTS access_analyzers_shape;
ALTER TABLE iam.access_analyzers ADD CONSTRAINT access_analyzers_shape CHECK(
  analyzer_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  AND analyzer_type='UNUSED_ACCESS' AND status IN ('ACTIVE','DISABLED')
  AND unused_access_age_days BETWEEN 1 AND 365
  AND ((disposition_mode='REVIEW_ONLY' AND disposition_delay_days=0)
    OR (disposition_mode='DISABLE_UNUSED_ACCESS_KEYS' AND disposition_delay_days BETWEEN 1 AND 30))
  AND resource_version BETWEEN 1 AND 9007199254740991
  AND isfinite(created_at) AND isfinite(updated_at) AND updated_at>=created_at
);

ALTER TABLE iam.access_findings ADD COLUMN IF NOT EXISTS resolution_reason text;
UPDATE iam.access_findings SET resolution_reason='CONDITION_CLEARED'
  WHERE status='RESOLVED' AND resolution_reason IS NULL;
ALTER TABLE iam.access_findings DROP CONSTRAINT IF EXISTS access_findings_check;
ALTER TABLE iam.access_findings DROP CONSTRAINT IF EXISTS access_findings_shape;
ALTER TABLE iam.access_findings ADD CONSTRAINT access_findings_shape CHECK(
  finding_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  AND target_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  AND ((finding_type='UNUSED_PASSWORD' AND target_kind='USER')
    OR (finding_type='UNUSED_ACCESS_KEY' AND target_kind='ACCESS_KEY')
    OR (finding_type='UNUSED_ROLE' AND target_kind='ROLE'))
  AND status IN ('ACTIVE','ARCHIVED','RESOLVED')
  AND analyzer_revision BETWEEN 1 AND 9007199254740991
  AND target_resource_version BETWEEN 1 AND 9007199254740991
  AND condition_generation BETWEEN 1 AND 9007199254740991
  AND activity_revision BETWEEN 1 AND 9007199254740991
  AND recovery_epoch BETWEEN 0 AND 9223372036854775807
  AND ((recovery_epoch=0 AND recovery_command_id IS NULL AND recovery_completed_at IS NULL)
    OR (recovery_epoch>0 AND recovery_command_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND recovery_completed_at IS NOT NULL AND window_started_at>=recovery_completed_at))
  AND resource_version BETWEEN 1 AND 9007199254740991
  AND isfinite(window_started_at) AND isfinite(observed_at) AND observed_at>window_started_at
  AND (last_activity_at IS NULL OR (isfinite(last_activity_at) AND last_activity_at<window_started_at))
  AND isfinite(created_at) AND isfinite(updated_at) AND created_at<=observed_at AND updated_at>=created_at
  AND ((status IN ('ACTIVE','ARCHIVED') AND resolved_at IS NULL AND resolution_reason IS NULL)
    OR (status='RESOLVED' AND resolved_at IS NOT NULL AND isfinite(resolved_at)
      AND resolved_at=updated_at AND observed_at=updated_at
      AND resolution_reason IN ('CONDITION_CLEARED','AUTOMATIC_DISPOSITION')))
);

ALTER TABLE iam.access_analyzer_receipts DROP CONSTRAINT IF EXISTS access_analyzer_receipts_action_name_check;
ALTER TABLE iam.access_analyzer_receipts DROP CONSTRAINT IF EXISTS access_analyzer_receipts_check;
ALTER TABLE iam.access_analyzer_receipts ADD CONSTRAINT access_analyzer_receipts_action_name_check CHECK(
  action_name IN ('iam.access-analyzer.create','iam.access-analyzer.update','iam.access-analyzer.set-disposition')
  AND request_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
  AND request_digest ~ '^sha256:[0-9a-f]{64}$' AND isfinite(completed_at)
);

CREATE OR REPLACE FUNCTION iam.valid_access_analyzer(value jsonb,tenant text,analyzer text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE created timestamptz; updated timestamptz; version numeric; age numeric; delay numeric;
BEGIN
    IF value IS NULL OR jsonb_typeof(value)<>'object'
      OR NOT value ?& ARRAY['apiVersion','kind','id','accountId','type','status','unusedAccessAgeDays','disposition','resourceVersion','createdAt','updatedAt']
      OR value-ARRAY['apiVersion','kind','id','accountId','type','status','unusedAccessAgeDays','disposition','resourceVersion','createdAt','updatedAt']<>'{}'::jsonb
      OR value->>'apiVersion'<>'iam.matrix.xiak.com/v1' OR value->>'kind'<>'AccessAnalyzer'
      OR value->>'id' IS DISTINCT FROM analyzer OR value->>'accountId' IS DISTINCT FROM tenant
      OR value->>'type'<>'UNUSED_ACCESS' OR value->>'status' NOT IN ('ACTIVE','DISABLED')
      OR jsonb_typeof(value->'disposition')<>'object'
      OR (value->'disposition')-ARRAY['mode','findingDelayDays']<>'{}'::jsonb
      OR NOT value->'disposition' ?& ARRAY['mode','findingDelayDays']
      OR value->>'unusedAccessAgeDays' !~ '^[0-9]{1,3}$'
      OR value#>>'{disposition,findingDelayDays}' !~ '^[0-9]{1,2}$'
      OR value->>'resourceVersion' !~ '^[1-9][0-9]{0,15}$'
      OR NOT pg_input_is_valid(value->>'createdAt','timestamptz')
      OR NOT pg_input_is_valid(value->>'updatedAt','timestamptz') THEN RETURN false; END IF;
    age:=(value->>'unusedAccessAgeDays')::numeric;
    delay:=(value#>>'{disposition,findingDelayDays}')::numeric;
    version:=(value->>'resourceVersion')::numeric;
    created:=(value->>'createdAt')::timestamptz; updated:=(value->>'updatedAt')::timestamptz;
    RETURN age BETWEEN 1 AND 365 AND version BETWEEN 1 AND 9007199254740991
      AND ((value#>>'{disposition,mode}'='REVIEW_ONLY' AND delay=0)
        OR (value#>>'{disposition,mode}'='DISABLE_UNUSED_ACCESS_KEYS' AND delay BETWEEN 1 AND 30))
      AND isfinite(created) AND isfinite(updated) AND updated>=created;
EXCEPTION WHEN others THEN RETURN false;
END $function$;

CREATE OR REPLACE FUNCTION iam.access_analyzer_document(tenant text,analyzer text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AccessAnalyzer','id',a.analyzer_id,
      'accountId',a.tenant_id,'type',a.analyzer_type,'status',a.status,'unusedAccessAgeDays',a.unused_access_age_days,
      'disposition',jsonb_build_object('mode',a.disposition_mode,'findingDelayDays',a.disposition_delay_days),
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
    ELSIF action_name IN ('iam.access-analyzer.read','iam.access-analyzer.update','iam.access-analyzer.set-disposition','iam.access-finding.list') THEN
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
      RETURN CASE WHEN previous.result_document ? 'disposition' THEN previous.result_document ELSE previous.result_document
        ||jsonb_build_object('disposition',jsonb_build_object('mode','REVIEW_ONLY','findingDelayDays',0)) END;
    END IF;
    IF NOT iam.valid_access_analyzer(analyzer_document,tenant,analyzer) OR analyzer_document->>'status'<>'ACTIVE'
      OR analyzer_document#>>'{disposition,mode}'<>'REVIEW_ONLY' OR analyzer_document#>>'{disposition,findingDelayDays}'<>'0'
      OR analyzer_document->>'resourceVersion'<>'1' OR (analyzer_document->>'createdAt')::timestamptz IS DISTINCT FROM effective_now
      OR (analyzer_document->>'updatedAt')::timestamptz IS DISTINCT FROM effective_now
      OR event->>'requestId' IS DISTINCT FROM request_id OR event->>'requestDigest' IS DISTINCT FROM request_digest THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analyzer content is invalid'; END IF;
    IF EXISTS(SELECT 1 FROM iam.access_analyzers a WHERE a.tenant_id=tenant AND a.analyzer_type=analyzer_document->>'type') THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='access analyzer already exists'; END IF;
    PERFORM iam.assert_audit_event(event,tenant,'iam.access-analyzer.created','ACCESS_ANALYZER',analyzer,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analyzer decision differs'; END IF;
    INSERT INTO iam.access_analyzers(tenant_id,analyzer_id,analyzer_type,status,unused_access_age_days,
      disposition_mode,disposition_delay_days,resource_version,created_at,updated_at)
      VALUES(tenant,analyzer,analyzer_document->>'type',analyzer_document->>'status',(analyzer_document->>'unusedAccessAgeDays')::integer,
        'REVIEW_ONLY',0,1,effective_now,effective_now);
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

CREATE OR REPLACE FUNCTION iam.update_access_analyzer(tenant text,actor text,actor_session text,decision text,analyzer text,
  request_id text,request_digest text,new_status text,new_age integer,expected_version bigint,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE previous iam.access_analyzer_receipts%ROWTYPE; stored iam.access_analyzers%ROWTYPE; result jsonb;
    effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    PERFORM iam.assert_access_analyzer_actor(tenant,actor,actor_session,decision,'iam.access-analyzer.update',analyzer);
    IF COALESCE(request_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(request_digest,'') !~ '^sha256:[0-9a-f]{64}$'
      OR new_status NOT IN ('ACTIVE','DISABLED') OR new_age NOT BETWEEN 1 AND 365
      OR expected_version NOT BETWEEN 1 AND 9007199254740991 THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analyzer update is invalid'; END IF;
    SELECT * INTO previous FROM iam.access_analyzer_receipts r WHERE r.tenant_id=tenant AND r.actor_id=actor
      AND r.action_name='iam.access-analyzer.update' AND r.request_id=update_access_analyzer.request_id;
    IF FOUND THEN
      IF previous.request_digest IS DISTINCT FROM request_digest OR previous.analyzer_id IS DISTINCT FROM analyzer THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='access analyzer update conflicts'; END IF;
      RETURN CASE WHEN previous.result_document ? 'disposition' THEN previous.result_document ELSE previous.result_document
        ||jsonb_build_object('disposition',jsonb_build_object('mode','REVIEW_ONLY','findingDelayDays',0)) END;
    END IF;
    SELECT * INTO stored FROM iam.access_analyzers a WHERE a.tenant_id=tenant AND a.analyzer_id=analyzer FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='access analyzer not found'; END IF;
    IF stored.resource_version IS DISTINCT FROM expected_version THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='access analyzer version conflicts'; END IF;
    PERFORM iam.assert_audit_event(event,tenant,'iam.access-analyzer.updated','ACCESS_ANALYZER',analyzer,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision OR event->>'requestId' IS DISTINCT FROM request_id
      OR event->>'requestDigest' IS DISTINCT FROM request_digest
      OR (event->>'occurredAt')::timestamptz IS DISTINCT FROM effective_now THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analyzer update decision differs'; END IF;
    UPDATE iam.access_analyzers a SET status=new_status,unused_access_age_days=new_age,
      resource_version=stored.resource_version+1,updated_at=effective_now WHERE a.tenant_id=tenant AND a.analyzer_id=analyzer;
    IF stored.status='ACTIVE' AND new_status='DISABLED' THEN
      UPDATE iam.access_analyzer_observations o SET observed_through=effective_now
        WHERE o.tenant_id=tenant AND o.analyzer_id=analyzer AND o.observed_from IS NOT NULL;
    ELSIF stored.status='DISABLED' AND new_status='ACTIVE' THEN
      UPDATE iam.access_analyzer_observations o SET observed_from=effective_now,observed_through=effective_now
        WHERE o.tenant_id=tenant AND o.analyzer_id=analyzer AND o.observed_from IS NOT NULL;
    END IF;
    result:=iam.access_analyzer_document(tenant,analyzer);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    INSERT INTO iam.access_analyzer_receipts(tenant_id,actor_id,action_name,request_id,request_digest,analyzer_id,
      result_document,decision_id,event_id,completed_at)
      VALUES(tenant,actor,'iam.access-analyzer.update',request_id,request_digest,analyzer,result,decision,event->>'eventId',effective_now);
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.set_access_disposition(tenant text,actor text,actor_session text,decision text,analyzer text,
  request_id text,request_digest text,new_mode text,new_delay integer,expected_version bigint,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE previous iam.access_analyzer_receipts%ROWTYPE; stored iam.access_analyzers%ROWTYPE; result jsonb;
    effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    PERFORM iam.assert_access_analyzer_actor(tenant,actor,actor_session,decision,'iam.access-analyzer.set-disposition',analyzer);
    IF COALESCE(request_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(request_digest,'') !~ '^sha256:[0-9a-f]{64}$'
      OR NOT ((new_mode='REVIEW_ONLY' AND new_delay=0)
        OR (new_mode='DISABLE_UNUSED_ACCESS_KEYS' AND new_delay BETWEEN 1 AND 30))
      OR expected_version NOT BETWEEN 1 AND 9007199254740991 THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access disposition is invalid'; END IF;
    SELECT * INTO previous FROM iam.access_analyzer_receipts r WHERE r.tenant_id=tenant AND r.actor_id=actor
      AND r.action_name='iam.access-analyzer.set-disposition' AND r.request_id=set_access_disposition.request_id;
    IF FOUND THEN
      IF previous.request_digest IS DISTINCT FROM request_digest OR previous.analyzer_id IS DISTINCT FROM analyzer THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='access disposition conflicts'; END IF;
      RETURN previous.result_document;
    END IF;
    SELECT * INTO stored FROM iam.access_analyzers a WHERE a.tenant_id=tenant AND a.analyzer_id=analyzer FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='access analyzer not found'; END IF;
    IF stored.resource_version IS DISTINCT FROM expected_version
      OR (stored.disposition_mode,stored.disposition_delay_days)=(new_mode,new_delay) THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='access disposition conflicts'; END IF;
    PERFORM iam.assert_audit_event(event,tenant,'iam.access-analyzer.disposition-updated','ACCESS_ANALYZER',analyzer,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision OR event->>'requestId' IS DISTINCT FROM request_id
      OR event->>'requestDigest' IS DISTINCT FROM request_digest
      OR (event->>'occurredAt')::timestamptz IS DISTINCT FROM effective_now THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access disposition decision differs'; END IF;
    UPDATE iam.access_analyzers a SET disposition_mode=new_mode,disposition_delay_days=new_delay,
      resource_version=stored.resource_version+1,updated_at=effective_now
      WHERE a.tenant_id=tenant AND a.analyzer_id=analyzer;
    result:=iam.access_analyzer_document(tenant,analyzer);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    INSERT INTO iam.access_analyzer_receipts(tenant_id,actor_id,action_name,request_id,request_digest,analyzer_id,
      result_document,decision_id,event_id,completed_at)
      VALUES(tenant,actor,'iam.access-analyzer.set-disposition',request_id,request_digest,analyzer,result,decision,event->>'eventId',effective_now);
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.assert_access_analyzer_receipt()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE fact jsonb; expected_event_action text; decision_target_kind text; decision_target_id text;
BEGIN
    expected_event_action:=CASE NEW.action_name
      WHEN 'iam.access-analyzer.create' THEN 'iam.access-analyzer.created'
      WHEN 'iam.access-analyzer.update' THEN 'iam.access-analyzer.updated'
      ELSE 'iam.access-analyzer.disposition-updated' END;
    decision_target_kind:=CASE NEW.action_name WHEN 'iam.access-analyzer.create' THEN 'ACCOUNT' ELSE 'ACCESS_ANALYZER' END;
    decision_target_id:=CASE NEW.action_name WHEN 'iam.access-analyzer.create' THEN NEW.tenant_id ELSE NEW.analyzer_id END;
    IF NOT iam.valid_access_analyzer(NEW.result_document,NEW.tenant_id,NEW.analyzer_id) OR NOT EXISTS(
      SELECT 1 FROM iam.authorization_decisions d WHERE d.tenant_id=NEW.tenant_id AND d.id=NEW.decision_id
        AND d.principal_id=NEW.actor_id AND d.allowed AND d.action_name=NEW.action_name
        AND d.target_kind=decision_target_kind AND d.target_id=decision_target_id
        AND d.resource_mode='INSTANCE' AND d.collection_usage IS NULL) THEN
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

CREATE OR REPLACE FUNCTION iam.access_finding_document(tenant text,finding text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
  SELECT jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AccessFinding','id',f.finding_id,
    'accountId',f.tenant_id,'analyzerId',f.analyzer_id,'analyzerRevision',f.analyzer_revision,'type',f.finding_type,
    'status',f.status,'target',jsonb_build_object('kind',f.target_kind,'id',f.target_id),
    'targetResourceVersion',f.target_resource_version,'conditionGeneration',f.condition_generation,
    'activityRevision',f.activity_revision,'recoveryEpoch',f.recovery_epoch,'recoveryCommandId',f.recovery_command_id,
    'recoveryCompletedAt',f.recovery_completed_at,'windowStartedAt',f.window_started_at,'observedAt',f.observed_at,
    'lastActivityAt',f.last_activity_at,'resourceVersion',f.resource_version,'createdAt',f.created_at,
    'updatedAt',f.updated_at,'resolvedAt',f.resolved_at,'resolutionReason',f.resolution_reason))
    FROM iam.access_findings f WHERE f.tenant_id=tenant AND f.finding_id=finding
$function$;

CREATE OR REPLACE FUNCTION iam.valid_access_finding(value jsonb,tenant text,analyzer text,finding text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE recovered timestamptz; window_start timestamptz; observed timestamptz; created timestamptz; updated timestamptz;
    resolved timestamptz; last_used timestamptz; epoch numeric; version numeric;
BEGIN
    IF value IS NULL OR jsonb_typeof(value)<>'object'
      OR NOT value ?& ARRAY['apiVersion','kind','id','accountId','analyzerId','analyzerRevision','type','status','target',
        'targetResourceVersion','conditionGeneration','activityRevision','recoveryEpoch','windowStartedAt','observedAt',
        'resourceVersion','createdAt','updatedAt']
      OR value-ARRAY['apiVersion','kind','id','accountId','analyzerId','analyzerRevision','type','status','target',
        'targetResourceVersion','conditionGeneration','activityRevision','recoveryEpoch','recoveryCommandId','recoveryCompletedAt',
        'windowStartedAt','observedAt','lastActivityAt','resourceVersion','createdAt','updatedAt','resolvedAt','resolutionReason']<>'{}'::jsonb
      OR value->>'apiVersion'<>'iam.matrix.xiak.com/v1' OR value->>'kind'<>'AccessFinding'
      OR value->>'id' IS DISTINCT FROM finding OR value->>'accountId' IS DISTINCT FROM tenant
      OR value->>'analyzerId' IS DISTINCT FROM analyzer OR jsonb_typeof(value->'target')<>'object'
      OR ((value->'target')-ARRAY['kind','id'])<>'{}'::jsonb
      OR NOT (((value->>'type')='UNUSED_PASSWORD' AND value#>>'{target,kind}'='USER')
        OR ((value->>'type')='UNUSED_ACCESS_KEY' AND value#>>'{target,kind}'='ACCESS_KEY')
        OR ((value->>'type')='UNUSED_ROLE' AND value#>>'{target,kind}'='ROLE'))
      OR value->>'status' NOT IN ('ACTIVE','ARCHIVED','RESOLVED')
      OR value#>>'{target,id}' COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR value->>'analyzerRevision' !~ '^[1-9][0-9]{0,15}$'
      OR value->>'targetResourceVersion' !~ '^[1-9][0-9]{0,15}$'
      OR value->>'conditionGeneration' !~ '^[1-9][0-9]{0,15}$'
      OR value->>'activityRevision' !~ '^[1-9][0-9]{0,15}$'
      OR value->>'resourceVersion' !~ '^[1-9][0-9]{0,15}$'
      OR value->>'recoveryEpoch' !~ '^[0-9]{1,19}$'
      OR NOT pg_input_is_valid(value->>'windowStartedAt','timestamptz')
      OR NOT pg_input_is_valid(value->>'observedAt','timestamptz')
      OR NOT pg_input_is_valid(value->>'createdAt','timestamptz')
      OR NOT pg_input_is_valid(value->>'updatedAt','timestamptz') THEN RETURN false; END IF;
    epoch:=(value->>'recoveryEpoch')::numeric; version:=(value->>'resourceVersion')::numeric;
    window_start:=(value->>'windowStartedAt')::timestamptz; observed:=(value->>'observedAt')::timestamptz;
    created:=(value->>'createdAt')::timestamptz; updated:=(value->>'updatedAt')::timestamptz;
    IF epoch NOT BETWEEN 0 AND 9223372036854775807 OR version NOT BETWEEN 1 AND 9007199254740991
      OR NOT isfinite(window_start) OR NOT isfinite(observed) OR observed<=window_start
      OR NOT isfinite(created) OR NOT isfinite(updated) OR created>observed OR updated<created THEN RETURN false; END IF;
    IF epoch=0 THEN
      IF value ?| ARRAY['recoveryCommandId','recoveryCompletedAt'] THEN RETURN false; END IF;
    ELSE
      IF value->>'recoveryCommandId' COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR NOT pg_input_is_valid(value->>'recoveryCompletedAt','timestamptz') THEN RETURN false; END IF;
      recovered:=(value->>'recoveryCompletedAt')::timestamptz;
      IF NOT isfinite(recovered) OR window_start<recovered THEN RETURN false; END IF;
    END IF;
    IF value ? 'lastActivityAt' THEN
      IF NOT pg_input_is_valid(value->>'lastActivityAt','timestamptz') THEN RETURN false; END IF;
      last_used:=(value->>'lastActivityAt')::timestamptz;
      IF NOT isfinite(last_used) OR last_used>=window_start THEN RETURN false; END IF;
    END IF;
    IF value->>'status'='RESOLVED' THEN
      IF NOT pg_input_is_valid(value->>'resolvedAt','timestamptz')
        OR value->>'resolutionReason' NOT IN ('CONDITION_CLEARED','AUTOMATIC_DISPOSITION') THEN RETURN false; END IF;
      resolved:=(value->>'resolvedAt')::timestamptz;
      RETURN isfinite(resolved) AND resolved=updated AND observed=updated;
    END IF;
    RETURN NOT value ?| ARRAY['resolvedAt','resolutionReason'];
EXCEPTION WHEN others THEN RETURN false;
END $function$;

-- The existing scanner is the sole path that resolves a condition without a
-- lifecycle mutation. The trigger records that exact reason before the new
-- table constraint is evaluated; the automatic disposition path supplies its
-- own explicit reason and is not rewritten.
CREATE OR REPLACE FUNCTION iam.assign_access_finding_resolution_reason()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF NEW.status='RESOLVED' AND OLD.status<>'RESOLVED' AND NEW.resolution_reason IS NULL
      AND current_setting('matrix.iam_access_analysis',true)='trusted' THEN
      NEW.resolution_reason:='CONDITION_CLEARED';
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS access_finding_resolution_reason ON iam.access_findings;
CREATE TRIGGER access_finding_resolution_reason BEFORE UPDATE OF status ON iam.access_findings
  FOR EACH ROW EXECUTE FUNCTION iam.assign_access_finding_resolution_reason();
ALTER TABLE iam.access_findings ENABLE ALWAYS TRIGGER access_finding_resolution_reason;

CREATE TABLE IF NOT EXISTS iam.access_disposition_state (
    tenant_id text COLLATE "C" NOT NULL,
    finding_id text COLLATE "C" NOT NULL,
    fence bigint NOT NULL DEFAULT 0,
    worker_id text COLLATE "C",
    lease_expires_at timestamptz(6),
    updated_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,finding_id),
    FOREIGN KEY(tenant_id,finding_id) REFERENCES iam.access_findings(tenant_id,finding_id),
    CHECK(fence BETWEEN 0 AND 9007199254740991 AND isfinite(updated_at)
      AND ((worker_id IS NULL AND lease_expires_at IS NULL)
        OR (worker_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
          AND lease_expires_at IS NOT NULL AND isfinite(lease_expires_at))))
);

CREATE TABLE IF NOT EXISTS iam.access_disposition_attempts (
    attempt_id text COLLATE "C" PRIMARY KEY,
    tenant_id text COLLATE "C" NOT NULL,
    analyzer_id text COLLATE "C" NOT NULL,
    finding_id text COLLATE "C" NOT NULL,
    worker_id text COLLATE "C" NOT NULL,
    fence bigint NOT NULL,
    snapshot_document jsonb NOT NULL,
    snapshot_digest text NOT NULL,
    claimed_at timestamptz(6) NOT NULL,
    lease_expires_at timestamptz(6) NOT NULL,
    completed_at timestamptz(6),
    completion_document jsonb,
    FOREIGN KEY(tenant_id,analyzer_id) REFERENCES iam.access_analyzers(tenant_id,analyzer_id),
    FOREIGN KEY(tenant_id,finding_id) REFERENCES iam.access_findings(tenant_id,finding_id),
    CHECK(attempt_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND worker_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND fence BETWEEN 1 AND 9007199254740991 AND jsonb_typeof(snapshot_document)='object'
      AND snapshot_digest ~ '^sha256:[0-9a-f]{64}$'
      AND isfinite(claimed_at) AND isfinite(lease_expires_at) AND lease_expires_at>claimed_at
      AND ((completed_at IS NULL AND completion_document IS NULL)
        OR (completed_at IS NOT NULL AND isfinite(completed_at) AND jsonb_typeof(completion_document)='object')))
);

DO $access_disposition_isolation$
DECLARE relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['access_disposition_state','access_disposition_attempts'] LOOP
        EXECUTE format('ALTER TABLE iam.%I ENABLE ROW LEVEL SECURITY',relation_name);
        EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',relation_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON iam.%I',relation_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON iam.%I USING (tenant_id=iam.current_tenant_id() OR current_setting(''matrix.iam_access_analysis'',true)=''trusted'') WITH CHECK (tenant_id=iam.current_tenant_id() OR current_setting(''matrix.iam_access_analysis'',true)=''trusted'')',relation_name);
    END LOOP;
END $access_disposition_isolation$;

-- This snapshot is evidence, never a permit. Completion acquires the same
-- identity locks as platform attachment writers and recomputes it.
CREATE OR REPLACE FUNCTION iam.access_disposition_snapshot(tenant text,finding text,evaluated_at timestamptz)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'accountId',a.tenant_id,'analyzerId',a.analyzer_id,'analyzerRevision',a.resource_version,
    'findingId',f.finding_id,'findingResourceVersion',f.resource_version,'findingCreatedAt',f.created_at,
    'conditionGeneration',f.condition_generation,'targetResourceVersion',f.target_resource_version,
    'activityRevision',(1+activity.activity_count)::bigint,'recoveryEpoch',f.recovery_epoch,
    'accessKeyId',k.id,'accessKeyResourceVersion',k.resource_version,'userId',k.user_id,
    'lastActivityAt',activity.last_activity,'evaluatedAt',evaluated_at))
  FROM iam.access_findings f
  JOIN iam.access_analyzers a ON (a.tenant_id,a.analyzer_id)=(f.tenant_id,f.analyzer_id)
  JOIN iam.access_keys k ON k.tenant_id=f.tenant_id AND k.id=f.target_id
  JOIN iam.principals p ON (p.tenant_id,p.id)=(k.tenant_id,k.user_id)
  JOIN iam.accounts account ON account.id=f.tenant_id
  JOIN iam.authentication_recovery_state recovery ON recovery.singleton
  LEFT JOIN LATERAL (
    SELECT count(d.id) AS activity_count,max(d.decided_at) AS last_activity
      FROM iam.authorization_decisions d WHERE d.tenant_id=k.tenant_id AND d.access_key_id=k.id
        AND d.decided_at<=evaluated_at
        AND (f.recovery_completed_at IS NULL OR d.decided_at>=f.recovery_completed_at)
  ) activity ON true
  WHERE f.tenant_id=tenant AND f.finding_id=finding
    AND account.status='ACTIVE' AND a.status='ACTIVE' AND a.analyzer_type='UNUSED_ACCESS'
    AND a.disposition_mode='DISABLE_UNUSED_ACCESS_KEYS' AND a.disposition_delay_days BETWEEN 1 AND 30
    AND a.resource_version=f.analyzer_revision
    AND f.status='ACTIVE' AND f.finding_type='UNUSED_ACCESS_KEY' AND f.target_kind='ACCESS_KEY'
    AND f.created_at+make_interval(days=>a.disposition_delay_days)<=evaluated_at
    AND recovery.state='OPEN' AND recovery.epoch=f.recovery_epoch
    AND ((f.recovery_epoch=0 AND f.recovery_command_id IS NULL AND f.recovery_completed_at IS NULL)
      OR (f.recovery_epoch>0 AND EXISTS(
        SELECT 1 FROM iam.authentication_recovery_closures c
        JOIN iam.authentication_recovery_completions completion ON completion.command_id=c.command_id
          AND completion.installation_id=c.installation_id AND completion.home_tenant_id=c.home_tenant_id
        WHERE c.epoch=f.recovery_epoch AND c.command_id=f.recovery_command_id
          AND completion.completed_at=f.recovery_completed_at)))
    AND k.status='ENABLED' AND k.deleted_at IS NULL AND k.format_version IS NOT NULL
    AND k.resource_version=f.target_resource_version
    AND p.principal_type='USER' AND p.status='ACTIVE' AND p.deleted_at IS NULL
    AND NOT EXISTS(SELECT 1 FROM iam.account_roots root
      WHERE root.account_id=k.tenant_id AND root.principal_id=k.user_id)
    AND NOT EXISTS(SELECT 1 FROM iam.policy_attachments attachment
      WHERE attachment.tenant_id=k.tenant_id AND attachment.target_kind='USER' AND attachment.target_id=k.user_id
        AND attachment.policy_id='system.platform-operator' AND attachment.revoked_at IS NULL)
    AND f.activity_revision=(1+activity.activity_count)::bigint
    AND f.last_activity_at IS NOT DISTINCT FROM activity.last_activity
    AND (SELECT count(*)=4 FROM iam.access_analyzer_observations observation
      WHERE observation.tenant_id=a.tenant_id AND observation.analyzer_id=a.analyzer_id
        AND observation.source IN ('IAM_PASSWORD_SESSIONS','IAM_ACCESS_KEY_AUTHORIZATIONS','IAM_ROLE_SESSIONS','IAM_ROLE_AUTHORIZATIONS')
        AND observation.state='COMPLETE' AND observation.recovery_epoch=recovery.epoch
        AND observation.observed_from<=f.window_started_at
        AND observation.observed_through>=evaluated_at-interval '10 minutes')
$function$;

CREATE OR REPLACE FUNCTION iam.assert_access_analysis_worker()
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF session_user<>'matrix_iam_access_analysis_worker_login'
      OR NOT pg_has_role(session_user,'matrix_iam_access_analysis_worker','USAGE')
      OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=session_user
        AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls))
      OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname NOT IN (session_user,'matrix_iam_access_analysis_worker')
        AND pg_has_role(session_user,r.oid,'MEMBER'))
      OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relnamespace='iam'::regnamespace AND c.relkind IN ('r','p','v','m','f')
        AND has_table_privilege(session_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
      OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.pronamespace='iam'::regnamespace
        AND p.oid NOT IN (to_regprocedure('iam.access_analysis_worker_ready()'),
          to_regprocedure('iam.claim_access_analysis(text,text)'),
          to_regprocedure('iam.complete_access_analysis(text,text,bigint,text,jsonb)'),
          to_regprocedure('iam.claim_access_disposition(text,text)'),
          to_regprocedure('iam.complete_access_disposition(text,text,bigint,text,jsonb)'))
        AND has_function_privilege(session_user,p.oid,'EXECUTE')) THEN
      RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='access analysis worker context is forbidden';
    END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.claim_access_disposition(worker text,attempt text)
RETURNS TABLE(attempt_id text,worker_id text,fence bigint,lease_expires_at timestamptz,snapshot_digest text,snapshot_document jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE candidate record; claimed_snapshot jsonb; digest text; effective_now timestamptz(6):=clock_timestamp();
    prior_scope text; prior_tenant text; claimed_fence bigint; claimed_lease timestamptz(6);
BEGIN
    PERFORM iam.assert_access_analysis_worker();
    IF COALESCE(worker,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(attempt,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access disposition claim is invalid'; END IF;
    prior_scope:=current_setting('matrix.iam_access_analysis',true);
    prior_tenant:=current_setting('matrix.iam_tenant_id',true);
    PERFORM set_config('matrix.iam_access_analysis','trusted',true);
    -- Finding/analyzer rows are visible through the purpose-only worker scope,
    -- but target USER/AccessKey state remains tenant-RLS protected. Select a
    -- bounded set of likely candidates, then evaluate each only after binding
    -- the authoritative tenant context. Do not broaden source-table policies.
    FOR candidate IN
      SELECT f.tenant_id,f.finding_id FROM iam.access_findings f
      JOIN iam.access_analyzers a ON (a.tenant_id,a.analyzer_id)=(f.tenant_id,f.analyzer_id)
      WHERE a.status='ACTIVE' AND a.disposition_mode='DISABLE_UNUSED_ACCESS_KEYS'
        AND f.status='ACTIVE' AND f.target_kind='ACCESS_KEY'
        AND f.created_at<=effective_now-make_interval(days=>a.disposition_delay_days)
      ORDER BY f.tenant_id COLLATE "C",f.finding_id COLLATE "C" LIMIT 100
    LOOP
      PERFORM set_config('matrix.iam_tenant_id',candidate.tenant_id,true);
      claimed_snapshot:=iam.access_disposition_snapshot(candidate.tenant_id,candidate.finding_id,effective_now);
      IF claimed_snapshot IS NOT NULL THEN
        INSERT INTO iam.access_disposition_state(tenant_id,finding_id,updated_at)
          VALUES(candidate.tenant_id,candidate.finding_id,effective_now)
          ON CONFLICT(tenant_id,finding_id) DO NOTHING;
      END IF;
    END LOOP;
    -- Locking precedes the final snapshot. Multiple workers may inspect the
    -- same bounded directory, but SKIP LOCKED and the monotonically increasing
    -- fence allow only one current claimant.
    FOR candidate IN
      SELECT state.tenant_id,state.finding_id,state.fence
      FROM iam.access_disposition_state state
      WHERE state.worker_id IS NULL OR state.lease_expires_at<=effective_now
      ORDER BY state.tenant_id COLLATE "C",state.finding_id COLLATE "C"
      FOR UPDATE OF state SKIP LOCKED LIMIT 100
    LOOP
      PERFORM set_config('matrix.iam_tenant_id',candidate.tenant_id,true);
      claimed_snapshot:=iam.access_disposition_snapshot(candidate.tenant_id,candidate.finding_id,effective_now);
      IF claimed_snapshot IS NULL THEN CONTINUE; END IF;
      IF candidate.fence>=9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='22003',MESSAGE='access disposition fence exhausted'; END IF;
      digest:='sha256:'||encode(sha256(convert_to(claimed_snapshot::text,'UTF8')),'hex');
      UPDATE iam.access_disposition_state state SET fence=state.fence+1,worker_id=worker,
        lease_expires_at=effective_now+interval '30 seconds',updated_at=effective_now
        WHERE (state.tenant_id,state.finding_id)=(candidate.tenant_id,candidate.finding_id)
        RETURNING state.fence,state.lease_expires_at INTO claimed_fence,claimed_lease;
      INSERT INTO iam.access_disposition_attempts(attempt_id,tenant_id,analyzer_id,finding_id,worker_id,fence,
        snapshot_document,snapshot_digest,claimed_at,lease_expires_at)
        VALUES(attempt,candidate.tenant_id,claimed_snapshot->>'analyzerId',candidate.finding_id,worker,claimed_fence,
          claimed_snapshot,digest,effective_now,claimed_lease);
      PERFORM set_config('matrix.iam_access_analysis',COALESCE(prior_scope,''),true);
      PERFORM set_config('matrix.iam_tenant_id',COALESCE(prior_tenant,''),true);
      RETURN QUERY SELECT attempt,worker,claimed_fence,claimed_lease,digest,claimed_snapshot;
      RETURN;
    END LOOP;
    PERFORM set_config('matrix.iam_access_analysis',COALESCE(prior_scope,''),true);
    PERFORM set_config('matrix.iam_tenant_id',COALESCE(prior_tenant,''),true);
END $function$;

CREATE OR REPLACE FUNCTION iam.access_disposition_event_digest(action_name text,attempt text,target text,snapshot_digest text)
RETURNS text LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
  SELECT 'sha256:'||encode(sha256(convert_to('matrix.iam.access-disposition-event.v1|'
    ||octet_length(action_name)||':'||action_name||'|'
    ||octet_length(attempt)||':'||attempt||'|'
    ||octet_length(target)||':'||target||'|'
    ||octet_length(snapshot_digest)||':'||snapshot_digest||'|','UTF8')),'hex')
$function$;

CREATE OR REPLACE FUNCTION iam.complete_access_disposition(attempt text,worker text,lease_fence bigint,tenant text,result jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE original iam.access_disposition_attempts%ROWTYPE; state iam.access_disposition_state%ROWTYPE;
    analyzer iam.access_analyzers%ROWTYPE; finding iam.access_findings%ROWTYPE; key_row iam.access_keys%ROWTYPE;
    current_snapshot jsonb; key_event jsonb; finding_event jsonb; completion jsonb;
    effective_now timestamptz(6):=clock_timestamp(); completion_time timestamptz(6):=transaction_timestamp();
BEGIN
    PERFORM iam.assert_access_analysis_worker();
    IF COALESCE(attempt,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(worker,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(tenant,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR lease_fence NOT BETWEEN 1 AND 9007199254740991 OR jsonb_typeof(result)<>'object'
      OR NOT result ?& ARRAY['keyEventId','keyRequestId','findingEventId','findingRequestId']
      OR result-ARRAY['keyEventId','keyRequestId','findingEventId','findingRequestId']<>'{}'::jsonb
      OR EXISTS(SELECT 1 FROM jsonb_each_text(result) entry
        WHERE entry.value COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access disposition completion is invalid'; END IF;
    PERFORM set_config('matrix.iam_access_analysis','trusted',true);
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    SELECT * INTO original FROM iam.access_disposition_attempts a WHERE a.attempt_id=attempt FOR UPDATE;
    IF NOT FOUND OR original.tenant_id IS DISTINCT FROM tenant OR original.worker_id IS DISTINCT FROM worker
      OR original.fence IS DISTINCT FROM lease_fence THEN
      RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='access disposition attempt is stale'; END IF;
    IF original.completed_at IS NOT NULL THEN
      IF original.completion_document->'request' IS DISTINCT FROM result THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='access disposition completion conflicts'; END IF;
      RETURN;
    END IF;
    SELECT * INTO state FROM iam.access_disposition_state s
      WHERE (s.tenant_id,s.finding_id)=(original.tenant_id,original.finding_id) FOR UPDATE;
    IF NOT FOUND OR state.worker_id IS DISTINCT FROM worker OR state.fence IS DISTINCT FROM lease_fence
      OR state.lease_expires_at IS DISTINCT FROM original.lease_expires_at OR state.lease_expires_at<=effective_now THEN
      RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='access disposition lease is stale'; END IF;
    -- Authentication recovery owns the global barrier before touching any
    -- Account credential or AccessKey. Take that barrier first as well, so an
    -- automatic disposition cannot hold a USER/Key row while waiting for a
    -- recovery transaction that will later fence the same rows.
    PERFORM 1 FROM iam.authentication_recovery_state recovery
      WHERE recovery.singleton AND recovery.state='OPEN' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='access disposition recovery state changed'; END IF;
    PERFORM 1 FROM iam.accounts account WHERE account.id=tenant AND account.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='access disposition account changed'; END IF;
    SELECT * INTO analyzer FROM iam.access_analyzers a WHERE (a.tenant_id,a.analyzer_id)=(tenant,original.analyzer_id) FOR UPDATE;
    SELECT * INTO finding FROM iam.access_findings f WHERE (f.tenant_id,f.finding_id)=(tenant,original.finding_id) FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='access disposition finding changed'; END IF;
    PERFORM 1 FROM iam.principals p WHERE (p.tenant_id,p.id)=(tenant,original.snapshot_document->>'userId')
      ORDER BY p.id FOR NO KEY UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='access disposition principal changed'; END IF;
    PERFORM 1 FROM iam.policies policy WHERE policy.id='system.platform-operator' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='access disposition platform policy changed'; END IF;
    SELECT * INTO key_row FROM iam.access_keys k WHERE (k.tenant_id,k.id)=(tenant,original.snapshot_document->>'accessKeyId') FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='access disposition access key changed'; END IF;
    current_snapshot:=iam.access_disposition_snapshot(tenant,original.finding_id,effective_now);
    IF current_snapshot IS NULL OR current_snapshot-'evaluatedAt' IS DISTINCT FROM original.snapshot_document-'evaluatedAt'
      OR original.snapshot_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(original.snapshot_document::text,'UTF8')),'hex') THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='access disposition evidence changed'; END IF;

    key_event:=jsonb_build_object('apiVersion','audit.matrix.xiak.com/v1','kind','AuditEvent',
      'eventId',result->>'keyEventId','tenantId',tenant,'actor',jsonb_build_object('type','SYSTEM','id','iam.access-analyzer'),
      'action','iam.access-key.automatically-disabled','target',jsonb_build_object('kind','ACCESS_KEY','id',key_row.id),
      'result','SUCCEEDED','requestDigest',iam.access_disposition_event_digest('iam.access-key.automatically-disabled',attempt,key_row.id,original.snapshot_digest),
      'requestId',result->>'keyRequestId','correlationId',attempt,
      'occurredAt',to_char(completion_time AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
    finding_event:=jsonb_build_object('apiVersion','audit.matrix.xiak.com/v1','kind','AuditEvent',
      'eventId',result->>'findingEventId','tenantId',tenant,'actor',jsonb_build_object('type','SYSTEM','id','iam.access-analyzer'),
      'action','iam.access-finding.resolved','target',jsonb_build_object('kind','ACCESS_FINDING','id',finding.finding_id),
      'result','SUCCEEDED','requestDigest',iam.access_disposition_event_digest('iam.access-finding.resolved',attempt,finding.finding_id,original.snapshot_digest),
      'requestId',result->>'findingRequestId','correlationId',attempt,
      'occurredAt',to_char(completion_time AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
    PERFORM iam.assert_audit_event(key_event,tenant,'iam.access-key.automatically-disabled','ACCESS_KEY',key_row.id,'SUCCEEDED');
    PERFORM iam.assert_audit_event(finding_event,tenant,'iam.access-finding.resolved','ACCESS_FINDING',finding.finding_id,'SUCCEEDED');

    UPDATE iam.access_keys k SET status='DISABLED',resource_version=k.resource_version+1,updated_at=completion_time
      WHERE (k.tenant_id,k.id)=(tenant,key_row.id);
    UPDATE iam.access_findings f SET status='RESOLVED',resolution_reason='AUTOMATIC_DISPOSITION',
      resource_version=f.resource_version+1,observed_at=completion_time,updated_at=completion_time,resolved_at=completion_time
      WHERE (f.tenant_id,f.finding_id)=(tenant,finding.finding_id);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,key_event->>'eventId',key_event,completion_time,completion_time,completion_time),
        (tenant,finding_event->>'eventId',finding_event,completion_time,completion_time,completion_time);
    completion:=jsonb_build_object('request',result,'accessKeyResourceVersion',key_row.resource_version+1,
      'findingResourceVersion',finding.resource_version+1,'completedAt',completion_time);
    UPDATE iam.access_disposition_attempts a SET completed_at=completion_time,completion_document=completion WHERE a.attempt_id=attempt;
    UPDATE iam.access_disposition_state s SET worker_id=NULL,lease_expires_at=NULL,updated_at=completion_time
      WHERE (s.tenant_id,s.finding_id)=(tenant,finding.finding_id) AND s.fence=lease_fence;
END $function$;

CREATE OR REPLACE FUNCTION iam.access_analyzer_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
  SELECT (SELECT count(*)=4 FROM pg_class relation WHERE relation.oid IN (
      to_regclass('iam.access_analyzers'),to_regclass('iam.access_analyzer_observations'),to_regclass('iam.access_analyzer_receipts'),
      to_regclass('iam.access_finding_receipts'))
      AND relation.relowner='matrix_iam_owner'::regrole AND relation.relrowsecurity AND relation.relforcerowsecurity
      AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) privilege WHERE privilege.grantee<>relation.relowner))
    AND (SELECT count(*)=3 FROM pg_policies p WHERE p.schemaname='iam'
      AND p.tablename IN ('access_analyzer_observations','access_analyzer_receipts','access_finding_receipts') AND p.policyname='tenant_isolation'
      AND p.qual='(tenant_id = iam.current_tenant_id())' AND p.with_check='(tenant_id = iam.current_tenant_id())')
    AND EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname='iam' AND p.tablename='access_analyzers'
      AND p.policyname='tenant_isolation'
      AND p.qual='((tenant_id = iam.current_tenant_id()) OR (current_setting(''matrix.iam_access_analysis''::text, true) = ''trusted''::text))'
      AND p.with_check='((tenant_id = iam.current_tenant_id()) OR (current_setting(''matrix.iam_access_analysis''::text, true) = ''trusted''::text))')
    AND (SELECT count(*)=9 FROM pg_proc f WHERE f.oid IN (
      to_regprocedure('iam.create_access_analyzer(text,text,text,text,text,text,jsonb,jsonb)'),
      to_regprocedure('iam.list_access_analyzers(text,text,text,text,text)'),
      to_regprocedure('iam.read_access_analyzer(text,text,text,text,text)'),
      to_regprocedure('iam.update_access_analyzer(text,text,text,text,text,text,text,text,integer,bigint,jsonb)'),
      to_regprocedure('iam.set_access_disposition(text,text,text,text,text,text,text,text,integer,bigint,jsonb)'),
      to_regprocedure('iam.read_access_finding_directory_revision(text,text,text,text,text)'),
      to_regprocedure('iam.list_access_findings(text,text,text,text,text,text,text)'),
      to_regprocedure('iam.read_access_finding(text,text,text,text,text,text)'),
      to_regprocedure('iam.set_access_finding_archived(text,text,text,text,text,text,text,text,bigint,boolean,jsonb)'))
      AND f.proowner='matrix_iam_owner'::regrole AND f.prosecdef AND f.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
      AND has_function_privilege('matrix_iam_api',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_worker',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_access_analysis_worker',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_credential_recovery',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_backup_custody',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_notification_worker',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_authentication_recovery',f.oid,'EXECUTE'))
    AND (SELECT count(*)=3 FROM pg_trigger t WHERE t.tgrelid='iam.access_analyzer_receipts'::regclass AND NOT t.tgisinternal
      AND t.tgname IN ('cannot_update','cannot_delete','cannot_truncate') AND t.tgenabled='A'
      AND t.tgfoid=to_regprocedure('iam.reject_policy_history_change()'))
    AND EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid='iam.access_analyzer_receipts'::regclass AND NOT t.tgisinternal
      AND t.tgname='access_analyzer_receipt_complete' AND t.tgenabled='A' AND t.tgfoid=to_regprocedure('iam.assert_access_analyzer_receipt()'))
    AND (SELECT count(*)=3 FROM pg_trigger t WHERE t.tgrelid='iam.access_finding_receipts'::regclass AND NOT t.tgisinternal
      AND t.tgname IN ('cannot_update','cannot_delete','cannot_truncate') AND t.tgenabled='A'
      AND t.tgfoid=to_regprocedure('iam.reject_policy_history_change()'))
    AND EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid='iam.access_finding_receipts'::regclass AND NOT t.tgisinternal
      AND t.tgname='access_finding_receipt_complete' AND t.tgenabled='A' AND t.tgfoid=to_regprocedure('iam.assert_access_finding_receipt()'))
$function$;

CREATE OR REPLACE FUNCTION iam.access_disposition_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
  SELECT (SELECT count(*)=3 FROM pg_catalog.pg_attribute a WHERE a.attrelid='iam.access_analyzers'::regclass
      AND a.attname IN ('disposition_mode','disposition_delay_days','resource_version') AND NOT a.attisdropped AND a.attnotnull)
    AND EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid='iam.access_findings'::regclass
      AND a.attname='resolution_reason' AND NOT a.attisdropped AND NOT a.attnotnull)
    AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid='iam.access_analyzers'::regclass
      AND c.conname='access_analyzers_shape' AND c.contype='c' AND c.convalidated)
    AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid='iam.access_findings'::regclass
      AND c.conname='access_findings_shape' AND c.contype='c' AND c.convalidated)
    AND EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid='iam.access_findings'::regclass
      AND t.tgname='access_finding_resolution_reason' AND NOT t.tgisinternal AND t.tgenabled='A'
      AND t.tgfoid=to_regprocedure('iam.assign_access_finding_resolution_reason()'))
    AND (SELECT count(*)=2 FROM pg_class relation WHERE relation.oid IN (
      to_regclass('iam.access_disposition_state'),to_regclass('iam.access_disposition_attempts'))
      AND relation.relowner='matrix_iam_owner'::regrole AND relation.relrowsecurity AND relation.relforcerowsecurity
      AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) privilege
        WHERE privilege.grantee<>relation.relowner))
    AND (SELECT count(*)=2 FROM pg_policies p WHERE p.schemaname='iam'
      AND p.tablename IN ('access_disposition_state','access_disposition_attempts') AND p.policyname='tenant_isolation'
      AND p.qual='((tenant_id = iam.current_tenant_id()) OR (current_setting(''matrix.iam_access_analysis''::text, true) = ''trusted''::text))'
      AND p.with_check='((tenant_id = iam.current_tenant_id()) OR (current_setting(''matrix.iam_access_analysis''::text, true) = ''trusted''::text))')
    AND (SELECT count(*)=2 FROM pg_proc p WHERE p.oid IN (
      to_regprocedure('iam.claim_access_disposition(text,text)'),
      to_regprocedure('iam.complete_access_disposition(text,text,bigint,text,jsonb)'))
      AND p.proowner='matrix_iam_owner'::regrole AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
      AND has_function_privilege('matrix_iam_access_analysis_worker',p.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_api',p.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_worker',p.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_notification_worker',p.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_authentication_recovery',p.oid,'EXECUTE'))
    AND iam.access_analyzer_contract_ready() AND iam.access_analysis_contract_ready()
$function$;

CREATE OR REPLACE FUNCTION iam.access_analysis_worker_ready()
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM iam.assert_access_analysis_worker();
    RETURN iam.access_analysis_contract_ready() AND iam.access_disposition_contract_ready();
END $function$;

REVOKE ALL ON TABLE iam.access_disposition_state,iam.access_disposition_attempts
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
REVOKE ALL ON FUNCTION iam.valid_access_analyzer(jsonb,text,text),iam.access_analyzer_document(text,text),
  iam.assert_access_analyzer_actor(text,text,text,text,text,text),iam.assert_access_analyzer_receipt(),
  iam.valid_access_finding(jsonb,text,text,text),iam.access_finding_document(text,text),
  iam.assign_access_finding_resolution_reason(),iam.access_disposition_snapshot(text,text,timestamptz),
  iam.access_disposition_event_digest(text,text,text,text),iam.access_disposition_contract_ready()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
REVOKE ALL ON FUNCTION iam.set_access_disposition(text,text,text,text,text,text,text,text,integer,bigint,jsonb)
  FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
GRANT EXECUTE ON FUNCTION iam.set_access_disposition(text,text,text,text,text,text,text,text,integer,bigint,jsonb)
  TO matrix_iam_api;
REVOKE ALL ON FUNCTION iam.claim_access_disposition(text,text),iam.complete_access_disposition(text,text,bigint,text,jsonb)
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
GRANT EXECUTE ON FUNCTION iam.claim_access_disposition(text,text),iam.complete_access_disposition(text,text,bigint,text,jsonb)
  TO matrix_iam_access_analysis_worker;

DO $access_disposition_readiness_cutover$
BEGIN
    IF to_regprocedure('iam.readiness_v63()') IS NOT NULL THEN DROP FUNCTION iam.readiness_v63(); END IF;
    ALTER FUNCTION iam.readiness() RENAME TO readiness_v63;
END $access_disposition_readiness_cutover$;
REVOKE ALL ON FUNCTION iam.readiness_v63() FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,
  matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
CREATE FUNCTION iam.readiness()
RETURNS TABLE(ready boolean,schema_version bigint,checked_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE predecessor record;
BEGIN
    SELECT * INTO predecessor FROM iam.readiness_v63();
    RETURN QUERY SELECT predecessor.ready AND iam.access_disposition_contract_ready(),64::bigint,predecessor.checked_at;
END $function$;
REVOKE ALL ON FUNCTION iam.readiness() FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,
  matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
GRANT EXECUTE ON FUNCTION iam.readiness() TO matrix_iam_api;
