SET LOCAL ROLE matrix_iam_owner;

ALTER TABLE iam.access_analyzer_observations ADD COLUMN IF NOT EXISTS recovery_epoch bigint NOT NULL DEFAULT 0;
ALTER TABLE iam.access_analyzer_observations ADD COLUMN IF NOT EXISTS recovery_command_id text COLLATE "C";
ALTER TABLE iam.access_analyzer_observations ADD COLUMN IF NOT EXISTS recovery_completed_at timestamptz(6);
ALTER TABLE iam.access_analyzer_observations DROP CONSTRAINT IF EXISTS access_analyzer_observations_check;
ALTER TABLE iam.access_analyzer_observations DROP CONSTRAINT IF EXISTS access_analyzer_observation_shape;
ALTER TABLE iam.access_analyzer_observations ADD CONSTRAINT access_analyzer_observation_shape CHECK(
  recovery_epoch BETWEEN 0 AND 9223372036854775807
  AND ((recovery_epoch=0 AND recovery_command_id IS NULL AND recovery_completed_at IS NULL)
    OR (recovery_epoch>0 AND recovery_command_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND recovery_completed_at IS NOT NULL AND isfinite(recovery_completed_at)))
  AND ((source IN ('IAM_PASSWORD_SESSIONS','IAM_ACCESS_KEY_AUTHORIZATIONS','IAM_ROLE_SESSIONS','IAM_ROLE_AUTHORIZATIONS')
      AND state IN ('COMPLETE','INSUFFICIENT_COVERAGE')
      AND ((state='COMPLETE' AND reason='') OR (state='INSUFFICIENT_COVERAGE'
        AND reason IN ('SOURCE_NOT_READY','OBSERVATION_WINDOW_INCOMPLETE','RESTORE_GAP')))
      AND observed_from IS NOT NULL AND observed_through IS NOT NULL
      AND isfinite(observed_from) AND isfinite(observed_through) AND observed_through>=observed_from)
    OR (source IN ('PAAS_RESULTS','EXTERNAL_FEDERATION') AND state='NOT_INCLUDED'
      AND reason='SOURCE_NOT_IMPLEMENTED' AND observed_from IS NULL AND observed_through IS NULL
      AND recovery_epoch=0 AND recovery_command_id IS NULL AND recovery_completed_at IS NULL))
);

CREATE TABLE IF NOT EXISTS iam.access_findings (
    tenant_id text COLLATE "C" NOT NULL,
    analyzer_id text COLLATE "C" NOT NULL,
    finding_id text COLLATE "C" NOT NULL,
    analyzer_revision bigint NOT NULL,
    finding_type text NOT NULL,
    status text NOT NULL,
    target_kind text NOT NULL,
    target_id text COLLATE "C" NOT NULL,
    target_resource_version bigint NOT NULL,
    condition_generation bigint NOT NULL,
    activity_revision bigint NOT NULL,
    recovery_epoch bigint NOT NULL,
    recovery_command_id text COLLATE "C",
    recovery_completed_at timestamptz(6),
    window_started_at timestamptz(6) NOT NULL,
    observed_at timestamptz(6) NOT NULL,
    last_activity_at timestamptz(6),
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    resolved_at timestamptz(6),
    PRIMARY KEY(tenant_id,finding_id),
    UNIQUE(tenant_id,analyzer_id,finding_type,target_kind,target_id,condition_generation),
    FOREIGN KEY(tenant_id,analyzer_id) REFERENCES iam.access_analyzers(tenant_id,analyzer_id),
    CHECK(finding_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
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
      AND ((status IN ('ACTIVE','ARCHIVED') AND resolved_at IS NULL)
        OR (status='RESOLVED' AND resolved_at IS NOT NULL AND isfinite(resolved_at)
          AND resolved_at=updated_at AND observed_at=updated_at)))
);
CREATE UNIQUE INDEX IF NOT EXISTS access_findings_unresolved_target_uq
  ON iam.access_findings(tenant_id,analyzer_id,finding_type,target_kind,target_id) WHERE status<>'RESOLVED';
CREATE INDEX IF NOT EXISTS access_findings_directory_idx
  ON iam.access_findings(tenant_id,analyzer_id,recovery_epoch,finding_id);
CREATE INDEX IF NOT EXISTS access_findings_status_directory_idx
  ON iam.access_findings(tenant_id,analyzer_id,recovery_epoch,status,finding_id);

CREATE TABLE IF NOT EXISTS iam.access_finding_receipts (
    tenant_id text COLLATE "C" NOT NULL,
    actor_id text COLLATE "C" NOT NULL,
    action_name text NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    request_digest text NOT NULL,
    analyzer_id text COLLATE "C" NOT NULL,
    finding_id text COLLATE "C" NOT NULL,
    result_document jsonb NOT NULL,
    decision_id text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    completed_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,actor_id,action_name,request_id),
    FOREIGN KEY(tenant_id,actor_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(tenant_id,finding_id) REFERENCES iam.access_findings(tenant_id,finding_id),
    FOREIGN KEY(tenant_id,decision_id) REFERENCES iam.authorization_decisions(tenant_id,id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,event_id) REFERENCES iam.audit_outbox(tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED,
    CHECK(action_name IN ('iam.access-finding.archive','iam.access-finding.unarchive')
      AND request_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND request_digest ~ '^sha256:[0-9a-f]{64}$' AND isfinite(completed_at))
);

CREATE TABLE IF NOT EXISTS iam.access_analysis_scan_state (
    tenant_id text COLLATE "C" NOT NULL,
    analyzer_id text COLLATE "C" NOT NULL,
    analyzer_revision bigint NOT NULL,
    recovery_epoch bigint NOT NULL,
    fence bigint NOT NULL DEFAULT 0,
    after_type text NOT NULL DEFAULT '',
    after_target_id text COLLATE "C" NOT NULL DEFAULT '',
    cycle_observed_at timestamptz(6) NOT NULL,
    next_scan_at timestamptz(6) NOT NULL,
    worker_id text COLLATE "C",
    lease_expires_at timestamptz(6),
    updated_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,analyzer_id),
    FOREIGN KEY(tenant_id,analyzer_id) REFERENCES iam.access_analyzers(tenant_id,analyzer_id),
    CHECK(analyzer_revision BETWEEN 1 AND 9007199254740991 AND recovery_epoch BETWEEN 0 AND 9223372036854775807
      AND fence BETWEEN 0 AND 9007199254740991
      AND ((after_type='' AND after_target_id='')
        OR (after_type IN ('UNUSED_PASSWORD','UNUSED_ACCESS_KEY','UNUSED_ROLE')
          AND after_target_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'))
      AND isfinite(cycle_observed_at) AND isfinite(next_scan_at) AND isfinite(updated_at)
      AND ((worker_id IS NULL AND lease_expires_at IS NULL)
        OR (worker_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
          AND lease_expires_at IS NOT NULL AND isfinite(lease_expires_at))))
);

CREATE TABLE IF NOT EXISTS iam.access_analysis_attempts (
    attempt_id text COLLATE "C" PRIMARY KEY,
    tenant_id text COLLATE "C" NOT NULL,
    analyzer_id text COLLATE "C" NOT NULL,
    worker_id text COLLATE "C" NOT NULL,
    fence bigint NOT NULL,
    snapshot_document jsonb NOT NULL,
    snapshot_digest text NOT NULL,
    after_type text NOT NULL,
    after_target_id text COLLATE "C" NOT NULL,
    last_type text NOT NULL,
    last_target_id text COLLATE "C" NOT NULL,
    cycle_complete boolean NOT NULL,
    claimed_at timestamptz(6) NOT NULL,
    lease_expires_at timestamptz(6) NOT NULL,
    completed_at timestamptz(6),
    completion_document jsonb,
    FOREIGN KEY(tenant_id,analyzer_id) REFERENCES iam.access_analyzers(tenant_id,analyzer_id),
    CHECK(attempt_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND worker_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND fence BETWEEN 1 AND 9007199254740991 AND jsonb_typeof(snapshot_document)='object'
      AND snapshot_digest ~ '^sha256:[0-9a-f]{64}$'
      AND isfinite(claimed_at) AND isfinite(lease_expires_at) AND lease_expires_at>claimed_at
      AND ((completed_at IS NULL AND completion_document IS NULL)
        OR (completed_at IS NOT NULL AND isfinite(completed_at) AND jsonb_typeof(completion_document)='object')))
);

DO $access_analysis_isolation$
DECLARE relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['access_findings','access_analysis_scan_state','access_analysis_attempts'] LOOP
        EXECUTE format('ALTER TABLE iam.%I ENABLE ROW LEVEL SECURITY',relation_name);
        EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',relation_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON iam.%I',relation_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON iam.%I USING (tenant_id=iam.current_tenant_id() OR current_setting(''matrix.iam_access_analysis'',true)=''trusted'') WITH CHECK (tenant_id=iam.current_tenant_id() OR current_setting(''matrix.iam_access_analysis'',true)=''trusted'')',relation_name);
    END LOOP;
    DROP POLICY IF EXISTS tenant_isolation ON iam.access_analyzers;
    CREATE POLICY tenant_isolation ON iam.access_analyzers
      USING(tenant_id=iam.current_tenant_id() OR current_setting('matrix.iam_access_analysis',true)='trusted')
      WITH CHECK(tenant_id=iam.current_tenant_id() OR current_setting('matrix.iam_access_analysis',true)='trusted');
    ALTER TABLE iam.access_finding_receipts ENABLE ROW LEVEL SECURITY;
    ALTER TABLE iam.access_finding_receipts FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tenant_isolation ON iam.access_finding_receipts;
    CREATE POLICY tenant_isolation ON iam.access_finding_receipts
      USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id());
END $access_analysis_isolation$;

DO $access_finding_receipt_immutability$
DECLARE operation_name text;
BEGIN
    FOREACH operation_name IN ARRAY ARRAY['update','delete','truncate'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS cannot_%s ON iam.access_finding_receipts',operation_name);
        EXECUTE format('CREATE TRIGGER cannot_%s BEFORE %s ON iam.access_finding_receipts FOR EACH %s EXECUTE FUNCTION iam.reject_policy_history_change()',
          operation_name,operation_name,CASE WHEN operation_name='truncate' THEN 'STATEMENT' ELSE 'ROW' END);
        EXECUTE format('ALTER TABLE iam.access_finding_receipts ENABLE ALWAYS TRIGGER cannot_%s',operation_name);
    END LOOP;
END $access_finding_receipt_immutability$;

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
    AND (SELECT count(*)=8 FROM pg_proc f WHERE f.oid IN (
      to_regprocedure('iam.create_access_analyzer(text,text,text,text,text,text,jsonb,jsonb)'),
      to_regprocedure('iam.list_access_analyzers(text,text,text,text,text)'),
      to_regprocedure('iam.read_access_analyzer(text,text,text,text,text)'),
      to_regprocedure('iam.update_access_analyzer(text,text,text,text,text,text,text,text,integer,bigint,jsonb)'),
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
REVOKE ALL ON FUNCTION iam.access_analyzer_contract_ready()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_access_analysis_worker,matrix_iam_credential_recovery,
    matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery;

CREATE OR REPLACE FUNCTION iam.access_finding_document(tenant text,finding text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
  SELECT jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AccessFinding','id',f.finding_id,
    'accountId',f.tenant_id,'analyzerId',f.analyzer_id,'analyzerRevision',f.analyzer_revision,'type',f.finding_type,
    'status',f.status,'target',jsonb_build_object('kind',f.target_kind,'id',f.target_id),
    'targetResourceVersion',f.target_resource_version,'conditionGeneration',f.condition_generation,
    'activityRevision',f.activity_revision,'recoveryEpoch',f.recovery_epoch,'recoveryCommandId',f.recovery_command_id,
    'recoveryCompletedAt',f.recovery_completed_at,'windowStartedAt',f.window_started_at,'observedAt',f.observed_at,
    'lastActivityAt',f.last_activity_at,'resourceVersion',f.resource_version,'createdAt',f.created_at,
    'updatedAt',f.updated_at,'resolvedAt',f.resolved_at))
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
        'windowStartedAt','observedAt','lastActivityAt','resourceVersion','createdAt','updatedAt','resolvedAt']<>'{}'::jsonb
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
      IF NOT pg_input_is_valid(value->>'resolvedAt','timestamptz') THEN RETURN false; END IF;
      resolved:=(value->>'resolvedAt')::timestamptz;
      RETURN isfinite(resolved) AND resolved=updated AND observed=updated;
    END IF;
    RETURN NOT value ? 'resolvedAt';
EXCEPTION WHEN others THEN RETURN false;
END $function$;

CREATE OR REPLACE FUNCTION iam.complete_access_analysis(attempt text,worker text,lease_fence bigint,tenant text,result jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE original iam.access_analysis_attempts%ROWTYPE; scan iam.access_analysis_scan_state%ROWTYPE;
    current_snapshot jsonb; expected jsonb; detection jsonb; resolution jsonb; finding jsonb; event jsonb;
    expected_detection jsonb; expected_event_digest text; effective_now timestamptz(6):=clock_timestamp();
    actual_count integer; expected_count integer;
BEGIN
    PERFORM iam.assert_access_analysis_worker();
    IF COALESCE(attempt,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(worker,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(tenant,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR lease_fence NOT BETWEEN 1 AND 9007199254740991 OR jsonb_typeof(result)<>'object'
      OR NOT result ?& ARRAY['detections','resolutions'] OR result-ARRAY['detections','resolutions']<>'{}'::jsonb
      OR jsonb_typeof(result->'detections')<>'array' OR jsonb_typeof(result->'resolutions')<>'array'
      OR jsonb_array_length(result->'detections')>100 OR jsonb_array_length(result->'resolutions')>100 THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analysis completion is invalid'; END IF;
    PERFORM set_config('matrix.iam_access_analysis','trusted',true);
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    SELECT * INTO original FROM iam.access_analysis_attempts a WHERE a.attempt_id=attempt FOR UPDATE;
    IF NOT FOUND OR original.tenant_id IS DISTINCT FROM tenant OR original.worker_id IS DISTINCT FROM worker
      OR original.fence IS DISTINCT FROM lease_fence OR original.completed_at IS NOT NULL THEN
      RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='access analysis attempt is stale'; END IF;
    SELECT * INTO scan FROM iam.access_analysis_scan_state s
      WHERE (s.tenant_id,s.analyzer_id)=(original.tenant_id,original.analyzer_id) FOR UPDATE;
    IF NOT FOUND OR scan.worker_id IS DISTINCT FROM worker OR scan.fence IS DISTINCT FROM lease_fence
      OR scan.lease_expires_at IS DISTINCT FROM original.lease_expires_at OR scan.lease_expires_at<=effective_now THEN
      RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='access analysis lease is stale'; END IF;
    PERFORM 1 FROM iam.authentication_recovery_state s WHERE s.singleton FOR SHARE;
    current_snapshot:=iam.access_analysis_snapshot(tenant,original.analyzer_id,
      (original.snapshot_document->>'observedAt')::timestamptz,original.after_type,original.after_target_id);
    IF current_snapshot IS DISTINCT FROM original.snapshot_document
      OR original.snapshot_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(current_snapshot::text,'UTF8')),'hex') THEN
      RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='access analysis snapshot changed'; END IF;
    expected:=iam.access_analysis_expected(current_snapshot);
    actual_count:=jsonb_array_length(result->'detections'); expected_count:=jsonb_array_length(expected->'detections');
    IF actual_count<>expected_count OR actual_count<>(SELECT count(DISTINCT item#>>'{finding,id}') FROM jsonb_array_elements(result->'detections') item) THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='access analysis detections differ'; END IF;
    actual_count:=jsonb_array_length(result->'resolutions'); expected_count:=jsonb_array_length(expected->'resolutions');
    IF actual_count<>expected_count OR actual_count<>(SELECT count(DISTINCT item->>'findingId') FROM jsonb_array_elements(result->'resolutions') item) THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='access analysis resolutions differ'; END IF;

    FOR detection IN SELECT value FROM jsonb_array_elements(result->'detections') LOOP
      IF jsonb_typeof(detection)<>'object' OR NOT detection ?& ARRAY['finding','event'] OR detection-ARRAY['finding','event']<>'{}'::jsonb THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='access analysis detection shape differs'; END IF;
      finding:=detection->'finding'; event:=detection->'event'; expected_detection:=NULL;
      SELECT item INTO expected_detection FROM jsonb_array_elements(expected->'detections') item
        WHERE item->>'type'=finding->>'type' AND item->'target'=finding->'target';
      IF expected_detection IS NULL OR NOT iam.valid_access_finding(finding,tenant,original.analyzer_id,finding->>'id')
        OR finding->>'status'<>'ACTIVE' OR (finding->>'resourceVersion')::bigint<>1
        OR (finding->>'analyzerRevision')::bigint<>(current_snapshot#>>'{analyzer,resourceVersion}')::bigint
        OR (finding->>'targetResourceVersion')::bigint<>(expected_detection->>'targetResourceVersion')::bigint
        OR (finding->>'conditionGeneration')::bigint<>(expected_detection->>'conditionGeneration')::bigint
        OR (finding->>'activityRevision')::bigint<>(expected_detection->>'activityRevision')::bigint
        OR (finding->>'recoveryEpoch')::bigint<>(current_snapshot->>'recoveryEpoch')::bigint
        OR COALESCE(finding->>'recoveryCommandId','')<>COALESCE(current_snapshot->>'recoveryCommandId','')
        OR COALESCE(finding->>'recoveryCompletedAt','')<>COALESCE(current_snapshot->>'recoveryCompletedAt','')
        OR (finding->>'windowStartedAt')::timestamptz<>(current_snapshot->>'observedAt')::timestamptz
          -make_interval(days=>(current_snapshot#>>'{analyzer,unusedAccessAgeDays}')::integer)
        OR (finding->>'observedAt')::timestamptz<>(current_snapshot->>'observedAt')::timestamptz
        OR (finding->>'createdAt')::timestamptz<>(current_snapshot->>'observedAt')::timestamptz
        OR (finding->>'updatedAt')::timestamptz<>(current_snapshot->>'observedAt')::timestamptz
        OR COALESCE(finding->>'lastActivityAt','')<>COALESCE(expected_detection->>'lastActivityAt','') THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='access analysis detection evidence differs'; END IF;
      PERFORM iam.assert_audit_event(event,tenant,'iam.access-finding.detected','ACCESS_FINDING',finding->>'id','SUCCEEDED');
      expected_event_digest:='sha256:'||encode(sha256(convert_to('matrix.iam.access-analysis-event.v1|'
        ||octet_length(event->>'action')||':'||(event->>'action')||'|'
        ||octet_length(attempt)||':'||attempt||'|'
        ||octet_length(finding->>'id')||':'||(finding->>'id')||'|'
        ||octet_length(original.snapshot_digest)||':'||original.snapshot_digest||'|','UTF8')),'hex');
      IF event->'actor' IS DISTINCT FROM jsonb_build_object('type','SYSTEM','id','iam.access-analyzer')
        OR event ?| ARRAY['iamDecisionId','installationId','operationId'] OR event->>'correlationId' IS DISTINCT FROM attempt
        OR (event->>'occurredAt')::timestamptz IS DISTINCT FROM (current_snapshot->>'observedAt')::timestamptz
        OR event->>'requestDigest' IS DISTINCT FROM expected_event_digest THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='access analysis detection fact differs'; END IF;
      INSERT INTO iam.access_findings(tenant_id,analyzer_id,finding_id,analyzer_revision,finding_type,status,target_kind,target_id,
        target_resource_version,condition_generation,activity_revision,recovery_epoch,recovery_command_id,recovery_completed_at,
        window_started_at,observed_at,last_activity_at,resource_version,created_at,updated_at)
        VALUES(tenant,original.analyzer_id,finding->>'id',(finding->>'analyzerRevision')::bigint,finding->>'type',finding->>'status',
          finding#>>'{target,kind}',finding#>>'{target,id}',(finding->>'targetResourceVersion')::bigint,
          (finding->>'conditionGeneration')::bigint,(finding->>'activityRevision')::bigint,(finding->>'recoveryEpoch')::bigint,
          finding->>'recoveryCommandId',(finding->>'recoveryCompletedAt')::timestamptz,(finding->>'windowStartedAt')::timestamptz,
          (finding->>'observedAt')::timestamptz,(finding->>'lastActivityAt')::timestamptz,1,
          (finding->>'createdAt')::timestamptz,(finding->>'updatedAt')::timestamptz);
      INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
        VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    END LOOP;

    FOR resolution IN SELECT value FROM jsonb_array_elements(result->'resolutions') LOOP
      IF jsonb_typeof(resolution)<>'object' OR NOT resolution ?& ARRAY['findingId','expectedResourceVersion','event']
        OR resolution-ARRAY['findingId','expectedResourceVersion','event']<>'{}'::jsonb
        OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(expected->'resolutions') item
          WHERE item->>'findingId'=resolution->>'findingId'
            AND (item->>'resourceVersion')::bigint=(resolution->>'expectedResourceVersion')::bigint) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='access analysis resolution evidence differs'; END IF;
      event:=resolution->'event';
      PERFORM iam.assert_audit_event(event,tenant,'iam.access-finding.resolved','ACCESS_FINDING',resolution->>'findingId','SUCCEEDED');
      expected_event_digest:='sha256:'||encode(sha256(convert_to('matrix.iam.access-analysis-event.v1|'
        ||octet_length(event->>'action')||':'||(event->>'action')||'|'
        ||octet_length(attempt)||':'||attempt||'|'
        ||octet_length(resolution->>'findingId')||':'||(resolution->>'findingId')||'|'
        ||octet_length(original.snapshot_digest)||':'||original.snapshot_digest||'|','UTF8')),'hex');
      IF event->'actor' IS DISTINCT FROM jsonb_build_object('type','SYSTEM','id','iam.access-analyzer')
        OR event ?| ARRAY['iamDecisionId','installationId','operationId'] OR event->>'correlationId' IS DISTINCT FROM attempt
        OR (event->>'occurredAt')::timestamptz IS DISTINCT FROM (current_snapshot->>'observedAt')::timestamptz
        OR event->>'requestDigest' IS DISTINCT FROM expected_event_digest THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='access analysis resolution fact differs'; END IF;
      UPDATE iam.access_findings f SET status='RESOLVED',resource_version=f.resource_version+1,
        observed_at=(current_snapshot->>'observedAt')::timestamptz,updated_at=(current_snapshot->>'observedAt')::timestamptz,
        resolved_at=(current_snapshot->>'observedAt')::timestamptz
        WHERE f.tenant_id=tenant AND f.analyzer_id=original.analyzer_id AND f.finding_id=resolution->>'findingId'
          AND f.status<>'RESOLVED' AND f.resource_version=(resolution->>'expectedResourceVersion')::bigint;
      IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='access finding changed'; END IF;
      INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
        VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    END LOOP;

    IF original.cycle_complete THEN
      UPDATE iam.access_analyzer_observations o SET
        state=entry.state,observed_from=entry."observedFrom",observed_through=entry."observedThrough",reason=entry.reason,
        recovery_epoch=(current_snapshot->>'recoveryEpoch')::bigint,
        recovery_command_id=current_snapshot->>'recoveryCommandId',
        recovery_completed_at=(current_snapshot->>'recoveryCompletedAt')::timestamptz
        FROM jsonb_to_recordset(current_snapshot->'coverage') AS entry(
          source text,state text,"observedFrom" timestamptz,"observedThrough" timestamptz,reason text)
        WHERE o.tenant_id=tenant AND o.analyzer_id=original.analyzer_id AND o.source=entry.source
          AND entry.source IN ('IAM_PASSWORD_SESSIONS','IAM_ACCESS_KEY_AUTHORIZATIONS','IAM_ROLE_SESSIONS','IAM_ROLE_AUTHORIZATIONS');
    END IF;
    UPDATE iam.access_analysis_attempts a SET completed_at=effective_now,completion_document=result WHERE a.attempt_id=attempt;
    UPDATE iam.access_analysis_scan_state s SET
      after_type=CASE WHEN original.cycle_complete THEN '' ELSE original.last_type END,
      after_target_id=CASE WHEN original.cycle_complete THEN '' ELSE original.last_target_id END,
      next_scan_at=CASE WHEN original.cycle_complete THEN effective_now+interval '5 minutes' ELSE effective_now END,
      worker_id=NULL,lease_expires_at=NULL,updated_at=effective_now
      WHERE (s.tenant_id,s.analyzer_id)=(tenant,original.analyzer_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.access_analysis_expected(snapshot jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
WITH coverage_contract AS (
  SELECT count(*)=4 AND count(DISTINCT coverage.source)=4 AS complete
    FROM jsonb_to_recordset(COALESCE(snapshot->'coverage','[]'::jsonb)) AS coverage(
      source text,state text,"observedFrom" timestamptz,"observedThrough" timestamptz,reason text)
    WHERE coverage.source IN ('IAM_PASSWORD_SESSIONS','IAM_ACCESS_KEY_AUTHORIZATIONS','IAM_ROLE_SESSIONS','IAM_ROLE_AUTHORIZATIONS')
      AND coverage.state='COMPLETE' AND coverage."observedFrom"<=(snapshot->>'observedAt')::timestamptz
        -make_interval(days=>(snapshot#>>'{analyzer,unusedAccessAgeDays}')::integer)
      AND coverage."observedThrough">=(snapshot->>'observedAt')::timestamptz
), candidates AS (
  SELECT c.type,c.target,c."targetResourceVersion" AS target_resource_version,c."createdAt" AS created_at,
      c."activityRevision" AS activity_revision,c."lastActivityAt" AS last_activity_at
    FROM jsonb_to_recordset(COALESCE(snapshot->'candidates','[]'::jsonb)) AS c(
      type text,target jsonb,"targetResourceVersion" bigint,"createdAt" timestamptz,
      "activityRevision" bigint,"lastActivityAt" timestamptz)
    WHERE (SELECT complete FROM coverage_contract)
      AND c."createdAt"<=(snapshot->>'observedAt')::timestamptz
      -make_interval(days=>(snapshot#>>'{analyzer,unusedAccessAgeDays}')::integer)
      AND (c."lastActivityAt" IS NULL OR c."lastActivityAt"<(snapshot->>'observedAt')::timestamptz
        -make_interval(days=>(snapshot#>>'{analyzer,unusedAccessAgeDays}')::integer))
), findings AS (
  SELECT value AS finding FROM jsonb_array_elements(COALESCE(snapshot->'findings','[]'::jsonb))
), detections AS (
  SELECT c.type,c.target,c.target_resource_version,c.activity_revision,c.last_activity_at,
    COALESCE((SELECT MAX((f.finding->>'conditionGeneration')::bigint) FROM findings f
      WHERE f.finding->>'type'=c.type AND f.finding->'target'=c.target),0)+1 AS condition_generation
    FROM candidates c WHERE NOT EXISTS(SELECT 1 FROM findings f
      WHERE f.finding->>'type'=c.type AND f.finding->'target'=c.target AND f.finding->>'status'<>'RESOLVED'
        AND (f.finding->>'analyzerRevision')::bigint=(snapshot#>>'{analyzer,resourceVersion}')::bigint
        AND (f.finding->>'targetResourceVersion')::bigint=c.target_resource_version
        AND (f.finding->>'activityRevision')::bigint=c.activity_revision
        AND (f.finding->>'recoveryEpoch')::bigint=(snapshot->>'recoveryEpoch')::bigint
        AND COALESCE(f.finding->>'recoveryCommandId','')=COALESCE(snapshot->>'recoveryCommandId','')
        AND COALESCE(f.finding->>'recoveryCompletedAt','')=COALESCE(snapshot->>'recoveryCompletedAt','')
        AND (f.finding->>'windowStartedAt')::timestamptz=(snapshot->>'observedAt')::timestamptz
          -make_interval(days=>(snapshot#>>'{analyzer,unusedAccessAgeDays}')::integer)
        AND COALESCE(f.finding->>'lastActivityAt','')=COALESCE(to_jsonb(c.last_activity_at)#>>'{}',''))
), resolutions AS (
  SELECT f.finding->>'id' AS finding_id,(f.finding->>'resourceVersion')::bigint AS resource_version
    FROM findings f WHERE (SELECT complete FROM coverage_contract)
      AND f.finding->>'status'<>'RESOLVED' AND NOT EXISTS(SELECT 1 FROM candidates c
      WHERE f.finding->>'type'=c.type AND f.finding->'target'=c.target
        AND (f.finding->>'analyzerRevision')::bigint=(snapshot#>>'{analyzer,resourceVersion}')::bigint
        AND (f.finding->>'targetResourceVersion')::bigint=c.target_resource_version
        AND (f.finding->>'activityRevision')::bigint=c.activity_revision
        AND (f.finding->>'recoveryEpoch')::bigint=(snapshot->>'recoveryEpoch')::bigint
        AND COALESCE(f.finding->>'recoveryCommandId','')=COALESCE(snapshot->>'recoveryCommandId','')
        AND COALESCE(f.finding->>'recoveryCompletedAt','')=COALESCE(snapshot->>'recoveryCompletedAt','')
        AND (f.finding->>'windowStartedAt')::timestamptz=(snapshot->>'observedAt')::timestamptz
          -make_interval(days=>(snapshot#>>'{analyzer,unusedAccessAgeDays}')::integer)
        AND COALESCE(f.finding->>'lastActivityAt','')=COALESCE(to_jsonb(c.last_activity_at)#>>'{}',''))
)
SELECT jsonb_build_object('detections',COALESCE((SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
    'type',d.type,'target',d.target,'targetResourceVersion',d.target_resource_version,
    'activityRevision',d.activity_revision,'lastActivityAt',d.last_activity_at,
    'conditionGeneration',d.condition_generation)) ORDER BY d.type COLLATE "C",d.target->>'id' COLLATE "C") FROM detections d),'[]'::jsonb),
  'resolutions',COALESCE((SELECT jsonb_agg(jsonb_build_object('findingId',r.finding_id,'resourceVersion',r.resource_version)
    ORDER BY r.finding_id COLLATE "C") FROM resolutions r),'[]'::jsonb))
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
          to_regprocedure('iam.complete_access_analysis(text,text,bigint,text,jsonb)'))
        AND has_function_privilege(session_user,p.oid,'EXECUTE')) THEN
      RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='access analysis worker context is forbidden';
    END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.claim_access_analysis(worker text,attempt text)
RETURNS TABLE(attempt_id text,worker_id text,fence bigint,lease_expires_at timestamptz,snapshot_digest text,snapshot_document jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE candidate record; scan iam.access_analysis_scan_state%ROWTYPE; effective_now timestamptz(6):=clock_timestamp();
    current_epoch bigint; snapshot jsonb; snapshot_hash text; prior_scope text; prior_tenant text;
BEGIN
    PERFORM iam.assert_access_analysis_worker();
    IF COALESCE(worker,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(attempt,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analysis claim is invalid'; END IF;
    prior_scope:=current_setting('matrix.iam_access_analysis',true);
    prior_tenant:=current_setting('matrix.iam_tenant_id',true);
    PERFORM set_config('matrix.iam_access_analysis','trusted',true);
    FOR candidate IN
      SELECT a.tenant_id,a.analyzer_id,a.resource_version,a.created_at,
        COALESCE(s.next_scan_at,a.created_at) AS eligible_at
        FROM iam.access_analyzers a LEFT JOIN iam.access_analysis_scan_state s
          ON (s.tenant_id,s.analyzer_id)=(a.tenant_id,a.analyzer_id)
        WHERE a.status='ACTIVE' AND COALESCE(s.next_scan_at,a.created_at)<=effective_now
          AND (s.worker_id IS NULL OR s.lease_expires_at<=effective_now)
        ORDER BY eligible_at,a.tenant_id COLLATE "C",a.analyzer_id COLLATE "C" LIMIT 16
        FOR UPDATE OF a SKIP LOCKED
    LOOP
      PERFORM set_config('matrix.iam_tenant_id',candidate.tenant_id,true);
      SELECT s.epoch INTO current_epoch FROM iam.authentication_recovery_state s WHERE s.singleton FOR SHARE;
      IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication recovery state is unavailable'; END IF;
      SELECT * INTO scan FROM iam.access_analysis_scan_state s
        WHERE (s.tenant_id,s.analyzer_id)=(candidate.tenant_id,candidate.analyzer_id) FOR UPDATE;
      IF NOT FOUND THEN
        INSERT INTO iam.access_analysis_scan_state(tenant_id,analyzer_id,analyzer_revision,recovery_epoch,fence,
          after_type,after_target_id,cycle_observed_at,next_scan_at,worker_id,lease_expires_at,updated_at)
          VALUES(candidate.tenant_id,candidate.analyzer_id,candidate.resource_version,current_epoch,1,'','',effective_now,effective_now,
            worker,effective_now+interval '2 minutes',effective_now) RETURNING * INTO scan;
      ELSE
        IF scan.analyzer_revision IS DISTINCT FROM candidate.resource_version OR scan.recovery_epoch IS DISTINCT FROM current_epoch THEN
          scan.after_type:=''; scan.after_target_id:=''; scan.cycle_observed_at:=effective_now;
        ELSIF scan.after_type='' THEN
          scan.cycle_observed_at:=effective_now;
        END IF;
        IF scan.fence>=9007199254740991 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='access analysis fence exhausted'; END IF;
        UPDATE iam.access_analysis_scan_state s SET analyzer_revision=candidate.resource_version,recovery_epoch=current_epoch,
          fence=s.fence+1,after_type=scan.after_type,after_target_id=scan.after_target_id,worker_id=worker,
          cycle_observed_at=scan.cycle_observed_at,lease_expires_at=effective_now+interval '2 minutes',updated_at=effective_now
          WHERE (s.tenant_id,s.analyzer_id)=(candidate.tenant_id,candidate.analyzer_id) RETURNING * INTO scan;
      END IF;
      snapshot:=iam.access_analysis_snapshot(candidate.tenant_id,candidate.analyzer_id,scan.cycle_observed_at,scan.after_type,scan.after_target_id);
      snapshot_hash:='sha256:'||encode(sha256(convert_to(snapshot::text,'UTF8')),'hex');
      INSERT INTO iam.access_analysis_attempts(attempt_id,tenant_id,analyzer_id,worker_id,fence,snapshot_document,snapshot_digest,
        after_type,after_target_id,last_type,last_target_id,cycle_complete,claimed_at,lease_expires_at)
        VALUES(attempt,candidate.tenant_id,candidate.analyzer_id,worker,scan.fence,snapshot,snapshot_hash,scan.after_type,scan.after_target_id,
          COALESCE(snapshot#>>'{batch,lastType}',''),COALESCE(snapshot#>>'{batch,lastTargetId}',''),
          (snapshot#>>'{batch,cycleComplete}')::boolean,effective_now,scan.lease_expires_at);
      RETURN QUERY SELECT attempt,worker,scan.fence,scan.lease_expires_at,snapshot_hash,snapshot;
      EXIT;
    END LOOP;
    PERFORM set_config('matrix.iam_access_analysis',COALESCE(prior_scope,''),true);
    PERFORM set_config('matrix.iam_tenant_id',COALESCE(prior_tenant,''),true);
END $function$;

CREATE OR REPLACE FUNCTION iam.access_analysis_snapshot(tenant text,analyzer text,observed timestamptz,after_kind text,after_id text)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE analyzer_document jsonb; recovery_state text; current_recovery_epoch bigint; recovery_command text; recovery_completed timestamptz;
    recovery_installation text; window_start timestamptz; coverage jsonb; all_keys jsonb; batch_keys jsonb;
    candidates jsonb; findings jsonb; cycle_complete boolean; last_kind text:=''; last_id text:='';
BEGIN
    IF COALESCE(tenant,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(analyzer,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR observed IS NULL OR NOT isfinite(observed)
      OR NOT ((COALESCE(after_kind,'')='' AND COALESCE(after_id,'')='')
        OR (after_kind IN ('UNUSED_PASSWORD','UNUSED_ACCESS_KEY','UNUSED_ROLE')
          AND after_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')) THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access analysis scope is invalid'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    analyzer_document:=iam.access_analyzer_document(tenant,analyzer);
    IF analyzer_document IS NULL OR analyzer_document->>'status'<>'ACTIVE' THEN
      RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='access analyzer unavailable'; END IF;
    window_start:=observed-make_interval(days=>(analyzer_document->>'unusedAccessAgeDays')::integer);
    SELECT s.state,s.epoch INTO recovery_state,current_recovery_epoch FROM iam.authentication_recovery_state s WHERE s.singleton;
    IF NOT FOUND OR recovery_state<>'OPEN' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication recovery is not open'; END IF;
    IF current_recovery_epoch>0 THEN
      SELECT c.command_id,p.completed_at,p.installation_id INTO recovery_command,recovery_completed,recovery_installation
        FROM iam.authentication_recovery_closures c
        JOIN iam.authentication_recovery_completions p ON p.command_id=c.command_id
          AND p.installation_id=c.installation_id AND p.home_tenant_id=c.home_tenant_id
        WHERE c.epoch=current_recovery_epoch;
      IF NOT FOUND OR recovery_completed IS NULL OR NOT isfinite(recovery_completed)
        OR NOT EXISTS(SELECT 1 FROM iam.bootstrap_receipts b WHERE b.installation_id=recovery_installation) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication recovery completion is unavailable'; END IF;
    END IF;

    SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object('source',o.source,
      'state',CASE WHEN o.source IN ('PAAS_RESULTS','EXTERNAL_FEDERATION') THEN 'NOT_INCLUDED'
        WHEN GREATEST(o.observed_from,CASE WHEN o.recovery_epoch<>current_recovery_epoch THEN recovery_completed END)<=window_start THEN 'COMPLETE'
        ELSE 'INSUFFICIENT_COVERAGE' END,
      'observedFrom',CASE WHEN o.source IN ('PAAS_RESULTS','EXTERNAL_FEDERATION') THEN NULL
        ELSE GREATEST(o.observed_from,CASE WHEN o.recovery_epoch<>current_recovery_epoch THEN recovery_completed END) END,
      'observedThrough',CASE WHEN o.source IN ('PAAS_RESULTS','EXTERNAL_FEDERATION') THEN NULL ELSE observed END,
      'reason',CASE WHEN o.source IN ('PAAS_RESULTS','EXTERNAL_FEDERATION') THEN 'SOURCE_NOT_IMPLEMENTED'
        WHEN GREATEST(o.observed_from,CASE WHEN o.recovery_epoch<>current_recovery_epoch THEN recovery_completed END)<=window_start THEN ''
        WHEN o.recovery_epoch<>current_recovery_epoch THEN 'RESTORE_GAP' ELSE 'OBSERVATION_WINDOW_INCOMPLETE' END))
      ORDER BY array_position(ARRAY['IAM_PASSWORD_SESSIONS','IAM_ACCESS_KEY_AUTHORIZATIONS','IAM_ROLE_SESSIONS',
        'IAM_ROLE_AUTHORIZATIONS','PAAS_RESULTS','EXTERNAL_FEDERATION'],o.source)) INTO coverage
      FROM iam.access_analyzer_observations o WHERE o.tenant_id=tenant AND o.analyzer_id=analyzer;
    IF jsonb_array_length(COALESCE(coverage,'[]'::jsonb))<>6 THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='access analysis coverage is incomplete'; END IF;

    WITH universe AS (
      SELECT 'UNUSED_PASSWORD'::text AS finding_type,'USER'::text AS target_kind,p.id AS target_id
        FROM iam.principals p WHERE p.tenant_id=tenant AND p.principal_type='USER' AND p.status='ACTIVE' AND p.deleted_at IS NULL
      UNION SELECT 'UNUSED_ACCESS_KEY','ACCESS_KEY',k.id FROM iam.access_keys k
        WHERE k.tenant_id=tenant AND k.status='ENABLED' AND k.deleted_at IS NULL
      UNION SELECT 'UNUSED_ROLE','ROLE',r.id FROM iam.roles r
        WHERE r.tenant_id=tenant AND r.management='CUSTOMER' AND r.status='ACTIVE' AND r.deleted_at IS NULL
      UNION SELECT f.finding_type,f.target_kind,f.target_id FROM iam.access_findings f
        WHERE f.tenant_id=tenant AND f.analyzer_id=analyzer AND f.status<>'RESOLVED'
    ), page AS (
      SELECT finding_type,target_kind,target_id FROM universe
        WHERE (finding_type COLLATE "C",target_id COLLATE "C")>(COALESCE(after_kind,'') COLLATE "C",COALESCE(after_id,'') COLLATE "C")
        ORDER BY finding_type COLLATE "C",target_id COLLATE "C" LIMIT 101
    )
    SELECT COALESCE(jsonb_agg(jsonb_build_object('type',finding_type,'kind',target_kind,'id',target_id)
      ORDER BY finding_type COLLATE "C",target_id COLLATE "C"),'[]'::jsonb) INTO all_keys FROM page;
    cycle_complete:=jsonb_array_length(all_keys)<=100;
    SELECT COALESCE(jsonb_agg(element ORDER BY ordinal),'[]'::jsonb) INTO batch_keys
      FROM jsonb_array_elements(all_keys) WITH ORDINALITY AS entry(element,ordinal) WHERE ordinal<=100;
    IF jsonb_array_length(batch_keys)>0 THEN
      last_kind:=batch_keys->(jsonb_array_length(batch_keys)-1)->>'type';
      last_id:=batch_keys->(jsonb_array_length(batch_keys)-1)->>'id';
    END IF;

    WITH keys AS (
      SELECT type,kind,id FROM jsonb_to_recordset(batch_keys) AS item(type text,kind text,id text)
    ), candidate_rows AS (
      SELECT keys.type,keys.kind,keys.id,p.resource_version,p.created_at,
        (1+COUNT(s.id))::bigint AS activity_revision,MAX(s.issued_at) AS last_activity
        FROM keys JOIN iam.principals p ON keys.type='UNUSED_PASSWORD' AND keys.kind='USER'
          AND p.tenant_id=tenant AND p.id=keys.id AND p.principal_type='USER' AND p.status='ACTIVE' AND p.deleted_at IS NULL
        LEFT JOIN iam.sessions s ON s.tenant_id=p.tenant_id AND s.principal_id=p.id
          AND s.authentication_method IN ('PASSWORD','PASSWORD_TOTP') AND s.issued_at<=observed
          AND (recovery_completed IS NULL OR s.issued_at>=recovery_completed)
        GROUP BY keys.type,keys.kind,keys.id,p.resource_version,p.created_at
      UNION ALL
      SELECT keys.type,keys.kind,keys.id,k.resource_version,k.created_at,
        (1+COUNT(d.id))::bigint,MAX(d.decided_at)
        FROM keys JOIN iam.access_keys k ON keys.type='UNUSED_ACCESS_KEY' AND keys.kind='ACCESS_KEY'
          AND k.tenant_id=tenant AND k.id=keys.id AND k.status='ENABLED' AND k.deleted_at IS NULL
        LEFT JOIN iam.authorization_decisions d ON d.tenant_id=k.tenant_id AND d.access_key_id=k.id AND d.decided_at<=observed
          AND (recovery_completed IS NULL OR d.decided_at>=recovery_completed)
        GROUP BY keys.type,keys.kind,keys.id,k.resource_version,k.created_at
      UNION ALL
      SELECT keys.type,keys.kind,keys.id,r.resource_version,r.created_at,
        (1+COUNT(activity.observed_at))::bigint,MAX(activity.observed_at)
        FROM keys JOIN iam.roles r ON keys.type='UNUSED_ROLE' AND keys.kind='ROLE'
          AND r.tenant_id=tenant AND r.id=keys.id AND r.management='CUSTOMER' AND r.status='ACTIVE' AND r.deleted_at IS NULL
        LEFT JOIN LATERAL (
          SELECT rs.issued_at AS observed_at FROM iam.role_sessions rs WHERE rs.tenant_id=r.tenant_id AND rs.role_id=r.id
          UNION ALL SELECT d.decided_at FROM iam.authorization_decisions d WHERE d.tenant_id=r.tenant_id AND d.role_id=r.id
        ) activity ON activity.observed_at<=observed AND (recovery_completed IS NULL OR activity.observed_at>=recovery_completed)
        GROUP BY keys.type,keys.kind,keys.id,r.resource_version,r.created_at
    )
    SELECT COALESCE(jsonb_agg(jsonb_strip_nulls(jsonb_build_object('type',type,'target',jsonb_build_object('kind',kind,'id',id),
      'targetResourceVersion',resource_version,'createdAt',created_at,'activityRevision',activity_revision,
      'lastActivityAt',last_activity)) ORDER BY type COLLATE "C",id COLLATE "C"),'[]'::jsonb) INTO candidates FROM candidate_rows;

    WITH keys AS (
      SELECT type,kind,id FROM jsonb_to_recordset(batch_keys) AS item(type text,kind text,id text)
    ), latest AS (
      SELECT DISTINCT ON (f.finding_type,f.target_kind,f.target_id) f.finding_id,f.finding_type,f.target_id
        FROM iam.access_findings f JOIN keys ON (keys.type,keys.kind,keys.id)=(f.finding_type,f.target_kind,f.target_id)
        WHERE f.tenant_id=tenant AND f.analyzer_id=analyzer
        ORDER BY f.finding_type,f.target_kind,f.target_id,f.condition_generation DESC
    )
    SELECT COALESCE(jsonb_agg(iam.access_finding_document(tenant,finding_id)
      ORDER BY finding_type COLLATE "C",target_id COLLATE "C"),'[]'::jsonb) INTO findings FROM latest;

    RETURN jsonb_strip_nulls(jsonb_build_object('analyzer',analyzer_document,'observedAt',observed,'coverage',coverage,
      'recoveryEpoch',current_recovery_epoch,'recoveryCommandId',recovery_command,'recoveryCompletedAt',recovery_completed,
      'candidates',candidates,'findings',findings,'batch',jsonb_strip_nulls(jsonb_build_object(
        'afterType',NULLIF(after_kind,''),'afterTargetId',NULLIF(after_id,''),'lastType',NULLIF(last_kind,''),
        'lastTargetId',NULLIF(last_id,''),'cycleComplete',cycle_complete))));
END $function$;

CREATE OR REPLACE FUNCTION iam.read_access_finding_directory_revision(tenant text,actor text,actor_session text,decision text,analyzer text)
RETURNS TABLE(analyzer_resource_version bigint,recovery_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE v_analyzer_resource_version bigint; v_recovery_epoch bigint; recovery_state text;
BEGIN
    PERFORM iam.assert_access_analyzer_actor(tenant,actor,actor_session,decision,'iam.access-finding.list',analyzer);
    SELECT a.resource_version INTO v_analyzer_resource_version FROM iam.access_analyzers a
      WHERE a.tenant_id=tenant AND a.analyzer_id=analyzer;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='access analyzer not found'; END IF;
    SELECT s.state,s.epoch INTO recovery_state,v_recovery_epoch FROM iam.authentication_recovery_state s WHERE s.singleton;
    IF NOT FOUND OR recovery_state<>'OPEN' THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication recovery is not open'; END IF;
    RETURN QUERY SELECT v_analyzer_resource_version,v_recovery_epoch;
END $function$;

CREATE OR REPLACE FUNCTION iam.list_access_findings(tenant text,actor text,actor_session text,decision text,analyzer text,after_id text,status_filter text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE analyzer_status text; effective_now timestamptz(6):=transaction_timestamp(); coverage jsonb; items jsonb;
    current_recovery_epoch bigint; recovery_state text; recovery_command text; recovery_completed timestamptz;
BEGIN
    PERFORM iam.assert_access_analyzer_actor(tenant,actor,actor_session,decision,'iam.access-finding.list',analyzer);
    IF (COALESCE(after_id,'')<>'' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
      OR status_filter NOT IN ('ALL','ACTIVE','ARCHIVED','RESOLVED') THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access finding page is invalid'; END IF;
    SELECT a.status INTO analyzer_status FROM iam.access_analyzers a WHERE a.tenant_id=tenant AND a.analyzer_id=analyzer;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='access analyzer not found'; END IF;
    SELECT s.state,s.epoch INTO recovery_state,current_recovery_epoch FROM iam.authentication_recovery_state s WHERE s.singleton;
    IF NOT FOUND OR recovery_state<>'OPEN' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication recovery is not open'; END IF;
    IF current_recovery_epoch>0 THEN
      SELECT c.command_id,p.completed_at INTO recovery_command,recovery_completed
        FROM iam.authentication_recovery_closures c JOIN iam.authentication_recovery_completions p
          ON p.command_id=c.command_id AND p.installation_id=c.installation_id AND p.home_tenant_id=c.home_tenant_id
        WHERE c.epoch=current_recovery_epoch;
      IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication recovery completion is unavailable'; END IF;
    END IF;
    SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object('source',o.source,
      'state',CASE WHEN o.source IN ('PAAS_RESULTS','EXTERNAL_FEDERATION') THEN 'NOT_INCLUDED'
        WHEN o.recovery_epoch<>current_recovery_epoch THEN 'INSUFFICIENT_COVERAGE' ELSE o.state END,
      'observedFrom',CASE WHEN o.source IN ('PAAS_RESULTS','EXTERNAL_FEDERATION') THEN NULL
        WHEN o.recovery_epoch<>current_recovery_epoch THEN recovery_completed ELSE o.observed_from END,
      'observedThrough',CASE WHEN o.source IN ('PAAS_RESULTS','EXTERNAL_FEDERATION') THEN NULL
        WHEN o.recovery_epoch<>current_recovery_epoch THEN recovery_completed
        WHEN analyzer_status='ACTIVE' THEN LEAST(effective_now,o.observed_through) ELSE o.observed_through END,
      'reason',CASE WHEN o.source IN ('PAAS_RESULTS','EXTERNAL_FEDERATION') THEN 'SOURCE_NOT_IMPLEMENTED'
        WHEN o.recovery_epoch<>current_recovery_epoch THEN 'RESTORE_GAP' ELSE o.reason END))
      ORDER BY array_position(ARRAY['IAM_PASSWORD_SESSIONS','IAM_ACCESS_KEY_AUTHORIZATIONS','IAM_ROLE_SESSIONS',
        'IAM_ROLE_AUTHORIZATIONS','PAAS_RESULTS','EXTERNAL_FEDERATION'],o.source)) INTO coverage
      FROM iam.access_analyzer_observations o WHERE o.tenant_id=tenant AND o.analyzer_id=analyzer;
    IF jsonb_array_length(COALESCE(coverage,'[]'::jsonb))<>6 THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='access analyzer coverage is incomplete'; END IF;
    IF (SELECT count(*)=4 FROM jsonb_to_recordset(coverage) AS c(source text,state text)
      WHERE c.source IN ('IAM_PASSWORD_SESSIONS','IAM_ACCESS_KEY_AUTHORIZATIONS','IAM_ROLE_SESSIONS','IAM_ROLE_AUTHORIZATIONS')
        AND c.state='COMPLETE') THEN
      SELECT COALESCE(jsonb_agg(iam.access_finding_document(tenant,f.finding_id) ORDER BY f.finding_id COLLATE "C"),'[]'::jsonb)
        INTO items FROM (SELECT finding_id FROM iam.access_findings
          WHERE tenant_id=tenant AND analyzer_id=analyzer AND recovery_epoch=current_recovery_epoch
            AND (status_filter='ALL' OR status=status_filter)
            AND (COALESCE(after_id,'')='' OR finding_id>after_id COLLATE "C") ORDER BY finding_id COLLATE "C" LIMIT 101) f;
    ELSE items:='[]'::jsonb; END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AccessFindingList','accountId',tenant,
      'analyzerId',analyzer,'observedAt',effective_now,'coverage',coverage,'items',items);
END $function$;

CREATE OR REPLACE FUNCTION iam.assert_access_finding_actor(tenant text,actor text,actor_session text,
  decision text,action_name text,analyzer text,finding text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF COALESCE(tenant,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor_session,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(analyzer,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(finding,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR action_name NOT IN ('iam.access-finding.read','iam.access-finding.archive','iam.access-finding.unarchive') THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access finding subject is invalid'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts a WHERE a.id=tenant AND a.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='access finding account is unavailable'; END IF;
    PERFORM iam.lock_mfa_session(tenant,actor,actor_session);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,action_name,'ACCESS_FINDING',finding,'INSTANCE',NULL);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_access_finding(tenant text,actor text,actor_session text,decision text,analyzer text,finding text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb; recovery_state text; current_recovery_epoch bigint;
BEGIN
    PERFORM iam.assert_access_finding_actor(tenant,actor,actor_session,decision,'iam.access-finding.read',analyzer,finding);
    SELECT s.state,s.epoch INTO recovery_state,current_recovery_epoch FROM iam.authentication_recovery_state s WHERE s.singleton;
    IF NOT FOUND OR recovery_state<>'OPEN' THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication recovery is not open'; END IF;
    SELECT iam.access_finding_document(tenant,f.finding_id) INTO result FROM iam.access_findings f
      WHERE f.tenant_id=tenant AND f.analyzer_id=analyzer AND f.finding_id=finding AND f.recovery_epoch=current_recovery_epoch;
    IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='access finding not found'; END IF;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.set_access_finding_archived(tenant text,actor text,actor_session text,decision text,
  analyzer text,finding text,request_id text,request_digest text,expected_version bigint,archived boolean,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE desired_action text:=CASE WHEN archived THEN 'iam.access-finding.archive' ELSE 'iam.access-finding.unarchive' END;
    event_action text:=CASE WHEN archived THEN 'iam.access-finding.archived' ELSE 'iam.access-finding.unarchived' END;
    expected_status text:=CASE WHEN archived THEN 'ACTIVE' ELSE 'ARCHIVED' END;
    new_status text:=CASE WHEN archived THEN 'ARCHIVED' ELSE 'ACTIVE' END;
    previous iam.access_finding_receipts%ROWTYPE; stored iam.access_findings%ROWTYPE; result jsonb;
    effective_now timestamptz(6):=transaction_timestamp(); recovery_state text; current_recovery_epoch bigint;
BEGIN
    PERFORM iam.assert_access_finding_actor(tenant,actor,actor_session,decision,desired_action,analyzer,finding);
    IF COALESCE(request_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(request_digest,'') !~ '^sha256:[0-9a-f]{64}$'
      OR expected_version NOT BETWEEN 1 AND 9007199254740991 THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access finding disposition is invalid'; END IF;
    SELECT * INTO previous FROM iam.access_finding_receipts r WHERE r.tenant_id=tenant AND r.actor_id=actor
      AND r.action_name=desired_action AND r.request_id=set_access_finding_archived.request_id;
    IF FOUND THEN
      IF previous.request_digest IS DISTINCT FROM request_digest OR previous.analyzer_id IS DISTINCT FROM analyzer
        OR previous.finding_id IS DISTINCT FROM finding THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='access finding disposition conflicts'; END IF;
      RETURN previous.result_document;
    END IF;
    SELECT s.state,s.epoch INTO recovery_state,current_recovery_epoch FROM iam.authentication_recovery_state s WHERE s.singleton;
    IF NOT FOUND OR recovery_state<>'OPEN' THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication recovery is not open'; END IF;
    SELECT * INTO stored FROM iam.access_findings f WHERE f.tenant_id=tenant AND f.analyzer_id=analyzer
      AND f.finding_id=finding AND f.recovery_epoch=current_recovery_epoch FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='access finding not found'; END IF;
    IF stored.resource_version IS DISTINCT FROM expected_version OR stored.status IS DISTINCT FROM expected_status THEN
      RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='access finding disposition conflicts'; END IF;
    PERFORM iam.assert_audit_event(event,tenant,event_action,'ACCESS_FINDING',finding,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision OR event->>'requestId' IS DISTINCT FROM request_id
      OR event->>'requestDigest' IS DISTINCT FROM request_digest
      OR (event->>'occurredAt')::timestamptz IS DISTINCT FROM effective_now THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='access finding disposition decision differs'; END IF;
    UPDATE iam.access_findings f SET status=new_status,resource_version=stored.resource_version+1,updated_at=effective_now
      WHERE f.tenant_id=tenant AND f.finding_id=finding;
    result:=iam.access_finding_document(tenant,finding);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    INSERT INTO iam.access_finding_receipts(tenant_id,actor_id,action_name,request_id,request_digest,analyzer_id,
      finding_id,result_document,decision_id,event_id,completed_at)
      VALUES(tenant,actor,desired_action,request_id,request_digest,analyzer,finding,result,decision,event->>'eventId',effective_now);
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.assert_access_finding_receipt()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE fact jsonb; expected_event_action text; expected_status text;
BEGIN
    expected_event_action:=CASE NEW.action_name WHEN 'iam.access-finding.archive' THEN 'iam.access-finding.archived'
      ELSE 'iam.access-finding.unarchived' END;
    expected_status:=CASE NEW.action_name WHEN 'iam.access-finding.archive' THEN 'ARCHIVED' ELSE 'ACTIVE' END;
    IF NOT iam.valid_access_finding(NEW.result_document,NEW.tenant_id,NEW.analyzer_id,NEW.finding_id)
      OR NEW.result_document->>'status' IS DISTINCT FROM expected_status
      OR (NEW.result_document->>'updatedAt')::timestamptz IS DISTINCT FROM NEW.completed_at
      OR NOT EXISTS(SELECT 1 FROM iam.authorization_decisions d WHERE d.tenant_id=NEW.tenant_id AND d.id=NEW.decision_id
        AND d.principal_id=NEW.actor_id AND d.allowed AND d.action_name=NEW.action_name
        AND d.target_kind='ACCESS_FINDING' AND d.target_id=NEW.finding_id AND d.resource_mode='INSTANCE' AND d.collection_usage IS NULL) THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='access finding decision proof differs'; END IF;
    SELECT o.event_document INTO fact FROM iam.audit_outbox o WHERE o.tenant_id=NEW.tenant_id AND o.event_id=NEW.event_id;
    IF fact IS NULL OR fact->>'action' IS DISTINCT FROM expected_event_action OR fact->>'tenantId' IS DISTINCT FROM NEW.tenant_id
      OR fact->'actor' IS DISTINCT FROM jsonb_build_object('type','USER','id',NEW.actor_id)
      OR fact->'target' IS DISTINCT FROM jsonb_build_object('kind','ACCESS_FINDING','id',NEW.finding_id)
      OR fact->>'iamDecisionId' IS DISTINCT FROM NEW.decision_id OR fact->>'requestId' IS DISTINCT FROM NEW.request_id
      OR fact->>'correlationId' IS DISTINCT FROM NEW.request_id OR fact->>'requestDigest' IS DISTINCT FROM NEW.request_digest
      OR (fact->>'occurredAt')::timestamptz IS DISTINCT FROM NEW.completed_at OR fact ?| ARRAY['installationId','operationId']
      OR fact->>'result'<>'SUCCEEDED' THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='access finding audit proof differs'; END IF;
    RETURN NULL;
END $function$;
DROP TRIGGER IF EXISTS access_finding_receipt_complete ON iam.access_finding_receipts;
CREATE CONSTRAINT TRIGGER access_finding_receipt_complete AFTER INSERT ON iam.access_finding_receipts
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.assert_access_finding_receipt();
ALTER TABLE iam.access_finding_receipts ENABLE ALWAYS TRIGGER access_finding_receipt_complete;

CREATE OR REPLACE FUNCTION iam.access_analysis_worker_ready()
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM iam.assert_access_analysis_worker();
    RETURN iam.access_analysis_contract_ready();
END $function$;

CREATE OR REPLACE FUNCTION iam.access_analysis_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
  SELECT (SELECT count(*)=3 FROM pg_class relation WHERE relation.oid IN (
      to_regclass('iam.access_findings'),to_regclass('iam.access_analysis_scan_state'),to_regclass('iam.access_analysis_attempts'))
      AND relation.relowner='matrix_iam_owner'::regrole AND relation.relrowsecurity AND relation.relforcerowsecurity
      AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) privilege
        WHERE privilege.grantee<>relation.relowner))
    AND (SELECT count(*)=3 FROM pg_policies p WHERE p.schemaname='iam'
      AND p.tablename IN ('access_findings','access_analysis_scan_state','access_analysis_attempts')
      AND p.policyname='tenant_isolation'
      AND p.qual='((tenant_id = iam.current_tenant_id()) OR (current_setting(''matrix.iam_access_analysis''::text, true) = ''trusted''::text))'
      AND p.with_check='((tenant_id = iam.current_tenant_id()) OR (current_setting(''matrix.iam_access_analysis''::text, true) = ''trusted''::text))')
    AND EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname='matrix_iam_access_analysis_worker'
      AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls)
    AND (SELECT count(*)=3 FROM pg_proc p WHERE p.oid IN (
      to_regprocedure('iam.access_analysis_worker_ready()'),to_regprocedure('iam.claim_access_analysis(text,text)'),
      to_regprocedure('iam.complete_access_analysis(text,text,bigint,text,jsonb)'))
      AND p.proowner='matrix_iam_owner'::regrole AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
      AND has_function_privilege('matrix_iam_access_analysis_worker',p.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_api',p.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_worker',p.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_notification_worker',p.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_authentication_recovery',p.oid,'EXECUTE'))
$function$;

REVOKE ALL ON TABLE iam.access_findings,iam.access_finding_receipts,iam.access_analysis_scan_state,iam.access_analysis_attempts
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA iam FROM matrix_iam_access_analysis_worker;
GRANT USAGE ON SCHEMA iam TO matrix_iam_access_analysis_worker;
GRANT EXECUTE ON FUNCTION iam.access_analysis_worker_ready(),iam.claim_access_analysis(text,text),
  iam.complete_access_analysis(text,text,bigint,text,jsonb) TO matrix_iam_access_analysis_worker;
REVOKE ALL ON FUNCTION iam.access_finding_document(text,text),iam.valid_access_finding(jsonb,text,text,text),
  iam.assert_access_finding_actor(text,text,text,text,text,text,text),iam.assert_access_finding_receipt(),
  iam.access_analysis_expected(jsonb),iam.assert_access_analysis_worker(),
  iam.access_analysis_snapshot(text,text,timestamptz,text,text),iam.access_analysis_contract_ready()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
REVOKE ALL ON FUNCTION iam.access_analysis_worker_ready(),iam.claim_access_analysis(text,text),
  iam.complete_access_analysis(text,text,bigint,text,jsonb)
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.read_access_finding_directory_revision(text,text,text,text,text),
  iam.list_access_findings(text,text,text,text,text,text,text),iam.read_access_finding(text,text,text,text,text,text),
  iam.set_access_finding_archived(text,text,text,text,text,text,text,text,bigint,boolean,jsonb)
  FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
GRANT EXECUTE ON FUNCTION iam.read_access_finding_directory_revision(text,text,text,text,text),
  iam.list_access_findings(text,text,text,text,text,text,text),iam.read_access_finding(text,text,text,text,text,text),
  iam.set_access_finding_archived(text,text,text,text,text,text,text,text,bigint,boolean,jsonb) TO matrix_iam_api;

DO $access_analysis_readiness_cutover$
BEGIN
    IF to_regprocedure('iam.readiness_v62()') IS NOT NULL THEN DROP FUNCTION iam.readiness_v62(); END IF;
    ALTER FUNCTION iam.readiness() RENAME TO readiness_v62;
END $access_analysis_readiness_cutover$;
REVOKE ALL ON FUNCTION iam.readiness_v62() FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,
  matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
CREATE FUNCTION iam.readiness()
RETURNS TABLE(ready boolean,schema_version bigint,checked_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE predecessor record;
BEGIN
    SELECT * INTO predecessor FROM iam.readiness_v62();
    RETURN QUERY SELECT predecessor.ready AND iam.access_analysis_contract_ready(),63::bigint,predecessor.checked_at;
END $function$;
REVOKE ALL ON FUNCTION iam.readiness() FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,
  matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
GRANT EXECUTE ON FUNCTION iam.readiness() TO matrix_iam_api;
