-- The seed document is supplied by the IAM Go policy/canonicalization owner.
-- This fragment runs inside the same IAM schema/data/function transaction.
DO $policy_cutover$
DECLARE
    seeds jsonb := __POLICY_SEED_DOCUMENT__;
    seed jsonb;
    legacy record;
    effective_now timestamptz(6) := transaction_timestamp();
BEGIN
    FOR seed IN SELECT value FROM jsonb_array_elements(seeds) LOOP
        INSERT INTO iam.policies(id,management,display_name,authority_scope,status,default_version_id,
            resource_version,created_at,updated_at)
        VALUES(seed->>'policyId','SYSTEM',seed->>'displayName',seed->>'scope','ACTIVE',seed->>'versionId',
            1,effective_now,effective_now) ON CONFLICT(id) DO NOTHING;
        IF NOT EXISTS(SELECT 1 FROM iam.policies AS policy WHERE policy.id=seed->>'policyId'
            AND policy.management='SYSTEM' AND policy.owner_tenant_id IS NULL AND policy.authority_scope=seed->>'scope') THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM system policy identity conflicts';
        END IF;
        INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at)
        VALUES(seed->>'policyId',seed->>'versionId',seed->>'scope',seed->'document',
            seed->>'canonicalDocument',seed->>'contentDigest',effective_now)
        ON CONFLICT(policy_id,id) DO NOTHING;
        IF NOT EXISTS(SELECT 1 FROM iam.policy_versions AS version
            WHERE version.policy_id=seed->>'policyId' AND version.id=seed->>'versionId'
            AND version.authority_scope=seed->>'scope' AND version.document=seed->'document'
            AND version.canonical_document=seed->>'canonicalDocument' AND version.content_digest=seed->>'contentDigest') THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM immutable policy version conflicts';
        END IF;
    END LOOP;

    IF to_regclass('iam.role_bindings') IS NOT NULL THEN
        -- The preflight holds an exclusive legacy-table lock. This migration-
        -- local owner policy permits copying every tenant, including disabled
        -- ones, without broadening any committed runtime access policy.
        EXECUTE 'CREATE POLICY policy_cutover_owner_read ON iam.role_bindings FOR SELECT TO matrix_iam_owner USING (true)';
        FOR legacy IN EXECUTE 'SELECT * FROM iam.role_bindings ORDER BY tenant_id,id' LOOP
            SELECT value INTO seed FROM jsonb_array_elements(seeds) WHERE value->>'legacyRole'=legacy.role_name;
            IF seed IS NULL THEN
                RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM historical role has no explicit policy mapping';
            END IF;
            PERFORM set_config('matrix.iam_tenant_id',legacy.tenant_id,true);
            INSERT INTO iam.policy_attachments(tenant_id,id,target_id,policy_id,resource_version,created_at,updated_at,revoked_at)
            VALUES(legacy.tenant_id,legacy.id,legacy.principal_id,seed->>'policyId',legacy.resource_version,
                legacy.created_at,legacy.updated_at,legacy.revoked_at);
        END LOOP;
    END IF;
END $policy_cutover$;

DROP FUNCTION IF EXISTS iam.put_role_binding(text,text,text,text,text,text,jsonb);
DROP FUNCTION IF EXISTS iam.lookup_role_binding_role(text,text);
DROP FUNCTION IF EXISTS iam.revoke_role_binding(text,text,text,text,jsonb);
DROP FUNCTION IF EXISTS iam.lookup_service_roles(text,text);
DROP TABLE IF EXISTS iam.role_bindings;

SET CONSTRAINTS iam.policies_default_version_fk IMMEDIATE;

CREATE UNIQUE INDEX IF NOT EXISTS customer_policies_active_name_uq
    ON iam.policies(owner_tenant_id,display_name COLLATE "C") WHERE management='CUSTOMER' AND status='ACTIVE';
CREATE INDEX IF NOT EXISTS policies_active_directory_idx
    ON iam.policies(authority_scope,owner_tenant_id,id) WHERE status='ACTIVE';
CREATE INDEX IF NOT EXISTS policy_attachments_live_policy_idx
    ON iam.policy_attachments(policy_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS policy_versions_active_inventory_idx
    ON iam.policy_versions(policy_id,id) WHERE retired_at IS NULL;

CREATE OR REPLACE FUNCTION iam.assert_customer_policy_document(canonical text,content_digest text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE document jsonb; statement jsonb; selected_action jsonb; selector jsonb; seen_sids text[]:='{}'; expected_kind text;
    condition jsonb; condition_value jsonb; condition_identity text; seen_conditions text[];
    boundary timestamptz; starts_at timestamptz; ends_at timestamptz;
BEGIN
    IF canonical IS NULL OR octet_length(canonical) NOT BETWEEN 1 AND 65536
       OR NOT (canonical IS JSON OBJECT WITH UNIQUE KEYS)
       OR content_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to('matrix.iam.policy.v1','UTF8')||decode('00','hex')||convert_to(canonical,'UTF8')),'hex') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy document is invalid';
    END IF;
    document:=canonical::jsonb;
    IF NOT (document ?& ARRAY['languageVersion','scope','statements'])
       OR document-ARRAY['languageVersion','scope','statements']<>'{}'::jsonb
       OR document->>'languageVersion' IS DISTINCT FROM '1' OR document->>'scope' IS DISTINCT FROM 'TENANT'
       OR jsonb_typeof(document->'languageVersion') IS DISTINCT FROM 'string'
       OR jsonb_typeof(document->'scope') IS DISTINCT FROM 'string'
       OR jsonb_typeof(document->'statements') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy document is invalid';
    END IF;
    IF jsonb_array_length(document->'statements') NOT BETWEEN 1 AND 64 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy statement limit exceeded';
    END IF;
    FOR statement IN SELECT value FROM jsonb_array_elements(document->'statements') LOOP
        IF jsonb_typeof(statement) IS DISTINCT FROM 'object' OR NOT (statement ?& ARRAY['sid','effect','actions','resources'])
           OR statement-ARRAY['sid','effect','actions','resources','conditions']<>'{}'::jsonb
           OR jsonb_typeof(statement->'sid') IS DISTINCT FROM 'string'
           OR COALESCE(statement->>'sid','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
           OR statement->>'sid'=ANY(seen_sids) OR COALESCE(statement->>'effect','') NOT IN ('ALLOW','DENY')
           OR jsonb_typeof(statement->'actions') IS DISTINCT FROM 'array'
           OR jsonb_typeof(statement->'resources') IS DISTINCT FROM 'array' THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy statement is invalid';
        END IF;
        seen_sids:=array_append(seen_sids,statement->>'sid');
        IF statement ? 'conditions' THEN
            IF jsonb_typeof(statement->'conditions') IS DISTINCT FROM 'array' THEN
                RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy conditions are invalid';
            END IF;
            IF jsonb_array_length(statement->'conditions') NOT BETWEEN 1 AND 16 THEN
                RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy condition limit exceeded';
            END IF;
            seen_conditions:='{}'; starts_at:=NULL; ends_at:=NULL;
            FOR condition IN SELECT value FROM jsonb_array_elements(statement->'conditions') LOOP
                IF jsonb_typeof(condition) IS DISTINCT FROM 'object' OR NOT(condition ?& ARRAY['key','operator','values'])
                   OR condition-ARRAY['key','operator','values']<>'{}'::jsonb
                   OR COALESCE(condition->>'key','') NOT IN ('iam.current-time','iam.account-id','iam.principal-id')
                   OR jsonb_typeof(condition->'values') IS DISTINCT FROM 'array' THEN
                    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy condition is invalid';
                END IF;
                condition_identity:=(condition->>'key')||'/'||(condition->>'operator');
                IF condition_identity IS NULL OR condition_identity=ANY(seen_conditions) THEN
                    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy condition is invalid';
                END IF;
                seen_conditions:=array_append(seen_conditions,condition_identity);
                IF condition->>'key' IN ('iam.account-id','iam.principal-id') THEN
                    IF COALESCE(condition->>'operator','') NOT IN ('STRING_EQUALS','STRING_NOT_EQUALS')
                       OR jsonb_array_length(condition->'values') NOT BETWEEN 1 AND 16
                       OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(condition->'values'))<>jsonb_array_length(condition->'values') THEN
                        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy identity condition is invalid';
                    END IF;
                    FOR condition_value IN SELECT value FROM jsonb_array_elements(condition->'values') LOOP
                        IF jsonb_typeof(condition_value) IS DISTINCT FROM 'string'
                           OR (condition_value#>>'{}') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
                            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy identity value is invalid';
                        END IF;
                    END LOOP;
                    CONTINUE;
                END IF;
                IF COALESCE(condition->>'operator','') NOT IN ('DATE_GREATER_THAN_EQUALS','DATE_LESS_THAN') THEN
                    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy condition operator is invalid';
                END IF;
                IF jsonb_array_length(condition->'values')<>1 OR jsonb_typeof(condition#>'{values,0}') IS DISTINCT FROM 'string'
                   OR COALESCE(condition#>>'{values,0}','') COLLATE "C" !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{0,5}[1-9])?Z$' THEN
                    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy condition value is invalid';
                END IF;
                BEGIN
                    boundary:=(condition#>>'{values,0}')::timestamptz;
                EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow THEN
                    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy condition time is invalid';
                END;
                IF boundary='0001-01-01T00:00:00Z'::timestamptz
                   OR to_char(boundary AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS')<>substring(condition#>>'{values,0}' FROM 1 FOR 19) THEN
                    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy condition time is invalid';
                END IF;
                IF condition->>'operator'='DATE_GREATER_THAN_EQUALS' THEN starts_at:=boundary; ELSE ends_at:=boundary; END IF;
                IF starts_at IS NOT NULL AND ends_at IS NOT NULL AND starts_at>=ends_at THEN
                    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy time window is invalid';
                END IF;
            END LOOP;
        END IF;
        IF jsonb_array_length(statement->'actions') NOT BETWEEN 1 AND 128
           OR jsonb_array_length(statement->'resources') NOT BETWEEN 1 AND 64
           OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(statement->'actions'))<>jsonb_array_length(statement->'actions')
           OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(statement->'resources'))<>jsonb_array_length(statement->'resources') THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy statement collections are invalid';
        END IF;
        FOR selected_action IN SELECT value FROM jsonb_array_elements(statement->'actions') LOOP
            expected_kind:=iam.resource_kind_for_action(selected_action#>>'{}');
            IF jsonb_typeof(selected_action) IS DISTINCT FROM 'string' OR expected_kind IS NULL
               OR iam.is_platform_action(selected_action#>>'{}') OR selected_action#>>'{}'='installation.verify'
               OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(statement->'resources') AS item WHERE item->>'kind'=expected_kind) THEN
                RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy action is invalid';
            END IF;
        END LOOP;
        FOR selector IN SELECT value FROM jsonb_array_elements(statement->'resources') LOOP
            IF jsonb_typeof(selector) IS DISTINCT FROM 'object' OR NOT (selector ?& ARRAY['kind','match'])
               OR selector-ARRAY['kind','match','id']<>'{}'::jsonb
               OR jsonb_typeof(selector->'kind') IS DISTINCT FROM 'string'
               OR COALESCE(selector->>'match','') NOT IN ('EXACT','ANY_IN_AUTHORITY')
               OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(statement->'actions') AS item
                    WHERE iam.resource_kind_for_action(item)=selector->>'kind')
               OR (selector->>'match'='ANY_IN_AUTHORITY' AND selector ? 'id')
               OR (selector->>'match'='EXACT' AND (jsonb_typeof(selector->'id') IS DISTINCT FROM 'string'
                    OR COALESCE(selector->>'id','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')) THEN
                RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy resource is invalid';
            END IF;
        END LOOP;
    END LOOP;
END $function$;

CREATE OR REPLACE FUNCTION iam.policy_detail_snapshot(tenant text,policy_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy jsonb; version jsonb;
BEGIN
    policy:=iam.lookup_policy(tenant,policy_id);
    IF policy IS NULL OR policy->>'scope'<>'TENANT' OR policy->>'status'<>'ACTIVE' THEN RETURN NULL; END IF;
    SELECT jsonb_build_object('policyId',v.policy_id,'versionId',v.id,'document',v.document,'contentDigest',v.content_digest)
      INTO version FROM iam.policy_versions AS v WHERE v.policy_id=policy_detail_snapshot.policy_id AND v.id=policy->>'defaultVersionId' AND v.retired_at IS NULL;
    IF version IS NULL THEN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='policy version is unavailable'; END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','PolicyDetail','policy',policy,'version',version);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_policy(tenant text,actor text,decision text,policy_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.read_account(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy.read','POLICY',policy_id);
    result:=iam.policy_detail_snapshot(tenant,policy_id);
    IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy is unavailable'; END IF;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.create_policy(tenant text,actor text,decision text,policy_id text,display_name text,version_id text,canonical text,content_digest text,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.policies%ROWTYPE; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    PERFORM iam.assert_customer_policy_document(canonical,content_digest);
    IF COALESCE(policy_id,'') COLLATE "C" !~ '^policy-[0-9a-f]{64}$'
       OR version_id IS DISTINCT FROM 'version-'||substring(content_digest FROM 8)
       OR display_name IS NULL OR octet_length(display_name) NOT BETWEEN 1 AND 128
       OR btrim(display_name)<>display_name OR display_name ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy creation input is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy account is unavailable'; END IF;
    PERFORM 1 FROM iam.principals WHERE tenant_id=tenant AND id=actor AND principal_type='USER'
        AND status='ACTIVE' AND NOT must_change_password AND deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy actor is unavailable'; END IF;
    PERFORM 1 FROM iam.account_roots WHERE account_id=tenant AND principal_id=actor FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy publisher is unavailable'; END IF;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy.create','ACCOUNT',tenant);
    PERFORM iam.assert_audit_event(event,tenant,'iam.policy.created','POLICY',policy_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy decision correlation is invalid'; END IF;
    IF EXISTS(SELECT 1 FROM iam.audit_outbox AS fact WHERE fact.tenant_id=tenant AND fact.event_document->>'action'='iam.policy.created'
        AND fact.event_document#>>'{actor,id}'=actor AND fact.event_document->>'requestId'=event->>'requestId'
        AND (fact.event_document->>'requestDigest' IS DISTINCT FROM event->>'requestDigest' OR fact.event_document->'target' IS DISTINCT FROM event->'target')) THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy command intent conflicts';
    END IF;
    SELECT * INTO stored FROM iam.policies AS p WHERE p.id=policy_id FOR UPDATE;
    IF FOUND THEN
        IF stored.management<>'CUSTOMER' OR stored.owner_tenant_id<>tenant OR stored.status<>'ACTIVE' OR stored.resource_version<>1
           OR stored.display_name<>display_name OR stored.default_version_id<>version_id
           OR NOT EXISTS(SELECT 1 FROM iam.policy_versions AS v WHERE v.policy_id=stored.id AND v.id=version_id
                AND v.canonical_document=canonical AND v.content_digest=create_policy.content_digest)
           OR NOT EXISTS(SELECT 1 FROM iam.audit_outbox AS fact WHERE fact.tenant_id=tenant AND fact.event_document->>'action'='iam.policy.created'
                AND fact.event_document#>>'{target,id}'=policy_id AND fact.event_document#>>'{actor,id}'=actor
                AND fact.event_document->>'requestId'=event->>'requestId' AND fact.event_document->>'requestDigest'=event->>'requestDigest') THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy creation replay conflicts';
        END IF;
        RETURN iam.policy_detail_snapshot(tenant,policy_id);
    END IF;
    IF (SELECT count(*) FROM iam.policies WHERE owner_tenant_id=tenant AND management='CUSTOMER' AND status='ACTIVE')>=128 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='customer policy limit exceeded';
    END IF;
    INSERT INTO iam.policies(id,management,owner_tenant_id,display_name,authority_scope,status,default_version_id,resource_version,created_at,updated_at)
    VALUES(policy_id,'CUSTOMER',tenant,display_name,'TENANT','ACTIVE',version_id,1,effective_now,effective_now);
    INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at)
    VALUES(policy_id,version_id,'TENANT',canonical::jsonb,canonical,content_digest,effective_now);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
    VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    RETURN iam.policy_detail_snapshot(tenant,policy_id);
END $function$;

REVOKE ALL ON FUNCTION iam.assert_customer_policy_document(text,text),iam.policy_detail_snapshot(text,text),
    iam.read_policy(text,text,text,text),iam.create_policy(text,text,text,text,text,text,text,text,jsonb)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.read_policy(text,text,text,text),iam.create_policy(text,text,text,text,text,text,text,text,jsonb) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.policy_version_detail(tenant text,policy_id text,version_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy jsonb; version jsonb;
BEGIN
    policy:=iam.lookup_policy(tenant,policy_id);
    IF policy IS NULL OR policy->>'management'<>'CUSTOMER' OR policy->>'accountId' IS DISTINCT FROM tenant
       OR policy->>'scope'<>'TENANT' OR policy->>'status'<>'ACTIVE' THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy is unavailable';
    END IF;
    SELECT jsonb_build_object('policyId',v.policy_id,'versionId',v.id,'document',v.document,'contentDigest',v.content_digest)
      INTO version FROM iam.policy_versions AS v WHERE v.policy_id=policy_version_detail.policy_id AND v.id=version_id AND v.retired_at IS NULL;
    IF version IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy version is unavailable'; END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','PolicyVersionDetail','policy',policy,'version',version);
END $function$;

CREATE OR REPLACE FUNCTION iam.list_policy_versions(tenant text,actor text,decision text,policy_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy jsonb; versions jsonb;
BEGIN
    PERFORM iam.read_account(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy-version.list','POLICY',policy_id);
    policy:=iam.lookup_policy(tenant,policy_id);
    IF policy IS NULL OR policy->>'management'<>'CUSTOMER' OR policy->>'accountId' IS DISTINCT FROM tenant OR policy->>'status'<>'ACTIVE' THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy is unavailable';
    END IF;
    SELECT jsonb_agg(jsonb_build_object('policyId',v.policy_id,'versionId',v.id,'document',v.document,'contentDigest',v.content_digest) ORDER BY v.id)
      INTO versions FROM (SELECT * FROM iam.policy_versions AS stored WHERE stored.policy_id=list_policy_versions.policy_id AND stored.retired_at IS NULL ORDER BY stored.id LIMIT 6) v;
    IF versions IS NULL OR jsonb_array_length(versions)>5 THEN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='policy version inventory is unavailable'; END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','PolicyVersionList','policy',policy,'items',versions);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_policy_version(tenant text,actor text,decision text,policy_id text,version_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM iam.read_account(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy-version.read','POLICY',policy_id);
    RETURN iam.policy_version_detail(tenant,policy_id,version_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.lock_policy_publisher(tenant text,actor text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy account is unavailable'; END IF;
    PERFORM 1 FROM iam.principals WHERE tenant_id=tenant AND id=actor AND principal_type='USER'
        AND status='ACTIVE' AND NOT must_change_password AND deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy actor is unavailable'; END IF;
    PERFORM 1 FROM iam.account_roots WHERE account_id=tenant AND principal_id=actor FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy publisher is unavailable'; END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.lock_customer_policy_publisher(tenant text,actor text,policy_id text)
RETURNS iam.policies LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy iam.policies%ROWTYPE;
BEGIN
    PERFORM iam.lock_policy_publisher(tenant,actor);
    SELECT * INTO policy FROM iam.policies AS p WHERE p.id=policy_id AND p.owner_tenant_id=tenant
      AND p.management='CUSTOMER' AND p.authority_scope='TENANT' AND p.status='ACTIVE' FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy is unavailable'; END IF;
    RETURN policy;
END $function$;

CREATE OR REPLACE FUNCTION iam.policy_version_intent_replayed(tenant text,actor text,event jsonb)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE previous jsonb;
BEGIN
    SELECT fact.event_document INTO previous FROM iam.audit_outbox AS fact WHERE fact.tenant_id=tenant
      AND fact.event_document->>'action'=event->>'action' AND fact.event_document#>>'{actor,id}'=actor
      AND fact.event_document->>'requestId'=event->>'requestId';
    IF NOT FOUND THEN RETURN false; END IF;
    IF previous->>'requestDigest' IS DISTINCT FROM event->>'requestDigest' OR previous->'target' IS DISTINCT FROM event->'target' THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy version command intent conflicts';
    END IF;
    RETURN true;
END $function$;

CREATE OR REPLACE FUNCTION iam.create_policy_version(tenant text,actor text,decision text,policy_id text,expected_version bigint,version_id text,canonical text,content_digest text,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy iam.policies%ROWTYPE; replayed boolean; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    PERFORM iam.assert_customer_policy_document(canonical,content_digest);
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740990
       OR version_id IS DISTINCT FROM 'version-'||substring(content_digest FROM 8)||'-'||(expected_version+1)::text THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy version input is invalid';
    END IF;
    policy:=iam.lock_customer_policy_publisher(tenant,actor,policy_id);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy-version.create','POLICY',policy_id);
    PERFORM iam.assert_audit_event(event,tenant,'iam.policy-version.created','POLICY',policy_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy version decision is invalid'; END IF;
    replayed:=iam.policy_version_intent_replayed(tenant,actor,event);
    IF replayed THEN
        IF policy.resource_version<>expected_version+1 OR NOT EXISTS(SELECT 1 FROM iam.policy_versions AS v
            WHERE v.policy_id=create_policy_version.policy_id AND v.id=version_id AND v.canonical_document=canonical AND v.content_digest=create_policy_version.content_digest AND v.retired_at IS NULL) THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy version replay conflicts';
        END IF;
        RETURN iam.policy_version_detail(tenant,policy_id,version_id);
    END IF;
    IF policy.resource_version<>expected_version OR EXISTS(SELECT 1 FROM iam.policy_versions AS v WHERE v.policy_id=create_policy_version.policy_id AND (v.id=version_id OR (v.retired_at IS NULL AND v.content_digest=create_policy_version.content_digest)))
       OR (SELECT count(*) FROM iam.policy_versions AS v WHERE v.policy_id=create_policy_version.policy_id AND v.retired_at IS NULL)>=5 THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy version revision or inventory conflicts';
    END IF;
    INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at)
      VALUES(policy_id,version_id,'TENANT',canonical::jsonb,canonical,content_digest,effective_now);
    UPDATE iam.policies AS p SET resource_version=resource_version+1,updated_at=effective_now WHERE p.id=policy_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    RETURN iam.policy_version_detail(tenant,policy_id,version_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.set_default_policy_version(tenant text,actor text,decision text,policy_id text,expected_version bigint,version_id text,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy iam.policies%ROWTYPE; replayed boolean; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740990 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy revision is invalid';
    END IF;
    policy:=iam.lock_customer_policy_publisher(tenant,actor,policy_id);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy.set-default-version','POLICY',policy_id);
    PERFORM iam.assert_audit_event(event,tenant,'iam.policy.default-version-set','POLICY',policy_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy version decision is invalid'; END IF;
    IF NOT EXISTS(SELECT 1 FROM iam.policy_versions AS v WHERE v.policy_id=set_default_policy_version.policy_id AND v.id=version_id AND v.retired_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy version is unavailable';
    END IF;
    replayed:=iam.policy_version_intent_replayed(tenant,actor,event);
    IF replayed THEN
        IF policy.resource_version<>expected_version+1 OR policy.default_version_id<>version_id THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='default policy version replay conflicts';
        END IF;
        RETURN iam.policy_detail_snapshot(tenant,policy_id);
    END IF;
    IF policy.resource_version<>expected_version OR policy.default_version_id=version_id THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='default policy version revision conflicts';
    END IF;
    UPDATE iam.policies AS p SET default_version_id=version_id,resource_version=resource_version+1,updated_at=effective_now WHERE p.id=policy_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    RETURN iam.policy_detail_snapshot(tenant,policy_id);
END $function$;

REVOKE ALL ON FUNCTION iam.policy_version_detail(text,text,text),iam.lock_customer_policy_publisher(text,text,text),iam.policy_version_intent_replayed(text,text,jsonb),
    iam.list_policy_versions(text,text,text,text),iam.read_policy_version(text,text,text,text,text),
    iam.create_policy_version(text,text,text,text,bigint,text,text,text,jsonb),iam.set_default_policy_version(text,text,text,text,bigint,text,jsonb)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.list_policy_versions(text,text,text,text),iam.read_policy_version(text,text,text,text,text),
    iam.create_policy_version(text,text,text,text,bigint,text,text,text,jsonb),iam.set_default_policy_version(text,text,text,text,bigint,text,jsonb) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.update_policy(tenant text,actor text,decision text,policy_id text,expected_version bigint,display_name text,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy iam.policies%ROWTYPE; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740990
       OR display_name IS NULL OR octet_length(display_name) NOT BETWEEN 1 AND 128 OR display_name<>btrim(display_name)
       OR display_name ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy metadata input is invalid';
    END IF;
    policy:=iam.lock_customer_policy_publisher(tenant,actor,policy_id);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy.update','POLICY',policy_id);
    PERFORM iam.assert_audit_event(event,tenant,'iam.policy.updated','POLICY',policy_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy metadata decision is invalid'; END IF;
    IF iam.policy_version_intent_replayed(tenant,actor,event) THEN
        IF policy.resource_version<>expected_version+1 OR policy.display_name<>display_name THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy metadata replay conflicts';
        END IF;
        RETURN iam.policy_detail_snapshot(tenant,policy_id);
    END IF;
    IF policy.resource_version<>expected_version OR policy.display_name=display_name THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy metadata revision conflicts';
    END IF;
    UPDATE iam.policies AS p SET display_name=update_policy.display_name,resource_version=resource_version+1,updated_at=effective_now WHERE p.id=policy_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    RETURN iam.policy_detail_snapshot(tenant,policy_id);
END $function$;
REVOKE ALL ON FUNCTION iam.update_policy(text,text,text,text,bigint,text,jsonb) FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.update_policy(text,text,text,text,bigint,text,jsonb) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.delete_policy(tenant text,actor text,decision text,policy_id text,expected_version bigint,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy iam.policies%ROWTYPE; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740990 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy revision is invalid';
    END IF;
    PERFORM iam.lock_policy_publisher(tenant,actor);
    SELECT * INTO policy FROM iam.policies AS p WHERE p.id=policy_id AND p.owner_tenant_id=tenant
      AND p.management='CUSTOMER' AND p.authority_scope='TENANT' FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy is unavailable'; END IF;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy.delete','POLICY',policy_id);
    PERFORM iam.assert_audit_event(event,tenant,'iam.policy.deleted','POLICY',policy_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy deletion decision is invalid'; END IF;
    IF iam.policy_version_intent_replayed(tenant,actor,event) THEN
        IF policy.status<>'RETIRED' OR policy.resource_version<>expected_version+1 THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy deletion replay conflicts';
        END IF;
        RETURN iam.lookup_policy(tenant,policy_id);
    END IF;
    IF policy.status<>'ACTIVE' OR policy.resource_version<>expected_version OR EXISTS(
        SELECT 1 FROM iam.policy_attachments AS a WHERE a.policy_id=delete_policy.policy_id AND a.revoked_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy revision or live reference conflicts';
    END IF;
    UPDATE iam.policies AS p SET status='RETIRED',resource_version=resource_version+1,updated_at=effective_now WHERE p.id=policy_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    RETURN iam.lookup_policy(tenant,policy_id);
END $function$;
REVOKE ALL ON FUNCTION iam.lock_policy_publisher(text,text),iam.delete_policy(text,text,text,text,bigint,jsonb)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.delete_policy(text,text,text,text,bigint,jsonb) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.delete_policy_version(tenant text,actor text,decision text,policy_id text,version_id text,expected_version bigint,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy iam.policies%ROWTYPE; version iam.policy_versions%ROWTYPE; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740990 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy revision is invalid';
    END IF;
    policy:=iam.lock_customer_policy_publisher(tenant,actor,policy_id);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy-version.delete','POLICY',policy_id);
    PERFORM iam.assert_audit_event(event,tenant,'iam.policy-version.deleted','POLICY',policy_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy version decision is invalid'; END IF;
    SELECT * INTO version FROM iam.policy_versions v WHERE v.policy_id=delete_policy_version.policy_id AND v.id=version_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy version is unavailable'; END IF;
    IF iam.policy_version_intent_replayed(tenant,actor,event) THEN
        IF policy.resource_version<>expected_version+1 OR version.retired_at IS NULL THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy version deletion replay conflicts';
        END IF;
        RETURN iam.policy_detail_snapshot(tenant,policy_id);
    END IF;
    IF policy.resource_version<>expected_version OR version.retired_at IS NOT NULL OR policy.default_version_id=version_id THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy version revision or default conflicts';
    END IF;
    UPDATE iam.policy_versions v SET retired_at=effective_now WHERE v.policy_id=delete_policy_version.policy_id AND v.id=version_id;
    UPDATE iam.policies p SET resource_version=resource_version+1,updated_at=effective_now WHERE p.id=policy_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    RETURN iam.policy_detail_snapshot(tenant,policy_id);
END $function$;
REVOKE ALL ON FUNCTION iam.delete_policy_version(text,text,text,text,text,bigint,jsonb) FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.delete_policy_version(text,text,text,text,text,bigint,jsonb) TO matrix_iam_api;
