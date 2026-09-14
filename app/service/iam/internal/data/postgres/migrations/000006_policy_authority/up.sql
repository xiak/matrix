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

CREATE OR REPLACE FUNCTION iam.assert_customer_policy_document(canonical text,content_digest text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE document jsonb; statement jsonb; selected_action jsonb; selector jsonb; seen_sids text[]:='{}'; expected_kind text;
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
           OR statement-ARRAY['sid','effect','actions','resources']<>'{}'::jsonb
           OR jsonb_typeof(statement->'sid') IS DISTINCT FROM 'string'
           OR COALESCE(statement->>'sid','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
           OR statement->>'sid'=ANY(seen_sids) OR COALESCE(statement->>'effect','') NOT IN ('ALLOW','DENY')
           OR jsonb_typeof(statement->'actions') IS DISTINCT FROM 'array'
           OR jsonb_typeof(statement->'resources') IS DISTINCT FROM 'array' THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy statement is invalid';
        END IF;
        seen_sids:=array_append(seen_sids,statement->>'sid');
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
      INTO version FROM iam.policy_versions AS v WHERE v.policy_id=policy_detail_snapshot.policy_id AND v.id=policy->>'defaultVersionId';
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
