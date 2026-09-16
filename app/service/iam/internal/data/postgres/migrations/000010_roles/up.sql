SET LOCAL ROLE matrix_iam_owner;

-- Role state and immutable carrier trust are separate from USER credentials,
-- GROUP membership and identity permission documents.
CREATE OR REPLACE FUNCTION iam.role_metadata_valid(value jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE tag jsonb; keys text[]:='{}'; metadata_bytes integer;
    -- Exact Unicode White_Space/Cc ranges used by Go's public validator;
    -- neither btrim's ASCII default nor locale-dependent POSIX classes suffice.
    whitespace text:=U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000';
BEGIN
    IF value IS NULL OR jsonb_typeof(value)<>'object'
       OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(value) key)
          IS DISTINCT FROM ARRAY['description','maxSessionDurationSeconds','name','tags']
       OR jsonb_typeof(value->'name')<>'string' OR jsonb_typeof(value->'description')<>'string'
       OR octet_length(value->>'name') NOT BETWEEN 1 AND 64 OR btrim(value->>'name',whitespace)<>value->>'name'
       OR octet_length(value->>'description')>512 OR btrim(value->>'description',whitespace)<>value->>'description'
       OR (value->>'name') COLLATE "C" ~ U&'[\0001-\001F\007F-\009F]' OR (value->>'description') COLLATE "C" ~ U&'[\0001-\001F\007F-\009F]'
       OR jsonb_typeof(value->'tags')<>'array' OR jsonb_array_length(value->'tags')>50
       OR jsonb_typeof(value->'maxSessionDurationSeconds')<>'number'
       OR (value->>'maxSessionDurationSeconds') !~ '^[0-9]{2,5}$' THEN RETURN false; END IF;
    IF (value->>'maxSessionDurationSeconds')::bigint NOT BETWEEN 60 AND 43200 THEN RETURN false; END IF;
    metadata_bytes:=octet_length(value->>'name')+octet_length(value->>'description');
    FOR tag IN SELECT item FROM jsonb_array_elements(value->'tags') item LOOP
        IF jsonb_typeof(tag)<>'object' OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(tag) key) IS DISTINCT FROM ARRAY['key','value']
           OR jsonb_typeof(tag->'key')<>'string' OR jsonb_typeof(tag->'value')<>'string'
           OR octet_length(tag->>'key') NOT BETWEEN 1 AND 64 OR octet_length(tag->>'value')>256
           OR (tag->>'key') COLLATE "C" ~ U&'[\0001-\001F\007F-\009F]' OR (tag->>'value') COLLATE "C" ~ U&'[\0001-\001F\007F-\009F]' OR (tag->>'key')=ANY(keys) THEN RETURN false; END IF;
        keys:=array_append(keys,tag->>'key');
        metadata_bytes:=metadata_bytes+octet_length(tag->>'key')+octet_length(tag->>'value');
    END LOOP;
    RETURN metadata_bytes<=4096;
END $function$;

CREATE OR REPLACE FUNCTION iam.role_trust_content_valid(canonical text,content_digest text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE document jsonb; statement jsonb; principal jsonb; sids text[]:='{}'; ids text[]; visits integer:=0;
BEGIN
    IF canonical IS NULL OR octet_length(canonical)>16384 OR canonical IS NOT JSON OBJECT WITH UNIQUE KEYS OR NOT pg_input_is_valid(canonical,'jsonb')
       OR content_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to('matrix.iam.role-trust.v1','UTF8')||decode('00','hex')||convert_to(canonical,'UTF8')),'hex') THEN RETURN false; END IF;
    document:=canonical::jsonb;
    IF jsonb_typeof(document)<>'object' OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(document) key) IS DISTINCT FROM ARRAY['languageVersion','statements']
       OR document->>'languageVersion' IS DISTINCT FROM '1' OR jsonb_typeof(document->'languageVersion')<>'string'
       OR jsonb_typeof(document->'statements')<>'array' OR jsonb_array_length(document->'statements')>8 THEN RETURN false; END IF;
    FOR statement IN SELECT item FROM jsonb_array_elements(document->'statements') item LOOP
        IF jsonb_typeof(statement)<>'object' OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(statement) key) IS DISTINCT FROM ARRAY['effect','principals','sid']
           OR jsonb_typeof(statement->'sid')<>'string' OR (statement->>'sid') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
           OR (statement->>'sid')=ANY(sids) OR jsonb_typeof(statement->'effect')<>'string' OR statement->>'effect' NOT IN ('ALLOW','DENY')
           OR jsonb_typeof(statement->'principals')<>'array' OR jsonb_array_length(statement->'principals') NOT BETWEEN 1 AND 32 THEN RETURN false; END IF;
        sids:=array_append(sids,statement->>'sid'); ids:='{}';
        FOR principal IN SELECT item FROM jsonb_array_elements(statement->'principals') item LOOP
            IF jsonb_typeof(principal)<>'object' OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(principal) key) IS DISTINCT FROM ARRAY['id','type']
               OR principal->>'type' IS DISTINCT FROM 'USER' OR jsonb_typeof(principal->'id')<>'string'
               OR (principal->>'id') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' OR (principal->>'id')=ANY(ids) THEN RETURN false; END IF;
            ids:=array_append(ids,principal->>'id'); visits:=visits+1;
        END LOOP;
    END LOOP;
    RETURN visits<=256;
END $function$;

CREATE TABLE IF NOT EXISTS iam.roles (
    tenant_id text COLLATE "C" NOT NULL REFERENCES iam.accounts(id),
    id text COLLATE "C" NOT NULL,
    metadata jsonb NOT NULL,
    status text NOT NULL CHECK(status IN ('ACTIVE','DISABLED')),
    resource_version bigint NOT NULL CHECK(resource_version BETWEEN 1 AND 9007199254740991),
    current_trust_version_id text COLLATE "C" NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    deleted_at timestamptz(6),
    revoked_attachments_count integer,
    PRIMARY KEY(tenant_id,id),
    CHECK(id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CHECK(iam.role_metadata_valid(metadata)),
    CHECK(updated_at>=created_at AND ((deleted_at IS NULL AND revoked_attachments_count IS NULL)
      OR (deleted_at IS NOT NULL AND deleted_at=updated_at AND resource_version>=2 AND revoked_attachments_count IS NOT NULL AND revoked_attachments_count>=0)))
);
CREATE UNIQUE INDEX IF NOT EXISTS roles_live_name_uq ON iam.roles(tenant_id,((metadata->>'name') COLLATE "C")) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS iam.role_trust_versions (
    tenant_id text COLLATE "C" NOT NULL,
    role_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    canonical_document text NOT NULL,
    content_digest text NOT NULL,
    created_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,role_id,id),
    FOREIGN KEY(tenant_id,role_id) REFERENCES iam.roles(tenant_id,id),
    CHECK(id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CHECK(iam.role_trust_content_valid(canonical_document,content_digest))
);
DO $role_fk$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='iam.roles'::regclass AND conname='roles_current_trust_fk') THEN
        ALTER TABLE iam.roles ADD CONSTRAINT roles_current_trust_fk FOREIGN KEY(tenant_id,id,current_trust_version_id)
            REFERENCES iam.role_trust_versions(tenant_id,role_id,id) DEFERRABLE INITIALLY DEFERRED;
    END IF;
END $role_fk$;

CREATE OR REPLACE FUNCTION iam.guard_role_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF ROW(NEW.tenant_id,NEW.id,NEW.created_at) IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.created_at)
       OR OLD.deleted_at IS NOT NULL OR NEW.resource_version<>OLD.resource_version+1 OR NEW.updated_at<>transaction_timestamp()
       OR (NEW.deleted_at IS NOT NULL AND (NEW.metadata IS DISTINCT FROM OLD.metadata OR NEW.status<>OLD.status
           OR NEW.current_trust_version_id<>OLD.current_trust_version_id)) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role transition is invalid';
    END IF;
    RETURN NEW;
END $function$;

DROP TRIGGER IF EXISTS roles_guard_change ON iam.roles;
CREATE TRIGGER roles_guard_change BEFORE UPDATE ON iam.roles FOR EACH ROW EXECUTE FUNCTION iam.guard_role_change();
ALTER TABLE iam.roles ENABLE ALWAYS TRIGGER roles_guard_change;
DO $role_protection$ DECLARE table_name text; BEGIN
    FOREACH table_name IN ARRAY ARRAY['roles','role_trust_versions'] LOOP
        EXECUTE format('ALTER TABLE iam.%I ENABLE ROW LEVEL SECURITY',table_name);
        EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON iam.%I',table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON iam.%I USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id())',table_name);
        EXECUTE format('DROP TRIGGER IF EXISTS cannot_delete ON iam.%I',table_name);
        EXECUTE format('CREATE TRIGGER cannot_delete BEFORE DELETE ON iam.%I FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change()',table_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER cannot_delete',table_name);
        EXECUTE format('DROP TRIGGER IF EXISTS cannot_truncate ON iam.%I',table_name);
        EXECUTE format('CREATE TRIGGER cannot_truncate BEFORE TRUNCATE ON iam.%I FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change()',table_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER cannot_truncate',table_name);
    END LOOP;
END $role_protection$;
DROP TRIGGER IF EXISTS trust_cannot_update ON iam.role_trust_versions;
CREATE TRIGGER trust_cannot_update BEFORE UPDATE ON iam.role_trust_versions FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.role_trust_versions ENABLE ALWAYS TRIGGER trust_cannot_update;

-- Callers pass a complete trust content commitment, never selector privileges.
-- Lock every real USER in stable order before credential and Role locks.
CREATE OR REPLACE FUNCTION iam.assert_role_writer(tenant text,actor text,actor_session_id text,trust jsonb)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE user_ids text[];
BEGIN
    IF COALESCE(actor_session_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role session reference is invalid'; END IF;
    IF trust IS NOT NULL THEN
        IF jsonb_typeof(trust)<>'object' OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(trust) key) IS DISTINCT FROM ARRAY['canonicalDocument','contentDigest']
           OR jsonb_typeof(trust->'canonicalDocument')<>'string' OR jsonb_typeof(trust->'contentDigest')<>'string'
           OR NOT iam.role_trust_content_valid(trust->>'canonicalDocument',trust->>'contentDigest') THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role trust content is invalid'; END IF;
        SELECT COALESCE(array_agg(DISTINCT principal->>'id'),'{}') INTO user_ids
          FROM jsonb_array_elements((trust->>'canonicalDocument')::jsonb->'statements') statement,
               jsonb_array_elements(statement->'principals') principal;
    ELSE user_ids:='{}'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role account is unavailable'; END IF;
    PERFORM 1 FROM iam.principals p WHERE p.tenant_id=tenant AND (p.id=actor OR p.id=ANY(user_ids)) ORDER BY p.id FOR UPDATE;
    PERFORM 1 FROM iam.principals p JOIN iam.account_roots root ON root.account_id=p.tenant_id AND root.principal_id=p.id
      WHERE p.tenant_id=tenant AND p.id=actor AND p.principal_type='USER' AND p.status='ACTIVE' AND p.deleted_at IS NULL AND NOT p.must_change_password FOR SHARE OF root;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role publisher is unavailable'; END IF;
    PERFORM 1 FROM iam.user_credentials c JOIN iam.sessions s ON s.tenant_id=c.tenant_id AND s.principal_id=c.principal_id
      WHERE c.tenant_id=tenant AND c.principal_id=actor AND s.id=actor_session_id AND s.status='ACTIVE' AND s.revoked_at IS NULL
        AND s.expires_at>clock_timestamp() AND s.credential_version=c.credential_version FOR SHARE OF c,s;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role session is unavailable'; END IF;
    IF (SELECT count(*) FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=ANY(user_ids) AND p.principal_type='USER' AND p.deleted_at IS NULL)<>cardinality(user_ids) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role trust subject is unavailable'; END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.assert_role_intent(tenant text,actor text,event jsonb)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF EXISTS(SELECT 1 FROM iam.audit_outbox fact WHERE fact.tenant_id=tenant
      AND fact.event_document#>>'{actor,id}'=actor AND fact.event_document->>'requestId'=event->>'requestId'
      AND (fact.event_document->>'action'=event->>'action' OR
        (fact.event_document->>'action' IN ('iam.role.disabled','iam.role.enabled') AND event->>'action' IN ('iam.role.disabled','iam.role.enabled')))
      AND (fact.event_document->>'action' IS DISTINCT FROM event->>'action'
        OR fact.event_document->>'requestDigest' IS DISTINCT FROM event->>'requestDigest'
        OR fact.event_document->'target' IS DISTINCT FROM event->'target')) THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role command intent conflicts';
    END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.role_event_matches(tenant text,actor text,event jsonb)
RETURNS boolean LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $function$
    SELECT EXISTS(SELECT 1 FROM iam.audit_outbox fact WHERE fact.tenant_id=tenant
      AND fact.event_document#>>'{actor,id}'=actor AND fact.event_document->>'action'=event->>'action'
      AND fact.event_document->>'requestId'=event->>'requestId'
      AND fact.event_document->>'requestDigest'=event->>'requestDigest'
      AND fact.event_document->'target'=event->'target')
$function$;

CREATE OR REPLACE FUNCTION iam.role_snapshot(tenant text,role_id text)
RETURNS jsonb LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $function$
    SELECT r.metadata||jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','Role','accountId',r.tenant_id,'id',r.id,
      'management','CUSTOMER','status',r.status,'resourceVersion',r.resource_version,'currentTrustVersionId',r.current_trust_version_id,
      'createdAt',r.created_at,'updatedAt',r.updated_at) FROM iam.roles r WHERE r.tenant_id=tenant AND r.id=role_id AND r.deleted_at IS NULL
$function$;
CREATE OR REPLACE FUNCTION iam.role_trust_snapshot(tenant text,role_id text,version_id text)
RETURNS jsonb LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','RoleTrustVersion','id',v.id,'accountId',v.tenant_id,
      'roleId',v.role_id,'document',v.canonical_document::jsonb,'contentDigest',v.content_digest,'createdAt',v.created_at)
      FROM iam.role_trust_versions v WHERE v.tenant_id=tenant AND v.role_id=role_trust_snapshot.role_id AND v.id=version_id
$function$;
CREATE OR REPLACE FUNCTION iam.role_access_snapshot(tenant text,role_id text)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE role_value jsonb; attachments jsonb;
BEGIN
    role_value:=iam.role_snapshot(tenant,role_id); IF role_value IS NULL THEN RETURN NULL; END IF;
    SELECT COALESCE(jsonb_agg(iam.lookup_policy_attachment(tenant,p.id) ORDER BY p.id),'[]') INTO attachments
      FROM (SELECT id FROM iam.policy_attachments WHERE tenant_id=tenant AND target_kind='ROLE' AND target_id=role_id AND revoked_at IS NULL ORDER BY id LIMIT 257) p;
    IF jsonb_array_length(attachments)>256 THEN RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='role attachment directory exceeds its budget'; END IF;
    RETURN jsonb_build_object('role',role_value,'trustVersion',iam.role_trust_snapshot(tenant,role_id,role_value->>'currentTrustVersionId'),'policyAttachments',attachments,'capabilities','[]'::jsonb);
END $function$;

CREATE OR REPLACE FUNCTION iam.list_roles(tenant text,actor text,decision text,after_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.read_account(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.role.list','ACCOUNT',tenant,'INSTANCE',NULL);
    IF COALESCE(after_id,'')<>'' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role page is invalid'; END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('role',iam.role_snapshot(tenant,r.id),'capabilities','[]'::jsonb) ORDER BY r.id),'[]') INTO result
      FROM (SELECT id FROM iam.roles WHERE tenant_id=tenant AND deleted_at IS NULL AND (COALESCE(after_id,'')='' OR id>after_id COLLATE "C") ORDER BY id LIMIT 101) r;
    RETURN result;
END $function$;
CREATE OR REPLACE FUNCTION iam.read_role(tenant text,actor text,decision text,role_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.read_account(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.role.read','ROLE',role_id,'INSTANCE',NULL);
    result:=iam.role_access_snapshot(tenant,role_id);
    IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role is unavailable'; END IF;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.create_role(tenant text,actor text,decision text,role_id text,trust_id text,metadata jsonb,trust jsonb,event jsonb,actor_session_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.roles%ROWTYPE; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF COALESCE(role_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(trust_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR NOT iam.role_metadata_valid(metadata) OR trust IS NULL THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role creation input is invalid'; END IF;
    PERFORM iam.assert_role_writer(tenant,actor,actor_session_id,trust);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.role.create','ACCOUNT',tenant,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(event,tenant,'iam.role.created','ROLE',role_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role decision correlation is invalid'; END IF;
    PERFORM iam.assert_role_intent(tenant,actor,event);
    SELECT * INTO stored FROM iam.roles r WHERE r.tenant_id=tenant AND r.id=role_id FOR UPDATE;
    IF FOUND THEN
        IF stored.deleted_at IS NOT NULL OR stored.resource_version<>1 OR stored.metadata IS DISTINCT FROM metadata OR stored.current_trust_version_id<>trust_id
           OR NOT EXISTS(SELECT 1 FROM iam.role_trust_versions v WHERE v.tenant_id=tenant AND v.role_id=create_role.role_id AND v.id=trust_id
               AND v.canonical_document=trust->>'canonicalDocument' AND v.content_digest=trust->>'contentDigest')
           OR NOT EXISTS(SELECT 1 FROM iam.audit_outbox WHERE tenant_id=tenant AND event_document->>'action'='iam.role.created' AND event_document#>>'{target,id}'=role_id
               AND event_document->>'requestId'=event->>'requestId' AND event_document->>'requestDigest'=event->>'requestDigest' AND event_document#>>'{actor,id}'=actor) THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role creation intent conflicts'; END IF;
        RETURN iam.role_snapshot(tenant,role_id);
    END IF;
    INSERT INTO iam.roles(tenant_id,id,metadata,status,resource_version,current_trust_version_id,created_at,updated_at)
      VALUES(tenant,role_id,metadata,'ACTIVE',1,trust_id,effective_now,effective_now);
    INSERT INTO iam.role_trust_versions(tenant_id,role_id,id,canonical_document,content_digest,created_at)
      VALUES(tenant,role_id,trust_id,trust->>'canonicalDocument',trust->>'contentDigest',effective_now);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    RETURN iam.role_snapshot(tenant,role_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.update_role(tenant text,actor text,decision text,role_id text,expected_version bigint,metadata jsonb,event jsonb,actor_session_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.roles%ROWTYPE;
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740991 OR NOT iam.role_metadata_valid(metadata) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role update input is invalid'; END IF;
    PERFORM iam.assert_role_writer(tenant,actor,actor_session_id,NULL);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.role.update','ROLE',role_id,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(event,tenant,'iam.role.updated','ROLE',role_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role decision correlation is invalid'; END IF;
    PERFORM iam.assert_role_intent(tenant,actor,event);
    SELECT * INTO stored FROM iam.roles r WHERE r.tenant_id=tenant AND r.id=role_id FOR UPDATE;
    IF NOT FOUND OR stored.deleted_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role is unavailable'; END IF;
    IF stored.resource_version=expected_version+1 AND stored.metadata=metadata AND iam.role_event_matches(tenant,actor,event) THEN
        RETURN iam.role_snapshot(tenant,role_id);
    END IF;
    IF stored.resource_version<>expected_version OR stored.resource_version=9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role revision conflicts'; END IF;
    UPDATE iam.roles r SET metadata=update_role.metadata,resource_version=r.resource_version+1,updated_at=transaction_timestamp()
      WHERE r.tenant_id=tenant AND r.id=role_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
    RETURN iam.role_snapshot(tenant,role_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.set_role_status(tenant text,actor text,decision text,role_id text,expected_version bigint,requested_status text,event jsonb,actor_session_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.roles%ROWTYPE; event_action text;
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740991 OR requested_status IS NULL OR requested_status NOT IN ('ACTIVE','DISABLED') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role status input is invalid'; END IF;
    event_action:=CASE requested_status WHEN 'ACTIVE' THEN 'iam.role.enabled' ELSE 'iam.role.disabled' END;
    PERFORM iam.assert_role_writer(tenant,actor,actor_session_id,NULL);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.role.set-status','ROLE',role_id,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(event,tenant,event_action,'ROLE',role_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role decision correlation is invalid'; END IF;
    PERFORM iam.assert_role_intent(tenant,actor,event);
    SELECT * INTO stored FROM iam.roles r WHERE r.tenant_id=tenant AND r.id=role_id FOR UPDATE;
    IF NOT FOUND OR stored.deleted_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role is unavailable'; END IF;
    IF stored.resource_version=expected_version+1 AND stored.status=requested_status AND iam.role_event_matches(tenant,actor,event) THEN
        RETURN iam.role_snapshot(tenant,role_id);
    END IF;
    IF stored.resource_version<>expected_version OR stored.resource_version=9007199254740991 OR stored.status=requested_status THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role status revision conflicts'; END IF;
    UPDATE iam.roles r SET status=requested_status,resource_version=r.resource_version+1,updated_at=transaction_timestamp()
      WHERE r.tenant_id=tenant AND r.id=role_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
    RETURN iam.role_snapshot(tenant,role_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.set_role_trust_policy(tenant text,actor text,decision text,role_id text,trust_id text,expected_version bigint,trust jsonb,event jsonb,actor_session_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.roles%ROWTYPE;
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740991
       OR COALESCE(trust_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' OR trust IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role trust input is invalid'; END IF;
    PERFORM iam.assert_role_writer(tenant,actor,actor_session_id,trust);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.role-trust.set','ROLE',role_id,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(event,tenant,'iam.role.trust-set','ROLE',role_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role decision correlation is invalid'; END IF;
    PERFORM iam.assert_role_intent(tenant,actor,event);
    SELECT * INTO stored FROM iam.roles r WHERE r.tenant_id=tenant AND r.id=role_id FOR UPDATE;
    IF NOT FOUND OR stored.deleted_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role is unavailable'; END IF;
    IF stored.resource_version=expected_version+1 AND stored.current_trust_version_id=trust_id AND iam.role_event_matches(tenant,actor,event)
       AND EXISTS(SELECT 1 FROM iam.role_trust_versions v WHERE v.tenant_id=tenant AND v.role_id=set_role_trust_policy.role_id AND v.id=trust_id
         AND v.canonical_document=trust->>'canonicalDocument' AND v.content_digest=trust->>'contentDigest') THEN
        RETURN iam.role_snapshot(tenant,role_id);
    END IF;
    IF stored.resource_version<>expected_version OR stored.resource_version=9007199254740991
       OR EXISTS(SELECT 1 FROM iam.role_trust_versions v WHERE v.tenant_id=tenant AND v.role_id=set_role_trust_policy.role_id
         AND v.id=stored.current_trust_version_id AND v.content_digest=trust->>'contentDigest') THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role trust revision conflicts'; END IF;
    INSERT INTO iam.role_trust_versions(tenant_id,role_id,id,canonical_document,content_digest,created_at)
      VALUES(tenant,role_id,trust_id,trust->>'canonicalDocument',trust->>'contentDigest',transaction_timestamp());
    UPDATE iam.roles r SET current_trust_version_id=trust_id,resource_version=r.resource_version+1,updated_at=transaction_timestamp()
      WHERE r.tenant_id=tenant AND r.id=role_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
    RETURN iam.role_snapshot(tenant,role_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.delete_role(tenant text,actor text,decision text,role_id text,expected_version bigint,event jsonb,actor_session_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.roles%ROWTYPE; attachment_count integer; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role deletion input is invalid'; END IF;
    PERFORM iam.assert_role_writer(tenant,actor,actor_session_id,NULL);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.role.delete','ROLE',role_id,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(event,tenant,'iam.role.deleted','ROLE',role_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role decision correlation is invalid'; END IF;
    PERFORM iam.assert_role_intent(tenant,actor,event);
    SELECT * INTO stored FROM iam.roles r WHERE r.tenant_id=tenant AND r.id=role_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role is unavailable'; END IF;
    IF stored.deleted_at IS NOT NULL THEN
        IF stored.resource_version<>expected_version+1 OR NOT iam.role_event_matches(tenant,actor,event) THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role deletion intent conflicts'; END IF;
    ELSE
        IF stored.resource_version<>expected_version OR stored.resource_version=9007199254740991 THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role revision conflicts'; END IF;
        PERFORM p.id FROM iam.policy_attachments p WHERE p.tenant_id=tenant AND p.target_kind='ROLE'
          AND p.target_id=role_id AND p.revoked_at IS NULL ORDER BY p.id FOR UPDATE;
        UPDATE iam.policy_attachments p SET resource_version=p.resource_version+1,updated_at=effective_now,revoked_at=effective_now
          WHERE p.tenant_id=tenant AND p.target_kind='ROLE' AND p.target_id=role_id AND p.revoked_at IS NULL;
        GET DIAGNOSTICS attachment_count=ROW_COUNT;
        UPDATE iam.roles r SET resource_version=r.resource_version+1,updated_at=effective_now,deleted_at=effective_now,revoked_attachments_count=attachment_count
          WHERE r.tenant_id=tenant AND r.id=role_id RETURNING * INTO stored;
        INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
          VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','RoleDeletion','accountId',tenant,'id',stored.id,
      'name',stored.metadata->>'name','resourceVersion',stored.resource_version,'revokedPolicyAttachments',stored.revoked_attachments_count,'deletedAt',stored.deleted_at);
END $function$;

CREATE OR REPLACE FUNCTION iam.list_role_trust_versions(tenant text,actor text,decision text,role_id text,after_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.read_role(tenant,actor,decision,role_id);
    IF COALESCE(after_id,'')<>'' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role trust page is invalid'; END IF;
    SELECT COALESCE(jsonb_agg(iam.role_trust_snapshot(tenant,role_id,v.id) ORDER BY v.id),'[]') INTO result
      FROM (SELECT id FROM iam.role_trust_versions WHERE tenant_id=tenant AND role_trust_versions.role_id=list_role_trust_versions.role_id
        AND (COALESCE(after_id,'')='' OR id>after_id COLLATE "C") ORDER BY id LIMIT 101) v;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.read_role_trust_version(tenant text,actor text,decision text,role_id text,version_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.read_role(tenant,actor,decision,role_id);
    result:=iam.role_trust_snapshot(tenant,role_id,version_id);
    IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role trust version is unavailable'; END IF;
    RETURN result;
END $function$;

-- Live readiness and migration verification use the same exact callable
-- contract. Neither metadata drift nor an extra overload is a compatible API.
CREATE OR REPLACE FUNCTION iam.role_contract_ready()
RETURNS boolean LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE table_name text; required record; entrypoint record; signature text; relation_oid oid;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['roles','role_trust_versions'] LOOP
        relation_oid:=to_regclass('iam.'||table_name);
        IF relation_oid IS NULL OR NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=relation_oid
          AND c.relowner='matrix_iam_owner'::regrole AND c.relrowsecurity AND c.relforcerowsecurity) THEN RETURN false; END IF;
        IF EXISTS(SELECT 1 FROM aclexplode(COALESCE((SELECT relacl FROM pg_class WHERE oid=relation_oid),acldefault('r','matrix_iam_owner'::regrole))) permission
          WHERE permission.grantee<>'matrix_iam_owner'::regrole) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('iam.list_roles(text,text,text,text)',false),('iam.read_role(text,text,text,text)',false),
      ('iam.list_role_trust_versions(text,text,text,text,text)',false),('iam.read_role_trust_version(text,text,text,text,text)',false),
      ('iam.create_role(text,text,text,text,text,jsonb,jsonb,jsonb,text)',true),
      ('iam.update_role(text,text,text,text,bigint,jsonb,jsonb,text)',true),
      ('iam.set_role_status(text,text,text,text,bigint,text,jsonb,text)',true),
      ('iam.set_role_trust_policy(text,text,text,text,text,bigint,jsonb,jsonb,text)',true),
      ('iam.delete_role(text,text,text,text,bigint,jsonb,text)',true)) expected(signature,writing) LOOP
        SELECT p.* INTO entrypoint FROM pg_proc p WHERE p.oid=to_regprocedure(required.signature);
        IF NOT FOUND THEN RETURN false; END IF;
        IF (SELECT count(*) FROM pg_proc p WHERE p.pronamespace=entrypoint.pronamespace AND p.proname=entrypoint.proname)<>1
          OR entrypoint.proowner<>'matrix_iam_owner'::regrole OR NOT entrypoint.prosecdef OR entrypoint.proretset
          OR entrypoint.prorettype<>'jsonb'::regtype OR entrypoint.pronargdefaults<>0 OR entrypoint.provariadic<>0
          OR entrypoint.provolatile<>'v' OR entrypoint.proparallel<>'u' OR entrypoint.proisstrict OR entrypoint.proleakproof
          OR entrypoint.proallargtypes IS NOT NULL OR entrypoint.proargmodes IS NOT NULL
          OR entrypoint.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']
          OR (required.writing AND entrypoint.proargnames[entrypoint.pronargs] IS DISTINCT FROM 'actor_session_id')
          OR NOT has_function_privilege('matrix_iam_api',entrypoint.oid,'EXECUTE')
          OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(entrypoint.proacl,acldefault('f',entrypoint.proowner))) permission
            WHERE permission.grantee NOT IN (entrypoint.proowner,'matrix_iam_api'::regrole)
              OR (permission.grantee='matrix_iam_api'::regrole AND permission.is_grantable)) THEN RETURN false; END IF;
    END LOOP;
    FOREACH signature IN ARRAY ARRAY['iam.role_metadata_valid(jsonb)','iam.role_trust_content_valid(text,text)',
      'iam.guard_role_change()','iam.assert_role_writer(text,text,text,jsonb)','iam.role_snapshot(text,text)',
      'iam.role_trust_snapshot(text,text,text)','iam.role_access_snapshot(text,text)',
      'iam.assert_role_intent(text,text,jsonb)','iam.role_event_matches(text,text,jsonb)'] LOOP
        SELECT p.* INTO entrypoint FROM pg_proc p WHERE p.oid=to_regprocedure(signature);
        IF NOT FOUND THEN RETURN false; END IF;
        IF entrypoint.proowner<>'matrix_iam_owner'::regrole OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(entrypoint.proacl,acldefault('f',entrypoint.proowner))) permission
          WHERE permission.grantee<>entrypoint.proowner) THEN RETURN false; END IF;
    END LOOP;
    IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=to_regclass('iam.roles')
      AND c.confrelid=to_regclass('iam.role_trust_versions') AND c.conname='roles_current_trust_fk'
      AND c.contype='f' AND c.convalidated AND c.condeferrable AND c.condeferred) THEN RETURN false; END IF;
    FOR required IN SELECT * FROM (VALUES ('roles','roles_guard_change'),('roles','cannot_delete'),('roles','cannot_truncate'),
      ('role_trust_versions','trust_cannot_update'),('role_trust_versions','cannot_delete'),('role_trust_versions','cannot_truncate')) expected(table_name,trigger_name) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=to_regclass('iam.'||required.table_name)
          AND t.tgname=required.trigger_name AND t.tgenabled='A' AND NOT t.tgisinternal) THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END $function$;

REVOKE ALL ON iam.roles,iam.role_trust_versions FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON FUNCTION iam.role_metadata_valid(jsonb),iam.role_trust_content_valid(text,text),
    iam.guard_role_change(),iam.assert_role_writer(text,text,text,jsonb),iam.role_snapshot(text,text),
    iam.role_trust_snapshot(text,text,text),iam.role_access_snapshot(text,text),
    iam.assert_role_intent(text,text,jsonb),iam.role_event_matches(text,text,jsonb),iam.role_contract_ready(),
    iam.list_roles(text,text,text,text),iam.read_role(text,text,text,text),
    iam.create_role(text,text,text,text,text,jsonb,jsonb,jsonb,text),
    iam.update_role(text,text,text,text,bigint,jsonb,jsonb,text),iam.set_role_status(text,text,text,text,bigint,text,jsonb,text),
    iam.set_role_trust_policy(text,text,text,text,text,bigint,jsonb,jsonb,text),iam.delete_role(text,text,text,text,bigint,jsonb,text),
    iam.list_role_trust_versions(text,text,text,text,text),iam.read_role_trust_version(text,text,text,text,text)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.list_roles(text,text,text,text),iam.read_role(text,text,text,text),
    iam.create_role(text,text,text,text,text,jsonb,jsonb,jsonb,text),
    iam.update_role(text,text,text,text,bigint,jsonb,jsonb,text),iam.set_role_status(text,text,text,text,bigint,text,jsonb,text),
    iam.set_role_trust_policy(text,text,text,text,text,bigint,jsonb,jsonb,text),iam.delete_role(text,text,text,text,bigint,jsonb,text),
    iam.list_role_trust_versions(text,text,text,text,text),iam.read_role_trust_version(text,text,text,text,text) TO matrix_iam_api;
