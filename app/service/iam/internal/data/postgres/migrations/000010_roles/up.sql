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

-- Roles had no sessions before this cutover. Starting their monotonic counter
-- does not authenticate or assign a generation to any existing USER session.
ALTER TABLE iam.roles ADD COLUMN IF NOT EXISTS security_generation bigint NOT NULL DEFAULT 1
    CONSTRAINT roles_security_generation_range CHECK(security_generation BETWEEN 1 AND 9007199254740991);

CREATE TABLE IF NOT EXISTS iam.role_permission_boundaries (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    role_id text COLLATE "C" NOT NULL,
    policy_id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    revoked_at timestamptz(6),
    PRIMARY KEY(tenant_id,id),
    CONSTRAINT role_boundaries_role_fk FOREIGN KEY(tenant_id,role_id) REFERENCES iam.roles(tenant_id,id),
    CONSTRAINT role_boundaries_policy_fk FOREIGN KEY(policy_id) REFERENCES iam.policies(id),
    CHECK(id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CONSTRAINT role_boundaries_terminal_state CHECK((resource_version=1 AND revoked_at IS NULL AND updated_at=created_at)
       OR (resource_version=2 AND revoked_at IS NOT NULL AND revoked_at=updated_at AND updated_at>=created_at))
);
CREATE UNIQUE INDEX IF NOT EXISTS role_boundaries_current_role_uq
    ON iam.role_permission_boundaries(tenant_id,role_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS role_boundaries_current_policy_idx
    ON iam.role_permission_boundaries(policy_id) WHERE revoked_at IS NULL;

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
    -- Attachment writers already hold this Role lock. Advancing their private
    -- security counter must not manufacture a metadata edit or a public CAS
    -- revision. No other column may change on this path.
    IF OLD.deleted_at IS NULL AND NEW.security_generation=OLD.security_generation+1
       AND to_jsonb(NEW)-'security_generation'=to_jsonb(OLD)-'security_generation' THEN RETURN NEW; END IF;
    IF ROW(NEW.tenant_id,NEW.id,NEW.created_at) IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.created_at)
       OR OLD.deleted_at IS NOT NULL OR NEW.resource_version<>OLD.resource_version+1 OR NEW.updated_at<>transaction_timestamp()
       OR NEW.security_generation NOT IN (OLD.security_generation,OLD.security_generation+1)
       OR (NEW.deleted_at IS NOT NULL AND (NEW.metadata IS DISTINCT FROM OLD.metadata OR NEW.status<>OLD.status
           OR NEW.current_trust_version_id<>OLD.current_trust_version_id)) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role transition is invalid';
    END IF;
    IF NEW.status<>OLD.status OR NEW.current_trust_version_id<>OLD.current_trust_version_id
       OR NEW.metadata->'maxSessionDurationSeconds' IS DISTINCT FROM OLD.metadata->'maxSessionDurationSeconds'
       OR NEW.deleted_at IS NOT NULL THEN
        NEW.security_generation:=OLD.security_generation+1;
    END IF;
    RETURN NEW;
END $function$;

CREATE OR REPLACE FUNCTION iam.guard_role_boundary_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.resource_version<>1 OR NEW.revoked_at IS NOT NULL OR NEW.created_at<>transaction_timestamp()
           OR NEW.updated_at<>NEW.created_at OR NOT EXISTS(SELECT 1 FROM iam.roles r
             WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.role_id AND r.deleted_at IS NULL)
           OR NOT EXISTS(SELECT 1 FROM iam.policies p WHERE p.id=NEW.policy_id AND p.status='ACTIVE'
             AND p.authority_scope='TENANT' AND (p.owner_tenant_id IS NULL OR p.owner_tenant_id=NEW.tenant_id)) THEN
            RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role boundary identity is invalid';
        END IF;
    ELSIF ROW(NEW.tenant_id,NEW.id,NEW.role_id,NEW.policy_id,NEW.created_at)
          IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.role_id,OLD.policy_id,OLD.created_at)
       OR OLD.revoked_at IS NOT NULL OR NEW.resource_version<>OLD.resource_version+1
       OR NEW.revoked_at IS DISTINCT FROM transaction_timestamp() OR NEW.updated_at IS DISTINCT FROM NEW.revoked_at THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role boundary history is immutable';
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS role_boundary_transitions ON iam.role_permission_boundaries;
CREATE TRIGGER role_boundary_transitions BEFORE INSERT OR UPDATE ON iam.role_permission_boundaries
    FOR EACH ROW EXECUTE FUNCTION iam.guard_role_boundary_change();
ALTER TABLE iam.role_permission_boundaries ENABLE ALWAYS TRIGGER role_boundary_transitions;

DROP TRIGGER IF EXISTS roles_guard_change ON iam.roles;
CREATE TRIGGER roles_guard_change BEFORE UPDATE ON iam.roles FOR EACH ROW EXECUTE FUNCTION iam.guard_role_change();
ALTER TABLE iam.roles ENABLE ALWAYS TRIGGER roles_guard_change;
DO $role_protection$ DECLARE table_name text; BEGIN
    FOREACH table_name IN ARRAY ARRAY['roles','role_trust_versions','role_permission_boundaries'] LOOP
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

-- Sparse discovery needs an O(1), non-ABA directory watermark. This is not
-- an account authority revision and readers never lock it for update. All
-- advances are deferred until commit, after existing domain locks. In
-- particular a multi-row User/Group deletion must not take the counter before
-- a remaining relationship lock. No authority or audit evidence uses it.
CREATE TABLE IF NOT EXISTS iam.role_directory_revisions (
    tenant_id text COLLATE "C" PRIMARY KEY REFERENCES iam.accounts(id),
    revision bigint NOT NULL CONSTRAINT role_directory_revision_range CHECK(revision BETWEEN 1 AND 9007199254740991)
);
ALTER TABLE iam.roles NO FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.role_directory_revisions NO FORCE ROW LEVEL SECURITY;
INSERT INTO iam.role_directory_revisions(tenant_id,revision)
    SELECT DISTINCT tenant_id,1 FROM iam.roles ON CONFLICT(tenant_id) DO NOTHING;
ALTER TABLE iam.roles FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.role_directory_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.role_directory_revisions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON iam.role_directory_revisions;
CREATE POLICY tenant_isolation ON iam.role_directory_revisions USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id());

CREATE OR REPLACE FUNCTION iam.guard_role_directory_revision()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF TG_OP<>'UPDATE' OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.revision<>OLD.revision+1 THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role directory revision is irreversible'; END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS role_directory_monotonic ON iam.role_directory_revisions;
CREATE TRIGGER role_directory_monotonic BEFORE UPDATE OR DELETE ON iam.role_directory_revisions FOR EACH ROW EXECUTE FUNCTION iam.guard_role_directory_revision();
ALTER TABLE iam.role_directory_revisions ENABLE ALWAYS TRIGGER role_directory_monotonic;
DROP TRIGGER IF EXISTS cannot_truncate ON iam.role_directory_revisions;
CREATE TRIGGER cannot_truncate BEFORE TRUNCATE ON iam.role_directory_revisions FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.role_directory_revisions ENABLE ALWAYS TRIGGER cannot_truncate;

CREATE OR REPLACE FUNCTION iam.advance_role_directory_revision()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE tenant text;
BEGIN
    IF TG_RELID='iam.roles'::regclass THEN tenant:=NEW.tenant_id;
    ELSIF TG_RELID='iam.policies'::regclass THEN
        IF NEW.management<>'CUSTOMER' OR NEW.authority_scope<>'TENANT' THEN RETURN NEW; END IF;
        tenant:=NEW.owner_tenant_id;
    ELSIF TG_RELID='iam.policy_attachments'::regclass THEN
        IF NEW.authority_scope<>'TENANT' OR NEW.target_kind NOT IN ('USER','GROUP') THEN RETURN NEW; END IF;
        tenant:=NEW.tenant_id;
    ELSIF TG_RELID='iam.group_memberships'::regclass THEN tenant:=NEW.tenant_id;
    ELSE RETURN NEW; END IF;
    -- Deferred triggers run outside the entrypoint's SECURITY DEFINER scope.
    -- Only immutable ownership of the triggering row selects this scope.
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    INSERT INTO iam.role_directory_revisions(tenant_id,revision) VALUES(tenant,1)
        ON CONFLICT(tenant_id) DO UPDATE SET revision=iam.role_directory_revisions.revision+1;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS roles_advance_directory ON iam.roles;
CREATE CONSTRAINT TRIGGER roles_advance_directory AFTER INSERT OR UPDATE ON iam.roles
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.advance_role_directory_revision();
ALTER TABLE iam.roles ENABLE ALWAYS TRIGGER roles_advance_directory;
-- A default/retirement change can affect a Role ceiling without updating the
-- Role itself. Conservatively invalidate this account's directory on every
-- CUSTOMER policy revision, including edits not used by this particular page.
DROP TRIGGER IF EXISTS policies_advance_role_directory ON iam.policies;
CREATE CONSTRAINT TRIGGER policies_advance_role_directory AFTER UPDATE ON iam.policies
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (OLD.resource_version IS DISTINCT FROM NEW.resource_version) EXECUTE FUNCTION iam.advance_role_directory_revision();
ALTER TABLE iam.policies ENABLE ALWAYS TRIGGER policies_advance_role_directory;
-- Active-source snapshots alone miss a newly added Deny that is later
-- revoked, or joining then leaving a group. Both must invalidate old pages.
DROP TRIGGER IF EXISTS attachments_advance_role_directory ON iam.policy_attachments;
CREATE CONSTRAINT TRIGGER attachments_advance_role_directory AFTER INSERT OR UPDATE ON iam.policy_attachments
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.advance_role_directory_revision();
ALTER TABLE iam.policy_attachments ENABLE ALWAYS TRIGGER attachments_advance_role_directory;
DROP TRIGGER IF EXISTS memberships_advance_role_directory ON iam.group_memberships;
CREATE CONSTRAINT TRIGGER memberships_advance_role_directory AFTER INSERT OR UPDATE ON iam.group_memberships
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.advance_role_directory_revision();
ALTER TABLE iam.group_memberships ENABLE ALWAYS TRIGGER memberships_advance_role_directory;
REVOKE ALL ON iam.role_directory_revisions FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON FUNCTION iam.guard_role_directory_revision(),iam.advance_role_directory_revision() FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;

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
    -- Principal keys are immutable. Preserve exclusive state/credential
    -- serialization without upgrading the preceding decision's FK KEY SHARE.
    PERFORM 1 FROM iam.principals p WHERE p.tenant_id=tenant AND (p.id=actor OR p.id=ANY(user_ids)) ORDER BY p.id FOR NO KEY UPDATE;
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
        PERFORM b.id FROM iam.role_permission_boundaries b WHERE b.tenant_id=tenant AND b.role_id=delete_role.role_id
          AND b.revoked_at IS NULL ORDER BY b.id FOR UPDATE;
        UPDATE iam.role_permission_boundaries b SET resource_version=b.resource_version+1,updated_at=effective_now,revoked_at=effective_now
          WHERE b.tenant_id=tenant AND b.role_id=delete_role.role_id AND b.revoked_at IS NULL;
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
CREATE OR REPLACE FUNCTION iam.role_permission_boundary_snapshot(tenant text,role_id text)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.roles%ROWTYPE; binding iam.role_permission_boundaries%ROWTYPE; reference jsonb;
BEGIN
    SELECT * INTO stored FROM iam.roles r WHERE r.tenant_id=tenant AND r.id=role_id AND r.deleted_at IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='boundary role is unavailable'; END IF;
    SELECT * INTO binding FROM iam.role_permission_boundaries b
      WHERE b.tenant_id=tenant AND b.role_id=role_permission_boundary_snapshot.role_id AND b.revoked_at IS NULL;
    IF FOUND THEN
        SELECT jsonb_build_object('policyId',p.id,'versionId',v.id,'contentDigest',v.content_digest) INTO reference
          FROM iam.policies p JOIN iam.policy_versions v ON v.policy_id=p.id AND v.id=p.default_version_id
          WHERE p.id=binding.policy_id AND p.status='ACTIVE' AND p.authority_scope='TENANT'
            AND (p.owner_tenant_id IS NULL OR p.owner_tenant_id=tenant) AND v.retired_at IS NULL AND v.authority_scope='TENANT';
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role boundary policy is unavailable'; END IF;
    END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','RolePermissionBoundary',
      'accountId',tenant,'roleId',role_id,'resourceVersion',stored.resource_version,'policy',reference);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_role_permission_boundary(tenant text,actor text,decision text,role_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.role.read','ROLE',role_id,'INSTANCE',NULL);
    RETURN iam.role_permission_boundary_snapshot(tenant,role_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.change_role_permission_boundary(tenant text,actor text,decision text,role_id text,
    expected_version bigint,policy_id text,expected_policy_version bigint,boundary_id text,event jsonb,actor_session_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.roles%ROWTYPE; current_binding iam.role_permission_boundaries%ROWTYPE; policy iam.policies%ROWTYPE;
    previous jsonb; action_name text; fact_name text; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740990
       OR policy_id IS NULL OR boundary_id IS NULL OR expected_policy_version IS NULL
       OR (policy_id='' AND (boundary_id<>'' OR expected_policy_version<>0))
       OR (policy_id<>'' AND (policy_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
          OR boundary_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' OR expected_policy_version NOT BETWEEN 1 AND 9007199254740991)) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role boundary mutation is invalid';
    END IF;
    PERFORM iam.assert_role_writer(tenant,actor,actor_session_id,NULL);
    SELECT * INTO stored FROM iam.roles r WHERE r.tenant_id=tenant AND r.id=role_id FOR UPDATE;
    IF NOT FOUND OR stored.deleted_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='boundary role is unavailable'; END IF;
    action_name:=CASE WHEN policy_id='' THEN 'iam.role.permission-boundary.remove' ELSE 'iam.role.permission-boundary.set' END;
    fact_name:=CASE WHEN policy_id='' THEN 'iam.role.permission-boundary.removed' ELSE 'iam.role.permission-boundary.set' END;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,action_name,'ROLE',role_id,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(event,tenant,fact_name,'ROLE',role_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='boundary decision is invalid'; END IF;
    SELECT * INTO current_binding FROM iam.role_permission_boundaries b
      WHERE b.tenant_id=tenant AND b.role_id=change_role_permission_boundary.role_id AND b.revoked_at IS NULL;
    -- Same Role -> Policy -> relationship order as Role attachment writers.
    PERFORM 1 FROM iam.policies p WHERE p.id IN(policy_id,current_binding.policy_id) ORDER BY p.id FOR UPDATE;
    IF policy_id<>'' THEN
        SELECT * INTO policy FROM iam.policies p WHERE p.id=change_role_permission_boundary.policy_id
          AND p.status='ACTIVE' AND p.authority_scope='TENANT' AND (p.owner_tenant_id IS NULL OR p.owner_tenant_id=tenant);
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='boundary policy is unavailable'; END IF;
        IF policy.resource_version<>expected_policy_version THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='boundary policy revision conflicts'; END IF;
    END IF;
    PERFORM 1 FROM iam.role_permission_boundaries b WHERE b.tenant_id=tenant AND b.id=current_binding.id FOR UPDATE;
    SELECT event_document INTO previous FROM iam.audit_outbox o WHERE o.tenant_id=tenant
      AND o.event_document->>'action' IN ('iam.role.permission-boundary.set','iam.role.permission-boundary.removed')
      AND o.event_document#>>'{actor,id}'=actor AND o.event_document->>'requestId'=event->>'requestId';
    IF FOUND THEN
        IF previous->>'action' IS DISTINCT FROM fact_name OR previous->>'requestDigest' IS DISTINCT FROM event->>'requestDigest'
           OR previous->'target' IS DISTINCT FROM event->'target' OR stored.resource_version<>expected_version+1
           OR (policy_id='' AND current_binding.id IS NOT NULL)
           OR (policy_id<>'' AND (current_binding.id IS DISTINCT FROM boundary_id OR current_binding.policy_id IS DISTINCT FROM policy_id)) THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role boundary command replay conflicts';
        END IF;
        RETURN iam.role_permission_boundary_snapshot(tenant,role_id);
    END IF;
    IF stored.resource_version<>expected_version OR stored.security_generation=9007199254740991
       OR (policy_id='' AND current_binding.id IS NULL) OR (policy_id<>'' AND current_binding.policy_id=policy_id) THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role boundary revision or state conflicts';
    END IF;
    IF current_binding.id IS NOT NULL THEN
        UPDATE iam.role_permission_boundaries b SET resource_version=b.resource_version+1,updated_at=effective_now,revoked_at=effective_now
          WHERE b.tenant_id=tenant AND b.id=current_binding.id;
    END IF;
    IF policy_id<>'' THEN
        INSERT INTO iam.role_permission_boundaries(tenant_id,id,role_id,policy_id,resource_version,created_at,updated_at)
          VALUES(tenant,boundary_id,role_id,policy_id,1,effective_now,effective_now);
    END IF;
    UPDATE iam.roles r SET resource_version=r.resource_version+1,security_generation=r.security_generation+1,updated_at=effective_now
      WHERE r.tenant_id=tenant AND r.id=role_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    RETURN iam.role_permission_boundary_snapshot(tenant,role_id);
END $function$;

-- Issuance is its own immutable identity, never a USER session or password.
-- Source authorization changes need their own irreversible clock. Active
-- policy snapshots alone cannot retain a Deny that was added and removed.
-- Separate rows keep late updates away from principal/group business locks.
DO $source_authority_cutover$
BEGIN
    IF to_regclass('iam.role_source_authority_generations') IS NULL THEN
        CREATE TABLE iam.role_source_authority_generations (
            tenant_id text COLLATE "C" NOT NULL REFERENCES iam.accounts(id),
            user_id text COLLATE "C",
            group_id text COLLATE "C",
            generation bigint NOT NULL,
            CONSTRAINT role_source_exact_kind CHECK((user_id IS NULL)<>(group_id IS NULL)),
            CONSTRAINT role_source_generation_range CHECK(generation BETWEEN 1 AND 9007199254740991),
            UNIQUE(tenant_id,user_id), UNIQUE(tenant_id,group_id),
            FOREIGN KEY(tenant_id,user_id) REFERENCES iam.principals(tenant_id,id),
            FOREIGN KEY(tenant_id,group_id) REFERENCES iam.groups(tenant_id,id)
        );
        ALTER TABLE iam.principals NO FORCE ROW LEVEL SECURITY;
        ALTER TABLE iam.groups NO FORCE ROW LEVEL SECURITY;
        INSERT INTO iam.role_source_authority_generations(tenant_id,user_id,generation)
          SELECT tenant_id,id,1 FROM iam.principals WHERE principal_type='USER';
        INSERT INTO iam.role_source_authority_generations(tenant_id,group_id,generation)
          SELECT tenant_id,id,1 FROM iam.groups;
        ALTER TABLE iam.principals FORCE ROW LEVEL SECURITY;
        ALTER TABLE iam.groups FORCE ROW LEVEL SECURITY;
    END IF;
END $source_authority_cutover$;
ALTER TABLE iam.role_source_authority_generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.role_source_authority_generations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON iam.role_source_authority_generations;
CREATE POLICY tenant_isolation ON iam.role_source_authority_generations
  USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id());

CREATE OR REPLACE FUNCTION iam.guard_role_source_authority_generation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.generation<>1 OR (NEW.user_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM iam.principals p
            WHERE p.tenant_id=NEW.tenant_id AND p.id=NEW.user_id AND p.principal_type='USER')) THEN
            RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role source authority identity is invalid'; END IF;
    ELSIF TG_OP<>'UPDATE' OR ROW(NEW.tenant_id,NEW.user_id,NEW.group_id) IS DISTINCT FROM ROW(OLD.tenant_id,OLD.user_id,OLD.group_id)
       OR NEW.generation<>OLD.generation+1 THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role source authority is irreversible';
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS source_authority_monotonic ON iam.role_source_authority_generations;
CREATE TRIGGER source_authority_monotonic BEFORE INSERT OR UPDATE OR DELETE ON iam.role_source_authority_generations
  FOR EACH ROW EXECUTE FUNCTION iam.guard_role_source_authority_generation();
ALTER TABLE iam.role_source_authority_generations ENABLE ALWAYS TRIGGER source_authority_monotonic;
DROP TRIGGER IF EXISTS cannot_truncate ON iam.role_source_authority_generations;
CREATE TRIGGER cannot_truncate BEFORE TRUNCATE ON iam.role_source_authority_generations
  FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.role_source_authority_generations ENABLE ALWAYS TRIGGER cannot_truncate;

CREATE OR REPLACE FUNCTION iam.advance_role_source_authority_generation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE tenant text; source_user text; source_group text; initializing boolean:=false;
BEGIN
    IF TG_RELID='iam.principals'::regclass THEN
        IF TG_OP<>'INSERT' OR NEW.principal_type<>'USER' THEN RETURN NEW; END IF;
        tenant:=NEW.tenant_id; source_user:=NEW.id; initializing:=true;
    ELSIF TG_RELID='iam.groups'::regclass THEN
        IF TG_OP<>'INSERT' THEN RETURN NEW; END IF;
        tenant:=NEW.tenant_id; source_group:=NEW.id; initializing:=true;
    ELSIF TG_RELID='iam.policy_attachments'::regclass THEN
        tenant:=NEW.tenant_id;
        IF NEW.target_kind='USER' THEN source_user:=NEW.target_id;
        ELSIF NEW.target_kind='GROUP' THEN source_group:=NEW.target_id;
        ELSE RETURN NEW; END IF;
    ELSIF TG_RELID IN ('iam.group_memberships'::regclass,'iam.user_permission_boundaries'::regclass) THEN
        tenant:=NEW.tenant_id; source_user:=NEW.user_id;
    ELSE RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role source authority producer is invalid'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    IF initializing THEN
        -- Only a newly inserted, not-yet-visible identity can initialize a key.
        INSERT INTO iam.role_source_authority_generations(tenant_id,user_id,group_id,generation)
          VALUES(tenant,source_user,source_group,1);
        RETURN NEW;
    END IF;
    -- Explicit barrier BEFORE any counter lock, including multi-user cascades.
    -- Its numeric value is neither read nor stored as session authority.
    INSERT INTO iam.role_directory_revisions(tenant_id,revision) VALUES(tenant,1) ON CONFLICT(tenant_id) DO NOTHING;
    PERFORM 1 FROM iam.role_directory_revisions WHERE tenant_id=tenant FOR UPDATE;
    UPDATE iam.role_source_authority_generations g SET generation=g.generation+1
      WHERE g.tenant_id=tenant AND g.user_id IS NOT DISTINCT FROM source_user AND g.group_id IS NOT DISTINCT FROM source_group;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='role source authority is unavailable'; END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS principals_initialize_role_source ON iam.principals;
CREATE CONSTRAINT TRIGGER principals_initialize_role_source AFTER INSERT ON iam.principals
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.advance_role_source_authority_generation();
DROP TRIGGER IF EXISTS groups_initialize_role_source ON iam.groups;
CREATE CONSTRAINT TRIGGER groups_initialize_role_source AFTER INSERT ON iam.groups
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.advance_role_source_authority_generation();
DROP TRIGGER IF EXISTS attachments_advance_role_source ON iam.policy_attachments;
CREATE CONSTRAINT TRIGGER attachments_advance_role_source AFTER INSERT OR UPDATE ON iam.policy_attachments
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.advance_role_source_authority_generation();
DROP TRIGGER IF EXISTS memberships_advance_role_source ON iam.group_memberships;
CREATE CONSTRAINT TRIGGER memberships_advance_role_source AFTER INSERT OR UPDATE ON iam.group_memberships
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.advance_role_source_authority_generation();
DROP TRIGGER IF EXISTS boundaries_advance_role_source ON iam.user_permission_boundaries;
CREATE CONSTRAINT TRIGGER boundaries_advance_role_source AFTER INSERT OR UPDATE ON iam.user_permission_boundaries
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.advance_role_source_authority_generation();
ALTER TABLE iam.principals ENABLE ALWAYS TRIGGER principals_initialize_role_source;
ALTER TABLE iam.groups ENABLE ALWAYS TRIGGER groups_initialize_role_source;
ALTER TABLE iam.policy_attachments ENABLE ALWAYS TRIGGER attachments_advance_role_source;
ALTER TABLE iam.group_memberships ENABLE ALWAYS TRIGGER memberships_advance_role_source;
ALTER TABLE iam.user_permission_boundaries ENABLE ALWAYS TRIGGER boundaries_advance_role_source;

CREATE OR REPLACE FUNCTION iam.role_source_authority_snapshot(tenant text,source_user text)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE source_generation bigint; group_generation bigint; member record; groups jsonb:='[]';
BEGIN
    SELECT generation INTO source_generation FROM iam.role_source_authority_generations g
      WHERE g.tenant_id=tenant AND g.user_id=source_user FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='role source authority is unavailable'; END IF;
    -- Include every effective membership, even groups with no policy yet.
    -- Take no Group business lock after the existing Role lock.
    FOR member IN SELECT m.id,m.group_id,m.resource_version FROM iam.group_memberships m
        JOIN iam.groups g ON g.tenant_id=m.tenant_id AND g.id=m.group_id AND g.deleted_at IS NULL
        WHERE m.tenant_id=tenant AND m.user_id=source_user AND m.removed_at IS NULL ORDER BY m.group_id LIMIT 101 LOOP
        IF jsonb_array_length(groups)=100 THEN RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='role source memberships exceed their budget'; END IF;
        SELECT generation INTO group_generation FROM iam.role_source_authority_generations g
          WHERE g.tenant_id=tenant AND g.group_id=member.group_id FOR SHARE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='role group authority is unavailable'; END IF;
        groups:=groups||jsonb_build_array(jsonb_build_object('groupId',member.group_id,'membershipId',member.id,
          'membershipResourceVersion',member.resource_version,'authorizationGeneration',group_generation));
    END LOOP;
    RETURN jsonb_build_object('userGeneration',source_generation,'groups',groups);
END $function$;
REVOKE ALL ON iam.role_source_authority_generations FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON FUNCTION iam.guard_role_source_authority_generation(),iam.advance_role_source_authority_generation(),iam.role_source_authority_snapshot(text,text)
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;

CREATE TABLE IF NOT EXISTS iam.role_sessions (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    role_id text COLLATE "C" NOT NULL,
    source_user_id text COLLATE "C" NOT NULL,
    source_session_id text COLLATE "C" NOT NULL,
    credential_generation bigint NOT NULL CHECK(credential_generation BETWEEN 1 AND 9007199254740991),
    security_generation bigint NOT NULL CHECK(security_generation BETWEEN 1 AND 9007199254740991),
    authority_contract_version integer NOT NULL,
    source_authorization_generation bigint,
    source_group_generations jsonb,
    trust_version_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_digest text NOT NULL CHECK(request_digest ~ '^sha256:[0-9a-f]{64}$'),
    verification_digest text NOT NULL CHECK(verification_digest ~ '^sha256:[0-9a-f]{64}$'),
    decision_id text COLLATE "C" NOT NULL,
    authority_evidence jsonb NOT NULL CHECK(jsonb_typeof(authority_evidence)='object'),
    session_policy_canonical text,
    session_policy_digest text,
    issued_at timestamptz(6) NOT NULL,
    expires_at timestamptz(6) NOT NULL,
    revoked_at timestamptz(6),
    PRIMARY KEY(tenant_id,id),
    UNIQUE(tenant_id,source_user_id,request_id),
    FOREIGN KEY(tenant_id,role_id) REFERENCES iam.roles(tenant_id,id),
    FOREIGN KEY(tenant_id,source_user_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(tenant_id,source_session_id) REFERENCES iam.sessions(tenant_id,id),
    FOREIGN KEY(tenant_id,role_id,trust_version_id) REFERENCES iam.role_trust_versions(tenant_id,role_id,id),
    FOREIGN KEY(tenant_id,decision_id) REFERENCES iam.authorization_decisions(tenant_id,id),
    CHECK(id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '12 hours' AND (revoked_at IS NULL OR revoked_at>=issued_at)),
    CHECK((session_policy_canonical IS NULL AND session_policy_digest IS NULL) OR
      (session_policy_canonical IS NOT NULL AND session_policy_digest IS NOT NULL AND session_policy_digest ~ '^sha256:[0-9a-f]{64}$'))
);
DO $role_authority_contract_cutover$
DECLARE original record;
BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='iam.role_sessions'::regclass
      AND attname='authority_contract_version' AND NOT attisdropped) THEN
        LOCK TABLE iam.role_sessions IN ACCESS EXCLUSIVE MODE;
        -- Only complete, actually retained issuances may receive the old
        -- interpretation marker. Do not manufacture current generation proof.
        ALTER TABLE iam.role_sessions NO FORCE ROW LEVEL SECURITY;
        FOR original IN SELECT tenant_id,id FROM iam.role_sessions LOOP
            PERFORM set_config('matrix.iam_tenant_id',original.tenant_id,true);
            IF iam.role_authorization_evidence(original.tenant_id,original.id) IS NULL THEN
                RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='retained role authority is incomplete'; END IF;
        END LOOP;
        ALTER TABLE iam.role_sessions ADD COLUMN authority_contract_version integer;
        ALTER TABLE iam.role_sessions DISABLE TRIGGER role_session_terminal_state;
        UPDATE iam.role_sessions SET authority_contract_version=1;
        ALTER TABLE iam.role_sessions ENABLE ALWAYS TRIGGER role_session_terminal_state;
        ALTER TABLE iam.role_sessions ALTER COLUMN authority_contract_version SET NOT NULL;
        ALTER TABLE iam.role_sessions FORCE ROW LEVEL SECURITY;
    END IF;
END $role_authority_contract_cutover$;
ALTER TABLE iam.role_sessions ADD COLUMN IF NOT EXISTS source_authorization_generation bigint;
ALTER TABLE iam.role_sessions ADD COLUMN IF NOT EXISTS source_group_generations jsonb;
ALTER TABLE iam.role_sessions DROP CONSTRAINT IF EXISTS role_sessions_authority_contract;
ALTER TABLE iam.role_sessions ADD CONSTRAINT role_sessions_authority_contract CHECK(
    (authority_contract_version=1 AND source_authorization_generation IS NULL AND source_group_generations IS NULL)
    OR (authority_contract_version=2 AND source_authorization_generation IS NOT NULL
      AND source_authorization_generation BETWEEN 1 AND 9007199254740991
      AND source_group_generations IS NOT NULL AND jsonb_typeof(source_group_generations)='array'
      AND jsonb_array_length(source_group_generations)<=100));
CREATE INDEX IF NOT EXISTS role_sessions_live_account_idx ON iam.role_sessions(tenant_id,expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS role_sessions_live_user_idx ON iam.role_sessions(tenant_id,source_user_id,expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS role_sessions_live_role_idx ON iam.role_sessions(tenant_id,role_id,expires_at) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS iam.role_session_index (
    lookup_digest text COLLATE "C" PRIMARY KEY CHECK(lookup_digest ~ '^sha256:[0-9a-f]{64}$'),
    tenant_id text COLLATE "C" NOT NULL,
    session_id text COLLATE "C" NOT NULL,
    UNIQUE(tenant_id,session_id),
    FOREIGN KEY(tenant_id,session_id) REFERENCES iam.role_sessions(tenant_id,id)
);
ALTER TABLE iam.role_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.role_sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON iam.role_sessions;
CREATE POLICY tenant_isolation ON iam.role_sessions USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id());
CREATE OR REPLACE FUNCTION iam.guard_role_session_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.authority_contract_version IS DISTINCT FROM 2
          OR jsonb_build_object('userGeneration',NEW.source_authorization_generation,'groups',NEW.source_group_generations)
             IS DISTINCT FROM iam.role_source_authority_snapshot(NEW.tenant_id,NEW.source_user_id) THEN
            RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role source authority is invalid'; END IF;
        RETURN NEW;
    END IF;
    IF TG_OP<>'UPDATE' THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role issuance history is immutable'; END IF;
    IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS DISTINCT FROM transaction_timestamp()
       OR to_jsonb(NEW)-'revoked_at' IS DISTINCT FROM to_jsonb(OLD)-'revoked_at' THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role issuance history is immutable'; END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS role_session_terminal_state ON iam.role_sessions;
CREATE TRIGGER role_session_terminal_state BEFORE INSERT OR UPDATE OR DELETE ON iam.role_sessions FOR EACH ROW EXECUTE FUNCTION iam.guard_role_session_change();
ALTER TABLE iam.role_sessions ENABLE ALWAYS TRIGGER role_session_terminal_state;
DROP TRIGGER IF EXISTS role_sessions_cannot_truncate ON iam.role_sessions;
CREATE TRIGGER role_sessions_cannot_truncate BEFORE TRUNCATE ON iam.role_sessions FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.role_sessions ENABLE ALWAYS TRIGGER role_sessions_cannot_truncate;
DROP TRIGGER IF EXISTS role_session_index_immutable ON iam.role_session_index;
CREATE TRIGGER role_session_index_immutable BEFORE UPDATE OR DELETE ON iam.role_session_index FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.role_session_index ENABLE ALWAYS TRIGGER role_session_index_immutable;
DROP TRIGGER IF EXISTS role_session_index_cannot_truncate ON iam.role_session_index;
CREATE TRIGGER role_session_index_cannot_truncate BEFORE TRUNCATE ON iam.role_session_index FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.role_session_index ENABLE ALWAYS TRIGGER role_session_index_cannot_truncate;

-- Issuance takes the Account lock exclusively to serialize its three quotas.
-- Ordinary authentication/authorization does not take this exclusive lock.
-- All paths then follow Account -> USER -> credential/session -> Role order.
CREATE OR REPLACE FUNCTION iam.assert_role_session_source(tenant text,actor text,source_session text,issuing boolean)
RETURNS bigint LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE generation bigint;
BEGIN
    IF COALESCE(source_session,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role source session is invalid'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    IF issuing THEN
        PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR UPDATE;
    ELSE
        PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR SHARE;
    END IF;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role source account is unavailable'; END IF;
    PERFORM 1 FROM iam.principals WHERE tenant_id=tenant AND id=actor AND principal_type='USER'
      AND status='ACTIVE' AND deleted_at IS NULL AND NOT must_change_password FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role source user is unavailable'; END IF;
    SELECT c.credential_version INTO generation FROM iam.user_credentials c JOIN iam.sessions s ON s.tenant_id=c.tenant_id AND s.principal_id=c.principal_id
      WHERE c.tenant_id=tenant AND c.principal_id=actor AND s.id=source_session AND s.status='ACTIVE' AND s.revoked_at IS NULL
        AND s.credential_version=c.credential_version AND s.expires_at>clock_timestamp() FOR SHARE OF c,s;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role source session is unavailable'; END IF;
    RETURN generation;
END $function$;

CREATE OR REPLACE FUNCTION iam.role_session_snapshot(tenant text,session_id text)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','RoleSession','id',s.id,
      'accountId',s.tenant_id,'roleId',s.role_id,'sourceUserId',s.source_user_id,'status',CASE WHEN s.revoked_at IS NULL THEN 'ACTIVE' ELSE 'REVOKED' END,
      'issuedAt',s.issued_at,'expiresAt',s.expires_at,'revokedAt',s.revoked_at)) FROM iam.role_sessions s WHERE s.tenant_id=tenant AND s.id=session_id
$function$;

CREATE OR REPLACE FUNCTION iam.read_role_assumption(tenant text,actor text,source_session text,role_id text,request_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE generation bigint; previous iam.role_sessions%ROWTYPE; role_value iam.roles%ROWTYPE;
BEGIN
    generation:=iam.assert_role_session_source(tenant,actor,source_session,true);
    IF COALESCE(request_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role intent is invalid'; END IF;
    SELECT * INTO previous FROM iam.role_sessions s WHERE s.tenant_id=tenant AND s.source_user_id=actor AND s.request_id=read_role_assumption.request_id;
    IF FOUND THEN
        RETURN jsonb_build_object('credentialGeneration',generation,'existing',jsonb_build_object(
          'session',iam.role_session_snapshot(tenant,previous.id),'sourceSessionId',previous.source_session_id,
          'credentialGeneration',previous.credential_generation,'requestDigest',previous.request_digest));
    END IF;
    SELECT * INTO role_value FROM iam.roles r WHERE r.tenant_id=tenant AND r.id=role_id AND r.deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role is unavailable'; END IF;
    RETURN jsonb_build_object('credentialGeneration',generation,'securityGeneration',role_value.security_generation,
      'role',iam.role_snapshot(tenant,role_id),'trust',iam.role_trust_snapshot(tenant,role_id,role_value.current_trust_version_id));
END $function$;

-- Read-only self discovery deliberately does not call the issuance reader or
-- assert_role_session_source: neither the account quota lock nor USER UPDATE
-- lock nor an issuance request ID belongs to this projection.
CREATE OR REPLACE FUNCTION iam.read_role_discovery_revision(tenant text,actor text,source_session text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE generation bigint; directory_revision bigint;
BEGIN
    IF COALESCE(tenant,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(actor,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(source_session,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role discovery source is invalid'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role discovery source is unavailable'; END IF;
    PERFORM 1 FROM iam.principals WHERE tenant_id=tenant AND id=actor AND principal_type='USER'
      AND status='ACTIVE' AND deleted_at IS NULL AND NOT must_change_password FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role discovery source is unavailable'; END IF;
    SELECT c.credential_version INTO generation FROM iam.user_credentials c JOIN iam.sessions s ON s.tenant_id=c.tenant_id AND s.principal_id=c.principal_id
      WHERE c.tenant_id=tenant AND c.principal_id=actor AND s.id=source_session AND s.status='ACTIVE' AND s.revoked_at IS NULL
        AND s.credential_version=c.credential_version AND s.expires_at>clock_timestamp() FOR SHARE OF c,s;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role discovery source is unavailable'; END IF;
    SELECT revision INTO directory_revision FROM iam.role_directory_revisions WHERE tenant_id=tenant FOR SHARE;
    IF NOT FOUND THEN
        IF EXISTS(SELECT 1 FROM iam.roles WHERE tenant_id=tenant) THEN
            RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='role discovery revision is unavailable'; END IF;
        directory_revision:=0;
    END IF;
    RETURN jsonb_build_object('credentialGeneration',generation,'directoryRevision',directory_revision);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_role_candidates(tenant text,actor text,source_session text,after_id text,role_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE revision jsonb; candidate record; boundary iam.role_permission_boundaries%ROWTYPE;
    policy iam.policies%ROWTYPE; version iam.policy_versions%ROWTYPE; boundary_value jsonb;
    items jsonb:='[]'; next_after text:=''; previous_id text:='';
BEGIN
    revision:=iam.read_role_discovery_revision(tenant,actor,source_session);
    IF after_id IS NULL OR role_id IS NULL OR (after_id<>'' AND role_id<>'')
      OR (after_id<>'' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
      OR (role_id<>'' AND role_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role discovery query is invalid'; END IF;
    FOR candidate IN SELECT r.id,r.current_trust_version_id FROM iam.roles r WHERE r.tenant_id=tenant AND r.deleted_at IS NULL
        AND (after_id='' OR r.id>after_id COLLATE "C") AND (role_id='' OR r.id=role_id) ORDER BY r.id LIMIT 21 LOOP
        IF jsonb_array_length(items)=20 THEN next_after:=previous_id; EXIT; END IF;
        boundary_value:=NULL;
        SELECT * INTO boundary FROM iam.role_permission_boundaries b WHERE b.tenant_id=tenant AND b.role_id=candidate.id AND b.revoked_at IS NULL;
        IF FOUND THEN
            SELECT * INTO policy FROM iam.policies p WHERE p.id=boundary.policy_id AND p.status='ACTIVE' AND p.authority_scope='TENANT'
              AND (p.owner_tenant_id IS NULL OR p.owner_tenant_id=tenant);
            IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='role discovery ceiling is unavailable'; END IF;
            SELECT * INTO version FROM iam.policy_versions v WHERE v.policy_id=policy.id AND v.id=policy.default_version_id AND v.retired_at IS NULL;
            IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='role discovery ceiling is unavailable'; END IF;
            boundary_value:=jsonb_build_object('boundaryId',boundary.id,'resourceVersion',boundary.resource_version,
              'policy',iam.lookup_policy(tenant,policy.id),'version',iam.policy_version_snapshot(version));
        END IF;
        items:=items||jsonb_build_array(jsonb_build_object('role',iam.role_snapshot(tenant,candidate.id),
          'trust',iam.role_trust_snapshot(tenant,candidate.id,candidate.current_trust_version_id),'boundary',boundary_value));
        previous_id:=candidate.id;
    END LOOP;
    IF role_id<>'' AND jsonb_array_length(items)<>1 THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role discovery target is unavailable'; END IF;
    RETURN jsonb_build_object('revision',revision,'items',items,'nextAfter',next_after);
END $function$;
REVOKE ALL ON FUNCTION iam.read_role_discovery_revision(text,text,text),iam.read_role_candidates(text,text,text,text,text)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.read_role_discovery_revision(text,text,text),iam.read_role_candidates(text,text,text,text,text) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.role_policy_snapshot(tenant text,role_id text)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT COALESCE(jsonb_agg(jsonb_build_object('policy',iam.lookup_policy(tenant,p.id),
      'version',iam.policy_version_snapshot(v),'attachment',iam.lookup_policy_attachment(tenant,a.id)) ORDER BY a.id),'[]'::jsonb)
    FROM (SELECT * FROM iam.policy_attachments WHERE tenant_id=tenant AND target_kind='ROLE' AND target_id=role_id AND revoked_at IS NULL ORDER BY id LIMIT 257) a
    JOIN iam.policies p ON p.id=a.policy_id AND p.status='ACTIVE'
    JOIN iam.policy_versions v ON v.policy_id=p.id AND v.id=p.default_version_id AND v.retired_at IS NULL
$function$;

CREATE OR REPLACE FUNCTION iam.issue_role_session(tenant text,actor text,source_session text,role_id text,decision text,
    intent jsonb,lookup_digest text,verification_digest text,session_policy jsonb,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE admission jsonb; selected iam.roles%ROWTYPE; trust jsonb; boundary iam.role_permission_boundaries%ROWTYPE;
    boundary_policy iam.policies%ROWTYPE; boundary_version iam.policy_versions%ROWTYPE;
    deadline timestamptz(6); source_expiry timestamptz(6); now_at timestamptz(6):=transaction_timestamp(); evidence jsonb;
    session_id text; canonical text; content_digest text; role_policies jsonb; source_authority jsonb;
BEGIN
    IF intent IS NULL OR jsonb_typeof(intent)<>'object' OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(intent) key)
      IS DISTINCT FROM ARRAY['credentialGeneration','durationSeconds','expiresAt','issuedAt','requestDigest','requestId','resourceVersion','securityGeneration','sessionId']
      OR COALESCE(intent->>'sessionId','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(intent->>'requestDigest','') !~ '^sha256:[0-9a-f]{64}$'
      OR COALESCE(lookup_digest,'') !~ '^sha256:[0-9a-f]{64}$' OR COALESCE(verification_digest,'') !~ '^sha256:[0-9a-f]{64}$'
      OR jsonb_typeof(intent->'durationSeconds') IS DISTINCT FROM 'number' OR (intent->>'durationSeconds') !~ '^[0-9]{2,5}$'
      OR (intent->>'durationSeconds')::integer NOT BETWEEN 60 AND 43200
      OR NOT pg_input_is_valid(intent->>'issuedAt','timestamptz') OR NOT pg_input_is_valid(intent->>'expiresAt','timestamptz') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role issuance intent is invalid'; END IF;
    admission:=iam.read_role_assumption(tenant,actor,source_session,role_id,intent->>'requestId');
    IF admission ? 'existing' THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role issuance already exists'; END IF;
    SELECT * INTO selected FROM iam.roles r WHERE r.tenant_id=tenant AND r.id=role_id;
    IF selected.status<>'ACTIVE' OR admission->'credentialGeneration' IS DISTINCT FROM intent->'credentialGeneration'
      OR admission->'securityGeneration' IS DISTINCT FROM intent->'securityGeneration'
      OR to_jsonb(selected.resource_version) IS DISTINCT FROM intent->'resourceVersion' THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role issuance authority changed'; END IF;
    trust:=admission#>'{trust,document}';
    IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(trust->'statements') s,jsonb_array_elements(s->'principals') p
        WHERE s->>'effect'='ALLOW' AND p=jsonb_build_object('type','USER','id',actor))
      OR EXISTS(SELECT 1 FROM jsonb_array_elements(trust->'statements') s,jsonb_array_elements(s->'principals') p
        WHERE s->>'effect'='DENY' AND p=jsonb_build_object('type','USER','id',actor)) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role source is not trusted'; END IF;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.role.assume','ROLE',role_id,'INSTANCE',NULL);
    SELECT * INTO boundary FROM iam.role_permission_boundaries b WHERE b.tenant_id=tenant AND b.role_id=issue_role_session.role_id AND b.revoked_at IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role permission boundary is required'; END IF;
    SELECT * INTO boundary_policy FROM iam.policies p WHERE p.id=boundary.policy_id AND p.status='ACTIVE' AND p.authority_scope='TENANT'
      AND (p.owner_tenant_id IS NULL OR p.owner_tenant_id=tenant) FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role permission boundary is unavailable'; END IF;
    SELECT * INTO boundary_version FROM iam.policy_versions v WHERE v.policy_id=boundary.policy_id AND v.id=boundary_policy.default_version_id AND v.retired_at IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role permission version is unavailable'; END IF;
    SELECT s.expires_at INTO source_expiry FROM iam.sessions s WHERE s.tenant_id=tenant AND s.id=source_session;
    deadline:=least(source_expiry,now_at+least((intent->>'durationSeconds')::integer,(selected.metadata->>'maxSessionDurationSeconds')::integer)*interval '1 second');
    IF (intent->>'issuedAt')::timestamptz IS DISTINCT FROM now_at OR (intent->>'expiresAt')::timestamptz IS DISTINCT FROM deadline OR deadline<=clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role issuance deadline is invalid'; END IF;
    IF session_policy IS NOT NULL THEN
        IF jsonb_typeof(session_policy)<>'object' OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(session_policy) key) IS DISTINCT FROM ARRAY['canonical','contentDigest'] THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role session policy is invalid'; END IF;
        canonical:=session_policy->>'canonical'; content_digest:=session_policy->>'contentDigest';
        PERFORM iam.assert_policy_compilation(canonical,content_digest,'TENANT');
    END IF;
    -- Invalidated but not explicitly revoked sessions still occupy the quota.
    IF (SELECT count(*) FROM iam.role_sessions s WHERE s.tenant_id=tenant AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp())>=1024
      OR (SELECT count(*) FROM iam.role_sessions s WHERE s.tenant_id=tenant AND s.source_user_id=actor AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp())>=16
      OR (SELECT count(*) FROM iam.role_sessions s WHERE s.tenant_id=tenant AND s.role_id=issue_role_session.role_id AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp())>=128 THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role session quota is exhausted'; END IF;
    session_id:=intent->>'sessionId';
    PERFORM iam.assert_audit_event(event,tenant,'iam.role-session.issued','ROLE_SESSION',session_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision OR event->>'requestId' IS DISTINCT FROM intent->>'requestId'
      OR event->>'requestDigest' IS DISTINCT FROM intent->>'requestDigest' THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role issuance correlation is invalid'; END IF;
    role_policies:=iam.role_policy_snapshot(tenant,role_id);
    IF jsonb_array_length(role_policies)>256 THEN RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='role authority exceeds its budget'; END IF;
    evidence:=jsonb_build_object('accountResourceVersion',(SELECT resource_version FROM iam.accounts WHERE id=tenant),
      'userResourceVersion',(SELECT resource_version FROM iam.principals WHERE tenant_id=tenant AND id=actor),
      'sourcePolicies',iam.current_policy_snapshot(tenant,actor),'sourceBoundary',iam.current_user_boundary(tenant,actor),
      'role',admission->'role','trust',admission->'trust','rolePolicies',role_policies,
      'roleBoundary',jsonb_build_object('boundaryId',boundary.id,'resourceVersion',boundary.resource_version,
        'policy',iam.lookup_policy(tenant,boundary_policy.id),'version',iam.policy_version_snapshot(boundary_version)));
    source_authority:=iam.role_source_authority_snapshot(tenant,actor);
    INSERT INTO iam.role_sessions(tenant_id,id,role_id,source_user_id,source_session_id,credential_generation,security_generation,trust_version_id,
      authority_contract_version,source_authorization_generation,source_group_generations,
      request_id,request_digest,verification_digest,decision_id,authority_evidence,session_policy_canonical,session_policy_digest,issued_at,expires_at)
    VALUES(tenant,session_id,role_id,actor,source_session,(admission->>'credentialGeneration')::bigint,selected.security_generation,selected.current_trust_version_id,
      2,(source_authority->>'userGeneration')::bigint,source_authority->'groups',
      intent->>'requestId',intent->>'requestDigest',verification_digest,decision,evidence,canonical,content_digest,now_at,deadline);
    INSERT INTO iam.role_session_index VALUES(lookup_digest,tenant,session_id);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,now_at,now_at,now_at);
    RETURN iam.role_session_snapshot(tenant,session_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_role_session_by_request(tenant text,actor text,source_session text,request_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE session_id text;
BEGIN
    PERFORM iam.assert_role_session_source(tenant,actor,source_session,false);
    SELECT s.id INTO session_id FROM iam.role_sessions s WHERE s.tenant_id=tenant AND s.source_user_id=actor AND s.request_id=read_role_session_by_request.request_id;
    RETURN iam.role_session_snapshot(tenant,session_id);
END $function$;

-- Resolve only this purpose-isolated credential. Revision equality is a
-- continuous eligibility check, not an allow decision. Current AssumeRole
-- conditions are still evaluated by the one PDP inside the calling transaction.
CREATE OR REPLACE FUNCTION iam.lookup_role_session(lookup_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE located iam.role_session_index%ROWTYPE; stored iam.role_sessions%ROWTYPE;
    account_row iam.accounts%ROWTYPE; source_user iam.principals%ROWTYPE; selected iam.roles%ROWTYPE;
    credential_generation bigint; source_lookup text; current_boundary jsonb; boundary_row iam.role_permission_boundaries%ROWTYPE;
    boundary_policy iam.policies%ROWTYPE; boundary_version iam.policy_versions%ROWTYPE;
BEGIN
    IF COALESCE(lookup_digest,'') !~ '^sha256:[0-9a-f]{64}$' THEN RETURN NULL; END IF;
    SELECT * INTO located FROM iam.role_session_index i WHERE i.lookup_digest=lookup_role_session.lookup_digest;
    IF NOT FOUND THEN RETURN NULL; END IF;
    PERFORM set_config('matrix.iam_tenant_id',located.tenant_id,true);
    -- Read immutable linkage before locks, then use the same Account -> USER ->
    -- credential/session -> Role order as issuance and security mutations.
    SELECT * INTO stored FROM iam.role_sessions s WHERE s.tenant_id=located.tenant_id AND s.id=located.session_id;
    IF NOT FOUND OR stored.authority_contract_version<>2 OR stored.revoked_at IS NOT NULL OR stored.expires_at<=clock_timestamp() THEN RETURN NULL; END IF;
    SELECT * INTO account_row FROM iam.accounts WHERE id=stored.tenant_id AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO source_user FROM iam.principals WHERE tenant_id=stored.tenant_id AND id=stored.source_user_id
      AND principal_type='USER' AND status='ACTIVE' AND deleted_at IS NULL AND NOT must_change_password FOR SHARE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT c.credential_version INTO credential_generation FROM iam.user_credentials c JOIN iam.sessions s
      ON s.tenant_id=c.tenant_id AND s.principal_id=c.principal_id
      WHERE c.tenant_id=stored.tenant_id AND c.principal_id=stored.source_user_id AND s.id=stored.source_session_id
        AND s.status='ACTIVE' AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
        AND s.credential_version=c.credential_version AND c.credential_version=stored.credential_generation
        AND iam.session_mfa_eligible(stored.tenant_id,stored.source_user_id,s.id) FOR SHARE OF c,s;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO selected FROM iam.roles WHERE tenant_id=stored.tenant_id AND id=stored.role_id
      AND status='ACTIVE' AND deleted_at IS NULL AND security_generation=stored.security_generation
      AND current_trust_version_id=stored.trust_version_id FOR SHARE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO boundary_row FROM iam.role_permission_boundaries b WHERE b.tenant_id=stored.tenant_id AND b.role_id=stored.role_id AND b.revoked_at IS NULL;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO boundary_policy FROM iam.policies p WHERE p.id=boundary_row.policy_id AND p.status='ACTIVE'
      AND p.authority_scope='TENANT' AND (p.owner_tenant_id IS NULL OR p.owner_tenant_id=stored.tenant_id);
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO boundary_version FROM iam.policy_versions v WHERE v.policy_id=boundary_policy.id AND v.id=boundary_policy.default_version_id AND v.retired_at IS NULL;
    IF NOT FOUND THEN RETURN NULL; END IF;
    current_boundary:=jsonb_build_object('boundaryId',boundary_row.id,'resourceVersion',boundary_row.resource_version,
      'policy',iam.lookup_policy(stored.tenant_id,boundary_policy.id),'version',iam.policy_version_snapshot(boundary_version));
    -- Full immutable relationship identities and mutable revisions prevent ABA:
    -- default selection, reattachment, group rejoin, boundary reset and source
    -- updates cannot silently renew an issued session. Role metadata is excluded.
    IF jsonb_build_object('userGeneration',stored.source_authorization_generation,'groups',stored.source_group_generations)
         IS DISTINCT FROM iam.role_source_authority_snapshot(stored.tenant_id,stored.source_user_id)
      OR stored.authority_evidence->'accountResourceVersion' IS DISTINCT FROM to_jsonb(account_row.resource_version)
      OR stored.authority_evidence->'userResourceVersion' IS DISTINCT FROM to_jsonb(source_user.resource_version)
      OR stored.authority_evidence->'sourcePolicies' IS DISTINCT FROM iam.current_policy_snapshot(stored.tenant_id,stored.source_user_id)
      OR stored.authority_evidence->'sourceBoundary' IS DISTINCT FROM iam.current_user_boundary(stored.tenant_id,stored.source_user_id)
      OR stored.authority_evidence->'rolePolicies' IS DISTINCT FROM iam.role_policy_snapshot(stored.tenant_id,stored.role_id)
      OR stored.authority_evidence->'roleBoundary' IS DISTINCT FROM current_boundary
      OR stored.authority_evidence->'trust' IS DISTINCT FROM iam.role_trust_snapshot(stored.tenant_id,stored.role_id,stored.trust_version_id) THEN RETURN NULL; END IF;
    SELECT i.lookup_digest INTO source_lookup FROM iam.session_index i WHERE i.tenant_id=stored.tenant_id AND i.session_id=stored.source_session_id;
    IF NOT FOUND THEN RETURN NULL; END IF;
    -- Locks or snapshot decoding can outlive the initial timestamp check.
    PERFORM 1 FROM iam.role_sessions s WHERE s.tenant_id=stored.tenant_id AND s.id=stored.id
      AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() FOR SHARE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    PERFORM 1 FROM iam.sessions s WHERE s.tenant_id=stored.tenant_id AND s.id=stored.source_session_id AND s.expires_at>clock_timestamp();
    IF NOT FOUND THEN RETURN NULL; END IF;
    RETURN jsonb_build_object('session',iam.role_session_snapshot(stored.tenant_id,stored.id),'sourceSessionId',stored.source_session_id,
      'sourceLookupDigest',source_lookup,'credentialGeneration',stored.credential_generation,'securityGeneration',stored.security_generation,
	  'assumeDecisionId',stored.decision_id,
      'authorityContractVersion',stored.authority_contract_version,'sourceAuthorizationGeneration',stored.source_authorization_generation,
      'sourceGroupGenerations',stored.source_group_generations,
      'verificationDigest',stored.verification_digest,'role',iam.role_snapshot(stored.tenant_id,stored.role_id),
      'authorityEvidence',stored.authority_evidence,'sessionPolicyCanonical',stored.session_policy_canonical,'sessionPolicyDigest',stored.session_policy_digest);
END $function$;

-- Possession-only projection. It never checks or grants current business
-- eligibility and is consumed only by the exact self-exit use case.
CREATE OR REPLACE FUNCTION iam.lookup_role_session_for_exit(lookup_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE located iam.role_session_index%ROWTYPE; stored iam.role_sessions%ROWTYPE;
BEGIN
    IF COALESCE(lookup_digest,'') !~ '^sha256:[0-9a-f]{64}$' THEN RETURN NULL; END IF;
    SELECT * INTO located FROM iam.role_session_index i WHERE i.lookup_digest=lookup_role_session_for_exit.lookup_digest;
    IF NOT FOUND THEN RETURN NULL; END IF;
    PERFORM set_config('matrix.iam_tenant_id',located.tenant_id,true);
    SELECT * INTO stored FROM iam.role_sessions s WHERE s.tenant_id=located.tenant_id AND s.id=located.session_id;
    IF NOT FOUND THEN RETURN NULL; END IF;
    RETURN jsonb_build_object('session',iam.role_session_snapshot(stored.tenant_id,stored.id),'verificationDigest',stored.verification_digest);
END $function$;

CREATE OR REPLACE FUNCTION iam.exit_role_session(lookup_digest text,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE located iam.role_session_index%ROWTYPE; stored iam.role_sessions%ROWTYPE;
    source_user text; expected_actor jsonb; now_at timestamptz(6):=transaction_timestamp();
BEGIN
    IF COALESCE(lookup_digest,'') !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role exit credential is unavailable';
    END IF;
    SELECT * INTO located FROM iam.role_session_index i WHERE i.lookup_digest=exit_role_session.lookup_digest;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role exit credential is unavailable'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',located.tenant_id,true);
    SELECT s.source_user_id INTO source_user FROM iam.role_sessions s WHERE s.tenant_id=located.tenant_id AND s.id=located.session_id;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role exit credential is unavailable'; END IF;
    -- Same Account -> USER -> session order as issuance/source revocation.
    -- No status/expiry check: disabling business access cannot prevent exit.
    PERFORM 1 FROM iam.accounts WHERE id=located.tenant_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role exit account is unavailable'; END IF;
    PERFORM 1 FROM iam.principals WHERE tenant_id=located.tenant_id AND id=source_user AND principal_type='USER' FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role exit source is unavailable'; END IF;
    SELECT * INTO stored FROM iam.role_sessions s WHERE s.tenant_id=located.tenant_id AND s.id=located.session_id FOR UPDATE;
    IF NOT FOUND OR stored.source_user_id IS DISTINCT FROM source_user THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role exit linkage differs';
    END IF;
    expected_actor:=jsonb_build_object('type','ROLE','id',stored.role_id,
      'roleSession',jsonb_build_object('sessionId',stored.id,'sourceUserId',stored.source_user_id));
    PERFORM iam.assert_audit_event(event,stored.tenant_id,'iam.role-session.exited','ROLE_SESSION',stored.id,'SUCCEEDED');
    IF event->'actor' IS DISTINCT FROM expected_actor OR event ? 'iamDecisionId' THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role exit actor differs';
    END IF;
    IF stored.revoked_at IS NOT NULL THEN
        IF NOT EXISTS(SELECT 1 FROM iam.audit_outbox fact WHERE fact.tenant_id=stored.tenant_id
          AND fact.event_document->>'action'='iam.role-session.exited' AND fact.event_document->'actor'=expected_actor
          AND fact.event_document->>'requestId'=event->>'requestId' AND fact.event_document->>'requestDigest'=event->>'requestDigest'
          AND fact.event_document->'target'=event->'target') THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role exit intent conflicts';
        END IF;
        RETURN iam.role_session_snapshot(stored.tenant_id,stored.id);
    END IF;
    IF EXISTS(SELECT 1 FROM iam.audit_outbox fact WHERE fact.tenant_id=stored.tenant_id
      AND fact.event_document->>'action'='iam.role-session.exited' AND fact.event_document->'actor'=expected_actor
      AND fact.event_document->>'requestId'=event->>'requestId') THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role exit intent conflicts';
    END IF;
    UPDATE iam.role_sessions SET revoked_at=now_at WHERE tenant_id=stored.tenant_id AND id=stored.id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(stored.tenant_id,event->>'eventId',event,now_at,now_at,now_at);
    RETURN iam.role_session_snapshot(stored.tenant_id,stored.id);
END $function$;

CREATE OR REPLACE FUNCTION iam.revoke_role_session_by_request(tenant text,actor text,source_session text,request_id text,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.role_sessions%ROWTYPE; now_at timestamptz(6):=transaction_timestamp();
BEGIN
    PERFORM iam.assert_role_session_source(tenant,actor,source_session,false);
    SELECT * INTO stored FROM iam.role_sessions s WHERE s.tenant_id=tenant AND s.source_user_id=actor AND s.request_id=revoke_role_session_by_request.request_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role issuance is unavailable'; END IF;
    PERFORM iam.assert_audit_event(event,tenant,'iam.role-session.revoked','ROLE_SESSION',stored.id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event ? 'iamDecisionId' THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='self revocation is not a business decision'; END IF;
    PERFORM iam.assert_role_intent(tenant,actor,event);
    IF stored.revoked_at IS NOT NULL THEN
        IF NOT iam.role_event_matches(tenant,actor,event) THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role revocation intent conflicts'; END IF;
        RETURN iam.role_session_snapshot(tenant,stored.id);
    END IF;
    UPDATE iam.role_sessions SET revoked_at=now_at WHERE tenant_id=tenant AND id=stored.id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,now_at,now_at,now_at);
    RETURN iam.role_session_snapshot(tenant,stored.id);
END $function$;

-- A per-role directory clock is not role security authority. Only actual
-- issuance and terminal transitions advance it; replay never resets it.
DO $session_directory_cutover$
BEGIN
    IF to_regclass('iam.role_session_directory_revisions') IS NULL THEN
        CREATE TABLE iam.role_session_directory_revisions (
            tenant_id text COLLATE "C" NOT NULL,
            role_id text COLLATE "C" NOT NULL,
            revision bigint NOT NULL,
            PRIMARY KEY(tenant_id,role_id),
            CONSTRAINT role_session_directory_role_fk FOREIGN KEY(tenant_id,role_id) REFERENCES iam.roles(tenant_id,id),
            CONSTRAINT role_session_directory_revision_range CHECK(revision BETWEEN 1 AND 9007199254740991)
        );
        ALTER TABLE iam.roles NO FORCE ROW LEVEL SECURITY;
        INSERT INTO iam.role_session_directory_revisions SELECT tenant_id,id,1 FROM iam.roles;
        ALTER TABLE iam.roles FORCE ROW LEVEL SECURITY;
    END IF;
END $session_directory_cutover$;
ALTER TABLE iam.role_session_directory_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.role_session_directory_revisions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON iam.role_session_directory_revisions;
CREATE POLICY tenant_isolation ON iam.role_session_directory_revisions
  USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id());
CREATE INDEX IF NOT EXISTS role_sessions_directory_idx ON iam.role_sessions(tenant_id,role_id,id);
CREATE OR REPLACE FUNCTION iam.guard_role_session_directory_revision()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF TG_OP='INSERT' AND NEW.revision=1 THEN RETURN NEW; END IF;
    IF TG_OP='UPDATE' AND NEW.tenant_id=OLD.tenant_id AND NEW.role_id=OLD.role_id AND NEW.revision=OLD.revision+1 THEN RETURN NEW; END IF;
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role session directory is irreversible';
END $function$;
DROP TRIGGER IF EXISTS role_session_directory_monotonic ON iam.role_session_directory_revisions;
CREATE TRIGGER role_session_directory_monotonic BEFORE INSERT OR UPDATE OR DELETE ON iam.role_session_directory_revisions
  FOR EACH ROW EXECUTE FUNCTION iam.guard_role_session_directory_revision();
ALTER TABLE iam.role_session_directory_revisions ENABLE ALWAYS TRIGGER role_session_directory_monotonic;
DROP TRIGGER IF EXISTS cannot_truncate ON iam.role_session_directory_revisions;
CREATE TRIGGER cannot_truncate BEFORE TRUNCATE ON iam.role_session_directory_revisions FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.role_session_directory_revisions ENABLE ALWAYS TRIGGER cannot_truncate;
CREATE OR REPLACE FUNCTION iam.advance_role_session_directory_revision()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',NEW.tenant_id,true);
    IF TG_TABLE_NAME='roles' AND TG_OP='INSERT' THEN
        INSERT INTO iam.role_session_directory_revisions VALUES(NEW.tenant_id,NEW.id,1);
    ELSIF TG_TABLE_NAME='role_sessions' AND (TG_OP='INSERT' OR (TG_OP='UPDATE' AND OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)) THEN
        UPDATE iam.role_session_directory_revisions SET revision=revision+1 WHERE tenant_id=NEW.tenant_id AND role_id=NEW.role_id;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='role session directory is unavailable'; END IF;
    ELSE RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role session directory transition is invalid';
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS roles_initialize_session_directory ON iam.roles;
CREATE TRIGGER roles_initialize_session_directory AFTER INSERT ON iam.roles FOR EACH ROW EXECUTE FUNCTION iam.advance_role_session_directory_revision();
ALTER TABLE iam.roles ENABLE ALWAYS TRIGGER roles_initialize_session_directory;
DROP TRIGGER IF EXISTS sessions_advance_directory ON iam.role_sessions;
CREATE TRIGGER sessions_advance_directory AFTER INSERT OR UPDATE ON iam.role_sessions FOR EACH ROW EXECUTE FUNCTION iam.advance_role_session_directory_revision();
ALTER TABLE iam.role_sessions ENABLE ALWAYS TRIGGER sessions_advance_directory;

-- Prepare before recording the USER decision, then repeat at the effect.
-- Source USER locks serialize custody only; no source login/role eligibility
-- is needed for an administrator to terminate an otherwise invalid session.
CREATE OR REPLACE FUNCTION iam.prepare_role_session_management(tenant text,actor text,actor_session text,role_id text,session_id text,writing boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE source_user text; generation bigint; directory_revision bigint; source_authority jsonb;
BEGIN
    IF COALESCE(tenant,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor_session,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(role_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR session_id IS NULL OR writing IS NULL OR (writing AND session_id='')
      OR (session_id<>'' AND session_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role session management reference is invalid'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role session management is unavailable'; END IF;
    PERFORM 1 FROM iam.roles r WHERE r.tenant_id=tenant AND r.id=role_id;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role session management is unavailable'; END IF;
    IF session_id<>'' THEN
        SELECT s.source_user_id INTO source_user FROM iam.role_sessions s WHERE s.tenant_id=tenant AND s.role_id=prepare_role_session_management.role_id AND s.id=session_id;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role session management is unavailable'; END IF;
    END IF;
    IF writing THEN
        PERFORM 1 FROM iam.principals p WHERE p.tenant_id=tenant AND (p.id=actor OR p.id=source_user) AND p.principal_type='USER' ORDER BY p.id FOR NO KEY UPDATE;
    ELSE
        PERFORM 1 FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=actor AND p.principal_type='USER' FOR SHARE;
    END IF;
    IF NOT EXISTS(SELECT 1 FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=actor AND p.principal_type='USER'
      AND p.status='ACTIVE' AND p.deleted_at IS NULL AND NOT p.must_change_password) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role session management actor is unavailable'; END IF;
    SELECT c.credential_version INTO generation FROM iam.user_credentials c JOIN iam.sessions s ON s.tenant_id=c.tenant_id AND s.principal_id=c.principal_id
      WHERE c.tenant_id=tenant AND c.principal_id=actor AND s.id=actor_session AND s.status='ACTIVE' AND s.revoked_at IS NULL
      AND s.credential_version=c.credential_version AND s.expires_at>clock_timestamp() FOR SHARE OF c,s;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role session management credential is unavailable'; END IF;
    source_authority:=iam.role_source_authority_snapshot(tenant,actor);
    IF writing THEN
        PERFORM 1 FROM iam.role_sessions s WHERE s.tenant_id=tenant AND s.role_id=prepare_role_session_management.role_id AND s.id=session_id FOR UPDATE;
        -- Do not take a shared directory lock and later upgrade it at UPDATE.
        SELECT d.revision INTO directory_revision FROM iam.role_session_directory_revisions d WHERE d.tenant_id=tenant AND d.role_id=prepare_role_session_management.role_id;
    ELSE
        SELECT d.revision INTO directory_revision FROM iam.role_session_directory_revisions d WHERE d.tenant_id=tenant AND d.role_id=prepare_role_session_management.role_id FOR SHARE;
    END IF;
    IF directory_revision IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='role session directory is unavailable'; END IF;
    RETURN jsonb_build_object('credentialGeneration',generation,'directoryRevision',directory_revision,
      'userAuthorizationGeneration',source_authority->'userGeneration','groups',source_authority->'groups');
END $function$;

CREATE OR REPLACE FUNCTION iam.managed_role_session_snapshot(tenant text,role_id text,session_id text)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_build_object('session',iam.role_session_snapshot(tenant,s.id),
      'sourceUser',jsonb_build_object('id',p.id,'loginName',p.login_name,'displayName',p.display_name))
    FROM iam.role_sessions s JOIN iam.principals p ON p.tenant_id=s.tenant_id AND p.id=s.source_user_id AND p.principal_type='USER'
    WHERE s.tenant_id=tenant AND s.role_id=managed_role_session_snapshot.role_id AND s.id=session_id
$function$;
CREATE OR REPLACE FUNCTION iam.list_managed_role_sessions(tenant text,actor text,actor_session text,role_id text,decision text,after_id text,source_user_id text,session_id text,lifecycle text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE candidate record; scanned integer:=0; previous_id text:=''; next_after text:=''; items jsonb:='[]'; observed timestamptz(6):=transaction_timestamp(); item jsonb;
BEGIN
    PERFORM iam.prepare_role_session_management(tenant,actor,actor_session,role_id,'',false);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.role-session.list','ROLE',role_id,'INSTANCE',NULL);
    IF after_id IS NULL OR source_user_id IS NULL OR session_id IS NULL OR lifecycle IS NULL OR lifecycle NOT IN ('ALL','UNREVOKED','EXPIRED','REVOKED')
      OR (after_id<>'' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
      OR (source_user_id<>'' AND source_user_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
      OR (session_id<>'' AND session_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role session query is invalid'; END IF;
    -- Filters cannot turn a response limit into an unbounded historical scan.
    FOR candidate IN SELECT s.id,s.source_user_id,s.revoked_at,s.expires_at FROM iam.role_sessions s
      WHERE s.tenant_id=tenant AND s.role_id=list_managed_role_sessions.role_id AND (after_id='' OR s.id>after_id COLLATE "C")
      AND (session_id='' OR s.id=session_id) ORDER BY s.id LIMIT 101 LOOP
        IF scanned=100 THEN next_after:=previous_id; EXIT; END IF;
        scanned:=scanned+1; previous_id:=candidate.id;
        IF (source_user_id='' OR candidate.source_user_id=source_user_id) AND (lifecycle='ALL'
          OR (lifecycle='REVOKED' AND candidate.revoked_at IS NOT NULL)
          OR (lifecycle='EXPIRED' AND candidate.revoked_at IS NULL AND candidate.expires_at<=observed)
          OR (lifecycle='UNREVOKED' AND candidate.revoked_at IS NULL AND candidate.expires_at>observed)) THEN
            item:=iam.managed_role_session_snapshot(tenant,role_id,candidate.id);
            IF item IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='role session display is unavailable'; END IF;
            items:=items||jsonb_build_array(item);
        END IF;
    END LOOP;
    RETURN jsonb_build_object('items',items,'nextAfter',next_after);
END $function$;
CREATE OR REPLACE FUNCTION iam.read_managed_role_session(tenant text,actor text,actor_session text,role_id text,session_id text,decision text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.prepare_role_session_management(tenant,actor,actor_session,role_id,session_id,false);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.role-session.read','ROLE_SESSION',session_id,'INSTANCE',NULL);
    result:=iam.managed_role_session_snapshot(tenant,role_id,session_id);
    IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='role session display is unavailable'; END IF;
    RETURN result;
END $function$;
CREATE OR REPLACE FUNCTION iam.revoke_managed_role_session(tenant text,actor text,actor_session text,role_id text,session_id text,decision text,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.role_sessions%ROWTYPE; now_at timestamptz(6):=transaction_timestamp();
BEGIN
    PERFORM iam.prepare_role_session_management(tenant,actor,actor_session,role_id,session_id,true);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.role-session.revoke','ROLE_SESSION',session_id,'INSTANCE',NULL);
    SELECT * INTO stored FROM iam.role_sessions s WHERE s.tenant_id=tenant AND s.role_id=revoke_managed_role_session.role_id AND s.id=session_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role session management is unavailable'; END IF;
    PERFORM iam.assert_audit_event(event,tenant,'iam.role-session.admin-revoked','ROLE_SESSION',stored.id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='role revocation decision is invalid'; END IF;
    PERFORM iam.assert_role_intent(tenant,actor,event);
    IF stored.revoked_at IS NOT NULL THEN
        IF NOT iam.role_event_matches(tenant,actor,event) THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role revocation intent conflicts'; END IF;
        RETURN jsonb_build_object('outcome','EQUAL_REPLAY','session',iam.role_session_snapshot(tenant,stored.id));
    END IF;
    IF stored.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='role session has expired'; END IF;
    UPDATE iam.role_sessions SET revoked_at=now_at WHERE tenant_id=tenant AND id=stored.id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,now_at,now_at,now_at);
    RETURN jsonb_build_object('outcome','APPLIED','session',iam.role_session_snapshot(tenant,stored.id));
END $function$;
REVOKE ALL ON iam.role_session_directory_revisions FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON FUNCTION iam.guard_role_session_directory_revision(),iam.advance_role_session_directory_revision(),
    iam.managed_role_session_snapshot(text,text,text),iam.prepare_role_session_management(text,text,text,text,text,boolean),
    iam.list_managed_role_sessions(text,text,text,text,text,text,text,text,text),iam.read_managed_role_session(text,text,text,text,text,text),
    iam.revoke_managed_role_session(text,text,text,text,text,text,jsonb) FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.prepare_role_session_management(text,text,text,text,text,boolean),
    iam.list_managed_role_sessions(text,text,text,text,text,text,text,text,text),iam.read_managed_role_session(text,text,text,text,text,text),
    iam.revoke_managed_role_session(text,text,text,text,text,text,jsonb) TO matrix_iam_api;

-- Pure historical linkage: lifecycle fields and current default pointers do
-- not reinterpret an immutable version captured when the session was issued.
CREATE OR REPLACE FUNCTION iam.role_snapshot_version_matches(snapshot jsonb)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT COALESCE(EXISTS(SELECT 1 FROM iam.policy_versions v
      WHERE v.policy_id=snapshot#>>'{value,policyId}' AND v.id=snapshot#>>'{value,versionId}'
        AND snapshot=iam.policy_version_snapshot(v)
        AND iam.recorded_policy_version_matches(jsonb_build_object('version',jsonb_build_object(
          'policyId',v.policy_id,'versionId',v.id,'contentDigest',v.content_digest),'contractVersion',v.contract_version)
          ||CASE WHEN v.contract_version=2 THEN jsonb_build_object('compilation',v.compilation) ELSE '{}'::jsonb END)),false)
$function$;

-- One reference to the sealed issuance, not a second credential or permit.
-- Do not add current status, expiry, credential generation or policy-head
-- checks here: accepted work must keep its proof after revocation or expiry.
CREATE OR REPLACE FUNCTION iam.role_authorization_evidence(tenant text,session_id text)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.role_sessions%ROWTYPE; original iam.authorization_decisions%ROWTYPE;
    item jsonb; ceiling jsonb; version jsonb; restriction jsonb; result jsonb; vector jsonb; previous_group text:='';
BEGIN
    SELECT * INTO stored FROM iam.role_sessions s WHERE s.tenant_id=tenant AND s.id=session_id;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF stored.authority_contract_version=1 THEN
        IF stored.source_authorization_generation IS NOT NULL OR stored.source_group_generations IS NOT NULL THEN RETURN NULL; END IF;
    ELSIF stored.authority_contract_version=2 THEN
        IF stored.source_authorization_generation IS NULL OR stored.source_authorization_generation NOT BETWEEN 1 AND 9007199254740991
          OR jsonb_typeof(stored.source_group_generations) IS DISTINCT FROM 'array' THEN RETURN NULL; END IF;
        IF jsonb_array_length(stored.source_group_generations)>100 THEN RETURN NULL; END IF;
        FOR item IN SELECT value FROM jsonb_array_elements(stored.source_group_generations) LOOP
            IF jsonb_typeof(item) IS DISTINCT FROM 'object' THEN RETURN NULL; END IF;
            IF (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(item) key) IS DISTINCT FROM
                ARRAY['authorizationGeneration','groupId','membershipId','membershipResourceVersion']
              OR jsonb_typeof(item->'authorizationGeneration') IS DISTINCT FROM 'number'
              OR COALESCE(item->>'authorizationGeneration','') !~ '^[1-9][0-9]{0,15}$'
              OR item->'membershipResourceVersion' IS DISTINCT FROM '1'::jsonb
              OR jsonb_typeof(item->'groupId') IS DISTINCT FROM 'string' OR jsonb_typeof(item->'membershipId') IS DISTINCT FROM 'string'
              OR (item->>'groupId') COLLATE "C"<=previous_group THEN RETURN NULL; END IF;
            IF (item->>'authorizationGeneration')::bigint>9007199254740991 OR NOT EXISTS(
                SELECT 1 FROM iam.group_memberships m WHERE m.tenant_id=tenant AND m.id=item->>'membershipId'
                  AND m.group_id=item->>'groupId' AND m.user_id=stored.source_user_id) THEN RETURN NULL; END IF;
            previous_group:=item->>'groupId';
        END LOOP;
    ELSE RETURN NULL;
    END IF;
    vector:=stored.authority_evidence;
    IF (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(vector) key) IS DISTINCT FROM ARRAY[
       'accountResourceVersion','role','roleBoundary','rolePolicies','sourceBoundary','sourcePolicies','trust','userResourceVersion']
      OR jsonb_typeof(vector->'sourcePolicies') IS DISTINCT FROM 'array' OR jsonb_typeof(vector->'rolePolicies') IS DISTINCT FROM 'array'
      OR jsonb_array_length(vector->'sourcePolicies')>256 OR jsonb_array_length(vector->'rolePolicies')>256
      OR vector#>>'{role,id}' IS DISTINCT FROM stored.role_id OR vector#>>'{role,accountId}' IS DISTINCT FROM stored.tenant_id
      OR vector->'trust' IS DISTINCT FROM iam.role_trust_snapshot(tenant,stored.role_id,stored.trust_version_id)
      OR NOT EXISTS(SELECT 1 FROM iam.sessions s WHERE s.tenant_id=tenant AND s.id=stored.source_session_id AND s.principal_id=stored.source_user_id)
      OR NOT EXISTS(SELECT 1 FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=stored.source_user_id AND p.principal_type='USER') THEN RETURN NULL; END IF;
    SELECT * INTO original FROM iam.authorization_decisions d WHERE d.tenant_id=tenant AND d.id=stored.decision_id;
    IF NOT FOUND OR NOT original.allowed OR original.principal_id IS DISTINCT FROM stored.source_user_id
      OR original.action_name<>'iam.role.assume' OR original.target_kind<>'ROLE' OR original.target_id<>stored.role_id
      OR original.decided_at<>stored.issued_at OR original.request_id<>stored.request_id
      OR original.document->'subject' IS DISTINCT FROM jsonb_build_object('type','USER','id',stored.source_user_id)
      OR original.contract_version NOT IN (2,3,4) OR original.access_key_id IS NOT NULL OR NOT iam.authorization_decision_profile_matches(original.document)
      OR NOT EXISTS(SELECT 1 FROM iam.audit_outbox o WHERE o.tenant_id=tenant AND o.event_document->>'action'='iam.role-session.issued'
          AND o.event_document#>>'{target,id}'=stored.id AND o.event_document->'actor'=jsonb_build_object('type','USER','id',stored.source_user_id)
          AND o.event_document->>'iamDecisionId'=stored.decision_id AND o.event_document->>'requestId'=stored.request_id
          AND o.event_document->>'requestDigest'=stored.request_digest) THEN RETURN NULL; END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(vector->'sourcePolicies') UNION ALL SELECT value FROM jsonb_array_elements(vector->'rolePolicies') LOOP
      IF iam.role_snapshot_version_matches(item->'version') IS DISTINCT FROM true THEN RETURN NULL; END IF;
    END LOOP;
    IF vector#>>'{sourceBoundary,state}'='BOUND' THEN
      IF iam.role_snapshot_version_matches(vector#>'{sourceBoundary,version}') IS DISTINCT FROM true THEN RETURN NULL; END IF;
    ELSIF vector#>>'{sourceBoundary,state}' IS DISTINCT FROM 'NONE' THEN RETURN NULL;
    END IF;
    ceiling:=vector->'roleBoundary'; version:=ceiling#>'{version,value}';
    IF iam.role_snapshot_version_matches(ceiling->'version') IS DISTINCT FROM true
      OR NOT EXISTS(SELECT 1 FROM iam.role_permission_boundaries b WHERE b.tenant_id=tenant AND b.id=ceiling->>'boundaryId'
          AND b.role_id=stored.role_id AND b.policy_id=version->>'policyId') THEN RETURN NULL; END IF;
    ceiling:=jsonb_build_object('boundaryId',ceiling->>'boundaryId','resourceVersion',ceiling->'resourceVersion',
      'version',jsonb_build_object('policyId',version->>'policyId','versionId',version->>'versionId','contentDigest',version->>'contentDigest'),
      'contractVersion',version->'contractVersion')||CASE WHEN version ? 'compilation' THEN jsonb_build_object('compilation',version->'compilation') ELSE '{}'::jsonb END;
    restriction:='null'::jsonb;
    IF stored.session_policy_canonical IS NOT NULL THEN
      -- Recheck the original byte commitment and exact archives, not today's
      -- publisher admission function (which intentionally requires head).
      IF stored.session_policy_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to('matrix.iam.policy-compilation.v1','UTF8')||decode('00','hex')||convert_to(stored.session_policy_canonical,'UTF8')),'hex') THEN RETURN NULL; END IF;
      item:=stored.session_policy_canonical::jsonb;
      IF item#>>'{document,scope}' IS DISTINCT FROM 'TENANT' OR jsonb_typeof(item->'profiles') IS DISTINCT FROM 'array'
        OR NOT item ?& ARRAY['document','compilationVersion','profiles','resolvedStatements']
        OR item-ARRAY['document','compilationVersion','profiles','resolvedStatements']<>'{}'::jsonb
        OR EXISTS(SELECT 1 FROM jsonb_array_elements(item->'profiles') r WHERE NOT EXISTS(SELECT 1 FROM iam.authorization_profiles p
          WHERE p.product=r->>'product' AND to_jsonb(p.revision)=r->'revision' AND p.content_digest=r->>'contentDigest')) THEN RETURN NULL; END IF;
      restriction:=jsonb_build_object('contentDigest',stored.session_policy_digest,'compilation',item-'document');
    END IF;
    result:=jsonb_build_object('sessionId',stored.id,'roleId',stored.role_id,'sourceUserId',stored.source_user_id,
      'sourceSessionId',stored.source_session_id,'credentialGeneration',stored.credential_generation,'securityGeneration',stored.security_generation,
      'trustVersionId',stored.trust_version_id,'trustDigest',vector#>>'{trust,contentDigest}','assumeDecisionId',stored.decision_id,
      'boundary',ceiling,'sessionPolicy',restriction);
    IF stored.authority_contract_version=2 THEN
        result:=result||jsonb_build_object('authorityContractVersion',2,'sourceAuthorizationGeneration',stored.source_authorization_generation,
          'sourceGroupGenerations',stored.source_group_generations);
    END IF;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.assert_current_role_authorization(tenant text,role_id text,evidence jsonb)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE expected jsonb; lookup_digest text; current_identity jsonb;
BEGIN
    IF evidence->'authorityContractVersion' IS DISTINCT FROM '2'::jsonb THEN
      RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role authority contract is not current'; END IF;
    expected:=iam.role_authorization_evidence(tenant,evidence->>'sessionId');
    IF expected IS NULL OR evidence IS DISTINCT FROM expected OR expected->>'roleId' IS DISTINCT FROM role_id THEN
      RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role authorization evidence is invalid'; END IF;
    SELECT i.lookup_digest INTO lookup_digest FROM iam.role_session_index i WHERE i.tenant_id=tenant AND i.session_id=evidence->>'sessionId';
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role authorization source is unavailable'; END IF;
    current_identity:=iam.lookup_role_session(lookup_digest);
    IF current_identity IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='role authorization is not current'; END IF;
END $function$;

REVOKE ALL ON FUNCTION iam.role_snapshot_version_matches(jsonb),iam.role_authorization_evidence(text,text),
    iam.assert_current_role_authorization(text,text,jsonb) FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
ALTER TABLE iam.authorization_decisions DROP CONSTRAINT IF EXISTS authorization_decisions_role_fk;
ALTER TABLE iam.authorization_decisions ADD CONSTRAINT authorization_decisions_role_fk
    FOREIGN KEY(tenant_id,role_id) REFERENCES iam.roles(tenant_id,id);

REVOKE ALL ON iam.role_sessions,iam.role_session_index FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON FUNCTION iam.guard_role_session_change(),iam.assert_role_session_source(text,text,text,boolean),iam.role_session_snapshot(text,text),
    iam.lookup_role_session_for_exit(text),iam.exit_role_session(text,jsonb),
    iam.role_policy_snapshot(text,text),iam.lookup_role_session(text),iam.read_role_assumption(text,text,text,text,text),
    iam.issue_role_session(text,text,text,text,text,jsonb,text,text,jsonb,jsonb),iam.read_role_session_by_request(text,text,text,text),
    iam.revoke_role_session_by_request(text,text,text,text,jsonb) FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.lookup_role_session(text),iam.read_role_assumption(text,text,text,text,text),iam.issue_role_session(text,text,text,text,text,jsonb,text,text,jsonb,jsonb),
    iam.lookup_role_session_for_exit(text),iam.exit_role_session(text,jsonb),
    iam.read_role_session_by_request(text,text,text,text),iam.revoke_role_session_by_request(text,text,text,text,jsonb) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.role_contract_ready()
RETURNS boolean LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE table_name text; required record; entrypoint record; signature text; relation_oid oid;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['roles','role_trust_versions','role_permission_boundaries','role_sessions','role_directory_revisions','role_source_authority_generations','role_session_directory_revisions'] LOOP
        relation_oid:=to_regclass('iam.'||table_name);
        IF relation_oid IS NULL OR NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=relation_oid
          AND c.relowner='matrix_iam_owner'::regrole AND c.relrowsecurity AND c.relforcerowsecurity) THEN RETURN false; END IF;
        IF EXISTS(SELECT 1 FROM aclexplode(COALESCE((SELECT relacl FROM pg_class WHERE oid=relation_oid),acldefault('r','matrix_iam_owner'::regrole))) permission
          WHERE permission.grantee<>'matrix_iam_owner'::regrole) THEN RETURN false; END IF;
    END LOOP;
    IF NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=to_regclass('iam.role_session_index') AND c.relowner='matrix_iam_owner'::regrole
      AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) permission WHERE permission.grantee<>c.relowner)) THEN RETURN false; END IF;
    FOR required IN SELECT * FROM (VALUES
      ('roles','security_generation','bigint'::regtype,true),
      ('role_directory_revisions','tenant_id','text'::regtype,true),('role_directory_revisions','revision','bigint'::regtype,true),
      ('role_session_directory_revisions','tenant_id','text'::regtype,true),('role_session_directory_revisions','role_id','text'::regtype,true),
      ('role_session_directory_revisions','revision','bigint'::regtype,true),
      ('role_source_authority_generations','tenant_id','text'::regtype,true),
      ('role_source_authority_generations','user_id','text'::regtype,false),
      ('role_source_authority_generations','group_id','text'::regtype,false),
      ('role_source_authority_generations','generation','bigint'::regtype,true),
      ('role_permission_boundaries','tenant_id','text'::regtype,true),
      ('role_permission_boundaries','id','text'::regtype,true),
      ('role_permission_boundaries','role_id','text'::regtype,true),
      ('role_permission_boundaries','policy_id','text'::regtype,true),
      ('role_permission_boundaries','resource_version','bigint'::regtype,true),
      ('role_permission_boundaries','created_at','timestamptz'::regtype,true),
      ('role_permission_boundaries','updated_at','timestamptz'::regtype,true),
      ('role_permission_boundaries','revoked_at','timestamptz'::regtype,false),
      ('role_sessions','tenant_id','text'::regtype,true),('role_sessions','id','text'::regtype,true),
      ('role_sessions','role_id','text'::regtype,true),('role_sessions','source_user_id','text'::regtype,true),
      ('role_sessions','source_session_id','text'::regtype,true),('role_sessions','credential_generation','bigint'::regtype,true),
      ('role_sessions','authority_contract_version','integer'::regtype,true),
      ('role_sessions','source_authorization_generation','bigint'::regtype,false),
      ('role_sessions','source_group_generations','jsonb'::regtype,false),
      ('role_sessions','security_generation','bigint'::regtype,true),('role_sessions','trust_version_id','text'::regtype,true),
      ('role_sessions','decision_id','text'::regtype,true),('role_sessions','request_id','text'::regtype,true),
      ('role_sessions','request_digest','text'::regtype,true),('role_sessions','verification_digest','text'::regtype,true),
      ('role_sessions','authority_evidence','jsonb'::regtype,true),('role_sessions','session_policy_canonical','text'::regtype,false),
      ('role_sessions','session_policy_digest','text'::regtype,false),('role_sessions','issued_at','timestamptz'::regtype,true),
      ('role_sessions','expires_at','timestamptz'::regtype,true),('role_sessions','revoked_at','timestamptz'::regtype,false)) expected(table_name,column_name,column_type,required_value) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=to_regclass('iam.'||required.table_name)
          AND a.attname=required.column_name AND a.atttypid=required.column_type AND a.attnotnull=required.required_value
          AND a.attnum>0 AND NOT a.attisdropped AND a.attgenerated='' AND a.attidentity=''
          AND (a.atttypid<>'timestamptz'::regtype OR a.atttypmod=6)) THEN RETURN false; END IF;
    END LOOP;
    IF EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid='iam.role_sessions'::regclass
      AND a.attname IN ('authority_contract_version','source_authorization_generation','source_group_generations')
      AND a.atthasdef) THEN RETURN false; END IF;
    FOR required IN SELECT * FROM (VALUES
      ('iam.role_sessions','iam.roles',ARRAY['tenant_id','role_id'],ARRAY['tenant_id','id']),
      ('iam.role_directory_revisions','iam.accounts',ARRAY['tenant_id'],ARRAY['id']),
      ('iam.role_source_authority_generations','iam.accounts',ARRAY['tenant_id'],ARRAY['id']),
      ('iam.role_source_authority_generations','iam.principals',ARRAY['tenant_id','user_id'],ARRAY['tenant_id','id']),
      ('iam.role_source_authority_generations','iam.groups',ARRAY['tenant_id','group_id'],ARRAY['tenant_id','id']),
      ('iam.role_sessions','iam.principals',ARRAY['tenant_id','source_user_id'],ARRAY['tenant_id','id']),
      ('iam.role_sessions','iam.sessions',ARRAY['tenant_id','source_session_id'],ARRAY['tenant_id','id']),
      ('iam.role_sessions','iam.role_trust_versions',ARRAY['tenant_id','role_id','trust_version_id'],ARRAY['tenant_id','role_id','id']),
      ('iam.role_sessions','iam.authorization_decisions',ARRAY['tenant_id','decision_id'],ARRAY['tenant_id','id']),
      ('iam.role_session_index','iam.role_sessions',ARRAY['tenant_id','session_id'],ARRAY['tenant_id','id'])) expected(source_table,target_table,source_columns,target_columns) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=to_regclass(required.source_table)
          AND c.contype='f' AND c.confrelid=to_regclass(required.target_table) AND c.convalidated AND NOT c.condeferrable
          AND c.confupdtype='a' AND c.confdeltype='a' AND c.confmatchtype='s'
          AND ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(number,position)
            JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.number ORDER BY k.position)=required.source_columns
          AND ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(number,position)
            JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.number ORDER BY k.position)=required.target_columns) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('iam.role_sessions',ARRAY['tenant_id','source_user_id','request_id']),
      ('iam.role_directory_revisions',ARRAY['tenant_id']),
      ('iam.role_source_authority_generations',ARRAY['tenant_id','user_id']),
      ('iam.role_source_authority_generations',ARRAY['tenant_id','group_id']),
      ('iam.role_session_index',ARRAY['lookup_digest']),('iam.role_session_index',ARRAY['tenant_id','session_id']),
      ('iam.role_session_directory_revisions',ARRAY['tenant_id','role_id'])) expected(table_name,column_names) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_index i WHERE i.indrelid=to_regclass(required.table_name)
          AND i.indisunique AND i.indisvalid AND i.indisready AND NOT i.indnullsnotdistinct AND i.indexprs IS NULL AND i.indpred IS NULL
          AND i.indnkeyatts=cardinality(required.column_names) AND i.indnatts=i.indnkeyatts
          AND ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(number,position)
            JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.number ORDER BY k.position)=required.column_names) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('role_boundaries_role_fk','iam.roles',ARRAY['tenant_id','role_id'],ARRAY['tenant_id','id']),
      ('role_boundaries_policy_fk','iam.policies',ARRAY['policy_id'],ARRAY['id'])) expected(constraint_name,target_table,source_columns,target_columns) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid='iam.role_permission_boundaries'::regclass
          AND c.conname=required.constraint_name AND c.contype='f' AND c.confrelid=to_regclass(required.target_table)
          AND c.convalidated AND NOT c.condeferrable AND c.confupdtype='a' AND c.confdeltype='a' AND c.confmatchtype='s'
          AND ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(number,position)
              JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.number ORDER BY k.position)=required.source_columns
          AND ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(number,position)
              JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.number ORDER BY k.position)=required.target_columns) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES ('roles','roles_security_generation_range'),
      ('role_permission_boundaries','role_boundaries_terminal_state'),('role_directory_revisions','role_directory_revision_range'),
      ('role_source_authority_generations','role_source_exact_kind'),('role_source_authority_generations','role_source_generation_range'),
      ('role_session_directory_revisions','role_session_directory_revision_range'),
      ('role_sessions','role_sessions_authority_contract')) expected(table_name,constraint_name) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=to_regclass('iam.'||required.table_name)
          AND c.conname=required.constraint_name AND c.contype='c' AND c.convalidated) THEN RETURN false; END IF;
    END LOOP;
    IF NOT EXISTS(SELECT 1 FROM pg_index i WHERE i.indexrelid=to_regclass('iam.role_boundaries_current_role_uq')
      AND i.indrelid='iam.role_permission_boundaries'::regclass AND i.indisunique AND i.indisvalid AND i.indisready
      AND i.indnkeyatts=2 AND i.indnatts=2 AND i.indexprs IS NULL AND pg_get_expr(i.indpred,i.indrelid)='(revoked_at IS NULL)'
      AND ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(number,position)
          JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.number ORDER BY k.position)=ARRAY['tenant_id','role_id']) THEN RETURN false; END IF;
    FOR required IN SELECT * FROM (VALUES
      ('iam.list_roles(text,text,text,text)',false),('iam.read_role(text,text,text,text)',false),
      ('iam.read_role_discovery_revision(text,text,text)',false),('iam.read_role_candidates(text,text,text,text,text)',false),
      ('iam.prepare_role_session_management(text,text,text,text,text,boolean)',false),
      ('iam.list_managed_role_sessions(text,text,text,text,text,text,text,text,text)',false),
      ('iam.read_managed_role_session(text,text,text,text,text,text)',false),
      ('iam.revoke_managed_role_session(text,text,text,text,text,text,jsonb)',false),
      ('iam.read_role_permission_boundary(text,text,text,text)',false),
      ('iam.lookup_role_session(text)',false),('iam.read_role_assumption(text,text,text,text,text)',false),
      ('iam.lookup_role_session_for_exit(text)',false),('iam.exit_role_session(text,jsonb)',false),
      ('iam.issue_role_session(text,text,text,text,text,jsonb,text,text,jsonb,jsonb)',false),
      ('iam.read_role_session_by_request(text,text,text,text)',false),
      ('iam.revoke_role_session_by_request(text,text,text,text,jsonb)',false),
      ('iam.change_role_permission_boundary(text,text,text,text,bigint,text,bigint,text,jsonb,text)',true),
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
          OR (entrypoint.proname='lookup_role_session_for_exit' AND entrypoint.proargnames IS DISTINCT FROM ARRAY['lookup_digest'])
          OR (entrypoint.proname='exit_role_session' AND entrypoint.proargnames IS DISTINCT FROM ARRAY['lookup_digest','event'])
          OR (entrypoint.proname='read_role_discovery_revision' AND entrypoint.proargnames IS DISTINCT FROM ARRAY['tenant','actor','source_session'])
          OR (entrypoint.proname='read_role_candidates' AND entrypoint.proargnames IS DISTINCT FROM ARRAY['tenant','actor','source_session','after_id','role_id'])
          OR (entrypoint.proname='prepare_role_session_management' AND entrypoint.proargnames IS DISTINCT FROM ARRAY['tenant','actor','actor_session','role_id','session_id','writing'])
          OR (entrypoint.proname='list_managed_role_sessions' AND entrypoint.proargnames IS DISTINCT FROM ARRAY['tenant','actor','actor_session','role_id','decision','after_id','source_user_id','session_id','lifecycle'])
          OR (entrypoint.proname='read_managed_role_session' AND entrypoint.proargnames IS DISTINCT FROM ARRAY['tenant','actor','actor_session','role_id','session_id','decision'])
          OR (entrypoint.proname='revoke_managed_role_session' AND entrypoint.proargnames IS DISTINCT FROM ARRAY['tenant','actor','actor_session','role_id','session_id','decision','event'])
          OR NOT has_function_privilege('matrix_iam_api',entrypoint.oid,'EXECUTE')
          OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(entrypoint.proacl,acldefault('f',entrypoint.proowner))) permission
            WHERE permission.grantee NOT IN (entrypoint.proowner,'matrix_iam_api'::regrole)
              OR (permission.grantee='matrix_iam_api'::regrole AND permission.is_grantable)) THEN RETURN false; END IF;
    END LOOP;
    FOREACH signature IN ARRAY ARRAY['iam.role_metadata_valid(jsonb)','iam.role_trust_content_valid(text,text)',
      'iam.guard_role_session_directory_revision()','iam.advance_role_session_directory_revision()','iam.managed_role_session_snapshot(text,text,text)',
      'iam.guard_role_change()','iam.assert_role_writer(text,text,text,jsonb)','iam.role_snapshot(text,text)',
      'iam.guard_role_directory_revision()','iam.advance_role_directory_revision()',
      'iam.guard_role_source_authority_generation()','iam.advance_role_source_authority_generation()','iam.role_source_authority_snapshot(text,text)',
      'iam.role_trust_snapshot(text,text,text)','iam.role_access_snapshot(text,text)',
      'iam.guard_role_boundary_change()','iam.role_permission_boundary_snapshot(text,text)',
      'iam.guard_role_session_change()','iam.assert_role_session_source(text,text,text,boolean)',
      'iam.role_session_snapshot(text,text)','iam.role_policy_snapshot(text,text)',
	  'iam.role_snapshot_version_matches(jsonb)','iam.role_authorization_evidence(text,text)','iam.assert_current_role_authorization(text,text,jsonb)',
      'iam.assert_role_intent(text,text,jsonb)','iam.role_event_matches(text,text,jsonb)'] LOOP
        SELECT p.* INTO entrypoint FROM pg_proc p WHERE p.oid=to_regprocedure(signature);
        IF NOT FOUND THEN RETURN false; END IF;
        IF entrypoint.proowner<>'matrix_iam_owner'::regrole OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(entrypoint.proacl,acldefault('f',entrypoint.proowner))) permission
          WHERE permission.grantee<>entrypoint.proowner) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('iam.guard_role_source_authority_generation()','trigger'::regtype,false,ARRAY[]::text[]),
      ('iam.advance_role_source_authority_generation()','trigger'::regtype,true,ARRAY[]::text[]),
      ('iam.role_source_authority_snapshot(text,text)','jsonb'::regtype,false,ARRAY['tenant','source_user']),
      ('iam.guard_role_session_directory_revision()','trigger'::regtype,false,ARRAY[]::text[]),
      ('iam.advance_role_session_directory_revision()','trigger'::regtype,true,ARRAY[]::text[])) expected(signature,result_type,defining,argument_names) LOOP
        SELECT p.* INTO entrypoint FROM pg_proc p WHERE p.oid=to_regprocedure(required.signature);
        IF NOT FOUND THEN RETURN false; END IF;
        IF (SELECT count(*) FROM pg_proc p WHERE p.pronamespace=entrypoint.pronamespace AND p.proname=entrypoint.proname)<>1
          OR entrypoint.prosecdef IS DISTINCT FROM required.defining OR entrypoint.proretset
          OR entrypoint.prorettype<>required.result_type OR entrypoint.pronargdefaults<>0 OR entrypoint.provariadic<>0
          OR entrypoint.provolatile<>'v' OR entrypoint.proparallel<>'u' OR entrypoint.proisstrict OR entrypoint.proleakproof
          OR entrypoint.proallargtypes IS NOT NULL OR entrypoint.proargmodes IS NOT NULL
          OR COALESCE(entrypoint.proargnames,ARRAY[]::text[]) IS DISTINCT FROM required.argument_names
          OR entrypoint.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RETURN false; END IF;
    END LOOP;
    IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=to_regclass('iam.roles')
      AND c.confrelid=to_regclass('iam.role_trust_versions') AND c.conname='roles_current_trust_fk'
      AND c.contype='f' AND c.convalidated AND c.condeferrable AND c.condeferred) THEN RETURN false; END IF;
    FOR required IN SELECT * FROM (VALUES ('roles','roles_guard_change'),('roles','cannot_delete'),('roles','cannot_truncate'),
      ('roles','roles_advance_directory'),('policies','policies_advance_role_directory'),
      ('policy_attachments','attachments_advance_role_directory'),('group_memberships','memberships_advance_role_directory'),
      ('role_directory_revisions','role_directory_monotonic'),('role_directory_revisions','cannot_truncate'),
      ('role_trust_versions','trust_cannot_update'),('role_trust_versions','cannot_delete'),('role_trust_versions','cannot_truncate'),
      ('role_permission_boundaries','role_boundary_transitions'),('role_permission_boundaries','cannot_delete'),('role_permission_boundaries','cannot_truncate'),
      ('role_sessions','role_session_terminal_state'),('role_sessions','role_sessions_cannot_truncate'),
      ('role_session_index','role_session_index_immutable'),('role_session_index','role_session_index_cannot_truncate')) expected(table_name,trigger_name) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=to_regclass('iam.'||required.table_name)
          AND t.tgname=required.trigger_name AND t.tgenabled='A' AND NOT t.tgisinternal) THEN RETURN false; END IF;
    END LOOP;
    FOREACH table_name IN ARRAY ARRAY['role_directory_revisions','role_source_authority_generations','role_session_directory_revisions'] LOOP
      relation_oid:=to_regclass('iam.'||table_name);
      IF (SELECT count(*) FROM pg_policy WHERE polrelid=relation_oid)<>1
       OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=relation_oid
         AND p.polname='tenant_isolation' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY[0::oid]
         AND pg_get_expr(p.polqual,p.polrelid)='(tenant_id = iam.current_tenant_id())'
         AND pg_get_expr(p.polwithcheck,p.polrelid)='(tenant_id = iam.current_tenant_id())') THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('roles','roles_advance_directory','iam.advance_role_directory_revision()',21),
      ('policies','policies_advance_role_directory','iam.advance_role_directory_revision()',17),
      ('policy_attachments','attachments_advance_role_directory','iam.advance_role_directory_revision()',21),
      ('group_memberships','memberships_advance_role_directory','iam.advance_role_directory_revision()',21),
      ('principals','principals_initialize_role_source','iam.advance_role_source_authority_generation()',5),
      ('groups','groups_initialize_role_source','iam.advance_role_source_authority_generation()',5),
      ('policy_attachments','attachments_advance_role_source','iam.advance_role_source_authority_generation()',21),
      ('group_memberships','memberships_advance_role_source','iam.advance_role_source_authority_generation()',21),
      ('user_permission_boundaries','boundaries_advance_role_source','iam.advance_role_source_authority_generation()',21),
      ('role_source_authority_generations','source_authority_monotonic','iam.guard_role_source_authority_generation()',31),
      ('role_source_authority_generations','cannot_truncate','iam.reject_policy_history_change()',34),
      ('role_sessions','role_session_terminal_state','iam.guard_role_session_change()',31),
      ('roles','roles_initialize_session_directory','iam.advance_role_session_directory_revision()',5),
      ('role_sessions','sessions_advance_directory','iam.advance_role_session_directory_revision()',21),
      ('role_session_directory_revisions','role_session_directory_monotonic','iam.guard_role_session_directory_revision()',31),
      ('role_session_directory_revisions','cannot_truncate','iam.reject_policy_history_change()',34),
      ('role_directory_revisions','role_directory_monotonic','iam.guard_role_directory_revision()',27),
      ('role_directory_revisions','cannot_truncate','iam.reject_policy_history_change()',34)) expected(table_name,trigger_name,signature,trigger_type) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=to_regclass('iam.'||required.table_name)
          AND t.tgname=required.trigger_name AND t.tgfoid=to_regprocedure(required.signature) AND t.tgtype=required.trigger_type
          AND t.tgenabled='A' AND t.tgnargs=0 AND NOT t.tgisinternal AND cardinality(t.tgattr::smallint[])=0
          AND (required.signature='iam.advance_role_directory_revision()' OR t.tgqual IS NULL)
          AND t.tgdeferrable=(required.signature IN ('iam.advance_role_directory_revision()','iam.advance_role_source_authority_generation()'))
          AND t.tginitdeferred=t.tgdeferrable) THEN RETURN false; END IF;
    END LOOP;
    IF NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid='iam.advance_role_directory_revision()'::regprocedure
        AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']) THEN RETURN false; END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid='iam.role_session_directory_revisions'::regclass
      AND c.conname='role_session_directory_role_fk' AND c.contype='f' AND c.confrelid='iam.roles'::regclass AND c.convalidated
      AND NOT c.condeferrable AND c.confupdtype='a' AND c.confdeltype='a' AND c.confmatchtype='s'
      AND ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(number,position)
        JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.number ORDER BY k.position)=ARRAY['tenant_id','role_id']
      AND ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(number,position)
        JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.number ORDER BY k.position)=ARRAY['tenant_id','id']) THEN RETURN false; END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_index i WHERE i.indexrelid=to_regclass('iam.role_sessions_directory_idx')
      AND i.indrelid='iam.role_sessions'::regclass AND i.indisvalid AND i.indisready AND NOT i.indisunique AND i.indexprs IS NULL AND i.indpred IS NULL
      AND i.indnkeyatts=3 AND i.indnatts=3 AND ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(number,position)
        JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.number ORDER BY k.position)=ARRAY['tenant_id','role_id','id']) THEN RETURN false; END IF;
    IF EXISTS(SELECT 1 FROM pg_attrdef WHERE adrelid='iam.role_session_directory_revisions'::regclass) THEN RETURN false; END IF;
    SELECT p.* INTO entrypoint FROM pg_proc p WHERE p.oid=to_regprocedure('iam.managed_role_session_snapshot(text,text,text)');
    IF NOT FOUND OR entrypoint.prosecdef OR entrypoint.proretset OR entrypoint.prorettype<>'jsonb'::regtype OR entrypoint.provolatile<>'s'
      OR entrypoint.pronargdefaults<>0 OR entrypoint.provariadic<>0 OR entrypoint.proparallel<>'u' OR entrypoint.proisstrict OR entrypoint.proleakproof
      OR entrypoint.proallargtypes IS NOT NULL OR entrypoint.proargmodes IS NOT NULL OR entrypoint.proargnames IS DISTINCT FROM ARRAY['tenant','role_id','session_id']
      OR entrypoint.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp'] THEN RETURN false; END IF;
    RETURN true;
END $function$;

REVOKE ALL ON iam.roles,iam.role_trust_versions,iam.role_permission_boundaries FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON FUNCTION iam.role_metadata_valid(jsonb),iam.role_trust_content_valid(text,text),
    iam.guard_role_change(),iam.assert_role_writer(text,text,text,jsonb),iam.role_snapshot(text,text),
    iam.role_trust_snapshot(text,text,text),iam.role_access_snapshot(text,text),
    iam.guard_role_boundary_change(),iam.role_permission_boundary_snapshot(text,text),
    iam.read_role_permission_boundary(text,text,text,text),iam.change_role_permission_boundary(text,text,text,text,bigint,text,bigint,text,jsonb,text),
    iam.assert_role_intent(text,text,jsonb),iam.role_event_matches(text,text,jsonb),iam.role_contract_ready(),
    iam.list_roles(text,text,text,text),iam.read_role(text,text,text,text),
    iam.create_role(text,text,text,text,text,jsonb,jsonb,jsonb,text),
    iam.update_role(text,text,text,text,bigint,jsonb,jsonb,text),iam.set_role_status(text,text,text,text,bigint,text,jsonb,text),
    iam.set_role_trust_policy(text,text,text,text,text,bigint,jsonb,jsonb,text),iam.delete_role(text,text,text,text,bigint,jsonb,text),
    iam.list_role_trust_versions(text,text,text,text,text),iam.read_role_trust_version(text,text,text,text,text)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.list_roles(text,text,text,text),iam.read_role(text,text,text,text),
    iam.read_role_permission_boundary(text,text,text,text),iam.change_role_permission_boundary(text,text,text,text,bigint,text,bigint,text,jsonb,text),
    iam.create_role(text,text,text,text,text,jsonb,jsonb,jsonb,text),
    iam.update_role(text,text,text,text,bigint,jsonb,jsonb,text),iam.set_role_status(text,text,text,text,bigint,text,jsonb,text),
    iam.set_role_trust_policy(text,text,text,text,text,bigint,jsonb,jsonb,text),iam.delete_role(text,text,text,text,bigint,jsonb,text),
    iam.list_role_trust_versions(text,text,text,text,text),iam.read_role_trust_version(text,text,text,text,text) TO matrix_iam_api;
