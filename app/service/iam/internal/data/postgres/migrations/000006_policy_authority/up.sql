


CREATE UNIQUE INDEX IF NOT EXISTS customer_policies_active_name_uq
    ON iam.policies(owner_tenant_id,display_name COLLATE "C") WHERE management='CUSTOMER' AND status='ACTIVE';
CREATE INDEX IF NOT EXISTS policies_active_directory_idx
    ON iam.policies(authority_scope,owner_tenant_id,id) WHERE status='ACTIVE';
CREATE INDEX IF NOT EXISTS policy_attachments_live_policy_idx
    ON iam.policy_attachments(policy_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS policy_versions_active_inventory_idx
    ON iam.policy_versions(policy_id,id) WHERE retired_at IS NULL;

CREATE TABLE IF NOT EXISTS iam.user_permission_boundaries (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    user_id text COLLATE "C" NOT NULL,
    policy_id text COLLATE "C" NOT NULL REFERENCES iam.policies(id),
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    revoked_at timestamptz(6),
    PRIMARY KEY(tenant_id,id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES iam.principals(tenant_id,id),
    CONSTRAINT user_permission_boundaries_values_valid CHECK (
        id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND user_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND resource_version BETWEEN 1 AND 9007199254740991
        AND updated_at>=created_at
        AND (revoked_at IS NULL OR (revoked_at=updated_at AND resource_version=2)))
);
CREATE UNIQUE INDEX IF NOT EXISTS user_permission_boundaries_current_user_uq
    ON iam.user_permission_boundaries(tenant_id,user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS user_permission_boundaries_current_policy_idx
    ON iam.user_permission_boundaries(policy_id) WHERE revoked_at IS NULL;
ALTER TABLE iam.user_permission_boundaries ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.user_permission_boundaries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON iam.user_permission_boundaries;
CREATE POLICY tenant_isolation ON iam.user_permission_boundaries
    USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id());
REVOKE ALL ON iam.user_permission_boundaries FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;

CREATE OR REPLACE FUNCTION iam.guard_user_permission_boundary_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.resource_version<>1 OR NEW.revoked_at IS NOT NULL OR NEW.created_at<>transaction_timestamp() OR NEW.updated_at<>NEW.created_at
           OR NOT EXISTS(SELECT 1 FROM iam.principals p WHERE p.tenant_id=NEW.tenant_id AND p.id=NEW.user_id
                AND p.principal_type='USER' AND p.deleted_at IS NULL)
           OR EXISTS(SELECT 1 FROM iam.account_roots r WHERE r.account_id=NEW.tenant_id AND r.principal_id=NEW.user_id)
           OR NOT EXISTS(SELECT 1 FROM iam.policies p WHERE p.id=NEW.policy_id AND p.authority_scope='TENANT' AND p.status='ACTIVE'
                AND (p.owner_tenant_id IS NULL OR p.owner_tenant_id=NEW.tenant_id)) THEN
            RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='user boundary identity is invalid';
        END IF;
    ELSIF ROW(NEW.tenant_id,NEW.id,NEW.user_id,NEW.policy_id,NEW.created_at)
            IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.user_id,OLD.policy_id,OLD.created_at)
       OR OLD.revoked_at IS NOT NULL OR NEW.resource_version<>OLD.resource_version+1
       OR NEW.revoked_at IS DISTINCT FROM transaction_timestamp() OR NEW.updated_at IS DISTINCT FROM NEW.revoked_at THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='user boundary history is immutable';
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS user_boundary_transitions ON iam.user_permission_boundaries;
CREATE TRIGGER user_boundary_transitions BEFORE INSERT OR UPDATE ON iam.user_permission_boundaries
    FOR EACH ROW EXECUTE FUNCTION iam.guard_user_permission_boundary_change();
DROP TRIGGER IF EXISTS user_boundaries_cannot_be_deleted ON iam.user_permission_boundaries;
CREATE TRIGGER user_boundaries_cannot_be_deleted BEFORE DELETE ON iam.user_permission_boundaries
    FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS user_boundaries_cannot_be_truncated ON iam.user_permission_boundaries;
CREATE TRIGGER user_boundaries_cannot_be_truncated BEFORE TRUNCATE ON iam.user_permission_boundaries
    FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.user_permission_boundaries ENABLE ALWAYS TRIGGER user_boundary_transitions;
ALTER TABLE iam.user_permission_boundaries ENABLE ALWAYS TRIGGER user_boundaries_cannot_be_deleted;
ALTER TABLE iam.user_permission_boundaries ENABLE ALWAYS TRIGGER user_boundaries_cannot_be_truncated;

-- A delegated default-version selection changes every current consumer on the
-- next request. Keep its exact closure proof separate from mutable Policy and
-- attachment rows so an exact no-effect replay can be distinguished from a
-- new authorization attempt after the ceiling or consumer set changes.
CREATE TABLE IF NOT EXISTS iam.policy_default_version_changes (
    tenant_id text COLLATE "C" NOT NULL,
    actor_principal_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    policy_id text COLLATE "C" NOT NULL,
    expected_resource_version bigint NOT NULL,
    version_id text COLLATE "C" NOT NULL,
    actor_boundary_evidence jsonb NOT NULL,
    attachment_count bigint NOT NULL,
    attachment_closure_digest text COLLATE "C" NOT NULL,
    decision_id text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    completed_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,actor_principal_id,request_id),
    FOREIGN KEY(tenant_id,actor_principal_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(policy_id,version_id) REFERENCES iam.policy_versions(policy_id,id),
    FOREIGN KEY(tenant_id,decision_id) REFERENCES iam.authorization_decisions(tenant_id,id),
    FOREIGN KEY(tenant_id,event_id) REFERENCES iam.audit_outbox(tenant_id,event_id),
    CONSTRAINT policy_default_version_changes_shape CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND actor_principal_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND policy_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND version_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND decision_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND event_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND expected_resource_version BETWEEN 1 AND 9007199254740990
        AND attachment_count BETWEEN 0 AND 9007199254740991
        AND attachment_closure_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND jsonb_typeof(actor_boundary_evidence)='object'
        AND actor_boundary_evidence->>'state'='BOUND'
        AND actor_boundary_evidence-ARRAY['state','userResourceVersion','boundaryId','resourceVersion','version','contractVersion','compilation']='{}'::jsonb
        AND jsonb_typeof(actor_boundary_evidence->'userResourceVersion')='number'
        AND jsonb_typeof(actor_boundary_evidence->'resourceVersion')='number'
        AND COALESCE(actor_boundary_evidence->>'userResourceVersion','') ~ '^[1-9][0-9]{0,15}$'
        AND COALESCE(actor_boundary_evidence->>'resourceVersion','') ~ '^[1-9][0-9]{0,15}$'
        AND COALESCE(actor_boundary_evidence->>'boundaryId','') COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND jsonb_typeof(actor_boundary_evidence->'version')='object'
        AND (actor_boundary_evidence->'version') ?& ARRAY['policyId','versionId','contentDigest']
        AND (actor_boundary_evidence->'version')-ARRAY['policyId','versionId','contentDigest']='{}'::jsonb
        AND actor_boundary_evidence#>>'{version,policyId}' COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND actor_boundary_evidence#>>'{version,versionId}' COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND actor_boundary_evidence#>>'{version,contentDigest}' COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND ((actor_boundary_evidence->'contractVersion'='1'::jsonb AND NOT actor_boundary_evidence ? 'compilation')
          OR (actor_boundary_evidence->'contractVersion'='2'::jsonb
            AND jsonb_typeof(actor_boundary_evidence->'compilation')='object')))
);
ALTER TABLE iam.policy_default_version_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_default_version_changes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON iam.policy_default_version_changes;
CREATE POLICY tenant_isolation ON iam.policy_default_version_changes
    USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id());

CREATE OR REPLACE FUNCTION iam.guard_policy_default_version_change_insert()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF current_setting('matrix.iam_policy_default_version_change',true) IS DISTINCT FROM 'trusted' THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy default version completion insertion is forbidden';
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS policy_default_version_change_insert_guard ON iam.policy_default_version_changes;
CREATE TRIGGER policy_default_version_change_insert_guard BEFORE INSERT ON iam.policy_default_version_changes
    FOR EACH ROW EXECUTE FUNCTION iam.guard_policy_default_version_change_insert();
DROP TRIGGER IF EXISTS policy_default_version_changes_cannot_be_updated ON iam.policy_default_version_changes;
CREATE TRIGGER policy_default_version_changes_cannot_be_updated BEFORE UPDATE ON iam.policy_default_version_changes
    FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS policy_default_version_changes_cannot_be_deleted ON iam.policy_default_version_changes;
CREATE TRIGGER policy_default_version_changes_cannot_be_deleted BEFORE DELETE ON iam.policy_default_version_changes
    FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS policy_default_version_changes_cannot_be_truncated ON iam.policy_default_version_changes;
CREATE TRIGGER policy_default_version_changes_cannot_be_truncated BEFORE TRUNCATE ON iam.policy_default_version_changes
    FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.policy_default_version_changes ENABLE ALWAYS TRIGGER policy_default_version_change_insert_guard;
ALTER TABLE iam.policy_default_version_changes ENABLE ALWAYS TRIGGER policy_default_version_changes_cannot_be_updated;
ALTER TABLE iam.policy_default_version_changes ENABLE ALWAYS TRIGGER policy_default_version_changes_cannot_be_deleted;
ALTER TABLE iam.policy_default_version_changes ENABLE ALWAYS TRIGGER policy_default_version_changes_cannot_be_truncated;
REVOKE ALL ON TABLE iam.policy_default_version_changes FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON FUNCTION iam.guard_policy_default_version_change_insert()
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;

-- Retiring a non-default version does not change current authorization, but a
-- delegated author still needs an immutable proof of the exact ceiling and
-- command that produced the terminal version state. Keep that proof separate
-- from the mutable Policy revision so a no-effect replay cannot be confused
-- with a new retirement after the actor ceiling is removed.
CREATE TABLE IF NOT EXISTS iam.policy_version_retirements (
    tenant_id text COLLATE "C" NOT NULL,
    actor_principal_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    policy_id text COLLATE "C" NOT NULL,
    version_id text COLLATE "C" NOT NULL,
    expected_resource_version bigint NOT NULL,
    actor_boundary_evidence jsonb NOT NULL,
    decision_id text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    completed_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,actor_principal_id,request_id),
    FOREIGN KEY(tenant_id,actor_principal_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(policy_id,version_id) REFERENCES iam.policy_versions(policy_id,id),
    FOREIGN KEY(tenant_id,decision_id) REFERENCES iam.authorization_decisions(tenant_id,id),
    FOREIGN KEY(tenant_id,event_id) REFERENCES iam.audit_outbox(tenant_id,event_id),
    CONSTRAINT policy_version_retirements_shape CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND actor_principal_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND policy_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND version_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND decision_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND event_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND expected_resource_version BETWEEN 1 AND 9007199254740990
        AND jsonb_typeof(actor_boundary_evidence)='object'
        AND actor_boundary_evidence->>'state'='BOUND'
        AND actor_boundary_evidence-ARRAY['state','userResourceVersion','boundaryId','resourceVersion','version','contractVersion','compilation']='{}'::jsonb
        AND jsonb_typeof(actor_boundary_evidence->'userResourceVersion')='number'
        AND jsonb_typeof(actor_boundary_evidence->'resourceVersion')='number'
        AND COALESCE(actor_boundary_evidence->>'userResourceVersion','') ~ '^[1-9][0-9]{0,15}$'
        AND COALESCE(actor_boundary_evidence->>'resourceVersion','') ~ '^[1-9][0-9]{0,15}$'
        AND COALESCE(actor_boundary_evidence->>'boundaryId','') COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND jsonb_typeof(actor_boundary_evidence->'version')='object'
        AND (actor_boundary_evidence->'version') ?& ARRAY['policyId','versionId','contentDigest']
        AND (actor_boundary_evidence->'version')-ARRAY['policyId','versionId','contentDigest']='{}'::jsonb
        AND actor_boundary_evidence#>>'{version,policyId}' COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND actor_boundary_evidence#>>'{version,versionId}' COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND actor_boundary_evidence#>>'{version,contentDigest}' COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND ((actor_boundary_evidence->'contractVersion'='1'::jsonb AND NOT actor_boundary_evidence ? 'compilation')
          OR (actor_boundary_evidence->'contractVersion'='2'::jsonb
            AND jsonb_typeof(actor_boundary_evidence->'compilation')='object')))
);
ALTER TABLE iam.policy_version_retirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_version_retirements FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON iam.policy_version_retirements;
CREATE POLICY tenant_isolation ON iam.policy_version_retirements
    USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id());

CREATE OR REPLACE FUNCTION iam.guard_policy_version_retirement_insert()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF current_setting('matrix.iam_policy_version_retirement',true) IS DISTINCT FROM 'trusted' THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy version retirement completion insertion is forbidden';
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS policy_version_retirement_insert_guard ON iam.policy_version_retirements;
CREATE TRIGGER policy_version_retirement_insert_guard BEFORE INSERT ON iam.policy_version_retirements
    FOR EACH ROW EXECUTE FUNCTION iam.guard_policy_version_retirement_insert();
DROP TRIGGER IF EXISTS policy_version_retirements_cannot_be_updated ON iam.policy_version_retirements;
CREATE TRIGGER policy_version_retirements_cannot_be_updated BEFORE UPDATE ON iam.policy_version_retirements
    FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS policy_version_retirements_cannot_be_deleted ON iam.policy_version_retirements;
CREATE TRIGGER policy_version_retirements_cannot_be_deleted BEFORE DELETE ON iam.policy_version_retirements
    FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS policy_version_retirements_cannot_be_truncated ON iam.policy_version_retirements;
CREATE TRIGGER policy_version_retirements_cannot_be_truncated BEFORE TRUNCATE ON iam.policy_version_retirements
    FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.policy_version_retirements ENABLE ALWAYS TRIGGER policy_version_retirement_insert_guard;
ALTER TABLE iam.policy_version_retirements ENABLE ALWAYS TRIGGER policy_version_retirements_cannot_be_updated;
ALTER TABLE iam.policy_version_retirements ENABLE ALWAYS TRIGGER policy_version_retirements_cannot_be_deleted;
ALTER TABLE iam.policy_version_retirements ENABLE ALWAYS TRIGGER policy_version_retirements_cannot_be_truncated;
REVOKE ALL ON TABLE iam.policy_version_retirements FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON FUNCTION iam.guard_policy_version_retirement_insert()
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;

-- A delegated metadata update changes no authority, but its exact actor
-- ceiling, intent and fact must remain independently provable after mutable
-- Policy metadata or the actor's current boundary changes.
CREATE TABLE IF NOT EXISTS iam.policy_metadata_updates (
    tenant_id text COLLATE "C" NOT NULL,
    actor_principal_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    policy_id text COLLATE "C" NOT NULL REFERENCES iam.policies(id),
    expected_resource_version bigint NOT NULL,
    display_name text COLLATE "C" NOT NULL,
    actor_boundary_evidence jsonb NOT NULL,
    decision_id text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    completed_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,actor_principal_id,request_id),
    FOREIGN KEY(tenant_id,actor_principal_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(tenant_id,decision_id) REFERENCES iam.authorization_decisions(tenant_id,id),
    FOREIGN KEY(tenant_id,event_id) REFERENCES iam.audit_outbox(tenant_id,event_id),
    CONSTRAINT policy_metadata_updates_shape CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND actor_principal_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND policy_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND decision_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND event_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND expected_resource_version BETWEEN 1 AND 9007199254740990
        AND octet_length(display_name) BETWEEN 1 AND 128
        AND display_name=btrim(display_name) AND display_name !~ '[[:cntrl:]]'
        AND jsonb_typeof(actor_boundary_evidence)='object'
        AND actor_boundary_evidence->>'state'='BOUND'
        AND actor_boundary_evidence-ARRAY['state','userResourceVersion','boundaryId','resourceVersion','version','contractVersion','compilation']='{}'::jsonb
        AND jsonb_typeof(actor_boundary_evidence->'userResourceVersion')='number'
        AND jsonb_typeof(actor_boundary_evidence->'resourceVersion')='number'
        AND COALESCE(actor_boundary_evidence->>'userResourceVersion','') ~ '^[1-9][0-9]{0,15}$'
        AND COALESCE(actor_boundary_evidence->>'resourceVersion','') ~ '^[1-9][0-9]{0,15}$'
        AND COALESCE(actor_boundary_evidence->>'boundaryId','') COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND jsonb_typeof(actor_boundary_evidence->'version')='object'
        AND (actor_boundary_evidence->'version') ?& ARRAY['policyId','versionId','contentDigest']
        AND (actor_boundary_evidence->'version')-ARRAY['policyId','versionId','contentDigest']='{}'::jsonb
        AND actor_boundary_evidence#>>'{version,policyId}' COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND actor_boundary_evidence#>>'{version,versionId}' COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND actor_boundary_evidence#>>'{version,contentDigest}' COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND ((actor_boundary_evidence->'contractVersion'='1'::jsonb AND NOT actor_boundary_evidence ? 'compilation')
          OR (actor_boundary_evidence->'contractVersion'='2'::jsonb
            AND jsonb_typeof(actor_boundary_evidence->'compilation')='object')))
);
ALTER TABLE iam.policy_metadata_updates ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_metadata_updates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON iam.policy_metadata_updates;
CREATE POLICY tenant_isolation ON iam.policy_metadata_updates
    USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id());

CREATE OR REPLACE FUNCTION iam.guard_policy_metadata_update_insert()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF current_setting('matrix.iam_policy_metadata_update',true) IS DISTINCT FROM 'trusted' THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy metadata completion insertion is forbidden';
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS policy_metadata_update_insert_guard ON iam.policy_metadata_updates;
CREATE TRIGGER policy_metadata_update_insert_guard BEFORE INSERT ON iam.policy_metadata_updates
    FOR EACH ROW EXECUTE FUNCTION iam.guard_policy_metadata_update_insert();
DROP TRIGGER IF EXISTS policy_metadata_updates_cannot_be_updated ON iam.policy_metadata_updates;
CREATE TRIGGER policy_metadata_updates_cannot_be_updated BEFORE UPDATE ON iam.policy_metadata_updates
    FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS policy_metadata_updates_cannot_be_deleted ON iam.policy_metadata_updates;
CREATE TRIGGER policy_metadata_updates_cannot_be_deleted BEFORE DELETE ON iam.policy_metadata_updates
    FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS policy_metadata_updates_cannot_be_truncated ON iam.policy_metadata_updates;
CREATE TRIGGER policy_metadata_updates_cannot_be_truncated BEFORE TRUNCATE ON iam.policy_metadata_updates
    FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.policy_metadata_updates ENABLE ALWAYS TRIGGER policy_metadata_update_insert_guard;
ALTER TABLE iam.policy_metadata_updates ENABLE ALWAYS TRIGGER policy_metadata_updates_cannot_be_updated;
ALTER TABLE iam.policy_metadata_updates ENABLE ALWAYS TRIGGER policy_metadata_updates_cannot_be_deleted;
ALTER TABLE iam.policy_metadata_updates ENABLE ALWAYS TRIGGER policy_metadata_updates_cannot_be_truncated;
REVOKE ALL ON TABLE iam.policy_metadata_updates FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON FUNCTION iam.guard_policy_metadata_update_insert()
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;

CREATE OR REPLACE FUNCTION iam.current_user_boundary(tenant text,user_id text)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE subject iam.principals%ROWTYPE; binding iam.user_permission_boundaries%ROWTYPE;
    policy iam.policies%ROWTYPE; version iam.policy_versions%ROWTYPE;
BEGIN
    SELECT * INTO subject FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=user_id
        AND p.principal_type='USER' AND p.deleted_at IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='boundary subject is unavailable'; END IF;
    SELECT * INTO binding FROM iam.user_permission_boundaries b WHERE b.tenant_id=tenant AND b.user_id=current_user_boundary.user_id AND b.revoked_at IS NULL;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('state','NONE','accountId',tenant,'userId',user_id,'userResourceVersion',subject.resource_version);
    END IF;
    SELECT * INTO policy FROM iam.policies p WHERE p.id=binding.policy_id AND p.status='ACTIVE'
        AND p.authority_scope='TENANT' AND (p.owner_tenant_id IS NULL OR p.owner_tenant_id=tenant);
    IF NOT FOUND OR EXISTS(SELECT 1 FROM iam.account_roots r WHERE r.account_id=tenant AND r.principal_id=user_id) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='boundary policy is unavailable';
    END IF;
    SELECT * INTO version FROM iam.policy_versions v WHERE v.policy_id=policy.id AND v.id=policy.default_version_id AND v.retired_at IS NULL;
    IF NOT FOUND OR version.authority_scope<>'TENANT' THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='boundary version is unavailable'; END IF;
    RETURN jsonb_build_object('state','BOUND','accountId',tenant,'userId',user_id,'userResourceVersion',subject.resource_version,
        'boundaryId',binding.id,'resourceVersion',binding.resource_version,
        'policy',jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','Policy',
            'id',policy.id,'management',policy.management,'accountId',policy.owner_tenant_id,'displayName',policy.display_name,
            'scope',policy.authority_scope,'status',policy.status,'defaultVersionId',policy.default_version_id,
            'resourceVersion',policy.resource_version,'createdAt',policy.created_at,'updatedAt',policy.updated_at)),
        'version',iam.policy_version_snapshot(version));
END $function$;

CREATE OR REPLACE FUNCTION iam.current_user_boundary_evidence(tenant text,user_id text)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE boundary jsonb; evidence jsonb;
BEGIN
    boundary:=iam.current_user_boundary(tenant,user_id);
    evidence:=jsonb_build_object('state',boundary->>'state','userResourceVersion',boundary->'userResourceVersion');
    IF boundary->>'state'='BOUND' THEN
        evidence:=evidence||jsonb_strip_nulls(jsonb_build_object(
            'boundaryId',boundary->>'boundaryId','resourceVersion',boundary->'resourceVersion',
            'version',jsonb_build_object('policyId',boundary#>>'{version,value,policyId}',
                'versionId',boundary#>>'{version,value,versionId}',
                'contentDigest',boundary#>>'{version,value,contentDigest}'),
            'contractVersion',boundary#>'{version,value,contractVersion}',
            'compilation',boundary#>'{version,value,compilation}'));
    END IF;
    RETURN evidence;
END $function$;

CREATE OR REPLACE FUNCTION iam.assert_current_user_boundary_evidence(tenant text,actor text,action_name text,evidence jsonb)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE actor_type text; expected jsonb;
BEGIN
    SELECT principal_type INTO actor_type FROM iam.principals WHERE tenant_id=tenant AND id=actor;
    IF actor_type IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='boundary actor is unavailable'; END IF;
    IF iam.resource_kind_for_action(action_name) IS NULL OR iam.is_platform_action(action_name) IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='boundary action is not registered';
    END IF;
    IF actor_type<>'USER' OR iam.is_platform_action(action_name) OR action_name='installation.verify' THEN
        expected:=jsonb_build_object('state','NOT_APPLICABLE');
    ELSE
        expected:=iam.current_user_boundary_evidence(tenant,actor);
    END IF;
    IF evidence IS DISTINCT FROM expected THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='authorization boundary evidence is not current';
    END IF;
END $function$;

-- Resolve and lock the exact delegation proof used by a policy attachment
-- mutation. Root and installation-scoped commands use closed states instead
-- of pretending to carry an ordinary tenant permission boundary. A delegated
-- tenant writer may manage a direct USER or a Group whose complete membership
-- is constrained by the same current ceiling.
CREATE OR REPLACE FUNCTION iam.lock_policy_attachment_delegation(
    submitted_tenant text,submitted_actor text,submitted_decision text,submitted_action text,
    submitted_target_kind text,submitted_target_id text,submitted_authority_scope text,submitted_policy_id text
)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE actor_is_root boolean; actor_version bigint; actor_evidence jsonb; target_evidence jsonb;
    ceiling_policy_id text; ceiling iam.policies%ROWTYPE; attached iam.policies%ROWTYPE;
    member_document jsonb; member_count bigint; member_digest text;
BEGIN
    IF COALESCE(submitted_tenant,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(submitted_actor,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(submitted_decision,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(submitted_action,'') COLLATE "C" !~ '^[a-z0-9][a-z0-9._:-]{0,127}$'
      OR submitted_target_kind NOT IN ('USER','GROUP','ROLE')
      OR COALESCE(submitted_target_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR submitted_authority_scope NOT IN ('TENANT','INSTALLATION')
      OR COALESCE(submitted_policy_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy attachment delegation input is invalid';
    END IF;
    SELECT principal.resource_version,EXISTS(SELECT 1 FROM iam.account_roots root
        WHERE root.account_id=submitted_tenant AND root.principal_id=submitted_actor)
      INTO actor_version,actor_is_root FROM iam.principals principal
      WHERE principal.tenant_id=submitted_tenant AND principal.id=submitted_actor AND principal.principal_type='USER'
        AND principal.status='ACTIVE' AND principal.deleted_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy attachment actor is unavailable';
    END IF;
    SELECT recorded.boundary_evidence INTO actor_evidence FROM iam.authorization_decisions recorded
      WHERE recorded.tenant_id=submitted_tenant AND recorded.id=submitted_decision AND recorded.principal_id=submitted_actor
        AND recorded.action_name=submitted_action AND recorded.allowed;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy attachment decision is unavailable';
    END IF;
    PERFORM iam.assert_current_user_boundary_evidence(submitted_tenant,submitted_actor,submitted_action,actor_evidence);

    -- The public attachment mutation already owns the actor USER. Membership
    -- writers likewise own their actor and candidate USER before the Group.
    -- Lock every current member in stable order before the Group barrier; the
    -- private Group authorization generation forces a fresh Serializable
    -- snapshot if a concurrent member/attachment wins.
    IF submitted_target_kind='GROUP' THEN
        PERFORM principal.id FROM iam.principals principal
          WHERE principal.tenant_id=submitted_tenant AND principal.id<>submitted_actor
            AND EXISTS(SELECT 1 FROM iam.group_memberships member
              WHERE member.tenant_id=submitted_tenant AND member.group_id=submitted_target_id
                AND member.user_id=principal.id AND member.removed_at IS NULL)
          ORDER BY principal.id FOR NO KEY UPDATE;
    END IF;
    -- Boundary writers first lock the same principal rows, so an absent row
    -- cannot be inserted around this check. Existing rows are then locked in
    -- stable USER order before the Group and either policy row are acquired.
    PERFORM boundary.user_id FROM iam.user_permission_boundaries boundary
      WHERE boundary.tenant_id=submitted_tenant AND boundary.revoked_at IS NULL
        AND (boundary.user_id=submitted_actor
          OR (submitted_target_kind='USER' AND boundary.user_id=submitted_target_id)
          OR (submitted_target_kind='GROUP' AND EXISTS(SELECT 1 FROM iam.group_memberships member
              WHERE member.tenant_id=submitted_tenant AND member.group_id=submitted_target_id
                AND member.user_id=boundary.user_id AND member.removed_at IS NULL)))
      ORDER BY boundary.user_id FOR NO KEY UPDATE;

    IF submitted_target_kind='GROUP' THEN
        PERFORM 1 FROM iam.groups target_group
          WHERE target_group.tenant_id=submitted_tenant AND target_group.id=submitted_target_id
            AND target_group.deleted_at IS NULL FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy attachment group is unavailable';
        END IF;
        PERFORM member.id FROM iam.group_memberships member
          WHERE member.tenant_id=submitted_tenant AND member.group_id=submitted_target_id
            AND member.removed_at IS NULL ORDER BY member.id FOR UPDATE;
    END IF;

    IF actor_is_root THEN
        target_evidence:='{"state":"ROOT"}'::jsonb;
        actor_evidence:=jsonb_build_object('state','ROOT','userResourceVersion',actor_version);
    ELSIF submitted_authority_scope='INSTALLATION' THEN
        actor_evidence:='{"state":"NOT_APPLICABLE"}'::jsonb;
        target_evidence:='{"state":"NOT_APPLICABLE"}'::jsonb;
    ELSE
        IF submitted_target_kind NOT IN ('USER','GROUP') OR actor_evidence->>'state' IS DISTINCT FROM 'BOUND'
          OR EXISTS(SELECT 1 FROM iam.policy_attachments attachment
              WHERE attachment.tenant_id=submitted_tenant AND attachment.target_kind='USER'
                AND attachment.target_id=submitted_actor AND attachment.authority_scope='INSTALLATION'
                AND attachment.revoked_at IS NULL) THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='delegated policy attachment is unavailable';
        END IF;
        ceiling_policy_id:=actor_evidence#>>'{version,policyId}';
        IF submitted_target_kind='USER' THEN
            IF EXISTS(SELECT 1 FROM iam.policy_attachments attachment
                WHERE attachment.tenant_id=submitted_tenant AND attachment.target_kind='USER'
                  AND attachment.target_id=submitted_target_id AND attachment.authority_scope='INSTALLATION'
                  AND attachment.revoked_at IS NULL)
              OR EXISTS(SELECT 1 FROM iam.account_roots root
                  WHERE root.account_id=submitted_tenant AND root.principal_id=submitted_target_id) THEN
                RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='delegated policy attachment is unavailable';
            END IF;
            target_evidence:=iam.current_user_boundary_evidence(submitted_tenant,submitted_target_id);
            IF target_evidence->>'state' IS DISTINCT FROM 'BOUND'
              OR target_evidence#>>'{version,policyId}' IS DISTINCT FROM ceiling_policy_id
              OR target_evidence#>>'{version,versionId}' IS DISTINCT FROM actor_evidence#>>'{version,versionId}'
              OR target_evidence#>>'{version,contentDigest}' IS DISTINCT FROM actor_evidence#>>'{version,contentDigest}'
              OR target_evidence->'contractVersion' IS DISTINCT FROM actor_evidence->'contractVersion'
              OR target_evidence->'compilation' IS DISTINCT FROM actor_evidence->'compilation' THEN
                RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy attachment target boundary is unavailable';
            END IF;
        ELSE
            IF EXISTS(SELECT 1 FROM iam.policy_attachments attachment
                WHERE attachment.tenant_id=submitted_tenant AND attachment.target_kind='GROUP'
                  AND attachment.target_id=submitted_target_id AND attachment.revoked_at IS NULL
                  AND attachment.delegation_ceiling_policy_id IS NOT NULL
                  AND attachment.delegation_ceiling_policy_id<>ceiling_policy_id)
              OR EXISTS(SELECT 1 FROM iam.group_memberships member
                JOIN iam.principals principal ON (principal.tenant_id,principal.id)=(member.tenant_id,member.user_id)
                CROSS JOIN LATERAL (SELECT iam.current_user_boundary_evidence(member.tenant_id,member.user_id) AS evidence) current_boundary
                WHERE member.tenant_id=submitted_tenant AND member.group_id=submitted_target_id
                  AND member.removed_at IS NULL AND (
                    principal.principal_type<>'USER' OR principal.status<>'ACTIVE' OR principal.deleted_at IS NOT NULL
                    OR EXISTS(SELECT 1 FROM iam.account_roots root
                      WHERE root.account_id=member.tenant_id AND root.principal_id=member.user_id)
                    OR EXISTS(SELECT 1 FROM iam.policy_attachments attachment
                      WHERE attachment.tenant_id=member.tenant_id AND attachment.target_kind='USER'
                        AND attachment.target_id=member.user_id AND attachment.authority_scope='INSTALLATION'
                        AND attachment.revoked_at IS NULL)
                    OR current_boundary.evidence->>'state' IS DISTINCT FROM 'BOUND'
                    OR current_boundary.evidence#>>'{version,policyId}' IS DISTINCT FROM ceiling_policy_id
                    OR current_boundary.evidence#>>'{version,versionId}' IS DISTINCT FROM actor_evidence#>>'{version,versionId}'
                    OR current_boundary.evidence#>>'{version,contentDigest}' IS DISTINCT FROM actor_evidence#>>'{version,contentDigest}'
                    OR current_boundary.evidence->'contractVersion' IS DISTINCT FROM actor_evidence->'contractVersion'
                    OR current_boundary.evidence->'compilation' IS DISTINCT FROM actor_evidence->'compilation')) THEN
                RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy attachment group boundary is unavailable';
            END IF;
            SELECT count(*),COALESCE(jsonb_agg(jsonb_build_object(
                'membershipId',member.id,'userId',member.user_id,
                'boundary',iam.current_user_boundary_evidence(member.tenant_id,member.user_id)) ORDER BY member.id),'[]'::jsonb)
              INTO member_count,member_document FROM iam.group_memberships member
              WHERE member.tenant_id=submitted_tenant AND member.group_id=submitted_target_id
                AND member.removed_at IS NULL;
            member_digest:='sha256:'||encode(sha256(
              convert_to('matrix.iam.group-delegation-members.v1','UTF8')||decode('00','hex')
              ||convert_to(submitted_tenant,'UTF8')||decode('00','hex')
              ||convert_to(submitted_target_id,'UTF8')||decode('00','hex')
              ||convert_to(ceiling_policy_id,'UTF8')||decode('00','hex')
              ||convert_to(member_document::text,'UTF8')),'hex');
            target_evidence:=jsonb_build_object('state','GROUP_BOUND','ceilingPolicyId',ceiling_policy_id,
              'memberCount',member_count,'membersDigest',member_digest);
        END IF;
    END IF;

    PERFORM policy.id FROM iam.policies policy
      WHERE policy.id IN (submitted_policy_id,ceiling_policy_id) ORDER BY policy.id FOR SHARE;
    SELECT * INTO attached FROM iam.policies policy WHERE policy.id=submitted_policy_id;
    IF NOT FOUND OR attached.status<>'ACTIVE' OR attached.authority_scope<>submitted_authority_scope
      OR (attached.owner_tenant_id IS NOT NULL AND attached.owner_tenant_id<>submitted_tenant) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy attachment policy is unavailable';
    END IF;
    IF ceiling_policy_id IS NOT NULL THEN
        SELECT * INTO ceiling FROM iam.policies policy WHERE policy.id=ceiling_policy_id;
        IF NOT FOUND OR ceiling.management<>'CUSTOMER' OR ceiling.owner_tenant_id<>submitted_tenant
          OR ceiling.authority_scope<>'TENANT' OR ceiling.status<>'ACTIVE' THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy attachment ceiling is unavailable';
        END IF;
    END IF;
    RETURN jsonb_build_object('actorBoundary',actor_evidence,'targetBoundary',target_evidence);
END $function$;

REVOKE ALL ON FUNCTION iam.guard_user_permission_boundary_change(),iam.current_user_boundary(text,text),
    iam.current_user_boundary_evidence(text,text),iam.assert_current_user_boundary_evidence(text,text,text,jsonb),
    iam.lock_policy_attachment_delegation(text,text,text,text,text,text,text,text)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;

DROP FUNCTION IF EXISTS iam.assert_customer_policy_document(text,text);
CREATE OR REPLACE FUNCTION iam.assert_policy_compilation(canonical text,content_digest text,required_scope text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE document jsonb; statement jsonb; selected_action jsonb; selector jsonb; seen_sids text[]:='{}'; expected_kind text;
    condition jsonb; condition_value jsonb; condition_identity text; seen_conditions text[];
    boundary timestamptz; starts_at timestamptz; ends_at timestamptz;
    envelope jsonb; reference jsonb; declaration jsonb; declared_action jsonb; resolved jsonb;
    registered_actions jsonb:='{}'; action_products jsonb:='{}'; seen_products text[]:='{}'; used_products text[]:='{}';
    action_token text; token_matches text[]; expanded_actions text[]; action_visits integer:=0;
BEGIN
    IF canonical IS NULL OR octet_length(canonical) NOT BETWEEN 1 AND 131072
       OR NOT (canonical IS JSON OBJECT WITH UNIQUE KEYS)
       OR required_scope IS NULL OR required_scope NOT IN ('TENANT','INSTALLATION','INSTALLATION_PROBE')
       OR content_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to('matrix.iam.policy-compilation.v1','UTF8')||decode('00','hex')||convert_to(canonical,'UTF8')),'hex') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy document is invalid';
    END IF;
    envelope:=canonical::jsonb;
    IF NOT(envelope ?& ARRAY['document','compilationVersion','profiles','resolvedStatements'])
       OR envelope-ARRAY['document','compilationVersion','profiles','resolvedStatements']<>'{}'::jsonb
       OR jsonb_typeof(envelope->'compilationVersion') IS DISTINCT FROM 'string' OR envelope->>'compilationVersion' IS DISTINCT FROM '1'
       OR jsonb_typeof(envelope->'document') IS DISTINCT FROM 'object'
       OR octet_length((canonical::json->'document')::text)>65536
       OR jsonb_typeof(envelope->'profiles') IS DISTINCT FROM 'array'
       OR jsonb_typeof(envelope->'resolvedStatements') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy compilation is invalid';
    END IF;
    IF jsonb_array_length(envelope->'profiles') NOT BETWEEN 1 AND 16 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy compilation references are invalid';
    END IF;
    -- Lock all selected current heads in a stable namespace order, retained to
    -- transaction end. Resolving archive content does not select a head.
    PERFORM 1 FROM iam.authorization_profile_heads head
        WHERE EXISTS(SELECT 1 FROM jsonb_array_elements(envelope->'profiles') item WHERE item->>'product'=head.product)
        ORDER BY head.product COLLATE "C" FOR SHARE;
    FOR reference IN SELECT value FROM jsonb_array_elements(envelope->'profiles') LOOP
        IF jsonb_typeof(reference) IS DISTINCT FROM 'object' OR NOT(reference ?& ARRAY['product','revision','contentDigest'])
           OR reference-ARRAY['product','revision','contentDigest']<>'{}'::jsonb
           OR jsonb_typeof(reference->'product') IS DISTINCT FROM 'string' OR COALESCE(reference->>'product','') COLLATE "C" !~ '^[a-z][a-z0-9_-]{0,63}$'
           OR reference->>'product'=ANY(seen_products) OR jsonb_typeof(reference->'revision') IS DISTINCT FROM 'number'
           OR NOT pg_input_is_valid(reference->>'revision','bigint') OR jsonb_typeof(reference->'contentDigest') IS DISTINCT FROM 'string'
           OR COALESCE(reference->>'contentDigest','') COLLATE "C" !~ '^sha256:[0-9a-f]{64}$' THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy compilation reference is invalid';
        END IF;
        SELECT archive.canonical_document::jsonb INTO declaration FROM iam.authorization_profile_heads head
          JOIN iam.authorization_profiles archive ON archive.product=head.product AND archive.revision=head.revision
          WHERE head.product=reference->>'product' AND head.revision=(reference->>'revision')::bigint AND archive.content_digest=reference->>'contentDigest';
        IF declaration IS NULL THEN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='policy compilation requires exact current declarations'; END IF;
        seen_products:=array_append(seen_products,reference->>'product');
        FOR declared_action IN SELECT value FROM jsonb_array_elements(declaration->'actions') LOOP
            IF registered_actions ? (declared_action->>'action') THEN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='policy compilation action is ambiguous'; END IF;
            registered_actions:=registered_actions||jsonb_build_object(declared_action->>'action',declared_action);
            action_products:=action_products||jsonb_build_object(declared_action->>'action',reference->>'product');
        END LOOP;
    END LOOP;
    document:=envelope->'document';
    IF NOT (document ?& ARRAY['languageVersion','scope','statements'])
       OR document-ARRAY['languageVersion','scope','statements']<>'{}'::jsonb
       OR document->>'languageVersion' IS DISTINCT FROM '1' OR document->>'scope' IS DISTINCT FROM required_scope
       OR jsonb_typeof(document->'languageVersion') IS DISTINCT FROM 'string'
       OR jsonb_typeof(document->'scope') IS DISTINCT FROM 'string'
       OR jsonb_typeof(document->'statements') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy document is invalid';
    END IF;
    IF jsonb_array_length(document->'statements') NOT BETWEEN 1 AND 64 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy statement limit exceeded';
    END IF;
    IF jsonb_array_length(envelope->'resolvedStatements')<>jsonb_array_length(document->'statements') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy compilation statement bindings are invalid';
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
        IF jsonb_array_length(statement->'actions') NOT BETWEEN 1 AND 128
           OR jsonb_array_length(statement->'resources') NOT BETWEEN 1 AND 64
           OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(statement->'actions'))<>jsonb_array_length(statement->'actions')
           OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(statement->'resources'))<>jsonb_array_length(statement->'resources') THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy statement collections are invalid';
        END IF;
        expanded_actions:='{}';
        FOR selected_action IN SELECT value FROM jsonb_array_elements(statement->'actions') LOOP
            action_token:=selected_action#>>'{}';
            IF jsonb_typeof(selected_action) IS DISTINCT FROM 'string' OR octet_length(action_token) NOT BETWEEN 1 AND 128 THEN
                RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy author action is invalid';
            END IF;
            IF position('*' IN action_token)>0 THEN
                IF required_scope<>'TENANT' OR action_token COLLATE "C" !~ '^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_-]{0,63}\.\*$' THEN
                    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy action family is invalid';
                END IF;
                -- Exact segment comparison, not SQL LIKE or a caller regex.
                -- Do not filter scope/capabilities: every match is checked below.
                SELECT COALESCE(array_agg(item ORDER BY item COLLATE "C"),'{}') INTO token_matches
                    FROM jsonb_object_keys(registered_actions) item
                    WHERE cardinality(string_to_array(item,'.'))=3
                      AND split_part(item,'.',1)=split_part(action_token,'.',1)
                      AND split_part(item,'.',2)=split_part(action_token,'.',2);
                IF cardinality(token_matches)=0 THEN
                    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy action family is empty';
                END IF;
            ELSE
                token_matches:=ARRAY[action_token];
            END IF;
            action_visits:=action_visits+cardinality(token_matches);
            IF action_visits>8192 THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy action work limit exceeded'; END IF;
            expanded_actions:=expanded_actions||token_matches;
        END LOOP;
        SELECT array_agg(DISTINCT item COLLATE "C" ORDER BY item COLLATE "C") INTO expanded_actions FROM unnest(expanded_actions) item;
        IF cardinality(expanded_actions) NOT BETWEEN 1 AND 128 THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy resolved action limit exceeded';
        END IF;
        SELECT value INTO resolved FROM jsonb_array_elements(envelope->'resolvedStatements') item
            WHERE item->>'sid'=statement->>'sid';
        IF resolved IS NULL OR jsonb_typeof(resolved) IS DISTINCT FROM 'object' OR NOT(resolved ?& ARRAY['sid','actions'])
           OR resolved-ARRAY['sid','actions']<>'{}'::jsonb OR jsonb_typeof(resolved->'sid') IS DISTINCT FROM 'string'
           OR resolved->'actions' IS DISTINCT FROM to_jsonb(expanded_actions)
           OR (SELECT count(*) FROM jsonb_array_elements(envelope->'resolvedStatements') item WHERE item->>'sid'=statement->>'sid')<>1 THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy compilation statement binding is invalid';
        END IF;
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
                   OR (COALESCE(condition->>'key','') NOT IN ('iam.current-time','iam.account-id','iam.principal-id','request.source-ip')
                       AND COALESCE(condition->>'key','') COLLATE "C" !~ '^(request|resource)\.tag/[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
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
                IF (condition->>'key') COLLATE "C" LIKE 'request.tag/%' COLLATE "C"
                   OR (condition->>'key') COLLATE "C" LIKE 'resource.tag/%' COLLATE "C" THEN
                    IF COALESCE(condition->>'operator','') NOT IN ('STRING_EQUALS','STRING_NOT_EQUALS')
                       OR jsonb_array_length(condition->'values') NOT BETWEEN 1 AND 16
                       OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(condition->'values'))<>jsonb_array_length(condition->'values') THEN
                        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy tag condition is invalid';
                    END IF;
                    FOR condition_value IN SELECT value FROM jsonb_array_elements(condition->'values') LOOP
                        IF jsonb_typeof(condition_value) IS DISTINCT FROM 'string'
                           OR NOT iam.authorization_tags_valid(jsonb_build_array(jsonb_build_object(
                               'key',split_part(condition->>'key','/',2),'value',condition_value#>>'{}'))) THEN
                            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy tag value is invalid';
                        END IF;
                    END LOOP;
                    CONTINUE;
                END IF;
                IF condition->>'key'='request.source-ip' THEN
                    IF COALESCE(condition->>'operator','') NOT IN ('IP_ADDRESS','NOT_IP_ADDRESS')
                       OR jsonb_array_length(condition->'values') NOT BETWEEN 1 AND 16
                       OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(condition->'values'))<>jsonb_array_length(condition->'values') THEN
                        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy IP condition is invalid';
                    END IF;
                    FOR condition_value IN SELECT value FROM jsonb_array_elements(condition->'values') LOOP
                        IF jsonb_typeof(condition_value) IS DISTINCT FROM 'string'
                           OR NOT pg_input_is_valid(condition_value#>>'{}','cidr') THEN
                            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy IP value is invalid';
                        END IF;
                        IF condition_value#>>'{}' IS DISTINCT FROM ((condition_value#>>'{}')::cidr)::text
                           OR (family((condition_value#>>'{}')::cidr)=6
                             AND network((condition_value#>>'{}')::cidr)::inet <<= '::ffff:0.0.0.0/96'::inet) THEN
                            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy IP value is invalid';
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
        FOR selected_action IN SELECT value FROM jsonb_array_elements(resolved->'actions') LOOP
            declared_action:=registered_actions->(selected_action#>>'{}');
            expected_kind:=declared_action->>'resourceKind';
            IF jsonb_typeof(selected_action) IS DISTINCT FROM 'string' OR expected_kind IS NULL
               OR declared_action->>'scope' IS DISTINCT FROM required_scope
               OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(statement->'resources') AS item WHERE item->>'kind'=expected_kind) THEN
                RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy action is invalid';
            END IF;
            used_products:=array_append(used_products,action_products->>(selected_action#>>'{}'));
            FOR condition IN SELECT value FROM jsonb_array_elements(COALESCE(statement->'conditions','[]'::jsonb)) LOOP
                IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(declared_action->'conditions','[]'::jsonb)) item
                    WHERE item->>'key'=condition->>'key') THEN
                    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy action condition is undeclared';
                END IF;
            END LOOP;
        END LOOP;
        FOR selector IN SELECT value FROM jsonb_array_elements(statement->'resources') LOOP
            IF jsonb_typeof(selector) IS DISTINCT FROM 'object' OR NOT (selector ?& ARRAY['kind','match'])
               OR selector-ARRAY['kind','match','id']<>'{}'::jsonb
               OR jsonb_typeof(selector->'kind') IS DISTINCT FROM 'string'
               OR COALESCE(selector->>'match','') NOT IN ('EXACT','ANY_IN_AUTHORITY','PREFIX_IN_AUTHORITY')
               OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(resolved->'actions') AS item
                    WHERE registered_actions->item->>'resourceKind'=selector->>'kind')
               OR (selector->>'match'='ANY_IN_AUTHORITY' AND selector ? 'id')
               OR (selector->>'match'='PREFIX_IN_AUTHORITY' AND (required_scope<>'TENANT' OR EXISTS(
                    SELECT 1 FROM jsonb_array_elements_text(resolved->'actions') AS item
                    WHERE registered_actions->item->>'resourceKind'=selector->>'kind' AND NOT EXISTS(
                        SELECT 1 FROM jsonb_array_elements(registered_actions->item->'resourceShapes') shape
                        WHERE shape->>'mode'='INSTANCE' AND shape->'prefixAllowed'='true'::jsonb))))
               OR (selector->>'match' IN ('EXACT','PREFIX_IN_AUTHORITY') AND (jsonb_typeof(selector->'id') IS DISTINCT FROM 'string'
                    OR COALESCE(selector->>'id','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')) THEN
                RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy resource is invalid';
            END IF;
        END LOOP;
    END LOOP;
    IF NOT seen_products <@ used_products THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy compilation has an unused declaration';
    END IF;
END $function$;

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
        INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at,contract_version,compilation)
        VALUES(seed->>'policyId',seed->>'versionId',seed->>'scope',seed->'document',
            seed->>'canonicalDocument',seed->>'contentDigest',effective_now,2,seed->'compilation')
        ON CONFLICT(policy_id,id) DO NOTHING;
        IF NOT EXISTS(SELECT 1 FROM iam.policy_versions AS version
            WHERE version.policy_id=seed->>'policyId' AND version.id=seed->>'versionId'
            AND version.authority_scope=seed->>'scope' AND version.document=seed->'document'
            AND version.canonical_document=seed->>'canonicalDocument' AND version.content_digest=seed->>'contentDigest'
            AND version.contract_version=2 AND version.compilation=seed->'compilation') THEN
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

CREATE OR REPLACE FUNCTION iam.policy_detail_snapshot(tenant text,policy_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy jsonb; version jsonb;
BEGIN
    policy:=iam.lookup_policy(tenant,policy_id);
    IF policy IS NULL OR policy->>'scope'<>'TENANT' OR policy->>'status'<>'ACTIVE' THEN RETURN NULL; END IF;
    SELECT iam.policy_version_snapshot(v)
      INTO version FROM iam.policy_versions AS v WHERE v.policy_id=policy_detail_snapshot.policy_id AND v.id=policy->>'defaultVersionId' AND v.retired_at IS NULL;
    IF version IS NULL THEN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='policy version is unavailable'; END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','PolicyDetail','policy',policy,'version',version);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_policy(tenant text,actor text,decision text,policy_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.read_account(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy.read','POLICY',policy_id,'INSTANCE',NULL);
    result:=iam.policy_detail_snapshot(tenant,policy_id);
    IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy is unavailable'; END IF;
    RETURN result;
END $function$;

DROP FUNCTION IF EXISTS iam.create_policy(text,text,text,text,text,text,text,text,jsonb);
DROP FUNCTION IF EXISTS iam.create_policy(text,text,text,text,text,text,text,text,jsonb,integer);
CREATE OR REPLACE FUNCTION iam.create_policy(tenant text,actor text,decision text,policy_id text,display_name text,version_id text,canonical text,content_digest text,event jsonb,submitted_contract integer,actor_session_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.policies%ROWTYPE; effective_now timestamptz(6):=transaction_timestamp();
    actor_is_root boolean; actor_evidence jsonb; boundary_policy_id text;
BEGIN
    IF submitted_contract IS DISTINCT FROM 2 THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy publication requires compiled content'; END IF;
    PERFORM iam.assert_policy_compilation(canonical,content_digest,'TENANT');
    IF COALESCE(policy_id,'') COLLATE "C" !~ '^policy-[0-9a-f]{64}$'
       OR version_id IS DISTINCT FROM 'version-'||substring(content_digest FROM 8)
       OR display_name IS NULL OR octet_length(display_name) NOT BETWEEN 1 AND 128
       OR COALESCE(actor_session_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR btrim(display_name)<>display_name OR display_name ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy creation input is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy account is unavailable'; END IF;
    PERFORM 1 FROM iam.principals WHERE tenant_id=tenant AND id=actor AND principal_type='USER'
        AND status='ACTIVE' AND NOT must_change_password AND deleted_at IS NULL FOR NO KEY UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy actor is unavailable'; END IF;
    PERFORM 1 FROM iam.user_credentials credential JOIN iam.sessions session
      ON (session.tenant_id,session.principal_id)=(credential.tenant_id,credential.principal_id)
      WHERE credential.tenant_id=tenant AND credential.principal_id=actor AND session.id=actor_session_id
        AND session.status='ACTIVE' AND session.revoked_at IS NULL AND session.expires_at>clock_timestamp()
        AND session.credential_version=credential.credential_version
        AND session.last_activity_at IS NOT NULL AND session.idle_timeout_seconds IS NOT NULL
        AND session.last_activity_at+make_interval(secs=>session.idle_timeout_seconds)>clock_timestamp()
      FOR SHARE OF credential,session;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy publisher session is unavailable'; END IF;
    PERFORM 1 FROM iam.account_roots WHERE account_id=tenant AND principal_id=actor FOR SHARE;
    actor_is_root:=FOUND;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy.create','ACCOUNT',tenant,'INSTANCE',NULL);
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
    IF NOT actor_is_root THEN
        SELECT boundary.policy_id INTO boundary_policy_id FROM iam.user_permission_boundaries boundary
          WHERE boundary.tenant_id=tenant AND boundary.user_id=actor AND boundary.revoked_at IS NULL
          FOR NO KEY UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy publisher boundary is unavailable'; END IF;
        PERFORM 1 FROM iam.policies boundary_policy
          WHERE boundary_policy.id=boundary_policy_id AND boundary_policy.management='CUSTOMER'
            AND boundary_policy.owner_tenant_id=tenant AND boundary_policy.authority_scope='TENANT'
            AND boundary_policy.status='ACTIVE' FOR SHARE;
        IF NOT FOUND OR EXISTS(SELECT 1 FROM iam.policy_attachments attachment
          WHERE attachment.tenant_id=tenant AND attachment.target_kind='USER' AND attachment.target_id=actor
            AND attachment.authority_scope='INSTALLATION' AND attachment.revoked_at IS NULL) THEN
            RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='delegated policy publisher is unavailable';
        END IF;
    END IF;
    SELECT recorded.boundary_evidence INTO actor_evidence FROM iam.authorization_decisions recorded
      WHERE recorded.tenant_id=tenant AND recorded.id=decision AND recorded.principal_id=actor
        AND recorded.action_name='iam.policy.create' AND recorded.allowed;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy publication decision is unavailable'; END IF;
    PERFORM iam.assert_current_user_boundary_evidence(tenant,actor,'iam.policy.create',actor_evidence);
    IF NOT actor_is_root AND (actor_evidence->>'state' IS DISTINCT FROM 'BOUND'
      OR actor_evidence#>>'{version,policyId}' IS DISTINCT FROM boundary_policy_id) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy publisher boundary is unavailable';
    END IF;
    IF (SELECT count(*) FROM iam.policies WHERE owner_tenant_id=tenant AND management='CUSTOMER' AND status='ACTIVE')>=128 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='customer policy limit exceeded';
    END IF;
    INSERT INTO iam.policies(id,management,owner_tenant_id,display_name,authority_scope,status,default_version_id,resource_version,created_at,updated_at)
    VALUES(policy_id,'CUSTOMER',tenant,display_name,'TENANT','ACTIVE',version_id,1,effective_now,effective_now);
    INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at,contract_version,compilation)
    VALUES(policy_id,version_id,'TENANT',canonical::jsonb->'document',canonical,content_digest,effective_now,submitted_contract,canonical::jsonb-'document');
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
    VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    RETURN iam.policy_detail_snapshot(tenant,policy_id);
END $function$;

REVOKE ALL ON FUNCTION iam.assert_policy_compilation(text,text,text),iam.policy_detail_snapshot(text,text),
    iam.read_policy(text,text,text,text),iam.create_policy(text,text,text,text,text,text,text,text,jsonb,integer,text)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.read_policy(text,text,text,text),iam.create_policy(text,text,text,text,text,text,text,text,jsonb,integer,text) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.policy_version_detail(tenant text,policy_id text,version_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy jsonb; version jsonb;
BEGIN
    policy:=iam.lookup_policy(tenant,policy_id);
    IF policy IS NULL OR policy->>'management'<>'CUSTOMER' OR policy->>'accountId' IS DISTINCT FROM tenant
       OR policy->>'scope'<>'TENANT' OR policy->>'status'<>'ACTIVE' THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy is unavailable';
    END IF;
    SELECT iam.policy_version_snapshot(v)
      INTO version FROM iam.policy_versions AS v WHERE v.policy_id=policy_version_detail.policy_id AND v.id=version_id AND v.retired_at IS NULL;
    IF version IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy version is unavailable'; END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','PolicyVersionDetail','policy',policy,'version',version);
END $function$;

CREATE OR REPLACE FUNCTION iam.list_policy_versions(tenant text,actor text,decision text,policy_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy jsonb; versions jsonb;
BEGIN
    PERFORM iam.read_account(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy-version.list','POLICY',policy_id,'INSTANCE',NULL);
    policy:=iam.lookup_policy(tenant,policy_id);
    IF policy IS NULL OR policy->>'management'<>'CUSTOMER' OR policy->>'accountId' IS DISTINCT FROM tenant OR policy->>'status'<>'ACTIVE' THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy is unavailable';
    END IF;
    SELECT jsonb_agg(iam.policy_version_snapshot(v) ORDER BY v.id)
      INTO versions FROM (SELECT * FROM iam.policy_versions AS stored WHERE stored.policy_id=list_policy_versions.policy_id AND stored.retired_at IS NULL ORDER BY stored.id LIMIT 6) v;
    IF versions IS NULL OR jsonb_array_length(versions)>5 THEN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='policy version inventory is unavailable'; END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','PolicyVersionList','policy',policy,'items',versions);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_policy_version(tenant text,actor text,decision text,policy_id text,version_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM iam.read_account(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy-version.read','POLICY',policy_id,'INSTANCE',NULL);
    RETURN iam.policy_version_detail(tenant,policy_id,version_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.lock_policy_publisher(tenant text,actor text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy account is unavailable'; END IF;
    -- Publication changes no principal key. Its prior decision holds a FK
    -- KEY SHARE, which must coexist with another publisher's identity lock.
    PERFORM 1 FROM iam.principals WHERE tenant_id=tenant AND id=actor AND principal_type='USER'
        AND status='ACTIVE' AND NOT must_change_password AND deleted_at IS NULL FOR NO KEY UPDATE;
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

DROP FUNCTION IF EXISTS iam.create_policy_version(text,text,text,text,bigint,text,text,text,jsonb);
DROP FUNCTION IF EXISTS iam.create_policy_version(text,text,text,text,bigint,text,text,text,jsonb,integer);
CREATE OR REPLACE FUNCTION iam.create_policy_version(tenant text,actor text,decision text,policy_id text,expected_version bigint,version_id text,canonical text,content_digest text,event jsonb,submitted_contract integer,actor_session_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy iam.policies%ROWTYPE; replayed boolean; actor_is_root boolean; actor_evidence jsonb;
    boundary_policy_id text; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF submitted_contract IS DISTINCT FROM 2 THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy publication requires compiled content'; END IF;
    PERFORM iam.assert_policy_compilation(canonical,content_digest,'TENANT');
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740990
       OR version_id IS DISTINCT FROM 'version-'||substring(content_digest FROM 8)||'-'||(expected_version+1)::text
       OR COALESCE(actor_session_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy version input is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy account is unavailable'; END IF;
    PERFORM 1 FROM iam.principals WHERE tenant_id=tenant AND id=actor AND principal_type='USER'
        AND status='ACTIVE' AND NOT must_change_password AND deleted_at IS NULL FOR NO KEY UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy actor is unavailable'; END IF;
    PERFORM 1 FROM iam.user_credentials credential JOIN iam.sessions session
      ON (session.tenant_id,session.principal_id)=(credential.tenant_id,credential.principal_id)
      WHERE credential.tenant_id=tenant AND credential.principal_id=actor AND session.id=actor_session_id
        AND session.status='ACTIVE' AND session.revoked_at IS NULL AND session.expires_at>clock_timestamp()
        AND session.credential_version=credential.credential_version
        AND session.last_activity_at IS NOT NULL AND session.idle_timeout_seconds IS NOT NULL
        AND session.last_activity_at+make_interval(secs=>session.idle_timeout_seconds)>clock_timestamp()
      FOR SHARE OF credential,session;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy publisher session is unavailable'; END IF;
    PERFORM 1 FROM iam.account_roots WHERE account_id=tenant AND principal_id=actor FOR SHARE;
    actor_is_root:=FOUND;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy-version.create','POLICY',policy_id,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(event,tenant,'iam.policy-version.created','POLICY',policy_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy version decision is invalid'; END IF;
    -- Close non-customer and foreign targets before consulting a command's
    -- replay key. The later locked read repeats this check before any effect.
    PERFORM 1 FROM iam.policies AS target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
      AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE';
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy is unavailable'; END IF;
    replayed:=iam.policy_version_intent_replayed(tenant,actor,event);
    IF replayed THEN
        SELECT * INTO policy FROM iam.policies AS target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
          AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE' FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy is unavailable'; END IF;
        IF policy.resource_version<>expected_version+1 OR NOT EXISTS(SELECT 1 FROM iam.policy_versions AS v
            WHERE v.policy_id=create_policy_version.policy_id AND v.id=version_id AND v.canonical_document=canonical AND v.content_digest=create_policy_version.content_digest AND v.retired_at IS NULL) THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy version replay conflicts';
        END IF;
        RETURN iam.policy_version_detail(tenant,policy_id,version_id);
    END IF;
    IF NOT actor_is_root THEN
        SELECT boundary.policy_id INTO boundary_policy_id FROM iam.user_permission_boundaries boundary
          WHERE boundary.tenant_id=tenant AND boundary.user_id=actor AND boundary.revoked_at IS NULL
          FOR NO KEY UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy publisher boundary is unavailable'; END IF;
        PERFORM locked.id FROM iam.policies locked WHERE locked.id IN(boundary_policy_id,policy_id)
          ORDER BY locked.id FOR UPDATE;
        SELECT * INTO policy FROM iam.policies AS target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
          AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE';
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy is unavailable'; END IF;
        PERFORM 1 FROM iam.policies boundary_policy
          WHERE boundary_policy.id=boundary_policy_id AND boundary_policy.management='CUSTOMER'
            AND boundary_policy.owner_tenant_id=tenant AND boundary_policy.authority_scope='TENANT'
            AND boundary_policy.status='ACTIVE';
        IF NOT FOUND OR EXISTS(SELECT 1 FROM iam.policy_attachments attachment
          WHERE attachment.tenant_id=tenant AND attachment.target_kind='USER' AND attachment.target_id=actor
            AND attachment.authority_scope='INSTALLATION' AND attachment.revoked_at IS NULL) THEN
            RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='delegated policy publisher is unavailable';
        END IF;
    ELSE
        SELECT * INTO policy FROM iam.policies AS target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
          AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE' FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy is unavailable'; END IF;
    END IF;
    SELECT recorded.boundary_evidence INTO actor_evidence FROM iam.authorization_decisions recorded
      WHERE recorded.tenant_id=tenant AND recorded.id=decision AND recorded.principal_id=actor
        AND recorded.action_name='iam.policy-version.create' AND recorded.allowed;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy version decision is unavailable'; END IF;
    PERFORM iam.assert_current_user_boundary_evidence(tenant,actor,'iam.policy-version.create',actor_evidence);
    IF NOT actor_is_root AND (actor_evidence->>'state' IS DISTINCT FROM 'BOUND'
      OR actor_evidence#>>'{version,policyId}' IS DISTINCT FROM boundary_policy_id
      OR EXISTS(SELECT 1 FROM iam.user_permission_boundaries boundary
          WHERE boundary.policy_id=create_policy_version.policy_id AND boundary.revoked_at IS NULL)
      OR EXISTS(SELECT 1 FROM iam.role_permission_boundaries boundary
          WHERE boundary.policy_id=create_policy_version.policy_id AND boundary.revoked_at IS NULL)) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='delegated policy version target is unavailable';
    END IF;
    IF policy.resource_version<>expected_version OR EXISTS(SELECT 1 FROM iam.policy_versions AS v WHERE v.policy_id=create_policy_version.policy_id AND (v.id=version_id OR (v.retired_at IS NULL AND v.content_digest=create_policy_version.content_digest)))
       OR (SELECT count(*) FROM iam.policy_versions AS v WHERE v.policy_id=create_policy_version.policy_id AND v.retired_at IS NULL)>=5 THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy version revision or inventory conflicts';
    END IF;
    INSERT INTO iam.policy_versions(policy_id,id,authority_scope,document,canonical_document,content_digest,created_at,contract_version,compilation)
      VALUES(policy_id,version_id,'TENANT',canonical::jsonb->'document',canonical,content_digest,effective_now,submitted_contract,canonical::jsonb-'document');
    UPDATE iam.policies AS p SET resource_version=resource_version+1,updated_at=effective_now WHERE p.id=policy_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    RETURN iam.policy_version_detail(tenant,policy_id,version_id);
END $function$;

-- Lock and prove every current consumer affected by a delegated default
-- switch. The caller already owns the Account, actor USER and authenticated
-- Session. This helper continues the shared order through USER boundaries,
-- Groups/Roles, Policies and finally attachment rows.
CREATE OR REPLACE FUNCTION iam.lock_policy_default_selection_delegation(
    tenant text,actor text,decision text,policy_id text
)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE actor_evidence jsonb; ceiling_policy_id text; target_policy iam.policies%ROWTYPE;
    ceiling_policy iam.policies%ROWTYPE; attachment iam.policy_attachments%ROWTYPE;
    target_principal iam.principals%ROWTYPE; target_group record;
    target_evidence jsonb; creation_actor_evidence jsonb; creation_target_evidence jsonb;
    creation_actor text; creation_request text; member_document jsonb; member_count bigint;
    member_digest text; closure_document jsonb:='[]'::jsonb; attachment_count bigint:=0;
    closure_digest text;
BEGIN
    SELECT recorded.boundary_evidence INTO actor_evidence FROM iam.authorization_decisions recorded
      WHERE recorded.tenant_id=tenant AND recorded.id=decision AND recorded.principal_id=actor
        AND recorded.action_name='iam.policy.set-default-version' AND recorded.allowed;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='default policy version decision is unavailable'; END IF;
    PERFORM iam.assert_current_user_boundary_evidence(tenant,actor,'iam.policy.set-default-version',actor_evidence);
    IF actor_evidence->>'state' IS DISTINCT FROM 'BOUND' THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='default policy version delegation is unavailable';
    END IF;
    ceiling_policy_id:=actor_evidence#>>'{version,policyId}';
    IF ceiling_policy_id IS NULL OR ceiling_policy_id=policy_id OR EXISTS(
        SELECT 1 FROM iam.policy_attachments a WHERE a.tenant_id=tenant AND a.target_kind='USER'
          AND a.target_id=actor AND a.authority_scope='INSTALLATION' AND a.revoked_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='default policy version delegation is unavailable';
    END IF;

    -- Lock every real USER whose current closure can be changed, including a
    -- USER boundary reference that will make the command fail closed.
    PERFORM principal.id FROM iam.principals principal
      WHERE principal.tenant_id=tenant AND principal.id<>actor AND (
        EXISTS(SELECT 1 FROM iam.policy_attachments a WHERE a.tenant_id=tenant
          AND a.policy_id=lock_policy_default_selection_delegation.policy_id AND a.revoked_at IS NULL
          AND a.target_kind='USER' AND a.target_id=principal.id)
        OR EXISTS(SELECT 1 FROM iam.policy_attachments a
          JOIN iam.group_memberships member ON member.tenant_id=a.tenant_id
            AND member.group_id=a.target_id AND member.removed_at IS NULL
          WHERE a.tenant_id=tenant AND a.policy_id=lock_policy_default_selection_delegation.policy_id
            AND a.target_kind='GROUP' AND a.revoked_at IS NULL AND member.user_id=principal.id)
        OR EXISTS(SELECT 1 FROM iam.user_permission_boundaries boundary
          WHERE boundary.tenant_id=tenant AND boundary.user_id=principal.id
            AND boundary.policy_id=lock_policy_default_selection_delegation.policy_id
            AND boundary.revoked_at IS NULL))
      ORDER BY principal.id FOR NO KEY UPDATE;

    -- USER boundary writers own the same principal first. Lock every current
    -- relation in stable USER order before Group/Policy barriers.
    PERFORM boundary.user_id FROM iam.user_permission_boundaries boundary
      WHERE boundary.tenant_id=tenant AND boundary.revoked_at IS NULL AND (
        boundary.user_id=actor OR boundary.policy_id=lock_policy_default_selection_delegation.policy_id
        OR EXISTS(SELECT 1 FROM iam.policy_attachments a WHERE a.tenant_id=tenant
          AND a.policy_id=lock_policy_default_selection_delegation.policy_id AND a.revoked_at IS NULL
          AND a.target_kind='USER' AND a.target_id=boundary.user_id)
        OR EXISTS(SELECT 1 FROM iam.policy_attachments a
          JOIN iam.group_memberships member ON member.tenant_id=a.tenant_id
            AND member.group_id=a.target_id AND member.removed_at IS NULL
          WHERE a.tenant_id=tenant AND a.policy_id=lock_policy_default_selection_delegation.policy_id
            AND a.target_kind='GROUP' AND a.revoked_at IS NULL AND member.user_id=boundary.user_id))
      ORDER BY boundary.user_id FOR NO KEY UPDATE;

    -- Role writers use Role -> Policy -> relationship; Group writers use
    -- Group -> membership -> Policy. No command owns both target kinds, so the
    -- two stable target sets can be acquired before the shared Policy rows.
    PERFORM role_value.id FROM iam.roles role_value WHERE role_value.tenant_id=tenant AND (
        EXISTS(SELECT 1 FROM iam.policy_attachments a WHERE a.tenant_id=tenant
          AND a.policy_id=lock_policy_default_selection_delegation.policy_id AND a.revoked_at IS NULL
          AND a.target_kind='ROLE' AND a.target_id=role_value.id)
        OR EXISTS(SELECT 1 FROM iam.role_permission_boundaries boundary WHERE boundary.tenant_id=tenant
          AND boundary.role_id=role_value.id AND boundary.policy_id=lock_policy_default_selection_delegation.policy_id
          AND boundary.revoked_at IS NULL))
      ORDER BY role_value.id FOR UPDATE;
    PERFORM target.id FROM iam.groups target WHERE target.tenant_id=tenant AND EXISTS(
        SELECT 1 FROM iam.policy_attachments a WHERE a.tenant_id=tenant
          AND a.policy_id=lock_policy_default_selection_delegation.policy_id AND a.revoked_at IS NULL
          AND a.target_kind='GROUP' AND a.target_id=target.id)
      ORDER BY target.id FOR UPDATE;
    PERFORM member.id FROM iam.group_memberships member WHERE member.tenant_id=tenant
      AND member.removed_at IS NULL AND EXISTS(SELECT 1 FROM iam.policy_attachments a
        WHERE a.tenant_id=tenant AND a.policy_id=lock_policy_default_selection_delegation.policy_id
          AND a.revoked_at IS NULL AND a.target_kind='GROUP' AND a.target_id=member.group_id)
      ORDER BY member.group_id,member.id FOR UPDATE;

    PERFORM locked.id FROM iam.policies locked WHERE locked.id IN(ceiling_policy_id,policy_id)
      ORDER BY locked.id FOR UPDATE;
    SELECT * INTO target_policy FROM iam.policies target WHERE target.id=policy_id
      AND target.owner_tenant_id=tenant AND target.management='CUSTOMER'
      AND target.authority_scope='TENANT' AND target.status='ACTIVE';
    SELECT * INTO ceiling_policy FROM iam.policies ceiling WHERE ceiling.id=ceiling_policy_id
      AND ceiling.owner_tenant_id=tenant AND ceiling.management='CUSTOMER'
      AND ceiling.authority_scope='TENANT' AND ceiling.status='ACTIVE';
    IF target_policy.id IS NULL OR ceiling_policy.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='default policy version target or ceiling is unavailable';
    END IF;
    -- A ceiling default may have changed while the original decision waited.
    -- Re-evaluate its exact version/digest only after both Policy rows are held.
    PERFORM iam.assert_current_user_boundary_evidence(tenant,actor,'iam.policy.set-default-version',actor_evidence);

    PERFORM boundary.id FROM iam.role_permission_boundaries boundary
      WHERE boundary.tenant_id=tenant AND boundary.policy_id=lock_policy_default_selection_delegation.policy_id
        AND boundary.revoked_at IS NULL ORDER BY boundary.role_id FOR NO KEY UPDATE;
    PERFORM current_attachment.id FROM iam.policy_attachments current_attachment
      WHERE current_attachment.tenant_id=tenant
        AND current_attachment.policy_id=lock_policy_default_selection_delegation.policy_id
        AND current_attachment.revoked_at IS NULL ORDER BY current_attachment.id FOR NO KEY UPDATE;

    IF EXISTS(SELECT 1 FROM iam.user_permission_boundaries boundary
          WHERE boundary.policy_id=lock_policy_default_selection_delegation.policy_id AND boundary.revoked_at IS NULL)
      OR EXISTS(SELECT 1 FROM iam.role_permission_boundaries boundary
          WHERE boundary.policy_id=lock_policy_default_selection_delegation.policy_id AND boundary.revoked_at IS NULL)
      OR EXISTS(SELECT 1 FROM iam.policy_attachments current_attachment
          WHERE current_attachment.tenant_id=tenant
            AND current_attachment.policy_id=lock_policy_default_selection_delegation.policy_id
            AND current_attachment.revoked_at IS NULL
            AND (current_attachment.authority_scope<>'TENANT' OR current_attachment.target_kind NOT IN ('USER','GROUP'))) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='default policy version consumer closure is unavailable';
    END IF;

    FOR attachment IN SELECT * FROM iam.policy_attachments current_attachment
      WHERE current_attachment.tenant_id=tenant
        AND current_attachment.policy_id=lock_policy_default_selection_delegation.policy_id
        AND current_attachment.revoked_at IS NULL ORDER BY current_attachment.id
    LOOP
        IF (SELECT count(*) FROM iam.policy_attachment_changes change_value
              WHERE change_value.tenant_id=tenant AND change_value.attachment_id=attachment.id
                AND change_value.operation='CREATE')<>1 THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='default policy version attachment proof is unavailable';
        END IF;
        SELECT change_value.actor_principal_id,change_value.request_id,
               change_value.actor_boundary_evidence,change_value.target_boundary_evidence
          INTO creation_actor,creation_request,creation_actor_evidence,creation_target_evidence
          FROM iam.policy_attachment_changes change_value
          WHERE change_value.tenant_id=tenant AND change_value.attachment_id=attachment.id
            AND change_value.operation='CREATE';
        IF creation_actor_evidence->>'state' IS DISTINCT FROM 'BOUND'
          OR creation_actor_evidence#>>'{version,policyId}' IS DISTINCT FROM ceiling_policy_id THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='default policy version attachment proof is unavailable';
        END IF;

        IF attachment.target_kind='USER' THEN
            SELECT * INTO target_principal FROM iam.principals principal
              WHERE principal.tenant_id=tenant AND principal.id=attachment.target_id
                AND principal.principal_type='USER' AND principal.deleted_at IS NULL;
            IF target_principal.id IS NULL
              OR EXISTS(SELECT 1 FROM iam.account_roots root
                  WHERE root.account_id=tenant AND root.principal_id=attachment.target_id)
              OR EXISTS(SELECT 1 FROM iam.policy_attachments platform_attachment
                  WHERE platform_attachment.tenant_id=tenant AND platform_attachment.target_kind='USER'
                    AND platform_attachment.target_id=attachment.target_id
                    AND platform_attachment.authority_scope='INSTALLATION'
                    AND platform_attachment.revoked_at IS NULL) THEN
                RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='default policy version USER consumer is unavailable';
            END IF;
            target_evidence:=iam.current_user_boundary_evidence(tenant,attachment.target_id);
            IF creation_target_evidence->>'state' IS DISTINCT FROM 'BOUND'
              OR creation_target_evidence#>>'{version,policyId}' IS DISTINCT FROM ceiling_policy_id
              OR target_evidence->>'state' IS DISTINCT FROM 'BOUND'
              OR target_evidence#>>'{version,policyId}' IS DISTINCT FROM ceiling_policy_id
              OR target_evidence->'version' IS DISTINCT FROM actor_evidence->'version'
              OR target_evidence->'contractVersion' IS DISTINCT FROM actor_evidence->'contractVersion'
              OR target_evidence->'compilation' IS DISTINCT FROM actor_evidence->'compilation' THEN
                RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='default policy version USER ceiling is unavailable';
            END IF;
        ELSE
            SELECT * INTO target_group FROM iam.groups target
              WHERE target.tenant_id=tenant AND target.id=attachment.target_id AND target.deleted_at IS NULL;
            IF target_group.id IS NULL OR attachment.delegation_ceiling_policy_id IS DISTINCT FROM ceiling_policy_id
              OR creation_target_evidence->>'state' IS DISTINCT FROM 'GROUP_BOUND'
              OR creation_target_evidence->>'ceilingPolicyId' IS DISTINCT FROM ceiling_policy_id
              OR EXISTS(SELECT 1 FROM iam.group_memberships member
                JOIN iam.principals principal ON (principal.tenant_id,principal.id)=(member.tenant_id,member.user_id)
                CROSS JOIN LATERAL (SELECT iam.current_user_boundary_evidence(member.tenant_id,member.user_id) AS evidence) current_boundary
                WHERE member.tenant_id=tenant AND member.group_id=attachment.target_id AND member.removed_at IS NULL AND (
                  principal.principal_type<>'USER' OR principal.deleted_at IS NOT NULL
                  OR EXISTS(SELECT 1 FROM iam.account_roots root
                    WHERE root.account_id=tenant AND root.principal_id=member.user_id)
                  OR EXISTS(SELECT 1 FROM iam.policy_attachments platform_attachment
                    WHERE platform_attachment.tenant_id=tenant AND platform_attachment.target_kind='USER'
                      AND platform_attachment.target_id=member.user_id
                      AND platform_attachment.authority_scope='INSTALLATION' AND platform_attachment.revoked_at IS NULL)
                  OR current_boundary.evidence->>'state' IS DISTINCT FROM 'BOUND'
                  OR current_boundary.evidence#>>'{version,policyId}' IS DISTINCT FROM ceiling_policy_id
                  OR current_boundary.evidence->'version' IS DISTINCT FROM actor_evidence->'version'
                  OR current_boundary.evidence->'contractVersion' IS DISTINCT FROM actor_evidence->'contractVersion'
                  OR current_boundary.evidence->'compilation' IS DISTINCT FROM actor_evidence->'compilation')) THEN
                RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='default policy version Group ceiling is unavailable';
            END IF;
            SELECT count(*),COALESCE(jsonb_agg(jsonb_build_object(
                'membershipId',member.id,'userId',member.user_id,
                'boundary',iam.current_user_boundary_evidence(member.tenant_id,member.user_id)) ORDER BY member.id),'[]'::jsonb)
              INTO member_count,member_document FROM iam.group_memberships member
              WHERE member.tenant_id=tenant AND member.group_id=attachment.target_id AND member.removed_at IS NULL;
            member_digest:='sha256:'||encode(sha256(
              convert_to('matrix.iam.policy-default-group-members.v1','UTF8')||decode('00','hex')
              ||convert_to(tenant,'UTF8')||decode('00','hex')||convert_to(attachment.target_id,'UTF8')||decode('00','hex')
              ||convert_to(ceiling_policy_id,'UTF8')||decode('00','hex')||convert_to(member_document::text,'UTF8')),'hex');
            target_evidence:=jsonb_build_object('state','GROUP_BOUND','ceilingPolicyId',ceiling_policy_id,
              'authorizationGeneration',target_group.authorization_generation,
              'memberCount',member_count,'membersDigest',member_digest);
        END IF;

        closure_document:=closure_document||jsonb_build_array(jsonb_build_object(
          'attachmentId',attachment.id,'targetKind',attachment.target_kind,'targetId',attachment.target_id,
          'creationActorPrincipalId',creation_actor,'creationRequestId',creation_request,
          'creationActorBoundary',creation_actor_evidence,'creationTargetBoundary',creation_target_evidence,
          'currentTargetBoundary',target_evidence));
        attachment_count:=attachment_count+1;
    END LOOP;
    closure_digest:='sha256:'||encode(sha256(
      convert_to('matrix.iam.policy-default-closure.v1','UTF8')||decode('00','hex')
      ||convert_to(tenant,'UTF8')||decode('00','hex')||convert_to(actor,'UTF8')||decode('00','hex')
      ||convert_to(policy_id,'UTF8')||decode('00','hex')||convert_to(ceiling_policy_id,'UTF8')||decode('00','hex')
      ||convert_to(closure_document::text,'UTF8')),'hex');
    RETURN jsonb_build_object('actorBoundary',actor_evidence,'attachmentCount',attachment_count,
      'attachmentClosureDigest',closure_digest);
END $function$;

DROP FUNCTION IF EXISTS iam.set_default_policy_version(text,text,text,text,bigint,text,jsonb);
CREATE OR REPLACE FUNCTION iam.set_default_policy_version(tenant text,actor text,decision text,policy_id text,
    expected_version bigint,version_id text,event jsonb,actor_session_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy iam.policies%ROWTYPE; replayed boolean; actor_is_root boolean; delegation jsonb;
    completed iam.policy_default_version_changes%ROWTYPE; prior_scope text;
    effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740990
      OR COALESCE(actor_session_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy revision or publisher session is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy account is unavailable'; END IF;
    PERFORM 1 FROM iam.principals principal WHERE principal.tenant_id=tenant AND principal.id=actor
      AND principal.principal_type='USER' AND principal.status='ACTIVE' AND NOT principal.must_change_password
      AND principal.deleted_at IS NULL FOR NO KEY UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy actor is unavailable'; END IF;
    PERFORM 1 FROM iam.user_credentials credential JOIN iam.sessions session
      ON (session.tenant_id,session.principal_id)=(credential.tenant_id,credential.principal_id)
      WHERE credential.tenant_id=tenant AND credential.principal_id=actor AND session.id=actor_session_id
        AND session.status='ACTIVE' AND session.revoked_at IS NULL AND session.expires_at>clock_timestamp()
        AND session.credential_version=credential.credential_version
        AND session.last_activity_at IS NOT NULL AND session.idle_timeout_seconds IS NOT NULL
        AND session.last_activity_at+make_interval(secs=>session.idle_timeout_seconds)>clock_timestamp()
      FOR SHARE OF credential,session;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy publisher session is unavailable'; END IF;
    PERFORM 1 FROM iam.account_roots root WHERE root.account_id=tenant AND root.principal_id=actor FOR SHARE;
    actor_is_root:=FOUND;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy.set-default-version','POLICY',policy_id,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(event,tenant,'iam.policy.default-version-set','POLICY',policy_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy version decision is invalid';
    END IF;
    -- Close foreign, SYSTEM and retired targets before consulting an old
    -- request identity. The locked path repeats the same classification.
    PERFORM 1 FROM iam.policies target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
      AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE';
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy is unavailable'; END IF;
    replayed:=iam.policy_version_intent_replayed(tenant,actor,event);
    IF replayed THEN
        SELECT * INTO policy FROM iam.policies target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
          AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE' FOR UPDATE;
        IF NOT FOUND OR policy.resource_version<>expected_version+1 OR policy.default_version_id<>version_id THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='default policy version replay conflicts';
        END IF;
        IF NOT actor_is_root THEN
            SELECT * INTO completed FROM iam.policy_default_version_changes change_value
              WHERE (change_value.tenant_id,change_value.actor_principal_id,change_value.request_id)=
                (tenant,actor,event->>'requestId');
            IF NOT FOUND OR completed.policy_id IS DISTINCT FROM policy_id
              OR completed.expected_resource_version IS DISTINCT FROM expected_version
              OR completed.version_id IS DISTINCT FROM version_id
              OR NOT EXISTS(SELECT 1 FROM iam.authorization_decisions original_decision
                JOIN iam.audit_outbox original_event
                  ON original_event.tenant_id=original_decision.tenant_id
                  AND original_event.event_id=completed.event_id
                WHERE original_decision.tenant_id=tenant AND original_decision.id=completed.decision_id
                  AND original_decision.principal_id=actor AND original_decision.allowed
                  AND original_decision.action_name='iam.policy.set-default-version'
                  AND original_decision.target_kind='POLICY' AND original_decision.target_id=completed.policy_id
                  AND original_decision.resource_mode='INSTANCE' AND original_decision.collection_usage IS NULL
                  AND original_decision.contract_version=7 AND original_decision.subject_type='USER'
                  AND original_decision.access_key_id IS NULL
                  AND original_decision.request_id=completed.request_id
                  AND original_decision.boundary_evidence=completed.actor_boundary_evidence
                  AND original_event.event_document->>'action'='iam.policy.default-version-set'
                  AND original_event.event_document#>>'{actor,id}'=actor
                  AND original_event.event_document#>>'{target,kind}'='POLICY'
                  AND original_event.event_document#>>'{target,id}'=completed.policy_id
                  AND original_event.event_document->>'result'='SUCCEEDED'
                  AND original_event.event_document->>'requestId'=completed.request_id
                  AND original_event.event_document->>'requestDigest'=event->>'requestDigest'
                  AND original_event.event_document->>'iamDecisionId'=completed.decision_id) THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='default policy version completion is unavailable';
            END IF;
        END IF;
        RETURN iam.policy_detail_snapshot(tenant,policy_id);
    END IF;

    IF actor_is_root THEN
        SELECT * INTO policy FROM iam.policies target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
          AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE' FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy is unavailable'; END IF;
    ELSE
        delegation:=iam.lock_policy_default_selection_delegation(tenant,actor,decision,policy_id);
        SELECT * INTO policy FROM iam.policies target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
          AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE';
        IF NOT FOUND OR delegation IS NULL THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='default policy version delegation is unavailable';
        END IF;
    END IF;
    IF NOT EXISTS(SELECT 1 FROM iam.policy_versions version_value
        WHERE version_value.policy_id=set_default_policy_version.policy_id
          AND version_value.id=version_id AND version_value.retired_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy version is unavailable';
    END IF;
    IF policy.resource_version<>expected_version OR policy.default_version_id=version_id THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='default policy version revision conflicts';
    END IF;
    UPDATE iam.policies AS target SET default_version_id=version_id,resource_version=resource_version+1,
      updated_at=effective_now WHERE target.id=policy_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    IF NOT actor_is_root THEN
        prior_scope:=current_setting('matrix.iam_policy_default_version_change',true);
        PERFORM set_config('matrix.iam_policy_default_version_change','trusted',true);
        INSERT INTO iam.policy_default_version_changes(tenant_id,actor_principal_id,request_id,policy_id,
          expected_resource_version,version_id,actor_boundary_evidence,attachment_count,attachment_closure_digest,
          decision_id,event_id,completed_at)
        VALUES(tenant,actor,event->>'requestId',policy_id,expected_version,version_id,delegation->'actorBoundary',
          (delegation->>'attachmentCount')::bigint,delegation->>'attachmentClosureDigest',decision,event->>'eventId',effective_now);
        PERFORM set_config('matrix.iam_policy_default_version_change',COALESCE(prior_scope,''),true);
    END IF;
    RETURN iam.policy_detail_snapshot(tenant,policy_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.policy_default_version_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
  SELECT EXISTS(SELECT 1 FROM pg_class relation
      WHERE relation.oid='iam.policy_default_version_changes'::regclass
        AND relation.relowner='matrix_iam_owner'::regrole
        AND relation.relrowsecurity AND relation.relforcerowsecurity
        AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) privilege
          WHERE privilege.grantee<>relation.relowner))
    AND EXISTS(SELECT 1 FROM pg_constraint constraint_value
      WHERE constraint_value.conrelid='iam.policy_default_version_changes'::regclass
        AND constraint_value.conname='policy_default_version_changes_shape'
        AND constraint_value.contype='c' AND constraint_value.convalidated)
    AND (SELECT count(*)=4 FROM pg_trigger trigger_value
      WHERE trigger_value.tgrelid='iam.policy_default_version_changes'::regclass
        AND NOT trigger_value.tgisinternal AND trigger_value.tgenabled='A'
        AND trigger_value.tgname IN ('policy_default_version_change_insert_guard',
          'policy_default_version_changes_cannot_be_updated','policy_default_version_changes_cannot_be_deleted',
          'policy_default_version_changes_cannot_be_truncated'))
    AND EXISTS(SELECT 1 FROM pg_proc entry
      WHERE entry.oid=to_regprocedure('iam.set_default_policy_version(text,text,text,text,bigint,text,jsonb,text)')
        AND entry.prosecdef AND entry.proowner='matrix_iam_owner'::regrole
        AND entry.prorettype='jsonb'::regtype AND NOT entry.proretset
        AND 'search_path=pg_catalog, pg_temp'=ANY(entry.proconfig))
    AND to_regprocedure('iam.set_default_policy_version(text,text,text,text,bigint,text,jsonb)') IS NULL
    AND EXISTS(SELECT 1 FROM pg_proc helper
      WHERE helper.oid=to_regprocedure('iam.lock_policy_default_selection_delegation(text,text,text,text)')
        AND NOT helper.prosecdef AND helper.proowner='matrix_iam_owner'::regrole
        AND helper.prorettype='jsonb'::regtype AND NOT helper.proretset
        AND 'search_path=pg_catalog, pg_temp'=ANY(helper.proconfig)
        AND NOT has_function_privilege('public',helper.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_api',helper.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_worker',helper.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_credential_recovery',helper.oid,'EXECUTE'))
$function$;
REVOKE ALL ON FUNCTION iam.policy_default_version_contract_ready()
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;

REVOKE ALL ON FUNCTION iam.policy_version_detail(text,text,text),iam.lock_customer_policy_publisher(text,text,text),iam.policy_version_intent_replayed(text,text,jsonb),
    iam.list_policy_versions(text,text,text,text),iam.read_policy_version(text,text,text,text,text),
    iam.create_policy_version(text,text,text,text,bigint,text,text,text,jsonb,integer,text),iam.lock_policy_default_selection_delegation(text,text,text,text),
    iam.set_default_policy_version(text,text,text,text,bigint,text,jsonb,text)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.list_policy_versions(text,text,text,text),iam.read_policy_version(text,text,text,text,text),
    iam.create_policy_version(text,text,text,text,bigint,text,text,text,jsonb,integer,text),
    iam.set_default_policy_version(text,text,text,text,bigint,text,jsonb,text) TO matrix_iam_api;

-- Metadata does not change effective authority, but a non-root author still
-- cannot maintain its own ceiling or any Policy currently used as a User or
-- Role ceiling. Lock both Policies before checking those relationships so a
-- concurrent boundary write has one deterministic winner.
CREATE OR REPLACE FUNCTION iam.lock_policy_metadata_update_delegation(
    tenant text,actor text,decision text,policy_id text
)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE actor_evidence jsonb; ceiling_policy_id text;
    target_policy iam.policies%ROWTYPE; ceiling_policy iam.policies%ROWTYPE;
BEGIN
    SELECT recorded.boundary_evidence INTO actor_evidence FROM iam.authorization_decisions recorded
      WHERE recorded.tenant_id=tenant AND recorded.id=decision AND recorded.principal_id=actor
        AND recorded.action_name='iam.policy.update' AND recorded.allowed;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy metadata decision is unavailable';
    END IF;
    SELECT boundary.policy_id INTO ceiling_policy_id FROM iam.user_permission_boundaries boundary
      WHERE boundary.tenant_id=tenant AND boundary.user_id=actor AND boundary.revoked_at IS NULL
      FOR NO KEY UPDATE;
    IF NOT FOUND OR actor_evidence->>'state' IS DISTINCT FROM 'BOUND'
      OR actor_evidence#>>'{version,policyId}' IS DISTINCT FROM ceiling_policy_id
      OR ceiling_policy_id=policy_id
      OR EXISTS(SELECT 1 FROM iam.policy_attachments attachment
          WHERE attachment.tenant_id=tenant AND attachment.target_kind='USER' AND attachment.target_id=actor
            AND attachment.authority_scope='INSTALLATION' AND attachment.revoked_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy metadata delegation is unavailable';
    END IF;

    PERFORM locked.id FROM iam.policies locked WHERE locked.id IN(ceiling_policy_id,policy_id)
      ORDER BY locked.id FOR UPDATE;
    SELECT * INTO target_policy FROM iam.policies target WHERE target.id=policy_id
      AND target.owner_tenant_id=tenant AND target.management='CUSTOMER'
      AND target.authority_scope='TENANT' AND target.status='ACTIVE';
    SELECT * INTO ceiling_policy FROM iam.policies ceiling WHERE ceiling.id=ceiling_policy_id
      AND ceiling.owner_tenant_id=tenant AND ceiling.management='CUSTOMER'
      AND ceiling.authority_scope='TENANT' AND ceiling.status='ACTIVE';
    IF target_policy.id IS NULL OR ceiling_policy.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy metadata target or ceiling is unavailable';
    END IF;
    PERFORM iam.assert_current_user_boundary_evidence(tenant,actor,'iam.policy.update',actor_evidence);
    IF EXISTS(SELECT 1 FROM iam.user_permission_boundaries boundary
          WHERE boundary.policy_id=lock_policy_metadata_update_delegation.policy_id AND boundary.revoked_at IS NULL)
      OR EXISTS(SELECT 1 FROM iam.role_permission_boundaries boundary
          WHERE boundary.policy_id=lock_policy_metadata_update_delegation.policy_id AND boundary.revoked_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='delegated policy metadata target is unavailable';
    END IF;
    RETURN actor_evidence;
END $function$;

DROP FUNCTION IF EXISTS iam.update_policy(text,text,text,text,bigint,text,jsonb);
CREATE OR REPLACE FUNCTION iam.update_policy(tenant text,actor text,decision text,policy_id text,expected_version bigint,
    display_name text,event jsonb,actor_session_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy iam.policies%ROWTYPE; replayed boolean; actor_is_root boolean;
    actor_evidence jsonb; completed iam.policy_metadata_updates%ROWTYPE; prior_scope text;
    effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740990
       OR display_name IS NULL OR octet_length(display_name) NOT BETWEEN 1 AND 128 OR display_name<>btrim(display_name)
       OR display_name ~ '[[:cntrl:]]'
       OR COALESCE(actor_session_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy metadata input or publisher session is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy account is unavailable'; END IF;
    PERFORM 1 FROM iam.principals principal WHERE principal.tenant_id=tenant AND principal.id=actor
      AND principal.principal_type='USER' AND principal.status='ACTIVE' AND NOT principal.must_change_password
      AND principal.deleted_at IS NULL FOR NO KEY UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy actor is unavailable'; END IF;
    PERFORM 1 FROM iam.user_credentials credential JOIN iam.sessions session
      ON (session.tenant_id,session.principal_id)=(credential.tenant_id,credential.principal_id)
      WHERE credential.tenant_id=tenant AND credential.principal_id=actor AND session.id=actor_session_id
        AND session.status='ACTIVE' AND session.revoked_at IS NULL AND session.expires_at>clock_timestamp()
        AND session.credential_version=credential.credential_version
        AND session.last_activity_at IS NOT NULL AND session.idle_timeout_seconds IS NOT NULL
        AND session.last_activity_at+make_interval(secs=>session.idle_timeout_seconds)>clock_timestamp()
      FOR SHARE OF credential,session;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy publisher session is unavailable'; END IF;
    PERFORM 1 FROM iam.account_roots root WHERE root.account_id=tenant AND root.principal_id=actor FOR SHARE;
    actor_is_root:=FOUND;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy.update','POLICY',policy_id,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(event,tenant,'iam.policy.updated','POLICY',policy_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy metadata decision is invalid';
    END IF;
    PERFORM 1 FROM iam.policies target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
      AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE';
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy is unavailable'; END IF;
    replayed:=iam.policy_version_intent_replayed(tenant,actor,event);
    IF replayed THEN
        SELECT * INTO policy FROM iam.policies target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
          AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE' FOR UPDATE;
        IF policy.id IS NULL OR policy.resource_version<>expected_version+1 OR policy.display_name<>display_name THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy metadata replay conflicts';
        END IF;
        IF NOT actor_is_root THEN
            SELECT * INTO completed FROM iam.policy_metadata_updates update_value
              WHERE (update_value.tenant_id,update_value.actor_principal_id,update_value.request_id)=
                (tenant,actor,event->>'requestId');
            IF NOT FOUND OR completed.policy_id IS DISTINCT FROM policy_id
              OR completed.expected_resource_version IS DISTINCT FROM expected_version
              OR completed.display_name IS DISTINCT FROM display_name
              OR completed.completed_at IS DISTINCT FROM policy.updated_at
              OR NOT EXISTS(SELECT 1 FROM iam.authorization_decisions original_decision
                JOIN iam.audit_outbox original_event
                  ON original_event.tenant_id=original_decision.tenant_id
                  AND original_event.event_id=completed.event_id
                WHERE original_decision.tenant_id=tenant AND original_decision.id=completed.decision_id
                  AND original_decision.principal_id=actor AND original_decision.allowed
                  AND original_decision.action_name='iam.policy.update'
                  AND original_decision.target_kind='POLICY' AND original_decision.target_id=completed.policy_id
                  AND original_decision.resource_mode='INSTANCE' AND original_decision.collection_usage IS NULL
                  AND original_decision.contract_version=7 AND original_decision.subject_type='USER'
                  AND original_decision.access_key_id IS NULL
                  AND original_decision.request_id=completed.request_id
                  AND original_decision.boundary_evidence=completed.actor_boundary_evidence
                  AND original_event.event_document->>'action'='iam.policy.updated'
                  AND original_event.event_document#>>'{actor,id}'=actor
                  AND original_event.event_document#>>'{target,kind}'='POLICY'
                  AND original_event.event_document#>>'{target,id}'=completed.policy_id
                  AND original_event.event_document->>'result'='SUCCEEDED'
                  AND original_event.event_document->>'requestId'=completed.request_id
                  AND original_event.event_document->>'requestDigest'=event->>'requestDigest'
                  AND original_event.event_document->>'iamDecisionId'=completed.decision_id) THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='policy metadata completion is unavailable';
            END IF;
        END IF;
        RETURN iam.policy_detail_snapshot(tenant,policy_id);
    END IF;

    IF actor_is_root THEN
        policy:=iam.lock_customer_policy_publisher(tenant,actor,policy_id);
    ELSE
        actor_evidence:=iam.lock_policy_metadata_update_delegation(tenant,actor,decision,policy_id);
        SELECT * INTO policy FROM iam.policies target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
          AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE';
        IF NOT FOUND OR actor_evidence IS NULL THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy metadata delegation is unavailable';
        END IF;
    END IF;
    IF policy.resource_version<>expected_version OR policy.display_name=display_name THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy metadata revision conflicts';
    END IF;
    UPDATE iam.policies AS p SET display_name=update_policy.display_name,resource_version=resource_version+1,
      updated_at=effective_now WHERE p.id=policy_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    IF NOT actor_is_root THEN
        prior_scope:=current_setting('matrix.iam_policy_metadata_update',true);
        PERFORM set_config('matrix.iam_policy_metadata_update','trusted',true);
        INSERT INTO iam.policy_metadata_updates(tenant_id,actor_principal_id,request_id,policy_id,
          expected_resource_version,display_name,actor_boundary_evidence,decision_id,event_id,completed_at)
        VALUES(tenant,actor,event->>'requestId',policy_id,expected_version,display_name,actor_evidence,
          decision,event->>'eventId',effective_now);
        PERFORM set_config('matrix.iam_policy_metadata_update',COALESCE(prior_scope,''),true);
    END IF;
    RETURN iam.policy_detail_snapshot(tenant,policy_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.policy_metadata_update_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
  SELECT EXISTS(SELECT 1 FROM pg_class relation
      WHERE relation.oid='iam.policy_metadata_updates'::regclass
        AND relation.relowner='matrix_iam_owner'::regrole
        AND relation.relrowsecurity AND relation.relforcerowsecurity
        AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) privilege
          WHERE privilege.grantee<>relation.relowner))
    AND EXISTS(SELECT 1 FROM pg_constraint constraint_value
      WHERE constraint_value.conrelid='iam.policy_metadata_updates'::regclass
        AND constraint_value.conname='policy_metadata_updates_shape'
        AND constraint_value.contype='c' AND constraint_value.convalidated)
    AND (SELECT count(*)=4 FROM pg_trigger trigger_value
      WHERE trigger_value.tgrelid='iam.policy_metadata_updates'::regclass
        AND NOT trigger_value.tgisinternal)
    AND NOT EXISTS(SELECT 1 FROM (VALUES
        ('policy_metadata_update_insert_guard','iam.guard_policy_metadata_update_insert()'::regprocedure,7::smallint),
        ('policy_metadata_updates_cannot_be_updated','iam.reject_policy_history_change()'::regprocedure,19::smallint),
        ('policy_metadata_updates_cannot_be_deleted','iam.reject_policy_history_change()'::regprocedure,11::smallint),
        ('policy_metadata_updates_cannot_be_truncated','iam.reject_policy_history_change()'::regprocedure,34::smallint)
      ) expected(name,function_oid,trigger_type)
      LEFT JOIN pg_trigger trigger_value ON trigger_value.tgrelid='iam.policy_metadata_updates'::regclass
        AND trigger_value.tgname=expected.name AND NOT trigger_value.tgisinternal
      WHERE trigger_value.oid IS NULL OR trigger_value.tgenabled<>'A'
        OR trigger_value.tgfoid<>expected.function_oid OR trigger_value.tgtype<>expected.trigger_type)
    AND EXISTS(SELECT 1 FROM pg_proc guard
      WHERE guard.oid='iam.guard_policy_metadata_update_insert()'::regprocedure
        AND NOT guard.prosecdef AND guard.proowner='matrix_iam_owner'::regrole
        AND guard.prorettype='trigger'::regtype AND guard.pronargs=0 AND NOT guard.proretset
        AND 'search_path=pg_catalog, pg_temp'=ANY(guard.proconfig)
        AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(guard.proacl,acldefault('f',guard.proowner))) privilege
          WHERE privilege.grantee<>guard.proowner))
    AND EXISTS(SELECT 1 FROM pg_proc entry
      WHERE entry.oid=to_regprocedure('iam.update_policy(text,text,text,text,bigint,text,jsonb,text)')
        AND entry.prosecdef AND entry.proowner='matrix_iam_owner'::regrole
        AND entry.prorettype='jsonb'::regtype AND NOT entry.proretset
        AND 'search_path=pg_catalog, pg_temp'=ANY(entry.proconfig))
    AND to_regprocedure('iam.update_policy(text,text,text,text,bigint,text,jsonb)') IS NULL
    AND EXISTS(SELECT 1 FROM pg_proc helper
      WHERE helper.oid=to_regprocedure('iam.lock_policy_metadata_update_delegation(text,text,text,text)')
        AND NOT helper.prosecdef AND helper.proowner='matrix_iam_owner'::regrole
        AND helper.prorettype='jsonb'::regtype AND NOT helper.proretset
        AND 'search_path=pg_catalog, pg_temp'=ANY(helper.proconfig)
        AND NOT has_function_privilege('public',helper.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_api',helper.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_worker',helper.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_credential_recovery',helper.oid,'EXECUTE'))
$function$;
REVOKE ALL ON FUNCTION iam.lock_policy_metadata_update_delegation(text,text,text,text),
    iam.policy_metadata_update_contract_ready(),iam.update_policy(text,text,text,text,bigint,text,jsonb,text)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.update_policy(text,text,text,text,bigint,text,jsonb,text) TO matrix_iam_api;

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
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy.delete','POLICY',policy_id,'INSTANCE',NULL);
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
        SELECT 1 FROM iam.policy_attachments AS a WHERE a.policy_id=delete_policy.policy_id AND a.revoked_at IS NULL)
        OR EXISTS(SELECT 1 FROM iam.user_permission_boundaries AS b WHERE b.policy_id=delete_policy.policy_id AND b.revoked_at IS NULL)
        OR EXISTS(SELECT 1 FROM iam.role_permission_boundaries AS b WHERE b.policy_id=delete_policy.policy_id AND b.revoked_at IS NULL) THEN
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

-- A non-root author may retire only a non-default version of another CUSTOMER
-- Policy while remaining inside one exact current User boundary. The target
-- family itself cannot be a User/Role boundary: delegated authors must not
-- maintain the policy that defines somebody's maximum authority.
CREATE OR REPLACE FUNCTION iam.lock_policy_version_retirement_delegation(
    tenant text,actor text,decision text,policy_id text
)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE actor_evidence jsonb; ceiling_policy_id text;
    target_policy iam.policies%ROWTYPE; ceiling_policy iam.policies%ROWTYPE;
BEGIN
    SELECT recorded.boundary_evidence INTO actor_evidence FROM iam.authorization_decisions recorded
      WHERE recorded.tenant_id=tenant AND recorded.id=decision AND recorded.principal_id=actor
        AND recorded.action_name='iam.policy-version.delete' AND recorded.allowed;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy version retirement decision is unavailable';
    END IF;
    SELECT boundary.policy_id INTO ceiling_policy_id FROM iam.user_permission_boundaries boundary
      WHERE boundary.tenant_id=tenant AND boundary.user_id=actor AND boundary.revoked_at IS NULL
      FOR NO KEY UPDATE;
    IF NOT FOUND OR actor_evidence->>'state' IS DISTINCT FROM 'BOUND'
      OR actor_evidence#>>'{version,policyId}' IS DISTINCT FROM ceiling_policy_id
      OR ceiling_policy_id=policy_id
      OR EXISTS(SELECT 1 FROM iam.policy_attachments attachment
          WHERE attachment.tenant_id=tenant AND attachment.target_kind='USER' AND attachment.target_id=actor
            AND attachment.authority_scope='INSTALLATION' AND attachment.revoked_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy version retirement delegation is unavailable';
    END IF;

    PERFORM locked.id FROM iam.policies locked WHERE locked.id IN(ceiling_policy_id,policy_id)
      ORDER BY locked.id FOR UPDATE;
    SELECT * INTO target_policy FROM iam.policies target WHERE target.id=policy_id
      AND target.owner_tenant_id=tenant AND target.management='CUSTOMER'
      AND target.authority_scope='TENANT' AND target.status='ACTIVE';
    SELECT * INTO ceiling_policy FROM iam.policies ceiling WHERE ceiling.id=ceiling_policy_id
      AND ceiling.owner_tenant_id=tenant AND ceiling.management='CUSTOMER'
      AND ceiling.authority_scope='TENANT' AND ceiling.status='ACTIVE';
    IF target_policy.id IS NULL OR ceiling_policy.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy version retirement target or ceiling is unavailable';
    END IF;
    PERFORM iam.assert_current_user_boundary_evidence(tenant,actor,'iam.policy-version.delete',actor_evidence);
    IF EXISTS(SELECT 1 FROM iam.user_permission_boundaries boundary
          WHERE boundary.policy_id=lock_policy_version_retirement_delegation.policy_id AND boundary.revoked_at IS NULL)
      OR EXISTS(SELECT 1 FROM iam.role_permission_boundaries boundary
          WHERE boundary.policy_id=lock_policy_version_retirement_delegation.policy_id AND boundary.revoked_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='delegated policy version retirement target is unavailable';
    END IF;
    RETURN actor_evidence;
END $function$;

DROP FUNCTION IF EXISTS iam.delete_policy_version(text,text,text,text,text,bigint,jsonb);
CREATE OR REPLACE FUNCTION iam.delete_policy_version(tenant text,actor text,decision text,policy_id text,version_id text,
    expected_version bigint,event jsonb,actor_session_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE policy iam.policies%ROWTYPE; version iam.policy_versions%ROWTYPE; replayed boolean; actor_is_root boolean;
    actor_evidence jsonb; completed iam.policy_version_retirements%ROWTYPE; prior_scope text;
    effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740990
      OR COALESCE(actor_session_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy revision or publisher session is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy account is unavailable'; END IF;
    PERFORM 1 FROM iam.principals principal WHERE principal.tenant_id=tenant AND principal.id=actor
      AND principal.principal_type='USER' AND principal.status='ACTIVE' AND NOT principal.must_change_password
      AND principal.deleted_at IS NULL FOR NO KEY UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy actor is unavailable'; END IF;
    PERFORM 1 FROM iam.user_credentials credential JOIN iam.sessions session
      ON (session.tenant_id,session.principal_id)=(credential.tenant_id,credential.principal_id)
      WHERE credential.tenant_id=tenant AND credential.principal_id=actor AND session.id=actor_session_id
        AND session.status='ACTIVE' AND session.revoked_at IS NULL AND session.expires_at>clock_timestamp()
        AND session.credential_version=credential.credential_version
        AND session.last_activity_at IS NOT NULL AND session.idle_timeout_seconds IS NOT NULL
        AND session.last_activity_at+make_interval(secs=>session.idle_timeout_seconds)>clock_timestamp()
      FOR SHARE OF credential,session;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy publisher session is unavailable'; END IF;
    PERFORM 1 FROM iam.account_roots root WHERE root.account_id=tenant AND root.principal_id=actor FOR SHARE;
    actor_is_root:=FOUND;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.policy-version.delete','POLICY',policy_id,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(event,tenant,'iam.policy-version.deleted','POLICY',policy_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='policy version decision is invalid';
    END IF;
    -- Close foreign, SYSTEM and terminal targets before consulting a request's
    -- replay key. The locked path repeats the same classification.
    PERFORM 1 FROM iam.policies target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
      AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE';
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy is unavailable'; END IF;
    replayed:=iam.policy_version_intent_replayed(tenant,actor,event);
    IF replayed THEN
        SELECT * INTO policy FROM iam.policies target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
          AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE' FOR UPDATE;
        SELECT * INTO version FROM iam.policy_versions candidate
          WHERE candidate.policy_id=delete_policy_version.policy_id AND candidate.id=version_id FOR UPDATE;
        IF policy.id IS NULL OR version.id IS NULL OR policy.resource_version<>expected_version+1
          OR version.retired_at IS NULL THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy version deletion replay conflicts';
        END IF;
        IF NOT actor_is_root THEN
            SELECT * INTO completed FROM iam.policy_version_retirements retirement
              WHERE (retirement.tenant_id,retirement.actor_principal_id,retirement.request_id)=
                (tenant,actor,event->>'requestId');
            IF NOT FOUND OR completed.policy_id IS DISTINCT FROM policy_id
              OR completed.version_id IS DISTINCT FROM version_id
              OR completed.expected_resource_version IS DISTINCT FROM expected_version
              OR completed.completed_at IS DISTINCT FROM version.retired_at
              OR NOT EXISTS(SELECT 1 FROM iam.authorization_decisions original_decision
                JOIN iam.audit_outbox original_event
                  ON original_event.tenant_id=original_decision.tenant_id
                  AND original_event.event_id=completed.event_id
                WHERE original_decision.tenant_id=tenant AND original_decision.id=completed.decision_id
                  AND original_decision.principal_id=actor AND original_decision.allowed
                  AND original_decision.action_name='iam.policy-version.delete'
                  AND original_decision.target_kind='POLICY' AND original_decision.target_id=completed.policy_id
                  AND original_decision.resource_mode='INSTANCE' AND original_decision.collection_usage IS NULL
                  AND original_decision.contract_version=7 AND original_decision.subject_type='USER'
                  AND original_decision.access_key_id IS NULL
                  AND original_decision.request_id=completed.request_id
                  AND original_decision.boundary_evidence=completed.actor_boundary_evidence
                  AND original_event.event_document->>'action'='iam.policy-version.deleted'
                  AND original_event.event_document#>>'{actor,id}'=actor
                  AND original_event.event_document#>>'{target,kind}'='POLICY'
                  AND original_event.event_document#>>'{target,id}'=completed.policy_id
                  AND original_event.event_document->>'result'='SUCCEEDED'
                  AND original_event.event_document->>'requestId'=completed.request_id
                  AND original_event.event_document->>'requestDigest'=event->>'requestDigest'
                  AND original_event.event_document->>'iamDecisionId'=completed.decision_id) THEN
                RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='policy version retirement completion is unavailable';
            END IF;
        END IF;
        RETURN iam.policy_detail_snapshot(tenant,policy_id);
    END IF;

    IF actor_is_root THEN
        SELECT * INTO policy FROM iam.policies target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
          AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE' FOR UPDATE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy is unavailable'; END IF;
    ELSE
        actor_evidence:=iam.lock_policy_version_retirement_delegation(tenant,actor,decision,policy_id);
        SELECT * INTO policy FROM iam.policies target WHERE target.id=policy_id AND target.owner_tenant_id=tenant
          AND target.management='CUSTOMER' AND target.authority_scope='TENANT' AND target.status='ACTIVE';
        IF NOT FOUND OR actor_evidence IS NULL THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy version retirement delegation is unavailable';
        END IF;
    END IF;
    SELECT * INTO version FROM iam.policy_versions candidate
      WHERE candidate.policy_id=delete_policy_version.policy_id AND candidate.id=version_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='policy version is unavailable'; END IF;
    IF policy.resource_version<>expected_version OR version.retired_at IS NOT NULL OR policy.default_version_id=version_id THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='policy version revision or default conflicts';
    END IF;
    UPDATE iam.policy_versions candidate SET retired_at=effective_now
      WHERE candidate.policy_id=delete_policy_version.policy_id AND candidate.id=version_id;
    UPDATE iam.policies target SET resource_version=resource_version+1,updated_at=effective_now WHERE target.id=policy_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    IF NOT actor_is_root THEN
        prior_scope:=current_setting('matrix.iam_policy_version_retirement',true);
        PERFORM set_config('matrix.iam_policy_version_retirement','trusted',true);
        INSERT INTO iam.policy_version_retirements(tenant_id,actor_principal_id,request_id,policy_id,version_id,
          expected_resource_version,actor_boundary_evidence,decision_id,event_id,completed_at)
        VALUES(tenant,actor,event->>'requestId',policy_id,version_id,expected_version,actor_evidence,
          decision,event->>'eventId',effective_now);
        PERFORM set_config('matrix.iam_policy_version_retirement',COALESCE(prior_scope,''),true);
    END IF;
    RETURN iam.policy_detail_snapshot(tenant,policy_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.policy_version_retirement_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
  SELECT EXISTS(SELECT 1 FROM pg_class relation
      WHERE relation.oid='iam.policy_version_retirements'::regclass
        AND relation.relowner='matrix_iam_owner'::regrole
        AND relation.relrowsecurity AND relation.relforcerowsecurity
        AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) privilege
          WHERE privilege.grantee<>relation.relowner))
    AND EXISTS(SELECT 1 FROM pg_constraint constraint_value
      WHERE constraint_value.conrelid='iam.policy_version_retirements'::regclass
        AND constraint_value.conname='policy_version_retirements_shape'
        AND constraint_value.contype='c' AND constraint_value.convalidated)
    AND (SELECT count(*)=4 FROM pg_trigger trigger_value
      WHERE trigger_value.tgrelid='iam.policy_version_retirements'::regclass
        AND NOT trigger_value.tgisinternal)
    AND NOT EXISTS(SELECT 1 FROM (VALUES
        ('policy_version_retirement_insert_guard','iam.guard_policy_version_retirement_insert()'::regprocedure,7::smallint),
        ('policy_version_retirements_cannot_be_updated','iam.reject_policy_history_change()'::regprocedure,19::smallint),
        ('policy_version_retirements_cannot_be_deleted','iam.reject_policy_history_change()'::regprocedure,11::smallint),
        ('policy_version_retirements_cannot_be_truncated','iam.reject_policy_history_change()'::regprocedure,34::smallint)
      ) expected(name,function_oid,trigger_type)
      LEFT JOIN pg_trigger trigger_value ON trigger_value.tgrelid='iam.policy_version_retirements'::regclass
        AND trigger_value.tgname=expected.name AND NOT trigger_value.tgisinternal
      WHERE trigger_value.oid IS NULL OR trigger_value.tgenabled<>'A'
        OR trigger_value.tgfoid<>expected.function_oid OR trigger_value.tgtype<>expected.trigger_type)
    AND EXISTS(SELECT 1 FROM pg_proc guard
      WHERE guard.oid='iam.guard_policy_version_retirement_insert()'::regprocedure
        AND NOT guard.prosecdef AND guard.proowner='matrix_iam_owner'::regrole
        AND guard.prorettype='trigger'::regtype AND guard.pronargs=0 AND NOT guard.proretset
        AND 'search_path=pg_catalog, pg_temp'=ANY(guard.proconfig)
        AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(guard.proacl,acldefault('f',guard.proowner))) privilege
          WHERE privilege.grantee<>guard.proowner))
    AND EXISTS(SELECT 1 FROM pg_proc entry
      WHERE entry.oid=to_regprocedure('iam.delete_policy_version(text,text,text,text,text,bigint,jsonb,text)')
        AND entry.prosecdef AND entry.proowner='matrix_iam_owner'::regrole
        AND entry.prorettype='jsonb'::regtype AND NOT entry.proretset
        AND 'search_path=pg_catalog, pg_temp'=ANY(entry.proconfig))
    AND to_regprocedure('iam.delete_policy_version(text,text,text,text,text,bigint,jsonb)') IS NULL
    AND EXISTS(SELECT 1 FROM pg_proc helper
      WHERE helper.oid=to_regprocedure('iam.lock_policy_version_retirement_delegation(text,text,text,text)')
        AND NOT helper.prosecdef AND helper.proowner='matrix_iam_owner'::regrole
        AND helper.prorettype='jsonb'::regtype AND NOT helper.proretset
        AND 'search_path=pg_catalog, pg_temp'=ANY(helper.proconfig)
        AND NOT has_function_privilege('public',helper.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_api',helper.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_worker',helper.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_credential_recovery',helper.oid,'EXECUTE'))
$function$;
REVOKE ALL ON FUNCTION iam.lock_policy_version_retirement_delegation(text,text,text,text),
    iam.policy_version_retirement_contract_ready(),iam.delete_policy_version(text,text,text,text,text,bigint,jsonb,text)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.delete_policy_version(text,text,text,text,text,bigint,jsonb,text) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.user_permission_boundary_snapshot(tenant text,user_id text)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE boundary jsonb; reference jsonb;
BEGIN
    boundary:=iam.current_user_boundary(tenant,user_id);
    IF boundary->>'state'='BOUND' THEN
        reference:=jsonb_build_object('policyId',boundary#>>'{version,value,policyId}','versionId',boundary#>>'{version,value,versionId}','contentDigest',boundary#>>'{version,value,contentDigest}');
    END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','UserPermissionBoundary',
        'accountId',tenant,'userId',user_id,'resourceVersion',boundary->'userResourceVersion','policy',reference);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_user_permission_boundary(tenant text,actor text,decision text,user_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.user.read','USER',user_id,'INSTANCE',NULL);
    RETURN iam.user_permission_boundary_snapshot(tenant,user_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.change_user_permission_boundary(tenant text,actor text,decision text,user_id text,
    expected_version bigint,policy_id text,expected_policy_version bigint,boundary_id text,event jsonb,actor_session_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE subject iam.principals%ROWTYPE; current_binding iam.user_permission_boundaries%ROWTYPE; policy iam.policies%ROWTYPE;
    previous jsonb; action_name text; fact_name text; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740990
        OR COALESCE(actor_session_id,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR policy_id IS NULL OR boundary_id IS NULL OR expected_policy_version IS NULL
        OR (policy_id='' AND (boundary_id<>'' OR expected_policy_version<>0))
        OR (policy_id<>'' AND (policy_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            OR boundary_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' OR expected_policy_version NOT BETWEEN 1 AND 9007199254740991)) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='user boundary mutation is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='boundary account is unavailable'; END IF;
    -- Keep actor and target state exclusive in stable order, but allow the
    -- immutable identity references from concurrent authorization decisions.
    PERFORM 1 FROM iam.principals p WHERE p.tenant_id=tenant AND p.id IN(actor,user_id) ORDER BY p.id FOR NO KEY UPDATE;
    PERFORM 1 FROM iam.principals p JOIN iam.account_roots r ON r.account_id=p.tenant_id AND r.principal_id=p.id
        WHERE p.tenant_id=tenant AND p.id=actor AND p.principal_type='USER' AND p.status='ACTIVE'
          AND p.deleted_at IS NULL AND NOT p.must_change_password FOR SHARE OF r;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='boundary publisher is unavailable'; END IF;
    -- Only the authenticated bearer supplies this private session reference.
    -- Credential/logout writers take the same principal lock first; locking
    -- the current rows forces stale SERIALIZABLE snapshots to retry, not apply.
    PERFORM 1 FROM iam.user_credentials c JOIN iam.sessions s
        ON s.tenant_id=c.tenant_id AND s.principal_id=c.principal_id
        WHERE c.tenant_id=tenant AND c.principal_id=actor AND s.id=actor_session_id
          AND s.status='ACTIVE' AND s.revoked_at IS NULL AND s.expires_at>effective_now
          AND s.credential_version=c.credential_version FOR SHARE OF c,s;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='boundary session is unavailable'; END IF;
    SELECT * INTO subject FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=user_id AND p.principal_type='USER' AND p.deleted_at IS NULL;
    IF NOT FOUND OR EXISTS(SELECT 1 FROM iam.account_roots r WHERE r.account_id=tenant AND r.principal_id=user_id) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='boundary target is unavailable';
    END IF;
    action_name:=CASE WHEN policy_id='' THEN 'iam.user.permission-boundary.remove' ELSE 'iam.user.permission-boundary.set' END;
    fact_name:=CASE WHEN policy_id='' THEN 'iam.user.permission-boundary.removed' ELSE 'iam.user.permission-boundary.set' END;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,action_name,'USER',user_id,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(event,tenant,fact_name,'USER',user_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='boundary decision is invalid'; END IF;
    SELECT * INTO current_binding FROM iam.user_permission_boundaries b
        WHERE b.tenant_id=tenant AND b.user_id=change_user_permission_boundary.user_id AND b.revoked_at IS NULL
        FOR UPDATE;
    -- A delegated Group attachment is a live upper-bound contract for every
    -- member. Boundary removal/replacement must first remove the member or
    -- revoke the attachment; changing the boundary in place would otherwise
    -- create an authorization path outside the sealed closure.
    PERFORM target_group.id FROM iam.group_memberships member
      JOIN iam.groups target_group ON (target_group.tenant_id,target_group.id)=(member.tenant_id,member.group_id)
      WHERE member.tenant_id=tenant AND member.user_id=change_user_permission_boundary.user_id AND member.removed_at IS NULL
        AND target_group.deleted_at IS NULL ORDER BY target_group.id FOR UPDATE OF target_group;
    PERFORM attachment.id FROM iam.group_memberships member
      JOIN iam.policy_attachments attachment ON attachment.tenant_id=member.tenant_id
        AND attachment.target_kind='GROUP' AND attachment.target_id=member.group_id
      WHERE member.tenant_id=tenant AND member.user_id=change_user_permission_boundary.user_id AND member.removed_at IS NULL
        AND attachment.revoked_at IS NULL AND attachment.delegation_ceiling_policy_id IS NOT NULL
      ORDER BY attachment.id FOR NO KEY UPDATE OF attachment;
    IF EXISTS(SELECT 1 FROM iam.group_memberships member
      JOIN iam.policy_attachments attachment ON attachment.tenant_id=member.tenant_id
        AND attachment.target_kind='GROUP' AND attachment.target_id=member.group_id
      WHERE member.tenant_id=tenant AND member.user_id=change_user_permission_boundary.user_id AND member.removed_at IS NULL
        AND attachment.revoked_at IS NULL AND attachment.delegation_ceiling_policy_id IS NOT NULL
        AND (change_user_permission_boundary.policy_id=''
          OR attachment.delegation_ceiling_policy_id<>change_user_permission_boundary.policy_id)) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='group delegation ceiling protects the user boundary';
    END IF;
    PERFORM 1 FROM iam.policies p WHERE p.id IN(policy_id,current_binding.policy_id) ORDER BY p.id FOR UPDATE;
    IF policy_id<>'' THEN
        SELECT * INTO policy FROM iam.policies p WHERE p.id=change_user_permission_boundary.policy_id
            AND p.status='ACTIVE' AND p.authority_scope='TENANT' AND (p.owner_tenant_id IS NULL OR p.owner_tenant_id=tenant);
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='boundary policy is unavailable'; END IF;
        IF policy.resource_version<>expected_policy_version THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='boundary policy revision conflicts'; END IF;
    END IF;
    SELECT event_document INTO previous FROM iam.audit_outbox o WHERE o.tenant_id=tenant AND o.event_document->>'action'=fact_name
        AND o.event_document#>>'{actor,id}'=actor AND o.event_document->>'requestId'=event->>'requestId';
    IF FOUND THEN
        IF previous->>'requestDigest' IS DISTINCT FROM event->>'requestDigest' OR previous->'target' IS DISTINCT FROM event->'target'
            OR subject.resource_version<>expected_version+1
            OR (policy_id='' AND current_binding.id IS NOT NULL)
            OR (policy_id<>'' AND (current_binding.id IS DISTINCT FROM boundary_id OR current_binding.policy_id IS DISTINCT FROM policy_id)) THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='boundary command replay conflicts';
        END IF;
        RETURN iam.user_permission_boundary_snapshot(tenant,user_id);
    END IF;
    IF subject.resource_version<>expected_version OR (policy_id='' AND current_binding.id IS NULL)
        OR (policy_id<>'' AND current_binding.policy_id=policy_id) THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='boundary user revision or state conflicts';
    END IF;
    IF current_binding.id IS NOT NULL THEN
        UPDATE iam.user_permission_boundaries b SET resource_version=b.resource_version+1,updated_at=effective_now,revoked_at=effective_now
            WHERE b.tenant_id=tenant AND b.id=current_binding.id;
    END IF;
    IF policy_id<>'' THEN
        INSERT INTO iam.user_permission_boundaries(tenant_id,id,user_id,policy_id,resource_version,created_at,updated_at)
            VALUES(tenant,boundary_id,user_id,policy_id,1,effective_now,effective_now);
    END IF;
    UPDATE iam.principals p SET resource_version=p.resource_version+1,updated_at=effective_now WHERE p.tenant_id=tenant AND p.id=user_id;
    PERFORM iam.append_account_event(tenant,actor,decision,fact_name,'USER',user_id,event);
    RETURN iam.user_permission_boundary_snapshot(tenant,user_id);
END $function$;
REVOKE ALL ON FUNCTION iam.user_permission_boundary_snapshot(text,text),iam.read_user_permission_boundary(text,text,text,text),
    iam.change_user_permission_boundary(text,text,text,text,bigint,text,bigint,text,jsonb,text)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.read_user_permission_boundary(text,text,text,text),
    iam.change_user_permission_boundary(text,text,text,text,bigint,text,bigint,text,jsonb,text) TO matrix_iam_api;

-- All current and historical authorization shapes now use the source-neutral
-- bounded tag validator. The pre-v1 request-only name is not a supported ABI.
DROP FUNCTION IF EXISTS iam.authorization_request_tags_valid(jsonb);
