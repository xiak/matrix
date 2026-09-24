SET LOCAL ROLE matrix_iam_owner;

-- Public key identity and encrypted material belong to the real USER. The
-- wrapping registry is installation-wide, append-only and never a permission.
CREATE TABLE IF NOT EXISTS iam.access_key_wrapping_registry (
    installation_id text COLLATE "C" NOT NULL,
    wrapping_key_id text COLLATE "C" NOT NULL,
    material_commitment text NOT NULL,
    created_at timestamptz(6) NOT NULL,
    PRIMARY KEY(installation_id,wrapping_key_id),
    FOREIGN KEY(installation_id) REFERENCES iam.bootstrap_receipts(installation_id),
    CHECK(wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CHECK(material_commitment ~ '^sha256:[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS iam.access_keys (
    id text COLLATE "C" PRIMARY KEY,
    tenant_id text COLLATE "C" NOT NULL,
    user_id text COLLATE "C" NOT NULL,
    created_by text COLLATE "C" NOT NULL,
    creation_request_id text COLLATE "C" NOT NULL CHECK(creation_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    creation_request_digest text NOT NULL CHECK(creation_request_digest ~ '^sha256:[0-9a-f]{64}$'),
    installation_id text COLLATE "C" NOT NULL,
    wrapping_key_id text COLLATE "C" NOT NULL,
    status text NOT NULL CHECK(status IN ('ENABLED','DISABLED')),
    resource_version bigint NOT NULL CHECK(resource_version BETWEEN 1 AND 9007199254740991),
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    deleted_at timestamptz(6),
    format_version integer,
    nonce bytea,
    ciphertext bytea,
    UNIQUE(tenant_id,id),
    UNIQUE(tenant_id,user_id,id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(tenant_id,created_by) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(installation_id,wrapping_key_id) REFERENCES iam.access_key_wrapping_registry(installation_id,wrapping_key_id),
    CHECK(id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CONSTRAINT access_keys_material_shape CHECK(
      (format_version IS NULL AND nonce IS NULL AND ciphertext IS NULL)
      OR (format_version IS NOT NULL AND format_version=1 AND nonce IS NOT NULL AND octet_length(nonce)=12
          AND ciphertext IS NOT NULL AND octet_length(ciphertext)=48)),
    CONSTRAINT access_keys_lifecycle CHECK(isfinite(created_at) AND isfinite(updated_at) AND updated_at>=created_at
      AND (resource_version<>1 OR (status='ENABLED' AND updated_at=created_at AND deleted_at IS NULL))
      AND (deleted_at IS NULL OR (deleted_at=updated_at AND resource_version>=2
          AND format_version IS NULL AND nonce IS NULL AND ciphertext IS NULL)))
);
CREATE INDEX IF NOT EXISTS access_keys_live_user_idx ON iam.access_keys(tenant_id,user_id,id) WHERE deleted_at IS NULL;

-- This owner-only locator crosses RLS only to find the physical owner. It is
-- not a credential or an authority selector, and survives irreversible delete.
CREATE TABLE IF NOT EXISTS iam.access_key_index (
    key_id text COLLATE "C" PRIMARY KEY,
    tenant_id text COLLATE "C" NOT NULL,
    user_id text COLLATE "C" NOT NULL,
    FOREIGN KEY(tenant_id,user_id,key_id) REFERENCES iam.access_keys(tenant_id,user_id,id)
);
ALTER TABLE iam.access_keys NO FORCE ROW LEVEL SECURITY;
INSERT INTO iam.access_key_index(key_id,tenant_id,user_id)
    SELECT id,tenant_id,user_id FROM iam.access_keys ON CONFLICT(key_id) DO NOTHING;
DO $verify_key_locator$ BEGIN
    IF EXISTS(SELECT 1 FROM iam.access_keys k LEFT JOIN iam.access_key_index i ON i.key_id=k.id
        WHERE i.tenant_id IS DISTINCT FROM k.tenant_id OR i.user_id IS DISTINCT FROM k.user_id) THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='access key locator conflicts'; END IF;
END $verify_key_locator$;
ALTER TABLE iam.access_keys FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION iam.register_access_key_identity()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    INSERT INTO iam.access_key_index(key_id,tenant_id,user_id) VALUES(NEW.id,NEW.tenant_id,NEW.user_id);
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS access_key_identity_registered ON iam.access_keys;
CREATE TRIGGER access_key_identity_registered AFTER INSERT ON iam.access_keys
    FOR EACH ROW EXECUTE FUNCTION iam.register_access_key_identity();
ALTER TABLE iam.access_keys ENABLE ALWAYS TRIGGER access_key_identity_registered;

-- One immutable row is both the authenticated request evidence and its
-- permanent nonce consumption. A duplicate never returns an old permit.
CREATE TABLE IF NOT EXISTS iam.access_key_authorization_evidence (
    tenant_id text COLLATE "C" NOT NULL,
    decision_id text COLLATE "C" NOT NULL,
    user_id text COLLATE "C" NOT NULL,
    access_key_id text COLLATE "C" NOT NULL,
    key_resource_version bigint NOT NULL,
    format_version integer NOT NULL,
    wrapping_key_id text COLLATE "C" NOT NULL,
    material_commitment text NOT NULL,
    installation_id text COLLATE "C" NOT NULL,
    service_tenant_id text COLLATE "C" NOT NULL,
    service_principal_id text COLLATE "C" NOT NULL,
    service_purpose text COLLATE "C" NOT NULL,
    service_lookup_digest text COLLATE "C" NOT NULL,
    service_verification_digest text COLLATE "C" NOT NULL,
    service_created_at timestamptz(6) NOT NULL,
    audience text COLLATE "C" NOT NULL,
    signed_request_digest text NOT NULL,
    nonce_digest text NOT NULL,
    signed_at bigint NOT NULL,
    PRIMARY KEY(tenant_id,decision_id),
    UNIQUE(access_key_id,nonce_digest),
    FOREIGN KEY(tenant_id,decision_id) REFERENCES iam.authorization_decisions(tenant_id,id),
    FOREIGN KEY(tenant_id,user_id,access_key_id) REFERENCES iam.access_keys(tenant_id,user_id,id),
    FOREIGN KEY(installation_id,wrapping_key_id) REFERENCES iam.access_key_wrapping_registry(installation_id,wrapping_key_id),
    FOREIGN KEY(service_tenant_id,service_principal_id,service_lookup_digest)
      REFERENCES iam.service_credentials(tenant_id,principal_id,lookup_digest),
    CONSTRAINT access_key_authorization_values CHECK(
      key_resource_version BETWEEN 1 AND 9007199254740991 AND format_version=1
      AND signed_at BETWEEN 1 AND 253402300799 AND isfinite(service_created_at)
      AND audience COLLATE "C" ~ '^[a-z][a-z0-9_-]{0,63}$'
      AND material_commitment ~ '^sha256:[0-9a-f]{64}$'
      AND signed_request_digest ~ '^sha256:[0-9a-f]{64}$' AND nonce_digest ~ '^sha256:[0-9a-f]{64}$')
);

-- The result is a nonsecret completion snapshot, not today's key state. An
-- intent cannot be reused with another target, command or input commitment.
CREATE OR REPLACE FUNCTION iam.access_key_result_valid(action_name text,value jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE expected text[]; field text; version bigint;
BEGIN
    expected:=CASE WHEN action_name='iam.access-key.delete'
      THEN ARRAY['accountId','apiVersion','deletedAt','id','kind','resourceVersion','userId']
      ELSE ARRAY['accountId','apiVersion','createdAt','id','kind','resourceVersion','status','updatedAt','userId'] END;
    IF value IS NULL OR jsonb_typeof(value)<>'object'
       OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(value) key) IS DISTINCT FROM expected
       OR value->>'apiVersion' IS DISTINCT FROM 'iam.matrix.xiak.com/v1'
       OR jsonb_typeof(value->'resourceVersion') IS DISTINCT FROM 'number'
       OR (value->>'resourceVersion') !~ '^[1-9][0-9]{0,15}$' THEN RETURN false; END IF;
    FOREACH field IN ARRAY expected LOOP
        IF field<>'resourceVersion' AND jsonb_typeof(value->field) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
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
    IF action_name NOT IN ('iam.access-key.create','iam.access-key.set-status') OR value->>'kind'<>'AccessKey'
       OR value->>'status' NOT IN ('ENABLED','DISABLED') OR NOT pg_input_is_valid(value->>'createdAt','timestamp with time zone')
       OR NOT pg_input_is_valid(value->>'updatedAt','timestamp with time zone') THEN RETURN false; END IF;
    RETURN isfinite((value->>'updatedAt')::timestamptz) AND isfinite((value->>'createdAt')::timestamptz)
      AND (value->>'updatedAt')::timestamptz>=(value->>'createdAt')::timestamptz
      AND ((action_name='iam.access-key.create' AND version=1 AND value->>'status'='ENABLED' AND value->>'createdAt'=value->>'updatedAt')
        OR (action_name='iam.access-key.set-status' AND version>=2));
END $function$;
CREATE TABLE IF NOT EXISTS iam.access_key_intents (
    tenant_id text COLLATE "C" NOT NULL,
    actor_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    action_name text NOT NULL CHECK(action_name IN ('iam.access-key.create','iam.access-key.set-status','iam.access-key.delete')),
    user_id text COLLATE "C" NOT NULL,
    key_id text COLLATE "C" NOT NULL,
    request_digest text NOT NULL CHECK(request_digest ~ '^sha256:[0-9a-f]{64}$'),
    result jsonb NOT NULL,
    decision_id text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    completed_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,actor_id,request_id),
    FOREIGN KEY(tenant_id,actor_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(tenant_id,user_id,key_id) REFERENCES iam.access_keys(tenant_id,user_id,id),
    FOREIGN KEY(tenant_id,decision_id) REFERENCES iam.authorization_decisions(tenant_id,id),
    FOREIGN KEY(tenant_id,event_id) REFERENCES iam.audit_outbox(tenant_id,event_id),
    CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CONSTRAINT access_key_intent_snapshot CHECK(iam.access_key_result_valid(action_name,result)
      AND result->>'accountId' IS NOT DISTINCT FROM tenant_id AND result->>'userId' IS NOT DISTINCT FROM user_id
      AND result->>'id' IS NOT DISTINCT FROM key_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS access_key_creation_intent_uq ON iam.access_key_intents(tenant_id,key_id) WHERE action_name='iam.access-key.create';

CREATE OR REPLACE FUNCTION iam.guard_access_key_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF ROW(NEW.id,NEW.tenant_id,NEW.user_id,NEW.installation_id,NEW.wrapping_key_id,NEW.created_at,NEW.created_by,NEW.creation_request_id,NEW.creation_request_digest)
       IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.user_id,OLD.installation_id,OLD.wrapping_key_id,OLD.created_at,OLD.created_by,OLD.creation_request_id,OLD.creation_request_digest)
       OR OLD.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='access key identity is immutable'; END IF;
    -- Only the reserved, uncommitted row may receive material, exactly once.
    IF OLD.format_version IS NULL AND OLD.resource_version=1 AND NEW.format_version=1
       AND NEW.resource_version=OLD.resource_version AND NEW.status=OLD.status AND NEW.updated_at=OLD.updated_at
       AND NEW.deleted_at IS NULL THEN RETURN NEW; END IF;
    IF OLD.format_version IS NULL OR NEW.resource_version<>OLD.resource_version+1
       OR NEW.updated_at<>transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='access key transition is invalid'; END IF;
    IF NEW.deleted_at IS NOT NULL THEN
        IF NEW.deleted_at<>NEW.updated_at OR NEW.status<>OLD.status OR NEW.format_version IS NOT NULL
           OR NEW.nonce IS NOT NULL OR NEW.ciphertext IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='access key deletion is invalid'; END IF;
    ELSIF NEW.status=OLD.status OR ROW(NEW.format_version,NEW.nonce,NEW.ciphertext)
          IS DISTINCT FROM ROW(OLD.format_version,OLD.nonce,OLD.ciphertext) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='access key material cannot be replaced';
    END IF;
    RETURN NEW;
END $function$;

CREATE OR REPLACE FUNCTION iam.assert_access_key_completed()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.access_keys%ROWTYPE;
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',NEW.tenant_id,true);
    SELECT * INTO stored FROM iam.access_keys WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
    IF NOT FOUND OR (stored.deleted_at IS NULL AND stored.format_version IS NULL)
       OR NOT EXISTS(SELECT 1 FROM iam.access_key_index i WHERE i.key_id=stored.id
           AND i.tenant_id=stored.tenant_id AND i.user_id=stored.user_id)
       OR NOT EXISTS(SELECT 1 FROM iam.access_key_intents i WHERE i.tenant_id=stored.tenant_id AND i.key_id=stored.id
           AND i.action_name='iam.access-key.create' AND i.actor_id=stored.created_by
           AND i.request_id=stored.creation_request_id AND i.request_digest=stored.creation_request_digest) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='access key creation is incomplete'; END IF;
    RETURN NULL;
END $function$;
DROP TRIGGER IF EXISTS access_key_transition ON iam.access_keys;
CREATE TRIGGER access_key_transition BEFORE UPDATE ON iam.access_keys FOR EACH ROW EXECUTE FUNCTION iam.guard_access_key_change();
ALTER TABLE iam.access_keys ENABLE ALWAYS TRIGGER access_key_transition;
DROP TRIGGER IF EXISTS access_key_creation_complete ON iam.access_keys;
CREATE CONSTRAINT TRIGGER access_key_creation_complete AFTER INSERT OR UPDATE ON iam.access_keys
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.assert_access_key_completed();
ALTER TABLE iam.access_keys ENABLE ALWAYS TRIGGER access_key_creation_complete;

DO $key_protection$ DECLARE table_name text; BEGIN
    FOREACH table_name IN ARRAY ARRAY['access_keys','access_key_intents','access_key_authorization_evidence'] LOOP
        EXECUTE format('ALTER TABLE iam.%I ENABLE ROW LEVEL SECURITY',table_name);
        EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON iam.%I',table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON iam.%I USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id())',table_name);
    END LOOP;
    FOREACH table_name IN ARRAY ARRAY['access_keys','access_key_intents','access_key_wrapping_registry','access_key_index','access_key_authorization_evidence'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS cannot_delete ON iam.%I',table_name);
        EXECUTE format('CREATE TRIGGER cannot_delete BEFORE DELETE ON iam.%I FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change()',table_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER cannot_delete',table_name);
        EXECUTE format('DROP TRIGGER IF EXISTS cannot_truncate ON iam.%I',table_name);
        EXECUTE format('CREATE TRIGGER cannot_truncate BEFORE TRUNCATE ON iam.%I FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change()',table_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER cannot_truncate',table_name);
    END LOOP;
    FOREACH table_name IN ARRAY ARRAY['access_key_intents','access_key_wrapping_registry','access_key_index','access_key_authorization_evidence'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS cannot_update ON iam.%I',table_name);
        EXECUTE format('CREATE TRIGGER cannot_update BEFORE UPDATE ON iam.%I FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change()',table_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER cannot_update',table_name);
    END LOOP;
END $key_protection$;

CREATE OR REPLACE FUNCTION iam.access_key_snapshot(tenant text,key_id text)
RETURNS jsonb LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AccessKey','id',k.id,
      'accountId',k.tenant_id,'userId',k.user_id,'status',k.status,'resourceVersion',k.resource_version,
      'createdAt',k.created_at,'updatedAt',k.updated_at)
      FROM iam.access_keys k WHERE k.tenant_id=tenant AND k.id=key_id AND k.deleted_at IS NULL AND k.format_version IS NOT NULL
$function$;
CREATE OR REPLACE FUNCTION iam.access_key_deletion_snapshot(tenant text,key_id text)
RETURNS jsonb LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','AccessKeyDeletion','id',k.id,
      'accountId',k.tenant_id,'userId',k.user_id,'resourceVersion',k.resource_version,'deletedAt',k.deleted_at)
      FROM iam.access_keys k WHERE k.tenant_id=tenant AND k.id=key_id AND k.deleted_at IS NOT NULL
$function$;

-- A MAC is checked by IAM, never SQL. This entrypoint returns only a locked
-- credential snapshot to the IAM API role, after independently resolving the
-- actual current calling service. Disabled target states are intentionally
-- retained so the later recorder can persist Deny and consume a valid nonce.
CREATE OR REPLACE FUNCTION iam.lookup_access_key(submitted_service_digest text,submitted_key_id text,submitted_installation text,submitted_audience text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE locator iam.access_key_index%ROWTYPE; caller iam.service_credential_index%ROWTYPE;
    credential iam.service_credentials%ROWTYPE; stored iam.access_keys%ROWTYPE;
    receipt iam.bootstrap_receipts%ROWTYPE; target iam.principals%ROWTYPE;
    selected record; material_commitment text;
BEGIN
    IF COALESCE(submitted_service_digest,'') COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
       OR COALESCE(submitted_key_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_installation,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_audience,'') COLLATE "C" !~ '^[a-z][a-z0-9_-]{0,63}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='signed credential request is invalid'; END IF;
    SELECT * INTO caller FROM iam.service_credential_index WHERE lookup_digest=submitted_service_digest;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO receipt FROM iam.bootstrap_receipts WHERE singleton AND organization_id=caller.tenant_id
      AND installation_id=submitted_installation;
    IF NOT FOUND THEN RETURN NULL; END IF;
	SELECT * INTO locator FROM iam.access_key_index WHERE key_id=submitted_key_id;
	IF NOT FOUND THEN RETURN NULL; END IF;
	IF EXISTS(SELECT 1 FROM iam.authentication_recovery_access_key_fences fence
		WHERE fence.access_key_id=locator.key_id) THEN RETURN NULL; END IF;

    -- Cross-account RLS is changed only using immutable physical locators.
    -- All Account locks precede all principal locks, even when the key belongs
    -- to a different account from the installed service's home account.
    FOR selected IN SELECT DISTINCT account_id COLLATE "C" AS account_id FROM (VALUES(caller.tenant_id),(locator.tenant_id)) owners(account_id)
      ORDER BY account_id LOOP
        PERFORM set_config('matrix.iam_tenant_id',selected.account_id,true);
        PERFORM 1 FROM iam.accounts WHERE id=selected.account_id FOR SHARE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='signed credential ownership is incomplete'; END IF;
    END LOOP;
    FOR selected IN SELECT DISTINCT tenant_id COLLATE "C" AS tenant_id,principal_id COLLATE "C" AS principal_id
      FROM (VALUES(caller.tenant_id,caller.principal_id),(locator.tenant_id,locator.user_id)) owners(tenant_id,principal_id)
      ORDER BY tenant_id,principal_id LOOP
        PERFORM set_config('matrix.iam_tenant_id',selected.tenant_id,true);
        PERFORM 1 FROM iam.principals p WHERE p.tenant_id=selected.tenant_id AND p.id=selected.principal_id FOR SHARE;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='signed credential identity is incomplete'; END IF;
    END LOOP;
    PERFORM set_config('matrix.iam_tenant_id',caller.tenant_id,true);
    SELECT * INTO credential FROM iam.service_credentials c WHERE c.tenant_id=caller.tenant_id
      AND c.principal_id=caller.principal_id AND c.lookup_digest=submitted_service_digest FOR SHARE;
    IF NOT FOUND OR credential.revoked_at IS NOT NULL
       OR NOT EXISTS(SELECT 1 FROM iam.accounts a WHERE a.id=caller.tenant_id AND a.status='ACTIVE')
       OR NOT EXISTS(SELECT 1 FROM iam.principals p WHERE p.tenant_id=caller.tenant_id AND p.id=caller.principal_id
         AND p.principal_type='SERVICE_ACCOUNT' AND p.status='ACTIVE' AND p.deleted_at IS NULL)
       OR NOT EXISTS(SELECT 1 FROM iam.authorization_profile_heads h JOIN iam.authorization_profiles p
         ON p.product=h.product AND p.revision=h.revision WHERE h.product=submitted_audience
           AND p.canonical_document::jsonb->>'callingService'=credential.purpose) THEN RETURN NULL; END IF;

    PERFORM set_config('matrix.iam_tenant_id',locator.tenant_id,true);
    SELECT * INTO target FROM iam.principals p WHERE p.tenant_id=locator.tenant_id AND p.id=locator.user_id;
    IF target.principal_type<>'USER' OR target.deleted_at IS NOT NULL THEN RETURN NULL; END IF;
    PERFORM 1 FROM iam.policies p WHERE p.id IN (
      SELECT a.policy_id FROM iam.policy_attachments a WHERE a.tenant_id=locator.tenant_id AND a.revoked_at IS NULL
        AND ((a.target_kind='USER' AND a.target_id=locator.user_id) OR (a.target_kind='GROUP' AND a.target_id IN (
          SELECT m.group_id FROM iam.group_memberships m WHERE m.tenant_id=locator.tenant_id AND m.user_id=locator.user_id AND m.removed_at IS NULL)))
      UNION SELECT b.policy_id FROM iam.user_permission_boundaries b WHERE b.tenant_id=locator.tenant_id AND b.user_id=locator.user_id AND b.revoked_at IS NULL)
      ORDER BY p.id FOR SHARE OF p;
    PERFORM 1 FROM iam.role_source_authority_generations g WHERE g.tenant_id=locator.tenant_id AND (
      g.user_id=locator.user_id OR g.group_id IN (SELECT m.group_id FROM iam.group_memberships m
        WHERE m.tenant_id=locator.tenant_id AND m.user_id=locator.user_id AND m.removed_at IS NULL))
      ORDER BY COALESCE(g.user_id,''),COALESCE(g.group_id,'') FOR SHARE OF g;
    IF NOT EXISTS(SELECT 1 FROM iam.role_source_authority_generations g WHERE g.tenant_id=locator.tenant_id AND g.user_id=locator.user_id)
       OR EXISTS(SELECT 1 FROM iam.group_memberships m WHERE m.tenant_id=locator.tenant_id AND m.user_id=locator.user_id AND m.removed_at IS NULL
         AND NOT EXISTS(SELECT 1 FROM iam.role_source_authority_generations g WHERE g.tenant_id=m.tenant_id AND g.group_id=m.group_id)) THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='signed credential authority is incomplete'; END IF;
    SELECT * INTO stored FROM iam.access_keys k WHERE k.tenant_id=locator.tenant_id AND k.user_id=locator.user_id
      AND k.id=locator.key_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='signed credential locator is incomplete'; END IF;
    IF stored.deleted_at IS NOT NULL THEN RETURN NULL; END IF;
    IF stored.installation_id<>receipt.installation_id OR stored.format_version IS NULL
       OR NOT EXISTS(SELECT 1 FROM iam.account_roots r WHERE r.account_id=locator.tenant_id) THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='signed credential material is incomplete'; END IF;
    SELECT r.material_commitment INTO material_commitment FROM iam.access_key_wrapping_registry r
      WHERE r.installation_id=stored.installation_id AND r.wrapping_key_id=stored.wrapping_key_id;
    IF material_commitment IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='signed credential custody is incomplete'; END IF;
    RETURN jsonb_build_object('account',iam.account_snapshot(locator.tenant_id),'user',iam.user_snapshot(locator.tenant_id,locator.user_id),
      'key',iam.access_key_snapshot(locator.tenant_id,locator.key_id),'installationId',stored.installation_id,
      'policies',iam.current_policy_snapshot(locator.tenant_id,locator.user_id),'boundary',iam.current_user_boundary(locator.tenant_id,locator.user_id),
      'hasUnrevokedPlatformAttachment',EXISTS(SELECT 1 FROM iam.policy_attachments a WHERE a.tenant_id=locator.tenant_id
        AND a.target_kind='USER' AND a.target_id=locator.user_id AND a.authority_scope='INSTALLATION' AND a.revoked_at IS NULL),
      'material',jsonb_build_object('formatVersion',stored.format_version,'wrappingKeyId',stored.wrapping_key_id,
        'materialCommitment',material_commitment,'nonce',encode(stored.nonce,'hex'),'ciphertext',encode(stored.ciphertext,'hex')));
END $function$;

-- Only record_authorization calls this private guard. SQL does not verify a
-- MAC: it verifies the complete locked ownership supplied by the trusted IAM
-- verifier, and never grants that authority to a client or another DB role.
CREATE OR REPLACE FUNCTION iam.assert_current_access_key_authorization(tenant text,actor text,decision jsonb,evidence jsonb)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE field text; snapshot jsonb;
BEGIN
    IF evidence IS NULL OR jsonb_typeof(evidence)<>'object'
       OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(evidence) key) IS DISTINCT FROM
         ARRAY['accessKeyId','audience','formatVersion','installationId','materialCommitment','nonceDigest','resourceVersion',
           'serviceLookupDigest','signedAt','signedRequestDigest','wrappingKeyId'] THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='signed authorization evidence is invalid'; END IF;
    FOREACH field IN ARRAY ARRAY['accessKeyId','installationId','wrappingKeyId'] LOOP
        IF jsonb_typeof(evidence->field)<>'string' OR (evidence->>field) COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='signed authorization identity is invalid'; END IF;
    END LOOP;
    FOREACH field IN ARRAY ARRAY['materialCommitment','nonceDigest','serviceLookupDigest','signedRequestDigest'] LOOP
        IF jsonb_typeof(evidence->field)<>'string' OR (evidence->>field) COLLATE "C" !~ '^sha256:[0-9a-f]{64}$' THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='signed authorization digest is invalid'; END IF;
    END LOOP;
    IF jsonb_typeof(evidence->'audience')<>'string' OR (evidence->>'audience') COLLATE "C" !~ '^[a-z][a-z0-9_-]{0,63}$'
       OR evidence->'audience' IS DISTINCT FROM decision#>'{profile,product}'
       OR jsonb_typeof(evidence->'resourceVersion')<>'number' OR (evidence->>'resourceVersion') !~ '^[1-9][0-9]{0,15}$'
       OR (evidence->>'resourceVersion')::bigint>9007199254740991 OR evidence->'formatVersion'<>'1'::jsonb
       OR jsonb_typeof(evidence->'signedAt')<>'number' OR (evidence->>'signedAt') !~ '^[1-9][0-9]{0,11}$'
       OR (evidence->>'signedAt')::bigint>253402300799 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='signed authorization binding is invalid'; END IF;
    snapshot:=iam.lookup_access_key(evidence->>'serviceLookupDigest',evidence->>'accessKeyId',evidence->>'installationId',evidence->>'audience');
    IF snapshot IS NULL OR snapshot#>>'{account,id}' IS DISTINCT FROM tenant OR snapshot#>>'{user,id}' IS DISTINCT FROM actor
       OR snapshot#>'{key,resourceVersion}' IS DISTINCT FROM evidence->'resourceVersion'
       OR snapshot#>'{material,formatVersion}' IS DISTINCT FROM evidence->'formatVersion'
       OR snapshot#>'{material,wrappingKeyId}' IS DISTINCT FROM evidence->'wrappingKeyId'
       OR snapshot#>'{material,materialCommitment}' IS DISTINCT FROM evidence->'materialCommitment' THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='signed authorization credential is unavailable'; END IF;
    IF decision->'allowed'='true'::jsonb AND (
       snapshot#>>'{account,status}'<>'ACTIVE' OR snapshot#>>'{user,status}'<>'ACTIVE'
       OR snapshot#>'{user,mustChangePassword}'<>'false'::jsonb OR snapshot#>>'{key,status}'<>'ENABLED'
       OR snapshot#>>'{account,rootIdentity,principalId}'=actor OR snapshot->'hasUnrevokedPlatformAttachment'<>'false'::jsonb
       OR to_timestamp((evidence->>'signedAt')::bigint)<transaction_timestamp()-interval '300 seconds'
       OR to_timestamp((evidence->>'signedAt')::bigint)>transaction_timestamp()+interval '30 seconds'
       OR NOT iam.authorization_decision_profile_matches(decision)) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='signed authorization is restricted'; END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.record_access_key_evidence(tenant text,actor text,decision text,evidence jsonb)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE caller iam.service_credential_index%ROWTYPE; credential iam.service_credentials%ROWTYPE;
BEGIN
    SELECT * INTO STRICT caller FROM iam.service_credential_index WHERE lookup_digest=evidence->>'serviceLookupDigest';
    PERFORM set_config('matrix.iam_tenant_id',caller.tenant_id,true);
    SELECT * INTO STRICT credential FROM iam.service_credentials c WHERE c.tenant_id=caller.tenant_id
      AND c.principal_id=caller.principal_id AND c.lookup_digest=caller.lookup_digest;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    INSERT INTO iam.access_key_authorization_evidence(tenant_id,decision_id,user_id,access_key_id,key_resource_version,
      format_version,wrapping_key_id,material_commitment,installation_id,service_tenant_id,service_principal_id,service_purpose,
      service_lookup_digest,service_verification_digest,service_created_at,audience,signed_request_digest,nonce_digest,signed_at)
    VALUES(tenant,decision,actor,evidence->>'accessKeyId',(evidence->>'resourceVersion')::bigint,(evidence->>'formatVersion')::integer,
      evidence->>'wrappingKeyId',evidence->>'materialCommitment',evidence->>'installationId',credential.tenant_id,credential.principal_id,
      credential.purpose,credential.lookup_digest,credential.verification_digest,credential.created_at,
      evidence->>'audience',evidence->>'signedRequestDigest',evidence->>'nonceDigest',(evidence->>'signedAt')::bigint);
END $function$;

-- Historical ownership is permanent, not current key material, permissions,
-- tenant activation or producer revocation. The caller separately authenticates
-- today's producer. This predicate never returns a permit or exposes evidence.
CREATE OR REPLACE FUNCTION iam.access_key_authorization_evidence_matches(tenant text,decision text)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE proof iam.access_key_authorization_evidence%ROWTYPE; valid boolean;
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    SELECT * INTO proof FROM iam.access_key_authorization_evidence e WHERE e.tenant_id=tenant AND e.decision_id=decision;
    IF NOT FOUND THEN RETURN EXISTS(SELECT 1 FROM iam.authorization_decisions d WHERE d.tenant_id=tenant AND d.id=decision AND d.access_key_id IS NULL); END IF;
    SELECT EXISTS(SELECT 1 FROM iam.authorization_decisions d
      JOIN iam.access_keys k ON k.tenant_id=d.tenant_id AND k.user_id=d.principal_id AND k.id=d.access_key_id
      JOIN iam.access_key_index i ON i.tenant_id=k.tenant_id AND i.user_id=k.user_id AND i.key_id=k.id
      JOIN iam.access_key_wrapping_registry r ON r.installation_id=k.installation_id AND r.wrapping_key_id=k.wrapping_key_id
      JOIN iam.bootstrap_receipts b ON b.installation_id=r.installation_id AND b.organization_id=proof.service_tenant_id
      JOIN iam.authorization_profiles p ON p.product=d.profile_product AND p.revision=d.profile_revision AND p.content_digest=d.profile_content_digest
      WHERE d.tenant_id=tenant AND d.id=decision AND d.contract_version=4 AND d.subject_type='USER'
        AND d.principal_id=proof.user_id AND d.access_key_id=proof.access_key_id AND d.role_evidence IS NULL
        AND k.resource_version>=proof.key_resource_version AND k.created_at<=d.decided_at
        AND r.installation_id=proof.installation_id AND r.wrapping_key_id=proof.wrapping_key_id AND r.material_commitment=proof.material_commitment
        AND proof.audience=d.profile_product AND p.canonical_document::jsonb->>'callingService'=proof.service_purpose
        AND EXISTS(SELECT 1 FROM iam.audit_outbox o WHERE o.tenant_id=tenant
          AND o.event_document->>'action'='iam.authorization.decided' AND o.event_document->>'iamDecisionId'=decision
          AND o.event_document->'actor'=jsonb_build_object('type','USER','id',proof.user_id,'accessKeyId',proof.access_key_id)
          AND o.event_document->>'requestId'=d.request_id AND o.event_document->'correlationId'=d.document->'correlationId'
          AND (o.event_document->>'occurredAt')::timestamptz=d.decided_at
          AND o.event_document->>'result'=CASE WHEN d.allowed THEN 'ALLOWED' ELSE 'DENIED' END)) INTO valid;
    IF NOT valid THEN RETURN false; END IF;
    PERFORM set_config('matrix.iam_tenant_id',proof.service_tenant_id,true);
    SELECT EXISTS(SELECT 1 FROM iam.service_credentials c JOIN iam.service_credential_index i
      ON i.tenant_id=c.tenant_id AND i.principal_id=c.principal_id AND i.lookup_digest=c.lookup_digest
      WHERE c.tenant_id=proof.service_tenant_id AND c.principal_id=proof.service_principal_id AND c.purpose=proof.service_purpose
        AND c.lookup_digest=proof.service_lookup_digest AND c.verification_digest=proof.service_verification_digest
        AND c.created_at=proof.service_created_at) INTO valid;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    RETURN valid;
END $function$;

CREATE OR REPLACE FUNCTION iam.assert_access_key_authorization_complete()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE decision text;
BEGIN
    IF TG_TABLE_NAME='authorization_decisions' THEN decision:=NEW.id; ELSE decision:=NEW.decision_id; END IF;
    IF NOT iam.access_key_authorization_evidence_matches(NEW.tenant_id,decision) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='signed authorization evidence is incomplete'; END IF;
    RETURN NULL;
END $function$;
DROP TRIGGER IF EXISTS access_key_authorization_complete ON iam.authorization_decisions;
CREATE CONSTRAINT TRIGGER access_key_authorization_complete AFTER INSERT ON iam.authorization_decisions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.assert_access_key_authorization_complete();
ALTER TABLE iam.authorization_decisions ENABLE ALWAYS TRIGGER access_key_authorization_complete;
DROP TRIGGER IF EXISTS access_key_authorization_complete ON iam.access_key_authorization_evidence;
CREATE CONSTRAINT TRIGGER access_key_authorization_complete AFTER INSERT ON iam.access_key_authorization_evidence
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.assert_access_key_authorization_complete();
ALTER TABLE iam.access_key_authorization_evidence ENABLE ALWAYS TRIGGER access_key_authorization_complete;

-- Same account -> sorted actor/target USER -> credential/session -> key/intent.
-- NO KEY UPDATE does not deadlock upgrading the already recorded decision FK.
CREATE OR REPLACE FUNCTION iam.assert_access_key_actor(tenant text,actor text,actor_session text,target_user text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF COALESCE(tenant,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(actor,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(actor_session,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(target_user,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='access key subject is invalid'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts WHERE id=tenant AND status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='access key account is unavailable'; END IF;
    PERFORM 1 FROM iam.principals p WHERE p.tenant_id=tenant AND p.id IN (actor,target_user) ORDER BY p.id FOR NO KEY UPDATE;
    IF NOT EXISTS(SELECT 1 FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=actor
      AND p.principal_type='USER' AND p.status='ACTIVE' AND p.deleted_at IS NULL AND NOT p.must_change_password) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='access key actor is unavailable'; END IF;
    PERFORM 1 FROM iam.user_credentials c JOIN iam.sessions s ON s.tenant_id=c.tenant_id AND s.principal_id=c.principal_id
      WHERE c.tenant_id=tenant AND c.principal_id=actor AND s.id=actor_session AND s.status='ACTIVE' AND s.revoked_at IS NULL
        AND s.expires_at>clock_timestamp() AND s.credential_version=c.credential_version FOR SHARE OF c,s;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='access key actor session is unavailable'; END IF;
    -- Default-version publication does not change a USER/GROUP attachment
    -- generation. Stabilize every current identity/boundary policy, including
    -- Deny sources, until this management transaction commits. Policy locks
    -- precede generation locks, matching attachment and boundary writers.
    PERFORM 1 FROM iam.policies p WHERE p.id IN (
      SELECT a.policy_id FROM iam.policy_attachments a WHERE a.tenant_id=tenant AND a.revoked_at IS NULL
        AND ((a.target_kind='USER' AND a.target_id=actor) OR (a.target_kind='GROUP' AND a.target_id IN (
          SELECT m.group_id FROM iam.group_memberships m WHERE m.tenant_id=tenant AND m.user_id=actor AND m.removed_at IS NULL)))
      UNION SELECT b.policy_id FROM iam.user_permission_boundaries b WHERE b.tenant_id=tenant AND b.user_id=actor AND b.revoked_at IS NULL)
      ORDER BY p.id FOR SHARE OF p;
    -- Principal locking alone does not refresh a Serializable snapshot when a
    -- platform attachment was inserted without updating that principal row.
    -- Reuse the existing USER/GROUP authority generation rows as an MVCC
    -- barrier. An already changed row forces a fresh transaction; a later
    -- grant/revoke cannot commit its generation while this check holds SHARE.
    -- Nothing is incremented or copied into the key: these are not AccessKey
    -- revocation epochs and password/session semantics remain unchanged.
    PERFORM 1 FROM iam.role_source_authority_generations g WHERE g.tenant_id=tenant AND (
      g.user_id IN (actor,target_user) OR g.group_id IN (SELECT m.group_id FROM iam.group_memberships m
        WHERE m.tenant_id=tenant AND m.user_id=actor AND m.removed_at IS NULL))
      ORDER BY COALESCE(g.user_id,''),COALESCE(g.group_id,'') FOR SHARE OF g;
    IF NOT EXISTS(SELECT 1 FROM iam.role_source_authority_generations g WHERE g.tenant_id=tenant AND g.user_id=actor)
       OR EXISTS(SELECT 1 FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=target_user AND p.principal_type='USER'
         AND NOT EXISTS(SELECT 1 FROM iam.role_source_authority_generations g WHERE g.tenant_id=tenant AND g.user_id=target_user)) THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='access key subject authority is incomplete'; END IF;
END $function$;
CREATE OR REPLACE FUNCTION iam.assert_access_key_target(tenant text,target_user text,activating boolean)
RETURNS iam.principals LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.principals%ROWTYPE;
BEGIN
    SELECT * INTO stored FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=target_user;
    IF NOT FOUND OR stored.principal_type<>'USER' OR stored.deleted_at IS NOT NULL
       OR EXISTS(SELECT 1 FROM iam.account_roots r WHERE r.account_id=tenant AND r.principal_id=target_user)
       OR EXISTS(SELECT 1 FROM iam.policy_attachments a WHERE a.tenant_id=tenant AND a.target_kind='USER' AND a.target_id=target_user
           AND a.authority_scope='INSTALLATION' AND a.revoked_at IS NULL)
       OR (activating AND (stored.status<>'ACTIVE' OR stored.must_change_password)) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='access key target is unavailable'; END IF;
    RETURN stored;
END $function$;

CREATE OR REPLACE FUNCTION iam.access_key_intent_result(tenant text,actor text,target_user text,key_id text,
    action_name text,request_id text,request_digest text)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.access_key_intents%ROWTYPE;
BEGIN
    IF COALESCE(request_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(request_digest,'') COLLATE "C" !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='access key intent is invalid'; END IF;
    SELECT * INTO stored FROM iam.access_key_intents i WHERE i.tenant_id=tenant AND i.actor_id=actor AND i.request_id=access_key_intent_result.request_id;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF stored.user_id IS DISTINCT FROM target_user OR stored.action_name IS DISTINCT FROM action_name
       OR stored.request_digest IS DISTINCT FROM request_digest OR (action_name<>'iam.access-key.create' AND stored.key_id IS DISTINCT FROM key_id) THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='access key intent conflicts'; END IF;
    RETURN jsonb_build_object('outcome','EQUAL_REPLAY',
      CASE WHEN action_name='iam.access-key.delete' THEN 'deletion' ELSE 'key' END,stored.result);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_access_key_custody()
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; keys jsonb;
BEGIN
    SELECT * INTO receipt FROM iam.bootstrap_receipts WHERE singleton;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='access key installation is unavailable'; END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('wrappingKeyId',r.wrapping_key_id,'materialCommitment',r.material_commitment)
      ORDER BY r.wrapping_key_id),'[]') INTO keys FROM iam.access_key_wrapping_registry r WHERE r.installation_id=receipt.installation_id;
    IF jsonb_array_length(keys)>1 OR EXISTS(SELECT 1 FROM iam.access_key_wrapping_registry r WHERE r.installation_id<>receipt.installation_id) THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='access key custody is incompatible'; END IF;
    RETURN jsonb_build_object('installationId',receipt.installation_id,'bootstrapDigest',receipt.content_digest,'keys',keys);
END $function$;

CREATE OR REPLACE FUNCTION iam.list_access_keys(tenant text,actor text,actor_session text,target_user text,decision text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE target iam.principals%ROWTYPE; items jsonb;
BEGIN
    PERFORM iam.assert_access_key_actor(tenant,actor,actor_session,target_user);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.access-key.list','USER',target_user,'INSTANCE',NULL);
    target:=iam.assert_access_key_target(tenant,target_user,false);
    SELECT COALESCE(jsonb_agg(iam.access_key_snapshot(tenant,k.id) ORDER BY k.id),'[]') INTO items
      FROM (SELECT id FROM iam.access_keys WHERE tenant_id=tenant AND user_id=target_user AND deleted_at IS NULL ORDER BY id LIMIT 3) k;
    IF jsonb_array_length(items)>2 OR EXISTS(SELECT 1 FROM jsonb_array_elements(items) value WHERE value='null'::jsonb) THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='access key directory is incompatible'; END IF;
    RETURN jsonb_build_object('userResourceVersion',target.resource_version,'userStatus',target.status,'mustChangePassword',target.must_change_password,'keys',items);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_access_key(tenant text,actor text,actor_session text,target_user text,key_id text,decision text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE target iam.principals%ROWTYPE; result jsonb;
BEGIN
    PERFORM iam.assert_access_key_actor(tenant,actor,actor_session,target_user);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.access-key.read','ACCESS_KEY',key_id,'INSTANCE',NULL);
    target:=iam.assert_access_key_target(tenant,target_user,false);
    IF NOT EXISTS(SELECT 1 FROM iam.access_keys k WHERE k.tenant_id=tenant AND k.id=key_id AND k.user_id=target_user AND k.deleted_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='access key is unavailable'; END IF;
    result:=iam.access_key_snapshot(tenant,key_id);
    IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='access key is incomplete'; END IF;
    RETURN jsonb_build_object('userResourceVersion',target.resource_version,'userStatus',target.status,'mustChangePassword',target.must_change_password,'keys',jsonb_build_array(result));
END $function$;

CREATE OR REPLACE FUNCTION iam.reserve_access_key(tenant text,actor text,actor_session text,target_user text,decision text,
    key_id text,expected_user_version bigint,installation text,wrapping_id text,commitment text,request_id text,request_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE target iam.principals%ROWTYPE; previous jsonb; inserted integer;
BEGIN
    PERFORM iam.assert_access_key_actor(tenant,actor,actor_session,target_user);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.access-key.create','USER',target_user,'INSTANCE',NULL);
    previous:=iam.access_key_intent_result(tenant,actor,target_user,NULL,'iam.access-key.create',request_id,request_digest);
    IF previous IS NOT NULL THEN RETURN previous; END IF;
    target:=iam.assert_access_key_target(tenant,target_user,true);
    IF expected_user_version IS NULL OR expected_user_version NOT BETWEEN 1 AND 9007199254740991
       OR expected_user_version<>target.resource_version THEN RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='access key user version changed'; END IF;
    IF (SELECT count(*) FROM iam.access_keys k WHERE k.tenant_id=tenant AND k.user_id=target_user AND k.deleted_at IS NULL)>=2 THEN
        RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='access key quota reached'; END IF;
    IF COALESCE(key_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(wrapping_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(commitment,'') COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
       OR NOT EXISTS(SELECT 1 FROM iam.bootstrap_receipts r WHERE r.singleton AND r.installation_id=installation) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='access key material reference is invalid'; END IF;
    INSERT INTO iam.access_key_wrapping_registry(installation_id,wrapping_key_id,material_commitment,created_at)
      VALUES(installation,wrapping_id,commitment,transaction_timestamp()) ON CONFLICT DO NOTHING;
    IF NOT EXISTS(SELECT 1 FROM iam.access_key_wrapping_registry r WHERE r.installation_id=installation
        AND r.wrapping_key_id=wrapping_id AND r.material_commitment=commitment)
       OR (SELECT count(*) FROM iam.access_key_wrapping_registry)<>1 THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='access key custody conflicts'; END IF;
    INSERT INTO iam.access_keys(id,tenant_id,user_id,created_by,creation_request_id,creation_request_digest,installation_id,wrapping_key_id,status,resource_version,created_at,updated_at)
      VALUES(key_id,tenant,target_user,actor,request_id,request_digest,installation,wrapping_id,'ENABLED',1,transaction_timestamp(),transaction_timestamp()) ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS inserted=ROW_COUNT;
    IF inserted=0 THEN RETURN jsonb_build_object('outcome','ID_COLLISION'); END IF;
    RETURN jsonb_build_object('outcome','RESERVED');
END $function$;

CREATE OR REPLACE FUNCTION iam.complete_access_key(tenant text,actor text,actor_session text,target_user text,decision text,
    key_id text,material_format integer,material_nonce bytea,material_ciphertext bytea,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.access_keys%ROWTYPE; result jsonb; previous jsonb;
BEGIN
    PERFORM iam.assert_access_key_actor(tenant,actor,actor_session,target_user);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.access-key.create','USER',target_user,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(event,tenant,'iam.access-key.created','ACCESS_KEY',key_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='access key decision differs'; END IF;
    previous:=iam.access_key_intent_result(tenant,actor,target_user,NULL,'iam.access-key.create',event->>'requestId',event->>'requestDigest');
    IF previous IS NOT NULL THEN RETURN previous; END IF;
    PERFORM iam.assert_access_key_target(tenant,target_user,true);
    SELECT * INTO stored FROM iam.access_keys k WHERE k.tenant_id=tenant AND k.id=key_id AND k.user_id=target_user FOR UPDATE;
    IF NOT FOUND OR stored.resource_version<>1 OR stored.format_version IS NOT NULL OR stored.deleted_at IS NOT NULL
       OR stored.created_at<>transaction_timestamp() OR stored.created_by<>actor
       OR stored.creation_request_id IS DISTINCT FROM event->>'requestId' OR stored.creation_request_digest IS DISTINCT FROM event->>'requestDigest' THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='access key reservation is unavailable'; END IF;
    IF material_format IS DISTINCT FROM 1 OR material_nonce IS NULL OR octet_length(material_nonce)<>12
       OR material_ciphertext IS NULL OR octet_length(material_ciphertext)<>48 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='access key sealed material is invalid'; END IF;
    UPDATE iam.access_keys k SET format_version=material_format,nonce=material_nonce,ciphertext=material_ciphertext WHERE k.tenant_id=tenant AND k.id=key_id;
    result:=iam.access_key_snapshot(tenant,key_id);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
    INSERT INTO iam.access_key_intents(tenant_id,actor_id,request_id,action_name,user_id,key_id,request_digest,result,decision_id,event_id,completed_at)
      VALUES(tenant,actor,event->>'requestId','iam.access-key.create',target_user,key_id,event->>'requestDigest',result,decision,event->>'eventId',transaction_timestamp());
    RETURN jsonb_build_object('outcome','APPLIED','key',result);
END $function$;

CREATE OR REPLACE FUNCTION iam.change_access_key(tenant text,actor text,actor_session text,target_user text,decision text,
    key_id text,expected_version bigint,new_status text,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.access_keys%ROWTYPE; action_name text; event_action text; result jsonb; previous jsonb;
BEGIN
    action_name:=CASE WHEN new_status IS NULL THEN 'iam.access-key.delete' ELSE 'iam.access-key.set-status' END;
    event_action:=CASE WHEN new_status IS NULL THEN 'iam.access-key.deleted' WHEN new_status='ENABLED' THEN 'iam.access-key.enabled' ELSE 'iam.access-key.disabled' END;
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740990 OR (new_status IS NOT NULL AND new_status NOT IN ('ENABLED','DISABLED')) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='access key mutation is invalid'; END IF;
    PERFORM iam.assert_access_key_actor(tenant,actor,actor_session,target_user);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,action_name,'ACCESS_KEY',key_id,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(event,tenant,event_action,'ACCESS_KEY',key_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='access key decision differs'; END IF;
    previous:=iam.access_key_intent_result(tenant,actor,target_user,key_id,action_name,event->>'requestId',event->>'requestDigest');
    IF previous IS NOT NULL THEN RETURN previous; END IF;
    PERFORM iam.assert_access_key_target(tenant,target_user,COALESCE(new_status='ENABLED',false));
    SELECT * INTO stored FROM iam.access_keys k WHERE k.tenant_id=tenant AND k.id=key_id AND k.user_id=target_user FOR UPDATE;
    IF NOT FOUND OR stored.deleted_at IS NOT NULL OR stored.format_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='access key is unavailable'; END IF;
    IF stored.resource_version<>expected_version OR stored.status=new_status OR (new_status IS NULL AND stored.status<>'DISABLED') THEN
        RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='access key version or state changed'; END IF;
    IF new_status IS NULL THEN
        UPDATE iam.access_keys k SET resource_version=k.resource_version+1,updated_at=transaction_timestamp(),deleted_at=transaction_timestamp(),
          format_version=NULL,nonce=NULL,ciphertext=NULL WHERE k.tenant_id=tenant AND k.id=key_id;
        result:=iam.access_key_deletion_snapshot(tenant,key_id);
    ELSE
        UPDATE iam.access_keys k SET resource_version=k.resource_version+1,updated_at=transaction_timestamp(),status=new_status WHERE k.tenant_id=tenant AND k.id=key_id;
        result:=iam.access_key_snapshot(tenant,key_id);
    END IF;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,event->>'eventId',event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
    INSERT INTO iam.access_key_intents(tenant_id,actor_id,request_id,action_name,user_id,key_id,request_digest,result,decision_id,event_id,completed_at)
      VALUES(tenant,actor,event->>'requestId',action_name,target_user,key_id,event->>'requestDigest',result,decision,event->>'eventId',transaction_timestamp());
    RETURN jsonb_build_object('outcome','APPLIED',CASE WHEN new_status IS NULL THEN 'deletion' ELSE 'key' END,result);
END $function$;

-- Only the existing, already-locked USER deletion transaction invokes this
-- bounded cascade. Its real USER decision does not become a generic key permit.
CREATE OR REPLACE FUNCTION iam.delete_user_access_keys(tenant text,actor text,decision text,target_user text,event jsonb)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE key_row iam.access_keys%ROWTYPE; key_event jsonb;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.user.delete','USER',target_user,'INSTANCE',NULL);
    IF (SELECT count(*) FROM iam.access_keys WHERE tenant_id=tenant AND user_id=target_user AND deleted_at IS NULL)>2 THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='access key cascade exceeds its budget'; END IF;
    FOR key_row IN SELECT * FROM iam.access_keys WHERE tenant_id=tenant AND user_id=target_user AND deleted_at IS NULL ORDER BY id FOR UPDATE LOOP
        key_event:=event||jsonb_build_object('eventId','access-key-delete-'||encode(sha256(convert_to(event->>'eventId','UTF8')||decode('00','hex')||convert_to(key_row.id,'UTF8')),'hex'),
          'action','iam.access-key.deleted','target',jsonb_build_object('kind','ACCESS_KEY','id',key_row.id));
        PERFORM iam.assert_audit_event(key_event,tenant,'iam.access-key.deleted','ACCESS_KEY',key_row.id,'SUCCEEDED');
        PERFORM iam.assert_user_audit_actor(tenant,actor,key_event);
        IF key_event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='access key cascade decision differs'; END IF;
        UPDATE iam.access_keys SET resource_version=resource_version+1,updated_at=transaction_timestamp(),deleted_at=transaction_timestamp(),
          format_version=NULL,nonce=NULL,ciphertext=NULL WHERE tenant_id=tenant AND id=key_row.id;
        INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
          VALUES(tenant,key_event->>'eventId',key_event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
    END LOOP;
END $function$;

REVOKE ALL ON iam.access_keys,iam.access_key_intents,iam.access_key_wrapping_registry FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON TABLE iam.access_key_index FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON TABLE iam.access_key_authorization_evidence FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON FUNCTION iam.assert_current_access_key_authorization(text,text,jsonb,jsonb),iam.record_access_key_evidence(text,text,text,jsonb),
    iam.access_key_authorization_evidence_matches(text,text),iam.assert_access_key_authorization_complete()
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON FUNCTION iam.register_access_key_identity(),iam.guard_access_key_change(),iam.assert_access_key_completed(),iam.access_key_result_valid(text,jsonb),
    iam.access_key_snapshot(text,text),iam.access_key_deletion_snapshot(text,text),
    iam.assert_access_key_actor(text,text,text,text),iam.assert_access_key_target(text,text,boolean),
    iam.access_key_intent_result(text,text,text,text,text,text,text),iam.delete_user_access_keys(text,text,text,text,jsonb)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON FUNCTION iam.lookup_access_key(text,text,text,text),iam.read_access_key_custody(),iam.list_access_keys(text,text,text,text,text),
    iam.read_access_key(text,text,text,text,text,text),iam.reserve_access_key(text,text,text,text,text,text,bigint,text,text,text,text,text),
    iam.complete_access_key(text,text,text,text,text,text,integer,bytea,bytea,jsonb),
    iam.change_access_key(text,text,text,text,text,text,bigint,text,jsonb)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.lookup_access_key(text,text,text,text),iam.read_access_key_custody(),iam.list_access_keys(text,text,text,text,text),
    iam.read_access_key(text,text,text,text,text,text),iam.reserve_access_key(text,text,text,text,text,text,bigint,text,text,text,text,text),
    iam.complete_access_key(text,text,text,text,text,text,integer,bytea,bytea,jsonb),
    iam.change_access_key(text,text,text,text,text,text,bigint,text,jsonb) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.access_key_contract_ready()
RETURNS boolean LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE required record; entrypoint record; relation_oid oid;
BEGIN
    FOR required IN SELECT * FROM (VALUES ('access_keys',true),('access_key_intents',true),('access_key_wrapping_registry',false),('access_key_index',false),('access_key_authorization_evidence',true),
      ('service_credentials',true),('service_credential_index',false)) expected(name,tenant_scoped) LOOP
        relation_oid:=to_regclass('iam.'||required.name);
        IF relation_oid IS NULL OR NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=relation_oid
            AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relispartition
            AND c.relowner='matrix_iam_owner'::regrole AND c.relrowsecurity=required.tenant_scoped AND c.relforcerowsecurity=required.tenant_scoped)
           OR EXISTS(SELECT 1 FROM pg_class c,aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) permission
             WHERE c.oid=relation_oid AND permission.grantee<>c.relowner)
           OR EXISTS(SELECT 1 FROM pg_attribute a,aclexplode(a.attacl) permission
             WHERE a.attrelid=relation_oid AND permission.grantee<>'matrix_iam_owner'::regrole) THEN RETURN false; END IF;
        IF (SELECT count(*) FROM pg_policy p WHERE p.polrelid=relation_oid)<>(CASE WHEN required.tenant_scoped THEN 1 ELSE 0 END) THEN RETURN false; END IF;
        IF required.tenant_scoped AND NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=relation_oid
          AND p.polname='tenant_isolation' AND p.polcmd='*' AND p.polpermissive
          AND p.polroles=ARRAY[0::oid] AND pg_get_expr(p.polqual,p.polrelid)='(tenant_id = iam.current_tenant_id())'
          AND pg_get_expr(p.polwithcheck,p.polrelid)='(tenant_id = iam.current_tenant_id())') THEN RETURN false; END IF;
    END LOOP;
    -- Relations must retain their real ownership/history FKs and uniqueness,
    -- not just the same columns or a matching schema number.
    FOR required IN SELECT * FROM (VALUES
      ('service_credential_index',ARRAY['tenant_id','principal_id','lookup_digest'],'service_credentials',ARRAY['tenant_id','principal_id','lookup_digest']),
      ('service_credentials',ARRAY['tenant_id','principal_id'],'principals',ARRAY['tenant_id','id']),
      ('access_key_authorization_evidence',ARRAY['tenant_id','decision_id'],'authorization_decisions',ARRAY['tenant_id','id']),
      ('access_key_authorization_evidence',ARRAY['tenant_id','user_id','access_key_id'],'access_keys',ARRAY['tenant_id','user_id','id']),
      ('access_key_authorization_evidence',ARRAY['installation_id','wrapping_key_id'],'access_key_wrapping_registry',ARRAY['installation_id','wrapping_key_id']),
      ('access_key_authorization_evidence',ARRAY['service_tenant_id','service_principal_id','service_lookup_digest'],'service_credentials',ARRAY['tenant_id','principal_id','lookup_digest']),
      ('access_key_index',ARRAY['tenant_id','user_id','key_id'],'access_keys',ARRAY['tenant_id','user_id','id']),
      ('access_key_wrapping_registry',ARRAY['installation_id'],'bootstrap_receipts',ARRAY['installation_id']),
      ('access_keys',ARRAY['tenant_id','user_id'],'principals',ARRAY['tenant_id','id']),
      ('access_keys',ARRAY['tenant_id','created_by'],'principals',ARRAY['tenant_id','id']),
      ('access_keys',ARRAY['installation_id','wrapping_key_id'],'access_key_wrapping_registry',ARRAY['installation_id','wrapping_key_id']),
      ('access_key_intents',ARRAY['tenant_id','actor_id'],'principals',ARRAY['tenant_id','id']),
      ('access_key_intents',ARRAY['tenant_id','user_id'],'principals',ARRAY['tenant_id','id']),
      ('access_key_intents',ARRAY['tenant_id','user_id','key_id'],'access_keys',ARRAY['tenant_id','user_id','id']),
      ('access_key_intents',ARRAY['tenant_id','decision_id'],'authorization_decisions',ARRAY['tenant_id','id']),
      ('access_key_intents',ARRAY['tenant_id','event_id'],'audit_outbox',ARRAY['tenant_id','event_id'])
    ) expected(table_name,columns,target_table,target_columns) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=to_regclass('iam.'||required.table_name)
          AND c.contype='f' AND c.confrelid=to_regclass('iam.'||required.target_table) AND c.convalidated AND c.conenforced
          AND NOT c.condeferrable AND c.confupdtype='a' AND c.confdeltype='a' AND c.confmatchtype='s'
          AND ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(number,position)
            JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.number ORDER BY k.position)=required.columns
          AND ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(number,position)
            JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.number ORDER BY k.position)=required.target_columns) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('service_credentials',ARRAY['tenant_id','principal_id','lookup_digest']),('service_credential_index',ARRAY['lookup_digest']),
      ('access_key_index',ARRAY['key_id']),
      ('access_key_authorization_evidence',ARRAY['tenant_id','decision_id']),('access_key_authorization_evidence',ARRAY['access_key_id','nonce_digest']),
      ('access_keys',ARRAY['id']),('access_keys',ARRAY['tenant_id','id']),('access_keys',ARRAY['tenant_id','user_id','id']),
      ('access_key_intents',ARRAY['tenant_id','actor_id','request_id']),
      ('access_key_wrapping_registry',ARRAY['installation_id','wrapping_key_id'])
    ) expected(table_name,columns) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_index i WHERE i.indrelid=to_regclass('iam.'||required.table_name)
          AND i.indisunique AND i.indisvalid AND i.indisready AND i.indimmediate AND NOT i.indnullsnotdistinct
          AND i.indexprs IS NULL AND i.indpred IS NULL AND i.indnkeyatts=cardinality(required.columns) AND i.indnatts=i.indnkeyatts
          AND ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(number,position)
            JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.number ORDER BY k.position)=required.columns) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('access_keys','access_keys_material_shape'),('access_keys','access_keys_lifecycle'),
      ('access_key_authorization_evidence','access_key_authorization_values'),
      ('access_keys','access_keys_status_check'),('access_keys','access_keys_resource_version_check'),
      ('access_keys','access_keys_id_check'),('access_keys','access_keys_creation_request_id_check'),('access_keys','access_keys_creation_request_digest_check'),
      ('access_key_intents','access_key_intent_snapshot'),('access_key_intents','access_key_intents_action_name_check'),
      ('access_key_intents','access_key_intents_request_id_check'),('access_key_intents','access_key_intents_request_digest_check'),
      ('access_key_wrapping_registry','access_key_wrapping_registry_wrapping_key_id_check'),
      ('access_key_wrapping_registry','access_key_wrapping_registry_material_commitment_check')
    ) expected(table_name,constraint_name) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=to_regclass('iam.'||required.table_name)
          AND c.conname=required.constraint_name AND c.contype='c' AND c.convalidated AND c.conenforced) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('access_keys','access_keys_live_user_idx',ARRAY['tenant_id','user_id','id'],false,'(deleted_at IS NULL)'),
      ('access_key_intents','access_key_creation_intent_uq',ARRAY['tenant_id','key_id'],true,'(action_name = ''iam.access-key.create''::text)')
    ) expected(table_name,index_name,columns,unique_index,predicate) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_index i WHERE i.indrelid=to_regclass('iam.'||required.table_name)
          AND i.indexrelid=to_regclass('iam.'||required.index_name) AND i.indisunique=required.unique_index
          AND i.indisvalid AND i.indisready AND i.indimmediate AND i.indexprs IS NULL
          AND i.indnkeyatts=cardinality(required.columns) AND i.indnatts=i.indnkeyatts
          AND pg_get_expr(i.indpred,i.indrelid)=required.predicate
          AND ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(number,position)
            JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.number ORDER BY k.position)=required.columns) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('service_credentials','tenant_id','text'::regtype,true),('service_credentials','principal_id','text'::regtype,true),
      ('service_credentials','purpose','text'::regtype,true),('service_credentials','lookup_digest','text'::regtype,true),
      ('service_credentials','verification_digest','text'::regtype,true),('service_credentials','created_at','timestamptz'::regtype,true),
      ('service_credentials','revoked_at','timestamptz'::regtype,false),
      ('service_credential_index','tenant_id','text'::regtype,true),('service_credential_index','principal_id','text'::regtype,true),
      ('service_credential_index','lookup_digest','text'::regtype,true),
      ('access_key_authorization_evidence','tenant_id','text'::regtype,true),('access_key_authorization_evidence','decision_id','text'::regtype,true),
      ('access_key_authorization_evidence','user_id','text'::regtype,true),('access_key_authorization_evidence','access_key_id','text'::regtype,true),
      ('access_key_authorization_evidence','key_resource_version','bigint'::regtype,true),('access_key_authorization_evidence','format_version','integer'::regtype,true),
      ('access_key_authorization_evidence','wrapping_key_id','text'::regtype,true),('access_key_authorization_evidence','material_commitment','text'::regtype,true),
      ('access_key_authorization_evidence','installation_id','text'::regtype,true),('access_key_authorization_evidence','service_tenant_id','text'::regtype,true),
      ('access_key_authorization_evidence','service_principal_id','text'::regtype,true),('access_key_authorization_evidence','service_purpose','text'::regtype,true),
      ('access_key_authorization_evidence','service_lookup_digest','text'::regtype,true),('access_key_authorization_evidence','service_verification_digest','text'::regtype,true),
      ('access_key_authorization_evidence','service_created_at','timestamptz'::regtype,true),('access_key_authorization_evidence','audience','text'::regtype,true),
      ('access_key_authorization_evidence','signed_request_digest','text'::regtype,true),('access_key_authorization_evidence','nonce_digest','text'::regtype,true),
      ('access_key_authorization_evidence','signed_at','bigint'::regtype,true),
      ('access_key_index','key_id','text'::regtype,true),('access_key_index','tenant_id','text'::regtype,true),('access_key_index','user_id','text'::regtype,true),
      ('access_keys','id','text'::regtype,true),('access_keys','tenant_id','text'::regtype,true),
      ('access_keys','user_id','text'::regtype,true),('access_keys','installation_id','text'::regtype,true),
      ('access_keys','created_by','text'::regtype,true),('access_keys','creation_request_id','text'::regtype,true),('access_keys','creation_request_digest','text'::regtype,true),
      ('access_keys','wrapping_key_id','text'::regtype,true),('access_keys','status','text'::regtype,true),
      ('access_keys','resource_version','bigint'::regtype,true),('access_keys','created_at','timestamptz'::regtype,true),
      ('access_keys','updated_at','timestamptz'::regtype,true),('access_keys','deleted_at','timestamptz'::regtype,false),
      ('access_keys','format_version','integer'::regtype,false),('access_keys','nonce','bytea'::regtype,false),('access_keys','ciphertext','bytea'::regtype,false),
      ('access_key_intents','tenant_id','text'::regtype,true),('access_key_intents','actor_id','text'::regtype,true),
      ('access_key_intents','request_id','text'::regtype,true),('access_key_intents','action_name','text'::regtype,true),
      ('access_key_intents','user_id','text'::regtype,true),('access_key_intents','key_id','text'::regtype,true),
      ('access_key_intents','request_digest','text'::regtype,true),('access_key_intents','result','jsonb'::regtype,true),
      ('access_key_intents','decision_id','text'::regtype,true),('access_key_intents','event_id','text'::regtype,true),
      ('access_key_intents','completed_at','timestamptz'::regtype,true),
      ('access_key_wrapping_registry','installation_id','text'::regtype,true),('access_key_wrapping_registry','wrapping_key_id','text'::regtype,true),
      ('access_key_wrapping_registry','material_commitment','text'::regtype,true),('access_key_wrapping_registry','created_at','timestamptz'::regtype,true)
    ) expected(table_name,column_name,column_type,required_value) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=to_regclass('iam.'||required.table_name)
          AND a.attname=required.column_name AND a.atttypid=required.column_type AND a.attnotnull=required.required_value
          AND a.attnum>0 AND NOT a.attisdropped AND a.attgenerated='' AND a.attidentity=''
          AND (required.column_name NOT IN ('id','tenant_id','user_id','actor_id','created_by','creation_request_id','installation_id','wrapping_key_id','request_id','key_id','decision_id','event_id','principal_id','purpose','lookup_digest','verification_digest',
            'access_key_id','service_tenant_id','service_principal_id','service_purpose','service_lookup_digest','service_verification_digest','audience')
            OR a.attcollation='pg_catalog."C"'::regcollation)
          AND (a.atttypid<>'timestamptz'::regtype OR a.atttypmod=6)) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('service_credentials','service_credential_revoked_once','iam.guard_service_credential_change()',false,19),
      ('service_credentials','identity_cannot_delete','iam.reject_policy_history_change()',false,11),
      ('service_credentials','identity_cannot_truncate','iam.reject_policy_history_change()',false,34),
      ('service_credential_index','identity_cannot_update','iam.reject_policy_history_change()',false,19),
      ('service_credential_index','identity_cannot_delete','iam.reject_policy_history_change()',false,11),
      ('service_credential_index','identity_cannot_truncate','iam.reject_policy_history_change()',false,34),
      ('access_key_index','cannot_update','iam.reject_policy_history_change()',false,19),
      ('access_key_index','cannot_delete','iam.reject_policy_history_change()',false,11),
      ('access_key_index','cannot_truncate','iam.reject_policy_history_change()',false,34),
      ('access_key_authorization_evidence','cannot_update','iam.reject_policy_history_change()',false,19),
      ('access_key_authorization_evidence','cannot_delete','iam.reject_policy_history_change()',false,11),
      ('access_key_authorization_evidence','cannot_truncate','iam.reject_policy_history_change()',false,34),
      ('access_key_authorization_evidence','access_key_authorization_complete','iam.assert_access_key_authorization_complete()',true,5),
      ('authorization_decisions','access_key_authorization_complete','iam.assert_access_key_authorization_complete()',true,5),
      ('access_keys','access_key_identity_registered','iam.register_access_key_identity()',false,5),
      ('access_keys','access_key_transition','iam.guard_access_key_change()',false,19),
      ('access_keys','access_key_creation_complete','iam.assert_access_key_completed()',true,21),
      ('access_keys','cannot_delete','iam.reject_policy_history_change()',false,11),
      ('access_keys','cannot_truncate','iam.reject_policy_history_change()',false,34),
      ('access_key_intents','cannot_update','iam.reject_policy_history_change()',false,19),
      ('access_key_intents','cannot_delete','iam.reject_policy_history_change()',false,11),
      ('access_key_intents','cannot_truncate','iam.reject_policy_history_change()',false,34),
      ('access_key_wrapping_registry','cannot_update','iam.reject_policy_history_change()',false,19),
      ('access_key_wrapping_registry','cannot_delete','iam.reject_policy_history_change()',false,11),
      ('access_key_wrapping_registry','cannot_truncate','iam.reject_policy_history_change()',false,34)
    ) expected(table_name,trigger_name,signature,deferred,event_type) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=to_regclass('iam.'||required.table_name)
          AND t.tgname=required.trigger_name AND t.tgfoid=to_regprocedure(required.signature)
          AND NOT t.tgisinternal AND t.tgenabled='A' AND t.tgdeferrable=required.deferred AND t.tginitdeferred=required.deferred
          AND t.tgtype=required.event_type AND t.tgnargs=0 AND t.tgqual IS NULL) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('iam.guard_service_credential_change()','trigger'::regtype,false,ARRAY[]::text[],false),
      ('iam.lookup_access_key(text,text,text,text)','jsonb'::regtype,true,ARRAY['submitted_service_digest','submitted_key_id','submitted_installation','submitted_audience'],true),
      ('iam.register_access_key_identity()','trigger'::regtype,false,ARRAY[]::text[],false),
      ('iam.assert_current_access_key_authorization(text,text,jsonb,jsonb)','void'::regtype,false,ARRAY['tenant','actor','decision','evidence'],false),
      ('iam.record_access_key_evidence(text,text,text,jsonb)','void'::regtype,false,ARRAY['tenant','actor','decision','evidence'],false),
      ('iam.access_key_authorization_evidence_matches(text,text)','boolean'::regtype,false,ARRAY['tenant','decision'],false),
      ('iam.assert_access_key_authorization_complete()','trigger'::regtype,true,ARRAY[]::text[],false),
      ('iam.read_access_key_custody()','jsonb'::regtype,true,ARRAY[]::text[],true),
      ('iam.list_access_keys(text,text,text,text,text)','jsonb'::regtype,true,ARRAY['tenant','actor','actor_session','target_user','decision'],true),
      ('iam.read_access_key(text,text,text,text,text,text)','jsonb'::regtype,true,ARRAY['tenant','actor','actor_session','target_user','key_id','decision'],true),
      ('iam.reserve_access_key(text,text,text,text,text,text,bigint,text,text,text,text,text)','jsonb'::regtype,true,
        ARRAY['tenant','actor','actor_session','target_user','decision','key_id','expected_user_version','installation','wrapping_id','commitment','request_id','request_digest'],true),
      ('iam.complete_access_key(text,text,text,text,text,text,integer,bytea,bytea,jsonb)','jsonb'::regtype,true,
        ARRAY['tenant','actor','actor_session','target_user','decision','key_id','material_format','material_nonce','material_ciphertext','event'],true),
      ('iam.change_access_key(text,text,text,text,text,text,bigint,text,jsonb)','jsonb'::regtype,true,
        ARRAY['tenant','actor','actor_session','target_user','decision','key_id','expected_version','new_status','event'],true),
      ('iam.guard_access_key_change()','trigger'::regtype,false,ARRAY[]::text[],false),
      ('iam.assert_access_key_completed()','trigger'::regtype,true,ARRAY[]::text[],false),
      ('iam.access_key_result_valid(text,jsonb)','boolean'::regtype,false,ARRAY['action_name','value'],false),
      ('iam.access_key_snapshot(text,text)','jsonb'::regtype,false,ARRAY['tenant','key_id'],false),
      ('iam.access_key_deletion_snapshot(text,text)','jsonb'::regtype,false,ARRAY['tenant','key_id'],false),
      ('iam.assert_access_key_actor(text,text,text,text)','void'::regtype,false,ARRAY['tenant','actor','actor_session','target_user'],false),
      ('iam.assert_access_key_target(text,text,boolean)','iam.principals'::regtype,false,ARRAY['tenant','target_user','activating'],false),
      ('iam.access_key_intent_result(text,text,text,text,text,text,text)','jsonb'::regtype,false,
        ARRAY['tenant','actor','target_user','key_id','action_name','request_id','request_digest'],false),
      ('iam.delete_user_access_keys(text,text,text,text,jsonb)','void'::regtype,false,ARRAY['tenant','actor','decision','target_user','event'],false)
    ) expected(signature,result_type,defining,argument_names,api_callable) LOOP
        SELECT p.* INTO entrypoint FROM pg_proc p WHERE p.oid=to_regprocedure(required.signature);
        IF NOT FOUND THEN RETURN false; END IF;
        IF (SELECT count(*) FROM pg_proc p WHERE p.pronamespace=entrypoint.pronamespace AND p.proname=entrypoint.proname)<>1
          OR entrypoint.proowner<>'matrix_iam_owner'::regrole OR entrypoint.prosecdef<>required.defining
          OR entrypoint.prokind<>'f' OR entrypoint.proparallel<>'u'
          OR entrypoint.provolatile::text<>(CASE WHEN required.signature='iam.access_key_result_valid(text,jsonb)' THEN 'i' ELSE 'v' END)
          OR entrypoint.proretset OR entrypoint.prorettype<>required.result_type
          OR entrypoint.pronargdefaults<>0 OR entrypoint.provariadic<>0 OR entrypoint.proisstrict OR entrypoint.proleakproof
          OR entrypoint.proallargtypes IS NOT NULL OR entrypoint.proargmodes IS NOT NULL
          OR COALESCE(entrypoint.proargnames,ARRAY[]::text[]) IS DISTINCT FROM required.argument_names
          OR entrypoint.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']
          OR has_function_privilege('matrix_iam_api',entrypoint.oid,'EXECUTE')<>required.api_callable
          OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(entrypoint.proacl,acldefault('f',entrypoint.proowner))) permission
            WHERE permission.grantee<>entrypoint.proowner
              AND (NOT required.api_callable OR permission.grantee<>'matrix_iam_api'::regrole OR permission.is_grantable)) THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END $function$;
REVOKE ALL ON FUNCTION iam.access_key_contract_ready() FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
