SET LOCAL ROLE matrix_iam_owner;

-- Service-role templates are release authority. Accounts may consent to an
-- exact immutable version, but neither an API caller nor a tenant row can
-- publish or reinterpret the template content.
CREATE TABLE IF NOT EXISTS iam.service_role_templates (
    id text COLLATE "C" NOT NULL,
    version bigint NOT NULL,
    canonical_spec text NOT NULL,
    content_digest text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL,
    created_at timestamptz(6) NOT NULL DEFAULT transaction_timestamp(),
    retired_at timestamptz(6),
    PRIMARY KEY(id,version),
    CONSTRAINT service_role_templates_valid CHECK(
        id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND version BETWEEN 1 AND 9007199254740991
        AND octet_length(canonical_spec) BETWEEN 1 AND 65536
        AND canonical_spec IS JSON OBJECT WITH UNIQUE KEYS
        AND jsonb_typeof(canonical_spec::jsonb)='object'
        AND content_digest='sha256:'||encode(sha256(convert_to('matrix.iam.service-role-template.v1','UTF8')
            ||decode('00','hex')||convert_to(canonical_spec,'UTF8')),'hex')
        AND ((status='ACTIVE' AND retired_at IS NULL)
          OR (status='RETIRED' AND retired_at IS NOT NULL AND retired_at>=created_at)))
);

CREATE OR REPLACE FUNCTION iam.guard_service_role_template_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.created_at<>transaction_timestamp()
          OR (NEW.status='ACTIVE' AND NEW.retired_at IS NOT NULL)
          OR (NEW.status='RETIRED' AND NEW.retired_at IS DISTINCT FROM transaction_timestamp()) THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role template publication is invalid';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP<>'UPDATE' OR OLD.status<>'ACTIVE' OR NEW.status<>'RETIRED'
      OR NEW.retired_at IS DISTINCT FROM transaction_timestamp()
      OR to_jsonb(NEW)-ARRAY['status','retired_at'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['status','retired_at'] THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role template history is immutable';
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS service_role_template_transitions ON iam.service_role_templates;
CREATE TRIGGER service_role_template_transitions BEFORE INSERT OR UPDATE OR DELETE ON iam.service_role_templates
    FOR EACH ROW EXECUTE FUNCTION iam.guard_service_role_template_change();
ALTER TABLE iam.service_role_templates ENABLE ALWAYS TRIGGER service_role_template_transitions;
DROP TRIGGER IF EXISTS service_role_templates_cannot_truncate ON iam.service_role_templates;
CREATE TRIGGER service_role_templates_cannot_truncate BEFORE TRUNCATE ON iam.service_role_templates
    FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.service_role_templates ENABLE ALWAYS TRIGGER service_role_templates_cannot_truncate;

DO $service_role_template_registration$
DECLARE seeds jsonb:=__SERVICE_ROLE_TEMPLATE_SEEDS__; seed jsonb;
BEGIN
    IF jsonb_typeof(seeds)<>'array' OR jsonb_array_length(seeds) NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='service role template catalog is invalid'; END IF;
    LOCK TABLE iam.service_role_templates IN SHARE ROW EXCLUSIVE MODE;
    FOR seed IN SELECT value FROM jsonb_array_elements(seeds) ORDER BY value->>'id',(value->>'version')::bigint LOOP
        IF (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(seed) key)
             IS DISTINCT FROM ARRAY['canonicalSpec','contentDigest','id','status','version']
          OR seed->>'status' NOT IN ('ACTIVE','RETIRED') THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='service role template seed is invalid'; END IF;
        INSERT INTO iam.service_role_templates(id,version,canonical_spec,content_digest,status,retired_at)
        VALUES(seed->>'id',(seed->>'version')::bigint,seed->>'canonicalSpec',seed->>'contentDigest',seed->>'status',
          CASE WHEN seed->>'status'='RETIRED' THEN transaction_timestamp() ELSE NULL END)
        ON CONFLICT(id,version) DO UPDATE SET status='RETIRED',retired_at=transaction_timestamp()
          WHERE iam.service_role_templates.status='ACTIVE' AND EXCLUDED.status='RETIRED';
        IF NOT EXISTS(SELECT 1 FROM iam.service_role_templates template
          WHERE template.id=seed->>'id' AND template.version=(seed->>'version')::bigint
            AND template.canonical_spec=seed->>'canonicalSpec' AND template.content_digest=seed->>'contentDigest'
            AND (template.status=seed->>'status'
              OR (template.status='RETIRED' AND seed->>'status'='ACTIVE'))) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='immutable service role template conflicts'; END IF;
    END LOOP;
    IF EXISTS(SELECT 1 FROM iam.service_role_templates template WHERE template.status='ACTIVE'
      AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(seeds) AS catalog_entry(value)
        WHERE catalog_entry.value->>'id'=template.id AND (catalog_entry.value->>'version')::bigint=template.version
          AND catalog_entry.value->>'contentDigest'=template.content_digest AND catalog_entry.value->>'status'='ACTIVE')) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='active service role template selection conflicts'; END IF;
END $service_role_template_registration$;

-- One relationship represents account consent to one exact template and one
-- physically authenticated service principal. Its home account is retained
-- privately and never treated as target-account authority.
CREATE TABLE IF NOT EXISTS iam.service_linked_roles (
    tenant_id text COLLATE "C" NOT NULL,
    role_id text COLLATE "C" NOT NULL,
    template_id text COLLATE "C" NOT NULL,
    template_version bigint NOT NULL,
    template_digest text COLLATE "C" NOT NULL,
    service_account_id text COLLATE "C" NOT NULL,
    service_installation_id text COLLATE "C" NOT NULL,
    service_principal_id text COLLATE "C" NOT NULL,
    service_purpose text COLLATE "C" NOT NULL,
    policy_id text COLLATE "C" NOT NULL,
    policy_version_id text COLLATE "C" NOT NULL,
    policy_content_digest text COLLATE "C" NOT NULL,
    actor_principal_id text COLLATE "C" NOT NULL,
    actor_session_id text COLLATE "C" NOT NULL,
    role_creation_decision_id text COLLATE "C" NOT NULL,
    role_pass_decision_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    request_digest text COLLATE "C" NOT NULL,
    created_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,role_id),
    CONSTRAINT service_linked_roles_principal_uq UNIQUE(
        tenant_id,template_id,template_version,service_installation_id,service_principal_id),
    CONSTRAINT service_linked_roles_role_fk FOREIGN KEY(tenant_id,role_id)
        REFERENCES iam.roles(tenant_id,id),
    CONSTRAINT service_linked_roles_template_fk FOREIGN KEY(template_id,template_version)
        REFERENCES iam.service_role_templates(id,version),
    CONSTRAINT service_linked_roles_service_credential_fk FOREIGN KEY(service_account_id,service_principal_id)
        REFERENCES iam.service_credentials(tenant_id,principal_id),
    CONSTRAINT service_linked_roles_policy_version_fk FOREIGN KEY(policy_id,policy_version_id)
        REFERENCES iam.policy_versions(policy_id,id),
    CONSTRAINT service_linked_roles_creation_decision_fk FOREIGN KEY(tenant_id,role_creation_decision_id)
        REFERENCES iam.authorization_decisions(tenant_id,id),
    CONSTRAINT service_linked_roles_pass_decision_fk FOREIGN KEY(tenant_id,role_pass_decision_id)
        REFERENCES iam.authorization_decisions(tenant_id,id),
    CONSTRAINT service_linked_roles_valid CHECK(
        role_id ~ '^slr-[0-9a-f]{64}$' AND template_version BETWEEN 1 AND 9007199254740991
        AND template_digest ~ '^sha256:[0-9a-f]{64}$'
        AND service_account_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND service_installation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND service_principal_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND service_purpose IN ('IAM','PAAS','AUDIT','INSTALLATION_VERIFIER')
        AND policy_content_digest ~ '^sha256:[0-9a-f]{64}$'
        AND actor_principal_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND actor_session_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_digest ~ '^sha256:[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS iam.workload_role_bindings (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    role_id text COLLATE "C" NOT NULL,
    template_id text COLLATE "C" NOT NULL,
    template_version bigint NOT NULL,
    template_digest text COLLATE "C" NOT NULL,
    workload_kind text COLLATE "C" NOT NULL,
    workload_id text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    actor_principal_id text COLLATE "C" NOT NULL,
    actor_session_id text COLLATE "C" NOT NULL,
    workload_decision_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    request_digest text COLLATE "C" NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    revoked_at timestamptz(6),
    PRIMARY KEY(tenant_id,id),
    CONSTRAINT workload_role_bindings_request_uq UNIQUE(tenant_id,request_id),
    CONSTRAINT workload_role_bindings_role_fk FOREIGN KEY(tenant_id,role_id)
        REFERENCES iam.service_linked_roles(tenant_id,role_id),
    CONSTRAINT workload_role_bindings_template_fk FOREIGN KEY(template_id,template_version)
        REFERENCES iam.service_role_templates(id,version),
    CONSTRAINT workload_role_bindings_decision_fk FOREIGN KEY(tenant_id,workload_decision_id)
        REFERENCES iam.authorization_decisions(tenant_id,id),
    CONSTRAINT workload_role_bindings_valid CHECK(
        id ~ '^wrb-[0-9a-f]{64}$' AND role_id ~ '^slr-[0-9a-f]{64}$'
        AND template_version BETWEEN 1 AND 9007199254740991
        AND template_digest ~ '^sha256:[0-9a-f]{64}$'
        AND workload_kind ~ '^[A-Z][A-Z0-9_]{0,63}$'
        AND workload_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND actor_principal_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND actor_session_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_digest ~ '^sha256:[0-9a-f]{64}$'
        AND ((status='ACTIVE' AND resource_version=1 AND revoked_at IS NULL AND updated_at=created_at)
          OR (status='REVOKED' AND resource_version=2 AND revoked_at IS NOT NULL
            AND revoked_at=updated_at AND updated_at>=created_at)))
);
CREATE UNIQUE INDEX IF NOT EXISTS workload_role_bindings_active_uq
    ON iam.workload_role_bindings(tenant_id,template_id,template_version,workload_kind,workload_id)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS workload_role_bindings_role_directory_idx
    ON iam.workload_role_bindings(tenant_id,role_id,id);

-- These two owner-only indexes resolve a caller-supplied binding ID and a
-- service-scoped request ID without accepting a target Account selector. They
-- contain no bearer material and never grant access by themselves.
CREATE TABLE IF NOT EXISTS iam.workload_role_binding_index (
    binding_id text COLLATE "C" PRIMARY KEY,
    tenant_id text COLLATE "C" NOT NULL,
    role_id text COLLATE "C" NOT NULL,
    service_account_id text COLLATE "C" NOT NULL,
    service_installation_id text COLLATE "C" NOT NULL,
    service_principal_id text COLLATE "C" NOT NULL,
    service_purpose text COLLATE "C" NOT NULL,
    CONSTRAINT workload_role_binding_index_binding_fk FOREIGN KEY(tenant_id,binding_id)
        REFERENCES iam.workload_role_bindings(tenant_id,id),
    CONSTRAINT workload_role_binding_index_relation_fk FOREIGN KEY(tenant_id,role_id)
        REFERENCES iam.service_linked_roles(tenant_id,role_id),
    CONSTRAINT workload_role_binding_index_service_fk FOREIGN KEY(service_account_id,service_principal_id)
        REFERENCES iam.service_credentials(tenant_id,principal_id),
    CONSTRAINT workload_role_binding_index_valid CHECK(
        binding_id ~ '^wrb-[0-9a-f]{64}$' AND role_id ~ '^slr-[0-9a-f]{64}$'
        AND tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND service_account_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND service_installation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND service_principal_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND service_purpose IN ('IAM','PAAS','AUDIT','INSTALLATION_VERIFIER'))
);

CREATE TABLE IF NOT EXISTS iam.service_role_session_evidence (
    tenant_id text COLLATE "C" NOT NULL,
    session_id text COLLATE "C" NOT NULL,
    binding_id text COLLATE "C" NOT NULL,
    binding_resource_version bigint NOT NULL,
    service_account_id text COLLATE "C" NOT NULL,
    service_installation_id text COLLATE "C" NOT NULL,
    service_principal_id text COLLATE "C" NOT NULL,
    service_purpose text COLLATE "C" NOT NULL,
    service_lookup_digest text COLLATE "C" NOT NULL,
    template_id text COLLATE "C" NOT NULL,
    template_version bigint NOT NULL,
    template_digest text COLLATE "C" NOT NULL,
    policy_id text COLLATE "C" NOT NULL,
    policy_version_id text COLLATE "C" NOT NULL,
    policy_content_digest text COLLATE "C" NOT NULL,
    workload_kind text COLLATE "C" NOT NULL,
    workload_id text COLLATE "C" NOT NULL,
    created_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,session_id),
    CONSTRAINT service_role_session_evidence_session_fk FOREIGN KEY(tenant_id,session_id)
        REFERENCES iam.role_sessions(tenant_id,id),
    CONSTRAINT service_role_session_evidence_binding_fk FOREIGN KEY(tenant_id,binding_id)
        REFERENCES iam.workload_role_bindings(tenant_id,id),
    CONSTRAINT service_role_session_evidence_service_fk FOREIGN KEY(service_account_id,service_principal_id)
        REFERENCES iam.service_credentials(tenant_id,principal_id),
    CONSTRAINT service_role_session_evidence_template_fk FOREIGN KEY(template_id,template_version)
        REFERENCES iam.service_role_templates(id,version),
    CONSTRAINT service_role_session_evidence_policy_fk FOREIGN KEY(policy_id,policy_version_id)
        REFERENCES iam.policy_versions(policy_id,id),
    CONSTRAINT service_role_session_evidence_valid CHECK(
        session_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND binding_id ~ '^wrb-[0-9a-f]{64}$' AND binding_resource_version BETWEEN 1 AND 9007199254740991
        AND service_account_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND service_installation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND service_principal_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND service_purpose IN ('IAM','PAAS','AUDIT','INSTALLATION_VERIFIER')
        AND service_lookup_digest ~ '^sha256:[0-9a-f]{64}$'
        AND template_version BETWEEN 1 AND 9007199254740991
        AND template_digest ~ '^sha256:[0-9a-f]{64}$'
        AND policy_content_digest ~ '^sha256:[0-9a-f]{64}$'
        AND workload_kind ~ '^[A-Z][A-Z0-9_]{0,63}$'
        AND workload_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
);

-- Extend the existing RoleSession management projection only after the
-- normalized service evidence owner exists. The public display is derived
-- from two immutable copies of the issuance lineage and closes on drift;
-- neither current service lookup nor caller input may rewrite history.
CREATE OR REPLACE FUNCTION iam.managed_role_session_snapshot(tenant text,role_id text,session_id text)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_build_object('session',iam.role_session_snapshot(tenant,s.id),
      'source',CASE WHEN s.source_user_id IS NOT NULL THEN jsonb_build_object(
        'type','USER','user',jsonb_build_object('id',p.id,'loginName',p.login_name,'displayName',p.display_name))
      ELSE jsonb_build_object('type','SERVICE_ACCOUNT','servicePrincipal',jsonb_build_object(
        'installationId',e.service_installation_id,
        'principalId',e.service_principal_id,
        'purpose',e.service_purpose)) END)
    FROM iam.role_sessions s LEFT JOIN iam.principals p
      ON p.tenant_id=s.tenant_id AND p.id=s.source_user_id AND p.principal_type='USER'
    LEFT JOIN iam.service_role_session_evidence e ON e.tenant_id=s.tenant_id AND e.session_id=s.id
    WHERE s.tenant_id=tenant AND s.role_id=managed_role_session_snapshot.role_id
      AND s.id=managed_role_session_snapshot.session_id
      AND ((s.source_user_id IS NOT NULL AND s.source_service_principal_id IS NULL AND p.id IS NOT NULL AND e.session_id IS NULL)
        OR (s.source_user_id IS NULL AND s.source_service_principal_id IS NOT NULL
          AND s.authority_contract_version=3
          AND e.service_principal_id=s.source_service_principal_id
          AND e.service_account_id=s.authority_evidence#>>'{serviceSource,accountId}'
          AND e.service_installation_id=s.authority_evidence#>>'{serviceSource,installationId}'
          AND e.service_principal_id=s.authority_evidence#>>'{serviceSource,principalId}'
          AND e.service_purpose=s.authority_evidence#>>'{serviceSource,purpose}'
          AND e.service_lookup_digest=s.authority_evidence#>>'{serviceSource,lookupDigest}'
          AND e.service_installation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
          AND e.service_purpose IN ('IAM','PAAS','AUDIT','INSTALLATION_VERIFIER')))
$function$;

CREATE TABLE IF NOT EXISTS iam.service_role_session_request_index (
    service_account_id text COLLATE "C" NOT NULL,
    service_principal_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    tenant_id text COLLATE "C" NOT NULL,
    session_id text COLLATE "C" NOT NULL,
    binding_id text COLLATE "C" NOT NULL,
    expires_at timestamptz(6) NOT NULL,
    PRIMARY KEY(service_account_id,service_principal_id,request_id),
    CONSTRAINT service_role_session_request_session_uq UNIQUE(tenant_id,session_id),
    CONSTRAINT service_role_session_request_session_fk FOREIGN KEY(tenant_id,session_id)
        REFERENCES iam.role_sessions(tenant_id,id),
    CONSTRAINT service_role_session_request_binding_fk FOREIGN KEY(tenant_id,binding_id)
        REFERENCES iam.workload_role_bindings(tenant_id,id),
    CONSTRAINT service_role_session_request_service_fk FOREIGN KEY(service_account_id,service_principal_id)
        REFERENCES iam.service_credentials(tenant_id,principal_id),
    CONSTRAINT service_role_session_request_valid CHECK(
        service_account_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND service_principal_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND session_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND binding_id ~ '^wrb-[0-9a-f]{64}$')
);
CREATE INDEX IF NOT EXISTS service_role_session_request_live_idx
    ON iam.service_role_session_request_index(service_account_id,service_principal_id,expires_at);

-- Existing current bindings are authoritative data, but the old schema had
-- no selector-free index. Build it from the exact immutable relationship;
-- this is not a legacy marker and grants no platform or tenant authority.
ALTER TABLE iam.service_linked_roles NO FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.workload_role_bindings NO FORCE ROW LEVEL SECURITY;
DO $service_role_binding_index_backfill$
BEGIN
  INSERT INTO iam.workload_role_binding_index(binding_id,tenant_id,role_id,service_account_id,
    service_installation_id,service_principal_id,service_purpose)
  SELECT binding.id,binding.tenant_id,binding.role_id,relation.service_account_id,
    relation.service_installation_id,relation.service_principal_id,relation.service_purpose
  FROM iam.workload_role_bindings binding JOIN iam.service_linked_roles relation
    ON relation.tenant_id=binding.tenant_id AND relation.role_id=binding.role_id
  ON CONFLICT(binding_id) DO NOTHING;
  IF EXISTS(
    SELECT 1 FROM iam.workload_role_bindings binding JOIN iam.service_linked_roles relation
      ON relation.tenant_id=binding.tenant_id AND relation.role_id=binding.role_id
    LEFT JOIN iam.workload_role_binding_index indexed ON indexed.binding_id=binding.id
    WHERE ROW(indexed.tenant_id,indexed.role_id,indexed.service_account_id,indexed.service_installation_id,
        indexed.service_principal_id,indexed.service_purpose)
      IS DISTINCT FROM ROW(binding.tenant_id,binding.role_id,relation.service_account_id,relation.service_installation_id,
        relation.service_principal_id,relation.service_purpose)
  ) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='workload role binding index conflicts';
  END IF;
END $service_role_binding_index_backfill$;
ALTER TABLE iam.service_linked_roles FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.workload_role_bindings FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION iam.guard_service_linked_role_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service-linked role history is immutable';
END $function$;
CREATE OR REPLACE FUNCTION iam.guard_workload_role_binding_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.status<>'ACTIVE' OR NEW.resource_version<>1 OR NEW.revoked_at IS NOT NULL
          OR NEW.created_at<>transaction_timestamp() OR NEW.updated_at<>NEW.created_at THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workload role binding creation is invalid'; END IF;
        RETURN NEW;
    END IF;
    IF TG_OP<>'UPDATE' OR OLD.status<>'ACTIVE' OR OLD.revoked_at IS NOT NULL
      OR NEW.status<>'REVOKED' OR NEW.resource_version<>2
      OR NEW.revoked_at IS DISTINCT FROM transaction_timestamp() OR NEW.updated_at IS DISTINCT FROM NEW.revoked_at
      OR to_jsonb(NEW)-ARRAY['status','resource_version','updated_at','revoked_at']
         IS DISTINCT FROM to_jsonb(OLD)-ARRAY['status','resource_version','updated_at','revoked_at'] THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workload role binding history is immutable'; END IF;
    RETURN NEW;
END $function$;
DO $service_role_relation_protection$
DECLARE relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['service_linked_roles','workload_role_bindings','service_role_session_evidence'] LOOP
        EXECUTE format('ALTER TABLE iam.%I ENABLE ROW LEVEL SECURITY',relation_name);
        EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',relation_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON iam.%I',relation_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON iam.%I USING(tenant_id=iam.current_tenant_id()) WITH CHECK(tenant_id=iam.current_tenant_id())',relation_name);
        EXECUTE format('DROP TRIGGER IF EXISTS cannot_truncate ON iam.%I',relation_name);
        EXECUTE format('CREATE TRIGGER cannot_truncate BEFORE TRUNCATE ON iam.%I FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change()',relation_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER cannot_truncate',relation_name);
    END LOOP;
END $service_role_relation_protection$;
DROP TRIGGER IF EXISTS service_linked_roles_are_immutable ON iam.service_linked_roles;
CREATE TRIGGER service_linked_roles_are_immutable BEFORE UPDATE OR DELETE ON iam.service_linked_roles
    FOR EACH ROW EXECUTE FUNCTION iam.guard_service_linked_role_change();
ALTER TABLE iam.service_linked_roles ENABLE ALWAYS TRIGGER service_linked_roles_are_immutable;
DROP TRIGGER IF EXISTS workload_role_binding_transitions ON iam.workload_role_bindings;
CREATE TRIGGER workload_role_binding_transitions BEFORE INSERT OR UPDATE OR DELETE ON iam.workload_role_bindings
    FOR EACH ROW EXECUTE FUNCTION iam.guard_workload_role_binding_change();
ALTER TABLE iam.workload_role_bindings ENABLE ALWAYS TRIGGER workload_role_binding_transitions;
DO $service_role_session_history_protection$
DECLARE relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['workload_role_binding_index','service_role_session_evidence','service_role_session_request_index'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS immutable_history ON iam.%I',relation_name);
        EXECUTE format('CREATE TRIGGER immutable_history BEFORE UPDATE OR DELETE ON iam.%I FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change()',relation_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER immutable_history',relation_name);
        EXECUTE format('DROP TRIGGER IF EXISTS cannot_truncate ON iam.%I',relation_name);
        EXECUTE format('CREATE TRIGGER cannot_truncate BEFORE TRUNCATE ON iam.%I FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change()',relation_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER cannot_truncate',relation_name);
    END LOOP;
END $service_role_session_history_protection$;

-- Ordinary policy APIs must never attach, revoke or mutate authority on a
-- SERVICE_LINKED Role. Its immutable PolicyVersion ceiling is owned solely by
-- the release template and the service relationship below.
CREATE OR REPLACE FUNCTION iam.guard_customer_role_policy_attachment()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF NEW.target_kind='ROLE' THEN
        PERFORM set_config('matrix.iam_tenant_id',NEW.tenant_id,true);
        IF EXISTS(SELECT 1 FROM iam.roles role_value WHERE role_value.tenant_id=NEW.tenant_id
          AND role_value.id=NEW.target_id AND role_value.management='SERVICE_LINKED') THEN
            RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service-linked role authority is immutable'; END IF;
    END IF;
    RETURN NEW;
END $function$;
DROP TRIGGER IF EXISTS policy_attachments_reject_service_roles ON iam.policy_attachments;
CREATE TRIGGER policy_attachments_reject_service_roles BEFORE INSERT OR UPDATE ON iam.policy_attachments
    FOR EACH ROW EXECUTE FUNCTION iam.guard_customer_role_policy_attachment();
ALTER TABLE iam.policy_attachments ENABLE ALWAYS TRIGGER policy_attachments_reject_service_roles;

CREATE OR REPLACE FUNCTION iam.service_linked_role_snapshot(tenant text,role_id text)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','ServiceLinkedRole',
      'role',iam.role_snapshot(relation.tenant_id,relation.role_id),
      'template',jsonb_build_object('id',relation.template_id,'version',relation.template_version,'contentDigest',relation.template_digest),
      'servicePrincipal',jsonb_build_object('installationId',relation.service_installation_id,
        'principalId',relation.service_principal_id,'purpose',relation.service_purpose),
      'permissionCeiling',jsonb_build_object('policyId',relation.policy_id,'versionId',relation.policy_version_id,
        'contentDigest',relation.policy_content_digest))
    FROM iam.service_linked_roles relation WHERE relation.tenant_id=tenant AND relation.role_id=service_linked_role_snapshot.role_id
$function$;
CREATE OR REPLACE FUNCTION iam.workload_role_binding_snapshot(tenant text,binding_id text)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','WorkloadRoleBinding',
      'id',binding.id,'accountId',binding.tenant_id,'roleId',binding.role_id,
      'template',jsonb_build_object('id',binding.template_id,'version',binding.template_version,'contentDigest',binding.template_digest),
      'workload',jsonb_build_object('kind',binding.workload_kind,'id',binding.workload_id),
      'status',binding.status,'resourceVersion',binding.resource_version,'createdAt',binding.created_at,
      'updatedAt',binding.updated_at,'revokedAt',binding.revoked_at))
    FROM iam.workload_role_bindings binding WHERE binding.tenant_id=tenant AND binding.id=binding_id
$function$;

-- Lock both authenticated sources before any authorization decision is
-- recorded. Recording a decision takes FK locks on the USER; attempting to
-- upgrade those locks later lets two concurrent commands deadlock. The order
-- here is identical to the final write entrypoint: service credential first,
-- then target Account USER and Session.
CREATE OR REPLACE FUNCTION iam.lock_workload_role_binding_sources(
    tenant text,actor text,actor_session text,service_lookup_digest text,service_purpose text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE service_index iam.service_credential_index%ROWTYPE;
BEGIN
    IF COALESCE(tenant,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor_session,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(service_lookup_digest,'') !~ '^sha256:[0-9a-f]{64}$'
      OR service_purpose NOT IN ('IAM','PAAS','AUDIT','INSTALLATION_VERIFIER') THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='service role source lock is invalid'; END IF;
    SELECT * INTO service_index FROM iam.service_credential_index indexed
      WHERE indexed.lookup_digest=service_lookup_digest;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role producer is unavailable'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',service_index.tenant_id,true);
    PERFORM 1 FROM iam.service_credentials credential
      JOIN iam.accounts account ON account.id=credential.tenant_id AND account.status='ACTIVE'
      JOIN iam.principals principal ON principal.tenant_id=credential.tenant_id AND principal.id=credential.principal_id
        AND principal.principal_type='SERVICE_ACCOUNT' AND principal.status='ACTIVE' AND principal.deleted_at IS NULL
      WHERE credential.tenant_id=service_index.tenant_id AND credential.principal_id=service_index.principal_id
        AND credential.lookup_digest=service_lookup_digest AND credential.purpose=service_purpose
        AND credential.revoked_at IS NULL FOR SHARE OF credential,account,principal;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role producer is unavailable'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM iam.assert_role_session_source(tenant,actor,actor_session,false);
    IF NOT iam.session_mfa_eligible(tenant,actor,actor_session) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role administrator session is unavailable'; END IF;
    RETURN true;
END $function$;

-- This is the only write entrypoint for the first service-role consent slice.
-- Every selector is either authenticated, release-owned or derived again here.
CREATE OR REPLACE FUNCTION iam.create_workload_role_binding(
    tenant text,actor text,actor_session text,service_lookup_digest text,
    request_document text,request_digest text,template jsonb,role_value jsonb,trust jsonb,binding jsonb,
    workload_decision text,role_creation_decision text,role_pass_decision text,
    role_event jsonb,binding_event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE request_value jsonb; stored_template iam.service_role_templates%ROWTYPE;
    service_index iam.service_credential_index%ROWTYPE; service_credential iam.service_credentials%ROWTYPE;
    service_account text; service_installation text; bind_action text; workload_kind text; workload_id text;
    expected_role_id text; expected_trust_id text; expected_binding_id text; role_identity text; trust_identity text; binding_identity text;
    metadata jsonb; policy_reference jsonb; existing_relation iam.service_linked_roles%ROWTYPE;
    existing_binding iam.workload_role_bindings%ROWTYPE; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF COALESCE(tenant,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor_session,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(service_lookup_digest,'') !~ '^sha256:[0-9a-f]{64}$'
      OR COALESCE(request_digest,'') !~ '^sha256:[0-9a-f]{64}$'
      OR request_document IS NULL OR octet_length(request_document)>262144
      OR NOT (request_document IS JSON OBJECT WITH UNIQUE KEYS)
      OR request_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to('matrix.iam.request.v1','UTF8')||decode('00','hex')
        ||convert_to('workload-role-binding-create','UTF8')||decode('00','hex')||convert_to(request_document,'UTF8')),'hex') THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='workload role binding command is invalid'; END IF;
    request_value:=request_document::jsonb;
    IF (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(request_value) key)
         IS DISTINCT FROM ARRAY['authorization','template']
      OR jsonb_typeof(request_value->'authorization')<>'object'
      OR jsonb_typeof(request_value->'template')<>'object'
      OR request_value#>>'{authorization,resourceMode}'<>'INSTANCE'
      OR request_value#>'{authorization,collectionUsage}' IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='workload role binding request is invalid'; END IF;

    SELECT * INTO stored_template FROM iam.service_role_templates published
      WHERE published.id=request_value#>>'{template,id}'
        AND published.version=(request_value#>>'{template,version}')::bigint
        AND published.content_digest=request_value#>>'{template,contentDigest}' FOR SHARE;
    IF NOT FOUND OR stored_template.status<>'ACTIVE' OR template IS DISTINCT FROM jsonb_build_object(
        'apiVersion','iam.matrix.xiak.com/v1','kind','ServiceRoleTemplate','id',stored_template.id,
        'version',stored_template.version,'spec',stored_template.canonical_spec::jsonb,
        'contentDigest',stored_template.content_digest,'status',stored_template.status) THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='service role template is unavailable'; END IF;
    workload_kind:=request_value#>>'{authorization,resource,kind}';
    workload_id:=request_value#>>'{authorization,resource,id}';
    SELECT workload->>'bindAction' INTO bind_action FROM jsonb_array_elements(stored_template.canonical_spec::jsonb->'workloads') workload
      WHERE workload->>'resourceKind'=workload_kind;
    IF NOT FOUND OR bind_action IS DISTINCT FROM request_value#>>'{authorization,action}'
      OR request_value#>>'{authorization,profile,product}' IS DISTINCT FROM stored_template.canonical_spec::jsonb->>'product' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='service role workload admission is invalid'; END IF;

    SELECT * INTO service_index FROM iam.service_credential_index indexed
      WHERE indexed.lookup_digest=service_lookup_digest;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role producer is unavailable'; END IF;
    service_account:=service_index.tenant_id;
    PERFORM set_config('matrix.iam_tenant_id',service_account,true);
    SELECT credential.* INTO service_credential FROM iam.service_credentials credential
      JOIN iam.accounts account ON account.id=credential.tenant_id AND account.status='ACTIVE'
      JOIN iam.principals principal ON principal.tenant_id=credential.tenant_id AND principal.id=credential.principal_id
        AND principal.principal_type='SERVICE_ACCOUNT' AND principal.status='ACTIVE' AND principal.deleted_at IS NULL
      WHERE credential.tenant_id=service_index.tenant_id AND credential.principal_id=service_index.principal_id
        AND credential.lookup_digest=service_lookup_digest AND credential.revoked_at IS NULL FOR SHARE OF credential,account,principal;
    IF NOT FOUND OR service_credential.purpose IS DISTINCT FROM stored_template.canonical_spec::jsonb->>'servicePurpose' THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role producer is unavailable'; END IF;
    SELECT receipt.installation_id INTO service_installation FROM iam.bootstrap_receipts receipt
      WHERE receipt.singleton AND receipt.organization_id=service_account FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role installation is unavailable'; END IF;

    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM iam.assert_role_session_source(tenant,actor,actor_session,false);
    IF NOT iam.session_mfa_eligible(tenant,actor,actor_session) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role administrator session is unavailable'; END IF;

    role_identity:='{"accountId":"'||tenant||'","template":{"id":"'||stored_template.id||'","version":'||stored_template.version
      ||',"contentDigest":"'||stored_template.content_digest||'"},"servicePrincipal":{"installationId":"'||service_installation
      ||'","principalId":"'||service_credential.principal_id||'","purpose":"'||service_credential.purpose||'"}}';
    expected_role_id:='slr-'||encode(sha256(convert_to('matrix.iam.request.v1','UTF8')||decode('00','hex')
      ||convert_to('service-linked-role-identity','UTF8')||decode('00','hex')||convert_to(role_identity,'UTF8')),'hex');
    trust_identity:='{"roleId":"'||expected_role_id||'","template":{"id":"'||stored_template.id||'","version":'
      ||stored_template.version||',"contentDigest":"'||stored_template.content_digest||'"}}';
    expected_trust_id:='trust-'||encode(sha256(convert_to('matrix.iam.request.v1','UTF8')||decode('00','hex')
      ||convert_to('service-linked-role-trust-identity','UTF8')||decode('00','hex')||convert_to(trust_identity,'UTF8')),'hex');
    binding_identity:='{"accountId":"'||tenant||'","template":{"id":"'||stored_template.id
      ||'","version":'||stored_template.version||',"contentDigest":"'||stored_template.content_digest
      ||'"},"workload":{"kind":"'||workload_kind||'","id":"'||workload_id||'"},"requestId":"'
      ||(request_value#>>'{authorization,requestId}')||'"}';
    expected_binding_id:='wrb-'||encode(sha256(convert_to('matrix.iam.request.v1','UTF8')||decode('00','hex')
      ||convert_to('workload-role-binding-identity','UTF8')||decode('00','hex')||convert_to(binding_identity,'UTF8')),'hex');

    metadata:=jsonb_build_object('name',stored_template.canonical_spec::jsonb->>'roleName',
      'description',stored_template.canonical_spec::jsonb->>'roleDescription','tags','[]'::jsonb,
      'maxSessionDurationSeconds',stored_template.canonical_spec::jsonb->'maxSessionDurationSeconds');
    policy_reference:=stored_template.canonical_spec::jsonb->'policyVersion';
    IF role_value->>'id' IS DISTINCT FROM expected_role_id OR role_value->>'accountId' IS DISTINCT FROM tenant
      OR role_value->>'management'<>'SERVICE_LINKED' OR role_value->>'status'<>'ACTIVE'
      OR (role_value->>'resourceVersion')::bigint<>1 OR role_value->>'currentTrustVersionId' IS DISTINCT FROM expected_trust_id
      OR role_value->'name' IS DISTINCT FROM to_jsonb(metadata->>'name')
      OR role_value->'description' IS DISTINCT FROM to_jsonb(metadata->>'description')
      OR role_value->'tags' IS DISTINCT FROM '[]'::jsonb
      OR role_value->'maxSessionDurationSeconds' IS DISTINCT FROM metadata->'maxSessionDurationSeconds'
      OR (role_value->>'createdAt')::timestamptz IS DISTINCT FROM effective_now
      OR (role_value->>'updatedAt')::timestamptz IS DISTINCT FROM effective_now
      OR NOT iam.role_metadata_valid(metadata)
      OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(trust) key) IS DISTINCT FROM ARRAY['canonicalDocument','contentDigest']
      OR trust->>'canonicalDocument' IS DISTINCT FROM '{"languageVersion":"1","statements":[]}'
      OR NOT iam.role_trust_content_valid(trust->>'canonicalDocument',trust->>'contentDigest')
      OR binding->>'id' IS DISTINCT FROM expected_binding_id OR binding->>'accountId' IS DISTINCT FROM tenant
      OR binding->>'roleId' IS DISTINCT FROM expected_role_id OR binding->'template' IS DISTINCT FROM request_value->'template'
      OR binding->'workload' IS DISTINCT FROM request_value#>'{authorization,resource}'
      OR binding->>'status'<>'ACTIVE' OR (binding->>'resourceVersion')::bigint<>1
      OR (binding->>'createdAt')::timestamptz IS DISTINCT FROM effective_now
      OR (binding->>'updatedAt')::timestamptz IS DISTINCT FROM effective_now OR binding ? 'revokedAt' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='service role derived identity is invalid'; END IF;
    IF NOT EXISTS(SELECT 1 FROM iam.policies policy JOIN iam.policy_versions version
      ON version.policy_id=policy.id AND version.id=policy_reference->>'versionId'
      WHERE policy.id=policy_reference->>'policyId' AND policy.management='SYSTEM' AND policy.status='ACTIVE'
        AND policy.authority_scope='TENANT' AND version.retired_at IS NULL
        AND version.content_digest=policy_reference->>'contentDigest') THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role permission ceiling is unavailable'; END IF;

    PERFORM iam.assert_allowed_decision(tenant,actor,workload_decision,bind_action,workload_kind,workload_id,'INSTANCE',NULL);
    PERFORM iam.assert_allowed_decision(tenant,actor,role_creation_decision,'iam.service-linked-role.create','ACCOUNT',tenant,'INSTANCE',NULL);
    PERFORM iam.assert_allowed_decision(tenant,actor,role_pass_decision,'iam.role.pass','ROLE',expected_role_id,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(role_event,tenant,'iam.service-linked-role.created','ROLE',expected_role_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,role_event);
    PERFORM iam.assert_audit_event(binding_event,tenant,'iam.workload-role-binding.created','WORKLOAD_ROLE_BINDING',expected_binding_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,binding_event);
    IF role_event->>'iamDecisionId' IS DISTINCT FROM role_creation_decision
      OR binding_event->>'iamDecisionId' IS DISTINCT FROM workload_decision
      OR role_event->>'requestId' IS DISTINCT FROM request_value#>>'{authorization,requestId}'
      OR binding_event->>'requestId' IS DISTINCT FROM role_event->>'requestId'
      OR role_event->>'requestDigest' IS DISTINCT FROM request_digest
      OR binding_event->>'requestDigest' IS DISTINCT FROM request_digest THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='service role audit correlation is invalid'; END IF;

    SELECT * INTO existing_relation FROM iam.service_linked_roles relation
      WHERE relation.tenant_id=tenant AND relation.role_id=expected_role_id FOR UPDATE;
    IF FOUND THEN
        IF ROW(existing_relation.template_id,existing_relation.template_version,existing_relation.template_digest,
             existing_relation.service_account_id,existing_relation.service_installation_id,existing_relation.service_principal_id,
             existing_relation.service_purpose,existing_relation.policy_id,existing_relation.policy_version_id,existing_relation.policy_content_digest)
           IS DISTINCT FROM ROW(stored_template.id,stored_template.version,stored_template.content_digest,
             service_account,service_installation,service_credential.principal_id,service_credential.purpose,
             policy_reference->>'policyId',policy_reference->>'versionId',policy_reference->>'contentDigest') THEN
            RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='service-linked role identity conflicts'; END IF;
    ELSE
        IF EXISTS(SELECT 1 FROM iam.roles existing WHERE existing.tenant_id=tenant AND existing.id=expected_role_id) THEN
            RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='service-linked role identity conflicts'; END IF;
        INSERT INTO iam.roles(tenant_id,id,metadata,management,status,resource_version,current_trust_version_id,created_at,updated_at)
          VALUES(tenant,expected_role_id,metadata,'SERVICE_LINKED','ACTIVE',1,expected_trust_id,effective_now,effective_now);
        INSERT INTO iam.role_trust_versions(tenant_id,role_id,id,canonical_document,content_digest,created_at)
          VALUES(tenant,expected_role_id,expected_trust_id,trust->>'canonicalDocument',trust->>'contentDigest',effective_now);
        INSERT INTO iam.service_linked_roles(tenant_id,role_id,template_id,template_version,template_digest,
          service_account_id,service_installation_id,service_principal_id,service_purpose,
          policy_id,policy_version_id,policy_content_digest,actor_principal_id,actor_session_id,
          role_creation_decision_id,role_pass_decision_id,request_id,request_digest,created_at)
        VALUES(tenant,expected_role_id,stored_template.id,stored_template.version,stored_template.content_digest,
          service_account,service_installation,service_credential.principal_id,service_credential.purpose,
          policy_reference->>'policyId',policy_reference->>'versionId',policy_reference->>'contentDigest',actor,actor_session,
          role_creation_decision,role_pass_decision,role_event->>'requestId',request_digest,effective_now);
        INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
          VALUES(tenant,role_event->>'eventId',role_event,effective_now,effective_now,effective_now);
    END IF;

    -- A request ID is one command identity inside one Account. It is not
    -- namespaced by the USER actor: a second administrator must not reuse the
    -- same command for another workload or obtain the first actor's result.
    SELECT * INTO existing_binding FROM iam.workload_role_bindings stored
      WHERE stored.tenant_id=tenant AND stored.request_id=binding_event->>'requestId' FOR UPDATE;
    IF FOUND THEN
        IF ROW(existing_binding.id,existing_binding.role_id,existing_binding.template_id,existing_binding.template_version,existing_binding.template_digest,
             existing_binding.workload_kind,existing_binding.workload_id,existing_binding.status,existing_binding.resource_version,
             existing_binding.actor_principal_id,existing_binding.request_id,existing_binding.request_digest)
           IS DISTINCT FROM ROW(expected_binding_id,expected_role_id,stored_template.id,stored_template.version,stored_template.content_digest,
             workload_kind,workload_id,'ACTIVE'::text,1::bigint,actor,binding_event->>'requestId',request_digest)
          OR NOT EXISTS(SELECT 1 FROM iam.audit_outbox fact WHERE fact.tenant_id=tenant
            AND fact.event_document->>'action'='iam.workload-role-binding.created'
            AND fact.event_document#>>'{target,id}'=expected_binding_id
            AND fact.event_document->>'requestId'=binding_event->>'requestId'
            AND fact.event_document->>'requestDigest'=request_digest) THEN
            RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='workload role binding intent conflicts'; END IF;
    ELSE
        INSERT INTO iam.workload_role_bindings(tenant_id,id,role_id,template_id,template_version,template_digest,
          workload_kind,workload_id,status,resource_version,actor_principal_id,actor_session_id,workload_decision_id,
          request_id,request_digest,created_at,updated_at)
        VALUES(tenant,expected_binding_id,expected_role_id,stored_template.id,stored_template.version,stored_template.content_digest,
          workload_kind,workload_id,'ACTIVE',1,actor,actor_session,workload_decision,
          binding_event->>'requestId',request_digest,effective_now,effective_now);
        INSERT INTO iam.workload_role_binding_index(binding_id,tenant_id,role_id,service_account_id,
          service_installation_id,service_principal_id,service_purpose)
        VALUES(expected_binding_id,tenant,expected_role_id,service_account,service_installation,
          service_credential.principal_id,service_credential.purpose);
        INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
          VALUES(tenant,binding_event->>'eventId',binding_event,effective_now,effective_now,effective_now);
    END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','ServiceLinkedRoleAccess',
      'relation',iam.service_linked_role_snapshot(tenant,expected_role_id),
      'bindings',jsonb_build_array(iam.workload_role_binding_snapshot(tenant,expected_binding_id)));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_datetime_format OR datetime_field_overflow THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='workload role binding command is invalid';
END $function$;

-- Resolve and lock one existing binding only after both current credentials
-- have been locked by lock_workload_role_binding_sources. The binding remains
-- the authority for Account, Role, template, workload and service principal;
-- its path ID is never a selector for any of those identities.
CREATE OR REPLACE FUNCTION iam.prepare_workload_role_binding_revocation(
    tenant text,binding_id text,service_lookup_digest text,service_purpose text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE service_index iam.service_credential_index%ROWTYPE;
    service_credential iam.service_credentials%ROWTYPE; service_installation text; target_role text;
    relation iam.service_linked_roles%ROWTYPE; binding iam.workload_role_bindings%ROWTYPE;
BEGIN
    IF COALESCE(tenant,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(binding_id,'') !~ '^wrb-[0-9a-f]{64}$'
      OR COALESCE(service_lookup_digest,'') !~ '^sha256:[0-9a-f]{64}$'
      OR service_purpose NOT IN ('IAM','PAAS','AUDIT','INSTALLATION_VERIFIER') THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='workload role binding revocation target is invalid'; END IF;

    SELECT * INTO service_index FROM iam.service_credential_index indexed
      WHERE indexed.lookup_digest=service_lookup_digest;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role producer is unavailable'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',service_index.tenant_id,true);
    SELECT credential.* INTO service_credential FROM iam.service_credentials credential
      JOIN iam.accounts account ON account.id=credential.tenant_id AND account.status='ACTIVE'
      JOIN iam.principals principal ON principal.tenant_id=credential.tenant_id AND principal.id=credential.principal_id
        AND principal.principal_type='SERVICE_ACCOUNT' AND principal.status='ACTIVE' AND principal.deleted_at IS NULL
      WHERE credential.tenant_id=service_index.tenant_id AND credential.principal_id=service_index.principal_id
        AND credential.lookup_digest=service_lookup_digest AND credential.purpose=service_purpose
        AND credential.revoked_at IS NULL FOR SHARE OF credential,account,principal;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role producer is unavailable'; END IF;
    SELECT receipt.installation_id INTO service_installation FROM iam.bootstrap_receipts receipt
      WHERE receipt.singleton AND receipt.organization_id=service_index.tenant_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role installation is unavailable'; END IF;

    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    SELECT candidate.role_id INTO target_role FROM iam.workload_role_bindings candidate
      WHERE candidate.tenant_id=tenant AND candidate.id=binding_id;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workload role binding is unavailable'; END IF;
    PERFORM 1 FROM iam.roles role_value WHERE role_value.tenant_id=tenant AND role_value.id=target_role
      AND role_value.management='SERVICE_LINKED' AND role_value.deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service-linked role is unavailable'; END IF;
    SELECT * INTO relation FROM iam.service_linked_roles stored
      WHERE stored.tenant_id=tenant AND stored.role_id=target_role FOR SHARE;
    SELECT * INTO binding FROM iam.workload_role_bindings stored
      WHERE stored.tenant_id=tenant AND stored.id=binding_id AND stored.role_id=target_role FOR UPDATE;
    IF NOT FOUND OR relation.role_id IS NULL
      OR ROW(relation.service_account_id,relation.service_installation_id,relation.service_principal_id,relation.service_purpose)
         IS DISTINCT FROM ROW(service_index.tenant_id,service_installation,service_credential.principal_id,service_purpose)
      OR ROW(binding.template_id,binding.template_version,binding.template_digest)
         IS DISTINCT FROM ROW(relation.template_id,relation.template_version,relation.template_digest) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workload role binding is unavailable'; END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','ServiceLinkedRoleAccess',
      'relation',iam.service_linked_role_snapshot(tenant,target_role),
      'bindings',jsonb_build_array(iam.workload_role_binding_snapshot(tenant,binding_id)));
END $function$;

-- This is the only terminal binding transition. Current authorization is
-- required even for an equal replay; the retained original outbox fact and
-- decision trio prove that a previous success was the same immutable intent.
CREATE OR REPLACE FUNCTION iam.revoke_workload_role_binding(
    tenant text,actor text,actor_session text,service_lookup_digest text,service_purpose text,
    binding_id text,request_document text,request_digest text,workload_decision text,
    binding_revoke_decision text,role_pass_decision text,binding_event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE request_value jsonb; service_index iam.service_credential_index%ROWTYPE;
    service_credential iam.service_credentials%ROWTYPE; service_installation text;
    stored iam.workload_role_bindings%ROWTYPE; relation iam.service_linked_roles%ROWTYPE;
    template iam.service_role_templates%ROWTYPE; role_value iam.roles%ROWTYPE;
    target_role text; unbind_action text; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF COALESCE(tenant,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor_session,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(service_lookup_digest,'') !~ '^sha256:[0-9a-f]{64}$'
      OR service_purpose NOT IN ('IAM','PAAS','AUDIT','INSTALLATION_VERIFIER')
      OR COALESCE(binding_id,'') !~ '^wrb-[0-9a-f]{64}$'
      OR COALESCE(request_digest,'') !~ '^sha256:[0-9a-f]{64}$'
      OR COALESCE(workload_decision,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(binding_revoke_decision,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(role_pass_decision,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR request_document IS NULL OR octet_length(request_document)>262144
      OR NOT (request_document IS JSON OBJECT WITH UNIQUE KEYS)
      OR request_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to('matrix.iam.request.v1','UTF8')||decode('00','hex')
        ||convert_to('workload-role-binding-revoke:'||binding_id,'UTF8')||decode('00','hex')||convert_to(request_document,'UTF8')),'hex') THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='workload role binding revocation command is invalid'; END IF;
    request_value:=request_document::jsonb;
    IF (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(request_value) key)
         IS DISTINCT FROM ARRAY['authorization','resourceVersion']
      OR jsonb_typeof(request_value->'authorization')<>'object'
      OR jsonb_typeof(request_value->'resourceVersion')<>'number'
      OR (request_value->>'resourceVersion')::bigint<>1
      OR request_value#>>'{authorization,resourceMode}'<>'INSTANCE'
      OR request_value#>'{authorization,collectionUsage}' IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='workload role binding revocation request is invalid'; END IF;

    -- Re-acquire the complete source lock inside the write authority. Calls
    -- from the use case already hold it, while direct adapter misuse cannot
    -- bypass current service, USER, Session or MFA validity.
    PERFORM iam.lock_workload_role_binding_sources(tenant,actor,actor_session,service_lookup_digest,service_purpose);
    SELECT * INTO service_index FROM iam.service_credential_index indexed
      WHERE indexed.lookup_digest=service_lookup_digest;
    PERFORM set_config('matrix.iam_tenant_id',service_index.tenant_id,true);
    SELECT credential.* INTO service_credential FROM iam.service_credentials credential
      JOIN iam.accounts account ON account.id=credential.tenant_id AND account.status='ACTIVE'
      JOIN iam.principals principal ON principal.tenant_id=credential.tenant_id AND principal.id=credential.principal_id
        AND principal.principal_type='SERVICE_ACCOUNT' AND principal.status='ACTIVE' AND principal.deleted_at IS NULL
      WHERE credential.tenant_id=service_index.tenant_id AND credential.principal_id=service_index.principal_id
        AND credential.lookup_digest=service_lookup_digest AND credential.purpose=service_purpose
        AND credential.revoked_at IS NULL FOR SHARE OF credential,account,principal;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role producer is unavailable'; END IF;
    SELECT receipt.installation_id INTO service_installation FROM iam.bootstrap_receipts receipt
      WHERE receipt.singleton AND receipt.organization_id=service_index.tenant_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role installation is unavailable'; END IF;

    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    SELECT candidate.role_id INTO target_role FROM iam.workload_role_bindings candidate
      WHERE candidate.tenant_id=tenant AND candidate.id=binding_id;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workload role binding is unavailable'; END IF;
    SELECT * INTO role_value FROM iam.roles candidate WHERE candidate.tenant_id=tenant AND candidate.id=target_role
      AND candidate.management='SERVICE_LINKED' AND candidate.deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service-linked role is unavailable'; END IF;
    SELECT * INTO relation FROM iam.service_linked_roles candidate
      WHERE candidate.tenant_id=tenant AND candidate.role_id=role_value.id FOR SHARE;
    SELECT * INTO stored FROM iam.workload_role_bindings candidate
      WHERE candidate.tenant_id=tenant AND candidate.id=binding_id AND candidate.role_id=role_value.id FOR UPDATE;
    IF NOT FOUND OR relation.role_id IS NULL
      OR ROW(relation.service_account_id,relation.service_installation_id,relation.service_principal_id,relation.service_purpose)
         IS DISTINCT FROM ROW(service_index.tenant_id,service_installation,service_credential.principal_id,service_purpose)
      OR ROW(stored.template_id,stored.template_version,stored.template_digest)
         IS DISTINCT FROM ROW(relation.template_id,relation.template_version,relation.template_digest) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workload role binding is unavailable'; END IF;
    SELECT * INTO template FROM iam.service_role_templates published
      WHERE published.id=stored.template_id AND published.version=stored.template_version
        AND published.content_digest=stored.template_digest FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role template is unavailable'; END IF;
    SELECT workload->>'unbindAction' INTO unbind_action
      FROM jsonb_array_elements(template.canonical_spec::jsonb->'workloads') workload
      WHERE workload->>'resourceKind'=stored.workload_kind;
    IF NOT FOUND OR unbind_action IS DISTINCT FROM request_value#>>'{authorization,action}'
      OR request_value#>>'{authorization,profile,product}' IS DISTINCT FROM template.canonical_spec::jsonb->>'product'
      OR request_value#>>'{authorization,resource,kind}' IS DISTINCT FROM stored.workload_kind
      OR request_value#>>'{authorization,resource,id}' IS DISTINCT FROM stored.workload_id
      OR template.canonical_spec::jsonb->>'servicePurpose' IS DISTINCT FROM service_purpose THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='service role workload revocation is invalid'; END IF;

    PERFORM iam.assert_allowed_decision(tenant,actor,workload_decision,unbind_action,
      stored.workload_kind,stored.workload_id,'INSTANCE',NULL);
    PERFORM iam.assert_allowed_decision(tenant,actor,binding_revoke_decision,
      'iam.workload-role-binding.revoke','WORKLOAD_ROLE_BINDING',stored.id,'INSTANCE',NULL);
    PERFORM iam.assert_allowed_decision(tenant,actor,role_pass_decision,
      'iam.role.pass','ROLE',stored.role_id,'INSTANCE',NULL);
    IF NOT EXISTS(SELECT 1 FROM iam.authorization_decisions decision
      JOIN iam.authorization_profiles profile ON profile.product=decision.profile_product
        AND profile.revision=decision.profile_revision AND profile.content_digest=decision.profile_content_digest
      WHERE decision.tenant_id=tenant AND decision.id=workload_decision
        AND decision.document->'profile'=request_value#>'{authorization,profile}'
        AND decision.document->'action'=request_value#>'{authorization,action}'
        AND decision.document->'resource'=request_value#>'{authorization,resource}'
        AND decision.document->'requestId'=request_value#>'{authorization,requestId}'
        AND decision.document->'correlationId'=request_value#>'{authorization,correlationId}'
        AND decision.document->'networkContext' IS NOT DISTINCT FROM request_value#>'{authorization,networkContext}'
        AND decision.document->'resourceMode'=request_value#>'{authorization,resourceMode}'
        AND NOT decision.document ? 'collectionUsage'
        AND profile.canonical_document::jsonb->>'callingService'=service_purpose) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workload role authorization is unavailable'; END IF;
    PERFORM iam.assert_audit_event(binding_event,tenant,'iam.workload-role-binding.revoked',
      'WORKLOAD_ROLE_BINDING',stored.id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,binding_event);
    IF binding_event->>'iamDecisionId' IS DISTINCT FROM binding_revoke_decision
      OR binding_event->>'requestId' IS DISTINCT FROM request_value#>>'{authorization,requestId}'
      OR binding_event->>'requestDigest' IS DISTINCT FROM request_digest THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='workload role revocation audit correlation is invalid'; END IF;

    IF stored.revoked_at IS NOT NULL THEN
        IF stored.status<>'REVOKED' OR stored.resource_version<>(request_value->>'resourceVersion')::bigint+1
          OR NOT EXISTS(SELECT 1 FROM iam.audit_outbox fact
            JOIN iam.authorization_decisions decision ON decision.tenant_id=fact.tenant_id
              AND decision.id=fact.event_document->>'iamDecisionId'
            WHERE fact.tenant_id=tenant AND fact.event_document->>'action'='iam.workload-role-binding.revoked'
              AND fact.event_document#>>'{target,kind}'='WORKLOAD_ROLE_BINDING'
              AND fact.event_document#>>'{target,id}'=stored.id
              AND fact.event_document->>'requestId'=request_value#>>'{authorization,requestId}'
              AND fact.event_document->>'requestDigest'=request_digest
              AND fact.event_document#>>'{actor,type}'='USER' AND fact.event_document#>>'{actor,id}'=actor
              AND (fact.event_document->>'occurredAt')::timestamptz=stored.revoked_at
              AND decision.allowed AND decision.action_name='iam.workload-role-binding.revoke'
              AND decision.target_kind='WORKLOAD_ROLE_BINDING' AND decision.target_id=stored.id
              AND decision.principal_id=actor AND decision.request_id=fact.event_document->>'requestId'
              AND decision.decided_at=stored.revoked_at)
          OR NOT EXISTS(SELECT 1 FROM iam.authorization_decisions decision
            WHERE decision.tenant_id=tenant AND decision.principal_id=actor AND decision.allowed
              AND decision.action_name=unbind_action AND decision.target_kind=stored.workload_kind
              AND decision.target_id=stored.workload_id AND decision.request_id=request_value#>>'{authorization,requestId}'
              AND decision.decided_at=stored.revoked_at)
          OR NOT EXISTS(SELECT 1 FROM iam.authorization_decisions decision
            WHERE decision.tenant_id=tenant AND decision.principal_id=actor AND decision.allowed
              AND decision.action_name='iam.role.pass' AND decision.target_kind='ROLE'
              AND decision.target_id=stored.role_id AND decision.request_id=request_value#>>'{authorization,requestId}'
              AND decision.decided_at=stored.revoked_at) THEN
            RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='workload role binding revocation intent conflicts'; END IF;
        RETURN iam.workload_role_binding_snapshot(tenant,stored.id);
    END IF;
    IF stored.status<>'ACTIVE' OR stored.resource_version<>(request_value->>'resourceVersion')::bigint
      OR role_value.security_generation=9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='workload role binding revision conflicts'; END IF;
    UPDATE iam.workload_role_bindings binding SET status='REVOKED',resource_version=stored.resource_version+1,
      updated_at=effective_now,revoked_at=effective_now WHERE binding.tenant_id=tenant AND binding.id=stored.id;
    UPDATE iam.roles role_update SET security_generation=role_update.security_generation+1
      WHERE role_update.tenant_id=tenant AND role_update.id=stored.role_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(tenant,binding_event->>'eventId',binding_event,effective_now,effective_now,effective_now);
    RETURN iam.workload_role_binding_snapshot(tenant,stored.id);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_datetime_format OR datetime_field_overflow THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='workload role binding revocation command is invalid';
END $function$;

-- These read entrypoints expose only the authenticated Account's consent.
-- They re-check the current authorization decision in the database and keep
-- binding history separate from the bounded relation directory.
CREATE OR REPLACE FUNCTION iam.list_service_linked_roles(
    tenant text,actor text,decision text,after_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.read_account(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,
      'iam.service-linked-role.list','ACCOUNT',tenant,'INSTANCE',NULL);
    IF COALESCE(after_id,'')<>'' AND after_id COLLATE "C" !~ '^slr-[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='service-linked role page is invalid'; END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
      'relation',iam.service_linked_role_snapshot(tenant,directory.role_id),
      'bindingCount',directory.binding_count,
      'activeBindingCount',directory.active_binding_count) ORDER BY directory.role_id),'[]') INTO result
    FROM (
      SELECT relation.role_id,
        (SELECT count(*) FROM iam.workload_role_bindings binding
          WHERE binding.tenant_id=tenant AND binding.role_id=relation.role_id) AS binding_count,
        (SELECT count(*) FROM iam.workload_role_bindings binding
          WHERE binding.tenant_id=tenant AND binding.role_id=relation.role_id AND binding.revoked_at IS NULL) AS active_binding_count
      FROM iam.service_linked_roles relation
      WHERE relation.tenant_id=tenant
        AND (COALESCE(after_id,'')='' OR relation.role_id>after_id COLLATE "C")
      ORDER BY relation.role_id LIMIT 101
    ) directory;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.read_service_linked_role(
    tenant text,actor text,decision text,role_id text,after_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE relation jsonb; bindings jsonb;
BEGIN
    PERFORM iam.read_account(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,
      'iam.service-linked-role.read','ROLE',role_id,'INSTANCE',NULL);
    IF COALESCE(role_id,'') COLLATE "C" !~ '^slr-[0-9a-f]{64}$'
      OR (COALESCE(after_id,'')<>'' AND after_id COLLATE "C" !~ '^wrb-[0-9a-f]{64}$') THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='service-linked role read is invalid'; END IF;
    relation:=iam.service_linked_role_snapshot(tenant,role_id);
    IF relation IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service-linked role is unavailable'; END IF;
    SELECT COALESCE(jsonb_agg(iam.workload_role_binding_snapshot(tenant,directory.id) ORDER BY directory.id),'[]') INTO bindings
    FROM (
      SELECT binding.id FROM iam.workload_role_bindings binding
      WHERE binding.tenant_id=tenant AND binding.role_id=read_service_linked_role.role_id
        AND (COALESCE(after_id,'')='' OR binding.id>after_id COLLATE "C")
      ORDER BY binding.id LIMIT 101
    ) directory;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','ServiceLinkedRoleAccess',
      'relation',relation,'bindings',bindings);
END $function$;

CREATE OR REPLACE FUNCTION iam.service_role_template_snapshot(template_id text,template_version bigint)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','ServiceRoleTemplate',
      'id',template.id,'version',template.version,'spec',template.canonical_spec::jsonb,
      'contentDigest',template.content_digest,'status',template.status)
    FROM iam.service_role_templates template
    WHERE template.id=service_role_template_snapshot.template_id
      AND template.version=service_role_template_snapshot.template_version
$function$;

-- Resolve one current physical service credential and its sealed installation
-- provenance. The result is private evidence, never a target-Account permit.
CREATE OR REPLACE FUNCTION iam.current_service_role_source(service_lookup_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE indexed iam.service_credential_index%ROWTYPE; credential iam.service_credentials%ROWTYPE;
    installation text;
BEGIN
    IF COALESCE(service_lookup_digest,'') !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='service role credential reference is invalid'; END IF;
    SELECT * INTO indexed FROM iam.service_credential_index candidate
      WHERE candidate.lookup_digest=service_lookup_digest;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role source is unavailable'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',indexed.tenant_id,true);
    SELECT service.* INTO credential FROM iam.service_credentials service
      JOIN iam.accounts account ON account.id=service.tenant_id AND account.status='ACTIVE'
      JOIN iam.principals principal ON principal.tenant_id=service.tenant_id AND principal.id=service.principal_id
        AND principal.principal_type='SERVICE_ACCOUNT' AND principal.status='ACTIVE' AND principal.deleted_at IS NULL
      WHERE service.tenant_id=indexed.tenant_id AND service.principal_id=indexed.principal_id
        AND service.lookup_digest=service_lookup_digest AND service.revoked_at IS NULL
      FOR SHARE OF service,account,principal;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role source is unavailable'; END IF;
    SELECT receipt.installation_id INTO installation FROM iam.bootstrap_receipts receipt
      WHERE receipt.singleton AND receipt.organization_id=credential.tenant_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role installation is unavailable'; END IF;
    RETURN jsonb_build_object('accountId',credential.tenant_id,'installationId',installation,
      'principalId',credential.principal_id,'purpose',credential.purpose,'lookupDigest',credential.lookup_digest);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_service_role_assumption(
    service_lookup_digest text,binding_id text,request_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE source jsonb; indexed iam.workload_role_binding_index%ROWTYPE;
    request_index iam.service_role_session_request_index%ROWTYPE;
    role_value iam.roles%ROWTYPE; relation iam.service_linked_roles%ROWTYPE;
    binding iam.workload_role_bindings%ROWTYPE; template iam.service_role_templates%ROWTYPE;
    policy iam.policies%ROWTYPE; version iam.policy_versions%ROWTYPE; result jsonb;
BEGIN
    IF COALESCE(binding_id,'') !~ '^wrb-[0-9a-f]{64}$'
      OR COALESCE(request_id,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='service role assumption is invalid'; END IF;
    source:=iam.current_service_role_source(service_lookup_digest);
    SELECT * INTO request_index FROM iam.service_role_session_request_index candidate
      WHERE candidate.service_account_id=source->>'accountId'
        AND candidate.service_principal_id=source->>'principalId'
        AND candidate.request_id=read_service_role_assumption.request_id FOR SHARE;
    IF FOUND AND request_index.binding_id IS DISTINCT FROM binding_id THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='service role request identity conflicts'; END IF;
    SELECT * INTO indexed FROM iam.workload_role_binding_index candidate
      WHERE candidate.binding_id=read_service_role_assumption.binding_id FOR SHARE;
    IF NOT FOUND OR ROW(indexed.service_account_id,indexed.service_installation_id,
        indexed.service_principal_id,indexed.service_purpose)
      IS DISTINCT FROM ROW(source->>'accountId',source->>'installationId',source->>'principalId',source->>'purpose') THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role binding is unavailable'; END IF;
    IF request_index.session_id IS NOT NULL AND ROW(request_index.tenant_id,request_index.binding_id)
      IS DISTINCT FROM ROW(indexed.tenant_id,indexed.binding_id) THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='service role request identity conflicts'; END IF;

    PERFORM set_config('matrix.iam_tenant_id',indexed.tenant_id,true);
    PERFORM 1 FROM iam.accounts account WHERE account.id=indexed.tenant_id AND account.status='ACTIVE' FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role target account is unavailable'; END IF;
    SELECT * INTO role_value FROM iam.roles candidate
      WHERE candidate.tenant_id=indexed.tenant_id AND candidate.id=indexed.role_id
        AND candidate.management='SERVICE_LINKED' AND candidate.status='ACTIVE' AND candidate.deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service-linked role is unavailable'; END IF;
    SELECT * INTO relation FROM iam.service_linked_roles candidate
      WHERE candidate.tenant_id=indexed.tenant_id AND candidate.role_id=indexed.role_id FOR SHARE;
    SELECT * INTO binding FROM iam.workload_role_bindings candidate
      WHERE candidate.tenant_id=indexed.tenant_id AND candidate.id=indexed.binding_id
        AND candidate.role_id=indexed.role_id AND candidate.status='ACTIVE' AND candidate.revoked_at IS NULL FOR UPDATE;
    IF relation.role_id IS NULL OR binding.id IS NULL
      OR ROW(relation.service_account_id,relation.service_installation_id,relation.service_principal_id,relation.service_purpose)
         IS DISTINCT FROM ROW(source->>'accountId',source->>'installationId',source->>'principalId',source->>'purpose')
      OR ROW(binding.template_id,binding.template_version,binding.template_digest)
         IS DISTINCT FROM ROW(relation.template_id,relation.template_version,relation.template_digest) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role binding is unavailable'; END IF;
    SELECT * INTO template FROM iam.service_role_templates published
      WHERE published.id=relation.template_id AND published.version=relation.template_version
        AND published.content_digest=relation.template_digest AND published.status='ACTIVE' FOR SHARE;
    IF NOT FOUND OR template.canonical_spec::jsonb->>'servicePurpose' IS DISTINCT FROM source->>'purpose'
      OR (template.canonical_spec::jsonb->>'maxSessionDurationSeconds')::integer
           IS DISTINCT FROM (role_value.metadata->>'maxSessionDurationSeconds')::integer THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role template is unavailable'; END IF;
    SELECT * INTO policy FROM iam.policies candidate
      WHERE candidate.id=relation.policy_id AND candidate.management='SYSTEM' AND candidate.status='ACTIVE'
        AND candidate.authority_scope='TENANT' FOR SHARE;
    SELECT * INTO version FROM iam.policy_versions candidate
      WHERE candidate.policy_id=relation.policy_id AND candidate.id=relation.policy_version_id
        AND candidate.content_digest=relation.policy_content_digest AND candidate.retired_at IS NULL FOR SHARE;
    IF policy.id IS NULL OR version.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role permission ceiling is unavailable'; END IF;
    result:=jsonb_build_object('relation',iam.service_linked_role_snapshot(indexed.tenant_id,indexed.role_id),
      'binding',iam.workload_role_binding_snapshot(indexed.tenant_id,indexed.binding_id),
      'template',iam.service_role_template_snapshot(template.id,template.version),
      'securityGeneration',role_value.security_generation);
    IF request_index.session_id IS NOT NULL THEN
      IF NOT EXISTS(SELECT 1 FROM iam.service_role_session_evidence evidence
          WHERE evidence.tenant_id=indexed.tenant_id AND evidence.session_id=request_index.session_id
            AND evidence.binding_id=indexed.binding_id AND evidence.service_account_id=source->>'accountId'
            AND evidence.service_principal_id=source->>'principalId') THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='service role completion evidence is unavailable'; END IF;
      result:=result||jsonb_build_object('existing',jsonb_build_object(
        'session',iam.role_session_snapshot(indexed.tenant_id,request_index.session_id),
        'bindingId',request_index.binding_id,
        'requestDigest',(SELECT session_value.request_digest FROM iam.role_sessions session_value
          WHERE session_value.tenant_id=indexed.tenant_id AND session_value.id=request_index.session_id)));
    END IF;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.issue_service_role_session(
    service_lookup_digest text,binding_id text,request_document text,intent jsonb,
    lookup_digest text,verification_digest text,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE source jsonb; admission jsonb; request_value jsonb; role_value iam.roles%ROWTYPE;
    relation iam.service_linked_roles%ROWTYPE; binding iam.workload_role_bindings%ROWTYPE;
    template iam.service_role_templates%ROWTYPE; policy iam.policies%ROWTYPE; version iam.policy_versions%ROWTYPE;
    evidence jsonb; duration integer;
    session_id text; now_at timestamptz(6):=transaction_timestamp(); deadline timestamptz(6);
BEGIN
    IF request_document IS NULL OR octet_length(request_document)>4096
      OR NOT (request_document IS JSON OBJECT WITH UNIQUE KEYS)
      OR intent IS NULL OR jsonb_typeof(intent)<>'object'
      OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(intent) key) IS DISTINCT FROM
        ARRAY['durationSeconds','expectedBindingVersion','expectedSecurityGeneration','expiresAt','issuedAt','requestDigest','requestId','sessionId']
      OR COALESCE(intent->>'sessionId','') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(intent->>'requestId','') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(intent->>'requestDigest','') !~ '^sha256:[0-9a-f]{64}$'
      OR COALESCE(lookup_digest,'') !~ '^sha256:[0-9a-f]{64}$'
      OR COALESCE(verification_digest,'') !~ '^sha256:[0-9a-f]{64}$'
      OR jsonb_typeof(intent->'durationSeconds') IS DISTINCT FROM 'number'
      OR jsonb_typeof(intent->'expectedBindingVersion') IS DISTINCT FROM 'number'
      OR jsonb_typeof(intent->'expectedSecurityGeneration') IS DISTINCT FROM 'number'
      OR NOT pg_input_is_valid(intent->>'issuedAt','timestamptz')
      OR NOT pg_input_is_valid(intent->>'expiresAt','timestamptz') THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='service role issuance intent is invalid'; END IF;
    request_value:=request_document::jsonb;
    IF (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(request_value) key)
         IS DISTINCT FROM ARRAY['bindingId','requestId']
      AND (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(request_value) key)
         IS DISTINCT FROM ARRAY['bindingId','durationSeconds','requestId']
      OR request_value->>'bindingId' IS DISTINCT FROM binding_id
      OR request_value->>'requestId' IS DISTINCT FROM intent->>'requestId'
      OR (request_value ? 'durationSeconds' AND jsonb_typeof(request_value->'durationSeconds')<>'number')
      OR intent->>'requestDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(
        convert_to('matrix.iam.request.v1','UTF8')||decode('00','hex')
        ||convert_to('service-role-session-assume','UTF8')||decode('00','hex')
        ||convert_to(request_document,'UTF8')),'hex') THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='service role issuance request is invalid'; END IF;
    source:=iam.current_service_role_source(service_lookup_digest);
    admission:=iam.read_service_role_assumption(service_lookup_digest,binding_id,intent->>'requestId');
    IF admission ? 'existing' THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='service role issuance already exists'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',admission#>>'{binding,accountId}',true);
    SELECT * INTO role_value FROM iam.roles candidate
      WHERE candidate.tenant_id=admission#>>'{binding,accountId}' AND candidate.id=admission#>>'{binding,roleId}'
        AND candidate.management='SERVICE_LINKED' AND candidate.status='ACTIVE' AND candidate.deleted_at IS NULL FOR UPDATE;
    SELECT * INTO relation FROM iam.service_linked_roles candidate
      WHERE candidate.tenant_id=role_value.tenant_id AND candidate.role_id=role_value.id FOR SHARE;
    SELECT * INTO binding FROM iam.workload_role_bindings candidate
      WHERE candidate.tenant_id=role_value.tenant_id AND candidate.id=binding_id
        AND candidate.role_id=role_value.id AND candidate.status='ACTIVE' AND candidate.revoked_at IS NULL FOR UPDATE;
    SELECT * INTO template FROM iam.service_role_templates published
      WHERE published.id=relation.template_id AND published.version=relation.template_version
        AND published.content_digest=relation.template_digest AND published.status='ACTIVE' FOR SHARE;
    SELECT * INTO policy FROM iam.policies candidate
      WHERE candidate.id=relation.policy_id AND candidate.management='SYSTEM' AND candidate.status='ACTIVE'
        AND candidate.authority_scope='TENANT' FOR SHARE;
    SELECT * INTO version FROM iam.policy_versions candidate
      WHERE candidate.policy_id=relation.policy_id AND candidate.id=relation.policy_version_id
        AND candidate.content_digest=relation.policy_content_digest AND candidate.retired_at IS NULL FOR SHARE;
    IF role_value.id IS NULL OR relation.role_id IS NULL OR binding.id IS NULL OR template.id IS NULL
      OR policy.id IS NULL OR version.id IS NULL
      OR ROW(relation.service_account_id,relation.service_installation_id,relation.service_principal_id,relation.service_purpose)
         IS DISTINCT FROM ROW(source->>'accountId',source->>'installationId',source->>'principalId',source->>'purpose')
      OR ROW(binding.template_id,binding.template_version,binding.template_digest)
         IS DISTINCT FROM ROW(template.id,template.version,template.content_digest)
      OR binding.resource_version IS DISTINCT FROM (intent->>'expectedBindingVersion')::bigint
      OR role_value.security_generation IS DISTINCT FROM (intent->>'expectedSecurityGeneration')::bigint
      OR admission->'securityGeneration' IS DISTINCT FROM intent->'expectedSecurityGeneration' THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='service role issuance authority changed'; END IF;
    duration:=(intent->>'durationSeconds')::integer;
    IF duration NOT BETWEEN 60 AND 43200 OR duration>(template.canonical_spec::jsonb->>'maxSessionDurationSeconds')::integer
      OR (request_value ? 'durationSeconds' AND (request_value->>'durationSeconds')::integer<>duration)
      OR (NOT (request_value ? 'durationSeconds') AND duration<>least(3600,(template.canonical_spec::jsonb->>'maxSessionDurationSeconds')::integer)) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role issuance duration is unavailable'; END IF;
    deadline:=now_at+duration*interval '1 second';
    IF (intent->>'issuedAt')::timestamptz IS DISTINCT FROM now_at
      OR (intent->>'expiresAt')::timestamptz IS DISTINCT FROM deadline OR deadline<=clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service role issuance deadline is unavailable'; END IF;
    session_id:=intent->>'sessionId';
    PERFORM iam.assert_audit_event(event,role_value.tenant_id,'iam.service-role-session.issued','ROLE_SESSION',session_id,'SUCCEEDED');
    IF event#>>'{actor,type}' IS DISTINCT FROM 'SERVICE_ACCOUNT'
      OR event#>>'{actor,id}' IS DISTINCT FROM source->>'principalId'
      OR event->>'requestId' IS DISTINCT FROM intent->>'requestId'
      OR event->>'correlationId' IS DISTINCT FROM intent->>'requestId'
      OR event->>'requestDigest' IS DISTINCT FROM intent->>'requestDigest'
      OR event ? 'iamDecisionId' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='service role issuance audit correlation is invalid'; END IF;
    IF (SELECT count(*) FROM iam.role_sessions session_value
          WHERE session_value.tenant_id=role_value.tenant_id AND session_value.revoked_at IS NULL
            AND session_value.expires_at>clock_timestamp())>=1024
      OR (SELECT count(*) FROM iam.role_sessions session_value
          WHERE session_value.tenant_id=role_value.tenant_id AND session_value.role_id=role_value.id
            AND session_value.revoked_at IS NULL AND session_value.expires_at>clock_timestamp())>=128
      OR (SELECT count(*) FROM iam.service_role_session_request_index request_value
          WHERE request_value.service_account_id=source->>'accountId'
            AND request_value.service_principal_id=source->>'principalId'
            AND request_value.expires_at>clock_timestamp())>=128 THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='service role session quota is exhausted'; END IF;
    evidence:=jsonb_build_object('serviceSource',source,
      'binding',iam.workload_role_binding_snapshot(role_value.tenant_id,binding.id),
      'template',iam.service_role_template_snapshot(template.id,template.version),
      'permissionVersion',iam.policy_version_snapshot(version));
    INSERT INTO iam.role_sessions(tenant_id,id,role_id,source_service_principal_id,security_generation,
      authority_contract_version,request_id,request_digest,verification_digest,authority_evidence,issued_at,expires_at)
    VALUES(role_value.tenant_id,session_id,role_value.id,source->>'principalId',role_value.security_generation,
      3,intent->>'requestId',intent->>'requestDigest',verification_digest,evidence,now_at,deadline);
    INSERT INTO iam.service_role_session_evidence(tenant_id,session_id,binding_id,binding_resource_version,
      service_account_id,service_installation_id,service_principal_id,service_purpose,service_lookup_digest,
      template_id,template_version,template_digest,policy_id,policy_version_id,policy_content_digest,
      workload_kind,workload_id,created_at)
    VALUES(role_value.tenant_id,session_id,binding.id,binding.resource_version,
      source->>'accountId',source->>'installationId',source->>'principalId',source->>'purpose',source->>'lookupDigest',
      template.id,template.version,template.content_digest,version.policy_id,version.id,version.content_digest,
      binding.workload_kind,binding.workload_id,now_at);
    INSERT INTO iam.role_session_index(lookup_digest,tenant_id,session_id)
      VALUES(lookup_digest,role_value.tenant_id,session_id);
    INSERT INTO iam.service_role_session_request_index(service_account_id,service_principal_id,request_id,
      tenant_id,session_id,binding_id,expires_at)
    VALUES(source->>'accountId',source->>'principalId',intent->>'requestId',role_value.tenant_id,session_id,binding.id,deadline);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
      VALUES(role_value.tenant_id,event->>'eventId',event,now_at,now_at,now_at);
    RETURN iam.role_session_snapshot(role_value.tenant_id,session_id);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_datetime_format OR datetime_field_overflow THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='service role issuance command is invalid';
END $function$;

CREATE OR REPLACE FUNCTION iam.read_service_role_session_by_request(
    service_lookup_digest text,request_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE source jsonb; indexed iam.service_role_session_request_index%ROWTYPE;
BEGIN
    IF COALESCE(request_id,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='service role completion request is invalid'; END IF;
    source:=iam.current_service_role_source(service_lookup_digest);
    SELECT * INTO indexed FROM iam.service_role_session_request_index candidate
      WHERE candidate.service_account_id=source->>'accountId'
        AND candidate.service_principal_id=source->>'principalId'
        AND candidate.request_id=read_service_role_session_by_request.request_id FOR SHARE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    PERFORM set_config('matrix.iam_tenant_id',indexed.tenant_id,true);
    IF NOT EXISTS(SELECT 1 FROM iam.service_role_session_evidence evidence
      WHERE evidence.tenant_id=indexed.tenant_id AND evidence.session_id=indexed.session_id
        AND evidence.binding_id=indexed.binding_id AND evidence.service_account_id=source->>'accountId'
        AND evidence.service_installation_id=source->>'installationId'
        AND evidence.service_principal_id=source->>'principalId' AND evidence.service_purpose=source->>'purpose'
        AND evidence.service_lookup_digest=source->>'lookupDigest') THEN
      RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='service role completion evidence is unavailable'; END IF;
    RETURN iam.role_session_snapshot(indexed.tenant_id,indexed.session_id);
END $function$;

-- Historical decision provenance for a SERVICE-origin RoleSession. This does
-- not require the service credential, binding, template or policy to remain
-- active: current request authorization performs those checks separately.
CREATE OR REPLACE FUNCTION iam.service_role_authorization_evidence(tenant text,session_id text)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.role_sessions%ROWTYPE; evidence iam.service_role_session_evidence%ROWTYPE;
    relation iam.service_linked_roles%ROWTYPE; binding iam.workload_role_bindings%ROWTYPE;
    template iam.service_role_templates%ROWTYPE; version iam.policy_versions%ROWTYPE;
    service_source jsonb; original_binding jsonb; original_template jsonb; original_vector jsonb;
    service_proof jsonb;
BEGIN
    SELECT * INTO stored FROM iam.role_sessions candidate
      WHERE candidate.tenant_id=tenant AND candidate.id=session_id;
    SELECT * INTO evidence FROM iam.service_role_session_evidence candidate
      WHERE candidate.tenant_id=tenant AND candidate.session_id=service_role_authorization_evidence.session_id;
    IF stored.id IS NULL OR evidence.session_id IS NULL OR stored.authority_contract_version<>3
      OR stored.source_user_id IS NOT NULL OR stored.source_service_principal_id IS NULL
      OR stored.source_session_id IS NOT NULL OR stored.credential_generation IS NOT NULL
      OR stored.trust_version_id IS NOT NULL OR stored.decision_id IS NOT NULL
      OR stored.session_policy_canonical IS NOT NULL OR stored.session_policy_digest IS NOT NULL
      OR stored.source_service_principal_id IS DISTINCT FROM evidence.service_principal_id
      OR stored.security_generation NOT BETWEEN 1 AND 9007199254740991
      OR stored.issued_at IS DISTINCT FROM evidence.created_at THEN RETURN NULL; END IF;
    SELECT * INTO relation FROM iam.service_linked_roles candidate
      WHERE candidate.tenant_id=tenant AND candidate.role_id=stored.role_id;
    SELECT * INTO binding FROM iam.workload_role_bindings candidate
      WHERE candidate.tenant_id=tenant AND candidate.id=evidence.binding_id AND candidate.role_id=stored.role_id;
    SELECT * INTO template FROM iam.service_role_templates published
      WHERE published.id=evidence.template_id AND published.version=evidence.template_version;
    SELECT * INTO version FROM iam.policy_versions candidate
      WHERE candidate.policy_id=evidence.policy_id AND candidate.id=evidence.policy_version_id;
    IF relation.role_id IS NULL OR binding.id IS NULL OR template.id IS NULL OR version.id IS NULL
      OR evidence.binding_resource_version<>1
      OR NOT EXISTS(SELECT 1 FROM iam.roles role_value WHERE role_value.tenant_id=tenant
          AND role_value.id=stored.role_id AND role_value.management='SERVICE_LINKED')
      OR ROW(relation.service_account_id,relation.service_installation_id,relation.service_principal_id,
          relation.service_purpose,relation.template_id,relation.template_version,relation.template_digest,
          relation.policy_id,relation.policy_version_id,relation.policy_content_digest)
        IS DISTINCT FROM ROW(evidence.service_account_id,evidence.service_installation_id,evidence.service_principal_id,
          evidence.service_purpose,evidence.template_id,evidence.template_version,evidence.template_digest,
          evidence.policy_id,evidence.policy_version_id,evidence.policy_content_digest)
      OR ROW(binding.template_id,binding.template_version,binding.template_digest,binding.workload_kind,binding.workload_id)
        IS DISTINCT FROM ROW(evidence.template_id,evidence.template_version,evidence.template_digest,
          evidence.workload_kind,evidence.workload_id)
      OR template.content_digest IS DISTINCT FROM evidence.template_digest
      OR version.content_digest IS DISTINCT FROM evidence.policy_content_digest THEN RETURN NULL; END IF;
    -- The immutable evidence row is FK-bound to the original service
    -- principal, relationship, binding, template and permission version. Do
    -- not re-read the producer's home Account through the target Account's
    -- RLS context: this function proves a committed historical decision, while
    -- lookup_service_role_session_authority separately requires the current
    -- producer credential and all current target authority before each use.
    service_source:=jsonb_build_object('accountId',evidence.service_account_id,
      'installationId',evidence.service_installation_id,'principalId',evidence.service_principal_id,
      'purpose',evidence.service_purpose,'lookupDigest',evidence.service_lookup_digest);
    original_binding:=jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','WorkloadRoleBinding',
      'id',binding.id,'accountId',binding.tenant_id,'roleId',binding.role_id,
      'template',jsonb_build_object('id',binding.template_id,'version',binding.template_version,'contentDigest',binding.template_digest),
      'workload',jsonb_build_object('kind',binding.workload_kind,'id',binding.workload_id),
      'status','ACTIVE','resourceVersion',1,'createdAt',binding.created_at,'updatedAt',binding.created_at);
    original_template:=jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','ServiceRoleTemplate',
      'id',template.id,'version',template.version,'spec',template.canonical_spec::jsonb,
      'contentDigest',template.content_digest,'status','ACTIVE');
    original_vector:=jsonb_build_object('serviceSource',service_source,'binding',original_binding,
      'template',original_template,'permissionVersion',iam.policy_version_snapshot(version));
    IF stored.authority_evidence IS DISTINCT FROM original_vector
      OR NOT EXISTS(SELECT 1 FROM iam.audit_outbox fact WHERE fact.tenant_id=tenant
        AND fact.event_document->>'action'='iam.service-role-session.issued'
        AND fact.event_document#>>'{target,kind}'='ROLE_SESSION'
        AND fact.event_document#>>'{target,id}'=stored.id
        AND fact.event_document#>>'{actor,type}'='SERVICE_ACCOUNT'
        AND fact.event_document#>>'{actor,id}'=stored.source_service_principal_id
        AND fact.event_document->>'requestId'=stored.request_id
        AND fact.event_document->>'requestDigest'=stored.request_digest
        AND NOT fact.event_document ? 'iamDecisionId'
        AND (fact.event_document->>'occurredAt')::timestamptz=stored.issued_at) THEN RETURN NULL; END IF;
    service_proof:=jsonb_build_object('identity',jsonb_build_object(
      'apiVersion','iam.matrix.xiak.com/v1','kind','ServiceIdentity',
      'installationId',evidence.service_installation_id,'organizationId',evidence.service_account_id,
      'principalId',evidence.service_principal_id,'purpose',evidence.service_purpose),
      'lookupDigest',evidence.service_lookup_digest,'bindingId',evidence.binding_id,
      'bindingResourceVersion',evidence.binding_resource_version,
      'template',jsonb_build_object('id',evidence.template_id,'version',evidence.template_version,'contentDigest',evidence.template_digest),
      'workload',jsonb_build_object('kind',evidence.workload_kind,'id',evidence.workload_id),
      'permissionVersion',jsonb_build_object('policyId',evidence.policy_id,'versionId',evidence.policy_version_id,
        'contentDigest',evidence.policy_content_digest),'contractVersion',version.contract_version)
      ||CASE WHEN version.contract_version=2 THEN jsonb_build_object('compilation',version.compilation) ELSE '{}'::jsonb END;
    RETURN jsonb_build_object('authorityContractVersion',3,'sessionId',stored.id,'roleId',stored.role_id,
      'sourceServicePrincipalId',stored.source_service_principal_id,'securityGeneration',stored.security_generation,
      'service',service_proof);
END $function$;

-- This is the service branch of the one RoleSession credential lookup. It
-- revalidates current producer, Account, Role, binding, template and immutable
-- permission ceiling. No cached issuance fact is treated as a permit.
CREATE OR REPLACE FUNCTION iam.lookup_service_role_session_authority(tenant text,session_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.role_sessions%ROWTYPE; stored_evidence iam.service_role_session_evidence%ROWTYPE;
    source jsonb; target_account iam.accounts%ROWTYPE; role_value iam.roles%ROWTYPE;
    relation iam.service_linked_roles%ROWTYPE; binding iam.workload_role_bindings%ROWTYPE;
    template iam.service_role_templates%ROWTYPE; policy iam.policies%ROWTYPE; version iam.policy_versions%ROWTYPE;
    current_evidence jsonb;
BEGIN
    IF COALESCE(tenant,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(session_id,'') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN RETURN NULL; END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    SELECT * INTO stored FROM iam.role_sessions candidate
      WHERE candidate.tenant_id=tenant AND candidate.id=session_id
        AND candidate.authority_contract_version=3 AND candidate.source_user_id IS NULL
        AND candidate.source_service_principal_id IS NOT NULL
        AND candidate.revoked_at IS NULL AND candidate.expires_at>clock_timestamp() FOR SHARE;
    SELECT * INTO stored_evidence FROM iam.service_role_session_evidence candidate
      WHERE candidate.tenant_id=tenant AND candidate.session_id=lookup_service_role_session_authority.session_id FOR SHARE;
    IF stored.id IS NULL OR stored_evidence.session_id IS NULL
      OR stored.source_service_principal_id IS DISTINCT FROM stored_evidence.service_principal_id
      OR stored.issued_at IS DISTINCT FROM stored_evidence.created_at THEN RETURN NULL; END IF;
    source:=iam.current_service_role_source(stored_evidence.service_lookup_digest);
    IF ROW(source->>'accountId',source->>'installationId',source->>'principalId',source->>'purpose',source->>'lookupDigest')
      IS DISTINCT FROM ROW(stored_evidence.service_account_id,stored_evidence.service_installation_id,
        stored_evidence.service_principal_id,stored_evidence.service_purpose,stored_evidence.service_lookup_digest) THEN RETURN NULL; END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    SELECT * INTO target_account FROM iam.accounts candidate WHERE candidate.id=tenant AND candidate.status='ACTIVE' FOR SHARE;
    SELECT * INTO role_value FROM iam.roles candidate WHERE candidate.tenant_id=tenant AND candidate.id=stored.role_id
      AND candidate.management='SERVICE_LINKED' AND candidate.status='ACTIVE' AND candidate.deleted_at IS NULL
      AND candidate.security_generation=stored.security_generation FOR SHARE;
    SELECT * INTO relation FROM iam.service_linked_roles candidate
      WHERE candidate.tenant_id=tenant AND candidate.role_id=stored.role_id FOR SHARE;
    SELECT * INTO binding FROM iam.workload_role_bindings candidate
      WHERE candidate.tenant_id=tenant AND candidate.id=stored_evidence.binding_id
        AND candidate.role_id=stored.role_id AND candidate.status='ACTIVE' AND candidate.revoked_at IS NULL
        AND candidate.resource_version=stored_evidence.binding_resource_version FOR SHARE;
    SELECT * INTO template FROM iam.service_role_templates published
      WHERE published.id=stored_evidence.template_id AND published.version=stored_evidence.template_version
        AND published.content_digest=stored_evidence.template_digest AND published.status='ACTIVE' FOR SHARE;
    SELECT * INTO policy FROM iam.policies candidate
      WHERE candidate.id=stored_evidence.policy_id AND candidate.management='SYSTEM' AND candidate.status='ACTIVE'
        AND candidate.authority_scope='TENANT' FOR SHARE;
    SELECT * INTO version FROM iam.policy_versions candidate
      WHERE candidate.policy_id=stored_evidence.policy_id AND candidate.id=stored_evidence.policy_version_id
        AND candidate.content_digest=stored_evidence.policy_content_digest AND candidate.retired_at IS NULL FOR SHARE;
    IF target_account.id IS NULL OR role_value.id IS NULL OR relation.role_id IS NULL OR binding.id IS NULL
      OR template.id IS NULL OR policy.id IS NULL OR version.id IS NULL
      OR ROW(relation.service_account_id,relation.service_installation_id,relation.service_principal_id,relation.service_purpose,
        relation.template_id,relation.template_version,relation.template_digest,relation.policy_id,relation.policy_version_id,relation.policy_content_digest)
        IS DISTINCT FROM ROW(stored_evidence.service_account_id,stored_evidence.service_installation_id,
          stored_evidence.service_principal_id,stored_evidence.service_purpose,stored_evidence.template_id,
          stored_evidence.template_version,stored_evidence.template_digest,stored_evidence.policy_id,
          stored_evidence.policy_version_id,stored_evidence.policy_content_digest)
      OR ROW(binding.template_id,binding.template_version,binding.template_digest,binding.workload_kind,binding.workload_id)
        IS DISTINCT FROM ROW(stored_evidence.template_id,stored_evidence.template_version,stored_evidence.template_digest,
          stored_evidence.workload_kind,stored_evidence.workload_id)
      OR template.canonical_spec::jsonb->>'servicePurpose' IS DISTINCT FROM stored_evidence.service_purpose THEN RETURN NULL; END IF;
    current_evidence:=jsonb_build_object('serviceSource',source,
      'binding',iam.workload_role_binding_snapshot(tenant,binding.id),
      'template',iam.service_role_template_snapshot(template.id,template.version),
      'permissionVersion',iam.policy_version_snapshot(version));
    IF stored.authority_evidence IS DISTINCT FROM current_evidence
      OR NOT EXISTS(SELECT 1 FROM iam.audit_outbox fact
        WHERE fact.tenant_id=tenant AND fact.event_document->>'action'='iam.service-role-session.issued'
          AND fact.event_document#>>'{target,kind}'='ROLE_SESSION'
          AND fact.event_document#>>'{target,id}'=stored.id
          AND fact.event_document#>>'{actor,type}'='SERVICE_ACCOUNT'
          AND fact.event_document#>>'{actor,id}'=stored.source_service_principal_id
          AND fact.event_document->>'requestId'=stored.request_id
          AND fact.event_document->>'requestDigest'=stored.request_digest
          AND (fact.event_document->>'occurredAt')::timestamptz=stored.issued_at) THEN RETURN NULL; END IF;
    RETURN jsonb_build_object('authorityContractVersion',3,
      'session',iam.role_session_snapshot(tenant,stored.id),
      'sourceServiceIdentity',jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','ServiceIdentity',
        'organizationId',source->>'accountId','installationId',source->>'installationId',
        'principalId',source->>'principalId','purpose',source->>'purpose'),
      'sourceServiceLookupDigest',source->>'lookupDigest','bindingId',stored_evidence.binding_id,
      'bindingResourceVersion',stored_evidence.binding_resource_version,
      'securityGeneration',stored.security_generation,'verificationDigest',stored.verification_digest,
      'role',iam.role_snapshot(tenant,stored.role_id),'template',iam.service_role_template_snapshot(template.id,template.version),
      'workload',jsonb_build_object('kind',stored_evidence.workload_kind,'id',stored_evidence.workload_id),
      'permissionVersion',iam.policy_version_snapshot(version));
END $function$;

REVOKE ALL ON iam.service_role_templates,iam.service_linked_roles,iam.workload_role_bindings,
  iam.workload_role_binding_index,iam.service_role_session_evidence,iam.service_role_session_request_index
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.guard_service_role_template_change(),iam.guard_service_linked_role_change(),
  iam.guard_workload_role_binding_change(),iam.guard_customer_role_policy_attachment(),
  iam.service_linked_role_snapshot(text,text),iam.workload_role_binding_snapshot(text,text),
  iam.service_role_template_snapshot(text,bigint),iam.current_service_role_source(text),
  iam.service_role_authorization_evidence(text,text),iam.lookup_service_role_session_authority(text,text)
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.lock_workload_role_binding_sources(text,text,text,text,text)
  FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.create_workload_role_binding(text,text,text,text,text,text,jsonb,jsonb,jsonb,jsonb,text,text,text,jsonb,jsonb)
  FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.prepare_workload_role_binding_revocation(text,text,text,text),
  iam.revoke_workload_role_binding(text,text,text,text,text,text,text,text,text,text,text,jsonb)
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.list_service_linked_roles(text,text,text,text),
  iam.read_service_linked_role(text,text,text,text,text)
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.read_service_role_assumption(text,text,text),
  iam.issue_service_role_session(text,text,text,jsonb,text,text,jsonb),
  iam.read_service_role_session_by_request(text,text)
  FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
GRANT EXECUTE ON FUNCTION iam.lock_workload_role_binding_sources(text,text,text,text,text) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.create_workload_role_binding(text,text,text,text,text,text,jsonb,jsonb,jsonb,jsonb,text,text,text,jsonb,jsonb)
  TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.prepare_workload_role_binding_revocation(text,text,text,text),
  iam.revoke_workload_role_binding(text,text,text,text,text,text,text,text,text,text,text,jsonb) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.list_service_linked_roles(text,text,text,text),
  iam.read_service_linked_role(text,text,text,text,text) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.read_service_role_assumption(text,text,text),
  iam.issue_service_role_session(text,text,text,jsonb,text,text,jsonb),
  iam.read_service_role_session_by_request(text,text) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.service_role_session_contract_ready()
RETURNS boolean LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE table_name text; expected_count integer; required record; entrypoint record; relation_oid oid;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['workload_role_binding_index','service_role_session_evidence','service_role_session_request_index'] LOOP
        relation_oid:=to_regclass('iam.'||table_name);
        IF relation_oid IS NULL OR NOT EXISTS(SELECT 1 FROM pg_class relation WHERE relation.oid=relation_oid
          AND relation.relowner='matrix_iam_owner'::regrole
          AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) privilege
            WHERE privilege.grantee<>relation.relowner)) THEN RETURN false; END IF;
        expected_count:=CASE table_name WHEN 'workload_role_binding_index' THEN 7
          WHEN 'service_role_session_evidence' THEN 18 ELSE 7 END;
        IF (SELECT count(*) FROM pg_attribute column_value WHERE column_value.attrelid=relation_oid
          AND column_value.attnum>0 AND NOT column_value.attisdropped)<>expected_count THEN RETURN false; END IF;
    END LOOP;
    IF NOT EXISTS(SELECT 1 FROM pg_class relation WHERE relation.oid='iam.service_role_session_evidence'::regclass
      AND relation.relrowsecurity AND relation.relforcerowsecurity)
      OR (SELECT count(*) FROM pg_policy policy_value
          WHERE policy_value.polrelid='iam.service_role_session_evidence'::regclass)<>1
      OR NOT EXISTS(SELECT 1 FROM pg_policy policy_value
          WHERE policy_value.polrelid='iam.service_role_session_evidence'::regclass
            AND policy_value.polname='tenant_isolation' AND policy_value.polcmd='*'
            AND policy_value.polpermissive AND policy_value.polroles=ARRAY[0::oid]
            AND pg_get_expr(policy_value.polqual,policy_value.polrelid)='(tenant_id = iam.current_tenant_id())'
            AND pg_get_expr(policy_value.polwithcheck,policy_value.polrelid)='(tenant_id = iam.current_tenant_id())') THEN RETURN false; END IF;
    FOR required IN SELECT * FROM (VALUES
      ('workload_role_binding_index','binding_id','text'::regtype),
      ('workload_role_binding_index','tenant_id','text'::regtype),
      ('workload_role_binding_index','role_id','text'::regtype),
      ('workload_role_binding_index','service_account_id','text'::regtype),
      ('workload_role_binding_index','service_installation_id','text'::regtype),
      ('workload_role_binding_index','service_principal_id','text'::regtype),
      ('workload_role_binding_index','service_purpose','text'::regtype),
      ('service_role_session_evidence','tenant_id','text'::regtype),
      ('service_role_session_evidence','session_id','text'::regtype),
      ('service_role_session_evidence','binding_id','text'::regtype),
      ('service_role_session_evidence','binding_resource_version','bigint'::regtype),
      ('service_role_session_evidence','service_account_id','text'::regtype),
      ('service_role_session_evidence','service_installation_id','text'::regtype),
      ('service_role_session_evidence','service_principal_id','text'::regtype),
      ('service_role_session_evidence','service_purpose','text'::regtype),
      ('service_role_session_evidence','service_lookup_digest','text'::regtype),
      ('service_role_session_evidence','template_id','text'::regtype),
      ('service_role_session_evidence','template_version','bigint'::regtype),
      ('service_role_session_evidence','template_digest','text'::regtype),
      ('service_role_session_evidence','policy_id','text'::regtype),
      ('service_role_session_evidence','policy_version_id','text'::regtype),
      ('service_role_session_evidence','policy_content_digest','text'::regtype),
      ('service_role_session_evidence','workload_kind','text'::regtype),
      ('service_role_session_evidence','workload_id','text'::regtype),
      ('service_role_session_evidence','created_at','timestamptz'::regtype),
      ('service_role_session_request_index','service_account_id','text'::regtype),
      ('service_role_session_request_index','service_principal_id','text'::regtype),
      ('service_role_session_request_index','request_id','text'::regtype),
      ('service_role_session_request_index','tenant_id','text'::regtype),
      ('service_role_session_request_index','session_id','text'::regtype),
      ('service_role_session_request_index','binding_id','text'::regtype),
      ('service_role_session_request_index','expires_at','timestamptz'::regtype)
    ) expected(table_name,column_name,column_type) LOOP
      IF NOT EXISTS(SELECT 1 FROM pg_attribute column_value
        WHERE column_value.attrelid=to_regclass('iam.'||required.table_name)
          AND column_value.attname=required.column_name AND column_value.atttypid=required.column_type
          AND column_value.attnotnull AND column_value.attnum>0 AND NOT column_value.attisdropped
          AND column_value.attgenerated='' AND column_value.attidentity=''
          AND (column_value.atttypid<>'timestamptz'::regtype OR column_value.atttypmod=6)) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('workload_role_binding_index','workload_role_binding_index_valid'),
      ('service_role_session_evidence','service_role_session_evidence_valid'),
      ('service_role_session_request_index','service_role_session_request_valid')
    ) expected(table_name,constraint_name) LOOP
      IF NOT EXISTS(SELECT 1 FROM pg_constraint constraint_value
        WHERE constraint_value.conrelid=to_regclass('iam.'||required.table_name)
          AND constraint_value.conname=required.constraint_name AND constraint_value.contype='c'
          AND constraint_value.convalidated) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('iam.workload_role_binding_index','workload_role_binding_index_binding_fk','iam.workload_role_bindings',ARRAY['tenant_id','binding_id']::text[],ARRAY['tenant_id','id']::text[]),
      ('iam.workload_role_binding_index','workload_role_binding_index_relation_fk','iam.service_linked_roles',ARRAY['tenant_id','role_id']::text[],ARRAY['tenant_id','role_id']::text[]),
      ('iam.workload_role_binding_index','workload_role_binding_index_service_fk','iam.service_credentials',ARRAY['service_account_id','service_principal_id']::text[],ARRAY['tenant_id','principal_id']::text[]),
      ('iam.service_role_session_evidence','service_role_session_evidence_session_fk','iam.role_sessions',ARRAY['tenant_id','session_id']::text[],ARRAY['tenant_id','id']::text[]),
      ('iam.service_role_session_evidence','service_role_session_evidence_binding_fk','iam.workload_role_bindings',ARRAY['tenant_id','binding_id']::text[],ARRAY['tenant_id','id']::text[]),
      ('iam.service_role_session_evidence','service_role_session_evidence_service_fk','iam.service_credentials',ARRAY['service_account_id','service_principal_id']::text[],ARRAY['tenant_id','principal_id']::text[]),
      ('iam.service_role_session_evidence','service_role_session_evidence_template_fk','iam.service_role_templates',ARRAY['template_id','template_version']::text[],ARRAY['id','version']::text[]),
      ('iam.service_role_session_evidence','service_role_session_evidence_policy_fk','iam.policy_versions',ARRAY['policy_id','policy_version_id']::text[],ARRAY['policy_id','id']::text[]),
      ('iam.service_role_session_request_index','service_role_session_request_session_fk','iam.role_sessions',ARRAY['tenant_id','session_id']::text[],ARRAY['tenant_id','id']::text[]),
      ('iam.service_role_session_request_index','service_role_session_request_binding_fk','iam.workload_role_bindings',ARRAY['tenant_id','binding_id']::text[],ARRAY['tenant_id','id']::text[]),
      ('iam.service_role_session_request_index','service_role_session_request_service_fk','iam.service_credentials',ARRAY['service_account_id','service_principal_id']::text[],ARRAY['tenant_id','principal_id']::text[])
    ) expected(source_table,constraint_name,target_table,source_columns,target_columns) LOOP
      IF NOT EXISTS(SELECT 1 FROM pg_constraint constraint_value
        WHERE constraint_value.conrelid=to_regclass(required.source_table)
          AND constraint_value.conname=required.constraint_name AND constraint_value.contype='f'
          AND constraint_value.confrelid=to_regclass(required.target_table) AND constraint_value.convalidated
          AND NOT constraint_value.condeferrable AND constraint_value.confupdtype='a'
          AND constraint_value.confdeltype='a' AND constraint_value.confmatchtype='s'
          AND ARRAY(SELECT column_value.attname::text FROM unnest(constraint_value.conkey) WITH ORDINALITY key_value(number,position)
            JOIN pg_attribute column_value ON column_value.attrelid=constraint_value.conrelid
              AND column_value.attnum=key_value.number ORDER BY key_value.position)=required.source_columns
          AND ARRAY(SELECT column_value.attname::text FROM unnest(constraint_value.confkey) WITH ORDINALITY key_value(number,position)
            JOIN pg_attribute column_value ON column_value.attrelid=constraint_value.confrelid
              AND column_value.attnum=key_value.number ORDER BY key_value.position)=required.target_columns) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('iam.workload_role_binding_index',ARRAY['binding_id']::text[]),
      ('iam.service_role_session_evidence',ARRAY['tenant_id','session_id']::text[]),
      ('iam.service_role_session_request_index',ARRAY['service_account_id','service_principal_id','request_id']::text[]),
      ('iam.service_role_session_request_index',ARRAY['tenant_id','session_id']::text[])
    ) expected(table_name,column_names) LOOP
      IF NOT EXISTS(SELECT 1 FROM pg_index index_value
        WHERE index_value.indrelid=to_regclass(required.table_name) AND index_value.indisunique
          AND index_value.indisvalid AND index_value.indisready AND NOT index_value.indnullsnotdistinct
          AND index_value.indexprs IS NULL AND index_value.indpred IS NULL
          AND index_value.indnkeyatts=cardinality(required.column_names) AND index_value.indnatts=index_value.indnkeyatts
          AND ARRAY(SELECT column_value.attname::text FROM unnest(index_value.indkey) WITH ORDINALITY key_value(number,position)
            JOIN pg_attribute column_value ON column_value.attrelid=index_value.indrelid
              AND column_value.attnum=key_value.number ORDER BY key_value.position)=required.column_names) THEN RETURN false; END IF;
    END LOOP;
    IF NOT EXISTS(SELECT 1 FROM pg_index index_value
      WHERE index_value.indexrelid=to_regclass('iam.service_role_session_request_live_idx')
        AND index_value.indrelid='iam.service_role_session_request_index'::regclass
        AND NOT index_value.indisunique AND index_value.indisvalid AND index_value.indisready
        AND index_value.indexprs IS NULL AND index_value.indpred IS NULL
        AND index_value.indnkeyatts=3 AND index_value.indnatts=3
        AND ARRAY(SELECT column_value.attname::text FROM unnest(index_value.indkey) WITH ORDINALITY key_value(number,position)
          JOIN pg_attribute column_value ON column_value.attrelid=index_value.indrelid
            AND column_value.attnum=key_value.number ORDER BY key_value.position)
          =ARRAY['service_account_id','service_principal_id','expires_at'])
      OR NOT EXISTS(SELECT 1 FROM pg_index index_value
      WHERE index_value.indexrelid=to_regclass('iam.role_sessions_live_service_idx')
        AND index_value.indrelid='iam.role_sessions'::regclass
        AND NOT index_value.indisunique AND index_value.indisvalid AND index_value.indisready
        AND index_value.indexprs IS NULL AND pg_get_expr(index_value.indpred,index_value.indrelid)='(revoked_at IS NULL)'
        AND index_value.indnkeyatts=2 AND index_value.indnatts=2
        AND ARRAY(SELECT column_value.attname::text FROM unnest(index_value.indkey) WITH ORDINALITY key_value(number,position)
          JOIN pg_attribute column_value ON column_value.attrelid=index_value.indrelid
            AND column_value.attnum=key_value.number ORDER BY key_value.position)
          =ARRAY['source_service_principal_id','expires_at']) THEN RETURN false; END IF;
    FOR required IN SELECT * FROM (VALUES
      ('workload_role_binding_index','immutable_history','iam.reject_policy_history_change()',27),
      ('workload_role_binding_index','cannot_truncate','iam.reject_policy_history_change()',34),
      ('service_role_session_evidence','immutable_history','iam.reject_policy_history_change()',27),
      ('service_role_session_evidence','cannot_truncate','iam.reject_policy_history_change()',34),
      ('service_role_session_request_index','immutable_history','iam.reject_policy_history_change()',27),
      ('service_role_session_request_index','cannot_truncate','iam.reject_policy_history_change()',34)
    ) expected(table_name,trigger_name,signature,trigger_type) LOOP
      IF NOT EXISTS(SELECT 1 FROM pg_trigger trigger_value
        WHERE trigger_value.tgrelid=to_regclass('iam.'||required.table_name)
          AND trigger_value.tgname=required.trigger_name
          AND trigger_value.tgfoid=to_regprocedure(required.signature)
          AND trigger_value.tgtype=required.trigger_type AND trigger_value.tgenabled='A'
          AND NOT trigger_value.tgisinternal) THEN RETURN false; END IF;
    END LOOP;
    FOR required IN SELECT * FROM (VALUES
      ('iam.read_service_role_assumption(text,text,text)',ARRAY['service_lookup_digest','binding_id','request_id']::text[],true,true,'v'::"char"),
      ('iam.issue_service_role_session(text,text,text,jsonb,text,text,jsonb)',ARRAY['service_lookup_digest','binding_id','request_document','intent','lookup_digest','verification_digest','event']::text[],true,true,'v'::"char"),
      ('iam.read_service_role_session_by_request(text,text)',ARRAY['service_lookup_digest','request_id']::text[],true,true,'v'::"char"),
      ('iam.service_role_template_snapshot(text,bigint)',ARRAY['template_id','template_version']::text[],false,false,'s'::"char"),
      ('iam.current_service_role_source(text)',ARRAY['service_lookup_digest']::text[],false,true,'v'::"char"),
      ('iam.service_role_authorization_evidence(text,text)',ARRAY['tenant','session_id']::text[],false,false,'s'::"char"),
      ('iam.lookup_service_role_session_authority(text,text)',ARRAY['tenant','session_id']::text[],false,true,'v'::"char")
    ) expected(signature,argument_names,api_access,security_definer,volatility) LOOP
      SELECT function_value.* INTO entrypoint FROM pg_proc function_value
        WHERE function_value.oid=to_regprocedure(required.signature);
      IF NOT FOUND OR (SELECT count(*) FROM pg_proc other
          WHERE other.pronamespace=entrypoint.pronamespace AND other.proname=entrypoint.proname)<>1
        OR entrypoint.proowner<>'matrix_iam_owner'::regrole
        OR entrypoint.prosecdef IS DISTINCT FROM required.security_definer
        OR entrypoint.prorettype<>'jsonb'::regtype OR entrypoint.proretset
        OR entrypoint.pronargdefaults<>0 OR entrypoint.provariadic<>0
        OR entrypoint.provolatile<>required.volatility OR entrypoint.proparallel<>'u'
        OR entrypoint.proisstrict OR entrypoint.proleakproof
        OR entrypoint.proallargtypes IS NOT NULL OR entrypoint.proargmodes IS NOT NULL
        OR entrypoint.proargnames IS DISTINCT FROM required.argument_names
        OR entrypoint.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']
        OR has_function_privilege('matrix_iam_api',entrypoint.oid,'EXECUTE') IS DISTINCT FROM required.api_access
        OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(entrypoint.proacl,acldefault('f',entrypoint.proowner))) privilege
          WHERE privilege.grantee NOT IN (entrypoint.proowner,'matrix_iam_api'::regrole)
            OR (privilege.grantee='matrix_iam_api'::regrole
              AND (NOT required.api_access OR privilege.is_grantable))) THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END $function$;
REVOKE ALL ON FUNCTION iam.service_role_session_contract_ready()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;

CREATE OR REPLACE FUNCTION iam.service_role_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT iam.role_contract_ready()
      AND iam.service_role_session_contract_ready()
      AND EXISTS(SELECT 1 FROM pg_attribute column_value WHERE column_value.attrelid='iam.roles'::regclass
        AND column_value.attname='management' AND column_value.atttypid='text'::regtype
        AND column_value.attnotnull AND NOT column_value.attisdropped)
      AND EXISTS(SELECT 1 FROM pg_constraint constraint_value WHERE constraint_value.conrelid='iam.roles'::regclass
        AND constraint_value.conname='roles_management_valid' AND constraint_value.contype='c' AND constraint_value.convalidated)
      AND EXISTS(SELECT 1 FROM pg_index index_value WHERE index_value.indexrelid=to_regclass('iam.roles_live_customer_name_uq')
        AND index_value.indrelid='iam.roles'::regclass AND index_value.indisunique AND index_value.indisvalid AND index_value.indisready)
      AND (SELECT count(*)=3 FROM pg_class relation WHERE relation.oid IN (
        to_regclass('iam.service_role_templates'),to_regclass('iam.service_linked_roles'),to_regclass('iam.workload_role_bindings'))
        AND relation.relowner='matrix_iam_owner'::regrole
        AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) privilege
          WHERE privilege.grantee<>relation.relowner))
      AND (SELECT count(*)=2 FROM pg_class relation WHERE relation.oid IN (
        to_regclass('iam.service_linked_roles'),to_regclass('iam.workload_role_bindings'))
        AND relation.relrowsecurity AND relation.relforcerowsecurity)
      AND (SELECT count(*)=2 FROM pg_policies policy_value
        WHERE policy_value.schemaname='iam'
          AND policy_value.tablename IN ('service_linked_roles','workload_role_bindings')
          AND policy_value.policyname='tenant_isolation'
          AND policy_value.roles=ARRAY['public']::name[]
          AND policy_value.qual='(tenant_id = iam.current_tenant_id())'
          AND policy_value.with_check='(tenant_id = iam.current_tenant_id())')
      AND EXISTS(SELECT 1 FROM pg_constraint constraint_value
        WHERE constraint_value.conrelid='iam.service_role_templates'::regclass
          AND constraint_value.conname='service_role_templates_valid'
          AND constraint_value.contype='c' AND constraint_value.convalidated)
      AND EXISTS(SELECT 1 FROM pg_constraint constraint_value
        WHERE constraint_value.conrelid='iam.service_linked_roles'::regclass
          AND constraint_value.conname='service_linked_roles_principal_uq'
          AND constraint_value.contype='u' AND constraint_value.convalidated
          AND (SELECT array_agg(column_value.attname::text ORDER BY key_value.ordinality)
            FROM unnest(constraint_value.conkey) WITH ORDINALITY AS key_value(attnum,ordinality)
            JOIN pg_attribute column_value ON column_value.attrelid=constraint_value.conrelid
              AND column_value.attnum=key_value.attnum)
            =ARRAY['tenant_id','template_id','template_version','service_installation_id','service_principal_id'])
      AND (SELECT count(*)=6 FROM pg_constraint constraint_value
        WHERE constraint_value.conrelid='iam.service_linked_roles'::regclass
          AND constraint_value.contype='f' AND constraint_value.convalidated
          AND pg_get_constraintdef(constraint_value.oid,true) IN (
            'FOREIGN KEY (tenant_id, role_id) REFERENCES iam.roles(tenant_id, id)',
            'FOREIGN KEY (template_id, template_version) REFERENCES iam.service_role_templates(id, version)',
            'FOREIGN KEY (service_account_id, service_principal_id) REFERENCES iam.service_credentials(tenant_id, principal_id)',
            'FOREIGN KEY (policy_id, policy_version_id) REFERENCES iam.policy_versions(policy_id, id)',
            'FOREIGN KEY (tenant_id, role_creation_decision_id) REFERENCES iam.authorization_decisions(tenant_id, id)',
            'FOREIGN KEY (tenant_id, role_pass_decision_id) REFERENCES iam.authorization_decisions(tenant_id, id)'))
      AND EXISTS(SELECT 1 FROM pg_constraint constraint_value
        WHERE constraint_value.conrelid='iam.service_linked_roles'::regclass
          AND constraint_value.conname='service_linked_roles_valid'
          AND constraint_value.contype='c' AND constraint_value.convalidated)
      AND EXISTS(SELECT 1 FROM pg_constraint constraint_value
        WHERE constraint_value.conrelid='iam.workload_role_bindings'::regclass
          AND constraint_value.contype='u' AND constraint_value.convalidated
          AND (SELECT array_agg(column_value.attname::text ORDER BY key_value.ordinality)
            FROM unnest(constraint_value.conkey) WITH ORDINALITY AS key_value(attnum,ordinality)
            JOIN pg_attribute column_value ON column_value.attrelid=constraint_value.conrelid
              AND column_value.attnum=key_value.attnum)
            =ARRAY['tenant_id','request_id'])
      AND (SELECT count(*)=3 FROM pg_constraint constraint_value
        WHERE constraint_value.conrelid='iam.workload_role_bindings'::regclass
          AND constraint_value.contype='f' AND constraint_value.convalidated
          AND pg_get_constraintdef(constraint_value.oid,true) IN (
            'FOREIGN KEY (tenant_id, role_id) REFERENCES iam.service_linked_roles(tenant_id, role_id)',
            'FOREIGN KEY (template_id, template_version) REFERENCES iam.service_role_templates(id, version)',
            'FOREIGN KEY (tenant_id, workload_decision_id) REFERENCES iam.authorization_decisions(tenant_id, id)'))
      AND EXISTS(SELECT 1 FROM pg_constraint constraint_value
        WHERE constraint_value.conrelid='iam.workload_role_bindings'::regclass
          AND constraint_value.conname='workload_role_bindings_valid'
          AND constraint_value.contype='c' AND constraint_value.convalidated)
      AND EXISTS(SELECT 1 FROM pg_index index_value
        WHERE index_value.indexrelid=to_regclass('iam.workload_role_bindings_active_uq')
          AND index_value.indrelid='iam.workload_role_bindings'::regclass
          AND index_value.indisunique AND index_value.indisvalid AND index_value.indisready
          AND (SELECT array_agg(column_value.attname::text ORDER BY key_value.ordinality)
            FROM unnest(index_value.indkey) WITH ORDINALITY AS key_value(attnum,ordinality)
            JOIN pg_attribute column_value ON column_value.attrelid=index_value.indrelid
              AND column_value.attnum=key_value.attnum)
            =ARRAY['tenant_id','template_id','template_version','workload_kind','workload_id']
          AND pg_get_expr(index_value.indpred,index_value.indrelid)='(revoked_at IS NULL)')
      AND EXISTS(SELECT 1 FROM pg_index index_value
        WHERE index_value.indexrelid=to_regclass('iam.workload_role_bindings_role_directory_idx')
          AND index_value.indrelid='iam.workload_role_bindings'::regclass
          AND NOT index_value.indisunique AND index_value.indisvalid AND index_value.indisready
          AND index_value.indnkeyatts=3 AND index_value.indnatts=3
          AND index_value.indpred IS NULL AND index_value.indexprs IS NULL
          AND (SELECT array_agg(column_value.attname::text ORDER BY key_value.ordinality)
            FROM unnest(index_value.indkey) WITH ORDINALITY AS key_value(attnum,ordinality)
            JOIN pg_attribute column_value ON column_value.attrelid=index_value.indrelid
              AND column_value.attnum=key_value.attnum)
            =ARRAY['tenant_id','role_id','id'])
      AND EXISTS(SELECT 1 FROM pg_proc function_value WHERE function_value.oid=to_regprocedure(
        'iam.lock_workload_role_binding_sources(text,text,text,text,text)')
        AND function_value.proowner='matrix_iam_owner'::regrole AND function_value.prosecdef
        AND function_value.prorettype='boolean'::regtype AND NOT function_value.proretset
        AND function_value.proargnames=ARRAY['tenant','actor','actor_session','service_lookup_digest','service_purpose']
        AND function_value.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND has_function_privilege('matrix_iam_api',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_worker',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_credential_recovery',function_value.oid,'EXECUTE'))
      AND EXISTS(SELECT 1 FROM pg_proc function_value WHERE function_value.oid=to_regprocedure(
        'iam.create_workload_role_binding(text,text,text,text,text,text,jsonb,jsonb,jsonb,jsonb,text,text,text,jsonb,jsonb)')
        AND function_value.proowner='matrix_iam_owner'::regrole AND function_value.prosecdef
        AND function_value.prorettype='jsonb'::regtype AND NOT function_value.proretset
        AND function_value.proargnames=ARRAY['tenant','actor','actor_session','service_lookup_digest','request_document','request_digest',
          'template','role_value','trust','binding','workload_decision','role_creation_decision','role_pass_decision','role_event','binding_event']
        AND function_value.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND has_function_privilege('matrix_iam_api',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_worker',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_credential_recovery',function_value.oid,'EXECUTE'))
      AND EXISTS(SELECT 1 FROM pg_proc function_value WHERE function_value.oid=to_regprocedure(
        'iam.prepare_workload_role_binding_revocation(text,text,text,text)')
        AND function_value.proowner='matrix_iam_owner'::regrole AND function_value.prosecdef
        AND function_value.prorettype='jsonb'::regtype AND NOT function_value.proretset
        AND function_value.proargnames=ARRAY['tenant','binding_id','service_lookup_digest','service_purpose']
        AND function_value.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND has_function_privilege('matrix_iam_api',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_worker',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_credential_recovery',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_backup_custody',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_notification_worker',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_authentication_recovery',function_value.oid,'EXECUTE'))
      AND EXISTS(SELECT 1 FROM pg_proc function_value WHERE function_value.oid=to_regprocedure(
        'iam.revoke_workload_role_binding(text,text,text,text,text,text,text,text,text,text,text,jsonb)')
        AND function_value.proowner='matrix_iam_owner'::regrole AND function_value.prosecdef
        AND function_value.prorettype='jsonb'::regtype AND NOT function_value.proretset
        AND function_value.proargnames=ARRAY['tenant','actor','actor_session','service_lookup_digest','service_purpose','binding_id',
          'request_document','request_digest','workload_decision','binding_revoke_decision','role_pass_decision','binding_event']
        AND function_value.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND has_function_privilege('matrix_iam_api',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_worker',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_credential_recovery',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_backup_custody',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_notification_worker',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_authentication_recovery',function_value.oid,'EXECUTE'))
      AND EXISTS(SELECT 1 FROM pg_proc function_value WHERE function_value.oid=to_regprocedure(
        'iam.list_service_linked_roles(text,text,text,text)')
        AND function_value.proowner='matrix_iam_owner'::regrole AND function_value.prosecdef
        AND function_value.prorettype='jsonb'::regtype AND NOT function_value.proretset
        AND function_value.proargnames=ARRAY['tenant','actor','decision','after_id']
        AND function_value.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND has_function_privilege('matrix_iam_api',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_worker',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_credential_recovery',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_backup_custody',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_notification_worker',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_authentication_recovery',function_value.oid,'EXECUTE'))
      AND EXISTS(SELECT 1 FROM pg_proc function_value WHERE function_value.oid=to_regprocedure(
        'iam.read_service_linked_role(text,text,text,text,text)')
        AND function_value.proowner='matrix_iam_owner'::regrole AND function_value.prosecdef
        AND function_value.prorettype='jsonb'::regtype AND NOT function_value.proretset
        AND function_value.proargnames=ARRAY['tenant','actor','decision','role_id','after_id']
        AND function_value.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND has_function_privilege('matrix_iam_api',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_worker',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_credential_recovery',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_backup_custody',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_notification_worker',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_authentication_recovery',function_value.oid,'EXECUTE'))
      AND (SELECT count(*)=2 FROM pg_proc function_value WHERE function_value.oid IN (
          to_regprocedure('iam.service_linked_role_snapshot(text,text)'),
          to_regprocedure('iam.workload_role_binding_snapshot(text,text)'))
        AND function_value.proowner='matrix_iam_owner'::regrole AND NOT function_value.prosecdef
        AND function_value.prorettype='jsonb'::regtype AND NOT function_value.proretset
        AND function_value.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND NOT has_function_privilege('matrix_iam_api',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_worker',function_value.oid,'EXECUTE')
        AND NOT has_function_privilege('matrix_iam_credential_recovery',function_value.oid,'EXECUTE'))
      AND EXISTS(SELECT 1 FROM pg_trigger trigger_value WHERE trigger_value.tgrelid='iam.policy_attachments'::regclass
        AND trigger_value.tgname='policy_attachments_reject_service_roles' AND trigger_value.tgenabled='A'
        AND trigger_value.tgfoid=to_regprocedure('iam.guard_customer_role_policy_attachment()'))
      AND EXISTS(SELECT 1 FROM pg_trigger trigger_value WHERE trigger_value.tgrelid='iam.service_role_templates'::regclass
        AND trigger_value.tgname='service_role_template_transitions' AND trigger_value.tgenabled='A'
        AND trigger_value.tgfoid=to_regprocedure('iam.guard_service_role_template_change()'))
      AND EXISTS(SELECT 1 FROM pg_trigger trigger_value WHERE trigger_value.tgrelid='iam.service_linked_roles'::regclass
        AND trigger_value.tgname='service_linked_roles_are_immutable' AND NOT trigger_value.tgisinternal
        AND trigger_value.tgenabled='A' AND trigger_value.tgtype=27
        AND trigger_value.tgfoid=to_regprocedure('iam.guard_service_linked_role_change()'))
      AND EXISTS(SELECT 1 FROM pg_trigger trigger_value WHERE trigger_value.tgrelid='iam.workload_role_bindings'::regclass
        AND trigger_value.tgname='workload_role_binding_transitions' AND NOT trigger_value.tgisinternal
        AND trigger_value.tgenabled='A' AND trigger_value.tgtype=31
        AND trigger_value.tgfoid=to_regprocedure('iam.guard_workload_role_binding_change()'))
      AND (SELECT count(*)=2 FROM pg_trigger trigger_value
        WHERE trigger_value.tgrelid IN ('iam.service_linked_roles'::regclass,'iam.workload_role_bindings'::regclass)
          AND trigger_value.tgname='cannot_truncate' AND NOT trigger_value.tgisinternal
          AND trigger_value.tgenabled='A' AND trigger_value.tgtype=34
          AND trigger_value.tgfoid=to_regprocedure('iam.reject_policy_history_change()'))
$function$;
REVOKE ALL ON FUNCTION iam.service_role_contract_ready()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;

-- Keep the predecessor readiness callable private so replay can still run the
-- earlier in-transaction checks before this final contract becomes current.
DO $service_role_readiness_cutover$
BEGIN
    IF to_regprocedure('iam.readiness_v53()') IS NOT NULL THEN DROP FUNCTION iam.readiness_v53(); END IF;
    ALTER FUNCTION iam.readiness() RENAME TO readiness_v53;
END $service_role_readiness_cutover$;
REVOKE ALL ON FUNCTION iam.readiness_v53() FROM PUBLIC,matrix_iam_api,matrix_iam_worker,
  matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery;
CREATE FUNCTION iam.readiness()
RETURNS TABLE(ready boolean,schema_version bigint,checked_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE predecessor record;
BEGIN
    SELECT * INTO predecessor FROM iam.readiness_v53();
    RETURN QUERY SELECT predecessor.ready AND iam.service_role_contract_ready(),56::bigint,predecessor.checked_at;
END $function$;
REVOKE ALL ON FUNCTION iam.readiness() FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,
  matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery;
GRANT EXECUTE ON FUNCTION iam.readiness() TO matrix_iam_api;
