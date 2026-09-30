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
            AND template.status=seed->>'status') THEN
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
    FOREACH relation_name IN ARRAY ARRAY['service_linked_roles','workload_role_bindings'] LOOP
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
        INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
          VALUES(tenant,binding_event->>'eventId',binding_event,effective_now,effective_now,effective_now);
    END IF;
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','ServiceLinkedRoleAccess',
      'relation',iam.service_linked_role_snapshot(tenant,expected_role_id),
      'bindings',jsonb_build_array(iam.workload_role_binding_snapshot(tenant,expected_binding_id)));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_datetime_format OR datetime_field_overflow THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='workload role binding command is invalid';
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

REVOKE ALL ON iam.service_role_templates,iam.service_linked_roles,iam.workload_role_bindings
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.guard_service_role_template_change(),iam.guard_service_linked_role_change(),
  iam.guard_workload_role_binding_change(),iam.guard_customer_role_policy_attachment(),
  iam.service_linked_role_snapshot(text,text),iam.workload_role_binding_snapshot(text,text)
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.lock_workload_role_binding_sources(text,text,text,text,text)
  FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.create_workload_role_binding(text,text,text,text,text,text,jsonb,jsonb,jsonb,jsonb,text,text,text,jsonb,jsonb)
  FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
REVOKE ALL ON FUNCTION iam.list_service_linked_roles(text,text,text,text),
  iam.read_service_linked_role(text,text,text,text,text)
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery;
GRANT EXECUTE ON FUNCTION iam.lock_workload_role_binding_sources(text,text,text,text,text) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.create_workload_role_binding(text,text,text,text,text,text,jsonb,jsonb,jsonb,jsonb,text,text,text,jsonb,jsonb)
  TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.list_service_linked_roles(text,text,text,text),
  iam.read_service_linked_role(text,text,text,text,text) TO matrix_iam_api;

CREATE OR REPLACE FUNCTION iam.service_role_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT iam.role_contract_ready()
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
    RETURN QUERY SELECT predecessor.ready AND iam.service_role_contract_ready(),54::bigint,predecessor.checked_at;
END $function$;
REVOKE ALL ON FUNCTION iam.readiness() FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,
  matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery;
GRANT EXECUTE ON FUNCTION iam.readiness() TO matrix_iam_api;
