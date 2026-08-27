BEGIN;
SET LOCAL ROLE matrix_iam_owner;

-- Credential lookup indexes are deliberately separate from tenant data. They
-- contain no secrets and have no PUBLIC or runtime table grants.
ALTER TABLE iam.login_index ADD COLUMN IF NOT EXISTS account_owner boolean NOT NULL DEFAULT false;
ALTER TABLE iam.login_index DROP CONSTRAINT IF EXISTS login_index_pkey;
ALTER TABLE iam.login_index ADD PRIMARY KEY (tenant_id, login_name);
UPDATE iam.login_index AS login SET account_owner = true
FROM iam.bootstrap_receipts AS receipt
WHERE login.tenant_id = receipt.organization_id
  AND login.principal_id = receipt.administrator_principal_id;
CREATE UNIQUE INDEX IF NOT EXISTS login_primary_name_uq ON iam.login_index (login_name) WHERE account_owner;
CREATE UNIQUE INDEX IF NOT EXISTS login_primary_tenant_uq ON iam.login_index (tenant_id) WHERE account_owner;

CREATE TABLE IF NOT EXISTS iam.account_aliases (
    alias text COLLATE "C" PRIMARY KEY,
    tenant_id text COLLATE "C" NOT NULL REFERENCES iam.organizations (id),
    active boolean NOT NULL,
    CONSTRAINT account_alias_valid CHECK (alias COLLATE "C" ~ '^[a-z][a-z0-9-]{1,61}[a-z0-9]$')
);
CREATE UNIQUE INDEX IF NOT EXISTS account_alias_active_uq ON iam.account_aliases (tenant_id) WHERE active;

CREATE OR REPLACE FUNCTION iam.is_bootstrap_administrator(tenant text, principal text)
RETURNS boolean LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $function$
    SELECT EXISTS (SELECT 1 FROM iam.bootstrap_receipts AS receipt
        WHERE receipt.organization_id = tenant AND receipt.administrator_principal_id = principal)
$function$;

CREATE OR REPLACE FUNCTION iam.lookup_login(submitted_login_name text)
RETURNS TABLE (tenant_id text, principal_id text, password_hash text,
    organization_status text, principal_status text, must_change_password boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE
    indexed iam.login_index%ROWTYPE;
    local_name text := split_part(submitted_login_name, '@', 1);
    account_name text := split_part(submitted_login_name, '@', 2);
    target_tenant text;
    tenant_count integer;
BEGIN
    IF submitted_login_name IS NULL OR submitted_login_name COLLATE "C"
        !~ '^[a-z][a-z0-9._-]{2,63}(@[A-Za-z0-9][A-Za-z0-9._:-]{0,127})?$' THEN RETURN; END IF;
    IF strpos(submitted_login_name, '@') = 0 THEN
        SELECT * INTO indexed FROM iam.login_index AS login
        WHERE login.login_name = local_name AND login.account_owner;
    ELSE
        SELECT count(DISTINCT candidates.id), min(candidates.id) INTO tenant_count, target_tenant
        FROM (
            SELECT login.tenant_id AS id FROM iam.login_index AS login
            WHERE login.account_owner AND login.tenant_id = account_name
            UNION
            SELECT alias.tenant_id FROM iam.account_aliases AS alias
            WHERE alias.alias = account_name AND alias.active
        ) AS candidates;
        IF tenant_count <> 1 THEN RETURN; END IF;
        SELECT * INTO indexed FROM iam.login_index AS login
        WHERE login.tenant_id = target_tenant AND login.login_name = local_name AND NOT login.account_owner;
    END IF;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM set_config('matrix.iam_tenant_id', indexed.tenant_id, true);
    RETURN QUERY SELECT organization.id, principal.id, credential.password_hash,
        organization.status, principal.status, principal.must_change_password
    FROM iam.organizations AS organization
    JOIN iam.principals AS principal ON principal.tenant_id = organization.id AND principal.id = indexed.principal_id
    JOIN iam.user_credentials AS credential ON credential.tenant_id = principal.tenant_id AND credential.principal_id = principal.id
    WHERE organization.id = indexed.tenant_id AND principal.login_name = local_name AND principal.principal_type = 'USER';
END
$function$;

-- Installation services produce audit for all registered accounts, but retain
-- their own identity. This function grants no user or resource authority.
CREATE OR REPLACE FUNCTION iam.can_produce_audit(origin_tenant text, producer text, producer_purpose text, event_tenant text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',origin_tenant,true);
    RETURN producer_purpose IN ('IAM','PAAS','AUDIT')
        AND EXISTS(SELECT 1 FROM iam.bootstrap_receipts AS receipt WHERE receipt.organization_id=origin_tenant)
        AND EXISTS(SELECT 1 FROM iam.service_credentials AS credential
            JOIN iam.principals AS principal ON principal.tenant_id=credential.tenant_id AND principal.id=credential.principal_id
            JOIN iam.organizations AS organization ON organization.id=credential.tenant_id
            WHERE credential.tenant_id=origin_tenant AND credential.principal_id=producer
                AND credential.purpose=producer_purpose AND credential.revoked_at IS NULL
                AND principal.principal_type='SERVICE_ACCOUNT' AND principal.status='ACTIVE' AND organization.status='ACTIVE')
        AND EXISTS(SELECT 1 FROM iam.login_index AS login WHERE login.tenant_id=event_tenant AND login.account_owner);
END
$function$;

-- Private projections name every public field; table rows and credentials are
-- never serialized wholesale. Callers set an exact tenant before using them.
CREATE OR REPLACE FUNCTION iam.account_snapshot(tenant text)
RETURNS jsonb LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM set_config('matrix.iam_tenant_id', tenant, true);
    SELECT jsonb_build_object(
        'organization', jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','Organization',
            'id',o.id,'displayName',o.display_name,'status',o.status,'resourceVersion',o.resource_version,
            'createdAt',o.created_at,'updatedAt',o.updated_at),
        'primaryPrincipalId',login.principal_id,'primaryLoginName',login.login_name,
        'loginAlias',(SELECT alias.alias FROM iam.account_aliases AS alias WHERE alias.tenant_id = tenant AND alias.active)
    ) INTO result FROM iam.organizations AS o
    JOIN iam.login_index AS login ON login.tenant_id = o.id AND login.account_owner
    WHERE o.id = tenant;
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.principal_snapshot(tenant text, principal text)
RETURNS jsonb LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $function$
    SELECT jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','Principal',
        'id',p.id,'organizationId',p.tenant_id,'type',p.principal_type,'loginName',p.login_name,
        'displayName',p.display_name,'status',p.status,'mustChangePassword',p.must_change_password,
        'resourceVersion',p.resource_version,'createdAt',p.created_at,'updatedAt',p.updated_at)
    FROM iam.principals AS p WHERE p.tenant_id = tenant AND p.id = principal AND p.principal_type = 'USER'
$function$;

CREATE OR REPLACE FUNCTION iam.read_account(tenant text, principal text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id', tenant, true);
    IF NOT EXISTS (SELECT 1 FROM iam.principals AS p JOIN iam.organizations AS o ON o.id = p.tenant_id
        WHERE p.tenant_id = tenant AND p.id = principal AND p.principal_type = 'USER'
        AND p.status = 'ACTIVE' AND o.status = 'ACTIVE') THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account is unavailable';
    END IF;
    RETURN iam.account_snapshot(tenant);
END
$function$;

CREATE OR REPLACE FUNCTION iam.list_principals(tenant text, actor text, decision text, after_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.principal.list','ORGANIZATION',tenant);
    PERFORM set_config('matrix.iam_tenant_id', tenant, true);
    IF after_id IS NULL OR (after_id <> '' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='page boundary is invalid';
    END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('principal',iam.principal_snapshot(tenant,p.id),
        'roleBindings',COALESCE((SELECT jsonb_agg(jsonb_build_object(
            'apiVersion','iam.matrix.xiak.com/v1','kind','RoleBinding','id',b.id,'organizationId',b.tenant_id,
            'principalId',b.principal_id,'role',b.role_name,'resourceVersion',b.resource_version,
            'createdAt',b.created_at,'updatedAt',b.updated_at) ORDER BY b.id)
            FROM iam.role_bindings AS b WHERE b.tenant_id=tenant AND b.principal_id=p.id AND b.revoked_at IS NULL),'[]'::jsonb))
        ORDER BY p.id),'[]'::jsonb) INTO result
    FROM (SELECT principal.id FROM iam.principals AS principal WHERE principal.tenant_id=tenant
        AND principal.principal_type='USER' AND principal.id > after_id COLLATE "C" ORDER BY principal.id LIMIT 101) AS p;
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.list_accounts(tenant text, actor text, decision text, after_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb := '[]'::jsonb; candidate record;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.organization.read','ORGANIZATION',tenant);
    IF NOT iam.is_bootstrap_administrator(tenant,actor) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account directory is forbidden';
    END IF;
    IF after_id IS NULL OR (after_id <> '' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='page boundary is invalid';
    END IF;
    FOR candidate IN SELECT login.tenant_id FROM iam.login_index AS login
        WHERE login.account_owner AND login.tenant_id > after_id COLLATE "C" ORDER BY login.tenant_id LIMIT 101 LOOP
        result := result || jsonb_build_array(iam.account_snapshot(candidate.tenant_id));
    END LOOP;
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.append_account_event(tenant text, actor text, decision text,
    action text, target_kind text, target_id text, event jsonb)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM iam.assert_audit_event(event,tenant,action,target_kind,target_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='account decision correlation is invalid';
    END IF;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
    VALUES(tenant,event->>'eventId',event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
END
$function$;

CREATE OR REPLACE FUNCTION iam.create_organization(tenant text, actor text, decision text,
    new_id text, display_name text, primary_id text, login_name text, primary_name text, password_hash text, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb; effective_now timestamptz := transaction_timestamp();
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.organization.create','ORGANIZATION',new_id);
    IF NOT iam.is_bootstrap_administrator(tenant,actor) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account opening is forbidden';
    END IF;
    IF new_id IS NULL OR primary_id IS NULL OR login_name IS NULL OR password_hash IS NULL
        OR new_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR primary_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR login_name COLLATE "C" !~ '^[a-z][a-z0-9._-]{2,63}$'
        OR password_hash NOT LIKE '$matrix-iam-v1$argon2id$v=19$%'
        OR length(display_name) NOT BETWEEN 1 AND 128 OR btrim(display_name) <> display_name
        OR length(primary_name) NOT BETWEEN 1 AND 128 OR btrim(primary_name) <> primary_name THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='account opening is invalid';
    END IF;
    IF EXISTS (SELECT 1 FROM iam.account_aliases AS alias WHERE alias.alias=new_id) THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='account namespace is reserved';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',new_id,true);
    INSERT INTO iam.organizations(id,display_name,status,resource_version,created_at,updated_at)
    VALUES(new_id,display_name,'ACTIVE',1,effective_now,effective_now);
    INSERT INTO iam.principals(tenant_id,id,principal_type,login_name,display_name,status,
        must_change_password,resource_version,created_at,updated_at)
    VALUES(new_id,primary_id,'USER',login_name,primary_name,'ACTIVE',true,1,effective_now,effective_now);
    INSERT INTO iam.user_credentials(tenant_id,principal_id,password_hash,changed_at)
    VALUES(new_id,primary_id,password_hash,effective_now);
    INSERT INTO iam.login_index(login_name,tenant_id,principal_id,account_owner) VALUES(login_name,new_id,primary_id,true);
    INSERT INTO iam.role_bindings(tenant_id,id,principal_id,role_name,resource_version,created_at,updated_at)
    VALUES(new_id,'primary-admin-binding',primary_id,'ORGANIZATION_ADMIN',1,effective_now,effective_now);
    result := iam.account_snapshot(new_id);
    PERFORM iam.append_account_event(tenant,actor,decision,'iam.organization.created','ORGANIZATION',new_id,event);
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.set_account_alias(tenant text, actor text, decision text,
    new_alias text, expected_version bigint, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE stored_version bigint;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account-alias.set','ORGANIZATION',tenant);
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    IF new_alias IS NULL OR new_alias COLLATE "C" !~ '^[a-z][a-z0-9-]{1,61}[a-z0-9]$'
        OR expected_version IS NULL OR expected_version < 1 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='account alias is invalid';
    END IF;
    SELECT o.resource_version INTO stored_version FROM iam.organizations AS o WHERE o.id=tenant FOR UPDATE;
    IF stored_version IS DISTINCT FROM expected_version THEN
        RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='account version changed';
    END IF;
    IF EXISTS(SELECT 1 FROM iam.login_index AS login WHERE login.account_owner AND login.tenant_id=new_alias AND login.tenant_id<>tenant)
        OR EXISTS(SELECT 1 FROM iam.account_aliases AS alias WHERE alias.alias=new_alias AND alias.tenant_id<>tenant) THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='account alias is reserved';
    END IF;
    UPDATE iam.account_aliases AS alias SET active=false WHERE alias.tenant_id=tenant AND alias.active;
    INSERT INTO iam.account_aliases(alias,tenant_id,active) VALUES(new_alias,tenant,true)
    ON CONFLICT(alias) DO UPDATE SET active=true WHERE iam.account_aliases.tenant_id=EXCLUDED.tenant_id;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='account alias is reserved'; END IF;
    UPDATE iam.organizations AS o SET resource_version=o.resource_version+1,updated_at=transaction_timestamp() WHERE o.id=tenant;
    PERFORM iam.append_account_event(tenant,actor,decision,'iam.account-alias.set','ORGANIZATION',tenant,event);
    RETURN iam.account_snapshot(tenant);
END
$function$;

CREATE OR REPLACE FUNCTION iam.change_subaccount(tenant text, actor text, decision text,
    principal text, expected_version bigint, new_status text, new_password_hash text, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE stored iam.principals%ROWTYPE; action text; event_action text;
BEGIN
    IF (new_status IS NULL) = (new_password_hash IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='subaccount change is invalid';
    END IF;
    IF new_status IS NOT NULL THEN action := 'iam.principal.set-status'; event_action := 'iam.principal.status-set';
    ELSE action := 'iam.password.reset'; event_action := 'iam.password.reset'; END IF;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,action,'PRINCIPAL',principal);
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    SELECT * INTO stored FROM iam.principals AS p WHERE p.tenant_id=tenant AND p.id=principal FOR UPDATE;
    IF NOT FOUND OR stored.principal_type <> 'USER' OR principal=actor
        OR EXISTS(SELECT 1 FROM iam.login_index AS login WHERE login.tenant_id=tenant AND login.principal_id=principal AND login.account_owner)
        OR EXISTS(SELECT 1 FROM iam.role_bindings AS binding
            WHERE binding.tenant_id=tenant AND binding.principal_id=principal
              AND binding.role_name='PLATFORM_OPERATOR' AND binding.revoked_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='subaccount is not manageable';
    END IF;
    IF expected_version IS NULL OR expected_version < 1 OR expected_version <> stored.resource_version THEN
        RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='subaccount version changed';
    END IF;
    IF (new_status IS NOT NULL AND new_status NOT IN ('ACTIVE','DISABLED'))
        OR (new_password_hash IS NOT NULL AND new_password_hash NOT LIKE '$matrix-iam-v1$argon2id$v=19$%') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='subaccount change is invalid';
    END IF;
    UPDATE iam.principals AS p SET status=COALESCE(new_status,p.status),
        must_change_password=CASE WHEN new_password_hash IS NULL THEN p.must_change_password ELSE true END,
        resource_version=p.resource_version+1,updated_at=transaction_timestamp() WHERE p.tenant_id=tenant AND p.id=principal;
    IF new_password_hash IS NOT NULL THEN
        UPDATE iam.user_credentials AS c SET password_hash=new_password_hash,changed_at=transaction_timestamp()
        WHERE c.tenant_id=tenant AND c.principal_id=principal;
    END IF;
    UPDATE iam.sessions AS s SET status='REVOKED',revoked_at=transaction_timestamp(),resource_version=s.resource_version+1
    WHERE s.tenant_id=tenant AND s.principal_id=principal AND s.status='ACTIVE';
    PERFORM iam.append_account_event(tenant,actor,decision,event_action,'PRINCIPAL',principal,event);
    RETURN iam.principal_snapshot(tenant,principal);
END
$function$;

REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM PUBLIC, matrix_iam_api, matrix_iam_worker;
REVOKE ALL ON FUNCTION iam.account_snapshot(text), iam.principal_snapshot(text,text),
    iam.append_account_event(text,text,text,text,text,text,jsonb) FROM PUBLIC, matrix_iam_api, matrix_iam_worker;
REVOKE ALL ON FUNCTION iam.is_bootstrap_administrator(text,text), iam.read_account(text,text),
    iam.can_produce_audit(text,text,text,text),
    iam.list_principals(text,text,text,text), iam.list_accounts(text,text,text,text),
    iam.create_organization(text,text,text,text,text,text,text,text,text,jsonb),
    iam.set_account_alias(text,text,text,text,bigint,jsonb),
    iam.change_subaccount(text,text,text,text,bigint,text,text,jsonb) FROM PUBLIC, matrix_iam_worker;
GRANT EXECUTE ON FUNCTION iam.is_bootstrap_administrator(text,text), iam.read_account(text,text),
    iam.can_produce_audit(text,text,text,text),
    iam.list_principals(text,text,text,text), iam.list_accounts(text,text,text,text),
    iam.create_organization(text,text,text,text,text,text,text,text,text,jsonb),
    iam.set_account_alias(text,text,text,text,bigint,jsonb),
    iam.change_subaccount(text,text,text,text,bigint,text,text,jsonb) TO matrix_iam_api;
COMMIT;
