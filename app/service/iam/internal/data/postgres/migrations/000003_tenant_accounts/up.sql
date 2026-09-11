SET LOCAL ROLE matrix_iam_owner;

-- Credential lookup indexes are deliberately separate from account ownership.
-- They contain no secrets and have no PUBLIC or runtime table grants.
DO $login_index_key_cutover$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint AS pk
        WHERE pk.conrelid='iam.login_index'::regclass AND pk.contype='p'
          AND (SELECT array_agg(attribute.attname ORDER BY key.ordinality)
               FROM unnest(pk.conkey) WITH ORDINALITY AS key(attnum,ordinality)
               JOIN pg_catalog.pg_attribute AS attribute
                 ON attribute.attrelid=pk.conrelid AND attribute.attnum=key.attnum)
              = ARRAY['tenant_id','login_name']::name[]
    ) THEN
        IF to_regclass('iam.account_roots') IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM login index conflicts with root relation';
        END IF;
        ALTER TABLE iam.login_index DROP CONSTRAINT IF EXISTS login_index_pkey;
        ALTER TABLE iam.login_index ADD PRIMARY KEY (tenant_id, login_name);
    END IF;
END $login_index_key_cutover$;

CREATE TABLE IF NOT EXISTS iam.account_roots (
    account_id text COLLATE "C" PRIMARY KEY REFERENCES iam.accounts(id),
    principal_id text COLLATE "C" NOT NULL,
    login_name text COLLATE "C" NOT NULL UNIQUE,
    CONSTRAINT account_roots_principal_fk FOREIGN KEY(account_id,principal_id)
        REFERENCES iam.principals(tenant_id,id),
    CONSTRAINT account_roots_login_fk FOREIGN KEY(account_id,login_name)
        REFERENCES iam.login_index(tenant_id,login_name),
    CONSTRAINT account_roots_values_valid CHECK (
        account_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND principal_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND login_name COLLATE "C" ~ '^[a-z][a-z0-9._-]{2,63}$')
);

-- The migration owner must inspect every retained Account and USER while the
-- old tables already enforce tenant RLS. These policies exist only inside the
-- surrounding migration transaction and are removed before commit.
DROP POLICY IF EXISTS account_root_cutover_owner_read ON iam.accounts;
CREATE POLICY account_root_cutover_owner_read ON iam.accounts
    FOR SELECT TO matrix_iam_owner USING (true);
DROP POLICY IF EXISTS account_root_cutover_owner_read ON iam.principals;
CREATE POLICY account_root_cutover_owner_read ON iam.principals
    FOR SELECT TO matrix_iam_owner USING (true);

DO $root_relation_cutover$
BEGIN
    IF EXISTS(SELECT 1 FROM pg_catalog.pg_attribute
        WHERE attrelid='iam.login_index'::regclass AND attname='account_owner' AND NOT attisdropped) THEN
        EXECUTE 'INSERT INTO iam.account_roots(account_id,principal_id,login_name)
            SELECT tenant_id,principal_id,login_name FROM iam.login_index WHERE account_owner
            ON CONFLICT(account_id) DO NOTHING';
        IF EXISTS(SELECT 1 FROM iam.login_index AS login WHERE login.account_owner
            AND NOT EXISTS(SELECT 1 FROM iam.account_roots AS root
                WHERE root.account_id=login.tenant_id AND root.principal_id=login.principal_id
                    AND root.login_name=login.login_name)) THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM root relation conflicts';
        END IF;
        DROP INDEX IF EXISTS iam.login_primary_name_uq;
        DROP INDEX IF EXISTS iam.login_primary_tenant_uq;
        ALTER TABLE iam.login_index DROP COLUMN account_owner;
    END IF;

    -- The original single-account release predates account_owner. Its sealed
    -- bootstrap receipt is the authoritative relation between the home
    -- Account and original primary USER; the login index supplies only that
    -- USER's immutable login name.
    INSERT INTO iam.account_roots(account_id,principal_id,login_name)
    SELECT receipt.organization_id,receipt.administrator_principal_id,login.login_name
      FROM iam.bootstrap_receipts AS receipt
      JOIN iam.login_index AS login
        ON login.tenant_id=receipt.organization_id
       AND login.principal_id=receipt.administrator_principal_id
      JOIN iam.principals AS principal
        ON principal.tenant_id=login.tenant_id AND principal.id=login.principal_id
       AND principal.principal_type='USER' AND principal.login_name=login.login_name
    ON CONFLICT(account_id) DO NOTHING;

    IF EXISTS (
        SELECT 1 FROM iam.bootstrap_receipts AS receipt
        LEFT JOIN iam.account_roots AS root ON root.account_id=receipt.organization_id
        WHERE root.principal_id IS DISTINCT FROM receipt.administrator_principal_id
    ) OR EXISTS (
        SELECT 1 FROM iam.accounts AS account
        LEFT JOIN iam.account_roots AS root ON root.account_id=account.id
        WHERE root.account_id IS NULL
    ) OR EXISTS (
        SELECT 1 FROM iam.account_roots AS root
        JOIN iam.principals AS principal
          ON principal.tenant_id=root.account_id AND principal.id=root.principal_id
        LEFT JOIN iam.login_index AS login
          ON login.tenant_id=root.account_id AND login.principal_id=root.principal_id
         AND login.login_name=root.login_name
        WHERE principal.principal_type<>'USER' OR principal.login_name<>root.login_name
           OR login.principal_id IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='IAM root relation is incomplete or conflicts';
    END IF;
END $root_relation_cutover$;

DROP POLICY account_root_cutover_owner_read ON iam.principals;
DROP POLICY account_root_cutover_owner_read ON iam.accounts;

CREATE TABLE IF NOT EXISTS iam.account_aliases (
    alias text COLLATE "C" PRIMARY KEY,
    tenant_id text COLLATE "C" NOT NULL REFERENCES iam.accounts (id),
    active boolean NOT NULL,
    CONSTRAINT account_alias_valid CHECK (alias COLLATE "C" ~ '^[a-z][a-z0-9-]{1,61}[a-z0-9]$')
);
CREATE UNIQUE INDEX IF NOT EXISTS account_alias_active_uq ON iam.account_aliases (tenant_id) WHERE active;

DROP FUNCTION IF EXISTS iam.is_bootstrap_administrator(text,text);

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
		SELECT login.* INTO indexed FROM iam.account_roots AS root
		JOIN iam.login_index AS login ON login.tenant_id=root.account_id AND login.principal_id=root.principal_id
			AND login.login_name=root.login_name WHERE root.login_name=local_name;
    ELSE
        SELECT count(DISTINCT candidates.id), min(candidates.id) INTO tenant_count, target_tenant
        FROM (
			SELECT root.account_id AS id FROM iam.account_roots AS root
			WHERE root.account_id = account_name
            UNION
            SELECT alias.tenant_id FROM iam.account_aliases AS alias
            WHERE alias.alias = account_name AND alias.active
        ) AS candidates;
        IF tenant_count <> 1 THEN RETURN; END IF;
		SELECT * INTO indexed FROM iam.login_index AS login
		WHERE login.tenant_id = target_tenant AND login.login_name = local_name
			AND NOT EXISTS(SELECT 1 FROM iam.account_roots AS root
				WHERE root.account_id=login.tenant_id AND root.principal_id=login.principal_id);
    END IF;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM set_config('matrix.iam_tenant_id', indexed.tenant_id, true);
    RETURN QUERY SELECT organization.id, principal.id, credential.password_hash,
        organization.status, principal.status, principal.must_change_password
    FROM iam.accounts AS organization
    JOIN iam.principals AS principal ON principal.tenant_id = organization.id AND principal.id = indexed.principal_id
    JOIN iam.user_credentials AS credential ON credential.tenant_id = principal.tenant_id AND credential.principal_id = principal.id
    WHERE organization.id = indexed.tenant_id AND principal.login_name = local_name AND principal.principal_type = 'USER';
END
$function$;

-- A registered tenant alone is not append authority. Historical facts are
-- read from this IAM installation only; current producer credentials remain
-- mandatory, while original user/session/tenant activation is not reevaluated.
DROP FUNCTION IF EXISTS iam.can_produce_audit(text,text,text,text);
CREATE INDEX IF NOT EXISTS audit_outbox_decision_fact_idx
ON iam.audit_outbox (tenant_id,(event_document->>'iamDecisionId'))
WHERE event_document->>'action'='iam.authorization.decided';
CREATE OR REPLACE FUNCTION iam.read_audit_evidence(origin_tenant text, producer text,
    producer_purpose text, producer_installation text, event jsonb)
RETURNS TABLE (installation_id text, event_document jsonb, decision_document jsonb, verifier_principal_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE
    proof_tenant text;
    sealed_installation text;
    verifier_id text;
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',origin_tenant,true);
    SELECT receipt.installation_id INTO sealed_installation FROM iam.bootstrap_receipts AS receipt
    WHERE receipt.organization_id=origin_tenant AND receipt.installation_id=producer_installation;
    IF NOT FOUND OR producer_purpose NOT IN ('IAM','PAAS','AUDIT')
        OR NOT EXISTS(SELECT 1 FROM iam.service_credentials AS credential
            JOIN iam.principals AS principal ON principal.tenant_id=credential.tenant_id AND principal.id=credential.principal_id
            JOIN iam.accounts AS organization ON organization.id=credential.tenant_id
            WHERE credential.tenant_id=origin_tenant AND credential.principal_id=producer
                AND credential.purpose=producer_purpose AND credential.revoked_at IS NULL
                AND principal.principal_type='SERVICE_ACCOUNT' AND principal.status='ACTIVE' AND organization.status='ACTIVE') THEN RETURN; END IF;
    IF event ? 'installationId' THEN
        IF event ? 'tenantId' OR event->>'installationId' IS DISTINCT FROM sealed_installation THEN RETURN; END IF;
        proof_tenant := origin_tenant;
    ELSE
        proof_tenant := event->>'tenantId';
        IF NOT EXISTS(SELECT 1 FROM iam.account_roots AS root WHERE root.account_id=proof_tenant) THEN RETURN; END IF;
    END IF;
    -- The original verifier actor remains historical evidence even after its
    -- own credential is revoked. It is never the producer's current credential.
    SELECT credential.principal_id INTO verifier_id FROM iam.service_credentials AS credential
    WHERE credential.tenant_id=origin_tenant AND credential.purpose='INSTALLATION_VERIFIER';
    PERFORM set_config('matrix.iam_tenant_id',proof_tenant,true);
    IF producer_purpose='IAM' THEN
        RETURN QUERY SELECT sealed_installation, outbox.event_document, NULL::jsonb, verifier_id
        FROM iam.audit_outbox AS outbox WHERE outbox.tenant_id=proof_tenant AND outbox.event_id=event->>'eventId';
    ELSE
        RETURN QUERY SELECT sealed_installation, outbox.event_document, decision.document, verifier_id
        FROM iam.authorization_decisions AS decision
        JOIN iam.audit_outbox AS outbox ON outbox.tenant_id=decision.tenant_id
            AND outbox.event_document->>'action'='iam.authorization.decided'
            AND outbox.event_document->>'iamDecisionId'=decision.id
        WHERE decision.tenant_id=proof_tenant AND decision.id=event->>'iamDecisionId' AND decision.allowed;
    END IF;
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
        'apiVersion','iam.matrix.xiak.com/v1','kind','Account',
        'id',account.id,'displayName',account.display_name,'status',account.status,
        'rootIdentity',jsonb_build_object('principalId',root.principal_id,'loginName',root.login_name),
        'loginAlias',(SELECT alias.alias FROM iam.account_aliases AS alias WHERE alias.tenant_id=tenant AND alias.active),
        'resourceVersion',account.resource_version,'createdAt',account.created_at,'updatedAt',account.updated_at
    ) INTO result FROM iam.accounts AS account
    JOIN iam.account_roots AS root ON root.account_id=account.id
    WHERE account.id=tenant;
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.user_snapshot(tenant text, user_id text)
RETURNS jsonb LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $function$
    SELECT jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','User',
        'id',p.id,'accountId',p.tenant_id,'loginName',p.login_name,
        'displayName',p.display_name,'status',p.status,'mustChangePassword',p.must_change_password,
        'resourceVersion',p.resource_version,'createdAt',p.created_at,'updatedAt',p.updated_at)
    FROM iam.principals AS p WHERE p.tenant_id=tenant AND p.id=user_id AND p.principal_type='USER'
$function$;

CREATE OR REPLACE FUNCTION iam.read_account(tenant text, principal text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id', tenant, true);
    IF NOT EXISTS (SELECT 1 FROM iam.principals AS p JOIN iam.accounts AS o ON o.id = p.tenant_id
        WHERE p.tenant_id = tenant AND p.id = principal AND p.principal_type = 'USER'
        AND p.status = 'ACTIVE' AND o.status = 'ACTIVE') THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account is unavailable';
    END IF;
    RETURN iam.account_snapshot(tenant);
END
$function$;

CREATE OR REPLACE FUNCTION iam.list_users(tenant text, actor text, decision text, after_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.user.list','ACCOUNT',tenant);
    PERFORM set_config('matrix.iam_tenant_id', tenant, true);
    IF after_id IS NULL OR (after_id <> '' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='page boundary is invalid';
    END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('user',iam.user_snapshot(tenant,p.id),
		'policyAttachments',COALESCE((SELECT jsonb_agg(iam.lookup_policy_attachment(tenant,b.id) ORDER BY b.id)
			FROM (SELECT a.id FROM iam.policy_attachments AS a WHERE a.tenant_id=tenant
				AND a.principal_id=p.id AND a.revoked_at IS NULL
                ORDER BY a.id LIMIT 257) AS b),'[]'::jsonb))
        ORDER BY p.id),'[]'::jsonb) INTO result
    FROM (SELECT principal.id FROM iam.principals AS principal WHERE principal.tenant_id=tenant
        AND principal.principal_type='USER' AND principal.id > after_id COLLATE "C"
        AND NOT EXISTS(SELECT 1 FROM iam.account_roots AS root
            WHERE root.account_id=tenant AND root.principal_id=principal.id)
        ORDER BY principal.id LIMIT 101) AS p;
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.list_accounts(tenant text, actor text, decision text, after_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb := '[]'::jsonb; candidate record;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account.read','ACCOUNT','accounts');
    IF after_id IS NULL OR (after_id <> '' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='page boundary is invalid';
    END IF;
    FOR candidate IN SELECT root.account_id FROM iam.account_roots AS root
        WHERE root.account_id > after_id COLLATE "C" ORDER BY root.account_id LIMIT 101 LOOP
        result := result || jsonb_build_array(iam.account_snapshot(candidate.account_id));
    END LOOP;
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.read_account_as_platform(tenant text, actor text, decision text, target_tenant text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account.read','ACCOUNT',target_tenant);
    result := iam.account_snapshot(target_tenant);
    IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account is unavailable'; END IF;
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.read_account_root(tenant text, actor text, decision text, target_tenant text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account.recover-root-credentials','ACCOUNT',target_tenant);
    PERFORM set_config('matrix.iam_tenant_id',target_tenant,true);
    SELECT jsonb_build_object('principalId',root.principal_id,'loginName',root.login_name)
      INTO result FROM iam.account_roots AS root WHERE root.account_id=target_tenant;
    IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account root is unavailable'; END IF;
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
    IF event->>'iamDecisionId' IS DISTINCT FROM decision
        OR NOT EXISTS(SELECT 1 FROM iam.authorization_decisions AS original
            WHERE original.tenant_id=tenant AND original.id=decision AND original.principal_id=actor
                AND original.request_id=event->>'requestId' AND original.request_id=event->>'correlationId'
                AND original.decided_at=transaction_timestamp()) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='account decision correlation is invalid';
    END IF;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
    VALUES(tenant,event->>'eventId',event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
END
$function$;

CREATE OR REPLACE FUNCTION iam.create_account(tenant text, actor text, decision text,
    new_id text, display_name text, primary_id text, login_name text, primary_name text, password_hash text, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE result jsonb; effective_now timestamptz := transaction_timestamp();
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account.create','ACCOUNT',new_id);
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
    INSERT INTO iam.accounts(id,display_name,status,resource_version,created_at,updated_at)
    VALUES(new_id,display_name,'ACTIVE',1,effective_now,effective_now);
    INSERT INTO iam.principals(tenant_id,id,principal_type,login_name,display_name,status,
        must_change_password,resource_version,created_at,updated_at)
    VALUES(new_id,primary_id,'USER',login_name,primary_name,'ACTIVE',true,1,effective_now,effective_now);
    INSERT INTO iam.user_credentials(tenant_id,principal_id,password_hash,changed_at)
    VALUES(new_id,primary_id,password_hash,effective_now);
    INSERT INTO iam.login_index(login_name,tenant_id,principal_id) VALUES(login_name,new_id,primary_id);
    INSERT INTO iam.account_roots(account_id,principal_id,login_name) VALUES(new_id,primary_id,login_name);
    INSERT INTO iam.policy_attachments(tenant_id,id,principal_id,policy_id,resource_version,created_at,updated_at)
    VALUES(new_id,'primary-admin-binding',primary_id,'system.account-administrator',1,effective_now,effective_now);
    result := iam.account_snapshot(new_id);
    PERFORM iam.append_account_event(tenant,actor,decision,'iam.account.created','ACCOUNT',new_id,event);
    RETURN result;
END
$function$;

CREATE OR REPLACE FUNCTION iam.set_account_status(tenant text, actor text, decision text,
    target_tenant text, new_status text, expected_version bigint, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE stored iam.accounts%ROWTYPE;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account.set-status','ACCOUNT',target_tenant);
    IF new_status IS NULL OR new_status NOT IN ('ACTIVE','DISABLED') OR expected_version IS NULL OR expected_version < 1 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='account status change is invalid';
    END IF;
    IF new_status='DISABLED' AND EXISTS(SELECT 1 FROM iam.bootstrap_receipts AS receipt WHERE receipt.organization_id=target_tenant) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='installation service account is protected';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',target_tenant,true);
    SELECT * INTO stored FROM iam.accounts AS account WHERE account.id=target_tenant FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account is unavailable'; END IF;
    IF stored.resource_version <> expected_version THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='account version conflicts';
    END IF;
    IF stored.status=new_status THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='account status already matches'; END IF;
    UPDATE iam.accounts AS account SET status=new_status,resource_version=account.resource_version+1,updated_at=transaction_timestamp()
    WHERE account.id=target_tenant;
    IF new_status='DISABLED' THEN
        UPDATE iam.sessions AS session SET status='REVOKED',revoked_at=transaction_timestamp(),resource_version=session.resource_version+1
        WHERE session.tenant_id=target_tenant AND session.status='ACTIVE';
    END IF;
    PERFORM iam.append_account_event(tenant,actor,decision,
        CASE WHEN new_status='DISABLED' THEN 'iam.account.disabled' ELSE 'iam.account.enabled' END,'ACCOUNT',target_tenant,event);
    RETURN iam.account_snapshot(target_tenant);
END
$function$;

CREATE OR REPLACE FUNCTION iam.recover_root_credentials(tenant text, actor text, decision text,
    target_tenant text, primary_id text, expected_version bigint, new_password_hash text, new_binding_id text, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE stored_version bigint;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account.recover-root-credentials','ACCOUNT',target_tenant);
    IF expected_version IS NULL OR expected_version < 1 OR new_password_hash IS NULL
        OR new_password_hash NOT LIKE '$matrix-iam-v1$argon2id$v=19$%'
        OR event#>>'{target,tenantId}' IS DISTINCT FROM target_tenant
        OR COALESCE(new_binding_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='root credential recovery is invalid';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',target_tenant,true);
    SELECT account.resource_version INTO stored_version FROM iam.accounts AS account WHERE account.id=target_tenant FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='account is unavailable'; END IF;
    IF stored_version <> expected_version THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='account version conflicts'; END IF;
    -- Serialize all credential takeover checks with platform grants on this USER.
    PERFORM 1 FROM iam.account_roots AS root JOIN iam.principals AS principal
        ON principal.tenant_id=root.account_id AND principal.id=root.principal_id
        WHERE root.account_id=target_tenant AND root.principal_id=primary_id
          AND principal.principal_type='USER' FOR UPDATE OF principal;
    IF NOT FOUND OR EXISTS(SELECT 1 FROM iam.policy_attachments AS binding WHERE binding.tenant_id=target_tenant
        AND binding.principal_id=primary_id AND binding.authority_scope='INSTALLATION' AND binding.revoked_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='root credential recovery is forbidden';
    END IF;
    UPDATE iam.principals AS principal SET status='ACTIVE',must_change_password=true,
        resource_version=principal.resource_version+1,updated_at=transaction_timestamp()
    WHERE principal.tenant_id=target_tenant AND principal.id=primary_id;
    UPDATE iam.user_credentials AS credential SET password_hash=new_password_hash,changed_at=transaction_timestamp(),
        credential_version=credential.credential_version+1
    WHERE credential.tenant_id=target_tenant AND credential.principal_id=primary_id;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='primary credential is unavailable'; END IF;
    UPDATE iam.sessions AS session SET status='REVOKED',revoked_at=transaction_timestamp(),resource_version=session.resource_version+1
    WHERE session.tenant_id=target_tenant AND session.principal_id=primary_id AND session.status='ACTIVE';
    INSERT INTO iam.policy_attachments(tenant_id,id,principal_id,policy_id,resource_version,created_at,updated_at)
    SELECT target_tenant,new_binding_id,primary_id,'system.account-administrator',1,transaction_timestamp(),transaction_timestamp()
    WHERE NOT EXISTS(SELECT 1 FROM iam.policy_attachments AS binding WHERE binding.tenant_id=target_tenant
        AND binding.principal_id=primary_id AND binding.policy_id='system.account-administrator' AND binding.revoked_at IS NULL);
    UPDATE iam.accounts AS account SET resource_version=account.resource_version+1,updated_at=transaction_timestamp()
    WHERE account.id=target_tenant;
    PERFORM iam.append_account_event(tenant,actor,decision,'iam.account-root.credentials-recovered','USER',primary_id,event);
    RETURN iam.account_snapshot(target_tenant);
END
$function$;

CREATE OR REPLACE FUNCTION iam.set_account_alias(tenant text, actor text, decision text,
    new_alias text, expected_version bigint, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE stored_version bigint;
BEGIN
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.account.alias-set','ACCOUNT',tenant);
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    IF new_alias IS NULL OR new_alias COLLATE "C" !~ '^[a-z][a-z0-9-]{1,61}[a-z0-9]$'
        OR expected_version IS NULL OR expected_version < 1 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='account alias is invalid';
    END IF;
    SELECT o.resource_version INTO stored_version FROM iam.accounts AS o WHERE o.id=tenant FOR UPDATE;
    IF stored_version IS DISTINCT FROM expected_version THEN
        RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='account version changed';
    END IF;
    IF EXISTS(SELECT 1 FROM iam.account_roots AS root WHERE root.account_id=new_alias AND root.account_id<>tenant)
        OR EXISTS(SELECT 1 FROM iam.account_aliases AS alias WHERE alias.alias=new_alias AND alias.tenant_id<>tenant) THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='account alias is reserved';
    END IF;
    UPDATE iam.account_aliases AS alias SET active=false WHERE alias.tenant_id=tenant AND alias.active;
    INSERT INTO iam.account_aliases(alias,tenant_id,active) VALUES(new_alias,tenant,true)
    ON CONFLICT(alias) DO UPDATE SET active=true WHERE iam.account_aliases.tenant_id=EXCLUDED.tenant_id;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='account alias is reserved'; END IF;
    UPDATE iam.accounts AS o SET resource_version=o.resource_version+1,updated_at=transaction_timestamp() WHERE o.id=tenant;
    PERFORM iam.append_account_event(tenant,actor,decision,'iam.account.alias-set','ACCOUNT',tenant,event);
    RETURN iam.account_snapshot(tenant);
END
$function$;

CREATE OR REPLACE FUNCTION iam.change_user(tenant text, actor text, decision text,
    user_id text, expected_version bigint, new_status text, new_password_hash text, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $function$
DECLARE stored iam.principals%ROWTYPE; action text; event_action text;
BEGIN
    IF (new_status IS NULL) = (new_password_hash IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='user change is invalid';
    END IF;
    IF new_status IS NOT NULL THEN action := 'iam.user.set-status'; event_action := 'iam.user.status-set';
    ELSE action := 'iam.user.reset-password'; event_action := 'iam.user.password-reset'; END IF;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,action,'USER',user_id);
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts AS organization
        WHERE organization.id=tenant AND organization.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='user account is unavailable';
    END IF;
    SELECT * INTO stored FROM iam.principals AS p WHERE p.tenant_id=tenant AND p.id=user_id FOR UPDATE;
    IF NOT FOUND OR stored.principal_type <> 'USER' OR user_id=actor
        OR EXISTS(SELECT 1 FROM iam.account_roots AS root WHERE root.account_id=tenant AND root.principal_id=user_id)
        OR EXISTS(SELECT 1 FROM iam.policy_attachments AS binding
            WHERE binding.tenant_id=tenant AND binding.principal_id=user_id
              AND binding.authority_scope='INSTALLATION' AND binding.revoked_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='user is not manageable';
    END IF;
    IF expected_version IS NULL OR expected_version < 1 OR expected_version <> stored.resource_version THEN
        RAISE EXCEPTION USING ERRCODE='P0002', MESSAGE='user version changed';
    END IF;
    IF (new_status IS NOT NULL AND new_status NOT IN ('ACTIVE','DISABLED'))
        OR (new_password_hash IS NOT NULL AND new_password_hash NOT LIKE '$matrix-iam-v1$argon2id$v=19$%') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='user change is invalid';
    END IF;
    UPDATE iam.principals AS p SET status=COALESCE(new_status,p.status),
        must_change_password=CASE WHEN new_password_hash IS NULL THEN p.must_change_password ELSE true END,
        resource_version=p.resource_version+1,updated_at=transaction_timestamp() WHERE p.tenant_id=tenant AND p.id=user_id;
    IF new_password_hash IS NOT NULL THEN
        UPDATE iam.user_credentials AS c SET password_hash=new_password_hash,changed_at=transaction_timestamp(),
            credential_version=c.credential_version+1
        WHERE c.tenant_id=tenant AND c.principal_id=user_id;
    END IF;
    UPDATE iam.sessions AS s SET status='REVOKED',revoked_at=transaction_timestamp(),resource_version=s.resource_version+1
    WHERE s.tenant_id=tenant AND s.principal_id=user_id AND s.status='ACTIVE';
    PERFORM iam.append_account_event(tenant,actor,decision,event_action,'USER',user_id,event);
    RETURN iam.user_snapshot(tenant,user_id);
END
$function$;

DROP FUNCTION IF EXISTS iam.read_organization(text,text,text,text);
DROP FUNCTION IF EXISTS iam.set_organization_status(text,text,text,text,text,bigint,jsonb);
DROP FUNCTION IF EXISTS iam.recover_organization_administrator(text,text,text,text,text,bigint,text,text,jsonb);
DROP FUNCTION IF EXISTS iam.list_principals(text,text,text,text);
DROP FUNCTION IF EXISTS iam.create_organization(text,text,text,text,text,text,text,text,text,jsonb);
DROP FUNCTION IF EXISTS iam.change_subaccount(text,text,text,text,bigint,text,text,jsonb);
DROP FUNCTION IF EXISTS iam.principal_snapshot(text,text);

REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM PUBLIC, matrix_iam_api, matrix_iam_worker;
REVOKE ALL ON FUNCTION iam.account_snapshot(text), iam.user_snapshot(text,text),
    iam.append_account_event(text,text,text,text,text,text,jsonb) FROM PUBLIC, matrix_iam_api, matrix_iam_worker;
REVOKE ALL ON FUNCTION iam.read_account(text,text), iam.read_account_as_platform(text,text,text,text),
    iam.read_account_root(text,text,text,text), iam.set_account_status(text,text,text,text,text,bigint,jsonb),
    iam.recover_root_credentials(text,text,text,text,text,bigint,text,text,jsonb),
    iam.read_audit_evidence(text,text,text,text,jsonb),
    iam.list_users(text,text,text,text), iam.list_accounts(text,text,text,text),
    iam.create_account(text,text,text,text,text,text,text,text,text,jsonb),
    iam.set_account_alias(text,text,text,text,bigint,jsonb),
    iam.change_user(text,text,text,text,bigint,text,text,jsonb) FROM PUBLIC, matrix_iam_worker;
GRANT EXECUTE ON FUNCTION iam.read_account(text,text), iam.read_account_as_platform(text,text,text,text),
    iam.read_account_root(text,text,text,text), iam.set_account_status(text,text,text,text,text,bigint,jsonb),
    iam.recover_root_credentials(text,text,text,text,text,bigint,text,text,jsonb),
    iam.read_audit_evidence(text,text,text,text,jsonb),
    iam.list_users(text,text,text,text), iam.list_accounts(text,text,text,text),
    iam.create_account(text,text,text,text,text,text,text,text,text,jsonb),
    iam.set_account_alias(text,text,text,text,bigint,jsonb),
    iam.change_user(text,text,text,text,bigint,text,text,jsonb) TO matrix_iam_api;
