BEGIN;
SET LOCAL ROLE matrix_iam_owner;

-- A completion is purpose-specific security evidence, not a generic command
-- journal. It contains no password/hash, capability, issuing key or DSN.
CREATE TABLE IF NOT EXISTS iam.local_credential_recoveries (
    tenant_id text COLLATE "C" NOT NULL,
    installation_id text COLLATE "C" NOT NULL,
    primary_principal_id text COLLATE "C" NOT NULL,
    bootstrap_digest text COLLATE "C" NOT NULL,
    command_id text COLLATE "C" PRIMARY KEY,
    input_commitment text COLLATE "C" NOT NULL,
    expected_state jsonb NOT NULL,
    completed_result jsonb NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    completed_at timestamptz(6) NOT NULL,
    FOREIGN KEY (tenant_id, primary_principal_id) REFERENCES iam.principals(tenant_id, id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES iam.audit_outbox(tenant_id, event_id),
    UNIQUE (tenant_id, event_id),
    CONSTRAINT local_credential_recovery_values_valid CHECK (
        command_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND input_commitment ~ '^sha256:[0-9a-f]{64}$'
        AND bootstrap_digest ~ '^sha256:[0-9a-f]{64}$'
        AND jsonb_typeof(expected_state) = 'object'
        AND jsonb_typeof(completed_result) = 'object'
        AND completed_result->>'commandId' = command_id
        AND completed_result->>'inputCommitment' = input_commitment
        AND completed_result->>'auditEventId' = event_id
        AND completed_result->>'state' = 'APPLIED'
    )
);

ALTER TABLE iam.local_credential_recoveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.local_credential_recoveries FORCE ROW LEVEL SECURITY;
DO $local_recovery_policy$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policies WHERE schemaname='iam'
        AND tablename='local_credential_recoveries' AND policyname='tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON iam.local_credential_recoveries
            USING (tenant_id=iam.current_tenant_id()) WITH CHECK (tenant_id=iam.current_tenant_id());
    END IF;
END
$local_recovery_policy$;

CREATE OR REPLACE FUNCTION iam.reject_local_recovery_receipt_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='local recovery completion is immutable';
END
$function$;

CREATE OR REPLACE TRIGGER local_recovery_receipts_are_immutable
BEFORE UPDATE OR DELETE ON iam.local_credential_recoveries
FOR EACH ROW EXECUTE FUNCTION iam.reject_local_recovery_receipt_change();
CREATE OR REPLACE TRIGGER local_recovery_receipts_cannot_be_truncated
BEFORE TRUNCATE ON iam.local_credential_recoveries
FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_local_recovery_receipt_change();
ALTER TABLE iam.local_credential_recoveries ENABLE ALWAYS TRIGGER local_recovery_receipts_are_immutable;
ALTER TABLE iam.local_credential_recoveries ENABLE ALWAYS TRIGGER local_recovery_receipts_cannot_be_truncated;

CREATE OR REPLACE FUNCTION iam.assert_local_recovery_scope(scope jsonb)
RETURNS void LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF jsonb_typeof(scope) IS DISTINCT FROM 'object'
        OR NOT (scope ?& ARRAY['installationId','bootstrapDigest','organizationId','principalId'])
        OR (scope - ARRAY['installationId','bootstrapDigest','organizationId','principalId']) <> '{}'::jsonb
        OR jsonb_typeof(scope->'installationId') IS DISTINCT FROM 'string'
        OR jsonb_typeof(scope->'bootstrapDigest') IS DISTINCT FROM 'string'
        OR jsonb_typeof(scope->'organizationId') IS DISTINCT FROM 'string'
        OR jsonb_typeof(scope->'principalId') IS DISTINCT FROM 'string'
        OR NOT EXISTS (SELECT 1 FROM iam.bootstrap_receipts AS sealed WHERE sealed.singleton
            AND sealed.installation_id=scope->>'installationId'
            AND sealed.content_digest=scope->>'bootstrapDigest'
            AND sealed.organization_id=scope->>'organizationId'
            AND sealed.administrator_principal_id=scope->>'principalId') THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='local recovery scope is forbidden';
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',scope->>'organizationId',true);
END
$function$;

CREATE OR REPLACE FUNCTION iam.inspect_local_credential_recovery(
    scope jsonb, submitted_command_id text, submitted_input_commitment text)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE
    stored iam.local_credential_recoveries%ROWTYPE;
    expected jsonb;
    result jsonb;
BEGIN
    PERFORM iam.assert_local_recovery_scope(scope);
    result := jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1',
        'kind','LocalCredentialRecoveryInspection','scope',scope);
    IF submitted_command_id IS NOT NULL OR submitted_input_commitment IS NOT NULL THEN
        IF submitted_command_id IS NULL OR submitted_command_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            OR submitted_input_commitment IS NULL OR submitted_input_commitment COLLATE "C" !~ '^sha256:[0-9a-f]{64}$' THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='local recovery receipt query is invalid';
        END IF;
        result := result || jsonb_build_object('commandId',submitted_command_id,'inputCommitment',submitted_input_commitment);
        SELECT * INTO stored FROM iam.local_credential_recoveries AS receipt WHERE receipt.command_id=submitted_command_id;
        IF NOT FOUND THEN RETURN result || jsonb_build_object('state','NOT_FOUND'); END IF;
        IF stored.input_commitment IS DISTINCT FROM submitted_input_commitment
            OR stored.completed_result->'scope' IS DISTINCT FROM scope THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='local recovery intent conflicts';
        END IF;
        -- Historical completion is independent of today's principal/binding.
        RETURN result || jsonb_build_object('state','COMPLETED','expected',stored.expected_state,'result',stored.completed_result);
    END IF;
    SELECT jsonb_build_object('organizationResourceVersion',organization.resource_version,
        'principalResourceVersion',principal.resource_version,'credentialGeneration',credential.credential_version,
        'platformBindingId',binding.id,'platformBindingResourceVersion',binding.resource_version)
      INTO expected FROM iam.organizations AS organization
      JOIN iam.principals AS principal ON principal.tenant_id=organization.id
      JOIN iam.login_index AS login ON login.tenant_id=principal.tenant_id AND login.principal_id=principal.id AND login.account_owner
      JOIN iam.user_credentials AS credential ON credential.tenant_id=principal.tenant_id AND credential.principal_id=principal.id
      JOIN iam.role_bindings AS binding ON binding.tenant_id=principal.tenant_id AND binding.principal_id=principal.id
       AND binding.role_name='PLATFORM_OPERATOR' AND binding.revoked_at IS NULL
     WHERE organization.id=scope->>'organizationId' AND organization.status='ACTIVE'
       AND principal.id=scope->>'principalId' AND principal.principal_type='USER' AND principal.status='ACTIVE'
       AND credential.credential_version BETWEEN 1 AND 9007199254740990
       AND principal.resource_version BETWEEN 1 AND 9007199254740990;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='local recovery is ineligible'; END IF;
    RETURN result || jsonb_build_object('state','ELIGIBLE','expected',expected);
END
$function$;

CREATE OR REPLACE FUNCTION iam.recover_local_credentials(scope jsonb, expected jsonb,
    submitted_command_id text, submitted_input_commitment text, new_password_hash text, event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE
    stored iam.local_credential_recoveries%ROWTYPE;
    binding iam.role_bindings%ROWTYPE;
    principal iam.principals%ROWTYPE;
    organization iam.organizations%ROWTYPE;
    generation bigint;
    revoked_count bigint;
    version_name text;
    result jsonb;
BEGIN
    PERFORM iam.assert_local_recovery_scope(scope);
    IF submitted_command_id IS NULL OR submitted_command_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR submitted_input_commitment IS NULL OR submitted_input_commitment COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
        OR new_password_hash IS NULL OR new_password_hash COLLATE "C"
            !~ '^\$matrix-iam-v1\$argon2id\$v=19\$m=65536,t=3,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$'
        OR jsonb_typeof(expected) IS DISTINCT FROM 'object'
        OR NOT (expected ?& ARRAY['organizationResourceVersion','principalResourceVersion',
            'credentialGeneration','platformBindingId','platformBindingResourceVersion'])
        OR (expected - ARRAY['organizationResourceVersion','principalResourceVersion',
            'credentialGeneration','platformBindingId','platformBindingResourceVersion']) <> '{}'::jsonb
        OR jsonb_typeof(expected->'platformBindingId') IS DISTINCT FROM 'string'
        OR COALESCE(expected->>'platformBindingId','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='local recovery intent is invalid';
    END IF;
    FOREACH version_name IN ARRAY ARRAY['organizationResourceVersion','principalResourceVersion',
        'credentialGeneration','platformBindingResourceVersion'] LOOP
        IF jsonb_typeof(expected->version_name) IS DISTINCT FROM 'number'
            OR (expected->>version_name) COLLATE "C" !~ '^[1-9][0-9]{0,15}$' THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='local recovery version is invalid';
        END IF;
        IF (expected->>version_name)::bigint > 9007199254740991
            OR (version_name IN ('principalResourceVersion','credentialGeneration')
                AND (expected->>version_name)::bigint = 9007199254740991) THEN
            RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='local recovery version is invalid';
        END IF;
    END LOOP;
    SELECT * INTO stored FROM iam.local_credential_recoveries AS receipt WHERE receipt.command_id=submitted_command_id;
    IF FOUND THEN
        IF stored.input_commitment IS DISTINCT FROM submitted_input_commitment
            OR stored.completed_result->'scope' IS DISTINCT FROM scope
            OR stored.expected_state IS DISTINCT FROM expected THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='local recovery intent conflicts';
        END IF;
        RETURN stored.completed_result || jsonb_build_object('state','EQUAL_REPLAY');
    END IF;
    -- The actual platform binding is locked before its target principal, as
    -- in revoke_role_binding. Grants/password changes serialize on principal.
    SELECT * INTO binding FROM iam.role_bindings AS candidate
     WHERE candidate.tenant_id=scope->>'organizationId' AND candidate.id=expected->>'platformBindingId'
       AND candidate.principal_id=scope->>'principalId' AND candidate.role_name='PLATFORM_OPERATOR'
     FOR UPDATE;
    IF NOT FOUND OR binding.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='local recovery platform binding is ineligible';
    END IF;
    SELECT * INTO organization FROM iam.organizations AS candidate WHERE candidate.id=scope->>'organizationId' FOR UPDATE;
    IF NOT FOUND OR organization.status <> 'ACTIVE' THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='local recovery organization is ineligible';
    END IF;
    SELECT * INTO principal FROM iam.principals AS candidate
     WHERE candidate.tenant_id=scope->>'organizationId' AND candidate.id=scope->>'principalId' FOR UPDATE;
    IF NOT FOUND OR principal.principal_type <> 'USER' OR principal.status <> 'ACTIVE'
        OR NOT EXISTS (SELECT 1 FROM iam.login_index AS login WHERE login.tenant_id=principal.tenant_id
            AND login.principal_id=principal.id AND login.account_owner) THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='local recovery primary is ineligible';
    END IF;
    SELECT credential.credential_version INTO generation FROM iam.user_credentials AS credential
     WHERE credential.tenant_id=principal.tenant_id AND credential.principal_id=principal.id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='local recovery credential is unavailable'; END IF;
    IF generation IS DISTINCT FROM (expected->>'credentialGeneration')::bigint
        OR principal.resource_version IS DISTINCT FROM (expected->>'principalResourceVersion')::bigint
        OR organization.resource_version IS DISTINCT FROM (expected->>'organizationResourceVersion')::bigint
        OR binding.resource_version IS DISTINCT FROM (expected->>'platformBindingResourceVersion')::bigint THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='local recovery expected state conflicts';
    END IF;
    PERFORM iam.assert_audit_event(event,principal.tenant_id,'iam.installation-primary.credentials-recovered','PRINCIPAL',principal.id,'SUCCEEDED');
    IF event->>'requestId' IS DISTINCT FROM submitted_command_id
        OR event->>'correlationId' IS DISTINCT FROM submitted_command_id
        OR event#>>'{target,tenantId}' IS DISTINCT FROM principal.tenant_id THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='local recovery audit correlation is invalid';
    END IF;
    UPDATE iam.user_credentials AS credential SET password_hash=new_password_hash,
        credential_version=generation+1,changed_at=transaction_timestamp()
     WHERE credential.tenant_id=principal.tenant_id AND credential.principal_id=principal.id;
    UPDATE iam.principals AS candidate SET must_change_password=true,
        resource_version=principal.resource_version+1,updated_at=transaction_timestamp()
     WHERE candidate.tenant_id=principal.tenant_id AND candidate.id=principal.id;
    UPDATE iam.sessions AS session SET status='REVOKED',revoked_at=transaction_timestamp(),resource_version=session.resource_version+1
     WHERE session.tenant_id=principal.tenant_id AND session.principal_id=principal.id AND session.status='ACTIVE';
    GET DIAGNOSTICS revoked_count = ROW_COUNT;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
    VALUES(principal.tenant_id,event->>'eventId',event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
    result := jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','LocalCredentialRecoveryResult',
        'state','APPLIED','commandId',submitted_command_id,'inputCommitment',submitted_input_commitment,'scope',scope,
        'previousCredentialGeneration',generation,'credentialGeneration',generation+1,
        'principalResourceVersion',principal.resource_version+1,'revokedSessions',revoked_count,
        'auditEventId',event->>'eventId','completedAt',transaction_timestamp());
    INSERT INTO iam.local_credential_recoveries(tenant_id,installation_id,primary_principal_id,bootstrap_digest,
        command_id,input_commitment,expected_state,completed_result,event_id,completed_at)
    VALUES(principal.tenant_id,scope->>'installationId',principal.id,scope->>'bootstrapDigest',submitted_command_id,
        submitted_input_commitment,expected,result,event->>'eventId',transaction_timestamp());
    RETURN result;
END
$function$;

REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM matrix_iam_credential_recovery;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA iam FROM matrix_iam_credential_recovery;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA iam FROM matrix_iam_credential_recovery;
REVOKE ALL ON iam.local_credential_recoveries FROM PUBLIC,matrix_iam_api,matrix_iam_worker;
REVOKE ALL ON FUNCTION iam.assert_local_recovery_scope(jsonb),iam.reject_local_recovery_receipt_change(),
    iam.inspect_local_credential_recovery(jsonb,text,text),iam.recover_local_credentials(jsonb,jsonb,text,text,text,jsonb)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker;
GRANT USAGE ON SCHEMA iam TO matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.inspect_local_credential_recovery(jsonb,text,text),
    iam.recover_local_credentials(jsonb,jsonb,text,text,text,jsonb) TO matrix_iam_credential_recovery;
COMMIT;
