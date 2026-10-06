SET LOCAL ROLE matrix_iam_owner;

-- A receipt is the immutable completion of one actor-scoped command. It is
-- deliberately separate from the current attachment row: later revocation,
-- policy retirement or identity status changes cannot rewrite the result that
-- the caller observed (or failed to observe) at commit time.
CREATE TABLE IF NOT EXISTS iam.policy_attachment_changes (
    tenant_id text COLLATE "C" NOT NULL,
    actor_principal_id text COLLATE "C" NOT NULL,
    request_id text COLLATE "C" NOT NULL,
    operation text COLLATE "C" NOT NULL,
    attachment_id text COLLATE "C" NOT NULL,
    target_kind text COLLATE "C" NOT NULL,
    target_id text COLLATE "C" NOT NULL,
    policy_id text COLLATE "C" NOT NULL,
    authority_scope text COLLATE "C" NOT NULL,
    installation_id text COLLATE "C",
    policy_resource_version bigint,
    expected_resource_version bigint,
    input_commitment text COLLATE "C" NOT NULL,
    result_document jsonb NOT NULL,
    decision_id text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    completed_at timestamptz(6) NOT NULL,
    PRIMARY KEY (tenant_id,actor_principal_id,request_id),
    CONSTRAINT policy_attachment_changes_principal_fk
      FOREIGN KEY(tenant_id,actor_principal_id) REFERENCES iam.principals(tenant_id,id),
    CONSTRAINT policy_attachment_changes_attachment_fk
      FOREIGN KEY(tenant_id,attachment_id) REFERENCES iam.policy_attachments(tenant_id,id),
    CONSTRAINT policy_attachment_changes_policy_fk
      FOREIGN KEY(policy_id) REFERENCES iam.policies(id),
    CONSTRAINT policy_attachment_changes_decision_fk
      FOREIGN KEY(tenant_id,decision_id) REFERENCES iam.authorization_decisions(tenant_id,id),
    CONSTRAINT policy_attachment_changes_event_fk
      FOREIGN KEY(tenant_id,event_id) REFERENCES iam.audit_outbox(tenant_id,event_id),
    CONSTRAINT policy_attachment_changes_shape CHECK (
      tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND actor_principal_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND request_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND attachment_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND target_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND policy_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND decision_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND event_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND target_kind IN ('USER','GROUP','ROLE')
      AND input_commitment COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
      AND jsonb_typeof(result_document)='object'
      AND ((authority_scope='TENANT' AND installation_id IS NULL)
        OR (authority_scope='INSTALLATION' AND target_kind='USER'
          AND installation_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'))
      AND ((operation='CREATE'
          AND policy_resource_version BETWEEN 1 AND 9007199254740991
          AND expected_resource_version IS NULL)
        OR (operation='REVOKE'
          AND policy_resource_version IS NULL
          AND expected_resource_version BETWEEN 1 AND 9007199254740990))
    )
);

ALTER TABLE iam.policy_attachment_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.policy_attachment_changes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON iam.policy_attachment_changes;
CREATE POLICY tenant_isolation ON iam.policy_attachment_changes
  USING(tenant_id=iam.current_tenant_id())
  WITH CHECK(tenant_id=iam.current_tenant_id());

-- Reject reuse of any request ID already present in the exact predecessor,
-- even though predecessor events cannot be safely backfilled into receipts.
CREATE UNIQUE INDEX IF NOT EXISTS policy_attachment_change_request_history_uq
  ON iam.audit_outbox(tenant_id,(event_document#>>'{actor,id}'),(event_document->>'requestId'))
  WHERE event_document->>'action' IN (
    'iam.policy-attachment.created','iam.policy-attachment.revoked',
    'iam.platform-policy-attachment.created','iam.platform-policy-attachment.revoked');

CREATE OR REPLACE FUNCTION iam.policy_attachment_change_input_digest(
  operation text,target_kind text,target_id text,policy_id text,policy_resource_version bigint,
  attachment_id text,expected_resource_version bigint,request_id text
)
RETURNS text LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE domain text; document text;
BEGIN
    IF COALESCE(request_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(attachment_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy attachment change input is invalid';
    END IF;
    IF operation='CREATE' AND target_kind IN ('USER','GROUP','ROLE')
      AND COALESCE(target_id,'') COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND COALESCE(policy_id,'') COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      AND policy_resource_version BETWEEN 1 AND 9007199254740991
      AND expected_resource_version IS NULL THEN
      domain:='policy-attachment-create';
      document:='{"target":{"kind":'||to_json(target_kind)::text||',"id":'||to_json(target_id)::text
        ||'},"policyId":'||to_json(policy_id)::text||',"policyResourceVersion":'||policy_resource_version::text
        ||',"requestId":'||to_json(request_id)::text||'}';
    ELSIF operation='REVOKE' AND expected_resource_version BETWEEN 1 AND 9007199254740990
      AND policy_resource_version IS NULL THEN
      domain:='policy-attachment-revoke';
      document:='{"id":'||to_json(attachment_id)::text||',"request":{"resourceVersion":'
        ||expected_resource_version::text||',"requestId":'||to_json(request_id)::text||'}}';
    ELSE
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy attachment change input is invalid';
    END IF;
    RETURN 'sha256:'||encode(sha256(convert_to('matrix.iam.request.v1','UTF8')||decode('00','hex')
      ||convert_to(domain,'UTF8')||decode('00','hex')||convert_to(document,'UTF8')),'hex');
END $function$;

CREATE OR REPLACE FUNCTION iam.policy_attachment_change_document(receipt iam.policy_attachment_changes)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE completed text:=to_char(receipt.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
BEGIN
    IF receipt.operation='CREATE' THEN
      RETURN jsonb_build_object(
        'apiVersion','iam.matrix.xiak.com/v1','kind','PolicyAttachmentChange','operation','CREATE',
        'accountId',receipt.tenant_id,'actorPrincipalId',receipt.actor_principal_id,
        'requestId',receipt.request_id,'completedAt',completed,
        'target',jsonb_build_object('kind',receipt.target_kind,'id',receipt.target_id),
        'policyId',receipt.policy_id,'policyResourceVersion',receipt.policy_resource_version,
        'attachment',jsonb_strip_nulls(jsonb_build_object(
          'apiVersion','iam.matrix.xiak.com/v1','kind','PolicyAttachment','id',receipt.attachment_id,
          'accountId',receipt.tenant_id,'target',jsonb_build_object('kind',receipt.target_kind,'id',receipt.target_id),
          'policyId',receipt.policy_id,'scope',receipt.authority_scope,'installationId',receipt.installation_id,
          'resourceVersion',1,'createdAt',completed,'updatedAt',completed)));
    ELSIF receipt.operation='REVOKE' THEN
      RETURN jsonb_build_object(
        'apiVersion','iam.matrix.xiak.com/v1','kind','PolicyAttachmentChange','operation','REVOKE',
        'accountId',receipt.tenant_id,'actorPrincipalId',receipt.actor_principal_id,
        'requestId',receipt.request_id,'completedAt',completed,
        'attachmentId',receipt.attachment_id,'expectedResourceVersion',receipt.expected_resource_version,
        'revocation',jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','Revocation',
          'id',receipt.attachment_id,'resourceVersion',receipt.expected_resource_version+1,'revokedAt',completed));
    END IF;
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='policy attachment change receipt is invalid';
END $function$;

CREATE OR REPLACE FUNCTION iam.verified_policy_attachment_change(
  tenant text,actor text,original_request text
)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.policy_attachment_changes%ROWTYPE; attachment iam.policy_attachments%ROWTYPE;
    decision iam.authorization_decisions%ROWTYPE; event jsonb; expected_action text; expected_event text;
    expected_digest text; expected_result jsonb;
BEGIN
    SELECT * INTO receipt FROM iam.policy_attachment_changes r
      WHERE (r.tenant_id,r.actor_principal_id,r.request_id)=(tenant,actor,original_request);
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO attachment FROM iam.policy_attachments a
      WHERE (a.tenant_id,a.id)=(receipt.tenant_id,receipt.attachment_id);
    SELECT * INTO decision FROM iam.authorization_decisions d
      WHERE (d.tenant_id,d.id)=(receipt.tenant_id,receipt.decision_id);
    SELECT o.event_document INTO event FROM iam.audit_outbox o
      WHERE (o.tenant_id,o.event_id)=(receipt.tenant_id,receipt.event_id);
    expected_action:=CASE
      WHEN receipt.operation='CREATE' AND receipt.target_kind='GROUP' THEN 'iam.group-policy-attachment.create'
      WHEN receipt.operation='CREATE' AND receipt.target_kind='ROLE' THEN 'iam.role-policy-attachment.create'
      WHEN receipt.operation='CREATE' AND receipt.authority_scope='INSTALLATION' THEN 'iam.platform-policy-attachment.create'
      WHEN receipt.operation='CREATE' THEN 'iam.policy-attachment.create'
      WHEN receipt.target_kind='GROUP' THEN 'iam.group-policy-attachment.revoke'
      WHEN receipt.target_kind='ROLE' THEN 'iam.role-policy-attachment.revoke'
      WHEN receipt.authority_scope='INSTALLATION' THEN 'iam.platform-policy-attachment.revoke'
      ELSE 'iam.policy-attachment.revoke' END;
    expected_event:=CASE
      WHEN receipt.authority_scope='INSTALLATION' AND receipt.operation='CREATE' THEN 'iam.platform-policy-attachment.created'
      WHEN receipt.authority_scope='INSTALLATION' THEN 'iam.platform-policy-attachment.revoked'
      WHEN receipt.operation='CREATE' THEN 'iam.policy-attachment.created'
      ELSE 'iam.policy-attachment.revoked' END;
    expected_digest:=iam.policy_attachment_change_input_digest(receipt.operation,receipt.target_kind,receipt.target_id,
      receipt.policy_id,receipt.policy_resource_version,receipt.attachment_id,receipt.expected_resource_version,receipt.request_id);
    expected_result:=iam.policy_attachment_change_document(receipt);
    IF attachment.id IS NULL OR decision.id IS NULL OR event IS NULL
      OR attachment.target_kind IS DISTINCT FROM receipt.target_kind
      OR attachment.target_id IS DISTINCT FROM receipt.target_id
      OR attachment.policy_id IS DISTINCT FROM receipt.policy_id
      OR attachment.authority_scope IS DISTINCT FROM receipt.authority_scope
      OR attachment.installation_id IS DISTINCT FROM receipt.installation_id
      OR attachment.created_at>receipt.completed_at
      OR (receipt.operation='CREATE' AND attachment.created_at IS DISTINCT FROM receipt.completed_at)
      OR (receipt.operation='REVOKE' AND (attachment.resource_version IS DISTINCT FROM receipt.expected_resource_version+1
        OR attachment.revoked_at IS DISTINCT FROM receipt.completed_at OR attachment.updated_at IS DISTINCT FROM receipt.completed_at))
      OR decision.principal_id IS DISTINCT FROM receipt.actor_principal_id OR NOT decision.allowed
      OR decision.action_name IS DISTINCT FROM expected_action
      OR decision.target_kind IS DISTINCT FROM (CASE WHEN receipt.operation='CREATE' THEN receipt.target_kind ELSE 'POLICY_ATTACHMENT' END)
      OR decision.target_id IS DISTINCT FROM (CASE WHEN receipt.operation='CREATE' THEN receipt.target_id ELSE receipt.attachment_id END)
      OR decision.request_id IS DISTINCT FROM receipt.request_id OR decision.resource_mode IS DISTINCT FROM 'INSTANCE'
      OR event->>'action' IS DISTINCT FROM expected_event
      OR event#>>'{actor,type}' IS DISTINCT FROM 'USER' OR event#>>'{actor,id}' IS DISTINCT FROM receipt.actor_principal_id
      OR event#>>'{target,kind}' IS DISTINCT FROM 'POLICY_ATTACHMENT'
      OR event#>>'{target,id}' IS DISTINCT FROM receipt.attachment_id
      OR event->>'requestId' IS DISTINCT FROM receipt.request_id
      OR event->>'requestDigest' IS DISTINCT FROM expected_digest
      OR event->>'iamDecisionId' IS DISTINCT FROM receipt.decision_id
      OR (event->>'occurredAt')::timestamptz IS DISTINCT FROM receipt.completed_at
      OR (receipt.authority_scope='TENANT' AND (event->>'tenantId' IS DISTINCT FROM receipt.tenant_id OR event ? 'installationId'))
      OR (receipt.authority_scope='INSTALLATION' AND (event->>'installationId' IS DISTINCT FROM receipt.installation_id OR event ? 'tenantId'))
      OR receipt.input_commitment IS DISTINCT FROM expected_digest
      OR receipt.result_document IS DISTINCT FROM expected_result THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='policy attachment change evidence is unavailable';
    END IF;
    RETURN receipt.result_document;
EXCEPTION WHEN invalid_text_representation OR datetime_field_overflow THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='policy attachment change evidence is unavailable';
END $function$;

CREATE OR REPLACE FUNCTION iam.guard_policy_attachment_change_insert()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF current_setting('matrix.iam_policy_attachment_change',true) IS DISTINCT FROM 'trusted' THEN
      RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy attachment change insertion is forbidden';
    END IF;
    RETURN NEW;
END $function$;

CREATE OR REPLACE FUNCTION iam.capture_policy_attachment_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE action_name text:=NEW.event_document->>'action'; operation text; tenant text:=NEW.tenant_id;
    actor text:=NEW.event_document#>>'{actor,id}'; original_request text:=NEW.event_document->>'requestId';
    attachment iam.policy_attachments%ROWTYPE; policy iam.policies%ROWTYPE; decision text:=NEW.event_document->>'iamDecisionId';
    original_action text; expected_digest text; prior_scope text; result jsonb; receipt iam.policy_attachment_changes%ROWTYPE;
    policy_revision bigint; expected_revision bigint;
BEGIN
    IF action_name NOT IN ('iam.policy-attachment.created','iam.policy-attachment.revoked',
      'iam.platform-policy-attachment.created','iam.platform-policy-attachment.revoked') THEN RETURN NEW; END IF;
    operation:=CASE WHEN action_name IN ('iam.policy-attachment.created','iam.platform-policy-attachment.created') THEN 'CREATE' ELSE 'REVOKE' END;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    SELECT * INTO attachment FROM iam.policy_attachments a
      WHERE (a.tenant_id,a.id)=(tenant,NEW.event_document#>>'{target,id}');
    SELECT * INTO policy FROM iam.policies p WHERE p.id=attachment.policy_id;
    IF attachment.id IS NULL OR policy.id IS NULL
      OR attachment.authority_scope IS DISTINCT FROM (CASE WHEN action_name LIKE 'iam.platform-%' THEN 'INSTALLATION' ELSE 'TENANT' END)
      OR (operation='CREATE' AND (attachment.resource_version<>1 OR attachment.revoked_at IS NOT NULL
        OR attachment.created_at IS DISTINCT FROM NEW.created_at OR attachment.updated_at IS DISTINCT FROM NEW.created_at))
      OR (operation='REVOKE' AND (attachment.revoked_at IS DISTINCT FROM NEW.created_at
        OR attachment.updated_at IS DISTINCT FROM NEW.created_at OR attachment.resource_version<2)) THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='policy attachment change relation is unavailable';
    END IF;
    policy_revision:=CASE WHEN operation='CREATE' THEN policy.resource_version END;
    expected_revision:=CASE WHEN operation='REVOKE' THEN attachment.resource_version-1 END;
    original_action:=CASE
      WHEN operation='CREATE' AND attachment.target_kind='GROUP' THEN 'iam.group-policy-attachment.create'
      WHEN operation='CREATE' AND attachment.target_kind='ROLE' THEN 'iam.role-policy-attachment.create'
      WHEN operation='CREATE' AND attachment.authority_scope='INSTALLATION' THEN 'iam.platform-policy-attachment.create'
      WHEN operation='CREATE' THEN 'iam.policy-attachment.create'
      WHEN attachment.target_kind='GROUP' THEN 'iam.group-policy-attachment.revoke'
      WHEN attachment.target_kind='ROLE' THEN 'iam.role-policy-attachment.revoke'
      WHEN attachment.authority_scope='INSTALLATION' THEN 'iam.platform-policy-attachment.revoke'
      ELSE 'iam.policy-attachment.revoke' END;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,original_action,
      CASE WHEN operation='CREATE' THEN attachment.target_kind ELSE 'POLICY_ATTACHMENT' END,
      CASE WHEN operation='CREATE' THEN attachment.target_id ELSE attachment.id END,'INSTANCE',NULL);
    PERFORM iam.assert_audit_event(NEW.event_document,tenant,action_name,'POLICY_ATTACHMENT',attachment.id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,NEW.event_document);
    IF NEW.event_document->>'iamDecisionId' IS DISTINCT FROM decision THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy attachment change decision is invalid'; END IF;
    expected_digest:=iam.policy_attachment_change_input_digest(operation,attachment.target_kind,attachment.target_id,
      attachment.policy_id,policy_revision,attachment.id,expected_revision,original_request);
    IF NEW.event_document->>'requestDigest' IS DISTINCT FROM expected_digest THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy attachment change commitment is invalid'; END IF;
    receipt.tenant_id:=tenant; receipt.actor_principal_id:=actor; receipt.request_id:=original_request;
    receipt.operation:=operation; receipt.attachment_id:=attachment.id; receipt.target_kind:=attachment.target_kind;
    receipt.target_id:=attachment.target_id; receipt.policy_id:=attachment.policy_id;
    receipt.authority_scope:=attachment.authority_scope; receipt.installation_id:=attachment.installation_id;
    receipt.policy_resource_version:=policy_revision; receipt.expected_resource_version:=expected_revision;
    receipt.input_commitment:=expected_digest; receipt.decision_id:=decision; receipt.event_id:=NEW.event_id;
    receipt.completed_at:=NEW.created_at; result:=iam.policy_attachment_change_document(receipt); receipt.result_document:=result;
    prior_scope:=current_setting('matrix.iam_policy_attachment_change',true);
    PERFORM set_config('matrix.iam_policy_attachment_change','trusted',true);
    INSERT INTO iam.policy_attachment_changes(tenant_id,actor_principal_id,request_id,operation,attachment_id,
      target_kind,target_id,policy_id,authority_scope,installation_id,policy_resource_version,expected_resource_version,
      input_commitment,result_document,decision_id,event_id,completed_at)
      VALUES(receipt.tenant_id,receipt.actor_principal_id,receipt.request_id,receipt.operation,receipt.attachment_id,
        receipt.target_kind,receipt.target_id,receipt.policy_id,receipt.authority_scope,receipt.installation_id,
        receipt.policy_resource_version,receipt.expected_resource_version,receipt.input_commitment,receipt.result_document,
        receipt.decision_id,receipt.event_id,receipt.completed_at);
    PERFORM set_config('matrix.iam_policy_attachment_change',COALESCE(prior_scope,''),true);
    IF iam.verified_policy_attachment_change(tenant,actor,original_request) IS DISTINCT FROM result THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='policy attachment change receipt is unavailable'; END IF;
    RETURN NEW;
END $function$;

DROP TRIGGER IF EXISTS policy_attachment_change_insert_guard ON iam.policy_attachment_changes;
CREATE TRIGGER policy_attachment_change_insert_guard BEFORE INSERT ON iam.policy_attachment_changes
  FOR EACH ROW EXECUTE FUNCTION iam.guard_policy_attachment_change_insert();
DROP TRIGGER IF EXISTS policy_attachment_changes_cannot_be_updated ON iam.policy_attachment_changes;
CREATE TRIGGER policy_attachment_changes_cannot_be_updated BEFORE UPDATE ON iam.policy_attachment_changes
  FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS policy_attachment_changes_cannot_be_deleted ON iam.policy_attachment_changes;
CREATE TRIGGER policy_attachment_changes_cannot_be_deleted BEFORE DELETE ON iam.policy_attachment_changes
  FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS policy_attachment_changes_cannot_be_truncated ON iam.policy_attachment_changes;
CREATE TRIGGER policy_attachment_changes_cannot_be_truncated BEFORE TRUNCATE ON iam.policy_attachment_changes
  FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.policy_attachment_changes ENABLE ALWAYS TRIGGER policy_attachment_change_insert_guard;
ALTER TABLE iam.policy_attachment_changes ENABLE ALWAYS TRIGGER policy_attachment_changes_cannot_be_updated;
ALTER TABLE iam.policy_attachment_changes ENABLE ALWAYS TRIGGER policy_attachment_changes_cannot_be_deleted;
ALTER TABLE iam.policy_attachment_changes ENABLE ALWAYS TRIGGER policy_attachment_changes_cannot_be_truncated;

DROP TRIGGER IF EXISTS policy_attachment_change_capture ON iam.audit_outbox;
CREATE CONSTRAINT TRIGGER policy_attachment_change_capture AFTER INSERT ON iam.audit_outbox
  DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW EXECUTE FUNCTION iam.capture_policy_attachment_change();
ALTER TABLE iam.audit_outbox ENABLE ALWAYS TRIGGER policy_attachment_change_capture;

CREATE OR REPLACE FUNCTION iam.assert_policy_attachment_change_reader(tenant text,actor text,actor_session text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE effective_now timestamptz(6):=clock_timestamp();
BEGIN
    IF COALESCE(tenant,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(actor_session,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy attachment change reader is invalid'; END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts a WHERE a.id=tenant AND a.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy attachment change account is unavailable'; END IF;
    PERFORM 1 FROM iam.principals p WHERE (p.tenant_id,p.id)=(tenant,actor) AND p.principal_type='USER'
      AND p.status='ACTIVE' AND p.deleted_at IS NULL AND NOT p.must_change_password FOR NO KEY UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy attachment change actor is unavailable'; END IF;
    PERFORM 1 FROM iam.user_credentials c JOIN iam.sessions s
      ON (s.tenant_id,s.principal_id)=(c.tenant_id,c.principal_id)
      WHERE (c.tenant_id,c.principal_id)=(tenant,actor) AND s.id=actor_session
        AND s.status='ACTIVE' AND s.revoked_at IS NULL AND s.expires_at>effective_now
        AND s.credential_version=c.credential_version AND s.last_activity_at IS NOT NULL
        AND s.idle_timeout_seconds IS NOT NULL
        AND s.last_activity_at+make_interval(secs=>s.idle_timeout_seconds)>effective_now FOR SHARE OF c,s;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy attachment change session is unavailable'; END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.lookup_policy_attachment_change_reference(
  tenant text,actor text,actor_session text,original_request text
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.policy_attachment_changes%ROWTYPE;
BEGIN
    IF COALESCE(original_request,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy attachment change request is invalid'; END IF;
    PERFORM iam.assert_policy_attachment_change_reader(tenant,actor,actor_session);
    SELECT * INTO receipt FROM iam.policy_attachment_changes r
      WHERE (r.tenant_id,r.actor_principal_id,r.request_id)=(tenant,actor,original_request);
    IF NOT FOUND THEN RETURN NULL; END IF;
    RETURN jsonb_strip_nulls(jsonb_build_object('accountId',receipt.tenant_id,'actorPrincipalId',receipt.actor_principal_id,
      'requestId',receipt.request_id,'attachmentId',receipt.attachment_id,'scope',receipt.authority_scope,
      'installationId',receipt.installation_id));
END $function$;

CREATE OR REPLACE FUNCTION iam.read_policy_attachment_change(
  tenant text,actor text,actor_session text,original_request text,attachment_id text,
  authority_scope text,installation_id text,decision_id text
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.policy_attachment_changes%ROWTYPE; action_name text; result jsonb;
BEGIN
    IF COALESCE(original_request,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(attachment_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR COALESCE(decision_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
      OR authority_scope NOT IN ('TENANT','INSTALLATION')
      OR (authority_scope='TENANT' AND installation_id IS NOT NULL)
      OR (authority_scope='INSTALLATION' AND COALESCE(installation_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='policy attachment change read is invalid'; END IF;
    PERFORM iam.assert_policy_attachment_change_reader(tenant,actor,actor_session);
    SELECT * INTO receipt FROM iam.policy_attachment_changes r
      WHERE (r.tenant_id,r.actor_principal_id,r.request_id)=(tenant,actor,original_request) FOR SHARE;
    IF NOT FOUND OR receipt.attachment_id IS DISTINCT FROM attachment_id
      OR receipt.authority_scope IS DISTINCT FROM authority_scope
      OR receipt.installation_id IS DISTINCT FROM installation_id THEN
      RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='policy attachment change is unavailable'; END IF;
    action_name:=CASE authority_scope WHEN 'INSTALLATION' THEN 'iam.platform-policy-attachment-change.read'
      ELSE 'iam.policy-attachment-change.read' END;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision_id,action_name,'POLICY_ATTACHMENT',attachment_id,'INSTANCE',NULL);
    result:=iam.verified_policy_attachment_change(tenant,actor,original_request);
    IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='policy attachment change is unavailable'; END IF;
    RETURN result;
END $function$;

-- The source owns a new immutable system-policy version. This release
-- explicitly adopts it for the two corresponding built-in administrative
-- policies; old policy-version bytes and historical decisions remain intact.
DO $policy_attachment_change_policy_adoption$
DECLARE tenant_version text; platform_version text; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    SELECT min(v.id) INTO tenant_version FROM iam.policy_versions v
      WHERE v.policy_id='system.account-administrator' AND v.retired_at IS NULL
        AND jsonb_typeof(v.compilation->'profiles')='array' AND jsonb_array_length(v.compilation->'profiles') BETWEEN 1 AND 16 AND EXISTS(
        SELECT 1 FROM jsonb_array_elements(v.document->'statements') statement,
          jsonb_array_elements_text(statement->'actions') action_value
        WHERE action_value='iam.policy-attachment-change.read')
        AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(v.compilation->'profiles') reference
          WHERE NOT EXISTS(SELECT 1 FROM iam.authorization_profile_heads head
            JOIN iam.authorization_profiles archive ON (archive.product,archive.revision)=(head.product,head.revision)
            WHERE head.product=reference->>'product' AND head.revision=(reference->>'revision')::bigint
              AND archive.content_digest=reference->>'contentDigest'));
    IF tenant_version IS NULL OR (SELECT count(*) FROM iam.policy_versions v
      WHERE v.policy_id='system.account-administrator' AND v.retired_at IS NULL
        AND jsonb_typeof(v.compilation->'profiles')='array' AND jsonb_array_length(v.compilation->'profiles') BETWEEN 1 AND 16 AND EXISTS(
        SELECT 1 FROM jsonb_array_elements(v.document->'statements') statement,
          jsonb_array_elements_text(statement->'actions') action_value
        WHERE action_value='iam.policy-attachment-change.read')
        AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(v.compilation->'profiles') reference
          WHERE NOT EXISTS(SELECT 1 FROM iam.authorization_profile_heads head
            JOIN iam.authorization_profiles archive ON (archive.product,archive.revision)=(head.product,head.revision)
            WHERE head.product=reference->>'product' AND head.revision=(reference->>'revision')::bigint
              AND archive.content_digest=reference->>'contentDigest')))<>1 THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='account administrator receipt policy is unavailable'; END IF;
    SELECT min(v.id) INTO platform_version FROM iam.policy_versions v
      WHERE v.policy_id='system.platform-operator' AND v.retired_at IS NULL
        AND jsonb_typeof(v.compilation->'profiles')='array' AND jsonb_array_length(v.compilation->'profiles') BETWEEN 1 AND 16 AND EXISTS(
        SELECT 1 FROM jsonb_array_elements(v.document->'statements') statement,
          jsonb_array_elements_text(statement->'actions') action_value
        WHERE action_value='iam.platform-policy-attachment-change.read')
        AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(v.compilation->'profiles') reference
          WHERE NOT EXISTS(SELECT 1 FROM iam.authorization_profile_heads head
            JOIN iam.authorization_profiles archive ON (archive.product,archive.revision)=(head.product,head.revision)
            WHERE head.product=reference->>'product' AND head.revision=(reference->>'revision')::bigint
              AND archive.content_digest=reference->>'contentDigest'));
    IF platform_version IS NULL OR (SELECT count(*) FROM iam.policy_versions v
      WHERE v.policy_id='system.platform-operator' AND v.retired_at IS NULL
        AND jsonb_typeof(v.compilation->'profiles')='array' AND jsonb_array_length(v.compilation->'profiles') BETWEEN 1 AND 16 AND EXISTS(
        SELECT 1 FROM jsonb_array_elements(v.document->'statements') statement,
          jsonb_array_elements_text(statement->'actions') action_value
        WHERE action_value='iam.platform-policy-attachment-change.read')
        AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(v.compilation->'profiles') reference
          WHERE NOT EXISTS(SELECT 1 FROM iam.authorization_profile_heads head
            JOIN iam.authorization_profiles archive ON (archive.product,archive.revision)=(head.product,head.revision)
            WHERE head.product=reference->>'product' AND head.revision=(reference->>'revision')::bigint
              AND archive.content_digest=reference->>'contentDigest')))<>1 THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='platform operator receipt policy is unavailable'; END IF;
    -- Only the exact schema-65 built-in defaults advance. Clean installs
    -- already select the new seed, while equal replay must not overwrite a
    -- later explicit default-version choice or bless an unknown old state.
    UPDATE iam.policies p SET default_version_id=tenant_version,resource_version=p.resource_version+1,updated_at=effective_now
      WHERE p.id='system.account-administrator'
        AND p.default_version_id='version-e49a3d4626b4352752cd43a67fae9c64622a45b9390d4cb32f2e4e549702f715';
    UPDATE iam.policies p SET default_version_id=platform_version,resource_version=p.resource_version+1,updated_at=effective_now
      WHERE p.id='system.platform-operator'
        AND p.default_version_id='version-adfc4caf50c1e501ad8ca42b1178a88027ad0c748a7aaf82569d12aa71678e79';
END $policy_attachment_change_policy_adoption$;

CREATE OR REPLACE FUNCTION iam.policy_attachment_change_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
  SELECT EXISTS(SELECT 1 FROM pg_class relation WHERE relation.oid='iam.policy_attachment_changes'::regclass
      AND relation.relowner='matrix_iam_owner'::regrole AND relation.relrowsecurity AND relation.relforcerowsecurity
      AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) privilege
        WHERE privilege.grantee<>relation.relowner))
    AND EXISTS(SELECT 1 FROM pg_policies p WHERE p.schemaname='iam' AND p.tablename='policy_attachment_changes'
      AND p.policyname='tenant_isolation' AND p.qual='(tenant_id = iam.current_tenant_id())'
      AND p.with_check='(tenant_id = iam.current_tenant_id())')
    AND (SELECT count(*)=4 FROM pg_trigger t WHERE t.tgrelid='iam.policy_attachment_changes'::regclass
      AND NOT t.tgisinternal AND t.tgenabled='A' AND t.tgname IN ('policy_attachment_change_insert_guard',
        'policy_attachment_changes_cannot_be_updated','policy_attachment_changes_cannot_be_deleted',
        'policy_attachment_changes_cannot_be_truncated'))
    AND EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid='iam.audit_outbox'::regclass AND NOT t.tgisinternal
      AND t.tgenabled='A' AND t.tgname='policy_attachment_change_capture'
      AND t.tgfoid=to_regprocedure('iam.capture_policy_attachment_change()'))
    AND (SELECT count(*)=2 FROM pg_proc f WHERE f.oid IN (
      to_regprocedure('iam.lookup_policy_attachment_change_reference(text,text,text,text)'),
      to_regprocedure('iam.read_policy_attachment_change(text,text,text,text,text,text,text,text)'))
      AND f.proowner='matrix_iam_owner'::regrole AND f.prosecdef AND f.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
      AND has_function_privilege('matrix_iam_api',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_worker',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_credential_recovery',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_notification_worker',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_authentication_recovery',f.oid,'EXECUTE')
      AND NOT has_function_privilege('matrix_iam_access_analysis_worker',f.oid,'EXECUTE'))
    AND EXISTS(SELECT 1 FROM iam.policies p JOIN iam.policy_versions v ON v.policy_id=p.id
      WHERE p.id='system.account-administrator' AND v.retired_at IS NULL
        AND EXISTS(SELECT 1 FROM jsonb_array_elements(v.document->'statements') statement,
        jsonb_array_elements_text(statement->'actions') action_value WHERE action_value='iam.policy-attachment-change.read'))
    AND EXISTS(SELECT 1 FROM iam.policies p JOIN iam.policy_versions v ON v.policy_id=p.id
      WHERE p.id='system.platform-operator' AND v.retired_at IS NULL
        AND EXISTS(SELECT 1 FROM jsonb_array_elements(v.document->'statements') statement,
        jsonb_array_elements_text(statement->'actions') action_value WHERE action_value='iam.platform-policy-attachment-change.read'))
$function$;

REVOKE ALL ON TABLE iam.policy_attachment_changes
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
REVOKE ALL ON FUNCTION iam.policy_attachment_change_input_digest(text,text,text,text,bigint,text,bigint,text),
  iam.policy_attachment_change_document(iam.policy_attachment_changes),
  iam.verified_policy_attachment_change(text,text,text),iam.guard_policy_attachment_change_insert(),
  iam.capture_policy_attachment_change(),iam.assert_policy_attachment_change_reader(text,text,text),
  iam.policy_attachment_change_contract_ready()
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
REVOKE ALL ON FUNCTION iam.lookup_policy_attachment_change_reference(text,text,text,text),
  iam.read_policy_attachment_change(text,text,text,text,text,text,text,text)
  FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,
    matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
GRANT EXECUTE ON FUNCTION iam.lookup_policy_attachment_change_reference(text,text,text,text),
  iam.read_policy_attachment_change(text,text,text,text,text,text,text,text) TO matrix_iam_api;

DO $policy_attachment_change_readiness_cutover$
BEGIN
    IF to_regprocedure('iam.readiness_v65()') IS NOT NULL THEN DROP FUNCTION iam.readiness_v65(); END IF;
    ALTER FUNCTION iam.readiness() RENAME TO readiness_v65;
END $policy_attachment_change_readiness_cutover$;
REVOKE ALL ON FUNCTION iam.readiness_v65() FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,
  matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
CREATE FUNCTION iam.readiness()
RETURNS TABLE(ready boolean,schema_version bigint,checked_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE predecessor record;
BEGIN
    SELECT * INTO predecessor FROM iam.readiness_v65();
    RETURN QUERY SELECT predecessor.ready AND iam.policy_attachment_change_contract_ready(),66::bigint,predecessor.checked_at;
END $function$;
REVOKE ALL ON FUNCTION iam.readiness() FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,
  matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
GRANT EXECUTE ON FUNCTION iam.readiness() TO matrix_iam_api;
