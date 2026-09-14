SET LOCAL ROLE matrix_iam_owner;

CREATE TABLE IF NOT EXISTS iam.groups (
    tenant_id text COLLATE "C" NOT NULL REFERENCES iam.accounts(id),
    id text COLLATE "C" NOT NULL,
    name text COLLATE "C" NOT NULL,
    description text NOT NULL DEFAULT '',
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    deleted_at timestamptz(6),
    deleted_memberships_count integer,
    revoked_attachments_count integer,
    PRIMARY KEY (tenant_id,id),
    CONSTRAINT groups_values_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND length(name) BETWEEN 1 AND 64 AND btrim(name)=name
        AND length(description)<=512 AND btrim(description)=description
        AND resource_version BETWEEN 1 AND 9007199254740991
        AND updated_at>=created_at
        AND ((deleted_at IS NULL AND deleted_memberships_count IS NULL AND revoked_attachments_count IS NULL)
          OR (deleted_at IS NOT NULL AND deleted_memberships_count IS NOT NULL AND revoked_attachments_count IS NOT NULL
              AND deleted_at=updated_at AND deleted_at>=created_at AND resource_version>=2
              AND deleted_memberships_count>=0 AND revoked_attachments_count>=0))
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS groups_active_name_uq ON iam.groups(tenant_id,name) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS iam.group_memberships (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    group_id text COLLATE "C" NOT NULL,
    user_id text COLLATE "C" NOT NULL,
    created_by text COLLATE "C" NOT NULL,
    removed_by text COLLATE "C",
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    removed_at timestamptz(6),
    PRIMARY KEY (tenant_id,id),
    FOREIGN KEY (tenant_id,group_id) REFERENCES iam.groups(tenant_id,id),
    FOREIGN KEY (tenant_id,user_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY (tenant_id,created_by) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY (tenant_id,removed_by) REFERENCES iam.principals(tenant_id,id),
    CONSTRAINT group_memberships_values_valid CHECK (
        id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND group_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND user_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND created_by COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND resource_version BETWEEN 1 AND 9007199254740991
        AND updated_at>=created_at
        AND ((removed_at IS NULL AND removed_by IS NULL AND resource_version=1 AND updated_at=created_at)
          OR (removed_at IS NOT NULL AND removed_at=updated_at AND removed_at>=created_at AND removed_by IS NOT NULL AND resource_version>=2))
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS group_memberships_active_uq
    ON iam.group_memberships(tenant_id,group_id,user_id) WHERE removed_at IS NULL;
CREATE INDEX IF NOT EXISTS group_memberships_active_user_idx
    ON iam.group_memberships(tenant_id,user_id,group_id) WHERE removed_at IS NULL;

CREATE OR REPLACE FUNCTION iam.guard_group_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF ROW(NEW.tenant_id,NEW.id,NEW.created_at) IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.created_at)
       OR OLD.deleted_at IS NOT NULL OR NEW.resource_version<>OLD.resource_version+1
       OR NEW.updated_at<>transaction_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM group transition is invalid';
    END IF;
    IF NEW.deleted_at IS NULL THEN
        IF NEW.deleted_memberships_count IS NOT NULL OR NEW.revoked_attachments_count IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM group profile transition is invalid';
        END IF;
    ELSIF NEW.deleted_at<>NEW.updated_at OR OLD.deleted_at IS NOT NULL
       OR NEW.name<>OLD.name OR NEW.description<>OLD.description
       OR NEW.deleted_memberships_count IS NULL OR NEW.revoked_attachments_count IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM group deletion transition is invalid';
    END IF;
    RETURN NEW;
END $function$;

CREATE OR REPLACE FUNCTION iam.guard_group_membership_change()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
	IF TG_OP='INSERT' THEN
		PERFORM 1 FROM iam.principals AS principal
		 WHERE principal.tenant_id=NEW.tenant_id AND principal.id=NEW.user_id
		   AND principal.principal_type='USER' AND principal.status='ACTIVE' AND principal.deleted_at IS NULL
		   AND NOT EXISTS(SELECT 1 FROM iam.account_roots AS root WHERE root.account_id=NEW.tenant_id AND root.principal_id=principal.id)
		 FOR SHARE;
		IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='group membership user is invalid'; END IF;
		PERFORM 1 FROM iam.groups WHERE tenant_id=NEW.tenant_id AND id=NEW.group_id AND deleted_at IS NULL FOR SHARE;
		IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='group membership group is invalid'; END IF;
		RETURN NEW;
	END IF;
    IF ROW(NEW.tenant_id,NEW.id,NEW.group_id,NEW.user_id,NEW.created_by,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.group_id,OLD.user_id,OLD.created_by,OLD.created_at)
       OR OLD.removed_at IS NOT NULL OR NEW.removed_at IS NULL OR NEW.removed_by IS NULL
       OR NEW.resource_version<>OLD.resource_version+1 OR NEW.updated_at<>transaction_timestamp()
       OR NEW.removed_at<>NEW.updated_at THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='IAM group membership transition is invalid';
    END IF;
    RETURN NEW;
END $function$;

DROP TRIGGER IF EXISTS groups_guard_change ON iam.groups;
CREATE TRIGGER groups_guard_change BEFORE UPDATE ON iam.groups FOR EACH ROW EXECUTE FUNCTION iam.guard_group_change();
DROP TRIGGER IF EXISTS groups_cannot_delete ON iam.groups;
CREATE TRIGGER groups_cannot_delete BEFORE DELETE ON iam.groups FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS groups_cannot_truncate ON iam.groups;
CREATE TRIGGER groups_cannot_truncate BEFORE TRUNCATE ON iam.groups FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS group_memberships_guard_change ON iam.group_memberships;
CREATE TRIGGER group_memberships_guard_change BEFORE INSERT OR UPDATE ON iam.group_memberships FOR EACH ROW EXECUTE FUNCTION iam.guard_group_membership_change();
DROP TRIGGER IF EXISTS group_memberships_cannot_delete ON iam.group_memberships;
CREATE TRIGGER group_memberships_cannot_delete BEFORE DELETE ON iam.group_memberships FOR EACH ROW EXECUTE FUNCTION iam.reject_policy_history_change();
DROP TRIGGER IF EXISTS group_memberships_cannot_truncate ON iam.group_memberships;
CREATE TRIGGER group_memberships_cannot_truncate BEFORE TRUNCATE ON iam.group_memberships FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change();
ALTER TABLE iam.groups ENABLE ALWAYS TRIGGER groups_guard_change;
ALTER TABLE iam.groups ENABLE ALWAYS TRIGGER groups_cannot_delete;
ALTER TABLE iam.groups ENABLE ALWAYS TRIGGER groups_cannot_truncate;
ALTER TABLE iam.group_memberships ENABLE ALWAYS TRIGGER group_memberships_guard_change;
ALTER TABLE iam.group_memberships ENABLE ALWAYS TRIGGER group_memberships_cannot_delete;
ALTER TABLE iam.group_memberships ENABLE ALWAYS TRIGGER group_memberships_cannot_truncate;

ALTER TABLE iam.groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.groups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS groups_tenant_isolation ON iam.groups;
CREATE POLICY groups_tenant_isolation ON iam.groups USING (tenant_id=iam.current_tenant_id()) WITH CHECK (tenant_id=iam.current_tenant_id());
ALTER TABLE iam.group_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.group_memberships FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS group_memberships_tenant_isolation ON iam.group_memberships;
CREATE POLICY group_memberships_tenant_isolation ON iam.group_memberships USING (tenant_id=iam.current_tenant_id()) WITH CHECK (tenant_id=iam.current_tenant_id());

CREATE OR REPLACE FUNCTION iam.assert_group_actor(tenant text,actor text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts AS account WHERE account.id=tenant AND account.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='group account is unavailable'; END IF;
    PERFORM 1 FROM iam.principals AS principal
     WHERE principal.tenant_id=tenant AND principal.id=actor AND principal.principal_type='USER'
       AND principal.status='ACTIVE' AND NOT principal.must_change_password AND principal.deleted_at IS NULL FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='group actor is unavailable'; END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.assert_group_intent(tenant text,actor text,event jsonb)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF EXISTS(SELECT 1 FROM iam.audit_outbox AS fact WHERE fact.tenant_id=tenant
        AND fact.event_document->>'action'=event->>'action'
        AND fact.event_document#>>'{actor,id}'=actor
        AND fact.event_document->>'requestId'=event->>'requestId'
        AND (fact.event_document->>'requestDigest' IS DISTINCT FROM event->>'requestDigest'
          OR fact.event_document->'target' IS DISTINCT FROM event->'target')) THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='group command intent conflicts';
    END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.group_snapshot(tenant text,group_id text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','Group','id',g.id,'accountId',g.tenant_id,
        'name',g.name,'description',g.description,'resourceVersion',g.resource_version,
        'createdAt',g.created_at,'updatedAt',g.updated_at)
      FROM iam.groups AS g WHERE g.tenant_id=tenant AND g.id=group_id AND g.deleted_at IS NULL
$function$;

CREATE OR REPLACE FUNCTION iam.group_access_snapshot(tenant text,group_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb; attachments jsonb;
BEGIN
    result := iam.group_snapshot(tenant,group_id);
    IF result IS NULL THEN RETURN NULL; END IF;
    SELECT COALESCE(jsonb_agg(iam.lookup_policy_attachment(tenant,selected.id) ORDER BY selected.id),'[]'::jsonb)
      INTO attachments FROM (SELECT attachment.id FROM iam.policy_attachments AS attachment
        WHERE attachment.tenant_id=tenant AND attachment.target_kind='GROUP' AND attachment.target_id=group_id
          AND attachment.revoked_at IS NULL ORDER BY attachment.id LIMIT 257) AS selected;
    IF jsonb_array_length(attachments)>256 THEN
        RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='group attachment directory exceeds its read budget';
    END IF;
    RETURN jsonb_build_object('group',result,'policyAttachments',attachments,'capabilities','[]'::jsonb);
END $function$;

CREATE OR REPLACE FUNCTION iam.group_membership_snapshot(tenant text,membership_id text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','GroupMembership',
        'id',m.id,'accountId',m.tenant_id,'groupId',m.group_id,'userId',m.user_id,'createdBy',m.created_by,
        'removedBy',m.removed_by,'resourceVersion',m.resource_version,'createdAt',m.created_at,
        'updatedAt',m.updated_at,'removedAt',m.removed_at))
      FROM iam.group_memberships AS m WHERE m.tenant_id=tenant AND m.id=membership_id
$function$;

CREATE OR REPLACE FUNCTION iam.list_groups(tenant text,actor text,decision text,after_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.assert_group_actor(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.group.list','ACCOUNT',tenant);
    IF COALESCE(after_id,'')<>'' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='group page is invalid';
    END IF;
    SELECT COALESCE(jsonb_agg(iam.group_access_snapshot(tenant,g.id) ORDER BY g.id),'[]'::jsonb) INTO result
      FROM (SELECT id FROM iam.groups WHERE tenant_id=tenant AND deleted_at IS NULL
        AND (COALESCE(after_id,'')='' OR id>after_id COLLATE "C") ORDER BY id LIMIT 101) AS g;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.read_group(tenant text,actor text,decision text,group_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.assert_group_actor(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.group.read','GROUP',group_id);
    result := iam.group_access_snapshot(tenant,group_id);
    IF result IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='group is unavailable'; END IF;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.create_group(tenant text,actor text,decision text,group_id text,group_name text,group_description text,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.groups%ROWTYPE; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF COALESCE(group_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR group_name IS NULL OR length(group_name) NOT BETWEEN 1 AND 64 OR btrim(group_name)<>group_name
       OR group_description IS NULL OR length(group_description)>512 OR btrim(group_description)<>group_description THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='group input is invalid';
    END IF;
    PERFORM iam.assert_group_actor(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.group.create','ACCOUNT',tenant);
    PERFORM iam.assert_audit_event(event,tenant,'iam.group.created','GROUP',group_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='group decision correlation is invalid'; END IF;
    PERFORM iam.assert_group_intent(tenant,actor,event);
    SELECT * INTO stored FROM iam.groups WHERE tenant_id=tenant AND id=group_id FOR UPDATE;
    IF FOUND THEN
        IF stored.deleted_at IS NOT NULL OR stored.resource_version<>1 OR stored.name<>group_name OR stored.description<>group_description OR NOT EXISTS(
            SELECT 1 FROM iam.audit_outbox WHERE tenant_id=tenant AND event_document->>'action'='iam.group.created'
              AND event_document#>>'{target,id}'=group_id AND event_document->>'requestId'=event->>'requestId'
              AND event_document->>'requestDigest'=event->>'requestDigest' AND event_document#>>'{actor,id}'=actor) THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='group intent conflicts';
        END IF;
        RETURN iam.group_snapshot(tenant,group_id);
    END IF;
    INSERT INTO iam.groups(tenant_id,id,name,description,resource_version,created_at,updated_at)
    VALUES(tenant,group_id,group_name,group_description,1,effective_now,effective_now);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
    VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    RETURN iam.group_snapshot(tenant,group_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.update_group(tenant text,actor text,decision text,group_id text,group_name text,group_description text,expected_version bigint,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.groups%ROWTYPE;
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740991
       OR group_name IS NULL OR length(group_name) NOT BETWEEN 1 AND 64 OR btrim(group_name)<>group_name
       OR group_description IS NULL OR length(group_description)>512 OR btrim(group_description)<>group_description THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='group update input is invalid';
    END IF;
    PERFORM iam.assert_group_actor(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.group.update','GROUP',group_id);
    PERFORM iam.assert_audit_event(event,tenant,'iam.group.updated','GROUP',group_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='group decision correlation is invalid'; END IF;
    PERFORM iam.assert_group_intent(tenant,actor,event);
    SELECT * INTO stored FROM iam.groups WHERE tenant_id=tenant AND id=group_id FOR UPDATE;
    IF NOT FOUND OR stored.deleted_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='group is unavailable'; END IF;
    IF stored.resource_version=expected_version+1 AND stored.name=group_name AND stored.description=group_description AND EXISTS(
        SELECT 1 FROM iam.audit_outbox WHERE tenant_id=tenant AND event_document->>'action'='iam.group.updated'
          AND event_document#>>'{target,id}'=group_id AND event_document->>'requestId'=event->>'requestId'
          AND event_document->>'requestDigest'=event->>'requestDigest' AND event_document#>>'{actor,id}'=actor) THEN
        RETURN iam.group_snapshot(tenant,group_id);
    END IF;
    IF stored.resource_version<>expected_version OR stored.resource_version=9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='group revision conflicts';
    END IF;
    UPDATE iam.groups SET name=group_name,description=group_description,resource_version=stored.resource_version+1,
        updated_at=transaction_timestamp() WHERE tenant_id=tenant AND id=group_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
    VALUES(tenant,event->>'eventId',event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
    RETURN iam.group_snapshot(tenant,group_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.delete_group(tenant text,actor text,decision text,group_id text,expected_version bigint,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.groups%ROWTYPE; effective_now timestamptz(6):=transaction_timestamp(); membership_count integer; attachment_count integer;
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='group deletion input is invalid';
    END IF;
    PERFORM iam.assert_group_actor(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.group.delete','GROUP',group_id);
    PERFORM iam.assert_audit_event(event,tenant,'iam.group.deleted','GROUP',group_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='group decision correlation is invalid'; END IF;
    PERFORM iam.assert_group_intent(tenant,actor,event);
    SELECT * INTO stored FROM iam.groups WHERE tenant_id=tenant AND id=group_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='group is unavailable'; END IF;
    IF stored.deleted_at IS NOT NULL THEN
        IF stored.resource_version<>expected_version+1 OR NOT EXISTS(
            SELECT 1 FROM iam.audit_outbox WHERE tenant_id=tenant AND event_document->>'action'='iam.group.deleted'
              AND event_document#>>'{target,id}'=group_id AND event_document->>'requestId'=event->>'requestId'
              AND event_document->>'requestDigest'=event->>'requestDigest' AND event_document#>>'{actor,id}'=actor) THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='group deletion intent conflicts';
        END IF;
        RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','GroupDeletion','accountId',tenant,
            'id',group_id,'name',stored.name,'resourceVersion',stored.resource_version,
            'removedMemberships',stored.deleted_memberships_count,'revokedPolicyAttachments',stored.revoked_attachments_count,'deletedAt',stored.deleted_at);
    END IF;
    IF stored.resource_version<>expected_version OR stored.resource_version=9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='group revision conflicts';
    END IF;
    PERFORM m.id FROM iam.group_memberships AS m WHERE m.tenant_id=tenant AND m.group_id=delete_group.group_id AND m.removed_at IS NULL ORDER BY m.id FOR UPDATE;
    PERFORM id FROM iam.policy_attachments WHERE tenant_id=tenant AND target_kind='GROUP' AND target_id=group_id AND revoked_at IS NULL ORDER BY id FOR UPDATE;
    UPDATE iam.group_memberships AS m SET resource_version=m.resource_version+1,updated_at=effective_now,removed_at=effective_now,removed_by=actor
     WHERE m.tenant_id=tenant AND m.group_id=delete_group.group_id AND m.removed_at IS NULL;
    GET DIAGNOSTICS membership_count=ROW_COUNT;
    UPDATE iam.policy_attachments SET resource_version=resource_version+1,updated_at=effective_now,revoked_at=effective_now
     WHERE tenant_id=tenant AND target_kind='GROUP' AND target_id=group_id AND revoked_at IS NULL;
    GET DIAGNOSTICS attachment_count=ROW_COUNT;
    UPDATE iam.groups SET resource_version=resource_version+1,updated_at=effective_now,deleted_at=effective_now,
        deleted_memberships_count=membership_count,revoked_attachments_count=attachment_count
     WHERE tenant_id=tenant AND id=group_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
    VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','GroupDeletion','accountId',tenant,
        'id',group_id,'name',stored.name,'resourceVersion',stored.resource_version+1,'removedMemberships',membership_count,
        'revokedPolicyAttachments',attachment_count,'deletedAt',effective_now);
END $function$;

CREATE OR REPLACE FUNCTION iam.list_group_memberships(tenant text,actor text,decision text,group_id text,after_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE result jsonb;
BEGIN
    PERFORM iam.assert_group_actor(tenant,actor);
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.group-membership.list','GROUP',group_id);
    PERFORM 1 FROM iam.groups WHERE tenant_id=tenant AND id=group_id AND deleted_at IS NULL FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='group is unavailable'; END IF;
    IF COALESCE(after_id,'')<>'' AND after_id COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='membership page is invalid';
    END IF;
    SELECT COALESCE(jsonb_agg(iam.group_membership_snapshot(tenant,m.id) ORDER BY m.id),'[]'::jsonb) INTO result
      FROM (SELECT row.id FROM iam.group_memberships AS row WHERE row.tenant_id=tenant AND row.group_id=list_group_memberships.group_id AND row.removed_at IS NULL
        AND (COALESCE(after_id,'')='' OR row.id>after_id COLLATE "C") ORDER BY row.id LIMIT 101) AS m;
    RETURN result;
END $function$;

CREATE OR REPLACE FUNCTION iam.create_group_membership(tenant text,actor text,decision text,membership_id text,group_id text,user_id text,event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.group_memberships%ROWTYPE; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF actor=user_id OR COALESCE(membership_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='group membership is forbidden';
    END IF;
    PERFORM iam.assert_group_actor(tenant,actor);
    PERFORM 1 FROM iam.principals AS principal
     WHERE principal.tenant_id=tenant AND principal.id=user_id AND principal.principal_type='USER'
       AND principal.status='ACTIVE' AND principal.deleted_at IS NULL
       AND NOT EXISTS(SELECT 1 FROM iam.account_roots AS root WHERE root.account_id=tenant AND root.principal_id=principal.id)
     FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='membership user is unavailable'; END IF;
    PERFORM 1 FROM iam.groups WHERE tenant_id=tenant AND id=group_id AND deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='membership group is unavailable'; END IF;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.group-membership.create','GROUP',group_id);
    PERFORM iam.assert_audit_event(event,tenant,'iam.group-membership.created','GROUP_MEMBERSHIP',membership_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='membership decision correlation is invalid'; END IF;
    PERFORM iam.assert_group_intent(tenant,actor,event);
    SELECT * INTO stored FROM iam.group_memberships WHERE tenant_id=tenant AND id=membership_id FOR UPDATE;
    IF FOUND THEN
        IF stored.group_id<>group_id OR stored.user_id<>user_id OR stored.created_by<>actor OR stored.removed_at IS NOT NULL OR NOT EXISTS(
            SELECT 1 FROM iam.audit_outbox WHERE tenant_id=tenant AND event_document->>'action'='iam.group-membership.created'
              AND event_document#>>'{target,id}'=membership_id AND event_document->>'requestId'=event->>'requestId'
              AND event_document->>'requestDigest'=event->>'requestDigest' AND event_document#>>'{actor,id}'=actor) THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='membership intent conflicts';
        END IF;
        RETURN iam.group_membership_snapshot(tenant,membership_id);
    END IF;
    IF (SELECT count(*) FROM iam.group_memberships AS m WHERE m.tenant_id=tenant AND m.user_id=create_group_membership.user_id AND m.removed_at IS NULL)>=100 THEN
        RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='user group membership budget exceeded';
    END IF;
    INSERT INTO iam.group_memberships(tenant_id,id,group_id,user_id,created_by,resource_version,created_at,updated_at)
    VALUES(tenant,membership_id,group_id,user_id,actor,1,effective_now,effective_now);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
    VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    RETURN iam.group_membership_snapshot(tenant,membership_id);
END $function$;

CREATE OR REPLACE FUNCTION iam.remove_group_membership(tenant text,actor text,decision text,group_id text,membership_id text,expected_version bigint,event jsonb)
RETURNS TABLE(membership jsonb,applied boolean) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE stored iam.group_memberships%ROWTYPE; effective_now timestamptz(6):=transaction_timestamp();
BEGIN
    IF expected_version IS NULL OR expected_version NOT BETWEEN 1 AND 9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='membership removal input is invalid';
    END IF;
    PERFORM iam.assert_group_actor(tenant,actor);
    PERFORM 1 FROM iam.groups WHERE tenant_id=tenant AND id=group_id AND deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='membership group is unavailable'; END IF;
    SELECT m.* INTO stored FROM iam.group_memberships AS m WHERE m.tenant_id=tenant AND m.id=membership_id AND m.group_id=remove_group_membership.group_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='membership is unavailable'; END IF;
    PERFORM iam.assert_allowed_decision(tenant,actor,decision,'iam.group-membership.remove','GROUP_MEMBERSHIP',membership_id);
    PERFORM iam.assert_audit_event(event,tenant,'iam.group-membership.removed','GROUP_MEMBERSHIP',membership_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,actor,event);
    IF event->>'iamDecisionId' IS DISTINCT FROM decision THEN RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='membership decision correlation is invalid'; END IF;
    PERFORM iam.assert_group_intent(tenant,actor,event);
    IF stored.removed_at IS NOT NULL THEN
        IF stored.resource_version<>expected_version+1 OR stored.removed_by<>actor OR NOT EXISTS(
            SELECT 1 FROM iam.audit_outbox WHERE tenant_id=tenant AND event_document->>'action'='iam.group-membership.removed'
              AND event_document#>>'{target,id}'=membership_id AND event_document->>'requestId'=event->>'requestId'
              AND event_document->>'requestDigest'=event->>'requestDigest' AND event_document#>>'{actor,id}'=actor) THEN
            RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='membership removal intent conflicts';
        END IF;
        RETURN QUERY SELECT iam.group_membership_snapshot(tenant,membership_id),false;
        RETURN;
    END IF;
    IF stored.resource_version<>expected_version OR stored.resource_version=9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='membership revision conflicts';
    END IF;
    UPDATE iam.group_memberships SET resource_version=resource_version+1,updated_at=effective_now,
        removed_at=effective_now,removed_by=actor WHERE tenant_id=tenant AND id=membership_id;
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
    VALUES(tenant,event->>'eventId',event,effective_now,effective_now,effective_now);
    RETURN QUERY SELECT iam.group_membership_snapshot(tenant,membership_id),true;
END $function$;

REVOKE ALL ON TABLE iam.groups,iam.group_memberships FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
REVOKE ALL ON FUNCTION iam.assert_group_actor(text,text),iam.assert_group_intent(text,text,jsonb),iam.group_snapshot(text,text),iam.group_access_snapshot(text,text),
    iam.group_membership_snapshot(text,text),iam.guard_group_change(),iam.guard_group_membership_change(),
    iam.list_groups(text,text,text,text),iam.read_group(text,text,text,text),
    iam.create_group(text,text,text,text,text,text,jsonb),iam.update_group(text,text,text,text,text,text,bigint,jsonb),
    iam.delete_group(text,text,text,text,bigint,jsonb),iam.list_group_memberships(text,text,text,text,text),
    iam.create_group_membership(text,text,text,text,text,text,jsonb),iam.remove_group_membership(text,text,text,text,text,bigint,jsonb)
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery;
GRANT EXECUTE ON FUNCTION iam.list_groups(text,text,text,text),iam.read_group(text,text,text,text),
    iam.create_group(text,text,text,text,text,text,jsonb),iam.update_group(text,text,text,text,text,text,bigint,jsonb),
    iam.delete_group(text,text,text,text,bigint,jsonb),iam.list_group_memberships(text,text,text,text,text),
    iam.create_group_membership(text,text,text,text,text,text,jsonb),iam.remove_group_membership(text,text,text,text,text,bigint,jsonb)
    TO matrix_iam_api;
