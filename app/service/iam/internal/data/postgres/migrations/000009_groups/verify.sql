DO $verify_groups$
DECLARE table_name text; function_name text; protection record; action record;
BEGIN
    IF EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid='iam.policy_attachments'::regclass
            AND attname='principal_id' AND NOT attisdropped)
       OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid='iam.policy_attachments'::regclass
            AND attname='target_id' AND atttypid='text'::regtype AND attnotnull AND NOT attisdropped)
       OR to_regprocedure('iam.create_policy_attachment(text,text,text,text,bigint,text,text,jsonb)') IS NOT NULL THEN
        RAISE EXCEPTION 'IAM attachment target contract is incompatible';
    END IF;
    FOREACH table_name IN ARRAY ARRAY['groups','group_memberships'] LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class AS relation
            WHERE relation.oid=to_regclass('iam.'||table_name) AND relation.relrowsecurity AND relation.relforcerowsecurity
              AND relation.relowner='matrix_iam_owner'::regrole)
           OR has_table_privilege('matrix_iam_api','iam.'||table_name,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
           OR has_table_privilege('matrix_iam_worker','iam.'||table_name,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
           OR has_table_privilege('matrix_iam_credential_recovery','iam.'||table_name,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
           OR has_table_privilege('public','iam.'||table_name,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE') THEN
            RAISE EXCEPTION 'IAM group ownership or forced isolation is invalid';
        END IF;
    END LOOP;
    FOR protection IN SELECT * FROM (VALUES
        ('groups','groups_guard_change'),('groups','groups_cannot_delete'),('groups','groups_cannot_truncate'),
        ('group_memberships','group_memberships_guard_change'),('group_memberships','group_memberships_cannot_delete'),
        ('group_memberships','group_memberships_cannot_truncate')
    ) AS expected(table_name,trigger_name) LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger AS trigger
            WHERE trigger.tgrelid=to_regclass('iam.'||protection.table_name) AND trigger.tgname=protection.trigger_name
              AND trigger.tgenabled='A' AND NOT trigger.tgisinternal
              AND (protection.trigger_name<>'group_memberships_guard_change' OR
                (trigger.tgtype=23 AND trigger.tgfoid='iam.guard_group_membership_change()'::regprocedure))) THEN
            RAISE EXCEPTION 'IAM group terminal history protection is invalid';
        END IF;
    END LOOP;
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_index WHERE indexrelid=to_regclass('iam.groups_active_name_uq') AND indisunique AND indisvalid)
       OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_index WHERE indexrelid=to_regclass('iam.group_memberships_active_uq') AND indisunique AND indisvalid)
       OR (SELECT count(*) FROM pg_catalog.pg_constraint WHERE conrelid='iam.group_memberships'::regclass AND contype='f' AND convalidated)<>4 THEN
        RAISE EXCEPTION 'IAM group relationship constraints are invalid';
    END IF;
    FOREACH function_name IN ARRAY ARRAY[
        'iam.list_groups(text,text,text,text)','iam.read_group(text,text,text,text)',
        'iam.create_group(text,text,text,text,text,text,jsonb)','iam.update_group(text,text,text,text,text,text,bigint,jsonb)',
        'iam.delete_group(text,text,text,text,bigint,jsonb)','iam.list_group_memberships(text,text,text,text,text)',
        'iam.create_group_membership(text,text,text,text,text,text,jsonb)',
        'iam.create_policy_attachment(text,text,text,text,text,bigint,text,text,jsonb,text)'
    ] LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS entrypoint WHERE entrypoint.oid=to_regprocedure(function_name)
            AND entrypoint.prosecdef AND entrypoint.proowner='matrix_iam_owner'::regrole
            AND entrypoint.prorettype='jsonb'::regtype AND NOT entrypoint.proretset)
           OR NOT has_function_privilege('matrix_iam_api',function_name,'EXECUTE')
           OR has_function_privilege('matrix_iam_worker',function_name,'EXECUTE')
           OR has_function_privilege('matrix_iam_credential_recovery',function_name,'EXECUTE')
           OR has_function_privilege('public',function_name,'EXECUTE') THEN
            RAISE EXCEPTION 'IAM group API contract or admission is invalid';
        END IF;
    END LOOP;
    function_name := 'iam.remove_group_membership(text,text,text,text,text,bigint,jsonb)';
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc AS removal WHERE removal.oid=to_regprocedure(function_name)
        AND removal.prosecdef AND removal.proowner='matrix_iam_owner'::regrole AND removal.proretset
        AND removal.proargnames[8:9]=ARRAY['membership','applied']
        AND removal.proallargtypes[8:9]=ARRAY['jsonb'::regtype::oid,'boolean'::regtype::oid]
        AND removal.proargmodes[8:9]=ARRAY['t','t']::"char"[])
       OR NOT has_function_privilege('matrix_iam_api',function_name,'EXECUTE')
       OR has_function_privilege('matrix_iam_worker',function_name,'EXECUTE')
       OR has_function_privilege('matrix_iam_credential_recovery',function_name,'EXECUTE')
       OR has_function_privilege('public',function_name,'EXECUTE') THEN
        RAISE EXCEPTION 'IAM group membership removal contract is invalid';
    END IF;
    FOREACH function_name IN ARRAY ARRAY['iam.assert_group_actor(text,text)','iam.assert_group_intent(text,text,jsonb)','iam.group_snapshot(text,text)',
        'iam.group_access_snapshot(text,text)','iam.group_membership_snapshot(text,text)'] LOOP
        IF to_regprocedure(function_name) IS NULL
           OR has_function_privilege('matrix_iam_api',function_name,'EXECUTE')
           OR has_function_privilege('matrix_iam_worker',function_name,'EXECUTE')
           OR has_function_privilege('matrix_iam_credential_recovery',function_name,'EXECUTE')
           OR has_function_privilege('public',function_name,'EXECUTE') THEN
            RAISE EXCEPTION 'IAM group internal projection is exposed';
        END IF;
    END LOOP;
    FOR action IN SELECT * FROM (VALUES
        ('iam.group.list','ACCOUNT'),('iam.group.create','ACCOUNT'),('iam.group.read','GROUP'),
        ('iam.group.update','GROUP'),('iam.group.delete','GROUP'),('iam.group-membership.list','GROUP'),
        ('iam.group-membership.create','GROUP'),('iam.group-membership.remove','GROUP_MEMBERSHIP'),
        ('iam.group-policy-attachment.create','GROUP'),('iam.group-policy-attachment.revoke','POLICY_ATTACHMENT')
    ) AS expected(name,kind) LOOP
        IF iam.resource_kind_for_action(action.name) IS DISTINCT FROM action.kind OR iam.is_platform_action(action.name) THEN
            RAISE EXCEPTION 'IAM group action authority is incompatible';
        END IF;
    END LOOP;
END $verify_groups$;
