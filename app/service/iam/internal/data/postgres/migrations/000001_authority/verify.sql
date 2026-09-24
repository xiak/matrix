DO $matrix_iam_verify$
DECLARE
    missing text;
BEGIN
    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES
        ('matrix_iam_owner'), ('matrix_iam_migrator'),
        ('matrix_iam_api'), ('matrix_iam_worker')
      ) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles AS role
         WHERE role.rolname = required.name
           AND NOT role.rolsuper AND NOT role.rolcreatedb
           AND NOT role.rolcreaterole AND NOT role.rolreplication
           AND NOT role.rolbypassrls AND NOT role.rolcanlogin
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing or overprivileged IAM roles: %', missing;
    END IF;

    IF NOT pg_has_role('matrix_iam_migrator', 'matrix_iam_owner', 'MEMBER')
       OR pg_has_role('matrix_iam_api', 'matrix_iam_owner', 'MEMBER')
       OR pg_has_role('matrix_iam_api', 'matrix_iam_migrator', 'MEMBER')
       OR pg_has_role('matrix_iam_worker', 'matrix_iam_owner', 'MEMBER')
       OR pg_has_role('matrix_iam_worker', 'matrix_iam_migrator', 'MEMBER') THEN
        RAISE EXCEPTION 'IAM role membership boundary is invalid';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_namespace AS namespace
          JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = namespace.nspowner
         WHERE namespace.nspname = 'iam'
           AND owner_role.rolname = 'matrix_iam_owner'
    ) OR has_schema_privilege('public', 'iam', 'USAGE') THEN
        RAISE EXCEPTION 'IAM schema ownership or PUBLIC boundary is invalid';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES
        ('bootstrap_receipts'), ('accounts'), ('principals'),
        ('policy_attachments'), ('user_credentials'), ('password_attempts'), ('login_index'),
        ('service_credentials'), ('service_credential_index'),
        ('sessions'), ('session_index'), ('authorization_decisions'),
        ('audit_outbox')
      ) AS required(name)
     WHERE to_regclass('iam.' || required.name) IS NULL;
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'missing IAM tables: %', missing;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_class AS class
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
          JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = class.relowner
         WHERE namespace.nspname = 'iam'
           AND class.relkind IN ('r', 'p')
           AND owner_role.rolname <> 'matrix_iam_owner'
    ) THEN
        RAISE EXCEPTION 'IAM tables are not owner-role owned';
    END IF;

    SELECT string_agg(required.name, ', ' ORDER BY required.name)
      INTO missing
      FROM (VALUES
        ('accounts'), ('principals'), ('policy_attachments'),
        ('user_credentials'), ('password_attempts'), ('service_credentials'), ('sessions'),
        ('authorization_decisions'), ('audit_outbox')
      ) AS required(name)
     WHERE NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_class AS class
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
         WHERE namespace.nspname = 'iam'
           AND class.relname = required.name
           AND class.relrowsecurity AND class.relforcerowsecurity
     );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'IAM tenant tables missing forced RLS: %', missing;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM information_schema.role_table_grants AS grant_row
         WHERE grant_row.table_schema = 'iam'
           AND grant_row.grantee IN ('matrix_iam_api', 'matrix_iam_worker', 'PUBLIC')
    ) THEN
        RAISE EXCEPTION 'IAM runtime or PUBLIC has direct table privileges';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM information_schema.columns AS column_row
         WHERE column_row.table_schema = 'iam'
           AND column_row.column_name IN (
                'password', 'credential', 'credential_value', 'secret', 'token'
           )
    ) THEN
        RAISE EXCEPTION 'IAM schema contains plaintext credential columns';
    END IF;

    IF NOT has_function_privilege(
            'matrix_iam_api',
            'iam.apply_bootstrap(text,text,text,text,text,text,text,text,jsonb,jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege('matrix_iam_api', 'iam.bootstrap_status()', 'EXECUTE')
       OR NOT has_function_privilege('matrix_iam_api', 'iam.readiness()', 'EXECUTE')
       OR has_function_privilege('matrix_iam_api', 'iam.lookup_login(text)', 'EXECUTE')
       OR NOT iam.password_attempt_contract_ready()
       OR NOT has_function_privilege(
            'matrix_iam_api',
            'iam.issue_session(text,text,text,text,text,integer,jsonb,text,bigint)',
            'EXECUTE'
       )
       OR NOT has_function_privilege('matrix_iam_api', 'iam.lookup_session(text)', 'EXECUTE')
       OR NOT has_function_privilege('matrix_iam_api', 'iam.lookup_service(text)', 'EXECUTE')
       OR NOT has_function_privilege(
            'matrix_iam_api', 'iam.lookup_service_policies(text,text)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_api',
            'iam.record_authorization(text,text,jsonb,jsonb,jsonb,jsonb,integer,jsonb,jsonb)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_api', 'iam.change_password(text,text,text,text,jsonb,text,boolean,text,bigint)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_api', 'iam.revoke_session(text,text,text,text,jsonb,text)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_api', 'iam.create_user(text,text,text,text,text,text,text,jsonb)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_api', 'iam.create_policy_attachment(text,text,text,text,text,bigint,text,text,jsonb,text)', 'EXECUTE'
       )
       OR NOT has_function_privilege('matrix_iam_api', 'iam.lookup_policy(text,text)', 'EXECUTE')
       OR NOT has_function_privilege('matrix_iam_api', 'iam.list_policies(text,text,text,text)', 'EXECUTE')
       OR has_function_privilege('matrix_iam_worker', 'iam.list_policies(text,text,text,text)', 'EXECUTE')
       OR has_function_privilege('matrix_iam_credential_recovery', 'iam.list_policies(text,text,text,text)', 'EXECUTE')
       OR NOT has_function_privilege('matrix_iam_api', 'iam.lookup_policy_attachment(text,text)', 'EXECUTE')
       OR has_function_privilege('matrix_iam_worker', 'iam.lookup_policy_attachment(text,text)', 'EXECUTE')
       OR has_function_privilege('matrix_iam_worker', 'iam.lookup_policy(text,text)', 'EXECUTE')
       OR NOT has_function_privilege(
            'matrix_iam_api', 'iam.revoke_policy_attachment(text,text,bigint,text,text,jsonb,text)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_worker', 'iam.claim_audit_event(text,integer)', 'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_worker',
            'iam.complete_audit_event(text,text,bigint,text,integer,text)',
            'EXECUTE'
       )
       OR NOT has_function_privilege(
            'matrix_iam_worker', 'iam.audit_outbox_snapshot()', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_iam_api', 'iam.claim_audit_event(text,integer)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_iam_worker', 'iam.lookup_login(text)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_iam_api', 'iam.audit_outbox_snapshot()', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_iam_worker',
            'iam.change_password(text,text,text,text,jsonb,text,boolean,text,bigint)',
            'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_iam_api', 'iam.resource_kind_for_action(text)', 'EXECUTE'
       )
       OR has_function_privilege('matrix_iam_api', 'iam.is_platform_action(text)', 'EXECUTE')
       OR has_function_privilege(
            'matrix_iam_api', 'iam.assert_allowed_decision(text,text,text,text,text,text,text,text)', 'EXECUTE'
       )
       OR has_function_privilege(
            'matrix_iam_api', 'iam.assert_user_audit_actor(text,text,jsonb)', 'EXECUTE'
       ) THEN
        RAISE EXCEPTION 'IAM API/worker function authority is invalid';
    END IF;

    IF to_regprocedure('iam.change_password(text,text,text,text,jsonb)') IS NOT NULL
       OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_attribute AS column_definition
            WHERE column_definition.attrelid = 'iam.sessions'::regclass
              AND column_definition.attname = 'credential_version'
              AND column_definition.atttypid = 'bigint'::regtype
              AND NOT column_definition.attisdropped
       ) OR NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_attribute AS column_definition
            WHERE column_definition.attrelid = 'iam.user_credentials'::regclass
              AND column_definition.attname = 'credential_version'
              AND column_definition.atttypid = 'bigint'::regtype
              AND column_definition.attnotnull
              AND NOT column_definition.attisdropped
       ) THEN
        RAISE EXCEPTION 'IAM password/session contract is invalid';
    END IF;

    IF to_regnamespace('audit') IS NOT NULL AND (
        has_schema_privilege('matrix_iam_api', 'audit', 'USAGE')
        OR has_schema_privilege('matrix_iam_worker', 'audit', 'USAGE')
    ) THEN
        RAISE EXCEPTION 'IAM runtime roles can access Audit schema';
    END IF;

    IF iam.resource_kind_for_action('managedservice.offering.read') IS DISTINCT FROM 'SERVICE_OFFERING'
       OR iam.resource_kind_for_action('managedservice.region.read') IS DISTINCT FROM 'REGION'
       OR iam.resource_kind_for_action('managedservice.quota-entitlement.activate') IS DISTINCT FROM 'QUOTA_ENTITLEMENT'
       OR iam.resource_kind_for_action('managedservice.quota-entitlement.read') IS DISTINCT FROM 'QUOTA_ENTITLEMENT'
       OR iam.resource_kind_for_action('managedservice.service-installation.create') IS DISTINCT FROM 'SERVICE_INSTALLATION'
       OR iam.resource_kind_for_action('managedservice.service-installation.read') IS DISTINCT FROM 'SERVICE_INSTALLATION'
       OR iam.resource_kind_for_action('paas.execution-target.register') IS DISTINCT FROM 'EXECUTION_TARGET'
       OR iam.resource_kind_for_action('paas.execution-pool.create') IS DISTINCT FROM 'EXECUTION_POOL'
       OR EXISTS (
           SELECT 1 FROM (VALUES
               ('paas.execution-pool.read','EXECUTION_POOL'),
               ('paas.execution-target.read','EXECUTION_TARGET'),
               ('paas.execution-target.drain','EXECUTION_TARGET'),
               ('paas.execution-target.activate','EXECUTION_TARGET'),
               ('paas.execution-target.remove','EXECUTION_TARGET'),
               ('paas.node-enrollment.create','NODE_ENROLLMENT'),
               ('paas.node-enrollment.read','NODE_ENROLLMENT'),
               ('paas.node-enrollment.revoke','NODE_ENROLLMENT'),
               ('paas.node-enrollment.regenerate','NODE_ENROLLMENT'),
               ('paas.platform-operation.read','OPERATION')
           ) AS platform(action,resource)
           WHERE iam.resource_kind_for_action(platform.action) IS DISTINCT FROM platform.resource
               OR NOT iam.is_platform_action(platform.action)
       )
       OR iam.resource_kind_for_action('iam.account.create') IS DISTINCT FROM 'ACCOUNT'
       OR iam.resource_kind_for_action('iam.account.read') IS DISTINCT FROM 'ACCOUNT'
       OR iam.resource_kind_for_action('iam.account.set-status') IS DISTINCT FROM 'ACCOUNT'
       OR iam.resource_kind_for_action('iam.account.recover-root-credentials') IS DISTINCT FROM 'ACCOUNT'
       OR iam.resource_kind_for_action('iam.account.alias-set') IS DISTINCT FROM 'ACCOUNT'
       OR iam.resource_kind_for_action('iam.user.list') IS DISTINCT FROM 'ACCOUNT'
       OR iam.resource_kind_for_action('iam.user.create') IS DISTINCT FROM 'ACCOUNT'
       OR iam.resource_kind_for_action('iam.user.read') IS DISTINCT FROM 'USER'
       OR iam.resource_kind_for_action('iam.user.update') IS DISTINCT FROM 'USER'
       OR iam.resource_kind_for_action('iam.user.delete') IS DISTINCT FROM 'USER'
       OR iam.resource_kind_for_action('iam.user.set-status') IS DISTINCT FROM 'USER'
       OR iam.resource_kind_for_action('iam.user.reset-password') IS DISTINCT FROM 'USER'
       OR iam.resource_kind_for_action('iam.policy-attachment.create') IS DISTINCT FROM 'USER'
       OR iam.resource_kind_for_action('iam.policy-attachment.revoke') IS DISTINCT FROM 'POLICY_ATTACHMENT'
       OR iam.resource_kind_for_action('iam.platform-policy-attachment.create') IS DISTINCT FROM 'USER'
       OR iam.resource_kind_for_action('iam.policy.list') IS DISTINCT FROM 'ACCOUNT'
       OR iam.resource_kind_for_action('iam.platform-policy.list') IS DISTINCT FROM 'INSTALLATION'
       OR NOT iam.is_platform_action('iam.platform-policy.list')
       OR iam.is_platform_action('iam.policy.list')
       OR iam.resource_kind_for_action('iam.platform-policy-attachment.revoke') IS DISTINCT FROM 'POLICY_ATTACHMENT'
       OR NOT iam.is_platform_action('iam.platform-policy-attachment.create')
       OR NOT iam.is_platform_action('iam.platform-policy-attachment.revoke')
       OR iam.is_platform_action('iam.policy-attachment.create')
       OR iam.is_platform_action('iam.policy-attachment.revoke')
       OR EXISTS (
           SELECT 1 FROM unnest(ARRAY[
               'iam.organization.create', 'iam.organization.read',
               'iam.organization.set-status', 'iam.organization-administrator.recover',
               'iam.account-alias.set', 'iam.principal.list',
               'iam.principal.set-status', 'iam.password.reset',
               'iam.principal.create', 'iam.principal.read',
               'iam.role-binding.put', 'iam.role-binding.revoke',
               'iam.platform-role-binding.put', 'iam.platform-role-binding.revoke'
           ]) AS retired(action)
           WHERE iam.resource_kind_for_action(retired.action) IS NOT NULL OR iam.is_platform_action(retired.action) IS NOT NULL
       )
       OR iam.resource_kind_for_action('unsupported') IS NOT NULL
       OR NOT iam.is_platform_action('paas.execution-target.register')
       OR iam.is_platform_action('paas.application.create')
       OR iam.is_platform_action('unsupported') IS NOT NULL THEN
        RAISE EXCEPTION 'IAM authorization action mapping is invalid';
    END IF;
    IF EXISTS(SELECT 1 FROM iam.authorization_profile_heads head
        JOIN iam.authorization_profiles archive ON archive.product=head.product AND archive.revision=head.revision
        CROSS JOIN LATERAL jsonb_array_elements(archive.canonical_document::jsonb->'actions') action
        WHERE iam.resource_kind_for_action(action->>'action') IS DISTINCT FROM action->>'resourceKind'
          OR iam.is_platform_action(action->>'action') IS DISTINCT FROM (action->>'scope'='INSTALLATION')) THEN
        RAISE EXCEPTION 'IAM current action projections differ from registered declarations';
    END IF;
END
$matrix_iam_verify$;

DO $matrix_profile_verify$
DECLARE
    seeds jsonb := __AUTHORIZATION_PROFILE_SEEDS__;
    seed jsonb;
    entry regprocedure;
BEGIN
    IF (SELECT schema_version FROM iam.readiness())<>44 OR NOT iam.authorization_decision_contract_ready()
        OR NOT iam.login_session_contract_ready()
        OR NOT iam.policy_attachment_contract_ready() THEN
        RAISE EXCEPTION 'IAM profile registry schema is invalid';
    END IF;
    FOREACH entry IN ARRAY ARRAY['iam.authorization_decision_contract_ready()'::regprocedure,
        'iam.policy_attachment_contract_ready()'::regprocedure,
        'iam.authorization_decision_profile_matches(jsonb)'::regprocedure,
        'iam.resource_kind_for_action(text)'::regprocedure,'iam.is_platform_action(text)'::regprocedure,
        'iam.assert_allowed_decision(text,text,text,text,text,text,text,text)'::regprocedure] LOOP
        IF has_function_privilege('matrix_iam_api',entry,'EXECUTE') OR has_function_privilege('matrix_iam_worker',entry,'EXECUTE')
            OR has_function_privilege('matrix_iam_credential_recovery',entry,'EXECUTE') OR has_function_privilege('public',entry,'EXECUTE') THEN
            RAISE EXCEPTION 'IAM internal decision boundary is exposed';
        END IF;
    END LOOP;
    FOREACH entry IN ARRAY ARRAY['iam.resource_kind_for_action(text)'::regprocedure,'iam.is_platform_action(text)'::regprocedure] LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid=entry AND p.provolatile='s' AND p.proparallel='u'
            AND NOT p.prosecdef AND NOT p.proretset AND p.proowner='matrix_iam_owner'::regrole
            AND (SELECT count(*)=1 AND bool_and(
                (SELECT array_agg(parse_ident(btrim(component.name),true) ORDER BY component.position)
                 FROM unnest(string_to_array(substr(config.setting,strpos(config.setting,'=')+1),','))
                    WITH ORDINALITY AS component(name,position))=ARRAY[ARRAY['pg_catalog'],ARRAY['pg_temp']])
                FROM unnest(p.proconfig) AS config(setting) WHERE split_part(config.setting,'=',1)='search_path')) THEN
            RAISE EXCEPTION 'IAM current projection function boundary is invalid';
        END IF;
    END LOOP;
    FOR seed IN SELECT value FROM jsonb_array_elements(seeds->'archive') LOOP
        IF NOT EXISTS(SELECT 1 FROM iam.authorization_profiles archive
            WHERE archive.product=seed->>'product' AND archive.revision=(seed->>'revision')::bigint
              AND archive.content_digest=seed->>'contentDigest' AND archive.canonical_document=seed->>'canonicalDocument') THEN
            RAISE EXCEPTION 'IAM immutable profile registration is missing or changed';
        END IF;
    END LOOP;
    IF (SELECT count(*) FROM iam.authorization_profile_heads)<>jsonb_array_length(seeds->'heads') THEN
        RAISE EXCEPTION 'IAM current product set differs from source';
    END IF;
    FOR seed IN SELECT value FROM jsonb_array_elements(seeds->'heads') LOOP
        IF NOT EXISTS(SELECT 1 FROM iam.authorization_profile_heads head
            JOIN iam.authorization_profiles archive USING(product,revision)
            WHERE head.product=seed->>'product' AND head.revision=(seed->>'revision')::bigint
              AND archive.content_digest=seed->>'contentDigest') THEN
            RAISE EXCEPTION 'IAM current product selection differs from source';
        END IF;
    END LOOP;
    IF (SELECT count(*) FROM pg_trigger protection
        WHERE protection.tgrelid IN ('iam.authorization_profiles'::regclass,'iam.authorization_profile_heads'::regclass)
          AND protection.tgname IN ('authorization_profiles_are_immutable','authorization_profiles_cannot_be_truncated',
            'authorization_profile_heads_advance','authorization_profile_heads_cannot_be_deleted','authorization_profile_heads_cannot_be_truncated')
          AND NOT protection.tgisinternal AND protection.tgenabled='A')<>5 THEN
        RAISE EXCEPTION 'IAM product registry mutation protection is invalid';
    END IF;
    FOREACH entry IN ARRAY ARRAY['iam.current_authorization_profiles()'::regprocedure,
        'iam.lookup_authorization_profile(text,bigint,text)'::regprocedure] LOOP
        IF NOT EXISTS(SELECT 1 FROM pg_proc entry_proc WHERE entry_proc.oid=entry AND entry_proc.prosecdef
            AND entry_proc.proowner='matrix_iam_owner'::regrole AND entry_proc.proretset
            AND (SELECT count(*)=1 AND bool_and(
                (SELECT array_agg(parse_ident(btrim(component.name),true) ORDER BY component.position)
                 FROM unnest(string_to_array(substr(config.setting,strpos(config.setting,'=')+1),','))
                    WITH ORDINALITY AS component(name,position))
                =ARRAY[ARRAY['pg_catalog'],ARRAY['pg_temp']])
                FROM unnest(entry_proc.proconfig) AS config(setting)
                WHERE split_part(config.setting,'=',1)='search_path')
            AND entry_proc.proargnames[cardinality(entry_proc.proargnames)-3:cardinality(entry_proc.proargnames)]
                =ARRAY['product','revision','canonical_document','content_digest']
            AND entry_proc.proallargtypes[cardinality(entry_proc.proallargtypes)-3:cardinality(entry_proc.proallargtypes)]
                =ARRAY['text'::regtype::oid,'bigint'::regtype::oid,'text'::regtype::oid,'text'::regtype::oid])
            OR NOT has_function_privilege('matrix_iam_api',entry,'EXECUTE')
            OR has_function_privilege('matrix_iam_worker',entry,'EXECUTE')
            OR has_function_privilege('matrix_iam_credential_recovery',entry,'EXECUTE')
            OR EXISTS(SELECT 1 FROM pg_proc entry_proc,
                LATERAL aclexplode(COALESCE(entry_proc.proacl,acldefault('f',entry_proc.proowner))) grant_entry
                WHERE entry_proc.oid=entry AND grant_entry.privilege_type='EXECUTE'
                  AND (grant_entry.grantee NOT IN (entry_proc.proowner,'matrix_iam_api'::regrole)
                    OR (grant_entry.grantee='matrix_iam_api'::regrole AND grant_entry.is_grantable))) THEN
            RAISE EXCEPTION 'IAM product registry read boundary is invalid';
        END IF;
    END LOOP;
END
$matrix_profile_verify$;
