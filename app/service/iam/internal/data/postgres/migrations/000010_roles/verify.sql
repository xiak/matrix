DO $verify_roles$
DECLARE expected record;
BEGIN
    IF NOT iam.role_contract_ready() THEN RAISE EXCEPTION 'IAM Role authority contract is incompatible'; END IF;
    IF has_function_privilege('matrix_iam_api','iam.role_contract_ready()','EXECUTE')
       OR has_function_privilege('matrix_iam_worker','iam.role_contract_ready()','EXECUTE')
       OR has_function_privilege('matrix_iam_credential_recovery','iam.role_contract_ready()','EXECUTE')
       OR has_function_privilege('public','iam.role_contract_ready()','EXECUTE') THEN
        RAISE EXCEPTION 'IAM Role internal verification is exposed';
    END IF;
    FOR expected IN SELECT * FROM (VALUES
      ('iam.role.list','ACCOUNT'),('iam.role.create','ACCOUNT'),('iam.role.read','ROLE'),('iam.role.update','ROLE'),
      ('iam.role.set-status','ROLE'),('iam.role.delete','ROLE'),('iam.role-trust.set','ROLE'),
      ('iam.role-policy-attachment.create','ROLE'),('iam.role-policy-attachment.revoke','POLICY_ATTACHMENT'),
      ('iam.role-session.list','ROLE'),('iam.role-session.read','ROLE_SESSION'),('iam.role-session.revoke','ROLE_SESSION')) action(name,kind) LOOP
        IF iam.resource_kind_for_action(expected.name) IS DISTINCT FROM expected.kind OR iam.is_platform_action(expected.name) THEN
            RAISE EXCEPTION 'IAM Role action authority is incompatible';
        END IF;
    END LOOP;
END $verify_roles$;
