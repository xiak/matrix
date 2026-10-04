DO $verify_access_keys$
DECLARE expected record;
BEGIN
    IF NOT iam.access_key_contract_ready() THEN RAISE EXCEPTION 'IAM AccessKey contract is incompatible'; END IF;
    FOR expected IN SELECT * FROM (VALUES ('iam.access-key.list','USER'),('iam.access-key.create','USER'),
      ('iam.access-key.read','ACCESS_KEY'),('iam.access-key.set-status','ACCESS_KEY'),('iam.access-key.delete','ACCESS_KEY')) action(name,kind) LOOP
        IF iam.resource_kind_for_action(expected.name) IS DISTINCT FROM expected.kind OR iam.is_platform_action(expected.name) THEN
            RAISE EXCEPTION 'IAM AccessKey action is incompatible'; END IF;
    END LOOP;
END $verify_access_keys$;
