SET LOCAL ROLE matrix_iam_owner;
DO $verify_authentication_recovery$
BEGIN
    IF NOT iam.authentication_recovery_contract_ready() THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM authentication recovery contract is unavailable';
    END IF;
    IF (SELECT schema_version FROM iam.readiness()) IS DISTINCT FROM 36::bigint THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM authentication recovery schema version is unavailable';
    END IF;
END $verify_authentication_recovery$;
