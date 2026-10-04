SET LOCAL ROLE matrix_iam_owner;
DO $verification$
BEGIN
    IF NOT iam.notification_contract_ready() THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM notification contract is invalid';
    END IF;
END $verification$;
