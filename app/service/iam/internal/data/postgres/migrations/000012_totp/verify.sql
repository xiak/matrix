SET LOCAL ROLE matrix_iam_owner;
DO $verification$
BEGIN
    IF NOT iam.totp_custody_contract_ready() OR NOT iam.totp_backup_custody_contract_ready() THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='TOTP custody contract is invalid';
    END IF;
END $verification$;
