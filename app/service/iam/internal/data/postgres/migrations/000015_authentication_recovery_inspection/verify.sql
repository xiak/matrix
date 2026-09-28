SET LOCAL ROLE matrix_iam_owner;
DO $verify_authentication_recovery_inspection$
BEGIN
    IF to_regprocedure('iam.inspect_new_authentication_recovery(jsonb,text)') IS NULL
      OR NOT iam.authentication_recovery_contract_ready()
      OR has_function_privilege('matrix_iam_api',
        'iam.inspect_new_authentication_recovery(jsonb,text)','EXECUTE')
      OR has_function_privilege('matrix_iam_worker',
        'iam.inspect_new_authentication_recovery(jsonb,text)','EXECUTE')
      OR has_function_privilege('matrix_iam_credential_recovery',
        'iam.inspect_new_authentication_recovery(jsonb,text)','EXECUTE')
      OR has_function_privilege('matrix_iam_backup_custody',
        'iam.inspect_new_authentication_recovery(jsonb,text)','EXECUTE')
      OR has_function_privilege('matrix_iam_notification_worker',
        'iam.inspect_new_authentication_recovery(jsonb,text)','EXECUTE') THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM new recovery inspection contract is unavailable';
    END IF;
END $verify_authentication_recovery_inspection$;
