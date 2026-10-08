SET LOCAL ROLE matrix_iam_owner;
DO $verify_security_reports$
BEGIN
    IF NOT iam.security_report_contract_ready() THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM security report storage contract is unavailable'; END IF;
    IF (SELECT schema_version FROM iam.readiness()) IS DISTINCT FROM 70::bigint THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='IAM security report schema version is unavailable'; END IF;
END $verify_security_reports$;
