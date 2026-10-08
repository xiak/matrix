SET LOCAL ROLE matrix_iam_owner;
DO $verify_access_analyzers$
BEGIN
    IF NOT iam.access_analyzer_contract_ready() THEN RAISE EXCEPTION 'IAM access analyzer contract is not ready'; END IF;
    IF (SELECT schema_version FROM iam.readiness()) IS DISTINCT FROM 69::bigint THEN RAISE EXCEPTION 'IAM access analyzer schema version differs'; END IF;
END $verify_access_analyzers$;
