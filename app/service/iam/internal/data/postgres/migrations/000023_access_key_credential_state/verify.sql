SET LOCAL ROLE matrix_iam_owner;
DO $verify_access_key_credential_state$
BEGIN
    IF (SELECT schema_version FROM iam.readiness()) IS DISTINCT FROM 82::bigint THEN
      RAISE EXCEPTION 'IAM access key credential state schema version differs'; END IF;
    IF NOT iam.access_key_credential_state_contract_ready() THEN
      RAISE EXCEPTION 'IAM access key credential state contract differs'; END IF;
    IF to_regprocedure('iam.readiness_v81()') IS NULL THEN
      RAISE EXCEPTION 'IAM access key credential state predecessor differs'; END IF;
END $verify_access_key_credential_state$;
