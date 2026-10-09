SET LOCAL ROLE matrix_iam_owner;
DO $verify_access_key_list_authorization$
BEGIN
    IF (SELECT schema_version FROM iam.readiness()) IS DISTINCT FROM 77::bigint THEN
      RAISE EXCEPTION 'IAM access key list authorization schema version differs'; END IF;
    IF NOT iam.access_key_contract_ready() THEN
      RAISE EXCEPTION 'IAM access key list authorization contract differs'; END IF;
    IF to_regprocedure('iam.readiness_v66()') IS NULL THEN
      RAISE EXCEPTION 'IAM access key list authorization predecessor differs'; END IF;
END $verify_access_key_list_authorization$;
