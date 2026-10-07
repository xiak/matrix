SET LOCAL ROLE matrix_iam_owner;
DO $verify_policy_attachment_changes$
BEGIN
    IF (SELECT schema_version FROM iam.readiness()) IS DISTINCT FROM 67::bigint THEN
      RAISE EXCEPTION 'IAM policy attachment change schema version differs'; END IF;
    IF NOT iam.policy_attachment_change_contract_ready() THEN
      RAISE EXCEPTION 'IAM policy attachment change contract differs'; END IF;
    IF to_regprocedure('iam.readiness_v65()') IS NULL
      OR to_regprocedure('iam.lookup_policy_attachment_change_reference(text,text,text,text)') IS NULL
      OR to_regprocedure('iam.read_policy_attachment_change(text,text,text,text,text,text,text,text)') IS NULL THEN
      RAISE EXCEPTION 'IAM policy attachment change function shape differs'; END IF;
END $verify_policy_attachment_changes$;
