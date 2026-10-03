SET LOCAL ROLE matrix_iam_owner;
DO $verify_access_disposition$
BEGIN
    IF (SELECT schema_version FROM iam.readiness()) IS DISTINCT FROM 65::bigint THEN
      RAISE EXCEPTION 'IAM access disposition schema version differs'; END IF;
    IF NOT iam.access_disposition_contract_ready() THEN
      RAISE EXCEPTION 'IAM access disposition contract differs'; END IF;
    IF to_regprocedure('iam.set_access_disposition(text,text,text,text,text,text,text,text,integer,bigint,jsonb)') IS NULL
      OR to_regprocedure('iam.claim_access_disposition(text,text)') IS NULL
      OR to_regprocedure('iam.complete_access_disposition(text,text,bigint,text,jsonb)') IS NULL
      OR to_regprocedure('iam.readiness_v63()') IS NULL THEN
      RAISE EXCEPTION 'IAM access disposition function shape differs'; END IF;
    IF EXISTS(SELECT 1 FROM iam.access_analyzers WHERE disposition_mode<>'REVIEW_ONLY' OR disposition_delay_days<>0) THEN
      RAISE EXCEPTION 'IAM access disposition migration enabled automatic writes'; END IF;
    IF EXISTS(SELECT 1 FROM iam.access_findings WHERE status='RESOLVED' AND resolution_reason IS DISTINCT FROM 'CONDITION_CLEARED') THEN
      RAISE EXCEPTION 'IAM access disposition migration changed historical resolution meaning'; END IF;
END $verify_access_disposition$;
