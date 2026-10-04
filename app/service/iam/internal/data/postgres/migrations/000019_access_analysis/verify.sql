SET LOCAL ROLE matrix_iam_owner;
DO $verify_access_analysis$
BEGIN
    IF NOT iam.access_analysis_contract_ready() THEN
      RAISE EXCEPTION 'IAM access analysis contract is not ready'; END IF;
    IF (SELECT schema_version FROM iam.readiness()) IS DISTINCT FROM 65::bigint THEN
      RAISE EXCEPTION 'IAM access analysis schema version differs'; END IF;
    IF to_regprocedure('iam.claim_access_analysis(text,text)') IS NULL
      OR to_regprocedure('iam.complete_access_analysis(text,text,bigint,text,jsonb)') IS NULL
      OR to_regprocedure('iam.read_access_finding_directory_revision(text,text,text,text,text)') IS NULL
      OR to_regprocedure('iam.list_access_findings(text,text,text,text,text,text,text)') IS NULL
      OR to_regprocedure('iam.read_access_finding(text,text,text,text,text,text)') IS NULL
      OR to_regprocedure('iam.set_access_finding_archived(text,text,text,text,text,text,text,text,bigint,boolean,jsonb)') IS NULL
      OR to_regprocedure('iam.readiness_v62()') IS NULL THEN
      RAISE EXCEPTION 'IAM access analysis function shape differs'; END IF;
    IF EXISTS(SELECT 1 FROM iam.access_findings) THEN
      RAISE EXCEPTION 'IAM access analysis migration invented findings'; END IF;
END $verify_access_analysis$;
