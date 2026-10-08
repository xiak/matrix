SET LOCAL ROLE matrix_iam_owner;

-- Schema 69 keeps one signed AccessKey request the durable nonce owner while
-- allowing its bounded list decisions to reference that same immutable proof.
-- The actual tables/functions are evolved in the access-key owner so clean
-- installs and retained schema-67 upgrades converge on one final contract.
DO $access_key_list_readiness_cutover$
BEGIN
    IF to_regprocedure('iam.readiness_v66()') IS NOT NULL THEN DROP FUNCTION iam.readiness_v66(); END IF;
    ALTER FUNCTION iam.readiness() RENAME TO readiness_v66;
END $access_key_list_readiness_cutover$;
REVOKE ALL ON FUNCTION iam.readiness_v66() FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,
  matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
CREATE FUNCTION iam.readiness()
RETURNS TABLE(ready boolean,schema_version bigint,checked_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE predecessor record;
BEGIN
    SELECT * INTO predecessor FROM iam.readiness_v66();
    RETURN QUERY SELECT predecessor.ready AND iam.access_key_contract_ready(),69::bigint,predecessor.checked_at;
END $function$;
REVOKE ALL ON FUNCTION iam.readiness() FROM PUBLIC,matrix_iam_worker,matrix_iam_credential_recovery,
  matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery,matrix_iam_access_analysis_worker;
GRANT EXECUTE ON FUNCTION iam.readiness() TO matrix_iam_api;
