SET LOCAL ROLE matrix_iam_owner;

-- New-intent inspection is a bounded pre-journal check. It cannot return the
-- private security snapshot or turn a historical close receipt into a fresh
-- recovery permit. Close independently repeats the complete qualification.
CREATE OR REPLACE FUNCTION iam.inspect_new_authentication_recovery(intent jsonb,intent_digest text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; snapshot jsonb;
BEGIN
    IF NOT pg_has_role(session_user,'matrix_iam_authentication_recovery','USAGE')
      OR current_setting('transaction_isolation')<>'serializable' OR current_setting('transaction_read_only')<>'off' THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication recovery inspection context is forbidden';
    END IF;
    IF jsonb_typeof(intent) IS DISTINCT FROM 'object'
      OR COALESCE(intent->>'installationId','') COLLATE "C" !~ '^mxi-[0-9a-f]{32}$'
      OR COALESCE(intent->>'commandId','') COLLATE "C" !~ '^cmd-[0-9a-f]{32}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='authentication recovery inspection intent is invalid';
    END IF;
    SELECT * INTO receipt FROM iam.bootstrap_receipts
      WHERE singleton AND installation_id=intent->>'installationId' FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='authentication recovery inspection installation is forbidden';
    END IF;
    -- This check precedes prepare's replay branch. An equal historical close
    -- must not yield ELIGIBLE, even if its original snapshot is still stored.
    IF EXISTS(SELECT 1 FROM iam.authentication_recovery_closures c
      WHERE c.command_id=intent->>'commandId') THEN
        RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='authentication recovery inspection command conflicts';
    END IF;
    snapshot:=iam.prepare_authentication_recovery_close(intent,intent_digest);
    IF snapshot->>'apiVersion' IS DISTINCT FROM 'installation.matrix.xiak.com/v1'
      OR snapshot->>'kind' IS DISTINCT FROM 'IAMAuthenticationRecoverySecuritySnapshot'
      OR snapshot->>'purpose' IS DISTINCT FROM 'IAM_AUTHENTICATION_BACKUP_RECOVERY'
      OR snapshot->>'installationId' IS DISTINCT FROM receipt.installation_id
      OR snapshot->>'bootstrapDigest' IS DISTINCT FROM receipt.content_digest
      OR snapshot->>'commandId' IS DISTINCT FROM intent->>'commandId'
      OR snapshot->>'recoveryIntentDigest' IS DISTINCT FROM intent_digest
      OR snapshot->>'authenticationStateDigest' IS DISTINCT FROM intent->>'authenticationStateDigest'
      OR jsonb_typeof(snapshot->'epoch') IS DISTINCT FROM 'number' THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='authentication recovery inspection projection is unavailable';
    END IF;
    RETURN jsonb_build_object(
      'apiVersion','installation.matrix.xiak.com/v1',
      'kind','IAMAuthenticationRecoveryInspection',
      'purpose','IAM_AUTHENTICATION_BACKUP_RECOVERY',
      'state','ELIGIBLE',
      'installationId',receipt.installation_id,
      'bootstrapDigest',receipt.content_digest,
      'epoch',snapshot->'epoch',
      'commandId',intent->>'commandId',
      'recoveryIntentDigest',intent_digest,
      'authenticationStateDigest',snapshot->>'authenticationStateDigest');
END $function$;

REVOKE ALL ON FUNCTION iam.inspect_new_authentication_recovery(jsonb,text)
  FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,
    matrix_iam_backup_custody,matrix_iam_notification_worker,matrix_iam_authentication_recovery;
GRANT EXECUTE ON FUNCTION iam.inspect_new_authentication_recovery(jsonb,text)
  TO matrix_iam_authentication_recovery;
