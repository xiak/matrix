SET LOCAL ROLE matrix_iam_owner;
DO $verify_release_product_authority$
BEGIN
    IF (SELECT schema_version FROM iam.readiness()) IS DISTINCT FROM 88::bigint THEN
        RAISE EXCEPTION 'IAM release product authority schema version differs';
    END IF;
    IF NOT iam.release_product_authority_contract_ready()
       OR to_regprocedure('iam.readiness_v87()') IS NULL THEN
        RAISE EXCEPTION 'IAM release product authority contract differs';
    END IF;
END
$verify_release_product_authority$;
