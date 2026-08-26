DO $matrix_iam_verify_managedservice_actions$
BEGIN
    IF iam.resource_kind_for_action('managedservice.offering.read')
           IS DISTINCT FROM 'SERVICE_OFFERING'
       OR iam.resource_kind_for_action('managedservice.region.read')
           IS DISTINCT FROM 'REGION'
       OR iam.resource_kind_for_action('managedservice.quota-entitlement.activate')
           IS DISTINCT FROM 'QUOTA_ENTITLEMENT'
       OR iam.resource_kind_for_action('managedservice.quota-entitlement.read')
           IS DISTINCT FROM 'QUOTA_ENTITLEMENT'
       OR iam.resource_kind_for_action('managedservice.service-installation.create')
           IS DISTINCT FROM 'SERVICE_INSTALLATION'
       OR iam.resource_kind_for_action('managedservice.service-installation.read')
           IS DISTINCT FROM 'SERVICE_INSTALLATION'
       OR iam.resource_kind_for_action('managedservice.unsupported') IS NOT NULL THEN
        RAISE EXCEPTION 'IAM managed-service action mapping is invalid';
    END IF;
END
$matrix_iam_verify_managedservice_actions$;
