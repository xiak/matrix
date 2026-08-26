BEGIN;

CREATE OR REPLACE FUNCTION iam.resource_kind_for_action(submitted_action text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT CASE submitted_action
        WHEN 'iam.principal.create' THEN 'ORGANIZATION'
        WHEN 'iam.principal.read' THEN 'PRINCIPAL'
        WHEN 'iam.role-binding.put' THEN 'PRINCIPAL'
        WHEN 'iam.role-binding.revoke' THEN 'ROLE_BINDING'
        WHEN 'iam.session.revoke' THEN 'SESSION'
        WHEN 'paas.application.create' THEN 'APPLICATION'
        WHEN 'paas.application.read' THEN 'APPLICATION'
        WHEN 'paas.configuration.create' THEN 'CONFIGURATION'
        WHEN 'paas.configuration.read' THEN 'CONFIGURATION'
        WHEN 'paas.configuration-revision.create' THEN 'CONFIGURATION_REVISION'
        WHEN 'paas.configuration-revision.read' THEN 'CONFIGURATION_REVISION'
        WHEN 'paas.application-revision.create' THEN 'APPLICATION_REVISION'
        WHEN 'paas.application-revision.read' THEN 'APPLICATION_REVISION'
        WHEN 'paas.deployment.create' THEN 'DEPLOYMENT'
        WHEN 'paas.deployment.update' THEN 'DEPLOYMENT'
        WHEN 'paas.deployment.rollback' THEN 'DEPLOYMENT'
        WHEN 'paas.deployment.stop' THEN 'DEPLOYMENT'
        WHEN 'paas.deployment.read' THEN 'DEPLOYMENT'
        WHEN 'paas.operation.read' THEN 'OPERATION'
        WHEN 'managedservice.offering.read' THEN 'SERVICE_OFFERING'
        WHEN 'managedservice.region.read' THEN 'REGION'
        WHEN 'managedservice.quota-entitlement.activate' THEN 'QUOTA_ENTITLEMENT'
        WHEN 'managedservice.quota-entitlement.read' THEN 'QUOTA_ENTITLEMENT'
        WHEN 'managedservice.service-installation.create' THEN 'SERVICE_INSTALLATION'
        WHEN 'managedservice.service-installation.read' THEN 'SERVICE_INSTALLATION'
        WHEN 'audit.record.read' THEN 'AUDIT_RECORD'
        WHEN 'audit.integrity.verify' THEN 'AUDIT_CHAIN'
        WHEN 'installation.verify' THEN 'INSTALLATION'
        ELSE NULL
    END
$function$;

COMMIT;
