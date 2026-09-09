BEGIN;

DO $matrix_devops_roles$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'matrix_devops_owner',
        'matrix_devops_migrator',
        'matrix_devops_api',
        'matrix_devops_check_reporter',
        'matrix_devops_source_fetcher',
        'matrix_devops_worker',
        'matrix_devops_source_observer'
    ]
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = role_name
        ) THEN
            EXECUTE format(
                'CREATE ROLE %I NOLOGIN INHERIT NOSUPERUSER NOCREATEDB '
                'NOCREATEROLE NOREPLICATION NOBYPASSRLS',
                role_name
            );
        ELSE
            EXECUTE format(
                'ALTER ROLE %I NOLOGIN INHERIT NOSUPERUSER NOCREATEDB '
                'NOCREATEROLE NOREPLICATION NOBYPASSRLS',
                role_name
            );
        END IF;
    END LOOP;
END
$matrix_devops_roles$;

DO $matrix_devops_migrator_membership$
BEGIN
    IF NOT pg_has_role('matrix_devops_migrator', 'matrix_devops_owner', 'MEMBER') THEN
        EXECUTE 'GRANT matrix_devops_owner TO matrix_devops_migrator';
    END IF;
END
$matrix_devops_migrator_membership$;

DO $matrix_devops_runtime_memberships$
DECLARE
    parent_name text;
    member_name text;
BEGIN
    FOREACH parent_name IN ARRAY ARRAY['matrix_devops_owner', 'matrix_devops_migrator']
    LOOP
        FOREACH member_name IN ARRAY ARRAY[
            'matrix_devops_api',
            'matrix_devops_check_reporter',
            'matrix_devops_source_fetcher',
            'matrix_devops_worker',
            'matrix_devops_source_observer'
        ]
        LOOP
            IF pg_has_role(member_name, parent_name, 'MEMBER') THEN
                EXECUTE format('REVOKE %I FROM %I', parent_name, member_name);
            END IF;
        END LOOP;
    END LOOP;
END
$matrix_devops_runtime_memberships$;

CREATE SCHEMA IF NOT EXISTS delivery AUTHORIZATION matrix_devops_owner;
ALTER SCHEMA delivery OWNER TO matrix_devops_owner;
REVOKE ALL ON SCHEMA delivery FROM PUBLIC;

COMMIT;
