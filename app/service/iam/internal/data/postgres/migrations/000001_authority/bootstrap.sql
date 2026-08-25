BEGIN;

DO $matrix_iam_roles$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'matrix_iam_owner',
        'matrix_iam_migrator',
        'matrix_iam_api',
        'matrix_iam_worker'
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
$matrix_iam_roles$;

DO $matrix_iam_migrator_membership$
BEGIN
    IF NOT pg_has_role('matrix_iam_migrator', 'matrix_iam_owner', 'MEMBER') THEN
        EXECUTE 'GRANT matrix_iam_owner TO matrix_iam_migrator';
    END IF;
END
$matrix_iam_migrator_membership$;
DO $matrix_iam_runtime_memberships$
DECLARE
    parent_name text;
    member_name text;
BEGIN
    FOREACH parent_name IN ARRAY ARRAY['matrix_iam_owner', 'matrix_iam_migrator']
    LOOP
        FOREACH member_name IN ARRAY ARRAY['matrix_iam_api', 'matrix_iam_worker']
        LOOP
            IF EXISTS (
                SELECT 1
                  FROM pg_catalog.pg_auth_members AS membership
                  JOIN pg_catalog.pg_roles AS parent_role
                    ON parent_role.oid = membership.roleid
                  JOIN pg_catalog.pg_roles AS member_role
                    ON member_role.oid = membership.member
                 WHERE parent_role.rolname = parent_name
                   AND member_role.rolname = member_name
            ) THEN
                EXECUTE format('REVOKE %I FROM %I', parent_name, member_name);
            END IF;
        END LOOP;
    END LOOP;
END
$matrix_iam_runtime_memberships$;

CREATE SCHEMA IF NOT EXISTS iam AUTHORIZATION matrix_iam_owner;
ALTER SCHEMA iam OWNER TO matrix_iam_owner;
REVOKE ALL ON SCHEMA iam FROM PUBLIC;

COMMIT;
