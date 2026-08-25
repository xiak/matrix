BEGIN;

DO $matrix_audit_roles$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'matrix_audit_owner',
        'matrix_audit_migrator',
        'matrix_audit_runtime'
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
$matrix_audit_roles$;

DO $matrix_audit_migrator_membership$
BEGIN
    IF NOT pg_has_role('matrix_audit_migrator', 'matrix_audit_owner', 'MEMBER') THEN
        EXECUTE 'GRANT matrix_audit_owner TO matrix_audit_migrator';
    END IF;
END
$matrix_audit_migrator_membership$;
DO $matrix_audit_runtime_memberships$
DECLARE
    parent_name text;
BEGIN
    FOREACH parent_name IN ARRAY ARRAY['matrix_audit_owner', 'matrix_audit_migrator']
    LOOP
        IF EXISTS (
            SELECT 1
              FROM pg_catalog.pg_auth_members AS membership
              JOIN pg_catalog.pg_roles AS parent_role
                ON parent_role.oid = membership.roleid
              JOIN pg_catalog.pg_roles AS member_role
                ON member_role.oid = membership.member
             WHERE parent_role.rolname = parent_name
               AND member_role.rolname = 'matrix_audit_runtime'
        ) THEN
            EXECUTE format('REVOKE %I FROM matrix_audit_runtime', parent_name);
        END IF;
    END LOOP;
END
$matrix_audit_runtime_memberships$;

CREATE SCHEMA IF NOT EXISTS audit AUTHORIZATION matrix_audit_owner;
ALTER SCHEMA audit OWNER TO matrix_audit_owner;
REVOKE ALL ON SCHEMA audit FROM PUBLIC;

COMMIT;
