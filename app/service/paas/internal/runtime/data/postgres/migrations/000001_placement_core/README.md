# 000001 placement core

This forward-only migration creates the minimum FEAT-003 Gate B persistence
closure. It must be applied by a non-runtime database owner with permission to
create the `matrix_paas_runtime` group role. Application logins inherit that
role but never own PaaS tables and must not have `BYPASSRLS`.

Capacity accounting is deliberately split. `capacity_reservations` is the
tenant-owned decision-to-claim mapping protected by forced RLS.
`capacity_claims` contains only target, resource, isolation, state, and lease
facts, so the scheduler can account for all tenants without learning another
tenant's identity or bypassing RLS.

`up.sql` is safe to invoke again after a successful application. It does not
silently repair changed table definitions; `verify.sql` fails on security or
constraint drift so a new migration must describe the repair.
