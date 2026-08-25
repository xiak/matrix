# Adoption policy

Matrix PaaS uses a slice-based adoption process. For every feature:

1. define the target enterprise contract and acceptance criteria;
2. inspect the fixed source revision;
3. classify each source slice as `REUSE`, `ADAPT`, `REFERENCE`, or `REJECT`;
4. admit only its minimal transitive dependency closure;
5. require local tests, build, architecture, license, and boundary checks;
6. record provenance in this repository.

Dirty donor worktrees are never adoption baselines. IAM and Audit data are not
migrated from the legacy embedded PaaS authorities.

Paths in `sources.yaml` identify donor-repository locations, not target
directories. In particular, legacy `platform/go/*` code is evaluated by
capability and admitted into its owning service; the directory is not copied
wholesale into Matrix PaaS.

See [sources.yaml](sources.yaml) for the initial fixed inputs.
