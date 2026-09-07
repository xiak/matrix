# Codex working checkpoint

> Non-authoritative portable memory. Validate it against Git and the owning
> FEAT before continuing.

- Updated: 2026-09-07
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/devops-cicd-prow-adoption`
- Current pushed implementation baseline: `e2249bc`

## Goal

Evolve Matrix from the accepted private Application PaaS into a private-cloud
foundation with independently selectable products, then deliver the DevOps
product through the repository's design, UX, architecture, FEAT, code, test,
and acceptance sequence.

## Current milestone

- FEAT-008 owns the current product-foundation work and remains `In progress`.
  Its unified shell, signed installed-product discovery, legacy IAM authority
  migration, and fixed productless-predecessor lifecycle compatibility are
  implemented. Read that FEAT and owning code/tests before continuing.
- A clean Docker-in-Docker host with outer network mode `none` verified the
  signed cross-version lifecycle from accepted source `c88a84f` Release A to
  `ea4e808` Release B, including failed-upgrade rollback, product readiness,
  explicit rollback, old-backup recovery, support leakage checks, and whole
  host restart.
- A separate clean network-disabled host verified that two current
  `e2249bc` releases install from an empty root, expose the exact signed PaaS
  product as ready, preserve it across every lifecycle transition, and recover
  after a whole-host restart without using the legacy path.
- FEAT-008 is not accepted yet. It still requires a fixture second-product
  transition and authenticated-browser/accessibility evidence. Keep those gaps
  in the owning FEAT rather than duplicating their acceptance details here.

## Adoption boundary

- Prow is fixed at source commit
  `1a000594c40919068dd43a5704f279f273135d18` and is a reference/selective
  adaptation donor, never a Matrix build or runtime dependency.
- CODING is a product-experience reference. Matrix owns the unified code,
  trigger, pipeline, artifact, and deployment experience while execution
  remains adapter-based and can later target native cloud execution or
  Jenkins.

## Continuation

Resume from FEAT-008 and Git state. Close its remaining real-runtime gates
before claiming product-foundation acceptance, then proceed to the DevOps FEAT
vertical slices. Preserve pragmatic DDD, the modular-monolith boundary,
replacement-first pre-v1 changes, fixed-donor classification, and the exact
repository-local Git identity `Xiak <Jellal@aliyun.com>`.
