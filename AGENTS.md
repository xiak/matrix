# Matrix engineering instructions

## Pragmatic DDD

- Put code under its bounded context and use the PaaS ubiquitous language.
- Domain rules stay pure; use cases own workflow and transactions; persistence
  and external systems remain adapters.
- Add an abstraction only when it protects a business invariant or boundary,
  isolates a real side effect/variation, or contains existing complexity.
- Do not create a class, interface, repository, package, layer, event, or
  duplicate model merely because a domain noun exists.
- Avoid ambiguous business names such as `Manager`, `Helper`, `Logic`, `DAO`,
  `Model`, `DTO`, and catch-all `common` packages.
- Keep Phase 1 a modular monolith. Split a context physically only for a real
  scaling, release, ownership, failure-isolation, security, or data boundary.

## Frontend experience

- Reuse the existing public UI owner for shared controls, brand assets,
  dimensions, focus, keyboard, loading, and error states. Extract components
  for demonstrated reuse or existing interaction complexity, not every node.
- New or rewritten UI uses semantic theme tokens and keyed locale messages.
  Keep business state language-neutral; format user-facing values at the
  presentation boundary. Preserve offline assets and the static host's CSP.

## Feature adoption

For each FEAT, design the smallest enterprise target first. Then inspect the
legacy repository only at a fixed commit and record each relevant slice as
`REUSE`, `ADAPT`, `REFERENCE`, or `REJECT`. The legacy repository must not
become a build or runtime dependency.

Deliver independently testable vertical slices. A feature is not accepted
until its specified unit, architecture, integration, security, and real-runtime
gates pass.

## Replacement-first pre-v1 changes

- Git history preserves superseded drafts; the working tree does not. When a
  pre-v1 concept, path, contract, test, or document is replaced or rejected,
  delete it in the same slice instead of adding an alias, compatibility layer,
  parallel implementation, or amendment history.
- Compatibility requires evidence: an already published contract, a real
  consumer that cannot migrate atomically, or an explicit FEAT requirement.
  Uncertainty by itself is not evidence and does not justify retaining old
  code.
- For a risky replacement, first commit and push the current coherent,
  verified state, then perform the replacement. Use Git for rollback; never
  keep duplicate source paths or dead code as an in-tree rollback mechanism.
- Before adding a file, package, interface, test suite, or document, identify
  its current owner. Modify that owner unless the new artifact protects a
  distinct boundary or proves an acceptance gate that has no existing owner.
- Tests survive only while they prove a current contract, invariant, security
  boundary, or supported runtime behavior. Delete tests for removed features;
  replace implementation snapshots such as SQL text, file layout, line counts,
  and incidental call order with behavior or schema-invariant checks.

## Documentation ownership and reading route

Every fact has exactly one documentation owner:

- a FEAT owns its requirement, design, implementation status, acceptance
  criteria, and evidence;
- an ADR owns only a costly-to-reverse boundary shared by multiple FEATs;
- an adoption record owns only fixed donor commits and
  `REUSE`/`ADAPT`/`REFERENCE`/`REJECT` decisions;
- an explicitly requested external reference collection under `docs/research/`
  owns source-backed findings, coverage and limitations, not Matrix requirements,
  implementation status or acceptance evidence;
- a runbook owns only commands that have been executed and verified.

README and index files are link-only navigation. They must not duplicate FEAT
status, resource tables, acceptance criteria, commands, or adoption results.
Transient research notes, implementation diaries, discussion, and progress
belong in GitHub Issues or the non-authoritative `notes/codex/CHECKPOINT.md`,
not formal repository documentation. External reference collections keep a
link-only topic index and distinguish sourced facts, observations, analysis,
and unadopted recommendations. Rewrite or remove stale prose instead of
appending amendment histories.

Load context on demand:

1. Normal FEAT work: this file, that one FEAT document, then owning code/tests.
2. Cross-FEAT boundary change: additionally read the directly relevant ADR.
3. Donor inspection: additionally read that FEAT's adoption record and fixed
   source entry.
4. Install/upgrade/operations: additionally read the directly relevant
   verified runbook.
5. Resume after compaction or handoff: read the single Codex checkpoint, then
   validate it against Git and the owning FEAT. Do not load it for normal work.
6. Tencent CAM reference: open `docs/research/tencent-cam/README.md`, then only
   the leaf for the current question. Open evidence files to check coverage or
   conflicts; do not preload the collection.

Do not scan or load the entire `docs/` tree by default. Do not add a document
for a newly learned fact; place durable conclusions in the existing owner.
Keep one rolling Codex checkpoint and replace it only at milestones; never
create per-turn or per-command log files.
For cross-machine handoff, the checkpoint describes only work committed and
pushed on the current feature branch. Absolute checkout paths and uncommitted
machine-local state are not portable memory.

Keep a persistent Codex goal short and outcome-only. It may name the
repository, release outcome, adoption rule, and final release gate, but it
must not duplicate FEAT inventories, resource/type vocabularies, acceptance
tables, implementation status, or next steps. Those details belong to their
existing FEAT owner or the rolling checkpoint. A one-time resume prompt points
to these files instead of restating them.

## GitHub workflow

Use GitHub's free repository capabilities when they protect a real delivery
boundary: Actions for independent gates, Issues for actionable FEAT work,
Milestones for phase releases, and Releases for accepted artifacts/notes.
Enable dependency/security automation when the corresponding dependency or
release surface exists. Do not create process artifacts for trivial edits.

## Git identity

Repository commits use exactly `Xiak <Jellal@aliyun.com>`. Keep this as
repository-local Git configuration; do not inherit or change the machine's
global Git profile.
