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

## Feature adoption

For each FEAT, design the smallest enterprise target first. Then inspect the
legacy repository only at a fixed commit and record each relevant slice as
`REUSE`, `ADAPT`, `REFERENCE`, or `REJECT`. The legacy repository must not
become a build or runtime dependency.

Deliver independently testable vertical slices. A feature is not accepted
until its specified unit, architecture, integration, security, and real-runtime
gates pass.

## Documentation ownership and reading route

Every fact has exactly one documentation owner:

- a FEAT owns its requirement, design, implementation status, acceptance
  criteria, and evidence;
- an ADR owns only a costly-to-reverse boundary shared by multiple FEATs;
- an adoption record owns only fixed donor commits and
  `REUSE`/`ADAPT`/`REFERENCE`/`REJECT` decisions;
- a runbook owns only commands that have been executed and verified.

README and index files are link-only navigation. They must not duplicate FEAT
status, resource tables, acceptance criteria, commands, or adoption results.
Research notes, implementation diaries, discussion, and transient progress
belong in GitHub Issues or the non-authoritative `notes/codex/CHECKPOINT.md`,
not formal repository documentation. Rewrite or remove stale prose instead of
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
