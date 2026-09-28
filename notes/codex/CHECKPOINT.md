# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam; exclusive
  independent worktree only. Milestone 2026-09-28. Full goal ACTIVE/incomplete.
- Latest committed and pushed production/test candidate:
  **18bdcd9aada6c03fbab7d701884306f12dba4ed2**.
  Voluntary TOTP removal and proved re-enrollment, source IAM46/Audit27.
  The existing process gate's actual PaaS2 is unchanged.
- Exact candidate Verification **36382998585**:
  https://github.com/xiak/matrix/actions/runs/36382998585
  GitHub API confirmed head SHA and queued status, not success.
  Source pushes cancel an in-progress branch run: do not supersede this gate
  with incidental source edits. Checkpoint/docs-only pushes do not trigger it.
- Latest independently accepted source is still
  **42035189eb823e388509f54525889c1a18c6b79d** (IAM45/Audit26).
  Exact Verification36367216408 was rechecked completed/success this turn.
  Do not backfill earlier failed/cancelled gates or call the new candidate
  accepted before its own result is inspected.

## Reading route and next outcome

Read AGENTS, IAM/FEAT-IAM-009-security-governance.md's voluntary removal
section, then the owning API, IAM/Audit SQL/use cases and tests. IAM/011 owns
the single-predecessor window and CI allocation; the existing FEAT-006
adoption record owns the fixed source decisions. Do not load foreign WIP.

First inspect the exact candidate CI and actual failed jobs, if any.
Local gates passed; final independent CI, LIVE UX and signed installation
remain separate acceptance boundaries. Notify the existing installation/UX
owners only with exact fixed source and evidence, never inherit their status.

Continue the full goal after this slice. Qualification-changed old-backup
recovery still needs trusted current-state carriage/rebuilding: permanent
rejection alone is not the final target. Other IAM/009 requirements and
IAM/011 capacity/fairness/database-HA gates remain incomplete. Use their
owners rather than redefining completion around removal.

## Fixed candidate behavior and evidence

TOTP_REMOVE is a same-Session/password/original-factor purpose. Ordinary
qualified USERs may remove their own factor only when the Account does not
require MFA; original roots and any unrevoked installation attachment remain
protected. No administrator impersonation or new grantable Policy action.
The atomic completion revokes old factor/batch, all login Sessions and
pending challenges, writes the permanent receipt/Audit/notification and
consumes the proof. New normal login is PASSWORD; later normal or required
ENROLLMENT binds a new factor with explicit removal provenance. Exact old
completion lookup/replay requires today's valid same USER but does not
revoke its new Session/factor or return a new REAUTHENTICATE instruction.

The sole internal qualification projection is now
matrix.iam.authentication-state.v2 and includes validated removal/rebind
lineage. Public Audit canonical, ServiceIdentity/lookup_service, seven-column
claim and private snapshot/envelope codecs are unchanged. Existing exact
completed private receipts remain immutable; old qualification is not a
new recovery permit.

Local evidence is in IAM/009, not a claim of signed release acceptance:
real PG18.6 removal/required-enrollment, stored-history attacks, settings,
authority/session/password/status/factor/recovery races and natural expiry;
actual restricted SMTP worker/Postfix Maildir and historical mail delivery;
dual IAM/PaaS/Audit/outbox with commit-then-lost TCP, restarts, RoleSession
non-revival and historical chain; dual-authority SQL/Audit HTTP.

This turn replaced the single retained predecessor with actual fixed420
IAM45 -> current IAM46 (57.48s/package60.834s). Old private binaries create
the real snapshot-bound history; CLOSED migration fails atomically, OPEN
completed replay preserves bytes/floors, and an unreconciled old snapshot
cannot authorize new effects. Old IAM44 snapshot-free branches were deleted,
not kept as a parallel matrix. Late DDL failure preserves old schema/data.
Real retained factors support current removal/rebind and original bounded
saved-code recovery; original canonical/producer proof and product catalog
evolution remain checked.

Final current-source three-database dump/restore race passed163.88s
(package167.462s); actual private backup/recovery process gate passed32.75s
(package36.180s), including lost stdout and original exact replay.
Whole-repository race-p2, architecture, vet, module verification, stable API
generation, Linux amd64 build, gofmt/diff and YAML/19 Bash checks passed.
Actual local Go1.26.3, GOMAXPROCS2/GOMEMLIMIT512MiB; external default SKIPs are
not real acceptance. New removal lanes are serial,15m each, same existing PG
limits and fail-closed aggregate. Exact candidate CI is pending.

CurrentDatabaseProfile remains the prior accepted 4/3/1+r4. Source version
46/27/2 is not a release profile or cross-profile compatibility claim.
Installation owns its actual PaaS/revision and signed consumers.

## Coordination and resource boundaries

Installation thread 01a04149-5dbb-7300-9e4c-31d9e85c8ada owns signed consumers,
profile/journal/keys/backups and actual restore. It previously received the
accepted420 dependency closure. Do not overlay its terminal/PaaS/host catalogs,
security-mail consumer, UI or profile, and do not read its WIP.

UX thread 01a07b21-9a0d-7fd0-b090-7827ce18262e owns feat/cloud-console-ux and
all UI work. It reported fixed5b191aa0/checkpoint2861651a with776 tests and
MOCK review improvements; no UI source or acceptance was imported.
Read-only fixed420 attachment review confirms no public historical by-request
lookup. Create/revoke exact retry still needs current authentication and
authorization; revoke retains original attachment/version/request/actor.
Unknown401/403/409 or an absent current relation does not prove no prior
commit. UX was told to retain the whole original intent under the same
Account/actor and never automatically mint a new grant after uncertainty.
This gap belongs to IAM/002, not the removal contract.

Markdown only, existing owners, no duplicate framework. Git identity exactly
Xiak <Jellal@aliyun.com>, repository-local only. No new agents/tasks, foreign
WIP, remote1.3/160/161 or withdrawn1.5/GitLab, shared Docker/WSL/global changes
or remote restarts. Own feature commits/resources only.

All local tests finished. After confirming zero other clients and the exact
owned PostgreSQL executable/data directory, the exclusive native PG was
normally stopped; its launcher returned exit0. All database data was retained.
The previous SMTP fixture and its empty same-owner network were removed after
an empty queue. No foreign process, volume or data was deleted. Revalidate
actual local ownership and live handles before resuming runtime work.
