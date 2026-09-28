# Codex working checkpoint

> Non-authoritative portable memory. Validate Git and the owning FEAT.

- Repository https://github.com/xiak/matrix.git, branch feat/iam; exclusive
  independent worktree only. Milestone 2026-09-28. Full goal ACTIVE/incomplete.
- Latest pushed implementation: **ba17e702b34895effd8ba5a250b31a2f87a569f2**.
  Cumulative pushed HEAD **3178b649f6e61c59786f6d0b14828ff3196876f3**
  includes the S3b settings-lineage design and **833cccf1** settings-relaxation
  races. Actual source IAM46/Audit27; the process gate's PaaS2 is unchanged.
- Exact candidate Verification **36391053858**:
  https://github.com/xiak/matrix/actions/runs/36391053858
  GitHub API confirmed head SHA and queued status, not success.
  Source pushes cancel an active branch run; do not cancel the real-window
  gate with incidental source pushes. Docs-only pushes do not trigger it.
- Previous18 run **36382998585** is completed/failure. Recovery-window
  completed/success at 2026-09-28 07:18:50 UTC. Replacement,
  replacement-qualification and removal-security failed; do not erase or
  relabel their failures.
- Latest independently accepted source remains
  **42035189eb823e388509f54525889c1a18c6b79d**, IAM45/Audit26,
  exact Verification36367216408 completed/success.

## Reading route and next outcome

Read AGENTS, IAM/FEAT-IAM-009-security-governance.md's S3b and current
implementation/evidence paragraphs, then the original password, settings,
credential and recovery owners. IAM/011 owns the single-predecessor window
and CI allocation; the FEAT-006 adoption record owns fixed sources.
Do not load foreign WIP or treat this checkpoint as feature authority.

Inspect exact candidate CI and actual failures. Continue account-configured
new-password rules and real history across every supported write path;
public settings/requirements APIs must not advertise unenforced behavior.
Age, idle expiry, security reports, qualification-changed old-backup recovery,
remaining FEATs and full capacity/fairness/database-HA are still required.
Permanent rejection of changed qualification is not the final recovery target.
UI and signed installation remain separate owner gates.

## Fixed behavior and evidence

The new-password baseline is 15–128 Unicode code points / 512 UTF-8 bytes,
preserves spaces/exact bytes and has no default composition requirement.
The unchanged Argon2id verifier accepts accurate historical secrets without
applying new admission. The bounded offline blocklist has 331 complete
entries from fixed SecLists c5a05259; exact source/license/adoption and asset
digest live in FEAT-006 adoption and the embedded authority asset.
No online secret lookup or complete-breach-coverage claim.

Original BootstrapDigest/installation/Account matching permits only exact
no-effect READY replay. Local recovery authenticates the private request,
checks the original commandId+inputCommitment and expected tuple before
hashing; exact completed results do not mutate again. First/NOT_FOUND and
changed inputs do not inherit old admission. No new SQL, FILE, recovery
power or release profile in this baseline.

Local PG18.6 under 2 logical CPU / 1GiB / 24 process / 16 connection limits;
Go1.26.3, GOMAXPROCS2/GOMEMLIMIT512MiB, real gates serial race-p1:
HTTP145.65s; local recovery37.19s; actual fixed420/IAM45 predecessor108.97s
(package112.415s); replacement/security/login package523.310s;
independent two-IAM/PaaS/Audit/dispatchers195.41s (package198.984s).
Old binary really creates 14-character passwords and sealed bootstrap;
current migration/restart preserves their exact verification/replay.
The old short-password local-recovery receipt special case is unit evidence,
not an actual predecessor-created receipt claim.
Whole repository race-p2/architecture, vet, module verification, stable API
generation, Linux amd64 build, gofmt/diff and YAML/19 Bash checks passed.
These are local source gates, not SMTP/LIVE UI/signed-release acceptance.

The replacement fixture now creates a real independent pending replacement
proof rather than sending an empty proof ID to a 400 decoder.
Removal-security keeps all six original fixtures but uses two sequential
Go processes; each keeps its original deadline, password cost and real OTP
window, the job stays15m and max-parallel1. The former shared Go10m timer
expired at600.087s while the last fixture had run only12s.
New independent CI is still required; no timeout or assertion was relaxed.

S3b design deliberately preserves settings completion lineage:
initial password defaults do not increment the continuous settings version,
fabricate USER/Decision/Audit or erase old completed bytes. Current writes
use complete MFA+password intent; old unfinished MFA-only settings proofs
cannot be consumed. Otherwise valid login Sessions do not need a migration-
only revocation. Real settings changes still advance the existing barrier.
Password history/age must record real hash writes, not credential-generation
fences. The sole private qualification projection must include the actual
rules/history/age; shared changes are coordinated before implementation.

CurrentDatabaseProfile remains the prior accepted4/3/1+r4.
Source46/27/2 is not a release profile or cross-profile compatibility claim.
ServiceIdentity/lookup_service, seven-column claim and Audit canonical
are unchanged. Do not change installation-owned profile/consumer admission.

## Coordination and resource boundaries

Installation thread **01a04149-5dbb-7300-9e4c-31d9e85c8ada** owns signed
consumers, profile/journal/keys/backups and actual restore. It received the
fixed3178/ba17 candidate and exact pending CI, not acceptance.
S3b proposes the sole internal authentication-state projection v3 while
retaining public snapshot/envelope/FILE framing; no release revision assigned.
Do not overwrite its PaaS/host catalogs, UI or profile or read its WIP.

UX thread **01a07b21-9a0d-7fd0-b090-7827ce18262e** owns all UI on
feat/cloud-console-ux. Its fixed **741eca88e39d1caeb9860bb35fc142125a0599f2**
reports the new Account/User identity/directory adapter and direct attachment
unknown-outcome handling, 781 tests and MOCK checks; no source or LIVE
acceptance imported. It and installation were asked to coordinate the full
fixed UI dependency closure rather than parallel old adapter rewrites.
UX knows no usable account-password settings/requirements contract is
frozen yet; do not expose placeholder saved rules.

Attachment unknown outcomes retain original Account/actor/request/target/
version; current auth failure or absent current relation does not prove the
old write never committed. No public historical by-request lookup was
invented; its gap belongs to IAM/002.

Markdown only, existing owners, no new agents/tasks, foreign WIP, remote1.3/
160/161 or withdrawn1.5/GitLab, shared Docker/WSL/global changes or remote
restarts. Local Git identity Xiak <Jellal@aliyun.com>. Own commits/resources.

All prior real tests and the exact owned native PG launcher exited normally.
PG was stopped only after zero other clients and exact executable/data-path
checks; data retained. Previous SMTP fixture/empty owned network removed
after an empty queue. Revalidate actual live ownership before new runtime work.
