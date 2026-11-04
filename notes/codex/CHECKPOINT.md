# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-04
- Repository: https://github.com/xiak/matrix.git
- Branch: feat/cloudflare-tunnel-entry
- Outcome: native Docker HTTPS deployment through Cloudflare Tunnel on Tencent Debian, with verified user workflows and no credentials in GitHub.
- Base main: c609e1078cee3c55442d0164738f03fc28676f15. Published v0.3.0 is immutable and has no HTTPS profile.

Follow AGENTS.md and repository-local identity `Xiak <Jellal@aliyun.com>`.
Read [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#local-https-proxy-ingress), then the owning code/tests and [deployment runbook](../../docs/runbooks/platform-installation.md#腾讯云-debian-与-cloudflare-tunnel).

Implementation f6cf6e76fb5f4df028e7e57ad877dbf0e9fcbf60 passed independent
Verification 41612656543 and native HTTPS lifecycle 41612484059. The latter
includes six first-use browser checks, 27 retained ELK/Redis browser checks,
engine restart and proxy interruption/recovery. Its candidate uses an
ephemeral acceptance signer, not the production signer. FEAT-005 owns
precise evidence; these gates do not prove the public Tencent deployment.

The dedicated Debian 12 host has its existing Docker engine and a healthy,
boot-enabled host-native Cloudflare connector. The accepted candidate and
public trust were delivered with both transport hashes verified. Live
installation remains incomplete. The CLI rejected an ordinary HTTPS URL
before the backend could add port 443. This snapshot fixes that premature
validation and passes CLI/backend/topology tests. The old accepted package
was retried with explicit 443, then rolled back safely with
IMAGE_VERIFICATION_FAILED: its classic-engine image config ID differs from
the archive OCI manifest ID loaded by the server's containerd store. A direct
authenticated APISIX archive load reproduced this. Do not weaken identity
verification, modify signed bundles, or switch the host image store to hide
the problem. Next inspect the existing releasebuild archive owner and signed
runtime identity contract, fix cross-store acceptance, and run its actual
runtime gate before retrying the public install. Preserve the failed
installation journal and original host images.

The user approved internal-only SMTP and a controlled DEMO: no public
registration or shared owner account; private owner and invited independent
read-only child accounts, using PaaSViewer as both boundary and grant.
deploy/demo-mail owns operator-side provisioning/verification, outside the
Matrix runtime and release bundle. Pinned Mailpit has passed twenty live
checks, Docker restart with retained messages, and certificate renewal with
unchanged CA/configuration. The canonical production SMTP codec accepts its
input. UI access through an authenticated SSH forward also works. FEAT-005
owns the limits: this is not external delivery, and Matrix's own notification
workflow awaits READY. Demo tenant/users have not yet been created.

Complete the public HTTPS first-use journey, Matrix-to-mailbox verification,
DEMO permission denials, proxy interruption and host reboot recovery. Then
finish reader-facing screenshots/workflows and acceptance evidence. Draft
PR #16 tracks this work; no merge or formal release has occurred. Do not
bypass main-only production signing or regenerate established signing keys.
A temporary broad sudo grant must be removed after deployment verification
as promised. Token rotation remains an operator-private handoff.

Keep all server identifiers, SSH access material, SMTP/Tunnel credentials,
browser storage and signing secrets out of Git and public evidence. Preserve
the user's original local Matrix installation and data. No large candidate
archive is stored on the Windows disks. The prior ELK/Redis goal is complete;
do not restart it.
