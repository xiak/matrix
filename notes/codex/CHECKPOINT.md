# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-11-04
- Repository: https://github.com/xiak/matrix.git
- Branch: feat/cloudflare-tunnel-entry
- Pushed delivery milestone: e864c375a8995c853f1d7d07feff3fd08c284bc6
- Outcome: native Docker HTTPS deployment through Cloudflare Tunnel, controlled DEMO access, internal-only mail, verified recovery and user guides; no credentials in Git.

Follow AGENTS.md and repository-local identity `Xiak <Jellal@aliyun.com>`.
Read [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md#local-https-proxy-ingress), then the owning code/tests and [deployment runbook](../../docs/runbooks/platform-installation.md#腾讯云-debian-与-cloudflare-tunnel).

Implementation 710d69cdd1882d2561e764cde412cfdb5955e9c6 passed independent
Verification 41767519880 and native HTTPS acceptance 41767522093, including
cold containerd image identity, classic-engine offline lifecycle, restart,
first-use and ELK/Redis browser journeys. Its disposable acceptance signer
does not authorize a production Release. The existing v0.3.0 is immutable.

That exact candidate is now accepted on the dedicated Tencent Debian host.
The public first-use, three private/individual identities, read-only MySQL,
permission denials, account withdrawal, actual Matrix internal mail, Tunnel
interruption and host reboot gates passed. FEAT-005 owns their evidence and
limits. The operator mailbox tools now cover the UFW notification-network
rule and the socket boot-order correction. User guides include real reviewed
screenshots and the actual create-user/boundary/grant sequence.

The user explicitly requests the GitHub Release workflow. PR #16 passed all
20 checks in 41786587929 and was fast-forward merged with the required Git
identity. Main is 0afed148437c9241ccd61e62742a7577c7f15176. Its independent
Verification 41790163222 and Product onboarding 41790180425 are running.
Keep main fixed until that source's production delivery is accepted. This
branch may retain documentation/checkpoint updates separately. After both
main gates pass, prepare v0.4.0 with successor v0.4.1 used only for
lifecycle acceptance, `prepare_release=true` and `https_proxy=true`. Use the
existing protected production signer; never regenerate it or relabel the
accepted feature candidate. Review the resulting draft's signature, source,
complete assets and evidence before publishing. No formal release for this
HTTPS change has occurred yet.

Keep server identifiers, SSH material, SMTP/Tunnel credentials, browser
storage and signing secrets outside Git and public evidence. The server's
temporary broad passwordless sudo grant has been removed; normal password
sudo remains. Private account handoff is outside the checkout and only the
current Windows user can read it. Token rotation remains an operator-private
handoff. Preserve the installed demo, original failed-installation diagnosis
and the user's original local Matrix data. No large archive is stored on the
Windows disks. The earlier ELK/Redis goal is complete; do not restart it.
