# Codex working checkpoint

> Non-authoritative portable memory. Validate against Git and the owning FEAT.

- Updated: 2026-09-28
- Repository: `https://github.com/xiak/matrix.git`
- Branch: `feat/phase3-mfa-enabling`
- Pushed milestone: `facbc5437c74ba67cedd6e662cd2097baa278637`.
  Its functional predecessor `b020d4a56c1b1cfb8fb9930d09e20fb0f7604c73`
  passed [Verification 36389282316](https://github.com/xiak/matrix/actions/runs/36389282316)
  in all four jobs. The current signed profile is IAM 45 / Audit 26 /
  PaaS 6, revision 16. This is not final combined-release acceptance.
- Historical host self-enrollment acceptance belongs to fixed
  `be3c4a96b4381426c01cd6315eaa3713c2855982`; the current composition
  still needs its own live-browser and source-preserving two-host gates.

## Resume route

1. [FEAT-005](../../docs/features/FEAT-005-offline-platform-lifecycle.md)
   owns the signed release and recovery gates.
2. [FEAT-007](../../docs/features/FEAT-007-control-plane-console.md)
   owns the IAM directory consumer and LIVE restricted first-enrollment browser gate.
3. [FEAT-008](../../docs/features/FEAT-008-linux-host-management.md)
   owns one-time host admission and its exact-source two-host runtime gate.
4. [FEAT-006](../../docs/features/FEAT-006-platform-authorities.md)
   owns the separately integrated IAM/Audit authority boundary.

The signed two-host attempt on the current composition reached real platform
install and original-primary recovery but could not prove host identity through
a NAT-forwarded control plane: both nodes appeared as one gateway peer.
FEAT-008 records the evidence and the required source-preserving topology.
Do not weaken observed-peer admission or claim this attempt as a pass. The
LIVE IAM browser also remains open; its current directory/API mismatch is in
FEAT-007. Preserve Phase 2 and remote machines, and clean isolated tests.
