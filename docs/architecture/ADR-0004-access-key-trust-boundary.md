# ADR-0004: AccessKey authentication and secret custody

- Status: Accepted
- Date: 2026-09-17

## Context

IAM owns user credentials and current authorization. Product services own
the HTTP requests and resources they enforce. Installation owns protected
local material, release topology and backup/recovery. Existing opaque login
and role credentials require only digests; HMAC program credentials require
usable shared-secret material at verification time. They must not inherit a
fake login Session or expose that material to every product service.

This is a distinct cross-context security decision, not a new service or a
replacement for [ADR-0002](ADR-0002-product-boundary.md). Product lifecycle,
wire protocol, limits, implementation and evidence belong exclusively to
[FEAT-IAM-007](../../IAM/FEAT-IAM-007-programmatic-credentials.md).

## Decision

### One identity, distinct authentication carriers

An AccessKey authenticates its actual USER. It does not become another
principal, a ServiceIdentity, a browser Session or a RoleSession. Credential
validation and the user policy input are separate boundaries; all carriers
reuse the same applicable policy and boundary evaluator. Current tenant,
user, key and policy state remains authoritative for every request.

Products construct signature input from the actual HTTP request they handle.
IAM verifies the request-bound signature under an independently authenticated
calling service, consumes its nonce and makes the current authorization
decision. A verification result is not an exchangeable or cacheable permit.
Transport signatures do not prove the final business payload or replace the
product transaction/outbox. Current producer credentials and immutable
historical decision evidence remain separate from current user permission.

### Independent installation-managed wrapping material

AccessKey uses a public key identifier and a one-time shared secret for
HMAC-SHA256. A one-way secret digest is not a sufficient HMAC verifier.
IAM stores authenticated ciphertext with a wrapping-key identifier and
nonce; authenticated associated data binds the sealed installation, account,
user, key identity and encoding version. It does not store plaintext or expose
database-side decryption to the API database login.

Only the IAM API receives the required read-only wrapping keyring. Products,
Audit, workers, installation verifiers and ordinary database readers do not
receive it. Wrapping material is distinct from bootstrap, service, cursor,
release-signing and offline-recovery secrets. Secret disclosure is limited
to the explicit first successful creation response; ability to decrypt for
verification does not authorize later display or replay of the secret.

Installation owns protected files and mounts, identity/permission validation,
multi-instance delivery, paired backup/recovery and key rotation. IAM owns
validation and purpose-limited use, and rejects unavailable, mismatched or
corrupt material. A process restart must not silently generate replacement
wrapping material. Matching database state alone is not proof that a backup
can be recovered under another installation or keyring.

### Durable replay rejection and preserved history

Nonce consumption is a shared authoritative transaction, not local process
memory. A cryptographically valid signed request consumes its nonce even
when current authority denies access, so later grants cannot reactivate the
same message. Bad signatures and unknown key IDs do not allocate arbitrary
nonce rows. A new transport retry uses a new nonce while preserving the
original business intent; the business service retains its own idempotency.

Public attribution exposes only the required key ID alongside the real
USER. Ciphertext, keyring versions, raw signatures, nonces and canonical
requests remain outside public decisions and Audit events. Immutable
historical evidence must remain verifiable after current key revocation;
older USER events cannot be rewritten to pretend they carried key lineage.

## Consequences

- IAM API compromise can expose material that it is authorized to decrypt;
  database-only compromise is a different boundary. This design does not
  claim HSM isolation or resistance to a root-controlled whole-install rollback.
- IAM and product PEPs require a coordinated typed request/evidence contract;
  adding a new accepted credential cannot globally widen USER or platform APIs.
- Production key files, recovery, rotation and release admission need their
  own real-runtime evidence. A test keyring or successful crypto vector does
  not establish deployability, high availability or cross-profile compatibility.
- Existing service identities, role-session evidence and old Audit canonical
  bytes are not loosened by this choice. No schema or release revision is
  allocated by this ADR.
